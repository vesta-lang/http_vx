/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/message.h
 * @brief
 * \~english A request and a response, the same whichever version brought them.
 * \~spanish Una peticion y una respuesta, iguales por la version que llegaran.
 * \~
 *
 * \~english
 * This is where R30 is either true or it is not: a handler must not need to
 * know which version a request arrived by.  What that costs is paid here,
 * because the three versions do not agree on where the same fact is written.
 *
 * | | HTTP/1.1 | HTTP/2 and HTTP/3 |
 * | :-- | :-- | :-- |
 * | the method | first word of the request line | `:method` |
 * | what is being asked for | the request-target | `:path` |
 * | which host | the `Host` field | `:authority` |
 * | http or https | not written; the connection knows | `:scheme` |
 * | the version | written out, `HTTP/1.1` | implied |
 *
 * So the request holds **five things the codec fills in from wherever its own
 * version keeps them**, and a handler reads the same five whichever it was.
 * The alternative -- handing over the fields as they arrived and letting the
 * reader look for `Host` or for `:authority` -- would put a conditional on the
 * version into every piece of code above this one, which is the same as not
 * having separated them.
 *
 * **There is no body here**, and that is deliberate.  A body is not a piece of
 * the message the way the target is: it may be framed by a length or by
 * chunks, it may be longer than memory, and it arrives after the fields do.
 * It is handed over as views while it arrives (R13), so a field holding it
 * would either be a lie for the streamed case or a buffer for the whole thing,
 * and the second one is what a server does when it is about to fall over.
 *
 * \~spanish
 * Aqui es donde R30 o es cierto o no lo es: un manejador no debe necesitar
 * saber por que version llego una peticion.  Lo que eso cuesta se paga aqui,
 * porque las tres versiones no coinciden en donde esta escrito el mismo hecho.
 *
 * | | HTTP/1.1 | HTTP/2 y HTTP/3 |
 * | :-- | :-- | :-- |
 * | el metodo | primera palabra de la linea de peticion | `:method` |
 * | que se pide | el destino de la peticion | `:path` |
 * | que anfitrion | la cabecera `Host` | `:authority` |
 * | http o https | no se escribe; lo sabe la conexion | `:scheme` |
 * | la version | escrita, `HTTP/1.1` | implicita |
 *
 * Asi que la peticion tiene **cinco cosas que el codec rellena de donde las
 * guarde su version**, y un manejador lee las mismas cinco sea cual fuera.  La
 * alternativa -- entregar las cabeceras tal como llegaron y dejar que quien lee
 * busque `Host` o `:authority` -- pondria un condicional sobre la version en
 * cada trozo de codigo por encima de este, que es lo mismo que no haberlas
 * separado.
 *
 * **Aqui no hay cuerpo**, y es a proposito.  Un cuerpo no es un trozo del
 * mensaje como lo es el destino: puede trocearse por longitud o por trozos,
 * puede medir mas que la memoria, y llega despues que las cabeceras.  Se
 * entrega como vistas segun llega (R13), asi que un campo que lo guardara seria
 * o una mentira para el caso en flujo o un buffer con todo entero, y lo segundo
 * es lo que hace un servidor justo antes de caerse.
 *
 * \~
 */
#ifndef HTTP_VX_MESSAGE_H
#define HTTP_VX_MESSAGE_H

#include "http_vx/fields.h"
#include "http_vx/method.h"
#include "http_vx/span.h"
#include "http_vx/status.h"

namespace http_vx {

/**
 * @brief
 * \~english Which version a message arrived by, or is to be written in.
 * \~spanish Por que version llego un mensaje, o en cual se va a escribir.
 * \~
 *
 * \~english
 * A handler must not NEED this (R30), which is not the same as not being
 * allowed to see it.  Some decisions genuinely depend on it -- whether saying
 * `Connection: close` means anything, whether a trailer will get through --
 * and hiding it would only move the guessing somewhere with less to go on.
 *
 * `Http09` is not here.  It had no fields and no version on the wire, so a
 * request in it is indistinguishable from a truncated one, and recognising it
 * means treating a broken message as a valid one.
 *
 * \~spanish
 * Un manejador no debe NECESITAR esto (R30), que no es lo mismo que no poder
 * verlo.  Algunas decisiones dependen de verdad de ello -- si decir
 * `Connection: close` significa algo, si un remolque va a llegar -- y
 * esconderlo solo moveria las conjeturas a un sitio con menos datos.
 *
 * `Http09` no esta.  No tenia cabeceras ni version en el cable, asi que una
 * peticion suya no se distingue de una truncada, y reconocerla es tratar un
 * mensaje roto como uno valido.
 *
 * \~
 */
enum class Version : uint8_t {
    /// \~english Nobody has said yet.  \~spanish Todavia no lo ha dicho nadie.  \~
    Unknown = 0,
    /// \~english HTTP/1.0: no reuse unless asked for.
    /// \~spanish HTTP/1.0: sin reutilizacion salvo que se pida.  \~
    Http10,
    /// \~english HTTP/1.1: text, one message at a time per connection.
    /// \~spanish HTTP/1.1: texto, un mensaje a la vez por conexion.  \~
    Http11,
    /// \~english HTTP/2: frames over TCP.  \~spanish HTTP/2: tramas sobre TCP.  \~
    Http2,
    /// \~english HTTP/3: frames over QUIC.  \~spanish HTTP/3: tramas sobre QUIC.  \~
    Http3,
};

/**
 * @brief
 * \~english One request, as the handler sees it.
 * \~spanish Una peticion, tal como la ve el manejador.
 * \~
 *
 * \~english
 * Every span is measured from the message's first byte, so reading any of them
 * takes the buffer's @c data() and nothing else.  Nothing here owns bytes.
 *
 * \~spanish
 * Todos los trozos se miden desde el primer byte del mensaje, asi que leer
 * cualquiera de ellos lleva el @c data() del buffer y nada mas.  Aqui nada es
 * dueno de ningun byte.
 *
 * \~
 */
struct Request {
    /**
     * \~english
     * The method, recognised.  @c Unknown is ordinary: the set is open and the
     * parser does not interpret it (R19).
     * \~spanish
     * El metodo, reconocido.  @c Unknown es corriente: el conjunto es abierto y
     * el analizador no lo interpreta (R19).
     * \~
     */
    MethodId method = MethodId::Unknown;

    /**
     * \~english
     * The method as the peer wrote it.  It is kept even when the method WAS
     * recognised, because an intermediary forwards what it received and not
     * the canonical spelling -- and because a method that was not recognised
     * has nowhere else to live.
     * \~spanish
     * El metodo tal como lo escribio el otro extremo.  Se guarda incluso cuando
     * el metodo SI se reconocio, porque un intermediario reenvia lo que recibio
     * y no la grafia canonica -- y porque un metodo que no se reconocio no
     * tiene otro sitio donde vivir.
     * \~
     */
    Span method_text = {0, 0};

    /**
     * \~english
     * What is being asked for: the path and query.  It is not decoded and not
     * validated here; a target is a URI and that is its own grammar.
     * \~spanish
     * Lo que se pide: la ruta y la consulta.  Aqui no se descodifica ni se
     * valida; un destino es una URI y esa es su propia gramatica.
     * \~
     */
    Span target = {0, 0};

    /**
     * \~english
     * Which host is being addressed.  The codec fills it from `Host` or from
     * `:authority`, and a handler does not learn which.
     * \~spanish
     * A que anfitrion se dirige.  El codec lo rellena de `Host` o de
     * `:authority`, y el manejador no se entera de cual.
     * \~
     */
    Span authority = {0, 0};

    /**
     * \~english
     * `http` or `https`.  HTTP/1.1 does not write it, so there the codec puts
     * what the connection is -- which is the one place that knows.
     * \~spanish
     * `http` o `https`.  HTTP/1.1 no lo escribe, asi que ahi el codec pone lo
     * que sea la conexion -- que es el unico sitio que lo sabe.
     * \~
     */
    Span scheme = {0, 0};

    /// \~english Which version brought it.  \~spanish Por que version llego.  \~
    Version version = Version::Unknown;

    /// \~english Its header fields.  \~spanish Sus cabeceras.  \~
    Fields fields;

    /**
     * @brief
     * \~english Empties it to serve the next request on the same connection.
     * \~spanish La vacia para servir la peticion siguiente de la misma conexion.
     * \~
     *
     * \~english
     * Every span goes back to nothing rather than being left as it was.  A
     * span that survived would name bytes of the previous message, and after
     * the buffer consumed them it would name whatever is at that offset now --
     * which is a piece of the request that came after, read as if it were a
     * piece of the one before.
     *
     * \~spanish
     * Todos los trozos vuelven a nada en vez de quedarse como estaban.  Un
     * trozo que sobreviviera nombraria bytes del mensaje anterior, y despues de
     * que el buffer los consumiera nombraria lo que haya ahora en ese
     * desplazamiento -- que es un pedazo de la peticion que vino despues, leido
     * como si fuera de la de antes.
     *
     * \~
     */
    void clear() noexcept;
};

/**
 * @brief
 * \~english One response, as it is about to be written.
 * \~spanish Una respuesta, tal como se va a escribir.
 * \~
 *
 * \~english
 * There is no reason phrase here.  HTTP/2 and HTTP/3 do not have one, and
 * HTTP/1.1 gets it from the status code when it writes the status line; a
 * field for it would be a field that two of the three codecs ignore and that
 * the third can work out.
 *
 * \~spanish
 * Aqui no hay frase de motivo.  HTTP/2 y HTTP/3 no la tienen, y HTTP/1.1 la
 * saca del codigo de estado al escribir la linea; un campo para ella seria un
 * campo que dos de los tres codecs ignoran y que el tercero sabe deducir.
 *
 * \~
 */
struct Response {
    /// \~english The status code.  \~spanish El codigo de estado.  \~
    StatusCode status = 0;

    /// \~english Which version it is written in.  \~spanish En que version se escribe.  \~
    Version version = Version::Unknown;

    /// \~english Its header fields.  \~spanish Sus cabeceras.  \~
    Fields fields;

    /// \~english Empties it for the next response.
    /// \~spanish La vacia para la respuesta siguiente.  \~
    void clear() noexcept;
};

/**
 * @brief
 * \~english Whether @p v is one of the text versions.
 * \~spanish Si @p v es una de las versiones de texto.
 * \~
 *
 * \~english
 * The two of them share a syntax and differ in what they assume: `HTTP/1.0`
 * closes the connection unless asked not to, and `HTTP/1.1` keeps it unless
 * asked to close.  Getting that backwards does not produce an error, it
 * produces a connection that one side thinks is still there.
 *
 * \~spanish
 * Las dos comparten sintaxis y difieren en lo que suponen: `HTTP/1.0` cierra la
 * conexion salvo que se le pida que no, y `HTTP/1.1` la conserva salvo que se
 * le pida cerrar.  Errarlo al reves no produce un error, produce una conexion
 * que una de las dos partes cree que sigue ahi.
 *
 * \~
 * @param v \~english the version  \~spanish la version  \~
 * @return  \~english true for HTTP/1.0 and HTTP/1.1
 *          \~spanish true para HTTP/1.0 y HTTP/1.1  \~
 */
constexpr bool version_is_text(Version v) noexcept {
    return v == Version::Http10 || v == Version::Http11;
}

/**
 * @brief
 * \~english The version as it is written on the wire, or an empty string.
 * \~spanish La version tal como se escribe en el cable, o cadena vacia.
 * \~
 *
 * \~english
 * Only HTTP/1.0 and HTTP/1.1 have one; the other two are not announced inside
 * the message.  Empty is the right answer for those and not a failure to
 * report -- it is what there is to write.
 *
 * \~spanish
 * Solo HTTP/1.0 y HTTP/1.1 la tienen; las otras dos no se anuncian dentro del
 * mensaje.  Vacio es la respuesta correcta para esas y no un fallo del que
 * informar: es lo que hay que escribir.
 *
 * \~
 * @param v \~english the version  \~spanish la version  \~
 * @return  \~english the text, or ""  \~spanish el texto, o ""  \~
 */
const char *version_text(Version v) noexcept;

} // namespace http_vx

#endif // HTTP_VX_MESSAGE_H
