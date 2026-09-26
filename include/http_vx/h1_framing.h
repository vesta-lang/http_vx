/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h1_framing.h
 * @brief
 * \~english Where the body of an HTTP/1.1 request ends.
 * \~spanish Donde acaba el cuerpo de una peticion HTTP/1.1.
 * \~
 *
 * \~english
 * This is the one decision in HTTP/1.1 that an attacker gets to argue about,
 * and it is worth saying why before saying how.
 *
 * A message says how long its body is in one of two ways: a length in a field,
 * or a sequence of chunks that announce their own sizes.  The problem is that
 * a message can say both, and then it has two ends -- and a chain of servers
 * does not have to agree on which one.  The one in front reads a body of five
 * bytes and forwards the rest as a second request; the one behind reads the
 * chunks and never sees it.  The request that appears out of nowhere was
 * written by whoever sent the first one, and it arrives with the
 * authentication of whoever sent the next.
 *
 * Nothing about that requires either server to be wrong on its own terms.  It
 * requires only that they be lenient in different ways.  So the rule here is
 * the specification's and it is the strict one: **a message that frames itself
 * twice is refused, and the connection goes with it.**  Answering on a
 * connection whose message boundaries could not be established is the part
 * that turns the disagreement into an attack.
 *
 * \~spanish
 * Esta es la unica decision de HTTP/1.1 sobre la que un atacante puede
 * discutir, y conviene decir por que antes de decir como.
 *
 * Un mensaje dice cuanto mide su cuerpo de una de dos formas: una longitud en
 * una cabecera, o una sucesion de trozos que anuncian su propio tamano.  El
 * problema es que un mensaje puede decir las dos, y entonces tiene dos
 * finales -- y una cadena de servidores no tiene por que coincidir en cual --.
 * El de delante lee un cuerpo de cinco bytes y reenvia el resto como una
 * segunda peticion; el de detras lee los trozos y no la ve nunca.  La peticion
 * que aparece de la nada la escribio quien mando la primera, y llega con la
 * autenticacion de quien mando la siguiente.
 *
 * Nada de eso exige que ninguno de los dos servidores se equivoque en sus
 * propios terminos.  Exige solo que sean permisivos de formas distintas.  Asi
 * que la regla de aqui es la de la especificacion y es la estricta: **un
 * mensaje que se trocea dos veces se rechaza, y la conexion se va con el.**
 * Contestar por una conexion en la que no se pudieron establecer las fronteras
 * de los mensajes es la parte que convierte la discrepancia en un ataque.
 *
 * \~
 */
#ifndef HTTP_VX_H1_FRAMING_H
#define HTTP_VX_H1_FRAMING_H

#include "http_vx/message.h"

#include <cstdint>

namespace http_vx {
namespace h1 {

/**
 * @brief
 * \~english How the end of a body is found.
 * \~spanish Como se encuentra el final de un cuerpo.
 * \~
 */
enum class BodyKind : uint8_t {
    /// \~english There is no body.  \~spanish No hay cuerpo.  \~
    None,
    /// \~english So many bytes, and then the next message.
    /// \~spanish Tantos bytes, y despues el mensaje siguiente.  \~
    Exact,
    /// \~english Chunks, each announcing its own size, until one of size zero.
    /// \~spanish Trozos, cada uno con su tamano, hasta uno de tamano cero.  \~
    Chunked,
};

/**
 * @brief
 * \~english Why the framing could not be established.
 * \~spanish Por que no se pudieron establecer las fronteras.
 * \~
 *
 * \~english
 * Every one of these ends the connection, whatever is answered on it first.
 * That is not severity for its own sake: if where the body ends is not known,
 * where the next message begins is not known either, and reading one from that
 * point is reading whatever the sender put there.
 *
 * \~spanish
 * Todos estos terminan la conexion, se conteste lo que se conteste antes por
 * ella.  No es severidad por la severidad: si no se sabe donde acaba el cuerpo,
 * tampoco se sabe donde empieza el mensaje siguiente, y leer uno desde ahi es
 * leer lo que quien envia haya puesto.
 *
 * \~
 */
enum class FramingError : uint8_t {
    /// \~english Nothing is wrong.  \~spanish No pasa nada.  \~
    None = 0,

    /**
     * \~english
     * The message frames itself both ways at once.  This is the one the file
     * is about: 400, and close.
     * \~spanish
     * El mensaje se trocea de las dos formas a la vez.  Esta es de la que habla
     * el fichero: 400, y cerrar.
     * \~
     */
    LengthAndEncoding,

    /// \~english The content length is not a number.  400.
    /// \~spanish La longitud de contenido no es un numero.  400.  \~
    MalformedLength,
    /// \~english It is given twice with different values.  400.
    /// \~spanish Se da dos veces con valores distintos.  400.  \~
    ConflictingLength,
    /// \~english It does not fit in sixty-four bits.  413.
    /// \~spanish No cabe en sesenta y cuatro bits.  413.  \~
    LengthTooLarge,

    /**
     * \~english
     * A transfer encoding is given and `chunked` is not the last of them.  For
     * a request there is then no way of knowing where the body ends, and the
     * specification says to answer 400 rather than guess.
     * \~spanish
     * Se da una codificacion de transferencia y `chunked` no es la ultima.  En
     * una peticion no hay entonces forma de saber donde acaba el cuerpo, y la
     * especificacion dice que se conteste 400 en vez de adivinar.
     * \~
     */
    ChunkedNotLast,

    /// \~english `chunked` is applied more than once, which frames it twice.  400.
    /// \~spanish `chunked` se aplica mas de una vez, que lo trocea dos veces.  400.  \~
    ChunkedTwice,

    /// \~english A transfer coding this server does not implement.  501.
    /// \~spanish Una codificacion de transferencia que este servidor no implementa.  501.  \~
    UnsupportedCoding,

    /**
     * \~english
     * A transfer encoding from a client that announced HTTP/1.0.  Chunked did
     * not exist in HTTP/1.0, so a client claiming that version and using it is
     * claiming one thing and doing another -- and the pair is a known way of
     * getting an old intermediary and a new one to disagree.
     * \~spanish
     * Una codificacion de transferencia de un cliente que anuncio HTTP/1.0.  En
     * HTTP/1.0 no existia el troceado, asi que un cliente que diga esa version
     * y lo use esta diciendo una cosa y haciendo otra -- y el par es una forma
     * conocida de hacer que un intermediario viejo y uno nuevo discrepen.
     * \~
     */
    EncodingInHttp10,
};

/**
 * @brief
 * \~english Where the body ends, or why that could not be established.
 * \~spanish Donde acaba el cuerpo, o por que no se pudo establecer.
 * \~
 */
struct Framing {
    /// \~english How the end is found.  \~spanish Como se encuentra el final.  \~
    BodyKind kind;
    /// \~english How many bytes, only when @c Exact.
    /// \~spanish Cuantos bytes, solo cuando @c Exact.  \~
    uint64_t length;
    /// \~english Why not, when there is a why not.
    /// \~spanish Por que no, cuando hay un por que no.  \~
    FramingError error;
};

/**
 * @brief
 * \~english Works out where the body of @p req ends.
 * \~spanish Averigua donde acaba el cuerpo de @p req.
 * \~
 *
 * \~english
 * The order is the specification's, and the order is the rule:
 *
 *  1. **Both a transfer encoding and a content length** -- refused.  Not
 *     "the encoding wins", which is what the older specification said and what
 *     made a generation of proxies disagree with a generation of servers.
 *  2. **A transfer encoding** -- chunks, and `chunked` must be the last
 *     coding and appear exactly once.
 *  3. **A content length** -- that many bytes.
 *  4. **Neither** -- a request has no body.  This one is not a guess: it is
 *     what the specification says, and it is why a `POST` with neither is a
 *     `POST` with nothing in it rather than one that reads until the
 *     connection closes.  A response is the opposite, which is one of the
 *     reasons this function is about requests.
 *
 * \~spanish
 * El orden es el de la especificacion, y el orden es la regla:
 *
 *  1. **Codificacion de transferencia Y longitud de contenido** -- rechazado.
 *     No "gana la codificacion", que es lo que decia la especificacion anterior
 *     y lo que hizo que una generacion de intermediarios discrepara de una
 *     generacion de servidores.
 *  2. **Codificacion de transferencia** -- trozos, y `chunked` tiene que ser la
 *     ultima codificacion y aparecer exactamente una vez.
 *  3. **Longitud de contenido** -- esos bytes.
 *  4. **Ninguna de las dos** -- una peticion no tiene cuerpo.  Esto no es una
 *     conjetura: es lo que dice la especificacion, y es la razon de que un
 *     `POST` sin ninguna sea un `POST` sin nada dentro y no uno que lee hasta
 *     que se cierre la conexion.  Una respuesta es al reves, que es una de las
 *     razones de que esta funcion sea de peticiones.
 *
 * \~
 * @param req  \~english the request, already read  \~spanish la peticion, ya leida  \~
 * @param base \~english the message's first byte, which is @c Buffer::data()
 *             \~spanish el primer byte del mensaje, que es @c Buffer::data()  \~
 * @return     \~english where the body ends, or why not
 *             \~spanish donde acaba el cuerpo, o por que no  \~
 */
Framing frame_request_body(const Request &req, const uint8_t *base) noexcept;

/**
 * @brief
 * \~english The status code that @p e should be answered with.
 * \~spanish El codigo de estado con el que contestar a @p e.
 * \~
 *
 * \~english
 * It is here and not left to the caller because the mapping is part of the
 * rule: a coding nobody implements is 501 and not 400, because the message is
 * well formed and the server is the one that cannot do it.  Two callers
 * deciding that for themselves would answer differently for the same message.
 *
 * Whatever is answered, the connection does not survive any of these -- see
 * @c FramingError.
 *
 * \~spanish
 * Esta aqui y no se le deja a quien llama porque la correspondencia es parte de
 * la regla: una codificacion que nadie implementa es 501 y no 400, porque el
 * mensaje esta bien formado y el que no puede es el servidor.  Dos llamantes
 * decidiendolo por su cuenta contestarian distinto al mismo mensaje.
 *
 * Se conteste lo que se conteste, la conexion no sobrevive a ninguno de
 * estos -- ver @c FramingError.
 *
 * \~
 * @param e \~english the reason  \~spanish el motivo  \~
 * @return  \~english the status code, or 0 if there is nothing to answer
 *          \~spanish el codigo de estado, o 0 si no hay nada que contestar  \~
 */
[[gnu::cold]] StatusCode framing_status(FramingError e) noexcept;

/**
 * @brief
 * \~english Whether the connection goes on after the answer to @p req (RFC 9112, 9.3).
 * \~spanish Si la conexion sigue tras la respuesta a @p req (RFC 9112, 9.3).
 * \~
 *
 * \~english
 * The version and the Connection field decide it together: the "close"
 * option ends it whatever the version -- a server that receives it MUST
 * close after its final response (9.6) --; otherwise HTTP/1.1 persists, and
 * HTTP/1.0 only with the "keep-alive" option.  Options are compared without
 * regard to case (RFC 9110, 7.6.1), in every Connection field and every
 * element of each.
 *
 * \~spanish
 * Lo deciden juntos la version y la cabecera Connection: la opcion "close" la
 * acaba sea cual sea la version -- un servidor que la recibe DEBE cerrar tras
 * su respuesta final (9.6) --; si no, HTTP/1.1 persiste, y HTTP/1.0 solo con la
 * opcion "keep-alive".  Las opciones se comparan sin atender a mayusculas (RFC
 * 9110, 7.6.1), en cada cabecera Connection y en cada elemento de cada una.
 * \~
 * @param req  \~english the request  \~spanish la peticion  \~
 * @param base \~english the bytes its spans point into  \~spanish los bytes a los que apuntan sus trozos  \~
 * @return     \~english true if the connection persists  \~spanish true si la conexion persiste  \~
 */
bool connection_persists(const Request &req, const uint8_t *base) noexcept;

} // namespace h1
} // namespace http_vx

#endif // HTTP_VX_H1_FRAMING_H
