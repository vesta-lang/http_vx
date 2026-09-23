/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/content_length.h
 * @brief
 * \~english How long the body says it is, and every way that can go wrong.
 * \~spanish Lo que el cuerpo dice medir, y todas las formas de que salga mal.
 * \~
 *
 * \~english
 * This is a field with one number in it, and it has more ways to be wrong than
 * anything else a message carries.  The reason is worth stating plainly,
 * because it is what drives every decision in this file:
 *
 * **Where the body ends is where the next message begins.**  A recipient that
 * reads a different length from the one the sender meant does not lose a
 * request -- it reads the rest of the body as a new request.  When two
 * recipients in a chain disagree, one of them is serving a request the other
 * one never saw, written by whoever controlled the body.  That is request
 * smuggling, and it is not a bug in an implementation: it is what happens when
 * two implementations are each lenient in their own way.
 *
 * So there is no leniency here.  Everything the grammar does not allow is
 * refused, and refused with a reason that says which rule was broken -- a
 * parser that returned "no length" for a malformed one would be answering the
 * question that was not asked.
 *
 * \~spanish
 * Esta es una cabecera con un numero dentro, y tiene mas formas de estar mal
 * que ninguna otra cosa que lleve un mensaje.  La razon merece decirse con
 * claridad, porque es la que gobierna todas las decisiones de este fichero:
 *
 * **Donde acaba el cuerpo es donde empieza el mensaje siguiente.**  Quien lea
 * una longitud distinta de la que quiso decir quien envia no pierde una
 * peticion: lee el resto del cuerpo como una peticion nueva.  Cuando dos
 * receptores de una cadena discrepan, uno de ellos esta sirviendo una peticion
 * que el otro no vio nunca, escrita por quien controlara el cuerpo.  Eso es el
 * contrabando de peticiones, y no es un error de una implementacion: es lo que
 * pasa cuando dos implementaciones son permisivas cada una a su manera.
 *
 * Asi que aqui no hay permisividad.  Se rechaza todo lo que la gramatica no
 * permite, y se rechaza con un motivo que dice que regla se rompio -- un
 * analizador que devolviera "no hay longitud" para una mal formada estaria
 * contestando la pregunta que no se le hizo.
 *
 * \~
 */
#ifndef HTTP_VX_CONTENT_LENGTH_H
#define HTTP_VX_CONTENT_LENGTH_H

#include "http_vx/fields.h"

#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What reading the field found.
 * \~spanish Que se encontro al leer la cabecera.
 * \~
 *
 * \~english
 * The three ways of being wrong are told apart on purpose.  They are not
 * degrees of the same failure: they answer different things to the peer and
 * they mean different things about it.
 *
 * | | what it means | what a server does |
 * | :-- | :-- | :-- |
 * | @c Conflicting | the message frames itself two ways | 400, and close |
 * | @c Malformed | the value is not a number | 400, and close |
 * | @c TooLarge | it is a number nobody can hold | 413 |
 *
 * Closing is part of the first two and not an afterthought: if the framing
 * cannot be trusted, neither can where the next message starts, so the
 * connection cannot be reused -- answering on it and carrying on would be
 * doing exactly what the attack wants.
 *
 * \~spanish
 * Las tres formas de estar mal se distinguen a proposito.  No son grados del
 * mismo fallo: contestan cosas distintas al otro extremo y significan cosas
 * distintas sobre el.
 *
 * | | que quiere decir | que hace un servidor |
 * | :-- | :-- | :-- |
 * | @c Conflicting | el mensaje se trocea de dos maneras | 400, y cerrar |
 * | @c Malformed | el valor no es un numero | 400, y cerrar |
 * | @c TooLarge | es un numero que no cabe | 413 |
 *
 * Cerrar es parte de los dos primeros y no un anadido: si no se puede confiar
 * en el troceado, tampoco en donde empieza el mensaje siguiente, asi que la
 * conexion no se puede reutilizar -- contestar por ella y seguir seria hacer
 * justo lo que el ataque busca.
 *
 * \~
 */
enum class ContentLengthStatus : uint8_t {
    /// \~english There is no such field.  \~spanish No hay tal cabecera.  \~
    Absent,
    /// \~english One value, and everything that repeats it agrees.
    /// \~spanish Un valor, y todo lo que lo repite coincide.  \~
    Present,
    /// \~english It appears more than once with different values.
    /// \~spanish Aparece mas de una vez con valores distintos.  \~
    Conflicting,
    /// \~english The value is not a sequence of digits.
    /// \~spanish El valor no es una sucesion de digitos.  \~
    Malformed,
    /// \~english It is a number, and it does not fit in sixty-four bits.
    /// \~spanish Es un numero, y no cabe en sesenta y cuatro bits.  \~
    TooLarge,
};

/**
 * @brief
 * \~english What the field said.
 * \~spanish Lo que decia la cabecera.
 * \~
 */
struct ContentLength {
    /// \~english What reading it found.  \~spanish Que se encontro al leerla.  \~
    ContentLengthStatus status;
    /// \~english The length, only when @c Present.
    /// \~spanish La longitud, solo cuando @c Present.  \~
    uint64_t value;
};

/**
 * @brief
 * \~english Reads the content length out of @p fields.
 * \~spanish Lee la longitud de contenido de @p fields.
 * \~
 *
 * \~english
 * Three rules the grammar imposes, and each one has been a vulnerability
 * somewhere:
 *
 *  - **The field may repeat, and may hold a list.**  RFC 9110 section 8.6
 *    allows `5, 5` and two separate fields both saying `5`, and requires that
 *    all of them agree.  An implementation that took the first and stopped, or
 *    the last, would frame the message the way the attacker chose from a pair
 *    that a stricter recipient would have refused.
 *  - **The value is decimal digits and nothing else.**  Not `0x10`, not `+5`,
 *    not `5 ` -- the spacing is stripped before this sees it -- and not the
 *    empty string.  Every one of those has been accepted somewhere and read as
 *    a different number than the neighbour read.
 *  - **Leading zeros are legal.**  `007` is seven.  It looks like something to
 *    refuse and it is not, and refusing what the grammar allows is how a proxy
 *    starts dropping traffic that works everywhere else.
 *
 * What it does NOT decide is whether the body is framed by this at all.  A
 * message may frame itself by chunks instead, and one that does both is
 * invalid -- but that rule belongs with the syntax that has chunks, which is
 * HTTP/1.1, and applying it here would be applying it to HTTP/2 and HTTP/3,
 * where there is no such field to conflict with.
 *
 * \~spanish
 * Tres reglas que impone la gramatica, y cada una ha sido una vulnerabilidad en
 * alguna parte:
 *
 *  - **La cabecera puede repetirse, y puede llevar una lista.**  El RFC 9110
 *    seccion 8.6 permite `5, 5` y dos cabeceras separadas diciendo `5` las dos,
 *    y exige que todas coincidan.  Una implementacion que cogiera la primera y
 *    parara, o la ultima, trocearia el mensaje como eligiera el atacante de un
 *    par que un receptor mas estricto habria rechazado.
 *  - **El valor son digitos decimales y nada mas.**  Ni `0x10`, ni `+5`, ni
 *    `5 ` -- el espaciado se quita antes de que esto lo vea -- ni la cadena
 *    vacia.  Todos ellos se han aceptado en alguna parte y se han leido como un
 *    numero distinto del que leyo el vecino.
 *  - **Los ceros a la izquierda son legales.**  `007` es siete.  Parece algo
 *    que rechazar y no lo es, y rechazar lo que la gramatica permite es como un
 *    intermediario empieza a tirar trafico que funciona en todas partes.
 *
 * Lo que NO decide es si el cuerpo se trocea por aqui siquiera.  Un mensaje
 * puede trocearse por trozos en vez de por esto, y uno que haga las dos cosas
 * es invalido -- pero esa regla va con la sintaxis que tiene trozos, que es
 * HTTP/1.1, y aplicarla aqui seria aplicarsela a HTTP/2 y HTTP/3, donde no hay
 * tal cabecera con la que entrar en conflicto.
 *
 * \~
 * @param fields \~english the message's fields  \~spanish las cabeceras del mensaje  \~
 * @param base   \~english the buffer the offsets are relative to, which is
 *               @c Buffer::data()
 *               \~spanish el buffer al que son relativos los desplazamientos,
 *               que es @c Buffer::data()  \~
 * @return       \~english what was found  \~spanish lo que se encontro  \~
 */
ContentLength parse_content_length(const Fields &fields,
                                   const uint8_t *base) noexcept;

} // namespace http_vx

#endif // HTTP_VX_CONTENT_LENGTH_H
