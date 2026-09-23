/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_huffman.h
 * @brief
 * \~english The code HPACK writes strings in, when writing them shorter helps.
 * \~spanish El codigo con el que HPACK escribe cadenas, cuando acortarlas ayuda.
 * \~
 *
 * \~english
 * A field name or value that both ends have not agreed on has to be spelled
 * out, and HPACK spells it in a Huffman code -- a fixed one, measured once
 * over real HTTP traffic and written into the specification, so neither end
 * sends a table and neither end computes one.
 *
 * What that buys is `e` in five bits instead of eight.  What it costs is the
 * subject of this file: the bits of a code do not line up with the bytes that
 * carry them, so where one symbol ends is a question about the bit before it,
 * and the last few bits of a string are not a symbol at all.
 *
 * **Two rules are worth stating before the code, because both are refusals
 * that look like pedantry and are not:**
 *
 *  - the bits left over at the end must be the beginning of the end-of-string
 *    symbol, and fewer than eight of them.  Anything else is a sender writing
 *    something into a place where nothing is read, which is a place to hide
 *    bytes that two implementations will disagree about;
 *  - and the end-of-string symbol itself may not appear.  A string knows how
 *    long it is before it starts -- HPACK writes the length first -- so a
 *    symbol whose only job is to say "it ends here" has no job, and accepting
 *    one would be accepting a second answer to a question already answered.
 *
 * \~spanish
 * Un nombre o un valor de cabecera en el que los dos extremos no se han puesto
 * de acuerdo hay que escribirlo, y HPACK lo escribe en un codigo Huffman -- uno
 * fijo, medido una vez sobre trafico HTTP real y escrito en la especificacion,
 * asi que ninguno de los dos manda una tabla ni la calcula.
 *
 * Lo que eso compra es la `e` en cinco bits en vez de ocho.  Lo que cuesta es
 * el tema de este fichero: los bits de un codigo no cuadran con los bytes que
 * los llevan, asi que donde acaba un simbolo es una pregunta sobre el bit
 * anterior, y los ultimos bits de una cadena no son ningun simbolo.
 *
 * **Dos reglas merecen decirse antes del codigo, porque las dos son rechazos
 * que parecen rigor y no lo son:**
 *
 *  - los bits que sobran al final tienen que ser el principio del simbolo de
 *    fin de cadena, y menos de ocho.  Otra cosa es quien envia escribiendo algo
 *    en un sitio donde no se lee nada, que es un sitio donde esconder bytes
 *    sobre los que dos implementaciones van a discrepar;
 *  - y el simbolo de fin de cadena no puede aparecer.  Una cadena sabe cuanto
 *    mide antes de empezar -- HPACK escribe la longitud delante -- asi que un
 *    simbolo cuyo unico trabajo es decir "acaba aqui" no tiene trabajo, y
 *    aceptar uno seria aceptar una segunda respuesta a una pregunta ya
 *    contestada.
 *
 * \~
 */
#ifndef HTTP_VX_H2_HUFFMAN_H
#define HTTP_VX_H2_HUFFMAN_H

#include "http_vx/h2_hpack.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {
namespace hpack {

/**
 * @brief
 * \~english What decoding a Huffman string came to.
 * \~spanish A que llego descodificar una cadena Huffman.
 * \~
 */
struct HuffmanResult {
    Status status;
    /// \~english How many bytes came out.  \~spanish Cuantos bytes salieron.  \~
    size_t len;
};

/**
 * @brief
 * \~english The most a Huffman string can grow when it is read.
 * \~spanish Lo mas que puede crecer una cadena Huffman al leerla.
 * \~
 *
 * \~english
 * Eight over five, because the shortest code is five bits and a byte is eight:
 * no arrangement of input produces more than one output byte per five input
 * bits.  It is worth having as a number because it is the bound on the one
 * way this layer could be made to allocate more than it was sent, and a bound
 * that is known is a bound that can be checked BEFORE the memory is asked for.
 *
 * It is a small number, and that is the point.  The way HPACK is made to
 * produce far more than it was sent is the table that remembers, not this --
 * and knowing which of the two it is keeps the check where it belongs.
 *
 * \~spanish
 * Ocho entre cinco, porque el codigo mas corto son cinco bits y un byte son
 * ocho: ninguna disposicion de la entrada produce mas de un byte de salida por
 * cada cinco bits de entrada.  Merece tenerlo como numero porque es la cota de
 * la unica forma en que se podria hacer que esta capa reservara mas de lo que
 * le mandaron, y una cota que se conoce es una cota que se puede comprobar
 * ANTES de pedir la memoria.
 *
 * Es un numero pequeno, y de eso se trata.  La forma de hacer que HPACK
 * produzca muchisimo mas de lo que le mandaron es la tabla que recuerda, no
 * esto -- y saber cual de las dos es mantiene la comprobacion donde le toca.
 *
 * \~
 * @param n \~english how many bytes went in  \~spanish cuantos bytes entraron  \~
 * @return  \~english the most that can come out
 *          \~spanish lo mas que puede salir  \~
 */
constexpr size_t huffman_max_decoded(size_t n) noexcept {
    return n + n * 3 / 5 + 1;
}

/**
 * @brief
 * \~english Reads @p n Huffman bytes from @p in into @p out.
 * \~spanish Lee @p n bytes Huffman de @p in a @p out.
 * \~
 *
 * @param out \~english where the bytes go  \~spanish donde van los bytes  \~
 * @param cap \~english how much room there is; see @c huffman_max_decoded
 *            \~spanish cuanto sitio hay; ver @c huffman_max_decoded  \~
 * @param in  \~english the coded bytes  \~spanish los bytes codificados  \~
 * @param n   \~english how many  \~spanish cuantos  \~
 * @return    \~english what came out, or why not
 *            \~spanish lo que salio, o por que no  \~
 */
HuffmanResult huffman_decode(uint8_t *out, size_t cap, const uint8_t *in,
                             size_t n) noexcept;

/**
 * @brief
 * \~english How many bytes @p in would take written in the code.
 * \~spanish Cuantos bytes ocuparia @p in escrito en el codigo.
 * \~
 *
 * \~english
 * Asked before writing, because HPACK lets a sender choose and the right
 * choice is whichever is shorter.  Huffman is not always: a string of bytes
 * the code was not measured on -- a token, a hash, anything binary -- comes
 * out LONGER, and sending it coded would be paying for the decoding as well.
 *
 * \~spanish
 * Se pregunta antes de escribir, porque HPACK deja elegir a quien envia y lo
 * correcto es lo que sea mas corto.  Huffman no siempre lo es: una cadena de
 * bytes sobre los que no se midio el codigo -- un testigo, un resumen,
 * cualquier cosa binaria -- sale MAS LARGA, y mandarla codificada seria pagar
 * ademas la descodificacion.
 *
 * \~
 * @param in \~english the bytes  \~spanish los bytes  \~
 * @param n  \~english how many  \~spanish cuantos  \~
 * @return   \~english how many it would take  \~spanish cuantos ocuparia  \~
 */
size_t huffman_encoded_length(const uint8_t *in, size_t n) noexcept;

/**
 * @brief
 * \~english Writes @p n bytes of @p in into @p out in the code.
 * \~spanish Escribe en el codigo los @p n bytes de @p in en @p out.
 * \~
 *
 * \~english
 * The bits left over in the last byte are filled with ones, which is the
 * beginning of the end-of-string symbol.  That is not decoration: it is what
 * makes the padding recognisable as padding, and it is what a reader checks
 * to know that nothing was hidden there.
 *
 * \~spanish
 * Los bits que sobren en el ultimo byte se llenan de unos, que es el principio
 * del simbolo de fin de cadena.  No es adorno: es lo que hace reconocible el
 * relleno como relleno, y es lo que comprueba quien lee para saber que ahi no
 * se escondio nada.
 *
 * \~
 * @param out \~english where to write; see @c huffman_encoded_length
 *            \~spanish donde escribir; ver @c huffman_encoded_length  \~
 * @param cap \~english how much room there is  \~spanish cuanto sitio hay  \~
 * @param in  \~english the bytes  \~spanish los bytes  \~
 * @param n   \~english how many  \~spanish cuantos  \~
 * @return    \~english how many were written, or zero if there was no room
 *            \~spanish cuantos se escribieron, o cero si no habia sitio  \~
 */
size_t huffman_encode(uint8_t *out, size_t cap, const uint8_t *in,
                      size_t n) noexcept;

} // namespace hpack
} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_HUFFMAN_H
