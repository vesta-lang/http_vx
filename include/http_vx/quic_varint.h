/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_varint.h
 * @brief
 * \~english The integer every other QUIC field is written in.
 * \~spanish El entero en el que se escribe todo otro campo de QUIC.
 * \~
 *
 * \~english
 * RFC 9000, section 16.  The two high bits of the first byte say how long the
 * integer is -- one, two, four or eight bytes -- and the rest is the value,
 * big-endian, which leaves sixty-two bits: the largest value is 2^62 - 1.
 *
 * It is the first thing written for QUIC because everything else stands on
 * it: packet lengths, token lengths, stream identifiers, offsets, frame types,
 * error codes, transport parameters.  A mistake here is not a bug in one field,
 * it is a bug in every field at once.
 *
 * **Two rules that look like details and are not:**
 *
 *  - A value may be written LONGER than it needs to be.  `0x25` and
 *    `0x40 0x25` are both thirty-seven, and a decoder that refused the second
 *    would refuse legal traffic.  So decoding does not check it.
 *  - Except where the specification says otherwise, and the case that matters
 *    is the FRAME TYPE, which must be as short as possible (section 12.4).  So
 *    the decoder reports how many bytes it read, and whoever reads a frame type
 *    compares that with @c varint_size of the value -- the rule lives where it
 *    applies rather than in a decoder every field shares.
 *
 * \~spanish
 * RFC 9000, seccion 16.  Los dos bits altos del primer byte dicen cuanto mide
 * el entero -- uno, dos, cuatro u ocho bytes -- y el resto es el valor, en orden
 * de red, lo que deja sesenta y dos bits: el valor mayor es 2^62 - 1.
 *
 * Es lo primero que se escribe de QUIC porque todo lo demas se apoya en ello:
 * longitudes de paquete, longitudes de testigo, identificadores de flujo,
 * desplazamientos, tipos de trama, codigos de error, parametros de transporte.
 * Un error aqui no es un fallo en un campo, es un fallo en todos a la vez.
 *
 * **Dos reglas que parecen detalles y no lo son:**
 *
 *  - Un valor se puede escribir MAS LARGO de lo necesario.  `0x25` y
 *    `0x40 0x25` son los dos treinta y siete, y un descodificador que rechazara
 *    el segundo rechazaria trafico legal.  Asi que al descodificar no se mira.
 *  - Salvo donde la especificacion diga otra cosa, y el caso que importa es el
 *    TIPO DE TRAMA, que tiene que ser lo mas corto posible (seccion 12.4).  Por
 *    eso el descodificador dice cuantos bytes leyo, y quien lea un tipo de trama
 *    lo compara con @c varint_size del valor -- la regla vive donde se aplica y
 *    no en un descodificador que comparten todos los campos.
 *
 * \~
 */
#ifndef HTTP_VX_QUIC_VARINT_H
#define HTTP_VX_QUIC_VARINT_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english The largest value a variable-length integer can carry.
 * \~spanish El valor mayor que puede llevar un entero de longitud variable.
 * \~
 */
constexpr uint64_t kVarintMax = (uint64_t{1} << 62) - 1;

/**
 * @brief
 * \~english How many bytes @p v takes when written as short as possible.
 * \~spanish Cuantos bytes ocupa @p v escrito lo mas corto posible.
 * \~
 *
 * @param v \~english the value  \~spanish el valor  \~
 * @return  \~english 1, 2, 4 or 8, or 0 if the value does not fit
 *          \~spanish 1, 2, 4 u 8, o 0 si el valor no cabe  \~
 */
inline size_t varint_size(uint64_t v) noexcept {
    if (v < (uint64_t{1} << 6)) return 1;
    if (v < (uint64_t{1} << 14)) return 2;
    if (v < (uint64_t{1} << 30)) return 4;
    if (v <= kVarintMax) return 8;
    return 0;
}

/**
 * @brief
 * \~english How many bytes the integer starting with @p first takes.
 * \~spanish Cuantos bytes ocupa el entero que empieza por @p first.
 * \~
 *
 * \~english
 * Known from the first byte alone, which is what lets a reader ask for exactly
 * enough before decoding -- and what makes a truncated integer a question of
 * "is the rest here" rather than something discovered half-way through.
 * \~spanish
 * Se sabe solo con el primer byte, que es lo que permite a un lector pedir lo
 * justo antes de descodificar -- y lo que convierte un entero truncado en una
 * pregunta de "esta el resto" y no en algo que se descubre a medias.
 * \~
 *
 * @param first \~english the first byte  \~spanish el primer byte  \~
 * @return      \~english 1, 2, 4 or 8  \~spanish 1, 2, 4 u 8  \~
 */
inline size_t varint_length(uint8_t first) noexcept {
    return size_t{1} << (first >> 6);
}

/**
 * @brief
 * \~english Reads one integer from @p n bytes at @p p.
 * \~spanish Lee un entero de los @p n bytes de @p p.
 * \~
 *
 * @param p   \~english where it starts  \~spanish donde empieza  \~
 * @param n   \~english how many bytes there are  \~spanish cuantos bytes hay  \~
 * @param out \~english the value  \~spanish el valor  \~
 * @return    \~english how many bytes it took, or 0 if it is not all here
 *            \~spanish cuantos bytes ocupo, o 0 si no esta entero  \~
 */
size_t decode_varint(const uint8_t *p, size_t n, uint64_t &out) noexcept;

/**
 * @brief
 * \~english Writes @p v as short as possible into @p room bytes at @p p.
 * \~spanish Escribe @p v lo mas corto posible en los @p room bytes de @p p.
 * \~
 *
 * \~english
 * A value past @c kVarintMax is refused rather than truncated.  Writing its low
 * sixty-two bits would put a DIFFERENT number on the wire, and a length that
 * silently shrank is the start of the peer reading two packets as one.
 * \~spanish
 * Un valor mayor que @c kVarintMax se rechaza en vez de recortarse.  Escribir
 * sus sesenta y dos bits bajos pondria OTRO numero en el cable, y una longitud
 * que encoge en silencio es el principio de que el otro extremo lea dos
 * paquetes como uno.
 * \~
 *
 * @param p    \~english where to write  \~spanish donde escribir  \~
 * @param room \~english how many bytes there are  \~spanish cuantos bytes hay  \~
 * @param v    \~english the value  \~spanish el valor  \~
 * @return     \~english how many bytes were written, or 0
 *             \~spanish cuantos bytes se escribieron, o 0  \~
 */
size_t encode_varint(uint8_t *p, size_t room, uint64_t v) noexcept;

/**
 * @brief
 * \~english Writes @p v in exactly @p width bytes.
 * \~spanish Escribe @p v en exactamente @p width bytes.
 * \~
 *
 * \~english
 * For the one case where the width is decided BEFORE the value is known: a
 * length that goes in front of what it measures.  The room is kept, the
 * content is written, and the length is filled in afterwards -- which only
 * works if the length does not change size when its value arrives.
 * \~spanish
 * Para el unico caso en que el ancho se decide ANTES de saber el valor: una
 * longitud que va delante de lo que mide.  Se guarda el sitio, se escribe el
 * contenido y la longitud se rellena despues -- que solo funciona si la
 * longitud no cambia de tamano cuando llega su valor.
 * \~
 *
 * @param p     \~english where to write  \~spanish donde escribir  \~
 * @param width \~english 1, 2, 4 or 8  \~spanish 1, 2, 4 u 8  \~
 * @param v     \~english the value  \~spanish el valor  \~
 * @return      \~english false if @p v does not fit in @p width
 *              \~spanish false si @p v no cabe en @p width  \~
 */
bool encode_varint_width(uint8_t *p, size_t width, uint64_t v) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_VARINT_H
