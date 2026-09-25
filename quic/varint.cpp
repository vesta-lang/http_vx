/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/varint.cpp
 * @brief
 * \~english Reading and writing QUIC's variable-length integers.
 * \~spanish Leer y escribir los enteros de longitud variable de QUIC.
 * \~
 */

#include "http_vx/quic_varint.h"

namespace http_vx {
namespace quic {

size_t decode_varint(const uint8_t *p, size_t n, uint64_t &out) noexcept {
    if (n == 0) return 0;

    const size_t len = varint_length(p[0]);

    /* \~english
     * The whole integer has to be here before any of it is read.  A reader
     * that decoded what it had and hoped would be reading the first bytes of a
     * length and treating them as all of it -- a small length that makes the
     * next packet start in the middle of this one.
     * \~spanish
     * El entero entero tiene que estar aqui antes de leer nada de el.  Un lector
     * que descodificara lo que tiene y esperara estaria leyendo los primeros
     * bytes de una longitud y tomandolos por toda ella -- una longitud pequena
     * que hace que el paquete siguiente empiece en mitad de este.
     * \~ */
    if (len > n) return 0;

    /* \~english
     * The two length bits are masked off the first byte and not off the
     * result: they are the top of the first byte, which after shifting is the
     * top of the value -- and a value that kept them would be four times too
     * large for a two-byte integer, sixteen for a four, and so on.
     * \~spanish
     * Los dos bits de longitud se quitan del primer byte y no del resultado: son
     * lo alto del primer byte, que tras desplazar es lo alto del valor -- y un
     * valor que los conservara seria cuatro veces demasiado grande en un entero
     * de dos bytes, dieciseis en uno de cuatro, y asi.
     * \~ */
    uint64_t v = p[0] & 0x3F;
    for (size_t i = 1; i < len; ++i) v = (v << 8) | p[i];

    out = v;
    return len;
}

bool encode_varint_width(uint8_t *p, size_t width, uint64_t v) noexcept {
    uint8_t prefix = 0;

    switch (width) {
    case 1:
        if (v >= (uint64_t{1} << 6)) return false;
        prefix = 0x00;
        break;
    case 2:
        if (v >= (uint64_t{1} << 14)) return false;
        prefix = 0x40;
        break;
    case 4:
        if (v >= (uint64_t{1} << 30)) return false;
        prefix = 0x80;
        break;
    case 8:
        if (v > kVarintMax) return false;
        prefix = 0xC0;
        break;
    default:
        return false;
    }

    for (size_t i = width; i-- > 0;) {
        p[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }

    p[0] = static_cast<uint8_t>(p[0] | prefix);
    return true;
}

size_t encode_varint(uint8_t *p, size_t room, uint64_t v) noexcept {
    const size_t len = varint_size(v);
    if (len == 0 || len > room) return 0;

    encode_varint_width(p, len, v);
    return len;
}

} // namespace quic
} // namespace http_vx
