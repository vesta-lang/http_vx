/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/bitmap.h
 * @brief
 * \~english Bit runs over a chunk's bitmap: what arrived, what was acknowledged, what to resend.
 * \~spanish Rachas de bits sobre el mapa de un trozo: que llego, que se confirmo, que reenviar.
 * \~
 *
 * \~english
 * Private to `quic/`: the receiving and the sending side of a stream both keep
 * one bit per byte of a chunk, and both need the same three questions
 * answered a 64-bit word at a time rather than a byte at a time.
 * \~spanish
 * Privado de `quic/`: la parte receptora y la emisora de un flujo guardan las dos
 * un bit por byte de trozo, y las dos necesitan que se contesten las mismas tres
 * preguntas de palabra en palabra de 64 bits y no de byte en byte.
 * \~
 */
#ifndef HTTP_VX_QUIC_BITMAP_H
#define HTTP_VX_QUIC_BITMAP_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {
namespace bits {

/// \~english The mask of @p take bits from bit @p b of a word.
/// \~spanish La mascara de @p take bits desde el bit @p b de una palabra.  \~
inline uint64_t span_mask(size_t b, size_t take) noexcept {
    return (take == 64 ? ~uint64_t{0} : ((uint64_t{1} << take) - 1)) << b;
}

/// \~english Sets @p n bits from @p from; returns how many were clear before.
/// \~spanish Pone @p n bits desde @p from; devuelve cuantos estaban a cero.  \~
inline size_t set(uint64_t *bits, size_t from, size_t n) noexcept {
    size_t fresh = 0;
    while (n != 0) {
        const size_t w = from / 64;
        const size_t b = from % 64;
        const size_t take = n < 64 - b ? n : 64 - b;
        const uint64_t mask = span_mask(b, take);
        fresh += static_cast<size_t>(__builtin_popcountll(mask & ~bits[w]));
        bits[w] |= mask;
        from += take;
        n -= take;
    }
    return fresh;
}

/// \~english Clears @p n bits from @p from; returns how many were set before.
/// \~spanish Borra @p n bits desde @p from; devuelve cuantos estaban puestos.  \~
inline size_t clear(uint64_t *bits, size_t from, size_t n) noexcept {
    size_t gone = 0;
    while (n != 0) {
        const size_t w = from / 64;
        const size_t b = from % 64;
        const size_t take = n < 64 - b ? n : 64 - b;
        const uint64_t mask = span_mask(b, take);
        gone += static_cast<size_t>(__builtin_popcountll(mask & bits[w]));
        bits[w] &= ~mask;
        from += take;
        n -= take;
    }
    return gone;
}

/// \~english Sets, in @p out, the bits of [from, from+n) that are clear in @p exclude; returns how many were newly set.
/// \~spanish Pone en @p out los bits de [from, from+n) que estan a cero en @p exclude; devuelve cuantos se pusieron de nuevo.  \~
inline size_t set_unless(uint64_t *out, const uint64_t *exclude, size_t from, size_t n) noexcept {
    size_t fresh = 0;
    while (n != 0) {
        const size_t w = from / 64;
        const size_t b = from % 64;
        const size_t take = n < 64 - b ? n : 64 - b;
        const uint64_t mask = span_mask(b, take) & ~exclude[w];
        fresh += static_cast<size_t>(__builtin_popcountll(mask & ~out[w]));
        out[w] |= mask;
        from += take;
        n -= take;
    }
    return fresh;
}

/**
 * @brief
 * \~english How many consecutive bits equal to @p value start at @p from, before @p end.
 * \~spanish Cuantos bits seguidos iguales a @p value empiezan en @p from, antes de @p end.
 * \~
 */
inline size_t run(const uint64_t *bits, size_t from, size_t end, bool value) noexcept {
    size_t n = 0;
    while (from < end) {
        const size_t w = from / 64;
        const size_t b = from % 64;
        const uint64_t word = (value ? bits[w] : ~bits[w]) >> b;
        const uint64_t stop = ~word;
        const size_t avail = 64 - b;
        size_t same = stop == 0 ? avail : static_cast<size_t>(__builtin_ctzll(stop));
        if (same > avail) same = avail;
        if (same > end - from) same = end - from;
        n += same;
        if (same < avail) break;
        from += same;
    }
    return n;
}

/// \~english The first set bit at or after @p from, before @p end; @p end if none.
/// \~spanish El primer bit puesto en o tras @p from, antes de @p end; @p end si ninguno.  \~
inline size_t first_set(const uint64_t *bits, size_t from, size_t end) noexcept {
    while (from < end) {
        const size_t w = from / 64;
        const size_t b = from % 64;
        const uint64_t word = bits[w] >> b;
        if (word != 0) {
            const size_t at = from + static_cast<size_t>(__builtin_ctzll(word));
            return at < end ? at : end;
        }
        from += 64 - b;
    }
    return end;
}

} // namespace bits
} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_BITMAP_H
