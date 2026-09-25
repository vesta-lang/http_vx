/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/common/chacha20_poly1305.cpp
 * @brief
 * \~english ChaCha20, Poly1305 and their AEAD, written from RFC 8439.
 * \~spanish ChaCha20, Poly1305 y su AEAD, escritos a partir del RFC 8439.
 * \~
 */

#include "chacha20_poly1305.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace chacha {

namespace {

/// \~english A little-endian 32-bit word from @p p.  \~spanish Una palabra de 32 bits en orden inverso de @p p.  \~
inline uint32_t load32(const uint8_t *p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

/// \~english Stores @p v little-endian at @p p.  \~spanish Guarda @p v en orden inverso en @p p.  \~
inline void store32(uint8_t *p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

/// \~english Stores @p v little-endian as eight bytes.  \~spanish Guarda @p v en orden inverso en ocho bytes.  \~
inline void store64(uint8_t *p, uint64_t v) noexcept {
    store32(p, static_cast<uint32_t>(v));
    store32(p + 4, static_cast<uint32_t>(v >> 32));
}

inline uint32_t rotl(uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

/// \~english The quarter round (RFC 8439, 2.1).  \~spanish El cuarto de ronda (RFC 8439, 2.1).  \~
inline void quarter(uint32_t *x, int a, int b, int c, int d) noexcept {
    x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 7);
}

/**
 * @brief
 * \~english Overwrites secret bytes so that the optimizer cannot drop it.
 * \~spanish Sobrescribe bytes secretos de forma que el optimizador no lo pueda quitar.
 * \~
 *
 * \~english
 * Same reason as in `quic/protection.cpp`: zeroing memory that is about to
 * die is a dead store, and a keystream or a one-time key left on the stack is
 * a key left on the stack.
 * \~spanish
 * Por lo mismo que en `quic/protection.cpp`: poner a cero memoria que va a
 * morir es un almacen muerto, y un flujo de clave o una clave de un solo uso que
 * se queda en la pila es una clave que se queda en la pila.
 * \~
 */
void wipe(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

constexpr uint32_t kMask26 = 0x3ffffff;

/**
 * @brief
 * \~english Absorbs one 16-byte block into the accumulator: h = (h + m) * r mod 2^130 - 5.
 * \~spanish Absorbe un bloque de 16 bytes en el acumulador: h = (h + m) * r mod 2^130 - 5.
 * \~
 *
 * @param hibit \~english 2^128 in limb form for a whole block, zero for the padded last one
 *              \~spanish 2^128 en forma de miembro para un bloque entero, cero para el ultimo rellenado  \~
 */
void absorb(Poly1305 &p, const uint8_t *m, uint32_t hibit) noexcept {
    const uint32_t t0 = load32(m);
    const uint32_t t1 = load32(m + 4);
    const uint32_t t2 = load32(m + 8);
    const uint32_t t3 = load32(m + 12);

    // \~english The 128-bit block cut into 26-bit limbs, plus the bit above it.
    // \~spanish El bloque de 128 bits cortado en miembros de 26 bits, mas el bit de encima.  \~
    uint64_t h0 = p.h[0] + (t0 & kMask26);
    uint64_t h1 = p.h[1] + (((t0 >> 26) | (t1 << 6)) & kMask26);
    uint64_t h2 = p.h[2] + (((t1 >> 20) | (t2 << 12)) & kMask26);
    uint64_t h3 = p.h[3] + (((t2 >> 14) | (t3 << 18)) & kMask26);
    uint64_t h4 = p.h[4] + ((t3 >> 8) | hibit);

    const uint64_t r0 = p.r[0], r1 = p.r[1], r2 = p.r[2], r3 = p.r[3], r4 = p.r[4];

    /* \~english
     * A limb that overflows past 2^130 comes back multiplied by five, because
     * 2^130 = 5 modulo 2^130 - 5.  Folding that into r (s_i = 5 r_i) is what
     * keeps the product at five terms per limb instead of nine.
     * \~spanish
     * Un miembro que se pasa de 2^130 vuelve multiplicado por cinco, porque
     * 2^130 = 5 modulo 2^130 - 5.  Meter eso en r (s_i = 5 r_i) es lo que deja el
     * producto en cinco terminos por miembro en vez de nueve.
     * \~ */
    const uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint64_t d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    uint64_t d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    // \~english Back to 26-bit limbs; what leaves the top re-enters times five.
    // \~spanish De vuelta a miembros de 26 bits; lo que sale por arriba vuelve por cinco.  \~
    d1 += d0 >> 26; h0 = d0 & kMask26;
    d2 += d1 >> 26; h1 = d1 & kMask26;
    d3 += d2 >> 26; h2 = d2 & kMask26;
    d4 += d3 >> 26; h3 = d3 & kMask26;
    h0 += (d4 >> 26) * 5; h4 = d4 & kMask26;
    h1 += h0 >> 26; h0 &= kMask26;

    p.h[0] = static_cast<uint32_t>(h0);
    p.h[1] = static_cast<uint32_t>(h1);
    p.h[2] = static_cast<uint32_t>(h2);
    p.h[3] = static_cast<uint32_t>(h3);
    p.h[4] = static_cast<uint32_t>(h4);
}

/// \~english Feeds zeros up to the next multiple of 16 (the AEAD's padding).
/// \~spanish Anade ceros hasta el siguiente multiplo de 16 (el relleno del AEAD).  \~
void pad16(Poly1305 &p, size_t n) noexcept {
    static const uint8_t kZeros[16] = {};
    if ((n & 15) != 0) poly1305_update(p, kZeros, 16 - (n & 15));
}

/// \~english The AEAD's tag over @p ad and the ciphertext @p ct.
/// \~spanish La marca del AEAD sobre @p ad y el texto cifrado @p ct.  \~
void aead_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
              size_t ad_len, const uint8_t *ct, size_t n,
              uint8_t *tag) noexcept {
    // \~english The one-time key is the first half of block zero (RFC 8439, 2.6).
    // \~spanish La clave de un solo uso es la primera mitad del bloque cero (RFC 8439, 2.6).  \~
    uint8_t otk[kBlockSize];
    block(key, 0, nonce, otk);

    Poly1305 p;
    poly1305_init(p, otk);
    wipe(otk, sizeof otk);

    poly1305_update(p, ad, ad_len);
    pad16(p, ad_len);
    poly1305_update(p, ct, n);
    pad16(p, n);

    uint8_t lens[16];
    store64(lens, ad_len);
    store64(lens + 8, n);
    poly1305_update(p, lens, sizeof lens);
    poly1305_finish(p, tag);
}

} // namespace

void block(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
           uint8_t *out) noexcept {
    uint32_t s[16];
    s[0] = 0x61707865;  // "expa"
    s[1] = 0x3320646e;  // "nd 3"
    s[2] = 0x79622d32;  // "2-by"
    s[3] = 0x6b206574;  // "te k"
    for (int i = 0; i < 8; ++i) s[4 + i] = load32(key + 4 * i);
    s[12] = counter;
    s[13] = load32(nonce);
    s[14] = load32(nonce + 4);
    s[15] = load32(nonce + 8);

    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = s[i];

    // \~english Ten double rounds: a column round, then a diagonal one.
    // \~spanish Diez rondas dobles: una de columnas y una diagonal.  \~
    for (int i = 0; i < 10; ++i) {
        quarter(x, 0, 4, 8, 12);
        quarter(x, 1, 5, 9, 13);
        quarter(x, 2, 6, 10, 14);
        quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15);
        quarter(x, 1, 6, 11, 12);
        quarter(x, 2, 7, 8, 13);
        quarter(x, 3, 4, 9, 14);
    }

    // \~english The input is added back: without it the rounds could be run backwards.
    // \~spanish Se vuelve a sumar la entrada: sin eso las rondas se podrian deshacer.  \~
    for (int i = 0; i < 16; ++i) store32(out + 4 * i, x[i] + s[i]);

    wipe(x, sizeof x);
    wipe(s, sizeof s);
}

void xor_stream(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                const uint8_t *in, uint8_t *out, size_t n) noexcept {
    uint8_t ks[kBlockSize];
    while (n != 0) {
        block(key, counter++, nonce, ks);
        const size_t take = n < kBlockSize ? n : kBlockSize;
        for (size_t i = 0; i < take; ++i) out[i] = static_cast<uint8_t>(in[i] ^ ks[i]);
        in += take;
        out += take;
        n -= take;
    }
    wipe(ks, sizeof ks);
}

void poly1305_init(Poly1305 &p, const uint8_t *key) noexcept {
    const uint32_t t0 = load32(key);
    const uint32_t t1 = load32(key + 4);
    const uint32_t t2 = load32(key + 8);
    const uint32_t t3 = load32(key + 12);

    /* \~english
     * r is clamped (RFC 8439, 2.5: the top four bits of bytes 3, 7, 11, 15 and
     * the bottom two of bytes 4, 8, 12 cleared) while it is cut into limbs;
     * each mask below is the 26-bit window of the clamp.
     * \~spanish
     * r se recorta (RFC 8439, 2.5: a cero los cuatro bits altos de los bytes 3,
     * 7, 11 y 15 y los dos bajos de los bytes 4, 8 y 12) mientras se corta en
     * miembros; cada mascara de abajo es la ventana de 26 bits del recorte.
     * \~ */
    p.r[0] = t0 & 0x3ffffff;
    p.r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    p.r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    p.r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    p.r[4] = (t3 >> 8) & 0x00fffff;

    for (int i = 0; i < 5; ++i) p.h[i] = 0;
    for (int i = 0; i < 4; ++i) p.pad[i] = load32(key + 16 + 4 * i);
    p.used = 0;
}

void poly1305_update(Poly1305 &p, const uint8_t *m, size_t n) noexcept {
    // \~english First, complete a block left half-full by the previous call.
    // \~spanish Primero, completar un bloque que la llamada anterior dejo a medias.  \~
    /* \~english
     * The copies into the pending block go out of line: they are under sixteen
     * bytes and only happen on a split block, and inlined GCC cannot see that
     * `used + take` stays within sixteen and warns about a write past the end
     * that cannot happen.
     * \~spanish
     * Las copias al bloque pendiente van fuera de linea: son de menos de
     * dieciseis bytes y solo pasan en un bloque partido, y en linea GCC no ve
     * que `used + take` se queda dentro de dieciseis y avisa de una escritura
     * pasado el final que no puede ocurrir.
     * \~ */
    if (p.used != 0) {
        const size_t take = n < 16 - p.used ? n : 16 - p.used;
        util::vesta_memcpy_noinline(p.pending + p.used, m, take);
        p.used += take;
        m += take;
        n -= take;
        if (p.used < 16) return;
        absorb(p, p.pending, 1u << 24);
        p.used = 0;
    }
    while (n >= 16) {
        absorb(p, m, 1u << 24);
        m += 16;
        n -= 16;
    }
    if (n != 0) {
        util::vesta_memcpy_noinline(p.pending, m, n);
        p.used = n;
    }
}

void poly1305_finish(Poly1305 &p, uint8_t *tag) noexcept {
    /* \~english
     * The last, short block: a 0x01 byte after the message and zeros after
     * that, which puts the "one bit above" inside the block instead of at
     * 2^128 -- hence no hibit.
     * \~spanish
     * El ultimo bloque, corto: un byte 0x01 detras del mensaje y ceros detras,
     * lo que pone el "bit de encima" dentro del bloque en vez de en 2^128 -- de
     * ahi que no haya hibit.
     * \~ */
    if (p.used != 0) {
        p.pending[p.used] = 1;
        for (size_t i = p.used + 1; i < 16; ++i) p.pending[i] = 0;
        absorb(p, p.pending, 0);
    }

    uint32_t h0 = p.h[0], h1 = p.h[1], h2 = p.h[2], h3 = p.h[3], h4 = p.h[4];

    /* \~english
     * Carry fully, so every limb holds 26 bits at most.  Twice: what the top
     * folds back times five can push limb one to exactly 2^26, and a second
     * pass is what guarantees it does not stay there -- that bit would be lost
     * when the limbs are packed into words below.
     * \~spanish
     * Llevar del todo, para que cada miembro tenga como mucho 26 bits.  Dos
     * veces: lo que lo alto devuelve por cinco puede dejar el miembro uno justo
     * en 2^26, y la segunda pasada es lo que garantiza que no se quede ahi -- ese
     * bit se perderia al empaquetar los miembros en palabras mas abajo.
     * \~ */
    for (int pass = 0; pass < 2; ++pass) {
        h2 += h1 >> 26; h1 &= kMask26;
        h3 += h2 >> 26; h2 &= kMask26;
        h4 += h3 >> 26; h3 &= kMask26;
        h0 += (h4 >> 26) * 5; h4 &= kMask26;
        h1 += h0 >> 26; h0 &= kMask26;
    }

    /* \~english
     * h is now below 2^130 but may still be at or above p = 2^130 - 5.  g =
     * h + 5 - 2^130 is h - p; it is used exactly when it is not negative.  The
     * choice is a mask, not a branch, so the time does not say which.
     * \~spanish
     * h ya esta por debajo de 2^130 pero puede seguir siendo mayor o igual que
     * p = 2^130 - 5.  g = h + 5 - 2^130 es h - p; se usa justo cuando no es
     * negativo.  La eleccion es una mascara, no una rama, asi que el tiempo no
     * dice cual.
     * \~ */
    uint32_t g0 = h0 + 5;
    uint32_t g1 = h1 + (g0 >> 26); g0 &= kMask26;
    uint32_t g2 = h2 + (g1 >> 26); g1 &= kMask26;
    uint32_t g3 = h3 + (g2 >> 26); g2 &= kMask26;
    uint32_t g4 = h4 + (g3 >> 26) - (1u << 26); g3 &= kMask26;

    const uint32_t use_g = (g4 >> 31) - 1;  // \~english all ones if g >= 0  \~spanish todo unos si g >= 0  \~
    h0 = (h0 & ~use_g) | (g0 & use_g);
    h1 = (h1 & ~use_g) | (g1 & use_g);
    h2 = (h2 & ~use_g) | (g2 & use_g);
    h3 = (h3 & ~use_g) | (g3 & use_g);
    h4 = (h4 & ~use_g) | (g4 & use_g);

    // \~english The low 128 bits as four words; then s is added modulo 2^128.
    // \~spanish Los 128 bits bajos como cuatro palabras; despues se suma s modulo 2^128.  \~
    const uint32_t w0 = h0 | (h1 << 26);
    const uint32_t w1 = (h1 >> 6) | (h2 << 20);
    const uint32_t w2 = (h2 >> 12) | (h3 << 14);
    const uint32_t w3 = (h3 >> 18) | (h4 << 8);

    uint64_t f = static_cast<uint64_t>(w0) + p.pad[0];
    store32(tag, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w1) + p.pad[1] + (f >> 32);
    store32(tag + 4, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w2) + p.pad[2] + (f >> 32);
    store32(tag + 8, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w3) + p.pad[3] + (f >> 32);
    store32(tag + 12, static_cast<uint32_t>(f));

    wipe(&p, sizeof p);
}

void seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
          size_t ad_len, const uint8_t *in, size_t n, uint8_t *out) noexcept {
    // \~english Encrypt from counter one (zero made the one-time key), then MAC the ciphertext.
    // \~spanish Cifrar desde el contador uno (el cero hizo la clave de un solo uso) y autenticar lo cifrado.  \~
    xor_stream(key, 1, nonce, in, out, n);
    aead_tag(key, nonce, ad, ad_len, out, n, out + n);
}

bool open(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
          size_t ad_len, const uint8_t *in, size_t n, uint8_t *out) noexcept {
    if (n < kTagSize) return false;
    const size_t body = n - kTagSize;

    uint8_t want[kTagSize];
    aead_tag(key, nonce, ad, ad_len, in, body, want);

    // \~english Every byte compared, whatever the first difference.
    // \~spanish Se comparan todos los bytes, este donde este la primera diferencia.  \~
    uint8_t diff = 0;
    for (size_t i = 0; i < kTagSize; ++i) diff = static_cast<uint8_t>(diff | (want[i] ^ in[body + i]));
    wipe(want, sizeof want);
    if (diff != 0) return false;

    xor_stream(key, 1, nonce, in, out, body);
    return true;
}

} // namespace chacha
} // namespace http_vx
