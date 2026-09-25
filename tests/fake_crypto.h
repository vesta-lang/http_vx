/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/fake_crypto.h
 * @brief
 * \~english A QUIC crypto provider with no cryptography in it, for tests only.
 * \~spanish Un proveedor criptografico de QUIC sin criptografia dentro, solo para pruebas.
 * \~
 *
 * \~english
 * So that the QUIC logic -- protection, and everything a connection does on
 * top -- can be checked on a machine with no cryptographic library at all.
 * It is not a no-op: its "AEAD" mixes the nonce into every byte and its tag
 * covers the associated data and the plaintext, so a wrong nonce or a header
 * left out of the associated data fails here as it would with AES; its mask
 * depends on the sample; and its "HKDF" gives different bytes for different
 * inputs, so that keys can be derived and told apart.  None of it is secure,
 * and none of it pretends to be.
 * \~spanish
 * Para que la logica de QUIC -- la proteccion, y todo lo que hace una conexion
 * encima -- se pueda comprobar en una maquina sin ninguna biblioteca
 * criptografica.  No es no hacer nada: su "AEAD" mezcla el nonce en cada byte y
 * su marca cubre los datos asociados y el texto claro, asi que un nonce
 * equivocado o una cabecera fuera de los datos asociados falla aqui como con
 * AES; su mascara depende de la muestra; y su "HKDF" da bytes distintos para
 * entradas distintas, para que se puedan derivar claves y distinguirlas.  Nada
 * de esto es seguro, ni lo pretende.
 * \~
 */
#ifndef HTTP_VX_TESTS_FAKE_CRYPTO_H
#define HTTP_VX_TESTS_FAKE_CRYPTO_H

#include "http_vx/quic_crypto.h"

#include <cstring>

namespace test_support {

using namespace http_vx::quic;

class FakeCrypto final : public Crypto {
public:
    /// \~english When set, the mask is this and not a function of the sample.
    /// \~spanish Si se pone, la mascara es esta y no una funcion de la muestra.  \~
    bool fixed_mask = false;
    uint8_t the_mask[kMaskSize] = {};

    /// \~english Makes every primitive fail, as a broken provider would.
    /// \~spanish Hace fallar todas las primitivas, como un proveedor roto.  \~
    bool broken = false;

    /// \~english When set, the mask is refused for any sample but this one.
    /// \~spanish Si se pone, la mascara se niega para cualquier muestra que no sea esta.  \~
    bool check_sample = false;
    uint8_t expected_sample[kSampleSize] = {};

    const char *name() const noexcept override { return "fake"; }
    bool supports(Aead) const noexcept override { return true; }

    bool extract(Hash h, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                 size_t ikm_len, uint8_t *prk) noexcept override {
        if (broken) return false;
        uint64_t a = mix(0x5A17, salt, salt_len);
        a = mix(a, ikm, ikm_len);
        spread(a, prk, hash_size(h));
        return true;
    }

    bool expand(Hash, const uint8_t *prk, size_t prk_len, const uint8_t *info,
                size_t info_len, uint8_t *out, size_t out_len) noexcept override {
        if (broken) return false;
        uint64_t a = mix(0xE9A4D, prk, prk_len);
        a = mix(a, info, info_len);
        spread(a, out, out_len);
        return true;
    }

    // \~english Any non-null pointer will do; nothing is kept behind it.
    // \~spanish Vale cualquier puntero no nulo; detras no se guarda nada.  \~
    void *prepare_aead(Aead, const uint8_t *) noexcept override { return this; }
    void *prepare_hp(Aead, const uint8_t *) noexcept override { return this; }
    void forget(void *) noexcept override {}

    bool seal(void *, const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
              const uint8_t *in, size_t n, uint8_t *out) noexcept override {
        if (broken) return false;
        uint8_t tag[kTagSize];
        make_tag(nonce, ad, ad_len, in, n, tag);
        for (size_t i = 0; i < n; ++i) out[i] = in[i] ^ stream(nonce, i);
        std::memcpy(out + n, tag, kTagSize);
        return true;
    }

    OpenResult open(void *, const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                    const uint8_t *in, size_t n, uint8_t *out) noexcept override {
        if (broken) return OpenResult::Failed;
        if (n < kTagSize) return OpenResult::Forged;
        const size_t body = n - kTagSize;
        uint8_t got[kTagSize];
        std::memcpy(got, in + body, kTagSize);
        for (size_t i = 0; i < body; ++i) out[i] = in[i] ^ stream(nonce, i);
        uint8_t want[kTagSize];
        make_tag(nonce, ad, ad_len, out, body, want);
        return std::memcmp(got, want, kTagSize) == 0 ? OpenResult::Ok : OpenResult::Forged;
    }

    bool mask(void *, const uint8_t *sample, uint8_t *out) noexcept override {
        if (broken) return false;
        if (check_sample && std::memcmp(sample, expected_sample, kSampleSize) != 0) return false;
        for (size_t i = 0; i < kMaskSize; ++i)
            out[i] = fixed_mask ? the_mask[i]
                                : static_cast<uint8_t>(sample[i] ^ sample[15 - i] ^ 0xA5);
        return true;
    }

private:
    static uint64_t mix(uint64_t a, const uint8_t *p, size_t n) {
        a ^= 1469598103934665603ull;
        for (size_t i = 0; i < n; ++i) a = (a ^ p[i]) * 1099511628211ull;
        return a ^ (n * 0x9E3779B97F4A7C15ull);
    }

    static void spread(uint64_t a, uint8_t *out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            a = (a ^ i) * 0x9E3779B97F4A7C15ull;
            out[i] = static_cast<uint8_t>(a >> 56);
        }
    }

    static uint8_t stream(const uint8_t *nonce, size_t i) {
        return static_cast<uint8_t>(nonce[i % kNonceSize] + 31 * i);
    }

    /// \~english An FNV-style checksum over nonce, associated data and plaintext.
    /// \~spanish Una suma de comprobacion al estilo FNV sobre nonce, datos asociados y texto claro.  \~
    static void make_tag(const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                         const uint8_t *pt, size_t n, uint8_t *tag) {
        uint64_t a = 1469598103934665603ull;
        uint64_t b = 0x9E3779B97F4A7C15ull;
        for (size_t i = 0; i < kNonceSize; ++i) a = (a ^ nonce[i]) * 1099511628211ull;
        for (size_t i = 0; i < ad_len; ++i) a = (a ^ ad[i]) * 1099511628211ull;
        b ^= ad_len;
        for (size_t i = 0; i < n; ++i) b = (b ^ pt[i]) * 1099511628211ull;
        for (size_t i = 0; i < 8; ++i) {
            tag[i] = static_cast<uint8_t>(a >> (8 * i));
            tag[8 + i] = static_cast<uint8_t>(b >> (8 * i));
        }
    }
};

} // namespace test_support

#endif // HTTP_VX_TESTS_FAKE_CRYPTO_H
