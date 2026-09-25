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
#include "http_vx/quic_protection.h"

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

    /// \~english Deterministic on purpose: a test run is repeatable.
    /// \~spanish Determinista a proposito: una corrida de prueba se puede repetir.  \~
    bool random(uint8_t *out, size_t n) noexcept override {
        if (broken) return false;
        for (size_t i = 0; i < n; ++i) {
            seed_ = seed_ * 6364136223846793005ull + 1442695040888963407ull;
            out[i] = static_cast<uint8_t>(seed_ >> 56);
        }
        return true;
    }

    bool digest(Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept override {
        if (broken) return false;
        spread(mix(0xD16E57, in, n), out, hash_size(h));
        return true;
    }

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

    /* \~english
     * A key exchange that agrees and a signature that checks, and nothing
     * more.  The public key is the private key; the shared secret mixes both
     * public keys in a fixed order, so either end computes the same.  A
     * "certificate" is the same bytes as the "PKCS#8" key it goes with.
     * \~spanish
     * Un intercambio de claves que se pone de acuerdo y una firma que se
     * comprueba, y nada mas.  La clave publica es la privada; el secreto
     * compartido mezcla las dos claves publicas en un orden fijo, asi que los dos
     * extremos calculan lo mismo.  Un "certificado" son los mismos bytes que la
     * clave "PKCS#8" con la que va.
     * \~ */
    struct FakeKey {
        Group group;
        bool signing;
        uint8_t pub[kMaxPublicKey];
        uint64_t id;
    };

    bool supports(Group) const noexcept override { return true; }

    void *generate_key(Group g, uint8_t *pub) noexcept override {
        uint8_t priv[32];
        if (!random(priv, sizeof priv)) return nullptr;
        uint8_t full[kMaxPublicKey];
        make_public(g, priv, full);
        return import_key(g, priv, 32, full) != nullptr ? copy_public(g, full, pub) : nullptr;
    }

    void *import_key(Group g, const uint8_t *priv, size_t priv_len, const uint8_t *pub) noexcept override {
        if (broken || priv_len != 32) return nullptr;
        uint8_t want[kMaxPublicKey];
        make_public(g, priv, want);
        if (std::memcmp(want, pub, public_key_size(g)) != 0) return nullptr;
        FakeKey *k = new FakeKey{g, false, {}, 0};
        std::memcpy(k->pub, want, public_key_size(g));
        last_ = k;
        return k;
    }

    Agreed agree(void *key, const uint8_t *peer, size_t peer_len, uint8_t *shared) noexcept override {
        FakeKey *k = static_cast<FakeKey *>(key);
        if (broken || k == nullptr || k->signing) return Agreed::Failed;
        const size_t n = public_key_size(k->group);
        uint8_t zero = 0;
        for (size_t i = 0; i < peer_len; ++i) zero = static_cast<uint8_t>(zero | peer[i]);
        if (peer_len != n || zero == 0) return Agreed::BadPeerKey;
        const bool mine_first = std::memcmp(k->pub, peer, n) < 0;
        uint64_t a = mix(0x5EC4E7, mine_first ? k->pub : peer, n);
        a = mix(a, mine_first ? peer : k->pub, n);
        spread(a, shared, 32);
        return Agreed::Ok;
    }

    void *signing_key(Scheme, const uint8_t *pkcs8, size_t len) noexcept override {
        if (broken || len == 0) return nullptr;
        return new FakeKey{Group::X25519, true, {}, mix(0x516, pkcs8, len)};
    }

    bool sign(void *key, const uint8_t *msg, size_t n, uint8_t *sig, size_t room,
              size_t &sig_len) noexcept override {
        FakeKey *k = static_cast<FakeKey *>(key);
        if (broken || k == nullptr || !k->signing || room < 64) return false;
        spread(mix(k->id, msg, n), sig, 64);
        sig_len = 64;
        return true;
    }

    Verified verify(Scheme, const uint8_t *cert, size_t cert_len, const uint8_t *msg, size_t n,
                    const uint8_t *sig, size_t sig_len) noexcept override {
        if (broken) return Verified::Failed;
        if (cert_len == 0) return Verified::WrongKey;
        uint8_t want[64];
        spread(mix(mix(0x516, cert, cert_len), msg, n), want, 64);
        return sig_len == 64 && std::memcmp(want, sig, 64) == 0 ? Verified::Ok : Verified::Bad;
    }

    void forget_key(void *key) noexcept override { delete static_cast<FakeKey *>(key); }

private:
    FakeKey *last_ = nullptr;

    static void make_public(Group g, const uint8_t *priv, uint8_t *pub) {
        if (g == Group::X25519) {
            std::memcpy(pub, priv, 32);
            return;
        }
        pub[0] = 4;
        std::memcpy(pub + 1, priv, 32);
        std::memcpy(pub + 33, priv, 32);
    }

    void *copy_public(Group g, const uint8_t *full, uint8_t *pub) {
        std::memcpy(pub, full, public_key_size(g));
        return last_;
    }
    uint64_t seed_ = 0x0123456789abcdefull;

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
