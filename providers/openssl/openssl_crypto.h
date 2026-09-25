/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/openssl/openssl_crypto.h
 * @brief
 * \~english A QUIC cryptographic provider on top of OpenSSL's libcrypto.
 * \~spanish Un proveedor criptografico de QUIC sobre la libcrypto de OpenSSL.
 * \~
 *
 * \~english
 * An adapter, and outside the core on purpose: R22 says http_vx links no TLS
 * library, and it does not -- this lives in its own library that only whoever
 * builds a server chooses to link.  No OpenSSL header leaks through this one,
 * so a program that uses the provider does not inherit OpenSSL's headers
 * either.
 *
 * It uses libcrypto only, never libssl: all QUIC asks of it are the
 * primitives in `quic_crypto.h`.
 * \~spanish
 * Un adaptador, y fuera del nucleo a proposito: la R22 dice que http_vx no
 * enlaza ninguna biblioteca de TLS, y no lo hace -- esto vive en su propia
 * biblioteca que solo enlaza quien construye un servidor y lo elige.  Ninguna
 * cabecera de OpenSSL se cuela por esta, asi que un programa que use el
 * proveedor tampoco hereda las cabeceras de OpenSSL.
 *
 * Usa solo libcrypto, nunca libssl: lo unico que le pide QUIC son las
 * primitivas de `quic_crypto.h`.
 * \~
 */
#ifndef HTTP_VX_PROVIDERS_OPENSSL_CRYPTO_H
#define HTTP_VX_PROVIDERS_OPENSSL_CRYPTO_H

#include "http_vx/quic_crypto.h"

namespace http_vx {

/**
 * @brief
 * \~english The primitives QUIC needs, run by OpenSSL 3.
 * \~spanish Las primitivas que necesita QUIC, ejecutadas por OpenSSL 3.
 * \~
 */
class OpensslCrypto final : public quic::Crypto {
public:
    OpensslCrypto() noexcept;
    ~OpensslCrypto() override;

    OpensslCrypto(const OpensslCrypto &) = delete;
    OpensslCrypto &operator=(const OpensslCrypto &) = delete;

    /**
     * @brief
     * \~english Whether OpenSSL gave everything this needs.
     * \~spanish Si OpenSSL dio todo lo que esto necesita.
     * \~
     *
     * \~english
     * A libcrypto built without HKDF, or configured to refuse it, would
     * otherwise fail on the first packet; asking here lets a server refuse to
     * start instead (R24).
     * \~spanish
     * Una libcrypto construida sin HKDF, o configurada para negarlo, fallaria si
     * no en el primer paquete; preguntar aqui deja que un servidor se niegue a
     * arrancar en su lugar (R24).
     * \~
     */
    bool ready() const noexcept { return kdf_ != nullptr; }

    const char *name() const noexcept override;
    bool supports(quic::Aead a) const noexcept override;
    bool random(uint8_t *out, size_t n) noexcept override;
    bool digest(quic::Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept override;
    bool extract(quic::Hash h, const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t *prk) noexcept override;
    bool expand(quic::Hash h, const uint8_t *prk, size_t prk_len,
                const uint8_t *info, size_t info_len, uint8_t *out,
                size_t out_len) noexcept override;
    void *prepare_aead(quic::Aead a, const uint8_t *key) noexcept override;
    void *prepare_hp(quic::Aead a, const uint8_t *key) noexcept override;
    void forget(void *state) noexcept override;
    bool seal(void *aead, const uint8_t *nonce, const uint8_t *ad,
              size_t ad_len, const uint8_t *in, size_t n,
              uint8_t *out) noexcept override;
    quic::OpenResult open(void *aead, const uint8_t *nonce, const uint8_t *ad,
                          size_t ad_len, const uint8_t *in, size_t n,
                          uint8_t *out) noexcept override;
    bool mask(void *hp, const uint8_t *sample, uint8_t *out) noexcept override;
    bool supports(quic::Group g) const noexcept override;
    void *generate_key(quic::Group g, uint8_t *pub) noexcept override;
    void *import_key(quic::Group g, const uint8_t *priv, size_t priv_len, const uint8_t *pub) noexcept override;
    quic::Agreed agree(void *key, const uint8_t *peer, size_t peer_len, uint8_t *shared) noexcept override;
    void *signing_key(quic::Scheme s, const uint8_t *pkcs8, size_t len) noexcept override;
    bool sign(void *key, const uint8_t *msg, size_t n, uint8_t *sig, size_t room,
              size_t &sig_len) noexcept override;
    quic::Verified verify(quic::Scheme s, const uint8_t *cert, size_t cert_len, const uint8_t *msg, size_t n,
                          const uint8_t *sig, size_t sig_len) noexcept override;
    void forget_key(void *key) noexcept override;

private:
    /// \~english OpenSSL's HKDF, fetched once.  \~spanish El HKDF de OpenSSL, buscado una vez.  \~
    void *kdf_ = nullptr;
};

} // namespace http_vx

#endif // HTTP_VX_PROVIDERS_OPENSSL_CRYPTO_H
