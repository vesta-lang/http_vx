/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/windows/cng_crypto.h
 * @brief
 * \~english A QUIC cryptographic provider on top of Windows' own CNG (bcrypt.dll).
 * \~spanish Un proveedor criptografico de QUIC sobre la CNG del propio Windows (bcrypt.dll).
 * \~
 *
 * \~english
 * The operating system as provider, which is what R22 names as the natural
 * one on Windows: no library to ship, none to patch -- the system's is
 * patched by Windows Update -- and nothing with a license.  Like the OpenSSL
 * one it lives in its own library and is linked only by whoever chooses it,
 * and no Windows header leaks through this one.
 *
 * **AES comes from the system; ChaCha20-Poly1305 does not.**  Windows 10's
 * CNG has neither the AEAD nor the raw ChaCha20 stream that ChaCha20's header
 * protection needs, so both come from `providers/common/chacha20_poly1305`,
 * written here from RFC 8439.  With that, this provider offers all three
 * suites, the same as the OpenSSL one.
 *
 * HKDF is split the way the RFC splits it.  Extract IS one HMAC (RFC 5869,
 * section 2.2), computed by the system's HMAC; expand is the system's own
 * HKDF, which CNG only exposes starting from a pseudorandom key.
 * \~spanish
 * El sistema operativo como proveedor, que es el que la R22 nombra como natural
 * en Windows: ninguna biblioteca que distribuir, ninguna que parchear -- la del
 * sistema la parchea Windows Update -- y nada con licencia.  Como el de OpenSSL,
 * vive en su propia biblioteca y solo lo enlaza quien lo elige, y ninguna
 * cabecera de Windows se cuela por esta.
 *
 * **AES sale del sistema; ChaCha20-Poly1305 no.**  La CNG de Windows 10 no
 * tiene ni el AEAD ni el flujo ChaCha20 en bruto que pide la proteccion de
 * cabecera de ChaCha20, asi que los dos salen de
 * `providers/common/chacha20_poly1305`, escrito aqui a partir del RFC 8439.  Con
 * eso, este proveedor ofrece los tres algoritmos, igual que el de OpenSSL.
 *
 * HKDF se parte como lo parte el RFC.  Extract ES un HMAC (RFC 5869, seccion
 * 2.2), calculado con el HMAC del sistema; expand es el HKDF del propio sistema,
 * que CNG solo expone a partir de una clave pseudoaleatoria.
 * \~
 */
#ifndef HTTP_VX_PROVIDERS_CNG_CRYPTO_H
#define HTTP_VX_PROVIDERS_CNG_CRYPTO_H

#include "http_vx/quic_crypto.h"

namespace http_vx {

/**
 * @brief
 * \~english The primitives QUIC needs, run by Windows CNG.
 * \~spanish Las primitivas que necesita QUIC, ejecutadas por la CNG de Windows.
 * \~
 */
class CngCrypto final : public quic::Crypto {
public:
    CngCrypto() noexcept;
    ~CngCrypto() override;

    CngCrypto(const CngCrypto &) = delete;
    CngCrypto &operator=(const CngCrypto &) = delete;

    /**
     * @brief
     * \~english Whether the system gave every algorithm this needs.
     * \~spanish Si el sistema dio todos los algoritmos que esto necesita.
     * \~
     *
     * \~english
     * HKDF arrived in CNG with Windows 10; on an older system this is false,
     * and a server should refuse to start with this provider (R24) rather
     * than fail on the first handshake.
     * \~spanish
     * HKDF llego a CNG con Windows 10; en un sistema mas viejo esto es falso, y
     * un servidor deberia negarse a arrancar con este proveedor (R24) en vez de
     * fallar en el primer handshake.
     * \~
     */
    bool ready() const noexcept;

    /// \~english Which algorithm the system refused, when not ready.
    /// \~spanish Que algoritmo nego el sistema, cuando no esta listo.  \~
    const char *missing() const noexcept { return missing_; }

    /// \~english The name it is chosen by; the only place it is written.
    /// \~spanish El nombre por el que se elige; el unico sitio donde esta escrito.  \~
    static constexpr const char *kName = "cng";

    const char *name() const noexcept override { return kName; }
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
    /// \~english The algorithm handles, opened once; opaque to keep bcrypt.h out.
    /// \~spanish Los manejadores de algoritmo, abiertos una vez; opacos para que no entre bcrypt.h.  \~
    void *x25519_ = nullptr;
    void *ecdh256_ = nullptr;
    void *ecdsa256_ = nullptr;
    void *rsa_ = nullptr;
    void *gcm_ = nullptr;
    void *ecb_ = nullptr;
    void *hmac256_ = nullptr;
    void *hmac384_ = nullptr;
    void *sha256_ = nullptr;
    void *sha384_ = nullptr;
    void *hkdf_ = nullptr;

    const char *missing_ = nullptr;
};

} // namespace http_vx

#endif // HTTP_VX_PROVIDERS_CNG_CRYPTO_H
