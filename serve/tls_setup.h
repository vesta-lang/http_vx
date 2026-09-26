/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/tls_setup.h
 * @brief
 * \~english What the runnable server needs to serve HTTPS: a provider, a certificate chain and its key, read from files.
 * \~spanish Lo que necesita el servidor ejecutable para servir HTTPS: un proveedor, una cadena de certificados y su clave, leidos de ficheros.
 * \~
 *
 * \~english
 * The provider is chosen by name among those this build has -- `cng`, the
 * system's own, and `openssl` -- and a build with none, or a name it does
 * not have, refuses to start and says so (R24): a server asked for TLS never
 * serves in the clear instead.  The certificate file is PEM (every
 * CERTIFICATE block, end-entity first) or one DER certificate; the key file
 * is a PKCS#8 PRIVATE KEY, PEM or DER, P-256 or RSA.
 * \~spanish
 * El proveedor se elige por nombre entre los que tiene esta construccion --
 * `cng`, el del propio sistema, y `openssl` -- y una construccion sin ninguno,
 * o un nombre que no tiene, se niega a arrancar y lo dice (R24): a un servidor
 * al que se le pide TLS nunca sirve en claro en su lugar.  El fichero del
 * certificado es PEM (cada bloque CERTIFICATE, el final primero) o un
 * certificado DER; el de la clave es una PRIVATE KEY PKCS#8, PEM o DER, P-256 o
 * RSA.
 * \~
 */
#ifndef HTTP_VX_SERVE_TLS_SETUP_H
#define HTTP_VX_SERVE_TLS_SETUP_H

#include "http_vx/quic_crypto.h"
#include "http_vx/tls_ticket.h"

#include <cstddef>
#include <cstdint>

namespace serve {

/**
 * @brief
 * \~english A provider, a chain and a key, loaded once, alive while the server runs.
 * \~spanish Un proveedor, una cadena y una clave, cargados una vez, vivos mientras corre el servidor.
 * \~
 */
class TlsSetup {
public:
    /// \~english The longest chain read from a file.  \~spanish La cadena mas larga que se lee de un fichero.  \~
    static constexpr size_t kMaxChain = 8;

    TlsSetup() noexcept = default;
    ~TlsSetup();
    TlsSetup(const TlsSetup &) = delete;
    TlsSetup &operator=(const TlsSetup &) = delete;

    /**
     * @brief
     * \~english Chooses the provider @p name (null: the build's first) and loads @p cert_path and @p key_path.
     * \~spanish Elige el proveedor @p name (nulo: el primero de la construccion) y carga @p cert_path y @p key_path.
     * \~
     * @return \~english false, with why(), when TLS cannot be served  \~spanish falso, con why(), cuando no se puede servir TLS  \~
     */
    bool load(const char *name, const char *cert_path, const char *key_path) noexcept;

    const char *why() const noexcept { return why_; }
    http_vx::quic::Crypto *crypto() const noexcept { return crypto_; }
    const uint8_t *const *certificates() const noexcept { return certs_; }
    const size_t *certificate_lens() const noexcept { return lens_; }
    size_t certificate_count() const noexcept { return count_; }
    void *signing_key() const noexcept { return key_; }
    http_vx::quic::Scheme scheme() const noexcept { return scheme_; }
    /// \~english A sealer with a key made now: tickets live as long as this process.
    /// \~spanish Un sellador con una clave hecha ahora: los tickets viven lo que este proceso.  \~
    const http_vx::tls::TicketSealer *tickets() const noexcept { return sealer_; }

private:
    bool choose(const char *name) noexcept;

    http_vx::quic::Crypto *crypto_ = nullptr;
    /// \~english The provider object, built in place: which class it is depends on the build.
    /// \~spanish El objeto proveedor, construido en su sitio: que clase es depende de la construccion.  \~
    void *provider_mem_ = nullptr;
    /// \~english Which provider class lives in provider_mem_: 0 none, 1 OpenSSL, 2 CNG.
    /// \~spanish Que clase de proveedor vive en provider_mem_: 0 ninguna, 1 OpenSSL, 2 CNG.  \~
    uint8_t kind_ = 0;
    http_vx::tls::TicketSealer *sealer_ = nullptr;
    uint8_t *file_ = nullptr;
    uint8_t *certs_[kMaxChain] = {};
    size_t lens_[kMaxChain] = {};
    size_t count_ = 0;
    uint8_t *key_der_ = nullptr;
    size_t key_len_ = 0;
    void *key_ = nullptr;
    http_vx::quic::Scheme scheme_ = http_vx::quic::Scheme::EcdsaSecp256r1Sha256;
    const char *why_ = nullptr;
};

} // namespace serve

#endif // HTTP_VX_SERVE_TLS_SETUP_H
