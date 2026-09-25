/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file cng_verify.h
 * @brief
 * \~english A certificate verifier that asks Windows: its chain engine, and its SSL policy.
 * \~spanish Un verificador de certificados que pregunta a Windows: su motor de cadenas, y su politica SSL.
 * \~
 *
 * \~english
 * The chain is built and judged by the system (crypt32), with the anchors,
 * the distrusted certificates and the rules Windows Update keeps current;
 * the name is checked by the SSL policy, as the system checks it for every
 * other program.  Two things are asked on top of the defaults:
 *
 * - **No network.**  Only what is already cached is fetched (the chain
 *   engine's cache-only retrieval): a handshake must not wait on a download.
 *   A chain that needs a certificate the peer did not send, and that is not
 *   cached, is not trusted -- which is what 4.4.2 asks of a peer anyway.
 * - **Strong signatures** (the system's "OS_1" set: SHA-2, RSA of 2048 bits
 *   or more, ECDSA on P-256 or P-384).  RFC 8446 says an MD5 signature MUST
 *   be refused and a SHA-1 one SHOULD be (4.4.2.4); this refuses both.
 *
 * Revocation is not checked unless asked; when it is, only from the cache,
 * and not knowing is a verdict of its own -- never a pass.
 * \~spanish
 * La cadena la construye y la juzga el sistema (crypt32), con las anclas, los
 * certificados de los que desconfia y las reglas que mantiene al dia Windows
 * Update; el nombre lo comprueba la politica SSL, como el sistema lo comprueba
 * para cualquier otro programa.  Se piden dos cosas encima de lo que hace por
 * defecto:
 *
 * - **Sin red.**  Solo se usa lo que ya esta en la cache (la recuperacion solo
 *   de cache del motor de cadenas): un saludo no debe esperar a una descarga.
 *   Una cadena que necesite un certificado que el otro no mando, y que no este
 *   en la cache, no es de fiar -- que es lo que 4.4.2 pide al otro de todos
 *   modos.
 * - **Firmas fuertes** (el conjunto "OS_1" del sistema: SHA-2, RSA de 2048 bits
 *   o mas, ECDSA sobre P-256 o P-384).  El RFC 8446 dice que una firma MD5 DEBE
 *   rechazarse y una SHA-1 DEBERIA (4.4.2.4); esto rechaza las dos.
 *
 * La revocacion no se comprueba salvo que se pida; cuando se pide, solo desde la
 * cache, y no saberla es un veredicto propio -- nunca un aprobado.
 * \~
 */
#ifndef HTTP_VX_PROVIDERS_CNG_VERIFY_H
#define HTTP_VX_PROVIDERS_CNG_VERIFY_H

#include "http_vx/tls_verify.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

class CngVerifier final : public tls::CertVerifier {
public:
    CngVerifier() noexcept;
    ~CngVerifier() override;

    CngVerifier(const CngVerifier &) = delete;
    CngVerifier &operator=(const CngVerifier &) = delete;

    /**
     * @brief
     * \~english Trusts @p der (a DER certificate) as an anchor -- and, from the first one on, ONLY the anchors added.
     * \~spanish Se fia de @p der (un certificado DER) como ancla -- y, desde la primera, SOLO de las anclas anadidas.
     * \~
     *
     * \~english
     * Without any, the anchors are the system's.  With some, the system's no
     * longer count: a private PKI does not also trust the whole world.
     * \~spanish
     * Sin ninguna, las anclas son las del sistema.  Con alguna, las del sistema
     * dejan de contar: una PKI privada no se fia ademas de todo el mundo.
     * \~
     */
    bool add_anchor(const uint8_t *der, size_t n) noexcept;

    /// \~english Checks as of @p unix_s (seconds since 1970); 0, the default, is now.
    /// \~spanish Comprueba a fecha de @p unix_s (segundos desde 1970); 0, lo de por defecto, es ahora.  \~
    void set_time(uint64_t unix_s) noexcept { time_ = unix_s; }

    /// \~english Asks for revocation, from the cache only.  \~spanish Pide la revocacion, solo desde la cache.  \~
    void check_revocation(bool on) noexcept { revocation_ = on; }

    tls::Verdict verify(const tls::Chain &chain, tls::Role role, const char *host) noexcept override;

private:
    /// \~english The engine for the added anchors, made when first needed after one was added.
    /// \~spanish El motor para las anclas anadidas, hecho cuando hace falta tras anadir una.  \~
    bool engine() noexcept;

    /* \~english HCERTSTORE and HCERTCHAINENGINE, opaque to keep wincrypt.h out.
     * \~spanish HCERTSTORE y HCERTCHAINENGINE, opacos para que no entre wincrypt.h.  \~ */
    void *anchors_ = nullptr;
    void *engine_ = nullptr;
    bool stale_ = false;
    uint64_t time_ = 0;
    bool revocation_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_PROVIDERS_CNG_VERIFY_H
