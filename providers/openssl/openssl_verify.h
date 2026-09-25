/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file openssl_verify.h
 * @brief
 * \~english A certificate verifier that asks OpenSSL: X509_verify_cert, with the name checked by it too.
 * \~spanish Un verificador de certificados que pregunta a OpenSSL: X509_verify_cert, y el nombre lo comprueba tambien el.
 * \~
 *
 * \~english
 * Path building, dates, key usage and matching the name are OpenSSL's, with
 * its defaults; the anchors are the ones its default
 * paths lead to -- on a Linux system, the distribution's -- or the ones
 * added.  On top of its defaults, **authentication level 1**: signatures of
 * less than 80 bits of security are refused, which takes MD5 and SHA-1 out
 * of any chain but its anchor, as RFC 8446 asks (4.4.2.4).
 *
 * Nothing is fetched: OpenSSL does not go to the network here.  Revocation
 * is not checked unless asked, and when it is, with no CRL at hand the
 * verdict is that it could not be found out -- never a pass.
 * \~spanish
 * Construir el camino, las fechas, el uso de la clave y comparar el nombre son
 * de OpenSSL, con lo que hace por defecto; las anclas
 * son aquellas a las que llevan sus rutas por defecto -- en un sistema Linux, las
 * de la distribucion -- o las anadidas.  Encima de lo que hace por defecto,
 * **nivel de autenticacion 1**: se rechazan las firmas de menos de 80 bits de
 * seguridad, lo que saca MD5 y SHA-1 de cualquier cadena salvo de su ancla, como
 * pide el RFC 8446 (4.4.2.4).
 *
 * No se descarga nada: OpenSSL no va a la red aqui.  La revocacion no se
 * comprueba salvo que se pida, y cuando se pide, sin una CRL a mano el
 * veredicto es que no se pudo averiguar -- nunca un aprobado.
 * \~
 */
#ifndef HTTP_VX_PROVIDERS_OPENSSL_VERIFY_H
#define HTTP_VX_PROVIDERS_OPENSSL_VERIFY_H

#include "http_vx/tls_verify.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

class OpensslVerifier final : public tls::CertVerifier {
public:
    OpensslVerifier() noexcept;
    ~OpensslVerifier() override;

    OpensslVerifier(const OpensslVerifier &) = delete;
    OpensslVerifier &operator=(const OpensslVerifier &) = delete;

    /// \~english Whether OpenSSL gave a store to verify with.  \~spanish Si OpenSSL dio un almacen con el que verificar.  \~
    bool ready() const noexcept { return store_ != nullptr; }

    /**
     * @brief
     * \~english Trusts @p der (a DER certificate) as an anchor -- and, from the first one on, ONLY the anchors added.
     * \~spanish Se fia de @p der (un certificado DER) como ancla -- y, desde la primera, SOLO de las anclas anadidas.
     * \~
     */
    bool add_anchor(const uint8_t *der, size_t n) noexcept;

    /// \~english Checks as of @p unix_s (seconds since 1970); 0, the default, is now.
    /// \~spanish Comprueba a fecha de @p unix_s (segundos desde 1970); 0, lo de por defecto, es ahora.  \~
    void set_time(uint64_t unix_s) noexcept { time_ = unix_s; }

    /// \~english Asks for revocation, from the CRLs in the store.  \~spanish Pide la revocacion, de las CRL del almacen.  \~
    void check_revocation(bool on) noexcept { revocation_ = on; }

    tls::Verdict verify(const tls::Chain &chain, tls::Role role, const char *host) noexcept override;

private:
    /// \~english X509_STORE, opaque to keep OpenSSL's headers out.  \~spanish X509_STORE, opaco para que no entren las cabeceras de OpenSSL.  \~
    void *store_ = nullptr;
    bool own_anchors_ = false;
    uint64_t time_ = 0;
    bool revocation_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_PROVIDERS_OPENSSL_VERIFY_H
