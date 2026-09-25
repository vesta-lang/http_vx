/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/verify.cpp
 * @brief
 * \~english From a verifier's verdict to the alert TLS names for it (RFC 8446, 6.2).
 * \~spanish Del veredicto de un verificador a la alerta que TLS nombra para el (RFC 8446, 6.2).
 * \~
 */
#include "http_vx/tls_verify.h"

namespace http_vx {
namespace tls {

Alert trust_alert(Trust t) noexcept {
    switch (t) {
    case Trust::Trusted: return Alert::None;
    // \~english "the CA certificate could not be located or could not be matched with a known trust anchor".
    // \~spanish "no se pudo encontrar el certificado de la CA o no casaba con un ancla de confianza conocida".  \~
    case Trust::UnknownIssuer: return Alert::UnknownCa;
    // \~english "has expired or is not currently valid".  \~spanish "ha caducado o no es valido ahora".  \~
    case Trust::Expired: return Alert::CertificateExpired;
    case Trust::Revoked: return Alert::CertificateRevoked;
    // \~english "contained signatures that did not verify correctly", or corrupt.
    // \~spanish "contenia firmas que no verificaban", o corrupto.  \~
    case Trust::BadSignature:
    case Trust::Invalid: return Alert::BadCertificate;
    case Trust::Unsupported: return Alert::UnsupportedCertificate;
    // \~english The rest: "some other (unspecified) issue ... rendering it unacceptable".
    // \~spanish El resto: "algun otro problema (sin especificar) ... que lo hace inaceptable".  \~
    case Trust::RevocationUnknown:
    case Trust::NameMismatch:
    case Trust::WrongUsage:
    case Trust::Rejected: return Alert::CertificateUnknown;
    case Trust::Failed: return Alert::InternalError;
    }
    return Alert::InternalError;
}

const char *trust_name(Trust t) noexcept {
    switch (t) {
    case Trust::Trusted:           return "trusted";
    case Trust::UnknownIssuer:     return "unknown issuer";
    case Trust::Expired:           return "expired or not yet valid";
    case Trust::Revoked:           return "revoked";
    case Trust::RevocationUnknown: return "revocation unknown";
    case Trust::NameMismatch:      return "name mismatch";
    case Trust::WrongUsage:        return "wrong usage";
    case Trust::BadSignature:      return "bad signature";
    case Trust::Invalid:           return "invalid";
    case Trust::Unsupported:       return "unsupported";
    case Trust::Rejected:          return "rejected";
    case Trust::Failed:            return "verifier failed";
    }
    return "unknown";
}

} // namespace tls
} // namespace http_vx
