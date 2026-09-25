/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file openssl_verify.cpp
 * @brief
 * \~english OpensslVerifier: an X509_STORE_CTX per chain, and X509_verify_cert.
 * \~spanish OpensslVerifier: un X509_STORE_CTX por cadena, y X509_verify_cert.
 * \~
 */
#include "openssl_verify.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <climits>
#include <ctime>

namespace http_vx {

using tls::Trust;
using tls::Verdict;

namespace {

Verdict verdict(Trust t, long code) noexcept {
    Verdict v;
    v.trust = t;
    v.code = static_cast<uint32_t>(code);
    return v;
}

/**
 * @brief
 * \~english X509_verify_cert's error, as a verdict.  \~spanish El error de X509_verify_cert, como veredicto.
 * \~
 */
Trust error_trust(int e) noexcept {
    switch (e) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_CERT_UNTRUSTED: return Trust::UnknownIssuer;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED: return Trust::Expired;
    case X509_V_ERR_CERT_REVOKED: return Trust::Revoked;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: return Trust::RevocationUnknown;
    case X509_V_ERR_HOSTNAME_MISMATCH: return Trust::NameMismatch;
    case X509_V_ERR_INVALID_PURPOSE:
    case X509_V_ERR_CERT_REJECTED:
    case X509_V_ERR_KEYUSAGE_NO_CERTSIGN: return Trust::WrongUsage;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_CA_MD_TOO_WEAK:
    case X509_V_ERR_CA_KEY_TOO_SMALL:
    case X509_V_ERR_EE_KEY_TOO_SMALL: return Trust::BadSignature;
    case X509_V_ERR_INVALID_CA:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_INVALID_EXTENSION:
    case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
    case X509_V_ERR_INVALID_NON_CA: return Trust::Invalid;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM: return Trust::Unsupported;
    case X509_V_ERR_OUT_OF_MEM: return Trust::Failed;
    default: return Trust::Rejected;
    }
}

/// \~english One DER certificate, all of it: bytes left over mean it is not one.
/// \~spanish Un certificado DER, entero: bytes de sobra quieren decir que no lo es.  \~
X509 *parse(const uint8_t *der, size_t n) noexcept {
    if (der == nullptr || n == 0 || n > static_cast<size_t>(LONG_MAX)) return nullptr;
    const unsigned char *p = der;
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(n));
    if (x != nullptr && p != der + n) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

} // namespace

OpensslVerifier::OpensslVerifier() noexcept {
    X509_STORE *s = X509_STORE_new();
    if (s == nullptr) return;
    // \~english The anchors the library was built to find: on a distribution, its own.
    // \~spanish Las anclas que la biblioteca sabe encontrar: en una distribucion, las suyas.  \~
    if (X509_STORE_set_default_paths(s) != 1) {
        X509_STORE_free(s);
        return;
    }
    store_ = s;
}

OpensslVerifier::~OpensslVerifier() {
    if (store_ != nullptr) X509_STORE_free(static_cast<X509_STORE *>(store_));
}

bool OpensslVerifier::add_anchor(const uint8_t *der, size_t n) noexcept {
    X509 *x = parse(der, n);
    if (x == nullptr) return false;
    // \~english The first anchor added replaces the default ones: a private PKI does not also trust the world.
    // \~spanish El primer ancla anadida sustituye a las de por defecto: una PKI privada no se fia ademas del mundo.  \~
    if (!own_anchors_) {
        X509_STORE *s = X509_STORE_new();
        if (s == nullptr) {
            X509_free(x);
            return false;
        }
        if (store_ != nullptr) X509_STORE_free(static_cast<X509_STORE *>(store_));
        store_ = s;
        own_anchors_ = true;
    }
    const int added = X509_STORE_add_cert(static_cast<X509_STORE *>(store_), x);
    X509_free(x);
    return added == 1;
}

Verdict OpensslVerifier::verify(const tls::Chain &chain, tls::Role role, const char *host) noexcept {
    if (store_ == nullptr) return verdict(Trust::Failed, 0);
    if (chain.count == 0 || chain.certs == nullptr || chain.lens == nullptr) return verdict(Trust::Invalid, 0);
    X509 *leaf = parse(chain.certs[0], chain.lens[0]);
    if (leaf == nullptr) return verdict(Trust::Invalid, 0);
    STACK_OF(X509) *sent = sk_X509_new_null();
    if (sent == nullptr) {
        X509_free(leaf);
        return verdict(Trust::Failed, X509_V_ERR_OUT_OF_MEM);
    }
    for (size_t i = 1; i < chain.count; ++i) {
        X509 *x = parse(chain.certs[i], chain.lens[i]);
        if (x == nullptr || sk_X509_push(sent, x) == 0) {
            if (x != nullptr) X509_free(x);
            sk_X509_pop_free(sent, X509_free);
            X509_free(leaf);
            return verdict(x == nullptr ? Trust::Invalid : Trust::Failed, 0);
        }
    }

    Verdict out = verdict(Trust::Failed, X509_V_ERR_OUT_OF_MEM);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx != nullptr && X509_STORE_CTX_init(ctx, static_cast<X509_STORE *>(store_), leaf, sent) == 1) {
        X509_VERIFY_PARAM *vp = X509_STORE_CTX_get0_param(ctx);
        // \~english The use asked of the leaf; weak signatures out (4.4.2.4); the name, matched as the library matches it.
        // \~spanish El uso que se pide a la hoja; fuera las firmas debiles (4.4.2.4); el nombre, comparado como lo compara la biblioteca.  \~
        bool set = X509_VERIFY_PARAM_set_purpose(vp, role == tls::Role::Server ? X509_PURPOSE_SSL_SERVER
                                                                               : X509_PURPOSE_SSL_CLIENT) == 1;
        X509_VERIFY_PARAM_set_auth_level(vp, 1);
        if (time_ != 0) X509_VERIFY_PARAM_set_time(vp, static_cast<time_t>(time_));
        if (revocation_) set = set && X509_VERIFY_PARAM_set_flags(vp, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1;
        if (host != nullptr) set = set && X509_VERIFY_PARAM_set1_host(vp, host, 0) == 1;
        if (!set) {
            out = verdict(Trust::Failed, 0);
        } else {
            const int r = X509_verify_cert(ctx);
            if (r == 1) {
                out = verdict(Trust::Trusted, 0);
            } else {
                const int e = X509_STORE_CTX_get_error(ctx);
                // \~english A failure with no error recorded is the verifier's own, not the chain's.
                // \~spanish Un fallo sin error apuntado es del propio verificador, no de la cadena.  \~
                out = r < 0 || e == X509_V_OK ? verdict(Trust::Failed, e) : verdict(error_trust(e), e);
            }
        }
    }
    if (ctx != nullptr) X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(sent, X509_free);
    X509_free(leaf);
    return out;
}

} // namespace http_vx
