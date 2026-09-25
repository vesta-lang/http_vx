/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file cng_verify.cpp
 * @brief
 * \~english CngVerifier: CertGetCertificateChain, then CertVerifyCertificateChainPolicy with the SSL policy.
 * \~spanish CngVerifier: CertGetCertificateChain, y luego CertVerifyCertificateChainPolicy con la politica SSL.
 * \~
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
// \~english The fields of CERT_CHAIN_PARA past the usage: the strong-signature parameters among them.
// \~spanish Los campos de CERT_CHAIN_PARA tras el uso: entre ellos los de firma fuerte.  \~
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include <windows.h>

#include <wincrypt.h>

#include "cng_verify.h"

namespace http_vx {

using tls::Trust;
using tls::Verdict;

namespace {

constexpr DWORD kEncoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

/// \~english A verdict and the system's code.  \~spanish Un veredicto y el codigo del sistema.  \~
Verdict verdict(Trust t, DWORD code) noexcept {
    Verdict v;
    v.trust = t;
    v.code = static_cast<uint32_t>(code);
    return v;
}

/**
 * @brief
 * \~english The SSL policy's error, as a verdict.  \~spanish El error de la politica SSL, como veredicto.
 * \~
 */
Trust policy_trust(DWORD e) noexcept {
    switch (static_cast<HRESULT>(e)) {
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
    case CERT_E_UNTRUSTEDTESTROOT:
    case CERT_E_UNTRUSTEDCA: return Trust::UnknownIssuer;
    case CERT_E_EXPIRED:
    case CERT_E_VALIDITYPERIODNESTING: return Trust::Expired;
    case CRYPT_E_REVOKED: return Trust::Revoked;
    case CRYPT_E_NO_REVOCATION_CHECK:
    case CRYPT_E_REVOCATION_OFFLINE:
    case CERT_E_REVOCATION_FAILURE: return Trust::RevocationUnknown;
    case CERT_E_CN_NO_MATCH:
    case CERT_E_INVALID_NAME: return Trust::NameMismatch;
    case CERT_E_WRONG_USAGE:
    case CERT_E_ROLE: return Trust::WrongUsage;
    case TRUST_E_CERT_SIGNATURE: return Trust::BadSignature;
    case TRUST_E_BASIC_CONSTRAINTS:
    case CERT_E_MALFORMED:
    case CERT_E_CRITICAL:
    case CERT_E_PATHLENCONST: return Trust::Invalid;
    default: return Trust::Rejected;
    }
}

/**
 * @brief
 * \~english Whether @p n bytes are one DER SEQUENCE, all of them: the system takes a certificate with bytes after it.
 * \~spanish Si @p n bytes son un SEQUENCE DER, todos: el sistema acepta un certificado con bytes detras.
 * \~
 *
 * \~english
 * Only the outer frame is read -- tag, length -- and the rest is left to
 * the system.  Bytes after a certificate would make the entry mean two
 * things: what the system judged, and what was sent.
 * \~spanish
 * Solo se lee el marco exterior -- etiqueta, longitud -- y el resto se deja al
 * sistema.  Bytes tras un certificado harian que la entrada significara dos
 * cosas: lo que juzgo el sistema, y lo que se mando.
 * \~
 */
bool whole_der(const uint8_t *p, size_t n) noexcept {
    if (n < 2 || p[0] != 0x30) return false;
    size_t len = p[1];
    size_t head = 2;
    if ((len & 0x80) != 0) {
        const size_t k = len & 0x7f;
        // \~english Long form: 1 to 4 length bytes, the first not zero (DER is minimal).
        // \~spanish Forma larga: de 1 a 4 bytes de longitud, el primero distinto de cero (DER es minimo).  \~
        if (k == 0 || k > 4 || n < 2 + k || p[2] == 0) return false;
        len = 0;
        for (size_t i = 0; i < k; ++i) len = (len << 8) | p[2 + i];
        if (len < 0x80) return false;
        head += k;
    }
    return len == n - head;
}

/// \~english Seconds since 1970 as a FILETIME: 100 ns ticks since 1601.  \~spanish Segundos desde 1970 como FILETIME: ticks de 100 ns desde 1601.  \~
FILETIME filetime(uint64_t unix_s) noexcept {
    const uint64_t ticks = (unix_s + 11644473600ull) * 10000000ull;
    FILETIME f;
    f.dwLowDateTime = static_cast<DWORD>(ticks);
    f.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    return f;
}

} // namespace

CngVerifier::CngVerifier() noexcept = default;

CngVerifier::~CngVerifier() {
    if (engine_ != nullptr) CertFreeCertificateChainEngine(static_cast<HCERTCHAINENGINE>(engine_));
    if (anchors_ != nullptr) CertCloseStore(static_cast<HCERTSTORE>(anchors_), 0);
}

bool CngVerifier::add_anchor(const uint8_t *der, size_t n) noexcept {
    if (der == nullptr || n == 0 || n > 0xffffffffu) return false;
    if (anchors_ == nullptr) {
        anchors_ = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
        if (anchors_ == nullptr) return false;
    }
    if (!CertAddEncodedCertificateToStore(static_cast<HCERTSTORE>(anchors_), kEncoding, der, static_cast<DWORD>(n),
                                          CERT_STORE_ADD_USE_EXISTING, nullptr))
        return false;
    // \~english An engine reads its anchors when it is made: a new one is needed.
    // \~spanish Un motor lee sus anclas al hacerse: hace falta uno nuevo.  \~
    stale_ = true;
    return true;
}

bool CngVerifier::engine() noexcept {
    if (!stale_) return true;
    if (engine_ != nullptr) {
        CertFreeCertificateChainEngine(static_cast<HCERTCHAINENGINE>(engine_));
        engine_ = nullptr;
    }
    CERT_CHAIN_ENGINE_CONFIG cfg;
    ZeroMemory(&cfg, sizeof cfg);
    cfg.cbSize = sizeof cfg;
    // \~english The added anchors, and only them: the system's roots do not count (Windows 7 and later).
    // \~spanish Las anclas anadidas, y solo ellas: las raices del sistema no cuentan (Windows 7 y posteriores).  \~
    cfg.hExclusiveRoot = static_cast<HCERTSTORE>(anchors_);
    cfg.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    HCERTCHAINENGINE e = nullptr;
    if (!CertCreateCertificateChainEngine(&cfg, &e)) return false;
    engine_ = e;
    stale_ = false;
    return true;
}

Verdict CngVerifier::verify(const tls::Chain &chain, tls::Role role, const char *host) noexcept {
    if (chain.count == 0 || chain.certs == nullptr || chain.lens == nullptr) return verdict(Trust::Invalid, 0);
    for (size_t i = 0; i < chain.count; ++i)
        if (chain.lens[i] > 0xffffffffu || !whole_der(chain.certs[i], chain.lens[i])) return verdict(Trust::Invalid, 0);

    // \~english The name, as the policy wants it: wide.  A DNS name is ASCII (A-labels) and at most 253 bytes.
    // \~spanish El nombre, como lo quiere la politica: ancho.  Un nombre DNS es ASCII (etiquetas A) y de 253 bytes como mucho.  \~
    WCHAR name[256];
    if (host != nullptr) {
        size_t i = 0;
        for (; host[i] != '\0'; ++i) {
            const unsigned char ch = static_cast<unsigned char>(host[i]);
            if (i == 253 || ch > 0x7f) return verdict(Trust::Failed, ERROR_INVALID_PARAMETER);
            name[i] = static_cast<WCHAR>(ch);
        }
        name[i] = 0;
    }
    if (!engine()) return verdict(Trust::Failed, GetLastError());

    PCCERT_CONTEXT leaf = CertCreateCertificateContext(kEncoding, chain.certs[0], static_cast<DWORD>(chain.lens[0]));
    if (leaf == nullptr) return verdict(Trust::Invalid, GetLastError());
    // \~english What came after the leaf, for the engine to build a path with.
    // \~spanish Lo que vino tras la hoja, para que el motor construya un camino con ello.  \~
    HCERTSTORE sent = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (sent == nullptr) {
        const DWORD e = GetLastError();
        CertFreeCertificateContext(leaf);
        return verdict(Trust::Failed, e);
    }
    for (size_t i = 1; i < chain.count; ++i)
        if (!CertAddEncodedCertificateToStore(sent, kEncoding, chain.certs[i], static_cast<DWORD>(chain.lens[i]),
                                              CERT_STORE_ADD_ALWAYS, nullptr)) {
            const DWORD e = GetLastError();
            CertCloseStore(sent, 0);
            CertFreeCertificateContext(leaf);
            return verdict(Trust::Invalid, e);
        }

    // \~english The use asked of the leaf, and signatures no weaker than the system's strong set.
    // \~spanish El uso que se pide a la hoja, y firmas no mas debiles que el conjunto fuerte del sistema.  \~
    char server_auth[] = szOID_PKIX_KP_SERVER_AUTH;
    char client_auth[] = szOID_PKIX_KP_CLIENT_AUTH;
    LPSTR usage[1] = {role == tls::Role::Server ? server_auth : client_auth};
    char strong_oid[] = szOID_CERT_STRONG_SIGN_OS_1;
    CERT_STRONG_SIGN_PARA strong;
    ZeroMemory(&strong, sizeof strong);
    strong.cbSize = sizeof strong;
    strong.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
    strong.pszOID = strong_oid;
    CERT_CHAIN_PARA para;
    ZeroMemory(&para, sizeof para);
    para.cbSize = sizeof para;
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
    para.pStrongSignPara = &strong;
    DWORD flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    if (revocation_) flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
    FILETIME when = filetime(time_);

    PCCERT_CHAIN_CONTEXT built = nullptr;
    const BOOL got = CertGetCertificateChain(static_cast<HCERTCHAINENGINE>(engine_), leaf, time_ != 0 ? &when : nullptr,
                                             sent, &para, flags, nullptr, &built);
    const DWORD built_error = GetLastError();
    CertCloseStore(sent, 0);
    CertFreeCertificateContext(leaf);
    if (!got || built == nullptr) return verdict(Trust::Failed, built_error);

    const DWORD status = built->TrustStatus.dwErrorStatus;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl;
    ZeroMemory(&ssl, sizeof ssl);
    ssl.cbSize = sizeof ssl;
    ssl.dwAuthType = role == tls::Role::Server ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT;
    ssl.pwszServerName = host != nullptr ? name : nullptr;
    CERT_CHAIN_POLICY_PARA policy;
    ZeroMemory(&policy, sizeof policy);
    policy.cbSize = sizeof policy;
    policy.pvExtraPolicyPara = &ssl;
    CERT_CHAIN_POLICY_STATUS result;
    ZeroMemory(&result, sizeof result);
    result.cbSize = sizeof result;
    const BOOL checked = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, built, &policy, &result);
    const DWORD policy_error = GetLastError();
    CertFreeCertificateChain(built);
    if (!checked) return verdict(Trust::Failed, policy_error);
    if (result.dwError == 0) {
        // \~english The policy passed what the chain itself flagged: not trusted, with the chain's status as the reason.
        // \~spanish La politica dejo pasar lo que marco la propia cadena: no es de fiar, con el estado de la cadena como razon.  \~
        if (status != CERT_TRUST_NO_ERROR) return verdict(Trust::Rejected, status);
        return verdict(Trust::Trusted, 0);
    }
    return verdict(policy_trust(result.dwError), result.dwError);
}

} // namespace http_vx
