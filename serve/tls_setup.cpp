/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/tls_setup.cpp
 * @brief
 * \~english The provider by name, and PEM or DER files turned into a chain and a signing key.
 * \~spanish El proveedor por nombre, y ficheros PEM o DER convertidos en una cadena y una clave de firma.
 * \~
 */

#include "serve/tls_setup.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <cstdio>
#include <cstring>
#include <new>

namespace serve {

namespace {

constexpr uint8_t kNone = 0;
constexpr uint8_t kOpenssl = 1;
constexpr uint8_t kCng = 2;

/// \~english The largest file read: certificates and keys are a few kilobytes.  \~spanish El fichero mas grande que se lee: certificados y claves son unos pocos kilobytes.  \~
constexpr size_t kMaxFile = 1u << 20;

/// \~english A whole file into memory; null if it cannot be read or is too large.  \~spanish Un fichero entero a memoria; nulo si no se puede leer o es demasiado grande.  \~
uint8_t *read_file(const char *path, size_t &n) noexcept {
    std::FILE *f = std::fopen(path, "rb");
    if (f == nullptr) return nullptr;
    uint8_t *buf = static_cast<uint8_t *>(util::host_alloc(kMaxFile + 1));
    n = buf != nullptr ? std::fread(buf, 1, kMaxFile + 1, f) : 0;
    std::fclose(f);
    if (buf != nullptr && (n == 0 || n > kMaxFile)) {
        util::host_free(buf);
        return nullptr;
    }
    return buf;
}

/// \~english The value of one base64 character, 64 for whitespace to skip, 65 for anything else.
/// \~spanish El valor de un caracter base64, 64 para el espacio que se salta, 65 para cualquier otra cosa.  \~
uint8_t b64(uint8_t ch) noexcept {
    if (ch >= 'A' && ch <= 'Z') return static_cast<uint8_t>(ch - 'A');
    if (ch >= 'a' && ch <= 'z') return static_cast<uint8_t>(ch - 'a' + 26);
    if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0' + 52);
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t') return 64;
    return 65;
}

/// \~english Decodes base64 in place over itself (the output is shorter); its size, or 0 if it is not base64.
/// \~spanish Decodifica base64 en su sitio sobre si mismo (la salida es mas corta); su tamano, o 0 si no es base64.  \~
size_t unbase64(uint8_t *p, size_t n) noexcept {
    size_t out = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == '=') break;
        const uint8_t v = b64(p[i]);
        if (v == 64) continue;
        if (v == 65) return 0;
        acc = acc << 6 | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            p[out++] = static_cast<uint8_t>(acc >> bits);
        }
    }
    return out;
}

/// \~english Where @p needle first is in @p hay from @p from, or @p n.  \~spanish Donde esta primero @p needle en @p hay desde @p from, o @p n.  \~
size_t find(const uint8_t *hay, size_t n, size_t from, const char *needle) noexcept {
    const size_t k = std::strlen(needle);
    for (size_t i = from; i + k <= n; ++i)
        if (std::memcmp(hay + i, needle, k) == 0) return i;
    return n;
}

/**
 * @brief
 * \~english The next PEM block labelled @p label from @p at, decoded in place; false when there is none.
 * \~spanish El siguiente bloque PEM con la etiqueta @p label desde @p at, decodificado en su sitio; falso cuando no hay.
 * \~
 */
bool next_block(uint8_t *file, size_t n, size_t &at, const char *label, uint8_t *&der, size_t &len) noexcept {
    char begin[64];
    char end[64];
    std::snprintf(begin, sizeof begin, "-----BEGIN %s-----", label);
    std::snprintf(end, sizeof end, "-----END %s-----", label);
    const size_t b = find(file, n, at, begin);
    if (b == n) return false;
    const size_t body = b + std::strlen(begin);
    const size_t e = find(file, n, body, end);
    if (e == n) return false;
    at = e + std::strlen(end);
    der = file + body;
    len = unbase64(der, e - body);
    return len != 0;
}

/**
 * \~english
 * The providers this build has, the default first, ending in null: their
 * names are the providers' own (@c kName), so a name typed on the command
 * line and a name printed in a message are the same string.
 * \~spanish
 * Los proveedores que tiene esta construccion, el de por defecto primero,
 * acabados en nulo: sus nombres son los de los propios proveedores (@c kName),
 * asi que un nombre tecleado en la linea de ordenes y uno impreso en un mensaje
 * son la misma cadena.
 * \~
 */
const char *const kProviders[] = {
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto::kName,
#endif
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto::kName,
#endif
    nullptr,
};

} // namespace

bool TlsSetup::has(const char *name) noexcept {
    for (const char *const *p = kProviders; *p != nullptr; ++p)
        if (std::strcmp(name, *p) == 0) return true;
    return false;
}

void TlsSetup::print_names(std::FILE *out) noexcept {
    if (kProviders[0] == nullptr) {
        std::fprintf(out, "none");
        return;
    }
    for (const char *const *p = kProviders; *p != nullptr; ++p)
        std::fprintf(out, "%s%s", p == kProviders ? "" : ", ", *p);
}

TlsSetup::~TlsSetup() {
    http_vx::wipe_secret(ticket_key_, sizeof ticket_key_);
    if (sealer_ != nullptr) {
        sealer_->~TicketSealer();
        util::host_free(sealer_);
    }
    if (crypto_ != nullptr) crypto_->forget_key(key_);
#if HTTP_VX_HAVE_OPENSSL
    if (kind_ == kOpenssl) static_cast<http_vx::OpensslCrypto *>(provider_mem_)->~OpensslCrypto();
#endif
#if HTTP_VX_HAVE_CNG
    if (kind_ == kCng) static_cast<http_vx::CngCrypto *>(provider_mem_)->~CngCrypto();
#endif
    if (provider_mem_ != nullptr) util::host_free(provider_mem_);
    if (file_ != nullptr) util::host_free(file_);
    if (key_der_ != nullptr) {
        http_vx::wipe_secret(key_der_, key_len_);
        util::host_free(key_der_);
    }
}

bool TlsSetup::choose(const char *name) noexcept {
    const bool any = name == nullptr;
#if HTTP_VX_HAVE_CNG
    // \~english On Windows the system's own comes first: nothing to install (section 9).
    // \~spanish En Windows va primero el del propio sistema: nada que instalar (seccion 9).  \~
    if (any || std::strcmp(name, http_vx::CngCrypto::kName) == 0) {
        provider_mem_ = util::host_alloc(sizeof(http_vx::CngCrypto));
        if (provider_mem_ == nullptr) return false;
        http_vx::CngCrypto *cng = new (provider_mem_) http_vx::CngCrypto();
        kind_ = kCng;
        if (!cng->ready()) {
            why_ = "the cng provider is not ready: the system refused an algorithm";
            return false;
        }
        crypto_ = cng;
        return true;
    }
#endif
#if HTTP_VX_HAVE_OPENSSL
    if (any || std::strcmp(name, http_vx::OpensslCrypto::kName) == 0) {
        provider_mem_ = util::host_alloc(sizeof(http_vx::OpensslCrypto));
        if (provider_mem_ == nullptr) return false;
        http_vx::OpensslCrypto *ossl = new (provider_mem_) http_vx::OpensslCrypto();
        kind_ = kOpenssl;
        if (!ossl->ready()) {
            why_ = "the openssl provider is not ready: its HKDF could not be fetched";
            return false;
        }
        crypto_ = ossl;
        return true;
    }
#endif
    (void)any;
    why_ = kind_ == kNone && name == nullptr
               ? "this build has no cryptographic provider, and TLS is not served in the clear instead (R24)"
               : "this build has no provider by that name";
    return false;
}

bool TlsSetup::load(const char *name, const char *cert_path, const char *key_path,
                    const uint8_t *ticket_key) noexcept {
    if (!choose(name)) {
        if (why_ == nullptr) why_ = "no memory for the provider";
        return false;
    }

    // \~english The chain: every CERTIFICATE block, or the whole file as one DER certificate.
    // \~spanish La cadena: cada bloque CERTIFICATE, o el fichero entero como un certificado DER.  \~
    size_t n = 0;
    file_ = read_file(cert_path, n);
    if (file_ == nullptr) {
        why_ = "the certificate file cannot be read";
        return false;
    }
    size_t at = 0;
    uint8_t *der = nullptr;
    size_t len = 0;
    while (count_ < kMaxChain && next_block(file_, n, at, "CERTIFICATE", der, len)) {
        certs_[count_] = der;
        lens_[count_] = len;
        ++count_;
    }
    if (count_ == 0 && find(file_, n, 0, "-----BEGIN") == n) {
        certs_[0] = file_;
        lens_[0] = n;
        count_ = 1;
    }
    if (count_ == 0) {
        why_ = "the certificate file holds no CERTIFICATE block";
        return false;
    }

    // \~english The key: PKCS#8 only; the older PEM kinds are named, so the fix can be too.
    // \~spanish La clave: solo PKCS#8; los tipos PEM mas viejos se nombran, para que se pueda nombrar el arreglo.  \~
    key_der_ = read_file(key_path, key_len_);
    if (key_der_ == nullptr) {
        why_ = "the key file cannot be read";
        return false;
    }
    if (find(key_der_, key_len_, 0, "-----BEGIN") != key_len_) {
        if (find(key_der_, key_len_, 0, "-----BEGIN EC PRIVATE KEY") != key_len_ ||
            find(key_der_, key_len_, 0, "-----BEGIN RSA PRIVATE KEY") != key_len_) {
            why_ = "the key is not PKCS#8: convert it with openssl pkcs8 -topk8 -nocrypt";
            return false;
        }
        size_t k = 0;
        uint8_t *kder = nullptr;
        size_t klen = 0;
        if (!next_block(key_der_, key_len_, k, "PRIVATE KEY", kder, klen)) {
            why_ = "the key file holds no PRIVATE KEY block (an encrypted key is not read)";
            return false;
        }
        util::vesta_memmove(key_der_, kder, klen);
        key_len_ = klen;
    }
    // \~english The scheme is the key's: P-256 first, then RSA-PSS.  \~spanish El esquema es el de la clave: P-256 primero, luego RSA-PSS.  \~
    key_ = crypto_->signing_key(http_vx::quic::Scheme::EcdsaSecp256r1Sha256, key_der_, key_len_);
    scheme_ = http_vx::quic::Scheme::EcdsaSecp256r1Sha256;
    if (key_ == nullptr) {
        key_ = crypto_->signing_key(http_vx::quic::Scheme::RsaPssRsaeSha256, key_der_, key_len_);
        scheme_ = http_vx::quic::Scheme::RsaPssRsaeSha256;
    }
    if (key_ == nullptr) {
        why_ = "the provider does not take the key: a PKCS#8 P-256 or RSA key is needed";
        return false;
    }

    // \~english Tickets, sealed with a key that never leaves this process (tls_ticket.h).
    // \~spanish Tickets, sellados con una clave que nunca sale de este proceso (tls_ticket.h).  \~
    // \~english With several shards the key is made once and given to each, or a ticket one shard issued would be refused by the next.
    // \~spanish Con varios fragmentos la clave se hace una vez y se da a cada uno, o un ticket que emitio un fragmento lo rechazaria el siguiente.  \~
    if (ticket_key != nullptr) {
        util::vesta_memcpy(ticket_key_, ticket_key, sizeof ticket_key_);
    } else if (!crypto_->random(ticket_key_, sizeof ticket_key_)) {
        why_ = "the provider gave no random bytes for the ticket key";
        return false;
    }
    void *mem = util::host_alloc(sizeof(http_vx::tls::TicketSealer));
    if (mem != nullptr) sealer_ = new (mem) http_vx::tls::TicketSealer(*crypto_, ticket_key_);
    if (sealer_ == nullptr || !sealer_->ready()) {
        why_ = "the ticket key could not be prepared";
        return false;
    }
    return true;
}

} // namespace serve
