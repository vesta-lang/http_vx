/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_verify.cpp
 * @brief
 * \~english The certificate verifiers against a small PKI: each verdict, from each library that gives it.
 * \~spanish Los verificadores de certificados contra una PKI pequena: cada veredicto, de cada biblioteca que lo da.
 * \~
 *
 * \~english
 * The same chains go to every verifier built here -- the Windows chain
 * engine, OpenSSL's X509_verify_cert -- and each must say the same thing:
 * trusted through the intermediate, and for each way a chain can be wrong,
 * the verdict that names it.  Then a whole handshake, real signatures and a
 * real verifier, ends complete or with the alert of its verdict.
 * \~spanish
 * Las mismas cadenas van a cada verificador construido aqui -- el motor de
 * cadenas de Windows, X509_verify_cert de OpenSSL -- y cada uno debe decir lo
 * mismo: de fiar a traves de la intermedia, y para cada forma en que una cadena
 * puede estar mal, el veredicto que la nombra.  Despues un saludo entero, firmas
 * de verdad y un verificador de verdad, acaba completo o con la alerta de su
 * veredicto.
 * \~
 */

#include "http_vx/tls_session.h"
#include "http_vx/tls_verify.h"

#include "tls_rfc8448.h"
#include "tls_test_certs.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#include "openssl_verify.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#include "cng_verify.h"
#endif

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::tls;
using http_vx::quic::Crypto;
using rfc8448::from_hex;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *provider, const char *name) {
    std::snprintf(current, sizeof current, "%s: %s", provider, name);
}

/// \~english A certificate from hex.  \~spanish Un certificado a partir de hex.  \~
struct Der {
    uint8_t b[1024];
    size_t n;
    explicit Der(const char *hex) : n(from_hex(hex, b, sizeof b)) {}
};

/// \~english The PKI of tls_test_certs.h, as bytes.  \~spanish La PKI de tls_test_certs.h, como bytes.  \~
struct Pki {
    Der root{test_certs::kRoot};
    Der other{test_certs::kOther};
    Der inter{test_certs::kIntermediate};
    Der leaf{test_certs::kLeaf};
    Der leaf_sha1{test_certs::kLeafSha1};
    Der client{test_certs::kClient};
    Der key{test_certs::kLeafKey};
};

/// \~english The verdict on up to three certificates.  \~spanish El veredicto sobre hasta tres certificados.  \~
Verdict ask(CertVerifier &v, Role role, const char *host, const Der *a, const Der *b = nullptr,
            const Der *c = nullptr) {
    const Der *all[3] = {a, b, c};
    const uint8_t *certs[3];
    size_t lens[3];
    Chain chain;
    for (const Der *d : all) {
        if (d == nullptr) break;
        certs[chain.count] = d->b;
        lens[chain.count] = d->n;
        ++chain.count;
    }
    chain.certs = certs;
    chain.lens = lens;
    return v.verify(chain, role, host);
}

void expect(const Verdict &got, Trust want, const char *what) {
    if (got.trust == want) return;
    std::fprintf(stderr, "FAIL [%s]: %s: want %s, got %s (code 0x%lx)\n", current, what, trust_name(want),
                 trust_name(got.trust), static_cast<unsigned long>(got.code));
    ++failures;
}

/**
 * @brief
 * \~english Every verdict one verifier class gives for the PKI; @p V has add_anchor, set_time and check_revocation.
 * \~spanish Cada veredicto que da una clase de verificador para la PKI; @p V tiene add_anchor, set_time y check_revocation.
 * \~
 */
template <class V>
void run(const char *provider) {
    const Pki p;
    section(provider, "anchors");
    {
        V v;
        check(!v.add_anchor(p.root.b, p.root.n - 1), "a cut certificate is no anchor");
        check(!v.add_anchor(nullptr, 0), "nor is nothing");
    }
    {
        // \~english The system's anchors: our private root is not among them.
        // \~spanish Las anclas del sistema: nuestra raiz privada no esta entre ellas.  \~
        V v;
        v.set_time(test_certs::kDuring);
        expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::UnknownIssuer,
               "a private chain against the system's anchors");
    }

    V v;
    check(v.add_anchor(p.root.b, p.root.n), "the test root is an anchor");
    v.set_time(test_certs::kDuring);

    section(provider, "trusted");
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::Trusted, "leaf, intermediate, anchor");
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter, &p.root), Trust::Trusted, "with the root sent too");
    expect(ask(v, Role::Server, "EXAMPLE.com", &p.leaf, &p.inter), Trust::Trusted, "a name is not case sensitive");
    expect(ask(v, Role::Server, nullptr, &p.leaf, &p.inter), Trust::Trusted, "with no name to check");
    expect(ask(v, Role::Client, nullptr, &p.client, &p.inter), Trust::Trusted, "a client's chain, as a client's");
    const Verdict ok = ask(v, Role::Server, "example.com", &p.leaf, &p.inter);
    check(ok.code == 0, "trusted carries no error code");

    section(provider, "issuer");
    expect(ask(v, Role::Server, "example.com", &p.leaf), Trust::UnknownIssuer, "the intermediate not sent (4.4.2)");
    {
        V w;
        check(w.add_anchor(p.other.b, p.other.n), "another root is an anchor");
        w.set_time(test_certs::kDuring);
        expect(ask(w, Role::Server, "example.com", &p.leaf, &p.inter), Trust::UnknownIssuer,
               "an anchor that signed nothing here, and only it: the system's do not count");
        const Verdict u = ask(w, Role::Server, "example.com", &p.leaf, &p.inter);
        check(u.code != 0, "and the library says why");
    }

    section(provider, "time");
    v.set_time(test_certs::kAfter);
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::Expired, "after the leaf expired");
    v.set_time(test_certs::kBefore);
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::Expired, "before any was valid");
    v.set_time(test_certs::kDuring);

    section(provider, "name");
    expect(ask(v, Role::Server, "other.example", &p.leaf, &p.inter), Trust::NameMismatch, "another name");
    expect(ask(v, Role::Server, "www.example.com", &p.leaf, &p.inter), Trust::NameMismatch, "a name under it");
    expect(ask(v, Role::Server, "example.co", &p.leaf, &p.inter), Trust::NameMismatch, "a prefix of it");
    const Der wild(test_certs::kWildcard);
    expect(ask(v, Role::Server, "a.example.com", &wild, &p.inter), Trust::Trusted, "a wildcard, one label");
    expect(ask(v, Role::Server, "a.b.example.com", &wild, &p.inter), Trust::NameMismatch,
           "a wildcard covers one label, not two");
    expect(ask(v, Role::Server, "example.com", &wild, &p.inter), Trust::NameMismatch, "nor none");
    // \~english A partial wildcard is the library's call, not this code's; both honour it by default.
    // \~spanish Un comodin parcial lo decide la biblioteca, no este codigo; las dos lo aceptan por defecto.  \~
    expect(ask(v, Role::Server, "www.example.org", &wild, &p.inter), Trust::Trusted,
           "a partial wildcard, as the library decides it");
    expect(ask(v, Role::Server, "www.example.net", &wild, &p.inter), Trust::NameMismatch,
           "but not under another domain");

    section(provider, "usage");
    expect(ask(v, Role::Client, nullptr, &p.leaf, &p.inter), Trust::WrongUsage, "a server's leaf as a client's");
    expect(ask(v, Role::Server, nullptr, &p.client, &p.inter), Trust::WrongUsage, "a client's leaf as a server's");

    section(provider, "signature");
    expect(ask(v, Role::Server, "example.com", &p.leaf_sha1, &p.inter), Trust::BadSignature,
           "a leaf signed with SHA-1 (4.4.2.4)");
    Der changed = p.leaf;
    changed.b[changed.n - 1] ^= 0x01;
    expect(ask(v, Role::Server, "example.com", &changed, &p.inter), Trust::BadSignature,
           "a leaf whose signature was changed");

    section(provider, "corrupt");
    Der cut = p.leaf;
    cut.n -= 10;
    expect(ask(v, Role::Server, "example.com", &cut, &p.inter), Trust::Invalid, "a cut leaf");
    Der cut_inter = p.inter;
    cut_inter.n -= 10;
    expect(ask(v, Role::Server, "example.com", &p.leaf, &cut_inter), Trust::Invalid, "a cut intermediate");
    Der longer = p.leaf;
    longer.b[longer.n++] = 0;
    expect(ask(v, Role::Server, "example.com", &longer, &p.inter), Trust::Invalid, "a leaf with a byte after it");
    Der longer_inter = p.inter;
    longer_inter.b[longer_inter.n++] = 0;
    expect(ask(v, Role::Server, "example.com", &p.leaf, &longer_inter), Trust::Invalid,
           "an intermediate with a byte after it");
    // \~english A frame that holds, around something that is no certificate: SEQUENCE { INTEGER 0 }.
    // \~spanish Un marco que se sostiene, alrededor de algo que no es un certificado: SEQUENCE { INTEGER 0 }.  \~
    Der junk("3003020100");
    expect(ask(v, Role::Server, "example.com", &junk, &p.inter), Trust::Invalid, "a leaf that is no certificate");
    expect(ask(v, Role::Server, "example.com", &p.leaf, &junk), Trust::Invalid, "an intermediate that is no certificate");
    Chain empty;
    expect(v.verify(empty, Role::Server, "example.com"), Trust::Invalid, "no certificate at all");

    section(provider, "revocation");
    v.check_revocation(true);
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::RevocationUnknown,
           "asked for, and nowhere to find it out: not a pass");
    v.check_revocation(false);
    expect(ask(v, Role::Server, "example.com", &p.leaf, &p.inter), Trust::Trusted, "and not asked for again");
}

const char *const kH3[] = {"h3"};
const uint8_t kClientTp[] = {0x0f, 0x04, 0xc1, 0xc2, 0xc3, 0xc4};
const uint8_t kServerTp[] = {0x00, 0x04, 0x5e, 0x5f, 0x60, 0x61, 0x0f, 0x02, 0xaa, 0xbb};

/**
 * @brief
 * \~english Moves each end's output to the other while that level is the one read.
 * \~spanish Pasa la salida de cada extremo al otro mientras ese nivel sea el que se lee.
 * \~
 */
void pump(Session &a, Session &b) {
    Session *const ends[2] = {&a, &b};
    for (bool moved = true; moved;) {
        moved = false;
        for (size_t e = 0; e < 2; ++e) {
            Session &from = *ends[e];
            Session &to = *ends[1 - e];
            for (size_t l = 0; l < 3; ++l) {
                const Space s = static_cast<Space>(l);
                size_t n = 0;
                const uint8_t *out = from.output(s, n);
                if (n == 0 || to.reading() != s || to.failed()) continue;
                to.receive(s, out, n);
                from.sent(s, n);
                moved = true;
            }
        }
    }
}

/**
 * @brief
 * \~english A whole handshake, real signatures, the server's real chain, and the client asking @p v about it for @p host.
 * \~spanish Un saludo entero, firmas de verdad, la cadena de verdad del servidor, y el cliente preguntando a @p v por ella para @p host.
 * \~
 */
void handshake(Crypto &c, CertVerifier &v, const char *host, uint64_t want_code, const char *what) {
    const Pki p;
    const uint8_t *certs[2] = {p.leaf.b, p.inter.b};
    const size_t lens[2] = {p.leaf.n, p.inter.n};
    SessionConfig cc;
    cc.alpn = kH3;
    cc.alpn_count = 1;
    cc.transport_params = kClientTp;
    cc.transport_params_len = sizeof kClientTp;
    cc.server_name = host;
    cc.verifier = &v;
    SessionConfig sc;
    sc.server = true;
    sc.alpn = kH3;
    sc.alpn_count = 1;
    sc.transport_params = kServerTp;
    sc.transport_params_len = sizeof kServerTp;
    sc.certificates = certs;
    sc.certificate_lens = lens;
    sc.certificate_count = 2;
    sc.scheme = Scheme::EcdsaSecp256r1Sha256;
    sc.signing_key = c.signing_key(sc.scheme, p.key.b, p.key.n);
    check(sc.signing_key != nullptr, "the provider takes the leaf's key");
    {
        Session client(c, cc);
        Session server(c, sc);
        client.start();
        pump(client, server);
        if (want_code == 0) {
            check(!client.failed() && client.complete() && server.complete(), what);
            check(client.peer_trusted(), "and the client knows the server is trusted");
        } else if (!client.failed() || client.failure().code != want_code) {
            std::fprintf(stderr, "FAIL [%s]: %s: want 0x%llx, got 0x%llx (%s)\n", current, what,
                         static_cast<unsigned long long>(want_code),
                         static_cast<unsigned long long>(client.failure().code),
                         client.failure().why != nullptr ? client.failure().why : "no failure");
            ++failures;
        }
    }
    c.forget_key(sc.signing_key);
}

/// \~english The handshakes, with @p c signing and a verifier of class @p V judging.
/// \~spanish Los saludos, con @p c firmando y un verificador de la clase @p V juzgando.  \~
template <class V>
void run_handshakes(Crypto &c, const char *provider) {
    const Pki p;
    section(provider, "handshake");
    V v;
    v.add_anchor(p.root.b, p.root.n);
    v.set_time(test_certs::kDuring);
    handshake(c, v, "example.com", 0, "a server the verifier trusts: complete");
    handshake(c, v, "other.example", kCryptoError + 46, "another name: certificate_unknown");
    v.set_time(test_certs::kAfter);
    handshake(c, v, "example.com", kCryptoError + 45, "expired: certificate_expired");
    V w;
    w.add_anchor(p.other.b, p.other.n);
    w.set_time(test_certs::kDuring);
    handshake(c, w, "example.com", kCryptoError + 48, "an unknown issuer: unknown_ca");
}

} // namespace

int main() {
    int verifiers = 0;
#if HTTP_VX_HAVE_CNG
    ++verifiers;
    run<http_vx::CngVerifier>(http_vx::CngCrypto::kName);
    http_vx::CngCrypto cng;
    if (cng.ready()) run_handshakes<http_vx::CngVerifier>(cng, http_vx::CngCrypto::kName);
#endif
#if HTTP_VX_HAVE_OPENSSL
    ++verifiers;
    {
        http_vx::OpensslVerifier probe;
        std::snprintf(current, sizeof current, "%s", http_vx::OpensslCrypto::kName);
        check(probe.ready(), "OpenSSL gave a store");
    }
    run<http_vx::OpensslVerifier>(http_vx::OpensslCrypto::kName);
    http_vx::OpensslCrypto openssl;
    run_handshakes<http_vx::OpensslVerifier>(openssl, http_vx::OpensslCrypto::kName);
#endif
    if (verifiers == 0) {
        std::fprintf(stderr, "FAIL: no verifier was built: nothing was checked\n");
        return 1;
    }
    if (failures != 0) {
        std::fprintf(stderr, "tls verify: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("tls verify, %d verifier(s): OK\n", verifiers);
    return 0;
}
