/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_crypto_keys.cpp
 * @brief
 * \~english The providers' key exchange and signatures, against the RFCs' known answers.
 * \~spanish El intercambio de claves y las firmas de los proveedores, contra las respuestas conocidas de los RFC.
 * \~
 *
 * \~english
 * X25519 against RFC 7748 (6.1) and the handshake of RFC 8448; P-256 ECDH
 * against RFC 5903 (8.1); ECDSA P-256 against RFC 6979 (A.2.5), whose key a
 * test certificate carries; RSA-PSS against RFC 8448's own CertificateVerify,
 * checked with the RFC's certificate over the RFC's transcript.  And what
 * MUST be refused: an X25519 key that gives the all-zero secret (RFC 8446,
 * 7.4.2), a P-256 point off the curve (4.2.8.2), a signature one bit off, a
 * key of the wrong kind.  With two real providers, what one signs the other
 * checks.
 * \~spanish
 * X25519 contra el RFC 7748 (6.1) y el saludo del RFC 8448; ECDH P-256 contra el
 * RFC 5903 (8.1); ECDSA P-256 contra el RFC 6979 (A.2.5), cuya clave lleva un
 * certificado de prueba; RSA-PSS contra el propio CertificateVerify del RFC
 * 8448, comprobado con el certificado del RFC sobre la transcripcion del RFC.  Y
 * lo que DEBE rechazarse: una clave X25519 que da el secreto a ceros (RFC 8446,
 * 7.4.2), un punto P-256 fuera de la curva (4.2.8.2), una firma con un bit
 * cambiado, una clave del tipo equivocado.  Con dos proveedores de verdad, lo
 * que firma uno lo comprueba el otro.
 * \~
 */

#include "http_vx/quic_crypto.h"

#include "fake_crypto.h"
#include "tls_rfc8448.h"
#include "tls_test_keys.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::quic;
using rfc8448::from_hex;
using rfc8448::same_as;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

/// \~english Bytes from hex, big enough for an RSA key.  \~spanish Bytes a partir de hex, con sitio para una clave RSA.  \~
struct Bytes {
    uint8_t b[2048];
    size_t n;
    explicit Bytes(const char *hex) : n(from_hex(hex, b, sizeof b)) {}
};

/// \~english Both sides of a known X25519 or P-256 exchange agree on @p shared.
/// \~spanish Los dos lados de un intercambio X25519 o P-256 conocido acuerdan @p shared.  \~
void known_exchange(Crypto &c, Group g, const char *priv_a, const char *pub_a, const char *priv_b,
                    const char *pub_b, const char *shared, const char *what) {
    const Bytes pa(priv_a), qa(pub_a), pb(priv_b), qb(pub_b);
    uint8_t out[kMaxShared];
    void *a = c.import_key(g, pa.b, pa.n, qa.b);
    void *b = c.import_key(g, pb.b, pb.n, qb.b);
    check(a != nullptr && b != nullptr, what);
    if (a != nullptr) check(c.agree(a, qb.b, qb.n, out) == Agreed::Ok && same_as(out, 32, shared), what);
    if (b != nullptr) check(c.agree(b, qa.b, qa.n, out) == Agreed::Ok && same_as(out, 32, shared), what);
    c.forget_key(a);
    c.forget_key(b);
}

void test_x25519(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/x25519", c.name());
    // \~english RFC 7748, 6.1.  \~spanish RFC 7748, 6.1.  \~
    known_exchange(c, Group::X25519, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                   "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                   "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                   "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                   "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                   "RFC 7748's X25519 exchange did not give its shared secret");
    // \~english RFC 8448, 3: the handshake's own keys, and the secret its key schedule starts from.
    // \~spanish RFC 8448, 3: las propias claves del saludo, y el secreto del que parte su calendario.  \~
    known_exchange(c, Group::X25519, "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05",
                   "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c",
                   "b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e",
                   "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f",
                   "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
                   "RFC 8448's X25519 exchange did not give the handshake's secret");

    // \~english Fresh keys agree with each other.  \~spanish Las claves nuevas se ponen de acuerdo.  \~
    uint8_t p1[kMaxPublicKey], p2[kMaxPublicKey], s1[kMaxShared], s2[kMaxShared];
    void *k1 = c.generate_key(Group::X25519, p1);
    void *k2 = c.generate_key(Group::X25519, p2);
    check(k1 != nullptr && k2 != nullptr && c.agree(k1, p2, 32, s1) == Agreed::Ok &&
              c.agree(k2, p1, 32, s2) == Agreed::Ok && std::memcmp(s1, s2, 32) == 0,
          "two fresh X25519 keys did not agree");

    // \~english RFC 8446, 7.4.2: an all-zero result MUST abort -- u = 0 and u = 1 give it.
    // \~spanish RFC 8446, 7.4.2: un resultado a ceros DEBE abortar -- u = 0 y u = 1 lo dan.  \~
    uint8_t low[32] = {};
    check(c.agree(k1, low, 32, s1) == Agreed::BadPeerKey, "u = 0 was accepted");
    low[0] = 1;
    check(c.agree(k1, low, 32, s1) == Agreed::BadPeerKey, "u = 1 was accepted");
    check(c.agree(k1, p2, 31, s1) == Agreed::BadPeerKey, "a 31-byte X25519 key was accepted");
    // \~english A pair given in full has to be a pair: another key's public half is refused.
    // \~spanish Un par dado entero tiene que ser un par: la mitad publica de otra clave se rechaza.  \~
    const Bytes priv_a("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const Bytes pub_b("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    void *mismatched = c.import_key(Group::X25519, priv_a.b, 32, pub_b.b);
    check(mismatched == nullptr, "an X25519 private key was imported with another key's public half");
    c.forget_key(mismatched);
    c.forget_key(k1);
    c.forget_key(k2);
}

void test_p256(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/p256", c.name());
    // \~english RFC 5903, 8.1: the secret is girx.  \~spanish RFC 5903, 8.1: el secreto es girx.  \~
    const char *gi = "04 DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180"
                     "5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3";
    const char *gr = "04 D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63"
                     "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB";
    // \~english from_hex reads lower case: the RFC's hex, lowered.  \~spanish from_hex lee minusculas: el hex del RFC, en minusculas.  \~
    char gi_l[256], gr_l[256];
    size_t i = 0;
    for (; gi[i] != '\0'; ++i) gi_l[i] = static_cast<char>(gi[i] >= 'A' && gi[i] <= 'F' ? gi[i] + 32 : gi[i]);
    gi_l[i] = '\0';
    for (i = 0; gr[i] != '\0'; ++i) gr_l[i] = static_cast<char>(gr[i] >= 'A' && gr[i] <= 'F' ? gr[i] + 32 : gr[i]);
    gr_l[i] = '\0';
    known_exchange(c, Group::Secp256r1, "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433", gi_l,
                   "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53", gr_l,
                   "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de",
                   "RFC 5903's P-256 exchange did not give girx");

    uint8_t p1[kMaxPublicKey], p2[kMaxPublicKey], s1[kMaxShared], s2[kMaxShared];
    void *k1 = c.generate_key(Group::Secp256r1, p1);
    void *k2 = c.generate_key(Group::Secp256r1, p2);
    check(k1 != nullptr && k2 != nullptr && p1[0] == 4 && c.agree(k1, p2, 65, s1) == Agreed::Ok &&
              c.agree(k2, p1, 65, s2) == Agreed::Ok && std::memcmp(s1, s2, 32) == 0,
          "two fresh P-256 keys did not agree");

    // \~english 4.2.8.2: the point MUST be on the curve, and uncompressed.
    // \~spanish 4.2.8.2: el punto DEBE estar en la curva, y sin comprimir.  \~
    uint8_t bad[65];
    std::memcpy(bad, p2, 65);
    bad[64] ^= 1;
    check(c.agree(k1, bad, 65, s1) == Agreed::BadPeerKey, "a P-256 point off the curve was accepted");
    std::memcpy(bad, p2, 65);
    bad[0] = 2;
    check(c.agree(k1, bad, 65, s1) == Agreed::BadPeerKey, "a P-256 point not marked uncompressed was accepted");
    check(c.agree(k1, p2, 33, s1) == Agreed::BadPeerKey, "a compressed-size P-256 key was accepted");
    const Bytes priv_i("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433");
    const Bytes pub_r(gr_l);
    void *mismatched = c.import_key(Group::Secp256r1, priv_i.b, 32, pub_r.b);
    check(mismatched == nullptr, "a P-256 private key was imported with another key's public point");
    c.forget_key(mismatched);
    c.forget_key(k1);
    c.forget_key(k2);
}

/// \~english RFC 6979, A.2.5, SHA-256 over "sample", as a DER ECDSA-Sig-Value.
/// \~spanish RFC 6979, A.2.5, SHA-256 sobre "sample", como un ECDSA-Sig-Value en DER.  \~
const char *kSampleSignature =
    "3046"
    "022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

void test_signatures(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/signatures", c.name());
    const Bytes ec_cert(test_keys::kP256Certificate), ec_key(test_keys::kP256Pkcs8);
    const Bytes rsa_cert(test_keys::kRsaCertificate), rsa_key(test_keys::kRsaPkcs8);
    const Scheme ecdsa = Scheme::EcdsaSecp256r1Sha256;
    const Scheme pss = Scheme::RsaPssRsaeSha256;
    const uint8_t sample[] = {'s', 'a', 'm', 'p', 'l', 'e'};

    // \~english RFC 6979's known signature verifies; one bit off, or one byte more, does not.
    // \~spanish La firma conocida del RFC 6979 se verifica; con un bit cambiado, o un byte de mas, no.  \~
    Bytes sig(kSampleSignature);
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, sig.b, sig.n) == Verified::Ok,
          "RFC 6979's ECDSA signature of \"sample\" did not verify");
    sig.b[sig.n - 1] ^= 1;
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, sig.b, sig.n) == Verified::Bad,
          "an ECDSA signature one bit off verified");
    sig.b[sig.n - 1] ^= 1;
    sig.b[sig.n] = 0;
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, sig.b, sig.n + 1) == Verified::Bad,
          "an ECDSA signature with a byte after its DER verified");
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 5, sig.b, sig.n) == Verified::Bad,
          "an ECDSA signature verified over another message");
    // \~english The key has to be of the scheme's kind.  \~spanish La clave tiene que ser del tipo del esquema.  \~
    check(c.verify(pss, ec_cert.b, ec_cert.n, sample, 6, sig.b, sig.n) == Verified::WrongKey,
          "an EC certificate was taken for RSA-PSS");
    check(c.verify(ecdsa, rsa_cert.b, rsa_cert.n, sample, 6, sig.b, sig.n) == Verified::WrongKey,
          "an RSA certificate was taken for ECDSA");
    const Bytes p384_cert(test_keys::kP384Certificate);
    check(c.verify(ecdsa, p384_cert.b, p384_cert.n, sample, 6, sig.b, sig.n) == Verified::WrongKey,
          "a P-384 certificate was taken for ecdsa_secp256r1_sha256");
    // \~english Not DER: r written as a negative integer (its sign bit set, no leading zero).
    // \~spanish No es DER: r escrito como entero negativo (con el bit de signo, sin cero delante).  \~
    Bytes negative("3045"
                   "0220efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                   "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, negative.b, negative.n) == Verified::Bad,
          "an ECDSA signature with a negative r verified");
    // \~english Not DER either: a byte inside the sequence, after s.  \~spanish Tampoco es DER: un byte dentro de la secuencia, tras s.  \~
    Bytes inside("3047"
                 "022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                 "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
                 "00");
    check(c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, inside.b, inside.n) == Verified::Bad,
          "an ECDSA signature with a byte inside its sequence verified");
    check(c.signing_key(ecdsa, rsa_key.b, rsa_key.n) == nullptr, "an RSA key was taken for ECDSA");
    check(c.signing_key(pss, ec_key.b, ec_key.n) == nullptr, "an EC key was taken for RSA-PSS");

    // \~english What is signed verifies, for both schemes.  \~spanish Lo que se firma se verifica, en los dos esquemas.  \~
    uint8_t made[kMaxSignature];
    size_t len = 0;
    void *k = c.signing_key(ecdsa, ec_key.b, ec_key.n);
    check(k != nullptr && c.sign(k, sample, 6, made, sizeof made, len) && made[0] == 0x30 &&
              c.verify(ecdsa, ec_cert.b, ec_cert.n, sample, 6, made, len) == Verified::Ok,
          "an ECDSA signature made here did not verify");
    c.forget_key(k);
    k = c.signing_key(pss, rsa_key.b, rsa_key.n);
    check(k != nullptr && c.sign(k, sample, 6, made, sizeof made, len) && len == 256 &&
              c.verify(pss, rsa_cert.b, rsa_cert.n, sample, 6, made, len) == Verified::Ok,
          "an RSA-PSS signature made here did not verify");
    made[10] ^= 1;
    check(c.verify(pss, rsa_cert.b, rsa_cert.n, sample, 6, made, len) == Verified::Bad,
          "an RSA-PSS signature one bit off verified");
    c.forget_key(k);
}

/**
 * @brief
 * \~english RFC 8448's CertificateVerify, checked as a client would: the RFC's certificate, the RFC's transcript.
 * \~spanish El CertificateVerify del RFC 8448, comprobado como lo haria un cliente: el certificado del RFC, la transcripcion del RFC.
 * \~
 *
 * \~english
 * The content is 64 spaces, "TLS 1.3, server CertificateVerify", a zero
 * byte and the transcript hash through Certificate (4.4.3).
 * \~spanish
 * El contenido son 64 espacios, "TLS 1.3, server CertificateVerify", un byte a
 * cero y el resumen de la transcripcion hasta Certificate (4.4.3).
 * \~
 */
void test_rfc8448_certificate_verify(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/rfc8448-cv", c.name());
    uint8_t transcript[1024];
    size_t n = 0;
    const char *msgs[] = {rfc8448::kClientHello, rfc8448::kServerHello, rfc8448::kEncryptedExtensions,
                          rfc8448::kCertificate};
    for (const char *m : msgs) n += from_hex(m, transcript + n, sizeof transcript - n);
    uint8_t content[64 + 33 + 1 + 32];
    std::memset(content, 0x20, 64);
    std::memcpy(content + 64, "TLS 1.3, server CertificateVerify", 33);
    content[97] = 0;
    check(n == 196 + 90 + 40 + 445 && c.digest(Hash::Sha256, transcript, n, content + 98),
          "the transcript through Certificate could not be hashed");

    const Bytes cert_msg(rfc8448::kCertificate);
    const Bytes cv(rfc8448::kCertificateVerify);
    // \~english The DER certificate starts after type, length, context and the two list lengths (11 bytes).
    // \~spanish El certificado DER empieza tras el tipo, la longitud, el contexto y las dos longitudes de lista (11 bytes).  \~
    const uint8_t *cert = cert_msg.b + 11;
    const size_t cert_len = 0x1b0;
    check(c.verify(Scheme::RsaPssRsaeSha256, cert, cert_len, content, sizeof content, cv.b + 8, 128) ==
              Verified::Ok,
          "RFC 8448's CertificateVerify did not verify with its certificate");
    content[sizeof content - 1] ^= 1;
    check(c.verify(Scheme::RsaPssRsaeSha256, cert, cert_len, content, sizeof content, cv.b + 8, 128) ==
              Verified::Bad,
          "RFC 8448's CertificateVerify verified over another transcript");
}

#if HTTP_VX_HAVE_OPENSSL && HTTP_VX_HAVE_CNG
/// \~english What one provider signs, the other checks: both speak the same DER.
/// \~spanish Lo que firma un proveedor lo comprueba el otro: los dos hablan el mismo DER.  \~
void test_across(Crypto &a, Crypto &b) {
    std::snprintf(current, sizeof current, "%s->%s", a.name(), b.name());
    const Bytes ec_cert(test_keys::kP256Certificate), ec_key(test_keys::kP256Pkcs8);
    const uint8_t msg[] = {1, 2, 3};
    uint8_t sig[kMaxSignature];
    size_t len = 0;
    void *k = a.signing_key(Scheme::EcdsaSecp256r1Sha256, ec_key.b, ec_key.n);
    check(k != nullptr && a.sign(k, msg, 3, sig, sizeof sig, len) &&
              b.verify(Scheme::EcdsaSecp256r1Sha256, ec_cert.b, ec_cert.n, msg, 3, sig, len) == Verified::Ok,
          "an ECDSA signature did not verify with the other provider");
    a.forget_key(k);
    // \~english And an exchange across them agrees, for both groups.
    // \~spanish Y un intercambio entre los dos se pone de acuerdo, en los dos grupos.  \~
    const Group groups[] = {Group::X25519, Group::Secp256r1};
    for (Group g : groups) {
        uint8_t pa[kMaxPublicKey], pb[kMaxPublicKey], sa[kMaxShared], sb[kMaxShared];
        void *ka = a.generate_key(g, pa);
        void *kb = b.generate_key(g, pb);
        const size_t len_g = public_key_size(g);
        check(ka != nullptr && kb != nullptr && a.agree(ka, pb, len_g, sa) == Agreed::Ok &&
                  b.agree(kb, pa, len_g, sb) == Agreed::Ok && std::memcmp(sa, sb, 32) == 0,
              "an exchange between the two providers did not agree");
        a.forget_key(ka);
        b.forget_key(kb);
    }
}
#endif

void run_real(Crypto &c) {
    test_x25519(c);
    test_p256(c);
    test_signatures(c);
    test_rfc8448_certificate_verify(c);
}

/// \~english The fake provider: the same calls, agreeing and verifying, for tests without a real one.
/// \~spanish El proveedor de mentira: las mismas llamadas, poniendose de acuerdo y verificando, para pruebas sin uno de verdad.  \~
void test_fake() {
    std::snprintf(current, sizeof current, "fake");
    test_support::FakeCrypto c;
    uint8_t p1[kMaxPublicKey], p2[kMaxPublicKey], s1[kMaxShared], s2[kMaxShared];
    void *k1 = c.generate_key(Group::X25519, p1);
    void *k2 = c.generate_key(Group::X25519, p2);
    check(c.agree(k1, p2, 32, s1) == Agreed::Ok && c.agree(k2, p1, 32, s2) == Agreed::Ok &&
              std::memcmp(s1, s2, 32) == 0,
          "the fake exchange did not agree");
    const uint8_t zero[32] = {};
    check(c.agree(k1, zero, 32, s1) == Agreed::BadPeerKey, "the fake took an all-zero key");
    c.forget_key(k1);
    c.forget_key(k2);
    const uint8_t cred[] = {7, 7, 7};
    const uint8_t msg[] = {1};
    uint8_t sig[64];
    size_t len = 0;
    void *k = c.signing_key(Scheme::EcdsaSecp256r1Sha256, cred, 3);
    check(c.sign(k, msg, 1, sig, sizeof sig, len) &&
              c.verify(Scheme::EcdsaSecp256r1Sha256, cred, 3, msg, 1, sig, len) == Verified::Ok,
          "the fake signature did not verify");
    c.forget_key(k);
}

} // namespace

int main() {
    test_fake();
    int providers = 0;
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    run_real(openssl);
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    if (cng.ready()) {
        run_real(cng);
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
#if HTTP_VX_HAVE_OPENSSL && HTTP_VX_HAVE_CNG
    if (cng.ready()) {
        test_across(openssl, cng);
        test_across(cng, openssl);
    }
#endif
    if (providers == 0) std::printf("SKIPPED: no real provider built, the known answers not checked\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("crypto keys, %d provider(s): OK\n", providers);
    return 0;
}
