/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_schedule.cpp
 * @brief
 * \~english TLS 1.3's key schedule against RFC 8448's simple 1-RTT handshake.
 * \~spanish El calendario de claves de TLS 1.3 contra el saludo 1-RTT simple del RFC 8448.
 * \~
 *
 * \~english
 * RFC 8448, section 3, prints a whole handshake: every message, the (EC)DHE
 * secret and every secret derived from them.  The labels -- the HkdfLabel
 * bytes -- are checked with any provider, since they are this project's
 * alone; the secrets with every real provider built, from the trace's own
 * messages, so the transcript is checked too.  What a provider-independent
 * rule needs -- the order of the steps, HelloRetryRequest's message_hash --
 * is checked with the fake one.
 * \~spanish
 * El RFC 8448, seccion 3, imprime un saludo entero: cada mensaje, el secreto
 * (EC)DHE y cada secreto derivado de ellos.  Las etiquetas -- los bytes del
 * HkdfLabel -- se comprueban con cualquier proveedor, porque son solo de este
 * proyecto; los secretos con cada proveedor de verdad construido, a partir de
 * los propios mensajes de la traza, asi que la transcripcion se comprueba
 * tambien.  Lo que necesita una regla que no depende del proveedor -- el orden
 * de los pasos, el message_hash del HelloRetryRequest -- se comprueba con el de
 * mentira.
 * \~
 */

#include "http_vx/tls_schedule.h"

#include "fake_crypto.h"
#include "tls_rfc8448.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::tls;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

using rfc8448::from_hex;
using rfc8448::same_as;
using rfc8448::kClientHello;
using rfc8448::kServerHello;
using rfc8448::kEncryptedExtensions;
using rfc8448::kCertificate;
using rfc8448::kCertificateVerify;
using rfc8448::kServerFinished;
using rfc8448::kClientFinished;

// \~english The x25519 shared secret, as the trace's "extract secret handshake" IKM.
// \~spanish El secreto compartido x25519, como el IKM de "extract secret handshake" de la traza.  \~
const char *kShared = "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d";

/// \~english Adds the message in @p hex to @p t.  \~spanish Anade a @p t el mensaje en @p hex.  \~
bool add_hex(Transcript &t, const char *hex, size_t expected) {
    uint8_t m[1024];
    const size_t n = from_hex(hex, m, sizeof m);
    return n == expected && t.add(m, n);
}

/// \~english The HkdfLabel bytes the trace prints as "info": the project's alone, any provider.
/// \~spanish Los bytes del HkdfLabel que la traza imprime como "info": solo del proyecto, cualquier proveedor.  \~
void test_labels() {
    std::snprintf(current, sizeof current, "labels");
    uint8_t out[600], ctx[64];
    size_t c = from_hex("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55",
                        ctx, sizeof ctx);
    size_t n = hkdf_label(out, sizeof out, 32, "derived", ctx, c);
    check(same_as(out, n,
                  "00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64 20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f"
                  "b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"),
          "the \"derived\" label is not the trace's");
    n = hkdf_label(out, sizeof out, 32, "finished", nullptr, 0);
    check(same_as(out, n, "00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65 64 00"),
          "the \"finished\" label is not the trace's");
    n = hkdf_label(out, sizeof out, 12, "iv", nullptr, 0);
    check(same_as(out, n, "00 0c 08 74 6c 73 31 33 20 69 76 00"), "the \"iv\" label is not the trace's");
    c = from_hex("00 00", ctx, sizeof ctx);
    n = hkdf_label(out, sizeof out, 32, "resumption", ctx, c);
    check(same_as(out, n, "00 20 10 74 6c 73 31 33 20 72 65 73 75 6d 70 74 69 6f 6e 02 00 00"),
          "the \"resumption\" label with its nonce is not the trace's");

    // \~english What does not fit the structure is refused, never cut (7.1).
    // \~spanish Lo que no cabe en la estructura se rechaza, nunca se corta (7.1).  \~
    uint8_t big[300] = {};
    check(hkdf_label(out, sizeof out, 32, "x", big, 256) == 0, "a context over 255 bytes was accepted");
    check(hkdf_label(out, sizeof out, 0x10000, "x", nullptr, 0) == 0, "a length over 65535 was accepted");
    check(hkdf_label(out, 10, 32, "finished", nullptr, 0) == 0, "a label was written past its room");
}

/// \~english The order of the steps, and HelloRetryRequest's message_hash (4.4.1).
/// \~spanish El orden de los pasos, y el message_hash del HelloRetryRequest (4.4.1).  \~
void test_rules() {
    std::snprintf(current, sizeof current, "rules");
    test_support::FakeCrypto c;
    uint8_t a[kMaxHash], b[kMaxHash], x[kMaxHash];
    uint8_t h[kMaxHash] = {};
    KeySchedule k(c, Hash::Sha256);
    check(!k.handshake(h, 32, h, a, b), "the handshake secrets came before the Early Secret");
    check(k.start(nullptr, 0) && !k.start(nullptr, 0), "the Early Secret was made twice");
    check(!k.application(h, a, b, x), "the application secrets came before the handshake ones");
    check(k.handshake(h, 32, h, a, b) && !k.resumption(h, x), "resumption came before the Master Secret");
    check(k.application(h, a, b, x) && k.resumption(h, x) && !k.resumption(h, x),
          "the resumption secret came out twice");

    Transcript t;
    uint8_t hello[40];
    for (size_t i = 0; i < sizeof hello; ++i) hello[i] = static_cast<uint8_t>(i);
    uint8_t want[kMaxHash];
    c.digest(Hash::Sha384, hello, sizeof hello, want);
    check(t.add(hello, sizeof hello) && t.replace_with_message_hash(c, Hash::Sha384),
          "ClientHello1 could not be replaced");
    check(t.size() == 4 + 48 && t.bytes()[0] == 254 && t.bytes()[1] == 0 && t.bytes()[2] == 0 &&
              t.bytes()[3] == 48 && std::memcmp(t.bytes() + 4, want, 48) == 0,
          "the synthetic message_hash is not type 254, length Hash.length and Hash(ClientHello1)");

    Transcript full;
    static uint8_t chunk[Transcript::kMaxSize];
    check(full.add(chunk, sizeof chunk) && !full.add(chunk, 1), "a transcript grew past its limit");
}

/// \~english The whole of RFC 8448, section 3, against @p c.  \~spanish Todo el RFC 8448, seccion 3, contra @p c.  \~
void test_trace(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/rfc8448-3", c.name());
    const Hash h = Hash::Sha256;
    uint8_t shared[32], hash[kMaxHash], a[kMaxHash], b[kMaxHash], x[kMaxHash];
    from_hex(kShared, shared, sizeof shared);

    Transcript t;
    check(add_hex(t, kClientHello, 196) && add_hex(t, kServerHello, 90), "the hellos did not go in");
    check(t.hash(c, h, hash) &&
              same_as(hash, 32, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c"
                                " f0 e1 ca d8"),
          "the transcript hash of ClientHello..ServerHello is not the trace's");

    KeySchedule k(c, h);
    check(k.start(nullptr, 0) && k.handshake(shared, 32, hash, a, b), "the handshake secrets failed");
    check(same_as(a, 32, "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e"
                         " 27 a5 5a 21"),
          "client_handshake_traffic_secret is not the trace's");
    check(same_as(b, 32, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59"
                         " d3 91 ad 38"),
          "server_handshake_traffic_secret is not the trace's");
    uint8_t client_hs[32], server_hs[32];
    std::memcpy(client_hs, a, 32);
    std::memcpy(server_hs, b, 32);

    // \~english The record keys of 7.3, as the trace derives them: "key" and "iv", empty context.
    // \~spanish Las claves de registro de 7.3, como las deriva la traza: "key" e "iv", contexto vacio.  \~
    uint8_t key[16], iv[12];
    check(expand_label(c, h, server_hs, "key", nullptr, 0, key, 16) &&
              same_as(key, 16, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc") &&
              expand_label(c, h, server_hs, "iv", nullptr, 0, iv, 12) &&
              same_as(iv, 12, "5d 31 3e b2 67 12 76 ee 13 00 0b 30"),
          "the server's handshake key and iv are not the trace's");

    // \~english The server's Finished, over the transcript to its CertificateVerify.
    // \~spanish El Finished del servidor, sobre la transcripcion hasta su CertificateVerify.  \~
    check(add_hex(t, kEncryptedExtensions, 40) && add_hex(t, kCertificate, 445) &&
              add_hex(t, kCertificateVerify, 136),
          "the server's flight did not go in");
    check(t.hash(c, h, hash) && finished_data(c, h, server_hs, hash, x) &&
              same_as(x, 32, "9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54"
                             " b7 8f 07 18"),
          "the server's verify_data is not the trace's");

    check(add_hex(t, kServerFinished, 36) && t.hash(c, h, hash) &&
              same_as(hash, 32, "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9"
                                " ff 83 df 13"),
          "the transcript hash to the server's Finished is not the trace's");
    check(k.application(hash, a, b, x), "the application secrets failed");
    check(same_as(a, 32, "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7"
                         " c1 75 04 a5"),
          "client_application_traffic_secret_0 is not the trace's");
    check(same_as(b, 32, "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f"
                         " cb 63 16 43"),
          "server_application_traffic_secret_0 is not the trace's");
    check(same_as(x, 32, "fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43"
                         " 09 d3 cf 50"),
          "exporter_master_secret is not the trace's");

    // \~english The client's Finished, over the transcript to the server's Finished.
    // \~spanish El Finished del cliente, sobre la transcripcion hasta el Finished del servidor.  \~
    check(finished_data(c, h, client_hs, hash, x) &&
              same_as(x, 32, "a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2"
                             " ed d5 ce 61"),
          "the client's verify_data is not the trace's");

    check(add_hex(t, kClientFinished, 36) && t.hash(c, h, hash) &&
              same_as(hash, 32, "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84 65 8d 60 49 e8 64 29 42 6d b8 7c"
                                " 54 ad 14 3d"),
          "the transcript hash to the client's Finished is not the trace's");
    check(k.resumption(hash, a) &&
              same_as(a, 32, "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4"
                             " 34 ec 19 6c"),
          "resumption_master_secret is not the trace's");
    const uint8_t nonce[2] = {0, 0};
    check(ticket_psk(c, h, a, nonce, 2, b) &&
              same_as(b, 32, "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94"
                             " 92 e1 c4 f3"),
          "the ticket's PSK is not the trace's");
}

/**
 * @brief
 * \~english RFC 8448, section 4: the resumption with the ticket of section 3.
 * \~spanish RFC 8448, seccion 4: la reanudacion con el ticket de la seccion 3.
 * \~
 *
 * \~english
 * The PSK is the one section 3 made; the binder is a Finished computed with
 * the binder key ("res binder": it is a resumption PSK) over the hash of the
 * ClientHello up to its binders, which the trace prints.
 * \~spanish
 * La PSK es la que hizo la seccion 3; el binder es un Finished calculado con la
 * clave del binder ("res binder": es una PSK de reanudacion) sobre el resumen del
 * ClientHello hasta sus binders, que imprime la traza.
 * \~
 */
void test_resumed(Crypto &c) {
    std::snprintf(current, sizeof current, "%s/rfc8448-4", c.name());
    const Hash h = Hash::Sha256;
    uint8_t psk[32], hash[32], key[kMaxHash], x[kMaxHash];
    from_hex("4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3",
             psk, sizeof psk);
    KeySchedule k(c, h);
    check(k.start(psk, sizeof psk), "the Early Secret from a PSK failed");
    check(k.binder_key(true, key) &&
              same_as(key, 32, "69 fe 13 1a 3b ba d5 d6 3c 64 ee bc c3 0e 39 5b 9d 81 07 72 6a 13 d0 74 e3 89 db c8"
                               " a4 e4 72 56"),
          "the resumption binder key is not the trace's");
    from_hex("63 22 4b 2e 45 73 f2 d3 45 4c a8 4b 9d 00 9a 04 f6 be 9e 05 71 1a 83 96 47 3a ef a0 1e 92 4a 14",
             hash, sizeof hash);
    check(finished_data(c, h, key, hash, x) &&
              same_as(x, 32, "3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3"
                             " 1b 9e 5f 9d"),
          "the PSK binder is not the trace's");
    // \~english An external PSK's binder key differs: the labels keep one from passing for the other (7.1).
    // \~spanish La clave del binder de una PSK externa es otra: las etiquetas impiden que una pase por la otra (7.1).  \~
    check(k.binder_key(false, x) && std::memcmp(x, key, 32) != 0, "the external binder key is the resumption one");

    from_hex("08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b 8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13",
             hash, sizeof hash);
    check(k.early_traffic(hash, x) &&
              same_as(x, 32, "3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63"
                             " b6 ca ab 62"),
          "client_early_traffic_secret is not the trace's");
}

} // namespace

int main() {
    test_labels();
    test_rules();
    int providers = 0;

#if HTTP_VX_HAVE_OPENSSL
    {
        http_vx::OpensslCrypto c;
        ++providers;
        test_trace(c);
        test_resumed(c);
    }
#endif
#if HTTP_VX_HAVE_CNG
    {
        http_vx::CngCrypto c;
        ++providers;
        if (c.ready()) {
            test_trace(c);
            test_resumed(c);
        } else {
            std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", c.missing());
            ++failures;
        }
    }
#endif

    // \~english Without a real provider the trace is not checked, and that is said.
    // \~spanish Sin un proveedor de verdad la traza no se comprueba, y se dice.  \~
    if (providers == 0) std::printf("SKIPPED: no real provider built, RFC 8448 not checked\n");

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls schedule, %d provider(s): OK\n", providers);
    return 0;
}
