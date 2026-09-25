/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_session.cpp
 * @brief
 * \~english The TLS 1.3 handshake state machine: our client against our server, and every rule that needs two messages.
 * \~spanish La maquina de estados del saludo de TLS 1.3: nuestro cliente contra nuestro servidor, y cada regla que necesita dos mensajes.
 * \~
 *
 * \~english
 * A whole handshake end to end -- delivered in one go and a byte at a time,
 * with a HelloRetryRequest, with each suite, with a CertificateRequest --
 * must leave both ends complete, holding the same secrets in opposite
 * directions, the same protocol and each other's transport parameters.
 * With the real providers the signatures and the key exchange are real, one
 * provider against the other included.  Then each rule of RFC 8446 and RFC
 * 9001 this code enforces, broken on purpose with a message built by hand or
 * a byte changed in flight, must end the handshake with its own code.
 * \~spanish
 * Un saludo entero de punta a punta -- entregado de una vez y byte a byte, con
 * un HelloRetryRequest, con cada algoritmo, con un CertificateRequest -- debe
 * dejar los dos extremos completos, con los mismos secretos en direcciones
 * opuestas, el mismo protocolo y los parametros de transporte del otro.  Con
 * los proveedores reales las firmas y el intercambio de claves son de verdad,
 * un proveedor contra el otro incluido.  Despues cada regla del RFC 8446 y del
 * RFC 9001 que hace cumplir este codigo, rota a proposito con un mensaje hecho a
 * mano o un byte cambiado por el camino, debe acabar el saludo con su propio
 * codigo.
 * \~
 */

#include "http_vx/tls_session.h"

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

using namespace http_vx::tls;
using http_vx::quic::Crypto;
using http_vx::quic::Hash;
using rfc8448::from_hex;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) {
    std::snprintf(current, sizeof current, "%s", name);
}

/* \~english The QUIC error codes the rules end with (RFC 9001, 4.8; RFC 9000, 20.1).
 * \~spanish Los codigos de error de QUIC con los que acaban las reglas (RFC 9001, 4.8; RFC 9000, 20.1).  \~ */
constexpr uint64_t kUnexpected = 0x10a;
constexpr uint64_t kHandshakeFailure = 0x128;
constexpr uint64_t kIllegal = 0x12f;
constexpr uint64_t kDecodeError = 0x132;
constexpr uint64_t kDecryptError = 0x133;
constexpr uint64_t kProtocolVersion = 0x146;
constexpr uint64_t kInternal = 0x150;
constexpr uint64_t kMissing = 0x16d;
constexpr uint64_t kUnsupported = 0x16e;
constexpr uint64_t kNoAlpn = 0x178;

/// \~english The session ended with @p code; says what it got otherwise.  \~spanish La sesion acabo con @p code; si no, dice que obtuvo.  \~
void expect(const Session &s, uint64_t code, const char *what) {
    if (s.failed() && s.failure().code == code) return;
    std::fprintf(stderr, "FAIL [%s]: %s: want 0x%llx, got 0x%llx (%s)\n", current, what,
                 static_cast<unsigned long long>(code), static_cast<unsigned long long>(s.failure().code),
                 s.failure().why != nullptr ? s.failure().why : "no failure");
    ++failures;
}

/// \~english The failure's words name the rule: @p part is in them.  \~spanish Las palabras del fallo nombran la regla: @p part esta en ellas.  \~
void expect_why(const Session &s, const char *part, const char *what) {
    check(s.failure().why != nullptr && std::strstr(s.failure().why, part) != nullptr, what);
}

/// \~english Nothing failed; says why otherwise.  \~spanish Nada fallo; si no, dice por que.  \~
void expect_ok(const Session &s, const char *what) {
    if (!s.failed()) return;
    std::fprintf(stderr, "FAIL [%s]: %s: failed with 0x%llx (%s)\n", current, what,
                 static_cast<unsigned long long>(s.failure().code), s.failure().why);
    ++failures;
}

const char *const kH3[] = {"h3"};
const char *const kH2H3[] = {"h2", "h3"};
const uint8_t kClientTp[] = {0x0f, 0x04, 0xc1, 0xc2, 0xc3, 0xc4, 0x04, 0x02, 0x44, 0x00};
const uint8_t kServerTp[] = {0x00, 0x04, 0x5e, 0x5f, 0x60, 0x61, 0x0f, 0x02, 0xaa, 0xbb, 0x0e, 0x01, 0x04};
/// \~english For the fake provider a certificate is its key's bytes.  \~spanish Para el proveedor falso un certificado son los bytes de su clave.  \~
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};

/// \~english Bytes from hex.  \~spanish Bytes a partir de hex.  \~
struct Hex {
    uint8_t b[2048];
    size_t n;
    explicit Hex(const char *hex) : n(from_hex(hex, b, sizeof b)) {}
};

/**
 * @brief
 * \~english The two configurations of a handshake, with the server's credential loaded.
 * \~spanish Las dos configuraciones de un saludo, con la credencial del servidor cargada.
 * \~
 */
struct Ends {
    Crypto &server_crypto;
    SessionConfig client;
    SessionConfig server;
    const uint8_t *certs[1];
    size_t cert_lens[1];

    Ends(Crypto &sc, const uint8_t *cert, size_t cert_len, const uint8_t *key, size_t key_len, Scheme scheme)
        : server_crypto(sc) {
        certs[0] = cert;
        cert_lens[0] = cert_len;
        client.alpn = kH3;
        client.alpn_count = 1;
        client.transport_params = kClientTp;
        client.transport_params_len = sizeof kClientTp;
        client.server_name = "example.com";
        server.server = true;
        server.alpn = kH2H3;
        server.alpn_count = 2;
        server.transport_params = kServerTp;
        server.transport_params_len = sizeof kServerTp;
        server.certificates = certs;
        server.certificate_lens = cert_lens;
        server.certificate_count = 1;
        server.scheme = scheme;
        server.signing_key = sc.signing_key(scheme, key, key_len);
    }
    ~Ends() { server_crypto.forget_key(server.signing_key); }
    Ends(const Ends &) = delete;
    Ends &operator=(const Ends &) = delete;
};

/// \~english A fake pair: the fake certificate is its own key.  \~spanish Un par falso: el certificado falso es su propia clave.  \~
struct FakeEnds : Ends {
    explicit FakeEnds(Crypto &c) : Ends(c, kFakeCert, sizeof kFakeCert, kFakeCert, sizeof kFakeCert,
                                        Scheme::EcdsaSecp256r1Sha256) {}
};

/**
 * @brief
 * \~english Moves each end's output to the other while that level is the one read, @p chunk bytes at a time.
 * \~spanish Pasa la salida de cada extremo al otro mientras ese nivel sea el que se lee, de @p chunk bytes en @p chunk.
 * \~
 */
void pump(Session &a, Session &b, size_t chunk = ~size_t{0}) {
    Session *const ends[2] = {&a, &b};
    for (bool moved = true; moved;) {
        moved = false;
        for (size_t e = 0; e < 2; ++e) {
            Session &from = *ends[e];
            Session &to = *ends[1 - e];
            for (size_t l = 0; l < 3; ++l) {
                const Space s = static_cast<Space>(l);
                size_t n = 0;
                const uint8_t *p = from.output(s, n);
                if (n == 0 || to.reading() != s || to.failed()) continue;
                const size_t k = n < chunk ? n : chunk;
                to.receive(s, p, k);
                from.sent(s, k);
                moved = true;
            }
        }
    }
}

/// \~english The same @p n bytes, or both null.  \~spanish Los mismos @p n bytes, o los dos nulos.  \~
bool same_secret(const uint8_t *a, const uint8_t *b, size_t n) {
    return a != nullptr && b != nullptr && std::memcmp(a, b, n) == 0;
}

/// \~english A span equal to the text @p s.  \~spanish Un tramo igual al texto @p s.  \~
bool is_text(const uint8_t *p, size_t n, const char *s) {
    return p != nullptr && n == std::strlen(s) && std::memcmp(p, s, n) == 0;
}

/**
 * @brief
 * \~english Both ends complete, with the same secrets in opposite directions and each other's parameters.
 * \~spanish Los dos extremos completos, con los mismos secretos en direcciones opuestas y los parametros del otro.
 * \~
 */
void check_agreed(const Session &c, const Session &s, const uint8_t *cert, size_t cert_len) {
    expect_ok(c, "client");
    expect_ok(s, "server");
    check(c.complete() && s.complete(), "both ends complete");
    check(c.aead() == s.aead() && c.secret_size() == s.secret_size(), "the same suite");
    const size_t n = c.secret_size();
    const Space levels[2] = {Space::Handshake, Space::Application};
    for (size_t i = 0; i < 2; ++i) {
        check(same_secret(c.write_secret(levels[i]), s.read_secret(levels[i]), n), "client writes what server reads");
        check(same_secret(s.write_secret(levels[i]), c.read_secret(levels[i]), n), "server writes what client reads");
        check(!same_secret(c.write_secret(levels[i]), c.read_secret(levels[i]), n), "two directions, two secrets");
    }
    check(c.read_secret(Space::Initial) == nullptr && c.write_secret(Space::Initial) == nullptr,
          "Initial secrets are not TLS's");
    size_t len = 0;
    const uint8_t *p = c.alpn(len);
    check(is_text(p, len, "h3"), "client: h3");
    p = s.alpn(len);
    check(is_text(p, len, "h3"), "server: h3, the one the client offered");
    p = c.peer_transport_params(len);
    check(p != nullptr && len == sizeof kServerTp && std::memcmp(p, kServerTp, len) == 0, "client has the server's parameters");
    p = s.peer_transport_params(len);
    check(p != nullptr && len == sizeof kClientTp && std::memcmp(p, kClientTp, len) == 0, "server has the client's parameters");
    p = s.server_name(len);
    check(is_text(p, len, "example.com"), "server has the host name");
    const uint8_t *leaf = nullptr;
    check(c.peer_certificate(0, leaf, len) && len == cert_len && std::memcmp(leaf, cert, len) == 0,
          "client has the server's certificate");
    check(!c.peer_certificate(1, leaf, len), "and only one");
    size_t left = 0;
    for (size_t l = 0; l < 3; ++l) {
        size_t k = 0;
        c.output(static_cast<Space>(l), k);
        left += k;
        s.output(static_cast<Space>(l), k);
        left += k;
    }
    check(left == 0, "nothing left to send");
    check(c.reading() == Space::Application && s.reading() == Space::Application, "both read 1-RTT");
}

/// \~english A full handshake with the pair's own configuration.  \~spanish Un saludo entero con la configuracion del par.  \~
void run_pair(Crypto &cc, Crypto &sc, Ends &e, const uint8_t *cert, size_t cert_len, size_t chunk) {
    Session client(cc, e.client);
    Session server(sc, e.server);
    check(client.start(), "the ClientHello is written");
    pump(client, server, chunk);
    check_agreed(client, server, cert, cert_len);
}

/* ------------------------------------------------------------------------ */
/* \~english Messages built by hand.  \~spanish Mensajes hechos a mano.  \~   */
/* ------------------------------------------------------------------------ */

/// \~english How a crafted ServerHello (or HelloRetryRequest) looks.  \~spanish Como es un ServerHello (o HelloRetryRequest) fabricado.  \~
struct ShSpec {
    bool retry = false;
    uint8_t session_id_len = 0;
    uint16_t suite = suite::Aes128GcmSha256;
    bool versions = true;
    uint16_t version = kTls13;
    bool key_share = true;
    uint16_t group = group::X25519;
    uint8_t key_fill = 0x11;
    bool psk = false;
    bool cookie = false;
};

size_t server_hello(const ShSpec &sp, uint8_t *out, size_t room) {
    Writer w(out, room);
    const size_t msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    if (sp.retry) {
        w.bytes(kHelloRetryRandom, 32);
    } else {
        for (size_t i = 0; i < 32; ++i) w.u8(static_cast<uint8_t>(0x40 + i));
    }
    w.u8(sp.session_id_len);
    for (size_t i = 0; i < sp.session_id_len; ++i) w.u8(7);
    w.u16(sp.suite);
    w.u8(0);
    const size_t exts = w.open(2);
    if (sp.versions) write_supported_versions_server(w, sp.version);
    if (sp.key_share) {
        if (sp.retry) {
            write_key_share_retry(w, sp.group);
        } else {
            uint8_t key[65];
            std::memset(key, sp.key_fill, sizeof key);
            key[0] = sp.group == group::X25519 ? sp.key_fill : 4;
            write_key_share_server(w, sp.group, key, sp.group == group::X25519 ? 32 : 65);
        }
    }
    if (sp.psk) write_psk_server(w, 0);
    if (sp.cookie) {
        const uint8_t cookie[] = {0xc0, 0x0c, 0x1e};
        write_cookie(w, cookie, sizeof cookie);
    }
    w.close(exts, 2);
    w.end_message(msg);
    return w.failed() ? 0 : w.size();
}

/// \~english How a crafted ClientHello looks.  \~spanish Como es un ClientHello fabricado.  \~
struct ChSpec {
    bool versions = true;
    uint16_t version = kTls13;
    uint8_t session_id_len = 0;
    uint16_t suites[3] = {suite::Aes128GcmSha256};
    size_t suite_count = 1;
    bool groups = true;
    uint16_t group_list[2] = {group::X25519, group::Secp256r1};
    size_t group_count = 2;
    bool key_share = true;
    uint16_t share_groups[2] = {group::X25519};
    size_t share_count = 1;
    uint8_t share_fill = 0x22;
    bool sigalgs = true;
    uint16_t scheme = scheme::EcdsaSecp256r1Sha256;
    bool alpn = true;
    const char *proto = "h3";
    bool tp = true;
    bool early_data = false;
    uint8_t random_fill = 0x33;
};

size_t client_hello(const ChSpec &sp, uint8_t *out, size_t room) {
    Writer w(out, room);
    const size_t msg = w.begin_message(Handshake::ClientHello);
    w.u16(kLegacyVersion);
    for (size_t i = 0; i < 32; ++i) w.u8(sp.random_fill);
    w.u8(sp.session_id_len);
    for (size_t i = 0; i < sp.session_id_len; ++i) w.u8(9);
    const size_t suites = w.open(2);
    for (size_t i = 0; i < sp.suite_count; ++i) w.u16(sp.suites[i]);
    w.close(suites, 2);
    w.u8(1);
    w.u8(0);
    const size_t exts = w.open(2);
    if (sp.groups) write_u16_list(w, ext::SupportedGroups, sp.group_list, sp.group_count);
    if (sp.sigalgs) write_u16_list(w, ext::SignatureAlgorithms, &sp.scheme, 1);
    if (sp.alpn) write_alpn(w, &sp.proto, 1);
    if (sp.versions) write_supported_versions_client(w, &sp.version, 1);
    if (sp.key_share) {
        uint8_t keys[2][65];
        const uint8_t *ptrs[2] = {keys[0], keys[1]};
        size_t lens[2] = {0, 0};
        for (size_t i = 0; i < sp.share_count; ++i) {
            std::memset(keys[i], sp.share_fill, 65);
            if (sp.share_groups[i] != group::X25519) keys[i][0] = 4;
            lens[i] = sp.share_groups[i] == group::X25519 ? 32 : 65;
        }
        write_key_share_client(w, sp.share_groups, ptrs, lens, sp.share_count);
    }
    if (sp.early_data) write_empty_extension(w, ext::EarlyData);
    if (sp.tp) write_transport_parameters(w, kClientTp, sizeof kClientTp);
    w.close(exts, 2);
    w.end_message(msg);
    return w.failed() ? 0 : w.size();
}

/// \~english How crafted EncryptedExtensions look.  \~spanish Como son unas EncryptedExtensions fabricadas.  \~
struct EeSpec {
    bool tp = true;
    bool alpn = true;
    const char *proto = "h3";
    bool server_name = false;
    bool early_data = false;
};

size_t encrypted_extensions(const EeSpec &sp, uint8_t *out, size_t room) {
    Writer w(out, room);
    const size_t msg = w.begin_message(Handshake::EncryptedExtensions);
    const size_t exts = w.open(2);
    if (sp.alpn) write_alpn(w, &sp.proto, 1);
    if (sp.server_name) write_empty_extension(w, ext::ServerName);
    if (sp.early_data) write_empty_extension(w, ext::EarlyData);
    if (sp.tp) write_transport_parameters(w, kServerTp, sizeof kServerTp);
    w.close(exts, 2);
    w.end_message(msg);
    return w.failed() ? 0 : w.size();
}

/// \~english A flight taken from one end, to be changed before the other sees it.
/// \~spanish Un vuelo tomado de un extremo, para cambiarlo antes de que lo vea el otro.  \~
struct Flight {
    uint8_t b[16384];
    size_t n = 0;
};

void take(Session &s, Space level, Flight &f) {
    size_t n = 0;
    const uint8_t *p = s.output(level, n);
    f.n = n;
    if (n != 0) std::memcpy(f.b, p, n);
    s.sent(level, n);
}

/// \~english Where the message of @p type starts in @p f, or f.n.  \~spanish Donde empieza el mensaje de @p type en @p f, o f.n.  \~
size_t find(const Flight &f, Handshake type) {
    size_t at = 0;
    while (at + 4 <= f.n) {
        Handshake t;
        Span body;
        const size_t used = frame_message(f.b + at, f.n - at, t, body);
        if (used == 0) break;
        if (t == type) return at;
        at += used;
    }
    return f.n;
}

/// \~english Puts @p len bytes in place of the message of @p type.  \~spanish Pone @p len bytes en lugar del mensaje de @p type.  \~
void replace(Flight &f, Handshake type, const uint8_t *msg, size_t len) {
    const size_t at = find(f, type);
    Handshake t;
    Span body;
    const size_t old = frame_message(f.b + at, f.n - at, t, body);
    uint8_t rest[16384];
    const size_t tail = f.n - at - old;
    std::memcpy(rest, f.b + at + old, tail);
    std::memcpy(f.b + at, msg, len);
    std::memcpy(f.b + at + len, rest, tail);
    f.n = at + len + tail;
}

/// \~english Flips a bit of byte @p off of the body of the message of @p type.  \~spanish Cambia un bit del byte @p off del cuerpo del mensaje de @p type.  \~
void flip(Flight &f, Handshake type, size_t off) {
    f.b[find(f, type) + 4 + off] ^= 0x01;
}

/* ------------------------------------------------------------------------ */

/// \~english A handshake runs to the end, in one go and a byte at a time.  \~spanish Un saludo llega al final, de una vez y byte a byte.  \~
void test_fake_handshakes() {
    test_support::FakeCrypto c;
    {
        section("fake: whole");
        FakeEnds e(c);
        run_pair(c, c, e, kFakeCert, sizeof kFakeCert, ~size_t{0});
    }
    {
        section("fake: byte by byte");
        FakeEnds e(c);
        run_pair(c, c, e, kFakeCert, sizeof kFakeCert, 1);
    }
    {
        // \~english Every suite, each chosen by the server's preference.  \~spanish Cada algoritmo, elegido por la preferencia del servidor.  \~
        section("fake: suites");
        const Aead suites[3] = {Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305};
        for (size_t i = 0; i < 3; ++i) {
            FakeEnds e(c);
            e.server.suites = &suites[i];
            e.server.suite_count = 1;
            Session client(c, e.client);
            Session server(c, e.server);
            client.start();
            pump(client, server);
            check_agreed(client, server, kFakeCert, sizeof kFakeCert);
            check(client.aead() == suites[i], "the suite the server prefers");
            check(client.secret_size() == (suites[i] == Aead::Aes256Gcm ? 48u : 32u), "its hash's size");
        }
    }
    {
        // \~english The client prefers AES-256; the server's preference, AES-128, is the one that counts.
        // \~spanish El cliente prefiere AES-256; la preferencia del servidor, AES-128, es la que cuenta.  \~
        section("fake: server's preference");
        FakeEnds e(c);
        const Aead mine[2] = {Aead::Aes256Gcm, Aead::Aes128Gcm};
        e.client.suites = mine;
        e.client.suite_count = 2;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
        check(server.aead() == Aead::Aes128Gcm, "the server's first choice");
    }
    {
        // \~english The server has its secrets before the client's Finished, and reads none of 1-RTT until then.
        // \~spanish El servidor tiene sus secretos antes del Finished del cliente, y no lee 1-RTT hasta entonces.  \~
        section("fake: 1-RTT waits");
        FakeEnds e(c);
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        size_t n = 0;
        const uint8_t *p = client.output(Space::Initial, n);
        server.receive(Space::Initial, p, n);
        client.sent(Space::Initial, n);
        expect_ok(server, "first flight");
        check(server.write_secret(Space::Application) != nullptr, "the server may send 0.5-RTT");
        check(server.read_secret(Space::Application) == nullptr, "but reads no 1-RTT before the handshake is complete");
        check(server.read_secret(Space::Handshake) != nullptr, "it reads Handshake");
        check(server.reading() == Space::Handshake, "and reads there");
        check(!server.complete(), "not complete yet");
        pump(client, server);
        check(server.read_secret(Space::Application) != nullptr, "now it reads 1-RTT");
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
    }
    {
        // \~english No share at all: the server asks for one (4.1.4) and it goes on.
        // \~spanish Ninguna clave: el servidor pide una (4.1.4) y sigue.  \~
        section("fake: retry, no share");
        FakeEnds e(c);
        e.client.key_shares = 0;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
        check(client.retried() && server.retried(), "both saw the retry");
        check(client.group() == group::X25519 && server.group() == group::X25519, "the server's first group");
    }
    {
        section("fake: retry, other group");
        FakeEnds e(c);
        const Group p256 = Group::Secp256r1;
        e.server.groups = &p256;
        e.server.group_count = 1;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
        check(client.retried() && server.retried(), "a retry for P-256");
        check(client.group() == group::Secp256r1 && server.group() == group::Secp256r1, "P-256 on both ends");
    }
    {
        // \~english Two shares: the server takes the first it supports, no retry.
        // \~spanish Dos claves: el servidor toma la primera que soporta, sin reintento.  \~
        section("fake: two shares");
        FakeEnds e(c);
        e.client.key_shares = 2;
        const Group p256 = Group::Secp256r1;
        e.server.groups = &p256;
        e.server.group_count = 1;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
        check(!client.retried() && client.group() == group::Secp256r1, "the second share, without a retry");
    }
    {
        // \~english A CertificateRequest: the client answers with nothing, the server goes on (4.4.2.4).
        // \~spanish Un CertificateRequest: el cliente responde con nada, el servidor sigue (4.4.2.4).  \~
        section("fake: certificate request");
        FakeEnds e(c);
        e.server.request_certificate = true;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, kFakeCert, sizeof kFakeCert);
        const uint8_t *cert = nullptr;
        size_t n = 0;
        check(!server.peer_certificate(0, cert, n), "the client showed no certificate");
    }
    {
        // \~english No host name: none travels, none is seen.  \~spanish Sin nombre: no viaja ninguno, no se ve ninguno.  \~
        section("fake: no server name");
        FakeEnds e(c);
        e.client.server_name = nullptr;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check(client.complete() && server.complete(), "complete");
        size_t n = 0;
        check(server.server_name(n) == nullptr, "no host name");
    }
}

/// \~english A fresh client that wrote its ClientHello.  \~spanish Un cliente nuevo que escribio su ClientHello.  \~
void feed_client_sh(Crypto &c, const ShSpec &sp, uint64_t code, const char *what, size_t key_shares = 1) {
    FakeEnds e(c);
    e.client.key_shares = key_shares;
    Session client(c, e.client);
    client.start();
    uint8_t m[512];
    const size_t n = server_hello(sp, m, sizeof m);
    client.receive(Space::Initial, m, n);
    if (code == 0)
        expect_ok(client, what);
    else
        expect(client, code, what);
}

/// \~english The client's rules on the ServerHello and the HelloRetryRequest.  \~spanish Las reglas del cliente sobre el ServerHello y el HelloRetryRequest.  \~
void test_client_hello_rules() {
    test_support::FakeCrypto c;
    section("client: server hello");
    ShSpec sp;
    sp.session_id_len = 32;
    feed_client_sh(c, sp, kIllegal, "a session ID that was not sent (4.1.3)");
    sp = ShSpec{};
    sp.suite = 0x1304;
    feed_client_sh(c, sp, kIllegal, "a suite that was not offered (4.1.3)");
    sp = ShSpec{};
    sp.versions = false;
    feed_client_sh(c, sp, kProtocolVersion, "no supported_versions: TLS 1.2 (RFC 9001, 4.2)");
    sp = ShSpec{};
    sp.version = 0x0303;
    feed_client_sh(c, sp, kIllegal, "a version that was not offered (4.2.1)");
    sp = ShSpec{};
    sp.key_share = false;
    feed_client_sh(c, sp, kMissing, "no key_share (4.1.3)");
    sp = ShSpec{};
    sp.group = group::Secp256r1;
    feed_client_sh(c, sp, kIllegal, "a share for a group the client sent none for (4.2.8)");
    sp = ShSpec{};
    sp.psk = true;
    feed_client_sh(c, sp, kUnsupported, "a pre_shared_key that was not offered (4.2)");
    sp = ShSpec{};
    sp.key_fill = 0;
    feed_client_sh(c, sp, kIllegal, "an all-zero X25519 key (4.2.8.2)");
    {
        // \~english The good one goes through: the control for the rest.  \~spanish El bueno pasa: el control del resto.  \~
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        uint8_t m[512];
        const size_t n = server_hello(ShSpec{}, m, sizeof m);
        client.receive(Space::Initial, m, n);
        expect_ok(client, "a good ServerHello");
        check(client.reading() == Space::Handshake, "then it reads Handshake");
        check(client.read_secret(Space::Handshake) != nullptr && client.write_secret(Space::Handshake) != nullptr,
              "with both Handshake secrets");
        check(client.read_secret(Space::Application) == nullptr && client.write_secret(Space::Application) == nullptr,
              "and no 1-RTT yet, either way");
    }
    {
        // \~english Anything left at Initial once Handshake keys are there (RFC 9001, 4.1.3).
        // \~spanish Cualquier cosa que quede en Initial cuando ya hay claves de Handshake (RFC 9001, 4.1.3).  \~
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        uint8_t m[512];
        size_t n = server_hello(ShSpec{}, m, sizeof m);
        m[n++] = 0x08;
        m[n++] = 0x00;
        client.receive(Space::Initial, m, n);
        expect(client, 0x0a, "bytes left at Initial");
    }
    {
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        const uint8_t m[] = {0x08, 0, 0, 2, 0, 0};
        client.receive(Space::Handshake, m, sizeof m);
        expect(client, 0x0a, "bytes at a level TLS is not reading");
    }
    {
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        const uint8_t m[] = {24, 0, 0, 1, 0};
        client.receive(Space::Initial, m, sizeof m);
        expect(client, kUnexpected, "a TLS KeyUpdate (RFC 9001, 6)");
        expect_why(client, "KeyUpdate", "and it says it was a KeyUpdate");
    }
    {
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        uint8_t m[8] = {2, 0xff, 0xff, 0xff};
        client.receive(Space::Initial, m, 4);
        expect(client, 0x0d, "a message larger than can be buffered");
    }

    section("client: retry");
    sp = ShSpec{};
    sp.retry = true;
    sp.group = group::Secp384r1;
    feed_client_sh(c, sp, kIllegal, "a retry for a group not offered (4.2.8)");
    sp.group = group::X25519;
    feed_client_sh(c, sp, kIllegal, "a retry for a group that had a share (4.2.8)");
    sp.key_share = false;
    feed_client_sh(c, sp, kIllegal, "a retry that changes nothing (4.1.4)");
    sp.cookie = true;
    feed_client_sh(c, sp, 0, "a cookie alone is a change");
    sp = ShSpec{};
    sp.retry = true;
    sp.suite = 0x1304;
    sp.group = group::Secp256r1;
    feed_client_sh(c, sp, kIllegal, "a retry with a suite not offered (4.1.4)");
    {
        FakeEnds e(c);
        Session client(c, e.client);
        client.start();
        size_t n = 0;
        const uint8_t *first = client.output(Space::Initial, n);
        ClientHello ch1;
        uint8_t ch1_bytes[2048];
        std::memcpy(ch1_bytes, first, n);
        const size_t ch1_len = n;
        client.sent(Space::Initial, n);
        parse_client_hello(ch1_bytes, ch1_len, ch1);

        ShSpec retry;
        retry.retry = true;
        retry.group = group::Secp256r1;
        retry.cookie = true;
        uint8_t m[512];
        n = server_hello(retry, m, sizeof m);
        client.receive(Space::Initial, m, n);
        expect_ok(client, "a good retry");
        check(client.retried(), "retried");
        size_t len = 0;
        const uint8_t *second = client.output(Space::Initial, len);
        ClientHello ch2;
        check(second != nullptr && parse_client_hello(second, len, ch2).ok(), "a second ClientHello");
        // \~english The same ClientHello, but for the share and the cookie (4.1.2).  \~spanish El mismo ClientHello, salvo la clave y la cookie (4.1.2).  \~
        check(std::memcmp(second + ch2.random.off, ch1_bytes + ch1.random.off, 32) == 0, "the same random");
        check(ch2.ext.has_cookie && ch2.ext.cookie.len == 3 && second[ch2.ext.cookie.off] == 0xc0, "the cookie echoed");
        check(ch2.ext.key_shares.len == 4 + 65 && read16(second + ch2.ext.key_shares.off) == group::Secp256r1,
              "one share, of the group asked for");
        check(ch2.cipher_suites.len == ch1.cipher_suites.len, "the same suites");
        client.sent(Space::Initial, len);

        // \~english A second retry is unexpected (4.1.4).  \~spanish Un segundo reintento es inesperado (4.1.4).  \~
        client.receive(Space::Initial, m, n);
        expect(client, kUnexpected, "a second HelloRetryRequest");
    }
    {
        // \~english After a retry, the ServerHello keeps its suite and its group (4.1.4, 4.2.8).
        // \~spanish Tras un reintento, el ServerHello mantiene su algoritmo y su grupo (4.1.4, 4.2.8).  \~
        ShSpec retry;
        retry.retry = true;
        retry.group = group::Secp256r1;
        ShSpec after[3];
        after[0].suite = suite::Aes256GcmSha384;
        after[0].group = group::Secp256r1;
        after[1].group = group::X25519;
        after[2].group = group::Secp256r1;
        const uint64_t want[3] = {kIllegal, kIllegal, 0};
        const char *what[3] = {"the suite changed after the retry", "the group changed after the retry",
                               "the same suite and group"};
        for (size_t i = 0; i < 3; ++i) {
            FakeEnds e(c);
            Session client(c, e.client);
            client.start();
            size_t n = 0;
            client.output(Space::Initial, n);
            client.sent(Space::Initial, n);
            uint8_t m[512];
            n = server_hello(retry, m, sizeof m);
            client.receive(Space::Initial, m, n);
            client.output(Space::Initial, n);
            client.sent(Space::Initial, n);
            n = server_hello(after[i], m, sizeof m);
            client.receive(Space::Initial, m, n);
            if (want[i] == 0)
                expect_ok(client, what[i]);
            else
                expect(client, want[i], what[i]);
        }
    }
}

/**
 * @brief
 * \~english A client that took the real ServerHello, then the server's Handshake flight changed by @p change.
 * \~spanish Un cliente que tomo el ServerHello de verdad, y luego el vuelo de Handshake del servidor cambiado por @p change.
 * \~
 */
SessionConfig with_name(SessionConfig k, bool sni) {
    k.server_name = sni ? "example.com" : nullptr;
    return k;
}

SessionConfig with_request(SessionConfig k, bool request) {
    k.request_certificate = request;
    return k;
}

struct Staged {
    FakeEnds e;
    Session client;
    Session server;
    Flight flight;

    explicit Staged(Crypto &c, bool sni = true, bool request = false)
        : e(c), client(c, with_name(e.client, sni)), server(c, with_request(e.server, request)) {
        client.start();
        size_t n = 0;
        const uint8_t *p = client.output(Space::Initial, n);
        server.receive(Space::Initial, p, n);
        client.sent(Space::Initial, n);
        p = server.output(Space::Initial, n);
        client.receive(Space::Initial, p, n);
        server.sent(Space::Initial, n);
        take(server, Space::Handshake, flight);
    }
    void deliver() { client.receive(Space::Handshake, flight.b, flight.n); }
};

/// \~english The client's rules on the server's encrypted flight.  \~spanish Las reglas del cliente sobre el vuelo cifrado del servidor.  \~
void test_client_flight_rules() {
    test_support::FakeCrypto c;
    section("client: encrypted extensions");
    const EeSpec base;
    EeSpec specs[5] = {base, base, base, base, base};
    specs[0].tp = false;
    specs[1].alpn = false;
    specs[2].proto = "h2";
    specs[3].server_name = true;
    specs[4].early_data = true;
    const uint64_t want[5] = {kMissing, kNoAlpn, kNoAlpn, kUnsupported, kUnsupported};
    const char *what[5] = {"no transport parameters (RFC 9001, 8.2)", "no ALPN (RFC 9001, 8.1)",
                           "a protocol not offered (RFC 9001, 8.1)", "a server_name that was not sent (4.2)",
                           "early_data not offered (4.2)"};
    for (size_t i = 0; i < 5; ++i) {
        Staged st(c, i != 3);
        uint8_t m[256];
        const size_t n = encrypted_extensions(specs[i], m, sizeof m);
        replace(st.flight, Handshake::EncryptedExtensions, m, n);
        st.deliver();
        expect(st.client, want[i], what[i]);
    }
    {
        // \~english The untouched flight: the control.  \~spanish El vuelo sin tocar: el control.  \~
        Staged st(c);
        st.deliver();
        expect_ok(st.client, "the server's own flight");
        check(st.client.complete(), "and the client is done");
    }

    section("client: authentication");
    {
        Staged st(c);
        flip(st.flight, Handshake::CertificateVerify, 10);
        st.deliver();
        expect(st.client, kDecryptError, "a signature one bit off (4.4.3)");
    }
    {
        Staged st(c);
        flip(st.flight, Handshake::Finished, 3);
        st.deliver();
        expect(st.client, kDecryptError, "a Finished one bit off (4.4.4)");
    }
    {
        Staged st(c);
        const size_t at = find(st.flight, Handshake::CertificateVerify);
        st.flight.b[at + 4] = 0x08;
        st.flight.b[at + 5] = 0x07;
        st.deliver();
        expect(st.client, kIllegal, "a signature scheme that was not offered (4.4.3)");
    }
    {
        Staged st(c);
        const uint8_t cert[] = {11, 0, 0, 5, 1, 'x', 0, 0, 0};
        replace(st.flight, Handshake::Certificate, cert, sizeof cert);
        st.deliver();
        expect(st.client, kIllegal, "a server Certificate with a request context (4.4.2)");
    }
    {
        Staged st(c);
        const uint8_t cert[] = {11, 0, 0, 4, 0, 0, 0, 0};
        replace(st.flight, Handshake::Certificate, cert, sizeof cert);
        st.deliver();
        expect(st.client, kDecodeError, "an empty server Certificate (4.4.2.4)");
    }
    {
        Staged st(c);
        replace(st.flight, Handshake::EncryptedExtensions, nullptr, 0);
        st.deliver();
        expect(st.client, kUnexpected, "a Certificate before the EncryptedExtensions");
    }
    {
        // \~english The right verify_data and one byte more: Hash.length is the length (4.4.4).
        // \~spanish El verify_data correcto y un byte mas: Hash.length es la longitud (4.4.4).  \~
        Staged st(c);
        const size_t at = find(st.flight, Handshake::Finished);
        uint8_t longer[64];
        const size_t len = st.flight.n - at;
        std::memcpy(longer, st.flight.b + at, len);
        longer[3] = static_cast<uint8_t>(longer[3] + 1);
        longer[len] = 0;
        replace(st.flight, Handshake::Finished, longer, len + 1);
        st.deliver();
        expect(st.client, kDecodeError, "a Finished longer than the hash (4.4.4)");
    }
    {
        Staged st(c);
        st.flight.b[st.flight.n++] = 0x04;
        st.deliver();
        expect(st.client, 0x0a, "bytes left at Handshake after the server's Finished (RFC 9001, 4.1.3)");
    }

    section("client: certificate request");
    {
        Staged st(c, true, true);
        check(find(st.flight, Handshake::CertificateRequest) != st.flight.n, "the server asked");
        // \~english The same request with a one-byte context.  \~spanish La misma peticion con un contexto de un byte.  \~
        uint8_t cr[64];
        Writer w(cr, sizeof cr);
        const size_t msg = w.begin_message(Handshake::CertificateRequest);
        w.u8(1);
        w.u8(0x55);
        const size_t exts = w.open(2);
        const uint16_t sch = scheme::EcdsaSecp256r1Sha256;
        write_u16_list(w, ext::SignatureAlgorithms, &sch, 1);
        w.close(exts, 2);
        w.end_message(msg);
        replace(st.flight, Handshake::CertificateRequest, cr, w.size());
        st.deliver();
        expect(st.client, kIllegal, "a request context in the handshake (4.3.2)");
    }
    {
        Staged st(c, true, true);
        const size_t cr_at = find(st.flight, Handshake::CertificateRequest);
        Handshake t;
        Span body;
        const size_t cr_len = frame_message(st.flight.b + cr_at, st.flight.n - cr_at, t, body);
        uint8_t twice[128];
        std::memcpy(twice, st.flight.b + cr_at, cr_len);
        std::memcpy(twice + cr_len, st.flight.b + cr_at, cr_len);
        replace(st.flight, Handshake::CertificateRequest, twice, 2 * cr_len);
        st.deliver();
        expect(st.client, kUnexpected, "two CertificateRequests");
    }
    {
        Staged st(c, true, true);
        const uint8_t cr[] = {13, 0, 0, 3, 0, 0, 0};
        replace(st.flight, Handshake::CertificateRequest, cr, sizeof cr);
        st.deliver();
        expect(st.client, kDecodeError, "a CertificateRequest with an empty extensions block (4.3.2)");
    }
    {
        Staged st(c, true, true);
        const uint8_t cr[] = {13, 0, 0, 7, 0, 0, 4, 0x00, 0x2f, 0, 0};
        replace(st.flight, Handshake::CertificateRequest, cr, sizeof cr);
        st.deliver();
        expect(st.client, kMissing, "a CertificateRequest without signature_algorithms (4.3.2)");
    }

    section("client: after the handshake");
    {
        FakeEnds e(c);
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        check(client.complete(), "complete");
        // \~english A ticket for 0-RTT carries 0xffffffff, and nothing else (RFC 9001, 4.6.1).
        // \~spanish Un ticket para 0-RTT lleva 0xffffffff, y nada mas (RFC 9001, 4.6.1).  \~
        uint8_t m[64];
        Writer w(m, sizeof m);
        size_t msg = w.begin_message(Handshake::NewSessionTicket);
        w.u32(3600);
        w.u32(0x01020304);
        w.u8(1);
        w.u8(0);
        w.u16(2);
        w.u16(0x7171);
        size_t exts = w.open(2);
        write_early_data_ticket(w, 0xffffffffu);
        w.close(exts, 2);
        w.end_message(msg);
        client.receive(Space::Application, m, w.size());
        expect_ok(client, "a ticket that allows 0-RTT");
        check(client.tickets() == 1, "kept");
        Writer w2(m, sizeof m);
        msg = w2.begin_message(Handshake::NewSessionTicket);
        w2.u32(3600);
        w2.u32(0x01020304);
        w2.u8(0);
        w2.u16(1);
        w2.u8(0x72);
        exts = w2.open(2);
        write_early_data_ticket(w2, 16384);
        w2.close(exts, 2);
        w2.end_message(msg);
        client.receive(Space::Application, m, w2.size());
        expect(client, 0x0a, "a ticket with a TLS early data size (RFC 9001, 4.6.1)");
    }
    {
        FakeEnds e(c);
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        const uint8_t cr[] = {13, 0, 0, 11, 0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3};
        client.receive(Space::Application, cr, sizeof cr);
        expect(client, 0x0a, "a CertificateRequest after the handshake (RFC 9001, 4.4)");
    }
}

/// \~english A fresh server fed one crafted ClientHello; @p why, if given, is in the failure's words.
/// \~spanish Un servidor nuevo al que se le da un ClientHello fabricado; @p why, si se da, esta en las palabras del fallo.  \~
void feed_server_ch(Crypto &c, const ChSpec &sp, uint64_t code, const char *what, const char *why = nullptr) {
    FakeEnds e(c);
    Session server(c, e.server);
    uint8_t m[1024];
    const size_t n = client_hello(sp, m, sizeof m);
    server.receive(Space::Initial, m, n);
    if (code == 0)
        expect_ok(server, what);
    else
        expect(server, code, what);
    if (why != nullptr) expect_why(server, why, what);
}

/// \~english The server's rules on the ClientHello.  \~spanish Las reglas del servidor sobre el ClientHello.  \~
void test_server_rules() {
    test_support::FakeCrypto c;
    section("server: client hello");
    feed_server_ch(c, ChSpec{}, 0, "a good ClientHello");
    ChSpec sp;
    sp.versions = false;
    feed_server_ch(c, sp, kProtocolVersion, "no supported_versions (RFC 9001, 4.2)");
    sp = ChSpec{};
    sp.version = 0x0303;
    feed_server_ch(c, sp, kProtocolVersion, "no TLS 1.3 among the versions (RFC 9001, 4.2)");
    sp = ChSpec{};
    sp.session_id_len = 32;
    feed_server_ch(c, sp, 0x0a, "a session ID: compatibility mode (RFC 9001, 8.4)");
    sp = ChSpec{};
    sp.key_share = false;
    feed_server_ch(c, sp, kMissing, "supported_groups without key_share (9.2)");
    sp = ChSpec{};
    sp.groups = false;
    sp.key_share = false;
    feed_server_ch(c, sp, kMissing, "neither groups nor shares, and no PSK (9.2)");
    sp = ChSpec{};
    sp.sigalgs = false;
    feed_server_ch(c, sp, kMissing, "no signature_algorithms (9.2)");
    sp = ChSpec{};
    sp.tp = false;
    feed_server_ch(c, sp, kMissing, "no transport parameters (RFC 9001, 8.2)");
    sp = ChSpec{};
    sp.suites[0] = 0x1304;
    feed_server_ch(c, sp, kHandshakeFailure, "no suite in common (4.1.1)");
    sp = ChSpec{};
    sp.scheme = scheme::Ed25519;
    feed_server_ch(c, sp, kHandshakeFailure, "no signature the certificate makes (4.1.1)");
    sp = ChSpec{};
    sp.alpn = false;
    feed_server_ch(c, sp, kNoAlpn, "no ALPN (RFC 9001, 8.1)", "RFC 9001, 8.1");
    sp = ChSpec{};
    sp.proto = "spdy/3";
    feed_server_ch(c, sp, kNoAlpn, "no protocol in common (RFC 7301, 3.2)", "RFC 7301, 3.2");
    sp = ChSpec{};
    sp.group_list[0] = group::Secp384r1;
    sp.group_count = 1;
    sp.share_groups[0] = group::Secp384r1;
    feed_server_ch(c, sp, kHandshakeFailure, "no group in common (4.1.1)");
    sp = ChSpec{};
    sp.share_fill = 0;
    feed_server_ch(c, sp, kIllegal, "an all-zero key share (4.2.8.2)");
    sp = ChSpec{};
    sp.suites[0] = 0x1304;
    sp.suites[1] = suite::Aes256GcmSha384;
    sp.suite_count = 2;
    feed_server_ch(c, sp, 0, "an unknown suite is skipped (4.1.2)");
    {
        FakeEnds e(c);
        Session server(c, e.server);
        uint8_t m[1024];
        size_t n = client_hello(ChSpec{}, m, sizeof m);
        m[n++] = 0x01;
        server.receive(Space::Initial, m, n);
        expect(server, 0x0a, "bytes after the ClientHello at Initial (RFC 9001, 4.1.3)");
    }
    {
        FakeEnds e(c);
        e.server.certificate_count = 0;
        Session server(c, e.server);
        uint8_t m[1024];
        const size_t n = client_hello(ChSpec{}, m, sizeof m);
        server.receive(Space::Initial, m, n);
        expect(server, kInternal, "a server without a certificate says so");
    }
    {
        test_support::FakeCrypto broken;
        FakeEnds e(broken);
        broken.broken = true;
        Session server(broken, e.server);
        uint8_t m[1024];
        const size_t n = client_hello(ChSpec{}, m, sizeof m);
        server.receive(Space::Initial, m, n);
        expect(server, kInternal, "a provider that fails is internal_error, not the peer's fault");
    }

    section("server: retry");
    {
        // \~english No share: the HelloRetryRequest names the group and the suite.
        // \~spanish Ninguna clave: el HelloRetryRequest nombra el grupo y el algoritmo.  \~
        FakeEnds e(c);
        Session server(c, e.server);
        ChSpec first;
        first.share_count = 0;
        uint8_t m[1024];
        const size_t n = client_hello(first, m, sizeof m);
        server.receive(Space::Initial, m, n);
        expect_ok(server, "a ClientHello without shares");
        size_t len = 0;
        const uint8_t *p = server.output(Space::Initial, len);
        ServerHello hrr;
        check(p != nullptr && parse_server_hello(p, len, hrr).ok(), "a HelloRetryRequest");
        check(hrr.retry && hrr.ext.share_group == group::X25519 && hrr.cipher_suite == suite::Aes128GcmSha256,
              "for X25519, with the suite chosen");
        check(server.reading() == Space::Initial && server.retried(), "still at Initial");
        check(server.read_secret(Space::Handshake) == nullptr, "no keys yet");
    }
    ChSpec second[6];
    second[0].random_fill = 0x34;
    second[1].suites[0] = suite::Aes256GcmSha384;
    second[2].share_count = 2;
    second[2].share_groups[1] = group::Secp256r1;
    second[3].share_groups[0] = group::Secp256r1;
    second[4].early_data = true;
    const uint64_t want[6] = {kIllegal, kIllegal, kIllegal, kIllegal, kIllegal, 0};
    const char *what[6] = {"the random changed (4.1.2)", "the suite dropped (4.1.4)", "two shares (4.1.2)",
                           "a share for another group (4.1.2)", "early_data after a retry (4.1.2)",
                           "the second ClientHello as it should be"};
    for (size_t i = 0; i < 6; ++i) {
        FakeEnds e(c);
        Session server(c, e.server);
        ChSpec first;
        first.share_count = 0;
        uint8_t m[1024];
        size_t n = client_hello(first, m, sizeof m);
        server.receive(Space::Initial, m, n);
        server.output(Space::Initial, n);
        server.sent(Space::Initial, n);
        n = client_hello(second[i], m, sizeof m);
        server.receive(Space::Initial, m, n);
        if (want[i] == 0) {
            expect_ok(server, what[i]);
            check(server.reading() == Space::Handshake, "and the handshake goes on");
        } else {
            expect(server, want[i], what[i]);
        }
    }

    section("server: finished");
    {
        FakeEnds e(c);
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        size_t n = 0;
        const uint8_t *p = client.output(Space::Initial, n);
        server.receive(Space::Initial, p, n);
        client.sent(Space::Initial, n);
        p = server.output(Space::Initial, n);
        client.receive(Space::Initial, p, n);
        server.sent(Space::Initial, n);
        p = server.output(Space::Handshake, n);
        client.receive(Space::Handshake, p, n);
        server.sent(Space::Handshake, n);
        Flight f;
        take(client, Space::Handshake, f);
        flip(f, Handshake::Finished, 0);
        server.receive(Space::Handshake, f.b, f.n);
        expect(server, kDecryptError, "a client Finished one bit off (4.4.4)");
        check(!server.complete() && server.read_secret(Space::Application) == nullptr, "and 1-RTT stays shut");
    }
    {
        // \~english A ClientHello after the handshake is renegotiation, which TLS 1.3 forbids (4.1.2).
        // \~spanish Un ClientHello tras el saludo es renegociar, lo que TLS 1.3 prohibe (4.1.2).  \~
        FakeEnds e(c);
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        pump(client, server);
        uint8_t m[1024];
        const size_t n = client_hello(ChSpec{}, m, sizeof m);
        server.receive(Space::Application, m, n);
        expect(server, kUnexpected, "a ClientHello after the handshake");
    }
    {
        // \~english Nothing more is taken once it failed.  \~spanish No se toma nada mas una vez que fallo.  \~
        FakeEnds e(c);
        Session server(c, e.server);
        ChSpec sp2;
        sp2.alpn = false;
        uint8_t m[1024];
        const size_t n = client_hello(sp2, m, sizeof m);
        server.receive(Space::Initial, m, n);
        const uint64_t first = server.failure().code;
        check(!server.receive(Space::Initial, m, n) && server.failure().code == first, "the first failure stays");
        check(server.failure().alert == Alert::NoApplicationProtocol, "and says which alert");
    }
}

/// \~english Appends the output at @p level to @p t and marks it sent.  \~spanish Anade la salida de @p level a @p t y la marca como enviada.  \~
size_t drain(Session &s, Space level, uint8_t *t, size_t at) {
    size_t n = 0;
    const uint8_t *p = s.output(level, n);
    if (n != 0) std::memcpy(t + at, p, n);
    s.sent(level, n);
    return at + n;
}

/**
 * @brief
 * \~english A client that shows a certificate: the server checks its CertificateVerify, "client" context and all.
 * \~spanish Un cliente que ensena un certificado: el servidor comprueba su CertificateVerify, contexto "client" incluido.
 * \~
 *
 * \~english
 * This project's client sends none, so its Certificate and CertificateVerify
 * are made here, signed with the fake provider over the transcript the
 * server keeps: every message so far, which the test saw go by.
 * \~spanish
 * El cliente de este proyecto no manda ninguno, asi que su Certificate y su
 * CertificateVerify se hacen aqui, firmados con el proveedor falso sobre la
 * transcripcion que guarda el servidor: cada mensaje hasta ahora, que la prueba
 * vio pasar.
 * \~
 */
void test_client_certificate() {
    test_support::FakeCrypto c;
    section("server: client certificate");
    const char *contexts[2] = {"TLS 1.3, client CertificateVerify", "TLS 1.3, server CertificateVerify"};
    for (size_t i = 0; i < 2; ++i) {
        FakeEnds e(c);
        e.server.request_certificate = true;
        Session client(c, e.client);
        Session server(c, e.server);
        client.start();
        uint8_t t[8192];
        size_t tn = drain(client, Space::Initial, t, 0);
        server.receive(Space::Initial, t, tn);
        tn = drain(server, Space::Initial, t, tn);
        tn = drain(server, Space::Handshake, t, tn);

        uint8_t flight[512];
        Writer w(flight, sizeof flight);
        size_t msg = w.begin_message(Handshake::Certificate);
        w.u8(0);
        const size_t list = w.open(3);
        const size_t entry = w.open(3);
        w.bytes(kFakeCert, sizeof kFakeCert);
        w.close(entry, 3);
        w.u16(0);
        w.close(list, 3);
        w.end_message(msg);
        std::memcpy(t + tn, flight, w.size());
        tn += w.size();

        uint8_t th[32];
        c.digest(Hash::Sha256, t, tn, th);
        uint8_t content[160];
        std::memset(content, 0x20, 64);
        std::memcpy(content + 64, contexts[i], 33);
        content[97] = 0;
        std::memcpy(content + 98, th, 32);
        void *key = c.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
        uint8_t sig[64];
        size_t sig_len = 0;
        c.sign(key, content, 130, sig, sizeof sig, sig_len);
        c.forget_key(key);
        msg = w.begin_message(Handshake::CertificateVerify);
        w.u16(scheme::EcdsaSecp256r1Sha256);
        const size_t s = w.open(2);
        w.bytes(sig, sig_len);
        w.close(s, 2);
        w.end_message(msg);
        server.receive(Space::Handshake, flight, w.size());
        if (i == 0) {
            expect_ok(server, "a client signature with the client's context");
            const uint8_t *cert = nullptr;
            size_t n = 0;
            check(server.peer_certificate(0, cert, n) && n == sizeof kFakeCert &&
                      std::memcmp(cert, kFakeCert, n) == 0,
                  "the server keeps the client's certificate");
            check(!server.complete(), "and waits for its Finished");
        } else {
            expect(server, kDecryptError, "a client signature with the server's context (4.4.3)");
        }
    }
}

/// \~english Handshakes where the key exchange and the signatures are real.  \~spanish Saludos en los que el intercambio de claves y las firmas son de verdad.  \~
void run_real(Crypto &client_crypto, Crypto &server_crypto, const char *name) {
    const Hex p256_cert(test_keys::kP256Certificate), p256_key(test_keys::kP256Pkcs8);
    const Hex rsa_cert(test_keys::kRsaCertificate), rsa_key(test_keys::kRsaPkcs8);
    char label[64];
    {
        std::snprintf(label, sizeof label, "%s: ecdsa", name);
        section(label);
        Ends e(server_crypto, p256_cert.b, p256_cert.n, p256_key.b, p256_key.n, Scheme::EcdsaSecp256r1Sha256);
        check(e.server.signing_key != nullptr, "the P-256 key loads");
        run_pair(client_crypto, server_crypto, e, p256_cert.b, p256_cert.n, ~size_t{0});
    }
    {
        std::snprintf(label, sizeof label, "%s: rsa-pss", name);
        section(label);
        Ends e(server_crypto, rsa_cert.b, rsa_cert.n, rsa_key.b, rsa_key.n, Scheme::RsaPssRsaeSha256);
        check(e.server.signing_key != nullptr, "the RSA key loads");
        run_pair(client_crypto, server_crypto, e, rsa_cert.b, rsa_cert.n, 7);
    }
    {
        // \~english P-256 for real, through a retry, and SHA-384.  \~spanish P-256 de verdad, a traves de un reintento, y SHA-384.  \~
        std::snprintf(label, sizeof label, "%s: retry p-256", name);
        section(label);
        Ends e(server_crypto, p256_cert.b, p256_cert.n, p256_key.b, p256_key.n, Scheme::EcdsaSecp256r1Sha256);
        const Group p256 = Group::Secp256r1;
        const Aead aes256 = Aead::Aes256Gcm;
        e.server.groups = &p256;
        e.server.group_count = 1;
        e.server.suites = &aes256;
        e.server.suite_count = 1;
        Session client(client_crypto, e.client);
        Session server(server_crypto, e.server);
        client.start();
        pump(client, server);
        check_agreed(client, server, p256_cert.b, p256_cert.n);
        check(client.retried() && client.group() == group::Secp256r1 && client.aead() == Aead::Aes256Gcm,
              "P-256 after a retry, with AES-256");
    }
    {
        std::snprintf(label, sizeof label, "%s: bad signature", name);
        section(label);
        Ends e(server_crypto, p256_cert.b, p256_cert.n, p256_key.b, p256_key.n, Scheme::EcdsaSecp256r1Sha256);
        Session client(client_crypto, e.client);
        Session server(server_crypto, e.server);
        client.start();
        size_t n = 0;
        const uint8_t *p = client.output(Space::Initial, n);
        server.receive(Space::Initial, p, n);
        client.sent(Space::Initial, n);
        p = server.output(Space::Initial, n);
        client.receive(Space::Initial, p, n);
        server.sent(Space::Initial, n);
        Flight f;
        take(server, Space::Handshake, f);
        Flight g = f;
        // \~english The last byte of the signature: the DER still reads, the value is wrong.
        // \~spanish El ultimo byte de la firma: el DER aun se lee, el valor esta mal.  \~
        f.b[find(f, Handshake::Finished) - 1] ^= 0x01;
        client.receive(Space::Handshake, f.b, f.n);
        expect(client, kDecryptError, "a real signature one bit off (4.4.3)");

        // \~english RSA-PSS claimed for an EC key: the scheme does not fit the certificate.
        // \~spanish RSA-PSS para una clave EC: el esquema no encaja con el certificado.  \~
        Session client2(client_crypto, e.client);
        Session server2(server_crypto, e.server);
        client2.start();
        p = client2.output(Space::Initial, n);
        server2.receive(Space::Initial, p, n);
        client2.sent(Space::Initial, n);
        p = server2.output(Space::Initial, n);
        client2.receive(Space::Initial, p, n);
        server2.sent(Space::Initial, n);
        take(server2, Space::Handshake, g);
        const size_t at = find(g, Handshake::CertificateVerify);
        g.b[at + 4] = 0x08;
        g.b[at + 5] = 0x04;
        client2.receive(Space::Handshake, g.b, g.n);
        expect(client2, kIllegal, "a scheme the certificate's key cannot make (4.4.3)");
    }
}

} // namespace

int main() {
    test_fake_handshakes();
    test_client_hello_rules();
    test_client_flight_rules();
    test_server_rules();
    test_client_certificate();
    int providers = 0;
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    run_real(openssl, openssl, "openssl");
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    if (cng.ready()) {
        run_real(cng, cng, "cng");
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
#if HTTP_VX_HAVE_OPENSSL && HTTP_VX_HAVE_CNG
    if (cng.ready()) {
        run_real(openssl, cng, "openssl to cng");
        run_real(cng, openssl, "cng to openssl");
    }
#endif
    if (providers == 0) std::printf("SKIPPED: no real provider built, real handshakes not run\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls session, %d provider(s): OK\n", providers);
    return 0;
}
