/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_channel.cpp
 * @brief
 * \~english TLS 1.3 over a byte stream: two channels shake hands and talk, and every broken record ends it with its alert.
 * \~spanish TLS 1.3 sobre un flujo de bytes: dos canales se dan la mano y hablan, y cada registro roto lo acaba con su alerta.
 * \~
 *
 * \~english
 * A client channel and a server channel, nothing between them but two
 * buffers -- delivered whole, or a byte at a time.  First what must work:
 * the handshake, application data both ways and in records of at most 2^14,
 * a handshake message larger than a record, ALPN, a HelloRetryRequest,
 * resumption, KeyUpdate both ways and on its own before the limit, and
 * close_notify.  Then what must not: each record RFC 8446 refuses, sent by
 * hand, must end the connection with the alert it names -- and the other
 * end must read that alert.
 * \~spanish
 * Un canal cliente y un canal servidor, sin nada entre ellos salvo dos buffers
 * -- entregados enteros, o de byte en byte.  Primero lo que tiene que
 * funcionar: el saludo, datos de aplicacion en los dos sentidos y en registros
 * de 2^14 como mucho, un mensaje del saludo mas grande que un registro, ALPN,
 * un HelloRetryRequest, la reanudacion, KeyUpdate en los dos sentidos y por su
 * cuenta antes del limite, y close_notify.  Despues lo que no: cada registro que
 * rechaza el RFC 8446, mandado a mano, tiene que acabar la conexion con la
 * alerta que nombra -- y el otro extremo tiene que leer esa alerta.
 * \~
 */

#include "http_vx/tls_channel.h"

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
#include <vector>

namespace {

using namespace http_vx::tls;
using http_vx::Buffer;
using http_vx::quic::Crypto;
using http_vx::quic::Scheme;

int failures = 0;
const char *where = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", where, what);
    ++failures;
}

const char *const kBoth[] = {"h2", "http/1.1"};
const char *const kH11[] = {"http/1.1"};
const char *const kFoo[] = {"foo"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};

void put(Buffer &b, const uint8_t *p, size_t n) {
    uint8_t *at = b.reserve(n);
    std::memcpy(at, p, n);
    b.commit(n);
}

void put(Buffer &b, const std::vector<uint8_t> &v) {
    put(b, v.data(), v.size());
}

/// \~english Moves up to @p n bytes from the front of @p from to the end of @p to.  \~spanish Mueve hasta @p n bytes del principio de @p from al final de @p to.  \~
size_t move(Buffer &from, Buffer &to, size_t n) {
    const size_t take = from.size() < n ? from.size() : n;
    if (take != 0) put(to, from.data(), take);
    from.consume(take);
    return take;
}

/// \~english What one end brings: its certificate and key, for a server.  \~spanish Lo que trae un extremo: su certificado y su clave, en un servidor.  \~
struct Identity {
    Crypto *c = nullptr;
    const uint8_t *cert = nullptr;
    size_t cert_len = 0;
    void *key = nullptr;
};

/**
 * @brief
 * \~english A client and a server channel and the four buffers between them.
 * \~spanish Un canal cliente y uno servidor y los cuatro buffers entre ellos.
 * \~
 */
struct Pair {
    SessionConfig ccfg;
    SessionConfig scfg;
    const uint8_t *certs[1] = {nullptr};
    size_t lens[1] = {0};
    Channel client;
    Channel server;
    /// \~english Written and not yet delivered.  \~spanish Escrito y todavia sin entregar.  \~
    Buffer c2s;
    Buffer s2c;
    /// \~english Delivered and not yet read whole.  \~spanish Entregado y todavia sin leer entero.  \~
    Buffer at_server;
    Buffer at_client;
    Buffer cplain;
    Buffer splain;
    ChannelStatus cs = ChannelStatus::Ok;
    ChannelStatus ss = ChannelStatus::Ok;

    Pair(Crypto &cc, const Identity &id) {
        ccfg.over_tcp = true;
        ccfg.alpn = kBoth;
        ccfg.alpn_count = 2;
        ccfg.trust_any_certificate = true;
        scfg.server = true;
        scfg.over_tcp = true;
        scfg.alpn = kBoth;
        scfg.alpn_count = 2;
        certs[0] = id.cert;
        lens[0] = id.cert_len;
        scfg.certificates = certs;
        scfg.certificate_lens = lens;
        scfg.certificate_count = 1;
        scfg.signing_key = id.key;
        client.configure(cc, ccfg);
        server.configure(*id.c, scfg);
    }

    bool start() { return client.start(c2s); }

    /// \~english Delivers both ways, @p chunk bytes at a time, until nothing moves.  \~spanish Entrega en los dos sentidos, de @p chunk en @p chunk bytes, hasta que nada se mueve.  \~
    void run(size_t chunk = ~size_t{0}) {
        for (int round = 0; round < 1000000; ++round) {
            size_t moved = move(c2s, at_server, chunk);
            ss = server.receive(at_server, splain, s2c);
            moved += move(s2c, at_client, chunk);
            cs = client.receive(at_client, cplain, c2s);
            if (moved == 0 && c2s.empty() && s2c.empty()) return;
        }
    }

    bool shake(size_t chunk = ~size_t{0}) {
        if (!start()) return false;
        run(chunk);
        return client.open() && server.open();
    }
};

Identity fake_identity(test_support::FakeCrypto &f) {
    Identity id;
    id.c = &f;
    id.cert = kFakeCert;
    id.cert_len = sizeof kFakeCert;
    id.key = f.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
    return id;
}

bool is(const Buffer &b, const char *s) {
    return b.size() == std::strlen(s) && std::memcmp(b.data(), s, b.size()) == 0;
}

/// \~english The ALPN a channel settled on, as a string compare.  \~spanish El ALPN en que se quedo un canal, como comparacion de cadena.  \~
bool alpn_is(const Channel &c, const char *want) {
    size_t n = 0;
    const uint8_t *p = c.alpn(n);
    if (want == nullptr) return p == nullptr;
    return p != nullptr && n == std::strlen(want) && std::memcmp(p, want, n) == 0;
}

/* ------------------------------------------------------------------------- */

void test_handshake_and_data(Crypto &c, const Identity &id, const char *name, size_t chunk) {
    where = name;
    Pair p(c, id);
    check(p.shake(chunk), "the handshake completes");
    check(alpn_is(p.client, "h2") && alpn_is(p.server, "h2"), "ALPN: the server's first choice the client offered");
    check(p.client.read_keys().installed() && p.server.write_keys().installed(), "application keys both ways");

    const char *hello = "hello over tls";
    check(p.client.send(reinterpret_cast<const uint8_t *>(hello), std::strlen(hello), p.c2s), "the client sends");
    p.run(chunk);
    check(is(p.splain, hello), "the server reads it");
    p.splain.consume(p.splain.size());

    // \~english 40000 bytes: three records, none over 2^14 (5.1).  \~spanish 40000 bytes: tres registros, ninguno de mas de 2^14 (5.1).  \~
    std::vector<uint8_t> big(40000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 7);
    const uint64_t before = p.server.write_keys().sequence();
    check(p.server.send(big.data(), big.size(), p.s2c), "the server sends 40000 bytes");
    check(p.server.write_keys().sequence() == before + 3, "in three records");
    size_t at = 0;
    bool records_ok = true;
    while (at + kRecordHeader <= p.s2c.size()) {
        const RecordHeader h = read_record_header(p.s2c.data() + at);
        records_ok = records_ok && h.length <= kMaxFragment + kRecordOverhead - kRecordHeader && h.type == 23;
        at += kRecordHeader + h.length;
    }
    check(records_ok && at == p.s2c.size(), "each record within 2^14 of content, outer type 23");
    p.run(chunk);
    check(p.cplain.size() == big.size() && std::memcmp(p.cplain.data(), big.data(), big.size()) == 0,
          "the client reads all 40000, in order");
    p.cplain.consume(p.cplain.size());

    check(p.server.release_handshake(), "the server gives the handshake back");
    check(p.server.session() == nullptr && alpn_is(p.server, "h2"), "keeping its ALPN answer");
    check(!p.client.release_handshake(), "a client keeps its session: its tickets live there");

    // \~english KeyUpdate both ways, after the server let go of its handshake.
    // \~spanish KeyUpdate en los dos sentidos, despues de que el servidor soltara su saludo.  \~
    check(p.client.key_update(true, p.c2s), "the client updates, asking the server to");
    p.run(chunk);
    check(p.server.key_updates_received() == 1 && p.server.key_updates_sent() == 1, "the server followed and answered once");
    check(p.client.key_updates_received() == 1, "the client took the answer");
    check(p.server.send(reinterpret_cast<const uint8_t *>(hello), std::strlen(hello), p.s2c), "data under the new keys");
    p.run(chunk);
    check(is(p.cplain, hello), "reads under generation 1");
    p.cplain.consume(p.cplain.size());

    // \~english close_notify: the peer is told, and what follows is ignored (6.1).
    // \~spanish close_notify: se le dice al otro, y lo que venga despues se ignora (6.1).  \~
    check(p.client.close(p.c2s), "the client closes");
    check(!p.client.send(reinterpret_cast<const uint8_t *>(hello), 3, p.c2s), "nothing goes out after close_notify");
    p.run(chunk);
    check(p.ss == ChannelStatus::Closed && p.server.peer_closed(), "the server saw close_notify");
    check(p.server.close(p.s2c), "and answers with its own");
    p.run(chunk);
    check(p.cs == ChannelStatus::Closed, "the client saw the server's");
    Buffer late;
    const uint8_t junk[7] = {23, 3, 3, 0, 2, 1, 1};
    put(late, junk, sizeof junk);
    Buffer o;
    check(p.server.receive(late, p.splain, o) == ChannelStatus::Closed && late.empty() && o.empty(),
          "bytes after close_notify are dropped unread");
}

void test_big_certificate(test_support::FakeCrypto &f) {
    where = "a certificate larger than a record";
    // \~english The Certificate message cannot fit in one record: it is split, and put back together (5.1).
    // \~spanish El mensaje Certificate no cabe en un registro: se parte, y se vuelve a juntar (5.1).  \~
    std::vector<uint8_t> cert(40000, 0xc3);
    Identity id = fake_identity(f);
    f.forget_key(id.key);
    id.cert = cert.data();
    id.cert_len = cert.size();
    // \~english The fake provider's key is tied to the certificate's bytes.  \~spanish La clave del proveedor de mentira va atada a los bytes del certificado.  \~
    id.key = f.signing_key(Scheme::EcdsaSecp256r1Sha256, cert.data(), cert.size());
    Pair p(f, id);
    check(p.shake(), "the handshake completes with a 40000-byte certificate");
    const uint8_t *got = nullptr;
    size_t n = 0;
    check(p.client.session()->peer_certificate(0, got, n) && n == cert.size(), "the client has it whole");
    Pair q(f, id);
    check(q.shake(1), "and a byte at a time");
    f.forget_key(id.key);
}

void test_alpn(test_support::FakeCrypto &f) {
    Identity id = fake_identity(f);
    {
        where = "alpn http/1.1";
        Pair p(f, id);
        p.ccfg.alpn = kH11;
        p.ccfg.alpn_count = 1;
        check(p.shake() && alpn_is(p.client, "http/1.1") && alpn_is(p.server, "http/1.1"), "the one both have");
    }
    {
        where = "alpn none offered";
        Pair p(f, id);
        p.ccfg.alpn_count = 0;
        check(p.shake() && alpn_is(p.client, nullptr) && alpn_is(p.server, nullptr), "no ALPN over TCP is allowed");
    }
    {
        where = "alpn none offered, required";
        Pair p(f, id);
        p.ccfg.alpn_count = 0;
        p.scfg.require_alpn = true;
        p.shake();
        check(p.server.failed() && p.server.alert() == Alert::NoApplicationProtocol, "a server that needs ALPN refuses");
        check(p.client.failed() && p.client.alert_received() && p.client.alert() == Alert::NoApplicationProtocol,
              "and the client reads why");
    }
    {
        where = "alpn nothing in common";
        Pair p(f, id);
        p.ccfg.alpn = kFoo;
        p.ccfg.alpn_count = 1;
        p.shake();
        check(p.server.alert() == Alert::NoApplicationProtocol && p.client.alert_received(),
              "no_application_protocol (RFC 7301, 3.2)");
    }
    {
        where = "transport parameters over tcp";
        Pair p(f, id);
        const uint8_t tp[2] = {1, 0};
        p.ccfg.transport_params = tp;
        p.ccfg.transport_params_len = 2;
        check(!p.start() && p.client.failed() && p.client.alert() == Alert::InternalError,
              "a TCP client refuses to send QUIC's parameters");
    }
    {
        where = "early data over tcp";
        Pair p(f, id);
        p.ccfg.early_data = true;
        check(!p.start() && p.client.failed(), "a TCP client refuses 0-RTT");
    }
    f.forget_key(id.key);
}

void test_retry_and_resume(test_support::FakeCrypto &f) {
    Identity id = fake_identity(f);
    {
        where = "hello retry";
        Pair p(f, id);
        p.ccfg.key_shares = 0;
        check(p.start(), "started");
        check(read_record_header(p.c2s.data()).version == kFirstHelloVersion, "the first ClientHello goes as 0x0301");
        p.run(1);
        check(p.client.open() && p.server.open() && p.client.session()->retried(), "complete after a retry");
    }
    {
        where = "resumption";
        const uint8_t key[TicketSealer::kKeySize] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
        const TicketSealer sealer(f, key);
        Pair p(f, id);
        p.scfg.tickets = &sealer;
        p.client.set_clock(1000000);
        p.server.set_clock(1000000);
        check(p.shake(), "the first connection");
        check(p.client.session()->tickets() == 2, "two tickets, read after the handshake");
        Ticket t;
        check(p.client.session()->take_ticket(t), "one taken");
        Pair q(f, id);
        q.scfg.tickets = &sealer;
        q.ccfg.resume = &t;
        q.client.set_clock(2000000);
        q.server.set_clock(2000000);
        check(q.shake(), "the second connection");
        check(q.client.session()->resumed() && q.server.session()->resumed(), "resumed, over TCP");
        check(!t.early_data, "and the ticket never allowed 0-RTT over TCP");
    }
    f.forget_key(id.key);
}

/* ------------------------------------------------------------------------- */

/// \~english A pair shaken hands, for the tests that break things after.  \~spanish Un par con el saludo hecho, para las pruebas que rompen cosas despues.  \~
struct Open {
    test_support::FakeCrypto &f;
    Identity id;
    Pair p;
    explicit Open(test_support::FakeCrypto &fc) : f(fc), id(fake_identity(fc)), p(fc, id) { p.shake(); }
    ~Open() { f.forget_key(id.key); }

    /// \~english Seals a record with the client's keys and hands it to the server.
    /// \~spanish Sella un registro con las claves del cliente y se lo da al servidor.  \~
    void client_record(ContentType type, const uint8_t *content, size_t n) {
        uint8_t rec[kRecordOverhead + 64];
        const size_t made = p.client.write_keys().seal(type, content, n, 0, rec, sizeof rec);
        put(p.c2s, rec, made);
    }

    /// \~english The server took it and failed with @p a, and the client read @p a.
    /// \~spanish El servidor lo tomo y fallo con @p a, y el cliente leyo @p a.  \~
    void expect(Alert a, const char *what) {
        p.run();
        check(p.server.failed() && p.server.alert() == a && !p.server.alert_received(), what);
        check(p.client.failed() && p.client.alert_received() && p.client.alert() == a, "the client reads the alert");
    }
};

void test_bad_records(test_support::FakeCrypto &f) {
    where = "bad records";
    {
        Open o(f);
        const uint8_t hi[2] = {'h', 'i'};
        o.p.client.send(hi, 2, o.p.c2s);
        o.p.c2s.writable()[8] ^= 1;
        o.expect(Alert::BadRecordMac, "a changed byte is bad_record_mac (5.2)");
    }
    {
        Open o(f);
        const uint8_t h[5] = {23, 3, 3, 0x41, 0x01};
        put(o.p.c2s, h, 5);
        o.expect(Alert::RecordOverflow, "2^14 + 257 is record_overflow, from the header alone (5.2)");
    }
    {
        Open o(f);
        const uint8_t r[6] = {22, 3, 3, 0, 1, 0};
        put(o.p.c2s, r, 6);
        o.expect(Alert::UnexpectedMessage, "an unprotected handshake record after protection (5.2)");
    }
    {
        Open o(f);
        const uint8_t r[6] = {24, 3, 3, 0, 1, 0};
        put(o.p.c2s, r, 6);
        o.expect(Alert::UnexpectedMessage, "an unknown record type (5)");
    }
    {
        Open o(f);
        const uint8_t r[6] = {20, 3, 3, 0, 1, 1};
        put(o.p.c2s, r, 6);
        o.expect(Alert::UnexpectedMessage, "change_cipher_spec after the Finished (5)");
    }
    {
        Open o(f);
        const uint8_t r[7] = {21, 3, 3, 0, 2, 2, 50};
        put(o.p.c2s, r, 7);
        o.expect(Alert::UnexpectedMessage, "an unprotected alert after the handshake (5.2)");
    }
    {
        Open o(f);
        const uint8_t one = 1;
        o.client_record(ContentType::ChangeCipherSpec, &one, 1);
        o.expect(Alert::UnexpectedMessage, "a protected change_cipher_spec (5)");
    }
    {
        Open o(f);
        o.client_record(ContentType::Alert, nullptr, 0);
        o.expect(Alert::UnexpectedMessage, "a zero-length alert (5.4)");
    }
    {
        Open o(f);
        const uint8_t three[3] = {2, 10, 0};
        o.client_record(ContentType::Alert, three, 3);
        o.expect(Alert::DecodeError, "an alert record with more than one alert (5.1)");
    }
    {
        Open o(f);
        o.client_record(ContentType::Handshake, nullptr, 0);
        o.expect(Alert::UnexpectedMessage, "a zero-length handshake record (5.4)");
    }
    {
        Open o(f);
        o.client_record(ContentType::Invalid, nullptr, 0);
        o.expect(Alert::UnexpectedMessage, "all padding, no content type (5.4)");
    }
    {
        Open o(f);
        for (int i = 0; i < 33; ++i) o.client_record(ContentType::ApplicationData, nullptr, 0);
        o.expect(Alert::UnexpectedMessage, "33 empty records in a row");
        Open q(f);
        const uint8_t x = 'x';
        for (int round = 0; round < 2; ++round) {
            for (int i = 0; i < 32; ++i) q.client_record(ContentType::ApplicationData, nullptr, 0);
            q.client_record(ContentType::ApplicationData, &x, 1);
        }
        q.p.run();
        check(q.p.server.open() && q.p.splain.size() == 2, "32 are taken, and data resets the count");
    }
    {
        Open o(f);
        // \~english The peer's fatal alert: the connection ends and nothing is sent back (6.2).
        // \~spanish La alerta fatal del otro: la conexion acaba y no se contesta nada (6.2).  \~
        const uint8_t alert[2] = {2, 47};
        o.client_record(ContentType::Alert, alert, 2);
        move(o.p.c2s, o.p.at_server, ~size_t{0});
        check(o.p.server.receive(o.p.at_server, o.p.splain, o.p.s2c) == ChannelStatus::Failed, "the server fails");
        check(o.p.server.alert_received() && o.p.server.alert() == Alert::IllegalParameter && o.p.s2c.empty(),
              "on the peer's illegal_parameter, sending nothing");
        Open q(f);
        const uint8_t unknown[2] = {1, 200};
        q.client_record(ContentType::Alert, unknown, 2);
        q.p.run();
        check(q.p.server.failed() && q.p.server.alert_received(), "an unknown alert is fatal, even as a warning (6)");
        Open u(f);
        const uint8_t canceled[2] = {1, 90};
        u.client_record(ContentType::Alert, canceled, 2);
        u.p.run();
        check(u.p.server.open(), "user_canceled is a closure alert and does not end it alone (6.1)");
    }
    {
        Open o(f);
        // \~english Application data inside a split handshake message (5.1).  \~spanish Datos de aplicacion dentro de un mensaje del saludo partido (5.1).  \~
        const uint8_t half[2] = {24, 0};
        o.client_record(ContentType::Handshake, half, 2);
        const uint8_t x = 'x';
        o.client_record(ContentType::ApplicationData, &x, 1);
        o.expect(Alert::UnexpectedMessage, "no other record inside a handshake message");
    }
    {
        Open o(f);
        o.p.server.read_keys().set_sequence(~uint64_t{0});
        const uint8_t x = 'x';
        o.p.client.send(&x, 1, o.p.c2s);
        o.expect(Alert::UnexpectedMessage, "a peer's sequence number at its end");
    }
}

void test_key_update(test_support::FakeCrypto &f) {
    where = "key update";
    {
        Open o(f);
        // \~english Two requests while the server is silent: one answer (4.6.3).
        // \~spanish Dos peticiones mientras el servidor calla: una respuesta (4.6.3).  \~
        o.p.client.key_update(true, o.p.c2s);
        o.p.client.key_update(true, o.p.c2s);
        o.p.run();
        check(o.p.server.key_updates_received() == 2 && o.p.server.key_updates_sent() == 1, "two taken, one answer");
        check(o.p.client.key_updates_received() == 1 && o.p.client.open(), "the client took it");
    }
    {
        Open o(f);
        // \~english A KeyUpdate split across two records, both under the old keys.
        // \~spanish Un KeyUpdate partido entre dos registros, los dos con las claves viejas.  \~
        const uint8_t ku[5] = {24, 0, 0, 1, 0};
        o.client_record(ContentType::Handshake, ku, 3);
        o.client_record(ContentType::Handshake, ku + 3, 2);
        o.p.run();
        check(o.p.server.open() && o.p.server.key_updates_received() == 1, "put back together, then applied");
        o.p.client.write_keys().update();
        const uint8_t x = 'x';
        o.client_record(ContentType::ApplicationData, &x, 1);
        o.p.run();
        check(o.p.splain.size() == 1, "and the next record opens with the new keys");
    }
    {
        Open o(f);
        const uint8_t ku[6] = {24, 0, 0, 1, 0, 23};
        o.client_record(ContentType::Handshake, ku, 6);
        o.expect(Alert::UnexpectedMessage, "a KeyUpdate that does not end its record (5.1)");
    }
    {
        Open o(f);
        const uint8_t ku[5] = {24, 0, 0, 1, 2};
        o.client_record(ContentType::Handshake, ku, 5);
        o.expect(Alert::IllegalParameter, "request_update 2 is illegal_parameter (4.6.3)");
    }
    {
        Open o(f);
        const uint8_t ku[6] = {24, 0, 0, 2, 0, 0};
        o.client_record(ContentType::Handshake, ku, 6);
        o.expect(Alert::DecodeError, "a KeyUpdate of two bytes is decode_error");
    }
    {
        Open o(f);
        const uint8_t nst[8] = {4, 0, 0, 4, 0, 0, 0, 0};
        o.client_record(ContentType::Handshake, nst, 8);
        o.expect(Alert::UnexpectedMessage, "a server takes no post-handshake message but KeyUpdate (4.6)");
    }
    {
        Open o(f);
        // \~english Refused from its header, before the rest of it is waited for.
        // \~spanish Rechazado por su cabecera, antes de esperar el resto.  \~
        const uint8_t nst[4] = {4, 0, 0x10, 0};
        o.client_record(ContentType::Handshake, nst, 4);
        o.expect(Alert::UnexpectedMessage, "a post-handshake message a server does not take, from its header");
    }
    {
        Open o(f);
        // \~english On its own, after N records: the reader follows without being told how many.
        // \~spanish Por su cuenta, tras N registros: el que lee sigue sin que le digan cuantos.  \~
        o.p.client.set_key_update_after(3);
        const uint8_t x[10] = {};
        for (int i = 0; i < 10; ++i) o.p.client.send(x, 10, o.p.c2s);
        o.p.run();
        check(o.p.client.key_updates_sent() == 3 && o.p.server.key_updates_received() == 3, "every third record");
        check(o.p.splain.size() == 100 && o.p.server.open(), "and nothing lost");
    }
    {
        Open o(f);
        // \~english Near the end of the numbers, the writer updates rather than wrap (5.3).
        // \~spanish Cerca del final de los numeros, el que escribe actualiza en vez de dar la vuelta (5.3).  \~
        o.p.client.write_keys().set_sequence(~uint64_t{0} - 1);
        o.p.server.read_keys().set_sequence(~uint64_t{0} - 1);
        const uint8_t x = 'x';
        check(o.p.client.send(&x, 1, o.p.c2s), "the send goes");
        o.p.run();
        check(o.p.client.key_updates_sent() == 1 && o.p.splain.size() == 1 && o.p.server.open(), "after a KeyUpdate");
    }
}

/* ------------------------------------------------------------------------- */

/// \~english The client's first record, taken out of @p p to be changed by hand.  \~spanish El primer registro del cliente, sacado de @p p para cambiarlo a mano.  \~
std::vector<uint8_t> take_hello(Pair &p) {
    p.start();
    std::vector<uint8_t> r(p.c2s.data(), p.c2s.data() + p.c2s.size());
    p.c2s.consume(p.c2s.size());
    return r;
}

/// \~english Fixes the record and message lengths after @p grow bytes were added to a ClientHello record.
/// \~spanish Arregla las longitudes del registro y del mensaje tras anadir @p grow bytes a un registro ClientHello.  \~
void grow_lengths(std::vector<uint8_t> &r, size_t grow) {
    const size_t rec = (size_t{r[3]} << 8 | r[4]) + grow;
    r[3] = static_cast<uint8_t>(rec >> 8);
    r[4] = static_cast<uint8_t>(rec);
    const size_t msg = (size_t{r[6]} << 16 | size_t{r[7]} << 8 | r[8]) + grow;
    r[6] = static_cast<uint8_t>(msg >> 16);
    r[7] = static_cast<uint8_t>(msg >> 8);
    r[8] = static_cast<uint8_t>(msg);
}

/// \~english Where the extensions' length is in a ClientHello record.  \~spanish Donde esta la longitud de las extensiones en un registro ClientHello.  \~
size_t extensions_at(const std::vector<uint8_t> &r) {
    size_t at = 5 + 4 + 2 + 32;
    at += 1 + r[at];
    at += 2 + (size_t{r[at]} << 8 | r[at + 1]);
    at += 1 + r[at];
    return at;
}

/// \~english Appends an extension to a ClientHello record.  \~spanish Anade una extension a un registro ClientHello.  \~
void add_extension(std::vector<uint8_t> &r, uint16_t type, const uint8_t *data, size_t n) {
    const size_t at = extensions_at(r);
    const size_t len = (size_t{r[at]} << 8 | r[at + 1]) + 4 + n;
    r[at] = static_cast<uint8_t>(len >> 8);
    r[at + 1] = static_cast<uint8_t>(len);
    r.push_back(static_cast<uint8_t>(type >> 8));
    r.push_back(static_cast<uint8_t>(type));
    r.push_back(static_cast<uint8_t>(n >> 8));
    r.push_back(static_cast<uint8_t>(n));
    r.insert(r.end(), data, data + n);
    grow_lengths(r, 4 + n);
}

void test_hello_rules(test_support::FakeCrypto &f) {
    Identity id = fake_identity(f);
    {
        where = "compatibility mode";
        // \~english A 32-byte session ID: the server echoes it and sends change_cipher_spec after the ServerHello (D.4).
        // \~spanish Un identificador de sesion de 32 bytes: el servidor lo devuelve y manda change_cipher_spec tras el ServerHello (D.4).  \~
        Pair p(f, id);
        std::vector<uint8_t> r = take_hello(p);
        r[5 + 4 + 2 + 32] = 32;
        r.insert(r.begin() + 5 + 4 + 2 + 32 + 1, 32, 0xab);
        grow_lengths(r, 32);
        put(p.at_server, r);
        p.server.receive(p.at_server, p.splain, p.s2c);
        const uint8_t *s = p.s2c.data();
        const size_t sh = kRecordHeader + read_record_header(s).length;
        check(s[5] == 2 && s[5 + 4 + 2 + 32] == 32 && s[5 + 4 + 2 + 32 + 1] == 0xab, "the ServerHello echoes the ID");
        const uint8_t ccs[6] = {20, 3, 3, 0, 1, 1};
        check(p.s2c.size() > sh + 6 && std::memcmp(s + sh, ccs, 6) == 0, "a change_cipher_spec right after it");
        // \~english Our client sent no ID: an echo that is not what it sent is illegal_parameter (4.1.3).
        // \~spanish Nuestro cliente no mando identificador: un eco que no es lo que mando es illegal_parameter (4.1.3).  \~
        p.run();
        check(p.client.failed() && p.client.alert() == Alert::IllegalParameter, "a client refuses a wrong echo");
    }
    {
        where = "compatibility mode and a retry";
        // \~english The HelloRetryRequest echoes the ID too, with the CCS after it; the second hello keeps it (4.1.2, D.4).
        // \~spanish El HelloRetryRequest devuelve tambien el identificador, con el CCS detras; el segundo saludo lo conserva (4.1.2, D.4).  \~
        Pair p(f, id);
        p.ccfg.key_shares = 0;
        const std::vector<uint8_t> plain_hello = take_hello(p);
        std::vector<uint8_t> r = plain_hello;
        r[5 + 4 + 2 + 32] = 32;
        r.insert(r.begin() + 5 + 4 + 2 + 32 + 1, 32, 0xcd);
        grow_lengths(r, 32);
        put(p.at_server, r);
        p.server.receive(p.at_server, p.splain, p.s2c);
        const uint8_t *s = p.s2c.data();
        const size_t hrr = kRecordHeader + read_record_header(s).length;
        const uint8_t ccs[6] = {20, 3, 3, 0, 1, 1};
        check(s[5 + 4 + 2 + 32] == 32 && s[5 + 4 + 2 + 32 + 1] == 0xcd && std::memcmp(s + hrr, ccs, 6) == 0,
              "the HelloRetryRequest echoes the ID, and a CCS follows it");
        put(p.at_server, plain_hello);
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(p.server.failed() && p.server.alert() == Alert::IllegalParameter && p.server.why() != nullptr &&
                  std::strstr(p.server.why(), "legacy_session_id") != nullptr,
              "a second ClientHello with another session ID is illegal_parameter");
    }
    {
        where = "change_cipher_spec dropped";
        Pair p(f, id);
        p.start();
        move(p.c2s, p.at_server, ~size_t{0});
        p.server.receive(p.at_server, p.splain, p.s2c);
        move(p.s2c, p.at_client, ~size_t{0});
        // \~english The client's CCS before its second flight, and the server's before its encrypted one (D.4).
        // \~spanish El CCS del cliente antes de su segundo vuelo, y el del servidor antes del cifrado (D.4).  \~
        const uint8_t ccs[6] = {20, 3, 3, 0, 1, 1};
        std::vector<uint8_t> with(p.at_client.data(), p.at_client.data() + p.at_client.size());
        const size_t sh = kRecordHeader + read_record_header(with.data()).length;
        with.insert(with.begin() + sh, ccs, ccs + 6);
        p.at_client.consume(p.at_client.size());
        put(p.at_client, with);
        p.client.receive(p.at_client, p.cplain, p.c2s);
        put(p.at_server, ccs, 6);
        p.run();
        check(p.client.open() && p.server.open(), "both dropped, the handshake completes");
        Pair q(f, id);
        const uint8_t bad[6] = {20, 3, 3, 0, 1, 2};
        put(q.at_server, bad, 6);
        q.server.receive(q.at_server, q.splain, q.s2c);
        check(q.server.failed() && q.server.alert() == Alert::UnexpectedMessage, "a CCS before any ClientHello");
        Pair w(f, id);
        put(w.at_server, take_hello(w));
        const uint8_t two[7] = {20, 3, 3, 0, 2, 1, 1};
        put(w.at_server, two, 7);
        w.server.receive(w.at_server, w.splain, w.s2c);
        check(w.server.failed() && w.server.alert() == Alert::UnexpectedMessage, "a CCS of two bytes, after the hello");
        Pair v(f, id);
        put(v.at_server, take_hello(v));
        put(v.at_server, bad, 6);
        v.server.receive(v.at_server, v.splain, v.s2c);
        check(v.server.failed() && v.server.alert() == Alert::UnexpectedMessage, "a CCS of 0x02, after the hello");
    }
    {
        where = "hello record rules";
        Pair p(f, id);
        std::vector<uint8_t> r = take_hello(p);
        r.push_back(1);
        r.push_back(0);
        r.push_back(0);
        r.push_back(0);
        const size_t rec = (size_t{r[3]} << 8 | r[4]) + 4;
        r[3] = static_cast<uint8_t>(rec >> 8);
        r[4] = static_cast<uint8_t>(rec);
        put(p.at_server, r);
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(p.server.failed() && p.server.alert() == Alert::UnexpectedMessage,
              "bytes after the ClientHello in its record: a message across a key change (5.1)");
        Pair q(f, id);
        const uint8_t app[6] = {23, 3, 3, 0, 1, 0};
        put(q.at_server, app, 6);
        q.server.receive(q.at_server, q.splain, q.s2c);
        const uint8_t fatal[7] = {21, 3, 3, 0, 2, 2, 10};
        check(q.server.alert() == Alert::UnexpectedMessage && q.s2c.size() == 7 && std::memcmp(q.s2c.data(), fatal, 7) == 0,
              "application data before the handshake: a fatal unexpected_message, in the clear (6)");
        Pair z(f, id);
        const uint8_t empty[5] = {22, 3, 1, 0, 0};
        put(z.at_server, empty, 5);
        z.server.receive(z.at_server, z.splain, z.s2c);
        check(z.server.alert() == Alert::UnexpectedMessage, "a zero-length handshake fragment (5.1)");
        Pair b(f, id);
        const uint8_t huge[5] = {22, 3, 1, 0x40, 0x01};
        put(b.at_server, huge, 5);
        b.server.receive(b.at_server, b.splain, b.s2c);
        check(b.server.alert() == Alert::RecordOverflow, "a plaintext record over 2^14 (5.1)");
        Pair m(f, id);
        const uint8_t big_msg[9] = {22, 3, 1, 0, 4, 1, 2, 0, 0};
        put(m.at_server, big_msg, 9);
        m.server.receive(m.at_server, m.splain, m.s2c);
        check(m.server.alert() == Alert::IllegalParameter, "a message announced past what is buffered");
        Pair t(f, id);
        std::vector<uint8_t> h = take_hello(t);
        const uint8_t tp[2] = {1, 0};
        add_extension(h, ext::QuicTransportParameters, tp, 2);
        put(t.at_server, h);
        t.run();
        check(t.server.alert() == Alert::UnsupportedExtension && t.client.alert_received(),
              "quic_transport_parameters over TCP is unsupported_extension (RFC 9001, 8.2)");
    }
    {
        where = "early data skipped";
        // \~english An early_data offer turned down: records that fail under the handshake keys are skipped (4.2.10).
        // \~spanish Una oferta de early_data rechazada: los registros que fallan con las claves del saludo se saltan (4.2.10).  \~
        Pair p(f, id);
        std::vector<uint8_t> h = take_hello(p);
        add_extension(h, ext::EarlyData, nullptr, 0);
        put(p.at_server, h);
        std::vector<uint8_t> early(kRecordHeader + 300, 0x5c);
        early[0] = 23;
        early[1] = 3;
        early[2] = 3;
        early[3] = 300 >> 8;
        early[4] = 300 & 0xff;
        put(p.at_server, early);
        put(p.at_server, early);
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(!p.server.failed() && p.server.early_skipped() == 600, "600 bytes of early data skipped");
        std::vector<uint8_t> flood(kRecordHeader + kMaxCiphertext, 0x5c);
        flood[0] = 23;
        flood[1] = 3;
        flood[2] = 3;
        flood[3] = static_cast<uint8_t>(kMaxCiphertext >> 8);
        flood[4] = static_cast<uint8_t>(kMaxCiphertext);
        for (int i = 0; i < 4 && !p.server.failed(); ++i) {
            put(p.at_server, flood);
            p.server.receive(p.at_server, p.splain, p.s2c);
        }
        check(p.server.failed() && p.server.alert() == Alert::BadRecordMac, "past the budget, bad_record_mac");

        Pair q(f, id);
        q.ccfg.key_shares = 0;
        std::vector<uint8_t> hq = take_hello(q);
        add_extension(hq, ext::EarlyData, nullptr, 0);
        put(q.at_server, hq);
        put(q.at_server, early);
        q.server.receive(q.at_server, q.splain, q.s2c);
        check(!q.server.failed() && q.server.early_skipped() == 300, "after a HelloRetryRequest, by the outer type");
    }
    f.forget_key(id.key);
}

void test_seams(test_support::FakeCrypto &f) {
    Identity id = fake_identity(f);
    {
        where = "data under handshake keys";
        // \~english Application data sealed with the client's handshake keys: before its Finished (2, 5.1).
        // \~spanish Datos de aplicacion sellados con las claves del saludo del cliente: antes de su Finished (2, 5.1).  \~
        Pair p(f, id);
        p.start();
        move(p.c2s, p.at_server, ~size_t{0});
        p.server.receive(p.at_server, p.splain, p.s2c);
        move(p.s2c, p.at_client, ~size_t{0});
        p.client.receive(p.at_client, p.cplain, p.c2s);
        p.c2s.consume(p.c2s.size());
        RecordKeys k;
        k.install(f, p.client.session()->aead(), p.client.session()->write_secret(Space::Handshake));
        uint8_t rec[64];
        const uint8_t x = 'x';
        put(p.at_server, rec, k.seal(ContentType::ApplicationData, &x, 1, 0, rec, sizeof rec));
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(p.server.failed() && p.server.alert() == Alert::UnexpectedMessage && p.splain.empty(),
              "unexpected_message, and nothing reaches the application");
    }
    {
        where = "client alert under handshake keys";
        // \~english A client that fails on the encrypted flight says so under its handshake keys (6).
        // \~spanish Un cliente que falla con el vuelo cifrado lo dice con sus claves del saludo (6).  \~
        Pair p(f, id);
        p.start();
        move(p.c2s, p.at_server, ~size_t{0});
        p.server.receive(p.at_server, p.splain, p.s2c);
        move(p.s2c, p.at_client, ~size_t{0});
        const size_t sh = kRecordHeader + read_record_header(p.at_client.data()).length;
        p.at_client.writable()[sh + kRecordHeader + 3] ^= 1;
        p.client.receive(p.at_client, p.cplain, p.c2s);
        check(p.client.alert() == Alert::BadRecordMac && read_record_header(p.c2s.data()).type == 23,
              "bad_record_mac, in a protected record");
        p.run();
        check(p.server.alert_received() && p.server.alert() == Alert::BadRecordMac, "which the server opens and reads");
    }
    {
        where = "early skip ends";
        // \~english After the first record that opens, a forged one is bad_record_mac again (4.2.10).
        // \~spanish Tras el primer registro que se abre, uno falsificado vuelve a ser bad_record_mac (4.2.10).  \~
        Pair p(f, id);
        std::vector<uint8_t> h = take_hello(p);
        add_extension(h, ext::EarlyData, nullptr, 0);
        put(p.at_server, h);
        p.server.receive(p.at_server, p.splain, p.s2c);
        RecordKeys k;
        k.install(f, p.server.session()->aead(), p.server.session()->read_secret(Space::Handshake));
        uint8_t rec[64];
        const uint8_t canceled[2] = {1, 90};
        put(p.at_server, rec, k.seal(ContentType::Alert, canceled, 2, 0, rec, sizeof rec));
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(!p.server.failed(), "a record that opens ends the skipping");
        const uint8_t junk[5 + 20] = {23, 3, 3, 0, 20};
        put(p.at_server, junk, sizeof junk);
        p.server.receive(p.at_server, p.splain, p.s2c);
        check(p.server.failed() && p.server.alert() == Alert::BadRecordMac && p.server.early_skipped() == 0,
              "and the next forged one is bad_record_mac");
    }
    f.forget_key(id.key);
}

void test_no_early_skip(test_support::FakeCrypto &f) {
    where = "no early data offered";
    Identity id = fake_identity(f);
    Pair p(f, id);
    std::vector<uint8_t> h = take_hello(p);
    put(p.at_server, h);
    std::vector<uint8_t> early(kRecordHeader + 30, 0x5c);
    early[0] = 23;
    early[1] = 3;
    early[2] = 3;
    early[3] = 0;
    early[4] = 30;
    put(p.at_server, early);
    p.server.receive(p.at_server, p.splain, p.s2c);
    check(p.server.failed() && p.server.alert() == Alert::BadRecordMac && p.server.early_skipped() == 0,
          "without an early_data offer a bad record is bad_record_mac at once");
    f.forget_key(id.key);
}

void test_client_side(test_support::FakeCrypto &f) {
    where = "client side";
    Identity id = fake_identity(f);
    Pair p(f, id);
    Buffer out;
    Buffer in;
    const uint8_t r[6] = {22, 3, 3, 0, 1, 0};
    put(in, r, 6);
    check(p.client.receive(in, p.cplain, out) == ChannelStatus::Failed, "a client that never started takes nothing");
    Pair q(f, id);
    check(q.start(), "started");
    check(!q.client.start(q.c2s), "start twice is refused");
    check(!q.client.send(r, 1, q.c2s) && !q.client.key_update(false, q.c2s), "no data nor KeyUpdate before the handshake");
    f.forget_key(id.key);
}

/* ------------------------------------------------------------------------- */

void run_real(Crypto &cc, Crypto &sc, const uint8_t *cert, size_t cert_len, void *key, const char *name) {
    Identity id;
    id.c = &sc;
    id.cert = cert;
    id.cert_len = cert_len;
    id.key = key;
    test_handshake_and_data(cc, id, name, ~size_t{0});
    where = name;
    Pair p(cc, id);
    check(p.shake(7), "seven bytes at a time");
    p.client.set_padding(64);
    const uint8_t x[5] = {1, 2, 3, 4, 5};
    p.client.send(x, 5, p.c2s);
    check(read_record_header(p.c2s.data()).length == 64 + 16, "padded to 64 (5.4)");
    p.run();
    check(p.splain.size() == 5 && std::memcmp(p.splain.data(), x, 5) == 0, "padding stripped");
}

} // namespace

int main() {
    test_support::FakeCrypto fake;
    Identity id = fake_identity(fake);
    test_handshake_and_data(fake, id, "fake, whole", ~size_t{0});
    test_handshake_and_data(fake, id, "fake, a byte at a time", 1);
    fake.forget_key(id.key);
    test_big_certificate(fake);
    test_alpn(fake);
    test_retry_and_resume(fake);
    test_bad_records(fake);
    test_key_update(fake);
    test_hello_rules(fake);
    test_no_early_skip(fake);
    test_seams(fake);
    test_client_side(fake);

    int providers = 0;
    uint8_t cert[2048];
    uint8_t pkcs8[2048];
    const size_t cert_len = rfc8448::from_hex(test_keys::kP256Certificate, cert, sizeof cert);
    const size_t key_len = rfc8448::from_hex(test_keys::kP256Pkcs8, pkcs8, sizeof pkcs8);
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    void *ok = openssl.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len);
    run_real(openssl, openssl, cert, cert_len, ok, "openssl");
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    void *ck = cng.ready() ? cng.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len) : nullptr;
    if (ck != nullptr) {
        run_real(cng, cng, cert, cert_len, ck, "cng");
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
#if HTTP_VX_HAVE_OPENSSL && HTTP_VX_HAVE_CNG
    if (ck != nullptr) run_real(openssl, cng, cert, cert_len, ck, "openssl client, cng server");
    if (ck != nullptr) run_real(cng, openssl, cert, cert_len, ok, "cng client, openssl server");
    if (ck != nullptr) cng.forget_key(ck);
#endif
#if HTTP_VX_HAVE_OPENSSL
    openssl.forget_key(ok);
#endif
    (void)cert_len;
    (void)key_len;
    if (providers == 0) std::printf("SKIPPED: no real provider built, real handshakes not run\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls channel, %d provider(s): OK\n", providers);
    return 0;
}
