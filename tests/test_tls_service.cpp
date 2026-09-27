/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_service.cpp
 * @brief
 * \~english HTTPS end to end: our TLS client against the TLS service, with a real Http1Service and Http2Service inside.
 * \~spanish HTTPS de punta a punta: nuestro cliente TLS contra el servicio TLS, con un Http1Service y un Http2Service de verdad dentro.
 * \~
 *
 * \~english
 * The service is driven as the shard drives it -- on_open, on_bytes with the
 * bytes that arrived and a fresh output, on_close -- and the client is a
 * Channel.  ALPN must pick the inner service and the same handler must
 * answer on both; a request in the same read as the client's Finished must
 * be answered; a request a byte at a time too.  Between exchanges no
 * plaintext buffer may be held (R1).  And a service that cannot serve TLS
 * must say so when it is set up (R24), not fall back to plaintext.
 * \~spanish
 * El servicio se lleva como lo lleva el fragmento -- on_open, on_bytes con los
 * bytes que llegaron y una salida nueva, on_close -- y el cliente es un
 * Channel.  ALPN tiene que elegir el servicio de dentro y el mismo manejador
 * tiene que contestar en los dos; una peticion en la misma lectura que el
 * Finished del cliente tiene que contestarse; una peticion de byte en byte
 * tambien.  Entre intercambios no se puede tener ningun buffer en claro (R1).
 * Y un servicio que no puede servir TLS tiene que decirlo al prepararse (R24),
 * no caer a texto claro.
 * \~
 */

#include "http_vx/http2_service.h"
#include "http_vx/tls_service.h"

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
#include <string>

namespace {

using http_vx::Buffer;
using http_vx::ConnHandle;
using http_vx::TlsService;
using http_vx::TlsServiceConfig;
using http_vx::quic::Crypto;
using http_vx::quic::Scheme;
using namespace http_vx::tls;

int failures = 0;
const char *where = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", where, what);
    ++failures;
}

const char *const kBoth[] = {"h2", "http/1.1"};
const char *const kH2[] = {"h2"};
const char *const kH11[] = {"http/1.1"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};

/// \~english The same handler for both versions: the target and the body's size; "/open" opens @c source.
/// \~spanish El mismo manejador para las dos versiones: el destino y el tamano del cuerpo; "/open" abre @c source.  \~
class Echo final : public http_vx::Handler {
public:
    void handle(const http_vx::Request &req, const uint8_t *head, const uint8_t *, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        if (source != nullptr && req.target.len == 5 &&
            std::memcmp(reinterpret_cast<const char *>(head) + req.target.off, "/open", 5) == 0) {
            opened = res.open(*source);
            return;
        }
        char text[256];
        const int len = std::snprintf(text, sizeof text, "you asked for %.*s with %zu bytes",
                                      static_cast<int>(req.target.len),
                                      reinterpret_cast<const char *>(head) + req.target.off, n);
        res.body(text, static_cast<size_t>(len));
    }

    http_vx::BodySource *source = nullptr;
    http_vx::OpenResponse opened;
};

/// \~english A source the test feeds by hand.  \~spanish Una fuente que la prueba alimenta a mano.  \~
class Stream final : public http_vx::BodySource {
public:
    size_t fill(http_vx::OpenResponse, uint8_t *dst, size_t room, bool &done) noexcept override {
        size_t n = 0;
        if (full_fills != 0) {
            --full_fills;
            std::memset(dst, 'x', room);
            n = room;
        } else {
            n = pending.size() < room ? pending.size() : room;
            std::memcpy(dst, pending.data(), n);
            pending.erase(0, n);
        }
        done = finish && pending.empty() && full_fills == 0;
        return n;
    }

    void gone(http_vx::OpenResponse, http_vx::GoneReason why) noexcept override {
        ++gones;
        last = why;
    }

    std::string pending;
    bool finish = false;
    int full_fills = 0;
    int gones = 0;
    http_vx::GoneReason last = http_vx::GoneReason::Finished;
};

/**
 * @brief
 * \~english The shard's side, played by the test over a real kick queue: it records what the service asks for.
 * \~spanish El lado del fragmento, hecho por la prueba sobre una cola de avisos de verdad: apunta lo que pide el servicio.
 * \~
 */
class TestPort final : public http_vx::StreamPort {
public:
    http_vx::OpenResponse open(ConnHandle c, uint64_t stream, http_vx::BodySource &s,
                               http_vx::KickTarget &target) noexcept override {
        http_vx::OpenResponse r;
        r.conn = c;
        r.stream = stream;
        kicks.open(s, target, r);
        return r;
    }
    size_t fill(http_vx::BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override {
        done = false;
        const size_t n = s.fill(s.response(), dst, room, done);
        return n < room ? n : room;
    }
    void end(http_vx::BodySource &s, http_vx::GoneReason why) noexcept override { kicks.close(s, why); }
    void want_writable(ConnHandle) noexcept override { ++writable; }
    void hold_reads(ConnHandle, bool hold) noexcept override {
        held = hold;
        if (!hold) ++resumes;
    }
    http_vx::GoneReason closing_reason(ConnHandle) const noexcept override {
        return http_vx::GoneReason::ConnectionClosed;
    }

    http_vx::KickQueue kicks;
    int writable = 0;
    int resumes = 0;
    bool held = false;
};

void put(Buffer &b, const void *p, size_t n) {
    uint8_t *at = b.reserve(n);
    std::memcpy(at, p, n);
    b.commit(n);
}

size_t move(Buffer &from, Buffer &to, size_t n) {
    const size_t take = from.size() < n ? from.size() : n;
    if (take != 0) put(to, from.data(), take);
    from.consume(take);
    return take;
}

std::string text(const Buffer &b) {
    return std::string(reinterpret_cast<const char *>(b.data()), b.size());
}

/**
 * @brief
 * \~english One server -- both inner services and the TLS one -- and a client per test.
 * \~spanish Un servidor -- los dos servicios de dentro y el TLS -- y un cliente por prueba.
 * \~
 */
struct Server {
    Echo echo;
    http_vx::Http1Service h1;
    http_vx::Http2Service h2;
    TlsService tls;
    const uint8_t *certs[1];
    size_t lens[1];
    bool ok = false;

    Server(Crypto &c, const uint8_t *cert, size_t cert_len, void *key, bool with_h1, bool with_h2,
           uint32_t buffers = 8) {
        const http_vx::h1::Limits l1;
        const http_vx::h2::Limits l2;
        certs[0] = cert;
        lens[0] = cert_len;
        TlsServiceConfig cfg;
        cfg.crypto = &c;
        cfg.http1 = with_h1 ? &h1 : nullptr;
        cfg.http2 = with_h2 ? &h2 : nullptr;
        cfg.certificates = certs;
        cfg.certificate_lens = lens;
        cfg.certificate_count = 1;
        cfg.signing_key = key;
        cfg.buffers = buffers;
        ok = h1.reset(4, echo, l1) && h2.reset(4, 4, 1 << 16, echo, l2) && tls.reset(4, cfg);
    }
};

/**
 * @brief
 * \~english A client connection to @c Server, driven as the shard would drive the server's side.
 * \~spanish Una conexion cliente a @c Server, llevada como llevaria el fragmento el lado del servidor.
 * \~
 */
struct Client {
    SessionConfig cfg;
    Channel ch;
    Server &srv;
    ConnHandle conn;
    Buffer c2s;
    Buffer in;
    Buffer s2c;
    Buffer plain;
    bool alive = true;

    Client(Crypto &c, Server &s, uint32_t slot, const char *const *alpn, size_t alpn_count) : srv(s) {
        cfg.over_tcp = true;
        cfg.alpn = alpn;
        cfg.alpn_count = alpn_count;
        cfg.trust_any_certificate = true;
        ch.configure(c, cfg);
        conn.slot = slot;
        conn.life = 1;
        srv.tls.on_open(conn);
        ch.start(c2s);
    }

    ~Client() {
        srv.tls.on_close(conn);
    }

    /// \~english Delivers both ways, @p chunk bytes at a time, until nothing moves.
    /// \~spanish Entrega en los dos sentidos, de @p chunk en @p chunk bytes, hasta que nada se mueve.  \~
    void run(size_t chunk = ~size_t{0}) {
        for (int round = 0; round < 1000000; ++round) {
            size_t moved = 0;
            if (alive && !c2s.empty()) {
                moved += move(c2s, in, chunk);
                Buffer out;
                alive = srv.tls.on_bytes(conn, in, out);
                put(s2c, out.data(), out.size());
            }
            Buffer got;
            moved += move(s2c, got, ~size_t{0});
            if (!got.empty()) ch.receive(got, plain, c2s);
            if (moved == 0) return;
        }
    }

    bool send(const std::string &s) {
        return ch.send(reinterpret_cast<const uint8_t *>(s.data()), s.size(), c2s);
    }
};

/// \~english An HTTP/2 frame header and payload.  \~spanish La cabecera y la carga de una trama HTTP/2.  \~
std::string frame(uint8_t type, uint8_t flags, uint32_t id, const std::string &payload) {
    std::string f;
    const size_t n = payload.size();
    f += static_cast<char>(n >> 16);
    f += static_cast<char>(n >> 8);
    f += static_cast<char>(n);
    f += static_cast<char>(type);
    f += static_cast<char>(flags);
    f += static_cast<char>((id >> 24) & 0x7f);
    f += static_cast<char>(id >> 16);
    f += static_cast<char>(id >> 8);
    f += static_cast<char>(id);
    return f + payload;
}

/// \~english A literal field without indexing, new name (RFC 7541, 6.2.2).  \~spanish Un campo literal sin indexar, nombre nuevo (RFC 7541, 6.2.2).  \~
std::string field(const char *name, const char *value) {
    std::string s(1, '\0');
    s += static_cast<char>(std::strlen(name));
    s += name;
    s += static_cast<char>(std::strlen(value));
    s += value;
    return s;
}

std::string h2_request(uint32_t stream, const char *path) {
    const std::string block =
        field(":method", "GET") + field(":scheme", "https") + field(":authority", "example.com") + field(":path", path);
    return frame(1, 0x4 | 0x1, stream, block);
}

/// \~english The DATA on @p stream in what the server sent, and whether a HEADERS came first.
/// \~spanish Los DATA de @p stream en lo que mando el servidor, y si antes llego un HEADERS.  \~
std::string h2_data(const Buffer &b, uint32_t stream, bool &headers) {
    std::string data;
    headers = false;
    const uint8_t *p = b.data();
    size_t at = 0;
    while (at + 9 <= b.size()) {
        const size_t n = size_t{p[at]} << 16 | size_t{p[at + 1]} << 8 | p[at + 2];
        const uint32_t id = (uint32_t{p[at + 5]} & 0x7f) << 24 | uint32_t{p[at + 6]} << 16 | uint32_t{p[at + 7]} << 8 |
                            p[at + 8];
        if (at + 9 + n > b.size()) break;
        if (id == stream && p[at + 3] == 1) headers = true;
        if (id == stream && p[at + 3] == 0) data.append(reinterpret_cast<const char *>(p + at + 9), n);
        at += 9 + n;
    }
    return data;
}

const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* ------------------------------------------------------------------------- */

void test_http1(Crypto &cc, Server &s, const char *name, size_t chunk) {
    where = name;
    Client c(cc, s, 0, kBoth + 1, 1);
    c.run(chunk);
    check(c.ch.open(), "the handshake completes");
    size_t n = 0;
    const uint8_t *a = c.ch.alpn(n);
    check(a != nullptr && n == 8 && std::memcmp(a, "http/1.1", 8) == 0, "ALPN chose http/1.1");
    check(s.tls.buffers_lent() == 0, "no plaintext buffer held after the handshake (R1)");
    const Channel *sc =s.tls.channel(c.conn);
    check(sc != nullptr && sc->session() == nullptr, "and the server gave its handshake memory back");
    c.send("GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n");
    c.run(chunk);
    const std::string r = text(c.plain);
    check(r.find("HTTP/1.1 200") == 0 && r.find("you asked for /one with 0 bytes") != std::string::npos,
          "HTTP/1.1 answered through TLS");
    c.plain.consume(c.plain.size());
    check(s.tls.buffers_lent() == 0, "no plaintext buffer held between requests (R1)");

    // \~english Half a request: the plaintext buffer is held, and given back when it completes.
    // \~spanish Media peticion: el buffer en claro se retiene, y se devuelve cuando se completa.  \~
    c.send("POST /two HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nab");
    c.run(chunk);
    check(s.tls.buffers_lent() == 1 && c.plain.empty(), "half a request holds one buffer");
    c.send("cde");
    c.run(chunk);
    check(text(c.plain).find("you asked for /two with 5 bytes") != std::string::npos, "the whole body arrived");
    check(s.tls.buffers_lent() == 0, "and the buffer went back");
    c.plain.consume(c.plain.size());

    // \~english The inner service ends the connection -- HTTP/1.0 without keep-alive -- and its answer still goes out.
    // \~spanish El servicio de dentro acaba la conexion -- HTTP/1.0 sin keep-alive -- y su respuesta sale igual.  \~
    c.send("GET /bye HTTP/1.0\r\n\r\n");
    c.run(chunk);
    check(text(c.plain).find("you asked for /bye") != std::string::npos, "the last answer went out");
    check(!c.alive && c.ch.peer_closed(), "then close_notify, and the connection ended (6.1)");
}

void test_http2(Crypto &cc, Server &s, const char *name, size_t chunk) {
    where = name;
    Client c(cc, s, 1, kBoth, 2);
    // \~english The server's flight in, then Finished and the request in the SAME read.
    // \~spanish El vuelo del servidor, y luego el Finished y la peticion en la MISMA lectura.  \~
    Buffer in;
    move(c.c2s, in, ~size_t{0});
    Buffer out;
    s.tls.on_bytes(c.conn, in, out);
    c.ch.receive(out, c.plain, c.c2s);
    check(c.ch.open(), "the client is done");
    c.send(std::string(kPreface) + frame(4, 0, 0, "") + h2_request(1, "/h2path"));
    c.run(chunk);
    size_t n = 0;
    const uint8_t *a = c.ch.alpn(n);
    check(a != nullptr && n == 2 && std::memcmp(a, "h2", 2) == 0, "ALPN chose h2, the server's preference");
    bool headers = false;
    const std::string data = h2_data(c.plain, 1, headers);
    check(headers && data.find("you asked for /h2path with 0 bytes") != std::string::npos,
          "HTTP/2 answered through TLS, by the same handler");
    check(s.tls.buffers_lent() == 0, "no plaintext buffer held after it (R1)");

    // \~english A KeyUpdate from the client, answered, and the next request under new keys.
    // \~spanish Un KeyUpdate del cliente, contestado, y la peticion siguiente con claves nuevas.  \~
    c.plain.consume(c.plain.size());
    c.ch.key_update(true, c.c2s);
    c.send(h2_request(3, "/after-update"));
    c.run(chunk);
    const std::string again = h2_data(c.plain, 3, headers);
    check(headers && again.find("/after-update") != std::string::npos, "answered under the updated keys");
    check(c.ch.key_updates_received() == 1, "and the server updated its own when asked");
    c.ch.close(c.c2s);
    c.run(chunk);
    check(!c.alive && c.ch.peer_closed(), "close_notify both ways");
}

void test_refusals(test_support::FakeCrypto &f, void *key) {
    where = "refusals";
    {
        Server s(f, kFakeCert, sizeof kFakeCert, key, false, true);
        check(s.ok, "an h2-only server");
        Client c(f, s, 2, nullptr, 0);
        c.run();
        check(c.ch.failed() && c.ch.alert() == Alert::NoApplicationProtocol && c.ch.alert_received(),
              "a client without ALPN is refused by an h2-only server (RFC 9113, 3.2)");
        check(!c.alive && s.tls.failures() == 1 && s.tls.last_alert() == Alert::NoApplicationProtocol,
              "counted, and the connection ends");
        Client d(f, s, 3, kH11, 1);
        d.run();
        check(d.ch.failed() && d.ch.alert() == Alert::NoApplicationProtocol, "nor one that offers only http/1.1");
    }
    {
        Server s(f, kFakeCert, sizeof kFakeCert, key, true, true);
        Client c(f, s, 0, kH2, 1);
        c.run();
        c.send("x");
        c.c2s.writable()[7] ^= 1;
        c.run();
        check(!c.alive && s.tls.last_alert() == Alert::BadRecordMac && c.ch.alert_received(),
              "a damaged record: bad_record_mac, told to the client");
    }
    {
        // \~english One plaintext buffer, two connections each mid-message: the second is told and closed.
        // \~spanish Un buffer en claro, dos conexiones a mitad de mensaje: a la segunda se le dice y se cierra.  \~
        Server s(f, kFakeCert, sizeof kFakeCert, key, true, false, 1);
        Client a(f, s, 0, kH11, 1);
        a.run();
        a.send("GET /a HTTP/1.1\r\n");
        a.run();
        Client b(f, s, 1, kH11, 1);
        b.run();
        check(!b.alive && s.tls.starved() == 1, "out of plaintext buffers is counted and closes");
        check(b.ch.failed() && b.ch.alert_received() && b.ch.alert() == Alert::InternalError,
              "with internal_error, not a silent drop");
    }
    {
        // \~english No ALPN, with HTTP/1.1 here: HTTP/1.1.  \~spanish Sin ALPN, con HTTP/1.1 aqui: HTTP/1.1.  \~
        Server s(f, kFakeCert, sizeof kFakeCert, key, true, true);
        Client c(f, s, 0, nullptr, 0);
        c.run();
        c.send("GET /plain HTTP/1.1\r\nHost: example.com\r\n\r\n");
        c.run();
        check(text(c.plain).find("you asked for /plain") != std::string::npos, "a client without ALPN gets HTTP/1.1");
    }
    // \~english Each missing piece alone is refused, with the rest in place.
    // \~spanish Cada pieza que falta se rechaza sola, con el resto en su sitio.  \~
    http_vx::Http1Service h1;
    const uint8_t *certs[1] = {kFakeCert};
    const size_t lens[1] = {sizeof kFakeCert};
    TlsServiceConfig full;
    full.crypto = &f;
    full.http1 = &h1;
    full.certificates = certs;
    full.certificate_lens = lens;
    full.certificate_count = 1;
    full.signing_key = key;
    TlsService t;
    check(t.reset(4, full), "everything there: taken");
    TlsServiceConfig cfg = full;
    cfg.crypto = nullptr;
    check(!t.reset(4, cfg) && t.why() != nullptr && std::strstr(t.why(), "provider") != nullptr,
          "no provider: refused at start, and said (R24)");
    cfg = full;
    cfg.http1 = nullptr;
    check(!t.reset(4, cfg), "no inner service: refused");
    cfg = full;
    cfg.signing_key = nullptr;
    check(!t.reset(4, cfg), "no key: refused");
    cfg = full;
    cfg.certificate_count = 0;
    check(!t.reset(4, cfg), "no certificate: refused");
}

/**
 * @brief
 * \~english An open HTTP/1.1 response through TLS: sealed in place a record per call, and the request behind it served on resume.
 * \~spanish Una respuesta abierta de HTTP/1.1 por TLS: sellada en su sitio un registro por llamada, y la peticion de detras servida al reanudar.
 * \~
 */
void test_open(Crypto &cc, Server &s, const char *name) {
    where = name;
    TestPort port;
    Stream source;
    s.tls.attach(&port);
    s.echo.source = &source;

    Client c(cc, s, 2, kBoth + 1, 1);
    c.run();
    check(c.ch.open(), "the handshake completes");

    // \~english The open response, and a request right behind it in the same read.
    // \~spanish La respuesta abierta, y una peticion justo detras en la misma lectura.  \~
    c.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\nGET /one HTTP/1.1\r\nHost: a\r\n\r\n");
    c.run();
    std::string r = text(c.plain);
    check(s.echo.opened.valid() && port.held, "the response opened and held the reads");
    check(r.find("transfer-encoding: chunked") != std::string::npos, "the open head came through TLS");
    check(r.find("you asked for /one") == std::string::npos, "the request behind was answered before the open one ended");

    // \~english A kick: one chunk, sealed where the service wrote it.
    // \~spanish Un aviso: un trozo, sellado donde lo escribio el servicio.  \~
    source.pending = "hello";
    source.kick();
    port.kicks.drain();
    check(port.writable == 1, "the kick did not ask for room");
    Buffer out;
    check(s.tls.on_writable(c.conn, out, 65536), "the connection ended on a fill");
    put(c.s2c, out.data(), out.size());
    c.run();
    check(text(c.plain).find("0005\r\nhello\r\n") != std::string::npos, "the chunk did not open on the client");

    // \~english Full fills: one record each, as many as fit the budget, all opening on the client.
    // \~spanish Rellenos llenos: un registro cada uno, tantos como quepan en el presupuesto, todos abriendose en el cliente.  \~
    c.plain.consume(c.plain.size());
    source.full_fills = 8;
    source.kick();
    port.kicks.drain();
    out.clear();
    check(s.tls.on_writable(c.conn, out, 65536), "the connection ended on full fills");
    const size_t records = out.size();
    put(c.s2c, out.data(), out.size());
    c.run();
    const std::string got = text(c.plain);
    size_t xs = 0;
    for (char ch : got) xs += ch == 'x' ? 1 : 0;
    check(xs == 3 * (http_vx::tls::kMaxFragment - http_vx::Http1Service::kFramingMax),
          "the budget did not give exactly three full records");
    check(records <= 65536, "more than the budget was written");
    check(source.full_fills == 5, "the service was asked past the budget");

    // \~english Done: the last chunk, and the request that waited is answered with no new bytes from the peer.
    // \~spanish Acabada: el ultimo trozo, y la peticion que espero se contesta sin bytes nuevos del otro.  \~
    source.full_fills = 0;
    source.finish = true;
    source.kick();
    port.kicks.drain();
    out.clear();
    s.tls.on_writable(c.conn, out, 65536);
    put(c.s2c, out.data(), out.size());
    c.run();
    check(source.gones == 1 && source.last == http_vx::GoneReason::Finished, "gone(Finished) did not come once");
    check(port.resumes == 1, "ending did not resume the reads");

    Buffer empty;
    out.clear();
    s.tls.on_bytes(c.conn, empty, out);
    put(c.s2c, out.data(), out.size());
    c.run();
    r = text(c.plain);
    check(r.find("0\r\n\r\n") != std::string::npos, "the last chunk did not come");
    check(r.find("you asked for /one") != std::string::npos, "the request behind was not answered on resume");

    s.echo.source = nullptr;
    s.tls.attach(nullptr);
}

void run_all(Crypto &c, const uint8_t *cert, size_t len, void *key, const char *name) {
    Server s(c, cert, len, key, true, true);
    where = name;
    check(s.ok, "the server is set up");
    test_http1(c, s, name, ~size_t{0});
    test_http1(c, s, name, 1);
    test_http2(c, s, name, ~size_t{0});
    test_http2(c, s, name, 3);
    check(s.tls.handshakes() == 4 && s.tls.failures() == 0, "four handshakes, no failure");
    test_open(c, s, name);
}

} // namespace

int main() {
    std::printf("tls service: %zu bytes of fixed state per connection, %zu more during the handshake\n",
                TlsService::slot_size(), sizeof(Session));
    test_support::FakeCrypto fake;
    void *fk = fake.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
    run_all(fake, kFakeCert, sizeof kFakeCert, fk, "fake");
    test_refusals(fake, fk);
    fake.forget_key(fk);

    int providers = 0;
    uint8_t cert[2048];
    uint8_t pkcs8[2048];
    const size_t cert_len = rfc8448::from_hex(test_keys::kP256Certificate, cert, sizeof cert);
    const size_t key_len = rfc8448::from_hex(test_keys::kP256Pkcs8, pkcs8, sizeof pkcs8);
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    void *ok = openssl.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len);
    run_all(openssl, cert, cert_len, ok, openssl.name());
    openssl.forget_key(ok);
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    void *ck = cng.ready() ? cng.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len) : nullptr;
    if (ck != nullptr) {
        run_all(cng, cert, cert_len, ck, cng.name());
        cng.forget_key(ck);
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
    (void)cert_len;
    (void)key_len;
    if (providers == 0) std::printf("SKIPPED: no real provider built, real handshakes not run\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls service, %d provider(s): OK\n", providers);
    return 0;
}
