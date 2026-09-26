/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h3_connection.cpp
 * @brief
 * \~english HTTP/3 over two real QUIC connections: requests and responses, and every rule of RFC 9114 broken on purpose.
 * \~spanish HTTP/3 sobre dos conexiones QUIC de verdad: peticiones y respuestas, y cada regla del RFC 9114 rota a proposito.
 * \~
 *
 * \~english
 * Two quic::Connection objects exchange datagrams with 1-RTT keys already
 * installed; an h3::Connection sits on each.  The well-behaved client
 * checks the whole exchange; a raw client -- bytes written straight onto
 * QUIC streams -- breaks the rules the good one never would, and each must
 * end with its own error code and scope: the stream, or the connection.
 * \~spanish
 * Dos quic::Connection intercambian datagramas con las claves 1-RTT ya
 * instaladas; sobre cada una hay una h3::Connection.  El cliente que se porta
 * bien comprueba el intercambio entero; un cliente en crudo -- bytes escritos
 * directamente en flujos QUIC -- rompe las reglas que el bueno nunca romperia,
 * y cada una debe acabar con su propio codigo y alcance: el flujo, o la
 * conexion.
 * \~
 */

#include "http_vx/h3_connection.h"

#include "fake_crypto.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace http_vx::quic;
namespace h3 = http_vx::h3;
namespace qpack = http_vx::qpack;
using http_vx::Buffer;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

const Path kPath{};
Path g_sent;

void secret(uint8_t *out, uint8_t tag, size_t len) {
    for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(tag * 17 + i);
}

bool install(Connection &c, uint8_t read_tag, uint8_t write_tag) {
    uint8_t r[kMaxSecret], w[kMaxSecret];
    const size_t len = hash_size(hash_of(Aead::Aes128Gcm));
    secret(r, read_tag, len);
    secret(w, write_tag, len);
    return c.install_secrets(Space::Application, Aead::Aes128Gcm, r, w, len, 0);
}

/// \~english Transport parameters as if they had been exchanged: room for HTTP/3's streams (6.1, 6.2).
/// \~spanish Parametros de transporte como si se hubieran intercambiado: sitio para los flujos de HTTP/3 (6.1, 6.2).  \~
void open_up(ConnectionConfig &c) {
    c.streams.peer_max_streams_bidi = 100;
    c.streams.peer_max_streams_uni = 8;
    c.streams.peer_uni_concurrency = 8;
    c.streams.peer_window_bidi_local = 1 << 20;
    c.streams.peer_window_bidi_remote = 1 << 20;
    c.streams.peer_window_uni = 1 << 20;
    c.peer_max_data = 16 << 20;
}

ConnectionConfig client_config() {
    ConnectionConfig cc;
    cc.is_server = false;
    cc.streams.is_server = false;
    for (int i = 0; i < 8; ++i) {
        cc.local_cid[i] = static_cast<uint8_t>(0xc0 + i);
        cc.peer_cid[i] = static_cast<uint8_t>(0x50 + i);
    }
    open_up(cc);
    return cc;
}

ConnectionConfig server_config() {
    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) {
        sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);
        sc.peer_cid[i] = static_cast<uint8_t>(0xc0 + i);
    }
    open_up(sc);
    return sc;
}

/// \~english One event, with any body bytes copied out.  \~spanish Un evento, con los bytes de cuerpo copiados.  \~
struct Rec {
    h3::EventKind kind;
    uint64_t stream;
    uint64_t code;
    std::string data;
    /// \~english For a Response: its status and how many fields, read at the event.
    /// \~spanish Para un Response: su estado y cuantos campos, leidos en el evento.  \~
    unsigned status = 0;
    size_t fields = 0;
};

/**
 * @brief
 * \~english A client and a server, each a QUIC connection with HTTP/3 on top.
 * \~spanish Un cliente y un servidor, cada uno una conexion QUIC con HTTP/3 encima.
 * \~
 */
struct Link {
    test_support::FakeCrypto cr;
    Connection qc;
    Connection qs;
    h3::Connection hc;
    h3::Connection hs;
    uint64_t now = 1000;
    std::vector<Rec> client_events;
    std::vector<Rec> server_events;

    Link() : qc(cr, client_config()), qs(cr, server_config()), hc(qc), hs(qs) {
        check(install(qc, 4, 3) && install(qs, 3, 4), "keys");
        qc.handshake_confirmed(0);
        qs.handshake_confirmed(0);
    }

    static h3::Config config(bool server, uint64_t capacity = 4096) {
        h3::Config c;
        c.server = server;
        c.local.qpack_max_table_capacity = capacity;
        c.local.qpack_blocked_streams = 16;
        return c;
    }

    /// \~english Starts both ends (or only the server: the client is then raw).
    /// \~spanish Arranca los dos extremos (o solo el servidor: el cliente es entonces en crudo).  \~
    void start(bool client_too = true, const h3::Config &sc = config(true)) {
        check(hs.start(sc), "the server starts");
        if (client_too) check(hc.start(config(false)), "the client starts");
    }

    /// \~english Only the client: the server is then raw.  \~spanish Solo el cliente: el servidor es entonces en crudo.  \~
    void start_client_only() { check(hc.start(config(false)), "the client starts"); }

    void drain(h3::Connection &h, std::vector<Rec> &into) {
        for (int guard = 0; guard < 1000; ++guard) {
            const h3::Event e = h.poll(now);
            if (e.kind == h3::EventKind::None) return;
            Rec r{e.kind, e.stream, e.code, std::string(reinterpret_cast<const char *>(e.data), e.len)};
            if (e.kind == h3::EventKind::Response) {
                const Buffer *b = nullptr;
                const http_vx::Response *resp = h.response(e.stream, b);
                if (resp != nullptr) {
                    r.status = resp->status;
                    r.fields = resp->fields.size();
                }
            }
            into.push_back(r);
        }
    }

    /// \~english Datagrams both ways, and each HTTP/3 side reads what came.  \~spanish Datagramas en los dos sentidos, y cada lado HTTP/3 lee lo que llego.  \~
    void pump(int rounds = 6, bool client_h3 = true, bool server_h3 = true) {
        uint8_t buf[1500];
        for (int r = 0; r < rounds; ++r) {
            size_t n;
            while ((n = qc.build_datagram(g_sent, buf, sizeof buf, now)) != 0) qs.on_datagram(kPath, buf, n, Ecn::NotEct, now);
            if (server_h3) drain(hs, server_events);
            while ((n = qs.build_datagram(g_sent, buf, sizeof buf, now)) != 0) qc.on_datagram(kPath, buf, n, Ecn::NotEct, now);
            if (client_h3) drain(hc, client_events);
            now += 5000;
            if (qc.timer() <= now) qc.on_timer(now);
            if (qs.timer() <= now) qs.on_timer(now);
        }
    }

    const Rec *find(const std::vector<Rec> &v, h3::EventKind k, uint64_t stream = ~uint64_t{0}) const {
        for (const Rec &r : v)
            if (r.kind == k && (stream == ~uint64_t{0} || r.stream == stream)) return &r;
        return nullptr;
    }

    std::string body(const std::vector<Rec> &v, uint64_t stream) const {
        std::string s;
        for (const Rec &r : v)
            if (r.kind == h3::EventKind::Body && r.stream == stream) s += r.data;
        return s;
    }
};

qpack::Line line(const char *name, const char *value) {
    qpack::Line l;
    l.name = reinterpret_cast<const uint8_t *>(name);
    l.name_len = std::strlen(name);
    l.value = reinterpret_cast<const uint8_t *>(value);
    l.value_len = std::strlen(value);
    return l;
}

std::vector<qpack::Line> get(const char *path = "/") {
    return {line(":method", "GET"), line(":scheme", "https"), line(":authority", "example.com"), line(":path", path)};
}

std::string text(const Buffer *b, http_vx::Span s) { return std::string(reinterpret_cast<const char *>(b->data()) + s.off, s.len); }

/// \~english A field section with only static and literal lines: no encoder stream needed.
/// \~spanish Una seccion de campos solo con lineas estaticas y literales: sin flujo del codificador.  \~
std::vector<uint8_t> section_of(const std::vector<qpack::Line> &lines) {
    qpack::Encoder e;
    e.reset(qpack::EncoderConfig{});
    Buffer out;
    e.encode(0, lines.data(), lines.size(), out, 0);
    return std::vector<uint8_t>(out.data(), out.data() + out.size());
}

void add_varint(std::vector<uint8_t> &v, uint64_t x) {
    Buffer b;
    h3::write_varint(b, x);
    v.insert(v.end(), b.data(), b.data() + b.size());
}

void add_frame(std::vector<uint8_t> &v, uint64_t type, const std::vector<uint8_t> &payload) {
    add_varint(v, type);
    add_varint(v, payload.size());
    v.insert(v.end(), payload.begin(), payload.end());
}

std::vector<uint8_t> bytes(const char *s) { return std::vector<uint8_t>(s, s + std::strlen(s)); }

/// \~english Raw bytes on a stream the raw client opens.  \~spanish Bytes en crudo en un flujo que abre el cliente en crudo.  \~
uint64_t raw(Link &k, bool bidi, const std::vector<uint8_t> &v, bool fin) {
    Stream *s = k.qc.streams().open(bidi);
    check(s != nullptr, "the raw client opens a stream");
    if (s == nullptr) return ~uint64_t{0};
    size_t took = 0;
    if (!v.empty()) s->send->write(v.data(), v.size(), took);
    if (fin) s->send->finish();
    return s->id;
}

/// \~english A raw control stream: its type and a SETTINGS, then @p more.  \~spanish Un flujo de control en crudo: su tipo y un SETTINGS, y despues @p more.  \~
std::vector<uint8_t> control(const std::vector<uint8_t> &more = {}) {
    std::vector<uint8_t> v;
    add_varint(v, h3::kControlStream);
    Buffer b;
    h3::write_settings(b, h3::Settings{});
    v.insert(v.end(), b.data(), b.data() + b.size());
    v.insert(v.end(), more.begin(), more.end());
    return v;
}

void expect_closed(Link &k, uint64_t code, const char *what) {
    if (k.hs.failed() && k.hs.failure().code == code) return;
    std::fprintf(stderr, "FAIL [%s]: %s: want 0x%llx, got 0x%llx (%s)\n", current, what,
                 static_cast<unsigned long long>(code), static_cast<unsigned long long>(k.hs.failure().code),
                 k.hs.failure().why != nullptr ? k.hs.failure().why : "no failure");
    ++failures;
}

void test_exchange() {
    section("exchange");
    Link k;
    k.start();
    k.pump();
    check(k.hs.peer_settings_known() && k.hc.peer_settings_known(), "both ends read the other's SETTINGS (6.2.1)");
    const std::vector<qpack::Line> req = get("/hello");
    const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
    check(id == 0, "the first request is on stream 0 (6.1)");
    k.pump();
    const Rec *r = k.find(k.server_events, h3::EventKind::Request, id);
    check(r != nullptr, "the server sees the request");
    const Buffer *b = nullptr;
    const http_vx::Request *q = k.hs.request(id, b);
    check(q != nullptr && q->method == http_vx::MethodId::Get && text(b, q->target) == "/hello" &&
              text(b, q->authority) == "example.com" && q->version == http_vx::Version::Http3,
          "and its pieces");
    check(k.find(k.server_events, h3::EventKind::End, id) != nullptr, "and its end");
    const qpack::Line ct = line("content-type", "text/plain");
    check(k.hs.respond(id, 103, nullptr, 0, false), "an interim response");
    check(k.hs.respond(id, 200, &ct, 1, false), "the final response");
    check(!k.hs.respond(id, 200, &ct, 1, false), "a second final response is refused (4.1)");
    const char hello[] = "hello, world";
    check(k.hs.send_body(id, reinterpret_cast<const uint8_t *>(hello), sizeof hello - 1, true), "the body");
    k.pump();
    std::vector<const Rec *> responses;
    for (const Rec &e : k.client_events)
        if (e.kind == h3::EventKind::Response) responses.push_back(&e);
    check(responses.size() == 2, "the client sees the interim and the final response");
    check(responses.size() == 2 && responses[0]->status == 103 && responses[1]->status == 200 && responses[1]->fields == 1,
          "103 first, then 200 with its field");
    check(k.body(k.client_events, id) == "hello, world", "the body arrives whole");
    check(k.find(k.client_events, h3::EventKind::End, id) != nullptr, "and the end");

    section("exchange, again, with the table");
    for (int i = 0; i < 3; ++i) {
        const uint64_t id2 = k.hc.send_request(req.data(), req.size(), true);
        k.pump();
        check(k.find(k.server_events, h3::EventKind::Request, id2) != nullptr, "each repeated request arrives");
        k.hs.respond(id2, 204, nullptr, 0, true);
        k.pump();
        check(k.find(k.client_events, h3::EventKind::End, id2) != nullptr, "and each answer");
    }
    check(k.hc.encoder().table().inserted() > 0, "the client's encoder used the dynamic table");
    check(k.hs.decoder().table().inserted() == k.hc.encoder().table().inserted(), "and the server's decoder followed it");
    check(!k.hs.failed() && !k.hc.failed(), "nothing failed");
}

void test_body_and_trailers() {
    section("body and trailers");
    Link k;
    k.start(false);
    k.pump(3, false);
    std::vector<qpack::Line> head = {line(":method", "POST"), line(":scheme", "https"), line(":authority", "example.com"),
                                     line(":path", "/up"), line("content-length", "6")};
    std::vector<uint8_t> v;
    add_frame(v, h3::kHeaders, section_of(head));
    add_frame(v, h3::kData, bytes("abc"));
    add_frame(v, h3::kData, bytes("def"));
    add_frame(v, h3::kHeaders, section_of({line("x-sum", "42")}));
    const uint64_t id = raw(k, true, v, true);
    k.pump(3, false);
    check(k.find(k.server_events, h3::EventKind::Request, id) != nullptr, "the request");
    check(k.body(k.server_events, id) == "abcdef", "its body, across two DATA frames");
    check(k.find(k.server_events, h3::EventKind::Trailers, id) != nullptr, "its trailers");
    const Buffer *b = nullptr;
    const http_vx::Request *q = k.hs.request(id, b);
    check(q != nullptr && q->fields.size() == 2, "the trailer joined the fields");
    check(k.find(k.server_events, h3::EventKind::End, id) != nullptr, "and its end");
    check(!k.hs.failed(), "nothing failed");
}

/// \~english A server with a raw client that sends @p v on a new request stream; @p fin ends it.
/// \~spanish Un servidor con un cliente en crudo que manda @p v en un flujo de peticion nuevo; @p fin lo acaba.  \~
void stream_case(const std::vector<uint8_t> &v, bool fin, uint64_t code, const char *what) {
    Link k;
    k.start(false);
    k.pump(3, false);
    const uint64_t id = raw(k, true, v, fin);
    k.pump(4, false);
    const Rec *r = k.find(k.server_events, h3::EventKind::Reset, id);
    if (r != nullptr && r->code == code && !k.hs.failed()) {
        Stream *s = k.qc.streams().find(id);
        check(s == nullptr || s->recv->state() == RecvState::ResetRecvd || s->recv->state() == RecvState::ResetRead,
              "the client sees the stream reset");
        return;
    }
    std::fprintf(stderr, "FAIL [%s]: %s: want a reset 0x%llx, got %s (%s)\n", current, what,
                 static_cast<unsigned long long>(code), r != nullptr ? "another code" : "no reset",
                 k.hs.stream_why() != nullptr ? k.hs.stream_why() : (k.hs.failed() ? k.hs.failure().why : "-"));
    ++failures;
}

/// \~english The same, expecting the connection to close with @p code.  \~spanish Lo mismo, esperando que la conexion se cierre con @p code.  \~
void conn_case(bool bidi, const std::vector<uint8_t> &v, bool fin, uint64_t code, const char *what) {
    Link k;
    k.start(false);
    k.pump(3, false);
    raw(k, bidi, v, fin);
    k.pump(4, false);
    expect_closed(k, code, what);
    check(k.find(k.server_events, h3::EventKind::Closed) != nullptr, "and says so once, as an event");
}

void test_stream_errors() {
    section("stream errors");
    std::vector<uint8_t> v;
    add_frame(v, h3::kHeaders, section_of({line(":method", "GET"), line(":scheme", "https"), line(":authority", "a")}));
    stream_case(v, true, h3::kMessageError, "a request with no :path (4.3.1)");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(get()));
    stream_case(std::vector<uint8_t>(), true, h3::kRequestIncomplete, "a request stream ended before HEADERS (4.1)");
    v.clear();
    std::vector<qpack::Line> cl = get();
    cl.push_back(line("content-length", "2"));
    add_frame(v, h3::kHeaders, section_of(cl));
    add_frame(v, h3::kData, bytes("abc"));
    stream_case(v, true, h3::kMessageError, "more content than Content-Length (4.1.2)");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(cl));
    add_frame(v, h3::kData, bytes("a"));
    stream_case(v, true, h3::kMessageError, "less content than Content-Length (4.1.2)");
    v.clear();
    cl.back() = line("content-length", "x");
    add_frame(v, h3::kHeaders, section_of(cl));
    stream_case(v, true, h3::kMessageError, "a Content-Length that is no number");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(get()));
    add_frame(v, h3::kHeaders, section_of({line(":path", "/x")}));
    stream_case(v, true, h3::kMessageError, "a pseudo-header field in trailers (4.3)");
    v.clear();
    std::vector<qpack::Line> te = get();
    te.push_back(line("transfer-encoding", "chunked"));
    add_frame(v, h3::kHeaders, section_of(te));
    stream_case(v, true, h3::kMessageError, "Transfer-Encoding (4.1, 4.2)");
    v.clear();
    std::vector<qpack::Line> host = get();
    host.push_back(line("host", "other.example"));
    add_frame(v, h3::kHeaders, section_of(host));
    stream_case(v, true, h3::kMessageError, "Host that differs from :authority (4.3.1)");
}

void test_connection_errors() {
    section("connection errors");
    std::vector<uint8_t> v;
    add_frame(v, h3::kData, bytes("x"));
    conn_case(true, v, true, h3::kFrameUnexpected, "DATA before HEADERS (4.1)");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(get()));
    add_frame(v, h3::kHeaders, section_of({line("x-a", "1")}));
    add_frame(v, h3::kHeaders, section_of({line("x-b", "1")}));
    conn_case(true, v, true, h3::kFrameUnexpected, "a HEADERS after the trailers (4.1)");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(get()));
    add_varint(v, h3::kData);
    add_varint(v, 10);
    v.push_back('x');
    conn_case(true, v, true, h3::kFrameError, "a stream that ends inside a frame (7.1)");
    v.clear();
    add_frame(v, 0x06, {});
    conn_case(true, v, true, h3::kFrameUnexpected, "an HTTP/2 frame type (7.2.8)");
    v.clear();
    add_frame(v, h3::kHeaders, section_of(get()));
    add_frame(v, h3::kSettings, {});
    conn_case(true, v, true, h3::kFrameUnexpected, "SETTINGS on a request stream (7.2.4)");
    v.clear();
    add_frame(v, h3::kPushPromise, {0x00});
    conn_case(true, v, true, h3::kFrameUnexpected, "a PUSH_PROMISE from a client (7.2.5)");

    section("control stream");
    v.clear();
    add_varint(v, h3::kControlStream);
    add_frame(v, h3::kGoaway, {0x00});
    conn_case(false, v, false, h3::kMissingSettings, "a control stream that does not start with SETTINGS (6.2.1)");
    v.clear();
    add_varint(v, h3::kControlStream);
    add_frame(v, 0x21, {});
    conn_case(false, v, false, h3::kMissingSettings, "a reserved frame before SETTINGS (9)");
    std::vector<uint8_t> more;
    Buffer b;
    h3::write_settings(b, h3::Settings{});
    more.assign(b.data(), b.data() + b.size());
    conn_case(false, control(more), false, h3::kFrameUnexpected, "a second SETTINGS (7.2.4)");
    more.clear();
    add_frame(more, h3::kData, bytes("x"));
    conn_case(false, control(more), false, h3::kFrameUnexpected, "DATA on the control stream (7.2.1)");
    more.clear();
    add_frame(more, h3::kHeaders, {0x00, 0x00});
    conn_case(false, control(more), false, h3::kFrameUnexpected, "HEADERS on the control stream (7.2.2)");
    conn_case(false, control(), true, h3::kClosedCriticalStream, "the control stream closed (6.2.1)");
    more.clear();
    add_frame(more, h3::kCancelPush, {0x00});
    conn_case(false, control(more), false, h3::kIdError, "a CANCEL_PUSH for a push never promised (7.2.3)");
    more.clear();
    add_frame(more, h3::kMaxPushId, {0x05});
    add_frame(more, h3::kMaxPushId, {0x04});
    conn_case(false, control(more), false, h3::kIdError, "a MAX_PUSH_ID that lowers the limit (7.2.7)");
    more.clear();
    add_frame(more, h3::kGoaway, {0x05});
    add_frame(more, h3::kGoaway, {0x06});
    conn_case(false, control(more), false, h3::kIdError, "a GOAWAY larger than the one before (5.2)");
    more.clear();
    add_frame(more, h3::kSettings, {0x02, 0x00});
    std::vector<uint8_t> bad;
    add_varint(bad, h3::kControlStream);
    add_frame(bad, h3::kSettings, {0x02, 0x00});
    conn_case(false, bad, false, h3::kSettingsError, "an HTTP/2 setting (7.2.4.1)");

    section("stream types");
    {
        Link k;
        k.start(false);
        k.pump(3, false);
        raw(k, false, control(), false);
        raw(k, false, control(), false);
        k.pump(4, false);
        expect_closed(k, h3::kStreamCreationError, "a second control stream (6.2.1)");
    }
    v.clear();
    add_varint(v, h3::kPushStream);
    add_varint(v, 0);
    conn_case(false, v, false, h3::kStreamCreationError, "a push stream from a client (6.2.2)");
    {
        Link k;
        k.start(false);
        k.pump(3, false);
        std::vector<uint8_t> enc;
        add_varint(enc, qpack::kEncoderStreamType);
        raw(k, false, enc, false);
        raw(k, false, enc, false);
        k.pump(4, false);
        expect_closed(k, h3::kStreamCreationError, "a second QPACK encoder stream (RFC 9204, 4.2)");
    }
    {
        Link k;
        k.start(false);
        k.pump(3, false);
        std::vector<uint8_t> enc;
        add_varint(enc, qpack::kEncoderStreamType);
        raw(k, false, enc, true);
        k.pump(4, false);
        expect_closed(k, h3::kClosedCriticalStream, "the QPACK encoder stream closed (RFC 9204, 4.2)");
    }
    {
        // \~english An unknown type is no error: reading stops, and the connection goes on (6.2).
        // \~spanish Un tipo desconocido no es un error: se deja de leer, y la conexion sigue (6.2).  \~
        Link k;
        k.start(false);
        k.pump(3, false);
        std::vector<uint8_t> unknown;
        add_varint(unknown, 0x21);
        unknown.push_back('z');
        raw(k, false, unknown, false);
        k.pump(4, false);
        check(!k.hs.failed(), "a reserved stream type is ignored (6.2.3)");
        check(k.qs.sent().stop_sending >= 1, "and its reading stopped (6.2)");
    }
}

void test_client_rules() {
    section("client rules");
    {
        // \~english A server-initiated bidirectional stream (6.1).  \~spanish Un flujo bidireccional abierto por el servidor (6.1).  \~
        Link k;
        k.start();
        k.pump();
        Stream *s = k.qs.streams().open(true);
        check(s != nullptr, "the raw server opens a bidirectional stream");
        size_t took = 0;
        const uint8_t x = 'x';
        if (s != nullptr) s->send->write(&x, 1, took);
        k.pump();
        check(k.hc.failed() && k.hc.failure().code == h3::kStreamCreationError, "is a connection error at the client");
    }
    {
        Link k;
        k.start();
        k.pump();
        check(k.hs.goaway(), "the server says GOAWAY");
        k.pump();
        const Rec *g = k.find(k.client_events, h3::EventKind::GoAway);
        check(g != nullptr && g->code == 0, "the client sees it, naming stream 0");
        const std::vector<qpack::Line> req = get();
        check(k.hc.send_request(req.data(), req.size(), true) == ~uint64_t{0}, "and opens no new request (5.2)");
    }
}

void test_server_limits() {
    section("server limits");
    {
        // \~english After GOAWAY, a new request is rejected before being read (5.2).
        // \~spanish Tras GOAWAY, una peticion nueva se rechaza antes de leerse (5.2).  \~
        Link k;
        k.start(false);
        k.pump(3, false);
        k.hs.goaway();
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(get()));
        const uint64_t id = raw(k, true, v, true);
        k.pump(4, false);
        Stream *s = k.qc.streams().find(id);
        check(k.find(k.server_events, h3::EventKind::Request) == nullptr, "no request reaches the application");
        check(s == nullptr || (s->recv->state() == RecvState::ResetRecvd && s->recv->reset_code() == h3::kRequestRejected) ||
                  s->recv->state() == RecvState::ResetRead,
              "it is reset with H3_REQUEST_REJECTED (4.1.1)");
    }
    {
        // \~english A section larger than announced is answered 431 (4.2.2).
        // \~spanish Una seccion mayor que la anunciada se contesta con 431 (4.2.2).  \~
        Link k;
        h3::Config c = Link::config(true);
        c.local.max_field_section_size = 200;
        k.start(true, c);
        k.pump();
        std::vector<qpack::Line> big = get();
        std::string lots(300, 'a');
        big.push_back(line("x-big", lots.c_str()));
        h3::Settings unlimited;
        (void)unlimited;
        const uint64_t id = k.hc.send_request(big.data(), big.size(), true);
        check(id == ~uint64_t{0}, "the client itself refuses: the peer said it takes less (4.2.2)");
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(big));
        Stream *s = k.qc.streams().open(true);
        size_t took = 0;
        s->send->write(v.data(), v.size(), took);
        s->send->finish();
        k.pump();
        check(k.find(k.server_events, h3::EventKind::Request, s->id) == nullptr, "no request reaches the application");
        check(k.hs.stream_why() != nullptr && std::strstr(k.hs.stream_why(), "431") != nullptr, "the server says why");
    }
    {
        // \~english The client gives up: the server sees the stream reset with its code (4.1.1).
        // \~spanish El cliente desiste: el servidor ve el flujo reiniciado con su codigo (4.1.1).  \~
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get();
        const uint64_t id = k.hc.send_request(req.data(), req.size(), false);
        k.pump();
        k.hc.cancel(id, h3::kRequestCancelled);
        k.pump();
        const Rec *r = k.find(k.server_events, h3::EventKind::Reset, id);
        check(r != nullptr && r->code == h3::kRequestCancelled, "the cancel reaches the server as H3_REQUEST_CANCELLED");
    }
    {
        // \~english A reset request stream is a Stream Cancellation on the server's decoder stream (RFC 9204, 2.2.2.2).
        // \~spanish Un flujo de peticion reiniciado es un Stream Cancellation en el flujo del descodificador del servidor (RFC 9204, 2.2.2.2).  \~
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get();
        const uint64_t id = k.hc.send_request(req.data(), req.size(), false);
        k.pump();
        // \~english The server's third stream of its own: control 3, encoder 7, decoder 11.
        // \~spanish El tercer flujo propio del servidor: control 3, codificador 7, descodificador 11.  \~
        Stream *dec = k.qs.streams().find(11);
        check(dec != nullptr, "the server's decoder stream is stream 11");
        const uint64_t before = dec != nullptr ? dec->send->written() : 0;
        k.qc.streams().find(id)->send->reset(h3::kRequestCancelled);
        k.pump();
        check(dec != nullptr && dec->send->written() == before + 1, "one Stream Cancellation went out");
    }
}

/**
 * @brief
 * \~english A real client, a raw server answering its request with @p v; the client should reset the stream with @p code.
 * \~spanish Un cliente de verdad, un servidor en crudo que contesta a su peticion con @p v; el cliente deberia reiniciar el flujo con @p code.
 * \~
 */
void response_case(const std::vector<uint8_t> &v, uint64_t code, const char *what) {
    Link k;
    k.start_client_only();
    const std::vector<qpack::Line> req = get();
    const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
    k.pump(3, true, false);
    Stream *s = k.qs.streams().find(id);
    check(s != nullptr, "the raw server has the request stream");
    if (s == nullptr) return;
    size_t took = 0;
    s->send->write(v.data(), v.size(), took);
    s->send->finish();
    k.pump(3, true, false);
    const Rec *r = k.find(k.client_events, h3::EventKind::Reset, id);
    if (r != nullptr && r->code == code) return;
    std::fprintf(stderr, "FAIL [%s]: %s: want a reset 0x%llx, got %s (%s)\n", current, what,
                 static_cast<unsigned long long>(code), r != nullptr ? "another code" : "no reset",
                 k.hc.stream_why() != nullptr ? k.hc.stream_why() : (k.hc.failed() ? k.hc.failure().why : "-"));
    ++failures;
}

void test_response_rules() {
    section("response rules");
    struct Bad {
        std::vector<qpack::Line> lines;
        const char *what;
    };
    const Bad bad[] = {
        {{line(":status", "200"), line("", "x")}, "an empty field name"},
        {{line(":status", "200"), line("x-a", "a\rb")}, "a CR in a value (10.3)"},
        {{line("x-a", "1"), line(":status", "200")}, "a pseudo-header field after a field (4.3)"},
        {{line(":status", "200"), line(":status", "200")}, ":status twice (4.3.2)"},
        {{line(":status", "20")}, "a :status of two digits"},
        {{line(":status", "2x0")}, "a :status that is no number"},
        {{line(":status", "099")}, "a :status below 100"},
        {{line(":status", "200"), line("X-A", "1")}, "an uppercase field name (4.2)"},
        {{line(":status", "200"), line("x a", "1")}, "a field name that is no token"},
        {{line(":status", "200"), line("connection", "close")}, "a connection-specific field (4.2)"},
        {{line("x-a", "1")}, "a response with no :status (4.3.2)"},
        {{line(":path", "/")}, "a request pseudo-header in a response (4.3)"},
    };
    for (const Bad &b : bad) {
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(b.lines));
        response_case(v, h3::kMessageError, b.what);
    }
    {
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of({line(":status", "200")}));
        add_frame(v, h3::kHeaders, section_of({line(":status", "200")}));
        response_case(v, h3::kMessageError, "a pseudo-header field in trailers (4.3)");
    }
    {
        // \~english A bad first section followed by a good one: refused for itself, not for what did not come.
        // \~spanish Una primera seccion mala seguida de una buena: rechazada por si misma, no por lo que no llego.  \~
        const std::vector<qpack::Line> firsts[] = {{line(":status", "099")}, {line("x-a", "1")}};
        for (const std::vector<qpack::Line> &f : firsts) {
            std::vector<uint8_t> v;
            add_frame(v, h3::kHeaders, section_of(f));
            add_frame(v, h3::kHeaders, section_of({line(":status", "200")}));
            response_case(v, h3::kMessageError, "a :status below 100, or none, before a good response");
        }
    }
    {
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of({line(":status", "200"), line("content-length", "5")}));
        add_frame(v, h3::kData, bytes("ab"));
        response_case(v, h3::kMessageError, "less content than Content-Length in a response (4.1.2)");
    }

    section("responses with no content");
    const char *statuses[] = {"204", "304"};
    for (const char *st : statuses) {
        Link k;
        k.start_client_only();
        const std::vector<qpack::Line> req = get();
        const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
        k.pump(3, true, false);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of({line(":status", st), line("content-length", "10")}));
        Stream *s = k.qs.streams().find(id);
        size_t took = 0;
        s->send->write(v.data(), v.size(), took);
        s->send->finish();
        k.pump(3, true, false);
        check(k.find(k.client_events, h3::EventKind::End, id) != nullptr,
              "a 204 or 304 has no content, whatever Content-Length says (RFC 9110, 6.4.1)");
    }
    {
        Link k;
        k.start_client_only();
        std::vector<qpack::Line> req = get();
        req[0] = line(":method", "HEAD");
        const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
        k.pump(3, true, false);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of({line(":status", "200"), line("content-length", "10")}));
        Stream *s = k.qs.streams().find(id);
        size_t took = 0;
        s->send->write(v.data(), v.size(), took);
        s->send->finish();
        k.pump(3, true, false);
        check(k.find(k.client_events, h3::EventKind::End, id) != nullptr, "neither has the response to HEAD");
    }

    section("server control stream, seen by a client");
    struct Ctl {
        std::vector<uint8_t> frames;
        uint64_t code;
        const char *what;
    };
    std::vector<uint8_t> goaway_uni, max_push;
    add_frame(goaway_uni, h3::kGoaway, {0x02});
    add_frame(max_push, h3::kMaxPushId, {0x01});
    const Ctl ctl[] = {
        {goaway_uni, h3::kIdError, "a GOAWAY naming a unidirectional stream (7.2.6)"},
        {max_push, h3::kFrameUnexpected, "a MAX_PUSH_ID from a server (7.2.7)"},
    };
    for (const Ctl &c : ctl) {
        Link k;
        k.start_client_only();
        k.pump(3, true, false);
        Stream *s = k.qs.streams().open(false);
        std::vector<uint8_t> v = control(c.frames);
        size_t took = 0;
        s->send->write(v.data(), v.size(), took);
        k.pump(3, true, false);
        if (!(k.hc.failed() && k.hc.failure().code == c.code)) {
            std::fprintf(stderr, "FAIL [%s]: %s: got 0x%llx\n", current, c.what,
                         static_cast<unsigned long long>(k.hc.failure().code));
            ++failures;
        }
    }
}

void test_more_rules() {
    section("more rules");
    {
        Link k;
        k.start(false);
        k.pump(3, false);
        std::vector<uint8_t> dec;
        add_varint(dec, qpack::kDecoderStreamType);
        raw(k, false, dec, false);
        raw(k, false, dec, false);
        k.pump(4, false);
        expect_closed(k, h3::kStreamCreationError, "a second QPACK decoder stream (RFC 9204, 4.2)");
    }
    {
        // \~english Too much content noticed before the end of the stream (4.1.2).
        // \~spanish Demasiado contenido detectado antes del final del flujo (4.1.2).  \~
        std::vector<qpack::Line> cl = get();
        cl.push_back(line("content-length", "2"));
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(cl));
        add_frame(v, h3::kData, bytes("abc"));
        stream_case(v, false, h3::kMessageError, "more content than Content-Length, the stream still open");
    }
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get();
        const uint64_t id = k.hc.send_request(req.data(), req.size(), false);
        k.pump();
        const char x[] = "x";
        check(!k.hs.send_body(id, reinterpret_cast<const uint8_t *>(x), 1, false), "no content before a final response (4.1)");
        check(!k.hs.respond(id, 101, nullptr, 0, false), "no 101 in HTTP/3 (4.5)");
        check(!k.hs.respond(id, 100, nullptr, 0, true), "an interim response cannot end the stream (4.1)");
        check(k.hs.respond(id, 100, nullptr, 0, false) && k.hs.respond(id, 200, nullptr, 0, false), "100 then 200");
        check(k.hs.send_body(id, reinterpret_cast<const uint8_t *>(x), 1, true), "then content");
    }
    {
        // \~english A second GOAWAY never names more than the first (5.2).
        // \~spanish Un segundo GOAWAY nunca nombra mas que el primero (5.2).  \~
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get();
        k.hc.send_request(req.data(), req.size(), true);
        k.pump();
        k.hs.goaway();
        k.pump();
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(get()));
        raw(k, true, v, true);
        k.pump();
        k.hs.goaway();
        k.pump();
        std::vector<uint64_t> ids;
        for (const Rec &r : k.client_events)
            if (r.kind == h3::EventKind::GoAway) ids.push_back(r.code);
        check(ids.size() == 2 && ids[0] == 4 && ids[1] == 4 && !k.hc.failed(), "both GOAWAYs name stream 4");
    }
    {
        Link k;
        h3::Config c = Link::config(true);
        c.local.max_field_section_size = 200;
        k.start(true, c);
        k.pump();
        std::vector<qpack::Line> big = get();
        std::string lots(300, 'a');
        big.push_back(line("x-big", lots.c_str()));
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(big));
        Stream *s = k.qc.streams().open(true);
        size_t took = 0;
        s->send->write(v.data(), v.size(), took);
        s->send->finish();
        k.pump();
        check(s->recv->highest() > 0, "the 431 answer reached the client (4.2.2)");
    }
    {
        // \~english Stream errors stop reading too (4.1.1).  \~spanish Los errores de flujo tambien dejan de leer (4.1.1).  \~
        Link k;
        k.start(false);
        k.pump(3, false);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of({line(":method", "GET")}));
        raw(k, true, v, false);
        k.pump(4, false);
        check(k.qs.sent().stop_sending >= 1, "the malformed request's stream is stopped as well as reset");
    }
}

/**
 * @brief
 * \~english QPACK blocking through HTTP/3: a section that waits for its inserts, then reads (RFC 9204, 2.2.1).
 * \~spanish El bloqueo de QPACK a traves de HTTP/3: una seccion que espera sus inserciones, y luego se lee (RFC 9204, 2.2.1).
 * \~
 */
void test_blocked() {
    for (int reset_it = 0; reset_it < 2; ++reset_it) {
        section(reset_it == 0 ? "blocked" : "blocked, then reset");
        Link k;
        k.start(false);
        k.pump(3, false);
        // \~english An encoder that knows the server's settings, so it inserts and may block.
        // \~spanish Un codificador que conoce los parametros del servidor, asi que inserta y puede bloquear.  \~
        qpack::Encoder e;
        e.reset(qpack::EncoderConfig{});
        e.on_peer_settings(4096, 16);
        std::vector<qpack::Line> req = get();
        req.push_back(line("x-custom", "value"));
        Buffer block;
        e.encode(0, req.data(), req.size(), block, 1 << 20);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, std::vector<uint8_t>(block.data(), block.data() + block.size()));
        const uint64_t id = raw(k, true, v, reset_it == 0);
        k.pump(3, false);
        check(k.find(k.server_events, h3::EventKind::Request, id) == nullptr && k.hs.decoder().blocked() == 1,
              "the request waits for its inserts");
        if (reset_it == 1) {
            k.qc.streams().find(id)->send->reset(h3::kRequestCancelled);
            k.pump(3, false);
            const Rec *r = k.find(k.server_events, h3::EventKind::Reset, id);
            check(r != nullptr && r->code == h3::kRequestCancelled, "a reset ends the wait, and is reported");
            check(k.hs.decoder().blocked() == 0, "and the stream no longer counts as blocked (RFC 9204, 2.2.2.2)");
            continue;
        }
        std::vector<uint8_t> enc;
        add_varint(enc, qpack::kEncoderStreamType);
        size_t n = 0;
        const uint8_t *p = e.output(n);
        enc.insert(enc.end(), p, p + n);
        raw(k, false, enc, false);
        k.pump(3, false);
        check(k.find(k.server_events, h3::EventKind::Request, id) != nullptr, "the inserts arrive: the request reads");
        const Buffer *b = nullptr;
        const http_vx::Request *q = k.hs.request(id, b);
        check(q != nullptr && q->fields.size() == 1, "with its field from the dynamic table");
        check(k.find(k.server_events, h3::EventKind::End, id) != nullptr && !k.hs.failed(), "and its end");
    }
}

} // namespace

int main() {
    test_exchange();
    test_body_and_trailers();
    test_stream_errors();
    test_connection_errors();
    test_client_rules();
    test_server_limits();
    test_response_rules();
    test_more_rules();
    test_blocked();
    if (failures != 0) {
        std::fprintf(stderr, "h3 connection: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("h3 connection: OK\n");
    return 0;
}
