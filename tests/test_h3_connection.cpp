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

    Link() : Link(client_config(), server_config()) {}

    /// \~english With transport configurations of the test's own.  \~spanish Con configuraciones de transporte propias de la prueba.  \~
    Link(const ConnectionConfig &cc, const ConnectionConfig &sc) : qc(cr, cc), qs(cr, sc), hc(qc), hs(qs) {
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

    /**
     * @brief
     * \~english Polls @p h one event at a time until one of kind @p k on @p stream, and stops there.
     * \~spanish Hace poll de @p h evento a evento hasta uno de tipo @p k en @p stream, y se para ahi.
     * \~
     *
     * \~english What the transport holds right after that event can then be looked at, before any later poll.
     * \~spanish Asi se puede mirar lo que tiene el transporte justo despues de ese evento, antes de otro poll.  \~
     *
     * @return \~english whether that event came  \~spanish si llego ese evento  \~
     */
    bool poll_until(h3::Connection &h, std::vector<Rec> &into, h3::EventKind k, uint64_t stream) {
        for (int guard = 0; guard < 1000; ++guard) {
            const h3::Event e = h.poll(now);
            if (e.kind == h3::EventKind::None) return false;
            into.push_back(Rec{e.kind, e.stream, e.code, std::string(reinterpret_cast<const char *>(e.data), e.len)});
            if (e.kind == k && e.stream == stream) return true;
        }
        return false;
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

/// \~english How many events of kind @p k came on @p stream.  \~spanish Cuantos eventos de tipo @p k llegaron en @p stream.  \~
size_t count_of(const std::vector<Rec> &v, h3::EventKind k, uint64_t stream) {
    size_t n = 0;
    for (const Rec &r : v)
        if (r.kind == k && r.stream == stream) ++n;
    return n;
}

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
        // \~english Whatever still arrives, and the end, are read and thrown away: the stream goes (RFC 9000, 3.2).
        // \~spanish Lo que siga llegando, y el final, se leen y se tiran: el flujo se va (RFC 9000, 3.2).  \~
        k.pump(4, false);
        check(k.qs.streams().find(id) == nullptr, "the server kept a stream it was done with");
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
        /* \~english
         * The whole request and its FIN came before it was rejected: too late
         * to stop it, so it is thrown away here and its end taken -- or the
         * stream, and a place in the peer's stream limit, would stay forever.
         * \~spanish
         * La peticion entera y su FIN llegaron antes de rechazarla: tarde para
         * pararla, asi que se tira aqui y se recoge su final -- o el flujo, y un
         * sitio en el limite de flujos del otro, se quedarian para siempre.
         * \~ */
        k.pump(4, false);
        check(k.qs.streams().find(id) == nullptr, "the rejected stream stayed at the server");
    }
    {
        /* \~english
         * Many rejected requests, each with a body, far more than the
         * connection's window: every rejected byte comes back to the window
         * (RFC 9000, 3.5), and every rejected stream goes, so both MAX_DATA
         * and MAX_STREAMS keep moving.  The raw client gives up reading each
         * answer, as the server gives up reading each request.
         * \~spanish
         * Muchas peticiones rechazadas, cada una con cuerpo, mucho mas que la
         * ventana de la conexion: cada byte rechazado vuelve a la ventana (RFC
         * 9000, 3.5), y cada flujo rechazado se va, asi que tanto MAX_DATA como
         * MAX_STREAMS siguen avanzando.  El cliente en crudo renuncia a leer cada
         * respuesta, como el servidor renuncia a leer cada peticion.
         * \~ */
        ConnectionConfig cc = client_config();
        ConnectionConfig sc = server_config();
        sc.data_window = 20000;
        cc.peer_max_data = 20000;
        cc.streams.peer_max_streams_bidi = 10;
        sc.streams.peer_bidi_concurrency = 10;
        Link k(cc, sc);
        k.start(false);
        k.pump(3, false);
        k.hs.goaway();
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(get()));
        add_frame(v, h3::kData, std::vector<uint8_t>(3000, 'z'));
        const int want = 60;
        int sent = 0;
        for (int round = 0; round < 400 && sent < want; ++round) {
            Stream *s = k.qc.streams().open(true);
            if (s == nullptr) {
                k.pump(1, false);
                continue;
            }
            size_t took = 0;
            s->send->write(v.data(), v.size(), took);
            s->send->finish();
            k.qc.stop_receiving(*s, h3::kNoError);
            ++sent;
        }
        k.pump(6, false);
        const RecvFlow &flow = k.qs.recv_flow();
        check(sent == want, "the client could not open every request: streams or window stuck");
        /* \~english
         * Not every body arrives whole: the server's STOP_SENDING makes the
         * client reset what it had not sent yet (3.5).  What did arrive is
         * several windows, which only a window that moved lets through.
         * \~spanish
         * No todos los cuerpos llegan enteros: el STOP_SENDING del servidor hace
         * que el cliente reinicie lo que aun no mando (3.5).  Lo que llego son
         * varias ventanas, que solo deja pasar una ventana que se movio.
         * \~ */
        check(flow.received() > 4 * sc.data_window, "the connection's window stopped moving");
        if (flow.consumed() != flow.received())
            std::fprintf(stderr, "FAIL [%s]: %llu of %llu bytes came back to the connection's window\n", current,
                         static_cast<unsigned long long>(flow.consumed()),
                         static_cast<unsigned long long>(flow.received()));
        failures += flow.consumed() != flow.received() ? 1 : 0;
        check(k.find(k.server_events, h3::EventKind::Request) == nullptr, "no request reaches the application");
        check(k.qs.streams().count() <= 3 + 1, "rejected streams stayed at the server");
        check(!k.hs.failed(), "nothing failed");
    }
    {
        /* \~english
         * Rejected requests whose bytes come out of order: the ends of their
         * bodies, FIN included, first.  The server rejects streams with holes
         * ("Size Known"): it asks them to stop (RFC 9000, 3.5), and each ends
         * when its hole is filled or its reset comes -- none stays, and the
         * window is whole.
         * \~spanish
         * Peticiones rechazadas cuyos bytes llegan desordenados: primero los
         * finales de sus cuerpos, FIN incluido.  El servidor rechaza flujos con
         * huecos ("Size Known"): les pide parar (RFC 9000, 3.5), y cada uno acaba
         * cuando se llena su hueco o llega su reinicio -- ninguno se queda, y la
         * ventana esta entera.
         * \~ */
        Link k;
        k.start(false);
        k.pump(3, false);
        k.hs.goaway();
        k.pump(2, false);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, section_of(get()));
        add_frame(v, h3::kData, std::vector<uint8_t>(3000, 'z'));
        uint64_t ids[6] = {};
        for (uint64_t &id : ids) {
            Stream *s = k.qc.streams().open(true);
            check(s != nullptr, "the raw client opens a stream");
            if (s == nullptr) return;
            size_t took = 0;
            s->send->write(v.data(), v.size(), took);
            s->send->finish();
            k.qc.stop_receiving(*s, h3::kNoError);
            id = s->id;
        }
        std::vector<std::vector<uint8_t>> air;
        uint8_t buf[1500];
        size_t n = 0;
        while ((n = k.qc.build_datagram(g_sent, buf, sizeof buf, k.now)) != 0) air.emplace_back(buf, buf + n);
        check(air.size() >= 6, "the requests did not take several datagrams");
        // \~english The later half first, read by the server; then the rest.
        // \~spanish Primero la mitad de detras, leida por el servidor; despues el resto.  \~
        const size_t half = air.size() / 2;
        for (size_t i = half; i < air.size(); ++i) k.qs.on_datagram(kPath, air[i].data(), air[i].size(), Ecn::NotEct, k.now);
        k.drain(k.hs, k.server_events);
        bool waiting = false;
        for (const uint64_t id : ids) {
            const Stream *s = k.qs.streams().find(id);
            if (s != nullptr && s->recv->state() == RecvState::SizeKnown && s->recv->abandoned()) waiting = true;
        }
        check(waiting, "no rejected stream was left waiting for its hole");
        for (size_t i = 0; i < half; ++i) k.qs.on_datagram(kPath, air[i].data(), air[i].size(), Ecn::NotEct, k.now);
        k.pump(8, false);
        bool gone = true;
        for (const uint64_t id : ids)
            if (k.qs.streams().find(id) != nullptr) gone = false;
        check(gone, "a rejected stream with a hole stayed at the server");
        check(k.qs.sent().stop_sending >= 1, "no STOP_SENDING asked the client to stop");
        check(k.qs.recv_flow().consumed() == k.qs.recv_flow().received(),
              "a byte of a rejected stream was not given back to the connection's window");
        check(k.find(k.server_events, h3::EventKind::Request) == nullptr && !k.hs.failed(),
              "a rejected request reached the application, or something failed");
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
        // \~english The section never read is given back, and the stream goes once answered (RFC 9000, 3.5).
        // \~spanish La seccion que nunca se leyo se devuelve, y el flujo se va una vez contestado (RFC 9000, 3.5).  \~
        k.pump();
        check(k.qs.streams().find(s->id) == nullptr, "the stream answered 431 stayed at the server");
        check(k.qs.recv_flow().consumed() == k.qs.recv_flow().received(),
              "the header section never read was not given back to the connection's window");
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
            k.pump(3, false, false);
            const bool reported = k.poll_until(k.hs, k.server_events, h3::EventKind::Reset, id);
            const Stream *s = k.qs.streams().find(id);
            check(reported && s != nullptr && s->recv->state() == RecvState::ResetRead,
                  "the reset is taken from the transport as it is reported (RFC 9000, 3.2)");
            k.pump(3, false);
            const Rec *r = k.find(k.server_events, h3::EventKind::Reset, id);
            check(r != nullptr && r->code == h3::kRequestCancelled, "a reset ends the wait, and is reported");
            check(count_of(k.server_events, h3::EventKind::Reset, id) == 1, "once");
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

    // \~english Several sections let go of in one batch: each is reread, not only the first.
    // \~spanish Varias secciones soltadas en una tanda: se relee cada una, no solo la primera.  \~
    section("blocked, several at once");
    Link k;
    k.start(false);
    k.pump(3, false);
    qpack::Encoder e;
    e.reset(qpack::EncoderConfig{});
    e.on_peer_settings(4096, 16);
    uint64_t ids[3];
    const char *values[3] = {"one", "two", "three"};
    for (int i = 0; i < 3; ++i) {
        std::vector<qpack::Line> req = get();
        req.push_back(line("x-custom", values[i]));
        Buffer block;
        e.encode(static_cast<uint64_t>(i) * 4, req.data(), req.size(), block, 1 << 20);
        std::vector<uint8_t> v;
        add_frame(v, h3::kHeaders, std::vector<uint8_t>(block.data(), block.data() + block.size()));
        ids[i] = raw(k, true, v, true);
    }
    k.pump(3, false);
    check(k.hs.decoder().blocked() == 3, "three requests wait for their inserts");
    std::vector<uint8_t> enc;
    add_varint(enc, qpack::kEncoderStreamType);
    size_t n = 0;
    const uint8_t *p = e.output(n);
    enc.insert(enc.end(), p, p + n);
    raw(k, false, enc, false);
    k.pump(3, false);
    for (int i = 0; i < 3; ++i)
        check(k.find(k.server_events, h3::EventKind::Request, ids[i]) != nullptr &&
                  k.find(k.server_events, h3::EventKind::End, ids[i]) != nullptr,
              "every request let go of in the batch is read");
    check(!k.hs.failed(), "nothing failed");
}

void test_stop_reading() {
    section("stop reading");
    Link k;
    k.start();
    k.pump();
    const std::vector<qpack::Line> req = {line(":method", "POST"), line(":scheme", "https"),
                                          line(":authority", "example.com"), line(":path", "/up")};
    const uint64_t id = k.hc.send_request(req.data(), req.size(), false);
    k.hc.send_body(id, reinterpret_cast<const uint8_t *>("abc"), 3, false);
    k.pump();
    check(k.find(k.server_events, h3::EventKind::Request, id) != nullptr && k.body(k.server_events, id) == "abc",
          "the request and the first of its body");
    check(!k.hc.stop_reading(id), "a client does not stop reading a request");
    check(k.hs.stop_reading(id), "the server stops reading it");
    check(!k.hs.stop_reading(id), "once");
    k.pump();
    Stream *cs = k.qc.streams().find(id);
    check(cs != nullptr && cs->send->reset_code() == h3::kNoError,
          "the client is asked to stop with H3_NO_ERROR (RFC 9114, 4.1.1)");
    check(k.hs.respond(id, 413, nullptr, 0, true), "the response still goes");
    k.hc.send_body(id, reinterpret_cast<const uint8_t *>("def"), 3, true);
    k.pump();
    check(k.body(k.server_events, id) == "abc" && k.find(k.server_events, h3::EventKind::End, id) == nullptr,
          "nothing more of the request is reported");
    const Rec *r = k.find(k.client_events, h3::EventKind::Response, id);
    check(r != nullptr && r->status == 413 && k.find(k.client_events, h3::EventKind::End, id) != nullptr,
          "the client has the whole response");
    check(!k.hs.failed() && !k.hc.failed(), "nothing failed");

    // \~english Trailers still waiting for QPACK: QPACK is told they will not be read (RFC 9204, 4.4.2).
    // \~spanish Remolques aun esperando a QPACK: se le dice a QPACK que no se leeran (RFC 9204, 4.4.2).  \~
    section("stop reading with blocked trailers");
    Link b;
    b.start(false);
    b.pump(3, false);
    std::vector<uint8_t> v;
    add_frame(v, h3::kHeaders, section_of(req));
    qpack::Encoder e;
    e.reset(qpack::EncoderConfig{});
    e.on_peer_settings(4096, 16);
    const std::vector<qpack::Line> trailers = {line("x-checksum", "abc123")};
    Buffer block;
    e.encode(0, trailers.data(), trailers.size(), block, 1 << 20);
    add_frame(v, h3::kHeaders, std::vector<uint8_t>(block.data(), block.data() + block.size()));
    const uint64_t bid = raw(b, true, v, false);
    b.pump(3, false);
    check(b.find(b.server_events, h3::EventKind::Request, bid) != nullptr && b.hs.decoder().blocked() == 1,
          "the request is read, its trailers wait for their inserts");
    check(b.hs.stop_reading(bid), "the server stops reading it");
    check(b.hs.decoder().blocked() == 0, "and QPACK no longer holds the trailers as blocked");
    b.pump(3, false);
    check(b.find(b.server_events, h3::EventKind::Reset, bid) == nullptr,
          "the reset the client answers with is not reported: the stream was already left");
    check(!b.hs.failed(), "nothing failed");

    /* \~english
     * Stopped right after a Body event, before the next poll takes its bytes:
     * those bytes were given back by the stop, and must not be counted a
     * second time; the client's data and FIN that were already on their way
     * are thrown away and given back too, and the stream goes.
     * \~spanish
     * Parada justo tras un evento Body, antes de que el siguiente poll recoja
     * sus bytes: esos bytes ya los devolvio la parada, y no deben contarse otra
     * vez; los datos y el FIN del cliente que ya iban de camino se tiran y se
     * devuelven tambien, y el flujo se va.
     * \~ */
    section("stop reading at a Body event");
    Link d;
    d.start();
    d.pump();
    const uint64_t did = d.hc.send_request(req.data(), req.size(), false);
    const std::string half(2000, 'q');
    d.hc.send_body(did, reinterpret_cast<const uint8_t *>(half.data()), half.size(), false);
    d.pump(3, true, false);
    check(d.poll_until(d.hs, d.server_events, h3::EventKind::Body, did), "the server has a Body event");
    check(d.hs.stop_reading(did), "and stops reading there");
    d.hc.send_body(did, reinterpret_cast<const uint8_t *>(half.data()), half.size(), true);
    d.pump();
    check(d.hs.respond(did, 413, nullptr, 0, true), "the response goes");
    d.pump();
    const RecvFlow &flow = d.qs.recv_flow();
    check(flow.consumed() == flow.received(), "a byte of the connection's window was lost or counted twice");
    check(d.qs.streams().find(did) == nullptr, "the stream stayed once both sides were done");
    check(!d.hs.failed() && !d.hc.failed(), "nothing failed");

    section("stop reading, a client");
    Link c;
    c.start();
    c.pump();
    const std::vector<qpack::Line> g = get();
    const uint64_t cid = c.hc.send_request(g.data(), g.size(), true);
    c.pump();
    check(c.hs.respond(cid, 200, nullptr, 0, false), "a response with more to come");
    c.pump();
    check(c.find(c.client_events, h3::EventKind::Response, cid) != nullptr, "the client has its header section");
    check(!c.hc.stop_reading(cid), "and cannot use what is a server's");
}

void test_stream_order() {
    /* \~english
     * Streams that finish give their slots back, and the next ones take them
     * in the other order: a higher ID in a lower slot.  Each must still be
     * read -- the server visits them by ID, not by slot.
     * \~spanish
     * Los flujos que acaban devuelven sus casillas, y los siguientes las cogen
     * en el orden contrario: un ID mayor en una casilla menor.  Cada uno se
     * tiene que leer igual -- el servidor los visita por ID, no por casilla.
     * \~ */
    section("request streams in slots out of order");
    Link k;
    k.start();
    k.pump();
    const std::vector<qpack::Line> req = get();
    for (int i = 0; i < 2; ++i) {
        const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
        k.pump();
        k.hs.respond(id, 204, nullptr, 0, true);
        k.pump();
        check(k.find(k.client_events, h3::EventKind::End, id) != nullptr, "an exchange finishes");
    }
    const uint64_t a = k.hc.send_request(req.data(), req.size(), true);
    const uint64_t b = k.hc.send_request(req.data(), req.size(), true);
    k.pump();
    check(k.find(k.server_events, h3::EventKind::Request, a) != nullptr, "the lower stream is read");
    check(k.find(k.server_events, h3::EventKind::Request, b) != nullptr, "and the higher one");

    {
        /* \~english
         * Two request slots and five exchanges: each finished request gives its
         * slot back and the next takes it -- and the finished one's ID no longer
         * finds anything, not even the request that took its slot.
         * \~spanish
         * Dos casillas de peticion y cinco intercambios: cada peticion acabada
         * devuelve su casilla y la siguiente la coge -- y el identificador de la
         * acabada ya no encuentra nada, ni siquiera la peticion que cogio su
         * casilla.
         * \~ */
        Link s;
        h3::Config c = Link::config(true);
        c.max_requests = 2;
        s.start(true, c);
        s.pump();
        uint64_t first = ~uint64_t{0};
        bool all_read = true;
        for (int i = 0; i < 5; ++i) {
            const uint64_t id = s.hc.send_request(req.data(), req.size(), true);
            if (i == 0) first = id;
            s.pump();
            if (s.find(s.server_events, h3::EventKind::Request, id) == nullptr) all_read = false;
            s.hs.respond(id, 204, nullptr, 0, true);
            s.pump(10);
        }
        check(all_read, "a request after the first two found no free slot");
        const Buffer *bytes = nullptr;
        check(s.hs.request(first, bytes) == nullptr, "a finished request is still found by its ID");
    }
    {
        /* \~english
         * Turns: one request with a body waiting and one that just arrived.  The
         * second's request is read before the first's body -- a request that
         * always has something to say cannot keep another waiting.
         * \~spanish
         * Turnos: una peticion con un cuerpo esperando y otra que acaba de llegar.
         * La peticion de la segunda se lee antes que el cuerpo de la primera --
         * una peticion que siempre tiene algo que decir no puede hacer esperar a
         * otra.
         * \~ */
        Link t;
        t.start();
        t.pump();
        const std::vector<qpack::Line> post = {line(":method", "POST"), line(":scheme", "https"),
                                               line(":authority", "example.com"), line(":path", "/")};
        const uint64_t first = t.hc.send_request(post.data(), post.size(), false);
        const std::string payload(3000, 'b');
        t.hc.send_body(first, reinterpret_cast<const uint8_t *>(payload.data()), payload.size(), false);
        const uint64_t second = t.hc.send_request(req.data(), req.size(), true);
        t.pump();
        size_t second_at = t.server_events.size();
        size_t first_body_at = t.server_events.size();
        for (size_t i = 0; i < t.server_events.size(); ++i) {
            const Rec &r = t.server_events[i];
            if (r.kind == h3::EventKind::Request && r.stream == second && second_at == t.server_events.size())
                second_at = i;
            if (r.kind == h3::EventKind::Body && r.stream == first && first_body_at == t.server_events.size())
                first_body_at = i;
        }
        check(second_at < t.server_events.size() && first_body_at < t.server_events.size(),
              "both requests and the body are read");
        check(second_at < first_body_at, "a request with more to say kept another waiting for its turn");
    }
    {
        /* \~english
         * Unidirectional streams past the ones this end keeps are stopped with
         * H3_STREAM_CREATION_ERROR, found by index like request streams.  The
         * eight kept are stopped too, for their unknown type (6.2) -- but only
         * after being read; the ninth is never read, so only finding it by
         * index can stop it.
         * \~spanish
         * Los flujos unidireccionales que pasan de los que guarda este extremo se
         * paran con H3_STREAM_CREATION_ERROR, encontrados por indice como los de
         * peticion.  Los ocho guardados tambien se paran, por su tipo desconocido
         * (6.2) -- pero despues de leerlos; el noveno no se lee nunca, asi que
         * solo encontrarlo por indice puede pararlo.
         * \~ */
        ConnectionConfig cc = client_config();
        ConnectionConfig sc = server_config();
        cc.streams.peer_max_streams_uni = 12;
        sc.streams.peer_uni_concurrency = 12;
        Link u(cc, sc);
        u.start(false);
        u.pump(3, false);
        std::vector<uint8_t> reserved;
        add_varint(reserved, 0x21);
        uint64_t ids[9] = {};
        for (uint64_t &id : ids) id = raw(u, false, reserved, false);
        u.pump(6, false);
        bool stopped = true;
        for (const uint64_t id : ids) {
            const Stream *s = u.qc.streams().find(id);
            if (s != nullptr && s->send->reset_code() != h3::kStreamCreationError) stopped = false;
        }
        check(stopped, "a unidirectional stream, kept or past what is kept, was not stopped (6.2)");

        /* \~english
         * A tenth, past what is kept, whose bytes and FIN all came before it
         * was seen: too late to stop, so it is thrown away and its end taken.
         * Then every one of them goes: the resets their stops asked for need
         * nobody to hear them (RFC 9000, 3.5), and nothing waits for a reader.
         * \~spanish
         * Un decimo, pasado lo que se guarda, cuyos bytes y FIN llegaron todos
         * antes de verlo: tarde para pararlo, asi que se tira y se recoge su
         * final.  Despues se van todos: los reinicios que pidieron sus paradas no
         * necesitan a nadie que los oiga (RFC 9000, 3.5), y nada espera a un
         * lector.
         * \~ */
        const uint64_t tenth = raw(u, false, reserved, true);
        u.pump(6, false);
        bool gone = u.qs.streams().find(tenth) == nullptr;
        for (const uint64_t id : ids)
            if (u.qs.streams().find(id) != nullptr) gone = false;
        check(gone, "a unidirectional stream this end is done with stayed");
        check(u.qs.recv_flow().consumed() == u.qs.recv_flow().received(),
              "a byte of a stream thrown away was not given back to the connection's window");
        check(!u.hs.failed(), "and nothing failed");
    }
}

/**
 * @brief
 * \~english A message whose FIN comes alone, after its last DATA was read: End, once, on both sides (RFC 9000, 3.2; RFC 9114, 4.1).
 * \~spanish Un mensaje cuyo FIN llega solo, tras leerse su ultimo DATA: End, una vez, en los dos lados (RFC 9000, 3.2; RFC 9114, 4.1).
 * \~
 *
 * \~english
 * In each case the other direction of the stream is already finished and
 * acknowledged, so nothing but the end still to report keeps the stream: the
 * transport must not collect it before HTTP/3 has taken that end.
 * \~spanish
 * En cada caso la otra direccion del flujo ya esta acabada y confirmada, asi que
 * nada salvo el final aun por informar mantiene el flujo: el transporte no debe
 * recogerlo antes de que HTTP/3 haya recogido ese final.
 * \~
 */
void test_lone_fin() {
    section("a response's FIN alone, after its body was read");
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get("/");
        const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
        k.pump();
        check(k.find(k.server_events, h3::EventKind::End, id) != nullptr, "the request ends");
        check(k.hs.respond(id, 200, nullptr, 0, false), "the head");
        check(k.hs.send_body(id, reinterpret_cast<const uint8_t *>("abc"), 3, false), "the body, not ended");
        k.pump();
        check(k.body(k.client_events, id) == "abc" && count_of(k.client_events, h3::EventKind::End, id) == 0,
              "the client reads the body, and no end yet");
        check(k.hs.send_body(id, nullptr, 0, true), "the end, alone");
        k.pump(3, false);
        const bool ended = k.poll_until(k.hc, k.client_events, h3::EventKind::End, id);
        const Stream *s = k.qc.streams().find(id);
        check(ended && s != nullptr && s->recv->state() == RecvState::DataRead,
              "the end is taken from the transport as it is reported (RFC 9000, 3.2)");
        k.pump();
        check(count_of(k.client_events, h3::EventKind::End, id) == 1, "the client hears the end, once");
        check(count_of(k.client_events, h3::EventKind::Reset, id) == 0, "and no reset");
        check(k.qc.streams().find(id) == nullptr, "and the stream is gone once its end was taken");
        check(!k.hc.failed() && !k.hs.failed(), "nothing failed");
    }

    section("a request's FIN alone, after its body, answered early");
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> post = {line(":method", "POST"), line(":scheme", "https"),
                                               line(":authority", "example.com"), line(":path", "/up")};
        const uint64_t id = k.hc.send_request(post.data(), post.size(), false);
        check(k.hc.send_body(id, reinterpret_cast<const uint8_t *>("abc"), 3, false), "the body, not ended");
        k.pump();
        check(k.find(k.server_events, h3::EventKind::Request, id) != nullptr && k.body(k.server_events, id) == "abc",
              "the server reads the request and its body");
        // \~english Answered before the request ended, as a server may (RFC 9114, 4.1).
        // \~spanish Contestada antes de que acabe la peticion, como puede un servidor (RFC 9114, 4.1).  \~
        check(k.hs.respond(id, 200, nullptr, 0, true), "an early, whole response");
        k.pump();
        check(count_of(k.client_events, h3::EventKind::End, id) == 1, "the client reads the response");
        const Stream *s = k.qs.streams().find(id);
        check(s != nullptr && s->send->state() == SendState::DataRecvd, "and the server's side is acknowledged");
        check(k.hc.send_body(id, nullptr, 0, true), "the request's end, alone");
        k.pump();
        check(count_of(k.server_events, h3::EventKind::End, id) == 1, "the server hears the request's end, once");
        check(k.qs.streams().find(id) == nullptr, "and the stream is gone once its end was taken");
        check(!k.hc.failed() && !k.hs.failed(), "nothing failed");
    }

    section("a request's FIN alone, before its body was read");
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> post = {line(":method", "POST"), line(":scheme", "https"),
                                               line(":authority", "example.com"), line(":path", "/up")};
        const uint64_t id = k.hc.send_request(post.data(), post.size(), false);
        k.hc.send_body(id, reinterpret_cast<const uint8_t *>("abc"), 3, false);
        k.pump(3, true, false);
        k.hc.send_body(id, nullptr, 0, true);
        k.pump(3, true, false);
        const Stream *s = k.qs.streams().find(id);
        check(s != nullptr && s->recv->state() == RecvState::DataRecvd && !s->recv->at_end(),
              "everything arrived and nothing was read");
        k.pump();
        check(k.body(k.server_events, id) == "abc" && count_of(k.server_events, h3::EventKind::End, id) == 1,
              "the body first, then the end, once");
        size_t end_at = 0;
        size_t body_at = 0;
        for (size_t i = 0; i < k.server_events.size(); ++i) {
            if (k.server_events[i].stream != id) continue;
            if (k.server_events[i].kind == h3::EventKind::End) end_at = i;
            if (k.server_events[i].kind == h3::EventKind::Body) body_at = i;
        }
        check(body_at < end_at, "the end came after the body");
        check(!k.hc.failed() && !k.hs.failed(), "nothing failed");
    }

    section("a response reset after its head, the request done");
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> req = get("/");
        const uint64_t id = k.hc.send_request(req.data(), req.size(), true);
        k.pump();
        check(k.hs.respond(id, 200, nullptr, 0, false), "the head");
        k.pump();
        k.hs.cancel(id, h3::kInternalError);
        k.pump(3, false);
        const bool reported = k.poll_until(k.hc, k.client_events, h3::EventKind::Reset, id);
        const Stream *s = k.qc.streams().find(id);
        check(reported && s != nullptr && s->recv->state() == RecvState::ResetRead,
              "the reset is reported, and taken from the transport as it is (RFC 9000, 3.2)");
        k.pump();
        check(count_of(k.client_events, h3::EventKind::Reset, id) == 1 &&
                  count_of(k.client_events, h3::EventKind::End, id) == 0,
              "once, and never as an end");
        check(k.qc.streams().find(id) == nullptr, "and the stream is gone");
    }

    section("a FIN that overtook the data");
    {
        Link k;
        k.start();
        k.pump();
        const std::vector<qpack::Line> post = {line(":method", "POST"), line(":scheme", "https"),
                                               line(":authority", "example.com"), line(":path", "/up")};
        const uint64_t id = k.hc.send_request(post.data(), post.size(), false);
        k.pump();
        check(k.find(k.server_events, h3::EventKind::Request, id) != nullptr, "the request");
        /* \~english
         * The FIN of a DATA frame of three bytes (two of header) arrives first,
         * as a reordering network would deliver it: the size is known, the
         * bytes before it are not here.
         * \~spanish
         * El FIN de una trama DATA de tres bytes (dos de cabecera) llega primero,
         * como lo entregaria una red que reordena: el tamano se sabe, los bytes
         * de delante no estan.
         * \~ */
        Stream *s = k.qs.streams().find(id);
        uint64_t fresh = 0;
        uint64_t released = 0;
        check(s != nullptr &&
                  s->recv->on_data(s->recv->highest() + 5, nullptr, 0, true, fresh, released) == StreamError::None,
              "the early FIN is taken");
        k.drain(k.hs, k.server_events);
        check(count_of(k.server_events, h3::EventKind::End, id) == 0,
              "no end while bytes before the FIN are missing");
        check(k.hc.send_body(id, reinterpret_cast<const uint8_t *>("abc"), 3, false), "the missing DATA");
        k.pump();
        check(k.body(k.server_events, id) == "abc" && count_of(k.server_events, h3::EventKind::End, id) == 1,
              "the body, then the end, once");
        check(k.hc.send_body(id, nullptr, 0, true), "the client's own FIN, at the same size");
        k.pump();
        check(count_of(k.server_events, h3::EventKind::End, id) == 1 && !k.hs.failed(), "changes nothing");
    }

    section("a unidirectional stream of unknown type, ended");
    {
        Link k;
        k.start(false);
        k.pump(3, false);
        // \~english A reserved type, a few bytes and the FIN in one go: thrown away, and given back (RFC 9114, 6.2, 9).
        // \~spanish Un tipo reservado, unos bytes y el FIN de una vez: se tira, y se devuelve (RFC 9114, 6.2, 9).  \~
        std::vector<uint8_t> v;
        add_varint(v, 0x21);
        const std::vector<uint8_t> junk = bytes("ignored");
        v.insert(v.end(), junk.begin(), junk.end());
        const uint64_t id = raw(k, false, v, true);
        k.pump(4, false);
        check(!k.hs.failed(), "an unknown stream type is not an error (6.2)");
        check(k.qs.streams().find(id) == nullptr, "the stream was read, its end taken, and it went");
        check(k.qs.recv_flow().consumed() == k.qs.recv_flow().received(),
              "the bytes after the type were not given back to the connection's window");
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
    test_stream_order();
    test_stop_reading();
    test_lone_fin();
    if (failures != 0) {
        std::fprintf(stderr, "h3 connection: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("h3 connection: OK\n");
    return 0;
}
