/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_http3_service.cpp
 * @brief
 * \~english The HTTP/3 service against real clients: handshake, requests, the handler's answers, and the service's own rules.
 * \~spanish El servicio HTTP/3 frente a clientes de verdad: saludo, peticiones, las respuestas del manejador, y las reglas del propio servicio.
 * \~
 *
 * \~english
 * Each client is a whole stack -- a QUIC connection, its TLS handshake and
 * HTTP/3 on top -- and the service is given nothing but datagrams, over a
 * simulated network with a delay.  The handler is the one any version would
 * use: it names no version.
 * \~spanish
 * Cada cliente es una pila entera -- una conexion QUIC, su saludo TLS y HTTP/3
 * encima -- y al servicio no se le da mas que datagramas, por una red simulada
 * con retardo.  El manejador es el que usaria cualquier version: no nombra
 * ninguna.
 * \~
 */
#include "http_vx/http3_service.h"

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
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace http_vx::quic;
namespace h3 = http_vx::h3;
namespace qpack = http_vx::qpack;
using http_vx::Buffer;
using http_vx::Http3Config;
using http_vx::Http3Service;
using http_vx::tls::QuicHandshake;
using http_vx::tls::SessionConfig;

int failures = 0;
char current[96] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

const char *const kH3[] = {"h3"};
const char *const kH2[] = {"h2"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};
const uint8_t kServerAddr[6] = {192, 0, 2, 1, 0x01, 0xbb};
constexpr uint64_t kDelay = 10000;

/**
 * @brief
 * \~english The handler: it answers by path, and knows nothing of HTTP/3.
 * \~spanish El manejador: contesta segun la ruta, y no sabe nada de HTTP/3.
 * \~
 */
class EchoHandler final : public http_vx::Handler {
  public:
    int calls = 0;

    void handle(const http_vx::Request &req, const uint8_t *head, const uint8_t *body, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        ++calls;
        const std::string path(reinterpret_cast<const char *>(head) + req.target.off, req.target.len);
        if (path == "/bad") {
            // \~english A value with CR LF: it cannot leave, in any version.  \~spanish Un valor con CR LF: no puede salir, en ninguna version.  \~
            res.field("X-Split", 7, "a\r\nb", 4);
            return;
        }
        if (path == "/connection") {
            res.field(http_vx::FieldId::Connection, "close", 5);
            return;
        }
        if (path == "/badname") {
            res.field("Bad Name", 8, "x", 1);
            return;
        }
        if (path == "/many") {
            for (int i = 0; i < 70; ++i) res.field("X-F", 3, "v", 1);
            return;
        }
        if (path == "/big") {
            std::string big(100000, 'x');
            for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>('a' + i % 26);
            res.field(http_vx::FieldId::ContentType, "text/plain", 10);
            res.body(big.data(), big.size());
            return;
        }
        if (path == "/secret") res.field(http_vx::FieldId::SetCookie, "id=42", 5);
        if (path == "/sized") res.field(http_vx::FieldId::ContentLength, "5", 1);
        if (path == "/teapot") res.status(418);
        const std::string method(reinterpret_cast<const char *>(head) + req.method_text.off, req.method_text.len);
        // \~english Spelled with capitals, as HTTP/1.1 allows: HTTP/3 must lower it.
        // \~spanish Escrito con mayusculas, como permite HTTP/1.1: HTTP/3 tiene que bajarlo.  \~
        res.field("X-Echo-Method", 13, method.data(), method.size());
        if (n != 0)
            res.body(body, n);
        else
            res.body("hello", 5);
    }
};

/// \~english What a client saw on one stream.  \~spanish Lo que vio un cliente en un flujo.  \~
struct Seen {
    unsigned status = 0;
    std::vector<std::pair<std::string, std::string>> fields;
    std::string body;
    bool ended = false;
    bool reset = false;
    uint64_t code = 0;

    const std::string *field(const char *name) const {
        for (const auto &f : fields)
            if (f.first == name) return &f.second;
        return nullptr;
    }

    size_t count(const char *name) const {
        size_t n = 0;
        for (const auto &f : fields)
            if (f.first == name) ++n;
        return n;
    }
};

ConnectionConfig base_config(bool server, uint8_t id) {
    ConnectionConfig c;
    c.is_server = server;
    for (int i = 0; i < 8; ++i) {
        c.local_cid[i] = static_cast<uint8_t>(id + i);
        c.peer_cid[i] = static_cast<uint8_t>(0x0d + id + i);
    }
    c.streams.is_server = server;
    c.streams.peer_max_streams_bidi = 0;
    c.streams.peer_window_bidi_local = 0;
    c.streams.peer_window_bidi_remote = 0;
    c.peer_max_data = 0;
    for (size_t i = 0; i < sizeof c.reset_key; ++i) c.reset_key[i] = static_cast<uint8_t>(0x33 + i);
    return c;
}

/**
 * @brief
 * \~english One client: QUIC, TLS and HTTP/3, with what it saw per stream.
 * \~spanish Un cliente: QUIC, TLS y HTTP/3, con lo que vio en cada flujo.
 * \~
 */
struct Client {
    Path path;
    SessionConfig tls;
    std::unique_ptr<Connection> q;
    std::unique_ptr<QuicHandshake> hs;
    std::unique_ptr<h3::Connection> h;
    bool started = false;
    std::vector<std::pair<uint64_t, Seen>> seen;

    Client(Crypto &crypto, uint8_t id, const char *const *alpn) {
        uint8_t me[6] = {198, 51, 100, id, 0x1f, 0x90};
        make_address(me, sizeof me, path.local);
        make_address(kServerAddr, sizeof kServerAddr, path.peer);
        ConnectionConfig cc = base_config(false, static_cast<uint8_t>(0x40 + id * 16));
        cc.path = path;
        q.reset(new Connection(crypto, cc));
        check(q->ready() && q->set_initial_keys(cc.peer_cid, 8), "the client starts");
        tls.alpn = alpn;
        tls.alpn_count = 1;
        tls.server_name = "example.com";
        tls.trust_any_certificate = true;
        hs.reset(new QuicHandshake(crypto, *q, tls));
        check(hs->start(0), "the client's handshake starts");
        h.reset(new h3::Connection(*q));
    }

    Seen &at(uint64_t stream) {
        for (auto &s : seen)
            if (s.first == stream) return s.second;
        seen.emplace_back(stream, Seen{});
        return seen.back().second;
    }

    void step(uint64_t now) {
        hs->step(now);
        if (!started && hs->complete()) {
            h3::Config c;
            c.server = false;
            c.local.qpack_max_table_capacity = 4096;
            c.local.qpack_blocked_streams = 16;
            started = h->start(c);
            check(started, "the client's HTTP/3 starts");
        }
        if (!started) return;
        for (int guard = 0; guard < 10000; ++guard) {
            const h3::Event e = h->poll(now);
            if (e.kind == h3::EventKind::None) break;
            if (e.kind == h3::EventKind::Response) {
                const Buffer *b = nullptr;
                const http_vx::Response *r = h->response(e.stream, b);
                Seen &s = at(e.stream);
                if (r != nullptr && r->status >= 200) {
                    s.status = r->status;
                    for (const http_vx::Field *f = r->fields.begin(); f != r->fields.end(); ++f)
                        s.fields.emplace_back(
                            std::string(reinterpret_cast<const char *>(b->data()) + f->name_off, f->name_len),
                            std::string(reinterpret_cast<const char *>(b->data()) + f->value_off, f->value_len));
                }
            } else if (e.kind == h3::EventKind::Body) {
                at(e.stream).body.append(reinterpret_cast<const char *>(e.data), e.len);
            } else if (e.kind == h3::EventKind::End) {
                at(e.stream).ended = true;
            } else if (e.kind == h3::EventKind::Reset) {
                at(e.stream).reset = true;
                at(e.stream).code = e.code;
            }
        }
    }

    qpack::Line line(const char *name, const char *value) {
        qpack::Line l;
        l.name = reinterpret_cast<const uint8_t *>(name);
        l.name_len = std::strlen(name);
        l.value = reinterpret_cast<const uint8_t *>(value);
        l.value_len = std::strlen(value);
        return l;
    }

    uint64_t request(const char *method, const char *path_text, const std::string &body = std::string()) {
        const qpack::Line lines[4] = {line(":method", method), line(":scheme", "https"),
                                      line(":authority", "example.com"), line(":path", path_text)};
        const uint64_t id = h->send_request(lines, 4, body.empty());
        if (id != ~uint64_t{0} && !body.empty())
            h->send_body(id, reinterpret_cast<const uint8_t *>(body.data()), body.size(), true);
        return id;
    }
};

struct Datagram {
    uint64_t at;
    int to;
    Path path;
    std::vector<uint8_t> bytes;
};

/**
 * @brief
 * \~english The service and its clients, over a network that delays every datagram.
 * \~spanish El servicio y sus clientes, por una red que retrasa cada datagrama.
 * \~
 */
struct World {
    Crypto &crypto;
    EchoHandler handler;
    Http3Service service;
    std::vector<std::unique_ptr<Client>> clients;
    std::vector<Datagram> air;
    std::vector<uint8_t> last_to_server;
    std::vector<uint8_t> first_to_server;
    /// \~english How many of the service's next datagrams the network loses.
    /// \~spanish Cuantos de los siguientes datagramas del servicio pierde la red.  \~
    int lose_to_clients = 0;
    uint64_t now = 0;

    explicit World(Crypto &c) : crypto(c), service(c, handler) {}

    Client &add(const char *const *alpn = kH3) {
        clients.emplace_back(new Client(crypto, static_cast<uint8_t>(clients.size() + 1), alpn));
        return *clients.back();
    }

    int client_of(const Path &p) const {
        for (size_t i = 0; i < clients.size(); ++i)
            if (same_address(clients[i]->path.local, p.peer)) return static_cast<int>(i);
        return -2;
    }

    /// \~english Runs until nothing is in the air and no timer is due before @p until.
    /// \~spanish Corre hasta que no quede nada en el aire ni temporizador antes de @p until.  \~
    void run(uint64_t until) {
        for (int step = 0; step < 200000; ++step) {
            uint8_t buf[1500];
            for (size_t i = 0; i < clients.size(); ++i) {
                Client &c = *clients[i];
                c.step(now);
                Path sent;
                size_t n;
                while ((n = c.q->build_datagram(sent, buf, sizeof buf, now)) != 0) {
                    Path to_server;
                    to_server.local = c.path.peer;
                    to_server.peer = c.path.local;
                    air.push_back(Datagram{now + kDelay, -1, to_server, std::vector<uint8_t>(buf, buf + n)});
                }
            }
            Path out;
            size_t n;
            while ((n = service.next_datagram(out, buf, sizeof buf, now)) != 0) {
                if (lose_to_clients > 0) {
                    --lose_to_clients;
                    continue;
                }
                air.push_back(Datagram{now + kDelay, client_of(out), out, std::vector<uint8_t>(buf, buf + n)});
            }

            uint64_t next = service.timer();
            for (auto &c : clients)
                if (c->q->timer() < next) next = c->q->timer();
            for (const Datagram &d : air)
                if (d.at < next) next = d.at;
            if (next == kNever || next > until) {
                // \~english Nothing more before then: the time passes anyway.
                // \~spanish Nada mas antes de eso: el tiempo pasa igual.  \~
                if (until > now) now = until;
                return;
            }
            if (next > now) now = next;

            for (size_t i = 0; i < air.size();) {
                if (air[i].at > now) {
                    ++i;
                    continue;
                }
                Datagram d = std::move(air[i]);
                air[i] = std::move(air.back());
                air.pop_back();
                if (d.to == -1) {
                    last_to_server = d.bytes;
                    if (first_to_server.empty()) first_to_server = d.bytes;
                    service.on_datagram(d.path, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                } else if (d.to >= 0) {
                    Client &c = *clients[static_cast<size_t>(d.to)];
                    c.q->on_datagram(c.path, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                }
            }
            for (auto &c : clients)
                if (c->q->timer() <= now) c->q->on_timer(now);
            if (service.timer() <= now) service.on_timer(now);
        }
        check(false, "the network did not settle");
    }

    void settle() { run(now + 2000000); }
};

struct Keys {
    const uint8_t *cert;
    size_t cert_len;
    void *key;
};

Http3Config server_config(const Keys &k, uint32_t connections = 8) {
    static const uint8_t *certs[1];
    static size_t lens[1];
    certs[0] = k.cert;
    lens[0] = k.cert_len;
    Http3Config c;
    c.connection = base_config(true, 0x70);
    c.connection.idle_timeout_us = 5000000;
    for (size_t i = 0; i < sizeof c.acceptor.reset_key; ++i) c.acceptor.reset_key[i] = c.connection.reset_key[i];
    for (size_t i = 0; i < sizeof c.acceptor.token_key; ++i) c.acceptor.token_key[i] = static_cast<uint8_t>(0x71 * i + 3);
    c.tls.server = true;
    c.tls.alpn = kH3;
    c.tls.alpn_count = 1;
    c.tls.certificates = certs;
    c.tls.certificate_lens = lens;
    c.tls.certificate_count = 1;
    c.tls.signing_key = k.key;
    c.tls.scheme = Scheme::EcdsaSecp256r1Sha256;
    c.h3.server = true;
    c.h3.local.qpack_max_table_capacity = 4096;
    c.h3.local.qpack_blocked_streams = 16;
    c.connections = connections;
    c.max_body = 1000;
    return c;
}

void test_exchange(Crypto &crypto, const Keys &k, const char *name) {
    std::snprintf(current, sizeof current, "%s: exchange", name);
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add();
    w.settle();
    check(c.started && w.service.connections() == 1, "the client connected and speaks HTTP/3");
    const uint64_t get = c.request("GET", "/");
    const uint64_t post = c.request("POST", "/echo", "ping pong");
    const uint64_t head = c.request("HEAD", "/");
    const uint64_t teapot = c.request("GET", "/teapot");
    const uint64_t sized = c.request("HEAD", "/sized");
    const uint64_t edge = c.request("POST", "/echo", std::string(1000, 'z'));
    w.settle();
    const Seen &g = c.at(get);
    check(g.status == 200 && g.body == "hello" && g.ended, "GET: 200 and the handler's body");
    check(g.field("x-echo-method") != nullptr && *g.field("x-echo-method") == "GET",
          "the handler's field arrives with its name in lower case (RFC 9114, 4.2)");
    check(g.field("X-Echo-Method") == nullptr, "and never as written");
    const Seen &p = c.at(post);
    check(p.status == 200 && p.body == "ping pong" && p.ended, "POST: the body is echoed");
    const Seen &h = c.at(head);
    check(h.status == 200 && h.body.empty() && h.ended, "HEAD: the response, with no content (RFC 9110, 9.3.2)");
    check(h.field("content-length") != nullptr && *h.field("content-length") == "5",
          "and the length GET would have had");
    check(c.at(teapot).status == 418, "the handler's status is kept");
    check(c.at(sized).count("content-length") == 1 && c.at(sized).body.empty(),
          "HEAD with the handler's own Content-Length: that one, not a second");
    check(c.at(edge).status == 200 && c.at(edge).body.size() == 1000, "a body of exactly max_body is taken");
    check(w.handler.calls == 6 && w.service.counts().served == 6, "six requests, six answers");
    check(!c.h->failed(), "the client saw no error");

    // \~english The connection gone, a packet for it is nobody's: a stateless reset, not a stale route (RFC 9000, 10.3).
    // \~spanish Ida la conexion, un paquete para ella no es de nadie: un reinicio sin estado, no una ruta rancia (RFC 9000, 10.3).  \~
    std::vector<uint8_t> last = w.last_to_server;
    w.clients.clear();
    w.air.clear();
    w.run(w.now + 60000000);
    check(w.service.connections() == 0, "the connection is gone");
    const uint64_t replies = w.service.counts().replies;
    Path gone;
    make_address(kServerAddr, sizeof kServerAddr, gone.local);
    const uint8_t from[6] = {198, 51, 100, 1, 0x1f, 0x90};
    make_address(from, sizeof from, gone.peer);
    check(!last.empty() && (last[0] & 0x80) == 0, "the client's last packet had a short header");
    w.service.on_datagram(gone, last.data(), last.size(), Ecn::NotEct, w.now);
    check(w.service.counts().replies == replies + 1, "and it is answered with a stateless reset");
}

void test_answers(Crypto &crypto, const Keys &k, const char *name) {
    std::snprintf(current, sizeof current, "%s: answers", name);
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add();
    w.settle();
    const uint64_t bad = c.request("GET", "/bad");
    const uint64_t conn = c.request("GET", "/connection");
    const uint64_t big = c.request("GET", "/big");
    const uint64_t secret = c.request("GET", "/secret");
    const uint64_t large = c.request("POST", "/echo", std::string(1500, 'y'));
    const uint64_t badname = c.request("GET", "/badname");
    const uint64_t many = c.request("GET", "/many");
    w.settle();
    check(c.at(bad).status == 500 && c.at(bad).ended, "a value with CR LF becomes a 500, never a changed answer");
    check(c.at(conn).status == 500, "a connection-specific field becomes a 500 (RFC 9114, 4.2)");
    check(c.at(badname).status == 500, "a name that is not a token becomes a 500");
    check(c.at(many).status == 500, "more fields than a response carries becomes a 500");
    check(w.service.counts().bad_answers == 4, "all four counted");
    const Seen &b = c.at(big);
    bool pattern = b.body.size() == 100000;
    for (size_t i = 0; pattern && i < b.body.size(); ++i) pattern = b.body[i] == static_cast<char>('a' + i % 26);
    check(b.status == 200 && pattern && b.ended, "a response larger than the windows arrives whole");
    check(c.at(secret).field("set-cookie") != nullptr, "a secret field is sent");
    check(w.service.connections() == 1, "and the connection is kept");
    const Seen &l = c.at(large);
    check(l.status == 413 && l.ended, "a body past max_body is answered 413, whole (RFC 9114, 4.1.1)");
    check(w.service.counts().too_large == 1, "and counted");
    check(w.handler.calls == 6, "the handler never sees the refused request");
    check(!c.h->failed(), "the client saw no connection error");
}

void test_many(Crypto &crypto, const Keys &k, const char *name) {
    std::snprintf(current, sizeof current, "%s: many clients", name);
    World w(crypto);
    check(w.service.start(server_config(k, 3)), "the service starts");
    Client &a = w.add();
    Client &b = w.add();
    Client &c = w.add();
    w.settle();
    check(w.service.connections() == 3, "three connections");
    const uint64_t ia = a.request("POST", "/", "from a");
    const uint64_t ib = b.request("POST", "/", "from b");
    const uint64_t ic = c.request("POST", "/", "from c");
    w.settle();
    check(a.at(ia).body == "from a" && b.at(ib).body == "from b" && c.at(ic).body == "from c",
          "each answer goes to its own client: routed by connection ID");

    Client &d = w.add();
    w.settle();
    check(!d.started && w.service.counts().full != 0, "a fourth finds no room, and it is counted");

    // \~english Silence past the idle timeout: the connections go, and their slots with them.
    // \~spanish Silencio pasado el plazo de inactividad: las conexiones se van, y sus casillas con ellas.  \~
    w.clients.clear();
    w.air.clear();
    w.run(w.now + 60000000);
    check(w.service.connections() == 0 && w.service.counts().closed == 3, "idle connections are gone");
    check(w.service.timer() == kNever, "and no timer is left");
    Client &e = w.add();
    w.settle();
    check(e.started && w.service.connections() == 1, "a slot freed is used again");
}

void test_retry(Crypto &crypto, const Keys &k, const char *name) {
    std::snprintf(current, sizeof current, "%s: retry", name);
    World w(crypto);
    Http3Config cfg = server_config(k);
    cfg.acceptor.require_retry = true;
    check(w.service.start(cfg), "the service starts");
    Client &c = w.add();
    w.settle();
    check(c.started && c.q->retried(), "the client proved its address with a Retry");
    const uint64_t id = c.request("GET", "/");
    w.settle();
    check(c.at(id).status == 200, "and is served");
    check(w.service.counts().replies != 0, "the Retry went out as a stateless reply");
}

void test_stateless(Crypto &crypto, const Keys &k) {
    section("stateless replies");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    // \~english A short header for no connection, large enough to answer smaller: a stateless reset (RFC 9000, 10.3).
    // \~spanish Una cabecera corta de ninguna conexion, lo bastante grande para contestar con algo menor: un reinicio sin estado (RFC 9000, 10.3).  \~
    std::vector<uint8_t> junk(100, 0x5a);
    junk[0] = 0x40;
    Path p;
    make_address(kServerAddr, sizeof kServerAddr, p.local);
    const uint8_t from[6] = {203, 0, 113, 9, 0x30, 0x39};
    make_address(from, sizeof from, p.peer);
    w.service.on_datagram(p, junk.data(), junk.size(), Ecn::NotEct, 1000);
    check(w.service.counts().replies == 1, "it is answered");
    uint8_t out[1500];
    Path to;
    const size_t n = w.service.next_datagram(to, out, sizeof out, 1000);
    check(n != 0 && n < junk.size() && same_address(to.peer, p.peer), "smaller than what came, to whoever sent it");
    check(w.service.next_datagram(to, out, sizeof out, 1000) == 0, "and only once");
    check(w.service.connections() == 0, "no connection was made");
    // \~english A full queue drops and counts; it never grows.  \~spanish Una cola llena tira y cuenta; nunca crece.  \~
    for (int i = 0; i < 40; ++i) w.service.on_datagram(p, junk.data(), junk.size(), Ecn::NotEct, 2000);
    check(w.service.counts().replies_dropped == 40 - 32, "past the queue, dropped and counted");
}

void test_start(Crypto &crypto, const Keys &k) {
    section("start");
    EchoHandler h;
    Http3Service s(crypto, h);
    Http3Config c = server_config(k);
    check(s.start(c) && s.why() == nullptr, "a good configuration starts");
    c.connections = 0;
    check(!s.start(c) && s.why() != nullptr, "no room for a connection is refused, saying why");
    c = server_config(k);
    c.acceptor.reset_key[3] ^= 1;
    check(!s.start(c) && std::strstr(s.why(), "stateless") != nullptr, "two reset keys are refused, not chosen from");
    c = server_config(k);
    c.acceptor.cid_len = 12;
    check(!s.start(c), "two ID lengths are refused");
    c = server_config(k);
    c.tls.alpn = kH2;
    check(!s.start(c) && std::strstr(s.why(), "h3") != nullptr, "a TLS configuration without h3 is refused");
    static const char *const draft[] = {"h3-29"};
    c = server_config(k);
    c.tls.alpn = draft;
    check(!s.start(c), "a draft's name is not h3");
    c = server_config(k);
    c.tls.server = false;
    check(!s.start(c), "a client's configuration is refused");
    c = server_config(k);
    c.h3.max_requests = 0;
    check(!s.start(c), "no room for a request is refused");
    check(s.connections() == 0 && s.timer() == kNever, "a service that did not start holds nothing");
    uint8_t junk[64] = {0x40};
    Path p;
    s.on_datagram(p, junk, sizeof junk, Ecn::NotEct, 0);
    uint8_t out[1500];
    check(s.next_datagram(p, out, sizeof out, 0) == 0, "and answers nothing");
}

void test_first_id(Crypto &crypto, const Keys &k) {
    section("the client's first ID");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    // \~english The server's first flight lost: the client sends its Initial again, still to its first ID.
    // \~spanish El primer vuelo del servidor perdido: el cliente vuelve a mandar su Initial, aun a su primer identificador.  \~
    w.lose_to_clients = 3;
    Client &c = w.add();
    // \~english Until the probes that recover the loss -- whose timeout doubles -- get it through; not past the idle timeout.
    // \~spanish Hasta que las sondas que recuperan la perdida -- cuyo plazo se dobla -- lo consigan; no mas alla de la inactividad.  \~
    for (int i = 0; i < 40 && !c.started; ++i) w.run(w.now + 250000);
    check(c.started && w.service.connections() == 1 && w.service.counts().accepted == 1,
          "the repeated Initial reaches the same connection, not a new one");
    const uint64_t id = c.request("GET", "/");
    w.settle();
    check(c.at(id).status == 200, "and it is served");
    // \~english A copy of the very first datagram, late: the connection drops it; no second connection.
    // \~spanish Una copia del primer datagrama, tarde: la conexion la tira; ninguna segunda conexion.  \~
    std::vector<uint8_t> late = w.first_to_server;
    Path from;
    from.local = c.path.peer;
    from.peer = c.path.local;
    w.service.on_datagram(from, late.data(), late.size(), Ecn::NotEct, w.now);
    w.settle();
    check(w.service.connections() == 1 && w.service.counts().accepted == 1, "a late Initial makes no ghost connection");
    const uint64_t again = c.request("GET", "/");
    w.settle();
    check(c.at(again).status == 200, "and the connection goes on");
}

void test_stop_sending(Crypto &crypto, const Keys &k) {
    section("stop sending");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add();
    w.settle();
    const uint64_t before = c.q->bytes_sent();
    const uint64_t id = c.request("POST", "/echo", std::string(300000, 'q'));
    w.settle();
    check(c.at(id).status == 413 && c.at(id).ended, "413, whole");
    check(c.q->bytes_sent() - before < 300000, "and the client was asked to stop: it did not send it all (RFC 9114, 4.1.1)");
}

void test_secret(Crypto &crypto, const Keys &k) {
    section("secrets");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add();
    w.settle();
    const uint64_t first = c.request("GET", "/");
    w.settle();
    check(c.at(first).status == 200, "a first answer fills the table");
    const uint64_t inserted = c.h->decoder().table().inserted();
    const uint64_t id = c.request("GET", "/secret");
    w.settle();
    check(c.at(id).field("set-cookie") != nullptr, "the secret field arrives");
    check(c.h->decoder().table().inserted() == inserted, "but never through QPACK's table (RFC 9204, 7.1.3)");
}

void test_h3_failure(Crypto &crypto, const Keys &k) {
    section("an HTTP/3 error");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add();
    w.settle();
    // \~english DATA before HEADERS on a request stream: a connection error (RFC 9114, 4.1).
    // \~spanish DATA antes de HEADERS en un flujo de peticion: un error de conexion (RFC 9114, 4.1).  \~
    Stream *s = c.q->streams().open(true);
    check(s != nullptr, "the client opens a stream");
    if (s != nullptr) {
        const uint8_t data_first[3] = {0x00, 0x01, 'x'};
        size_t took = 0;
        s->send->write(data_first, sizeof data_first, took);
    }
    w.settle();
    check(w.service.counts().failed == 1, "the failure is counted");
    check(c.q->state() != ConnState::Active, "and the connection is closed");
}

void test_alpn(Crypto &crypto, const Keys &k) {
    section("alpn");
    World w(crypto);
    check(w.service.start(server_config(k)), "the service starts");
    Client &c = w.add(kH2);
    w.settle();
    check(!c.started && c.q->state() != ConnState::Active, "a client that does not offer h3 is turned away");
}

void run_all(Crypto &crypto, const Keys &k, const char *name) {
    test_exchange(crypto, k, name);
    test_answers(crypto, k, name);
    test_many(crypto, k, name);
    test_retry(crypto, k, name);
}

} // namespace

int main() {
    test_support::FakeCrypto fake;
    Keys fk{kFakeCert, sizeof kFakeCert, fake.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert)};
    run_all(fake, fk, "fake");
    test_stateless(fake, fk);
    test_start(fake, fk);
    test_alpn(fake, fk);
    test_first_id(fake, fk);
    test_stop_sending(fake, fk);
    test_secret(fake, fk);
    test_h3_failure(fake, fk);
    fake.forget_key(fk.key);

    int providers = 0;
    uint8_t cert[2048];
    uint8_t pkcs8[2048];
    const size_t cert_len = rfc8448::from_hex(test_keys::kP256Certificate, cert, sizeof cert);
    const size_t key_len = rfc8448::from_hex(test_keys::kP256Pkcs8, pkcs8, sizeof pkcs8);
#if HTTP_VX_HAVE_OPENSSL
    {
        http_vx::OpensslCrypto openssl;
        ++providers;
        Keys ok{cert, cert_len, openssl.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len)};
        test_exchange(openssl, ok, "openssl");
        openssl.forget_key(ok.key);
    }
#endif
#if HTTP_VX_HAVE_CNG
    {
        http_vx::CngCrypto cng;
        ++providers;
        void *ck = cng.ready() ? cng.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len) : nullptr;
        if (ck != nullptr) {
            Keys kk{cert, cert_len, ck};
            test_exchange(cng, kk, "cng");
            cng.forget_key(ck);
        } else {
            std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
            ++failures;
        }
    }
#endif
    (void)cert_len;
    (void)key_len;
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("http3 service, %d real provider(s): OK\n", providers);
    return 0;
}
