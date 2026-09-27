/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/h3_test_client.h
 * @brief
 * \~english What the HTTP/3 service tests share: a whole client stack, what it saw, and the server's configuration.
 * \~spanish Lo que comparten las pruebas del servicio HTTP/3: una pila de cliente entera, lo que vio, y la configuracion del servidor.
 * \~
 *
 * \~english
 * Each client is a QUIC connection, its TLS handshake and HTTP/3 on top; the
 * tests give the service nothing but datagrams.  Kept in one place so that
 * the service's tests and its open responses' tests drive it the same way.
 * \~spanish
 * Cada cliente es una conexion QUIC, su saludo TLS y HTTP/3 encima; las pruebas
 * no le dan al servicio mas que datagramas.  En un solo sitio para que las
 * pruebas del servicio y las de sus respuestas abiertas lo muevan igual.
 * \~
 */
#ifndef HTTP_VX_TESTS_H3_TEST_CLIENT_H
#define HTTP_VX_TESTS_H3_TEST_CLIENT_H

#include "http_vx/http3_service.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace h3_test {

using namespace http_vx::quic;
namespace h3 = http_vx::h3;
namespace qpack = http_vx::qpack;
using http_vx::Buffer;
using http_vx::Http3Config;
using http_vx::tls::QuicHandshake;
using http_vx::tls::SessionConfig;

inline int failures = 0;
inline char current[96] = "";

/**
 * @brief
 * \~english Counts and says a failed check, naming the section.
 * \~spanish Cuenta y dice una comprobacion fallida, nombrando la seccion.
 * \~
 *
 * @param ok   \~english what should hold  \~spanish lo que deberia cumplirse  \~
 * @param what \~english what it means  \~spanish que significa  \~
 */
inline void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

/**
 * @brief
 * \~english Names what the next checks are about.
 * \~spanish Nombra de que van las comprobaciones siguientes.
 * \~
 *
 * @param name \~english the section  \~spanish la seccion  \~
 */
inline void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

inline const char *const kH3[] = {"h3"};
inline const char *const kH2[] = {"h2"};
inline const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};
inline const uint8_t kServerAddr[6] = {192, 0, 2, 1, 0x01, 0xbb};
constexpr uint64_t kDelay = 10000;

/// \~english What a client saw on one stream.  \~spanish Lo que vio un cliente en un flujo.  \~
struct Seen {
    unsigned status = 0;
    std::vector<std::pair<std::string, std::string>> fields;
    std::string body;
    bool ended = false;
    /// \~english How many times the end was reported: never more than once.
    /// \~spanish Cuantas veces se informo del final: nunca mas de una.  \~
    int ends = 0;
    bool reset = false;
    uint64_t code = 0;

    /**
     * @brief
     * \~english The value of field @p name, or null.  \~spanish El valor de la cabecera @p name, o nulo.
     * \~
     *
     * @param name \~english the name, lower case  \~spanish el nombre, en minusculas  \~
     * @return     \~english its value, or null  \~spanish su valor, o nulo  \~
     */
    const std::string *field(const char *name) const {
        for (const auto &f : fields)
            if (f.first == name) return &f.second;
        return nullptr;
    }

    /**
     * @brief
     * \~english How many times field @p name came.  \~spanish Cuantas veces llego la cabecera @p name.
     * \~
     *
     * @param name \~english the name  \~spanish el nombre  \~
     * @return     \~english the count  \~spanish la cuenta  \~
     */
    size_t count(const char *name) const {
        size_t n = 0;
        for (const auto &f : fields)
            if (f.first == name) ++n;
        return n;
    }
};

/**
 * @brief
 * \~english A connection's configuration with fixed IDs and keys, and no peer parameters yet.
 * \~spanish La configuracion de una conexion con identificadores y claves fijos, y aun sin parametros del otro.
 * \~
 *
 * @param server \~english which end  \~spanish que extremo  \~
 * @param id     \~english what the IDs are made from  \~spanish de que se hacen los identificadores  \~
 * @return       \~english the configuration  \~spanish la configuracion  \~
 */
inline ConnectionConfig base_config(bool server, uint8_t id) {
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
    /// \~english HTTP/3 is not read while set: what arrives stays in QUIC's streams, unread.
    /// \~spanish Mientras esta puesto no se lee HTTP/3: lo que llega se queda en los flujos de QUIC, sin leer.  \~
    bool hold = false;
    std::vector<std::pair<uint64_t, Seen>> seen;

    /**
     * @brief
     * \~english Builds the stack and starts its handshake.
     * \~spanish Construye la pila y empieza su saludo.
     * \~
     *
     * @param window      \~english the receive window of the streams it opens: the server's credit on each response; 0 keeps the default
     *                    \~spanish la ventana de recepcion de los flujos que abre: el credito del servidor en cada respuesta; 0 deja la de siempre  \~
     * @param data_window \~english the connection's receive window (MAX_DATA); 0 keeps the default
     *                    \~spanish la ventana de recepcion de la conexion (MAX_DATA); 0 deja la de siempre  \~
     */
    Client(Crypto &crypto, uint8_t id, const char *const *alpn, uint64_t now = 0,
           const http_vx::tls::Ticket *resume = nullptr, uint64_t window = 0, uint64_t data_window = 0) {
        uint8_t me[6] = {198, 51, 100, id, 0x1f, 0x90};
        make_address(me, sizeof me, path.local);
        make_address(kServerAddr, sizeof kServerAddr, path.peer);
        ConnectionConfig cc = base_config(false, static_cast<uint8_t>(0x40 + id * 16));
        cc.path = path;
        if (window != 0) cc.streams.window_bidi_local = window;
        if (data_window != 0) cc.data_window = data_window;
        q.reset(new Connection(crypto, cc));
        check(q->ready() && q->set_initial_keys(cc.peer_cid, 8), "the client starts");
        tls.alpn = alpn;
        tls.alpn_count = 1;
        tls.server_name = "example.com";
        tls.trust_any_certificate = true;
        // \~english With a ticket: resume, and offer 0-RTT.  \~spanish Con un ticket: reanudar, y ofrecer 0-RTT.  \~
        tls.resume = resume;
        tls.early_data = resume != nullptr;
        hs.reset(new QuicHandshake(crypto, *q, tls));
        check(hs->start(now), "the client's handshake starts");
        h.reset(new h3::Connection(*q));
    }

    /**
     * @brief
     * \~english What was seen on @p stream, made on first use.  \~spanish Lo visto en @p stream, creado al primer uso.
     * \~
     *
     * @param stream \~english the stream  \~spanish el flujo  \~
     * @return       \~english its record  \~spanish su registro  \~
     */
    Seen &at(uint64_t stream) {
        for (auto &s : seen)
            if (s.first == stream) return s.second;
        seen.emplace_back(stream, Seen{});
        return seen.back().second;
    }

    /**
     * @brief
     * \~english Runs the handshake and reads every HTTP/3 event, unless held.
     * \~spanish Hace avanzar el saludo y lee cada evento de HTTP/3, salvo si esta retenido.
     * \~
     *
     * @param now \~english the clock  \~spanish el reloj  \~
     */
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
        if (!started || hold) return;
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
                ++at(e.stream).ends;
            } else if (e.kind == h3::EventKind::Reset) {
                at(e.stream).reset = true;
                at(e.stream).code = e.code;
            }
        }
    }

    /**
     * @brief
     * \~english A field line over two C strings.  \~spanish Una linea de cabecera sobre dos cadenas C.
     * \~
     *
     * @return \~english the line  \~spanish la linea  \~
     */
    qpack::Line line(const char *name, const char *value) {
        qpack::Line l;
        l.name = reinterpret_cast<const uint8_t *>(name);
        l.name_len = std::strlen(name);
        l.value = reinterpret_cast<const uint8_t *>(value);
        l.value_len = std::strlen(value);
        return l;
    }

    /**
     * @brief
     * \~english Sends a request, with @p body if not empty.  \~spanish Manda una peticion, con @p body si no esta vacio.
     * \~
     *
     * @return \~english its stream, or ~0  \~spanish su flujo, o ~0  \~
     */
    uint64_t request(const char *method, const char *path_text, const std::string &body = std::string()) {
        const qpack::Line lines[4] = {line(":method", method), line(":scheme", "https"),
                                      line(":authority", "example.com"), line(":path", path_text)};
        const uint64_t id = h->send_request(lines, 4, body.empty());
        if (id != ~uint64_t{0} && !body.empty())
            h->send_body(id, reinterpret_cast<const uint8_t *>(body.data()), body.size(), true);
        return id;
    }
};

/// \~english A datagram in the air: when it lands, and at whom (-1: the server).
/// \~spanish Un datagrama en el aire: cuando llega, y a quien (-1: el servidor).  \~
struct Datagram {
    uint64_t at;
    int to;
    Path path;
    std::vector<uint8_t> bytes;
};

/// \~english A certificate and its key.  \~spanish Un certificado y su clave.  \~
struct Keys {
    const uint8_t *cert;
    size_t cert_len;
    void *key;
};

/**
 * @brief
 * \~english The server's configuration for tests: short idle timeout, small max_body.
 * \~spanish La configuracion del servidor para las pruebas: inactividad corta, max_body pequeno.
 * \~
 *
 * @param k           \~english its certificate and key  \~spanish su certificado y su clave  \~
 * @param connections \~english how many at once  \~spanish cuantas a la vez  \~
 * @return            \~english the configuration  \~spanish la configuracion  \~
 */
inline Http3Config server_config(const Keys &k, uint32_t connections = 8) {
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

} // namespace h3_test

#endif // HTTP_VX_TESTS_H3_TEST_CLIENT_H
