/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_http2_service.cpp
 * @brief
 * \~english A whole server speaking HTTP/2, answering with the HTTP/1.1 handler.
 * \~spanish Un servidor entero hablando HTTP/2, contestando con el manejador de HTTP/1.1.
 * \~
 *
 * \~english
 * The one that says whether the project's central claim is true.  The handler
 * in this file says a status, some fields and a body, and it says nothing else
 * -- no frames, no streams, no windows.  If it answers HTTP/2 correctly without
 * naming any of them, then a handler is genuinely version-blind; if it cannot,
 * the cut between semantics and syntax was in the wrong place and everything
 * above it is written against a lie.
 *
 * The cases are the ones where HTTP/2 differs from HTTP/1.1 in a way that can
 * break something:
 *
 *  - a body arrives in frames that are nine bytes apart, so what the message
 *    MEANS is interleaved with how it is written;
 *  - two requests are being read at once, so state that belongs to a message
 *    cannot live in the connection;
 *  - a response is bounded by windows the peer controls, so an answer that does
 *    not fit has to wait rather than be truncated or refused;
 *  - and every byte the peer spent window on has to be given back, including
 *    the ones nobody will ever read.
 *
 * \~spanish
 * La que dice si la afirmacion central del proyecto es cierta.  El manejador de
 * este fichero dice un estado, unas cabeceras y un cuerpo, y no dice nada mas --
 * ni tramas, ni flujos, ni ventanas --.  Si contesta HTTP/2 correctamente sin
 * nombrar ninguna de esas cosas, entonces un manejador es de verdad ciego a la
 * version; si no puede, el corte entre semantica y sintaxis estaba en el sitio
 * equivocado y todo lo que hay encima esta escrito contra una mentira.
 *
 * Los casos son aquellos donde HTTP/2 difiere de HTTP/1.1 de una forma que puede
 * romper algo:
 *
 *  - un cuerpo llega en tramas separadas por nueve bytes, asi que lo que el
 *    mensaje SIGNIFICA va intercalado con como esta escrito;
 *  - se estan leyendo dos peticiones a la vez, asi que el estado que es de un
 *    mensaje no puede vivir en la conexion;
 *  - una respuesta la acotan unas ventanas que controla el otro extremo, asi que
 *    una que no quepa tiene que esperar en vez de truncarse o rechazarse;
 *  - y todos los bytes por los que el otro extremo gasto ventana hay que
 *    devolverselos, incluidos los que no va a leer nadie.
 *
 * \~
 */

#include "http_vx/h2_hpack.h"
#include "http_vx/h2_huffman.h"
#include "http_vx/http2_service.h"
#include "http_vx/memory_backend.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Buffer;
using http_vx::ConnHandle;
using http_vx::Handler;
using http_vx::Http2Service;
using http_vx::MemoryBackend;
using http_vx::Request;
using http_vx::Shard;
using http_vx::ShardConfig;

using http_vx::h2::ErrorCode;
using http_vx::h2::FrameType;
using http_vx::h2::kEndHeaders;
using http_vx::h2::kEndStream;
using http_vx::h2::kFrameHeaderSize;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/* ------------------------------------------------------------------------- *
 * \~english What a client puts on the wire.
 * \~spanish Lo que pone un cliente en el cable.
 * \~
 * ------------------------------------------------------------------------- */

/**
 * @brief
 * \~english Bytes being built, frame by frame.
 * \~spanish Bytes que se van construyendo, trama a trama.
 * \~
 */
struct Wire {
    uint8_t b[16384] = {};
    size_t n = 0;

    void raw(const void *p, size_t len) {
        std::memcpy(b + n, p, len);
        n += len;
    }

    void text(const char *s) { raw(s, std::strlen(s)); }

    void frame(FrameType type, uint8_t flags, uint32_t id, const uint8_t *p,
               size_t len) {
        b[n++] = static_cast<uint8_t>((len >> 16) & 0xFF);
        b[n++] = static_cast<uint8_t>((len >> 8) & 0xFF);
        b[n++] = static_cast<uint8_t>(len & 0xFF);
        b[n++] = static_cast<uint8_t>(type);
        b[n++] = flags;
        b[n++] = static_cast<uint8_t>((id >> 24) & 0x7F);
        b[n++] = static_cast<uint8_t>((id >> 16) & 0xFF);
        b[n++] = static_cast<uint8_t>((id >> 8) & 0xFF);
        b[n++] = static_cast<uint8_t>(id & 0xFF);

        if (len != 0) raw(p, len);
    }
};

/**
 * @brief
 * \~english Writes one field as a literal nobody is to remember.
 * \~spanish Escribe una cabecera como un literal que nadie debe recordar.
 * \~
 *
 * \~english
 * Written out in full rather than indexed, and not Huffman coded, so that what
 * these tests send is readable in a hex dump and does not depend on the tables
 * being right.  A test that built its input with the code under test would pass
 * whenever the two were wrong in the same way.
 *
 * \~spanish
 * Escrita entera en vez de indexada, y sin codificar en Huffman, para que lo que
 * mandan estas pruebas se lea en un volcado hexadecimal y no dependa de que las
 * tablas esten bien.  Una prueba que construyera su entrada con el codigo que
 * prueba pasaria siempre que los dos estuvieran mal de la misma forma.
 * \~
 */
void field(uint8_t *at, size_t &n, const char *name, const char *value) {
    const size_t nlen = std::strlen(name);
    const size_t vlen = std::strlen(value);

    at[n++] = 0x00;
    at[n++] = static_cast<uint8_t>(nlen);
    std::memcpy(at + n, name, nlen);
    n += nlen;
    at[n++] = static_cast<uint8_t>(vlen);
    std::memcpy(at + n, value, vlen);
    n += vlen;
}

/**
 * @brief
 * \~english A whole request head, as a header block.
 * \~spanish Una cabeza de peticion entera, como bloque de cabeceras.
 * \~
 */
size_t request_block(uint8_t *at, const char *method, const char *path) {
    size_t n = 0;
    field(at, n, ":method", method);
    field(at, n, ":scheme", "http");
    field(at, n, ":authority", "example.com");
    field(at, n, ":path", path);
    return n;
}

/* ------------------------------------------------------------------------- *
 * \~english What came back, read as frames.
 * \~spanish Lo que volvio, leido como tramas.
 * \~
 * ------------------------------------------------------------------------- */

/**
 * @brief
 * \~english Walks the answer and counts what it finds.
 * \~spanish Recorre la respuesta y cuenta lo que encuentra.
 * \~
 */
struct Seen {
    size_t frames = 0;
    size_t headers_on[8] = {};
    size_t data_bytes_on[8] = {};
    size_t resets_on[8] = {};
    uint32_t reset_code_on[8] = {};
    /// \~english Window given back on the connection, and on each stream.
    /// \~spanish Ventana devuelta en la conexion, y en cada flujo.  \~
    size_t window_given = 0;
    size_t window_on[8] = {};
    bool ended_on[8] = {};
    bool goaway = false;

    /// \~english The first header block of each stream, as it went out.
    /// \~spanish El primer bloque de cabeceras de cada flujo, tal como salio.  \~
    uint8_t block_on[8][512] = {};
    size_t block_len_on[8] = {};

    void read(const uint8_t *p, size_t n) {
        size_t at = 0;

        while (at + kFrameHeaderSize <= n) {
            const size_t len = (static_cast<size_t>(p[at]) << 16) |
                               (static_cast<size_t>(p[at + 1]) << 8) |
                               static_cast<size_t>(p[at + 2]);
            const uint8_t type = p[at + 3];
            const uint8_t flags = p[at + 4];
            const uint32_t id =
                (static_cast<uint32_t>(p[at + 5] & 0x7F) << 24) |
                (static_cast<uint32_t>(p[at + 6]) << 16) |
                (static_cast<uint32_t>(p[at + 7]) << 8) |
                static_cast<uint32_t>(p[at + 8]);

            if (at + kFrameHeaderSize + len > n) break;

            const uint8_t *payload = p + at + kFrameHeaderSize;
            const size_t slot = id < 8 ? id : 0;

            ++frames;

            switch (static_cast<FrameType>(type)) {
            case FrameType::Headers:
                if (headers_on[slot] == 0 && len <= sizeof block_on[slot]) {
                    std::memcpy(block_on[slot], payload, len);
                    block_len_on[slot] = len;
                }
                ++headers_on[slot];
                if ((flags & kEndStream) != 0) ended_on[slot] = true;
                break;

            case FrameType::Data:
                data_bytes_on[slot] += len;
                if ((flags & kEndStream) != 0) ended_on[slot] = true;
                break;

            case FrameType::RstStream:
                ++resets_on[slot];
                reset_code_on[slot] = (static_cast<uint32_t>(payload[0]) << 24) |
                                      (static_cast<uint32_t>(payload[1]) << 16) |
                                      (static_cast<uint32_t>(payload[2]) << 8) |
                                      static_cast<uint32_t>(payload[3]);
                break;

            case FrameType::WindowUpdate: {
                const size_t k = (static_cast<size_t>(payload[0] & 0x7F) << 24) |
                                 (static_cast<size_t>(payload[1]) << 16) |
                                 (static_cast<size_t>(payload[2]) << 8) |
                                 static_cast<size_t>(payload[3]);
                if (id == 0)
                    window_given += k;
                else
                    window_on[slot] += k;
                break;
            }

            case FrameType::Goaway:
                goaway = true;
                break;

            default:
                break;
            }

            at += kFrameHeaderSize + len;
        }
    }
};

/**
 * @brief
 * \~english The field lines of a response header block, read back.
 * \~spanish Las lineas de campo de un bloque de cabeceras de respuesta, leidas de vuelta.
 * \~
 *
 * \~english
 * Only what this server writes: indexed fields of the static table and
 * literals whose name is a static index or a string.  Anything else -- the
 * dynamic table, a size update -- makes the read fail, which a test reports:
 * a reader that skipped what it did not know would agree with any block.
 * @c never marks the lines sent as never indexed (RFC 7541, 6.2.3).
 *
 * \~spanish
 * Solo lo que escribe este servidor: cabeceras indexadas de la tabla estatica y
 * literales cuyo nombre es un indice estatico o una cadena.  Cualquier otra cosa
 * -- la tabla dinamica, una actualizacion de tamano -- hace fallar la lectura,
 * que la prueba cuenta: un lector que se saltara lo que no conoce le daria la
 * razon a cualquier bloque.  @c never marca las lineas mandadas como no
 * indexables nunca (RFC 7541, 6.2.3).
 * \~
 */
struct Lines {
    char name[16][64] = {};
    char value[16][128] = {};
    bool never[16] = {};
    size_t count = 0;
    bool ok = false;

    /// \~english The value of @p n, or null.  \~spanish El valor de @p n, o nulo.  \~
    const char *of(const char *n) const {
        for (size_t i = 0; i < count; ++i)
            if (std::strcmp(name[i], n) == 0) return value[i];
        return nullptr;
    }

    /// \~english Whether the line called @p n was sent as never indexed.
    /// \~spanish Si la linea llamada @p n se mando como no indexable nunca.  \~
    bool never_of(const char *n) const {
        for (size_t i = 0; i < count; ++i)
            if (std::strcmp(name[i], n) == 0) return never[i];
        return false;
    }

    /// \~english How many lines are called @p n.  \~spanish Cuantas lineas se llaman @p n.  \~
    size_t how_many(const char *n) const {
        size_t k = 0;
        for (size_t i = 0; i < count; ++i)
            if (std::strcmp(name[i], n) == 0) ++k;
        return k;
    }
};

/// \~english Reads one string literal at @p at into @p out.  \~spanish Lee una cadena literal en @p at a @p out.  \~
bool read_string(const uint8_t *p, size_t n, size_t &at, char *out, size_t cap) {
    if (at >= n) return false;
    const bool huffman = (p[at] & 0x80) != 0;
    const http_vx::h2::hpack::IntResult len = http_vx::h2::hpack::decode_int(p + at, n - at, 7);
    if (len.status != http_vx::h2::hpack::Status::Ok) return false;
    at += len.used;
    if (len.value > n - at) return false;

    size_t got = static_cast<size_t>(len.value);
    if (huffman) {
        uint8_t tmp[256];
        const http_vx::h2::hpack::HuffmanResult h =
            http_vx::h2::hpack::huffman_decode(tmp, sizeof tmp, p + at, got);
        if (h.status != http_vx::h2::hpack::Status::Ok || h.len >= cap) return false;
        std::memcpy(out, tmp, h.len);
        out[h.len] = '\0';
    } else {
        if (got >= cap) return false;
        std::memcpy(out, p + at, got);
        out[got] = '\0';
    }
    at += static_cast<size_t>(len.value);
    return true;
}

/// \~english Copies a static entry's name, or value, into @p out.  \~spanish Copia el nombre, o el valor, de una entrada estatica a @p out.  \~
bool static_text(const char *s, size_t len, char *out, size_t cap) {
    if (s == nullptr || len >= cap) return false;
    std::memcpy(out, s, len);
    out[len] = '\0';
    return true;
}

/// \~english Reads the block sent on @p stream.  \~spanish Lee el bloque mandado en @p stream.  \~
Lines lines_of(const Seen &seen, size_t stream) {
    Lines l;
    const uint8_t *p = seen.block_on[stream];
    const size_t n = seen.block_len_on[stream];
    size_t at = 0;

    while (at < n) {
        if (l.count == 16) return l;
        const uint8_t lead = p[at];
        const size_t i = l.count;

        if ((lead & 0x80) != 0) {
            const http_vx::h2::hpack::IntResult idx = http_vx::h2::hpack::decode_int(p + at, n - at, 7);
            if (idx.status != http_vx::h2::hpack::Status::Ok) return l;
            at += idx.used;
            const http_vx::h2::hpack::StaticEntry *e = http_vx::h2::hpack::static_entry(idx.value);
            if (e == nullptr || !static_text(e->name, e->name_len, l.name[i], sizeof l.name[i]) ||
                !static_text(e->value, e->value_len, l.value[i], sizeof l.value[i]))
                return l;
            ++l.count;
            continue;
        }

        // \~english Only the two literals that add nothing to a table.  \~spanish Solo los dos literales que no anaden nada a una tabla.  \~
        if ((lead & 0xE0) != 0x00) return l;
        l.never[i] = (lead & 0x10) != 0;

        const http_vx::h2::hpack::IntResult idx = http_vx::h2::hpack::decode_int(p + at, n - at, 4);
        if (idx.status != http_vx::h2::hpack::Status::Ok) return l;
        at += idx.used;

        if (idx.value != 0) {
            const http_vx::h2::hpack::StaticEntry *e = http_vx::h2::hpack::static_entry(idx.value);
            if (e == nullptr || !static_text(e->name, e->name_len, l.name[i], sizeof l.name[i])) return l;
        } else if (!read_string(p, n, at, l.name[i], sizeof l.name[i])) {
            return l;
        }
        if (!read_string(p, n, at, l.value[i], sizeof l.value[i])) return l;
        ++l.count;
    }

    l.ok = true;
    return l;
}

/* ------------------------------------------------------------------------- *
 * \~english The server, made of all of it.
 * \~spanish El servidor, hecho de todo ello.
 * \~
 * ------------------------------------------------------------------------- */

/**
 * @brief
 * \~english A handler that names no version, because there is none to name.
 * \~spanish Un manejador que no nombra ninguna version, porque no hay ninguna que nombrar.
 * \~
 */
class Echo final : public Handler {
  public:
    void handle(const Request &req, const uint8_t *head, const uint8_t *body,
                size_t n, http_vx::ResponseBuilder &res) noexcept override {
        ++calls;
        last_body_size = n;

        if (n != 0 && n < sizeof last_body) {
            std::memcpy(last_body, body, n);
            last_body[n] = '\0';
        } else {
            last_body[0] = '\0';
        }

        if (req.target.len < sizeof last_target) {
            std::memcpy(last_target, head + req.target.off, req.target.len);
            last_target[req.target.len] = '\0';
        }

        // \~english The last field, spelled out, over the base the handler was given.
        // \~spanish La ultima cabecera, escrita entera, sobre la base que se le dio al manejador.  \~
        last_fields = req.fields.size();
        last_field[0] = '\0';
        if (!req.fields.empty()) {
            const http_vx::Field &f = req.fields.end()[-1];
            if (static_cast<size_t>(f.name_len) + f.value_len + 2 < sizeof last_field) {
                std::memcpy(last_field, head + f.name_off, f.name_len);
                last_field[f.name_len] = '=';
                std::memcpy(last_field + f.name_len + 1, head + f.value_off, f.value_len);
                last_field[f.name_len + 1 + f.value_len] = '\0';
            }
        }

        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        for (size_t i = 0; i < extras; ++i)
            res.field(extra_name[i], std::strlen(extra_name[i]), extra_value[i], std::strlen(extra_value[i]));
        if (reply_size != 0) res.body(reply, reply_size);
        // \~english A field after the body: the builder refuses it and says it failed.
        // \~spanish Una cabecera despues del cuerpo: el constructor la rechaza y dice que fallo.  \~
        if (field_after_body) res.field(http_vx::FieldId::Server, "late", 4);
    }

    /// \~english Whether to write a field after the body, which fails the answer.
    /// \~spanish Si escribir una cabecera despues del cuerpo, que hace fallar la respuesta.  \~
    bool field_after_body = false;

    /// \~english Fields added to every answer, spelled as a handler would.
    /// \~spanish Cabeceras anadidas a cada respuesta, escritas como lo haria un manejador.  \~
    const char *extra_name[4] = {};
    const char *extra_value[4] = {};
    size_t extras = 0;

    int calls = 0;
    size_t last_body_size = 0;
    char last_body[4096] = {};
    char last_target[256] = {};
    size_t last_fields = 0;
    char last_field[256] = {};

    char reply[4096] = {};
    size_t reply_size = 0;
};

/**
 * @brief
 * \~english A server with nothing standing in for anything.
 * \~spanish Un servidor sin nada que sustituya a nada.
 * \~
 */
struct Server {
    Echo handler;
    Http2Service service;
    Shard shard;
    MemoryBackend io;

    Server() : io(shard.buffers()) {}

    bool start(size_t max_body = 4096, uint32_t max_header_list = 0) {
        http_vx::h2::Limits limits;
        if (max_header_list != 0) limits.max_header_list_size = max_header_list;
        if (!service.reset(8, 4, max_body, handler, limits)) return false;

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.idle_ticks = 10;
        cfg.wheel_slots = 64;
        return shard.reset(cfg, io, service, 0);
    }

    void send(const Wire &w) { io.feed(w.b, w.n); }

    void run() {
        for (int i = 0; i < 64; ++i) shard.poll(1, 0);
    }

    Seen seen() const {
        Seen s;
        s.read(io.written(), io.written_size());
        return s;
    }
};

/// \~english The preface and an empty SETTINGS, which every client sends.
/// \~spanish El preambulo y un SETTINGS vacio, que manda todo cliente.  \~
void hello(Wire &w) {
    w.text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    w.frame(FrameType::Settings, 0, 0, nullptr, 0);
}

/* ------------------------------------------------------------------------- *
 * \~english The cases.
 * \~spanish Los casos.
 * \~
 * ------------------------------------------------------------------------- */

/**
 * @brief
 * \~english One request in, one response out.
 * \~spanish Entra una peticion, sale una respuesta.
 * \~
 */
void test_a_request_is_answered() {
    Server s;
    check(s.start(), "the server would not start");
    std::memcpy(s.handler.reply, "hello", 5);
    s.handler.reply_size = 5;

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    const size_t n = request_block(block, "GET", "/hello");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, block, n);

    s.send(w);
    s.run();

    check(s.handler.calls == 1, "the handler was not called");
    check(std::strcmp(s.handler.last_target, "/hello") == 0,
          "the handler was given the wrong target");
    check(s.service.served() == 1, "the service did not count the request");

    const Seen got = s.seen();
    check(got.headers_on[1] == 1, "the response head did not go out");
    check(got.data_bytes_on[1] == 5, "the response body did not go out whole");
    check(got.ended_on[1], "the response never ended the stream");
    check(!got.goaway, "the connection was given up on");
    check(s.service.in_hand() == 0, "the request was never let go of");
}

/**
 * @brief
 * \~english A body that arrived in one frame reaches the handler as it lies.
 * \~spanish Un cuerpo que llego en una trama le llega al manejador tal cual.
 * \~
 */
void test_a_body_in_one_frame() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    const size_t n = request_block(block, "POST", "/upload");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);
    w.frame(FrameType::Data, kEndStream,
            1, reinterpret_cast<const uint8_t *>("body bytes"), 10);

    s.send(w);
    s.run();

    check(s.handler.calls == 1, "the handler was not called");
    check(s.handler.last_body_size == 10, "the body was the wrong length");
    check(std::strcmp(s.handler.last_body, "body bytes") == 0,
          "the body was not what was sent");
    check(std::strcmp(s.handler.last_target, "/upload") == 0,
          "the target was lost between the head and the body");
    check(s.service.in_hand() == 0, "the request was never let go of");

    /* \~english
     * The window goes back after the handler, and by then the answer has
     * closed the stream: only the connection's may be given, because "an
     * endpoint MUST NOT send frames other than PRIORITY on a closed stream"
     * (RFC 9113, 5.1).
     * \~spanish
     * La ventana vuelve despues del manejador, y para entonces la respuesta ha
     * cerrado el flujo: solo se puede dar la de la conexion, porque "an
     * endpoint MUST NOT send frames other than PRIORITY on a closed stream"
     * (RFC 9113, 5.1).
     * \~ */
    const Seen got = s.seen();
    check(got.window_given >= 10, "the connection's window for the body never went back");
    check(got.window_on[1] == 0, "a WINDOW_UPDATE went out on a closed stream (RFC 9113, 5.1)");
}

/**
 * @brief
 * \~english A body split over frames is joined before the handler sees it.
 * \~spanish Un cuerpo partido en tramas se junta antes de que lo vea el manejador.
 * \~
 *
 * \~english
 * The pieces are nine bytes of framing apart on the wire, so a service that
 * handed over what it read would hand over a body with frame headers inside it.
 * \~spanish
 * Los pedazos estan a nueve bytes de troceado unos de otros en el cable, asi que
 * un servicio que entregara lo que leyo entregaria un cuerpo con cabeceras de
 * trama dentro.
 * \~
 */
void test_a_body_in_pieces_is_joined() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    const size_t n = request_block(block, "POST", "/upload");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);
    w.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("one"), 3);
    w.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("two"), 3);
    w.frame(FrameType::Data, kEndStream, 1,
            reinterpret_cast<const uint8_t *>("three"), 5);

    s.send(w);
    s.run();

    check(s.handler.calls == 1, "the handler was not called");
    check(s.handler.last_body_size == 11, "the body was the wrong length");
    check(std::strcmp(s.handler.last_body, "onetwothree") == 0,
          "the pieces were not joined, or the framing came with them");

    const Seen got = s.seen();
    check(got.window_given >= 11,
          "the window for the body that was read never went back");
}

/**
 * @brief
 * \~english Two requests at once, and neither becomes the other.
 * \~spanish Dos peticiones a la vez, y ninguna se convierte en la otra.
 * \~
 *
 * \~english
 * The case HTTP/1.1 does not have, and the one that decides where the state of
 * a message may live.  Stream 1 is waiting for its body when stream 3's head
 * arrives, so a service that kept the decoded request in the CONNECTION would
 * answer stream 1 with stream 3's target -- and it would do it silently, on a
 * connection that goes on working.
 *
 * The body of stream 1 is sent in two frames with ANOTHER head between them,
 * which is what makes this cover both shapes a body can have: a body that
 * arrives whole is handed over where it lies, and one that is split is joined
 * somewhere, and those are two different pieces of code that both have to keep
 * hold of the right request.  A first version of this sent the body in one
 * frame, and the state-in-the-connection mistake was injected into the joining
 * path and the test went on passing -- which is a test agreeing with a bug
 * because it never went that way.
 *
 * \~spanish
 * El caso que HTTP/1.1 no tiene, y el que decide donde puede vivir el estado de
 * un mensaje.  El flujo 1 esta esperando su cuerpo cuando llega la cabeza del
 * flujo 3, asi que un servicio que guardara la peticion descodificada en la
 * CONEXION contestaria al flujo 1 con el destino del flujo 3 -- y lo haria en
 * silencio, en una conexion que sigue funcionando.
 *
 * El cuerpo del flujo 1 se manda en dos tramas con OTRA cabeza en medio, que es
 * lo que hace que esto cubra las dos formas que puede tener un cuerpo: uno que
 * llega entero se entrega donde esta, y uno partido se junta en algun sitio, y
 * esos son dos trozos de codigo distintos que los dos tienen que seguir
 * agarrando la peticion correcta.  Una primera version de esto mandaba el cuerpo
 * en una trama, y la equivocacion de guardar el estado en la conexion se inyecto
 * en el camino de juntar y la prueba siguio pasando -- que es una prueba dandole
 * la razon a un fallo porque no paso nunca por ahi.
 * \~
 */
void test_two_requests_at_once() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t one[256];
    const size_t n1 = request_block(one, "POST", "/first");
    w.frame(FrameType::Headers, kEndHeaders, 1, one, n1);

    uint8_t three[256];
    const size_t n3 = request_block(three, "GET", "/second");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 3, three, n3);

    w.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("mi"), 2);

    uint8_t five[256];
    const size_t n5 = request_block(five, "GET", "/third");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 5, five, n5);

    w.frame(FrameType::Data, kEndStream, 1,
            reinterpret_cast<const uint8_t *>("ne"), 2);

    s.send(w);
    s.run();

    check(s.handler.calls == 3, "the three requests were not answered");
    check(std::strcmp(s.handler.last_target, "/first") == 0,
          "the request waiting for its body was overwritten by a later head");
    check(std::strcmp(s.handler.last_body, "mine") == 0,
          "the body did not reach the request it belonged to, or lost a piece");

    const Seen got = s.seen();
    check(got.headers_on[1] == 1, "stream 1 was not answered");
    check(got.headers_on[3] == 1, "stream 3 was not answered");
    check(got.headers_on[5] == 1, "stream 5 was not answered");
    check(got.ended_on[1] && got.ended_on[3] && got.ended_on[5],
          "a stream was left open");
    check(s.service.in_hand() == 0, "a request was never let go of");
}

/**
 * @brief
 * \~english An answer that does not fit waits, and is not cut short.
 * \~spanish Una respuesta que no cabe espera, y no se corta.
 * \~
 *
 * \~english
 * The peer says it will hold ten bytes of any stream, and the answer is forty.
 * Ten go out and thirty wait; a WINDOW_UPDATE later, the thirty follow.  The
 * two mistakes this catches are the loud one -- truncating the response -- and
 * the quiet one, which is answering anyway and letting the peer decide what to
 * do with bytes it said it could not hold.
 *
 * \~spanish
 * El otro extremo dice que guardara diez bytes de cualquier flujo, y la
 * respuesta son cuarenta.  Salen diez y esperan treinta; un WINDOW_UPDATE
 * despues, los treinta van detras.  Las dos equivocaciones que esto coge son la
 * ruidosa -- truncar la respuesta -- y la silenciosa, que es contestar igual y
 * dejar que el otro extremo decida que hacer con unos bytes que dijo que no
 * podia guardar.
 * \~
 */
void test_an_answer_waits_for_a_window() {
    Server s;
    check(s.start(), "the server would not start");

    std::memset(s.handler.reply, 'x', 40);
    s.handler.reply_size = 40;

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    w.text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    /* \~english
     * SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 10.  It is announced before the
     * request, so the stream is opened with it -- a setting that arrived later
     * would move the window of a stream already open, which is a different
     * path.
     * \~spanish
     * SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 10.  Se anuncia antes de la peticion,
     * asi que el flujo se abre con ella -- un ajuste que llegara despues moveria
     * la ventana de un flujo ya abierto, que es otro camino.
     * \~ */
    const uint8_t small[6] = {0x00, 0x04, 0x00, 0x00, 0x00, 0x0A};
    w.frame(FrameType::Settings, 0, 0, small, sizeof small);

    uint8_t block[256];
    const size_t n = request_block(block, "GET", "/big");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, block, n);

    s.send(w);
    s.run();

    Seen got = s.seen();
    check(got.headers_on[1] == 1, "the response head did not go out");
    check(got.data_bytes_on[1] == 10,
          "the response did not stop at the window the peer offered");
    check(!got.ended_on[1], "a response that is not finished said it was");
    check(s.service.in_hand() == 1, "the rest of the answer was not kept");

    /* \~english
     * And now the peer makes room, on the stream and on the connection: the
     * two are counted separately and an answer that waited on one is not
     * released by the other.
     * \~spanish
     * Y ahora el otro extremo hace sitio, en el flujo y en la conexion: se
     * cuentan por separado y una respuesta que esperaba a una no la suelta la
     * otra.
     * \~ */
    Wire more;
    const uint8_t plus[4] = {0x00, 0x00, 0x00, 0x40};
    more.frame(FrameType::WindowUpdate, 0, 1, plus, sizeof plus);
    more.frame(FrameType::WindowUpdate, 0, 0, plus, sizeof plus);

    s.send(more);
    s.run();

    got = s.seen();
    check(got.data_bytes_on[1] == 40,
          "the rest of the answer did not follow the window");
    check(got.ended_on[1], "the finished response never said so");
    check(s.service.in_hand() == 0, "the request was never let go of");
    check(s.handler.calls == 1, "the handler was asked twice for one answer");
}

/**
 * @brief
 * \~english A body larger than this server takes is refused, not read.
 * \~spanish Un cuerpo mayor de lo que acepta este servidor se rechaza, no se lee.
 * \~
 */
void test_a_body_too_large_is_refused() {
    Server s;
    check(s.start(16), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    const size_t n = request_block(block, "POST", "/upload");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);

    uint8_t big[64];
    std::memset(big, 'z', sizeof big);
    w.frame(FrameType::Data, 0, 1, big, sizeof big);

    s.send(w);
    s.run();

    check(s.handler.calls == 0, "a body over the limit reached the handler");

    const Seen got = s.seen();
    check(got.headers_on[1] == 1, "the refusal was not answered");
    check(got.resets_on[1] == 1,
          "the peer was not told to stop sending the body");
    check(got.window_given >= sizeof big,
          "the window of the refused body never went back");
    check(!got.goaway, "one refused upload ended the whole connection");
    check(s.service.in_hand() == 0, "the refused request was never let go of");
}

/**
 * @brief
 * \~english The padding of a frame gives its window back.
 * \~spanish El relleno de una trama devuelve su ventana.
 * \~
 *
 * \~english
 * Padding is charged to both windows by the peer and stripped by the reader, so
 * nobody upstream ever learns those bytes existed.  A server that did not
 * credit them would lose a little allowance on every padded frame and stop for
 * good after enough of them -- with nothing to point at, because every frame
 * involved was perfectly legal.
 *
 * \~spanish
 * El relleno se lo cobran las dos ventanas al otro extremo y lo quita el lector,
 * asi que nadie de mas arriba llega a enterarse de que esos bytes existieran.  Un
 * servidor que no los abonara perderia un poco de credito en cada trama
 * rellenada y se pararia para siempre despues de bastantes -- sin nada a lo que
 * senalar, porque todas las tramas de por medio eran perfectamente legales.
 * \~
 */
void test_padding_gives_its_window_back() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    const size_t n = request_block(block, "POST", "/upload");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);

    /* \~english
     * One byte saying how much padding there is, four bytes of body, and eleven
     * of padding: sixteen bytes of payload of which four mean anything.
     * \~spanish
     * Un byte diciendo cuanto relleno hay, cuatro bytes de cuerpo y once de
     * relleno: dieciseis bytes de carga de los que cuatro significan algo.
     * \~ */
    uint8_t padded[16] = {};
    padded[0] = 11;
    std::memcpy(padded + 1, "four", 4);

    w.frame(FrameType::Data, kEndStream | 0x08, 1, padded, sizeof padded);

    s.send(w);
    s.run();

    check(s.handler.calls == 1, "the handler was not called");
    check(s.handler.last_body_size == 4,
          "the padding was handed over as if it were body");

    const Seen got = s.seen();
    check(got.window_given >= 16,
          "the window the padding cost never went back");
    check(!got.goaway, "a padded frame ended the connection");
}

/**
 * @brief
 * \~english Trailers reach the handler with the head, and the body is still the body (RFC 9113, 8.1).
 * \~spanish Los remolques llegan al manejador con la cabecera, y el cuerpo sigue siendo el cuerpo (RFC 9113, 8.1).
 * \~
 */
void test_trailers_reach_the_handler() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    size_t n = request_block(block, "POST", "/upload");
    field(block, n, "content-length", "6");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);
    w.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("pie"), 3);

    /* \~english
     * A GET in between, answered where it stands: the trailers that follow
     * must not pick up its fields from the decoding slot.
     * \~spanish
     * Un GET en medio, contestado donde esta: los remolques que siguen no
     * pueden llevarse sus cabeceras de la ranura de descodificacion.
     * \~ */
    uint8_t get[256];
    size_t g = request_block(get, "GET", "/other");
    field(get, g, "x-other", "no");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 3, get, g);

    w.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("ces"), 3);

    uint8_t tail[64];
    size_t t = 0;
    field(tail, t, "x-sum", "42");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, tail, t);

    s.send(w);
    s.run();

    check(s.handler.calls == 2, "the request with trailers was not answered");
    check(std::strcmp(s.handler.last_target, "/upload") == 0, "the trailers were given to the wrong request");
    check(std::strcmp(s.handler.last_body, "pieces") == 0, "the trailers changed the body");
    check(s.handler.last_body_size == 6, "the trailer bytes were counted as body");
    check(s.handler.last_fields == 2, "the request did not carry its head and its trailers, and nothing else");
    check(std::strcmp(s.handler.last_field, "x-sum=42") == 0, "the trailer did not reach the handler");

    const Seen got = s.seen();
    check(got.headers_on[1] == 1 && got.ended_on[1], "the request with trailers was not answered");
    check(got.resets_on[1] == 0, "a request with trailers was reset");
    check(!got.goaway, "trailers ended the connection");
    check(s.service.in_hand() == 0, "the request with trailers was never let go of");
}

/**
 * @brief
 * \~english A body that does not match its content-length never reaches the handler (RFC 9113, 8.1.1).
 * \~spanish Un cuerpo que no coincide con su content-length no llega nunca al manejador (RFC 9113, 8.1.1).
 * \~
 */
void test_a_content_length_that_lies_is_refused() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);

    uint8_t block[256];
    size_t n = request_block(block, "POST", "/short");
    field(block, n, "content-length", "10");
    w.frame(FrameType::Headers, kEndHeaders, 1, block, n);
    w.frame(FrameType::Data, kEndStream, 1, reinterpret_cast<const uint8_t *>("four"), 4);

    n = request_block(block, "POST", "/long");
    field(block, n, "content-length", "2");
    w.frame(FrameType::Headers, kEndHeaders, 3, block, n);
    w.frame(FrameType::Data, 0, 3, reinterpret_cast<const uint8_t *>("four"), 4);

    n = request_block(block, "POST", "/exact");
    field(block, n, "content-length", "4");
    w.frame(FrameType::Headers, kEndHeaders, 5, block, n);
    w.frame(FrameType::Data, kEndStream, 5, reinterpret_cast<const uint8_t *>("four"), 4);

    s.send(w);
    s.run();

    check(s.handler.calls == 1, "a body that did not match its content-length reached the handler");
    check(std::strcmp(s.handler.last_target, "/exact") == 0, "the exact body was not the one answered");

    const Seen got = s.seen();
    check(got.resets_on[1] == 1, "too little DATA was not reset");
    check(got.resets_on[3] == 1, "too much DATA was not reset");
    check(got.headers_on[1] == 0 && got.headers_on[3] == 0, "a malformed request was answered");
    check(!got.goaway, "a malformed request ended the connection");
    check(got.window_given >= 12, "the window of the refused bodies never went back");
    check(s.service.in_hand() == 0, "a refused request was never let go of");
}

/// \~english A server, a connection and one GET for @p path on stream 1.
/// \~spanish Un servidor, una conexion y un GET de @p path en el flujo 1.  \~
void one_request(Server &s, const char *method, const char *path) {
    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);
    uint8_t block[256];
    const size_t n = request_block(block, method, path);
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, block, n);
    s.send(w);
    s.run();
}

/**
 * @brief
 * \~english A handler's field names go out in lower case, and secrets are never indexed (RFC 9113, 8.2; RFC 7541, 7.1.3).
 * \~spanish Los nombres de cabecera de un manejador salen en minusculas, y los secretos no se indexan nunca (RFC 9113, 8.2; RFC 7541, 7.1.3).
 * \~
 *
 * \~english
 * The handler spells `X-Request-Id` as HTTP/1.1 lets it; HTTP/2 says the name
 * MUST be lowered, and a peer that reads a capital treats the response as
 * malformed.  `Set-Cookie` is one of the fields that must never be remembered
 * by anybody on the way, so it travels as never indexed.
 * \~spanish
 * El manejador escribe `X-Request-Id` como le deja HTTP/1.1; HTTP/2 dice que el
 * nombre DEBE bajarse a minusculas, y un extremo que lee una mayuscula trata la
 * respuesta como mal formada.  `Set-Cookie` es de las cabeceras que no debe
 * recordar nadie del camino, asi que viaja como no indexable nunca.
 * \~
 */
void test_field_names_go_out_in_lower_case() {
    Server s;
    check(s.start(), "the server would not start");
    s.handler.extra_name[0] = "X-Request-Id";
    s.handler.extra_value[0] = "abc";
    s.handler.extra_name[1] = "Set-Cookie";
    s.handler.extra_value[1] = "id=1";
    s.handler.extras = 2;

    one_request(s, "GET", "/");

    const Seen got = s.seen();
    const Lines l = lines_of(got, 1);
    check(l.ok, "the response header block could not be read back");
    check(l.of(":status") != nullptr && std::strcmp(l.of(":status"), "200") == 0, "the answer was not a 200");
    check(l.of("x-request-id") != nullptr && std::strcmp(l.of("x-request-id"), "abc") == 0,
          "an upper-case field name was not lowered (RFC 9113, 8.2)");
    check(l.how_many("X-Request-Id") == 0, "a field name went out with capitals (RFC 9113, 8.2)");
    check(l.of("content-type") != nullptr, "a known field was lost");
    check(l.of("set-cookie") != nullptr && std::strcmp(l.of("set-cookie"), "id=1") == 0,
          "a set-cookie was lost");
    check(l.never_of("set-cookie"), "a set-cookie was not sent as never indexed (RFC 7541, 7.1.3)");
    check(!l.never_of("x-request-id"), "an ordinary field was sent as a secret");
    check(s.service.bad_answers() == 0, "a good answer was counted as bad");
}

/**
 * @brief
 * \~english An answer HTTP/2 cannot carry as written is a 500, counted -- never a changed answer (RFC 9113, 8.2.1, 8.2.2).
 * \~spanish Una respuesta que HTTP/2 no puede llevar tal como se escribio es un 500, contado -- nunca una respuesta cambiada (RFC 9113, 8.2.1, 8.2.2).
 * \~
 */
void test_an_answer_that_cannot_travel_is_a_500() {
    const char *names[] = {"Connection", "Transfer-Encoding", "Keep-Alive", "Upgrade", "Proxy-Connection",
                           "x-bad", "x-edge", "bad name", "x:colon"};
    const char *values[] = {"close", "chunked", "5", "h2c", "close", "a\r\nb", " padded", "v", "v"};

    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i) {
        Server s;
        check(s.start(), "the server would not start");
        std::memcpy(s.handler.reply, "hello", 5);
        s.handler.reply_size = 5;
        s.handler.extra_name[0] = names[i];
        s.handler.extra_value[0] = values[i];
        s.handler.extras = 1;

        one_request(s, "GET", "/");

        const Seen got = s.seen();
        const Lines l = lines_of(got, 1);
        char what[160];
        std::snprintf(what, sizeof what, "a response with `%s` was not answered 500", names[i]);
        check(l.ok && l.of(":status") != nullptr && std::strcmp(l.of(":status"), "500") == 0, what);
        std::snprintf(what, sizeof what, "a response with `%s` was not counted as bad", names[i]);
        check(s.service.bad_answers() == 1, what);
        std::snprintf(what, sizeof what, "a response with `%s` was refused without a reason", names[i]);
        check(s.service.last_bad_answer() != nullptr && std::strstr(s.service.last_bad_answer(), "RFC") != nullptr,
              what);
        check(l.count == 1, "the 500 carried the handler's fields");
        check(got.data_bytes_on[1] == 0, "the 500 carried the handler's body");
        check(got.ended_on[1], "the 500 did not end the stream");
        check(got.resets_on[1] == 0, "a stream that was over was reset (RFC 9113, 5.1)");
        check(!got.goaway, "a bad answer ended the connection");
        check(s.service.in_hand() == 0, "the request was never let go of");
    }
}

/**
 * @brief
 * \~english A handler that failed is answered 500, and a stream already over is not reset afterwards (RFC 9113, 5.1).
 * \~spanish A un manejador que fallo se le contesta 500, y un flujo que ya acabo no se reinicia despues (RFC 9113, 5.1).
 * \~
 *
 * \~english
 * The request ended with its HEADERS, so the 500's END_STREAM closes the
 * stream -- and "an endpoint MUST NOT send frames other than PRIORITY on a
 * closed stream".  The RST_STREAM(NO_ERROR) that asks a client to stop
 * uploading is for a request still arriving, and this one is not.
 * \~spanish
 * La peticion acabo con su HEADERS, asi que el END_STREAM del 500 cierra el
 * flujo -- y "an endpoint MUST NOT send frames other than PRIORITY on a closed
 * stream".  El RST_STREAM(NO_ERROR) que le pide a un cliente que deje de subir
 * es para una peticion que sigue llegando, y esta no.
 * \~
 */
void test_a_failed_handler_is_a_500_without_a_reset() {
    Server s;
    check(s.start(), "the server would not start");
    std::memcpy(s.handler.reply, "hello", 5);
    s.handler.reply_size = 5;
    s.handler.field_after_body = true;

    one_request(s, "GET", "/");

    const Seen got = s.seen();
    const Lines l = lines_of(got, 1);
    check(l.ok && l.of(":status") != nullptr && std::strcmp(l.of(":status"), "500") == 0,
          "a handler that failed was not answered 500");
    check(got.ended_on[1], "the 500 did not end the stream");
    check(got.resets_on[1] == 0, "a closed stream was reset after its answer (RFC 9113, 5.1)");
    check(s.service.bad_answers() == 1, "a failed handler was not counted");
    check(s.service.last_bad_answer() != nullptr && std::strstr(s.service.last_bad_answer(), "handler") != nullptr,
          "a failed handler was not said to be the reason");
    check(!got.goaway, "a failed handler ended the connection");
}

/**
 * @brief
 * \~english HEAD gets the fields GET would, and no content (RFC 9110, 9.3.2; RFC 9113, 8.1.1).
 * \~spanish HEAD recibe las cabeceras que recibiria GET, y ningun contenido (RFC 9110, 9.3.2; RFC 9113, 8.1.1).
 * \~
 */
void test_head_sends_no_content() {
    {
        // \~english The length GET would have had.  \~spanish La longitud que habria tenido GET.  \~
        Server s;
        check(s.start(), "the server would not start");
        std::memcpy(s.handler.reply, "hello", 5);
        s.handler.reply_size = 5;

        one_request(s, "HEAD", "/");

        const Seen got = s.seen();
        const Lines l = lines_of(got, 1);
        check(s.handler.calls == 1, "the handler was not asked about a HEAD");
        check(got.headers_on[1] == 1 && got.ended_on[1], "a HEAD was not answered with one ended header block");
        check(got.data_bytes_on[1] == 0, "a HEAD was sent content (RFC 9110, 9.3.2)");
        check(l.ok && l.of("content-length") != nullptr && std::strcmp(l.of("content-length"), "5") == 0,
              "a HEAD did not say the length GET would have had");
        check(l.of("content-type") != nullptr, "a HEAD lost the fields GET would have had");
        check(s.service.in_hand() == 0, "a HEAD was never let go of");
    }
    {
        // \~english The handler's own length is the one that goes, once.  \~spanish La longitud del propio manejador es la que sale, una vez.  \~
        Server s;
        check(s.start(), "the server would not start");
        std::memcpy(s.handler.reply, "hello", 5);
        s.handler.reply_size = 5;
        s.handler.extra_name[0] = "Content-Length";
        s.handler.extra_value[0] = "99";
        s.handler.extras = 1;

        one_request(s, "HEAD", "/");

        const Lines l = lines_of(s.seen(), 1);
        check(l.ok && l.how_many("content-length") == 1 && std::strcmp(l.of("content-length"), "99") == 0,
              "a HEAD's own content-length was replaced or doubled");
    }
    {
        // \~english No content means nothing waits for a window; GET gets no length added.
        // \~spanish Sin contenido no hay nada que espere una ventana; a GET no se le anade longitud.  \~
        Server s;
        check(s.start(), "the server would not start");
        std::memset(s.handler.reply, 'x', 40);
        s.handler.reply_size = 40;

        const ConnHandle c = s.shard.adopt(7, 0);
        check(c.valid(), "the connection was not adopted");
        Wire w;
        w.text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        const uint8_t small[6] = {0x00, 0x04, 0x00, 0x00, 0x00, 0x0A};
        w.frame(FrameType::Settings, 0, 0, small, sizeof small);
        uint8_t block[256];
        size_t n = request_block(block, "HEAD", "/big");
        w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, block, n);
        n = request_block(block, "GET", "/big");
        w.frame(FrameType::Headers, kEndHeaders | kEndStream, 3, block, n);
        s.send(w);
        s.run();

        const Seen got = s.seen();
        const Lines head = lines_of(got, 1);
        check(got.ended_on[1] && got.data_bytes_on[1] == 0, "a HEAD waited for a window it did not need");
        check(head.ok && head.of("content-length") != nullptr && std::strcmp(head.of("content-length"), "40") == 0,
              "a HEAD larger than the window did not say its length");
        const Lines get = lines_of(got, 3);
        check(get.ok && get.of("content-length") == nullptr, "a GET was given a length nobody wrote");
        check(got.data_bytes_on[3] == 10, "the GET beside it did not stop at its window");
        check(s.service.in_hand() == 1, "the HEAD was kept, or the GET's rest was not");
    }
}

/**
 * @brief
 * \~english A header list over the limit is answered 431 on its stream (RFC 9113, 10.5.1).
 * \~spanish Una lista de cabeceras por encima del limite se contesta 431 en su flujo (RFC 9113, 10.5.1).
 * \~
 */
void test_a_header_list_too_large_is_431() {
    Server s;
    check(s.start(4096, 256), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    char big[101];
    std::memset(big, 'b', 100);
    big[100] = '\0';

    Wire w;
    hello(w);
    uint8_t block[512];
    size_t n = request_block(block, "GET", "/large");
    field(block, n, "x-big", big);
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 1, block, n);

    n = request_block(block, "POST", "/large");
    field(block, n, "x-big", big);
    w.frame(FrameType::Headers, kEndHeaders, 3, block, n);

    n = request_block(block, "GET", "/after");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 5, block, n);

    // \~english Trailers over the limit, behind a body being gathered.  \~spanish Remolques por encima del limite, detras de un cuerpo que se esta juntando.  \~
    n = request_block(block, "POST", "/trailed");
    w.frame(FrameType::Headers, kEndHeaders, 7, block, n);
    w.frame(FrameType::Data, 0, 7, reinterpret_cast<const uint8_t *>("abc"), 3);
    // \~english Room for three fields of a hundred-odd bytes each.  \~spanish Sitio para tres campos de un centenar largo de bytes cada uno.  \~
    uint8_t tail[512];
    size_t t = 0;
    field(tail, t, "x-big", big);
    field(tail, t, "x-big2", big);
    field(tail, t, "x-big3", big);
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 7, tail, t);

    s.send(w);
    s.run();

    check(s.handler.calls == 1 && std::strcmp(s.handler.last_target, "/after") == 0,
          "a request over the header limit reached the handler, or the next one did not");

    const Seen seven = s.seen();
    const Lines trailed = lines_of(seven, 7);
    check(trailed.ok && trailed.of(":status") != nullptr && std::strcmp(trailed.of(":status"), "431") == 0,
          "trailers over the header limit were not answered 431 (RFC 9113, 10.5.1)");
    check(seven.ended_on[7] && seven.resets_on[7] == 0, "the 431 to finished trailers did not end the stream cleanly");

    const Seen got = s.seen();
    const Lines one = lines_of(got, 1);
    check(one.ok && one.of(":status") != nullptr && std::strcmp(one.of(":status"), "431") == 0,
          "a GET over the header limit was not answered 431 (RFC 9113, 10.5.1)");
    check(got.ended_on[1] && got.resets_on[1] == 0, "the 431 to a finished request did not end it cleanly");

    const Lines three = lines_of(got, 3);
    check(three.ok && three.of(":status") != nullptr && std::strcmp(three.of(":status"), "431") == 0,
          "a POST over the header limit was not answered 431 (RFC 9113, 10.5.1)");
    check(got.ended_on[3] && got.resets_on[3] == 1 &&
              got.reset_code_on[3] == static_cast<uint32_t>(ErrorCode::NoError),
          "a client still sending was not asked to stop with NO_ERROR after the 431 (RFC 9113, 8.1)");

    check(got.headers_on[5] == 1 && got.ended_on[5], "the request after them was not answered");
    check(!got.goaway, "a header list over the limit ended the connection");
    check(s.service.in_hand() == 0, "a refused request was never let go of");
}

/**
 * @brief
 * \~english An answer the handler gave is never reset as REFUSED_STREAM (RFC 9113, 8.7).
 * \~spanish Una respuesta que dio el manejador no se reinicia nunca como REFUSED_STREAM (RFC 9113, 8.7).
 * \~
 *
 * \~english
 * REFUSED_STREAM tells a client that nothing was processed and the request
 * may be sent again.  Once the handler has run that is false -- a POST sent
 * twice is a POST done twice -- so an answer with nowhere to wait for a window
 * is an INTERNAL_ERROR.  Four uploads hold the four pieces of work, and a
 * GET whose answer is larger than the window arrives behind them.
 * \~spanish
 * REFUSED_STREAM le dice a un cliente que no se proceso nada y que puede volver
 * a mandar la peticion.  Una vez que ha corrido el manejador eso es falso -- un
 * POST mandado dos veces es un POST hecho dos veces --, asi que una respuesta
 * sin donde esperar una ventana es un INTERNAL_ERROR.  Cuatro subidas tienen los
 * cuatro trabajos, y detras llega un GET cuya respuesta es mayor que la ventana.
 * \~
 */
void test_an_answer_with_nowhere_to_wait_is_not_refused() {
    Server s;
    check(s.start(), "the server would not start");
    std::memset(s.handler.reply, 'x', 40);
    s.handler.reply_size = 40;

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    w.text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    const uint8_t small[6] = {0x00, 0x04, 0x00, 0x00, 0x00, 0x0A};
    w.frame(FrameType::Settings, 0, 0, small, sizeof small);
    uint8_t block[256];
    for (uint32_t id = 1; id <= 7; id += 2) {
        const size_t n = request_block(block, "POST", "/upload");
        w.frame(FrameType::Headers, kEndHeaders, id, block, n);
    }
    const size_t n = request_block(block, "GET", "/big");
    w.frame(FrameType::Headers, kEndHeaders | kEndStream, 9, block, n);
    s.send(w);
    s.run();

    // \~english Stream 9 is counted in slot 0 by @c Seen.  \~spanish @c Seen cuenta el flujo 9 en la ranura 0.  \~
    const Seen got = s.seen();
    check(s.handler.calls == 1, "the GET was not answered by the handler");
    check(got.resets_on[0] == 1, "an answer with nowhere to wait was not reset");
    check(got.reset_code_on[0] == static_cast<uint32_t>(ErrorCode::InternalError),
          "an answer the handler gave was reset as if it had never been processed (RFC 9113, 8.7)");
    check(!got.goaway, "one answer with nowhere to wait ended the connection");
}

/**
 * @brief
 * \~english A request that needs a body and finds no work left is REFUSED_STREAM, before any processing (RFC 9113, 8.7).
 * \~spanish Una peticion que necesita cuerpo y no encuentra trabajo libre es REFUSED_STREAM, antes de procesar nada (RFC 9113, 8.7).
 * \~
 */
void test_a_request_with_no_work_left_is_refused() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    Wire w;
    hello(w);
    uint8_t block[256];
    for (uint32_t id = 1; id <= 9; id += 2) {
        const size_t n = request_block(block, "POST", "/upload");
        w.frame(FrameType::Headers, kEndHeaders, id, block, n);
    }
    s.send(w);
    s.run();

    // \~english Stream 9 is counted in slot 0 by @c Seen.  \~spanish @c Seen cuenta el flujo 9 en la ranura 0.  \~
    const Seen got = s.seen();
    check(s.handler.calls == 0, "a request with no work left reached the handler");
    check(got.resets_on[0] == 1 && got.reset_code_on[0] == static_cast<uint32_t>(ErrorCode::RefusedStream),
          "a request with no work left was not refused as one that may be sent again");
    check(got.resets_on[1] == 0 && got.resets_on[7] == 0, "a request that found work was refused");
    check(!got.goaway, "running out of work ended the connection");
    check(s.service.in_hand() == 4, "the four requests that found work were not kept");
}

} // namespace

int main() {
    test_a_request_is_answered();
    test_a_body_in_one_frame();
    test_a_body_in_pieces_is_joined();
    test_two_requests_at_once();
    test_an_answer_waits_for_a_window();
    test_a_body_too_large_is_refused();
    test_padding_gives_its_window_back();
    test_trailers_reach_the_handler();
    test_a_content_length_that_lies_is_refused();
    test_field_names_go_out_in_lower_case();
    test_an_answer_that_cannot_travel_is_a_500();
    test_a_failed_handler_is_a_500_without_a_reset();
    test_head_sends_no_content();
    test_a_header_list_too_large_is_431();
    test_an_answer_with_nowhere_to_wait_is_not_refused();
    test_a_request_with_no_work_left_is_refused();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
