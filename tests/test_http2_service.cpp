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
    size_t window_given = 0;
    bool ended_on[8] = {};
    bool goaway = false;

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
                ++headers_on[slot];
                if ((flags & kEndStream) != 0) ended_on[slot] = true;
                break;

            case FrameType::Data:
                data_bytes_on[slot] += len;
                if ((flags & kEndStream) != 0) ended_on[slot] = true;
                break;

            case FrameType::RstStream:
                ++resets_on[slot];
                break;

            case FrameType::WindowUpdate:
                window_given += (static_cast<size_t>(payload[0] & 0x7F) << 24) |
                                (static_cast<size_t>(payload[1]) << 16) |
                                (static_cast<size_t>(payload[2]) << 8) |
                                static_cast<size_t>(payload[3]);
                break;

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
        if (reply_size != 0) res.body(reply, reply_size);
    }

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

    bool start(size_t max_body = 4096) {
        http_vx::h2::Limits limits;
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

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
