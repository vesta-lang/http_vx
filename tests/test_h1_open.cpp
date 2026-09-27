/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_open.cpp
 * @brief
 * \~english Open responses in HTTP/1.1, with no network: chunks, kicks, the requests behind, limits, and every gone (HVX-5).
 * \~spanish Respuestas abiertas en HTTP/1.1, sin red: trozos, avisos, las peticiones de detras, topes, y cada gone (HVX-5).
 * \~
 */

#include "http_vx/http1_service.h"
#include "http_vx/memory_backend.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

using http_vx::BodySource;
using http_vx::ConnHandle;
using http_vx::GoneReason;
using http_vx::Handler;
using http_vx::Http1Service;
using http_vx::MemoryBackend;
using http_vx::OpenResponse;
using http_vx::Request;
using http_vx::ResponseBuilder;
using http_vx::Shard;
using http_vx::ShardConfig;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english A source the test feeds by hand.  \~spanish Una fuente que la prueba alimenta a mano.  \~
class Stream final : public BodySource {
  public:
    size_t fill(OpenResponse, uint8_t *dst, size_t room, bool &done) noexcept override {
        ++fills;
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
        return n == room ? n + lie : n;
    }

    void gone(OpenResponse, GoneReason why) noexcept override {
        ++gones;
        last = why;
    }

    std::string pending;
    bool finish = false;
    /// \~english How many fills take all the room; the memory backend keeps 64 KiB.
    /// \~spanish Cuantos rellenos usan todo el sitio; el backend de memoria guarda 64 KiB.  \~
    int full_fills = 0;
    /// \~english Added to what fill says it wrote: a source that lies.  \~spanish Se suma a lo que fill dice que escribio: una fuente que miente.  \~
    size_t lie = 0;
    int fills = 0;
    int gones = 0;
    GoneReason last = GoneReason::Finished;
};

/// \~english Opens on "/open", answers anything else whole.  \~spanish Abre en "/open", contesta lo demas entero.  \~
class Opener final : public Handler {
  public:
    void handle(const Request &req, const uint8_t *head, const uint8_t *, size_t,
                ResponseBuilder &res) noexcept override {
        ++calls;
        const std::string target(reinterpret_cast<const char *>(head + req.target.off), req.target.len);
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/event-stream", 17);
        if (target == "/open") {
            if (!before.empty()) res.body(before.data(), before.size());
            opened = res.open(*next);
        } else {
            res.body("whole", 5);
        }
    }

    Stream *next = nullptr;
    std::string before;
    OpenResponse opened;
    int calls = 0;
};

struct Server {
    Opener handler;
    Stream source;
    Http1Service service;
    Shard shard;
    MemoryBackend io;

    Server() : io(shard.buffers()) { handler.next = &source; }

    bool start(uint32_t max_open = 16, uint16_t per_conn = 16) {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 16;
        cfg.idle_ticks = 10;
        cfg.wheel_slots = 64;
        cfg.max_open = max_open;
        cfg.max_open_per_conn = per_conn;
        return shard.reset(cfg, io, service, 0);
    }

    void send(const char *s) { io.feed(reinterpret_cast<const uint8_t *>(s), std::strlen(s)); }

    void run() {
        for (int i = 0; i < 64; ++i) shard.poll(1, 0);
    }

    std::string out() const {
        return std::string(reinterpret_cast<const char *>(io.written()), io.written_size());
    }

    bool out_has(const char *what) const { return out().find(what) != std::string::npos; }
};

/**
 * @brief
 * \~english The head goes at once, chunked; each kick is a chunk; done ends it and gone says Finished, once.
 * \~spanish La cabecera sale ya, por trozos; cada aviso es un trozo; done la acaba y gone dice Finished, una vez.
 * \~
 */
void test_open_fill_and_finish() {
    Server s;
    check(s.start(), "the server would not start");
    s.handler.before = "first";
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");

    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    check(s.handler.opened.valid(), "the response was not opened");
    check(s.out_has("HTTP/1.1 200 OK\r\n"), "the head did not go out");
    check(s.out_has("transfer-encoding: chunked\r\n"), "an open HTTP/1.1 response is not chunked");
    check(!s.out_has("content-length"), "an open response announced a length");
    check(s.out_has("\r\n\r\n5\r\nfirst\r\n"), "what was written before opening is not the first chunk");
    check(s.source.fills == 1, "the source was not asked once on opening");

    s.source.pending = "hello";
    check(s.source.kick(), "the kick was refused");
    s.run();
    check(s.out_has("0005\r\nhello\r\n"), "a kick did not become a chunk");
    check(s.source.fills == 2, "a kick did not become one fill");

    s.run();
    check(s.source.fills == 2, "the source was asked again with no kick and no room used up");

    s.source.pending = "bye";
    s.source.finish = true;
    s.source.kick();
    s.run();
    check(s.out_has("0003\r\nbye\r\n0\r\n\r\n"), "done did not write the last chunk");
    check(s.source.gones == 1 && s.source.last == GoneReason::Finished, "gone(Finished) did not come once");

    s.source.kick();
    s.run();
    check(s.source.fills == 3 && s.source.gones == 1, "a kick after gone reached the source");

    const http_vx::OpenCounts c = s.shard.open_counts();
    check(c.opened == 1 && c.open_now == 0 && c.fills == 3 && c.filled_bytes == 8, "the counts are wrong");
}

/**
 * @brief
 * \~english A request behind an open response waits for it, and is answered after it, in order.
 * \~spanish Una peticion detras de una respuesta abierta la espera, y se contesta despues, en orden.
 * \~
 */
void test_the_request_behind_waits() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");

    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();
    check(s.handler.calls == 1, "the request behind an open response was answered before it ended");

    s.source.pending = "tail";
    s.source.finish = true;
    s.source.kick();
    s.run();

    check(s.handler.calls == 2, "the request behind was not answered when the open response ended");
    const std::string o = s.out();
    const size_t last = o.find("0\r\n\r\n");
    const size_t whole = o.find("whole");
    check(last != std::string::npos && whole != std::string::npos && last < whole,
          "the answer behind overtook the open response");
}

/**
 * @brief
 * \~english A source that fills all the room is asked again without a kick, until it gives less.
 * \~spanish A una fuente que llena todo el sitio se le vuelve a pedir sin aviso, hasta que da menos.
 * \~
 */
void test_a_full_fill_is_asked_again() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");

    s.source.full_fills = 2;
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    /* \~english
     * Two full fills and the one after them that gives nothing: asked
     * without a kick exactly while it kept taking all the room.
     * \~spanish
     * Dos rellenos llenos y el de despues que no da nada: se le pidio sin aviso
     * exactamente mientras siguio usando todo el sitio.
     * \~ */
    check(s.source.fills == 3, "a source was not asked again exactly while it used all the room");
    check(s.out_has("4000\r\nxxxx"), "a full fill did not go out as a full chunk");
    check(s.source.gones == 0, "the open response ended by itself");
    check(s.shard.open_counts().starved == 0, "the pool ran dry for one open response");
}

/**
 * @brief
 * \~english A source that says it wrote more than the room is believed no further than the room.
 * \~spanish A una fuente que dice haber escrito mas que el sitio no se le cree mas alla del sitio.
 * \~
 */
void test_a_source_that_lies_is_clamped() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");

    s.source.full_fills = 1;
    s.source.lie = 5;
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    check(s.out_has("\r\n4000\r\n") && !s.out_has("4005"), "a chunk announced more than the room");
    check(s.shard.open_counts().filled_bytes == Http1Service::kFillRoom, "more than the room was counted");
}

/**
 * @brief
 * \~english HEAD does not open; the answer goes whole with its head.
 * \~spanish HEAD no abre; la respuesta sale entera con su cabecera.
 * \~
 */
void test_head_does_not_open() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");

    s.send("HEAD /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();
    check(!s.handler.opened.valid(), "a HEAD response was opened");
    check(s.source.fills == 0 && s.source.gones == 0, "a refused source was used");
    check(s.out_has("HTTP/1.1 200 OK\r\n") && !s.out_has("chunked"), "the HEAD answer is not a whole one");
}

/**
 * @brief
 * \~english With the limit reached the answer is 503, counted, and the connection carries on.
 * \~spanish Con el tope agotado la respuesta es 503, contada, y la conexion sigue.
 * \~
 */
void test_the_limit_is_answered_503() {
    Server s;
    check(s.start(1, 1), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the first connection was not adopted");
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();
    check(s.handler.opened.valid(), "the first response was not opened");

    Stream other;
    s.handler.next = &other;
    check(s.shard.adopt(8, 0).valid(), "the second connection was not adopted");
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();
    check(!s.handler.opened.valid(), "the second response was opened past the limit");
    check(s.out_has("HTTP/1.1 503 Service Unavailable\r\n"), "the limit was not answered 503");
    check(other.fills == 0 && other.gones == 0, "a refused source was used");
    check(s.shard.open_counts().refused == 1, "the refusal was not counted");
}

/**
 * @brief
 * \~english A connection that says nothing for too long ends its open response with IdleTimeout.
 * \~spanish Una conexion que calla demasiado acaba su respuesta abierta con IdleTimeout.
 * \~
 */
void test_idle_timeout() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    s.shard.expire(100);
    s.run();
    check(s.source.gones == 1 && s.source.last == GoneReason::IdleTimeout, "the deadline did not end it with IdleTimeout");
    check(s.shard.open_counts().open_now == 0, "an expired response is still counted open");
}

/**
 * @brief
 * \~english Letting the shard go ends what is open with Shutdown.
 * \~spanish Soltar el fragmento acaba lo abierto con Shutdown.
 * \~
 */
void test_shutdown() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");
    s.send("GET /open HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    s.source.kick();
    s.shard.release();
    check(s.source.gones == 1 && s.source.last == GoneReason::Shutdown, "letting the shard go did not end it with Shutdown");
}

/**
 * @brief
 * \~english HTTP/1.0 has no chunks: the body goes as it is and ends with the connection.
 * \~spanish HTTP/1.0 no tiene trozos: el cuerpo sale tal cual y acaba con la conexion.
 * \~
 */
void test_http10_ends_by_closing() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.shard.adopt(7, 0).valid(), "the connection was not adopted");
    // \~english Asked to be kept alive: an open body still has to end it.
    // \~spanish Pidiendo que se mantenga viva: un cuerpo abierto tiene que acabarla igual.  \~
    s.send("GET /open HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    s.run();
    check(s.handler.opened.valid(), "an HTTP/1.0 response was not opened");
    check(!s.out_has("chunked"), "an HTTP/1.0 response was chunked");

    s.source.pending = "raw";
    s.source.finish = true;
    s.source.kick();
    s.run();
    check(s.out_has("\r\n\r\nraw") && !s.out_has("0003"), "the HTTP/1.0 body was framed");
    check(s.shard.conns().count() == 0, "the HTTP/1.0 connection did not end with its body");
    check(s.source.gones == 1 && s.source.last == GoneReason::Finished, "gone(Finished) did not come");
}

} // namespace

int main() {
    test_open_fill_and_finish();
    test_the_request_behind_waits();
    test_a_full_fill_is_asked_again();
    test_a_source_that_lies_is_clamped();
    test_head_does_not_open();
    test_the_limit_is_answered_503();
    test_idle_timeout();
    test_shutdown();
    test_http10_ends_by_closing();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("h1 open responses: OK\n");
    return 0;
}
