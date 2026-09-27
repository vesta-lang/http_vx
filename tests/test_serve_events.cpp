/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_serve_events.cpp
 * @brief
 * \~english The demonstration's event stream, with the real handler: events from another thread reach the client, and a closed one frees its stream.
 * \~spanish El flujo de eventos de la demostracion, con el manejador de verdad: los eventos de otro hilo llegan al cliente, y uno cerrado libera su flujo.
 * \~
 */

#include "serve/greeting.h"

#include "http_vx/memory_backend.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english Polls for @p ms milliseconds, as a server loop would.  \~spanish Da vueltas durante @p ms milisegundos, como un bucle de servidor.  \~
void run_for(http_vx::Shard &shard, int ms) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) shard.poll(1, 20);
}

size_t count(const std::string &s, const char *what) {
    size_t n = 0;
    for (size_t at = s.find(what); at != std::string::npos; at = s.find(what, at + 1)) ++n;
    return n;
}

} // namespace

int main() {
    serve::Greeting greeting;
    serve::Events events;
    greeting.events = &events;
    check(events.start(), "the event thread did not start");

    http_vx::Http1Service service;
    http_vx::Shard shard;
    http_vx::MemoryBackend io(shard.buffers());
    http_vx::h1::Limits limits;
    check(service.reset(8, greeting, limits), "the service would not start");
    http_vx::ShardConfig cfg;
    cfg.connections = 8;
    cfg.buffers = 16;
    cfg.idle_ticks = 10;
    cfg.wheel_slots = 64;
    check(shard.reset(cfg, io, service, 0), "the shard would not start");
    check(shard.adopt(7, 0).valid(), "the connection was not adopted");

    const char req[] = "GET /events HTTP/1.1\r\nHost: a\r\n\r\n";
    io.feed(reinterpret_cast<const uint8_t *>(req), sizeof req - 1);
    run_for(shard, 2500);

    const std::string out(reinterpret_cast<const char *>(io.written()), io.written_size());
    check(out.find("content-type: text/event-stream\r\n") != std::string::npos, "not an event stream");
    check(out.find("transfer-encoding: chunked\r\n") != std::string::npos, "the stream is not chunked");
    check(count(out, "data: tick ") >= 2, "the events of the other thread did not arrive");
    check(shard.open_counts().open_now == 1, "the stream is not counted open");

    // \~english Letting the shard go ends the stream; its slot is free for the next one.
    // \~spanish Soltar el fragmento acaba el flujo; su casilla queda libre para el siguiente.  \~
    shard.release();
    check(shard.open_counts().open_now == 0, "the stream is still counted open");
    events.stop();
    check(events.dropped() == 0, "events were dropped for a client that reads");

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("serve events: OK\n");
    return 0;
}
