/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard_streamless.cpp
 * @brief
 * \~english A shard with no stream side: what it refuses, and what it gives back.
 * \~spanish Un fragmento sin lado de flujos: lo que rechaza, y lo que devuelve.
 * \~
 *
 * \~english
 * Every stream completion that reaches such a shard is somebody else's
 * operation, and each one carries something that has to go back: a pooled
 * buffer, or an accepted socket.  So every case here ends by counting the
 * pool and the closes -- a shard that merely did not crash would pass
 * without them.
 * \~spanish
 * Toda finalizacion de flujo que le llega a un fragmento asi es una operacion
 * de otro, y cada una lleva algo que tiene que volver: un buffer del pozo, o un
 * socket aceptado.  Asi que cada caso acaba contando el pozo y los cierres -- un
 * fragmento que simplemente no reventara pasaria sin ellos.
 * \~
 */
#include "http_vx/memory_backend.h"
#include "http_vx/shard.h"

#include <cstdio>

namespace {

using http_vx::MemoryBackend;
using http_vx::Op;
using http_vx::OpKind;
using http_vx::Shard;
using http_vx::ShardConfig;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

ShardConfig sizes() {
    ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 4;
    cfg.idle_ticks = 10;
    cfg.wheel_slots = 64;
    return cfg;
}

/**
 * @brief
 * \~english Accepting with nobody to hand a connection to is refused as a configuration.
 * \~spanish Aceptar sin nadie a quien dar una conexion se rechaza como configuracion.
 * \~
 */
void test_accepting_is_refused_at_reset() {
    Shard shard;
    MemoryBackend io(shard.buffers());

    ShardConfig cfg = sizes();
    cfg.accepts = 1;
    check(!shard.reset(cfg, io, 0), "a shard with no stream side was told to accept");

    cfg.accepts = 0;
    check(shard.reset(cfg, io, 0), "a datagram-only shard would not start");
    check(!shard.serves_streams(), "it claims a stream side it does not have");
    check(io.pending() == 0, "it asked the backend for something");
}

/**
 * @brief
 * \~english @c adopt refuses, counts it apart, and leaves the socket to the caller.
 * \~spanish @c adopt se niega, lo cuenta aparte, y deja el socket a quien llama.
 * \~
 */
void test_adopt_is_refused_and_counted() {
    Shard shard;
    MemoryBackend io(shard.buffers());
    check(shard.reset(sizes(), io, 0), "the shard would not start");

    check(!shard.adopt(7, 0).valid(), "a connection was adopted with nothing to serve it");
    check(shard.counts().refused_adoptions == 1, "the refusal was not counted");
    check(shard.counts().unserved == 0, "a refusal was counted as unserved");
    check(shard.conns().count() == 0, "the table holds a connection");
    check(io.closed() == 0, "the shard closed a socket that is still the caller's");
}

/**
 * @brief
 * \~english A stream read that reaches it gives its buffer back.
 * \~spanish Una lectura de flujo que le llega devuelve su buffer.
 * \~
 */
void test_a_stray_read_gives_its_buffer_back() {
    Shard shard;
    MemoryBackend io(shard.buffers());
    check(shard.reset(sizes(), io, 0), "the shard would not start");

    check(io.feed(reinterpret_cast<const uint8_t *>("GET"), 3), "the bytes were not fed");

    Op op;
    op.kind = OpKind::Recv;
    op.fd = 7;
    op.buffer = shard.buffers().acquire();
    op.length = 64;
    check(op.buffer != http_vx::kNoBuffer, "no buffer to lend");
    check(io.submit(op), "the read was not taken");

    shard.poll(1, 0);
    check(shard.counts().unserved == 1, "the stray read was not counted");
    check(shard.buffers().lent() == 0, "the stray read kept its buffer");
    check(shard.conns().count() == 0, "a read became a connection");
}

/**
 * @brief
 * \~english An accept that reaches it closes the socket it made.
 * \~spanish Una aceptacion que le llega cierra el socket que hizo.
 * \~
 */
void test_a_stray_accept_closes_its_socket() {
    Shard shard;
    MemoryBackend io(shard.buffers());
    check(shard.reset(sizes(), io, 0), "the shard would not start");

    check(io.arrive(9), "the arrival was not taken");
    Op op;
    op.kind = OpKind::Accept;
    check(io.submit(op), "the accept was not taken");

    shard.poll(1, 0);
    check(shard.counts().unserved == 1, "the stray accept was not counted");
    shard.poll(2, 0);
    check(io.closed() == 1, "the accepted socket was left open");
    check(shard.conns().count() == 0, "an accept became a connection");
}

/**
 * @brief
 * \~english A readiness notice, which carries no buffer, is counted and nothing else.
 * \~spanish Un aviso de disponibilidad, que no lleva buffer, se cuenta y nada mas.
 * \~
 */
void test_a_stray_notice_is_counted() {
    Shard shard;
    MemoryBackend io(shard.buffers());
    check(shard.reset(sizes(), io, 0), "the shard would not start");

    check(io.feed(reinterpret_cast<const uint8_t *>("x"), 1), "the byte was not fed");
    Op op;
    op.kind = OpKind::Ready;
    op.fd = 7;
    check(io.submit(op), "the notice was not taken");

    shard.poll(1, 0);
    check(shard.counts().unserved == 1, "the stray notice was not counted");
    check(io.closed() == 0, "a notice closed a socket that is not the shard's");
    check(shard.buffers().lent() == 0, "a notice took a buffer");
}

/**
 * @brief
 * \~english Starting again forgets the counts and may bring the stream side back.
 * \~spanish Empezar de nuevo olvida las cuentas y puede devolver el lado de flujos.
 * \~
 */
void test_release_forgets_the_counts() {
    Shard shard;
    MemoryBackend io(shard.buffers());
    check(shard.reset(sizes(), io, 0), "the shard would not start");
    check(!shard.adopt(7, 0).valid(), "a connection was adopted");

    shard.release();
    check(shard.counts().refused_adoptions == 0, "the counts outlived the shard");
    check(!shard.serves_streams(), "a released shard serves streams");
}

} // namespace

int main() {
    test_accepting_is_refused_at_reset();
    test_adopt_is_refused_and_counted();
    test_a_stray_read_gives_its_buffer_back();
    test_a_stray_accept_closes_its_socket();
    test_a_stray_notice_is_counted();
    test_release_forgets_the_counts();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("shard streamless: OK\n");
    return 0;
}
