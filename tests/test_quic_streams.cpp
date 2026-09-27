/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_streams.cpp
 * @brief
 * \~english The stream table: IDs, directions, limits, implicit opening, closing and MAX_STREAMS.
 * \~spanish La tabla de flujos: identificadores, direcciones, limites, apertura implicita, cierre y MAX_STREAMS.
 * \~
 *
 * \~english
 * Each rule on its own, and then a property against a model written apart
 * from the table: thousands of random frames naming random streams, each one
 * classified the way the RFC's rules say, and the table never holding more
 * than its capacity.
 * \~spanish
 * Cada regla por su cuenta, y despues una propiedad contra un modelo escrito
 * aparte de la tabla: miles de tramas al azar que nombran flujos al azar, cada
 * una clasificada como dicen las reglas del RFC, y la tabla sin guardar nunca mas
 * de su capacidad.
 * \~
 */

#include "http_vx/quic_streams.h"

#include <cstdio>
#include <random>
#include <set>

namespace {

using namespace http_vx::quic;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

StreamConfig server_config() {
    StreamConfig c;
    c.is_server = true;
    c.peer_bidi_concurrency = 3;
    c.peer_uni_concurrency = 2;
    c.local_concurrency = 4;
    c.window_bidi_local = 4096;
    c.window_bidi_remote = 8192;
    c.window_uni = 12288;
    c.send_capacity = 16384;
    c.peer_max_streams_bidi = 1;
    c.peer_max_streams_uni = 2;
    c.peer_window_bidi_local = 1000;
    c.peer_window_bidi_remote = 2000;
    c.peer_window_uni = 3000;
    return c;
}

StreamLookup frame(StreamTable &t, uint64_t id, FrameType type, Stream *&s, TransportError &e) {
    return t.on_peer_frame(id, type, s, e);
}

/// \~english Ends both parts of @p s, so that collect() may take it.
/// \~spanish Acaba las dos partes de @p s, para que collect() pueda llevarselo.  \~
void finish(Stream *s) {
    // \~english A stream the test counted on is missing: say so, rather than crash.
    // \~spanish Falta un flujo con el que contaba la prueba: decirlo, en vez de estrellarse.  \~
    if (s == nullptr) {
        check(false, "a stream that should be open is missing");
        return;
    }
    uint64_t fresh = 0;
    uint64_t released = 0;
    if (s->recv != nullptr) {
        s->recv->on_data(0, nullptr, 0, true, fresh, released);
        // \~english The application takes the end: only then is the part done (RFC 9000, 3.2).
        // \~spanish La aplicacion recoge el final: solo entonces acaba la parte (RFC 9000, 3.2).  \~
        s->recv->read_end();
    }
    if (s->send != nullptr) {
        s->send->finish();
        StreamPiece p;
        if (s->send->next(p, 1200, 1u << 20)) {
            s->send->on_sent(p);
            s->send->on_acked(p.offset, p.len, p.fin);
        }
    }
}

void test_peer_streams() {
    StreamTable t(server_config());
    check(t.ready() && t.capacity() == 3 + 2 + 4, "the table is not 9 streams");

    Stream *s = nullptr;
    TransportError e;

    // \~english Client bidi 0: both parts, with the windows crossed over.
    // \~spanish Bidi 0 del cliente: las dos partes, con las ventanas cruzadas.  \~
    check(frame(t, 0, FrameType::Stream, s, e) == StreamLookup::Found && s->id == 0 &&
              s->recv != nullptr && s->send != nullptr && s->recv->limit() == 8192 &&
              s->send->limit() == 1000,
          "client stream 0 did not open with bidi_remote to receive and the peer's bidi_local to send");

    // \~english Client bidi 8 (index 2) opens 4 as well.
    // \~spanish Bidi 8 del cliente (indice 2) abre tambien el 4.  \~
    check(frame(t, 8, FrameType::Stream, s, e) == StreamLookup::Found && t.count() == 3 &&
              t.find(4) != nullptr,
          "stream 8 did not implicitly open stream 4");

    check(frame(t, 12, FrameType::Stream, s, e) == StreamLookup::Error &&
              e == TransportError::StreamLimitError,
          "a fourth client stream past MAX_STREAMS 3 was not a STREAM_LIMIT_ERROR");

    // \~english Client uni 2: receive only; flow control for it makes no sense.
    // \~spanish Uni 2 del cliente: solo recepcion; control de flujo para el no tiene sentido.  \~
    check(frame(t, 2, FrameType::Stream, s, e) == StreamLookup::Found && s->recv != nullptr &&
              s->send == nullptr && s->recv->limit() == 12288,
          "client uni stream 2 is not receive-only with the uni window");
    check(frame(t, 2, FrameType::MaxStreamData, s, e) == StreamLookup::Error &&
              e == TransportError::StreamStateError,
          "MAX_STREAM_DATA on a receive-only stream was accepted");
    check(frame(t, 2, FrameType::StopSending, s, e) == StreamLookup::Error &&
              e == TransportError::StreamStateError,
          "STOP_SENDING on a receive-only stream was accepted");

    // \~english A peer's bidi stream may be opened by a MAX_STREAM_DATA too (3.2).
    // \~spanish Un flujo bidi del otro extremo tambien lo puede abrir un MAX_STREAM_DATA (3.2).  \~
    StreamTable u(server_config());
    check(frame(u, 0, FrameType::MaxStreamData, s, e) == StreamLookup::Found,
          "MAX_STREAM_DATA did not open a peer's bidirectional stream");
}

void test_local_streams() {
    StreamTable t(server_config());
    Stream *s = nullptr;
    TransportError e;

    check(frame(t, 1, FrameType::Stream, s, e) == StreamLookup::Error &&
              e == TransportError::StreamStateError,
          "data on a server stream the server never opened was accepted");

    Stream *mine = t.open(true);
    check(mine != nullptr && mine->id == 1 && mine->recv->limit() == 4096 &&
              mine->send->limit() == 2000,
          "the server's first bidi stream is not 1, with bidi_local to receive and the peer's bidi_remote to send");
    check(t.open(true) == nullptr && t.blocked_by_peer(true),
          "a second bidi stream went past the peer's MAX_STREAMS 1");
    t.on_max_streams(true, 0);
    check(t.open(true) == nullptr, "a lower MAX_STREAMS let a stream open");
    t.on_max_streams(true, 2);
    check(t.open(true) != nullptr && t.blocked_by_peer(true),
          "a raised MAX_STREAMS did not let exactly one more stream open");

    Stream *uni = t.open(false);
    check(uni != nullptr && uni->id == 3 && uni->recv == nullptr && uni->send != nullptr &&
              uni->send->limit() == 3000,
          "the server's first uni stream is not 3, send-only, with the peer's uni window");
    check(frame(t, 3, FrameType::Stream, s, e) == StreamLookup::Error &&
              e == TransportError::StreamStateError,
          "data on a send-only stream was accepted");
    check(frame(t, 3, FrameType::StopSending, s, e) == StreamLookup::Found && s == uni,
          "STOP_SENDING on a send-only stream was refused");

    // \~english This end's own limit: four streams it opened, at most.
    // \~spanish El limite propio de este extremo: cuatro flujos abiertos por el, como mucho.  \~
    t.on_max_streams(false, 10);
    check(t.open(false) != nullptr && t.open(false) == nullptr && !t.blocked_by_peer(false),
          "this end opened more streams than its own concurrency");
}

void test_closing_and_max_streams() {
    StreamTable t(server_config());
    Stream *s = nullptr;
    TransportError e;

    frame(t, 8, FrameType::Stream, s, e);
    check(t.count() == 3 && t.max_streams(true) == 3 && !t.wants_max_streams(true),
          "three open streams at the limit");

    finish(t.find(0));
    finish(t.find(4));
    check(t.collect() == 2 && t.count() == 1, "two finished streams were not collected");
    check(frame(t, 0, FrameType::Stream, s, e) == StreamLookup::Closed,
          "a frame for a closed stream was not ignored");

    // \~english Two closed of three: past half, so MAX_STREAMS moves to 2 + 3 = 5.
    // \~spanish Dos cerrados de tres: pasado de la mitad, asi que MAX_STREAMS pasa a 2 + 3 = 5.  \~
    check(t.wants_max_streams(true) && t.advertise_max_streams(true) == 5,
          "closing streams did not move MAX_STREAMS to closed plus concurrency");
    check(frame(t, 16, FrameType::Stream, s, e) == StreamLookup::Found && t.count() == 3,
          "a stream within the new limit was refused");

    // \~english A stream half done is not collected.
    // \~spanish Un flujo terminado a medias no se recoge.  \~
    Stream *half = t.find(8);
    uint64_t fresh = 0;
    uint64_t released = 0;
    half->recv->on_data(0, nullptr, 0, true, fresh, released);
    half->recv->read_end();
    check(t.collect() == 0 && t.find(8) != nullptr, "a stream still sending was collected");
}

/**
 * @brief
 * \~english A receiving part is done when the application took its end, not when the end arrived (RFC 9000, 3.2).
 * \~spanish Una parte receptora acaba cuando la aplicacion recogio su final, no cuando llego el final (RFC 9000, 3.2).
 * \~
 */
void test_end_untaken_is_not_collected() {
    StreamTable t(server_config());
    Stream *s = nullptr;
    TransportError e;
    frame(t, 8, FrameType::Stream, s, e);
    uint64_t fresh = 0;
    uint64_t released = 0;
    const uint8_t data[4] = {1, 2, 3, 4};

    // \~english Stream 0: every byte read, then the FIN alone; its sending part done.
    // \~spanish Flujo 0: todos los bytes leidos, luego el FIN solo; su parte emisora acabada.  \~
    Stream *a = t.find(0);
    a->recv->on_data(0, data, sizeof data, false, fresh, released);
    a->recv->consume(sizeof data);
    a->recv->on_data(sizeof data, nullptr, 0, true, fresh, released);
    a->send->reset(1);
    a->send->on_reset_acked();
    check(a->recv->state() == RecvState::DataRecvd && t.collect() == 0 && t.find(0) != nullptr,
          "a stream whose lone FIN nobody took was collected, and its end with it");
    // \~english Looked up again: a stream wrongly collected is gone, not to be touched.
    // \~spanish Buscado de nuevo: un flujo recogido por error ya no esta, y no se toca.  \~
    a = t.find(0);
    check(a != nullptr && a->recv->read_end() && t.collect() == 1 && t.find(0) == nullptr,
          "a stream whose end was taken was not collected");

    // \~english Stream 4: reset by the peer; its end is the reset, and it has to be taken too.
    // \~spanish Flujo 4: reiniciado por el otro; su final es el reinicio, y tambien hay que recogerlo.  \~
    Stream *b = t.find(4);
    b->recv->on_reset(0, 7, fresh, released);
    b->send->reset(1);
    b->send->on_reset_acked();
    check(b->recv->state() == RecvState::ResetRecvd && t.collect() == 0 && t.find(4) != nullptr,
          "a stream whose reset nobody took was collected");
    b = t.find(4);
    check(b != nullptr && b->recv->read_end() && t.collect() == 1, "a stream whose reset was taken was not collected");

    // \~english Stream 8: the application stopped it; the reset answering it has nobody to tell (3.5).
    // \~spanish Flujo 8: la aplicacion lo paro; el reinicio que lo contesta no tiene a quien decirselo (3.5).  \~
    Stream *c = t.find(8);
    check(c->recv->stop(1, released), "the stream could not be stopped");
    c->recv->on_reset(0, 1, fresh, released);
    c->send->reset(1);
    c->send->on_reset_acked();
    check(c->recv->state() == RecvState::ResetRead && t.collect() == 1,
          "a stream the application stopped was not collected once reset");

    // \~english Stream 12: stopped, then data and FIN instead of a reset -- ended, and collected, with no reader (3.5).
    // \~spanish Flujo 12: parado, y luego datos y FIN en vez de un reinicio -- acabado, y recogido, sin lector (3.5).  \~
    t.advertise_max_streams(true);
    frame(t, 12, FrameType::Stream, s, e);
    Stream *d = t.find(12);
    check(d != nullptr && d->recv->stop(1, released), "stream 12 could not be stopped");
    if (d == nullptr) return;
    d->recv->on_data(0, data, sizeof data, true, fresh, released);
    d->send->reset(1);
    d->send->on_reset_acked();
    check(released == sizeof data && d->recv->state() == RecvState::DataRead && t.collect() == 1 &&
              t.find(12) == nullptr,
          "a stopped stream answered with data and FIN was not ended and collected");
}

/**
 * @brief
 * \~english Random frames against a model of the rules, written apart.
 * \~spanish Tramas al azar contra un modelo de las reglas, escrito aparte.
 * \~
 */
void test_against_a_model() {
    std::mt19937_64 rng(4);
    const FrameType kinds[] = {FrameType::Stream, FrameType::ResetStream,
                               FrameType::StreamDataBlocked, FrameType::MaxStreamData,
                               FrameType::StopSending};

    for (int round = 0; round < 50; ++round) {
        StreamConfig cfg = server_config();
        cfg.peer_bidi_concurrency = 1 + rng() % 8;
        cfg.peer_uni_concurrency = 1 + rng() % 4;
        StreamTable t(cfg);

        uint64_t opened[4] = {0, 0, 0, 0};
        uint64_t limit[4] = {cfg.peer_bidi_concurrency, 0, cfg.peer_uni_concurrency, 0};
        std::set<uint64_t> closed;

        for (int step = 0; step < 2000; ++step) {
            const uint64_t id = rng() % 64;
            const FrameType k = kinds[rng() % 5];
            const uint64_t ty = id & 3;
            const bool local = (ty & 1) != 0;  // \~english the server's  \~spanish del servidor  \~
            const bool uni = (ty & 2) != 0;
            const bool recv_part = k == FrameType::Stream || k == FrameType::ResetStream ||
                                   k == FrameType::StreamDataBlocked;

            // \~english The model: the RFC's rules, one by one.  \~spanish El modelo: las reglas del RFC, una a una.  \~
            StreamLookup want;
            TransportError want_err = TransportError::NoError;
            if ((uni && local && recv_part) || (uni && !local && !recv_part)) {
                want = StreamLookup::Error;
                want_err = TransportError::StreamStateError;
            } else if (local) {
                want = StreamLookup::Error;  // \~english the server opens none here  \~spanish aqui el servidor no abre ninguno  \~
                want_err = TransportError::StreamStateError;
            } else if (id / 4 < opened[ty]) {
                want = closed.count(id) ? StreamLookup::Closed : StreamLookup::Found;
            } else if (id / 4 >= limit[ty]) {
                want = StreamLookup::Error;
                want_err = TransportError::StreamLimitError;
            } else {
                want = StreamLookup::Found;
                opened[ty] = id / 4 + 1;
            }

            Stream *s = nullptr;
            TransportError e;
            const StreamLookup got = t.on_peer_frame(id, k, s, e);
            if (got != want || (got == StreamLookup::Error && e != want_err) ||
                (got == StreamLookup::Found && (s == nullptr || s->id != id))) {
                std::fprintf(stderr, "FAIL: frame %d on stream %llu: got %d/%llu, the model says %d/%llu\n",
                             static_cast<int>(k), static_cast<unsigned long long>(id),
                             static_cast<int>(got), static_cast<unsigned long long>(e),
                             static_cast<int>(want), static_cast<unsigned long long>(want_err));
                ++failures;
                return;
            }
            if (t.count() > t.capacity()) {
                check(false, "the table held more streams than its capacity");
                return;
            }

            // \~english Now and then, finish one, collect, and let the limit move.
            // \~spanish De vez en cuando, acabar uno, recoger, y dejar que el limite se mueva.  \~
            if (got == StreamLookup::Found && rng() % 3 == 0) {
                finish(s);
                const uint64_t fid = s->id;
                if (t.collect() != 0) closed.insert(fid);
                for (int bidi = 0; bidi < 2; ++bidi)
                    if (t.wants_max_streams(bidi != 0))
                        limit[bidi ? 0 : 2] = t.advertise_max_streams(bidi != 0);
            }
        }
    }
}

} // namespace

int main() {
    test_peer_streams();
    test_local_streams();
    test_closing_and_max_streams();
    test_end_untaken_is_not_collected();
    test_against_a_model();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic streams: OK\n");
    return 0;
}
