/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_stream_recv.cpp
 * @brief
 * \~english The receiving part of a stream: reassembly, flow control, final size, reset, memory.
 * \~spanish La parte receptora de un flujo: reensamblado, control de flujo, tamano final, reinicio, memoria.
 * \~
 *
 * \~english
 * The central case is a property: a message cut into segments, shuffled,
 * duplicated and overlapped, fed while the application reads, has to come out
 * byte for byte as it went in -- and the memory has to go back to nothing
 * when it has been read.
 * \~spanish
 * El caso central es una propiedad: un mensaje cortado en segmentos, barajados,
 * duplicados y solapados, dados mientras la aplicacion lee, tiene que salir byte
 * a byte como entro -- y la memoria tiene que volver a nada cuando se ha leido.
 * \~
 */

#include "http_vx/quic_stream_recv.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

namespace {

using namespace http_vx::quic;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english A STREAM frame's data for @p r; only an abandoned stream may give bytes back.
 * \~spanish Los datos de una trama STREAM para @p r; solo un flujo abandonado puede devolver bytes.
 * \~
 *
 * @param fresh \~english what it cost the connection's window  \~spanish lo que costo a la ventana de la conexion  \~
 * @return      \~english what `on_data` said  \~spanish lo que dijo `on_data`  \~
 */
StreamError feed(RecvStream &r, uint64_t off, const uint8_t *p, size_t len, bool fin, uint64_t &fresh) {
    uint64_t released = 0;
    const StreamError e = r.on_data(off, p, len, fin, fresh, released);
    check(released == 0 || r.abandoned(), "a stream nobody abandoned gave bytes back");
    return e;
}

/// \~english Reads everything available into @p out.  \~spanish Lee todo lo disponible en @p out.  \~
size_t drain(RecvStream &s, std::vector<uint8_t> &out) {
    size_t total = 0;
    const uint8_t *p = nullptr;
    size_t n;
    while ((n = s.peek(p)) != 0) {
        out.insert(out.end(), p, p + n);
        s.consume(n);
        total += n;
    }
    return total;
}

void test_in_order_across_chunks() {
    RecvStream s(16384);
    std::vector<uint8_t> msg(10000);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 3);

    uint64_t fresh = 0;
    check(feed(s, 0, msg.data(), msg.size(), false, fresh) == StreamError::None && fresh == 10000,
          "10000 bytes in order were not taken");
    check(s.chunks_held() == 3, "10000 bytes do not sit in three chunks");

    // \~english peek gives at most a chunk: 4096, 4096, 1808.
    // \~spanish peek da como mucho un trozo: 4096, 4096, 1808.  \~
    const uint8_t *p = nullptr;
    check(s.peek(p) == 4096, "the first peek is not the first chunk");
    std::vector<uint8_t> out;
    check(drain(s, out) == 10000 && out == msg, "the bytes did not come out as they went in");
    check(s.chunks_held() == 1, "chunks read past were not freed");

    check(feed(s, 10000, nullptr, 0, true, fresh) == StreamError::None && fresh == 0 &&
              s.state() == RecvState::DataRecvd && s.at_end() && s.chunks_held() == 0,
          "an empty FIN at the end did not wait for the application with its memory freed");
    check(s.read_end() && s.state() == RecvState::DataRead, "taking the end did not finish the stream");
}

/// \~english The property: shuffled, duplicated, overlapping segments reassemble exactly.
/// \~spanish La propiedad: segmentos barajados, duplicados y solapados se reensamblan exactos.  \~
void test_reassembly_property() {
    std::mt19937 rng(2);
    for (int round = 0; round < 300; ++round) {
        const size_t size = 1 + rng() % 60000;
        std::vector<uint8_t> msg(size);
        for (uint8_t &b : msg) b = static_cast<uint8_t>(rng());

        struct Seg {
            size_t off, len;
        };
        std::vector<Seg> segs;
        for (size_t off = 0; off < size;) {
            const size_t len = std::min(size - off, static_cast<size_t>(1 + rng() % 3000));
            segs.push_back({off, len});
            // \~english An overlapping copy now and then, like a repacked retransmission.
            // \~spanish Una copia solapada de vez en cuando, como una retransmision reempaquetada.  \~
            if (rng() % 4 == 0 && off > 0) {
                const size_t back = std::min(off, static_cast<size_t>(rng() % 500));
                segs.push_back({off - back, std::min(size - (off - back), len + back)});
            }
            if (rng() % 5 == 0) segs.push_back({off, len});
            off += len;
        }
        std::shuffle(segs.begin(), segs.end(), rng);

        RecvStream s(65536);
        std::vector<uint8_t> out;
        uint64_t charged = 0;
        for (const Seg &g : segs) {
            const bool fin = g.off + g.len == size;
            uint64_t fresh = 0;
            if (feed(s, g.off, msg.data() + g.off, g.len, fin, fresh) != StreamError::None) {
                check(false, "a legal segment was refused");
                return;
            }
            charged += fresh;
            if (s.chunks_held() > 65536 / kRecvChunk + 1) {
                check(false, "the stream held more chunks than its window covers");
                return;
            }
            if (rng() % 3 == 0) drain(s, out);
        }

        /* \~english
         * Everything has arrived, so the stream must know it (3.2) -- before
         * the last read, not because of it.  A count of waiting bytes that
         * counted a duplicate twice would never see "all here" and would
         * still deliver the right bytes, so only the state can catch it.
         * \~spanish
         * Ya llego todo, asi que el flujo lo tiene que saber (3.2) -- antes de
         * la ultima lectura, no gracias a ella.  Una cuenta de bytes en espera
         * que contara dos veces un duplicado no veria nunca "todo aqui" y aun
         * asi entregaria los bytes correctos, asi que solo el estado puede
         * cogerlo.
         * \~ */
        if (s.state() != RecvState::DataRecvd && s.state() != RecvState::DataRead) {
            std::fprintf(stderr, "FAIL: all %zu bytes arrived and the stream is in state %d\n", size,
                         static_cast<int>(s.state()));
            ++failures;
            return;
        }
        drain(s, out);

        if (out != msg || !s.at_end() || !s.read_end() || s.state() != RecvState::DataRead ||
            s.chunks_held() != 0 || charged != size) {
            std::fprintf(stderr, "FAIL: a %zu-byte message came out %zu bytes, state %d, %zu chunks, %llu charged\n",
                         size, out.size(), static_cast<int>(s.state()), s.chunks_held(),
                         static_cast<unsigned long long>(charged));
            ++failures;
            return;
        }
    }
}

/// \~english 4.1: the limit, exactly at it and past it, and moving it.
/// \~spanish 4.1: el limite, justo en el y pasado, y moverlo.  \~
void test_flow_control() {
    RecvStream s(8192);
    std::vector<uint8_t> buf(9000, 0x5a);
    uint64_t fresh = 0;

    check(feed(s, 0, buf.data(), 8192, false, fresh) == StreamError::None,
          "data ending exactly at the limit was refused");
    check(feed(s, 8192, buf.data(), 1, false, fresh) == StreamError::FlowControl &&
              transport_error_of(StreamError::FlowControl) == TransportError::FlowControlError,
          "one byte past the limit was not a FLOW_CONTROL_ERROR");

    // \~english A window that is not whole chunks: the limit is still exactly it (4.1, 19.10).
    // \~spanish Una ventana que no son trozos enteros: el limite sigue siendo exactamente ella (4.1, 19.10).  \~
    {
        RecvStream odd(1000);
        uint64_t f2 = 0;
        check(feed(odd, 0, buf.data(), 1000, false, f2) == StreamError::None,
              "data up to an odd window was refused");
        check(feed(odd, 1000, buf.data(), 1, false, f2) == StreamError::FlowControl,
              "one byte past an odd window was let through: the limit was rounded up");
    }

    check(!s.wants_update(), "an update was wanted before anything was read");
    const uint8_t *p = nullptr;
    s.consume(s.peek(p));
    check(!s.wants_update(), "an update was wanted after reading less than half");
    s.consume(s.peek(p));
    check(s.wants_update() && s.advertise() == 8192 + 8192 && s.limit() == 16384,
          "reading the window did not move the limit a window past what was read");
    check(feed(s, 8192, buf.data(), 8192, false, fresh) == StreamError::None,
          "data within the new limit was refused");

    RecvFlow f(1000);
    check(f.on_received(600) && !f.on_received(500), "the connection limit did not hold at 1000");
    RecvFlow g(1000);
    g.on_received(900);
    check(!g.wants_update(), "the connection wanted an update with nothing consumed");
    g.on_consumed(600);
    check(g.wants_update() && g.advertise() == 1600, "consuming did not move the connection limit");
}

/// \~english 4.5: the final size cannot change, and nothing goes past it.
/// \~spanish 4.5: el tamano final no puede cambiar, y nada pasa de el.  \~
void test_final_size() {
    uint8_t b[300] = {};
    uint64_t fresh = 0;
    {
        RecvStream s(4096);
        feed(s, 0, b, 100, true, fresh);
        check(feed(s, 0, b, 100, true, fresh) == StreamError::None, "the same FIN twice was refused");
        check(feed(s, 100, b, 1, false, fresh) == StreamError::FinalSize, "data past the final size");
        check(feed(s, 0, b, 90, true, fresh) == StreamError::FinalSize, "a FIN moved back");
        check(feed(s, 50, b, 60, true, fresh) == StreamError::FinalSize, "a FIN moved forward");
        check(transport_error_of(StreamError::FinalSize) == TransportError::FinalSizeError,
              "FinalSize does not close with FINAL_SIZE_ERROR");
    }
    {
        RecvStream s(4096);
        feed(s, 0, b, 200, false, fresh);
        check(feed(s, 100, b, 50, true, fresh) == StreamError::FinalSize,
              "a FIN below data already received was taken");
    }
}

/// \~english RESET_STREAM: what it releases, and what it may not claim.
/// \~spanish RESET_STREAM: lo que libera, y lo que no puede decir.  \~
void test_reset() {
    std::vector<uint8_t> b(2000, 1);
    uint64_t fresh = 0;
    uint64_t released = 0;
    {
        RecvStream s(4096);
        feed(s, 0, b.data(), 1000, false, fresh);
        const uint8_t *p = nullptr;
        s.peek(p);
        s.consume(300);

        check(s.on_reset(900, 7, fresh, released) == StreamError::FinalSize,
              "a reset below the data already received was taken");
        check(s.on_reset(1500, 7, fresh, released) == StreamError::None && fresh == 500 &&
                  released == 1200 && s.state() == RecvState::ResetRecvd &&
                  s.reset_code() == 7 && s.chunks_held() == 0,
              "a reset did not charge its final size, release the unread bytes and free the chunks");
        check(s.peek(p) == 0, "a reset stream still had bytes to read");
        check(feed(s, 1000, b.data(), 100, false, fresh) == StreamError::None && fresh == 0,
              "a late retransmission after a reset was not quietly dropped");
        check(feed(s, 1400, b.data(), 200, false, fresh) == StreamError::FinalSize,
              "data past a reset's final size was taken");
        check(s.on_reset(1400, 7, fresh, released) == StreamError::FinalSize,
              "a second reset with another final size was taken");
        check(!s.at_end() && s.read_end() && s.state() == RecvState::ResetRead && !s.read_end(),
              "the reset was not taken exactly once (3.2)");
        check(s.on_reset(1500, 7, fresh, released) == StreamError::None && fresh == 0 && released == 0 &&
                  s.state() == RecvState::ResetRead,
              "the same reset again, once read, changed something");
    }
    {
        RecvStream s(4096);
        check(s.on_reset(5000, 1, fresh, released) == StreamError::FlowControl,
              "a reset claiming more than the limit was taken");
    }
    {
        // \~english All data already here: the reset changes nothing, the data is delivered.
        // \~spanish Todos los datos ya aqui: el reinicio no cambia nada, los datos se entregan.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 100, true, fresh);
        check(s.state() == RecvState::DataRecvd && s.on_reset(100, 1, fresh, released) == StreamError::None &&
                  s.state() == RecvState::DataRecvd && released == 0,
              "a reset after all data arrived threw the data away");
    }
}

/// \~english Stopping to read: a STOP_SENDING owed while it can still matter (RFC 9000, 3.5).
/// \~spanish Dejar de leer: un STOP_SENDING debido mientras aun pueda importar (RFC 9000, 3.5).  \~
void test_stop() {
    std::vector<uint8_t> b(100, 1);
    uint64_t fresh = 0;
    uint64_t released = 0;
    {
        RecvStream s(4096);
        check(!s.stop_pending() && !s.stopped() && !s.abandoned(), "nothing owed before asking");
        check(s.stop(0x10c, released) && released == 0 && s.abandoned(), "stopping in \"Recv\" was refused");
        check(s.stop_pending() && s.stopped() && s.stop_code() == 0x10c, "the STOP_SENDING and its code are not owed");
        check(!s.stop(0x10b, released) && released == 0 && s.stop_code() == 0x10c, "asking twice was taken");
        s.on_stop_sent();
        check(!s.stop_pending(), "still owed once sent");
        s.on_stop_lost();
        check(s.stop_pending(), "not owed again once lost");
        feed(s, 0, b.data(), 100, false, fresh);
        check(s.stop_pending(), "data after asking does not change what is owed");
        feed(s, 100, b.data(), 0, true, fresh);
        check(s.state() == RecvState::DataRead && !s.stop_pending(),
              "once the final size is here, a STOP_SENDING is pointless and not owed (3.5)");
    }
    {
        RecvStream s(4096);
        feed(s, 0, b.data(), 10, true, fresh);
        check(!s.stop(1, released) && !s.stopped() && !s.stop_pending(),
              "a STOP_SENDING was owed after all data arrived (3.3)");
    }
    {
        // \~english In "Size Known" every byte is accounted for: nothing to ask, the stream ends.
        // \~spanish En "Size Known" cada byte esta en la cuenta: nada que pedir, el flujo acaba.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 10, false, fresh);
        feed(s, 50, b.data(), 0, true, fresh);
        check(s.state() == RecvState::SizeKnown && !s.stop(1, released) && !s.stop_pending() &&
                  released == 50 && s.state() == RecvState::DataRead,
              "stopping in \"Size Known\" did not give back all 50 bytes counted and end the stream");
        check(s.on_reset(50, 1, fresh, released) == StreamError::None && released == 0 &&
                  s.state() == RecvState::DataRead,
              "a reset after the stream ended changed something");
    }
    {
        // \~english Stopped in "Recv", then reset: the reset has nobody to tell (3.5).
        // \~spanish Parado en "Recv", y luego reiniciado: el reinicio no tiene a quien decirselo (3.5).  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 10, false, fresh);
        check(s.stop(1, released) && released == 10, "the 10 unread bytes were not given back");
        s.on_stop_sent();
        check(s.on_reset(50, 1, fresh, released) == StreamError::None && fresh == 40 && released == 40,
              "the reset did not charge and give back the 40 bytes past what arrived");
        s.on_stop_lost();
        check(!s.stop_pending(), "a reset arrived: a lost STOP_SENDING is not sent again (3.5)");
        check(s.state() == RecvState::ResetRead && !s.read_end(),
              "the reset a stop asked for waited for an application that gave the stream up (3.5)");
    }
    {
        // \~english Not stopped: the reset waits for the application.  \~spanish Sin parar: el reinicio espera a la aplicacion.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 10, false, fresh);
        s.on_reset(50, 1, fresh, released);
        check(s.state() == RecvState::ResetRecvd, "a reset nobody asked for did not wait to be taken");
    }
}

/**
 * @brief
 * \~english An abandoned stream: the transport throws away what it holds and what comes, gives every byte back, and ends it alone (RFC 9000, 3.5, 4.5).
 * \~spanish Un flujo abandonado: el transporte tira lo que tiene y lo que llega, devuelve cada byte, y lo acaba solo (RFC 9000, 3.5, 4.5).
 * \~
 *
 * \~english
 * The sums are the connection's: every byte a stream was charged (`fresh`)
 * has to come back as read or released, or the connection's window shrinks
 * for good.
 * \~spanish
 * Las cuentas son las de la conexion: cada byte que se le cobro a un flujo
 * (`fresh`) tiene que volver como leido o liberado, o la ventana de la conexion
 * encoge para siempre.
 * \~
 */
void test_abandon() {
    std::vector<uint8_t> b(9000, 3);
    uint64_t fresh = 0;
    uint64_t released = 0;
    const uint8_t *p = nullptr;
    {
        // \~english Stopped with nothing here, then data and its FIN: all given back, the stream ended.
        // \~spanish Parado sin nada aqui, luego datos y su FIN: todo devuelto, el flujo acabado.  \~
        RecvStream r(16384);
        check(r.stop(1, released) && released == 0, "stopping an empty stream gave something back");
        check(r.on_data(0, b.data(), 5000, true, fresh, released) == StreamError::None && fresh == 5000 &&
                  released == 5000,
              "data with its FIN on an abandoned stream was not charged and given back whole");
        check(r.state() == RecvState::DataRead && r.chunks_held() == 0 && r.peek(p) == 0 && !r.stop_pending(),
              "the stream did not end by itself, with nothing kept and nothing owed");
        check(!r.read_end(), "an end was left for an application that gave the stream up");
    }
    {
        // \~english Bytes already waiting, holes included, go back at once.
        // \~spanish Los bytes que ya esperaban, huecos incluidos, vuelven en el acto.  \~
        RecvStream r(16384);
        uint64_t charged = 0;
        // \~english Whatever the caller left in it: nothing is released on a stream still read.
        // \~spanish Deje lo que deje en el quien llama: nada se libera en un flujo que aun se lee.  \~
        released = 99;
        r.on_data(0, b.data(), 3000, false, fresh, released);
        check(released == 0, "a stream still read said it released bytes");
        charged += fresh;
        r.on_data(6000, b.data(), 1000, false, fresh, released);
        charged += fresh;
        check(r.peek(p) == 3000, "the first 3000 bytes are not readable");
        check(r.consume(1000) == 1000, "a read did not say how much it read");
        check(r.stop(1, released) && released == charged - 1000 && r.chunks_held() == 0,
              "the 6000 bytes counted and not read, the hole included, were not given back at once");
        check(r.consume(500) == 0 && r.read_offset() == 7000,
              "a read still pending after the stop counted its bytes a second time");
        // \~english The hole arrives: nothing new to charge, nothing more to give back.
        // \~spanish Llega el hueco: nada nuevo que cobrar, nada mas que devolver.  \~
        check(r.on_data(3000, b.data(), 3000, false, fresh, released) == StreamError::None && fresh == 0 &&
                  released == 0 && r.chunks_held() == 0,
              "a retransmission below what was given back was charged or kept");
        // \~english More data, no FIN: charged and given back; the stream waits for its end.
        // \~spanish Mas datos, sin FIN: cobrados y devueltos; el flujo espera su final.  \~
        check(r.on_data(7000, b.data(), 2000, false, fresh, released) == StreamError::None && fresh == 2000 &&
                  released == 2000 && r.state() == RecvState::Recv,
              "data past what arrived was not charged and given back");
        check(!r.wants_update() && !r.takes_credit(), "an abandoned stream still wanted credit");
        // \~english Then the FIN alone.  \~spanish Luego el FIN solo.  \~
        check(r.on_data(9000, nullptr, 0, true, fresh, released) == StreamError::None && fresh == 0 &&
                  released == 0 && r.state() == RecvState::DataRead,
              "a lone FIN at what was counted did not end the abandoned stream");
    }
    {
        // \~english The final size still holds (4.5).  \~spanish El tamano final sigue valiendo (4.5).  \~
        RecvStream r(16384);
        r.on_data(0, b.data(), 4000, false, fresh, released);
        r.stop(1, released);
        check(r.on_data(3000, nullptr, 0, true, fresh, released) == StreamError::FinalSize,
              "a FIN below what arrived was taken on an abandoned stream");
        check(r.on_data(16000, b.data(), 1000, false, fresh, released) == StreamError::FlowControl,
              "data past the limit was taken on an abandoned stream");
        r.on_data(4000, nullptr, 0, true, fresh, released);
        check(r.on_data(4000, b.data(), 1, false, fresh, released) == StreamError::FinalSize &&
                  r.on_data(0, nullptr, 0, true, fresh, released) == StreamError::FinalSize,
              "the final size of an abandoned stream moved");
    }
    {
        // \~english All here and unread: nothing to ask, every byte back, the stream ended.
        // \~spanish Todo aqui y sin leer: nada que pedir, cada byte devuelto, el flujo acabado.  \~
        RecvStream r(16384);
        r.on_data(0, b.data(), 700, true, fresh, released);
        check(!r.stop(1, released) && released == 700 && r.state() == RecvState::DataRead && r.chunks_held() == 0 &&
                  !r.stop_pending(),
              "stopping a stream with everything here did not give it all back and end it");
    }
    {
        // \~english Reset and not yet told: the stop is the telling.  \~spanish Reiniciado y aun sin decir: la parada es el decirlo.  \~
        RecvStream r(16384);
        r.on_data(0, b.data(), 100, false, fresh, released);
        r.on_reset(300, 5, fresh, released);
        check(!r.stop(1, released) && released == 0 && r.state() == RecvState::ResetRead && !r.read_end(),
              "stopping a reset stream gave something back twice, or left its end");
    }
    {
        // \~english Already ended: nothing changes.  \~spanish Ya acabado: nada cambia.  \~
        RecvStream r(16384);
        r.on_data(0, b.data(), 10, true, fresh, released);
        r.consume(10);
        r.read_end();
        check(!r.stop(1, released) && released == 0 && r.state() == RecvState::DataRead,
              "stopping an ended stream changed it");
    }
}

/**
 * @brief
 * \~english The end is the application's to take, once, whenever the FIN came (RFC 9000, 3.2, 4.5).
 * \~spanish El final lo recoge la aplicacion, una vez, llegue cuando llegue el FIN (RFC 9000, 3.2, 4.5).
 * \~
 */
void test_end() {
    std::vector<uint8_t> b(100, 7);
    std::vector<uint8_t> out;
    uint64_t fresh = 0;
    const uint8_t *p = nullptr;
    {
        // \~english The FIN alone after every byte was read: an end still to tell.
        // \~spanish El FIN solo tras leerse cada byte: un final aun por decir.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 100, false, fresh);
        check(drain(s, out) == 100 && s.state() == RecvState::Recv && !s.at_end() && !s.read_end(),
              "a stream with no FIN had an end to take");
        check(feed(s, 100, nullptr, 0, true, fresh) == StreamError::None && fresh == 0,
              "a lone FIN at the size already received was refused or charged");
        check(s.state() == RecvState::DataRecvd && s.at_end() && s.peek(p) == 0 && s.chunks_held() == 0,
              "a lone FIN after everything was read did not wait in \"Data Recvd\", nothing to read, memory freed");
        check(feed(s, 100, nullptr, 0, true, fresh) == StreamError::None && fresh == 0 &&
                  s.state() == RecvState::DataRecvd,
              "the same lone FIN twice, before the end was taken, changed something");
        check(s.read_end() && s.state() == RecvState::DataRead, "the end was not taken");
        check(!s.read_end() && s.state() == RecvState::DataRead, "the end was taken twice");
        check(feed(s, 100, nullptr, 0, true, fresh) == StreamError::None && fresh == 0 &&
                  s.state() == RecvState::DataRead && s.at_end(),
              "the same lone FIN once more, after the end was taken, changed something");
        check(feed(s, 90, b.data(), 10, true, fresh) == StreamError::None && fresh == 0,
              "a late retransmission of the last bytes with the FIN was refused");
    }
    {
        // \~english The FIN alone before the bytes were read: the end comes after them.
        // \~spanish El FIN solo antes de leerse los bytes: el final llega despues de ellos.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 100, false, fresh);
        feed(s, 100, nullptr, 0, true, fresh);
        check(s.state() == RecvState::DataRecvd && !s.at_end() && !s.read_end() &&
                  s.state() == RecvState::DataRecvd,
              "the end was taken with bytes still unread");
        check(s.peek(p) == 100, "the bytes were not there to read");
        s.consume(60);
        check(!s.at_end() && !s.read_end(), "the end was taken with 40 bytes unread");
        s.consume(40);
        check(s.at_end() && s.chunks_held() == 0 && s.read_end() && s.state() == RecvState::DataRead,
              "reading the last byte did not leave the end to take");
    }
    {
        // \~english The FIN with the data, read at once: as always.
        // \~spanish El FIN con los datos, leido de una vez: como siempre.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 100, true, fresh);
        check(s.state() == RecvState::DataRecvd && fresh == 100, "the FIN with the data did not end the receiving");
        check(drain(s, out) == 100 && s.at_end() && s.read_end() && s.state() == RecvState::DataRead,
              "reading it all did not end the stream");
    }
    {
        // \~english A FIN past what arrived: the size is known, the hole still to come.
        // \~spanish Un FIN mas alla de lo que llego: el tamano se sabe, el hueco aun por llegar.  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 50, false, fresh);
        drain(s, out);
        check(feed(s, 80, nullptr, 0, true, fresh) == StreamError::None && fresh == 30 &&
                  s.state() == RecvState::SizeKnown && !s.at_end() && !s.read_end(),
              "a lone FIN past the data received was not charged, or ended the stream");
        feed(s, 50, b.data(), 30, false, fresh);
        check(fresh == 0 && s.state() == RecvState::DataRecvd && drain(s, out) == 30 && s.read_end(),
              "the hole filled did not end the stream");
    }
    {
        // \~english A lone FIN that contradicts what arrived: FINAL_SIZE_ERROR (4.5).
        // \~spanish Un FIN solo que contradice lo que llego: FINAL_SIZE_ERROR (4.5).  \~
        RecvStream s(4096);
        feed(s, 0, b.data(), 100, false, fresh);
        drain(s, out);
        check(feed(s, 99, nullptr, 0, true, fresh) == StreamError::FinalSize,
              "a lone FIN below the data received was taken");
        feed(s, 100, nullptr, 0, true, fresh);
        check(feed(s, 101, nullptr, 0, true, fresh) == StreamError::FinalSize,
              "a second lone FIN past the final size was taken");
        check(feed(s, 99, nullptr, 0, true, fresh) == StreamError::FinalSize,
              "a second lone FIN before the final size was taken");
        s.read_end();
        check(feed(s, 101, nullptr, 0, true, fresh) == StreamError::FinalSize,
              "a lone FIN that moves the final size was taken once the end was read");
    }
}

/// \~english One-byte fragments across the whole window: no cap to reach, memory bounded.
/// \~spanish Fragmentos de un byte por toda la ventana: ningun tope que alcanzar, memoria acotada.  \~
void test_fragments() {
    RecvStream s(32768);
    const uint8_t one = 0xee;
    uint64_t fresh = 0;
    bool ok = true;
    for (uint64_t off = 1; off < 32768; off += 2)
        ok = ok && feed(s, off, &one, 1, false, fresh) == StreamError::None;
    check(ok, "one-byte fragments were refused");
    check(s.chunks_held() <= 32768 / kRecvChunk + 1, "fragments took more chunks than the window");

    const uint8_t *p = nullptr;
    check(s.peek(p) == 0, "a hole at offset 0 still let bytes be read");
    for (uint64_t off = 0; off < 32768; off += 2) feed(s, off, &one, 1, false, fresh);
    std::vector<uint8_t> out;
    check(drain(s, out) == 32768, "filling every hole did not make the window readable");
}

} // namespace

int main() {
    test_in_order_across_chunks();
    test_reassembly_property();
    test_flow_control();
    test_final_size();
    test_reset();
    test_stop();
    test_end();
    test_abandon();
    test_fragments();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic stream receive: OK\n");
    return 0;
}
