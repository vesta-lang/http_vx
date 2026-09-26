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
    check(s.on_data(0, msg.data(), msg.size(), false, fresh) == StreamError::None && fresh == 10000,
          "10000 bytes in order were not taken");
    check(s.chunks_held() == 3, "10000 bytes do not sit in three chunks");

    // \~english peek gives at most a chunk: 4096, 4096, 1808.
    // \~spanish peek da como mucho un trozo: 4096, 4096, 1808.  \~
    const uint8_t *p = nullptr;
    check(s.peek(p) == 4096, "the first peek is not the first chunk");
    std::vector<uint8_t> out;
    check(drain(s, out) == 10000 && out == msg, "the bytes did not come out as they went in");
    check(s.chunks_held() == 1, "chunks read past were not freed");

    check(s.on_data(10000, nullptr, 0, true, fresh) == StreamError::None && fresh == 0 &&
              s.state() == RecvState::DataRead && s.chunks_held() == 0,
          "an empty FIN at the end did not finish the stream and free it");
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
            if (s.on_data(g.off, msg.data() + g.off, g.len, fin, fresh) != StreamError::None) {
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

        if (out != msg || s.state() != RecvState::DataRead || s.chunks_held() != 0 ||
            charged != size) {
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

    check(s.on_data(0, buf.data(), 8192, false, fresh) == StreamError::None,
          "data ending exactly at the limit was refused");
    check(s.on_data(8192, buf.data(), 1, false, fresh) == StreamError::FlowControl &&
              transport_error_of(StreamError::FlowControl) == TransportError::FlowControlError,
          "one byte past the limit was not a FLOW_CONTROL_ERROR");

    // \~english A window that is not whole chunks: the limit is still exactly it (4.1, 19.10).
    // \~spanish Una ventana que no son trozos enteros: el limite sigue siendo exactamente ella (4.1, 19.10).  \~
    {
        RecvStream odd(1000);
        uint64_t f2 = 0;
        check(odd.on_data(0, buf.data(), 1000, false, f2) == StreamError::None,
              "data up to an odd window was refused");
        check(odd.on_data(1000, buf.data(), 1, false, f2) == StreamError::FlowControl,
              "one byte past an odd window was let through: the limit was rounded up");
    }

    check(!s.wants_update(), "an update was wanted before anything was read");
    const uint8_t *p = nullptr;
    s.consume(s.peek(p));
    check(!s.wants_update(), "an update was wanted after reading less than half");
    s.consume(s.peek(p));
    check(s.wants_update() && s.advertise() == 8192 + 8192 && s.limit() == 16384,
          "reading the window did not move the limit a window past what was read");
    check(s.on_data(8192, buf.data(), 8192, false, fresh) == StreamError::None,
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
        s.on_data(0, b, 100, true, fresh);
        check(s.on_data(0, b, 100, true, fresh) == StreamError::None, "the same FIN twice was refused");
        check(s.on_data(100, b, 1, false, fresh) == StreamError::FinalSize, "data past the final size");
        check(s.on_data(0, b, 90, true, fresh) == StreamError::FinalSize, "a FIN moved back");
        check(s.on_data(50, b, 60, true, fresh) == StreamError::FinalSize, "a FIN moved forward");
        check(transport_error_of(StreamError::FinalSize) == TransportError::FinalSizeError,
              "FinalSize does not close with FINAL_SIZE_ERROR");
    }
    {
        RecvStream s(4096);
        s.on_data(0, b, 200, false, fresh);
        check(s.on_data(100, b, 50, true, fresh) == StreamError::FinalSize,
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
        s.on_data(0, b.data(), 1000, false, fresh);
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
        check(s.on_data(1000, b.data(), 100, false, fresh) == StreamError::None && fresh == 0,
              "a late retransmission after a reset was not quietly dropped");
        check(s.on_data(1400, b.data(), 200, false, fresh) == StreamError::FinalSize,
              "data past a reset's final size was taken");
        check(s.on_reset(1400, 7, fresh, released) == StreamError::FinalSize,
              "a second reset with another final size was taken");
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
        s.on_data(0, b.data(), 100, true, fresh);
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
        check(!s.stop_pending() && !s.stopped(), "nothing owed before asking");
        check(s.stop(0x10c), "stopping in \"Recv\" was refused");
        check(s.stop_pending() && s.stopped() && s.stop_code() == 0x10c, "the STOP_SENDING and its code are not owed");
        check(!s.stop(0x10b), "asking twice was taken");
        s.on_stop_sent();
        check(!s.stop_pending(), "still owed once sent");
        s.on_stop_lost();
        check(s.stop_pending(), "not owed again once lost");
        s.on_data(0, b.data(), 100, false, fresh);
        check(s.stop_pending(), "data after asking does not change what is owed");
        s.on_data(100, b.data(), 0, true, fresh);
        check(s.state() == RecvState::DataRecvd && !s.stop_pending(),
              "once everything arrived, a STOP_SENDING is pointless and not owed (3.5)");
    }
    {
        RecvStream s(4096);
        s.on_data(0, b.data(), 10, true, fresh);
        check(!s.stop(1) && !s.stopped(), "stopping after all data arrived was taken");
    }
    {
        RecvStream s(4096);
        s.on_data(0, b.data(), 10, false, fresh);
        s.on_data(50, b.data(), 0, true, fresh);
        check(s.state() == RecvState::SizeKnown && s.stop(1), "stopping in \"Size Known\" was refused");
        s.on_stop_sent();
        s.on_reset(50, 1, fresh, released);
        s.on_stop_lost();
        check(!s.stop_pending(), "a reset arrived: a lost STOP_SENDING is not sent again (3.5)");
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
        ok = ok && s.on_data(off, &one, 1, false, fresh) == StreamError::None;
    check(ok, "one-byte fragments were refused");
    check(s.chunks_held() <= 32768 / kRecvChunk + 1, "fragments took more chunks than the window");

    const uint8_t *p = nullptr;
    check(s.peek(p) == 0, "a hole at offset 0 still let bytes be read");
    for (uint64_t off = 0; off < 32768; off += 2) s.on_data(off, &one, 1, false, fresh);
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
    test_fragments();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic stream receive: OK\n");
    return 0;
}
