/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_stream_send.cpp
 * @brief
 * \~english The sending part of a stream, and both halves across a network that loses and reorders.
 * \~spanish La parte emisora de un flujo, y las dos mitades a traves de una red que pierde y desordena.
 * \~
 *
 * \~english
 * The central case joins the two halves: a sender and a receiver across a
 * simulated network that loses, reorders, duplicates, and sometimes loses
 * only in the sender's mind -- a packet declared lost that arrives anyway.
 * Whatever happens, the receiver has to read exactly what was written, both
 * sides have to end in their terminal state, and no memory may be left.
 * \~spanish
 * El caso central junta las dos mitades: un emisor y un receptor a traves de una
 * red simulada que pierde, desordena, duplica, y a veces pierde solo en la
 * cabeza del emisor -- un paquete declarado perdido que llega igualmente.  Pase
 * lo que pase, el receptor tiene que leer exactamente lo que se escribio, los
 * dos lados tienen que acabar en su estado terminal, y no puede quedar memoria.
 * \~
 */

#include "http_vx/quic_stream_send.h"

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

std::vector<uint8_t> pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i * 31 + 7);
    return v;
}

/// \~english Sends one piece and returns it.  \~spanish Manda un trozo y lo devuelve.  \~
bool send_one(SendStream &s, StreamPiece &p, size_t max_len, uint64_t credit = 1u << 30) {
    if (!s.next(p, max_len, credit)) return false;
    s.on_sent(p);
    return true;
}

void test_basic() {
    SendStream s(65536, 1u << 20);
    const std::vector<uint8_t> msg = pattern(10000);
    size_t took = 0;
    check(s.write(msg.data(), msg.size(), took) == StreamError::None && took == 10000,
          "10000 bytes were not all taken");
    check(s.state() == SendState::Ready && s.chunks_held() == 3, "the data does not sit in three chunks");

    StreamPiece p;
    uint64_t expect = 0;
    while (send_one(s, p, 1200)) {
        if (p.offset != expect || p.retransmit || std::memcmp(p.data, msg.data() + p.offset, p.len) != 0) {
            check(false, "a new piece is not the next bytes in order");
            return;
        }
        expect += p.len;
    }
    check(expect == 10000 && s.sent() == 10000 && s.state() == SendState::Send,
          "not everything went out once");

    s.on_acked(0, 5000, false);
    check(s.acked() == 5000 && s.chunks_held() == 2, "acknowledging the first 5000 did not free a chunk");
    s.on_acked(5000, 5000, false);
    check(s.acked() == 10000 && s.chunks_held() == 1 && s.state() == SendState::Send,
          "acknowledging everything unfinished ended the stream");

    s.finish();
    check(send_one(s, p, 1200) && p.fin && p.len == 0 && p.offset == 10000 && !p.retransmit,
          "finishing after everything went did not send a FIN on its own");
    check(s.state() == SendState::DataSent, "a sent FIN did not move to Data Sent");
    s.on_acked(10000, 0, true);
    check(s.state() == SendState::DataRecvd && s.chunks_held() == 0,
          "an acknowledged FIN did not end the stream and free it");
}

/// \~english 4.1: the stream's limit and the connection's credit.
/// \~spanish 4.1: el limite del flujo y el credito de la conexion.  \~
void test_flow_control() {
    SendStream s(65536, 3000);
    const std::vector<uint8_t> msg = pattern(8000);
    size_t took = 0;
    s.write(msg.data(), msg.size(), took);

    StreamPiece p;
    uint64_t sent = 0;
    while (send_one(s, p, 1200)) sent += p.len;
    check(sent == 3000 && s.blocked(), "the stream went past its limit, or did not say it was blocked");
    s.on_max_stream_data(2000);
    check(s.limit() == 3000 && !s.next(p, 1200, 1u << 30), "a lower MAX_STREAM_DATA changed the limit");
    s.on_max_stream_data(5000);
    check(!s.blocked() && send_one(s, p, 1200) && p.offset == 3000, "a raised limit did not let data through");

    check(s.next(p, 1200, 500) && p.len == 500, "connection credit did not bound new data");
    check(!s.next(p, 1200, 0), "new data went out with no connection credit");

    // \~english A retransmission is free: it goes even with no credit at all.
    // \~spanish Una retransmision es gratis: sale incluso sin credito ninguno.  \~
    s.on_lost(0, 1200, false);
    check(s.next(p, 1200, 0) && p.retransmit && p.offset == 0 && p.len == 1200,
          "a retransmission was held back by connection credit");
}

void test_loss_and_retransmission() {
    SendStream s(65536, 1u << 20);
    const std::vector<uint8_t> msg = pattern(6000);
    size_t took = 0;
    s.write(msg.data(), msg.size(), took);

    StreamPiece p;
    for (int i = 0; i < 3; ++i) send_one(s, p, 1000);
    s.on_acked(0, 1000, false);
    s.on_lost(1000, 1000, false);
    s.on_acked(2000, 1000, false);

    check(s.to_resend() == 1000 && s.next(p, 1200, 1u << 30) && p.retransmit &&
              p.offset == 1000 && p.len == 1000 &&
              std::memcmp(p.data, msg.data() + 1000, 1000) == 0,
          "the lost middle was not the next thing to go, before new data");
    s.on_sent(p);
    check(s.to_resend() == 0 && s.next(p, 1200, 1u << 30) && !p.retransmit && p.offset == 3000,
          "after the retransmission, new data did not follow");

    /* \~english
     * A piece never crosses a chunk -- its data has to be contiguous -- so the
     * one at 3000 stops at 4096, 1096 bytes, not 1200.
     * \~spanish
     * Un trozo no cruza nunca un trozo de memoria -- sus datos tienen que ser
     * contiguos --, asi que el de 3000 se para en 4096, 1096 bytes, no 1200.
     * \~ */
    check(p.len == 1096, "a piece crossed a chunk boundary");

    // \~english Lost only in the sender's mind: acknowledged after all, nothing to resend.
    // \~spanish Perdido solo en la cabeza del emisor: confirmado al final, nada que reenviar.  \~
    s.on_sent(p);
    s.on_lost(p.offset, p.len, false);
    s.on_acked(p.offset, p.len, false);
    check(s.to_resend() == 0 && s.next(p, 1200, 1u << 30) && !p.retransmit,
          "a packet acknowledged after being declared lost was still resent");

    // \~english The last hole filled: the prefix joins up to everything sent.
    // \~spanish El ultimo hueco relleno: el prefijo se junta hasta todo lo mandado.  \~
    s.on_acked(1000, 1000, false);
    check(s.acked() == 4096 && s.acked() == s.sent(), "the acknowledged prefix did not join up to 4096");
}

void test_fin_rules() {
    {
        SendStream s(65536, 1u << 20);
        const std::vector<uint8_t> msg = pattern(100);
        size_t took = 0;
        s.write(msg.data(), msg.size(), took);
        s.finish();
        StreamPiece p;
        check(send_one(s, p, 1200) && p.fin && p.len == 100, "the last data did not carry the FIN");

        s.on_lost(0, 100, true);
        check(s.next(p, 1200, 0) && p.retransmit && p.fin && p.len == 100,
              "the lost last piece was not resent with its FIN");
        s.on_sent(p);
        s.on_acked(0, 100, true);
        check(s.state() == SendState::DataRecvd, "the stream did not end once everything was acknowledged");
    }
    {
        SendStream s(65536, 1u << 20);
        const std::vector<uint8_t> msg = pattern(100);
        size_t took = 0;
        s.write(msg.data(), msg.size(), took);
        StreamPiece p;
        send_one(s, p, 1200);
        s.finish();
        send_one(s, p, 1200);
        s.on_acked(0, 100, false);
        s.on_lost(100, 0, true);
        check(s.next(p, 1200, 0) && p.fin && p.len == 0 && p.retransmit,
              "a lost FIN on its own was not sent again on its own");
        size_t more = 0;
        s.write(msg.data(), 10, more);
        check(more == 0, "data was written after the stream finished");
    }
}

void test_capacity() {
    SendStream s(4096, 1u << 20);
    const std::vector<uint8_t> msg = pattern(10000);
    size_t took = 0;
    s.write(msg.data(), msg.size(), took);
    check(took == 4096, "the stream took more than its capacity");

    StreamPiece p;
    send_one(s, p, 1000);
    s.write(msg.data(), 1000, took);
    check(took == 0, "sending without acknowledgement made room");
    s.on_acked(0, 1000, false);
    s.write(msg.data(), 5000, took);
    check(took == 1000, "acknowledging 1000 bytes did not make room for exactly 1000");
}

/// \~english RESET_STREAM and STOP_SENDING (3.1, 3.5, 4.5).
/// \~spanish RESET_STREAM y STOP_SENDING (3.1, 3.5, 4.5).  \~
void test_reset() {
    SendStream s(65536, 1u << 20);
    const std::vector<uint8_t> msg = pattern(9000);
    size_t took = 0;
    s.write(msg.data(), msg.size(), took);
    StreamPiece p;
    for (int i = 0; i < 5; ++i) send_one(s, p, 1000);

    // \~english Four of 1000 and one cut at the chunk: 4096 sent.
    // \~spanish Cuatro de 1000 y uno cortado en el trozo: 4096 mandados.  \~
    s.reset(9);
    check(s.state() == SendState::ResetSent && s.reset_pending() && s.final_size() == 4096 &&
              s.reset_code() == 9 && s.chunks_held() == 0,
          "a reset did not owe a RESET_STREAM with the highest offset sent, and free the data");
    check(!s.next(p, 1200, 1u << 30), "a reset stream still sent data");

    s.on_reset_sent();
    s.on_reset_lost();
    check(s.reset_pending(), "a lost RESET_STREAM was not owed again");
    s.on_reset_sent();
    s.on_reset_acked();
    check(s.state() == SendState::ResetRecvd && !s.reset_pending(), "an acknowledged reset did not end");

    SendStream t(65536, 1u << 20);
    t.on_stop_sending(0x10c);
    check(t.state() == SendState::ResetSent && t.reset_code() == 0x10c && t.final_size() == 0,
          "STOP_SENDING did not reset the stream with its code (3.5)");
}

/**
 * @brief
 * \~english Sender and receiver across a lossy, reordering, duplicating network.
 * \~spanish Emisor y receptor a traves de una red que pierde, desordena y duplica.
 * \~
 */
void test_end_to_end() {
    std::mt19937 rng(9000);
    for (int round = 0; round < 150; ++round) {
        const size_t size = rng() % 120000;
        const std::vector<uint8_t> msg = pattern(size);
        const uint64_t window = 32768;

        SendStream tx(16384, window);
        RecvStream rx(window);
        SendFlow flow(1u << 30);

        struct Flight {
            uint64_t offset;
            std::vector<uint8_t> data;
            bool fin;
        };
        std::vector<Flight> air;
        std::vector<uint8_t> out;
        size_t written = 0;
        int guard = 0;

        while (tx.state() != SendState::DataRecvd && ++guard < 200000) {
            // \~english Write what fits; finish once everything is written.
            // \~spanish Escribir lo que quepa; terminar cuando todo este escrito.  \~
            if (written < size) {
                size_t took = 0;
                tx.write(msg.data() + written, size - written, took);
                written += took;
            }
            if (written == size) tx.finish();

            StreamPiece p;
            for (int k = 0; k < 4 && tx.next(p, 1 + rng() % 1500, flow.credit()); ++k) {
                air.push_back({p.offset, std::vector<uint8_t>(p.data, p.data + p.len), p.fin});
                if (!p.retransmit) flow.on_sent(p.len);
                tx.on_sent(p);
            }

            // \~english The network: any order, some lost, some twice, some lost only in the sender's mind.
            // \~spanish La red: cualquier orden, algunos perdidos, algunos dos veces, algunos perdidos solo en la cabeza del emisor.  \~
            for (int k = 0; k < 3 && !air.empty(); ++k) {
                const size_t i = rng() % air.size();
                Flight f = air[i];
                air[i] = air.back();
                air.pop_back();

                const unsigned fate = rng() % 10;
                if (fate < 2) {
                    tx.on_lost(f.offset, f.data.size(), f.fin);
                    continue;
                }
                uint64_t fresh = 0;
                if (rx.on_data(f.offset, f.data.data(), f.data.size(), f.fin, fresh) != StreamError::None) {
                    check(false, "the receiver refused what the sender sent");
                    return;
                }
                if (fate == 2) tx.on_lost(f.offset, f.data.size(), f.fin);
                tx.on_acked(f.offset, f.data.size(), f.fin);
                if (fate == 3) air.push_back(f);
            }

            const uint8_t *q = nullptr;
            size_t n;
            while ((n = rx.peek(q)) != 0) {
                out.insert(out.end(), q, q + n);
                rx.consume(n);
            }
            if (rx.wants_update()) tx.on_max_stream_data(rx.advertise());
        }

        if (out != msg || tx.state() != SendState::DataRecvd || rx.state() != RecvState::DataRead ||
            tx.chunks_held() != 0 || rx.chunks_held() != 0) {
            std::fprintf(stderr, "FAIL: %zu bytes: got %zu, sender state %d, receiver state %d, chunks %zu/%zu\n",
                         size, out.size(), static_cast<int>(tx.state()), static_cast<int>(rx.state()),
                         tx.chunks_held(), rx.chunks_held());
            ++failures;
            return;
        }
    }
}

} // namespace

int main() {
    test_basic();
    test_flow_control();
    test_loss_and_retransmission();
    test_fin_rules();
    test_capacity();
    test_reset();
    test_end_to_end();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic stream send: OK\n");
    return 0;
}
