/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_ack.cpp
 * @brief
 * \~english The received side of a packet number space: duplicates, ranges, and when to acknowledge.
 * \~spanish El lado de recepcion de un espacio de numeros de paquete: duplicados, rangos, y cuando confirmar.
 * \~
 *
 * \~english
 * The rules of RFC 9000, 13.2 one by one, and then a property against a
 * plain model: after any sequence of arrivals -- reordered, duplicated,
 * with holes, with more holes than the tracker has room for -- the ranges
 * hold EXACTLY the packets received at or above the floor, and a packet is
 * new exactly when the model says it is.  A tracker that forgot a received
 * packet would acknowledge less than it got; one that invented a packet
 * would acknowledge something never received -- and the peer would drop its
 * retransmission of data this end never saw.
 * \~spanish
 * Las reglas del RFC 9000, 13.2 una a una, y despues una propiedad contra un
 * modelo sencillo: tras cualquier secuencia de llegadas -- desordenadas,
 * duplicadas, con huecos, con mas huecos de los que le caben al seguidor --, los
 * rangos tienen EXACTAMENTE los paquetes recibidos en o por encima del suelo, y
 * un paquete es nuevo justo cuando el modelo dice que lo es.  Un seguidor que
 * olvidara un paquete recibido confirmaria menos de lo que recibio; uno que se
 * inventara un paquete confirmaria algo que nunca llego -- y el otro extremo
 * dejaria de retransmitir datos que este extremo no vio nunca.
 * \~
 */

#include "http_vx/quic_ack.h"

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

/// \~english Reads back the ACK @p t writes, as ranges.  \~spanish Lee de vuelta el ACK que escribe @p t, como rangos.  \~
size_t written_ranges(const AckTracker &t, uint64_t now, AckRange *out, size_t max,
                      Frame &f, size_t room = 512) {
    uint8_t b[512];
    const size_t n = t.write_ack(b, room, now);
    if (n == 0) return 0;
    FrameContext ctx;
    FrameReader r(b, n, ctx);
    if (r.next(f) != FrameReader::Step::Frame || f.type != FrameType::Ack) return 0;
    AckRangeReader ar(b, f);
    size_t k = 0;
    while (k < max && ar.next(out[k])) ++k;
    return k;
}

void test_in_order() {
    AckTracker t;
    for (uint64_t pn = 0; pn < 10; ++pn)
        check(t.on_received(pn, true, Ecn::NotEct, 100 * pn) == Receipt::New, "a new packet was not new");
    check(t.ranges() == 1 && t.range(0).smallest == 0 && t.range(0).largest == 9,
          "ten packets in order are not the one range [0, 9]");
    check(t.largest() == 9 && t.expected_pn() == 10, "the largest is not 9");

    AckRange r[4];
    Frame f;
    check(written_ranges(t, 1000, r, 4, f) == 1 && r[0].smallest == 0 && r[0].largest == 9,
          "the ACK written does not say [0, 9]");
    check(t.on_received(5, true, Ecn::NotEct, 1000) == Receipt::Duplicate &&
              t.classify(5) == Receipt::Duplicate && t.classify(10) == Receipt::New,
          "a duplicate was not recognised");
}

/// \~english 13.2.1 and 13.2.2: when an ACK must go out now, and when it may wait.
/// \~spanish 13.2.1 y 13.2.2: cuando un ACK tiene que salir ya, y cuando puede esperar.  \~
void test_when_to_acknowledge() {
    AckPolicy p;
    p.max_ack_delay_us = 25000;

    {
        AckTracker t(p);
        t.on_received(0, true, Ecn::NotEct, 1000);
        check(!t.ack_now() && t.ack_deadline() == 1000 + 25000,
              "one ack-eliciting packet did not wait for max_ack_delay");
        t.on_received(1, true, Ecn::NotEct, 1500);
        check(t.ack_now() && t.ack_deadline() == 0, "the second ack-eliciting packet did not ack now");
        t.on_ack_sent();
        check(!t.ack_now() && t.ack_deadline() == kNever, "an ACK sent still left one owed");
    }
    {
        AckTracker t(p);
        t.on_received(0, false, Ecn::NotEct, 0);
        t.on_received(1, false, Ecn::NotEct, 0);
        t.on_received(5, false, Ecn::NotEct, 0);
        check(!t.ack_now() && t.ack_deadline() == kNever,
              "packets that elicit nothing made an ACK owed -- an endless ACK loop");
    }
    {
        AckTracker t(p);
        t.on_received(0, true, Ecn::NotEct, 0);
        t.on_ack_sent();
        t.on_received(3, true, Ecn::NotEct, 0);
        check(t.ack_now(), "a hole below a new packet did not ack now");
        t.on_ack_sent();
        t.on_received(2, true, Ecn::NotEct, 0);
        check(t.ack_now(), "a packet arriving out of order did not ack now");
    }
    {
        AckTracker t(p);
        t.on_received(0, true, Ecn::Ce, 0);
        check(t.ack_now(), "a CE-marked packet did not ack now");
        t.on_ack_sent();
        t.on_received(1, false, Ecn::Ce, 0);
        check(!t.ack_now(), "a CE-marked packet that elicits nothing made an ACK owed");
    }
    {
        AckPolicy handshake = p;
        handshake.immediate = true;
        AckTracker t(handshake);
        t.on_received(0, true, Ecn::NotEct, 0);
        check(t.ack_now(), "an Initial or Handshake packet was not acked at once");
    }
}

void test_reordering_and_merging() {
    AckTracker t;
    const uint64_t order[] = {0, 1, 5, 3, 9, 4, 2};
    for (uint64_t pn : order) t.on_received(pn, true, Ecn::NotEct, 0);

    // \~english 0-5 joined up once 4 and 2 arrived; 9 stands alone.
    // \~spanish 0-5 se juntaron al llegar 4 y 2; 9 queda solo.  \~
    check(t.ranges() == 2 && t.range(0).smallest == 9 && t.range(0).largest == 9 &&
              t.range(1).smallest == 0 && t.range(1).largest == 5,
          "reordered packets did not merge into [9, 9] and [0, 5]");

    t.on_received(7, true, Ecn::NotEct, 0);
    t.on_received(8, true, Ecn::NotEct, 0);
    t.on_received(6, true, Ecn::NotEct, 0);
    check(t.ranges() == 1 && t.range(0).smallest == 0 && t.range(0).largest == 9,
          "filling every hole did not leave one range");
}

/// \~english The ACK delay and the ECN counts, as written.
/// \~spanish El retraso del ACK y las cuentas ECN, tal como se escriben.  \~
void test_delay_and_ecn() {
    AckPolicy p;
    p.ack_delay_exponent = 3;
    AckTracker t(p);
    t.on_received(0, true, Ecn::Ect0, 1000);
    t.on_received(1, true, Ecn::Ect0, 2000);
    t.on_received(2, true, Ecn::Ce, 2200);

    AckRange r[2];
    Frame f;
    check(written_ranges(t, 3000, r, 2, f) == 1 && f.ack_delay == (3000 - 2200) / 8,
          "the ACK delay is not the time since the largest, scaled by 2^3");
    check(f.has_ecn && f.ecn[0] == 2 && f.ecn[1] == 0 && f.ecn[2] == 1,
          "the ECN counts are not ECT0=2, ECT1=0, CE=1");

    AckTracker plain;
    plain.on_received(0, true, Ecn::NotEct, 0);
    check(written_ranges(plain, 0, r, 2, f) == 1 && !f.has_ecn,
          "an ACK with no ECN-marked packet carried ECN counts");

    check(written_ranges(t, 1000, r, 2, f) == 1 && f.ack_delay == 0,
          "a clock behind the largest gave a delay other than zero");
}

/// \~english More holes than ranges: the lowest go, the floor rises, and it is counted.
/// \~spanish Mas huecos que rangos: los mas bajos se van, el suelo sube, y se cuenta.  \~
void test_bounded_memory() {
    // \~english Every third packet: 0, 3, 6 ... each one its own range.
    // \~spanish Uno de cada tres paquetes: 0, 3, 6 ... cada uno su propio rango.  \~
    AckTracker t;
    for (uint64_t pn = 0; pn < 3 * (kAckRanges + 4); pn += 3)
        t.on_received(pn, false, Ecn::NotEct, 0);

    check(t.ranges() == kAckRanges, "the tracker holds more ranges than it has room for");
    check(t.ranges_evicted() == 4, "the dropped ranges were not counted");
    check(t.floor() == 10, "the floor did not rise past the four dropped ranges");
    check(t.classify(0) == Receipt::TooOld && t.classify(8) == Receipt::TooOld,
          "a packet below the floor was not refused");
    check(t.classify(10) == Receipt::New, "the first packet at the floor was refused");

    // \~english A new range that would be the lowest is the one forgotten.
    // \~spanish Un rango nuevo que seria el mas bajo es el que se olvida.  \~
    const uint64_t before = t.ranges_evicted();
    check(t.on_received(10, false, Ecn::NotEct, 0) == Receipt::New && t.ranges() == kAckRanges &&
              t.ranges_evicted() == before + 1 && t.classify(10) == Receipt::TooOld,
          "a new lowest range was kept past the limit");
}

/// \~english 13.2.3: an ACK that does not fit loses its oldest ranges, never the largest.
/// \~spanish 13.2.3: un ACK que no cabe pierde sus rangos mas viejos, nunca el del mayor.  \~
void test_ack_that_does_not_fit() {
    AckTracker t;
    for (uint64_t pn = 0; pn < 20; pn += 2) t.on_received(pn, true, Ecn::NotEct, 0);

    AckRange r[16];
    Frame f;
    const size_t all = written_ranges(t, 0, r, 16, f);
    check(all == 10, "the ACK does not carry the ten ranges");

    const size_t some = written_ranges(t, 0, r, 16, f, 9);
    check(some >= 1 && some < 10 && r[0].largest == 18,
          "a short ACK did not keep the newest ranges");

    uint8_t tiny[3];
    check(t.write_ack(tiny, sizeof tiny, 0) == 0, "an ACK was written into three bytes");

    AckTracker empty;
    uint8_t b[64];
    check(empty.write_ack(b, sizeof b, 0) == 0, "an ACK was written with nothing received");
}

/// \~english 13.2.4: once the peer saw an ACK, what it covered is not acknowledged again.
/// \~spanish 13.2.4: cuando el otro extremo vio un ACK, lo que cubria no se vuelve a confirmar.  \~
void test_ack_of_ack() {
    AckTracker t;
    for (uint64_t pn = 0; pn < 10; ++pn) t.on_received(pn, true, Ecn::NotEct, 0);
    t.on_received(20, true, Ecn::NotEct, 0);

    t.on_ack_acknowledged(5);
    check(t.ranges() == 2 && t.range(1).smallest == 6 && t.range(1).largest == 9,
          "the range under the acknowledged ACK was not cut at 5");
    check(t.classify(3) == Receipt::TooOld && t.floor() == 6,
          "packets the peer knows were acknowledged are accepted again");

    t.on_ack_acknowledged(20);
    check(t.ranges() == 0 && t.largest() == 20 && t.expected_pn() == 21,
          "dropping every range lost the largest, which decoding still needs");
    uint8_t b[64];
    check(t.write_ack(b, sizeof b, 0) == 0, "an ACK was written for ranges already acknowledged");

    t.on_received(21, true, Ecn::NotEct, 0);
    check(t.ranges() == 1 && t.range(0).smallest == 21, "a new packet after it did not start a range");
}

/**
 * @brief
 * \~english The property: the ranges are exactly what was received above the floor.
 * \~spanish La propiedad: los rangos son exactamente lo recibido por encima del suelo.
 * \~
 */
void test_against_a_model() {
    std::mt19937_64 rng(13);
    for (int round = 0; round < 300; ++round) {
        AckTracker t;
        std::set<uint64_t> got;
        const uint64_t span = 20 + rng() % 400;

        for (int step = 0; step < 600; ++step) {
            // \~english Mostly forwards with jitter, sometimes far back, sometimes an ack of acks.
            // \~spanish Casi siempre hacia delante con vaiven, a veces muy atras, a veces un ack de acks.  \~
            const uint64_t pn = (static_cast<uint64_t>(step) * span / 600 + rng() % 24) % (span + 24);
            if (rng() % 97 == 0 && t.any()) t.on_ack_acknowledged(pn % (t.largest() + 1));

            const Receipt want = pn < t.floor() ? Receipt::TooOld
                                 : got.count(pn) ? Receipt::Duplicate
                                                 : Receipt::New;
            const Receipt r = t.on_received(pn, (rng() & 1) != 0, Ecn::NotEct, step);
            if (r != want) {
                std::fprintf(stderr, "FAIL: packet %llu classified %d, the model says %d\n",
                             static_cast<unsigned long long>(pn), static_cast<int>(r),
                             static_cast<int>(want));
                ++failures;
                return;
            }
            if (r == Receipt::New) got.insert(pn);

            // \~english Ranges: ordered, apart, above the floor, and exactly the model.
            // \~spanish Los rangos: ordenados, separados, sobre el suelo, y exactamente el modelo.  \~
            uint64_t held = 0;
            for (size_t i = 0; i < t.ranges(); ++i) {
                const AckRange &a = t.range(i);
                const bool shape = a.smallest <= a.largest && a.smallest >= t.floor() &&
                                   (i == 0 || a.largest + 2 <= t.range(i - 1).smallest);
                bool all_in = true;
                for (uint64_t x = a.smallest; x <= a.largest; ++x) all_in = all_in && got.count(x);
                if (!shape || !all_in) {
                    std::fprintf(stderr, "FAIL: range %zu [%llu, %llu] is malformed or invented\n", i,
                                 static_cast<unsigned long long>(a.smallest),
                                 static_cast<unsigned long long>(a.largest));
                    ++failures;
                    return;
                }
                held += a.largest - a.smallest + 1;
            }
            uint64_t expected = 0;
            for (uint64_t x : got) expected += x >= t.floor() ? 1 : 0;
            if (held != expected) {
                std::fprintf(stderr, "FAIL: the ranges hold %llu packets, %llu were received above the floor\n",
                             static_cast<unsigned long long>(held),
                             static_cast<unsigned long long>(expected));
                ++failures;
                return;
            }
        }
    }
}

} // namespace

int main() {
    test_in_order();
    test_when_to_acknowledge();
    test_reordering_and_merging();
    test_delay_and_ecn();
    test_bounded_memory();
    test_ack_that_does_not_fit();
    test_ack_of_ack();
    test_against_a_model();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic ack tracking: OK\n");
    return 0;
}
