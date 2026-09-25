/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_recovery.cpp
 * @brief
 * \~english RFC 9002: RTT, loss detection, probe timeouts and NewReno, with numbers worked by hand.
 * \~spanish RFC 9002: RTT, deteccion de perdidas, plazos de sondeo y NewReno, con numeros hechos a mano.
 * \~
 *
 * \~english
 * Every expected value here is computed in the comment next to it from the
 * RFC's formulas, not taken from the implementation: a test that printed
 * what the code gives and pasted it back would agree with any mistake.
 * \~spanish
 * Cada valor esperado aqui se calcula en el comentario de al lado con las
 * formulas del RFC, no se saca de la implementacion: una prueba que imprimiera
 * lo que da el codigo y lo pegara de vuelta estaria de acuerdo con cualquier
 * error.
 * \~
 */

#include "http_vx/quic_recovery.h"

#include <cstdio>

namespace {

using namespace http_vx::quic;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english Remembers what was acknowledged and lost, by tag.
/// \~spanish Recuerda que se confirmo y que se perdio, por etiqueta.  \~
class Log final : public RecoveryListener {
public:
    uint64_t acked[64];
    uint64_t lost[64];
    uint64_t ack_largest[64];
    size_t n_acked = 0;
    size_t n_lost = 0;

    void on_acked(Space, const SentPacket &p) noexcept override {
        if (n_acked < 64) {
            ack_largest[n_acked] = p.ack_largest;
            acked[n_acked++] = p.tag;
        }
    }
    void on_lost(Space, const SentPacket &p) noexcept override {
        if (n_lost < 64) lost[n_lost++] = p.tag;
    }
    bool was_lost(uint64_t tag) const {
        for (size_t i = 0; i < n_lost; ++i)
            if (lost[i] == tag) return true;
        return false;
    }
    void clear() { n_acked = n_lost = 0; }
};

/// \~english Feeds an ACK of @p ranges to @p r, as it would arrive: written, then read.
/// \~spanish Le da a @p r un ACK de @p ranges, como llegaria: escrito y luego leido.  \~
AckResult ack(Recovery &r, Space s, const AckRange *ranges, size_t count,
              uint64_t delay_field, uint64_t now, Log &log, const uint64_t *ecn = nullptr) {
    uint8_t b[256];
    const size_t n = write_ack(b, sizeof b, ranges, count, delay_field, ecn);
    FrameContext ctx;
    FrameReader reader(b, n, ctx);
    Frame f;
    if (n == 0 || reader.next(f) != FrameReader::Step::Frame) {
        check(false, "the test could not build its ACK");
        return AckResult::Ok;
    }
    return r.on_ack_received(s, f, b, now, log);
}

AckResult ack_one(Recovery &r, Space s, uint64_t pn, uint64_t now, Log &log,
                  uint64_t delay_field = 0) {
    const AckRange one[] = {{pn, pn}};
    return ack(r, s, one, 1, delay_field, now, log);
}

bool send(Recovery &r, Space s, uint64_t pn, uint64_t now, uint32_t bytes = 1200,
          bool eliciting = true) {
    return r.on_packet_sent(s, pn, bytes, eliciting, true, pn, kNever, now);
}

/// \~english 5.3, worked by hand.  \~spanish 5.3, hecho a mano.  \~
void test_rtt() {
    Recovery r;
    Log log;
    const Space app = Space::Application;

    // \~english First sample: 100 ms.  smoothed = 100 ms, rttvar = 50 ms, min = 100 ms.
    // \~spanish Primera muestra: 100 ms.  smoothed = 100 ms, rttvar = 50 ms, min = 100 ms.  \~
    send(r, app, 0, 0);
    ack_one(r, app, 0, 100000, log);
    check(r.latest_rtt() == 100000 && r.smoothed_rtt() == 100000 && r.rttvar() == 50000 &&
              r.min_rtt() == 100000,
          "the first RTT sample did not set smoothed, rttvar and min");

    /* \~english
     * 80 ms with a reported delay of 10 ms (field 1250, exponent 3).  min
     * becomes 80 ms, and 80 < 80 + 10, so the delay is NOT subtracted:
     * rttvar = (3 * 50 + |100 - 80|) / 4 = 42.5 ms,
     * smoothed = (7 * 100 + 80) / 8 = 97.5 ms.
     * \~spanish
     * 80 ms con un retraso anunciado de 10 ms (campo 1250, exponente 3).  min
     * pasa a 80 ms, y 80 < 80 + 10, asi que el retraso NO se resta:
     * rttvar = (3 * 50 + |100 - 80|) / 4 = 42,5 ms,
     * smoothed = (7 * 100 + 80) / 8 = 97,5 ms.
     * \~ */
    send(r, app, 1, 200000);
    ack_one(r, app, 1, 280000, log, 1250);
    check(r.min_rtt() == 80000 && r.rttvar() == 42500 && r.smoothed_rtt() == 97500,
          "an implausible ack delay was subtracted");

    /* \~english
     * 120 ms with 10 ms of delay: 120 >= 80 + 10, so adjusted = 110 ms.
     * rttvar = (3 * 42.5 + |97.5 - 110|) / 4 = 35 ms,
     * smoothed = (7 * 97.5 + 110) / 8 = 99.0625 ms -> 99062 us.
     * \~spanish
     * 120 ms con 10 ms de retraso: 120 >= 80 + 10, asi que ajustado = 110 ms.
     * rttvar = (3 * 42,5 + |97,5 - 110|) / 4 = 35 ms,
     * smoothed = (7 * 97,5 + 110) / 8 = 99,0625 ms -> 99062 us.
     * \~ */
    send(r, app, 2, 300000);
    ack_one(r, app, 2, 420000, log, 1250);
    check(r.rttvar() == 35000 && r.smoothed_rtt() == 99062 && r.min_rtt() == 80000,
          "a plausible ack delay was not subtracted");

    // \~english An ACK of a non-eliciting packet takes no sample.
    // \~spanish Un ACK de un paquete que no pide confirmacion no toma muestra.  \~
    const uint64_t before = r.smoothed_rtt();
    send(r, app, 3, 500000, 50, false);
    ack_one(r, app, 3, 900000, log);
    check(r.smoothed_rtt() == before, "an ACK of an ACK-only packet changed the RTT");
}

/// \~english 6.1: lost by packet count, then by time.  \~spanish 6.1: perdidos por cuenta, y luego por tiempo.  \~
void test_loss_detection() {
    Recovery r;
    Log log;
    const Space app = Space::Application;
    for (uint64_t pn = 0; pn < 5; ++pn) send(r, app, pn, pn * 1000);

    // \~english Only 4 acknowledged: 0 and 1 are three behind; 2 and 3 are not yet.
    // \~spanish Solo se confirma el 4: 0 y 1 van tres por detras; 2 y 3 aun no.  \~
    ack_one(r, app, 4, 50000, log);
    check(log.n_lost == 2 && log.was_lost(0) && log.was_lost(1) && !log.was_lost(2),
          "packet-threshold loss did not take exactly 0 and 1");
    check(r.packets_lost() == 2 && r.bytes_in_flight() == 2 * 1200,
          "lost packets were not taken out of flight");

    /* \~english
     * 2 and 3 wait for time: loss_delay = 9/8 * max(latest, smoothed).  The
     * sample was 50 - 4 = 46 ms, so smoothed = latest = 46 ms and the delay
     * is 51.75 ms: packet 2, sent at 2 ms, is lost at 53.75 ms.
     * \~spanish
     * 2 y 3 esperan al tiempo: loss_delay = 9/8 * max(latest, smoothed).  La
     * muestra fue 50 - 4 = 46 ms, asi que smoothed = latest = 46 ms y el
     * retraso son 51,75 ms: el paquete 2, enviado a los 2 ms, se pierde a los
     * 53,75 ms.
     * \~ */
    check(r.timer() == 2000 + 46000 + 46000 / 8, "the loss timer is not at 53.75 ms");
    log.clear();
    TimeoutAction a = r.on_timeout(r.timer() - 1, log);
    check(a.kind == TimeoutAction::None && log.n_lost == 0, "the loss timer fired early");
    a = r.on_timeout(r.timer(), log);
    check(a.kind == TimeoutAction::Loss && a.space == app && log.n_lost == 1 && log.was_lost(2),
          "time-threshold loss did not take packet 2");
    a = r.on_timeout(r.timer(), log);
    check(a.kind == TimeoutAction::Loss && log.was_lost(3), "time-threshold loss did not take packet 3");
    check(r.bytes_in_flight() == 0, "bytes remained in flight after everything was lost");
}

/// \~english 7: slow start, one reduction per recovery period, and avoidance counted in bytes.
/// \~spanish 7: arranque lento, una reduccion por periodo de recuperacion, y evitacion contada en bytes.  \~
void test_newreno() {
    Recovery r;
    Log log;
    const Space app = Space::Application;

    // \~english 7.2: min(10 * 1200, max(14720, 2400)) = 12000.
    // \~spanish 7.2: min(10 * 1200, max(14720, 2400)) = 12000.  \~
    check(r.congestion_window() == 12000 && r.initial_window() == 12000 && r.minimum_window() == 2400,
          "the initial and minimum windows are not 12000 and 2400");
    check(r.window_allows(12000) && !r.window_allows(12001), "the window did not bound what may go out");

    for (uint64_t pn = 0; pn < 10; ++pn) send(r, app, pn, 1000 + pn);
    ack_one(r, app, 0, 20000, log);
    check(r.congestion_window() == 13200, "slow start did not add the bytes acknowledged");

    // \~english Packets 1 and 2 lost at once (5 acked): one event, halving 13200.
    // \~spanish Paquetes 1 y 2 perdidos a la vez (se confirma 5): un evento, que parte 13200.  \~
    const AckRange five[] = {{5, 5}};
    ack(r, app, five, 1, 0, 30000, log);
    check(r.congestion_events() == 1 && r.ssthresh() == 6600 && r.congestion_window() == 6600,
          "a loss did not halve the window into ssthresh");

    // \~english 3 and 4, sent before recovery began, are lost too: no second halving.
    // \~spanish 3 y 4, enviados antes de empezar la recuperacion, tambien se pierden: sin segunda reduccion.  \~
    const AckRange eight[] = {{8, 8}};
    ack(r, app, eight, 1, 0, 31000, log);
    check(r.congestion_events() == 1 && r.congestion_window() == 6600,
          "losses from inside the recovery period halved the window again");

    /* \~english
     * Congestion avoidance: cwnd 6600 grows by one datagram once 6600 bytes
     * are acknowledged -- six packets of 1200 is 7200, so it grows once.
     * \~spanish
     * Evitacion de congestion: cwnd 6600 crece un datagrama cuando se
     * confirman 6600 bytes -- seis paquetes de 1200 son 7200, asi que crece una
     * vez.
     * \~ */
    for (uint64_t pn = 10; pn < 16; ++pn) send(r, app, pn, 40000 + pn);
    const AckRange fresh[] = {{10, 15}};
    ack(r, app, fresh, 1, 0, 60000, log);
    check(r.congestion_window() == 6600 + 1200, "congestion avoidance did not add one datagram per window");

    r.set_app_limited(true);
    for (uint64_t pn = 16; pn < 20; ++pn) send(r, app, pn, 70000 + pn);
    const AckRange limited[] = {{16, 19}};
    ack(r, app, limited, 1, 0, 90000, log);
    check(r.congestion_window() == 7800, "the window grew while the application had nothing to send");
}

/// \~english 7.6: persistent congestion, and a run broken by an acknowledgement.
/// \~spanish 7.6: congestion persistente, y una racha rota por una confirmacion.  \~
void test_persistent_congestion() {
    for (int broken = 0; broken < 2; ++broken) {
        RecoveryConfig cfg;
        cfg.max_ack_delay_us = 20000;
        Recovery r(cfg);
        Log log;
        const Space app = Space::Application;

        // \~english First sample: 60 ms.  \~spanish Primera muestra: 60 ms.  \~
        send(r, app, 0, 0);
        ack_one(r, app, 0, 60000, log);

        for (uint64_t pn = 1; pn <= 9; ++pn) send(r, app, pn, pn * 100000);
        send(r, app, 10, 1000000);

        /* \~english
         * On the ACK of 10 at 1010 ms: latest = 10 ms, smoothed = 53.75 ms,
         * rttvar = 35 ms, so the duration is (53.75 + 140 + 20) * 3 =
         * 641.25 ms.  1 to 9 are all lost, sent from 100 ms to 900 ms: 800 ms,
         * persistent.  With 5 acknowledged too, the runs are 100-400 and
         * 600-900, 300 ms each: not persistent.
         * \~spanish
         * Con el ACK del 10 a los 1010 ms: latest = 10 ms, smoothed = 53,75 ms,
         * rttvar = 35 ms, asi que la duracion es (53,75 + 140 + 20) * 3 =
         * 641,25 ms.  Del 1 al 9 se pierden todos, enviados de 100 a 900 ms:
         * 800 ms, persistente.  Con el 5 confirmado tambien, las rachas son
         * 100-400 y 600-900, 300 ms cada una: no persistente.
         * \~ */
        const AckRange just_ten[] = {{10, 10}};
        const AckRange ten_and_five[] = {{10, 10}, {5, 5}};
        ack(r, app, broken ? ten_and_five : just_ten, broken ? 2 : 1, 0, 1010000, log);

        /* \~english
         * The window drops to the minimum, 2400 -- and then packet 10, the one
         * this ACK acknowledged, grows it in slow start: B.8 runs before B.5,
         * and persistent congestion ends the recovery period, so packet 10 is
         * not inside one.  2400 + 1200.
         * \~spanish
         * La ventana cae al minimo, 2400 -- y luego el paquete 10, el que
         * confirmo este ACK, la hace crecer en arranque lento: B.8 va antes que
         * B.5, y la congestion persistente acaba el periodo de recuperacion, asi
         * que el paquete 10 no esta dentro de uno.  2400 + 1200.
         * \~ */
        if (!broken) {
            check(r.persistent_congestion_events() == 1 &&
                      r.congestion_window() == r.minimum_window() + 1200,
                  "800 ms of losses with nothing acknowledged was not persistent congestion");
        } else {
            check(r.persistent_congestion_events() == 0 && r.congestion_window() > r.minimum_window(),
                  "a run broken by an acknowledgement was taken for persistent congestion");
        }
    }

    // \~english Losses from before the first RTT sample never count (7.6.2).
    // \~spanish Las perdidas de antes de la primera muestra de RTT no cuentan nunca (7.6.2).  \~
    Recovery r;
    Log log;
    for (uint64_t pn = 0; pn < 9; ++pn) send(r, Space::Application, pn, pn * 1000000);
    ack_one(r, Space::Application, 8, 9000000, log);
    check(r.persistent_congestion_events() == 0,
          "persistent congestion was declared with no RTT sample before the losses");
}

void test_bad_acks_and_full_rings() {
    RecoveryConfig cfg;
    cfg.capacity[2] = 4;
    Recovery r(cfg);
    Log log;
    const Space app = Space::Application;

    check(ack_one(r, app, 0, 0, log) == AckResult::AcknowledgedUnsent,
          "an ACK with nothing ever sent was accepted");
    for (uint64_t pn = 0; pn < 4; ++pn) check(send(r, app, pn, 0), "a packet did not fit the ring");
    check(ack_one(r, app, 7, 1000, log) == AckResult::AcknowledgedUnsent,
          "an ACK of a packet never sent was accepted");

    check(!r.can_record(app) && !send(r, app, 4, 0), "a full ring took one more packet");
    ack_one(r, app, 0, 1000, log);
    check(r.can_record(app) && send(r, app, 4, 1000), "acknowledging the oldest did not free its slot");
    check(!send(r, app, 4, 1000) && !send(r, app, 3, 1000), "a packet number that did not grow was taken");

    // \~english What the listener hears: the tag, and the ACK the packet carried.
    // \~spanish Lo que oye el oyente: la etiqueta, y el ACK que llevaba el paquete.  \~
    Recovery t;
    Log l2;
    t.on_packet_sent(app, 0, 100, true, true, 777, 41, 0);
    ack_one(t, app, 0, 1000, l2);
    check(l2.n_acked == 1 && l2.acked[0] == 777 && l2.ack_largest[0] == 41,
          "the listener did not hear the tag and the ACK the packet carried");

    // \~english A duplicate ACK changes nothing and says nothing twice.
    // \~spanish Un ACK repetido no cambia nada y no dice nada dos veces.  \~
    ack_one(t, app, 0, 2000, l2);
    check(l2.n_acked == 1, "a packet acknowledged twice was reported twice");
}

/// \~english 6.2: the probe timeout, its backoff, and when it is not armed.
/// \~spanish 6.2: el plazo de sondeo, su crecimiento, y cuando no se arma.  \~
void test_pto() {
    Recovery r;
    Log log;

    /* \~english
     * No sample yet: smoothed = 333 ms, rttvar = 166.5 ms, so the PTO is
     * 333 + 4 * 166.5 = 999 ms after the packet.
     * \~spanish
     * Aun sin muestra: smoothed = 333 ms, rttvar = 166,5 ms, asi que el PTO es
     * 333 + 4 * 166,5 = 999 ms despues del paquete.
     * \~ */
    send(r, Space::Initial, 0, 0);
    check(r.timer() == 999000, "the first PTO is not 999 ms");
    check(r.on_timeout(998999, log).kind == TimeoutAction::None, "the PTO fired early");

    TimeoutAction a = r.on_timeout(999000, log);
    check(a.kind == TimeoutAction::Probe && a.space == Space::Initial && r.pto_count() == 1 &&
              r.probes_owed() == 2 && r.pto_events() == 1,
          "the PTO did not ask for two probes in Initial");
    check(r.window_allows(1u << 30), "probes were held back by the congestion window");

    send(r, Space::Initial, 1, 999000);
    check(r.probes_owed() == 1, "sending a probe did not use one up");
    check(r.timer() == 999000 + 2 * 999000, "the second PTO did not double");

    // \~english An ACK resets the backoff (the server's peer is always validated).
    // \~spanish Un ACK reinicia el crecimiento (el otro extremo del servidor siempre esta validado).  \~
    ack_one(r, Space::Initial, 1, 1100000, log);
    check(r.pto_count() == 0, "an ACK did not reset the PTO count");

    // \~english Application data arms nothing until the handshake is confirmed.
    // \~spanish Los datos de aplicacion no arman nada hasta que se confirma el saludo.  \~
    Recovery s;
    send(s, Space::Application, 0, 5000);
    check(s.timer() == kNever, "application data armed a PTO before confirmation");
    s.set_handshake_confirmed(5000);
    check(s.timer() == 5000 + 999000 + 25000, "the application PTO does not include max_ack_delay");

    // \~english A server at its amplification limit arms nothing: it could not send.
    // \~spanish Un servidor en su limite de amplificacion no arma nada: no podria mandar.  \~
    s.set_amplification_blocked(true, 6000);
    check(s.timer() == kNever, "a server that may not send armed a timer");
    s.set_amplification_blocked(false, 6000);
    check(s.timer() != kNever, "lifting the limit did not re-arm the timer");

    // \~english A client with nothing in flight keeps an anti-deadlock timer.
    // \~spanish Un cliente sin nada en vuelo mantiene un temporizador antibloqueo.  \~
    RecoveryConfig client;
    client.is_server = false;
    Recovery c(client);
    send(c, Space::Initial, 0, 0);
    ack_one(c, Space::Initial, 0, 50000, log);
    check(c.timer() != kNever, "a client whose address is unproven dropped its timer");
    c.set_peer_address_validated(60000);
    check(c.timer() == kNever, "a validated client kept a timer with nothing in flight");
}

void test_discard_ecn() {
    Recovery r;
    Log log;
    send(r, Space::Initial, 0, 0);
    send(r, Space::Handshake, 0, 0);
    check(r.bytes_in_flight() == 2400, "two packets are not 2400 bytes in flight");
    r.discard_space(Space::Initial, 1000);
    check(r.bytes_in_flight() == 1200 && r.can_record(Space::Initial),
          "discarding Initial did not take its packets out of flight");

    // \~english B.7: a rising CE count halves the window like a loss.
    // \~spanish B.7: una cuenta CE que sube parte la ventana como una perdida.  \~
    Recovery e;
    for (uint64_t pn = 0; pn < 3; ++pn) send(e, Space::Application, pn, pn);
    const AckRange all[] = {{0, 2}};
    const uint64_t ce[3] = {3, 0, 1};
    ack(e, Space::Application, all, 1, 0, 10000, log, ce);
    check(e.congestion_events() == 1 && e.congestion_window() < 12000,
          "a rising ECN-CE count was not a congestion event");
}

} // namespace

int main() {
    test_rtt();
    test_loss_detection();
    test_newreno();
    test_persistent_congestion();
    test_bad_acks_and_full_rings();
    test_pto();
    test_discard_ecn();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic recovery: OK\n");
    return 0;
}
