/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/recovery.cpp
 * @brief
 * \~english RFC 9002: RTT estimation, loss detection, probe timeouts and NewReno.
 * \~spanish RFC 9002: estimacion del RTT, deteccion de perdidas, plazos de sondeo y NewReno.
 * \~
 */

#include "http_vx/quic_recovery.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {
namespace quic {

namespace {

/// \~english A sent packet's state in its ring.  \~spanish El estado de un paquete enviado en su anillo.  \~
enum : uint8_t {
    kOutstanding = 0,
    kAcked = 1,
    kLost = 2,
    /// \~english Acknowledged by the ACK being processed, window not yet grown for it.
    /// \~spanish Confirmado por el ACK en proceso, sin haber crecido aun la ventana por el.  \~
    kAckedNow = 3,
};

inline uint64_t max64(uint64_t a, uint64_t b) noexcept { return a > b ? a : b; }
inline uint64_t min64(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }

/// \~english @p v times 2^@p n, saturating instead of wrapping.
/// \~spanish @p v por 2^@p n, saturando en vez de dar la vuelta.  \~
inline uint64_t shl_sat(uint64_t v, uint32_t n) noexcept {
    if (v == 0) return 0;
    if (n >= 63 || v > (kNever >> n)) return kNever;
    return v << n;
}

inline uint64_t add_sat(uint64_t a, uint64_t b) noexcept {
    return a > kNever - b ? kNever : a + b;
}

} // namespace

Recovery::Recovery(const RecoveryConfig &config) noexcept : cfg_(config) {
    cwnd_ = initial_window();

    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);
    ready_ = true;
    for (size_t s = 0; s < kSpaces; ++s) {
        const uint32_t cap = cfg_.capacity[s];
        if (cap == 0) {
            ready_ = false;
            continue;
        }
        ring_[s].buf = static_cast<SentPacket *>(
            util::host_alloc(static_cast<size_t>(cap) * sizeof(SentPacket)));
        ring_[s].cap = ring_[s].buf != nullptr ? cap : 0;
        if (ring_[s].buf == nullptr) ready_ = false;
    }
}

Recovery::~Recovery() {
    for (Ring &r : ring_)
        if (r.buf != nullptr) util::host_free(r.buf);
}

bool Recovery::ready() const noexcept {
    return ready_;
}

uint64_t Recovery::initial_window() const noexcept {
    // \~english 7.2: ten datagrams, capped at the larger of 14720 bytes or two datagrams.
    // \~spanish 7.2: diez datagramas, con tope en lo mayor de 14720 bytes o dos datagramas.  \~
    const uint64_t mds = cfg_.max_datagram_size;
    return min64(10 * mds, max64(14720, 2 * mds));
}

bool Recovery::can_record(Space s) const noexcept {
    const Ring &r = ring_[idx(s)];
    return r.buf != nullptr && r.size < r.cap;
}

bool Recovery::window_allows(uint64_t bytes) const noexcept {
    if (probes_ > 0) return true;
    return bytes_in_flight_ + bytes <= cwnd_;
}

bool Recovery::in_recovery(uint64_t sent_time) const noexcept {
    /* \~english
     * With an explicit flag rather than the pseudocode's start time of zero:
     * with zero, a packet sent at time zero would count as sent inside a
     * recovery period that never began.
     * \~spanish
     * Con un indicador explicito y no con el inicio a cero del pseudocodigo: con
     * cero, un paquete enviado en el instante cero contaria como enviado dentro
     * de un periodo de recuperacion que nunca empezo.
     * \~ */
    return in_recovery_period_ && sent_time <= recovery_start_;
}

bool Recovery::peer_validated() const noexcept {
    // \~english A.8: a client's address is what is in doubt; the server's never is.
    // \~spanish A.8: lo que esta en duda es la direccion del cliente; la del servidor nunca.  \~
    return cfg_.is_server || peer_address_validated_ || handshake_confirmed_;
}

bool Recovery::any_eliciting_in_flight() const noexcept {
    return eliciting_in_flight_[0] + eliciting_in_flight_[1] + eliciting_in_flight_[2] != 0;
}

void Recovery::pop_front(Ring &r) noexcept {
    while (r.size != 0 && r.at(0).state != kOutstanding) {
        r.head = (r.head + 1) % r.cap;
        --r.size;
    }
}

bool Recovery::on_packet_sent(Space s, uint64_t pn, uint32_t bytes, bool ack_eliciting,
                              bool in_flight, uint64_t tag, uint64_t ack_largest,
                              uint64_t now_us) noexcept {
    const size_t i = idx(s);
    Ring &r = ring_[i];
    if (!can_record(s)) return false;

    // \~english Packet numbers only grow: the ring is ordered by them, and by send time.
    // \~spanish Los numeros de paquete solo crecen: el anillo esta ordenado por ellos, y por envio.  \~
    if (any_sent_[i] && pn <= largest_sent_[i]) return false;

    SentPacket &p = r.at(r.size);
    p.pn = pn;
    p.time_sent = now_us;
    p.tag = tag;
    p.ack_largest = ack_largest;
    p.bytes = bytes;
    p.ack_eliciting = ack_eliciting;
    p.in_flight = in_flight;
    p.state = kOutstanding;
    ++r.size;

    largest_sent_[i] = pn;
    any_sent_[i] = true;

    if (in_flight) {
        bytes_in_flight_ += bytes;
        if (ack_eliciting) {
            last_eliciting_time_[i] = now_us;
            ++eliciting_in_flight_[i];
            if (probes_ > 0) --probes_;
        }
        set_timer(now_us);
    }
    return true;
}

void Recovery::update_rtt(uint64_t ack_delay_us, uint64_t now_us) noexcept {
    if (!has_rtt_sample_) {
        min_rtt_ = latest_rtt_;
        smoothed_rtt_ = latest_rtt_;
        rttvar_ = latest_rtt_ / 2;
        first_rtt_sample_ = now_us;
        has_rtt_sample_ = true;
        return;
    }

    // \~english min_rtt ignores the ack delay: it is the path's floor.
    // \~spanish min_rtt no tiene en cuenta el retraso del ack: es el suelo del camino.  \~
    min_rtt_ = min64(min_rtt_, latest_rtt_);

    // \~english After confirmation the peer promised max_ack_delay; hold it to that (5.3).
    // \~spanish Tras la confirmacion el otro extremo prometio max_ack_delay; se le ata a eso (5.3).  \~
    if (handshake_confirmed_) ack_delay_us = min64(ack_delay_us, cfg_.max_ack_delay_us);

    /* \~english
     * Subtract the delay only if what is left is still at least min_rtt: an
     * ack delay that would make the round trip shorter than the path's
     * fastest ever is not believed.
     * \~spanish
     * Se resta el retraso solo si lo que queda sigue siendo al menos min_rtt: un
     * retraso de ack que haria el viaje mas corto que el mas rapido del camino no
     * se cree.
     * \~ */
    uint64_t adjusted = latest_rtt_;
    if (latest_rtt_ >= add_sat(min_rtt_, ack_delay_us)) adjusted = latest_rtt_ - ack_delay_us;

    const uint64_t diff = smoothed_rtt_ > adjusted ? smoothed_rtt_ - adjusted : adjusted - smoothed_rtt_;
    rttvar_ = (3 * rttvar_ + diff) / 4;
    smoothed_rtt_ = (7 * smoothed_rtt_ + adjusted) / 8;
}

void Recovery::congestion_event(uint64_t sent_time, uint64_t now_us) noexcept {
    // \~english One reduction per round trip: losses from before this recovery began are its own.
    // \~spanish Una reduccion por viaje: las perdidas de antes de empezar esta recuperacion son de ella.  \~
    if (in_recovery(sent_time)) return;

    in_recovery_period_ = true;
    recovery_start_ = now_us;
    ssthresh_ = cwnd_ / 2;
    cwnd_ = max64(ssthresh_, minimum_window());
    bytes_acked_ca_ = 0;
    ++congestion_events_;
}

void Recovery::on_acked_cc(const SentPacket &p) noexcept {
    if (!p.in_flight) return;
    if (app_limited_) return;
    if (in_recovery(p.time_sent)) return;

    if (cwnd_ < ssthresh_) {
        // \~english Slow start: one byte of window per byte acknowledged.
        // \~spanish Arranque lento: un byte de ventana por byte confirmado.  \~
        cwnd_ += p.bytes;
        return;
    }

    /* \~english
     * Congestion avoidance: one datagram per window's worth acknowledged.
     * Counted in bytes (RFC 3465, 2.1) instead of the pseudocode's
     * `mds * bytes / cwnd`, which in integers rounds to zero whenever a
     * packet is smaller than cwnd / mds -- and the window would never grow.
     * \~spanish
     * Evitacion de congestion: un datagrama por cada ventana confirmada.
     * Contado en bytes (RFC 3465, 2.1) en vez del `mds * bytes / cwnd` del
     * pseudocodigo, que en enteros redondea a cero siempre que un paquete mida
     * menos que cwnd / mds -- y la ventana no creceria nunca.
     * \~ */
    bytes_acked_ca_ += p.bytes;
    if (bytes_acked_ca_ >= cwnd_) {
        bytes_acked_ca_ -= cwnd_;
        cwnd_ += cfg_.max_datagram_size;
    }
}

void Recovery::detect_lost(Space s, uint64_t now_us, RecoveryListener &l) noexcept {
    const size_t i = idx(s);
    Ring &r = ring_[i];
    loss_time_[i] = 0;
    if (largest_acked_[i] == kNever) return;

    const uint64_t base = max64(latest_rtt_, smoothed_rtt_);
    const uint64_t loss_delay = max64(base + base / 8, kGranularityUs);
    const bool can_be_late = now_us >= loss_delay;
    const uint64_t lost_send_time = can_be_late ? now_us - loss_delay : 0;

    /* \~english
     * Persistent congestion (7.6.2), watched during the same walk: a run of
     * ack-eliciting packets lost now, sent after the first RTT sample, with
     * no acknowledged packet between them.  The ring is in send order and
     * keeps the acknowledged ones as tombstones, so "between" is just "met
     * on the way".
     * \~spanish
     * Congestion persistente (7.6.2), vigilada en el mismo recorrido: una racha
     * de paquetes que piden confirmacion perdidos ahora, enviados tras la
     * primera muestra de RTT, sin ningun paquete confirmado entre ellos.  El
     * anillo esta en orden de envio y guarda los confirmados como lapidas, asi
     * que "entre" es solo "encontrado por el camino".
     * \~ */
    const uint64_t pc_duration =
        (smoothed_rtt_ + max64(4 * rttvar_, kGranularityUs) + cfg_.max_ack_delay_us) *
        kPersistentCongestionThreshold;
    bool run = false;
    uint64_t run_start = 0;
    bool persistent = false;

    uint64_t last_loss_sent = 0;
    bool any_in_flight_lost = false;

    for (uint32_t k = 0; k < r.size; ++k) {
        SentPacket &p = r.at(k);
        if (p.pn > largest_acked_[i]) break;

        if (p.state == kAcked || p.state == kAckedNow) {
            run = false;
            continue;
        }
        if (p.state != kOutstanding) continue;

        const bool late = can_be_late && p.time_sent <= lost_send_time;
        const bool reordered = largest_acked_[i] >= p.pn + kPacketThreshold;
        if (!late && !reordered) {
            // \~english Not yet: remember when it will be, the earliest of them.
            // \~spanish Aun no: se recuerda cuando lo sera, el antes de todos.  \~
            const uint64_t when = p.time_sent + loss_delay;
            if (loss_time_[i] == 0 || when < loss_time_[i]) loss_time_[i] = when;
            continue;
        }

        p.state = kLost;
        ++lost_;
        if (p.in_flight) {
            bytes_in_flight_ -= p.bytes;
            if (p.ack_eliciting) --eliciting_in_flight_[i];
            last_loss_sent = max64(last_loss_sent, p.time_sent);
            any_in_flight_lost = true;
        }
        if (p.ack_eliciting && has_rtt_sample_ && p.time_sent > first_rtt_sample_) {
            if (!run) {
                run = true;
                run_start = p.time_sent;
            }
            if (p.time_sent - run_start > pc_duration) persistent = true;
        }
        l.on_lost(s, p);
    }

    if (any_in_flight_lost) congestion_event(last_loss_sent, now_us);

    if (persistent) {
        // \~english The window collapses to its minimum, and recovery starts over.
        // \~spanish La ventana cae a su minimo, y la recuperacion empieza de nuevo.  \~
        cwnd_ = minimum_window();
        in_recovery_period_ = false;
        recovery_start_ = 0;
        bytes_acked_ca_ = 0;
        ++persistent_;
    }
}

AckResult Recovery::on_ack_received(Space s, const Frame &ack, const uint8_t *payload,
                                    uint64_t now_us, RecoveryListener &l) noexcept {
    const size_t i = idx(s);
    Ring &r = ring_[i];

    // \~english An acknowledgement of something never sent (RFC 9000, 13.1).
    // \~spanish Una confirmacion de algo que no se mando nunca (RFC 9000, 13.1).  \~
    if (!any_sent_[i] || ack.largest > largest_sent_[i]) return AckResult::AcknowledgedUnsent;

    if (largest_acked_[i] == kNever || ack.largest > largest_acked_[i])
        largest_acked_[i] = ack.largest;

    /* \~english
     * Pass 1: mark what this ACK newly acknowledges.  Ring and ranges are both
     * ordered, so they are walked together, from the largest down, once.
     * \~spanish
     * Pasada 1: marcar lo que este ACK confirma de nuevo.  Anillo y rangos estan
     * los dos ordenados, asi que se recorren juntos, del mayor hacia abajo, una
     * vez.
     * \~ */
    AckRangeReader ranges(payload, ack);
    AckRange cur;
    bool have = ranges.next(cur);
    bool newly_any = false;
    bool newly_eliciting = false;
    bool largest_newly = false;
    uint64_t largest_time = 0;

    for (uint32_t k = r.size; k-- > 0 && have;) {
        SentPacket &p = r.at(k);
        while (have && p.pn < cur.smallest) have = ranges.next(cur);
        if (!have) break;
        if (p.pn > cur.largest || p.state != kOutstanding) continue;

        p.state = kAckedNow;
        newly_any = true;
        if (p.ack_eliciting) newly_eliciting = true;
        if (p.pn == ack.largest) {
            largest_newly = true;
            largest_time = p.time_sent;
        }
        if (p.in_flight) {
            bytes_in_flight_ -= p.bytes;
            if (p.ack_eliciting) --eliciting_in_flight_[i];
        }
    }

    if (!newly_any) return AckResult::Ok;

    // \~english An RTT sample only from the largest, and only if something asked for this ACK.
    // \~spanish Una muestra de RTT solo del mayor, y solo si algo pidio este ACK.  \~
    if (largest_newly && newly_eliciting) {
        latest_rtt_ = now_us > largest_time ? now_us - largest_time : 0;

        // \~english Initial ACKs are not delayed on purpose: their delay is ignored (5.3).
        // \~spanish Los ACK de Initial no se retrasan a proposito: su retraso se ignora (5.3).  \~
        const uint64_t delay =
            s == Space::Initial ? 0 : shl_sat(ack.ack_delay, cfg_.peer_ack_delay_exponent);
        update_rtt(delay, now_us);
    }

    // \~english A rising CE count is a congestion event, like a loss (B.7).
    // \~spanish Una cuenta CE que sube es un evento de congestion, como una perdida (B.7).  \~
    if (ack.has_ecn && ack.ecn[2] > ecn_ce_[i]) {
        ecn_ce_[i] = ack.ecn[2];
        if (largest_newly) congestion_event(largest_time, now_us);
    }

    detect_lost(s, now_us, l);

    // \~english Pass 2: the window grows for what was acknowledged, after any reduction.
    // \~spanish Pasada 2: la ventana crece por lo confirmado, tras cualquier reduccion.  \~
    for (uint32_t k = 0; k < r.size; ++k) {
        SentPacket &p = r.at(k);
        if (p.state != kAckedNow) continue;
        p.state = kAcked;
        on_acked_cc(p);
        l.on_acked(s, p);
    }

    if (peer_validated()) pto_count_ = 0;
    pop_front(r);
    set_timer(now_us);
    return AckResult::Ok;
}

uint64_t Recovery::loss_time(Space &space) const noexcept {
    uint64_t t = 0;
    for (size_t k = 0; k < kSpaces; ++k) {
        if (loss_time_[k] != 0 && (t == 0 || loss_time_[k] < t)) {
            t = loss_time_[k];
            space = static_cast<Space>(k);
        }
    }
    return t;
}

uint64_t Recovery::pto_base() const noexcept {
    const uint64_t d = smoothed_rtt_ + max64(4 * rttvar_, kGranularityUs);
    return shl_sat(d, pto_count_);
}

uint64_t Recovery::pto_time(Space &space, uint64_t now_us) const noexcept {
    uint64_t duration = pto_base();

    // \~english Nothing in flight, address unproven: the client's anti-deadlock timer.
    // \~spanish Nada en vuelo, direccion sin probar: el temporizador antibloqueo del cliente.  \~
    if (!any_eliciting_in_flight()) {
        space = has_handshake_keys_ ? Space::Handshake : Space::Initial;
        return add_sat(now_us, duration);
    }

    uint64_t best = kNever;
    space = Space::Initial;
    for (size_t k = 0; k < kSpaces; ++k) {
        if (eliciting_in_flight_[k] == 0) continue;
        if (k == idx(Space::Application)) {
            // \~english Application data waits for confirmation, then counts max_ack_delay.
            // \~spanish Los datos de aplicacion esperan a la confirmacion, y luego cuentan max_ack_delay.  \~
            if (!handshake_confirmed_) return best;
            duration = add_sat(duration, shl_sat(cfg_.max_ack_delay_us, pto_count_));
        }
        const uint64_t t = add_sat(last_eliciting_time_[k], duration);
        if (t < best) {
            best = t;
            space = static_cast<Space>(k);
        }
    }
    return best;
}

void Recovery::set_timer(uint64_t now_us) noexcept {
    Space space;
    const uint64_t earliest_loss = loss_time(space);
    if (earliest_loss != 0) {
        timer_ = earliest_loss;
        return;
    }

    // \~english A server that may not send sets no timer: it could not act on it (A.8).
    // \~spanish Un servidor que no puede mandar no pone temporizador: no podria atenderlo (A.8).  \~
    if (amplification_blocked_) {
        timer_ = kNever;
        return;
    }
    if (!any_eliciting_in_flight() && peer_validated()) {
        timer_ = kNever;
        return;
    }
    timer_ = pto_time(space, now_us);
}

TimeoutAction Recovery::on_timeout(uint64_t now_us, RecoveryListener &l) noexcept {
    TimeoutAction a;
    if (timer_ == kNever || now_us < timer_) return a;

    Space space = Space::Initial;
    if (loss_time(space) != 0) {
        detect_lost(space, now_us, l);
        pop_front(ring_[idx(space)]);
        set_timer(now_us);
        a.kind = TimeoutAction::Loss;
        a.space = space;
        return a;
    }

    if (!any_eliciting_in_flight()) {
        // \~english The client's anti-deadlock probe: Handshake if it can, else a padded Initial.
        // \~spanish El sondeo antibloqueo del cliente: Handshake si puede, si no un Initial rellenado.  \~
        a.space = has_handshake_keys_ ? Space::Handshake : Space::Initial;
    } else {
        pto_time(space, now_us);
        a.space = space;
    }

    // \~english Up to two probes, which the congestion window does not hold back (6.2.4).
    // \~spanish Hasta dos sondeos, que la ventana de congestion no retiene (6.2.4).  \~
    a.kind = TimeoutAction::Probe;
    probes_ = 2;
    ++pto_count_;
    ++pto_events_;
    set_timer(now_us);
    return a;
}

void Recovery::discard_space(Space s, uint64_t now_us) noexcept {
    const size_t i = idx(s);
    Ring &r = ring_[i];

    // \~english Its packets leave the flight; they will never be acknowledged or lost.
    // \~spanish Sus paquetes salen del vuelo; no se van a confirmar ni perder nunca.  \~
    for (uint32_t k = 0; k < r.size; ++k) {
        const SentPacket &p = r.at(k);
        if (p.state == kOutstanding && p.in_flight) bytes_in_flight_ -= p.bytes;
    }
    r.head = 0;
    r.size = 0;
    eliciting_in_flight_[i] = 0;
    last_eliciting_time_[i] = 0;
    loss_time_[i] = 0;
    pto_count_ = 0;
    set_timer(now_us);
}

void Recovery::on_retry(uint64_t now_us, RecoveryListener &l) noexcept {
    const Ring &r = ring_[idx(Space::Initial)];
    for (uint32_t k = 0; k < r.size; ++k) {
        const SentPacket &p = r.at(k);
        if (p.state == kOutstanding) l.on_lost(Space::Initial, p);
    }

    // \~english The flight empties like a discarded space, but the numbering goes on.
    // \~spanish El vuelo se vacia como en un espacio tirado, pero la numeracion sigue.  \~
    discard_space(Space::Initial, now_us);

    cwnd_ = initial_window();
    ssthresh_ = kNever;
    bytes_acked_ca_ = 0;
    recovery_start_ = 0;
    in_recovery_period_ = false;
    probes_ = 0;
    pto_count_ = 0;
    set_timer(now_us);
}

void Recovery::set_handshake_confirmed(uint64_t now_us) noexcept {
    handshake_confirmed_ = true;
    set_timer(now_us);
}

void Recovery::set_peer_address_validated(uint64_t now_us) noexcept {
    peer_address_validated_ = true;
    set_timer(now_us);
}

void Recovery::set_has_handshake_keys(uint64_t now_us) noexcept {
    has_handshake_keys_ = true;
    set_timer(now_us);
}

void Recovery::set_amplification_blocked(bool blocked, uint64_t now_us) noexcept {
    amplification_blocked_ = blocked;
    set_timer(now_us);
}

} // namespace quic
} // namespace http_vx
