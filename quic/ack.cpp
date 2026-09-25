/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/ack.cpp
 * @brief
 * \~english Tracking received packet numbers and deciding when to acknowledge them.
 * \~spanish Seguir los numeros de paquete recibidos y decidir cuando confirmarlos.
 * \~
 */

#include "http_vx/quic_ack.h"

namespace http_vx {
namespace quic {

Receipt AckTracker::classify(uint64_t pn) const noexcept {
    if (pn < floor_) return Receipt::TooOld;

    // \~english Largest first, so a new packet -- the common case -- stops at once.
    // \~spanish Del mayor al menor, asi que un paquete nuevo -- el caso comun -- para enseguida.  \~
    for (size_t i = 0; i < count_; ++i) {
        if (pn > r_[i].largest) break;
        if (pn >= r_[i].smallest) return Receipt::Duplicate;
    }
    return Receipt::New;
}

void AckTracker::drop_lowest() noexcept {
    const AckRange &low = r_[count_ - 1];

    // \~english Forgetting a range means refusing its packets from now on (13.2.3).
    // \~spanish Olvidar un rango es rechazar sus paquetes a partir de ahora (13.2.3).  \~
    if (low.largest + 1 > floor_) floor_ = low.largest + 1;
    --count_;
    ++evicted_;
}

void AckTracker::insert(uint64_t pn) noexcept {
    // \~english The first range lying wholly below pn; the one before it lies wholly above.
    // \~spanish El primer rango que queda entero por debajo de pn; el anterior queda entero por encima.  \~
    size_t i = 0;
    while (i < count_ && r_[i].largest > pn) ++i;

    const bool joins_above = i > 0 && r_[i - 1].smallest == pn + 1;
    const bool joins_below = i < count_ && r_[i].largest + 1 == pn;

    if (joins_above && joins_below) {
        // \~english pn filled the only hole between two ranges: they become one.
        // \~spanish pn relleno el unico hueco entre dos rangos: pasan a ser uno.  \~
        r_[i - 1].smallest = r_[i].smallest;
        for (size_t k = i; k + 1 < count_; ++k) r_[k] = r_[k + 1];
        --count_;
        return;
    }
    if (joins_above) {
        r_[i - 1].smallest = pn;
        return;
    }
    if (joins_below) {
        r_[i].largest = pn;
        return;
    }

    if (count_ == kAckRanges) {
        /* \~english
         * No room for a new range.  If it would be the lowest one, it is the
         * one forgotten, at once; otherwise the lowest goes to make room.
         * \~spanish
         * No hay sitio para un rango nuevo.  Si seria el mas bajo, es el que se
         * olvida, en el acto; si no, el mas bajo se va para hacer sitio.
         * \~ */
        if (i == count_) {
            if (pn + 1 > floor_) floor_ = pn + 1;
            ++evicted_;
            return;
        }
        drop_lowest();
    }

    for (size_t k = count_; k > i; --k) r_[k] = r_[k - 1];
    r_[i] = {pn, pn};
    ++count_;
}

Receipt AckTracker::on_received(uint64_t pn, bool ack_eliciting, Ecn ecn,
                                uint64_t now_us) noexcept {
    const Receipt c = classify(pn);
    if (c != Receipt::New) return c;

    // \~english A hole right below this packet: something between was not received.
    // \~spanish Un hueco justo debajo de este paquete: algo de en medio no se recibio.  \~
    const bool hole_below = any_ && pn > largest_ + 1;

    insert(pn);

    if (ecn == Ecn::Ect0) ++ecn_[0];
    else if (ecn == Ecn::Ect1) ++ecn_[1];
    else if (ecn == Ecn::Ce) ++ecn_[2];

    if (!any_ || pn > largest_) {
        largest_ = pn;
        largest_time_ = now_us;
    }
    any_ = true;

    /* \~english
     * Only an ack-eliciting packet obliges an ACK.  Answering a packet that
     * does not elicit one would let two endpoints acknowledge each other's
     * acknowledgements forever (13.2.1) -- even for CE, which is why the CE
     * rule sits inside this branch.
     * \~spanish
     * Solo un paquete que pide confirmacion obliga a un ACK.  Contestar a un
     * paquete que no la pide dejaria a dos extremos confirmando las
     * confirmaciones del otro para siempre (13.2.1) -- tambien con CE, y por
     * eso la regla de CE esta dentro de esta rama.
     * \~ */
    if (ack_eliciting) {
        if (policy_.immediate) ack_now_ = true;

        // \~english Out of order, or a hole below: the sender needs to hear now (13.2.1).
        // \~spanish Desordenado, o un hueco debajo: el emisor tiene que saberlo ya (13.2.1).  \~
        if (any_eliciting_ && pn < largest_eliciting_) ack_now_ = true;
        if (any_eliciting_ && pn > largest_eliciting_ && hole_below) ack_now_ = true;
        if (ecn == Ecn::Ce) ack_now_ = true;

        if (!any_eliciting_ || pn > largest_eliciting_) largest_eliciting_ = pn;
        any_eliciting_ = true;

        if (eliciting_unacked_ == 0) first_unacked_time_ = now_us;
        ++eliciting_unacked_;
        if (eliciting_unacked_ >= policy_.eliciting_threshold) ack_now_ = true;
    }
    return Receipt::New;
}

uint64_t AckTracker::ack_deadline() const noexcept {
    if (ack_now_) return 0;
    if (eliciting_unacked_ == 0) return kNever;
    return first_unacked_time_ + policy_.max_ack_delay_us;
}

size_t AckTracker::write_ack(uint8_t *p, size_t room, uint64_t now_us) const noexcept {
    if (count_ == 0) return 0;

    /* \~english
     * The delay this end added on purpose since the largest arrived (13.2.5),
     * scaled down by the exponent it announced.  A clock that went backwards
     * says zero rather than a huge number.
     * \~spanish
     * El retraso que este extremo metio a proposito desde que llego el mayor
     * (13.2.5), reducido por el exponente que anuncio.  Un reloj que fue hacia
     * atras dice cero en vez de un numero enorme.
     * \~ */
    const uint64_t delay =
        now_us > largest_time_ ? (now_us - largest_time_) >> policy_.ack_delay_exponent : 0;

    const bool with_ecn = ecn_[0] != 0 || ecn_[1] != 0 || ecn_[2] != 0;

    // \~english As many ranges as fit, newest first; never fewer than the one with the largest.
    // \~spanish Tantos rangos como quepan, los nuevos primero; nunca menos que el del mayor.  \~
    for (size_t k = count_; k >= 1; --k) {
        const size_t n = quic::write_ack(p, room, r_, k, delay, with_ecn ? ecn_ : nullptr);
        if (n != 0) return n;
    }
    return 0;
}

void AckTracker::on_ack_sent() noexcept {
    ack_now_ = false;
    eliciting_unacked_ = 0;
}

void AckTracker::on_ack_acknowledged(uint64_t largest) noexcept {
    // \~english Whole ranges at or below it go; one that straddles it is cut.
    // \~spanish Los rangos enteros hasta ahi se van; uno que lo cruza se corta.  \~
    while (count_ > 0 && r_[count_ - 1].largest <= largest) --count_;
    if (count_ > 0 && r_[count_ - 1].smallest <= largest)
        r_[count_ - 1].smallest = largest + 1;

    // \~english And none of them is accepted again, as 13.2.3 requires.
    // \~spanish Y ninguno se vuelve a aceptar, como pide 13.2.3.  \~
    if (largest + 1 > floor_) floor_ = largest + 1;
}

} // namespace quic
} // namespace http_vx
