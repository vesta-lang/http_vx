/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/timer_wheel.cpp
 * @brief
 * \~english Arming, cancelling and expiring, none of which looks anything up.
 * \~spanish Armar, cancelar y vencer, y ninguna de las tres busca nada.
 * \~
 */

#include "http_vx/timer_wheel.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {

namespace {

/**
 * @brief
 * \~english The smallest power of two that is at least @p n.
 * \~spanish La menor potencia de dos que llega a @p n.
 * \~
 *
 * \~english
 * So that the slot of a deadline is a mask rather than a division.  It is not
 * the division being slow that decides it -- it is that the wheel turns, so
 * the arithmetic has to wrap, and wrapping by a mask is exactly right while
 * wrapping by a remainder is right only while the tick count fits.
 *
 * \~spanish
 * Para que la casilla de un plazo sea una mascara y no una division.  No lo
 * decide que la division sea lenta -- lo decide que la rueda gira, asi que la
 * aritmetica tiene que dar la vuelta, y darla con una mascara es exactamente
 * correcto mientras que darla con un resto solo lo es mientras quepa la cuenta
 * de tics.
 *
 * \~
 */
uint32_t round_up_pow2(uint32_t n) noexcept {
    if (n <= 1) return 1;

    uint32_t p = 1;
    while (p < n && p < 0x40000000u) p <<= 1;
    return p;
}

} // namespace

TimerWheel::~TimerWheel() { release(); }

void TimerWheel::release() noexcept {
    if (entries_ != nullptr) {
        util::host_free(entries_);
        entries_ = nullptr;
    }
    if (heads_ != nullptr) {
        util::host_free(heads_);
        heads_ = nullptr;
    }

    capacity_ = 0;
    slots_ = 0;
    mask_ = 0;
    armed_ = 0;
}

bool TimerWheel::reset(uint32_t capacity, uint32_t slots,
                       uint64_t now) noexcept {
    release();

    if (capacity == 0 || capacity >= kNoTimer) return false;

    slots_ = round_up_pow2(slots);
    mask_ = slots_ - 1;
    capacity_ = capacity;

    /* \~english
     * All of it, once, for the life of the shard.  The scope says exactly
     * that: long-lived, never resized, and touched in scattered places rather
     * than swept -- a wheel's whole point is that only the slots that have
     * something in them are ever read.
     *
     * \~spanish
     * Todo de una vez, para toda la vida del fragmento.  El alcance dice justo
     * eso: de vida larga, sin cambiar de tamano nunca, y tocado a salto de mata
     * en vez de recorrido -- toda la gracia de una rueda es que solo se leen las
     * casillas que tienen algo.
     * \~ */
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    entries_ = static_cast<Entry *>(
        util::host_alloc(static_cast<size_t>(capacity_) * sizeof(Entry)));
    if (entries_ == nullptr) {
        release();
        return false;
    }

    heads_ = static_cast<uint32_t *>(
        util::host_alloc(static_cast<size_t>(slots_) * sizeof(uint32_t)));
    if (heads_ == nullptr) {
        release();
        return false;
    }

    for (uint32_t i = 0; i < capacity_; ++i)
        entries_[i] = Entry{kNoTimer, kNoTimer, kNoTimer};

    for (uint32_t i = 0; i < slots_; ++i) heads_[i] = kNoTimer;

    armed_ = 0;
    swept_ = now;
    return true;
}

void TimerWheel::unlink(uint32_t id) noexcept {
    Entry &e = entries_[id];
    if (e.slot == kNoTimer) return;

    /* \~english
     * A doubly linked list, and the reason for the second link is this line:
     * a node that knows who is behind it can leave without the list being
     * walked.  A single link would make cancelling O(n) in the slot, and the
     * slot is exactly where all the connections with the same deadline are --
     * which, when a server is idle, is all of them.
     *
     * \~spanish
     * Una lista doblemente enlazada, y la razon del segundo enlace es esta
     * linea: un nodo que sabe quien va detras de el puede irse sin recorrer la
     * lista.  Con un solo enlace, cancelar seria lineal en la casilla, y la
     * casilla es justo donde estan todas las conexiones con el mismo plazo --
     * que, cuando un servidor esta parado, son todas.
     * \~ */
    if (e.prev != kNoTimer)
        entries_[e.prev].next = e.next;
    else
        heads_[e.slot] = e.next;

    if (e.next != kNoTimer) entries_[e.next].prev = e.prev;

    e.prev = kNoTimer;
    e.next = kNoTimer;
    e.slot = kNoTimer;
    --armed_;
}

bool TimerWheel::arm(uint32_t id, uint32_t ticks) noexcept {
    if (entries_ == nullptr || id >= capacity_) return false;

    /* \~english
     * Zero is refused along with anything past the horizon.  A deadline of
     * zero ticks is one that has already passed, and putting it in the slot
     * being emptied would either fire it now -- which the caller could have
     * done itself -- or hide it for a whole turn.  Neither is what anybody
     * meant, so neither is guessed at.
     *
     * \~spanish
     * El cero se rechaza junto con todo lo que pase del horizonte.  Un plazo de
     * cero tics es uno que ya paso, y meterlo en la casilla que se esta vaciando
     * lo haria vencer ahora -- cosa que quien llama podia haber hecho el -- o lo
     * esconderia una vuelta entera.  Ninguna de las dos es lo que queria decir
     * nadie, asi que no se adivina ninguna.
     * \~ */
    if (ticks == 0 || ticks > horizon()) return false;

    unlink(id);

    const uint32_t slot = static_cast<uint32_t>((swept_ + ticks) & mask_);

    Entry &e = entries_[id];
    e.prev = kNoTimer;
    e.next = heads_[slot];
    e.slot = slot;

    if (e.next != kNoTimer) entries_[e.next].prev = id;
    heads_[slot] = id;

    ++armed_;
    return true;
}

void TimerWheel::cancel(uint32_t id) noexcept {
    if (entries_ == nullptr || id >= capacity_) return;
    unlink(id);
}

bool TimerWheel::armed(uint32_t id) const noexcept {
    if (entries_ == nullptr || id >= capacity_) return false;
    return entries_[id].slot != kNoTimer;
}

uint32_t TimerWheel::take_due(uint64_t now) noexcept {
    if (entries_ == nullptr) return kNoTimer;

    for (;;) {
        const uint32_t slot = static_cast<uint32_t>(swept_ & mask_);
        const uint32_t id = heads_[slot];

        if (id != kNoTimer) {
            unlink(id);
            return id;
        }

        /* \~english
         * The slot for this tick is empty, so move on -- but only up to now.
         * A clock that went backwards leaves this loop at once instead of
         * turning the wheel the long way round, which at sixty-four bits would
         * not finish.
         *
         * \~spanish
         * La casilla de este tic esta vacia, asi que se pasa a la siguiente --
         * pero solo hasta ahora.  Un reloj que fue hacia atras sale de este
         * bucle en el acto en vez de dar la vuelta larga a la rueda, que con
         * sesenta y cuatro bits no acabaria.
         * \~ */
        if (swept_ >= now) return kNoTimer;
        ++swept_;
    }
}

} // namespace http_vx
