/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/kick_queue.cpp
 * @brief
 * \~english The kick stack, the coalesced wake, and the end of a source.
 * \~spanish La pila de avisos, el despertar agrupado, y el final de una fuente.
 * \~
 */
#include "http_vx/kick_queue.h"

#include "http_vx/reactor_ops.h"

namespace http_vx {

const char *gone_reason_name(GoneReason why) noexcept {
    switch (why) {
    case GoneReason::Finished:
        return "finished";
    case GoneReason::PeerReset:
        return "reset by the peer";
    case GoneReason::ConnectionClosed:
        return "connection closed";
    case GoneReason::IdleTimeout:
        return "idle timeout";
    case GoneReason::Shutdown:
        return "shard shutting down";
    }
    return "unknown";
}

KickTarget::~KickTarget() = default;

BodySource::~BodySource() = default;

bool BodySource::kick() noexcept {
    KickQueue *q = queue_;
    return q != nullptr && q->kick(*this);
}

void KickQueue::reset(Backend *io) noexcept { io_ = io; }

void KickQueue::open(BodySource &s, KickTarget &target, OpenResponse r) noexcept {
    s.target_ = &target;
    s.response_ = r;
    s.closing_ = false;
    s.why_ = GoneReason::Finished;
    s.next_ = nullptr;
    s.coalesced_.store(0, std::memory_order_relaxed);
    s.queue_ = this;
    // \~english Last: from here a kick from any thread pushes it.
    // \~spanish Lo ultimo: desde aqui un aviso desde cualquier hilo la mete.  \~
    s.queued_.store(0, std::memory_order_release);
}

bool KickQueue::kick(BodySource &s) noexcept {
    /* \~english
     * Already queued, or ended: nothing to push.  The count goes on the
     * source's own line, which this exchange has just taken anyway.
     * \~spanish
     * Ya en la cola, o acabada: nada que meter.  La cuenta va en la linea de la
     * propia fuente, que este intercambio acaba de coger de todas formas.
     * \~ */
    if (s.queued_.exchange(1, std::memory_order_acq_rel) != 0) {
        s.coalesced_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    BodySource *h = head_.load(std::memory_order_relaxed);
    do {
        s.next_ = h;
    } while (!head_.compare_exchange_weak(h, &s, std::memory_order_seq_cst,
                                          std::memory_order_relaxed));

    /* \~english
     * Dekker's second half: the push above, THEN "is it sleeping".  Only the
     * first kick since the shard went to sleep finds 1 and pays the system
     * call; every other one is this exchange and nothing more.
     * \~spanish
     * La segunda mitad de Dekker: el push de arriba, DESPUES "esta durmiendo".
     * Solo el primer aviso desde que el fragmento se durmio encuentra un 1 y paga
     * la llamada al sistema; cualquier otro es este intercambio y nada mas.
     * \~ */
    if (sleeping_.exchange(0, std::memory_order_seq_cst) == 1) {
        wakes_.fetch_add(1, std::memory_order_relaxed);
        if (io_ == nullptr || !io_->wake()) {
            failed_wakes_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }
    return true;
}

bool KickQueue::about_to_sleep() noexcept {
    /* \~english
     * Dekker's first half: publish "sleeping", THEN look at the stack.  Either
     * a kicker pushed before this store -- and the load below sees it -- or
     * after it, and that kicker's exchange sees the 1 and wakes.
     * \~spanish
     * La primera mitad de Dekker: publicar "durmiendo", DESPUES mirar la pila.
     * O quien avisa metio antes de esta escritura -- y la lectura de abajo lo
     * ve -- o despues, y su intercambio ve el 1 y despierta.
     * \~ */
    sleeping_.store(1, std::memory_order_seq_cst);
    if (head_.load(std::memory_order_seq_cst) != nullptr) {
        sleeping_.store(0, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void KickQueue::awake() noexcept { sleeping_.store(0, std::memory_order_relaxed); }

void KickQueue::deliver_gone(BodySource &s) noexcept {
    ++gone_[static_cast<size_t>(s.why_)];
    coalesced_ += s.coalesced_.exchange(0, std::memory_order_relaxed);
    const OpenResponse r = s.response_;
    const GoneReason why = s.why_;
    s.target_ = nullptr;
    /* \~english
     * queue_ is NOT cleared: a kick may still be running on another thread --
     * the application has not been told yet -- and it reads queue_.  The mark,
     * set for good, is what makes that kick do nothing.
     * \~spanish
     * queue_ NO se limpia: un aviso puede estar corriendo aun en otro hilo -- a
     * la aplicacion todavia no se le ha dicho -- y lee queue_.  La marca, puesta
     * para siempre, es lo que hace que ese aviso no haga nada.
     * \~ */
    s.gone(r, why);
}

void KickQueue::close(BodySource &s, GoneReason why) noexcept {
    if (s.closing_) return;
    s.closing_ = true;
    s.why_ = why;
    if (s.queued_.exchange(1, std::memory_order_acq_rel) == 0) deliver_gone(s);
}

size_t KickQueue::drain() noexcept {
    BodySource *list = head_.exchange(nullptr, std::memory_order_acquire);
    if (list == nullptr) return 0;

    // \~english A stack comes out last first: turned round, the first kicked is served first.
    // \~spanish Una pila sale al reves: dada la vuelta, la primera avisada se atiende primero.  \~
    BodySource *ordered = nullptr;
    while (list != nullptr) {
        BodySource *next = list->next_;
        list->next_ = ordered;
        ordered = list;
        list = next;
    }

    size_t n = 0;
    while (ordered != nullptr) {
        BodySource &s = *ordered;
        ordered = s.next_;
        s.next_ = nullptr;
        ++n;
        if (s.closing_) {
            // \~english The mark stays set: no later kick pushes it again.
            // \~spanish La marca se queda puesta: ningun aviso posterior la vuelve a meter.  \~
            deliver_gone(s);
            continue;
        }
        coalesced_ += s.coalesced_.exchange(0, std::memory_order_relaxed);
        // \~english Cleared BEFORE the target fills: a kick meanwhile queues it again.
        // \~spanish Limpia ANTES de que el destino rellene: un aviso mientras tanto la vuelve a meter.  \~
        s.queued_.exchange(0, std::memory_order_acq_rel);
        s.target_->on_kick(s);
    }
    taken_ += n;
    return n;
}

KickCounts KickQueue::counts() const noexcept {
    KickCounts c;
    c.taken = taken_;
    c.coalesced = coalesced_;
    c.wakes = wakes_.load(std::memory_order_relaxed);
    c.failed_wakes = failed_wakes_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < 5; ++i) c.gone[i] = gone_[i];
    return c;
}

} // namespace http_vx
