/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard_open.cpp
 * @brief
 * \~english The shard's side of open responses: limits, counts, room to write, and held reads (HVX-5).
 * \~spanish El lado del fragmento de las respuestas abiertas: topes, cuentas, sitio para escribir, y lecturas retenidas (HVX-5).
 * \~
 */

#include "http_vx/shard.h"

namespace http_vx {

OpenPort::~OpenPort() = default;

OpenCounts Shard::open_counts() const noexcept { return open_counts_; }

OpenResponse Shard::open(ConnHandle c, uint64_t stream, BodySource &s,
                         KickTarget &target) noexcept {
    ConnHot *h = conns_.hot(c);
    ConnCold *cold = conns_.cold(c);

    /* \~english
     * A connection that is ending, or a shard letting go, opens nothing: the
     * response would be ended before its first fill.  Refused like a limit,
     * and counted the same.
     * \~spanish
     * Una conexion que se esta acabando, o un fragmento que lo suelta todo, no
     * abre nada: la respuesta acabaria antes de su primer relleno.  Se rechaza
     * como un tope, y se cuenta igual.
     * \~ */
    if (h == nullptr || cold == nullptr || (h->flags & kClosing) != 0 || shutting_down_ ||
        open_counts_.open_now >= cfg_.max_open || cold->open >= cfg_.max_open_per_conn) {
        ++open_counts_.refused;
        return OpenResponse();
    }

    OpenResponse r;
    r.conn = c;
    r.stream = stream;
    kicks_.open(s, target, r);

    ++cold->open;
    ++open_counts_.open_now;
    ++open_counts_.opened;
    return r;
}

size_t Shard::fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept {
    done = false;
    size_t n = s.fill(s.response(), dst, room, done);
    if (n > room) n = room;
    ++open_counts_.fills;
    open_counts_.filled_bytes += n;
    return n;
}

void Shard::end(BodySource &s, GoneReason why) noexcept {
    /* \~english
     * The response is read BEFORE closing: @c gone may be delivered inside
     * the close, and after it the source is the application's to free.
     * \~spanish
     * La respuesta se lee ANTES de cerrar: @c gone puede entregarse dentro del
     * cierre, y despues la fuente es de la aplicacion para liberarla.
     * \~ */
    const OpenResponse r = s.response();
    if (!kicks_.close(s, why)) return;

    ConnCold *cold = conns_.cold(r.conn);
    if (cold != nullptr && cold->open != 0) --cold->open;
    if (open_counts_.open_now != 0) --open_counts_.open_now;
}

void Shard::ask(ConnHandle c) noexcept {
    if (asked_next_ == nullptr || c.slot >= cfg_.connections) return;
    if (asked_next_[c.slot] != kNotAsked) return;

    asked_next_[c.slot] = kNoSlot;
    if (asked_tail_ == kNoSlot) {
        asked_head_ = c.slot;
    } else {
        asked_next_[asked_tail_] = c.slot;
    }
    asked_tail_ = c.slot;
}

void Shard::want_writable(ConnHandle c) noexcept {
    ConnHot *h = conns_.hot(c);
    if (h == nullptr || (h->flags & kClosing) != 0 || shutting_down_) return;
    if ((h->flags & kWantWritable) != 0) return;

    h->flags |= kWantWritable;
    ask(c);
}

void Shard::hold_reads(ConnHandle c, bool hold) noexcept {
    ConnHot *h = conns_.hot(c);
    if (h == nullptr) return;

    if (hold) {
        h->flags |= kHeld;
        return;
    }
    if ((h->flags & kHeld) == 0) return;

    h->flags &= static_cast<uint16_t>(~kHeld);
    h->flags |= kResume;
    ask(c);
}

GoneReason Shard::closing_reason(ConnHandle c) const noexcept {
    if (shutting_down_) return GoneReason::Shutdown;
    const ConnHot *h = conns_.hot(c);
    if (h != nullptr && (h->flags & kExpired) != 0) return GoneReason::IdleTimeout;
    return GoneReason::ConnectionClosed;
}

void Shard::run_writable(ConnHandle c, ConnHot &h) noexcept {
    h.flags &= static_cast<uint16_t>(~kWantWritable);

    /* \~english
     * No buffer is not a failure of the connection: the pool is lent out,
     * and a completion that gives one back is what ends the wait.  So the
     * request is kept and asked again -- counted, because a number that moves
     * says the pool is too small for what is open.
     * \~spanish
     * Que no haya buffer no es un fallo de la conexion: el pozo esta prestado, y
     * una finalizacion que devuelva uno es lo que acaba la espera.  Asi que la
     * peticion se guarda y se vuelve a pedir -- contado, porque un numero que se
     * mueve dice que el pozo es pequeno para lo que hay abierto.
     * \~ */
    const uint32_t b = pool_.acquire();
    if (b == kNoBuffer) {
        ++open_counts_.starved;
        h.flags |= kWantWritable;
        ask(c);
        return;
    }

    Buffer *out = pool_.at(b);
    const bool keep = service_->on_writable(c, *out, cfg_.write_size);

    ConnHot *now = conns_.hot(c);
    if (now == nullptr) {
        pool_.release(b);
        return;
    }

    if (out->empty()) {
        pool_.release(b);
    } else if (!want_write(c, *now, b)) {
        pool_.release(b);
        close(c);
        return;
    }

    if (!keep) close(c);
}

void Shard::run_asked() noexcept {
    /* \~english
     * The list is taken whole first: what is asked while it is served goes on
     * a new one, for the next turn.  A buffer that could not be had is asked
     * again that way, and waits for the completion that frees one instead of
     * turning here.
     * \~spanish
     * La lista se coge entera primero: lo que se pida mientras se atiende va a
     * una nueva, para la vuelta siguiente.  Un buffer que no se pudo conseguir se
     * vuelve a pedir asi, y espera a la finalizacion que libere uno en vez de dar
     * vueltas aqui.
     * \~ */
    uint32_t at = asked_head_;
    asked_head_ = kNoSlot;
    asked_tail_ = kNoSlot;

    while (at != kNoSlot) {
        const uint32_t next = asked_next_[at];
        asked_next_[at] = kNotAsked;

        const ConnHandle c = conns_.at(at);
        at = next;

        ConnHot *h = conns_.hot(c);
        if (h == nullptr) continue;

        if ((h->flags & kResume) != 0) {
            h->flags &= static_cast<uint16_t>(~kResume);

            /* \~english
             * Held no more: what arrived while it was held is handed over
             * first -- the requests that waited behind the open response --
             * and only then is anything more read.
             * \~spanish
             * Ya no esta retenida: lo que llego mientras lo estaba se entrega
             * primero -- las peticiones que esperaron detras de la respuesta
             * abierta -- y solo despues se lee algo mas.
             * \~ */
            /* \~english
             * The service is called even when the shard holds nothing of the
             * connection: a service that wraps another -- TLS -- may hold what
             * waited, already decrypted, and nothing else would hand it over
             * until the peer said something new.
             * \~spanish
             * Se llama al servicio aunque el fragmento no guarde nada de la
             * conexion: un servicio que envuelve a otro -- TLS -- puede tener lo
             * que espero, ya descifrado, y nada mas lo entregaria hasta que el
             * otro extremo dijera algo nuevo.
             * \~ */
            if ((h->flags & (kHeld | kClosing | kReadPending)) == 0) {
                const uint32_t b = h->reading;
                h->reading = kNoBuffer;
                serve(c, *h, b);
            }

            h = conns_.hot(c);
            if (h == nullptr) continue;
        }

        if ((h->flags & (kWantWritable | kWritePending | kClosing)) == kWantWritable &&
            h->queue == kNoBuffer) {
            run_writable(c, *h);
        }
    }
}

void Shard::shut_down() noexcept {
    /* \~english
     * Every connection still here is told it went, so the service ends what
     * it had open -- with @c GoneReason::Shutdown, which is what
     * @c closing_reason says from now on.  A @c gone that had to wait for its
     * source to leave the stack is delivered by the drain after.
     * \~spanish
     * A cada conexion que sigue aqui se le dice que se fue, para que el servicio
     * acabe lo que tuviera abierto -- con @c GoneReason::Shutdown, que es lo que
     * dice @c closing_reason desde ahora.  Un @c gone que tuvo que esperar a que
     * su fuente saliera de la pila lo entrega el vaciado de despues.
     * \~ */
    shutting_down_ = true;

    if (service_ != nullptr) {
        for (uint32_t slot = 0; slot < cfg_.connections; ++slot) {
            const ConnHandle c = conns_.at(slot);
            if (c.valid()) service_->on_close(c);
        }
    }
    if (datagram_service_ != nullptr) datagram_service_->on_shutdown();

    kicks_.drain();
}

OpenResponse Shard::DatagramPort::open(ConnHandle c, uint64_t stream, BodySource &s,
                                       KickTarget &target) noexcept {
    Shard &sh = *shard_;
    if (sh.shutting_down_ || sh.open_counts_.open_now >= sh.cfg_.max_open) {
        ++sh.open_counts_.refused;
        return OpenResponse();
    }

    OpenResponse r;
    r.conn = c;
    r.stream = stream;
    sh.kicks_.open(s, target, r);

    ++sh.open_counts_.open_now;
    ++sh.open_counts_.opened;
    return r;
}

size_t Shard::DatagramPort::fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept {
    return shard_->fill(s, dst, room, done);
}

void Shard::DatagramPort::end(BodySource &s, GoneReason why) noexcept {
    Shard &sh = *shard_;
    if (!sh.kicks_.close(s, why)) return;
    if (sh.open_counts_.open_now != 0) --sh.open_counts_.open_now;
}

} // namespace http_vx
