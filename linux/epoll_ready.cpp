/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/epoll_ready.cpp
 * @brief
 * \~english The completions epoll already knows, and the rule that none is ever lost.
 * \~spanish Las finalizaciones que epoll ya sabe, y la regla de que no se pierde ninguna.
 * \~
 *
 * \~english
 * On epoll a completion can be true before anybody waits for it -- an
 * operation tried at once, a refusal, a socket closed with operations still
 * queued on it -- so it has to be kept somewhere until @c wait hands it out.
 * That list used to be 256 places, and the code that filled it either checked
 * for room (and parked or refused) or did not: closing a datagram socket
 * answered up to 128 queued operations into it without looking, and every one
 * that did not fit was a pooled buffer that never came back -- a leak that
 * ends in a server that cannot read, with nothing anywhere saying why.
 *
 * So the bound moved to where a refusal is still honest.  Every operation
 * this backend ACCEPTS is either in the list or waiting (@c in_flight_), and
 * the list is kept at least as large as both together: @c submit makes that
 * true before it does anything, growing the list if it must.  After that,
 * writing a completion never needs a check, because the room was reserved
 * when the operation was accepted.  The only failure left is the memory for
 * growing it, and that is said where it can be said: @c submit returns false
 * with nothing done, @c last_error is `ENOMEM`, and @c refused counts it.
 *
 * Growing is not the steady state: the list starts with 256 places, grows by
 * doubling, and never shrinks, so a server pays for its largest burst once.
 *
 * \~spanish
 * En epoll una finalizacion puede ser cierta antes de que la espere nadie --
 * una operacion intentada en el acto, un rechazo, un socket cerrado con
 * operaciones todavia en cola -- asi que hay que guardarla en algun sitio hasta
 * que @c wait la entregue.  Esa lista tenia 256 sitios, y el codigo que la
 * llenaba o miraba si habia sitio (y guardaba o rechazaba) o no: cerrar un
 * socket de datagramas contestaba ahi hasta 128 operaciones encoladas sin
 * mirar, y cada una que no cabia era un buffer del pozo que no volvia nunca --
 * una fuga que acaba en un servidor que no puede leer, sin nada en ningun sitio
 * que diga por que.
 *
 * Asi que el limite se movio a donde un rechazo todavia es honesto.  Toda
 * operacion que este backend ACEPTA esta o en la lista o esperando
 * (@c in_flight_), y la lista se mantiene al menos tan grande como las dos
 * juntas: @c submit lo hace cierto antes de hacer nada, haciendo crecer la
 * lista si hace falta.  Despues, escribir una finalizacion no necesita
 * comprobar nada, porque el sitio se reservo al aceptar la operacion.  El unico
 * fallo que queda es la memoria para crecer, y se dice donde se puede decir:
 * @c submit devuelve false sin haber hecho nada, @c last_error es `ENOMEM`, y
 * @c refused lo cuenta.
 *
 * Crecer no es el estado normal: la lista empieza con 256 sitios, crece
 * doblando y no encoge nunca, asi que un servidor paga su rafaga mayor una vez.
 * \~
 */

#include "epoll_waiting.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <errno.h>

#include <type_traits>

namespace http_vx {

namespace {

/**
 * \~english
 * The places the list starts with.  A power of two, like every size it grows
 * to, so that a position in the ring is a mask and not a division.
 * \~spanish
 * Los sitios con los que empieza la lista.  Potencia de dos, como todos los
 * tamanos a los que crece, para que una posicion del anillo sea una mascara y
 * no una division.
 * \~
 */
constexpr size_t kFirstReadyRoom = 256;

static_assert((kFirstReadyRoom & (kFirstReadyRoom - 1)) == 0,
              "the ready ring is indexed with a mask");
static_assert(std::is_trivially_copyable<Completion>::value,
              "completions are moved as bytes when the ring grows");

} // namespace

bool EpollBackend::make_room() noexcept {
    if (ready_count_ + in_flight_ < ready_room_) return true;

    const size_t room = ready_room_ == 0 ? kFirstReadyRoom : ready_room_ * 2;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);
    Completion *grown =
        static_cast<Completion *>(util::host_alloc(room * sizeof(Completion)));

    if (grown == nullptr) {
        last_error_ = ENOMEM;
        ++refused_;
        return false;
    }

    /* \~english
     * The ring is laid out flat in the new room, oldest first: at most two
     * pieces, the one from the head to the end and the one that wrapped.
     * \~spanish
     * El anillo se coloca plano en el sitio nuevo, el mas viejo primero: como
     * mucho dos trozos, el de la cabeza al final y el que dio la vuelta.
     * \~ */
    if (ready_count_ != 0) {
        const size_t first = ready_room_ - ready_head_ < ready_count_
                                 ? ready_room_ - ready_head_
                                 : ready_count_;
        util::vesta_memcpy(grown, ready_ + ready_head_, first * sizeof(Completion));
        util::vesta_memcpy(grown + first, ready_,
                           (ready_count_ - first) * sizeof(Completion));
    }

    if (ready_ != nullptr) util::host_free(ready_);

    ready_ = grown;
    ready_room_ = room;
    ready_head_ = 0;
    return true;
}

void EpollBackend::drop_ready() noexcept {
    if (ready_ != nullptr) util::host_free(ready_);
    ready_ = nullptr;
    ready_room_ = 0;
    ready_head_ = 0;
    ready_count_ = 0;
}

void EpollBackend::remember(const Op &op, int32_t result, int32_t fd) noexcept {
    Completion &c = ready_[(ready_head_ + ready_count_) & (ready_room_ - 1)];
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = result;
    c.fd = fd;
    ++ready_count_;
}

size_t EpollBackend::take_ready(Completion *out, size_t cap,
                                size_t made) noexcept {
    while (made < cap && ready_count_ != 0) {
        out[made] = ready_[ready_head_];
        ++made;
        ready_head_ = (ready_head_ + 1) & (ready_room_ - 1);
        --ready_count_;
    }
    return made;
}

void EpollBackend::fail_waiting(int32_t fd) noexcept {
    Waiting &w = waiting_[fd];

    if (w.dgram >= 0) {
        dgram_fail(w.dgram);
        return;
    }

    if (w.has_read) {
        remember(w.read, -1, -1);
        w.has_read = false;
        --in_flight_;
    }

    if (w.has_write) {
        remember(w.write, -1, -1);
        w.has_write = false;
        --in_flight_;
    }
}

} // namespace http_vx
