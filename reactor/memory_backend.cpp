/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/memory_backend.cpp
 * @brief
 * \~english Taking operations and finishing them, with no kernel involved.
 * \~spanish Coger operaciones y acabarlas, sin ningun nucleo por medio.
 * \~
 */

#include "http_vx/memory_backend.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

Backend::~Backend() = default;

bool MemoryBackend::feed(const uint8_t *p, size_t n) noexcept {
    if (in_len_ + n > sizeof in_) return false;
    util::vesta_memcpy(in_ + in_len_, p, n);
    in_len_ += n;
    return true;
}

bool MemoryBackend::submit(const Op &op) noexcept {
    if (pending_count_ == kMaxPending) return false;

    const size_t at = (pending_head_ + pending_count_) % kMaxPending;
    pending_[at] = op;
    ++pending_count_;
    return true;
}

Completion MemoryBackend::finish(const Op &op) noexcept {
    Completion c;
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;

    /* \~english
     * A failure is checked before anything else, so that an operation which
     * was going to fail does not move bytes first.  On a real backend that is
     * not a choice -- an operation either happened or it did not -- and a
     * backend for testing that half-did things would be teaching the loop to
     * cope with a state no kernel produces.
     * \~spanish
     * Un fallo se comprueba antes que nada, para que una operacion que iba a
     * fallar no mueva bytes primero.  En un backend de verdad eso no es una
     * eleccion -- una operacion ocurrio o no ocurrio -- y un backend de pruebas
     * que hiciera las cosas a medias estaria ensenando al bucle a apanarse con
     * un estado que no produce ningun nucleo.
     * \~ */
    if (failures_ != 0) {
        --failures_;
        c.result = failure_;
        return c;
    }

    switch (op.kind) {
    case OpKind::Accept:
    case OpKind::Close:
        c.result = 0;
        return c;

    case OpKind::Recv:
    case OpKind::RecvFrom: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr) {
            c.result = -1;
            return c;
        }

        size_t take = in_len_ - in_read_;
        if (take > op.length) take = op.length;
        if (chunk_ != 0 && take > chunk_) take = chunk_;

        /* \~english
         * Nothing left and the peer has closed: the read finishes with zero,
         * which is end of stream.  Nothing left and the peer has NOT closed:
         * the operation stays outstanding, which is what a socket does and is
         * the only way a test can arrange a read that is in flight.
         * \~spanish
         * No queda nada y el otro extremo ha cerrado: la lectura acaba con cero,
         * que es fin de flujo.  No queda nada y el otro NO ha cerrado: la
         * operacion sigue pendiente, que es lo que hace un socket y es la unica
         * forma de que una prueba prepare una lectura en vuelo.
         * \~ */
        if (take == 0 && !ended_) {
            c.result = -1;
            return c;
        }

        if (take != 0) {
            /* \~english
             * Written into the buffer HERE, at completion time, and not when
             * the operation was submitted.  That is the whole difference
             * between the two models and the reason the buffer may not be
             * touched in between: the kernel writes when it gets round to it.
             * A backend that filled the buffer on submission would make a loop
             * with the use-after-free in it pass every test.
             * \~spanish
             * Se escribe en el buffer AQUI, al acabar, y no cuando se entrego la
             * operacion.  Esa es toda la diferencia entre los dos modelos y la
             * razon de que no se pueda tocar el buffer en medio: el nucleo
             * escribe cuando le viene bien.  Un backend que llenara el buffer al
             * entregarla haria que un bucle con el uso despues de liberar dentro
             * pasara todas las pruebas.
             * \~ */
            uint8_t *room = b->reserve(take);
            if (room == nullptr) {
                c.result = -1;
                return c;
            }
            util::vesta_memcpy(room, in_ + in_read_, take);
            b->commit(take);
            in_read_ += take;
        }

        c.result = static_cast<int32_t>(take);
        return c;
    }

    case OpKind::Send:
    case OpKind::SendTo: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr) {
            c.result = -1;
            return c;
        }

        size_t take = op.length;
        if (chunk_ != 0 && take > chunk_) take = chunk_;
        if (out_len_ + take > sizeof out_) take = sizeof out_ - out_len_;

        if (op.offset + take > b->size()) {
            c.result = -1;
            return c;
        }

        util::vesta_memcpy(out_ + out_len_, b->data() + op.offset, take);
        out_len_ += take;

        c.result = static_cast<int32_t>(take);
        return c;
    }
    }

    c.result = -1;
    return c;
}

size_t MemoryBackend::wait(Completion *out, size_t cap,
                           int timeout_ms) noexcept {
    (void)timeout_ms;

    size_t made = 0;

    /* \~english
     * A read with nothing to read stays where it is, and everything behind it
     * is looked at ANYWAY.  Stopping at it would be head-of-line blocking that
     * no real backend has: a kernel finishes whichever operation is ready, in
     * whatever order they become so.  A shard whose writes waited behind an
     * idle read would deadlock against a peer that is waiting for the
     * response it has not been sent -- and it would deadlock only against a
     * backend that behaved like this one, which is the worst possible place
     * for a difference.
     *
     * \~spanish
     * Una lectura sin nada que leer se queda donde esta, y lo que va detras se
     * mira IGUAL.  Pararse en ella seria un bloqueo de cabecera que no tiene
     * ningun backend de verdad: un nucleo acaba la operacion que este lista, en
     * el orden en que lo esten.  Un fragmento cuyas escrituras esperaran detras
     * de una lectura parada se abrazaria con un extremo que espera la respuesta
     * que no le han mandado -- y se abrazaria solo contra un backend que se
     * portara como este, que es el peor sitio posible para una diferencia.
     * \~ */
    Op keep[kMaxPending];
    size_t kept = 0;

    const size_t was = pending_count_;
    for (size_t k = 0; k < was; ++k) {
        const Op &op = pending_[(pending_head_ + k) % kMaxPending];

        const bool is_read =
            op.kind == OpKind::Recv || op.kind == OpKind::RecvFrom;
        const bool ready =
            !is_read || in_read_ < in_len_ || ended_ || failures_ != 0;

        if (made < cap && ready) {
            out[made] = finish(op);
            ++made;
        } else {
            keep[kept] = op;
            ++kept;
        }
    }

    for (size_t i = 0; i < kept; ++i) pending_[i] = keep[i];
    pending_head_ = 0;
    pending_count_ = kept;

    return made;
}

} // namespace http_vx
