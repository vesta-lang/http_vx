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

bool MemoryBackend::arrive(int32_t fd) noexcept {
    if (arrivals_count_ == 16) return false;

    arrivals_[(arrivals_head_ + arrivals_count_) % 16] = fd;
    ++arrivals_count_;
    return true;
}

bool MemoryBackend::feed(const uint8_t *p, size_t n) noexcept {
    /* \~english
     * What has been read is forgotten before more is added.  Without this the
     * room fills up with bytes nobody will look at again, and a run long
     * enough -- a benchmark, a fuzzing session -- stops being able to feed
     * anything: the peer would appear to go quiet for no reason, which is the
     * kind of thing that looks like a bug in what is being measured.
     * \~spanish
     * Lo que ya se leyo se olvida antes de anadir mas.  Sin esto el sitio se
     * llena de bytes que no va a mirar nadie, y una corrida larga -- un banco,
     * una sesion de fuzzing -- deja de poder dar nada: el otro extremo pareceria
     * quedarse callado sin motivo, que es de las cosas que parecen un fallo de
     * lo que se esta midiendo.
     * \~ */
    if (in_read_ == in_len_) {
        in_read_ = 0;
        in_len_ = 0;
    }

    if (in_len_ + n > sizeof in_) return false;
    util::vesta_memcpy(in_ + in_len_, p, n);
    in_len_ += n;
    return true;
}

bool MemoryBackend::submit(const Op &op) noexcept {
    /* \~english
     * A cancel is not queued: it marks the read outstanding on that socket,
     * which then completes as a failure on the next wait, bytes or not.  A
     * scan, because this backend exists for tests and holds a few operations.
     * \~spanish
     * Una cancelacion no se encola: marca la lectura pendiente en ese socket,
     * que acaba como fallo en la espera siguiente, haya bytes o no.  Una
     * busqueda, porque este backend existe para las pruebas y tiene pocas
     * operaciones.
     * \~ */
    if (op.kind == OpKind::Cancel) {
        for (size_t k = 0; k < pending_count_; ++k) {
            Op &p = pending_[(pending_head_ + k) % kMaxPending];
            if ((p.kind == OpKind::Ready || p.kind == OpKind::Recv) && p.fd == op.fd) {
                p.fd = kCancelledFd;
                ++cancelled_;
                break;
            }
        }
        return true;
    }

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

    // \~english A cancelled read: a failure, and nothing read.  \~spanish Una lectura cancelada: un fallo, y nada leido.  \~
    if (op.fd == kCancelledFd) {
        c.result = -1;
        return c;
    }

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
        /* \~english
         * The socket that arrived, taken in the order they arrived in.  The
         * count is not checked here because @c wait already decided this
         * operation was ready, and it decided it by looking at exactly this.
         * \~spanish
         * El socket que llego, cogido en el orden en que llegaron.  Aqui no se
         * comprueba la cuenta porque @c wait ya decidio que esta operacion estaba
         * lista, y lo decidio mirando justo esto.
         * \~ */
        c.fd = arrivals_[arrivals_head_];
        arrivals_head_ = (arrivals_head_ + 1) % 16;
        --arrivals_count_;
        c.result = 0;
        return c;

    case OpKind::Ready:
        /* \~english
         * It is ready, and nothing was read to find that out.  @c wait decided
         * it by looking at the same bytes a read would have taken, and left
         * them where they are -- which is the whole of what this operation is:
         * the answer to "is there something" without the buffer that answering
         * "what is it" would need.
         * \~spanish
         * Esta listo, y no se leyo nada para averiguarlo.  @c wait lo decidio
         * mirando los mismos bytes que se habria llevado una lectura, y los dejo
         * donde estan -- que es todo lo que es esta operacion: la respuesta a "hay
         * algo" sin el buffer que necesitaria contestar "que es".
         * \~ */
        c.result = 0;
        return c;

    case OpKind::Close:
        /* \~english
         * Counted rather than done, because there is no socket to close: what
         * a test needs to be able to see is that the shard ASKED, which is the
         * difference between a refused connection and a leaked descriptor.
         * \~spanish
         * Se cuenta en vez de hacerse, porque no hay ningun socket que cerrar: lo
         * que una prueba tiene que poder ver es que el fragmento lo PIDIO, que es
         * la diferencia entre una conexion rechazada y un descriptor perdido.
         * \~ */
        ++closed_;
        c.result = 0;
        return c;

    // \~english Never queued (see submit).  \~spanish Nunca se encola (ver submit).  \~
    case OpKind::Cancel:
        c.result = 0;
        return c;

    case OpKind::RecvFrom:
    case OpKind::SendTo:
        return finish_datagram(op);

    case OpKind::Recv: {
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

    case OpKind::Send: {
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

        /* \~english
         * No room left is a FAILURE and not a write of nothing.  Reporting
         * zero would say the operation worked and moved nothing, and a caller
         * that believed it would submit the rest -- for ever, because there is
         * no rest that will ever fit.  A loop that spins is worse than an
         * error, because an error stops.
         * \~spanish
         * Que no quede sitio es un FALLO y no una escritura de nada.  Decir cero
         * diria que la operacion funciono y no movio nada, y quien se lo creyera
         * entregaria el resto -- para siempre, porque no hay resto que vaya a
         * caber nunca.  Un bucle que da vueltas es peor que un error, porque un
         * error para.
         * \~ */
        if (take == 0 && op.length != 0) {
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
    /* \~english
     * What is kept is written back over what has been read, in place.  The
     * first version copied the whole ring into an array on the stack -- two
     * hundred and fifty-six operations, eight kilobytes, on EVERY wait -- and
     * that is what the benchmark found first: thirty-three microseconds to
     * serve a request through memory, almost all of it moving operations
     * nobody had asked about.
     *
     * It works because what is kept is never more than what has been looked
     * at, so the write index is never ahead of the read index.
     *
     * \~spanish
     * Lo que se queda se escribe encima de lo ya leido, en el sitio.  La
     * primera version copiaba el anillo entero a un array de la pila --
     * doscientas cincuenta y seis operaciones, ocho kilobytes, en CADA espera --
     * y eso es lo primero que encontro el banco: treinta y tres microsegundos en
     * servir una peticion por memoria, casi todos moviendo operaciones por las
     * que no habia preguntado nadie.
     *
     * Funciona porque lo que se queda no es nunca mas que lo que ya se ha
     * mirado, asi que el indice de escritura no va nunca por delante del de
     * lectura.
     * \~ */
    size_t kept = 0;
    const size_t was = pending_count_;

    for (size_t k = 0; k < was; ++k) {
        const Op op = pending_[(pending_head_ + k) % kMaxPending];

        const bool ready = !waiting(op) || failures_ != 0;

        if (made < cap && ready) {
            out[made] = finish(op);
            ++made;
        } else {
            pending_[(pending_head_ + kept) % kMaxPending] = op;
            ++kept;
        }
    }

    pending_count_ = kept;
    return made;
}

} // namespace http_vx
