/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/stdio_backend.cpp
 * @brief
 * \~english Finishing operations against two ordinary streams.
 * \~spanish Acabar operaciones contra dos flujos corrientes.
 * \~
 */

#include "http_vx/stdio_backend.h"

/* \~english
 * Writing a descriptor is two spellings of the same call, and is spelled
 * here.  Reading is not: a read has to be ended by a wake from another
 * thread (HVX-5, 6.4), and how is platform SHAPED -- poll on an eventfd,
 * cancelling a synchronous read -- so it lives in each platform's
 * stdio_wake.cpp, and this file is built with it, in that platform's library.
 *
 * \~spanish
 * Escribir un descriptor son dos grafias de la misma llamada, y se escriben
 * aqui.  Leer no: una lectura la tiene que poder acabar un despertar desde otro
 * hilo (HVX-5, 6.4), y el como tiene FORMA de plataforma -- esperar en un
 * eventfd, cancelar una lectura sincrona --, asi que vive en el stdio_wake.cpp
 * de cada plataforma, y este fichero se construye con el, en la biblioteca de
 * esa plataforma.
 * \~ */
#ifdef _WIN32
#include <io.h>
#define HTTP_VX_WRITE _write
#else
#include <unistd.h>
#define HTTP_VX_WRITE ::write
#endif

namespace http_vx {

bool StdioBackend::submit(const Op &op) noexcept {
    /* \~english
     * A cancel is not queued: the read outstanding for that socket is marked
     * and completes as a failure on the next wait, having read nothing.  A
     * read the platform already has in flight is abandoned first, so its
     * buffer is nobody's when it comes back.
     * \~spanish
     * Una cancelacion no se encola: la lectura pendiente de ese socket se marca
     * y acaba como fallo en la espera siguiente, sin haber leido nada.  Una
     * lectura que la plataforma ya tenga en vuelo se abandona antes, para que su
     * buffer no sea de nadie cuando vuelva.
     * \~ */
    if (op.kind == OpKind::Cancel) {
        for (size_t k = 0; k < count_; ++k) {
            Op &p = pending_[(head_ + k) % kStdioPending];
            if ((p.kind == OpKind::Ready || p.kind == OpKind::Recv) && p.fd == op.fd) {
                abandon_read();
                p.fd = kCancelledFd;
                break;
            }
        }
        return true;
    }

    if (count_ == kStdioPending) return false;

    pending_[(head_ + count_) % kStdioPending] = op;
    ++count_;
    return true;
}

bool StdioBackend::finish(const Op &op, Completion &c, int timeout_ms) noexcept {
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = 0;

    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    // \~english A cancelled read: a failure, and nothing read.  \~spanish Una lectura cancelada: un fallo, y nada leido.  \~
    if (op.fd == kCancelledFd) {
        c.result = -1;
        return true;
    }

    switch (op.kind) {
    case OpKind::Accept:
    case OpKind::Close:
    case OpKind::Cancel:
        return true;

    case OpKind::Ready:
        /* \~english
         * Always, at once.  A pipe is not something that can be asked whether
         * it has anything without taking it, so the honest answer is "go and
         * read", and the read below blocks until there is something -- which is
         * what reading a pipe has always done here.
         *
         * It costs one extra completion per message and buys nothing, and that
         * is right: what the asking-in-two-halves buys is a buffer not held by
         * an idle connection, and a server that talks down a pipe has exactly
         * one connection.  R1 is about a million of them.
         *
         * \~spanish
         * Siempre, en el acto.  A una tuberia no se le puede preguntar si tiene
         * algo sin llevarselo, asi que la respuesta honesta es "ve y lee", y la
         * lectura de abajo se queda esperando hasta que haya algo -- que es lo que
         * ha hecho siempre aqui leer de una tuberia.
         *
         * Cuesta una finalizacion mas por mensaje y no compra nada, y eso esta
         * bien: lo que compra preguntar en dos mitades es un buffer que no tiene
         * una conexion parada, y un servidor que habla por una tuberia tiene
         * exactamente una conexion.  La R1 va de un millon de ellas.
         * \~ */
        return true;

    case OpKind::RecvFrom:
    case OpKind::SendTo:
        /* \~english
         * Refused, and counted.  A pipe has no datagrams, and answering as a
         * stream would hand up bytes with no sender as if they were one.
         * \~spanish
         * Rechazado, y contado.  Una tuberia no tiene datagramas, y contestar
         * como flujo entregaria bytes sin remitente como si fueran uno.
         * \~ */
        ++refused_datagrams_;
        c.result = -1;
        return true;

    case OpKind::Recv: {
        if (b == nullptr || in_ < 0) {
            c.result = -1;
            return true;
        }

        /* \~english
         * Room is asked of the buffer first and the stream is read straight
         * into it.  Reading somewhere else and copying would be a copy of
         * every byte the server ever receives, to gain nothing: the buffer is
         * where the bytes are going.
         * \~spanish
         * Primero se le pide sitio al buffer y el flujo se lee directamente
         * dentro.  Leer en otro sitio y copiar seria una copia de todos los
         * bytes que reciba el servidor en su vida, para no ganar nada: el buffer
         * es adonde van los bytes.
         * \~ */
        uint8_t *room = b->reserve(op.length);
        if (room == nullptr) {
            c.result = -1;
            return true;
        }

        /* \~english
         * Whatever has arrived, which is what a descriptor read gives back and
         * a buffered one does not.  A read that waited for all it asked for
         * would wait for the request AFTER this one.
         * \~spanish
         * Lo que haya llegado, que es lo que devuelve una lectura de descriptor
         * y no una con buffer.  Una que esperara a todo lo que pidio esperaria a
         * la peticion SIGUIENTE a esta.
         * \~ */
        bool woken = false;
        const long got = read_or_wake(room, op.length, timeout_ms, woken);
        // \~english Woken first: nothing read, and the read stays pending for the next wait.
        // \~spanish Despertado antes: nada leido, y la lectura sigue pendiente para la espera siguiente.  \~
        if (woken) return false;
        if (got < 0) {
            c.result = -1;
            return true;
        }

        b->commit(static_cast<size_t>(got));

        /* \~english
         * Nothing read is the end of the stream, which is not an error: it is
         * the peer closing its sending half, and a zero on a read is how that
         * is said.
         * \~spanish
         * No leer nada es el fin del flujo, que no es un error: es el otro
         * extremo cerrando su mitad de enviar, y un cero en una lectura es como
         * se dice eso.
         * \~ */
        if (got == 0) ended_ = true;

        c.result = static_cast<int32_t>(got);
        return true;
    }

    case OpKind::Send: {
        if (b == nullptr || out_ < 0 || op.offset + op.length > b->size()) {
            c.result = -1;
            return true;
        }

        /* \~english
         * A short write is reported as a short write and not retried here.
         * The loop above already knows how to carry a response on from where
         * it stopped -- it consumes what went out and submits the rest -- so
         * looping in here would be the same thing written twice, and the copy
         * inside a backend would be the one nobody tests.
         * \~spanish
         * Una escritura corta se informa como escritura corta y no se reintenta
         * aqui.  El bucle de arriba ya sabe continuar una respuesta desde donde
         * se paro -- consume lo que salio y entrega el resto -- asi que dar
         * vueltas aqui seria lo mismo escrito dos veces, y la copia de dentro de
         * un backend seria la que no prueba nadie.
         * \~ */
        const auto put = HTTP_VX_WRITE(out_, b->data() + op.offset, op.length);
        if (put < 0) {
            c.result = -1;
            return true;
        }

        c.result = static_cast<int32_t>(put);
        return true;
    }
    }

    c.result = -1;
    return true;
}

size_t StdioBackend::wait(Completion *done, size_t cap,
                          int timeout_ms) noexcept {
    size_t made = 0;

    // \~english Nothing pending: sleep until a wake or the deadline (see idle).
    // \~spanish Nada pendiente: dormir hasta un despertar o el plazo (ver idle).  \~
    if (count_ == 0) {
        if (timeout_ms != 0) idle(timeout_ms);
        return 0;
    }

    /* \~english
     * Writes are finished first, and that is the one ordering decision here.
     * A read blocks until the peer says something, so finishing a write behind
     * a read would hold an answer that is ready until the peer sends the NEXT
     * request -- and a peer that is waiting for this answer before it sends
     * anything would wait for ever.  Both ends waiting for each other is a
     * deadlock, and here it would be one this backend invented.
     *
     * \~spanish
     * Las escrituras se acaban primero, y es la unica decision de orden que hay
     * aqui.  Una lectura bloquea hasta que el otro extremo diga algo, asi que
     * acabar una escritura detras de una lectura retendria una respuesta ya
     * lista hasta que el otro mandara la peticion SIGUIENTE -- y un extremo que
     * espera esta respuesta antes de mandar nada esperaria para siempre.  Los
     * dos extremos esperandose es un abrazo mortal, y aqui seria uno que se
     * invento este backend.
     * \~ */
    /* \~english
     * A wake ends the pass: the read it interrupted, and every one behind
     * it, stay pending, and the wait returns so the shard can take its kicks.
     * \~spanish
     * Un despertar acaba la pasada: la lectura que interrumpio, y todas las de
     * detras, siguen pendientes, y la espera vuelve para que el fragmento atienda
     * sus avisos.
     * \~ */
    bool woken = false;

    for (int pass = 0; pass < 2 && made < cap; ++pass) {
        const bool writes = pass == 0;

        size_t kept = 0;
        const size_t was = count_;

        for (size_t k = 0; k < was; ++k) {
            const size_t at = (head_ + k) % kStdioPending;
            const Op op = pending_[at];

            const bool is_read = op.kind == OpKind::Recv ||
                                 op.kind == OpKind::RecvFrom ||
                                 op.kind == OpKind::Ready;

            if (!woken && made < cap && is_read != writes &&
                finish(op, done[made], made != 0 ? 0 : timeout_ms)) {
                ++made;
            } else {
                if (is_read != writes && made < cap) woken = true;
                pending_[(head_ + kept) % kStdioPending] = op;
                ++kept;
            }
        }

        count_ = kept;
    }

    return made;
}

} // namespace http_vx
