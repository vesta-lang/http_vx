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
 * The only place in this project that names a platform, and it names two
 * spellings of the same call: reading a descriptor and writing one.  It is
 * here and not in `linux/` or `windows/` because there is nothing platform
 * SHAPED about it -- a pipe is a pipe -- and putting it in one of those would
 * mean writing it twice to say the same thing.
 *
 * \~spanish
 * El unico sitio de este proyecto que nombra una plataforma, y nombra dos
 * grafias de la misma llamada: leer un descriptor y escribir uno.  Esta aqui y
 * no en `linux/` o `windows/` porque no tiene nada de FORMA de plataforma -- una
 * tuberia es una tuberia -- y ponerlo en uno de esos seria escribirlo dos veces
 * para decir lo mismo.
 * \~ */
#ifdef _WIN32
#include <io.h>
#define HTTP_VX_READ _read
#define HTTP_VX_WRITE _write
#else
#include <unistd.h>
#define HTTP_VX_READ ::read
#define HTTP_VX_WRITE ::write
#endif

namespace http_vx {

bool StdioBackend::submit(const Op &op) noexcept {
    if (count_ == kStdioPending) return false;

    pending_[(head_ + count_) % kStdioPending] = op;
    ++count_;
    return true;
}

Completion StdioBackend::finish(const Op &op) noexcept {
    Completion c;
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = 0;

    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    switch (op.kind) {
    case OpKind::Accept:
    case OpKind::Close:
        return c;

    case OpKind::Recv:
    case OpKind::RecvFrom: {
        if (b == nullptr || in_ < 0) {
            c.result = -1;
            return c;
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
            return c;
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
        const auto got = HTTP_VX_READ(in_, room, op.length);
        if (got < 0) {
            c.result = -1;
            return c;
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
        return c;
    }

    case OpKind::Send:
    case OpKind::SendTo: {
        if (b == nullptr || out_ < 0 || op.offset + op.length > b->size()) {
            c.result = -1;
            return c;
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
            return c;
        }

        c.result = static_cast<int32_t>(put);
        return c;
    }
    }

    c.result = -1;
    return c;
}

size_t StdioBackend::wait(Completion *done, size_t cap,
                          int timeout_ms) noexcept {
    (void)timeout_ms;

    size_t made = 0;

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
    for (int pass = 0; pass < 2 && made < cap; ++pass) {
        const bool writes = pass == 0;

        size_t kept = 0;
        const size_t was = count_;

        for (size_t k = 0; k < was; ++k) {
            const size_t at = (head_ + k) % kStdioPending;
            const Op op = pending_[at];

            const bool is_read =
                op.kind == OpKind::Recv || op.kind == OpKind::RecvFrom;

            if (made < cap && is_read != writes) {
                done[made] = finish(op);
                ++made;
            } else {
                pending_[(head_ + kept) % kStdioPending] = op;
                ++kept;
            }
        }

        count_ = kept;
    }

    return made;
}

} // namespace http_vx
