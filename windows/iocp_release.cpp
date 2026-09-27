/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_release.cpp
 * @brief
 * \~english Giving everything back, and not before the kernel has.
 * \~spanish Devolverlo todo, y no antes de que lo haya devuelto el nucleo.
 * \~
 *
 * \~english
 * An operation handed to IOCP names two pieces of memory: its record, whose
 * `OVERLAPPED` the kernel fills in when it finishes, and its buffer, which a
 * read writes into.  Both belong to the kernel until the completion is TAKEN
 * from the port -- and closing the port does not change that: it cancels
 * nothing.  What cancels is closing the socket the operation is on, or
 * `CancelIoEx`, and even a cancelled operation finishes later, writing its
 * result as it goes.
 *
 * So releasing is three steps, in this order: cancel everything (closing the
 * sockets this backend owns, and `CancelIoEx` on the ones the caller owns,
 * which stay open); take every completion back from the port until nothing
 * is held; and only then free the records.  The records used to be freed
 * right after the port was closed, with the reads on the caller's sockets
 * still posted: the next bytes a peer sent landed in a buffer of the pool and
 * in a record that had been given back.
 *
 * If the kernel does not give everything back in time the records are NOT
 * freed: memory kept on purpose is a leak that is counted (@c stranded), and
 * memory freed under the kernel is corruption that nothing would ever point
 * at.
 *
 * \~spanish
 * Una operacion entregada a IOCP nombra dos trozos de memoria: su registro,
 * cuyo `OVERLAPPED` rellena el nucleo al acabar, y su buffer, en el que escribe
 * una lectura.  Los dos son del nucleo hasta que se RECOGE la finalizacion del
 * puerto -- y cerrar el puerto no cambia eso: no cancela nada.  Lo que cancela
 * es cerrar el socket en el que esta la operacion, o `CancelIoEx`, e incluso
 * una operacion cancelada acaba despues, escribiendo su resultado.
 *
 * Asi que soltar son tres pasos, en este orden: cancelarlo todo (cerrando los
 * sockets que son de este backend, y con `CancelIoEx` en los de quien llama,
 * que siguen abiertos); recoger del puerto cada finalizacion hasta que no quede
 * nada pendiente; y solo entonces liberar los registros.  Antes los registros
 * se liberaban nada mas cerrar el puerto, con las lecturas de los sockets de
 * quien llama todavia puestas: los bytes siguientes que mandaba el otro extremo
 * caian en un buffer del pozo y en un registro que ya se habia devuelto.
 *
 * Si el nucleo no lo devuelve todo a tiempo los registros NO se liberan:
 * memoria guardada a proposito es una fuga que se cuenta (@c stranded), y
 * memoria liberada por debajo del nucleo es una corrupcion que nada senalaria
 * nunca.
 * \~
 */
#include "iocp_context.h"

#include "util/alloc/host_allocator.h"

namespace http_vx {

namespace {

/**
 * \~english
 * How long one round of the drain waits for the kernel.  A cancelled
 * operation is given back at once in practice; this bounds the case where
 * something never answers, so that releasing cannot hang for ever.
 * \~spanish
 * Cuanto espera al nucleo una vuelta del vaciado.  Una operacion cancelada se
 * devuelve enseguida en la practica; esto acota el caso de algo que no contesta
 * nunca, para que soltar no pueda quedarse colgado para siempre.
 * \~
 */
constexpr DWORD kDrainRoundMs = 2000;

/// \~english How many completions one round takes.  \~spanish Cuantas finalizaciones recoge una vuelta.  \~
constexpr ULONG kDrainBatch = 64;

/// \~english Whether @p kind runs on a socket the caller owns.
/// \~spanish Si @p kind corre en un socket que es de quien llama.  \~
bool on_callers_socket(OpKind kind) noexcept {
    return kind == OpKind::Ready || kind == OpKind::Recv ||
           kind == OpKind::Send;
}

} // namespace

void IocpBackend::cancel_pending() noexcept {
    for (uint32_t i = 0; i < context_count_; ++i) {
        Context &c = contexts_[i];

        /* \~english
         * Only the caller's sockets: an accept is cancelled by closing the
         * listener and a datagram operation by closing its socket, both done
         * before this.  A socket closed already may have had its number given
         * to somebody else, and cancelling on it would cancel THEIR operation.
         * \~spanish
         * Solo los sockets de quien llama: una aceptacion se cancela al cerrar el
         * socket de escucha y una operacion de datagramas al cerrar su socket, las
         * dos cosas hechas antes que esto.  Un socket ya cerrado puede haberle
         * dado su numero a otro, y cancelar sobre el cancelaria la operacion DE
         * ESE.
         * \~ */
        if (c.busy && on_callers_socket(c.op.kind) && c.op.fd >= 0)
            CancelIoEx(reinterpret_cast<HANDLE>(as_socket(c.op.fd)), &c.ov);
    }
}

bool IocpBackend::drain() noexcept {
    OVERLAPPED_ENTRY entries[kDrainBatch];

    while (in_flight_ != 0) {
        ULONG got = 0;

        if (GetQueuedCompletionStatusEx(static_cast<HANDLE>(iocp_), entries,
                                        kDrainBatch, &got, kDrainRoundMs,
                                        FALSE) == FALSE) {
            last_error_ = static_cast<int32_t>(GetLastError());
            return false;
        }

        for (ULONG i = 0; i < got; ++i) {
            Context *c = reinterpret_cast<Context *>(entries[i].lpOverlapped);
            if (c == nullptr) continue;

            /* \~english
             * An accept that finished before the cancel reached it made a
             * socket nobody will ever be told about: it is closed here.
             * \~spanish
             * Una aceptacion que acabo antes de que llegara la cancelacion hizo un
             * socket del que no se va a enterar nadie: se cierra aqui.
             * \~ */
            if (c->op.kind == OpKind::Accept && c->sock != INVALID_SOCKET)
                closesocket(c->sock);

            give(c);
        }
    }

    return true;
}

void IocpBackend::release() noexcept {
    if (listener_ != kNoSocket) {
        closesocket(static_cast<SOCKET>(listener_));
        listener_ = kNoSocket;
    }

    close_datagrams();

    bool drained = true;
    if (iocp_ != nullptr && contexts_ != nullptr) {
        cancel_pending();
        drained = drain();
    }

    if (iocp_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(iocp_));
        iocp_ = nullptr;
    }

    if (contexts_ != nullptr) {
        if (drained) {
            for (uint32_t i = 0; i < context_count_; ++i) {
                if (contexts_[i].sock != INVALID_SOCKET)
                    closesocket(contexts_[i].sock);
                contexts_[i].~Context();
            }
            util::host_free(contexts_);
        } else {
            /* \~english
             * Kept, not freed: the kernel still names these records.  Counted,
             * because a leak nobody can see is the other way of being silent.
             * \~spanish
             * Guardados, no liberados: el nucleo todavia nombra estos registros.
             * Contados, porque una fuga que no ve nadie es la otra forma de
             * callar.
             * \~ */
            stranded_ += in_flight_;
        }
        contexts_ = nullptr;
    }

    context_count_ = 0;
    free_head_ = 0xFFFFFFFF;
    in_flight_ = 0;
    failed_count_ = 0;
    accept_fn_ = nullptr;
    port_ = 0;

    if (started_) {
        WSACleanup();
        started_ = false;
    }
}

} // namespace http_vx
