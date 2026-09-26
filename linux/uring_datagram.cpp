/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/uring_datagram.cpp
 * @brief
 * \~english Datagrams on io_uring: one message per ring entry, the ring as the batch.
 * \~spanish Datagramas sobre io_uring: un mensaje por entrada del anillo, el anillo como lote.
 * \~
 *
 * \~english
 * Each datagram is an `IORING_OP_RECVMSG` or `IORING_OP_SENDMSG` naming a
 * `msghdr` -- the same message epoll builds, from `datagram_linux.h`.  The
 * difference is lifetime: the kernel reads the message when it gets to the
 * entry and writes the address and the control data when the datagram
 * arrives, so the message lives here, one per slot, until the completion.
 *
 * The receive asks with `MSG_TRUNC`, so that a cut datagram comes back with
 * its real length (recvmsg(2), MSG_TRUNC for Internet datagram sockets) as
 * well as with the flag the kernel writes back into the message.
 *
 * \~spanish
 * Cada datagrama es un `IORING_OP_RECVMSG` o un `IORING_OP_SENDMSG` que nombra
 * un `msghdr` -- el mismo mensaje que construye epoll, de `datagram_linux.h`.
 * La diferencia es la vida: el nucleo lee el mensaje cuando llega a la entrada y
 * escribe la direccion y los datos de control cuando llega el datagrama, asi que
 * el mensaje vive aqui, uno por sitio, hasta la finalizacion.
 *
 * La recepcion pide con `MSG_TRUNC`, para que un datagrama cortado vuelva con su
 * longitud real (recvmsg(2), MSG_TRUNC para sockets de datagramas de Internet)
 * ademas de con el indicador que el nucleo vuelve a escribir en el mensaje.
 * \~
 */

#include "http_vx/uring_backend.h"

#include "datagram_linux.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memset.h"

#include <errno.h>
#include <linux/io_uring.h>
#include <unistd.h>

#include <new>

namespace http_vx {

/**
 * @brief
 * \~english The message of one datagram in flight.
 * \~spanish El mensaje de un datagrama en vuelo.
 * \~
 */
struct UringBackend::DgramMsg {
    msghdr msg;
    udp::MsgRoom room;
};

void UringBackend::release_datagrams() noexcept {
    if (msgs_ == nullptr) return;
    for (uint32_t i = 0; i < slot_count_; ++i) msgs_[i].~DgramMsg();
    util::host_free(msgs_);
    msgs_ = nullptr;
}

int32_t UringBackend::open_datagram(const char *host, uint16_t port,
                                    NetAddress &bound) noexcept {
    bound.len = 0;
    if (ring_ == nullptr || slots_ == nullptr) return -1;

    /* \~english
     * The messages are made with the first datagram socket and not with the
     * ring: a backend that only ever serves streams does not pay for them.
     * \~spanish
     * Los mensajes se hacen con el primer socket de datagramas y no con el
     * anillo: un backend que solo sirve flujos no los paga.
     * \~ */
    if (msgs_ == nullptr) {
        const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                     util::AllocFill::Sparse);
        msgs_ = static_cast<DgramMsg *>(
            util::host_alloc(static_cast<size_t>(slot_count_) * sizeof(DgramMsg)));
        if (msgs_ == nullptr) {
            last_error_ = ENOMEM;
            return -1;
        }
        for (uint32_t i = 0; i < slot_count_; ++i) new (&msgs_[i]) DgramMsg();
    }

    /* \~english
     * Blocking, as the listening socket here is: a ring waits on a socket by
     * itself, and one marked non-blocking would have its receives come back
     * as "try again" instead of waiting.
     * \~spanish
     * Bloqueante, como el socket de escucha de aqui: un anillo espera sobre un
     * socket por su cuenta, y uno marcado como no bloqueante haria que sus
     * recepciones volvieran con "prueba otra vez" en vez de esperar.
     * \~ */
    const int s = udp::open_socket(host, port, false, bound, last_error_);
    if (s < 0) return -1;

    if (!dgram_.add(s, bound)) {
        close(s);
        bound.len = 0;
        last_error_ = EMFILE;
        return -1;
    }

    return s;
}

bool UringBackend::prep_datagram(const Op &op, void *entry,
                                 uint32_t slot) noexcept {
    io_uring_sqe *sqe = static_cast<io_uring_sqe *>(entry);
    const int32_t at = dgram_.find(op.fd);
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    /* \~english
     * Only on a socket opened for datagrams: on any other a receive would be
     * a stream's bytes delivered as a datagram from nobody.
     * \~spanish
     * Solo sobre un socket abierto para datagramas: sobre cualquier otro una
     * recepcion serian los bytes de un flujo entregados como un datagrama de
     * nadie.
     * \~ */
    if (at < 0 || b == nullptr || msgs_ == nullptr) {
        last_error_ = ENOTSOCK;
        if (op.kind == OpKind::RecvFrom)
            ++dgram_counts_.receive_errors;
        else
            ++dgram_counts_.send_errors;
        return false;
    }

    DgramMsg &m = msgs_[slot];

    if (op.kind == OpKind::RecvFrom) {
        uint8_t *into = datagram_reserve(*b, op.length);
        if (into == nullptr) {
            ++dgram_counts_.receive_errors;
            return false;
        }

        udp::aim_receive(m.msg, m.room, into, op.length);
        sqe->opcode = IORING_OP_RECVMSG;
        sqe->fd = op.fd;
        sqe->addr = reinterpret_cast<uint64_t>(&m.msg);
        sqe->len = 1;
        sqe->msg_flags = MSG_TRUNC;
        return true;
    }

    if (!udp::aim_send(m.msg, m.room, *b, op.length,
                       dgram_.bound(static_cast<size_t>(at)).len)) {
        last_error_ = EINVAL;
        ++dgram_counts_.send_errors;
        return false;
    }

    sqe->opcode = IORING_OP_SENDMSG;
    sqe->fd = op.fd;
    sqe->addr = reinterpret_cast<uint64_t>(&m.msg);
    sqe->len = 1;
    sqe->msg_flags = MSG_NOSIGNAL;
    return true;
}

int32_t UringBackend::finish_datagram(const Op &op, int32_t res,
                                      uint32_t slot) noexcept {
    if (op.kind == OpKind::SendTo) {
        if (res < 0) {
            last_error_ = -res;
            ++dgram_counts_.send_errors;
            return -1;
        }
        ++dgram_counts_.sent;
        return res;
    }

    const int32_t at = dgram_.find(op.fd);
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    if (res < 0 || at < 0 || b == nullptr || msgs_ == nullptr) {
        last_error_ = res < 0 ? -res : EBADF;
        ++dgram_counts_.receive_errors;
        return -1;
    }

    return udp::finish_receive(msgs_[slot].msg, static_cast<size_t>(res),
                               op.length, dgram_.bound(static_cast<size_t>(at)),
                               *b, dgram_counts_);
}

} // namespace http_vx
