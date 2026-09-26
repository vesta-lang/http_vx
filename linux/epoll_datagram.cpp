/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/epoll_datagram.cpp
 * @brief
 * \~english Datagrams on epoll: every waiting receive in one recvmmsg, every waiting send in one sendmmsg.
 * \~spanish Datagramas sobre epoll: todas las recepciones que esperan en un recvmmsg, todos los envios en un sendmmsg.
 * \~
 *
 * \~english
 * Readiness is what makes the batch here: when the socket says it has
 * something, one `recvmmsg` answers as many of the receives waiting as there
 * are datagrams (recvmmsg(2): a nonblocking call "reads as many messages as
 * are available (up to the limit specified by n)").  Sends are not tried when
 * they are asked for; they wait until the backend next waits and leave
 * together in one `sendmmsg` (sendmmsg(2): "A nonblocking call sends as many
 * messages as possible"; fewer than asked means the rest can be retried, and
 * an error is returned only if none could be sent).  The UDP GSO segmentation
 * R26 also names is not used: it sends several datagrams of one size to ONE
 * peer, and the shape here is one datagram per buffer to any peer.
 *
 * R1 is kept as the platform allows: a receive waiting here holds its buffer,
 * but the buffers are per SOCKET (see @c DatagramConfig::receives), and on
 * epoll nothing is written into them until the datagram is there.
 *
 * \~spanish
 * Aqui el lote lo hace la disponibilidad: cuando el socket dice que tiene
 * algo, un `recvmmsg` contesta tantas de las recepciones que esperan como
 * datagramas haya (recvmmsg(2): una llamada que no bloquea "lee tantos mensajes
 * como haya disponibles (hasta el limite n)").  Los envios no se intentan
 * cuando se piden; esperan a la proxima vez que espere el backend y salen
 * juntos en un `sendmmsg` (sendmmsg(2): "Una llamada que no bloquea manda
 * tantos mensajes como puede"; menos de los pedidos quiere decir que el resto se
 * puede reintentar, y solo se devuelve un error si no se pudo mandar ninguno).
 * La segmentacion GSO de UDP que tambien nombra la R26 no se usa: manda varios
 * datagramas de un tamano a UN extremo, y aqui la forma es un datagrama por
 * buffer a cualquier extremo.
 *
 * La R1 se cumple hasta donde deja la plataforma: una recepcion que espera aqui
 * tiene su buffer, pero los buffers son por SOCKET (ver
 * @c DatagramConfig::receives), y en epoll no se escribe nada en ellos hasta que
 * esta el datagrama.
 * \~
 */

#include "epoll_waiting.h"

#include "datagram_linux.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <new>

namespace http_vx {

namespace {

/**
 * \~english
 * How many operations of each kind wait on one socket, and how many go in one
 * call.  The same number: a call that could take more than can wait would
 * never be full.
 * \~spanish
 * Cuantas operaciones de cada clase esperan en un socket, y cuantas van en una
 * llamada.  El mismo numero: una llamada que pudiera coger mas de las que pueden
 * esperar no se llenaria nunca.
 * \~
 */
constexpr size_t kDgramQueue = 64;

/// \~english Whether the system said "not now" rather than "no".
/// \~spanish Si el sistema dijo "ahora no" en vez de "no".  \~
bool not_now(int e) noexcept {
#if EAGAIN == EWOULDBLOCK
    return e == EAGAIN;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

/**
 * @brief
 * \~english A ring of operations waiting on a datagram socket.
 * \~spanish Un anillo de operaciones que esperan en un socket de datagramas.
 * \~
 */
struct OpRing {
    Op ops[kDgramQueue];
    size_t head = 0;
    size_t count = 0;

    bool full() const noexcept { return count == kDgramQueue; }
    const Op &at(size_t k) const noexcept { return ops[(head + k) % kDgramQueue]; }

    void push(const Op &op) noexcept {
        ops[(head + count) % kDgramQueue] = op;
        ++count;
    }

    void pop() noexcept {
        head = (head + 1) % kDgramQueue;
        --count;
    }
};

} // namespace

/**
 * @brief
 * \~english One datagram socket and the operations waiting on it.
 * \~spanish Un socket de datagramas y las operaciones que esperan en el.
 * \~
 */
struct EpollBackend::DgramSocket {
    int32_t fd = -1;
    NetAddress bound;
    OpRing receives;
    OpRing sends;

    /// \~english The last send was told "not now": wait to be writable.
    /// \~spanish Al ultimo envio le dijeron "ahora no": esperar a poder escribir.  \~
    bool blocked = false;
};

bool EpollBackend::dgram_reset() noexcept {
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    dgram_ = static_cast<DgramSocket *>(
        util::host_alloc(kMaxDatagramSockets * sizeof(DgramSocket)));
    if (dgram_ == nullptr) return false;

    for (size_t i = 0; i < kMaxDatagramSockets; ++i) new (&dgram_[i]) DgramSocket();
    return true;
}

void EpollBackend::dgram_release() noexcept {
    if (dgram_ == nullptr) return;

    for (size_t i = 0; i < kMaxDatagramSockets; ++i) {
        if (dgram_[i].fd >= 0) ::close(dgram_[i].fd);
        dgram_[i].~DgramSocket();
    }

    util::host_free(dgram_);
    dgram_ = nullptr;
}

int32_t EpollBackend::open_datagram(const char *host, uint16_t port,
                                    NetAddress &bound) noexcept {
    bound.len = 0;
    if (queue_ < 0 || dgram_ == nullptr) return -1;

    int32_t slot = -1;
    for (size_t i = 0; i < kMaxDatagramSockets && slot < 0; ++i)
        if (dgram_[i].fd < 0) slot = static_cast<int32_t>(i);

    if (slot < 0) {
        last_error_ = EMFILE;
        return -1;
    }

    const int s = udp::open_socket(host, port, true, bound, last_error_);
    if (s < 0) return -1;

    if (static_cast<uint32_t>(s) >= max_fds_) {
        ::close(s);
        bound.len = 0;
        last_error_ = EMFILE;
        return -1;
    }

    DgramSocket &d = dgram_[slot];
    d = DgramSocket();
    d.fd = s;
    d.bound = bound;

    Waiting &w = waiting_[s];
    w.has_read = false;
    w.has_write = false;
    w.armed = 0;
    w.known = false;
    w.dgram = static_cast<int8_t>(slot);
    return s;
}

uint32_t EpollBackend::dgram_events(int32_t i) const noexcept {
    const DgramSocket &d = dgram_[i];

    uint32_t want = 0;
    if (d.receives.count != 0) want |= EPOLLIN;
    if (d.blocked && d.sends.count != 0) want |= EPOLLOUT;
    return want;
}

bool EpollBackend::dgram_submit(const Op &op, int32_t i) noexcept {
    DgramSocket &d = dgram_[i];

    if (op.kind == OpKind::RecvFrom) {
        if (d.receives.full()) return false;
        d.receives.push(op);
        ++in_flight_;
        arm(d.fd);
        return true;
    }

    /* \~english
     * A full queue is flushed before it is refused: a loop sending faster than
     * it waits would otherwise be told "no room" for datagrams that could have
     * gone out now.
     * \~spanish
     * Una cola llena se vacia antes de rechazar: a un bucle que manda mas
     * deprisa de lo que espera se le diria "no hay sitio" por datagramas que
     * podian haber salido ya.
     * \~ */
    if (d.sends.full()) dgram_flush(i);
    if (d.sends.full()) return false;

    d.sends.push(op);
    ++in_flight_;
    return true;
}

void EpollBackend::dgram_flush(int32_t i) noexcept {
    DgramSocket &d = dgram_[i];
    if (d.fd < 0 || d.blocked) return;

    mmsghdr msgs[kDgramQueue];
    udp::MsgRoom rooms[kDgramQueue];

    while (d.sends.count != 0) {
        /* \~english
         * No more than there is room to report: a datagram sent with nowhere
         * to say so would leave its buffer with the kernel's word and the
         * loop's ignorance.
         * \~spanish
         * No mas de las que hay sitio para informar: un datagrama mandado sin
         * donde decirlo dejaria su buffer con la palabra del nucleo y la
         * ignorancia del bucle.
         * \~ */
        size_t n = d.sends.count;
        if (n > 256 - ready_count_) n = 256 - ready_count_;
        if (n == 0) return;

        size_t k = 0;
        while (k < n) {
            const Op &op = d.sends.at(k);
            Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
            if (b == nullptr ||
                !udp::aim_send(msgs[k].msg_hdr, rooms[k], *b, op.length,
                               d.bound.len))
                break;
            msgs[k].msg_len = 0;
            ++k;
        }

        /* \~english
         * The one at the front cannot be sent at all -- no buffer, no
         * datagram, a peer of the other family -- so it fails on its own and
         * the rest carry on.
         * \~spanish
         * El de delante no se puede mandar de ninguna forma -- sin buffer, sin
         * datagrama, un extremo de la otra familia -- asi que falla el solo y los
         * demas siguen.
         * \~ */
        if (k == 0) {
            last_error_ = EINVAL;
            ++dgram_counts_.send_errors;
            remember(d.sends.at(0), -1, -1);
            d.sends.pop();
            --in_flight_;
            continue;
        }

        ++dgram_counts_.send_calls;
        const int sent = sendmmsg(d.fd, msgs, static_cast<unsigned>(k),
                                  MSG_DONTWAIT | MSG_NOSIGNAL);

        if (sent < 0) {
            if (not_now(errno)) {
                d.blocked = true;
                arm(d.fd);
                return;
            }

            last_error_ = errno;
            ++dgram_counts_.send_errors;
            remember(d.sends.at(0), -1, -1);
            d.sends.pop();
            --in_flight_;
            continue;
        }

        for (int j = 0; j < sent; ++j) {
            remember(d.sends.at(0), static_cast<int32_t>(msgs[j].msg_len), -1);
            d.sends.pop();
            --in_flight_;
            ++dgram_counts_.sent;
        }
    }
}

size_t EpollBackend::dgram_ready(int32_t i, bool readable, bool writable,
                                 Completion *out, size_t room) noexcept {
    DgramSocket &d = dgram_[i];
    size_t made = 0;

    if (writable && d.blocked) {
        d.blocked = false;
        dgram_flush(i);
    }

    if (!readable) return 0;

    mmsghdr msgs[kDgramQueue];
    udp::MsgRoom rooms[kDgramQueue];

    while (made < room && d.receives.count != 0) {
        size_t n = d.receives.count;
        if (n > room - made) n = room - made;

        size_t k = 0;
        while (k < n) {
            const Op &op = d.receives.at(k);
            Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
            uint8_t *into = b == nullptr ? nullptr : datagram_reserve(*b, op.length);
            if (into == nullptr) break;
            udp::aim_receive(msgs[k].msg_hdr, rooms[k], into, op.length);
            msgs[k].msg_len = 0;
            ++k;
        }

        if (k == 0) {
            const Op op = d.receives.at(0);
            d.receives.pop();
            --in_flight_;
            ++dgram_counts_.receive_errors;
            out[made].conn = op.conn;
            out[made].kind = op.kind;
            out[made].buffer = op.buffer;
            out[made].result = -1;
            out[made].fd = -1;
            ++made;
            continue;
        }

        ++dgram_counts_.receive_calls;
        const int got = recvmmsg(d.fd, msgs, static_cast<unsigned>(k),
                                 MSG_DONTWAIT | MSG_TRUNC, nullptr);

        if (got < 0) {
            if (not_now(errno)) break;

            /* \~english
             * A failure other than "nothing there" is given to the receive at
             * the front, so that it is SEEN; the others stay waiting.
             * \~spanish
             * Un fallo que no es "no hay nada" se le da a la recepcion de delante,
             * para que se VEA; las demas siguen esperando.
             * \~ */
            last_error_ = errno;
            ++dgram_counts_.receive_errors;
            const Op op = d.receives.at(0);
            d.receives.pop();
            --in_flight_;
            out[made].conn = op.conn;
            out[made].kind = op.kind;
            out[made].buffer = op.buffer;
            out[made].result = -1;
            out[made].fd = -1;
            ++made;
            break;
        }

        for (int j = 0; j < got; ++j) {
            const Op op = d.receives.at(0);
            d.receives.pop();
            --in_flight_;

            Buffer *b = pool_->at(op.buffer);
            out[made].conn = op.conn;
            out[made].kind = op.kind;
            out[made].buffer = op.buffer;
            out[made].result = udp::finish_receive(
                msgs[j].msg_hdr, msgs[j].msg_len, op.length, d.bound, *b,
                dgram_counts_);
            out[made].fd = -1;
            ++made;
        }

        if (static_cast<size_t>(got) < k) break;
    }

    return made;
}

void EpollBackend::dgram_close(int32_t i) noexcept {
    DgramSocket &d = dgram_[i];

    /* \~english
     * Everything waiting is answered, as a failure: each holds a buffer, and
     * an operation never answered is a buffer never given back.
     * \~spanish
     * Todo lo que espera se contesta, como fallo: cada una tiene un buffer, y
     * una operacion que no se contesta nunca es un buffer que no vuelve nunca.
     * \~ */
    while (d.receives.count != 0) {
        remember(d.receives.at(0), -1, -1);
        d.receives.pop();
        --in_flight_;
    }
    while (d.sends.count != 0) {
        remember(d.sends.at(0), -1, -1);
        d.sends.pop();
        --in_flight_;
    }

    if (d.fd >= 0 && static_cast<uint32_t>(d.fd) < max_fds_)
        waiting_[d.fd].dgram = -1;

    d = DgramSocket();
}

} // namespace http_vx
