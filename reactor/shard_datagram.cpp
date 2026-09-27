/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard_datagram.cpp
 * @brief
 * \~english The datagram side of a shard: receives kept posted, sends pulled.
 * \~spanish El lado de datagramas de un fragmento: recepciones siempre puestas, envios sacados.
 * \~
 */

#include "http_vx/datagram_service.h"
#include "http_vx/shard.h"

namespace http_vx {

DatagramService::~DatagramService() = default;

bool ShardDatagrams::reset(const DatagramConfig &cfg, Backend &io,
                           BufferPool &pool, DatagramService &service) noexcept {
    release();

    /* \~english
     * A configuration that cannot work is refused here, where it is a
     * sentence, rather than later as a socket that never receives (no
     * receives) or a service that is never asked (no sends per turn).
     * \~spanish
     * Una configuracion que no puede funcionar se rechaza aqui, donde es una
     * frase, y no despues como un socket que no recibe nunca (sin recepciones)
     * o un servicio al que no se le pregunta nunca (sin envios por vuelta).
     * \~ */
    if (cfg.receives == 0 || cfg.room == 0 || cfg.sends_per_turn == 0)
        return false;

    cfg_ = cfg;
    io_ = &io;
    pool_ = &pool;
    service_ = &service;
    return true;
}

void ShardDatagrams::release() noexcept {
    for (size_t i = 0; i < count_; ++i) sockets_[i] = Socket();
    count_ = 0;
    sending_ = 0;
    io_ = nullptr;
    pool_ = nullptr;
    service_ = nullptr;
    counts_ = ShardDatagramCounts();
}

bool ShardDatagrams::add_socket(int32_t fd, const NetAddress &bound) noexcept {
    if (service_ == nullptr || fd < 0 || count_ == kMaxDatagramSockets)
        return false;

    Socket &s = sockets_[count_];
    s.fd = fd;
    s.bound = bound;
    s.posted = 0;
    ++count_;

    post(static_cast<uint32_t>(count_ - 1));
    return true;
}

void ShardDatagrams::post(uint32_t i) noexcept {
    Socket &s = sockets_[i];

    while (s.posted < cfg_.receives) {
        const uint32_t b = pool_->acquire();

        /* \~english
         * No buffer is not a failure: the receives already out keep the socket
         * receiving, and the next turn tops them up once something has come
         * back to the pool.
         * \~spanish
         * No tener buffer no es un fallo: las recepciones que ya estan fuera
         * siguen recibiendo, y la vuelta siguiente las repone en cuanto vuelva
         * algo al pozo.
         * \~ */
        if (b == kNoBuffer) return;

        Op op;
        op.conn.slot = i;
        op.conn.life = 0;
        op.kind = OpKind::RecvFrom;
        op.buffer = b;
        op.offset = 0;
        op.length = cfg_.room;
        op.fd = s.fd;

        if (!io_->submit(op)) {
            pool_->release(b);
            return;
        }

        ++s.posted;
    }
}

void ShardDatagrams::on_received(const Completion &done, uint64_t now) noexcept {
    const uint32_t i = done.conn.slot;
    if (i < count_ && sockets_[i].posted != 0) --sockets_[i].posted;

    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(done.buffer);

    /* \~english
     * Three ways not to deliver, each counted apart, because each asks for a
     * different fix: a cut datagram is a room too small for what peers send, a
     * failure is the socket or the network, and a completion without a header
     * is a backend that broke its side of the layout.
     * \~spanish
     * Tres formas de no entregar, cada una contada aparte, porque cada una pide
     * un arreglo distinto: un datagrama cortado es un sitio demasiado pequeno
     * para lo que mandan los otros, un fallo es el socket o la red, y una
     * finalizacion sin cabecera es un backend que rompio su parte de la
     * disposicion.
     * \~ */
    DatagramHeader h;

    if (done.truncated()) {
        ++counts_.truncated;
    } else if (!done.ok() || b == nullptr || !datagram_header(*b, h) ||
               datagram_size(*b) != static_cast<size_t>(done.result)) {
        ++counts_.receive_failures;
    } else {
        ++counts_.delivered;
        service_->on_datagram(h.path, b->writable() + kDatagramHeaderRoom,
                              datagram_size(*b), h.ecn, now);
    }

    if (done.buffer != kNoBuffer) pool_->release(done.buffer);

    /* \~english
     * And the receive is replaced at once, whatever happened to this one: a
     * receive that is not replaced is a socket that quietly takes fewer and
     * fewer, until it takes none.
     * \~spanish
     * Y la recepcion se repone en el acto, pasara lo que pasara con esta: una
     * recepcion que no se repone es un socket que por lo bajo coge cada vez
     * menos, hasta que no coge ninguno.
     * \~ */
    if (i < count_) post(i);
}

void ShardDatagrams::on_sent(const Completion &done) noexcept {
    if (sending_ != 0) --sending_;

    if (done.ok())
        ++counts_.sent;
    else
        ++counts_.send_failures;

    if (done.buffer != kNoBuffer && pool_ != nullptr) pool_->release(done.buffer);
}

int32_t ShardDatagrams::route(const DatagramPath &path) const noexcept {
    int32_t first = -1;

    for (size_t i = 0; i < count_; ++i) {
        if (sockets_[i].bound.len != path.peer.len) continue;

        if (path.local.len != 0 &&
            same_net_address(sockets_[i].bound, path.local))
            return static_cast<int32_t>(i);

        if (first < 0) first = static_cast<int32_t>(i);
    }

    return first;
}

bool ShardDatagrams::send_one(uint64_t now) noexcept {
    const uint32_t b = pool_->acquire();
    if (b == kNoBuffer) {
        ++counts_.starved;
        return false;
    }

    Buffer *buf = pool_->at(b);
    uint8_t *room = buf == nullptr ? nullptr : datagram_reserve(*buf, cfg_.room);
    if (room == nullptr) {
        pool_->release(b);
        ++counts_.starved;
        return false;
    }

    DatagramPath path;
    const size_t n = service_->next_datagram(path, room, cfg_.room, now);

    if (n == 0) {
        pool_->release(b);
        return false;
    }

    const int32_t s = n > cfg_.room ? -1 : route(path);
    if (s < 0) {
        pool_->release(b);
        ++counts_.dropped;
        return true;
    }

    DatagramHeader h;
    h.path = path;
    h.ecn = EcnMark::NotEct;
    h.flags = path.local.len != 0 ? kDatagramLocalKnown : 0;
    datagram_commit(*buf, h, n);

    Op op;
    op.conn.slot = static_cast<uint32_t>(s);
    op.conn.life = 0;
    op.kind = OpKind::SendTo;
    op.buffer = b;
    op.offset = 0;
    op.length = static_cast<uint32_t>(n);
    op.fd = sockets_[s].fd;

    /* \~english
     * Refused after the service produced it is a datagram lost, and it is
     * counted as one: the service believes it went.  QUIC recovers from that
     * as from any loss, but a loss this end caused must not look like the
     * network's.
     * \~spanish
     * Rechazado despues de que el servicio lo produjera es un datagrama
     * perdido, y se cuenta como tal: el servicio cree que salio.  QUIC se
     * recupera de eso como de cualquier perdida, pero una perdida que causo este
     * extremo no puede parecer de la red.
     * \~ */
    if (!io_->submit(op)) {
        pool_->release(b);
        ++counts_.dropped;
        return false;
    }

    ++sending_;
    return true;
}

size_t ShardDatagrams::flush(uint64_t now) noexcept {
    if (service_ == nullptr) return 0;

    for (uint32_t i = 0; i < count_; ++i) post(i);

    if (count_ == 0) return 0;

    size_t handed = 0;
    for (uint32_t k = 0; k < cfg_.sends_per_turn; ++k) {
        const uint32_t before = sending_;
        if (!send_one(now)) break;
        if (sending_ != before) ++handed;
    }

    return handed;
}

void ShardDatagrams::run_timers(uint64_t now) noexcept {
    if (service_ == nullptr) return;
    if (service_->timer() <= now) service_->on_timer(now);
}

uint64_t ShardDatagrams::timer() const noexcept {
    return service_ == nullptr ? kNoDatagramTimer : service_->timer();
}

bool Shard::attach_datagrams(DatagramService &service,
                             const DatagramConfig &cfg) noexcept {
    if (io_ == nullptr) return false;
    if (!datagrams_.reset(cfg, *io_, pool_, service)) return false;

    datagram_service_ = &service;
    service.attach(&datagram_port_);
    return true;
}

bool Shard::add_datagram_socket(int32_t fd, const NetAddress &bound) noexcept {
    return datagrams_.add_socket(fd, bound);
}

} // namespace http_vx
