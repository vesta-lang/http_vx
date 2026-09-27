/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/memory_datagram.cpp
 * @brief
 * \~english Datagrams in and out of memory, cut where a kernel would cut them.
 * \~spanish Datagramas dentro y fuera de memoria, cortados donde los cortaria un nucleo.
 * \~
 */

#include "http_vx/memory_backend.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

bool MemoryBackend::feed_datagram(const DatagramPath &path, const uint8_t *p,
                                  size_t n, EcnMark ecn,
                                  uint8_t flags) noexcept {
    if (dgram_in_count_ == kMemoryDatagrams || n > kMemoryDatagramRoom)
        return false;

    MemoryDatagram &d =
        dgram_in_[(dgram_in_head_ + dgram_in_count_) % kMemoryDatagrams];
    d.header.path = path;
    d.header.ecn = ecn;
    d.header.flags = flags;
    d.size = n;
    if (n != 0) util::vesta_memcpy(d.bytes, p, n);

    ++dgram_in_count_;
    return true;
}

bool MemoryBackend::waiting(const Op &op) const noexcept {
    if (op.fd == kCancelledFd) return false;
    switch (op.kind) {
    case OpKind::Recv:
    case OpKind::Ready:
        return in_read_ >= in_len_ && !ended_;

    /* \~english
     * A datagram socket has no end, so a receive with nothing queued waits
     * for ever -- which is what a real one does, and what lets a test hold
     * receives outstanding while it looks at something else.
     * \~spanish
     * Un socket de datagramas no tiene final, asi que una recepcion sin nada en
     * cola espera para siempre -- que es lo que hace uno de verdad, y lo que deja
     * a una prueba tener recepciones pendientes mientras mira otra cosa.
     * \~ */
    case OpKind::RecvFrom:
        return dgram_in_count_ == 0;

    /* \~english
     * An accept waits for a connection the way a read waits for bytes, and
     * for the same reason: neither is something this end can make happen.
     * Finishing one that nobody arrived for would be a backend inventing a
     * client, and the loop above it would spin accepting nothing.
     * \~spanish
     * Una aceptacion espera una conexion igual que una lectura espera bytes, y
     * por lo mismo: ninguna de las dos es algo que pueda provocar este extremo.
     * Acabar una a la que no llego nadie seria un backend inventandose un
     * cliente, y el bucle de encima daria vueltas aceptando nada.
     * \~ */
    case OpKind::Accept:
        return arrivals_count_ == 0;

    case OpKind::Send:
    case OpKind::SendTo:
    case OpKind::Close:
    case OpKind::Cancel:
        return false;
    }

    return false;
}

Completion MemoryBackend::finish_datagram(const Op &op) noexcept {
    Completion c;
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = -1;

    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    if (op.kind == OpKind::RecvFrom) {
        if (b == nullptr) {
            ++dgram_counts_.receive_errors;
            return c;
        }

        const MemoryDatagram &d = dgram_in_[dgram_in_head_];
        dgram_in_head_ = (dgram_in_head_ + 1) % kMemoryDatagrams;
        --dgram_in_count_;
        ++dgram_counts_.receive_calls;

        /* \~english
         * Too large for the room is cut and NOT delivered, as every kernel
         * does it: the datagram is gone either way, and the only choice left
         * is whether anybody is told.
         * \~spanish
         * Demasiado grande para el sitio se corta y NO se entrega, como lo hace
         * cualquier nucleo: el datagrama se pierde igual, y la unica eleccion que
         * queda es si se le dice a alguien.
         * \~ */
        if (d.size > op.length) {
            ++dgram_counts_.truncated;
            c.result = kTruncated;
            return c;
        }

        uint8_t *room = datagram_reserve(*b, op.length);
        if (room == nullptr) {
            ++dgram_counts_.receive_errors;
            return c;
        }

        if (d.size != 0) util::vesta_memcpy(room, d.bytes, d.size);
        datagram_commit(*b, d.header, d.size);

        ++dgram_counts_.received;
        c.result = static_cast<int32_t>(d.size);
        return c;
    }

    /* \~english
     * A send is checked as a real backend checks it: the header has to be
     * there and the payload has to be exactly what the operation says.  A
     * backend for tests that let a malformed send through would be the one
     * place where a loop that builds them wrongly passes.
     * \~spanish
     * Un envio se comprueba como lo comprueba un backend de verdad: la cabecera
     * tiene que estar y la carga tiene que ser exactamente lo que dice la
     * operacion.  Un backend de pruebas que dejara pasar un envio mal hecho seria
     * el unico sitio donde pasa un bucle que los construye mal.
     * \~ */
    DatagramHeader h;
    if (b == nullptr || !datagram_header(*b, h) ||
        datagram_size(*b) != op.length || op.length > kMemoryDatagramRoom ||
        dgram_out_count_ == kMemoryDatagrams) {
        ++dgram_counts_.send_errors;
        return c;
    }

    MemoryDatagram &d = dgram_out_[dgram_out_count_];
    d.header = h;
    d.fd = op.fd;
    d.size = op.length;
    if (op.length != 0) util::vesta_memcpy(d.bytes, datagram_payload(*b), op.length);
    ++dgram_out_count_;

    ++dgram_counts_.send_calls;
    ++dgram_counts_.sent;
    c.result = static_cast<int32_t>(op.length);
    return c;
}

} // namespace http_vx
