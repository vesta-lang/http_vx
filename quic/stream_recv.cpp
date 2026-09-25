/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/stream_recv.cpp
 * @brief
 * \~english Reassembling a stream's bytes, and receive-side flow control.
 * \~spanish Reensamblar los bytes de un flujo, y el control de flujo del lado receptor.
 * \~
 */

#include "http_vx/quic_stream_recv.h"

#include "bitmap.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace quic {

/// \~english One chunk of the window: its bytes, and which of them arrived.
/// \~spanish Un trozo de la ventana: sus bytes, y cuales de ellos llegaron.  \~
struct RecvStream::Chunk {
    uint8_t data[kRecvChunk];
    uint64_t bits[kRecvChunk / 64];
};

namespace {

inline uint64_t min64(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }

} // namespace

const char *stream_error_name(StreamError e) noexcept {
    switch (e) {
    case StreamError::None:        return "none";
    case StreamError::FlowControl: return "flow-control";
    case StreamError::FinalSize:   return "final-size";
    case StreamError::OutOfMemory: return "out-of-memory";
    }
    return "unknown";
}

TransportError transport_error_of(StreamError e) noexcept {
    switch (e) {
    case StreamError::None:        return TransportError::NoError;
    case StreamError::FlowControl: return TransportError::FlowControlError;
    case StreamError::FinalSize:   return TransportError::FinalSizeError;
    case StreamError::OutOfMemory: return TransportError::InternalError;
    }
    return TransportError::InternalError;
}

RecvStream::RecvStream(uint64_t window) noexcept {
    // \~english A whole number of chunks, and at least one.
    // \~spanish Un numero entero de trozos, y al menos uno.  \~
    const uint64_t chunks = window == 0 ? 1 : (window + kRecvChunk - 1) / kRecvChunk;
    window_ = chunks * kRecvChunk;
    limit_ = window_;

    /* \~english
     * One slot more than the window holds whole chunks: a window that starts
     * in the middle of a chunk ends in the middle of another, and touches
     * one chunk more than its size divided by the chunk.
     * \~spanish
     * Una ranura mas de los trozos enteros que caben en la ventana: una ventana
     * que empieza en mitad de un trozo acaba en mitad de otro, y toca un trozo
     * mas que su tamano dividido por el del trozo.
     * \~ */
    nslots_ = static_cast<size_t>(chunks) + 1;
}

RecvStream::~RecvStream() {
    release_all();
    if (slots_ != nullptr) util::host_free(slots_);
}

RecvStream::Chunk *RecvStream::chunk_for(uint64_t index, bool create) noexcept {
    if (slots_ == nullptr) {
        if (!create) return nullptr;

        // \~english The slot table too is only paid for once data arrives.
        // \~spanish La tabla de ranuras tambien se paga solo cuando llegan datos.  \~
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                     util::AllocFill::All);
        slots_ = static_cast<Chunk **>(util::host_alloc(nslots_ * sizeof(Chunk *)));
        if (slots_ == nullptr) return nullptr;
        util::vesta_memset(slots_, 0, nslots_ * sizeof(Chunk *));
    }

    Chunk *&slot = slots_[index % nslots_];
    if (slot == nullptr && create) {
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                     util::AllocFill::Dense);
        slot = static_cast<Chunk *>(util::host_alloc(sizeof(Chunk)));
        if (slot == nullptr) return nullptr;
        util::vesta_memset(slot->bits, 0, sizeof slot->bits);
        ++held_;
    }
    return slot;
}

void RecvStream::release_below(uint64_t offset) noexcept {
    if (slots_ == nullptr) return;

    // \~english Every chunk that lies wholly below @p offset has been read.
    // \~spanish Cada trozo que queda entero por debajo de @p offset ya se leyo.  \~
    const uint64_t first = read_ / kRecvChunk;
    const uint64_t last = offset / kRecvChunk;
    for (uint64_t i = first; i < last; ++i) {
        Chunk *&slot = slots_[i % nslots_];
        if (slot != nullptr) {
            util::host_free(slot);
            slot = nullptr;
            --held_;
        }
    }
}

void RecvStream::release_all() noexcept {
    if (slots_ == nullptr) return;
    for (size_t i = 0; i < nslots_; ++i) {
        if (slots_[i] != nullptr) {
            util::host_free(slots_[i]);
            slots_[i] = nullptr;
        }
    }
    held_ = 0;
}

bool RecvStream::all_received() const noexcept {
    return size_known_ && read_ + buffered_ == final_;
}

StreamError RecvStream::on_data(uint64_t offset, const uint8_t *p, size_t len, bool fin,
                                uint64_t &new_bytes) noexcept {
    new_bytes = 0;
    const uint64_t end = offset + len;

    /* \~english
     * The final size rules hold even after a reset or once everything was
     * read (4.5): data past it, or a FIN elsewhere, is the peer lying about
     * how much it sent -- and so about how much of the connection's window
     * it used.
     * \~spanish
     * Las reglas del tamano final siguen valiendo tras un reinicio o cuando ya
     * se leyo todo (4.5): datos mas alla, o un FIN en otro sitio, es el otro
     * extremo mintiendo sobre cuanto mando -- y por tanto sobre cuanta ventana
     * de la conexion gasto.
     * \~ */
    if (size_known_) {
        if (end > final_ || (fin && end != final_)) return StreamError::FinalSize;
    } else if (fin && end < highest_) {
        return StreamError::FinalSize;
    }
    if (end > limit_) return StreamError::FlowControl;

    if (state_ == RecvState::ResetRecvd || state_ == RecvState::ResetRead) return StreamError::None;

    if (fin && !size_known_) {
        size_known_ = true;
        final_ = end;
        if (state_ == RecvState::Recv) state_ = RecvState::SizeKnown;
    }
    if (end > highest_) {
        new_bytes = end - highest_;
        highest_ = end;
    }
    if (state_ == RecvState::DataRecvd || state_ == RecvState::DataRead) return StreamError::None;

    // \~english What was already read is dropped; the rest is copied chunk by chunk.
    // \~spanish Lo ya leido se tira; el resto se copia trozo a trozo.  \~
    uint64_t pos = offset > read_ ? offset : read_;
    while (pos < end) {
        Chunk *c = chunk_for(pos / kRecvChunk, true);
        if (c == nullptr) return StreamError::OutOfMemory;

        const size_t in = static_cast<size_t>(pos % kRecvChunk);
        const size_t n = static_cast<size_t>(min64(end - pos, kRecvChunk - in));

        /* \~english
         * Copied over whatever was there: a retransmission carries the same
         * bytes (2.2), so rewriting them is cheaper than skipping them.
         * \~spanish
         * Copiado encima de lo que hubiera: una retransmision lleva los mismos
         * bytes (2.2), asi que reescribirlos es mas barato que saltarselos.
         * \~ */
        util::vesta_memcpy(c->data + in, p + (pos - offset), n);
        buffered_ += bits::set(c->bits, in, n);
        pos += n;
    }

    if (all_received()) {
        state_ = RecvState::DataRecvd;

        // \~english A FIN that arrives after everything was read leaves nothing to read.
        // \~spanish Un FIN que llega cuando ya se leyo todo no deja nada que leer.  \~
        if (read_ == final_) {
            state_ = RecvState::DataRead;
            release_all();
        }
    }
    return StreamError::None;
}

StreamError RecvStream::on_reset(uint64_t final_size, uint64_t error_code,
                                 uint64_t &new_bytes, uint64_t &released) noexcept {
    new_bytes = 0;
    released = 0;

    if (size_known_ && final_size != final_) return StreamError::FinalSize;
    if (final_size < highest_) return StreamError::FinalSize;
    if (final_size > limit_) return StreamError::FlowControl;

    /* \~english
     * Everything already received, or already reset: the reset changes
     * nothing -- the RFC makes that transition optional, and delivering data
     * that fully arrived beats throwing it away.
     * \~spanish
     * Todo ya recibido, o ya reiniciado: el reinicio no cambia nada -- el RFC
     * hace opcional esa transicion, y entregar datos que llegaron enteros es
     * mejor que tirarlos.
     * \~ */
    if (state_ != RecvState::Recv && state_ != RecvState::SizeKnown) return StreamError::None;

    new_bytes = final_size - highest_;
    highest_ = final_size;
    final_ = final_size;
    size_known_ = true;

    // \~english Counted as received, never to be read: the connection gets it back.
    // \~spanish Contado como recibido, sin leerse nunca: la conexion lo recupera.  \~
    released = final_size - read_;
    reset_code_ = error_code;
    state_ = RecvState::ResetRecvd;
    buffered_ = 0;
    release_all();
    return StreamError::None;
}

size_t RecvStream::peek(const uint8_t *&p) const noexcept {
    if (state_ == RecvState::ResetRecvd || state_ == RecvState::ResetRead ||
        state_ == RecvState::DataRead || slots_ == nullptr)
        return 0;

    const Chunk *c = slots_[(read_ / kRecvChunk) % nslots_];
    if (c == nullptr) return 0;

    const size_t in = static_cast<size_t>(read_ % kRecvChunk);
    const size_t n = bits::run(c->bits, in, kRecvChunk, true);
    p = c->data + in;
    return n;
}

void RecvStream::consume(size_t n) noexcept {
    const uint64_t to = read_ + n;
    release_below(to);
    read_ = to;
    buffered_ -= n;

    if (size_known_ && read_ == final_ &&
        (state_ == RecvState::DataRecvd || state_ == RecvState::SizeKnown)) {
        state_ = RecvState::DataRead;
        release_all();
    }
}

bool RecvStream::wants_update() const noexcept {
    // \~english With the size known there is nothing more to allow (3.2).
    // \~spanish Con el tamano conocido no hay nada mas que permitir (3.2).  \~
    if (state_ != RecvState::Recv) return false;
    return limit_ - read_ < window_ / 2;
}

uint64_t RecvStream::advertise() noexcept {
    const uint64_t next = read_ + window_;
    if (next > limit_) limit_ = next;
    return limit_;
}

bool RecvFlow::on_received(uint64_t new_bytes) noexcept {
    received_ += new_bytes;
    return received_ <= limit_;
}

uint64_t RecvFlow::advertise() noexcept {
    const uint64_t next = consumed_ + window_;
    if (next > limit_) limit_ = next;
    return limit_;
}

} // namespace quic
} // namespace http_vx
