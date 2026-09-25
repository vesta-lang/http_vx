/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/stream_send.cpp
 * @brief
 * \~english Keeping a stream's bytes until they are acknowledged, and choosing what goes next.
 * \~spanish Guardar los bytes de un flujo hasta que se confirman, y elegir que sale despues.
 * \~
 */

#include "http_vx/quic_stream_send.h"

#include "bitmap.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace quic {

/// \~english One chunk: its bytes, which are acknowledged, and which must go again.
/// \~spanish Un trozo: sus bytes, cuales estan confirmados, y cuales tienen que salir otra vez.  \~
struct SendStream::Chunk {
    uint8_t data[kRecvChunk];
    uint64_t acked[kRecvChunk / 64];
    uint64_t pending[kRecvChunk / 64];
};

namespace {

inline uint64_t min64(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }
inline uint64_t max64(uint64_t a, uint64_t b) noexcept { return a > b ? a : b; }

} // namespace

SendStream::SendStream(uint64_t capacity, uint64_t peer_limit) noexcept : limit_(peer_limit) {
    const uint64_t chunks = capacity == 0 ? 1 : (capacity + kRecvChunk - 1) / kRecvChunk;
    capacity_ = chunks * kRecvChunk;

    // \~english One slot more, for the same reason as on the receiving side.
    // \~spanish Una ranura mas, por lo mismo que en la parte receptora.  \~
    nslots_ = static_cast<size_t>(chunks) + 1;
}

SendStream::~SendStream() {
    release_all();
    if (slots_ != nullptr) util::host_free(slots_);
}

bool SendStream::done_or_reset() const noexcept {
    return state_ == SendState::DataRecvd || state_ == SendState::ResetSent ||
           state_ == SendState::ResetRecvd;
}

SendStream::Chunk *SendStream::chunk_for(uint64_t index, bool create) noexcept {
    if (slots_ == nullptr) {
        if (!create) return nullptr;
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
        util::vesta_memset(slot->acked, 0, sizeof slot->acked);
        util::vesta_memset(slot->pending, 0, sizeof slot->pending);
        ++held_;
    }
    return slot;
}

void SendStream::free_chunk(uint64_t index) noexcept {
    if (slots_ == nullptr) return;
    Chunk *&slot = slots_[index % nslots_];
    if (slot != nullptr) {
        util::host_free(slot);
        slot = nullptr;
        --held_;
    }
}

void SendStream::release_all() noexcept {
    if (slots_ == nullptr) return;
    for (size_t i = 0; i < nslots_; ++i) {
        if (slots_[i] != nullptr) {
            util::host_free(slots_[i]);
            slots_[i] = nullptr;
        }
    }
    held_ = 0;
}

StreamError SendStream::write(const uint8_t *p, size_t n, size_t &accepted) noexcept {
    accepted = 0;
    if (finished_ || done_or_reset()) return StreamError::None;

    // \~english What fits: the capacity minus what is written and not yet acknowledged.
    // \~spanish Lo que cabe: la capacidad menos lo escrito y aun sin confirmar.  \~
    const uint64_t room = capacity_ - (written_ - acked_);
    size_t left = static_cast<size_t>(min64(n, room));

    while (left != 0) {
        Chunk *c = chunk_for(written_ / kRecvChunk, true);
        if (c == nullptr) return StreamError::OutOfMemory;
        const size_t in = static_cast<size_t>(written_ % kRecvChunk);
        const size_t take = left < kRecvChunk - in ? left : kRecvChunk - in;
        util::vesta_memcpy(c->data + in, p + accepted, take);
        written_ += take;
        accepted += take;
        left -= take;
    }
    return StreamError::None;
}

void SendStream::finish() noexcept {
    finished_ = true;
}

bool SendStream::next(StreamPiece &out, size_t max_len, uint64_t conn_credit) const noexcept {
    if (done_or_reset()) return false;

    /* \~english
     * Retransmissions first: they are older, the peer is waiting on them to
     * deliver everything behind, and they cost no credit.
     * \~spanish
     * Retransmisiones primero: son mas viejas, el otro extremo las espera para
     * entregar todo lo de detras, y no gastan credito.
     * \~ */
    if (pending_ != 0 && max_len != 0 && slots_ != nullptr) {
        uint64_t pos = acked_;
        while (pos < sent_) {
            const uint64_t idx = pos / kRecvChunk;
            const uint64_t base = idx * kRecvChunk;
            const size_t in = static_cast<size_t>(pos - base);
            const size_t hi = static_cast<size_t>(min64(kRecvChunk, sent_ - base));
            const Chunk *c = slots_[idx % nslots_];
            if (c != nullptr) {
                const size_t at = bits::first_set(c->pending, in, hi);
                if (at < hi) {
                    const size_t run = bits::run(c->pending, at, hi, true);
                    out.offset = base + at;
                    out.data = c->data + at;
                    out.len = run < max_len ? run : max_len;
                    out.retransmit = true;
                    out.fin = finished_ && !fin_acked_ && out.offset + out.len == written_;
                    return true;
                }
            }
            pos = base + hi;
        }
    }

    // \~english A lost FIN with no data left to carry it goes alone.
    // \~spanish Un FIN perdido sin datos que lo lleven sale solo.  \~
    if (fin_pending_ && sent_ == written_ && pending_ == 0) {
        out = StreamPiece{};
        out.offset = written_;
        out.fin = true;
        out.retransmit = true;
        return true;
    }

    // \~english New data: within the stream's limit, the connection's credit and the packet.
    // \~spanish Datos nuevos: dentro del limite del flujo, el credito de la conexion y el paquete.  \~
    if (sent_ < written_ && sent_ < limit_ && conn_credit != 0 && max_len != 0) {
        const uint64_t idx = sent_ / kRecvChunk;
        const Chunk *c = slots_ != nullptr ? slots_[idx % nslots_] : nullptr;
        if (c != nullptr) {
            const size_t in = static_cast<size_t>(sent_ % kRecvChunk);
            uint64_t len = min64(written_ - sent_, limit_ - sent_);
            len = min64(len, conn_credit);
            len = min64(len, max_len);
            len = min64(len, kRecvChunk - in);
            out.offset = sent_;
            out.data = c->data + in;
            out.len = static_cast<size_t>(len);
            out.retransmit = false;
            out.fin = finished_ && sent_ + len == written_;
            return true;
        }
    }

    // \~english Everything sent and the stream finished: a FIN on its own, which costs no credit.
    // \~spanish Todo mandado y el flujo terminado: un FIN solo, que no gasta credito.  \~
    if (finished_ && !fin_sent_ && sent_ == written_) {
        out = StreamPiece{};
        out.offset = written_;
        out.fin = true;
        return true;
    }
    return false;
}

void SendStream::on_sent(const StreamPiece &piece) noexcept {
    if (done_or_reset()) return;

    if (piece.retransmit) {
        // \~english Those bytes are on their way again: no longer owed.
        // \~spanish Esos bytes van otra vez de camino: ya no se deben.  \~
        uint64_t pos = max64(piece.offset, acked_);
        const uint64_t end = piece.offset + piece.len;
        while (pos < end && slots_ != nullptr) {
            const uint64_t idx = pos / kRecvChunk;
            const size_t in = static_cast<size_t>(pos % kRecvChunk);
            const size_t n = static_cast<size_t>(min64(end - pos, kRecvChunk - in));
            Chunk *c = slots_[idx % nslots_];
            if (c != nullptr) pending_ -= bits::clear(c->pending, in, n);
            pos += n;
        }
        if (piece.fin) fin_pending_ = false;
    } else {
        sent_ = piece.offset + piece.len;
    }

    if (piece.fin) fin_sent_ = true;
    if (state_ == SendState::Ready) state_ = SendState::Send;
    if (fin_sent_ && state_ == SendState::Send) state_ = SendState::DataSent;
}

void SendStream::on_acked(uint64_t offset, size_t len, bool fin) noexcept {
    if (done_or_reset()) return;

    // \~english Mark what this packet carried, and forget it needed resending.
    // \~spanish Marcar lo que llevaba este paquete, y olvidar que habia que reenviarlo.  \~
    uint64_t pos = max64(offset, acked_);
    const uint64_t end = min64(offset + len, sent_);
    while (pos < end && slots_ != nullptr) {
        const uint64_t idx = pos / kRecvChunk;
        const size_t in = static_cast<size_t>(pos % kRecvChunk);
        const size_t n = static_cast<size_t>(min64(end - pos, kRecvChunk - in));
        Chunk *c = slots_[idx % nslots_];
        if (c != nullptr) {
            bits::set(c->acked, in, n);
            pending_ -= bits::clear(c->pending, in, n);
        }
        pos += n;
    }

    // \~english The acknowledged prefix moves over whatever is now contiguous, freeing chunks.
    // \~spanish El prefijo confirmado avanza sobre lo que ahora es contiguo, liberando trozos.  \~
    while (acked_ < sent_ && slots_ != nullptr) {
        const uint64_t idx = acked_ / kRecvChunk;
        const uint64_t base = idx * kRecvChunk;
        const size_t in = static_cast<size_t>(acked_ - base);
        const size_t hi = static_cast<size_t>(min64(kRecvChunk, sent_ - base));
        const Chunk *c = slots_[idx % nslots_];
        if (c == nullptr) break;
        const size_t run = bits::run(c->acked, in, hi, true);
        acked_ += run;
        if (in + run == kRecvChunk) free_chunk(idx);
        if (in + run < hi || hi < kRecvChunk) break;
    }

    if (fin) {
        fin_acked_ = true;
        fin_pending_ = false;
    }
    if (finished_ && fin_acked_ && acked_ == written_) {
        state_ = SendState::DataRecvd;
        release_all();
    }
}

void SendStream::on_lost(uint64_t offset, size_t len, bool fin) noexcept {
    if (done_or_reset()) return;

    // \~english Only what nothing else acknowledged goes out again.
    // \~spanish Solo sale otra vez lo que no confirmo ninguna otra cosa.  \~
    uint64_t pos = max64(offset, acked_);
    const uint64_t end = min64(offset + len, sent_);
    while (pos < end && slots_ != nullptr) {
        const uint64_t idx = pos / kRecvChunk;
        const size_t in = static_cast<size_t>(pos % kRecvChunk);
        const size_t n = static_cast<size_t>(min64(end - pos, kRecvChunk - in));
        Chunk *c = slots_[idx % nslots_];
        if (c != nullptr) pending_ += bits::set_unless(c->pending, c->acked, in, n);
        pos += n;
    }
    if (fin && !fin_acked_) fin_pending_ = true;
}

void SendStream::on_max_stream_data(uint64_t limit) noexcept {
    if (limit > limit_) limit_ = limit;
}

bool SendStream::blocked() const noexcept {
    return !done_or_reset() && sent_ < written_ && sent_ >= limit_;
}

void SendStream::reset(uint64_t error_code) noexcept {
    if (done_or_reset()) return;

    // \~english From now on only the RESET_STREAM goes, until it is acknowledged.
    // \~spanish A partir de aqui solo sale el RESET_STREAM, hasta que se confirme.  \~
    state_ = SendState::ResetSent;
    reset_code_ = error_code;
    reset_pending_ = true;
    pending_ = 0;
    fin_pending_ = false;
    release_all();
}

void SendStream::on_stop_sending(uint64_t error_code) noexcept {
    reset(error_code);
}

void SendStream::on_reset_lost() noexcept {
    if (state_ == SendState::ResetSent) reset_pending_ = true;
}

void SendStream::on_reset_acked() noexcept {
    if (state_ == SendState::ResetSent) {
        state_ = SendState::ResetRecvd;
        reset_pending_ = false;
    }
}

} // namespace quic
} // namespace http_vx
