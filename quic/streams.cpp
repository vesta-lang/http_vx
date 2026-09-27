/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/streams.cpp
 * @brief
 * \~english The stream table: IDs, limits, implicit opening, and which frames may name which stream.
 * \~spanish La tabla de flujos: identificadores, limites, apertura implicita, y que tramas pueden nombrar que flujo.
 * \~
 */

#include "http_vx/quic_streams.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {
namespace quic {

namespace {

/// \~english The stream types, by who opens them.  \~spanish Los tipos de flujo, segun quien los abre.  \~
inline uint64_t local_type(bool is_server, bool bidi) noexcept {
    return (is_server ? 1u : 0u) | (bidi ? 0u : 2u);
}
inline uint64_t peer_type(bool is_server, bool bidi) noexcept {
    return (is_server ? 0u : 1u) | (bidi ? 0u : 2u);
}

/// \~english Whether @p t names the receiving part of a stream.  \~spanish Si @p t nombra la parte receptora de un flujo.  \~
inline bool names_receiving_part(FrameType t) noexcept {
    return t == FrameType::Stream || t == FrameType::ResetStream ||
           t == FrameType::StreamDataBlocked;
}

/// \~english Whether @p t names the sending part.  \~spanish Si @p t nombra la parte emisora.  \~
inline bool names_sending_part(FrameType t) noexcept {
    return t == FrameType::MaxStreamData || t == FrameType::StopSending;
}

} // namespace

StreamTable::StreamTable(const StreamConfig &config) noexcept : cfg_(config), base_(config) {
    const bool srv = cfg_.is_server;
    limit_[peer_type(srv, true)] = cfg_.peer_bidi_concurrency;
    limit_[peer_type(srv, false)] = cfg_.peer_uni_concurrency;
    limit_[local_type(srv, true)] = cfg_.peer_max_streams_bidi;
    limit_[local_type(srv, false)] = cfg_.peer_max_streams_uni;

    /* \~english
     * Room for everything that can be open at once: the peer's concurrency of
     * each kind, which the MAX_STREAMS policy guarantees, plus this end's own.
     * \~spanish
     * Sitio para todo lo que puede estar abierto a la vez: la concurrencia del
     * otro extremo de cada clase, que garantiza la politica de MAX_STREAMS, mas la
     * de este extremo.
     * \~ */
    const uint64_t cap = cfg_.peer_bidi_concurrency + cfg_.peer_uni_concurrency +
                         cfg_.local_concurrency;
    if (cap == 0 || cap > (uint64_t{1} << 24)) return;
    capacity_ = static_cast<size_t>(cap);

    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);
    slots_ = static_cast<Stream *>(util::host_alloc(capacity_ * sizeof(Stream)));
    free_ = static_cast<uint32_t *>(util::host_alloc(capacity_ * sizeof(uint32_t)));
    if (slots_ == nullptr || free_ == nullptr || !index_.reset(capacity_)) {
        if (slots_ != nullptr) util::host_free(slots_);
        if (free_ != nullptr) util::host_free(free_);
        index_.release();
        slots_ = nullptr;
        free_ = nullptr;
        return;
    }

    for (size_t i = 0; i < capacity_; ++i) {
        slots_[i] = Stream{};
        slots_[i].id = kNever;
        // \~english Handed out lowest first: slots in use stay together in memory.
        // \~spanish Se entregan de la mas baja a la mas alta: las ranuras en uso quedan juntas.  \~
        free_[i] = static_cast<uint32_t>(capacity_ - 1 - i);
    }
    free_count_ = capacity_;
}

StreamTable::~StreamTable() {
    if (slots_ == nullptr) return;
    for (size_t i = 0; i < capacity_; ++i)
        if (slots_[i].id != kNever) destroy(i);
    util::host_free(slots_);
    util::host_free(free_);
}

bool StreamTable::is_local(uint64_t id) const noexcept {
    return stream_is_server_initiated(id) == cfg_.is_server;
}

Stream *StreamTable::create(uint64_t id) noexcept {
    if (free_count_ == 0) return nullptr;
    const uint32_t slot = free_[--free_count_];
    Stream &s = slots_[slot];
    // \~english A reused slot starts clean: nothing owed by the stream that held it before.
    // \~spanish Una ranura reutilizada empieza limpia: nada debido por el flujo que la tuvo antes.  \~
    s.id = id;
    s.recv = nullptr;
    s.send = nullptr;
    s.max_stream_data_owed = false;
    s.blocked_sent_at = kNever;
    s.blocked_sent_time = 0;

    const bool local = is_local(id);
    const bool uni = stream_is_uni(id);

    /* \~english
     * The windows cross over: this end receives on its own bidirectional
     * streams with its "bidi_local" window, and sends on them within the
     * PEER's "bidi_remote" -- because for the peer those are remote streams.
     * \~spanish
     * Las ventanas se cruzan: este extremo recibe en sus propios flujos
     * bidireccionales con su ventana "bidi_local", y manda por ellos dentro de
     * la "bidi_remote" del OTRO extremo -- porque para el otro esos son flujos
     * remotos.
     * \~ */
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    if (!(uni && local)) {
        const uint64_t window = uni ? cfg_.window_uni
                              : local ? cfg_.window_bidi_local
                                      : cfg_.window_bidi_remote;
        void *mem = util::host_alloc(sizeof(RecvStream));
        if (mem == nullptr) {
            destroy(slot);
            return nullptr;
        }
        s.recv = new (mem) RecvStream(window);
    }
    if (!(uni && !local)) {
        const uint64_t limit = uni ? cfg_.peer_window_uni
                             : local ? cfg_.peer_window_bidi_remote
                                     : cfg_.peer_window_bidi_local;
        void *mem = util::host_alloc(sizeof(SendStream));
        if (mem == nullptr) {
            destroy(slot);
            return nullptr;
        }
        s.send = new (mem) SendStream(cfg_.send_capacity, limit);
    }

    index_.insert(id, slot);
    return &s;
}

void StreamTable::destroy(size_t slot) noexcept {
    Stream &s = slots_[slot];
    if (s.recv != nullptr) {
        s.recv->~RecvStream();
        util::host_free(s.recv);
        s.recv = nullptr;
    }
    if (s.send != nullptr) {
        s.send->~SendStream();
        util::host_free(s.send);
        s.send = nullptr;
    }
    index_.erase(s.id);
    s.id = kNever;
    free_[free_count_++] = static_cast<uint32_t>(slot);
}

Stream *StreamTable::find(uint64_t id) noexcept {
    const uint32_t at = index_.find(id);
    return at == IdIndex::kAbsent ? nullptr : &slots_[at];
}

StreamLookup StreamTable::on_peer_frame(uint64_t id, FrameType type, Stream *&out,
                                        TransportError &err) noexcept {
    out = nullptr;
    err = TransportError::NoError;

    const uint64_t t = id & 0x03;
    const bool local = is_local(id);
    const bool uni = stream_is_uni(id);
    const uint64_t idx = stream_index(id);

    // \~english The direction the frame speaks for has to exist on this stream.
    // \~spanish La direccion de la que habla la trama tiene que existir en este flujo.  \~
    if ((uni && local && names_receiving_part(type)) ||
        (uni && !local && names_sending_part(type))) {
        err = TransportError::StreamStateError;
        return StreamLookup::Error;
    }

    if (local) {
        // \~english One of ours that we never opened: the peer cannot know of it.
        // \~spanish Uno nuestro que nunca abrimos: el otro extremo no puede conocerlo.  \~
        if (idx >= opened_[t]) {
            err = TransportError::StreamStateError;
            return StreamLookup::Error;
        }
        out = find(id);
        return out != nullptr ? StreamLookup::Found : StreamLookup::Closed;
    }

    if (idx < opened_[t]) {
        out = find(id);
        return out != nullptr ? StreamLookup::Found : StreamLookup::Closed;
    }
    if (idx >= limit_[t]) {
        err = TransportError::StreamLimitError;
        return StreamLookup::Error;
    }

    // \~english Opening this one opens every lower one of its type (3.2).
    // \~spanish Abrir este abre todos los de debajo de su tipo (3.2).  \~
    for (uint64_t k = opened_[t]; k <= idx; ++k) {
        out = create(k * 4 + t);
        if (out == nullptr) {
            err = TransportError::InternalError;
            return StreamLookup::Error;
        }
        opened_[t] = k + 1;
    }
    return StreamLookup::Found;
}

Stream *StreamTable::open(bool bidirectional) noexcept {
    const uint64_t t = local_type(cfg_.is_server, bidirectional);
    // \~english Refused by the PEER's limit: that is what STREAMS_BLOCKED tells it (4.6).
    // \~spanish Negado por el limite del OTRO: eso es lo que le dice STREAMS_BLOCKED (4.6).  \~
    if (opened_[t] >= limit_[t]) {
        refused(bidirectional);
        return nullptr;
    }
    if (local_open_ >= cfg_.local_concurrency) return nullptr;
    Stream *s = create(opened_[t] * 4 + t);
    if (s == nullptr) return nullptr;
    ++opened_[t];
    ++local_open_;
    return s;
}

bool StreamTable::blocked_by_peer(bool bidirectional) const noexcept {
    const uint64_t t = local_type(cfg_.is_server, bidirectional);
    return opened_[t] >= limit_[t];
}

void StreamTable::on_max_streams(bool bidirectional, uint64_t maximum) noexcept {
    const uint64_t t = local_type(cfg_.is_server, bidirectional);
    if (maximum > limit_[t]) {
        limit_[t] = maximum;
        refused_[bidirectional ? 1 : 0] = false;
    }
}

void StreamTable::reset() noexcept {
    if (slots_ == nullptr) return;
    for (size_t i = 0; i < capacity_; ++i)
        if (slots_[i].id != kNever) destroy(i);
    // \~english Back to what the table was built with: numbering, limits and windows start over.
    // \~spanish De vuelta a con lo que se construyo la tabla: numeracion, limites y ventanas empiezan de nuevo.  \~
    for (size_t t = 0; t < 4; ++t) {
        opened_[t] = 0;
        closed_[t] = 0;
    }
    const bool srv = cfg_.is_server;
    limit_[peer_type(srv, true)] = base_.peer_bidi_concurrency;
    limit_[peer_type(srv, false)] = base_.peer_uni_concurrency;
    limit_[local_type(srv, true)] = base_.peer_max_streams_bidi;
    limit_[local_type(srv, false)] = base_.peer_max_streams_uni;
    cfg_.peer_window_bidi_local = base_.peer_window_bidi_local;
    cfg_.peer_window_bidi_remote = base_.peer_window_bidi_remote;
    cfg_.peer_window_uni = base_.peer_window_uni;
    refused_[0] = false;
    refused_[1] = false;
    local_open_ = 0;
}

void StreamTable::on_peer_params(uint64_t max_bidi, uint64_t max_uni, uint64_t window_bidi_local,
                                 uint64_t window_bidi_remote, uint64_t window_uni) noexcept {
    // \~english The initial limits are a MAX_STREAMS that came with the handshake (4.6).
    // \~spanish Los limites iniciales son un MAX_STREAMS que llego con el saludo (4.6).  \~
    on_max_streams(true, max_bidi);
    on_max_streams(false, max_uni);
    cfg_.peer_window_bidi_local = window_bidi_local;
    cfg_.peer_window_bidi_remote = window_bidi_remote;
    cfg_.peer_window_uni = window_uni;
    /* \~english
     * A stream opened before the parameters came -- in 0-RTT -- takes the
     * new window too, as the handshake's values replace the remembered ones
     * (7.4.1).  Its limit never goes down.
     * \~spanish
     * Un flujo abierto antes de que llegaran los parametros -- en 0-RTT -- toma
     * tambien la ventana nueva, porque los valores del saludo sustituyen a los
     * recordados (7.4.1).  Su limite nunca baja.
     * \~ */
    for (size_t i = 0; i < capacity_; ++i) {
        Stream &s = slots_[i];
        if (s.id == kNever || s.send == nullptr) continue;
        const bool uni = stream_is_uni(s.id);
        const bool local = is_local(s.id);
        s.send->on_max_stream_data(uni ? window_uni : local ? window_bidi_remote : window_bidi_local);
    }
}

size_t StreamTable::collect() noexcept {
    size_t removed = 0;
    for (size_t i = 0; i < capacity_; ++i) {
        Stream &s = slots_[i];
        if (s.id == kNever) continue;

        /* \~english
         * Only the terminal states the application reached (3.2): "Data
         * Recvd" and "Reset Recvd" still hold an end it has not heard, and a
         * stream collected there takes that end with it.
         * \~spanish
         * Solo los estados terminales a los que llego la aplicacion (3.2):
         * "Data Recvd" y "Reset Recvd" aun guardan un final que no ha oido, y un
         * flujo recogido ahi se lleva ese final con el.
         * \~ */
        const bool recv_done = s.recv == nullptr || s.recv->state() == RecvState::DataRead ||
                               s.recv->state() == RecvState::ResetRead;
        const bool send_done = s.send == nullptr || s.send->state() == SendState::DataRecvd ||
                               s.send->state() == SendState::ResetRecvd;
        if (!recv_done || !send_done) continue;

        ++closed_[s.id & 0x03];
        if (is_local(s.id)) --local_open_;
        destroy(i);
        ++removed;
    }
    return removed;
}

bool StreamTable::wants_max_streams(bool bidirectional) const noexcept {
    const uint64_t t = peer_type(cfg_.is_server, bidirectional);
    const uint64_t conc = bidirectional ? cfg_.peer_bidi_concurrency : cfg_.peer_uni_concurrency;
    const uint64_t target = closed_[t] + conc;

    // \~english In batches of half the concurrency: a frame per closed stream would be noise.
    // \~spanish En tandas de media concurrencia: una trama por flujo cerrado seria ruido.  \~
    return target > limit_[t] && (target - limit_[t]) * 2 >= conc;
}

uint64_t StreamTable::next_max_streams(bool bidirectional) const noexcept {
    const uint64_t t = peer_type(cfg_.is_server, bidirectional);
    const uint64_t conc = bidirectional ? cfg_.peer_bidi_concurrency : cfg_.peer_uni_concurrency;
    uint64_t target = closed_[t] + conc;
    if (target > kMaxStreams) target = kMaxStreams;
    return target > limit_[t] ? target : limit_[t];
}

uint64_t StreamTable::advertise_max_streams(bool bidirectional) noexcept {
    const uint64_t t = peer_type(cfg_.is_server, bidirectional);
    limit_[t] = next_max_streams(bidirectional);
    return limit_[t];
}

void StreamTable::refused(bool bidirectional) noexcept {
    refused_[bidirectional ? 1 : 0] = true;
}

bool StreamTable::open_refused(bool bidirectional) const noexcept {
    return refused_[bidirectional ? 1 : 0] && blocked_by_peer(bidirectional);
}

uint64_t StreamTable::peer_limit(bool bidirectional) const noexcept {
    return limit_[local_type(cfg_.is_server, bidirectional)];
}

uint64_t StreamTable::peer_opened(bool bidirectional) const noexcept {
    return opened_[peer_type(cfg_.is_server, bidirectional)];
}

uint64_t StreamTable::max_streams(bool bidirectional) const noexcept {
    return limit_[peer_type(cfg_.is_server, bidirectional)];
}

} // namespace quic
} // namespace http_vx
