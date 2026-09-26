/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/frame.cpp
 * @brief
 * \~english HTTP/3 frames: the per-stream reader, the payloads with fixed fields, and the writers (RFC 9114, 7).
 * \~spanish Las tramas de HTTP/3: el lector por flujo, las cargas con campos fijos, y los escritores (RFC 9114, 7).
 * \~
 */
#include "http_vx/h3_frame.h"

#include "http_vx/quic_varint.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h3 {

namespace {

/// \~english The settings of HTTP/2 that HTTP/3 reserved: receiving one is an error (7.2.4.1).
/// \~spanish Los parametros de HTTP/2 que HTTP/3 reservo: recibir uno es un error (7.2.4.1).  \~
bool is_h2_only_setting(uint64_t id) noexcept { return id == 0x00 || (id >= 0x02 && id <= 0x05); }

/// \~english Frames this end reads whole.  \~spanish Tramas que este extremo lee enteras.  \~
bool is_held(uint64_t t) noexcept {
    return t == kHeaders || t == kCancelPush || t == kSettings || t == kPushPromise || t == kGoaway || t == kMaxPushId;
}

/// \~english The most settings one frame may carry here.  \~spanish Los parametros que puede llevar una trama aqui como mucho.  \~
constexpr size_t kMostSettings = 64;

} // namespace

void FrameReader::reset(uint64_t max_held) noexcept {
    state_ = State::Head;
    head_len_ = 0;
    type_ = 0;
    left_ = 0;
    max_held_ = max_held;
    held_.clear();
    piece_ = nullptr;
    piece_len_ = 0;
    frames_ = 0;
    skipped_ = 0;
    failure_ = Failure{};
}

Step FrameReader::fail(uint64_t code, const char *why) noexcept {
    state_ = State::Failed;
    failure_.code = code;
    failure_.why = why;
    return Step::Failed;
}

const uint8_t *FrameReader::payload(size_t &n) const noexcept {
    n = held_.size();
    return held_.data();
}

Step FrameReader::next(const uint8_t *p, size_t n, size_t &used) noexcept {
    used = 0;
    piece_ = nullptr;
    piece_len_ = 0;
    for (;;) {
        switch (state_) {
        case State::Failed:
            return Step::Failed;
        case State::Head: {
            // \~english The head a byte at a time: two varints whose lengths come in their first bytes.
            // \~spanish La cabecera byte a byte: dos varints cuya longitud viene en su primer byte.  \~
            size_t need = 1;
            for (;;) {
                if (head_len_ >= 1) {
                    const size_t tlen = quic::varint_length(head_[0]);
                    need = tlen + 1;
                    if (head_len_ >= tlen + 1) need = tlen + quic::varint_length(head_[tlen]);
                }
                if (head_len_ == need || used == n) break;
                head_[head_len_++] = p[used++];
            }
            if (head_len_ < need) return Step::More;
            uint64_t length = 0;
            const size_t tlen = quic::decode_varint(head_, head_len_, type_);
            quic::decode_varint(head_ + tlen, head_len_ - tlen, length);
            head_len_ = 0;
            left_ = length;
            if (is_h2_only_frame(type_))
                return fail(kFrameUnexpected, "an HTTP/2 frame type with no meaning in HTTP/3 (7.2.8)");
            if (type_ == kData) {
                state_ = State::Data;
                // \~english An empty DATA frame is still a frame: reported, with nothing in it.
                // \~spanish Una trama DATA vacia sigue siendo una trama: se informa, sin nada dentro.  \~
                if (left_ == 0) {
                    state_ = State::Head;
                    ++frames_;
                    return Step::Data;
                }
            } else if (is_held(type_)) {
                if (length > max_held_) return fail(kExcessiveLoad, "a frame larger than this end holds (10.5)");
                held_.clear();
                state_ = State::Hold;
            } else {
                // \~english Unknown and reserved types: skipped, never held (9).  \~spanish Tipos desconocidos y reservados: saltados, nunca guardados (9).  \~
                ++skipped_;
                state_ = State::Skip;
            }
            break;
        }
        case State::Hold: {
            const size_t k = left_ < n - used ? static_cast<size_t>(left_) : n - used;
            if (k != 0) {
                uint8_t *dst = held_.reserve(k);
                if (dst == nullptr) return fail(kInternalError, "out of memory holding a frame");
                util::vesta_memcpy(dst, p + used, k);
                held_.commit(k);
                used += k;
                left_ -= k;
            }
            if (left_ != 0) return Step::More;
            state_ = State::Head;
            ++frames_;
            return Step::Frame;
        }
        case State::Skip: {
            const size_t k = left_ < n - used ? static_cast<size_t>(left_) : n - used;
            used += k;
            left_ -= k;
            if (left_ != 0) return Step::More;
            state_ = State::Head;
            break;
        }
        case State::Data: {
            const size_t k = left_ < n - used ? static_cast<size_t>(left_) : n - used;
            if (k == 0) return Step::More;
            piece_ = p + used;
            piece_len_ = k;
            used += k;
            left_ -= k;
            if (left_ == 0) {
                state_ = State::Head;
                ++frames_;
            }
            return Step::Data;
        }
        }
    }
}

bool read_settings(const uint8_t *p, size_t n, Settings &out, Failure &why) noexcept {
    out = Settings{};
    uint64_t seen[kMostSettings];
    size_t count = 0;
    size_t at = 0;
    while (at < n) {
        uint64_t id = 0;
        uint64_t value = 0;
        const size_t a = quic::decode_varint(p + at, n - at, id);
        const size_t b = a == 0 ? 0 : quic::decode_varint(p + at + a, n - at - a, value);
        if (a == 0 || b == 0) {
            why.code = kFrameError;
            why.why = "a SETTINGS payload that ends inside a setting (7.1)";
            return false;
        }
        at += a + b;
        for (size_t i = 0; i < count; ++i)
            if (seen[i] == id) {
                why.code = kSettingsError;
                why.why = "a setting identifier twice in one SETTINGS (7.2.4)";
                return false;
            }
        if (count == kMostSettings) {
            why.code = kExcessiveLoad;
            why.why = "more settings in one frame than this end reads (10.5)";
            return false;
        }
        seen[count++] = id;
        if (is_h2_only_setting(id)) {
            why.code = kSettingsError;
            why.why = "an HTTP/2 setting with no meaning in HTTP/3 (7.2.4.1)";
            return false;
        }
        // \~english The known ones taken; the rest -- reserved or unknown -- ignored (7.2.4).
        // \~spanish Los conocidos se toman; el resto -- reservados o desconocidos -- se ignora (7.2.4).  \~
        if (id == kSettingQpackMaxTableCapacity) out.qpack_max_table_capacity = value;
        if (id == kSettingQpackBlockedStreams) out.qpack_blocked_streams = value;
        if (id == kSettingMaxFieldSectionSize) out.max_field_section_size = value;
    }
    return true;
}

bool read_id(const uint8_t *p, size_t n, uint64_t &out, Failure &why) noexcept {
    const size_t k = quic::decode_varint(p, n, out);
    // \~english Exactly its fields: nothing missing, nothing after (7.1, 10.8).
    // \~spanish Exactamente sus campos: nada que falte, nada detras (7.1, 10.8).  \~
    if (k == 0 || k != n) {
        why.code = kFrameError;
        why.why = k == 0 ? "a frame that ends inside its identifier (7.1)" : "bytes after a frame's identifier (7.1)";
        return false;
    }
    return true;
}

bool write_varint(Buffer &out, uint64_t v) noexcept {
    uint8_t *dst = out.reserve(8);
    if (dst == nullptr) return false;
    const size_t k = quic::encode_varint(dst, 8, v);
    if (k == 0) return false;
    out.commit(k);
    return true;
}

bool write_head(Buffer &out, uint64_t type, uint64_t length) noexcept {
    return write_varint(out, type) && write_varint(out, length);
}

bool write_id(Buffer &out, uint64_t type, uint64_t id) noexcept {
    return id <= quic::kVarintMax && write_head(out, type, quic::varint_size(id)) && write_varint(out, id);
}

bool write_settings(Buffer &out, const Settings &s) noexcept {
    // \~english One reserved setting, so the peer keeps ignoring what it does not know (7.2.4.1).
    // \~spanish Un parametro reservado, para que el otro siga ignorando lo que no conoce (7.2.4.1).  \~
    constexpr uint64_t kGrease = 0x21;
    uint64_t pairs[4][2];
    size_t count = 0;
    if (s.qpack_max_table_capacity != 0) {
        pairs[count][0] = kSettingQpackMaxTableCapacity;
        pairs[count++][1] = s.qpack_max_table_capacity;
    }
    if (s.max_field_section_size != ~uint64_t{0}) {
        pairs[count][0] = kSettingMaxFieldSectionSize;
        pairs[count++][1] = s.max_field_section_size;
    }
    if (s.qpack_blocked_streams != 0) {
        pairs[count][0] = kSettingQpackBlockedStreams;
        pairs[count++][1] = s.qpack_blocked_streams;
    }
    pairs[count][0] = kGrease;
    pairs[count++][1] = 0;
    uint64_t length = 0;
    for (size_t i = 0; i < count; ++i) {
        if (pairs[i][1] > quic::kVarintMax) return false;
        length += quic::varint_size(pairs[i][0]) + quic::varint_size(pairs[i][1]);
    }
    if (!write_head(out, kSettings, length)) return false;
    for (size_t i = 0; i < count; ++i)
        if (!write_varint(out, pairs[i][0]) || !write_varint(out, pairs[i][1])) return false;
    return true;
}

} // namespace h3
} // namespace http_vx
