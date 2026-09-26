/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/qpack_encoder.cpp
 * @brief
 * \~english The QPACK encoder: a single pass per section (Appendix C), with the tracking 2.1 asks for.
 * \~spanish El codificador de QPACK: una pasada por seccion (apendice C), con el seguimiento que pide 2.1.
 * \~
 */
#include "http_vx/qpack_encoder.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace qpack {

namespace {

constexpr uint64_t kNone = ~uint64_t{0};
constexpr size_t kBroken = ~size_t{0};

/// \~english The bytes an integer takes.  \~spanish Los bytes que ocupa un entero.  \~
size_t int_size(uint64_t v, unsigned prefix) noexcept {
    uint8_t tmp[kMaxIntBytes];
    return write_int(tmp, v, prefix, 0);
}

/// \~english Writes an integer at the end of @p out.  \~spanish Escribe un entero al final de @p out.  \~
bool put_int(Buffer &out, uint64_t v, unsigned prefix, uint8_t high) noexcept {
    uint8_t *dst = out.reserve(kMaxIntBytes);
    if (dst == nullptr) return false;
    const size_t k = write_int(dst, v, prefix, high);
    if (k == 0) return false;
    out.commit(k);
    return true;
}

/// \~english Writes a string literal at the end of @p out.  \~spanish Escribe una cadena literal al final de @p out.  \~
bool put_str(Buffer &out, const uint8_t *s, size_t n, unsigned prefix, uint8_t high) noexcept {
    const size_t need = str_size(s, n, prefix);
    uint8_t *dst = out.reserve(need);
    if (dst == nullptr) return false;
    if (write_str(dst, need, s, n, prefix, high) != need) return false;
    out.commit(need);
    return true;
}

} // namespace

Encoder::~Encoder() { release(); }

void Encoder::release() noexcept {
    table_.release();
    out_.release();
    pending_in_.release();
    body_.release();
    if (refcount_ != nullptr) util::host_free(refcount_);
    if (sections_ != nullptr) util::host_free(sections_);
    refcount_ = nullptr;
    refcount_cap_ = 0;
    sections_ = nullptr;
    pending_count_ = 0;
}

bool Encoder::reset(const EncoderConfig &cfg) noexcept {
    release();
    cfg_ = cfg;
    failure_ = Failure{};
    peer_capacity_ = 0;
    peer_blocked_ = 0;
    settings_ = false;
    remembered_ = false;
    known_ = 0;
    table_.reset(0);
    if (cfg.max_capacity > Table::kLargestMax) return fail(kInternalError, "a QPACK table larger than this encoder keeps");
    return true;
}

bool Encoder::fail(uint64_t code, const char *why) noexcept {
    if (failure_.code == 0) {
        failure_.code = code;
        failure_.why = why;
    }
    return false;
}

bool Encoder::start_table() noexcept {
    // \~english The smaller of what the peer allows and what this end is willing to keep (3.2.3).
    // \~spanish La menor entre lo que permite el otro y lo que este extremo quiere guardar (3.2.3).  \~
    const uint64_t capacity = peer_capacity_ < cfg_.max_capacity ? peer_capacity_ : cfg_.max_capacity;
    // \~english A maximum of zero: no insert and no instruction at all (3.2.3).  \~spanish Un maximo de cero: ninguna insercion ni ninguna instruccion (3.2.3).  \~
    if (capacity < kEntryOverhead) return true;
    if (!table_.reset(capacity) || !table_.set_capacity(capacity))
        return fail(kInternalError, "the QPACK table could not be set up");
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::All);
    refcount_cap_ = static_cast<size_t>(capacity / kEntryOverhead);
    refcount_ = static_cast<uint32_t *>(util::host_alloc(refcount_cap_ * sizeof(uint32_t)));
    sections_ = static_cast<Section *>(util::host_alloc(kPendingSections * sizeof(Section)));
    if (refcount_ == nullptr || sections_ == nullptr) return fail(kInternalError, "out of memory for the QPACK encoder");
    util::vesta_memset_noinline(refcount_, 0, refcount_cap_ * sizeof(uint32_t));
    // \~english Set Dynamic Table Capacity: '001', 5-bit prefix (4.3.1).  \~spanish Set Dynamic Table Capacity: '001', prefijo de 5 bits (4.3.1).  \~
    return instruction(capacity, 5, 0x20);
}

bool Encoder::remember_peer_settings(uint64_t max_table_capacity, uint64_t blocked_streams) noexcept {
    if (failed() || settings_ || remembered_) return fail(kInternalError, "remembered QPACK settings given twice, or after the real ones");
    remembered_ = true;
    peer_capacity_ = max_table_capacity;
    peer_blocked_ = blocked_streams;
    return start_table();
}

bool Encoder::on_peer_settings(uint64_t max_table_capacity, uint64_t blocked_streams) noexcept {
    if (failed()) return false;
    if (settings_) return fail(kInternalError, "the peer's QPACK settings given twice");
    settings_ = true;
    if (remembered_ && peer_capacity_ != 0) {
        // \~english A remembered non-zero capacity MUST come back the same (3.2.3).
        // \~spanish Una capacidad recordada distinta de cero DEBE volver igual (3.2.3).  \~
        if (max_table_capacity != peer_capacity_)
            return fail(kDecoderStreamError, "the SETTINGS changed a remembered non-zero table capacity (3.2.3)");
        peer_blocked_ = blocked_streams;
        return true;
    }
    peer_capacity_ = max_table_capacity;
    peer_blocked_ = blocked_streams;
    return start_table();
}

bool Encoder::instruction(uint64_t value, unsigned prefix, uint8_t high) noexcept {
    if (!put_int(out_, value, prefix, high)) return fail(kInternalError, "out of memory for the encoder stream");
    return true;
}

const uint8_t *Encoder::output(size_t &n) const noexcept {
    n = out_.size();
    return out_.data();
}

void Encoder::sent(size_t n) noexcept { out_.consume(n < out_.size() ? n : out_.size()); }

bool Encoder::is_blocking(uint64_t stream) const noexcept {
    for (size_t i = 0; i < pending_count_; ++i)
        if (sections_[i].stream == stream && sections_[i].required > known_) return true;
    return false;
}

size_t Encoder::blocking_streams() const noexcept {
    size_t n = 0;
    for (size_t i = 0; i < pending_count_; ++i) {
        if (sections_[i].required <= known_) continue;
        // \~english Counted once per stream: at its first blocking section.  \~spanish Contado una vez por flujo: en su primera seccion que bloquea.  \~
        bool first = true;
        for (size_t j = 0; j < i && first; ++j)
            if (sections_[j].stream == sections_[i].stream && sections_[j].required > known_) first = false;
        if (first) ++n;
    }
    return n;
}

bool Encoder::evictable(uint64_t abs) const noexcept {
    // \~english Acknowledged, and referenced by no unacknowledged section (2.1.1).
    // \~spanish Confirmada, y sin que la referencie ninguna seccion sin confirmar (2.1.1).  \~
    return abs < known_ && refcount_[abs % refcount_cap_] == 0;
}

bool Encoder::can_insert(uint64_t cost) const noexcept {
    uint64_t room = table_.capacity() - table_.size();
    // \~english The oldest go first: an insert that would evict one that may not go is not made (2.1.1).
    // \~english One larger than the whole table runs out of entries before it runs out of need.
    // \~spanish Las mas viejas van primero: una insercion que desalojaria una que no puede irse no se hace (2.1.1).
    // \~spanish Una mayor que toda la tabla se queda sin entradas antes que sin necesidad.  \~
    for (uint64_t abs = table_.dropped(); room < cost; ++abs) {
        if (abs >= table_.inserted() || !evictable(abs)) return false;
        room += table_.cost(abs);
    }
    return true;
}

uint64_t Encoder::find_exact(const Line &l) const noexcept {
    // \~english The newest first: the farthest from eviction.  \~spanish La mas nueva primero: la mas lejos de ser desalojada.  \~
    for (uint64_t abs = table_.inserted(); abs > table_.dropped(); --abs)
        if (table_.is(abs - 1, l.name, l.name_len, l.value, l.value_len)) return abs - 1;
    return kNone;
}

uint64_t Encoder::find_name(const Line &l) const noexcept {
    for (uint64_t abs = table_.inserted(); abs > table_.dropped(); --abs)
        if (table_.has_name(abs - 1, l.name, l.name_len)) return abs - 1;
    return kNone;
}

bool Encoder::reference(Section &s, uint64_t abs) noexcept {
    for (uint32_t i = 0; i < s.ref_count; ++i)
        if (s.refs[i] == abs) return true;
    if (s.ref_count == kRefsPerSection) return false;
    s.refs[s.ref_count++] = abs;
    ++refcount_[abs % refcount_cap_];
    return true;
}

bool Encoder::insert(const Line &l, const StaticMatch &st, size_t &room) noexcept {
    const uint64_t cost = static_cast<uint64_t>(l.name_len) + l.value_len + kEntryOverhead;
    if (!can_insert(cost)) return false;
    // \~english The name by reference when a table has it (4.3.2), else as a literal (4.3.3).
    // \~spanish El nombre por referencia si alguna tabla lo tiene (4.3.2), si no como literal (4.3.3).  \~
    const uint64_t name_abs = st.index == kStaticLines ? find_name(l) : kNone;
    size_t need = str_size(l.value, l.value_len, 8);
    if (st.index != kStaticLines)
        need += int_size(st.index, 6);
    else if (name_abs != kNone)
        need += int_size(table_.inserted() - 1 - name_abs, 6);
    else
        need += str_size(l.name, l.name_len, 6);
    // \~english Only what flow control has room for (2.1.3).  \~spanish Solo lo que cabe en el control de flujo (2.1.3).  \~
    if (need > room) return false;
    bool ok;
    if (st.index != kStaticLines)
        ok = put_int(out_, st.index, 6, 0xc0);
    else if (name_abs != kNone)
        ok = put_int(out_, table_.inserted() - 1 - name_abs, 6, 0x80);
    else
        ok = put_str(out_, l.name, l.name_len, 6, 0x40);
    ok = ok && put_str(out_, l.value, l.value_len, 8, 0x00);
    if (!ok || table_.insert(l.name, l.name_len, l.value, l.value_len) != Table::Insert::Ok)
        return fail(kInternalError, "out of memory inserting into the QPACK table");
    room -= need;
    return true;
}

bool Encoder::encode(uint64_t stream, const Line *lines, size_t count, Buffer &out, size_t room) noexcept {
    if (failed()) return false;
    body_.clear();
    Section sec;
    sec.stream = stream;
    sec.required = 0;
    sec.ref_count = 0;
    // \~english The table is used only while a new section can still be tracked (7.3).
    // \~spanish La tabla solo se usa mientras aun se pueda seguir una seccion nueva (7.3).  \~
    const bool tracking = table_.capacity() != 0 && pending_count_ < kPendingSections;
    // \~english May this stream reference what the decoder may not have yet (2.1.2)?
    // \~spanish Puede este flujo referenciar lo que el descodificador puede no tener aun (2.1.2)?  \~
    const bool may_block = tracking && (is_blocking(stream) || blocking_streams() < peer_blocked_);
    // \~english Single pass: the Base is the Insert Count before the section (Appendix C).
    // \~spanish Una pasada: la Base es el Insert Count antes de la seccion (apendice C).  \~
    const uint64_t base = table_.inserted();
    uint64_t largest = 0;
    for (size_t i = 0; i < count; ++i) {
        const Line &l = lines[i];
        const bool never = l.indexing == Indexing::Never;
        const StaticMatch st = find_static(l.name, l.name_len, l.value, l.value_len);
        bool ok;
        if (!never && st.exact) {
            // \~english Indexed Field Line, static (4.5.2).  \~spanish Indexed Field Line, estatica (4.5.2).  \~
            ok = put_int(body_, st.index, 6, 0xc0);
        } else {
            uint64_t abs = kNone;
            if (!never && tracking) {
                const uint64_t found = find_exact(l);
                if (found != kNone && (found < known_ || may_block) && reference(sec, found)) abs = found;
                if (abs == kNone && found == kNone && l.indexing == Indexing::Insert && insert(l, st, room)) {
                    const uint64_t added = table_.inserted() - 1;
                    if (may_block && reference(sec, added)) abs = added;
                }
                if (failed()) return false;
            }
            if (abs != kNone) {
                if (abs + 1 > largest) largest = abs + 1;
                // \~english Relative below the Base (4.5.2), post-Base above it (4.5.3).
                // \~spanish Relativa por debajo de la Base (4.5.2), post-Base por encima (4.5.3).  \~
                ok = abs < base ? put_int(body_, base - 1 - abs, 6, 0x80) : put_int(body_, abs - base, 4, 0x10);
            } else {
                const uint8_t n45 = never ? 0x20 : 0x00;
                uint64_t name_abs = kNone;
                if (st.index == kStaticLines && tracking) {
                    const uint64_t found = find_name(l);
                    if (found != kNone && (found < known_ || may_block) && reference(sec, found)) name_abs = found;
                }
                if (st.index != kStaticLines) {
                    // \~english Literal with a static name reference: '01', N, T=1 (4.5.4).  \~spanish Literal con referencia de nombre estatica: '01', N, T=1 (4.5.4).  \~
                    ok = put_int(body_, st.index, 4, static_cast<uint8_t>(0x50 | n45));
                } else if (name_abs != kNone) {
                    if (name_abs + 1 > largest) largest = name_abs + 1;
                    ok = name_abs < base ? put_int(body_, base - 1 - name_abs, 4, static_cast<uint8_t>(0x40 | n45))
                                         : put_int(body_, name_abs - base, 3, static_cast<uint8_t>(never ? 0x08 : 0x00));
                } else {
                    // \~english Literal name: '001', N, a 4-bit prefix string (4.5.6).  \~spanish Nombre literal: '001', N, una cadena con prefijo de 4 bits (4.5.6).  \~
                    ok = put_str(body_, l.name, l.name_len, 4, static_cast<uint8_t>(0x20 | (never ? 0x10 : 0x00)));
                }
                ok = ok && put_str(body_, l.value, l.value_len, 8, 0x00);
            }
        }
        if (!ok) return fail(kInternalError, "out of memory encoding a field section");
    }
    // \~english The prefix (4.5.1): Required Insert Count, then the Base as a sign and a Delta Base.
    // \~spanish El prefijo (4.5.1): Required Insert Count, y la Base como signo y Delta Base.  \~
    bool ok;
    if (largest == 0) {
        ok = put_int(out, 0, 8, 0) && put_int(out, 0, 7, 0);
    } else {
        const uint64_t full = 2 * (peer_capacity_ / kEntryOverhead);
        ok = put_int(out, largest % full + 1, 8, 0) &&
             (base >= largest ? put_int(out, base - largest, 7, 0x00) : put_int(out, largest - base - 1, 7, 0x80));
        sec.required = largest;
        sections_[pending_count_++] = sec;
    }
    if (ok && !body_.empty()) {
        uint8_t *dst = out.reserve(body_.size());
        ok = dst != nullptr;
        if (ok) {
            util::vesta_memcpy(dst, body_.data(), body_.size());
            out.commit(body_.size());
        }
    }
    if (!ok) return fail(kInternalError, "out of memory encoding a field section");
    // \~english References this section did not keep in the end hold nothing: a section with no RIC is not tracked.
    // \~spanish Las referencias que esta seccion no llego a guardar no retienen nada: una seccion sin RIC no se sigue.  \~
    return true;
}

void Encoder::drop_section(size_t i) noexcept {
    const Section &s = sections_[i];
    for (uint32_t k = 0; k < s.ref_count; ++k) --refcount_[s.refs[k] % refcount_cap_];
    for (size_t j = i + 1; j < pending_count_; ++j) sections_[j - 1] = sections_[j];
    --pending_count_;
}

size_t Encoder::decoder_instruction(const uint8_t *p, size_t n) noexcept {
    const uint8_t b = p[0];
    const unsigned prefix = (b & 0x80) != 0 ? 7 : 6;
    const Int v = read_int(p, n, prefix);
    if (v.status == Status::Truncated) return 0;
    if (v.status != Status::Ok) return fail(kDecoderStreamError, "a decoder instruction integer too large (7.4)"), kBroken;
    if ((b & 0x80) != 0) {
        // \~english Section Acknowledgment: the earliest unacknowledged section on that stream (4.4.1, 2.2.2.1).
        // \~spanish Section Acknowledgment: la primera seccion sin confirmar de ese flujo (4.4.1, 2.2.2.1).  \~
        for (size_t i = 0; i < pending_count_; ++i)
            if (sections_[i].stream == v.value) {
                if (sections_[i].required > known_) known_ = sections_[i].required;
                drop_section(i);
                return v.used;
            }
        return fail(kDecoderStreamError, "a Section Acknowledgment for a stream with nothing to acknowledge (4.4.1)"),
               kBroken;
    }
    if ((b & 0x40) != 0) {
        // \~english Stream Cancellation: every reference on that stream released (4.4.2).
        // \~spanish Stream Cancellation: liberadas todas las referencias de ese flujo (4.4.2).  \~
        for (size_t i = 0; i < pending_count_;) {
            if (sections_[i].stream == v.value)
                drop_section(i);
            else
                ++i;
        }
        return v.used;
    }
    // \~english Insert Count Increment (4.4.3).  \~spanish Insert Count Increment (4.4.3).  \~
    if (v.value == 0) return fail(kDecoderStreamError, "an Insert Count Increment of zero (4.4.3)"), kBroken;
    if (v.value > table_.inserted() - known_)
        return fail(kDecoderStreamError, "an Insert Count Increment past what was inserted (4.4.3)"), kBroken;
    known_ += v.value;
    return v.used;
}

bool Encoder::on_decoder_stream(const uint8_t *p, size_t n) noexcept {
    if (failed()) return false;
    uint8_t *dst = pending_in_.reserve(n);
    if (n != 0 && dst == nullptr) return fail(kInternalError, "out of memory for the decoder stream");
    if (n != 0) {
        util::vesta_memcpy(dst, p, n);
        pending_in_.commit(n);
    }
    while (!pending_in_.empty()) {
        const size_t used = decoder_instruction(pending_in_.data(), pending_in_.size());
        if (used == kBroken) return false;
        if (used == 0) break;
        pending_in_.consume(used);
    }
    return true;
}

} // namespace qpack
} // namespace http_vx
