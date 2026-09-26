/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/qpack_decoder.cpp
 * @brief
 * \~english The QPACK decoder: encoder instructions (4.3), field line representations (4.5), decoder instructions (4.4).
 * \~spanish El descodificador de QPACK: instrucciones del codificador (4.3), representaciones de lineas de campo (4.5), instrucciones del descodificador (4.4).
 * \~
 */
#include "http_vx/qpack_decoder.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace qpack {

namespace {

/// \~english An instruction that failed, as instruction() reports it.  \~spanish Una instruccion que fallo, como la informa instruction().  \~
constexpr size_t kBroken = ~size_t{0};

/// \~english The most blocked streams a decoder keeps room for.  \~spanish Los flujos bloqueados para los que un descodificador guarda sitio como mucho.  \~
constexpr uint64_t kMostBlocked = 65536;

/// \~english Appends @p n bytes to @p out; where they landed goes to @p where.  \~spanish Anade @p n bytes a @p out; donde quedaron va a @p where.  \~
bool append(Buffer &out, const void *p, size_t n, Span &where) noexcept {
    where.off = static_cast<uint32_t>(out.size());
    where.len = static_cast<uint32_t>(n);
    if (n == 0) return true;
    uint8_t *dst = out.reserve(n);
    if (dst == nullptr) return false;
    util::vesta_memcpy(dst, p, n);
    out.commit(n);
    return true;
}

} // namespace

Decoder::~Decoder() { release(); }

void Decoder::release() noexcept {
    table_.release();
    pending_.release();
    scratch_.release();
    discard_.release();
    out_.release();
    if (blocked_ != nullptr) util::host_free(blocked_);
    blocked_ = nullptr;
    blocked_count_ = 0;
}

bool Decoder::reset(const DecoderConfig &cfg) noexcept {
    release();
    cfg_ = cfg;
    failure_ = Failure{};
    section_why_ = nullptr;
    need_ = 0;
    reads_ = 0;
    known_ = 0;
    if (!table_.reset(cfg.max_table_capacity) || cfg.blocked_streams > kMostBlocked)
        return fail(kInternalError, "QPACK limits larger than this decoder keeps");
    if (cfg.blocked_streams != 0) {
        const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
        blocked_ = static_cast<Blocked *>(util::host_alloc(static_cast<size_t>(cfg.blocked_streams) * sizeof(Blocked)));
        if (blocked_ == nullptr) return fail(kInternalError, "out of memory for the blocked streams");
    }
    return true;
}

bool Decoder::fail(uint64_t code, const char *why) noexcept {
    if (failure_.code == 0) {
        failure_.code = code;
        failure_.why = why;
    }
    return false;
}

Outcome Decoder::section_fail(Outcome o, const char *why) noexcept {
    section_why_ = why;
    return o;
}

bool Decoder::emit(uint64_t value, unsigned prefix, uint8_t high) noexcept {
    uint8_t tmp[kMaxIntBytes];
    const size_t k = write_int(tmp, value, prefix, high);
    Span unused;
    if (k == 0 || !append(out_, tmp, k, unused)) return fail(kInternalError, "out of memory for the decoder stream");
    return true;
}

const uint8_t *Decoder::output(size_t &n) const noexcept {
    n = out_.size();
    return out_.data();
}

void Decoder::sent(size_t n) noexcept { out_.consume(n < out_.size() ? n : out_.size()); }

bool Decoder::dynamic_name(uint64_t relative, Span &name) noexcept {
    // \~english On the encoder stream, relative 0 is the newest entry (3.2.5).  \~spanish En el flujo del codificador, el relativo 0 es la entrada mas nueva (3.2.5).  \~
    if (relative >= table_.inserted())
        return fail(kEncoderStreamError, "an encoder instruction naming an entry before the first insert (3.2.5)");
    const uint64_t abs = table_.inserted() - 1 - relative;
    if (!table_.has(abs))
        return fail(kEncoderStreamError, "an encoder instruction naming an evicted entry (2.2.3)");
    if (!table_.copy_name(abs, scratch_, name)) return fail(kInternalError, "out of memory copying a table entry");
    return true;
}

size_t Decoder::instruction(const uint8_t *p, size_t n) noexcept {
    ++reads_;
    scratch_.clear();
    const uint8_t b = p[0];
    Span name{0, 0};
    Str value;
    size_t head = 0;
    const char *static_name = nullptr;
    if ((b & 0x80) != 0 || (b & 0xc0) == 0x40) {
        if ((b & 0x80) != 0) {
            // \~english Insert with Name Reference: '1', T, a 6-bit index (4.3.2).  \~spanish Insert with Name Reference: '1', T, un indice de 6 bits (4.3.2).  \~
            const Int idx = read_int(p, n, 6);
            if (idx.status == Status::Truncated) return 0;
            if (idx.status != Status::Ok) return fail(kEncoderStreamError, "an encoder instruction index too large (7.4)"), kBroken;
            head = idx.used;
            if ((b & 0x40) != 0) {
                const StaticLine *line = static_line(idx.value);
                if (line == nullptr)
                    return fail(kEncoderStreamError, "an insert naming a static line that does not exist (3.1)"), kBroken;
                static_name = line->name;
                name.len = line->name_len;
            } else if (!dynamic_name(idx.value, name)) {
                return kBroken;
            }
        } else {
            // \~english Insert with Literal Name: '01', then a 6-bit prefix string (4.3.3).  \~spanish Insert with Literal Name: '01', y una cadena con prefijo de 6 bits (4.3.3).  \~
            const Str s = read_str(p, n, 6, cfg_.max_string, scratch_);
            if (s.status == Status::Truncated) {
                need_ = s.used;
                return 0;
            }
            if (s.status == Status::NoMemory) return fail(kInternalError, "out of memory for an inserted name"), kBroken;
            if (s.status == Status::TooLarge) return fail(kEncoderStreamError, "an inserted name longer than this end reads (7.4)"), kBroken;
            if (s.status != Status::Ok) return fail(kEncoderStreamError, "an inserted name that does not decode (4.1.2)"), kBroken;
            name = s.span;
            head = s.used;
        }
        value = read_str(p + head, n - head, 8, cfg_.max_string, scratch_);
        if (value.status == Status::Truncated) {
            need_ = value.used != 0 ? head + value.used : 0;
            return 0;
        }
        if (value.status == Status::NoMemory) return fail(kInternalError, "out of memory for an inserted value"), kBroken;
        if (value.status == Status::TooLarge) return fail(kEncoderStreamError, "an inserted value longer than this end reads (7.4)"), kBroken;
        if (value.status != Status::Ok) return fail(kEncoderStreamError, "an inserted value that does not decode (4.1.2)"), kBroken;
        const uint8_t *nm = static_name != nullptr ? reinterpret_cast<const uint8_t *>(static_name) : scratch_.data() + name.off;
        const Table::Insert r = table_.insert(nm, name.len, scratch_.data() + value.span.off, value.span.len);
        if (r == Table::Insert::TooLarge) return fail(kEncoderStreamError, "an entry larger than the table's capacity (3.2.2)"), kBroken;
        if (r != Table::Insert::Ok) return fail(kInternalError, "out of memory for the dynamic table"), kBroken;
        return head + value.used;
    }
    const Int v = read_int(p, n, 5);
    if (v.status == Status::Truncated) return 0;
    if (v.status != Status::Ok) return fail(kEncoderStreamError, "an encoder instruction integer too large (7.4)"), kBroken;
    if ((b & 0xe0) == 0x20) {
        // \~english Set Dynamic Table Capacity: '001', a 5-bit capacity (4.3.1).  \~spanish Set Dynamic Table Capacity: '001', una capacidad de 5 bits (4.3.1).  \~
        if (!table_.set_capacity(v.value))
            return fail(kEncoderStreamError, "a table capacity above the maximum this end announced (4.3.1)"), kBroken;
        return v.used;
    }
    // \~english Duplicate: '000', a 5-bit relative index (4.3.4).  \~spanish Duplicate: '000', un indice relativo de 5 bits (4.3.4).  \~
    if (v.value >= table_.inserted())
        return fail(kEncoderStreamError, "a duplicate of an entry before the first insert (3.2.5)"), kBroken;
    const uint64_t abs = table_.inserted() - 1 - v.value;
    if (!table_.has(abs)) return fail(kEncoderStreamError, "a duplicate of an evicted entry (2.2.3)"), kBroken;
    Span val;
    if (!table_.copy_name(abs, scratch_, name) || !table_.copy_value(abs, scratch_, val))
        return fail(kInternalError, "out of memory copying a table entry"), kBroken;
    const Table::Insert r =
        table_.insert(scratch_.data() + name.off, name.len, scratch_.data() + val.off, val.len);
    if (r == Table::Insert::TooLarge) return fail(kEncoderStreamError, "an entry larger than the table's capacity (3.2.2)"), kBroken;
    if (r != Table::Insert::Ok) return fail(kInternalError, "out of memory for the dynamic table"), kBroken;
    return v.used;
}

bool Decoder::on_encoder_stream(const uint8_t *p, size_t n) noexcept {
    if (failed()) return false;
    Span unused;
    if (!append(pending_, p, n, unused)) return fail(kInternalError, "out of memory for the encoder stream");
    while (!pending_.empty()) {
        // \~english An instruction whose length is known is not read again until all of it is here.
        // \~spanish Una instruccion cuya longitud se sabe no se vuelve a leer hasta que este entera aqui.  \~
        if (need_ != 0 && pending_.size() < need_) break;
        need_ = 0;
        const size_t used = instruction(pending_.data(), pending_.size());
        if (used == kBroken) return false;
        if (used == 0) {
            if (need_ == 0) need_ = pending_.size() + 1;
            break;
        }
        pending_.consume(used);
    }
    return true;
}

bool Decoder::flush() noexcept {
    if (failed()) return false;
    // \~english What is new and no Section Acknowledgment covered, in one Insert Count Increment (4.4.3; 2.2.2.3).
    // \~spanish Lo nuevo que no cubrio ningun Section Acknowledgment, en un Insert Count Increment (4.4.3; 2.2.2.3).  \~
    if (table_.inserted() > known_) {
        if (!emit(table_.inserted() - known_, 6, 0x00)) return false;
        known_ = table_.inserted();
    }
    return true;
}

bool Decoder::remember_blocked(uint64_t stream, uint64_t required) noexcept {
    for (size_t i = 0; i < blocked_count_; ++i)
        if (blocked_[i].stream == stream) {
            blocked_[i].required = required;
            return true;
        }
    if (blocked_count_ == cfg_.blocked_streams)
        return fail(kDecompressionFailed, "more blocked streams than this end announced (2.1.2)");
    blocked_[blocked_count_].stream = stream;
    blocked_[blocked_count_].required = required;
    ++blocked_count_;
    return true;
}

void Decoder::forget_blocked(uint64_t stream) noexcept {
    for (size_t i = 0; i < blocked_count_; ++i)
        if (blocked_[i].stream == stream) {
            blocked_[i] = blocked_[--blocked_count_];
            return;
        }
}

size_t Decoder::take_unblocked(uint64_t *ids, size_t cap) noexcept {
    size_t k = 0;
    for (size_t i = 0; i < blocked_count_ && k < cap;) {
        if (blocked_[i].required <= table_.inserted()) {
            ids[k++] = blocked_[i].stream;
            blocked_[i] = blocked_[--blocked_count_];
        } else {
            ++i;
        }
    }
    return k;
}

void Decoder::cancel_stream(uint64_t stream) noexcept {
    forget_blocked(stream);
    // \~english With no dynamic table there is nothing to release, and the cancellation MAY be left out (2.2.2.2).
    // \~spanish Sin tabla dinamica no hay nada que liberar, y la cancelacion PUEDE omitirse (2.2.2.2).  \~
    if (cfg_.max_table_capacity != 0 && !failed()) emit(stream, 6, 0x40);
}

Outcome Decoder::decode(uint64_t stream, const uint8_t *block, size_t n, Buffer &out, FieldSink &sink) noexcept {
    section_why_ = nullptr;
    if (failed()) return Outcome::Failed;
    // \~english The prefix: Required Insert Count, 8-bit prefix (4.5.1.1).  \~spanish El prefijo: Required Insert Count, prefijo de 8 bits (4.5.1.1).  \~
    const Int enc = read_int(block, n, 8);
    if (enc.status == Status::TooLarge) return section_fail(Outcome::StreamFailed, "a Required Insert Count too large (7.4)");
    if (enc.status != Status::Ok)
        return fail(kDecompressionFailed, "a field section prefix cut short (4.5.1)"), Outcome::Failed;
    uint64_t ric = 0;
    if (enc.value != 0) {
        const uint64_t max_entries = table_.max_entries();
        const uint64_t full = 2 * max_entries;
        if (enc.value > full)
            return fail(kDecompressionFailed, "an Encoded Insert Count no conformant encoder produces (4.5.1.1)"), Outcome::Failed;
        const uint64_t max_value = table_.inserted() + max_entries;
        ric = max_value / full * full + enc.value - 1;
        if (ric > max_value) {
            if (ric <= full)
                return fail(kDecompressionFailed, "an Encoded Insert Count no conformant encoder produces (4.5.1.1)"), Outcome::Failed;
            ric -= full;
        }
        if (ric == 0)
            return fail(kDecompressionFailed, "an Encoded Insert Count no conformant encoder produces (4.5.1.1)"), Outcome::Failed;
    }
    // \~english The Base: a sign bit and a 7-bit Delta Base (4.5.1.2).  \~spanish La Base: un bit de signo y un Delta Base de 7 bits (4.5.1.2).  \~
    size_t at = enc.used;
    if (at >= n) return fail(kDecompressionFailed, "a field section prefix cut short (4.5.1)"), Outcome::Failed;
    const bool negative = (block[at] & 0x80) != 0;
    const Int delta = read_int(block + at, n - at, 7);
    if (delta.status == Status::TooLarge) return section_fail(Outcome::StreamFailed, "a Delta Base too large (7.4)");
    if (delta.status != Status::Ok) return fail(kDecompressionFailed, "a field section prefix cut short (4.5.1)"), Outcome::Failed;
    at += delta.used;
    uint64_t base = 0;
    if (!negative) {
        if (delta.value > kMaxInt - ric) return section_fail(Outcome::StreamFailed, "a Base too large (7.4)");
        base = ric + delta.value;
    } else {
        if (ric <= delta.value)
            return fail(kDecompressionFailed, "a negative Base (4.5.1.2)"), Outcome::Failed;
        base = ric - delta.value - 1;
    }
    // \~english Inserts it needs are not in yet: blocked (2.2.1).  \~spanish Las inserciones que necesita aun no han llegado: bloqueada (2.2.1).  \~
    if (ric > table_.inserted()) return remember_blocked(stream, ric) ? Outcome::Blocked : Outcome::Failed;
    forget_blocked(stream);

    uint64_t largest = 0;
    uint64_t size = 0;
    bool over = false;
    while (at < n) {
        // \~english Past the limit, lines are still read -- the table's references resolve -- but land nowhere kept.
        // \~spanish Pasado el limite, las lineas se siguen leyendo -- las referencias a la tabla se resuelven -- pero no quedan en nada guardado.  \~
        Buffer &dst = over ? discard_ : out;
        if (over) discard_.clear();
        FieldLine line;
        const uint8_t b = block[at];
        bool name_done = false;
        bool value_done = false;
        uint64_t name_abs = ~uint64_t{0};
        bool name_static = false;
        uint64_t name_index = 0;
        unsigned prefix = 0;
        if ((b & 0x80) != 0) {
            // \~english Indexed Field Line: '1', T, a 6-bit index (4.5.2).  \~spanish Indexed Field Line: '1', T, un indice de 6 bits (4.5.2).  \~
            prefix = 6;
            name_static = (b & 0x40) != 0;
            value_done = true;
        } else if ((b & 0xf0) == 0x10) {
            // \~english Indexed Field Line with Post-Base Index: '0001', a 4-bit index (4.5.3).  \~spanish Indexed Field Line with Post-Base Index: '0001', un indice de 4 bits (4.5.3).  \~
            prefix = 4;
            value_done = true;
        } else if ((b & 0xc0) == 0x40) {
            // \~english Literal Field Line with Name Reference: '01', N, T, a 4-bit index (4.5.4).  \~spanish Literal Field Line with Name Reference: '01', N, T, un indice de 4 bits (4.5.4).  \~
            prefix = 4;
            line.never_indexed = (b & 0x20) != 0;
            name_static = (b & 0x10) != 0;
        } else if ((b & 0xf0) == 0x00) {
            // \~english Literal Field Line with Post-Base Name Reference: '0000', N, a 3-bit index (4.5.5).  \~spanish Literal Field Line with Post-Base Name Reference: '0000', N, un indice de 3 bits (4.5.5).  \~
            prefix = 3;
            line.never_indexed = (b & 0x08) != 0;
        } else {
            // \~english Literal Field Line with Literal Name: '001', N, a 4-bit prefix string (4.5.6).  \~spanish Literal Field Line with Literal Name: '001', N, una cadena con prefijo de 4 bits (4.5.6).  \~
            line.never_indexed = (b & 0x10) != 0;
            const Str s = read_str(block + at, n - at, 4, cfg_.max_string, dst);
            if (s.status == Status::TooLarge) return section_fail(Outcome::StreamFailed, "a field name longer than this end reads (7.4)");
            if (s.status == Status::NoMemory) return fail(kInternalError, "out of memory for a field name"), Outcome::Failed;
            if (s.status != Status::Ok) return fail(kDecompressionFailed, "a field name cut short or not decoding (4.5.6)"), Outcome::Failed;
            line.name = s.span;
            at += s.used;
            name_done = true;
        }
        if (!name_done) {
            const Int idx = read_int(block + at, n - at, prefix);
            if (idx.status == Status::TooLarge) return section_fail(Outcome::StreamFailed, "a field line index too large (7.4)");
            if (idx.status != Status::Ok) return fail(kDecompressionFailed, "a field line cut short (4.5)"), Outcome::Failed;
            at += idx.used;
            name_index = idx.value;
            const bool post_base = (b & 0x80) == 0 && (b & 0xc0) != 0x40;
            if (name_static) {
                const StaticLine *s = static_line(name_index);
                if (s == nullptr)
                    return fail(kDecompressionFailed, "a field line naming a static line that does not exist (3.1)"), Outcome::Failed;
                if (!append(dst, s->name, s->name_len, line.name) ||
                    (value_done && !append(dst, s->value, s->value_len, line.value)))
                    return fail(kInternalError, "out of memory for a field line"), Outcome::Failed;
            } else {
                // \~english Relative to the Base, or past it (3.2.5, 3.2.6).  \~spanish Relativo a la Base, o mas alla (3.2.5, 3.2.6).  \~
                if (post_base) {
                    if (name_index > kMaxInt - base)
                        return fail(kDecompressionFailed, "a post-Base index past any entry (3.2.6)"), Outcome::Failed;
                    name_abs = base + name_index;
                } else {
                    if (name_index >= base)
                        return fail(kDecompressionFailed, "a relative index below the Base's first entry (3.2.5)"), Outcome::Failed;
                    name_abs = base - 1 - name_index;
                }
                if (name_abs >= ric)
                    return fail(kDecompressionFailed, "a reference at or past the Required Insert Count (2.2.3)"), Outcome::Failed;
                if (!table_.has(name_abs))
                    return fail(kDecompressionFailed, "a reference to an evicted entry (2.2.3)"), Outcome::Failed;
                if (name_abs + 1 > largest) largest = name_abs + 1;
                if (!table_.copy_name(name_abs, dst, line.name) ||
                    (value_done && !table_.copy_value(name_abs, dst, line.value)))
                    return fail(kInternalError, "out of memory for a field line"), Outcome::Failed;
            }
        }
        if (!value_done) {
            const Str v = read_str(block + at, n - at, 8, cfg_.max_string, dst);
            if (v.status == Status::TooLarge) return section_fail(Outcome::StreamFailed, "a field value longer than this end reads (7.4)");
            if (v.status == Status::NoMemory) return fail(kInternalError, "out of memory for a field value"), Outcome::Failed;
            if (v.status != Status::Ok) return fail(kDecompressionFailed, "a field value cut short or not decoding (4.1.2)"), Outcome::Failed;
            line.value = v.span;
            at += v.used;
        }
        // \~english The size RFC 9114, 4.2.2 counts: name, value and 32 a line.
        // \~spanish El tamano que cuenta el RFC 9114, 4.2.2: nombre, valor y 32 por linea.  \~
        size += static_cast<uint64_t>(line.name.len) + line.value.len + kEntryOverhead;
        if (!over && size > cfg_.max_section) over = true;
        if (!over && !sink.field(out, line)) return section_fail(Outcome::Rejected, "the field lines were refused above QPACK");
    }
    // \~english The Required Insert Count is exactly one past the largest reference (2.1.2): larger MAY be refused, and is (2.2.1).
    // \~spanish El Required Insert Count es exactamente uno mas que la mayor referencia (2.1.2): uno mayor PUEDE rechazarse, y se rechaza (2.2.1).  \~
    if (ric != largest)
        return fail(kDecompressionFailed, "a Required Insert Count larger than the references need (2.2.1)"), Outcome::Failed;
    // \~english A section that used the table is acknowledged (2.2.2.1, 4.4.1).  \~spanish Una seccion que uso la tabla se confirma (2.2.2.1, 4.4.1).  \~
    if (ric != 0) {
        if (!emit(stream, 7, 0x80)) return Outcome::Failed;
        if (ric > known_) known_ = ric;
    }
    return over ? section_fail(Outcome::TooLarge, "a field section larger than this end keeps (RFC 9114, 4.2.2)") : Outcome::Done;
}

} // namespace qpack
} // namespace http_vx
