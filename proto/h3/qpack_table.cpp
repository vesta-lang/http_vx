/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/qpack_table.cpp
 * @brief
 * \~english The dynamic table as two rings: bytes and entries, nothing ever moved.
 * \~spanish La tabla dinamica como dos anillos: bytes y entradas, sin mover nunca nada.
 * \~
 */
#include "http_vx/qpack_table.h"

#include "http_vx/qpack.h"
#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace qpack {

namespace {

/// \~english The table lives as long as the connection.  \~spanish La tabla vive lo que la conexion.  \~
inline util::AllocScope open_scope() noexcept {
    return util::AllocScope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
}

} // namespace

Table::~Table() { release(); }

void Table::release() noexcept {
    if (bytes_ != nullptr) util::host_free(bytes_);
    if (entries_ != nullptr) util::host_free(entries_);
    bytes_ = nullptr;
    entries_ = nullptr;
    bytes_cap_ = 0;
    entries_cap_ = 0;
    bytes_head_ = 0;
    bytes_len_ = 0;
    oldest_ = 0;
    count_ = 0;
    inserted_ = 0;
    size_ = 0;
    capacity_ = 0;
}

bool Table::reset(uint64_t max) noexcept {
    release();
    if (max > kLargestMax) {
        max_ = 0;
        return false;
    }
    max_ = max;
    return true;
}

bool Table::make_room() noexcept {
    const util::AllocScope scope = open_scope();
    // \~english The strings never take more than the maximum: every entry costs its bytes plus 32.
    // \~spanish Las cadenas no ocupan nunca mas que el maximo: cada entrada cuesta sus bytes mas 32.  \~
    bytes_cap_ = static_cast<size_t>(max_);
    entries_cap_ = static_cast<size_t>(max_ / kEntryOverhead);
    bytes_ = static_cast<uint8_t *>(util::host_alloc(bytes_cap_));
    entries_ = static_cast<Entry *>(util::host_alloc(entries_cap_ * sizeof(Entry)));
    if (bytes_ == nullptr || entries_ == nullptr) {
        if (bytes_ != nullptr) util::host_free(bytes_);
        if (entries_ != nullptr) util::host_free(entries_);
        bytes_ = nullptr;
        entries_ = nullptr;
        bytes_cap_ = 0;
        entries_cap_ = 0;
        return false;
    }
    return true;
}

void Table::evict_oldest() noexcept {
    const Entry &e = entries_[oldest_];
    const size_t len = static_cast<size_t>(e.name_len) + e.value_len;
    bytes_head_ = (bytes_head_ + len) % bytes_cap_;
    bytes_len_ -= len;
    size_ -= len + kEntryOverhead;
    oldest_ = (oldest_ + 1) % entries_cap_;
    --count_;
    if (count_ == 0) {
        bytes_head_ = 0;
        bytes_len_ = 0;
    }
}

bool Table::set_capacity(uint64_t c) noexcept {
    if (c > max_) return false;
    capacity_ = c;
    // \~english Smaller takes effect now: both ends evict at the same instruction (3.2.2).
    // \~spanish Mas pequena surte efecto ahora: los dos extremos desalojan en la misma instruccion (3.2.2).  \~
    while (count_ != 0 && size_ > capacity_) evict_oldest();
    return true;
}

Table::Insert Table::insert(const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) noexcept {
    const uint64_t cost = static_cast<uint64_t>(nlen) + vlen + kEntryOverhead;
    if (cost > capacity_) return Insert::TooLarge;
    if (bytes_ == nullptr && !make_room()) return Insert::NoMemory;
    // \~english Evict until "size <= capacity - size of new entry" (3.2.2).  \~spanish Desalojar hasta "tamano <= capacidad - tamano de la nueva" (3.2.2).  \~
    while (count_ != 0 && size_ > capacity_ - cost) evict_oldest();
    const size_t start = (bytes_head_ + bytes_len_) % bytes_cap_;
    size_t at = start;
    const uint8_t *src[2] = {name, value};
    const size_t lens[2] = {nlen, vlen};
    for (int part = 0; part < 2; ++part) {
        size_t left = lens[part];
        const uint8_t *from = src[part];
        while (left != 0) {
            const size_t room = bytes_cap_ - at;
            const size_t n = left < room ? left : room;
            util::vesta_memcpy(bytes_ + at, from, n);
            from += n;
            left -= n;
            at = (at + n) % bytes_cap_;
        }
    }
    bytes_len_ += nlen + vlen;
    Entry &e = entries_[(oldest_ + count_) % entries_cap_];
    e.at = static_cast<uint32_t>(start);
    e.name_len = static_cast<uint32_t>(nlen);
    e.value_len = static_cast<uint32_t>(vlen);
    ++count_;
    ++inserted_;
    size_ += cost;
    return Insert::Ok;
}

const Table::Entry *Table::find(uint64_t abs) const noexcept {
    if (!has(abs)) return nullptr;
    return &entries_[(oldest_ + static_cast<size_t>(abs - dropped())) % entries_cap_];
}

uint64_t Table::cost(uint64_t abs) const noexcept {
    const Entry *e = find(abs);
    return e == nullptr ? 0 : static_cast<uint64_t>(e->name_len) + e->value_len + kEntryOverhead;
}

bool Table::copy_piece(size_t at, size_t len, Buffer &out, Span &where) const noexcept {
    where.off = static_cast<uint32_t>(out.size());
    where.len = static_cast<uint32_t>(len);
    if (len == 0) return true;
    uint8_t *dst = out.reserve(len);
    if (dst == nullptr) return false;
    // \~english A piece may straddle the end of the ring: two copies then.  \~spanish Un pedazo puede quedar a caballo del final del anillo: dos copias entonces.  \~
    const size_t first = bytes_cap_ - at < len ? bytes_cap_ - at : len;
    util::vesta_memcpy(dst, bytes_ + at, first);
    if (first != len) util::vesta_memcpy(dst + first, bytes_, len - first);
    out.commit(len);
    return true;
}

bool Table::copy_name(uint64_t abs, Buffer &out, Span &where) const noexcept {
    const Entry *e = find(abs);
    return e != nullptr && copy_piece(e->at, e->name_len, out, where);
}

bool Table::copy_value(uint64_t abs, Buffer &out, Span &where) const noexcept {
    const Entry *e = find(abs);
    return e != nullptr && copy_piece((e->at + e->name_len) % bytes_cap_, e->value_len, out, where);
}

bool Table::piece_is(size_t at, size_t len, const uint8_t *p) const noexcept {
    for (size_t i = 0; i < len; ++i)
        if (bytes_[(at + i) % bytes_cap_] != p[i]) return false;
    return true;
}

bool Table::has_name(uint64_t abs, const uint8_t *name, size_t nlen) const noexcept {
    const Entry *e = find(abs);
    return e != nullptr && e->name_len == nlen && piece_is(e->at, nlen, name);
}

bool Table::is(uint64_t abs, const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) const noexcept {
    const Entry *e = find(abs);
    return e != nullptr && e->name_len == nlen && e->value_len == vlen && piece_is(e->at, nlen, name) &&
           piece_is((e->at + nlen) % bytes_cap_, vlen, value);
}

} // namespace qpack
} // namespace http_vx
