/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/routes.cpp
 * @brief
 * \~english Connection IDs to owners; the rules are in quic_routes.h.
 * \~spanish Identificadores de conexion a duenos; las reglas estan en quic_routes.h.
 * \~
 */
#include "http_vx/quic_routes.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {
namespace quic {

namespace {

bool same_cid(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) noexcept {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

} // namespace

uint64_t CidRoutes::hash(const uint8_t *cid, size_t len, const uint64_t *key) noexcept {
    // \~english Eight bytes at a time, each mixed with the key, multiplied and folded.
    // \~spanish Ocho bytes a la vez, cada tanda mezclada con la clave, multiplicada y plegada.  \~
    uint64_t h = key[0] ^ (len * 0x9E3779B97F4A7C15ull);
    for (size_t at = 0; at < len; at += 8) {
        uint64_t word = 0;
        for (size_t i = 0; i < 8 && at + i < len; ++i) word |= uint64_t{cid[at + i]} << (8 * i);
        h = (h ^ word ^ key[1]) * 0xBF58476D1CE4E5B9ull;
        h ^= h >> 31;
    }
    h *= 0x94D049BB133111EBull;
    h ^= h >> 29;
    return h;
}

bool CidRoutes::reset(size_t capacity, const uint8_t *key) noexcept {
    release();
    // \~english At most half full, so a probe ends soon.  \~spanish Como mucho medio llena, para que un sondeo acabe pronto.  \~
    size_t n = 16;
    while (n < capacity * 2) n <<= 1;
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    entries_ = static_cast<Entry *>(util::host_alloc(n * sizeof(Entry)));
    if (entries_ == nullptr) return false;
    for (size_t i = 0; i < n; ++i) entries_[i].owner = kNone;
    mask_ = n - 1;
    capacity_ = capacity;
    for (size_t i = 0; i < 2; ++i) {
        key_[i] = 0;
        for (size_t b = 0; b < 8; ++b) key_[i] |= uint64_t{key[i * 8 + b]} << (8 * b);
    }
    return true;
}

void CidRoutes::release() noexcept {
    if (entries_ != nullptr) util::host_free(entries_);
    entries_ = nullptr;
    mask_ = 0;
    capacity_ = 0;
    count_ = 0;
}

size_t CidRoutes::slot_of(const uint8_t *cid, size_t len) const noexcept {
    size_t i = static_cast<size_t>(hash(cid, len, key_)) & mask_;
    while (entries_[i].owner != kNone && !same_cid(entries_[i].cid, entries_[i].len, cid, len)) i = (i + 1) & mask_;
    return i;
}

uint32_t CidRoutes::find(const uint8_t *cid, size_t len) const noexcept {
    if (entries_ == nullptr || len == 0 || len > kMaxConnectionId) return kNone;
    return entries_[slot_of(cid, len)].owner;
}

bool CidRoutes::add(const uint8_t *cid, size_t len, uint32_t owner) noexcept {
    if (entries_ == nullptr || len == 0 || len > kMaxConnectionId || owner == kNone) return false;
    const size_t i = slot_of(cid, len);
    if (entries_[i].owner != kNone) return entries_[i].owner == owner;
    if (count_ >= capacity_) return false;
    for (size_t b = 0; b < len; ++b) entries_[i].cid[b] = cid[b];
    entries_[i].len = static_cast<uint8_t>(len);
    entries_[i].owner = owner;
    ++count_;
    return true;
}

bool CidRoutes::remove(const uint8_t *cid, size_t len) noexcept {
    if (entries_ == nullptr || len == 0 || len > kMaxConnectionId) return false;
    size_t i = slot_of(cid, len);
    if (entries_[i].owner == kNone) return false;
    entries_[i].owner = kNone;
    --count_;
    // \~english Backward shift: the entries after the hole that probed past it move back into it.
    // \~spanish Desplazando hacia atras: las entradas de detras del hueco que pasaron por el al sondear vuelven a el.  \~
    size_t j = i;
    for (;;) {
        j = (j + 1) & mask_;
        if (entries_[j].owner == kNone) return true;
        const size_t k = static_cast<size_t>(hash(entries_[j].cid, entries_[j].len, key_)) & mask_;
        // \~english Is j's home cyclically outside (i, j]?  Then it may fill the hole.
        // \~spanish Esta el origen de j ciclicamente fuera de (i, j]?  Entonces puede rellenar el hueco.  \~
        const bool movable = (i <= j) ? (k <= i || k > j) : (k <= i && k > j);
        if (movable) {
            entries_[i] = entries_[j];
            entries_[j].owner = kNone;
            i = j;
        }
    }
}

} // namespace quic
} // namespace http_vx
