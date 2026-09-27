/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file core/id_index.cpp
 * @brief
 * \~english Open addressing with linear probing and backward-shift deletion.
 * \~spanish Direccionamiento abierto con sondeo lineal y borrado desplazando hacia atras.
 * \~
 */
#include "http_vx/id_index.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {

IdIndex::~IdIndex() { release(); }

void IdIndex::release() noexcept {
    if (table_ != nullptr) util::host_free(table_);
    table_ = nullptr;
    mask_ = 0;
    most_ = 0;
    count_ = 0;
}

bool IdIndex::reset(size_t most) noexcept {
    release();
    if (most == 0 || most > (size_t{1} << 30)) return false;

    /* \~english
     * At least twice the entries, and a power of two so that a place is a
     * mask: at a load of one half, linear probing looks at about one and a
     * half places to find what is there and two and a half to miss.
     * \~spanish
     * Al menos el doble de las entradas, y potencia de dos para que un sitio
     * sea una mascara: con carga de la mitad, el sondeo lineal mira alrededor de
     * uno y medio sitios para encontrar lo que hay y dos y medio para no
     * encontrarlo.
     * \~ */
    size_t room = 8;
    while (room < 2 * most) room *= 2;

    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);
    table_ = static_cast<Entry *>(util::host_alloc(room * sizeof(Entry)));
    if (table_ == nullptr) return false;
    for (size_t i = 0; i < room; ++i) table_[i].id = kNoId;
    mask_ = room - 1;
    most_ = most;
    return true;
}

size_t IdIndex::home(uint64_t id) const noexcept {
    // \~english Fibonacci hashing, with the high bits folded down: consecutive IDs spread apart.
    // \~spanish Hash de Fibonacci, con los bits altos plegados hacia abajo: identificadores seguidos se separan.  \~
    uint64_t h = id * 0x9E3779B97F4A7C15ull;
    h ^= h >> 29;
    return static_cast<size_t>(h) & mask_;
}

size_t IdIndex::place(uint64_t id) const noexcept {
    size_t i = home(id);
    while (table_[i].id != kNoId) {
        if (table_[i].id == id) return i;
        i = (i + 1) & mask_;
    }
    return mask_ + 1;
}

bool IdIndex::insert(uint64_t id, uint32_t slot) noexcept {
    if (id == kNoId || count_ == most_) return false;
    size_t i = home(id);
    while (table_[i].id != kNoId) i = (i + 1) & mask_;
    table_[i].id = id;
    table_[i].slot = slot;
    ++count_;
    return true;
}

uint32_t IdIndex::find(uint64_t id) const noexcept {
    if (table_ == nullptr || id == kNoId) return kAbsent;
    const size_t at = place(id);
    return at > mask_ ? kAbsent : table_[at].slot;
}

bool IdIndex::erase(uint64_t id) noexcept {
    if (table_ == nullptr || id == kNoId) return false;
    size_t i = place(id);
    if (i > mask_) return false;

    table_[i].id = kNoId;
    --count_;
    size_t j = i;
    for (;;) {
        j = (j + 1) & mask_;
        if (table_[j].id == kNoId) return true;
        const size_t k = home(table_[j].id);

        // \~english Does j's home lie cyclically outside (i, j]?  Then it may fill the hole.
        // \~spanish Esta el origen de j ciclicamente fuera de (i, j]?  Entonces puede rellenar el hueco.  \~
        const bool movable = (i <= j) ? (k <= i || k > j) : (k <= i && k > j);
        if (movable) {
            table_[i] = table_[j];
            table_[j].id = kNoId;
            i = j;
        }
    }
}

} // namespace http_vx
