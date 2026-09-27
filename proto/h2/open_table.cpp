/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/open_table.cpp
 * @brief
 * \~english The HTTP/2 table of open responses: taken, threaded per connection, and given back.
 * \~spanish La tabla HTTP/2 de respuestas abiertas: se cogen, se enhebran por conexion, y se devuelven.
 * \~
 */

#include "http_vx/h2_open.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {
namespace h2 {

OpenTable::~OpenTable() { release(); }

void OpenTable::release() noexcept {
    if (entries_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) entries_[i].~OpenStream();
        util::host_free(entries_);
        entries_ = nullptr;
    }
    capacity_ = 0;
    free_ = kNoOpen;
    in_use_ = 0;
}

bool OpenTable::reset(uint32_t n) noexcept {
    release();
    if (n == 0) return true;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    entries_ = static_cast<OpenStream *>(
        util::host_alloc(static_cast<size_t>(n) * sizeof(OpenStream)));
    if (entries_ == nullptr) return false;

    capacity_ = n;
    for (uint32_t i = 0; i < capacity_; ++i) {
        new (&entries_[i]) OpenStream();
        entries_[i].next = i + 1 == capacity_ ? kNoOpen : i + 1;
    }
    free_ = 0;
    return true;
}

uint32_t OpenTable::take(BodySource &s, uint32_t stream) noexcept {
    if (free_ == kNoOpen) return kNoOpen;

    const uint32_t i = free_;
    OpenStream &e = entries_[i];
    free_ = e.next;

    e.source = &s;
    e.stream = stream;
    e.next = kNoOpen;
    e.kicked = false;
    e.hungry = false;
    e.prefix.clear();
    ++in_use_;
    return i;
}

void OpenTable::give_back(uint32_t i) noexcept {
    OpenStream &e = entries_[i];

    /* \~english
     * The prefix's memory goes back with the entry, not merely emptied: a
     * table of a thousand quiet streams must hold no buffer (R34), and one
     * that kept the largest prefix it ever saw in every entry would.
     * \~spanish
     * La memoria del prefijo vuelve con la entrada, no se vacia sin mas: una
     * tabla de mil flujos callados no puede tener ningun buffer (R34), y una que
     * guardara en cada entrada el prefijo mas grande que vio lo tendria.
     * \~ */
    e.prefix.release();
    e.source = nullptr;
    e.stream = 0;
    e.kicked = false;
    e.hungry = false;

    e.next = free_;
    free_ = i;
    --in_use_;
}

void OpenTable::push(OpenList &list, uint32_t i) noexcept {
    entries_[i].next = kNoOpen;
    if (list.tail == kNoOpen) {
        list.head = i;
    } else {
        entries_[list.tail].next = i;
    }
    list.tail = i;
    ++list.count;
}

uint32_t OpenTable::pop(OpenList &list) noexcept {
    const uint32_t i = list.head;
    if (i == kNoOpen) return kNoOpen;

    list.head = entries_[i].next;
    if (list.head == kNoOpen) list.tail = kNoOpen;
    entries_[i].next = kNoOpen;
    --list.count;
    return i;
}

void OpenTable::unlink(OpenList &list, uint32_t i) noexcept {
    /* \~english
     * Found by walking: a connection holds at most the shard's per-connection
     * limit of open responses, and a second link per entry kept in step would
     * cost more than the walk it saves.
     * \~spanish
     * Se encuentra recorriendo: una conexion tiene como mucho el tope por
     * conexion del fragmento, y un segundo enlace por entrada que mantener de
     * acuerdo costaria mas que el recorrido que ahorra.
     * \~ */
    uint32_t before = kNoOpen;
    uint32_t at = list.head;
    while (at != kNoOpen && at != i) {
        before = at;
        at = entries_[at].next;
    }
    if (at == kNoOpen) return;

    const uint32_t after = entries_[i].next;
    if (before == kNoOpen) {
        list.head = after;
    } else {
        entries_[before].next = after;
    }
    if (list.tail == i) list.tail = before;
    entries_[i].next = kNoOpen;
    --list.count;
}

uint32_t OpenTable::find(const OpenList &list, uint32_t stream) const noexcept {
    for (uint32_t i = list.head; i != kNoOpen; i = entries_[i].next)
        if (entries_[i].stream == stream) return i;
    return kNoOpen;
}

uint32_t OpenTable::find(const OpenList &list, const BodySource *s) const noexcept {
    for (uint32_t i = list.head; i != kNoOpen; i = entries_[i].next)
        if (entries_[i].source == s) return i;
    return kNoOpen;
}

} // namespace h2
} // namespace http_vx
