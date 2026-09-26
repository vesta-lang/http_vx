/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file core/deadline_heap.cpp
 * @brief
 * \~english Deadlines by identifier, the earliest first; the rules are in deadline_heap.h.
 * \~spanish Plazos por identificador, el primero delante; las reglas estan en deadline_heap.h.
 * \~
 */
#include "http_vx/deadline_heap.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {

bool DeadlineHeap::reset(uint32_t capacity) noexcept {
    release();
    if (capacity == 0 || capacity == kOut) return false;
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    heap_ = static_cast<uint32_t *>(util::host_alloc(capacity * sizeof(uint32_t)));
    pos_ = static_cast<uint32_t *>(util::host_alloc(capacity * sizeof(uint32_t)));
    when_ = static_cast<uint64_t *>(util::host_alloc(capacity * sizeof(uint64_t)));
    if (heap_ == nullptr || pos_ == nullptr || when_ == nullptr) {
        release();
        return false;
    }
    for (uint32_t i = 0; i < capacity; ++i) {
        pos_[i] = kOut;
        when_[i] = kNever;
    }
    capacity_ = capacity;
    return true;
}

void DeadlineHeap::release() noexcept {
    if (heap_ != nullptr) util::host_free(heap_);
    if (pos_ != nullptr) util::host_free(pos_);
    if (when_ != nullptr) util::host_free(when_);
    heap_ = nullptr;
    pos_ = nullptr;
    when_ = nullptr;
    capacity_ = 0;
    count_ = 0;
}

void DeadlineHeap::set(uint32_t id, uint64_t when) noexcept {
    if (id >= capacity_) return;
    if (when == kNever) {
        remove(id);
        return;
    }
    if (pos_[id] == kOut) {
        when_[id] = when;
        place(count_, id);
        up(count_++);
        return;
    }
    const uint64_t before = when_[id];
    when_[id] = when;
    if (when < before)
        up(pos_[id]);
    else
        down(pos_[id]);
}

void DeadlineHeap::remove(uint32_t id) noexcept {
    if (id >= capacity_ || pos_[id] == kOut) return;
    const uint32_t at = pos_[id];
    pos_[id] = kOut;
    const uint32_t last = heap_[--count_];
    if (at == count_) return;
    // \~english The last one fills the hole, then goes whichever way its deadline says.
    // \~spanish El ultimo rellena el hueco, y despues va hacia donde diga su plazo.  \~
    place(at, last);
    up(at);
    down(pos_[last]);
}

void DeadlineHeap::up(uint32_t at) noexcept {
    const uint32_t id = heap_[at];
    const uint64_t w = when_[id];
    while (at != 0) {
        const uint32_t parent = (at - 1) / 2;
        if (when_[heap_[parent]] <= w) break;
        place(at, heap_[parent]);
        at = parent;
    }
    place(at, id);
}

void DeadlineHeap::down(uint32_t at) noexcept {
    const uint32_t id = heap_[at];
    const uint64_t w = when_[id];
    for (;;) {
        uint32_t child = at * 2 + 1;
        if (child >= count_) break;
        if (child + 1 < count_ && when_[heap_[child + 1]] < when_[heap_[child]]) ++child;
        if (when_[heap_[child]] >= w) break;
        place(at, heap_[child]);
        at = child;
    }
    place(at, id);
}

} // namespace http_vx
