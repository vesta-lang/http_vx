/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/events.cpp
 * @brief
 * \~english The event streams and the thread that feeds them.
 * \~spanish Los flujos de eventos y el hilo que los alimenta.
 * \~
 */

#include "serve/events.h"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace serve {

size_t EventStream::fill(http_vx::OpenResponse, uint8_t *dst, size_t room, bool &done) noexcept {
    done = false;
    const std::lock_guard<std::mutex> hold(lock_);
    const size_t n = len_ < room ? len_ : room;
    std::memcpy(dst, pending_, n);
    std::memmove(pending_, pending_ + n, len_ - n);
    len_ -= n;
    return n;
}

void EventStream::gone(http_vx::OpenResponse, http_vx::GoneReason) noexcept {
    {
        const std::lock_guard<std::mutex> hold(lock_);
        live_ = false;
        len_ = 0;
    }
    // \~english Free only after live is down: nothing kicks it any more.
    // \~spanish Libre solo despues de bajar live: ya no lo avisa nadie.  \~
    used_.store(false, std::memory_order_release);
}

bool EventStream::claim() noexcept {
    bool free = false;
    return used_.compare_exchange_strong(free, true, std::memory_order_acq_rel);
}

void EventStream::opened(bool ok) noexcept {
    if (!ok) {
        used_.store(false, std::memory_order_release);
        return;
    }
    const std::lock_guard<std::mutex> hold(lock_);
    live_ = true;
    len_ = 0;
}

void EventStream::tick(uint64_t n) noexcept {
    const std::lock_guard<std::mutex> hold(lock_);
    if (!live_) return;

    char line[64];
    const int len = std::snprintf(line, sizeof line, "data: tick %llu\n\n", static_cast<unsigned long long>(n));
    if (len <= 0 || len_ + static_cast<size_t>(len) > sizeof pending_) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
    } else {
        std::memcpy(pending_ + len_, line, static_cast<size_t>(len));
        len_ += static_cast<size_t>(len);
    }

    // \~english Under the lock gone takes: never after it (HVX-5, 4.4).
    // \~spanish Bajo el cerrojo que toma gone: nunca despues de el (HVX-5, 4.4).  \~
    kick();
}

Events::~Events() { stop(); }

bool Events::start() noexcept {
    stopping_.store(false, std::memory_order_relaxed);
    thread_ = std::thread(run, this);
    return thread_.joinable();
}

void Events::stop() noexcept {
    stopping_.store(true, std::memory_order_relaxed);
    if (thread_.joinable()) thread_.join();
}

void Events::answer(http_vx::ResponseBuilder &res) noexcept {
    static const char kType[] = "text/event-stream";
    static const char kNoCache[] = "no-cache";

    EventStream *s = nullptr;
    for (size_t i = 0; i < kStreams && s == nullptr; ++i)
        if (streams_[i].claim()) s = &streams_[i];

    if (s == nullptr) {
        static const char kFull[] = "every event stream is taken\n";
        res.status(503);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body(kFull, sizeof kFull - 1);
        return;
    }

    res.status(200);
    res.field(http_vx::FieldId::ContentType, kType, sizeof kType - 1);
    res.field(http_vx::FieldId::CacheControl, kNoCache, sizeof kNoCache - 1);
    static const char kHello[] = ": open\n\n";
    res.body(kHello, sizeof kHello - 1);
    s->opened(res.open(*s).valid());
}

uint64_t Events::dropped() const noexcept {
    uint64_t n = 0;
    for (size_t i = 0; i < kStreams; ++i) n += streams_[i].dropped();
    return n;
}

void Events::run(Events *self) noexcept {
    uint64_t n = 0;
    while (!self->stopping_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++n;
        for (size_t i = 0; i < kStreams; ++i) self->streams_[i].tick(n);
    }
}

} // namespace serve
