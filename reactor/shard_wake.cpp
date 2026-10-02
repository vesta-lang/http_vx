/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard_wake.cpp
 * @brief
 * \~english The coalesced wake shared by every stack that can wake a shard.
 * \~spanish El despertar agrupado que comparten todas las pilas que pueden despertar a un fragmento.
 * \~
 */
#include "http_vx/shard_wake.h"

#include "http_vx/reactor_ops.h"

namespace http_vx {

void ShardWake::reset(Backend *io) noexcept {
    io_ = io;
    sleeping_.store(0, std::memory_order_relaxed);
    wakes_.store(0, std::memory_order_relaxed);
    failed_wakes_.store(0, std::memory_order_relaxed);
}

bool ShardWake::notify() noexcept {
    /* \~english
     * Dekker's second half: the caller's push, THEN "is it sleeping".  The
     * exchange clears the mark, so a burst of pushes while the shard is still
     * waking pays one system call and not one each.
     * \~spanish
     * La segunda mitad de Dekker: el push de quien llama, DESPUES "esta
     * durmiendo".  El intercambio limpia la marca, asi que una rafaga de pushes
     * mientras el fragmento aun despierta paga una llamada al sistema y no una
     * cada uno.
     * \~ */
    if (sleeping_.exchange(0, std::memory_order_seq_cst) != 1) return true;

    wakes_.fetch_add(1, std::memory_order_relaxed);
    if (io_ != nullptr && io_->wake()) return true;

    failed_wakes_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

WakeCounts ShardWake::counts() const noexcept {
    WakeCounts c;
    c.wakes = wakes_.load(std::memory_order_relaxed);
    c.failed_wakes = failed_wakes_.load(std::memory_order_relaxed);
    return c;
}

} // namespace http_vx
