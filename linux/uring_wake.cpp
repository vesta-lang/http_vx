/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/uring_wake.cpp
 * @brief
 * \~english Waking an io_uring backend from another thread: a read of an eventfd, always armed in the ring.
 * \~spanish Despertar un backend de io_uring desde otro hilo: una lectura de un eventfd, siempre armada en el anillo.
 * \~
 *
 * \~english
 * HVX-5, 6.4.  `IORING_OP_MSG_RING` posts into another ring without an
 * eventfd, but a thread with no ring of its own can only use it from kernel
 * 6.13; an eventfd read works on every kernel with io_uring, and is what
 * Netty's io_uring loop does.  The eventfd is blocking on purpose
 * (wake_fd_open).
 * \~spanish
 * HVX-5, 6.4.  `IORING_OP_MSG_RING` publica en otro anillo sin eventfd, pero un
 * hilo sin anillo propio solo puede usarlo desde el nucleo 6.13; una lectura de
 * un eventfd funciona en cualquier nucleo con io_uring, y es lo que hace el
 * bucle de io_uring de Netty.  El eventfd es bloqueante a proposito
 * (wake_fd_open).
 * \~
 */
#include "uring_ring.h"
#include "wake_fd.h"

#include "util/mem/vesta_memset.h"

#include <unistd.h>

namespace http_vx {

bool UringBackend::wake_open() noexcept {
    wake_fd_ = wake_fd_open(false, last_error_);
    wake_armed_ = false;
    return wake_fd_ >= 0;
}

void UringBackend::wake_close() noexcept {
    if (wake_fd_ >= 0) ::close(wake_fd_);
    wake_fd_ = -1;
    wake_armed_ = false;
}

void UringBackend::arm_wake() noexcept {
    if (ring_ == nullptr || wake_fd_ < 0) return;

    const uint32_t tail = *ring_->sq_tail;
    const uint32_t head = ring_load_acquire(ring_->sq_head);
    // \~english No room now: armed on the next wait, before it can sleep.
    // \~spanish Sin sitio ahora: se arma en la espera siguiente, antes de que pueda dormir.  \~
    if (tail - head >= ring_->sq_entries) return;

    io_uring_sqe *sqe = &ring_->sqes[tail & ring_->sq_mask];
    util::vesta_memset(sqe, 0, sizeof *sqe);
    sqe->opcode = IORING_OP_READ;
    sqe->fd = wake_fd_;
    sqe->addr = reinterpret_cast<uint64_t>(&wake_buf_);
    sqe->len = sizeof wake_buf_;
    sqe->user_data = kWakeData;

    ring_store_release(ring_->sq_tail, tail + 1);
    ++waiting_;
    wake_armed_ = true;
}

bool UringBackend::wake() noexcept {
    const int fd = wake_fd_;
    if (fd < 0) return false;
    int32_t error = 0;
    if (wake_fd_signal(fd, error)) return true;
    wake_error_.store(error, std::memory_order_relaxed);
    return false;
}

} // namespace http_vx
