/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/stdio_wake.cpp
 * @brief
 * \~english A stdio backend that another thread can wake: poll on the input and an eventfd.
 * \~spanish Un backend de stdio que otro hilo puede despertar: poll sobre la entrada y un eventfd.
 * \~
 *
 * \~english
 * HVX-5, 6.4.  The read waits in `poll` on two things -- the peer's stream
 * and the wake eventfd -- instead of blocking inside `read`.  A wake alone
 * ends the wait with nothing read; the stream readable reads it, even when a
 * wake arrived too, because the bytes are what the shard needs next and the
 * wake has been taken either way.
 * \~spanish
 * HVX-5, 6.4.  La lectura espera en `poll` sobre dos cosas -- el flujo del otro
 * extremo y el eventfd de despertar -- en vez de bloquearse dentro de `read`.
 * Un despertar solo acaba la espera sin leer nada; el flujo con datos se lee,
 * aunque haya llegado tambien un despertar, porque los bytes son lo siguiente
 * que necesita el fragmento y el despertar se ha recogido de todas formas.
 * \~
 */
#include "http_vx/stdio_backend.h"

#include "wake_fd.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

namespace http_vx {

StdioBackend::StdioBackend(BufferPool &pool, int in, int out) noexcept
    : pool_(&pool), in_(in), out_(out) {
    int32_t error = 0;
    wake_fd_ = wake_fd_open(true, error);
    if (wake_fd_ < 0) wake_error_.store(error, std::memory_order_relaxed);
}

StdioBackend::~StdioBackend() {
    if (wake_fd_ >= 0) ::close(wake_fd_);
}

bool StdioBackend::ready() const noexcept { return wake_fd_ >= 0; }

bool StdioBackend::wake() noexcept {
    if (wake_fd_ < 0) return false;
    int32_t error = 0;
    if (wake_fd_signal(wake_fd_, error)) return true;
    wake_error_.store(error, std::memory_order_relaxed);
    return false;
}

long StdioBackend::read_or_wake(uint8_t *room, uint32_t n, int timeout_ms, bool &woken) noexcept {
    woken = false;
    if (wake_fd_ < 0) return -1;

    pollfd fds[2];
    fds[0].fd = in_;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = wake_fd_;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    int ready = 0;
    while ((ready = ::poll(fds, 2, timeout_ms < 0 ? -1 : timeout_ms)) < 0) {
        if (errno != EINTR) return -1;
    }
    // \~english The deadline, with nothing: the read stays pending, as after a wake.
    // \~spanish El plazo, sin nada: la lectura sigue pendiente, como tras un despertar.  \~
    if (ready == 0) {
        woken = true;
        return 0;
    }

    if ((fds[1].revents & POLLIN) != 0) wake_fd_drain(wake_fd_);

    // \~english Readable, closed or broken: the read says which.
    // \~spanish Con datos, cerrado o roto: la lectura dice cual.  \~
    if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
        woken = true;
        return 0;
    }

    for (;;) {
        const ssize_t got = ::read(in_, room, n);
        if (got >= 0) return static_cast<long>(got);
        if (errno != EINTR) return -1;
    }
}

} // namespace http_vx
