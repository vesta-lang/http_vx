/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/wake_fd.cpp
 * @brief
 * \~english Opening, signalling and emptying the wake eventfd.
 * \~spanish Abrir, senalar y vaciar el eventfd de despertar.
 * \~
 */
#include "wake_fd.h"

#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace http_vx {

int wake_fd_open(bool nonblocking, int32_t &error) noexcept {
    const int fd = eventfd(0, EFD_CLOEXEC | (nonblocking ? EFD_NONBLOCK : 0));
    if (fd < 0) error = errno;
    return fd;
}

bool wake_fd_signal(int fd, int32_t &error) noexcept {
    const uint64_t one = 1;
    for (;;) {
        if (::write(fd, &one, sizeof one) == static_cast<ssize_t>(sizeof one)) return true;
        if (errno == EINTR) continue;
        if (errno == EAGAIN) {
            wake_fd_drain(fd);
            continue;
        }
        error = errno;
        return false;
    }
}

void wake_fd_drain(int fd) noexcept {
    uint64_t value = 0;
    while (::read(fd, &value, sizeof value) < 0 && errno == EINTR) {
    }
}

} // namespace http_vx
