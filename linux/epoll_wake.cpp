/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/epoll_wake.cpp
 * @brief
 * \~english Waking an epoll backend from another thread: an eventfd on its queue, edge-triggered.
 * \~spanish Despertar un backend de epoll desde otro hilo: un eventfd en su cola, por flanco.
 * \~
 *
 * \~english
 * Edge-triggered and never read on a wake (HVX-5, 6.4): every write fires
 * the edge again, so nothing has to be read to re-arm it -- the choice of
 * libuv, Netty and nginx.  Level-triggered it would have to be read on every
 * wake, or epoll would hand it back for ever: one more system call each time.
 * The counter is only emptied when it would overflow (wake_fd_signal).
 * \~spanish
 * Por flanco y sin leerlo en cada despertar (HVX-5, 6.4): cada escritura vuelve
 * a disparar el flanco, asi que no hay que leer nada para rearmarlo -- lo que
 * eligen libuv, Netty y nginx.  Por nivel habria que leerlo en cada despertar,
 * o epoll lo devolveria para siempre: una llamada al sistema mas cada vez.  El
 * contador solo se vacia cuando fuera a desbordarse (wake_fd_signal).
 * \~
 */
#include "http_vx/epoll_backend.h"

#include "wake_fd.h"

#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

namespace http_vx {

bool EpollBackend::wake_open() noexcept {
    wake_fd_ = wake_fd_open(true, last_error_);
    if (wake_fd_ < 0) return false;

    epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 0;
    ev.data.fd = wake_fd_;
    if (epoll_ctl(queue_, EPOLL_CTL_ADD, wake_fd_, &ev) != 0) {
        last_error_ = errno;
        wake_close();
        return false;
    }
    return true;
}

void EpollBackend::wake_close() noexcept {
    if (wake_fd_ >= 0) ::close(wake_fd_);
    wake_fd_ = -1;
}

bool EpollBackend::wake() noexcept {
    const int fd = wake_fd_;
    if (fd < 0) return false;
    int32_t error = 0;
    if (wake_fd_signal(fd, error)) return true;
    wake_error_.store(error, std::memory_order_relaxed);
    return false;
}

} // namespace http_vx
