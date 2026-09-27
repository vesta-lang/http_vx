/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/wake_fd.h
 * @brief
 * \~english The eventfd every Linux backend is woken through (private to linux/).
 * \~spanish El eventfd por el que se despierta a cada backend de Linux (privado de linux/).
 * \~
 *
 * \~english
 * One place for what epoll, io_uring and the stdio backend all need
 * (HVX-5, 6.4): a counter another thread can bump, which each backend waits
 * on in its own way.  A plain eventfd, not EFD_SEMAPHORE: one read takes
 * every signal at once.
 * \~spanish
 * Un sitio para lo que necesitan epoll, io_uring y el backend de stdio (HVX-5,
 * 6.4): un contador que otro hilo puede subir, y por el que cada backend espera
 * a su manera.  Un eventfd corriente, no EFD_SEMAPHORE: una lectura se lleva
 * todas las senales de una vez.
 * \~
 */
#ifndef HTTP_VX_LINUX_WAKE_FD_H
#define HTTP_VX_LINUX_WAKE_FD_H

#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english An eventfd, or -1 with @p error.
 * \~spanish Un eventfd, o -1 con @p error.
 * \~
 *
 * \~english
 * Blocking for io_uring, which honours O_NONBLOCK: a read of a non-blocking
 * eventfd with nothing in it completes at once with @c EAGAIN instead of
 * waiting, and the ring would never sleep.  Its write could only block with
 * the counter at 2^64 - 2.  Non-blocking for epoll and poll.
 * \~spanish
 * Bloqueante para io_uring, que respeta O_NONBLOCK: una lectura de un eventfd
 * que no bloquea sin nada dentro acaba en el acto con @c EAGAIN en vez de
 * esperar, y el anillo no dormiria nunca.  Su escritura solo podria bloquear
 * con el contador en 2^64 - 2.  Que no bloquea para epoll y poll.
 * \~
 */
int wake_fd_open(bool nonblocking, int32_t &error) noexcept;

/**
 * @brief
 * \~english Signals @p fd; any thread.
 * \~spanish Senala @p fd; cualquier hilo.
 * \~
 *
 * \~english
 * A full counter (@c EAGAIN, after 2^64 - 2 signals nobody read) is emptied
 * and the signal written again: a signal refused there would be a wake lost.
 * \~spanish
 * Un contador lleno (@c EAGAIN, tras 2^64 - 2 senales que nadie leyo) se vacia
 * y la senal se vuelve a escribir: una senal rechazada ahi seria un despertar
 * perdido.
 * \~
 *
 * @return \~english false, with @p error, if the system refused it
 *         \~spanish false, con @p error, si el sistema la rechazo  \~
 */
bool wake_fd_signal(int fd, int32_t &error) noexcept;

/// \~english Takes every signal waiting on @p fd.  \~spanish Se lleva todas las senales que esperan en @p fd.  \~
void wake_fd_drain(int fd) noexcept;

} // namespace http_vx

#endif // HTTP_VX_LINUX_WAKE_FD_H
