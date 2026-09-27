/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/socket_open.h
 * @brief
 * \~english An address of either family from its text, and a listening socket on it (private to linux/).
 * \~spanish Una direccion de cualquiera de las dos familias a partir de su texto, y un socket de escucha en ella (privado de linux/).
 * \~
 *
 * \~english
 * Both backends listen and both open datagram sockets, and each used to read
 * the host on its own -- as IPv4 only, for TCP, and with the error of a host
 * that does not parse taken from an `errno` that `inet_pton` never sets.
 * Once, here: v4 or v6, and a host that is neither is `EINVAL`.
 * \~spanish
 * Los dos backends escuchan y los dos abren sockets de datagramas, y cada uno
 * leia el anfitrion por su cuenta -- solo como IPv4, para TCP, y con el error de
 * un anfitrion que no se entiende sacado de un `errno` que `inet_pton` no pone
 * nunca.  Una vez, aqui: v4 o v6, y un anfitrion que no es ninguno es `EINVAL`.
 * \~
 */
#ifndef HTTP_VX_LINUX_SOCKET_OPEN_H
#define HTTP_VX_LINUX_SOCKET_OPEN_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english The socket address @p host and @p port name, in room for either family.
 * \~spanish La direccion de socket que nombran @p host y @p port, en sitio para cualquier familia.
 * \~
 */
struct SocketAddress {
    sockaddr_in6 raw;
    socklen_t len = 0;
    int family = AF_INET;
};

/**
 * @brief
 * \~english Reads @p host as an IPv4 or IPv6 literal.
 * \~spanish Lee @p host como un literal IPv4 o IPv6.
 * \~
 *
 * @return \~english false, with @p error @c EINVAL, if it is neither
 *         \~spanish false, con @p error @c EINVAL, si no es ninguno  \~
 */
bool socket_address(const char *host, uint16_t port, SocketAddress &out,
                    int32_t &error) noexcept;

/**
 * @brief
 * \~english A TCP socket listening on @p host and @p port.
 * \~spanish Un socket TCP escuchando en @p host y @p port.
 * \~
 *
 * @param nonblock \~english whether it must not block (epoll) or may (io_uring)
 *                 \~spanish si no debe bloquear (epoll) o puede (io_uring)  \~
 * @param bound    \~english the port it got  \~spanish el puerto que le toco  \~
 * @param error    \~english the system's error when it fails  \~spanish el error del sistema cuando falla  \~
 * @return         \~english the socket, or -1  \~spanish el socket, o -1  \~
 */
int open_listener(const char *host, uint16_t port, int backlog, bool nonblock,
                  uint16_t &bound, int32_t &error) noexcept;

} // namespace http_vx

#endif // HTTP_VX_LINUX_SOCKET_OPEN_H
