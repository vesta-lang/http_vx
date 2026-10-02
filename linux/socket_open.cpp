/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/socket_open.cpp
 * @brief
 * \~english Reading a host of either family, and listening on it.
 * \~spanish Leer un anfitrion de cualquiera de las dos familias, y escuchar en el.
 * \~
 */
#include "socket_open.h"

#include "util/mem/vesta_memset.h"

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include <cstddef>

namespace http_vx {

bool socket_address(const char *host, uint16_t port, SocketAddress &out,
                    int32_t &error) noexcept {
    util::vesta_memset(&out.raw, 0, sizeof out.raw);

    sockaddr_in *v4 = reinterpret_cast<sockaddr_in *>(&out.raw);
    if (host != nullptr && inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        out.family = AF_INET;
        out.len = sizeof(sockaddr_in);
        return true;
    }
    if (host != nullptr && inet_pton(AF_INET6, host, &out.raw.sin6_addr) == 1) {
        out.raw.sin6_family = AF_INET6;
        out.raw.sin6_port = htons(port);
        out.family = AF_INET6;
        out.len = sizeof out.raw;
        return true;
    }

    /* \~english `inet_pton` says "not an address" by returning zero, with no errno.
     * \~spanish `inet_pton` dice "no es una direccion" devolviendo cero, sin errno.  \~ */
    error = EINVAL;
    return false;
}

int open_listener(const char *host, uint16_t port, int backlog, bool nonblock,
                  ListenShare share, uint16_t &bound, int32_t &error) noexcept {
    SocketAddress addr;
    if (!socket_address(host, port, addr, error)) return -1;

    const int s = ::socket(addr.family,
                           SOCK_STREAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0),
                           IPPROTO_TCP);
    if (s < 0) {
        error = errno;
        return -1;
    }

    /* \~english
     * `SO_REUSEADDR`, which on Linux means what a server wants it to mean: a
     * port whose last connection is still in `TIME_WAIT` can be bound again.
     * Without it, a server that restarts fails to start for a minute or two
     * after having worked perfectly -- which reads as a broken build.  And a
     * v6 listener is v6 ONLY, as the datagram sockets are: a dual-stack one
     * would take v4 clients as mapped addresses, one peer with two spellings.
     * \~spanish
     * `SO_REUSEADDR`, que en Linux quiere decir lo que un servidor quiere que
     * quiera decir: un puerto cuya ultima conexion siga en `TIME_WAIT` se puede
     * volver a atar.  Sin el, un servidor que se reinicia no arranca durante un
     * minuto o dos despues de haber funcionado perfectamente -- que se lee como
     * una construccion rota.  Y un socket de escucha v6 es SOLO v6, como los de
     * datagramas: uno de doble pila cogeria clientes v4 como direcciones
     * mapeadas, un extremo con dos grafias.
     * \~ */
    /* \~english
     * `SO_REUSEPORT` goes before `bind`, on EVERY socket of the group: the
     * kernel only lets sockets share an address when all of them asked for it
     * before binding, and then spreads incoming connections among them by a
     * hash of the four-tuple (HVX-6, 4.1).
     * \~spanish
     * `SO_REUSEPORT` va antes de `bind`, en CADA socket del grupo: el nucleo solo
     * deja que varios sockets compartan una direccion cuando todos lo pidieron
     * antes de atarse, y entonces reparte las conexiones entre ellos por un hash
     * de la cuadrupla (HVX-6, 4.1).
     * \~ */
    const int on = 1;
    const bool fine =
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) == 0 &&
        (share != ListenShare::SharedPort ||
         setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) == 0) &&
        (addr.family != AF_INET6 ||
         setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) == 0) &&
        bind(s, reinterpret_cast<const sockaddr *>(&addr.raw), addr.len) == 0 &&
        ::listen(s, backlog) == 0;

    SocketAddress name;
    socklen_t len = sizeof name.raw;
    if (!fine || getsockname(s, reinterpret_cast<sockaddr *>(&name.raw), &len) != 0) {
        error = errno;
        ::close(s);
        return -1;
    }

    /* \~english The port is in the same place in both families.
     * \~spanish El puerto esta en el mismo sitio en las dos familias.  \~ */
    bound = ntohs(name.raw.sin6_port);
    static_assert(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port),
                  "the port is read from the same place for both families");
    return s;
}

} // namespace http_vx
