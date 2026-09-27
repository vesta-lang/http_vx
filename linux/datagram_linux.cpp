/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/datagram_linux.cpp
 * @brief
 * \~english A UDP socket and its messages, as both Linux backends build and read them.
 * \~spanish Un socket UDP y sus mensajes, como los construyen y leen los dos backends de Linux.
 * \~
 */

#include "datagram_linux.h"
#include "socket_open.h"

#include "http_vx/reactor_ops.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

namespace http_vx {
namespace udp {

namespace {

/**
 * @brief
 * \~english A socket address in the canonical form @c NetAddress promises.
 * \~spanish Una direccion de socket en la forma canonica que promete @c NetAddress.
 * \~
 *
 * \~english
 * Linux already leaves the v4 padding and the v6 flow label at zero on what
 * it returns; they are cleared anyway, because the promise is this file's and
 * not the kernel's.
 * \~spanish
 * Linux ya deja a cero el relleno de la v4 y la etiqueta de flujo de la v6 en
 * lo que devuelve; se limpian igual, porque la promesa es de este fichero y no
 * del nucleo.
 * \~
 */
void canonical(const sockaddr_in6 &raw, NetAddress &out) noexcept {
    out.len = 0;

    if (raw.sin6_family == AF_INET) {
        sockaddr_in v4;
        util::vesta_memcpy(&v4, &raw, sizeof v4);
        util::vesta_memset(v4.sin_zero, 0, sizeof v4.sin_zero);
        util::vesta_memcpy(out.bytes, &v4, sizeof v4);
        out.len = sizeof v4;
    } else if (raw.sin6_family == AF_INET6) {
        sockaddr_in6 v6 = raw;
        v6.sin6_flowinfo = 0;
        util::vesta_memcpy(out.bytes, &v6, sizeof v6);
        out.len = sizeof v6;
    }
}

/// \~english Whether @p a is a link-local v6 address, fe80::/10.
/// \~spanish Si @p a es una direccion v6 de enlace local, fe80::/10.  \~
bool link_local(const in6_addr &a) noexcept {
    return a.s6_addr[0] == 0xFE && (a.s6_addr[1] & 0xC0) == 0x80;
}

} // namespace

int open_socket(const char *host, uint16_t port, bool nonblock,
                NetAddress &bound, int32_t &error) noexcept {
    bound.len = 0;

    SocketAddress where;
    if (!socket_address(host, port, where, error)) return -1;
    const int family = where.family;

    const int s = ::socket(family,
                           SOCK_DGRAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0),
                           IPPROTO_UDP);
    if (s < 0) {
        error = errno;
        return -1;
    }

    /* \~english
     * A v6 socket is v6 ONLY (ipv6(7), IPV6_V6ONLY): a dual-stack one would
     * hand up v4 peers as mapped v6 addresses, one peer with two spellings.
     * Then packet information, so each datagram says where it was sent
     * (ip(7) IP_PKTINFO, ipv6(7) IPV6_RECVPKTINFO), and the traffic class, so
     * it says its ECN mark (ip(7) IP_RECVTOS; IPV6_RECVTCLASS).  Any of them
     * refused ends the open: a socket that half works looks like one that
     * works.
     * \~spanish
     * Un socket v6 es SOLO v6 (ipv6(7), IPV6_V6ONLY): uno de doble pila
     * entregaria los extremos v4 como v6 mapeadas, un extremo con dos grafias.
     * Despues la informacion del paquete, para que cada datagrama diga a donde se
     * mando (ip(7) IP_PKTINFO, ipv6(7) IPV6_RECVPKTINFO), y la clase de trafico,
     * para que diga su marca ECN (ip(7) IP_RECVTOS; IPV6_RECVTCLASS).  Que se
     * rechace cualquiera acaba la apertura: un socket que funciona a medias
     * parece uno que funciona.
     * \~ */
    const int on = 1;
    const bool v6 = family == AF_INET6;
    const bool fine =
        (!v6 || setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) == 0) &&
        bind(s, reinterpret_cast<const sockaddr *>(&where.raw), where.len) == 0 &&
        setsockopt(s, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   v6 ? IPV6_RECVPKTINFO : IP_PKTINFO, &on, sizeof on) == 0 &&
        setsockopt(s, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   v6 ? IPV6_RECVTCLASS : IP_RECVTOS, &on, sizeof on) == 0;

    sockaddr_in6 name;
    util::vesta_memset(&name, 0, sizeof name);
    socklen_t name_len = sizeof name;

    if (!fine ||
        getsockname(s, reinterpret_cast<sockaddr *>(&name), &name_len) != 0) {
        error = errno;
        ::close(s);
        return -1;
    }

    canonical(name, bound);
    return s;
}

void aim_receive(msghdr &m, MsgRoom &r, uint8_t *room, size_t n) noexcept {
    util::vesta_memset(&r.name, 0, sizeof r.name);
    r.iov.iov_base = room;
    r.iov.iov_len = n;

    util::vesta_memset(&m, 0, sizeof m);
    m.msg_name = &r.name;
    m.msg_namelen = sizeof r.name;
    m.msg_iov = &r.iov;
    m.msg_iovlen = 1;
    m.msg_control = r.control.bytes;
    m.msg_controllen = sizeof r.control.bytes;
}

bool aim_send(msghdr &m, MsgRoom &r, Buffer &b, uint32_t len,
              uint8_t family_len) noexcept {
    DatagramHeader h;
    if (!datagram_header(b, h) || datagram_size(b) != len ||
        h.path.peer.len != family_len)
        return false;

    /* \~english
     * The whole room is copied and the length says how much counts, so no
     * copy is sized by a byte somebody else wrote.
     * \~spanish
     * Se copia todo el sitio y la longitud dice cuanto cuenta, asi que ninguna
     * copia la mide un byte que escribio otro.
     * \~ */
    static_assert(sizeof r.name == kMaxNetAddress,
                  "a v6 socket address is the largest a NetAddress holds");
    util::vesta_memcpy(&r.name, h.path.peer.bytes, sizeof r.name);

    r.iov.iov_base = const_cast<uint8_t *>(datagram_payload(b));
    r.iov.iov_len = len;

    util::vesta_memset(&m, 0, sizeof m);
    m.msg_name = &r.name;
    m.msg_namelen = h.path.peer.len;
    m.msg_iov = &r.iov;
    m.msg_iovlen = 1;

    if ((h.flags & kDatagramLocalKnown) == 0 || h.path.local.len != family_len)
        return true;

    /* \~english
     * The source, as packet information (ip(7): a non-zero ipi_spec_dst "is
     * used as the local source address"; ipv6(7) and RFC 3542, 6.1 for
     * in6_pktinfo).  The interface is left to the routing table except for a
     * link-local v6 source, which means nothing without it.
     * \~spanish
     * El origen, como informacion del paquete (ip(7): un ipi_spec_dst distinto
     * de cero "se usa como direccion local de origen"; ipv6(7) y RFC 3542, 6.1
     * para in6_pktinfo).  La interfaz se deja a la tabla de rutas salvo para un
     * origen v6 de enlace local, que no significa nada sin ella.
     * \~ */
    util::vesta_memset(r.control.bytes, 0, sizeof r.control.bytes);
    m.msg_control = r.control.bytes;
    m.msg_controllen = sizeof r.control.bytes;
    cmsghdr *c = CMSG_FIRSTHDR(&m);

    if (family_len == sizeof(sockaddr_in)) {
        sockaddr_in v4;
        util::vesta_memcpy(&v4, h.path.local.bytes, sizeof v4);

        in_pktinfo pi;
        util::vesta_memset(&pi, 0, sizeof pi);
        pi.ipi_spec_dst = v4.sin_addr;

        c->cmsg_level = IPPROTO_IP;
        c->cmsg_type = IP_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof pi);
        util::vesta_memcpy(CMSG_DATA(c), &pi, sizeof pi);
        m.msg_controllen = CMSG_SPACE(sizeof pi);
        return true;
    }

    sockaddr_in6 v6;
    util::vesta_memcpy(&v6, h.path.local.bytes, sizeof v6);

    in6_pktinfo pi;
    util::vesta_memset(&pi, 0, sizeof pi);
    pi.ipi6_addr = v6.sin6_addr;
    pi.ipi6_ifindex = link_local(v6.sin6_addr) ? v6.sin6_scope_id : 0;

    c->cmsg_level = IPPROTO_IPV6;
    c->cmsg_type = IPV6_PKTINFO;
    c->cmsg_len = CMSG_LEN(sizeof pi);
    util::vesta_memcpy(CMSG_DATA(c), &pi, sizeof pi);
    m.msg_controllen = CMSG_SPACE(sizeof pi);
    return true;
}

int32_t finish_receive(const msghdr &m, size_t got, size_t room,
                       const NetAddress &bound, Buffer &b,
                       DatagramCounts &c) noexcept {
    /* \~english
     * Cut, by either sign the kernel gives: the flag (recvmsg(2), MSG_TRUNC
     * in msg_flags) or, with MSG_TRUNC asked for, a length larger than the
     * room.  The bytes that did land are not committed, so nothing in the
     * buffer can be read as the datagram.
     * \~spanish
     * Cortado, por cualquiera de las dos senales que da el nucleo: el indicador
     * (recvmsg(2), MSG_TRUNC en msg_flags) o, pedido MSG_TRUNC, una longitud
     * mayor que el sitio.  Los bytes que si cayeron no se confirman, asi que no
     * queda nada en el buffer que se pueda leer como el datagrama.
     * \~ */
    if ((m.msg_flags & MSG_TRUNC) != 0 || got > room) {
        ++c.truncated;
        return kTruncated;
    }

    if ((m.msg_flags & MSG_CTRUNC) != 0) ++c.control_truncated;

    DatagramHeader h;
    canonical(*static_cast<const sockaddr_in6 *>(m.msg_name), h.path.peer);

    for (const cmsghdr *at = CMSG_FIRSTHDR(&m); at != nullptr;
         at = CMSG_NXTHDR(const_cast<msghdr *>(&m), const_cast<cmsghdr *>(at))) {
        const uint8_t *data = CMSG_DATA(at);

        if (at->cmsg_level == IPPROTO_IP && at->cmsg_type == IP_PKTINFO &&
            bound.len == sizeof(sockaddr_in)) {
            /* \~english
             * ipi_addr, "the destination address in the packet header" (ip(7)):
             * the address the peer wrote to.  ipi_spec_dst is the routing
             * table's idea of the local address, which differs for a
             * broadcast.
             * \~spanish
             * ipi_addr, "la direccion de destino de la cabecera del paquete"
             * (ip(7)): la direccion a la que escribio el otro extremo.
             * ipi_spec_dst es la idea de la tabla de rutas de la direccion local,
             * que difiere para una difusion.
             * \~ */
            in_pktinfo pi;
            util::vesta_memcpy(&pi, data, sizeof pi);

            sockaddr_in v4;
            util::vesta_memcpy(&v4, bound.bytes, sizeof v4);
            v4.sin_addr = pi.ipi_addr;
            util::vesta_memcpy(h.path.local.bytes, &v4, sizeof v4);
            h.path.local.len = sizeof v4;
            h.flags |= kDatagramLocalKnown;
        } else if (at->cmsg_level == IPPROTO_IPV6 &&
                   at->cmsg_type == IPV6_PKTINFO &&
                   bound.len == sizeof(sockaddr_in6)) {
            in6_pktinfo pi;
            util::vesta_memcpy(&pi, data, sizeof pi);

            sockaddr_in6 v6;
            util::vesta_memcpy(&v6, bound.bytes, sizeof v6);
            v6.sin6_addr = pi.ipi6_addr;
            v6.sin6_flowinfo = 0;
            v6.sin6_scope_id = link_local(pi.ipi6_addr) ? pi.ipi6_ifindex : 0;
            util::vesta_memcpy(h.path.local.bytes, &v6, sizeof v6);
            h.path.local.len = sizeof v6;
            h.flags |= kDatagramLocalKnown;
        } else if (at->cmsg_level == IPPROTO_IP && at->cmsg_type == IP_TOS) {
            /* \~english One byte, the TOS field (ip(7), IP_RECVTOS).
             * \~spanish Un byte, el campo TOS (ip(7), IP_RECVTOS).  \~ */
            h.ecn = ecn_from_tos(*data);
            h.flags |= kDatagramEcnKnown;
        } else if (at->cmsg_level == IPPROTO_IPV6 &&
                   at->cmsg_type == IPV6_TCLASS) {
            /* \~english An int, the traffic class (RFC 3542, 6.5).
             * \~spanish Un int, la clase de trafico (RFC 3542, 6.5).  \~ */
            int tclass = 0;
            util::vesta_memcpy(&tclass, data, sizeof tclass);
            h.ecn = ecn_from_tos(static_cast<uint8_t>(tclass));
            h.flags |= kDatagramEcnKnown;
        }
    }

    datagram_commit(b, h, got);
    ++c.received;
    return static_cast<int32_t>(got);
}

} // namespace udp
} // namespace http_vx
