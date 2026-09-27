/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_datagram.cpp
 * @brief
 * \~english Datagrams on a completion port: one call each way, completions in batches.
 * \~spanish Datagramas sobre un puerto de finalizacion: una llamada por sentido, finalizaciones por lotes.
 * \~
 *
 * \~english
 * What Windows offers, said plainly, because R26 asks for batches and this is
 * where the answer is partly no:
 *
 *  - receiving is `WSARecvMsg`, one datagram per call, posted ahead of time;
 *    it is the call that also gives the local address (`IP_PKTINFO`,
 *    `IPV6_PKTINFO`).  Several are kept posted per socket, so datagrams
 *    arriving together complete together and are TAKEN in one batch by
 *    `GetQueuedCompletionStatusEx` -- but each was posted by its own call;
 *  - sending is `WSASendMsg`, one datagram per call, with the source address
 *    in the control data.  Windows has no call that sends several datagrams
 *    to several peers; what it has (send coalescing with `UDP_SEND_MSG_SIZE`,
 *    registered I/O) is not in this toolchain's headers and not used;
 *  - the ECN bits are not read: the socket options that deliver them are not
 *    in this toolchain's headers either, so every datagram says ECN is not
 *    known, and RFC 9000, 13.4.1 says what a transport does then.
 *
 * Relied on: Microsoft's pages for `LPFN_WSARECVMSG` (a datagram larger than
 * the buffers completes with `WSAEMSGSIZE` and the excess is lost; the output
 * flags carry `MSG_TRUNC` and `MSG_CTRUNC`; `WSAECONNRESET` on a receive is a
 * previous send's ICMP Port Unreachable) and for the socket IOCTLs
 * (`SIO_UDP_CONNRESET`).
 *
 * \~spanish
 * Lo que ofrece Windows, dicho claro, porque la R26 pide lotes y aqui es donde
 * la respuesta es en parte que no:
 *
 *  - recibir es `WSARecvMsg`, un datagrama por llamada, puesto de antemano; es
 *    la llamada que ademas da la direccion local (`IP_PKTINFO`,
 *    `IPV6_PKTINFO`).  Se tienen varias puestas por socket, asi que los
 *    datagramas que llegan juntos acaban juntos y se RECOGEN en un lote con
 *    `GetQueuedCompletionStatusEx` -- pero cada una se puso con su llamada;
 *  - mandar es `WSASendMsg`, un datagrama por llamada, con la direccion de
 *    origen en los datos de control.  Windows no tiene una llamada que mande
 *    varios datagramas a varios extremos; lo que tiene (agrupar envios con
 *    `UDP_SEND_MSG_SIZE`, E/S registrada) no esta en las cabeceras de este
 *    compilador y no se usa;
 *  - los bits ECN no se leen: las opciones de socket que los entregan tampoco
 *    estan en las cabeceras de este compilador, asi que cada datagrama dice que
 *    no se sabe su ECN, y el RFC 9000, 13.4.1 dice que hace un transporte
 *    entonces.
 *
 * En que se apoya: las paginas de Microsoft de `LPFN_WSARECVMSG` (un datagrama
 * mayor que los buffers acaba con `WSAEMSGSIZE` y lo que sobra se pierde; los
 * indicadores de salida llevan `MSG_TRUNC` y `MSG_CTRUNC`; un `WSAECONNRESET`
 * en una recepcion es el ICMP Port Unreachable de un envio anterior) y de los
 * IOCTL de socket (`SIO_UDP_CONNRESET`).
 * \~
 */

#include "iocp_context.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

/* \~english
 * `SIO_UDP_CONNRESET` is documented by Microsoft but missing from this
 * toolchain's `mstcpip.h`.  The value is Microsoft's own definition,
 * `_WSAIOW(IOC_VENDOR, 12)`; a wrong one would be refused by `WSAIoctl`, which
 * is checked, so it cannot fail quietly.
 * \~spanish
 * `SIO_UDP_CONNRESET` lo documenta Microsoft pero falta en el `mstcpip.h` de
 * este compilador.  El valor es la definicion de Microsoft,
 * `_WSAIOW(IOC_VENDOR, 12)`; uno equivocado lo rechazaria `WSAIoctl`, que se
 * comprueba, asi que no puede fallar en silencio.
 * \~ */
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace http_vx {

namespace {

/**
 * @brief
 * \~english A socket address in the canonical form @c NetAddress promises.
 * \~spanish Una direccion de socket en la forma canonica que promete @c NetAddress.
 * \~
 *
 * \~english
 * The v4 padding and the v6 flow label are zeroed, so that the same peer is
 * the same bytes whichever datagram it came in.
 * \~spanish
 * Se ponen a cero el relleno de la v4 y la etiqueta de flujo de la v6, para que
 * el mismo extremo sean los mismos bytes venga en el datagrama que venga.
 * \~
 */
void canonical(const void *raw, NetAddress &out) noexcept {
    ADDRESS_FAMILY family;
    util::vesta_memcpy(&family, raw, sizeof family);

    out.len = 0;

    if (family == AF_INET) {
        sockaddr_in v4;
        util::vesta_memcpy(&v4, raw, sizeof v4);
        util::vesta_memset(v4.sin_zero, 0, sizeof v4.sin_zero);
        util::vesta_memcpy(out.bytes, &v4, sizeof v4);
        out.len = sizeof v4;
    } else if (family == AF_INET6) {
        sockaddr_in6 v6;
        util::vesta_memcpy(&v6, raw, sizeof v6);
        v6.sin6_flowinfo = 0;
        util::vesta_memcpy(out.bytes, &v6, sizeof v6);
        out.len = sizeof v6;
    }
}

/**
 * @brief
 * \~english The local address a datagram was sent to, from its packet information.
 * \~spanish La direccion local a la que se mando un datagrama, de la informacion del paquete.
 * \~
 *
 * \~english
 * The address comes from the packet and the port from the socket, which is
 * the only one it can have been sent to.  The scope is kept only for a
 * link-local v6 address, the one kind that means nothing without it.
 * \~spanish
 * La direccion sale del paquete y el puerto del socket, que es el unico al que
 * se ha podido mandar.  El ambito se guarda solo para una v6 de enlace local,
 * la unica clase que no significa nada sin el.
 * \~
 */
bool local_from(const WSAMSG &msg, const NetAddress &bound,
                NetAddress &out) noexcept {
    const uint8_t *at = reinterpret_cast<const uint8_t *>(msg.Control.buf);
    size_t left = msg.Control.len;

    while (left >= sizeof(WSACMSGHDR)) {
        WSACMSGHDR h;
        util::vesta_memcpy(&h, at, sizeof h);
        if (h.cmsg_len < sizeof h || h.cmsg_len > left) return false;

        const uint8_t *data = at + WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR));

        if (h.cmsg_level == IPPROTO_IP && h.cmsg_type == IP_PKTINFO &&
            bound.len == sizeof(sockaddr_in)) {
            IN_PKTINFO pi;
            util::vesta_memcpy(&pi, data, sizeof pi);

            sockaddr_in v4;
            util::vesta_memcpy(&v4, bound.bytes, sizeof v4);
            v4.sin_addr = pi.ipi_addr;
            util::vesta_memcpy(out.bytes, &v4, sizeof v4);
            out.len = sizeof v4;
            return true;
        }

        if (h.cmsg_level == IPPROTO_IPV6 && h.cmsg_type == IPV6_PKTINFO &&
            bound.len == sizeof(sockaddr_in6)) {
            IN6_PKTINFO pi;
            util::vesta_memcpy(&pi, data, sizeof pi);

            sockaddr_in6 v6;
            util::vesta_memcpy(&v6, bound.bytes, sizeof v6);
            v6.sin6_addr = pi.ipi6_addr;
            v6.sin6_flowinfo = 0;
            const bool link_local = pi.ipi6_addr.s6_addr[0] == 0xFE &&
                                    (pi.ipi6_addr.s6_addr[1] & 0xC0) == 0x80;
            v6.sin6_scope_id = link_local ? pi.ipi6_ifindex : 0;
            util::vesta_memcpy(out.bytes, &v6, sizeof v6);
            out.len = sizeof v6;
            return true;
        }

        const size_t step = WSA_CMSGHDR_ALIGN(h.cmsg_len);
        if (step == 0 || step > left) return false;
        at += step;
        left -= step;
    }

    return false;
}

/**
 * @brief
 * \~english Writes the packet information that makes a datagram leave from @p local.
 * \~spanish Escribe la informacion del paquete que hace que un datagrama salga desde @p local.
 * \~
 *
 * @return \~english how many control bytes were written
 *         \~spanish cuantos bytes de control se escribieron  \~
 */
size_t source_control(const NetAddress &local, uint8_t *control) noexcept {
    WSACMSGHDR h;
    util::vesta_memset(&h, 0, sizeof h);
    uint8_t *data = control + WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR));

    if (local.len == sizeof(sockaddr_in)) {
        sockaddr_in v4;
        util::vesta_memcpy(&v4, local.bytes, sizeof v4);

        IN_PKTINFO pi;
        util::vesta_memset(&pi, 0, sizeof pi);
        pi.ipi_addr = v4.sin_addr;

        h.cmsg_len = WSA_CMSG_LEN(sizeof pi);
        h.cmsg_level = IPPROTO_IP;
        h.cmsg_type = IP_PKTINFO;
        util::vesta_memcpy(control, &h, sizeof h);
        util::vesta_memcpy(data, &pi, sizeof pi);
        return WSA_CMSG_SPACE(sizeof pi);
    }

    sockaddr_in6 v6;
    util::vesta_memcpy(&v6, local.bytes, sizeof v6);

    IN6_PKTINFO pi;
    util::vesta_memset(&pi, 0, sizeof pi);
    pi.ipi6_addr = v6.sin6_addr;
    pi.ipi6_ifindex = v6.sin6_scope_id;

    h.cmsg_len = WSA_CMSG_LEN(sizeof pi);
    h.cmsg_level = IPPROTO_IPV6;
    h.cmsg_type = IPV6_PKTINFO;
    util::vesta_memcpy(control, &h, sizeof h);
    util::vesta_memcpy(data, &pi, sizeof pi);
    return WSA_CMSG_SPACE(sizeof pi);
}

} // namespace

void IocpBackend::close_datagrams() noexcept {
    for (size_t i = 0; i < dgram_.count(); ++i)
        closesocket(as_socket(dgram_.fd(i)));
    dgram_.clear();
}

int32_t IocpBackend::open_datagram(const char *host, uint16_t port,
                                   NetAddress &bound) noexcept {
    bound.len = 0;
    if (iocp_ == nullptr || host == nullptr) return -1;

    WinAddress where;
    if (!win_address(host, port, where)) {
        last_error_ = WSAEINVAL;
        return -1;
    }
    const int family = where.family;

    const SOCKET s = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                                WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        return -1;
    }

    const DWORD on = 1;
    const DWORD off = 0;
    DWORD got = 0;

    /* \~english
     * Each step that can fail is checked and ends the open: a socket without
     * packet information would deliver datagrams with no local address, and
     * one still reporting old ICMP errors would fail receives at random -- a
     * socket that half works is worse than none, because it looks like one.
     * \~spanish
     * Cada paso que puede fallar se comprueba y acaba la apertura: un socket sin
     * informacion del paquete entregaria datagramas sin direccion local, y uno
     * que siguiera contando errores ICMP viejos haria fallar recepciones al azar
     * -- un socket que funciona a medias es peor que ninguno, porque lo parece.
     * \~ */
    const bool v6 = family == AF_INET6;
    const bool fine =
        (!v6 || setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                           reinterpret_cast<const char *>(&on), sizeof on) == 0) &&
        bind(s, reinterpret_cast<const sockaddr *>(&where.raw), where.len) == 0 &&
        setsockopt(s, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   v6 ? IPV6_PKTINFO : IP_PKTINFO,
                   reinterpret_cast<const char *>(&on), sizeof on) == 0 &&
        WSAIoctl(s, SIO_UDP_CONNRESET, const_cast<DWORD *>(&off), sizeof off,
                 nullptr, 0, &got, nullptr, nullptr) == 0;

    if (!fine) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return -1;
    }

    if (recvmsg_fn_ == nullptr) {
        GUID id = WSAID_WSARECVMSG;
        LPFN_WSARECVMSG fn = nullptr;

        if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fn,
                     sizeof fn, &got, nullptr, nullptr) == SOCKET_ERROR) {
            last_error_ = WSAGetLastError();
            closesocket(s);
            return -1;
        }
        recvmsg_fn_ = reinterpret_cast<void *>(fn);
    }

    if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(s),
                               static_cast<HANDLE>(iocp_), 0, 0) == nullptr) {
        last_error_ = static_cast<int32_t>(GetLastError());
        closesocket(s);
        return -1;
    }

    sockaddr_in6 name;
    util::vesta_memset(&name, 0, sizeof name);
    int name_len = sizeof name;
    if (getsockname(s, reinterpret_cast<sockaddr *>(&name), &name_len) != 0) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return -1;
    }
    canonical(&name, bound);

    if (!dgram_.add(as_fd(s), bound)) {
        last_error_ = WSAEMFILE;
        bound.len = 0;
        closesocket(s);
        return -1;
    }

    return as_fd(s);
}

bool IocpBackend::start_recv_from(const Op &op, Context *c) noexcept {
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);

    /* \~english
     * Only on a socket this backend opened for datagrams.  On any other, a
     * receive would still "work" and hand up a stream's bytes as a datagram
     * from nobody.
     * \~spanish
     * Solo sobre un socket que este backend abrio para datagramas.  Sobre
     * cualquier otro, una recepcion "funcionaria" igual y entregaria los bytes de
     * un flujo como un datagrama de nadie.
     * \~ */
    if (b == nullptr || dgram_.find(op.fd) < 0 || recvmsg_fn_ == nullptr) {
        last_error_ = WSAENOTSOCK;
        ++dgram_counts_.receive_errors;
        return false;
    }

    uint8_t *room = datagram_reserve(*b, op.length);
    if (room == nullptr) {
        ++dgram_counts_.receive_errors;
        return false;
    }

    c->payload.len = op.length;
    c->payload.buf = reinterpret_cast<CHAR *>(room);

    /* \~english
     * The control room is cleared before it is lent, so that a provider that
     * leaves the length alone can only ever be read as "nothing there".
     * \~spanish
     * El sitio de control se limpia antes de prestarlo, para que un proveedor
     * que no toque la longitud solo pueda leerse como "no hay nada".
     * \~ */
    util::vesta_memset(&c->name, 0, sizeof c->name);
    util::vesta_memset(c->control.bytes, 0, sizeof c->control.bytes);

    c->msg.name = reinterpret_cast<LPSOCKADDR>(&c->name);
    c->msg.namelen = sizeof c->name;
    c->msg.lpBuffers = &c->payload;
    c->msg.dwBufferCount = 1;
    c->msg.Control.len = sizeof c->control.bytes;
    c->msg.Control.buf = reinterpret_cast<CHAR *>(c->control.bytes);
    c->msg.dwFlags = 0;

    LPFN_WSARECVMSG fn = reinterpret_cast<LPFN_WSARECVMSG>(recvmsg_fn_);
    ++dgram_counts_.receive_calls;

    if (fn(as_socket(op.fd), &c->msg, nullptr, &c->ov, nullptr) ==
        SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            last_error_ = e;
            ++dgram_counts_.receive_errors;
            return false;
        }
    }

    return true;
}

bool IocpBackend::start_send_to(const Op &op, Context *c) noexcept {
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
    const int32_t at = dgram_.find(op.fd);

    DatagramHeader h;

    /* \~english
     * A peer of the other family is refused here rather than by the system:
     * the system's answer would come back as a completion that says only
     * "invalid argument", after the loop had thought the datagram was on its
     * way.
     * \~spanish
     * Un extremo de la otra familia se rechaza aqui y no en el sistema: la
     * respuesta del sistema volveria como una finalizacion que solo dice
     * "argumento no valido", despues de que el bucle creyera que el datagrama iba
     * de camino.
     * \~ */
    if (b == nullptr || at < 0 || !datagram_header(*b, h) ||
        datagram_size(*b) != op.length ||
        h.path.peer.len != dgram_.bound(static_cast<size_t>(at)).len) {
        last_error_ = WSAEINVAL;
        ++dgram_counts_.send_errors;
        return false;
    }

    /* \~english
     * All the room is copied and the length says how much of it counts: a
     * copy sized by a byte the service wrote could be told to read past the
     * address.
     * \~spanish
     * Se copia todo el sitio y la longitud dice cuanto cuenta: una copia medida
     * por un byte que escribio el servicio podria acabar leyendo mas alla de la
     * direccion.
     * \~ */
    static_assert(sizeof c->name == kMaxNetAddress,
                  "a v6 socket address is the largest a NetAddress holds");
    util::vesta_memcpy(&c->name, h.path.peer.bytes, sizeof c->name);

    c->payload.len = op.length;
    c->payload.buf =
        reinterpret_cast<CHAR *>(const_cast<uint8_t *>(datagram_payload(*b)));

    c->msg.name = reinterpret_cast<LPSOCKADDR>(&c->name);
    c->msg.namelen = h.path.peer.len;
    c->msg.lpBuffers = &c->payload;
    c->msg.dwBufferCount = 1;
    c->msg.Control.len = 0;
    c->msg.Control.buf = nullptr;
    c->msg.dwFlags = 0;

    if ((h.flags & kDatagramLocalKnown) != 0 &&
        h.path.local.len == h.path.peer.len) {
        c->msg.Control.len = static_cast<ULONG>(
            source_control(h.path.local, c->control.bytes));
        c->msg.Control.buf = reinterpret_cast<CHAR *>(c->control.bytes);
    }

    ++dgram_counts_.send_calls;

    if (WSASendMsg(as_socket(op.fd), &c->msg, 0, nullptr, &c->ov, nullptr) ==
        SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            last_error_ = e;
            ++dgram_counts_.send_errors;
            return false;
        }
    }

    return true;
}

int32_t IocpBackend::finish_datagram(Context *c, bool fine, uint32_t moved,
                                     uint32_t flags) noexcept {
    if (c->op.kind == OpKind::SendTo) {
        if (!fine) {
            last_error_ = WSAGetLastError();
            ++dgram_counts_.send_errors;
            return -1;
        }
        ++dgram_counts_.sent;
        return static_cast<int32_t>(moved);
    }

    const uint32_t said = flags | c->msg.dwFlags;

    /* \~english
     * Cut is told apart from failed, whichever way Windows says it: as the
     * error the documentation names, or as the flag.  Either way the bytes
     * that did arrive are NOT committed, so there is nothing in the buffer
     * that could be read as the datagram.
     * \~spanish
     * Cortado se distingue de fallado, lo diga Windows como lo diga: como el
     * error que nombra la documentacion, o como el indicador.  De las dos formas
     * los bytes que si llegaron NO se confirman, asi que no queda nada en el
     * buffer que se pueda leer como el datagrama.
     * \~ */
    if (!fine) {
        const int e = WSAGetLastError();
        if (e == WSAEMSGSIZE) {
            ++dgram_counts_.truncated;
            return kTruncated;
        }
        last_error_ = e;
        ++dgram_counts_.receive_errors;
        return -1;
    }

    if ((said & MSG_TRUNC) != 0) {
        ++dgram_counts_.truncated;
        return kTruncated;
    }

    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(c->op.buffer);
    const int32_t at = dgram_.find(c->op.fd);
    if (b == nullptr || at < 0) {
        ++dgram_counts_.receive_errors;
        return -1;
    }

    DatagramHeader h;
    canonical(&c->name, h.path.peer);

    if ((said & MSG_CTRUNC) != 0) ++dgram_counts_.control_truncated;

    if (local_from(c->msg, dgram_.bound(static_cast<size_t>(at)), h.path.local))
        h.flags = kDatagramLocalKnown;

    datagram_commit(*b, h, moved);
    ++dgram_counts_.received;
    return static_cast<int32_t>(moved);
}

} // namespace http_vx
