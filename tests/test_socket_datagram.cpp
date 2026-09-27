/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_socket_datagram.cpp
 * @brief
 * \~english Datagrams over a real UDP socket, on every backend this system has.
 * \~spanish Datagramas por un socket UDP de verdad, en todos los backends que tenga este sistema.
 * \~
 *
 * \~english
 * The datagram half of `test_socket_backend.cpp`, and built the same way for
 * the same reason (R8): ONE list of cases, run against IOCP here and against
 * epoll and io_uring on Linux, over IPv4 and over IPv6.  It is its own file
 * only because the stream one is long enough already.
 *
 * What only a real socket can show: that the peer's address is the peer's,
 * that the local address is the one the datagram was SENT TO even on a socket
 * bound to every address, that a datagram too large for its room is reported
 * instead of delivered cut, and that the batch R26 asks for is really one
 * system call where the platform has one.
 *
 * Before this file every backend took a @c RecvFrom for a @c Recv: no
 * address came back, a cut datagram was delivered as whole, and there was no
 * way to open a UDP socket at all -- so every case here failed.
 *
 * \~spanish
 * La mitad de datagramas de `test_socket_backend.cpp`, y hecha igual por lo
 * mismo (R8): UNA lista de casos, que corre contra IOCP aqui y contra epoll e
 * io_uring en Linux, por IPv4 y por IPv6.  Es un fichero aparte solo porque el
 * de flujos ya es bastante largo.
 *
 * Lo que solo puede ensenar un socket de verdad: que la direccion del otro
 * extremo es la suya, que la direccion local es aquella a la que se MANDO el
 * datagrama aunque el socket este atado a todas, que un datagrama demasiado
 * grande para su sitio se informa en vez de entregarse cortado, y que el lote
 * que pide la R26 es de verdad una llamada al sistema donde la plataforma la
 * tiene.
 *
 * Antes de este fichero todos los backends tomaban un @c RecvFrom por un
 * @c Recv: no volvia ninguna direccion, un datagrama cortado se entregaba como
 * entero, y no habia forma de abrir un socket UDP -- asi que todos los casos de
 * aqui fallaban.
 * \~
 */

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <winsock2.h>

#include <ws2tcpip.h>

#include "http_vx/iocp_backend.h"

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"

#endif

#include "http_vx/datagram_service.h"
#include "http_vx/memory_backend.h"
#include "http_vx/shard.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::DatagramCounts;
using http_vx::DatagramHeader;
using http_vx::DatagramPath;
using http_vx::kNoBuffer;
using http_vx::NetAddress;
using http_vx::Op;
using http_vx::OpKind;

/* ------------------------------------------------------------------------- *
 * \~english The part that names a system.
 * \~spanish La parte que nombra un sistema.
 * \~
 * ------------------------------------------------------------------------- */

#ifdef _WIN32

using Sock = SOCKET;
constexpr Sock kNoSock = INVALID_SOCKET;

enum class Which { Iocp };
const char *which_name(Which) { return http_vx::IocpBackend::kName; }

void unmake(Sock s) { closesocket(s); }

void dont_block(Sock s) {
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
}

void breathe() { Sleep(1); }

#else

using Sock = int;
constexpr Sock kNoSock = -1;

enum class Which { Epoll, Uring };
const char *which_name(Which w) {
    return w == Which::Epoll ? http_vx::EpollBackend::kName : http_vx::UringBackend::kName;
}

void unmake(Sock s) { ::close(s); }
void dont_block(Sock s) { (void)s; }
void breathe() { usleep(1000); }

#endif

int failures = 0;
const char *against = "?";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
    ++failures;
}

/// \~english A family, as the test names it.  \~spanish Una familia, como la nombra la prueba.  \~
struct Family {
    const char *name;
    int af;
    const char *any;
    const char *loopback;

    /**
     * \~english
     * A SECOND local address of this machine, where there is one: v4 has all
     * of 127.0.0.0/8 on loopback.  A datagram written to it proves the local
     * address came from the packet, and one sent from it proves the source
     * was chosen -- with a single address, the system's own choice would be
     * right by accident.  v6 loopback has only ::1.
     * \~spanish
     * Una SEGUNDA direccion local de esta maquina, donde la hay: v4 tiene todo
     * 127.0.0.0/8 en bucle local.  Un datagrama escrito a ella demuestra que la
     * direccion local salio del paquete, y uno mandado desde ella que se eligio
     * el origen -- con una sola direccion, la eleccion del propio sistema
     * acertaria por casualidad.  El bucle local v6 solo tiene ::1.
     * \~
     *
     * \~english
     * Windows takes datagrams written to 127.0.0.2 but will not send FROM it
     * (only 127.0.0.1 is assigned), so there the second address is the first.
     * \~spanish
     * Windows recibe datagramas escritos a 127.0.0.2 pero no manda DESDE ella
     * (solo tiene asignada 127.0.0.1), asi que ahi la segunda es la primera.
     * \~
     */
    const char *other;
};

#ifdef _WIN32
const Family kV4 = {"v4", AF_INET, "0.0.0.0", "127.0.0.1", "127.0.0.1"};
#else
const Family kV4 = {"v4", AF_INET, "0.0.0.0", "127.0.0.1", "127.0.0.2"};
#endif
const Family kV6 = {"v6", AF_INET6, "::", "::1", "::1"};

/**
 * @brief
 * \~english The address @p text : @p port, in the canonical form the reactor uses.
 * \~spanish La direccion @p text : @p port, en la forma canonica que usa el reactor.
 * \~
 */
NetAddress address(const Family &f, const char *text, uint16_t port) {
    NetAddress a;
    if (f.af == AF_INET) {
        sockaddr_in v4;
        std::memset(&v4, 0, sizeof v4);
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        inet_pton(AF_INET, text, &v4.sin_addr);
        std::memcpy(a.bytes, &v4, sizeof v4);
        a.len = sizeof v4;
    } else {
        sockaddr_in6 v6;
        std::memset(&v6, 0, sizeof v6);
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        inet_pton(AF_INET6, text, &v6.sin6_addr);
        std::memcpy(a.bytes, &v6, sizeof v6);
        a.len = sizeof v6;
    }
    return a;
}

/// \~english The port inside @p a.  \~spanish El puerto dentro de @p a.  \~
uint16_t port_of(const NetAddress &a) {
    uint16_t p;
    std::memcpy(&p, a.bytes + 2, sizeof p);
    return ntohs(p);
}

/**
 * @brief
 * \~english A plain UDP socket for the other end, driven round the same loop.
 * \~spanish Un socket UDP corriente para el otro extremo, movido por el mismo bucle.
 * \~
 */
struct Peer {
    Sock sock = kNoSock;
    NetAddress self;

    ~Peer() { shut(); }

    void shut() {
        if (sock != kNoSock) unmake(sock);
        sock = kNoSock;
    }

    bool open(const Family &f) {
#ifdef _WIN32
        sock = socket(f.af, SOCK_DGRAM, IPPROTO_UDP);
#else
        sock = socket(f.af, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
#endif
        if (sock == kNoSock) return false;
        dont_block(sock);

        self = address(f, f.loopback, 0);
        if (bind(sock, reinterpret_cast<const sockaddr *>(self.bytes), self.len) != 0)
            return false;

        sockaddr_in6 got;
        std::memset(&got, 0, sizeof got);
        socklen_t len = sizeof got;
        if (getsockname(sock, reinterpret_cast<sockaddr *>(&got), &len) != 0)
            return false;
        self = address(f, f.loopback, ntohs(got.sin6_port));
        return true;
    }

    bool send(const NetAddress &to, const void *p, size_t n) {
        const int sent = static_cast<int>(
            sendto(sock, static_cast<const char *>(p), static_cast<int>(n), 0,
                   reinterpret_cast<const sockaddr *>(to.bytes), to.len));
        return sent == static_cast<int>(n);
    }

    /// \~english One datagram if there is one; -1 if none.
    /// \~spanish Un datagrama si lo hay; -1 si no.  \~
    int take(char *into, size_t room, NetAddress *from) {
        sockaddr_in6 src;
        std::memset(&src, 0, sizeof src);
        socklen_t len = sizeof src;
        const int n = static_cast<int>(
            recvfrom(sock, into, static_cast<int>(room), 0,
                     reinterpret_cast<sockaddr *>(&src), &len));
        if (n >= 0 && from != nullptr) {
            *from = NetAddress();
            std::memcpy(from->bytes, &src, static_cast<size_t>(len));
            from->len = static_cast<uint8_t>(len);
            if (len == sizeof(sockaddr_in6)) {
                sockaddr_in6 v6;
                std::memcpy(&v6, from->bytes, sizeof v6);
                v6.sin6_flowinfo = 0;
                std::memcpy(from->bytes, &v6, sizeof v6);
            }
        }
        return n;
    }
};

bool same(const NetAddress &a, const NetAddress &b) {
    return http_vx::same_net_address(a, b);
}

/**
 * @brief
 * \~english Every backend this system has, and only one started.
 * \~spanish Todos los backends que tiene este sistema, y solo uno arrancado.
 * \~
 */
struct Rig {
    BufferPool pool;

#ifdef _WIN32
    http_vx::IocpBackend iocp;
#else
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
#endif

    http_vx::Backend *io = nullptr;
    Which which = {};

    bool start(Which w, uint32_t buffers = 32) {
        which = w;
        if (!pool.reset(buffers, 1 << 20)) return false;
#ifdef _WIN32
        if (!iocp.reset(pool, 64)) return false;
        io = &iocp;
#else
        if (w == Which::Epoll) {
            if (!epoll.reset(pool, 1024)) return false;
            io = &epoll;
        } else {
            if (!uring.reset(pool, 256)) return false;
            io = &uring;
        }
#endif
        return true;
    }

    int32_t open(const char *host, uint16_t port, NetAddress &bound) {
#ifdef _WIN32
        return iocp.open_datagram(host, port, bound);
#else
        return which == Which::Epoll ? epoll.open_datagram(host, port, bound)
                                     : uring.open_datagram(host, port, bound);
#endif
    }

    const DatagramCounts &counts() const {
#ifdef _WIN32
        return iocp.datagrams();
#else
        return which == Which::Epoll ? epoll.datagrams() : uring.datagrams();
#endif
    }

    /**
     * \~english
     * Trips into the kernel, for io_uring, where the batch is the ring's and
     * not a call per datagram; zero elsewhere.
     * \~spanish
     * Viajes al nucleo, para io_uring, donde el lote es el del anillo y no una
     * llamada por datagrama; cero en los demas.
     * \~
     */
    size_t enters() const {
#ifdef _WIN32
        return 0;
#else
        return which == Which::Uring ? uring.enters() : 0;
#endif
    }

    /// \~english Posts a receive of up to @p room bytes on @p fd.
    /// \~spanish Pone una recepcion de hasta @p room bytes en @p fd.  \~
    bool receive(int32_t fd, uint32_t room) {
        const uint32_t b = pool.acquire();
        if (b == kNoBuffer) return false;

        Op op;
        op.kind = OpKind::RecvFrom;
        op.buffer = b;
        op.length = room;
        op.fd = fd;
        if (io->submit(op)) return true;

        pool.release(b);
        return false;
    }

    /// \~english Asks for @p n bytes to go to @p path.peer from @p fd.
    /// \~spanish Pide que @p n bytes vayan a @p path.peer desde @p fd.  \~
    bool send(int32_t fd, const DatagramPath &path, const void *p, size_t n) {
        const uint32_t b = pool.acquire();
        if (b == kNoBuffer) return false;

        http_vx::Buffer *buf = pool.at(b);
        uint8_t *room = http_vx::datagram_reserve(*buf, n);
        if (room == nullptr) {
            pool.release(b);
            return false;
        }
        std::memcpy(room, p, n);

        DatagramHeader h;
        h.path = path;
        h.flags = path.local.len != 0 ? http_vx::kDatagramLocalKnown : 0;
        http_vx::datagram_commit(*buf, h, n);

        Op op;
        op.kind = OpKind::SendTo;
        op.buffer = b;
        op.length = static_cast<uint32_t>(n);
        op.fd = fd;
        if (io->submit(op)) return true;

        pool.release(b);
        return false;
    }

    /// \~english Waits until @p want completions came back, or gives up.
    /// \~spanish Espera hasta que vuelvan @p want finalizaciones, o se rinde.  \~
    size_t collect(Completion *out, size_t want) {
        size_t got = 0;
        for (int i = 0; i < 2000 && got < want; ++i) {
            got += io->wait(out + got, want - got, 0);
            if (got < want) breathe();
        }
        return got;
    }
};

/**
 * @brief
 * \~english Datagrams arrive whole, with who sent them and where they were sent.
 * \~spanish Los datagramas llegan enteros, con quien los mando y a donde se mandaron.
 * \~
 *
 * \~english
 * The socket is bound to EVERY address and the peer writes to loopback, so
 * the local address can only be right if it came from the packet: the
 * address the socket is bound to is the wildcard, which is not where anything
 * was sent.  Several datagrams are sent before the backend looks, which is
 * what makes a batch possible.
 * \~spanish
 * El socket esta atado a TODAS las direcciones y el otro extremo escribe a la
 * de bucle local, asi que la direccion local solo puede estar bien si salio del
 * paquete: aquella a la que esta atado el socket es la comodin, que no es adonde
 * se mando nada.  Se mandan varios datagramas antes de que mire el backend, que
 * es lo que hace posible un lote.
 * \~
 */
void test_datagrams_arrive_with_both_addresses(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.any, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;
    check(port_of(bound) != 0, "the socket did not say which port it got");

    for (int i = 0; i < 8; ++i)
        check(r.receive(fd, 1500), "a receive could not be posted");

    Peer p;
    check(p.open(f), "the peer could not open");

    const NetAddress to = address(f, f.other, port_of(bound));
    char msg[5][16];
    for (int i = 0; i < 5; ++i) {
        std::snprintf(msg[i], sizeof msg[i], "datagram-%d", i);
        check(p.send(to, msg[i], std::strlen(msg[i])), "the peer could not send");
    }

    Completion done[8];
    const size_t trips = r.enters();
    const size_t got = r.collect(done, 5);
    check(got == 5, "the five datagrams did not all arrive");
    const size_t spent = r.enters() - trips;

    int seen[5] = {};
    for (size_t k = 0; k < got; ++k) {
        check(done[k].kind == OpKind::RecvFrom, "a completion of the wrong kind");
        check(done[k].ok(), "a receive failed");
        check(!done[k].eof(), "a datagram was taken for the end of a stream");

        http_vx::Buffer *b = r.pool.at(done[k].buffer);
        DatagramHeader h;
        check(b != nullptr && http_vx::datagram_header(*b, h),
              "the datagram came back without its header");
        if (b == nullptr) continue;

        const size_t n = http_vx::datagram_size(*b);
        check(n == static_cast<size_t>(done[k].result),
              "the result is not the payload's size");

        for (int i = 0; i < 5; ++i)
            if (n == std::strlen(msg[i]) &&
                std::memcmp(http_vx::datagram_payload(*b), msg[i], n) == 0)
                ++seen[i];

        check(same(h.path.peer, p.self), "the peer's address is not the peer's");
        check((h.flags & http_vx::kDatagramLocalKnown) != 0,
              "the local address of a received datagram is not known");
        check(same(h.path.local, to),
              "the local address is not the one the datagram was sent to");
        r.pool.release(done[k].buffer);
    }

    for (int i = 0; i < 5; ++i)
        check(seen[i] == 1, "a datagram was lost, repeated or changed");

    const DatagramCounts &c = r.counts();
    check(c.received == 5, "the backend did not count what it received");
    std::printf("     %s: 5 datagrams in %llu receive calls, %zu ring enters\n",
                f.name, static_cast<unsigned long long>(c.receive_calls), spent);

#ifndef _WIN32
    /* \~english
     * On io_uring the eight receives were handed over in the enter that also
     * waited, so five datagrams cost far fewer than five trips.
     * \~spanish
     * En io_uring las ocho recepciones se entregaron en la misma entrada que
     * espero, asi que cinco datagramas cuestan muchos menos de cinco viajes.
     * \~ */
    if (which == Which::Uring)
        check(spent < 5, "io_uring entered the kernel once per datagram");

    /* \~english
     * The batch, counted.  On epoll the eight receives were waiting when the
     * five datagrams arrived, and one `recvmmsg` answers all of them; a
     * backend receiving one per call would make five.
     * \~spanish
     * El lote, contado.  En epoll las ocho recepciones esperaban cuando llegaron
     * los cinco datagramas, y un `recvmmsg` las contesta todas; un backend que
     * recibiera uno por llamada haria cinco.
     * \~ */
    if (which == Which::Epoll)
        check(c.receive_calls != 0 && c.receive_calls < 5,
              "epoll did not receive in one batch, or did not count the calls");
#endif
}

/**
 * @brief
 * \~english Several datagrams go out, from the address asked for, to the peer named.
 * \~spanish Salen varios datagramas, desde la direccion pedida, al extremo nombrado.
 * \~
 */
void test_a_batch_goes_out(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.any, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    Peer p;
    check(p.open(f), "the peer could not open");

    DatagramPath path;
    path.peer = p.self;
    path.local = address(f, f.other, port_of(bound));

    for (int i = 0; i < 6; ++i) {
        char msg[16];
        std::snprintf(msg, sizeof msg, "out-%d", i);
        check(r.send(fd, path, msg, std::strlen(msg)), "a send was refused");
    }

    Completion done[8];
    const size_t trips = r.enters();
    const size_t got = r.collect(done, 6);
    check(got == 6, "the six sends did not all come back");
    const size_t spent = r.enters() - trips;

    for (size_t k = 0; k < got; ++k) {
        check(done[k].kind == OpKind::SendTo, "a completion of the wrong kind");
        check(done[k].ok() && done[k].result == 5, "a send did not send it all");
        r.pool.release(done[k].buffer);
    }

    int arrived = 0;
    for (int i = 0; i < 2000 && arrived < 6; ++i) {
        char into[64];
        NetAddress from;
        const int n = p.take(into, sizeof into, &from);
        if (n < 0) {
            breathe();
            continue;
        }
        ++arrived;
        check(n == 5 && std::memcmp(into, "out-", 4) == 0,
              "a datagram arrived changed");
        check(same(from, path.local),
              "a datagram did not leave from the address asked for");
    }
    check(arrived == 6, "the peer did not get all six");

    const DatagramCounts &c = r.counts();
    check(c.sent == 6, "the backend did not count what it sent");
    std::printf("     %s: 6 datagrams in %llu send calls, %zu ring enters\n",
                f.name, static_cast<unsigned long long>(c.send_calls), spent);

#ifndef _WIN32
    if (which == Which::Uring)
        check(spent < 6, "io_uring entered the kernel once per datagram");

    if (which == Which::Epoll)
        check(c.send_calls < 6, "epoll sent one datagram per call");
#endif
}

/**
 * @brief
 * \~english A datagram larger than its room is reported, never delivered cut.
 * \~spanish Un datagrama mayor que su sitio se informa, nunca se entrega cortado.
 * \~
 */
void test_a_datagram_too_large_is_reported(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.loopback, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    check(r.receive(fd, 16), "a receive could not be posted");

    Peer p;
    check(p.open(f), "the peer could not open");

    char big[100];
    std::memset(big, 'b', sizeof big);
    check(p.send(bound, big, sizeof big), "the peer could not send");

    Completion done[2];
    check(r.collect(done, 1) == 1, "the large datagram never came back");
    check(!done[0].ok(), "a cut datagram was reported as a success");
    check(done[0].truncated(), "a cut datagram was not reported as cut");
    check(r.counts().truncated == 1, "the cut was not counted");

    http_vx::Buffer *b = r.pool.at(done[0].buffer);
    check(b != nullptr && b->empty(), "the cut bytes were left in the buffer");
    r.pool.release(done[0].buffer);

    /* \~english
     * And the socket is still fine: the next datagram that fits arrives.
     * \~spanish
     * Y el socket sigue bien: el siguiente datagrama que cabe llega.
     * \~ */
    check(r.receive(fd, 16), "a receive could not be posted again");
    check(p.send(bound, "small", 5), "the peer could not send");
    check(r.collect(done, 1) == 1 && done[0].ok() && done[0].result == 5,
          "a datagram after a cut one did not arrive");
    r.pool.release(done[0].buffer);
}

/**
 * @brief
 * \~english An empty datagram is a datagram, not the end of anything.
 * \~spanish Un datagrama vacio es un datagrama, no el final de nada.
 * \~
 */
void test_an_empty_datagram(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.loopback, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    check(r.receive(fd, 64), "a receive could not be posted");

    Peer p;
    check(p.open(f), "the peer could not open");
    check(p.send(bound, "", 0), "the peer could not send nothing");

    Completion done[2];
    check(r.collect(done, 1) == 1, "the empty datagram never came back");
    check(done[0].ok() && done[0].result == 0, "an empty datagram failed");
    check(!done[0].eof(), "an empty datagram was taken for an end");

    DatagramHeader h;
    http_vx::Buffer *b = r.pool.at(done[0].buffer);
    check(b != nullptr && http_vx::datagram_header(*b, h) &&
              same(h.path.peer, p.self),
          "an empty datagram came without its sender");
    r.pool.release(done[0].buffer);
}

/**
 * @brief
 * \~english A send to nobody does not break the next receive.
 * \~spanish Un envio a nadie no rompe la recepcion siguiente.
 * \~
 *
 * \~english
 * Windows by default fails a later receive with "connection reset" when an
 * earlier send drew an ICMP Port Unreachable; on a socket shared by every
 * peer, one peer that went away would fail receives meant for the others.
 * \~spanish
 * Windows por defecto hace fallar una recepcion posterior con "conexion
 * reiniciada" cuando un envio anterior provoco un ICMP Port Unreachable; en un
 * socket compartido por todos los extremos, uno que se fue haria fallar
 * recepciones que eran para los demas.
 * \~
 */
void test_a_send_to_nobody_does_not_break_receiving(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.loopback, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    NetAddress gone;
    {
        Peer ghost;
        check(ghost.open(f), "the peer could not open");
        gone = ghost.self;
    }

    DatagramPath path;
    path.peer = gone;
    check(r.send(fd, path, "anyone", 6), "the send was refused");

    Completion done[2];
    check(r.collect(done, 1) == 1, "the send never came back");
    r.pool.release(done[0].buffer);

    for (int i = 0; i < 20; ++i) breathe();

    check(r.receive(fd, 64), "a receive could not be posted");

    Peer p;
    check(p.open(f), "the peer could not open");
    check(p.send(bound, "hello", 5), "the peer could not send");

    check(r.collect(done, 1) == 1, "the datagram never came back");
    check(done[0].ok() && done[0].result == 5,
          "a receive failed because of an earlier send to nobody");
    r.pool.release(done[0].buffer);
    check(r.counts().receive_errors == 0, "a receive error was counted");
}

/**
 * @brief
 * \~english A socket that is not a datagram socket is refused, not read as one.
 * \~spanish Un socket que no es de datagramas se rechaza, no se lee como uno.
 * \~
 */
void test_a_stream_socket_is_refused(Which which) {
    Rig r;
    check(r.start(which), "the backend would not start");

    const Sock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check(s != kNoSock, "a stream socket could not be made");

    check(r.receive(static_cast<int32_t>(s), 64), "the receive was not answered");

    Completion done[2];
    check(r.collect(done, 1) == 1, "the refusal never came back");
    check(!done[0].ok(), "a datagram receive on a stream socket succeeded");
    r.pool.release(done[0].buffer);
    unmake(s);
}

/**
 * @brief
 * \~english Answers every datagram with the same bytes, to the same peer, from the same address.
 * \~spanish Contesta cada datagrama con los mismos bytes, al mismo extremo, desde la misma direccion.
 * \~
 */
class Echo final : public http_vx::DatagramService {
  public:
    void on_datagram(const DatagramPath &path, uint8_t *data, size_t n,
                     http_vx::EcnMark ecn, uint64_t now) noexcept override {
        (void)ecn;
        (void)now;
        if (count_ == 16 || n > sizeof held_[0].bytes) return;
        held_[count_].path = path;
        held_[count_].n = n;
        std::memcpy(held_[count_].bytes, data, n);
        ++count_;
        ++got;
    }

    size_t next_datagram(DatagramPath &path, uint8_t *out, size_t room,
                         uint64_t now) noexcept override {
        (void)now;
        if (next_ == count_ || held_[next_].n > room) return 0;
        const Held &h = held_[next_++];
        path.local = h.path.local;
        path.peer = h.path.peer;
        std::memcpy(out, h.bytes, h.n);
        return h.n;
    }

    uint64_t timer() const noexcept override { return http_vx::kNoDatagramTimer; }
    void on_timer(uint64_t now) noexcept override { (void)now; }

    int got = 0;

  private:
    struct Held {
        DatagramPath path;
        size_t n = 0;
        uint8_t bytes[256];
    };
    Held held_[16];
    size_t count_ = 0;
    size_t next_ = 0;
};

/**
 * @brief
 * \~english A datagram service driven by the shard over a real socket, end to end.
 * \~spanish Un servicio de datagramas movido por el fragmento sobre un socket de verdad, de punta a punta.
 * \~
 */
void test_a_shard_serves_datagrams(Which which, const Family &f) {
    Echo echo;
    http_vx::Shard shard;

#ifdef _WIN32
    (void)which;
    http_vx::IocpBackend iocp;
    http_vx::Backend *io = &iocp;
    const bool made = iocp.reset(shard.buffers(), 64);
#else
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
    http_vx::Backend *io = which == Which::Epoll
                               ? static_cast<http_vx::Backend *>(&epoll)
                               : static_cast<http_vx::Backend *>(&uring);
    const bool made = which == Which::Epoll ? epoll.reset(shard.buffers(), 1024)
                                            : uring.reset(shard.buffers(), 256);
#endif
    check(made, "the backend would not start");

    http_vx::ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 32;
    cfg.idle_ticks = 100;
    check(shard.reset(cfg, *io, 0), "the shard would not start");

    http_vx::DatagramConfig dc;
    dc.receives = 4;
    dc.room = 1500;
    check(shard.attach_datagrams(echo, dc), "the datagram side would not attach");

    NetAddress bound;
#ifdef _WIN32
    const int32_t fd = iocp.open_datagram(f.any, 0, bound);
#else
    const int32_t fd = which == Which::Epoll ? epoll.open_datagram(f.any, 0, bound)
                                             : uring.open_datagram(f.any, 0, bound);
#endif
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;
    check(shard.add_datagram_socket(fd, bound), "the shard did not take the socket");
    check(shard.datagrams().posted(0) == 4, "the receives were not posted");

    Peer p;
    check(p.open(f), "the peer could not open");
    const NetAddress to = address(f, f.other, port_of(bound));

    for (int i = 0; i < 6; ++i) {
        char msg[16];
        std::snprintf(msg, sizeof msg, "echo-%d", i);
        check(p.send(to, msg, std::strlen(msg)), "the peer could not send");
    }

    int back = 0;
    for (int i = 0; i < 2000 && back < 6; ++i) {
        shard.poll(static_cast<uint64_t>(i), 0);
        char into[64];
        NetAddress from;
        const int n = p.take(into, sizeof into, &from);
        if (n < 0) {
            breathe();
            continue;
        }
        ++back;
        check(n == 6 && std::memcmp(into, "echo-", 5) == 0, "an echo came back changed");
        check(same(from, to), "an echo did not come from the address written to");
    }

    for (int i = 0; i < 20; ++i) shard.poll(3000, 0);

    check(back == 6, "the echoes did not all come back");
    check(echo.got == 6, "the service was not handed every datagram");

    const http_vx::ShardDatagramCounts &c = shard.datagrams().counts();
    check(c.delivered == 6 && c.sent == 6, "the shard did not count what it moved");
    check(c.dropped == 0 && c.send_failures == 0 && c.receive_failures == 0,
          "the shard lost something");
    check(shard.datagrams().posted(0) == 4, "the receives were not kept posted");
    check(shard.datagrams().sending() == 0, "a send never came back");

    /* \~english
     * R1 as far as datagrams allow: what is held while idle is exactly the
     * receives posted, and nothing for the peers that were served.
     * \~spanish
     * La R1 hasta donde dejan los datagramas: lo que se tiene parado son
     * exactamente las recepciones puestas, y nada por los extremos servidos.
     * \~ */
    check(shard.buffers().lent() == 4,
          "the shard holds more buffers than its posted receives");
}

/**
 * @brief
 * \~english A send from an address this machine does not have fails, and is counted.
 * \~spanish Un envio desde una direccion que esta maquina no tiene falla, y se cuenta.
 * \~
 *
 * \~english
 * Which is also the proof that the source asked for is really handed to the
 * system: were it dropped, the datagram would leave from the socket's own
 * address and "succeed".  The addresses are from the documentation ranges
 * (RFC 5737 for v4, RFC 3849 for v6), which no machine has.
 * \~spanish
 * Que es ademas la prueba de que el origen pedido se le da de verdad al
 * sistema: si se tirara, el datagrama saldria desde la direccion propia del
 * socket y "funcionaria".  Las direcciones son de los rangos de documentacion
 * (RFC 5737 para v4, RFC 3849 para v6), que no tiene ninguna maquina.
 * \~
 */
void test_a_send_from_a_foreign_address_fails(Which which, const Family &f) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open(f.any, 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    Peer p;
    check(p.open(f), "the peer could not open");

    DatagramPath path;
    path.peer = p.self;
    path.local = address(f, f.af == AF_INET ? "192.0.2.1" : "2001:db8::1",
                         port_of(bound));

    Completion done[2];
    const bool asked = r.send(fd, path, "stray", 5);

    /* \~english
     * The system may refuse it on the spot or when it completes; either way
     * it comes back as a completion that failed, never as a send.
     * \~spanish
     * El sistema puede rechazarlo en el acto o al acabar; de cualquier forma
     * vuelve como una finalizacion que fallo, nunca como un envio.
     * \~ */
    check(asked, "the send was not answered");
    check(r.collect(done, 1) == 1, "the send never came back");
    check(!done[0].ok(), "a datagram left from an address this machine lacks");
    check(r.counts().send_errors == 1 && r.counts().sent == 0,
          "the failed send was not counted as one");
    r.pool.release(done[0].buffer);
}

/**
 * @brief
 * \~english A v6 socket is v6 only: a v4 datagram to its port does not reach it.
 * \~spanish Un socket v6 es solo v6: un datagrama v4 a su puerto no le llega.
 * \~
 */
void test_a_v6_socket_takes_no_v4(Which which) {
    Rig r;
    check(r.start(which), "the backend would not start");

    NetAddress bound;
    const int32_t fd = r.open("::", 0, bound);
    check(fd >= 0, "a v6 datagram socket could not be opened");
    if (fd < 0) return;

    check(r.receive(fd, 64), "a receive could not be posted");

    Peer p;
    check(p.open(kV4), "the v4 peer could not open");
    p.send(address(kV4, "127.0.0.1", port_of(bound)), "v4", 2);

    Completion done[2];
    size_t got = 0;
    for (int i = 0; i < 100 && got == 0; ++i) {
        got = r.io->wait(done, 2, 0);
        breathe();
    }
    check(got == 0, "a v4 datagram reached a v6 socket as a mapped address");
}

void run_every_case(Which which) {
    against = which_name(which);
    std::printf("  -- %s --\n", against);

    const Family *families[2] = {&kV4, &kV6};
    for (const Family *f : families) {
        test_datagrams_arrive_with_both_addresses(which, *f);
        test_a_batch_goes_out(which, *f);
        test_a_datagram_too_large_is_reported(which, *f);
        test_an_empty_datagram(which, *f);
        test_a_send_to_nobody_does_not_break_receiving(which, *f);
        test_a_shard_serves_datagrams(which, *f);
        test_a_send_from_a_foreign_address_fails(which, *f);
    }
    test_a_stream_socket_is_refused(which);
    test_a_v6_socket_takes_no_v4(which);
}

} // namespace

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    run_every_case(Which::Iocp);

    WSACleanup();
#else
    run_every_case(Which::Epoll);

    if (http_vx::uring_available()) {
        run_every_case(Which::Uring);
    } else {
        std::printf("  -- io_uring: SKIPPED, this kernel gives no ring --\n");
    }
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
