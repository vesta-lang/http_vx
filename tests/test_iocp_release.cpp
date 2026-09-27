/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_iocp_release.cpp
 * @brief
 * \~english What IOCP must wait for before it lets go, and what it must not do twice.
 * \~spanish Lo que IOCP tiene que esperar antes de soltar, y lo que no puede hacer dos veces.
 * \~
 *
 * \~english
 * The kernel writes into an operation's buffer whenever the operation
 * finishes, so a backend that lets go too early is caught by the one thing
 * it cannot fake: bytes that arrive AFTER the release.  A read posted on a
 * socket that stays open is left in place, the backend is released, the peer
 * then sends, and the buffer is looked at.  With the read cancelled and
 * waited for, those bytes land nowhere; without it they land in the pool.
 *
 * Winsock is started here too, and not only by the backend: the backend's
 * own start is undone by its release, and the peer has to be able to send
 * after that.
 * \~spanish
 * El nucleo escribe en el buffer de una operacion cuando la operacion acaba,
 * asi que un backend que suelta demasiado pronto se pilla con lo unico que no
 * puede fingir: bytes que llegan DESPUES de soltar.  Se deja puesta una lectura
 * en un socket que sigue abierto, se suelta el backend, el otro extremo manda,
 * y se mira el buffer.  Con la lectura cancelada y esperada, esos bytes no caen
 * en ningun sitio; sin eso caen en el pozo.
 *
 * Winsock se arranca tambien aqui, y no solo en el backend: lo que arranca el
 * backend lo deshace su release, y el otro extremo tiene que poder mandar
 * despues de eso.
 * \~
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <winsock2.h>

#include <ws2tcpip.h>

#include "http_vx/buffer_pool.h"
#include "http_vx/iocp_backend.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::IocpBackend;
using http_vx::Op;
using http_vx::OpKind;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english A blocking client connected to @p port on the loopback.
/// \~spanish Un cliente que bloquea, conectado a @p port en el bucle local.  \~
SOCKET connect_to(uint16_t port) {
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/// \~english Whether @p s is still an open socket.
/// \~spanish Si @p s sigue siendo un socket abierto.  \~
bool is_open(SOCKET s) {
    int type = 0;
    int len = sizeof type;
    return getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&type),
                      &len) == 0;
}

/**
 * @brief
 * \~english A read on the caller's socket is cancelled and waited for; later bytes land nowhere.
 * \~spanish Una lectura en el socket de quien llama se cancela y se espera; los bytes de despues no caen en ningun sitio.
 * \~
 */
void test_a_posted_read_is_cancelled_before_release() {
    BufferPool pool;
    check(pool.reset(4, 16384), "the pool would not start");

    IocpBackend io;
    check(io.reset(pool, 8), "the backend would not start");
    check(io.listen("127.0.0.1", 0, 4), "the backend would not listen");

    Op accept;
    accept.kind = OpKind::Accept;
    check(io.submit(accept), "the accept was not taken");

    const SOCKET client = connect_to(io.port());
    check(client != INVALID_SOCKET, "the client could not connect");

    Completion done[4];
    const size_t n = io.wait(done, 4, 2000);
    check(n == 1 && done[0].kind == OpKind::Accept && done[0].result == 0,
          "the connection was not accepted");
    const SOCKET server = static_cast<SOCKET>(done[0].fd);

    /* \~english
     * A pattern where the read would write.  The read reserves the same room
     * again -- nothing is committed -- so this is exactly where bytes would go.
     * \~spanish
     * Un patron donde escribiria la lectura.  La lectura vuelve a reservar el
     * mismo sitio -- no hay nada confirmado --, asi que es justo donde irian los
     * bytes.
     * \~ */
    const uint32_t id = pool.acquire();
    http_vx::Buffer *b = pool.at(id);
    check(b != nullptr, "no buffer to lend");
    uint8_t *room = b->reserve(64);
    std::memset(room, 0xAB, 64);

    Op read;
    read.kind = OpKind::Recv;
    read.fd = static_cast<int32_t>(server);
    read.buffer = id;
    read.length = 64;
    check(io.submit(read), "the read was not taken");
    check(io.in_flight() == 1, "the read is not with the kernel");

    io.release();
    check(io.in_flight() == 0, "release left operations behind");
    check(io.stranded() == 0, "the kernel did not give the cancelled read back");
    check(is_open(server), "release closed a socket that is the caller's");

    check(send(client, "late bytes", 10, 0) == 10, "the peer could not send");
    Sleep(200);

    bool untouched = true;
    for (size_t i = 0; i < 64; ++i)
        if (room[i] != 0xAB) untouched = false;
    check(untouched, "bytes sent after release landed in the pool's buffer");
    check(b->size() == 0, "the buffer grew after release");

    closesocket(server);
    closesocket(client);
    pool.release(id);
}

/**
 * @brief
 * \~english A posted accept is given back too, with the socket it had made.
 * \~spanish Una aceptacion puesta tambien se devuelve, con el socket que habia hecho.
 * \~
 */
void test_a_posted_accept_is_given_back() {
    BufferPool pool;
    check(pool.reset(2, 4096), "the pool would not start");

    /* \~english
     * Each accept makes its socket before it is posted, and a socket is a
     * handle: what the process holds before and after says whether any was
     * left behind.
     * \~spanish
     * Cada aceptacion hace su socket antes de ponerse, y un socket es un
     * handle: lo que tiene el proceso antes y despues dice si se quedo alguno.
     * \~ */
    DWORD before = 0;
    GetProcessHandleCount(GetCurrentProcess(), &before);

    IocpBackend io;
    check(io.reset(pool, 4), "the backend would not start");
    check(io.listen("127.0.0.1", 0, 4), "the backend would not listen");

    Op accept;
    accept.kind = OpKind::Accept;
    check(io.submit(accept), "the first accept was not taken");
    check(io.submit(accept), "the second accept was not taken");
    check(io.in_flight() == 2, "the accepts are not with the kernel");

    io.release();
    check(io.in_flight() == 0, "release left accepts behind");
    check(io.stranded() == 0, "the kernel did not give the accepts back");

    DWORD after = 0;
    GetProcessHandleCount(GetCurrentProcess(), &after);
    check(after <= before, "release left the accepts' sockets open");
}

/**
 * @brief
 * \~english With no room to report a close, the socket is NOT closed and the caller hears "no".
 * \~spanish Sin sitio para contar un cierre, el socket NO se cierra y quien llama oye "no".
 * \~
 */
void test_a_close_with_no_room_leaves_the_socket_open() {
    BufferPool pool;
    check(pool.reset(2, 4096), "the pool would not start");

    IocpBackend io;
    check(io.reset(pool, 4), "the backend would not start");

    /* \~english
     * Operations that fail on the spot fill the list of completions owed.
     * \~spanish
     * Operaciones que fallan en el acto llenan la lista de finalizaciones
     * debidas.
     * \~ */
    Op bad;
    bad.kind = OpKind::Ready;
    bad.fd = -1;
    size_t owed = 0;
    while (io.submit(bad)) ++owed;
    check(owed == 64, "the list of completions owed is not the size it says");

    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check(s != INVALID_SOCKET, "no socket to close");

    Op close;
    close.kind = OpKind::Close;
    close.fd = static_cast<int32_t>(s);
    check(!io.submit(close), "a close with nowhere to report it was taken");
    check(is_open(s), "a refused close closed the socket anyway");

    Completion done[64];
    check(io.wait(done, 64, 0) == 64, "the owed completions did not come out");

    check(io.submit(close), "the close was refused with room to report it");
    check(!is_open(s), "the close did not close");
    check(io.wait(done, 64, 0) == 1 && done[0].kind == OpKind::Close,
          "the close was not reported");

    io.release();
}

} // namespace

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "FAIL: Winsock would not start\n");
        return 1;
    }

    test_a_posted_read_is_cancelled_before_release();
    test_a_posted_accept_is_given_back();
    test_a_close_with_no_room_leaves_the_socket_open();

    WSACleanup();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("iocp release: OK\n");
    return 0;
}
