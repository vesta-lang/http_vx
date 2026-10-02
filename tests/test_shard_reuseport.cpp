/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard_reuseport.cpp
 * @brief
 * \~english Four shards, each with its own listening socket on the same address: every connection is served, by more than one shard.
 * \~spanish Cuatro fragmentos, cada uno con su propio socket de escucha en la misma direccion: cada conexion se sirve, y por mas de un fragmento.
 * \~
 *
 * \~english
 * HVX-6, 4.1.  Linux only: the kernel spreads incoming connections among the
 * sockets that share an address with `SO_REUSEPORT`, and each connection is
 * accepted by the shard that owns the socket it landed on -- no hand-over.
 * The same cases run against epoll and io_uring (R8).  Also that a second
 * socket on the address WITHOUT the option is refused: the option is what
 * makes the sharing, and a listener that silently shared would hide a bug.
 * \~spanish
 * HVX-6, 4.1.  Solo Linux: el nucleo reparte las conexiones entrantes entre los
 * sockets que comparten una direccion con `SO_REUSEPORT`, y cada conexion la
 * acepta el fragmento dueno del socket en el que cayo -- sin traspaso.  Los
 * mismos casos corren contra epoll e io_uring (R8).  Y que un segundo socket en
 * la direccion SIN la opcion se rechaza: la opcion es lo que hace el reparto, y
 * un socket que compartiera en silencio taparia un fallo.
 * \~
 */
#include "http_vx/epoll_backend.h"
#include "http_vx/http1_service.h"
#include "http_vx/shard.h"
#include "http_vx/uring_backend.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {

using http_vx::ListenShare;

constexpr int kShards = 4;
constexpr int kClients = 64;

int failures = 0;
const char *against = "-";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
    ++failures;
}

class Hello final : public http_vx::Handler {
public:
    void handle(const http_vx::Request &, const uint8_t *, const uint8_t *, size_t,
                http_vx::ResponseBuilder &res) noexcept override {
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body("hello", 5);
    }
};

/// \~english One shard: its handler, service, backend and thread.  \~spanish Un fragmento: su manejador, servicio, backend e hilo.  \~
struct Node {
    Hello handler;
    http_vx::Http1Service service;
    http_vx::Shard shard;
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
    http_vx::Backend *io = nullptr;
    uint16_t port = 0;
    std::thread thread;
    std::atomic<bool> quit{false};

    /// \~english Makes the backend and listens: on @p want_port, sharing the address when @p share.  \~spanish Hace el backend y escucha: en @p want_port, compartiendo la direccion si @p share.  \~
    bool start(bool use_uring, uint16_t want_port, ListenShare share) {
        http_vx::h1::Limits limits;
        if (!service.reset(64, handler, limits)) return false;
        if (use_uring) {
            if (!uring.reset(shard.buffers(), 256) || !uring.listen("127.0.0.1", want_port, 128, share)) return false;
            io = &uring;
            port = uring.port();
        } else {
            if (!epoll.reset(shard.buffers(), 512) || !epoll.listen("127.0.0.1", want_port, 128, share)) return false;
            io = &epoll;
            port = epoll.port();
        }
        http_vx::ShardConfig cfg;
        cfg.connections = 64;
        cfg.buffers = 32;
        cfg.idle_ticks = 1000;
        cfg.wheel_slots = 4096;
        cfg.accepts = 4;
        return shard.reset(cfg, *io, service, 0);
    }

    static void loop(Node *n) {
        while (!n->quit.load(std::memory_order_acquire)) n->shard.poll(1, 20);
    }
};

/// \~english One blocking client: connects, asks, reads to the end; whether it was answered.  \~spanish Un cliente bloqueante: conecta, pregunta, lee hasta el final; si le contestaron.  \~
bool one_request(uint16_t port) {
    const int s = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return false;

    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    sockaddr_in to;
    std::memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);

    bool answered = false;
    if (connect(s, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0) {
        const char req[] = "GET /hi HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        if (send(s, req, sizeof req - 1, 0) == static_cast<ssize_t>(sizeof req - 1)) {
            char got[1024] = {};
            size_t len = 0;
            for (;;) {
                const ssize_t n = recv(s, got + len, sizeof got - len - 1, 0);
                if (n <= 0) break;
                len += static_cast<size_t>(n);
            }
            answered = std::strstr(got, "HTTP/1.1 200") != nullptr && std::strstr(got, "hello") != nullptr;
        }
    }
    ::close(s);
    return answered;
}

void run(bool use_uring) {
    against = use_uring ? http_vx::UringBackend::kName : http_vx::EpollBackend::kName;

    Node nodes[kShards];
    if (!nodes[0].start(use_uring, 0, ListenShare::SharedPort)) {
        check(false, "shard 0 would not listen");
        return;
    }
    const uint16_t port = nodes[0].port;
    for (int i = 1; i < kShards; ++i) {
        if (!nodes[i].start(use_uring, port, ListenShare::SharedPort)) {
            check(false, "a shard could not listen on the address shard 0 got");
            return;
        }
        check(nodes[i].port == port, "a shard got another port");
    }

    // \~english Without the option the address is taken: sharing is asked for, never silent.
    // \~spanish Sin la opcion la direccion esta cogida: compartir se pide, nunca es en silencio.  \~
    {
        Node alone;
        check(!alone.start(use_uring, port, ListenShare::Alone), "a listener without SO_REUSEPORT shared an address");
    }

    for (Node &n : nodes) n.thread = std::thread(Node::loop, &n);

    int answered = 0;
    for (int i = 0; i < kClients; ++i)
        if (one_request(port)) ++answered;
    check(answered == kClients, "not every connection was served");

    for (Node &n : nodes) n.quit.store(true, std::memory_order_release);
    for (Node &n : nodes) n.thread.join();

    uint64_t total = 0;
    int busy = 0;
    for (const Node &n : nodes) {
        const uint64_t a = n.shard.counts().accepted;
        total += a;
        if (a > 0) ++busy;
    }
    check(total == kClients, "the shards did not accept exactly the connections made");
    check(busy >= 2, "every connection went to one shard: the kernel did not spread them");

    std::printf("  %s: %d connections over %d shards:", against, answered, kShards);
    for (const Node &n : nodes) std::printf(" %llu", static_cast<unsigned long long>(n.shard.counts().accepted));
    std::printf("\n");
}

} // namespace

int main() {
    run(false);
    run(true);

    if (failures != 0) {
        std::fprintf(stderr, "shard reuseport: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("shard reuseport: OK\n");
    return 0;
}
