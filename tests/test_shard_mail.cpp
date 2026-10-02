/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard_mail.cpp
 * @brief
 * \~english Two shards on two threads: one hands a socket to the other, which adopts it and serves a request.
 * \~spanish Dos fragmentos en dos hilos: uno le pasa un socket al otro, que lo adopta y sirve una peticion.
 * \~
 *
 * \~english
 * HVX-6, 6 and 10: "without a network, two shards on threads with the memory
 * backend; a socket handed over through the mailbox arrives, is served, and the
 * message goes back to its pool".  Shard B sleeps with no deadline over the
 * sleeping memory backend; the only thing that can wake it is shard A's push,
 * so a request that is answered is a wake that was not lost.  Shard A's thread
 * is the one that sends -- the pool is A's and nobody else's -- and what comes
 * back goes onto A's returned stack, which A drains when it next sends.
 * \~spanish
 * HVX-6, 6 y 10: "sin red, dos fragmentos en hilos con el backend de memoria;
 * un socket traspasado por el buzon llega, se atiende, y el mensaje vuelve a su
 * pozo".  El fragmento B duerme sin plazo sobre el backend de memoria que
 * duerme; lo unico que puede despertarlo es el push del fragmento A, asi que
 * una peticion que se contesta es un despertar que no se perdio.  El hilo del
 * fragmento A es el que manda -- el pozo es de A y de nadie mas --, y lo que
 * vuelve va a la pila de devueltos de A, que A vacia cuando manda otra vez.
 * \~
 */
#include "shard_rig.h"

#include "http_vx/http1_service.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace {

using http_vx::MailKind;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english Whether @p what is somewhere in the @p n bytes at @p p.  \~spanish Si @p what esta en algun sitio de los @p n bytes de @p p.  \~
bool contains(const uint8_t *p, size_t n, const char *what) {
    const size_t m = std::strlen(what);
    return n >= m && std::search(p, p + n, what, what + m) != p + n;
}

/// \~english Answers every request with "hello", counting them.  \~spanish Contesta cada peticion con "hello", contandolas.  \~
class Hello final : public http_vx::Handler {
public:
    void handle(const http_vx::Request &, const uint8_t *, const uint8_t *, size_t,
                http_vx::ResponseBuilder &res) noexcept override {
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body("hello", 5);
        calls.fetch_add(1, std::memory_order_release);
    }
    std::atomic<int> calls{0};
};

/// \~english Shard B: HTTP/1.1 over the sleeping memory backend, on its own thread.  \~spanish Fragmento B: HTTP/1.1 sobre el backend de memoria que duerme, en su propio hilo.  \~
struct ServingShard {
    Hello handler;
    http_vx::Http1Service service;
    http_vx::Shard shard;
    rig::SleepyBackend io{shard.buffers()};
    std::thread thread;
    std::atomic<bool> exited{false};

    bool start() {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;
        http_vx::ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.wheel_slots = 64;
        return shard.reset(cfg, io, service, 0);
    }

    static void loop(ServingShard *s) {
        // \~english No deadline: the wait ends only when something wakes it.  \~spanish Sin plazo: la espera acaba solo cuando algo la despierta.  \~
        while (!s->shard.stop_requested()) s->shard.poll(1, -1);
        s->exited.store(true, std::memory_order_release);
    }

    ~ServingShard() {
        if (!thread.joinable()) return;
        // \~english Only a failed test gets here with the thread running: stop it through the mailbox, as anybody would.  \~spanish Solo una prueba fallida llega aqui con el hilo corriendo: se para por el buzon, como lo haria cualquiera.  \~
        http_vx::MailPool p;
        if (p.reset(1) && p.send(shard.mailbox(), MailKind::Stop, -1)) thread.join();
    }
};

/// \~english Shard A's thread: hands one socket to B, and then sends a Stop.  \~spanish El hilo del fragmento A: le pasa un socket a B, y luego manda un Stop.  \~
struct Sender {
    http_vx::Shard shard;
    http_vx::Mailbox *to = nullptr;
    bool adopt_sent = false;
    bool stop_sent = false;
    std::atomic<int> stage{0};
};

void send_adopt(Sender *a) {
    a->adopt_sent = a->shard.mail_pool().send(*a->to, MailKind::AdoptSocket, 7);
    a->stage.store(1, std::memory_order_release);
}

void send_stop(Sender *a) {
    a->stop_sent = a->shard.mail_pool().send(*a->to, MailKind::Stop, -1);
    a->stage.store(2, std::memory_order_release);
}

void test_a_socket_handed_over_is_served() {
    ServingShard b;
    check(b.start(), "shard B would not start");

    // \~english Shard A: only its mail pool is needed to send, made on the thread that sends.  \~spanish Fragmento A: solo necesita su pozo de correo para mandar, hecho en el hilo que manda.  \~
    Sender a;
    http_vx::MemoryBackend a_io(a.shard.buffers());
    http_vx::ShardConfig a_cfg;
    a_cfg.connections = 4;
    a_cfg.buffers = 4;
    a_cfg.wheel_slots = 64;
    a_cfg.mail_nodes = 4;
    check(a.shard.reset(a_cfg, a_io, 0), "shard A would not start");
    a.to = &b.shard.mailbox();

    // \~english The request is waiting in B's backend before the socket arrives: only the adoption is missing.  \~spanish La peticion espera en el backend de B antes de que llegue el socket: solo falta la adopcion.  \~
    const char request[] = "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n";
    check(b.io.memory().feed(reinterpret_cast<const uint8_t *>(request), sizeof request - 1), "the request was not taken by the backend");

    b.thread = std::thread(ServingShard::loop, &b);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::thread t(send_adopt, &a);
    t.join();
    check(a.adopt_sent, "shard A's send was refused");

    const rig::Clock::time_point t0 = rig::Clock::now();
    while (b.handler.calls.load(std::memory_order_acquire) == 0 && rig::ms_since(t0) < 3000)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    check(b.handler.calls.load() == 1, "shard B did not serve the request on the socket it was handed");

    std::thread u(send_stop, &a);
    u.join();
    check(a.stop_sent, "shard A's stop was refused");

    const rig::Clock::time_point t1 = rig::Clock::now();
    while (!b.exited.load(std::memory_order_acquire) && rig::ms_since(t1) < 3000)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    check(b.exited.load(), "shard B did not stop");
    if (b.exited.load()) b.thread.join();

    // \~english Read now that B's thread is gone.  \~spanish Se lee ahora que el hilo de B se fue.  \~
    check(b.shard.counts().mail_adopted == 1 && b.shard.counts().mail_adopt_refused == 0, "shard B did not count the adoption");
    check(b.shard.mail_received().received == 2, "shard B did not count its two messages");
    const uint8_t *out = b.io.memory().written();
    const size_t n = b.io.memory().written_size();
    check(contains(out, n, "HTTP/1.1 200") && contains(out, n, "hello"), "the response on the adopted socket is not the handler's");

    // \~english Both nodes went home to A's pool, the one that owns them.  \~spanish Los dos nodos volvieron al pozo de A, que es el dueno.  \~
    a.shard.mail_pool().reclaim();
    check(a.shard.mail_pool().free_count() == a.shard.mail_pool().capacity(), "the messages did not go back to shard A's pool");
    check(a.shard.mail_pool().counts().sent == 2 && a.shard.mail_pool().counts().returned == 2, "shard A's pool did not count its traffic");
}

/// \~english A shard with no room for an accepted socket closes it and counts it, and counts the ones it takes.  \~spanish Un fragmento sin sitio para un socket aceptado lo cierra y lo cuenta, y cuenta los que coge.  \~
void test_a_full_shard_refuses_an_accepted_socket() {
    Hello handler;
    http_vx::Http1Service service;
    http_vx::Shard shard;
    http_vx::MemoryBackend io(shard.buffers());

    http_vx::h1::Limits limits;
    check(service.reset(1, handler, limits), "the service would not start");
    http_vx::ShardConfig cfg;
    cfg.connections = 1;
    cfg.buffers = 2;
    cfg.wheel_slots = 64;
    cfg.accepts = 1;
    check(shard.reset(cfg, io, service, 0), "the shard would not start");

    check(io.arrive(10) && io.arrive(11), "the backend would not take the arrivals");
    for (int i = 0; i < 6; ++i) shard.poll(1, 0);

    check(shard.counts().accepted == 1, "the socket that fitted was not counted as accepted");
    check(shard.counts().accept_refused == 1, "the socket that did not fit was not counted as refused");
    check(io.closed() == 1, "the socket that did not fit was not closed: a descriptor leaked");
}

} // namespace

int main() {
    test_a_full_shard_refuses_an_accepted_socket();
    test_a_socket_handed_over_is_served();

    if (failures != 0) {
        std::fprintf(stderr, "shard mail: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("shard mail: OK\n");
    return 0;
}
