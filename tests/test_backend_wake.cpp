/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_backend_wake.cpp
 * @brief
 * \~english Every backend of this system woken from another thread, and no kick lost under many producers.
 * \~spanish Cada backend de este sistema despertado desde otro hilo, y ningun aviso perdido con muchos productores.
 * \~
 *
 * \~english
 * HVX-5, 6.  A lost wake does not fail: it leaves a shard asleep with a kick
 * waiting, and a response that never goes out.  So the shard here sleeps
 * with NO deadline -- a lost wake is a shard that never comes back -- and the
 * test keeps its own deadline to say so instead of hanging.
 *
 * The same cases run against every backend this system has, the stdio one
 * included: R8 says no backend is a path nobody runs.
 * \~spanish
 * HVX-5, 6.  Un despertar perdido no falla: deja a un fragmento dormido con un
 * aviso esperando, y una respuesta que no sale nunca.  Asi que aqui el
 * fragmento duerme SIN plazo -- un despertar perdido es un fragmento que no
 * vuelve nunca --, y la prueba tiene su propio plazo para decirlo en vez de
 * quedarse colgada.
 *
 * Los mismos casos corren contra cada backend que tiene este sistema, el de
 * stdio incluido: la R8 dice que ningun backend es un camino que no corre
 * nadie.
 * \~
 */
#include "http_vx/buffer_pool.h"
#include "http_vx/kick_queue.h"
#include "http_vx/stdio_backend.h"

#ifdef _WIN32
#include "http_vx/iocp_backend.h"

#include <fcntl.h>
#include <io.h>
#else
#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"

#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {

using http_vx::Backend;
using http_vx::BodySource;
using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::GoneReason;
using http_vx::KickQueue;
using http_vx::KickTarget;
using http_vx::OpenResponse;

using Clock = std::chrono::steady_clock;

int failures = 0;
const char *against = "?";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
    ++failures;
}

long ms_since(Clock::time_point t) {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count());
}

/// \~english What a blocked waiter reports.  \~spanish Lo que informa quien espera bloqueado.  \~
struct Blocked {
    Backend *io = nullptr;
    size_t made = 0;
    long waited_ms = 0;
};

/// \~english Waits with no deadline, as a shard with nothing to do.  \~spanish Espera sin plazo, como un fragmento sin nada que hacer.  \~
void wait_forever(Blocked *b) {
    Completion done[8];
    const Clock::time_point t = Clock::now();
    b->made = b->io->wait(done, 8, -1);
    b->waited_ms = ms_since(t);
}

/**
 * @brief
 * \~english A wait with no deadline returns when another thread wakes the backend.
 * \~spanish Una espera sin plazo vuelve cuando otro hilo despierta al backend.
 * \~
 */
void test_a_blocked_wait_is_woken(Backend &io) {
    Blocked b;
    b.io = &io;
    std::thread waiter(wait_forever, &b);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const Clock::time_point t = Clock::now();
    check(io.wake(), "the wake was refused");
    waiter.join();
    check(ms_since(t) < 2000, "the waiter took too long to come back");
    check(b.waited_ms >= 50, "the wait did not block at all before the wake");
}

/// \~english One source, counting what it produced and what the shard has seen.
/// \~spanish Una fuente, que cuenta lo que produjo y lo que ha visto el fragmento.  \~
class Counted final : public BodySource {
public:
    size_t fill(OpenResponse, uint8_t *, size_t, bool &) noexcept override { return 0; }
    void gone(OpenResponse, GoneReason) noexcept override {}
    std::atomic<uint64_t> produced{0};
    /// \~english Written by the shard, polled by the test's main thread: atomic.  \~spanish Lo escribe el fragmento y lo sondea el hilo principal de la prueba: atomico.  \~
    std::atomic<uint64_t> seen{0};
};

/// \~english The shard's side: on a kick, what the source has produced is seen.
/// \~spanish El lado del fragmento: al avisar, se ve lo que ha producido la fuente.  \~
class Seer final : public KickTarget {
public:
    void on_kick(BodySource &s) noexcept override {
        Counted &c = static_cast<Counted &>(s);
        c.seen.store(c.produced.load(std::memory_order_acquire), std::memory_order_release);
        ++kicks;
    }
    uint64_t kicks = 0;
};

/// \~english A shard's loop over one backend, as Shard::poll does it, until told to stop.
/// \~spanish El bucle de un fragmento sobre un backend, como lo hace Shard::poll, hasta que le digan que pare.  \~
struct Loop {
    Backend *io = nullptr;
    KickQueue *q = nullptr;
    std::atomic<bool> stop{false};
    /// \~english Turns of the loop: an idle shard makes none.  \~spanish Vueltas del bucle: un fragmento ocioso no da ninguna.  \~
    std::atomic<uint64_t> turns{0};
};

void run_loop(Loop *l) {
    Completion done[64];
    while (!l->stop.load(std::memory_order_acquire)) {
        const int ms = l->q->about_to_sleep() ? -1 : 0;
        l->io->wait(done, 64, ms);
        l->q->awake();
        l->q->drain();
        l->turns.fetch_add(1, std::memory_order_relaxed);
    }
}

/// \~english One producer: bumps each of its sources and kicks it, many times.
/// \~spanish Un productor: sube cada una de sus fuentes y la avisa, muchas veces.  \~
void produce(std::vector<Counted *> *sources, int rounds) {
    for (int r = 0; r < rounds; ++r) {
        for (Counted *s : *sources) {
            s->produced.fetch_add(1, std::memory_order_release);
            s->kick();
        }
        if ((r & 63) == 0) std::this_thread::yield();
    }
}

/**
 * @brief
 * \~english Many producers, many sources, a shard that sleeps without deadline: every kick is seen.
 * \~spanish Muchos productores, muchas fuentes, un fragmento que duerme sin plazo: cada aviso se ve.
 * \~
 */
void test_no_kick_is_lost(Backend &io) {
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 16;
    constexpr int kRounds = 4000;

    KickQueue q;
    q.reset(&io);
    Seer seer;
    std::vector<Counted> sources(kProducers * kPerProducer);
    std::vector<std::vector<Counted *>> mine(kProducers);
    for (size_t i = 0; i < sources.size(); ++i) {
        OpenResponse r;
        r.conn.slot = static_cast<uint32_t>(i);
        r.conn.life = 1;
        q.open(sources[i], seer, r);
        mine[i % kProducers].push_back(&sources[i]);
    }

    Loop loop;
    loop.io = &io;
    loop.q = &q;
    std::thread shard(run_loop, &loop);

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) producers.emplace_back(produce, &mine[p], kRounds);
    for (std::thread &t : producers) t.join();

    /* \~english
     * Every source must be seen at its last value, and soon: the shard sleeps
     * without a deadline, so a lost wake keeps it asleep with the last kicks
     * waiting.  The check is made by the kicks themselves -- a final kick per
     * source would wake it and hide the bug -- so none is added here.
     * \~spanish
     * Cada fuente se tiene que ver en su ultimo valor, y pronto: el fragmento
     * duerme sin plazo, asi que un despertar perdido lo deja dormido con los
     * ultimos avisos esperando.  Lo comprueban los propios avisos -- un aviso
     * final por fuente lo despertaria y taparia el fallo --, asi que aqui no se
     * anade ninguno.
     * \~ */
    const Clock::time_point t = Clock::now();
    bool all_seen = false;
    while (!all_seen && ms_since(t) < 3000) {
        all_seen = true;
        for (Counted &s : sources) {
            if (s.seen.load(std::memory_order_acquire) != s.produced.load(std::memory_order_acquire)) {
                all_seen = false;
                break;
            }
        }
        if (!all_seen) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    check(all_seen, "a kick was lost: a source was never seen at its last value");

    /* \~english
     * And with nothing left to do, the shard sleeps.  A wake left behind --
     * an eventfd never drained on a level-triggered queue, a "data" event
     * that keeps coming back -- would give the same results while spinning a
     * core, and only this sees it.
     * \~spanish
     * Y sin nada que hacer, el fragmento duerme.  Un despertar que se queda
     * atras -- un eventfd sin vaciar en una cola por nivel, un suceso de "datos"
     * que vuelve una y otra vez -- daria los mismos resultados con un nucleo
     * dando vueltas, y solo esto lo ve.
     * \~ */
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const uint64_t before = loop.turns.load(std::memory_order_relaxed);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    check(loop.turns.load(std::memory_order_relaxed) - before < 5, "the idle shard spins instead of sleeping");

    loop.stop.store(true, std::memory_order_release);
    io.wake();
    shard.join();

    const http_vx::KickCounts c = q.counts();
    check(c.failed_wakes == 0, "a wake could not be delivered");
    const uint64_t kicks = static_cast<uint64_t>(kProducers) * kPerProducer * kRounds;
    std::printf("  %s: %llu kicks, %llu taken, %llu wakes\n", against,
                static_cast<unsigned long long>(kicks), static_cast<unsigned long long>(c.taken),
                static_cast<unsigned long long>(c.wakes));
    check(c.wakes < kicks / 10, "wakes were not coalesced");
}

/// \~english The same cases against one backend.  \~spanish Los mismos casos contra un backend.  \~
void run_all(Backend &io, const char *name) {
    against = name;
    test_a_blocked_wait_is_woken(io);
    test_no_kick_is_lost(io);
}

/// \~english Writes all of @p s to @p fd.  \~spanish Escribe todo @p s en @p fd.  \~
bool put(int fd, const char *s, unsigned n) {
#ifdef _WIN32
    return _write(fd, s, n) == static_cast<int>(n);
#else
    return write(fd, s, n) == static_cast<ssize_t>(n);
#endif
}

/// \~english Closes @p fd.  \~spanish Cierra @p fd.  \~
void close_fd(int fd) {
#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif
}

/**
 * @brief
 * \~english The stdio backend, with a read of an empty pipe pending: a wake ends it without losing it.
 * \~spanish El backend de stdio, con una lectura pendiente de una tuberia vacia: un despertar la acaba sin perderla.
 * \~
 */
void test_stdio(int read_fd, int write_fd) {
    BufferPool pool;
    check(pool.reset(4, 4096), "the pool would not start");
    http_vx::StdioBackend io(pool, read_fd, write_fd);
    check(io.ready(), "the stdio backend's wake could not be made");

    http_vx::Op read;
    read.kind = http_vx::OpKind::Recv;
    read.buffer = pool.acquire();
    read.length = 64;
    check(io.submit(read), "the read was not taken");

    run_all(io, "stdio");
    check(io.pending() == 1, "a woken read was lost instead of kept pending");

    /* \~english
     * The read every wake cut short is still the SAME read: what the peer
     * says now lands once, where it was reserved, and the next read gets the
     * next thing said.  Starting the read again on each wait would read twice
     * -- the second time over bytes already handed up.
     * \~spanish
     * La lectura que cada despertar corto sigue siendo la MISMA: lo que diga
     * ahora el otro extremo llega una vez, donde se reservo, y la lectura
     * siguiente recibe lo siguiente que diga.  Volver a empezar la lectura en
     * cada espera leeria dos veces -- la segunda sobre bytes ya entregados.
     * \~ */
    Completion done[2];
    check(io.wait(done, 2, 0) == 0, "an empty pipe answered a read");
    check(put(write_fd, "abc", 3), "the pipe could not be written");
    check(io.wait(done, 2, 2000) == 1 && done[0].result == 3, "the woken read did not get what came after");
    check(io.submit(read), "the second read was not taken");
    check(put(write_fd, "def", 3), "the pipe could not be written");
    check(io.wait(done, 2, 2000) == 1 && done[0].result == 3, "the second read did not get what came next");
    const http_vx::Buffer *b = pool.at(read.buffer);
    check(b->size() == 6 && std::memcmp(b->data(), "abcdef", 6) == 0, "the bytes were read twice or out of place");

    /* \~english
     * The peer closing its end is the end of the stream, not an error -- on
     * Windows a read of a pipe whose writer is gone fails with
     * ERROR_BROKEN_PIPE, and that has to come up as a zero.
     * \~spanish
     * Que el otro extremo cierre su lado es el fin del flujo, no un error -- en
     * Windows la lectura de una tuberia sin escritor falla con
     * ERROR_BROKEN_PIPE, y eso tiene que subir como un cero.
     * \~ */
    check(io.submit(read), "the last read was not taken");
    close_fd(write_fd);
    check(io.wait(done, 2, 2000) == 1 && done[0].result == 0, "a closed peer was not the end of the stream");
    check(io.ended(), "the end of the stream was not noticed");
}

} // namespace

int main() {
#ifdef _WIN32
    {
        BufferPool pool;
        check(pool.reset(4, 4096), "the pool would not start");
        http_vx::IocpBackend io;
        check(io.reset(pool, 64), "iocp would not start");
        run_all(io, http_vx::IocpBackend::kName);
    }
    int fds[2];
    if (_pipe(fds, 4096, _O_BINARY) == 0) {
        test_stdio(fds[0], fds[1]);
        _close(fds[0]);
    } else {
        check(false, "a pipe could not be made");
    }
#else
    {
        BufferPool pool;
        check(pool.reset(4, 4096), "the pool would not start");
        http_vx::EpollBackend io;
        check(io.reset(pool, 1024), "epoll would not start");
        run_all(io, http_vx::EpollBackend::kName);
    }
    if (http_vx::uring_available()) {
        BufferPool pool;
        check(pool.reset(4, 4096), "the pool would not start");
        http_vx::UringBackend io;
        check(io.reset(pool, 256), "io_uring would not start");
        run_all(io, http_vx::UringBackend::kName);
    } else {
        std::printf("  -- io_uring: SKIPPED, this kernel gives no ring --\n");
    }
    int fds[2];
    if (pipe(fds) == 0) {
        test_stdio(fds[0], fds[1]);
        close(fds[0]);
    } else {
        check(false, "a pipe could not be made");
    }
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("backend wake: OK\n");
    return 0;
}
