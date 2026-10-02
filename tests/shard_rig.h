/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/shard_rig.h
 * @brief
 * \~english A shard on its own thread over a backend that really sleeps, for the tests of what shards say to each other.
 * \~spanish Un fragmento en su propio hilo sobre un backend que de verdad duerme, para las pruebas de lo que se dicen los fragmentos.
 * \~
 *
 * \~english
 * The memory backend never blocks, so it cannot show a shard that sleeps and a
 * wake that is lost.  @c SleepyBackend is the memory backend with a real wait:
 * it blocks on a condition until @c wake, with the contract of the real ones --
 * a wake that finds nobody waiting makes the next wait return early, once.
 * @c Rig runs a shard on a thread over it, or over the real backend of the
 * platform (IOCP, epoll, io_uring).
 * \~spanish
 * El backend de memoria no bloquea nunca, asi que no puede mostrar un fragmento
 * que duerme ni un despertar perdido.  @c SleepyBackend es el backend de
 * memoria con una espera de verdad: bloquea en una condicion hasta @c wake, con
 * el contrato de los de verdad -- un despertar que no encuentra a nadie
 * esperando hace que la espera siguiente vuelva antes, una vez.  @c Rig corre un
 * fragmento en un hilo sobre el, o sobre el backend real de la plataforma
 * (IOCP, epoll, io_uring).
 * \~
 */
#ifndef HTTP_VX_TESTS_SHARD_RIG_H
#define HTTP_VX_TESTS_SHARD_RIG_H

#include "http_vx/memory_backend.h"
#include "http_vx/shard.h"

#ifdef _WIN32
#include "http_vx/iocp_backend.h"
#else
#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

namespace rig {

using Clock = std::chrono::steady_clock;

/// \~english Milliseconds since @p t.  \~spanish Milisegundos desde @p t.  \~
inline long ms_since(Clock::time_point t) {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count());
}

/**
 * @brief
 * \~english The memory backend with a wait that blocks until woken.
 * \~spanish El backend de memoria con una espera que bloquea hasta que la despierten.
 * \~
 */
class SleepyBackend final : public http_vx::Backend {
public:
    explicit SleepyBackend(http_vx::BufferPool &pool) noexcept : inner_(pool) {}

    bool submit(const http_vx::Op &op) noexcept override {
        if (op.kind == http_vx::OpKind::Close) close_submits_.fetch_add(1, std::memory_order_relaxed);
        return inner_.submit(op);
    }

    /// \~english How many closes the shard asked for: the memory backend closes nothing, so this is what shows a socket was let go.  \~spanish Cuantos cierres pidio el fragmento: el backend de memoria no cierra nada, asi que esto es lo que muestra que se solto un socket.  \~
    uint64_t close_submits() const noexcept { return close_submits_.load(std::memory_order_relaxed); }

    bool wake() noexcept override {
        {
            std::lock_guard<std::mutex> g(lock_);
            woken_ = true;
        }
        woken_cv_.notify_one();
        return true;
    }

    size_t wait(http_vx::Completion *out, size_t cap, int timeout_ms) noexcept override {
        const size_t ready = inner_.wait(out, cap, 0);
        if (ready != 0 || timeout_ms == 0) return ready;

        std::unique_lock<std::mutex> g(lock_);
        while (!woken_) {
            if (timeout_ms < 0) {
                woken_cv_.wait(g);
            } else if (woken_cv_.wait_for(g, std::chrono::milliseconds(timeout_ms)) == std::cv_status::timeout) {
                break;
            }
        }
        woken_ = false;
        g.unlock();
        return inner_.wait(out, cap, 0);
    }

    const char *name() const noexcept override { return "sleepy-memory"; }

    http_vx::MemoryBackend &memory() noexcept { return inner_; }

private:
    http_vx::MemoryBackend inner_;
    std::mutex lock_;
    std::condition_variable woken_cv_;
    bool woken_ = false;
    std::atomic<uint64_t> close_submits_{0};
};

/**
 * @brief
 * \~english A service that remembers who was adopted, in order, and closes each after the turn.
 * \~spanish Un servicio que recuerda a quien se adopto, en orden, y cierra a cada uno tras la vuelta.
 * \~
 *
 * \~english
 * A socket handed over as @c p * 100000 + seq says which sender it came from
 * and which of its messages it was, so the order a sender's messages arrive in
 * can be read off the connection table.
 * \~spanish
 * Un socket pasado como @c p * 100000 + seq dice de que remitente vino y cual
 * de sus mensajes era, asi que el orden en que llegan los mensajes de un
 * remitente se lee de la tabla de conexiones.
 * \~
 */
class Recorder final : public http_vx::Service {
public:
    static constexpr int kProducers = 8;

    bool on_bytes(http_vx::ConnHandle, http_vx::Buffer &in, http_vx::Buffer &out) noexcept override {
        // \~english Echoes, so a request through an adopted socket is served.  \~spanish Repite, para que una peticion por un socket adoptado se sirva.  \~
        const size_t n = in.size();
        uint8_t *room = out.reserve(n);
        if (room == nullptr) return false;
        for (size_t i = 0; i < n; ++i) room[i] = in.data()[i];
        out.commit(n);
        in.consume(n);
        ++echoed;
        return true;
    }

    void on_open(http_vx::ConnHandle c) noexcept override {
        const http_vx::ConnHot *h = shard->conns().hot(c);
        const int32_t fd = h != nullptr ? h->fd : -1;
        const int p = fd / 100000;
        const int seq = fd % 100000;

        if (check_order && p >= 0 && p < kProducers) {
            if (seq <= last[p]) disorder.fetch_add(1, std::memory_order_relaxed);
            last[p] = seq;
        }
        if (fd >= 0) to_close.push_back(c);
        opened.fetch_add(1, std::memory_order_release);
    }

    /// \~english Closes what was adopted this turn; the shard's thread, after a poll.  \~spanish Cierra lo adoptado en esta vuelta; el hilo del fragmento, tras un poll.  \~
    void sweep() noexcept {
        if (!close_after_turn) {
            to_close.clear();
            return;
        }
        for (const http_vx::ConnHandle c : to_close) shard->close(c);
        to_close.clear();
    }

    http_vx::Shard *shard = nullptr;
    bool close_after_turn = true;
    /// \~english Whether the fd names its sender and sequence: only for fds a test made up.  \~spanish Si el fd nombra su remitente y su secuencia: solo para fds que invento la prueba.  \~
    bool check_order = true;
    int last[kProducers] = {-1, -1, -1, -1, -1, -1, -1, -1};
    std::atomic<uint64_t> opened{0};
    std::atomic<uint64_t> disorder{0};
    std::atomic<uint64_t> echoed{0};
    std::vector<http_vx::ConnHandle> to_close;
};

/**
 * @brief
 * \~english One shard, its backend and its thread.
 * \~spanish Un fragmento, su backend y su hilo.
 * \~
 */
class Rig {
public:
    /// \~english Which backends a run has: the sleeping memory one, and every real one of the platform.  \~spanish Que backends tiene una corrida: el de memoria que duerme, y cada uno de los reales de la plataforma.  \~
#ifdef _WIN32
    static constexpr int kBackends = 2;
#else
    static constexpr int kBackends = 3;
#endif

    /// \~english The name of backend @p which.  \~spanish El nombre del backend @p which.  \~
    static const char *name_of(int which) {
        if (which == 0) return "sleepy-memory";
#ifdef _WIN32
        return http_vx::IocpBackend::kName;
#else
        return which == 1 ? http_vx::EpollBackend::kName : http_vx::UringBackend::kName;
#endif
    }

    Rig() { service.shard = &shard; }

    /// \~english A test that failed must not leave its shard asleep behind a thread that is still joinable.  \~spanish Una prueba que fallo no debe dejar a su fragmento dormido tras un hilo que todavia se puede esperar.  \~
    ~Rig() {
        if (!thread.joinable()) return;
        quit.store(true, std::memory_order_release);
        if (io != nullptr) io->wake();
        thread.join();
    }

    /**
     * @brief
     * \~english Starts the shard over backend @p which; no thread yet.
     * \~spanish Arranca el fragmento sobre el backend @p which; todavia sin hilo.
     * \~
     *
     * @param streams \~english false: a shard with no stream side, which refuses what it is handed  \~spanish false: un fragmento sin lado de flujos, que rechaza lo que le pasan  \~
     */
    bool start(int which, http_vx::ShardConfig cfg, bool streams = true) {
        if (which == 0) {
            io = &sleepy;
#ifdef _WIN32
        } else {
            if (!iocp.reset(shard.buffers(), 4096)) return false;
            io = &iocp;
#else
        } else if (which == 1) {
            if (!epoll.reset(shard.buffers(), 4096)) return false;
            io = &epoll;
        } else {
            if (!uring.reset(shard.buffers(), 1024)) return false;
            io = &uring;
#endif
        }
        return streams ? shard.reset(cfg, *io, service, 0) : shard.reset(cfg, *io, 0);
    }

    /// \~english Runs the shard's loop on a thread: it waits with no deadline, as a shard with nothing to do.  \~spanish Corre el bucle del fragmento en un hilo: espera sin plazo, como un fragmento sin nada que hacer.  \~
    void launch() { thread = std::thread(loop, this); }

    /// \~english Waits for the loop to end (a @c Stop was handled), up to @p ms.  \~spanish Espera a que acabe el bucle (se atendio un @c Stop), hasta @p ms.  \~
    bool join(long ms) {
        const Clock::time_point t = Clock::now();
        while (!exited.load(std::memory_order_acquire) && ms_since(t) < ms) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!exited.load(std::memory_order_acquire)) return false;
        thread.join();
        return true;
    }

    http_vx::Shard shard;
    Recorder service;
    SleepyBackend sleepy{shard.buffers()};
#ifdef _WIN32
    http_vx::IocpBackend iocp;
#else
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
#endif
    http_vx::Backend *io = nullptr;
    std::thread thread;

    /// \~english Turns of the loop: an idle shard makes none.  \~spanish Vueltas del bucle: un fragmento ocioso no da ninguna.  \~
    std::atomic<uint64_t> turns{0};
    std::atomic<bool> exited{false};
    std::atomic<bool> quit{false};

private:
    static void loop(Rig *r) {
        while (!r->shard.stop_requested() && !r->quit.load(std::memory_order_acquire)) {
            r->shard.poll(1, -1);
            r->service.sweep();
            r->turns.fetch_add(1, std::memory_order_relaxed);
        }
        r->exited.store(true, std::memory_order_release);
    }
};

} // namespace rig

#endif // HTTP_VX_TESTS_SHARD_RIG_H
