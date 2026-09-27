/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_kick_queue.cpp
 * @brief
 * \~english The kick queue on one thread: coalescing, requeueing during a fill, and when gone is owed.
 * \~spanish La cola de avisos en un hilo: agrupar, volver a encolar durante un fill, y cuando se debe gone.
 * \~
 *
 * \~english
 * Every rule of HVX-5, 4.4 and 6, one at a time and deterministically.  What
 * the rules are for -- other threads -- is test_backend_wake; here each
 * interleaving that matters is written out by hand.
 * \~spanish
 * Cada regla de HVX-5, 4.4 y 6, una a una y de forma determinista.  Aquello
 * para lo que son las reglas -- otros hilos -- es test_backend_wake; aqui cada
 * intercalado que importa se escribe a mano.
 * \~
 */
#include "http_vx/kick_queue.h"
#include "http_vx/memory_backend.h"

#include <cstdio>

namespace {

using http_vx::BodySource;
using http_vx::GoneReason;
using http_vx::KickQueue;
using http_vx::KickTarget;
using http_vx::OpenResponse;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english A source that counts what it is told.  \~spanish Una fuente que cuenta lo que le dicen.  \~
class Counting final : public BodySource {
public:
    size_t fill(OpenResponse, uint8_t *, size_t, bool &) noexcept override { return 0; }
    void gone(OpenResponse, GoneReason why) noexcept override {
        ++gones;
        last = why;
    }
    int gones = 0;
    GoneReason last = GoneReason::Finished;
};

/// \~english A target that counts kicks, and may kick the source again from inside.
/// \~spanish Un destino que cuenta avisos, y puede volver a avisar a la fuente desde dentro.  \~
class Target final : public KickTarget {
public:
    void on_kick(BodySource &s) noexcept override {
        ++kicks;
        if (kick_again) {
            kick_again = false;
            s.kick();
        }
    }
    int kicks = 0;
    bool kick_again = false;
};

OpenResponse response(uint32_t slot) {
    OpenResponse r;
    r.conn.slot = slot;
    r.conn.life = 1;
    r.stream = 4;
    return r;
}

void test_a_source_not_opened_cannot_be_kicked() {
    Counting s;
    check(!s.kick(), "a source never opened took a kick");
}

void test_many_kicks_are_one() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting s;
    Target t;
    q.open(s, t, response(1));

    for (int i = 0; i < 1000; ++i) check(s.kick(), "a kick was refused");
    check(q.pending(), "the kick is not waiting");
    check(q.drain() == 1, "a thousand kicks were not one entry");
    check(t.kicks == 1, "the target was not told exactly once");
    check(q.counts().coalesced == 999, "the kicks that found it queued were not counted");
    check(q.drain() == 0 && t.kicks == 1, "a drained source came out again");
}

void test_a_kick_during_the_fill_is_not_lost() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting s;
    Target t;
    q.open(s, t, response(1));

    s.kick();
    t.kick_again = true;
    q.drain();
    check(t.kicks == 1, "the first kick was not handed on");
    // \~english The mark was cleared before the target ran: the kick inside queued it again.
    // \~spanish La marca se limpio antes de que corriera el destino: el aviso de dentro la volvio a meter.  \~
    check(q.pending(), "a kick made while filling was lost");
    q.drain();
    check(t.kicks == 2, "the requeued source was not handed on");
}

void test_gone_now_when_not_queued() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting s;
    Target t;
    q.open(s, t, response(1));

    q.close(s, GoneReason::PeerReset);
    check(s.gones == 1 && s.last == GoneReason::PeerReset, "gone was not delivered at once");
    check(!q.pending(), "an ended source is in the queue");
    s.kick();
    check(!q.pending(), "a kick after gone pushed the source");
    q.close(s, GoneReason::Shutdown);
    check(s.gones == 1, "gone was delivered twice");
    check(q.counts().gone[static_cast<size_t>(GoneReason::PeerReset)] == 1, "the reason was not counted");
}

void test_gone_waits_while_queued() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting s;
    Target t;
    q.open(s, t, response(1));

    s.kick();
    q.close(s, GoneReason::Finished);
    // \~english In the stack: the application may not free it yet, so gone must wait.
    // \~spanish En la pila: la aplicacion aun no puede liberarla, asi que gone tiene que esperar.  \~
    check(s.gones == 0, "gone was delivered while the source was still in the stack");
    q.drain();
    check(s.gones == 1 && s.last == GoneReason::Finished, "gone was not delivered when the source came out");
    check(t.kicks == 0, "an ended source was handed to its target");
    s.kick();
    check(!q.pending(), "a kick after gone pushed the source");
}

void test_sleeping_and_waking() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting s;
    Target t;
    q.open(s, t, response(1));

    check(q.about_to_sleep(), "an empty queue did not let the shard sleep");
    s.kick();
    check(io.wakes() == 1, "a kick to a sleeping shard did not wake it");
    q.awake();
    q.drain();
    s.kick();
    check(io.wakes() == 1, "a kick to an awake shard woke it");
    check(!q.about_to_sleep(), "a shard with a kick waiting went to sleep");
    check(q.counts().wakes == 1, "the wake was not counted");
}

void test_order_is_the_order_of_kicks() {
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    KickQueue q;
    q.reset(&io);
    Counting a;
    Counting b;
    Counting c;

    /// \~english Records the order it is told in.  \~spanish Apunta el orden en que se lo dicen.  \~
    class Order final : public KickTarget {
    public:
        void on_kick(BodySource &s) noexcept override { seen[n++] = s.response().conn.slot; }
        uint32_t seen[3] = {};
        int n = 0;
    } order;

    q.open(a, order, response(1));
    q.open(b, order, response(2));
    q.open(c, order, response(3));
    b.kick();
    c.kick();
    a.kick();
    q.drain();
    check(order.n == 3 && order.seen[0] == 2 && order.seen[1] == 3 && order.seen[2] == 1,
          "the stack came out in another order than the kicks went in");
}

} // namespace

int main() {
    test_a_source_not_opened_cannot_be_kicked();
    test_many_kicks_are_one();
    test_a_kick_during_the_fill_is_not_lost();
    test_gone_now_when_not_queued();
    test_gone_waits_while_queued();
    test_sleeping_and_waking();
    test_order_is_the_order_of_kicks();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("kick queue: OK\n");
    return 0;
}
