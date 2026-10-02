/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_mailbox.cpp
 * @brief
 * \~english The mailbox between shards: its pools and return path, and a shard that sleeps with both stacks to watch.
 * \~spanish El buzon entre fragmentos: sus pozos y su camino de vuelta, y un fragmento que duerme con las dos pilas que vigilar.
 * \~
 *
 * \~english
 * HVX-6, 6.  The first half is on one thread, case by case: a pool that runs
 * out refuses and counts, a node goes back to the pool it came from, the
 * oldest message is served first, and the kick queue and the mailbox share ONE
 * "sleeping" mark.  The second half is what that is for: producers on other
 * threads against a shard that sleeps with NO deadline -- a lost wake is a
 * shard that never comes back, and the test keeps its own deadline to say so --
 * over the sleeping memory backend and every real backend of the platform.
 * \~spanish
 * HVX-6, 6.  La primera mitad es en un hilo, caso a caso: un pozo que se
 * agota rechaza y cuenta, un nodo vuelve al pozo del que salio, se atiende
 * primero el mensaje mas antiguo, y la cola de avisos y el buzon comparten UNA
 * marca de "durmiendo".  La segunda es para lo que sirve eso: productores en
 * otros hilos contra un fragmento que duerme SIN plazo -- un despertar perdido
 * es un fragmento que no vuelve nunca, y la prueba tiene su propio plazo para
 * decirlo -- sobre el backend de memoria que duerme y cada backend real de la
 * plataforma.
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
#else
#include <sys/socket.h>
#endif

#include "shard_rig.h"

#include <cstdio>
#include <vector>

namespace {

using http_vx::BodySource;
using http_vx::GoneReason;
using http_vx::KickQueue;
using http_vx::KickTarget;
using http_vx::MailKind;
using http_vx::MailNode;
using http_vx::MailPool;
using http_vx::Mailbox;
using http_vx::OpenResponse;
using http_vx::ShardConfig;
using http_vx::ShardWake;
using rig::Clock;
using rig::ms_since;

int failures = 0;
const char *against = "-";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
    ++failures;
}

/// \~english A real socket the shard will close, or -1.  \~spanish Un socket real que cerrara el fragmento, o -1.  \~
int32_t make_socket() {
#ifdef _WIN32
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    return s == INVALID_SOCKET ? -1 : static_cast<int32_t>(s);
#else
    return ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
}

/// \~english Collects a taken list into an array, because @c give_back overwrites the links.  \~spanish Recoge una lista sacada en un array, porque @c give_back pisa los enlaces.  \~
size_t collect(MailNode *list, MailNode **out, size_t cap) {
    size_t k = 0;
    while (list != nullptr && k < cap) {
        MailNode *next = list->next;
        out[k++] = list;
        list = next;
    }
    return k;
}

/* ------------------------------------------------------------------------- *
 * One thread.
 * ------------------------------------------------------------------------- */

/// \~english A pool that runs out refuses the send and counts it; what comes back is sendable again; oldest first.  \~spanish Un pozo que se agota rechaza el envio y lo cuenta; lo que vuelve se puede volver a mandar; el mas antiguo primero.  \~
void test_exhaustion_fifo_and_return() {
    against = "pool";
    ShardWake wake;
    wake.reset(nullptr);
    Mailbox box;
    box.reset(wake);
    MailPool pool;
    check(pool.reset(4), "the pool would not start");

    check(!box.pending() && box.take_all() == nullptr, "an empty mailbox gave something");

    for (int i = 0; i < 4; ++i) check(pool.send(box, MailKind::AdoptSocket, 10 + i), "a send with nodes free was refused");
    check(!pool.send(box, MailKind::AdoptSocket, 99), "a send with no node free was taken");
    check(pool.counts().sent == 4 && pool.counts().refused == 1, "sent and refused were not counted");
    check(pool.free_count() == 0, "the pool says it has nodes");

    MailNode *got[4] = {};
    check(box.pending(), "the messages are not waiting");
    check(collect(box.take_all(), got, 4) == 4, "not every message came out");
    for (int i = 0; i < 4; ++i) check(got[i]->fd == 10 + i, "the oldest message was not first");
    check(box.counts().received == 4, "the mailbox did not count what it took");
    check(box.counts().by_kind[static_cast<size_t>(MailKind::AdoptSocket)] == 4, "the mailbox did not count by kind");

    // \~english Handled but not given back: still away.  \~spanish Atendidos pero sin devolver: siguen fuera.  \~
    check(!pool.send(box, MailKind::Stop, -1), "a node that is still away was sent again");
    check(pool.counts().refused == 2, "the second refusal was not counted");

    MailPool::give_back(*got[0]);
    MailPool::give_back(*got[1]);
    check(pool.send(box, MailKind::Stop, -1), "a node that came back could not be sent");
    check(pool.send(box, MailKind::Stop, -1), "the second node that came back could not be sent");
    check(!pool.send(box, MailKind::Stop, -1), "more nodes were sent than came back");
    check(pool.counts().returned == 2, "the returned nodes were not counted");

    MailNode *again[4] = {};
    const size_t k = collect(box.take_all(), again, 4);
    check(k == 2 && again[0]->kind == MailKind::Stop, "the new messages did not come out");
    for (size_t i = 0; i < k; ++i) MailPool::give_back(*again[i]);
    MailPool::give_back(*got[2]);
    MailPool::give_back(*got[3]);
    check(pool.release() == 0, "a pool with every node home kept its memory");
}

/// \~english Each node goes back to the pool it was taken from, never to another.  \~spanish Cada nodo vuelve al pozo del que se saco, nunca a otro.  \~
void test_nodes_go_home() {
    against = "two pools";
    ShardWake wake;
    wake.reset(nullptr);
    Mailbox box;
    box.reset(wake);
    MailPool a;
    MailPool b;
    check(a.reset(2) && b.reset(3), "the pools would not start");

    check(a.send(box, MailKind::AdoptSocket, 1) && b.send(box, MailKind::AdoptSocket, 2) &&
              a.send(box, MailKind::AdoptSocket, 3) && b.send(box, MailKind::AdoptSocket, 4),
          "the sends were refused");

    MailNode *got[4] = {};
    check(collect(box.take_all(), got, 4) == 4, "not every message came out");
    check(got[0]->fd == 1 && got[1]->fd == 2 && got[2]->fd == 3 && got[3]->fd == 4,
          "the messages of two senders did not come out in the order they were sent");
    check(got[0]->home == &a && got[1]->home == &b, "a node does not know its pool");

    for (int i = 0; i < 4; ++i) MailPool::give_back(*got[i]);

    check(a.reclaim() == 2, "pool A did not get exactly its own nodes back");
    check(b.reclaim() == 2, "pool B did not get exactly its own nodes back");
    check(a.free_count() == 2 && b.free_count() == 3, "a pool's free list is not its own nodes");
    check(a.counts().returned == 2 && b.counts().returned == 2, "returns were counted on the wrong pool");
}

/// \~english A pool with a node still away keeps its block, and says how many; once home it frees.  \~spanish Un pozo con un nodo todavia fuera conserva su bloque, y dice cuantos; en casa, libera.  \~
void test_release_with_a_node_away() {
    against = "release";
    ShardWake wake;
    wake.reset(nullptr);
    Mailbox box;
    box.reset(wake);
    MailPool pool;
    check(pool.reset(2), "the pool would not start");
    check(pool.send(box, MailKind::Stop, -1), "the send was refused");

    check(pool.release() == 1 && pool.capacity() == 2, "a node still away was freed under its receiver");
    MailNode *got[1] = {};
    check(collect(box.take_all(), got, 1) == 1, "the message did not come out");
    MailPool::give_back(*got[0]);
    check(pool.release() == 0 && pool.capacity() == 0, "a pool with every node home was not freed");
}

class Counting final : public BodySource {
public:
    size_t fill(OpenResponse, uint8_t *, size_t, bool &) noexcept override { return 0; }
    void gone(OpenResponse, GoneReason) noexcept override {}
    std::atomic<uint64_t> produced{0};
    std::atomic<uint64_t> seen{0};
};

class Seer final : public KickTarget {
public:
    void on_kick(BodySource &s) noexcept override {
        Counting &c = static_cast<Counting &>(s);
        c.seen.store(c.produced.load(std::memory_order_acquire), std::memory_order_release);
    }
};

/// \~english Kicks and mail wake through the same mark: one wake per sleep, whichever pushes first.  \~spanish Los avisos y el correo despiertan por la misma marca: un despertar por sueno, empuje quien empuje primero.  \~
void test_one_mark_for_both_stacks() {
    against = "one mark";
    http_vx::BufferPool pool;
    http_vx::MemoryBackend io(pool);
    ShardWake wake;
    wake.reset(&io);
    Mailbox box;
    box.reset(wake);
    KickQueue q;
    q.reset(wake);
    MailPool mail;
    check(mail.reset(8), "the pool would not start");
    Counting src;
    Seer seer;
    OpenResponse r;
    r.conn.slot = 1;
    r.conn.life = 1;
    q.open(src, seer, r);

    // \~english Awake: nothing to wake.  \~spanish Despierto: nada que despertar.  \~
    check(mail.send(box, MailKind::Stop, -1), "a send was refused");
    check(io.wakes() == 0, "a shard that was awake was woken");

    wake.publish_sleeping();
    check(mail.send(box, MailKind::Stop, -1) && io.wakes() == 1, "a message did not wake a sleeping shard");
    check(mail.send(box, MailKind::Stop, -1) && io.wakes() == 1, "a second message woke the shard again");

    wake.publish_sleeping();
    check(q.kick(src) && io.wakes() == 2, "a kick did not wake a sleeping shard");

    // \~english A message and a kick while it sleeps: the first one pays the wake, the other finds the mark clear.  \~spanish Un mensaje y un aviso mientras duerme: el primero paga el despertar, el otro encuentra la marca limpia.  \~
    wake.publish_sleeping();
    src.produced.store(1);
    check(mail.send(box, MailKind::Stop, -1), "a send was refused");
    q.drain();
    src.produced.store(2);
    check(q.kick(src), "a kick was refused");
    check(io.wakes() == 3, "a message and a kick woke a sleeping shard more than once");

    check(q.counts().wakes == wake.counts().wakes && wake.counts().wakes == 3, "the kick queue does not report the shared wake");
    check(wake.counts().failed_wakes == 0, "a wake failed");
}

/// \~english A backend whose wake always fails, as one that cannot signal.  \~spanish Un backend cuyo despertar siempre falla, como uno que no puede avisar.  \~
class DeafBackend final : public http_vx::Backend {
public:
    bool submit(const http_vx::Op &) noexcept override { return true; }
    bool wake() noexcept override { return false; }
    size_t wait(http_vx::Completion *, size_t, int) noexcept override { return 0; }
    const char *name() const noexcept override { return "deaf"; }
};

/// \~english A wake the backend cannot deliver is counted and said, to the sender; the message is still queued.  \~spanish Un despertar que el backend no puede entregar se cuenta y se le dice al remitente; el mensaje queda en la cola igual.  \~
void test_a_failed_wake_is_counted() {
    against = "failed wake";
    DeafBackend io;
    ShardWake wake;
    wake.reset(&io);
    Mailbox box;
    box.reset(wake);
    MailPool pool;
    check(pool.reset(2), "the pool would not start");

    // \~english Awake: no wake is needed, so none can fail.  \~spanish Despierto: no hace falta despertar, asi que ninguno puede fallar.  \~
    MailNode *got[2] = {};
    check(pool.send(box, MailKind::Stop, -1) && wake.counts().failed_wakes == 0, "a send to an awake shard failed a wake");

    wake.publish_sleeping();
    check(pool.send(box, MailKind::Stop, -1), "a send whose wake failed was refused: the message is queued all the same");
    check(wake.counts().wakes == 1 && wake.counts().failed_wakes == 1, "a wake that could not be delivered was not counted");
    check(box.pending() && collect(box.take_all(), got, 2) == 2, "the messages are not both queued");
}

/* ------------------------------------------------------------------------- *
 * A shard that sleeps with nobody to wake it but the producers.
 * ------------------------------------------------------------------------- */

/// \~english What a sending thread does: its own pool, its messages, retrying while the pool is dry.  \~spanish Lo que hace un hilo que manda: su pozo, sus mensajes, reintentando mientras el pozo esta seco.  \~
struct SendJob {
    MailPool pool;
    http_vx::Mailbox *to = nullptr;
    int index = 0;
    int count = 0;
    bool real_sockets = false;
    uint64_t dry = 0;
    int made = 0;
    /// \~english The sender gave up waiting for a free node: the shard stopped handling its messages.  \~spanish El remitente dejo de esperar un nodo libre: el fragmento dejo de atender sus mensajes.  \~
    bool gave_up = false;
};

void send_all(SendJob *j) {
    for (int i = 0; i < j->count; ++i) {
        // \~english Made up for the memory backend, which closes nothing; real where a close is real.  \~spanish Inventado para el backend de memoria, que no cierra nada; real donde un cierre es real.  \~
        const int32_t fd = j->real_sockets ? make_socket() : (j->index + 1) * 100000 + i;
        if (fd < 0) continue;

        // \~english A pool that never refills is a shard that stopped; waiting for ever would hang the test instead of failing it.
        // \~spanish Un pozo que no se rellena nunca es un fragmento que se paro; esperar para siempre colgaria la prueba en vez de fallarla.  \~
        const Clock::time_point since = Clock::now();
        while (!j->pool.send(*j->to, MailKind::AdoptSocket, fd)) {
            ++j->dry;
            if (ms_since(since) > 5000) {
                j->gave_up = true;
                return;
            }
            std::this_thread::yield();
        }
        ++j->made;
    }
}

/// \~english What a kicking thread does: bumps each source and kicks it, many times.  \~spanish Lo que hace un hilo que avisa: sube cada fuente y la avisa, muchas veces.  \~
struct KickJob {
    std::vector<Counting *> sources;
    int rounds = 0;
};

void kick_all(KickJob *j) {
    for (int r = 0; r < j->rounds; ++r) {
        for (Counting *s : j->sources) {
            s->produced.fetch_add(1, std::memory_order_release);
            s->kick();
        }
        if ((r & 63) == 0) std::this_thread::yield();
    }
}

/// \~english Waits until every pool has all its nodes back, which only happens if the shard handled every message.  \~spanish Espera a que cada pozo tenga todos sus nodos de vuelta, que solo pasa si el fragmento atendio cada mensaje.  \~
bool all_home(std::vector<SendJob *> &jobs, long ms) {
    const Clock::time_point t = Clock::now();
    for (;;) {
        bool home = true;
        for (SendJob *j : jobs) {
            j->pool.reclaim();
            if (j->pool.free_count() != j->pool.capacity()) home = false;
        }
        if (home) return true;
        if (ms_since(t) >= ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// \~english The shard went to sleep: no turns while nothing happens.  \~spanish El fragmento se durmio: ninguna vuelta mientras no pasa nada.  \~
void check_idle(rig::Rig &r) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const uint64_t before = r.turns.load(std::memory_order_relaxed);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    check(r.turns.load(std::memory_order_relaxed) - before < 5, "the idle shard spins instead of sleeping");
}

/// \~english Stops the shard through its mailbox, as the group does, and waits for its loop to end.  \~spanish Para el fragmento por su buzon, como hace el grupo, y espera a que acabe su bucle.  \~
bool stop_through_mail(rig::Rig &r) {
    MailPool control;
    if (!control.reset(2)) return false;
    if (!control.send(r.shard.mailbox(), MailKind::Stop, -1)) return false;
    const bool ended = r.join(3000);
    if (ended) {
        control.reclaim();
        check(control.free_count() == control.capacity(), "the stop message did not go home");
    }
    return ended;
}

/// \~english Waits until every source shows its last value.  \~spanish Espera a que cada fuente muestre su ultimo valor.  \~
bool all_seen(std::vector<Counting> &sources, long ms) {
    const Clock::time_point t = Clock::now();
    for (;;) {
        bool done = true;
        for (Counting &s : sources)
            if (s.seen.load(std::memory_order_acquire) != s.produced.load(std::memory_order_acquire)) done = false;
        if (done) return true;
        if (ms_since(t) >= ms) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/**
 * @brief
 * \~english Mail and kicks from other threads at once, a shard asleep with no deadline: nothing lost.
 * \~spanish Correo y avisos desde otros hilos a la vez, un fragmento dormido sin plazo: no se pierde nada.
 * \~
 *
 * \~english
 * A shard with no stream side refuses every socket it is handed and closes it,
 * which makes each message observable as a count.  Nothing nudges the shard at
 * the end: the last messages and kicks must wake it by themselves.
 * \~spanish
 * Un fragmento sin lado de flujos rechaza cada socket que le pasan y lo cierra,
 * lo que hace cada mensaje observable como una cuenta.  Al final nada empuja al
 * fragmento: los ultimos mensajes y avisos tienen que despertarlo solos.
 * \~
 */
void test_mail_and_kicks_wake_a_sleeping_shard(int which) {
    against = rig::Rig::name_of(which);

    constexpr int kSenders = 2;
    constexpr int kPerSender = 400;
    constexpr int kKickers = 2;
    constexpr int kSourcesPerKicker = 4;
    constexpr int kRounds = 3000;

    rig::Rig r;
    ShardConfig cfg;
    cfg.connections = 64;
    cfg.buffers = 16;
    cfg.wheel_slots = 64;
    if (!r.start(which, cfg, false)) {
        check(false, "the shard would not start");
        return;
    }

    std::vector<Counting> sources(kKickers * kSourcesPerKicker);
    Seer seer;
    for (size_t i = 0; i < sources.size(); ++i) {
        OpenResponse resp;
        resp.conn.slot = static_cast<uint32_t>(i);
        resp.conn.life = 1;
        r.shard.kicks().open(sources[i], seer, resp);
    }

    std::vector<SendJob> senders(kSenders);
    std::vector<SendJob *> pools;
    for (int i = 0; i < kSenders; ++i) {
        // \~english Small pools: they run dry and are refilled by the return path, many times over.  \~spanish Pozos pequenos: se quedan secos y los rellena el camino de vuelta, muchas veces.  \~
        check(senders[i].pool.reset(8), "a sender's pool would not start");
        senders[i].to = &r.shard.mailbox();
        senders[i].index = i;
        senders[i].count = kPerSender;
        senders[i].real_sockets = which != 0;
        pools.push_back(&senders[i]);
    }
    std::vector<KickJob> kickers(kKickers);
    for (int k = 0; k < kKickers; ++k) {
        kickers[k].rounds = kRounds;
        for (int s = 0; s < kSourcesPerKicker; ++s) kickers[k].sources.push_back(&sources[k * kSourcesPerKicker + s]);
    }

    r.launch();

    std::vector<std::thread> threads;
    for (SendJob &j : senders) threads.emplace_back(send_all, &j);
    for (KickJob &j : kickers) threads.emplace_back(kick_all, &j);
    for (std::thread &t : threads) t.join();

    for (const SendJob &j : senders) check(!j.gave_up, "a sender waited 5 s for a free node: the shard stopped handling its messages");
    check(all_home(pools, 5000), "a message was never handled: its node did not come home");
    check(all_seen(sources, 5000), "a kick was lost: a source was never seen at its last value");
    check_idle(r);

    uint64_t sent = 0;
    uint64_t dry = 0;
    for (SendJob &j : senders) {
        sent += static_cast<uint64_t>(j.made);
        dry += j.dry;
        check(j.pool.counts().sent == static_cast<uint64_t>(j.made), "a pool's sent count is not what it sent");
        check(j.pool.counts().refused == j.dry, "a pool's refusals were not all counted");
        check(j.pool.counts().returned == static_cast<uint64_t>(j.made), "not every node was counted as returned");
    }
    // \~english Only where making a message is cheap: a real socket per message slows the sender enough for the pool never to run dry.
    // \~spanish Solo donde hacer un mensaje es barato: un socket real por mensaje frena al remitente lo bastante para que el pozo no se seque nunca.  \~
    if (which == 0) check(dry > 0, "the pools never ran dry: the refusal path was not exercised");

    if (!stop_through_mail(r)) {
        check(false, "the shard did not stop on a Stop message");
        return;
    }

    // \~english Read now that the shard's thread is gone.  \~spanish Se lee ahora que el hilo del fragmento se fue.  \~
    const http_vx::ShardCounts &c = r.shard.counts();
    check(c.mail_adopt_refused == sent, "a handed-over socket was not refused and closed exactly once");
    check(c.mail_adopted == 0, "a shard with no stream side took a socket");
    check(r.shard.mail_received().received == sent + 1, "the mailbox did not take exactly what was sent");
    check(r.shard.wake_counts().failed_wakes == 0, "a wake could not be delivered");
    check(c.unclosed == 0, "a socket's close was refused");
    // \~english The memory backend closes nothing, but the shard must have ASKED for each refused socket to be closed.
    // \~spanish El backend de memoria no cierra nada, pero el fragmento tiene que haber PEDIDO que se cierre cada socket rechazado.  \~
    if (which == 0) check(r.sleepy.close_submits() == sent, "a refused socket was not closed: a descriptor leaked");
    std::printf("  %s: %llu messages (%llu refusals while dry), %llu wakes\n", against, static_cast<unsigned long long>(sent),
                static_cast<unsigned long long>(dry), static_cast<unsigned long long>(r.shard.wake_counts().wakes));
}

/**
 * @brief
 * \~english Four senders, a shard that serves what it adopts: every socket once, each sender's in order.
 * \~spanish Cuatro remitentes, un fragmento que sirve lo que adopta: cada socket una vez, los de cada remitente en orden.
 * \~
 */
void test_senders_are_served_in_order() {
    against = "sleepy-memory, adopting";

    constexpr int kSenders = 4;
    constexpr int kPerSender = 1500;

    rig::Rig r;
    ShardConfig cfg;
    cfg.connections = 512;
    cfg.buffers = 64;
    cfg.wheel_slots = 64;
    if (!r.start(0, cfg, true)) {
        check(false, "the shard would not start");
        return;
    }

    std::vector<SendJob> senders(kSenders);
    std::vector<SendJob *> pools;
    for (int i = 0; i < kSenders; ++i) {
        check(senders[i].pool.reset(16), "a sender's pool would not start");
        senders[i].to = &r.shard.mailbox();
        senders[i].index = i;
        senders[i].count = kPerSender;
        pools.push_back(&senders[i]);
    }

    r.launch();
    std::vector<std::thread> threads;
    for (SendJob &j : senders) threads.emplace_back(send_all, &j);
    for (std::thread &t : threads) t.join();

    for (const SendJob &j : senders) check(!j.gave_up, "a sender waited 5 s for a free node: the shard stopped handling its messages");
    check(all_home(pools, 5000), "a message was never handled: its node did not come home");
    check_idle(r);

    if (!stop_through_mail(r)) {
        check(false, "the shard did not stop on a Stop message");
        return;
    }

    const uint64_t total = static_cast<uint64_t>(kSenders) * kPerSender;
    check(r.service.opened.load() == total, "not every socket was adopted exactly once");
    check(r.service.disorder.load() == 0, "a sender's messages were served out of order");
    check(r.shard.counts().mail_adopted == total && r.shard.counts().mail_adopt_refused == 0,
          "the adoptions were not counted");
}

/// \~english A message already waiting makes the shard not sleep: found by the re-check of EACH stack.  \~spanish Un mensaje que ya espera hace que el fragmento no duerma: lo encuentra la mirada de CADA pila.  \~
void test_a_waiting_message_or_kick_prevents_sleep(int which) {
    against = rig::Rig::name_of(which);

    // \~english Mail only: no wake was ever sent (the shard was not asleep when it was pushed), so only the re-check can see it.
    // \~spanish Solo correo: nunca se mando un despertar (el fragmento no dormia al meterlo), asi que solo lo puede ver la mirada.  \~
    {
        rig::Rig r;
        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.wheel_slots = 64;
        if (!r.start(which, cfg, false)) {
            check(false, "the shard would not start");
            return;
        }
        MailPool control;
        check(control.reset(1) && control.send(r.shard.mailbox(), MailKind::Stop, -1), "the stop was refused");
        r.launch();
        check(r.join(3000), "a shard went to sleep with a message already in its mailbox");
    }

    // \~english Kick only: the same, for the other stack.  \~spanish Solo aviso: lo mismo, para la otra pila.  \~
    {
        rig::Rig r;
        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.wheel_slots = 64;
        if (!r.start(which, cfg, false)) {
            check(false, "the shard would not start");
            return;
        }
        Counting src;
        Seer seer;
        OpenResponse resp;
        resp.conn.slot = 1;
        resp.conn.life = 1;
        r.shard.kicks().open(src, seer, resp);
        src.produced.store(1);
        src.kick();

        r.launch();
        const Clock::time_point t = Clock::now();
        while (src.seen.load(std::memory_order_acquire) != 1 && ms_since(t) < 3000) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        check(src.seen.load() == 1, "a shard went to sleep with a kick already in its stack");

        MailPool control;
        check(control.reset(1) && control.send(r.shard.mailbox(), MailKind::Stop, -1), "the stop was refused");
        check(r.join(3000), "the shard did not stop");
    }
}

/// \~english Messages never handled are not leaked: their sockets are closed and their nodes go home on release.  \~spanish Los mensajes nunca atendidos no se pierden: se cierran sus sockets y sus nodos vuelven a casa al soltar.  \~
void test_release_gives_back_unhandled_mail() {
    against = "release";
    rig::Rig r;
    ShardConfig cfg;
    cfg.connections = 8;
    cfg.buffers = 8;
    cfg.wheel_slots = 64;
    if (!r.start(0, cfg, true)) {
        check(false, "the shard would not start");
        return;
    }
    MailPool sender;
    check(sender.reset(4), "the pool would not start");
    for (int i = 0; i < 3; ++i) check(sender.send(r.shard.mailbox(), MailKind::AdoptSocket, 100000 + i), "a send was refused");

    r.shard.release();
    sender.reclaim();
    check(sender.free_count() == sender.capacity(), "a message nobody handled never went home");
    check(r.sleepy.close_submits() == 3, "a socket nobody took was not closed on release");
}

} // namespace

int main() {
    test_exhaustion_fifo_and_return();
    test_nodes_go_home();
    test_release_with_a_node_away();
    test_one_mark_for_both_stacks();
    test_a_failed_wake_is_counted();
    test_release_gives_back_unhandled_mail();
    test_senders_are_served_in_order();
    for (int which = 0; which < rig::Rig::kBackends; ++which) {
        test_a_waiting_message_or_kick_prevents_sleep(which);
        test_mail_and_kicks_wake_a_sleeping_shard(which);
    }

    if (failures != 0) {
        std::fprintf(stderr, "mailbox: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("mailbox: OK\n");
    return 0;
}
