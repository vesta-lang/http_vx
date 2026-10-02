/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/shard_group.cpp
 * @brief
 * \~english Starting the shards one thread each, in order, and stopping them through their mailboxes.
 * \~spanish Arrancar los fragmentos un hilo cada uno, en orden, y pararlos por sus buzones.
 * \~
 */
#include "serve/shard_group.h"

#include <cstdio>
#include <new>

namespace serve {

ShardGroup::~ShardGroup() {
    stop();
    delete[] slots_;
}

RunnerPlan ShardGroup::plan_for(uint32_t index) const noexcept {
    const Options &opt = *plan_.options;

    RunnerPlan p;
    p.options = plan_.options;
    p.backend = plan_.backend;
    p.index = index;
    p.count = plan_.count;
    p.port = index == 0 ? opt.port : port_;
    p.events = plan_.events;
    p.ticket_key = plan_.ticket_key;
    p.pin = plan_.count > 1;

    /* \~english
     * One shard listens as it always did.  With several, Linux gives every
     * shard its own socket on the shared address (HVX-6, 4.1).  Windows cannot
     * share an address: only shard 0 listens until the acceptor that hands
     * sockets to the others exists (HVX-6, 4.2), and the rest run without one.
     * \~spanish
     * Un fragmento escucha como siempre.  Con varios, Linux da a cada fragmento
     * su propio socket en la direccion compartida (HVX-6, 4.1).  Windows no
     * puede compartir una direccion: solo escucha el fragmento 0 hasta que
     * exista el aceptador que pase sockets a los demas (HVX-6, 4.2), y el resto
     * corre sin uno.
     * \~ */
    if (plan_.count == 1) {
        p.listening = Listening::Alone;
    } else {
#ifdef _WIN32
        p.listening = index == 0 ? Listening::Alone : Listening::Off;
#else
        p.listening = Listening::Shared;
#endif
    }

    // \~english QUIC lives on shard 0 for now: its datagrams all land on one socket (HVX-6, 5).
    // \~spanish QUIC vive por ahora en el fragmento 0: todos sus datagramas caen en un socket (HVX-6, 5).  \~
    p.serves_h3 = opt.h3 && index == 0;
    return p;
}

void ShardGroup::thread_main(ShardGroup *group, uint32_t index) noexcept {
    Slot &slot = group->slots_[index];

    // \~english Made HERE, on the shard's thread: nothing of a shard is touched first by another.
    // \~spanish Hecho AQUI, en el hilo del fragmento: nada de un fragmento lo toca antes otro.  \~
    ShardRunner *runner = new (std::nothrow) ShardRunner;
    const bool ok = runner != nullptr && runner->build(group->plan_for(index));

    {
        std::lock_guard<std::mutex> g(group->lock_);
        if (ok) {
            slot.runner = runner;
            slot.port = runner->port();
            std::snprintf(slot.backend, sizeof slot.backend, "%s", runner->backend_name());
            slot.state = State::Running;
        } else {
            std::snprintf(slot.why, sizeof slot.why, "%s", runner != nullptr ? runner->why() : "no memory for the shard");
            slot.state = State::Failed;
        }
    }
    group->changed_.notify_all();

    if (!ok) {
        delete runner;
        return;
    }

    runner->run();
    runner->finish();

    {
        // \~english Out of the slot before it is deleted: nobody may send to a shard that is gone.
        // \~spanish Fuera de la casilla antes de borrarlo: nadie puede mandar a un fragmento que se fue.  \~
        std::lock_guard<std::mutex> g(group->lock_);
        slot.runner = nullptr;
        slot.state = State::Done;
    }
    delete runner;
}

bool ShardGroup::wait_started(uint32_t index) noexcept {
    std::unique_lock<std::mutex> g(lock_);
    while (slots_[index].state == State::Starting) changed_.wait(g);

    if (slots_[index].state == State::Running) return true;
    std::snprintf(why_, sizeof why_, "shard %u did not start: %s", static_cast<unsigned>(index), slots_[index].why);
    return false;
}

bool ShardGroup::start(const GroupPlan &plan) noexcept {
    plan_ = plan;
    if (plan.count == 0 || plan.options == nullptr) {
        std::snprintf(why_, sizeof why_, "a group needs at least one shard");
        return false;
    }

    slots_ = new (std::nothrow) Slot[plan.count];
    if (slots_ == nullptr || !control_.reset(plan.count)) {
        std::snprintf(why_, sizeof why_, "no memory for the shard group");
        return false;
    }

    stopped_ = false;
    for (uint32_t i = 0; i < plan.count; ++i) {
        {
            std::lock_guard<std::mutex> g(lock_);
            slots_[i].state = State::Starting;
        }

        try {
            slots_[i].thread = std::thread(thread_main, this, i);
        } catch (...) {
            std::lock_guard<std::mutex> g(lock_);
            slots_[i].state = State::Failed;
            std::snprintf(why_, sizeof why_, "the system would not make the thread of shard %u", static_cast<unsigned>(i));
            // \~english Not waited for: there is no thread to wait for.
            // \~spanish No se espera: no hay hilo al que esperar.  \~
            stopped_ = false;
            break;
        }

        // \~english In order: the others need the port shard 0 got.
        // \~spanish En orden: los demas necesitan el puerto que obtuvo el 0.  \~
        if (!wait_started(i)) {
            stop();
            return false;
        }
        if (i == 0) {
            port_ = slots_[0].port;
            std::snprintf(backend_name_, sizeof backend_name_, "%s", slots_[0].backend);
        }
    }

    // \~english Only the break above leaves a shard short.
    // \~spanish Solo el break de arriba deja corto un fragmento.  \~
    for (uint32_t i = 0; i < plan.count; ++i) {
        if (slots_[i].state == State::Running) continue;
        stop();
        return false;
    }
    return true;
}

void ShardGroup::stop() noexcept {
    if (stopped_ || slots_ == nullptr) return;
    stopped_ = true;

    for (uint32_t i = 0; i < plan_.count; ++i) {
        std::lock_guard<std::mutex> g(lock_);
        if (slots_[i].state != State::Running || slots_[i].runner == nullptr) continue;

        // \~english A pool of the main thread's, as any other sender: nothing is allocated, and the node goes home.
        // \~spanish Un pozo del hilo principal, como cualquier otro remitente: no se reserva nada, y el nodo vuelve a casa.  \~
        if (!control_.send(slots_[i].runner->shard().mailbox(), http_vx::MailKind::Stop, -1))
            std::fprintf(stderr, "http_vx: could not send the stop message to shard %u\n", static_cast<unsigned>(i));
    }

    for (uint32_t i = 0; i < plan_.count; ++i)
        if (slots_[i].thread.joinable()) slots_[i].thread.join();
}

} // namespace serve
