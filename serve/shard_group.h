/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/shard_group.h
 * @brief
 * \~english N shards of the runnable server, one thread each, started in order and stopped through their mailboxes.
 * \~spanish N fragmentos del servidor ejecutable, un hilo cada uno, arrancados en orden y parados por sus buzones.
 * \~
 *
 * \~english
 * HVX-6, 3.  It lives in @c serve/ and not in the library: how many shards a
 * program runs, where they listen and what each is given is the program's
 * decision, and the library only offers the shard and its mailbox.
 *
 * Each thread builds its OWN shard (see @c ShardRunner), so the main thread
 * reserves nothing of any shard.  They start one at a time, shard 0 first,
 * because the others need the port shard 0 got when the port asked for was 0;
 * a shard that fails to start stops the ones already running and the group
 * does not start -- and says why.  They stop the way shards talk to each other:
 * a @c Stop message through the mailbox, sent from a pool of the main thread's.
 * \~spanish
 * HVX-6, 3.  Vive en @c serve/ y no en la biblioteca: cuantos fragmentos corre
 * un programa, donde escuchan y que recibe cada uno es decision del programa, y
 * la biblioteca solo ofrece el fragmento y su buzon.
 *
 * Cada hilo construye SU fragmento (ver @c ShardRunner), asi que el hilo
 * principal no reserva nada de ningun fragmento.  Arrancan de uno en uno, el 0
 * primero, porque los demas necesitan el puerto que obtuvo el 0 cuando el
 * pedido era 0; un fragmento que no arranca para los que ya corrian y el grupo
 * no arranca -- y dice por que.  Paran como se hablan los fragmentos entre si:
 * un mensaje @c Stop por el buzon, mandado desde un pozo del hilo principal.
 * \~
 */
#ifndef HTTP_VX_SERVE_SHARD_GROUP_H
#define HTTP_VX_SERVE_SHARD_GROUP_H

#include "serve/shard_runner.h"

#include "http_vx/mailbox.h"

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace serve {

/**
 * @brief
 * \~english What a group is asked to run.
 * \~spanish Lo que se le pide correr a un grupo.
 * \~
 */
struct GroupPlan {
    /// \~english The command line; read only.  \~spanish La linea de ordenes; solo lectura.  \~
    const Options *options = nullptr;
    /// \~english The backend's name.  \~spanish El nombre del backend.  \~
    const char *backend = nullptr;
    /// \~english How many shards.  \~spanish Cuantos fragmentos.  \~
    uint32_t count = 1;
    /// \~english The shared event streams.  \~spanish Los flujos de eventos compartidos.  \~
    Events *events = nullptr;
    /// \~english The ticket key every shard uses, or null.  \~spanish La clave de tickets que usa cada fragmento, o nulo.  \~
    const uint8_t *ticket_key = nullptr;
};

/**
 * @brief
 * \~english The shards, their threads, and the way to stop them.
 * \~spanish Los fragmentos, sus hilos, y la forma de pararlos.
 * \~
 */
class ShardGroup {
public:
    ShardGroup() noexcept = default;
    ~ShardGroup();
    ShardGroup(const ShardGroup &) = delete;
    ShardGroup &operator=(const ShardGroup &) = delete;

    /**
     * @brief
     * \~english Starts every shard, or none: false, with @c why, if any could not.
     * \~spanish Arranca todos los fragmentos, o ninguno: false, con @c why, si alguno no pudo.
     * \~
     */
    bool start(const GroupPlan &plan) noexcept;

    /// \~english Sends every shard a @c Stop and waits for their threads; each prints its counters first.  \~spanish Manda a cada fragmento un @c Stop y espera a sus hilos; cada uno imprime antes sus contadores.  \~
    void stop() noexcept;

    /// \~english Why @c start failed.  \~spanish Por que fallo @c start.  \~
    const char *why() const noexcept { return why_; }

    /// \~english The port the shards listen on (the one shard 0 got).  \~spanish El puerto en el que escuchan los fragmentos (el que obtuvo el 0).  \~
    uint16_t port() const noexcept { return port_; }

    /// \~english The backend's name, once started.  \~spanish El nombre del backend, una vez arrancado.  \~
    const char *backend_name() const noexcept { return backend_name_; }

private:
    /// \~english Where a shard is in its life; written under @c lock_.  \~spanish En que punto de su vida esta un fragmento; se escribe bajo @c lock_.  \~
    enum class State : uint8_t { NotStarted, Starting, Running, Failed, Done };

    /// \~english One shard's thread and what the group needs to know of it.  \~spanish El hilo de un fragmento y lo que necesita saber de el el grupo.  \~
    struct Slot {
        std::thread thread;
        State state = State::NotStarted;
        /// \~english Set by the shard's thread before it says it runs; read after.  \~spanish Lo pone el hilo del fragmento antes de decir que corre; se lee despues.  \~
        ShardRunner *runner = nullptr;
        uint16_t port = 0;
        char backend[16] = {};
        char why[192] = {};
    };

    /// \~english The thread of shard @p index: builds, says so, runs, finishes.  \~spanish El hilo del fragmento @p index: construye, lo dice, corre, acaba.  \~
    static void thread_main(ShardGroup *group, uint32_t index) noexcept;

    /// \~english Waits until slot @p index is no longer starting; returns whether it runs.  \~spanish Espera a que la casilla @p index deje de arrancar; devuelve si corre.  \~
    bool wait_started(uint32_t index) noexcept;

    /// \~english The plan for shard @p index.  \~spanish El plan del fragmento @p index.  \~
    RunnerPlan plan_for(uint32_t index) const noexcept;

    GroupPlan plan_;
    Slot *slots_ = nullptr;
    uint16_t port_ = 0;
    char backend_name_[16] = {};
    char why_[224] = {};
    bool stopped_ = true;

    std::mutex lock_;
    std::condition_variable changed_;

    /// \~english The main thread's own pool of messages, to send the stops from.  \~spanish El pozo de mensajes propio del hilo principal, para mandar desde el los stops.  \~
    http_vx::MailPool control_;
};

} // namespace serve

#endif // HTTP_VX_SERVE_SHARD_GROUP_H
