/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/shard_runner.h
 * @brief
 * \~english Everything one shard of the runnable server is made of, built and run on that shard's own thread.
 * \~spanish Todo de lo que esta hecho un fragmento del servidor ejecutable, construido y corrido en el propio hilo de ese fragmento.
 * \~
 *
 * \~english
 * HVX-6, 3 and 7.2.  A shard is a thread with everything of its own: its
 * backend, its services, its handler, its tables.  The thread pins itself to a
 * CPU FIRST and builds all of it AFTER, so the memory is touched for the first
 * time on that CPU (R9, R44).  The handler is built per shard -- a
 * @c Greeting each -- and the only thing shared is @c Events, which is
 * thread-safe and whose sources are bound to whichever shard opened them.
 * Nothing here is created by the main thread.
 * \~spanish
 * HVX-6, 3 y 7.2.  Un fragmento es un hilo con todo lo suyo: su backend, sus
 * servicios, su manejador, sus tablas.  El hilo se fija a una CPU PRIMERO y
 * construye todo DESPUES, asi que la memoria se toca por primera vez en esa CPU
 * (R9, R44).  El manejador se construye por fragmento -- un @c Greeting cada
 * uno --, y lo unico compartido es @c Events, que es seguro entre hilos y cuyas
 * fuentes quedan atadas al fragmento que las abrio.  Nada de esto lo crea el
 * hilo principal.
 * \~
 */
#ifndef HTTP_VX_SERVE_SHARD_RUNNER_H
#define HTTP_VX_SERVE_SHARD_RUNNER_H

#include "serve/clock.h"
#include "serve/events.h"
#include "serve/greeting.h"
#include "serve/h3_setup.h"
#include "serve/options.h"
#include "serve/reactors.h"
#include "serve/report.h"
#include "serve/tls_setup.h"

#include "http_vx/http2_service.h"
#include "http_vx/shard.h"
#include "http_vx/tls_service.h"

#include <cstdint>

namespace serve {

/**
 * @brief
 * \~english What the server decided for one shard.
 * \~spanish Lo que decidio el servidor para un fragmento.
 * \~
 */
struct RunnerPlan {
    /// \~english What was asked for on the command line; read only.  \~spanish Lo que se pidio en la linea de ordenes; solo lectura.  \~
    const Options *options = nullptr;
    /// \~english The backend's name, one @c Reactors::has accepted.  \~spanish El nombre del backend, uno que @c Reactors::has acepto.  \~
    const char *backend = nullptr;
    /// \~english This shard's number, from 0.  \~spanish El numero de este fragmento, desde 0.  \~
    uint32_t index = 0;
    /// \~english How many shards there are.  \~spanish Cuantos fragmentos hay.  \~
    uint32_t count = 1;
    /// \~english The port to listen on (the one shard 0 got, for the others).  \~spanish El puerto en el que escuchar (el que obtuvo el fragmento 0, para los demas).  \~
    uint16_t port = 0;
    /// \~english How this shard's backend listens.  \~spanish Como escucha el backend de este fragmento.  \~
    Listening listening = Listening::Alone;
    /// \~english Whether the datagram side (HTTP/3) lives on this shard.  \~spanish Si el lado de datagramas (HTTP/3) vive en este fragmento.  \~
    bool serves_h3 = false;
    /// \~english Whether to pin the thread to a CPU.  \~spanish Si fijar el hilo a una CPU.  \~
    bool pin = false;
    /// \~english The shared event streams.  \~spanish Los flujos de eventos compartidos.  \~
    Events *events = nullptr;
    /// \~english The ticket key every shard's TLS setup uses, or null.  \~spanish La clave de tickets que usa el setup de TLS de cada fragmento, o nulo.  \~
    const uint8_t *ticket_key = nullptr;
};

/**
 * @brief
 * \~english One shard, its backend, its services and its loop.
 * \~spanish Un fragmento, su backend, sus servicios y su bucle.
 * \~
 */
class ShardRunner {
public:
    ShardRunner() noexcept = default;
    ShardRunner(const ShardRunner &) = delete;
    ShardRunner &operator=(const ShardRunner &) = delete;

    /**
     * @brief
     * \~english Pins the calling thread, then builds everything; false, with @c why, if it could not.
     * \~spanish Fija el hilo que llama, y despues construye todo; false, con @c why, si no pudo.
     * \~
     */
    bool build(const RunnerPlan &plan) noexcept;

    /// \~english Serves until a stop message arrives; the shard's own thread.  \~spanish Sirve hasta que llegue un mensaje de parar; el hilo del propio fragmento.  \~
    void run() noexcept;

    /// \~english Says what the shard counted and gives everything back; the shard's own thread, after @c run.  \~spanish Dice lo que conto el fragmento y lo devuelve todo; el hilo del propio fragmento, tras @c run.  \~
    void finish() noexcept;

    /// \~english Why @c build failed.  \~spanish Por que fallo @c build.  \~
    const char *why() const noexcept { return why_; }

    /// \~english The port the backend got.  \~spanish El puerto que obtuvo el backend.  \~
    uint16_t port() const noexcept { return reactors_.port(); }

    /// \~english The backend's name.  \~spanish El nombre del backend.  \~
    const char *backend_name() const noexcept { return reactors_.io() != nullptr ? reactors_.io()->name() : "?"; }

    /// \~english The shard, whose mailbox other threads send to.  \~spanish El fragmento, cuyo buzon usan otros hilos para mandar.  \~
    http_vx::Shard &shard() noexcept { return shard_; }

private:
    /// \~english Prints this shard's counters on one line.  \~spanish Imprime los contadores de este fragmento en una linea.  \~
    void print_counts(const char *when) noexcept;

    /// \~english Whether anything the line reports moved since it was last printed.  \~spanish Si se movio algo de lo que cuenta la linea desde la ultima vez que se imprimio.  \~
    bool counts_moved() noexcept;

    /// \~english Says why the build failed, with the system's error where there is one.  \~spanish Dice por que fallo la construccion, con el error del sistema donde lo hay.  \~
    bool fail(const char *what) noexcept;

    RunnerPlan plan_;
    uint32_t cpu_ = 0;
    bool pinned_ = false;
    char why_[192] = {};

    Reactors reactors_;
    Greeting greeting_;
    http_vx::Http1Service service_;
    TlsSetup tls_setup_;
    http_vx::Http2Service h2_service_;
    http_vx::TlsService tls_service_;
    H3Setup h3_{now_us};
    Report report_;
    http_vx::Shard shard_;

    bool tls_ = false;
    bool h3_active_ = false;
    uint64_t last_moved_ = 0;
};

} // namespace serve

#endif // HTTP_VX_SERVE_SHARD_RUNNER_H
