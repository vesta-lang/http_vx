/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/events.h
 * @brief
 * \~english A stream of server-sent events fed from another thread: what an open response is for (HVX-5).
 * \~spanish Un flujo de eventos enviados por el servidor alimentado desde otro hilo: para lo que es una respuesta abierta (HVX-5).
 * \~
 *
 * \~english
 * `GET /events` answers `text/event-stream` and never ends by itself: a
 * thread that is not the shard's writes one event a second into every stream
 * that is open and kicks it, and the shard fills the response when there is
 * room.  The same handler serves it over HTTP/1.1, HTTP/2 and HTTP/3, over a
 * pipe or a port, and nothing here knows which.
 *
 * @code
 * curl -N http://127.0.0.1:8080/events
 * @endcode
 *
 * What a stream holds waiting is bounded: a client that does not read loses
 * events -- counted -- instead of making the server keep them.  The event
 * thread kicks under the same lock @c gone takes, so no stream is kicked
 * after its @c gone, which is the contract of HVX-5, 4.4.
 *
 * \~spanish
 * `GET /events` contesta `text/event-stream` y no acaba nunca por si mismo: un
 * hilo que no es el del fragmento escribe un evento por segundo en cada flujo
 * abierto y lo avisa, y el fragmento rellena la respuesta cuando hay sitio.  El
 * mismo manejador lo sirve por HTTP/1.1, HTTP/2 y HTTP/3, por una tuberia o un
 * puerto, y nada de aqui sabe cual.
 *
 * Lo que un flujo guarda esperando esta acotado: un cliente que no lee pierde
 * eventos -- contados -- en vez de hacer que el servidor los guarde.  El hilo de
 * eventos avisa bajo el mismo cerrojo que toma @c gone, asi que a ningun flujo se
 * le avisa despues de su @c gone, que es el contrato del HVX-5, 4.4.
 * \~
 */
#ifndef HTTP_VX_SERVE_EVENTS_H
#define HTTP_VX_SERVE_EVENTS_H

#include "http_vx/open_response.h"
#include "http_vx/response.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>

namespace serve {

/**
 * @brief
 * \~english One event stream: what the event thread wrote and the shard has not taken yet.
 * \~spanish Un flujo de eventos: lo que escribio el hilo de eventos y el fragmento todavia no se llevo.
 * \~
 */
class EventStream final : public http_vx::BodySource {
  public:
    size_t fill(http_vx::OpenResponse r, uint8_t *dst, size_t room, bool &done) noexcept override;
    void gone(http_vx::OpenResponse r, http_vx::GoneReason why) noexcept override;

    /// \~english Takes it if it is free.  \~spanish La coge si esta libre.  \~
    bool claim() noexcept;

    /// \~english Says whether opening worked: it lives until its gone, or is free again now.
    /// \~spanish Dice si abrir funciono: vive hasta su gone, o vuelve a estar libre ya.  \~
    void opened(bool ok) noexcept;

    /// \~english Appends event @p n and kicks, if it is open; the event thread's.
    /// \~spanish Anade el evento @p n y avisa, si esta abierta; del hilo de eventos.  \~
    void tick(uint64_t n) noexcept;

    /// \~english Events dropped because the client was not reading.  \~spanish Eventos descartados porque el cliente no leia.  \~
    uint64_t dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }

  private:
    std::mutex lock_;
    char pending_[2048];
    size_t len_ = 0;
    bool live_ = false;
    std::atomic<bool> used_{false};
    std::atomic<uint64_t> dropped_{0};
};

/**
 * @brief
 * \~english The event streams of a server, and the thread that feeds them.
 * \~spanish Los flujos de eventos de un servidor, y el hilo que los alimenta.
 * \~
 */
class Events {
  public:
    /// \~english How many streams may be open at once.  \~spanish Cuantos flujos pueden estar abiertos a la vez.  \~
    static constexpr size_t kStreams = 64;

    Events() noexcept = default;
    ~Events();
    Events(const Events &) = delete;
    Events &operator=(const Events &) = delete;

    /// \~english Starts the event thread.  \~spanish Arranca el hilo de eventos.  \~
    bool start() noexcept;

    /// \~english Stops it and waits for it.  \~spanish Lo para y lo espera.  \~
    void stop() noexcept;

    /**
     * @brief
     * \~english Answers @p res as an event stream.
     * \~spanish Contesta @p res como un flujo de eventos.
     * \~
     *
     * \~english
     * With every stream taken the answer is 503 and says so; with the
     * response not opened -- a `HEAD`, a limit -- the stream is free again.
     * \~spanish
     * Con todos los flujos cogidos la respuesta es 503 y lo dice; con la
     * respuesta sin abrir -- un `HEAD`, un tope -- el flujo vuelve a estar libre.
     * \~
     */
    void answer(http_vx::ResponseBuilder &res) noexcept;

    /// \~english Events dropped by every stream.  \~spanish Eventos descartados por todos los flujos.  \~
    uint64_t dropped() const noexcept;

  private:
    /// \~english The event thread: one event a second into every open stream.
    /// \~spanish El hilo de eventos: un evento por segundo en cada flujo abierto.  \~
    static void run(Events *self) noexcept;

    EventStream streams_[kStreams];
    std::thread thread_;
    std::atomic<bool> stopping_{false};
};

} // namespace serve

#endif // HTTP_VX_SERVE_EVENTS_H
