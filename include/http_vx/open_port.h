/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/open_port.h
 * @brief
 * \~english What a service is given to open responses, fill them and have them written (HVX-5).
 * \~spanish Lo que se le da a un servicio para abrir respuestas, rellenarlas y que se escriban (HVX-5).
 * \~
 *
 * \~english
 * The half of HVX-5 that is not a version's: the limits, the counts, the kick
 * queue, and asking the loop for a buffer to write into.  Whoever drives the
 * connections implements it -- the shard for stream services -- and a service
 * that answers one version uses it the same way whatever carries its bytes.
 *
 * A service is the @c KickTarget of the sources it opens, because it is the
 * one that knows which stream of which connection a source feeds; this port
 * is how it then asks to be given room.
 *
 * \~spanish
 * La mitad del HVX-5 que no es de ninguna version: los topes, las cuentas, la
 * cola de avisos, y pedirle al bucle un buffer en el que escribir.  Lo
 * implementa quien mueve las conexiones -- el fragmento para los servicios de
 * flujo -- y un servicio que contesta una version lo usa igual lleve quien lleve
 * sus bytes.
 *
 * Un servicio es el @c KickTarget de las fuentes que abre, porque es el que sabe
 * a que flujo de que conexion alimenta una fuente; esta puerta es como pide
 * despues que le den sitio.
 * \~
 */
#ifndef HTTP_VX_OPEN_PORT_H
#define HTTP_VX_OPEN_PORT_H

#include "http_vx/open_response.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What was done with open responses, counted (HVX-5, 10).
 * \~spanish Lo que se hizo con las respuestas abiertas, contado (HVX-5, 10).
 * \~
 */
struct OpenCounts {
    /// \~english Responses opened.  \~spanish Respuestas abiertas.  \~
    uint64_t opened = 0;
    /// \~english Refused because a limit was reached.  \~spanish Rechazadas por un tope agotado.  \~
    uint64_t refused = 0;
    /// \~english Calls to @c BodySource::fill.  \~spanish Llamadas a @c BodySource::fill.  \~
    uint64_t fills = 0;
    /// \~english Bytes those calls produced.  \~spanish Bytes que produjeron esas llamadas.  \~
    uint64_t filled_bytes = 0;
    /// \~english Open right now.  \~spanish Abiertas ahora mismo.  \~
    uint64_t open_now = 0;
    /// \~english Times room was asked for and no buffer was free; asked again.  \~spanish Veces que se pidio sitio y no habia buffer libre; se volvio a pedir.  \~
    uint64_t starved = 0;
};

/**
 * @brief
 * \~english The loop's side of open responses, as a service sees it.
 * \~spanish El lado del bucle de las respuestas abiertas, tal como lo ve un servicio.
 * \~
 *
 * \~english
 * Every call is made on the loop's own thread, from inside the service's own
 * callbacks.  None of them calls back into the service: what they ask for
 * happens after the callback returns.
 * \~spanish
 * Toda llamada se hace en el hilo del propio bucle, desde dentro de las
 * llamadas del servicio.  Ninguna vuelve a llamar al servicio: lo que piden pasa
 * despues de que vuelva la llamada.
 * \~
 */
class OpenPort {
  public:
    virtual ~OpenPort();

    OpenPort() noexcept = default;
    OpenPort(const OpenPort &) = delete;
    OpenPort &operator=(const OpenPort &) = delete;

    /**
     * @brief
     * \~english Opens a response on stream @p stream of @p c, fed by @p s.
     * \~spanish Abre una respuesta en el flujo @p stream de @p c, alimentada por @p s.
     * \~
     *
     * @param target \~english who is told when @p s is kicked  \~spanish a quien se avisa cuando se avisa a @p s  \~
     * @return       \~english the response, or an invalid one if a limit is reached (counted)
     *               \~spanish la respuesta, o una invalida si hay un tope agotado (contado)  \~
     */
    virtual OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s,
                              KickTarget &target) noexcept = 0;

    /**
     * @brief
     * \~english Asks @p s for body, counting what it gives.
     * \~spanish Le pide cuerpo a @p s, contando lo que da.
     * \~
     *
     * \~english
     * The one place @c BodySource::fill is called from, so the count cannot
     * miss a call.  What comes back is clamped to @p room: a source that says
     * it wrote more than it was given is believed no further than the room.
     * \~spanish
     * El unico sitio desde el que se llama a @c BodySource::fill, asi que la
     * cuenta no se puede saltar ninguna.  Lo que vuelve se recorta a @p room: a
     * una fuente que dice haber escrito mas de lo que se le dio no se le cree mas
     * alla del sitio.
     * \~
     */
    virtual size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept = 0;

    /**
     * @brief
     * \~english Ends the response @p s feeds; its @c gone comes with @p why, now or on the next drain.
     * \~spanish Acaba la respuesta que alimenta @p s; su @c gone llega con @p why, ahora o en el vaciado siguiente.
     * \~
     */
    virtual void end(BodySource &s, GoneReason why) noexcept = 0;

    /**
     * @brief
     * \~english Asks for @c Service::on_writable on @p c once what is going out has gone.
     * \~spanish Pide @c Service::on_writable en @p c en cuanto haya salido lo que esta saliendo.
     * \~
     *
     * \~english
     * One buffer at a time per connection: the call comes when nothing of
     * @p c is being written, so a source that always has something never
     * holds more than one buffer of it (R34).
     * \~spanish
     * Un buffer cada vez por conexion: la llamada llega cuando no se esta
     * escribiendo nada de @p c, asi que una fuente que siempre tiene algo nunca
     * retiene mas de un buffer suyo (R34).
     * \~
     */
    virtual void want_writable(ConnHandle c) noexcept = 0;

    /**
     * @brief
     * \~english Stops or resumes handing @p c's bytes to the service.
     * \~spanish Para o reanuda la entrega al servicio de los bytes de @p c.
     * \~
     *
     * \~english
     * What HTTP/1.1 needs while a response is open: the requests behind it
     * wait (RFC 9112, 9.3.2), so what has arrived stays where it is, nothing
     * more is read, and TCP slows the peer.  Resuming hands over what was left.
     * \~spanish
     * Lo que necesita HTTP/1.1 mientras hay una respuesta abierta: las peticiones
     * de detras esperan (RFC 9112, 9.3.2), asi que lo que ha llegado se queda donde
     * esta, no se lee mas, y TCP frena al otro extremo.  Reanudar entrega lo que
     * quedo.
     * \~
     */
    virtual void hold_reads(ConnHandle c, bool hold) noexcept = 0;

    /**
     * @brief
     * \~english Why @p c is going away, for the @c gone of the responses still open on it.
     * \~spanish Por que se va @p c, para el @c gone de las respuestas que siguen abiertas en ella.
     * \~
     */
    virtual GoneReason closing_reason(ConnHandle c) const noexcept = 0;
};

} // namespace http_vx

#endif // HTTP_VX_OPEN_PORT_H
