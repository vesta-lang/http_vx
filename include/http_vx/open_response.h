/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/open_response.h
 * @brief
 * \~english A response whose body is still being produced: the source that fills it, and how it is kicked.
 * \~spanish Una respuesta cuyo cuerpo se sigue produciendo: la fuente que la rellena, y como se la avisa.
 * \~
 *
 * \~english
 * HVX-5 is the design; this is its contract.  The server asks, the
 * application fills: @c BodySource::fill writes straight into the buffer the
 * bytes leave from, and only when the transport has room.  @c kick says "I
 * have something" from any thread, costs a few atomic operations and never
 * allocates: the queue's node is the source itself.
 * \~spanish
 * HVX-5 es el diseno; esto es su contrato.  El servidor pide, la aplicacion
 * rellena: @c BodySource::fill escribe directamente en el buffer del que salen
 * los bytes, y solo cuando el transporte tiene sitio.  @c kick dice "tengo
 * algo" desde cualquier hilo, cuesta unas pocas operaciones atomicas y nunca
 * reserva: el nodo de la cola es la propia fuente.
 * \~
 */
#ifndef HTTP_VX_OPEN_RESPONSE_H
#define HTTP_VX_OPEN_RESPONSE_H

#include "http_vx/conn_table.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace http_vx {

class BodySource;
class KickQueue;

/**
 * @brief
 * \~english Which open response: the connection, with its life, and the stream (zero in HTTP/1.1).
 * \~spanish Que respuesta abierta: la conexion, con su vida, y el flujo (cero en HTTP/1.1).
 * \~
 *
 * \~english
 * A value, copied freely.  The connection's life is what makes a stale one
 * harmless: a response of a connection that is gone finds nothing, never the
 * connection that took its slot.
 * \~spanish
 * Un valor, que se copia sin mas.  La vida de la conexion es lo que hace
 * inofensiva una caducada: una respuesta de una conexion que ya no esta no
 * encuentra nada, nunca la conexion que cogio su casilla.
 * \~
 */
struct OpenResponse {
    ConnHandle conn;
    uint64_t stream = 0;

    /// \~english Whether this names a response at all.  \~spanish Si esto nombra una respuesta siquiera.  \~
    bool valid() const noexcept { return conn.valid(); }
};

/**
 * @brief
 * \~english Why an open response ended.
 * \~spanish Por que acabo una respuesta abierta.
 * \~
 */
enum class GoneReason : uint8_t {
    /// \~english The source said @c done, and all it produced was handed on.
    /// \~spanish La fuente dijo @c done, y todo lo que produjo se entrego.  \~
    Finished,
    /// \~english The peer reset the stream or stopped reading it.
    /// \~spanish El otro extremo reinicio el flujo o dejo de leerlo.  \~
    PeerReset,
    /// \~english The connection closed, for any reason of its own.
    /// \~spanish La conexion se cerro, por cualquier motivo suyo.  \~
    ConnectionClosed,
    /// \~english Nothing went out for the connection's idle deadline.
    /// \~spanish No salio nada durante el plazo de inactividad de la conexion.  \~
    IdleTimeout,
    /// \~english The shard is being let go.  \~spanish El fragmento se suelta.  \~
    Shutdown,
};

/// \~english The reason's name, for a log line.  \~spanish El nombre del motivo, para una linea de registro.  \~
const char *gone_reason_name(GoneReason why) noexcept;

/**
 * @brief
 * \~english Who is told that a source was kicked: the service that opened its response.
 * \~spanish A quien se le dice que avisaron a una fuente: el servicio que abrio su respuesta.
 * \~
 */
class KickTarget {
public:
    virtual ~KickTarget();

    /// \~english @p source was kicked; called on the shard's thread.
    /// \~spanish Avisaron a @p source; se llama en el hilo del fragmento.  \~
    virtual void on_kick(BodySource &source) noexcept = 0;
};

/**
 * @brief
 * \~english What produces the body of an open response.  The application's; lives until its @c gone.
 * \~spanish Lo que produce el cuerpo de una respuesta abierta.  De la aplicacion; vive hasta su @c gone.
 * \~
 *
 * \~english
 * @c fill and @c gone are called on the shard's thread, always.  @c kick may
 * be called from any thread, any number of times, until @c gone -- and never
 * after it: the queue's node lives inside the source, so a source freed with
 * a kick in flight would be the shard reading freed memory (HVX-5, 4.4).
 * \~spanish
 * @c fill y @c gone se llaman en el hilo del fragmento, siempre.  @c kick se
 * puede llamar desde cualquier hilo, cualquier numero de veces, hasta @c gone
 * -- y nunca despues: el nodo de la cola vive dentro de la fuente, asi que una
 * fuente liberada con un aviso en vuelo seria el fragmento leyendo memoria
 * liberada (HVX-5, 4.4).
 * \~
 */
class BodySource {
public:
    BodySource() noexcept = default;
    virtual ~BodySource();
    BodySource(const BodySource &) = delete;
    BodySource &operator=(const BodySource &) = delete;

    /**
     * @brief
     * \~english Writes up to @p room bytes of body at @p dst.
     * \~spanish Escribe hasta @p room bytes de cuerpo en @p dst.
     * \~
     *
     * \~english
     * @p dst is the output buffer the bytes leave from, with the version's
     * framing already reserved in front: write body and nothing else.  Zero
     * without @p done is fine -- "nothing now".  A source that returns less
     * than @p room is not asked again until it is kicked (HVX-5, 4.3).
     * \~spanish
     * @p dst es el buffer de salida del que saldran los bytes, con el enmarcado
     * de la version ya reservado delante: se escribe cuerpo y nada mas.  Cero
     * sin @p done esta bien -- "ahora nada".  A una fuente que devuelve menos
     * que @p room no se le vuelve a preguntar hasta que la avisen (HVX-5, 4.3).
     * \~
     *
     * @param done \~english set to end the response after these bytes  \~spanish se pone para acabar la respuesta tras estos bytes  \~
     * @return     \~english how many were written  \~spanish cuantos se escribieron  \~
     */
    virtual size_t fill(OpenResponse r, uint8_t *dst, size_t room, bool &done) noexcept = 0;

    /**
     * @brief
     * \~english The response ended; the source may be freed once this returns.
     * \~spanish La respuesta acabo; la fuente se puede liberar cuando esto vuelva.
     * \~
     *
     * \~english
     * Exactly once per opened source, including when it ended itself
     * (@c GoneReason::Finished).  No @c fill follows.
     * \~spanish
     * Exactamente una vez por fuente abierta, tambien cuando acabo ella misma
     * (@c GoneReason::Finished).  No le sigue ningun @c fill.
     * \~
     */
    virtual void gone(OpenResponse r, GoneReason why) noexcept = 0;

    /**
     * @brief
     * \~english Says "I have something", from any thread; free when already said.
     * \~spanish Dice "tengo algo", desde cualquier hilo; gratis si ya estaba dicho.
     * \~
     *
     * @return \~english false if the source is not open, or its shard could not be woken
     *         \~spanish false si la fuente no esta abierta, o no se pudo despertar a su fragmento  \~
     */
    bool kick() noexcept;

    /// \~english The response this source fills; shard thread.  \~spanish La respuesta que rellena esta fuente; hilo del fragmento.  \~
    OpenResponse response() const noexcept { return response_; }

private:
    friend class KickQueue;

    /// \~english In the queue, or ended: a kick then does nothing.  \~spanish En la cola, o acabada: un aviso entonces no hace nada.  \~
    std::atomic<uint8_t> queued_{1};
    /// \~english Kicks that found it already queued, read by the shard.  \~spanish Avisos que la encontraron ya en la cola, que lee el fragmento.  \~
    std::atomic<uint32_t> coalesced_{0};
    BodySource *next_ = nullptr;
    KickQueue *queue_ = nullptr;
    KickTarget *target_ = nullptr;
    OpenResponse response_;
    /// \~english Ended, its gone owed; shard thread only.  \~spanish Acabada, se le debe su gone; solo el hilo del fragmento.  \~
    bool closing_ = false;
    GoneReason why_ = GoneReason::Finished;
};

} // namespace http_vx

#endif // HTTP_VX_OPEN_RESPONSE_H
