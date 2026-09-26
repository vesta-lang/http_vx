/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/datagram_service.h
 * @brief
 * \~english The shard's datagram side: what it asks of a service, and how it drives one.
 * \~spanish El lado de datagramas del fragmento: lo que le pide a un servicio, y como lo mueve.
 * \~
 *
 * \~english
 * The stream side hands a service a BUFFER, because a stream's messages come
 * in pieces and what is left over has to wait for the rest.  A datagram has no
 * rest: it arrives whole or not at all.  So this side hands over the bytes and
 * takes them back, and the buffer never leaves the loop -- which is also what
 * lets it go back to the pool the moment the service returns.
 *
 * And the service does not WRITE when it answers; it is ASKED.  QUIC decides
 * what to send from its own state -- acknowledgements owed, data the peer's
 * window allows, a probe because a timer fired -- rather than as a reply to
 * one datagram, so the loop pulls with @c next_datagram until the service has
 * nothing more.  The pull is also what makes the pool the limit: a datagram is
 * asked for only once there is a buffer to put it in, so a service is never
 * made to produce something that then has nowhere to go.
 *
 * R27: this knows nothing of QUIC or HTTP/3.  The shape is the one a sans-IO
 * transport already has -- datagrams in with a path, datagrams out with a
 * path, and one timer -- so an adapter over one is a copy of two addresses and
 * a cast of the ECN mark, and nothing else.
 *
 * \~spanish
 * El lado de flujos le da a un servicio un BUFFER, porque los mensajes de un
 * flujo llegan a trozos y lo que sobra tiene que esperar al resto.  Un
 * datagrama no tiene resto: llega entero o no llega.  Asi que este lado entrega
 * los bytes y los recoge, y el buffer no sale nunca del bucle -- que es ademas
 * lo que permite devolverlo al pozo en cuanto vuelve el servicio.
 *
 * Y el servicio no ESCRIBE cuando contesta; se le PREGUNTA.  QUIC decide que
 * mandar a partir de su propio estado -- acuses que debe, datos que deja la
 * ventana del otro, una sonda porque vencio un temporizador -- y no como
 * respuesta a un datagrama, asi que el bucle tira de @c next_datagram hasta que
 * el servicio no tenga mas.  Tirar es tambien lo que hace del pozo el limite: un
 * datagrama se pide solo cuando hay un buffer donde ponerlo, asi que a un
 * servicio no se le hace producir algo que luego no tiene adonde ir.
 *
 * R27: esto no sabe nada de QUIC ni de HTTP/3.  La forma es la que ya tiene un
 * transporte sin entrada ni salida -- datagramas que entran con un camino,
 * datagramas que salen con un camino, y un temporizador -- asi que un adaptador
 * sobre uno es una copia de dos direcciones y un cast de la marca ECN, y nada
 * mas.
 * \~
 */
#ifndef HTTP_VX_DATAGRAM_SERVICE_H
#define HTTP_VX_DATAGRAM_SERVICE_H

#include "http_vx/buffer_pool.h"
#include "http_vx/datagram.h"
#include "http_vx/reactor_ops.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/// \~english A service with no timer running says this.
/// \~spanish Un servicio sin ningun temporizador en marcha dice esto.  \~
constexpr uint64_t kNoDatagramTimer = UINT64_MAX;

/**
 * @brief
 * \~english What the shard does with datagrams.
 * \~spanish Lo que hace el fragmento con los datagramas.
 * \~
 *
 * \~english
 * @p now is whatever clock the caller drives the shard with, handed through
 * untouched; a service that counts time differently converts in its adapter.
 * \~spanish
 * @p now es el reloj con el que quien llama mueva el fragmento, pasado sin
 * tocar; un servicio que cuente el tiempo de otra forma lo convierte en su
 * adaptador.
 * \~
 */
class DatagramService {
  public:
    virtual ~DatagramService();

    DatagramService() noexcept = default;
    DatagramService(const DatagramService &) = delete;
    DatagramService &operator=(const DatagramService &) = delete;

    /**
     * @brief
     * \~english A datagram arrived on @p path.
     * \~spanish Llego un datagrama por @p path.
     * \~
     *
     * \~english
     * The bytes are the service's to change in place until it returns -- a
     * transport that decrypts does so where the bytes are -- and not a moment
     * longer: the buffer goes back to the pool right after.  @p ecn is
     * @c EcnMark::NotEct when the platform could not read it, which is what
     * RFC 9000, 13.4.1 asks of an endpoint without access to the field: count
     * nothing.
     * \~spanish
     * Los bytes son del servicio para cambiarlos en su sitio hasta que vuelva --
     * un transporte que descifra lo hace donde estan los bytes -- y ni un momento
     * mas: el buffer vuelve al pozo justo despues.  @p ecn es
     * @c EcnMark::NotEct cuando la plataforma no pudo leerlo, que es lo que pide
     * el RFC 9000, 13.4.1 a un extremo sin acceso al campo: no contar nada.
     * \~
     *
     * @param path \~english both addresses  \~spanish las dos direcciones  \~
     * @param data \~english the payload  \~spanish la carga  \~
     * @param n    \~english its size, maybe zero  \~spanish su tamano, quiza cero  \~
     * @param ecn  \~english its ECN mark  \~spanish su marca ECN  \~
     * @param now  \~english the caller's clock  \~spanish el reloj de quien llama  \~
     */
    virtual void on_datagram(const DatagramPath &path, uint8_t *data, size_t n,
                             EcnMark ecn, uint64_t now) noexcept = 0;

    /**
     * @brief
     * \~english The next datagram to send and its path; zero when there is none.
     * \~spanish El siguiente datagrama que mandar y su camino; cero cuando no hay.
     * \~
     *
     * \~english
     * @c path.peer is where it goes.  A @c path.local left empty lets the
     * system choose the source; a known one asks for it to leave FROM there,
     * which is how a reply leaves from the address the peer wrote to.
     * \~spanish
     * @c path.peer es adonde va.  Un @c path.local vacio deja que el sistema
     * elija el origen; uno conocido pide que salga DESDE ahi, que es como una
     * respuesta sale de la direccion a la que escribio el otro extremo.
     * \~
     *
     * @param path \~english where it goes, filled in  \~spanish adonde va, a rellenar  \~
     * @param out  \~english where the payload goes  \~spanish donde va la carga  \~
     * @param room \~english how much fits  \~spanish cuanto cabe  \~
     * @param now  \~english the caller's clock  \~spanish el reloj de quien llama  \~
     * @return     \~english its size, or zero  \~spanish su tamano, o cero  \~
     */
    virtual size_t next_datagram(DatagramPath &path, uint8_t *out, size_t room,
                                 uint64_t now) noexcept = 0;

    /// \~english When the earliest timer fires, or @c kNoDatagramTimer.
    /// \~spanish Cuando vence el primer temporizador, o @c kNoDatagramTimer.  \~
    virtual uint64_t timer() const noexcept = 0;

    /// \~english Runs every timer due by @p now.
    /// \~spanish Ejecuta cada temporizador vencido a @p now.  \~
    virtual void on_timer(uint64_t now) noexcept = 0;
};

/**
 * @brief
 * \~english What the datagram side is built with.
 * \~spanish Con que se hace el lado de datagramas.
 * \~
 */
struct DatagramConfig {
    /**
     * \~english
     * How many receives each socket keeps outstanding.  More than one because
     * each receive is one datagram, and the batch R26 asks for is made of the
     * receives waiting when the datagrams arrive: with one, every datagram
     * costs a full turn of the loop.
     *
     * **It is the one place R1 bends, and by a fixed amount.**  A completion
     * interface -- IOCP, io_uring without provided buffers -- has to be given
     * the memory BEFORE a datagram arrives, and the zero-byte trick that
     * spares a stream its buffer does not work here: on a datagram socket it
     * would consume the datagram and cut it to nothing.  So each socket holds
     * this many buffers while idle.  They are per SOCKET, not per connection:
     * a hundred thousand QUIC connections behind one socket hold exactly these
     * and nothing more, which is the number R1 is about.
     *
     * \~spanish
     * Cuantas recepciones mantiene pendientes cada socket.  Mas de una porque
     * cada recepcion es un datagrama, y el lote que pide la R26 se hace con las
     * recepciones que esperan cuando llegan los datagramas: con una, cada
     * datagrama cuesta una vuelta entera del bucle.
     *
     * **Es el unico sitio donde se dobla la R1, y en una cantidad fija.**  A una
     * interfaz por finalizacion -- IOCP, io_uring sin buffers provistos -- hay
     * que darle la memoria ANTES de que llegue un datagrama, y el truco de la
     * recepcion de cero bytes que le ahorra el buffer a un flujo aqui no sirve:
     * en un socket de datagramas consumiria el datagrama y lo cortaria a nada.
     * Asi que cada socket tiene estos buffers estando parado.  Son por SOCKET,
     * no por conexion: cien mil conexiones QUIC detras de un socket tienen
     * exactamente estos y ninguno mas, que es el numero del que va la R1.
     * \~
     */
    uint32_t receives = 8;

    /**
     * \~english
     * The largest payload received or sent.  A datagram larger than this is
     * cut by the system, and it is counted and dropped, never delivered.
     * \~spanish
     * La mayor carga que se recibe o se manda.  Un datagrama mayor lo corta el
     * sistema, y se cuenta y se tira, nunca se entrega.
     * \~
     */
    uint32_t room = 1500;

    /**
     * \~english
     * The most datagrams pulled from the service in one turn.  A bound so that
     * a service with a great deal to say cannot keep the loop from reading.
     * \~spanish
     * Los mas datagramas que se sacan del servicio en una vuelta.  Una cota para
     * que un servicio con mucho que decir no impida al bucle leer.
     * \~
     */
    uint32_t sends_per_turn = 64;
};

/**
 * @brief
 * \~english What the datagram side did, counted.
 * \~spanish Lo que hizo el lado de datagramas, contado.
 * \~
 */
struct ShardDatagramCounts {
    /// \~english Handed to the service.  \~spanish Entregados al servicio.  \~
    uint64_t delivered = 0;

    /// \~english Cut by the system and dropped.  \~spanish Cortados por el sistema y tirados.  \~
    uint64_t truncated = 0;

    /// \~english Receives that failed.  \~spanish Recepciones que fallaron.  \~
    uint64_t receive_failures = 0;

    /// \~english Sent.  \~spanish Mandados.  \~
    uint64_t sent = 0;

    /// \~english Sends that failed in the system.  \~spanish Envios que fallaron en el sistema.  \~
    uint64_t send_failures = 0;

    /**
     * \~english
     * Datagrams the service produced that were LOST before reaching the
     * system: no socket of the peer's family, a size larger than the room, or
     * a backend that refused them.  Every one is a datagram gone, so none is
     * dropped without this growing.
     * \~spanish
     * Datagramas que produjo el servicio y se PERDIERON antes de llegar al
     * sistema: ningun socket de la familia del otro extremo, un tamano mayor que
     * el sitio, o un backend que los rechazo.  Cada uno es un datagrama perdido,
     * asi que ninguno se tira sin que esto crezca.
     * \~
     */
    uint64_t dropped = 0;

    /**
     * \~english
     * Turns in which the pool had no buffer to send with.  Not a loss -- the
     * service keeps what it had to say and is asked again -- but a pool that
     * is too small shows up here first.
     * \~spanish
     * Vueltas en las que el pozo no tenia buffer con el que mandar.  No es una
     * perdida -- el servicio se queda lo que tenia que decir y se le vuelve a
     * preguntar -- pero un pozo demasiado pequeno se ve aqui antes que en nada.
     * \~
     */
    uint64_t starved = 0;
};

/**
 * @brief
 * \~english The datagram side of one shard.
 * \~spanish El lado de datagramas de un fragmento.
 * \~
 *
 * \~english
 * Owned by the @c Shard and driven from its @c poll; it lives apart only so
 * that neither the stream loop nor this one has to be read to understand the
 * other.  It shares the shard's pool and backend, which is R9: one thread,
 * one allocator, nothing locked.
 * \~spanish
 * Lo posee el @c Shard y se mueve desde su @c poll; vive aparte solo para que
 * ni el bucle de flujos ni este tengan que leerse para entender el otro.
 * Comparte el pozo y el backend del fragmento, que es la R9: un hilo, un
 * asignador, nada cerrado con cerrojo.
 * \~
 */
class ShardDatagrams {
  public:
    ShardDatagrams() noexcept = default;
    ShardDatagrams(const ShardDatagrams &) = delete;
    ShardDatagrams &operator=(const ShardDatagrams &) = delete;

    /**
     * @brief
     * \~english Makes it ready to drive @p service.
     * \~spanish Lo deja listo para mover @p service.
     * \~
     *
     * @return \~english false for a configuration that cannot work
     *         \~spanish false para una configuracion que no puede funcionar  \~
     */
    bool reset(const DatagramConfig &cfg, Backend &io, BufferPool &pool,
               DatagramService &service) noexcept;

    /**
     * @brief
     * \~english Starts receiving on @p fd, bound to @p bound.
     * \~spanish Empieza a recibir por @p fd, atado a @p bound.
     * \~
     *
     * \~english
     * @p bound is what the backend said the socket is bound to.  Its length
     * names its family, and a datagram goes out on the socket of its peer's
     * family -- preferring, among several, the one bound to exactly the local
     * address the service asked for.
     * \~spanish
     * @p bound es lo que dijo el backend que es la direccion del socket.  Su
     * longitud nombra su familia, y un datagrama sale por el socket de la familia
     * de su otro extremo -- prefiriendo, entre varios, el atado exactamente a la
     * direccion local que pidio el servicio.
     * \~
     *
     * @return \~english false when there is no room for another socket
     *         \~spanish false cuando no cabe otro socket  \~
     */
    bool add_socket(int32_t fd, const NetAddress &bound) noexcept;

    /// \~english A @c RecvFrom came back.  \~spanish Volvio un @c RecvFrom.  \~
    void on_received(const Completion &done, uint64_t now) noexcept;

    /// \~english A @c SendTo came back.  \~spanish Volvio un @c SendTo.  \~
    void on_sent(const Completion &done) noexcept;

    /**
     * @brief
     * \~english Keeps the receives posted and asks the service what to send.
     * \~spanish Mantiene puestas las recepciones y le pregunta al servicio que mandar.
     * \~
     *
     * @return \~english how many datagrams were handed to the backend
     *         \~spanish cuantos datagramas se le dieron al backend  \~
     */
    size_t flush(uint64_t now) noexcept;

    /// \~english Runs the service's timer if it is due.
    /// \~spanish Ejecuta el temporizador del servicio si ha vencido.  \~
    void run_timers(uint64_t now) noexcept;

    /// \~english When the service's timer fires, or @c kNoDatagramTimer.
    /// \~spanish Cuando vence el temporizador del servicio, o @c kNoDatagramTimer.  \~
    uint64_t timer() const noexcept;

    /// \~english Whether a service is attached.  \~spanish Si hay un servicio puesto.  \~
    bool attached() const noexcept { return service_ != nullptr; }

    /// \~english How many sockets.  \~spanish Cuantos sockets.  \~
    size_t sockets() const noexcept { return count_; }

    /// \~english How many receives socket @p i has outstanding.
    /// \~spanish Cuantas recepciones tiene pendientes el socket @p i.  \~
    uint32_t posted(size_t i) const noexcept {
        return i < count_ ? sockets_[i].posted : 0;
    }

    /// \~english How many sends are with the backend.
    /// \~spanish Cuantos envios tiene el backend.  \~
    uint32_t sending() const noexcept { return sending_; }

    const ShardDatagramCounts &counts() const noexcept { return counts_; }

    /// \~english Forgets the service and the sockets.
    /// \~spanish Olvida el servicio y los sockets.  \~
    void release() noexcept;

  private:
    /// \~english One socket and how many receives it has out.
    /// \~spanish Un socket y cuantas recepciones tiene fuera.  \~
    struct Socket {
        int32_t fd = -1;
        NetAddress bound;
        uint32_t posted = 0;
    };

    /// \~english Tops up the receives of socket @p i.
    /// \~spanish Repone las recepciones del socket @p i.  \~
    void post(uint32_t i) noexcept;

    /// \~english Which socket @p path leaves by, or -1.
    /// \~spanish Por que socket sale @p path, o -1.  \~
    int32_t route(const DatagramPath &path) const noexcept;

    /// \~english Pulls one datagram and hands it over; false to stop pulling.
    /// \~spanish Saca un datagrama y lo entrega; false para dejar de sacar.  \~
    bool send_one(uint64_t now) noexcept;

    Socket sockets_[kMaxDatagramSockets];
    size_t count_ = 0;
    uint32_t sending_ = 0;

    DatagramConfig cfg_;
    Backend *io_ = nullptr;
    BufferPool *pool_ = nullptr;
    DatagramService *service_ = nullptr;
    ShardDatagramCounts counts_;
};

} // namespace http_vx

#endif // HTTP_VX_DATAGRAM_SERVICE_H
