/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/http3_service.h
 * @brief
 * \~english HTTP/3 on datagrams, answering with the same handler as HTTP/1.1 and HTTP/2.
 * \~spanish HTTP/3 sobre datagramas, contestando con el mismo manejador que HTTP/1.1 y HTTP/2.
 * \~
 *
 * \~english
 * The third version behind the same claim: the handler does not change.  What
 * does is everything under it.  There is no connection the operating system
 * hands over: a datagram arrives with an address, and this service decides
 * whose it is -- by the destination connection ID, which is the whole reason
 * QUIC has them (RFC 9000, 5.2) -- or hands it to the acceptor, which decides
 * without remembering anything whether a connection should exist at all.
 *
 * It does no input or output.  Datagrams go in with `on_datagram`, come out of
 * `next_datagram`, and time goes in with `on_timer`; the loop that owns the
 * socket is someone else's, as it is for the other two versions.  That is what
 * lets a test put a client and this service face to face over nothing but
 * arrays, and it is what the reactor's datagram operations will drive.
 *
 * Three things are kept so that no step walks every connection:
 *
 *  - which connection owns each connection ID, in a hash table, kept in step
 *    with the IDs each connection hands out and retires;
 *  - which connections have something to send, in a queue that holds each
 *    once;
 *  - when each connection's timer fires, in a heap.
 *
 * \~spanish
 * La tercera version detras de la misma afirmacion: el manejador no cambia.  Lo
 * que cambia es todo lo de debajo.  No hay una conexion que entregue el sistema
 * operativo: llega un datagrama con una direccion, y este servicio decide de
 * quien es -- por el identificador de conexion de destino, que es toda la razon
 * de que QUIC los tenga (RFC 9000, 5.2) -- o se lo pasa al acceptor, que decide
 * sin recordar nada si deberia existir una conexion.
 *
 * No hace entrada ni salida.  Los datagramas entran con `on_datagram`, salen de
 * `next_datagram`, y el tiempo entra con `on_timer`; el bucle dueno del socket
 * es de otro, como con las otras dos versiones.  Eso es lo que deja a una
 * prueba poner frente a frente un cliente y este servicio sin mas que arrays, y
 * es lo que moveran las operaciones de datagramas del reactor.
 *
 * Se guardan tres cosas para que ningun paso recorra todas las conexiones:
 *
 *  - que conexion es duena de cada identificador, en una tabla hash, al dia con
 *    los identificadores que cada conexion reparte y retira;
 *  - que conexiones tienen algo que mandar, en una cola que tiene a cada una
 *    una vez;
 *  - cuando vence el temporizador de cada conexion, en un monticulo.
 * \~
 */
#ifndef HTTP_VX_HTTP3_SERVICE_H
#define HTTP_VX_HTTP3_SERVICE_H

#include "http_vx/buffer.h"
#include "http_vx/deadline_heap.h"
#include "http_vx/h3_connection.h"
#include "http_vx/http1_service.h"
#include "http_vx/quic_acceptor.h"
#include "http_vx/quic_connection.h"
#include "http_vx/quic_routes.h"
#include "http_vx/tls_quic.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english How an HTTP/3 service behaves.
 * \~spanish Como se porta un servicio HTTP/3.
 * \~
 *
 * \~english
 * The stateless reset key and the length of the connection IDs appear twice,
 * in @c acceptor and in @c connection, because each piece needs its own.  They
 * MUST be equal -- a reset token handed out by a connection has to be the one
 * the acceptor answers with once the connection is gone -- and `start` refuses
 * them if they are not, rather than choosing one in silence.
 *
 * \~spanish
 * La clave del reinicio sin estado y la longitud de los identificadores
 * aparecen dos veces, en @c acceptor y en @c connection, porque cada pieza
 * necesita la suya.  DEBEN ser iguales -- el testigo de reinicio que entrega una
 * conexion tiene que ser con el que contesta el acceptor cuando ya no exista --,
 * y `start` las rechaza si no lo son, en vez de elegir una en silencio.
 * \~
 */
struct Http3Config {
    quic::AcceptorConfig acceptor;
    /// \~english Every connection's; its IDs and the peer's are filled in per connection.
    /// \~spanish La de cada conexion; sus identificadores y los del otro se rellenan por conexion.  \~
    quic::ConnectionConfig connection;
    /// \~english The server's TLS: its certificate, key, and "h3" among the ALPN it accepts.
    /// \~spanish El TLS del servidor: su certificado, su clave, y "h3" entre los ALPN que acepta.  \~
    tls::SessionConfig tls;
    h3::Config h3;
    /// \~english How many connections at once; one more is not accepted.
    /// \~spanish Cuantas conexiones a la vez; una mas no se acepta.  \~
    uint32_t connections = 64;
    /// \~english The largest request body taken; a larger one is answered 413.
    /// \~spanish El cuerpo de peticion mas grande que se acepta; uno mayor se contesta 413.  \~
    size_t max_body = size_t{1} << 20;
};

/**
 * @brief
 * \~english Why things happened: every outcome has a counter.
 * \~spanish Por que pasaron las cosas: cada resultado tiene su contador.
 * \~
 */
struct Http3Counts {
    /// \~english Connections created, and datagrams that found no room for one.
    /// \~spanish Conexiones creadas, y datagramas que no encontraron sitio para una.  \~
    uint64_t accepted = 0;
    uint64_t full = 0;
    /// \~english Stateless replies the acceptor wrote, and those dropped because the queue was full.
    /// \~spanish Respuestas sin estado que escribio el acceptor, y las tiradas porque la cola estaba llena.  \~
    uint64_t replies = 0;
    uint64_t replies_dropped = 0;
    /// \~english Requests answered, refused 413, and answered 500 because the handler's answer could not travel.
    /// \~spanish Peticiones contestadas, rechazadas con 413, y contestadas 500 porque la respuesta del manejador no podia viajar.  \~
    uint64_t served = 0;
    uint64_t too_large = 0;
    uint64_t bad_answers = 0;
    /// \~english Connections that failed in HTTP/3, and connections gone.
    /// \~spanish Conexiones que fallaron en HTTP/3, y conexiones terminadas.  \~
    uint64_t failed = 0;
    uint64_t closed = 0;
    /// \~english Connections gone, by why they ended.  \~spanish Conexiones terminadas, por que acabaron.  \~
    uint64_t ended[static_cast<size_t>(quic::EndReason::kCount)] = {};
};

/**
 * @brief
 * \~english How one connection ended: the transport's reason and code, and the words of the layer that closed it.
 * \~spanish Como acabo una conexion: el motivo y el codigo del transporte, y las palabras de la capa que la cerro.
 * \~
 */
struct Http3End {
    quic::EndReason reason = quic::EndReason::None;
    uint64_t code = 0;
    bool application = false;
    /// \~english HTTP/3's or the handshake's reason, if either closed it; null otherwise.
    /// \~spanish La razon de HTTP/3 o del saludo, si alguno la cerro; nulo si no.  \~
    const char *why = nullptr;
};

/**
 * @brief
 * \~english A QUIC server speaking HTTP/3, without input or output.
 * \~spanish Un servidor QUIC que habla HTTP/3, sin entrada ni salida.
 * \~
 */
class Http3Service {
  public:
    Http3Service(quic::Crypto &crypto, Handler &handler) noexcept;
    ~Http3Service();
    Http3Service(const Http3Service &) = delete;
    Http3Service &operator=(const Http3Service &) = delete;

    /**
     * @brief
     * \~english Takes @p cfg and the memory for its connections; false, with why(), if either does not hold.
     * \~spanish Toma @p cfg y la memoria de sus conexiones; falso, con why(), si alguna no se sostiene.
     * \~
     *
     * \~english The pointers in @p cfg.tls outlive the service.
     * \~spanish Los punteros de @p cfg.tls viven mas que el servicio.  \~
     */
    bool start(const Http3Config &cfg) noexcept;

    /// \~english Why start() refused; null if it did not.  \~spanish Por que rechazo start(); nulo si no.  \~
    const char *why() const noexcept { return why_; }

    /**
     * @brief
     * \~english A datagram arrived on @p path.  Its bytes are decrypted in place.
     * \~spanish Llego un datagrama por @p path.  Sus bytes se descifran en su sitio.
     * \~
     */
    void on_datagram(const quic::Path &path, uint8_t *data, size_t n, quic::Ecn ecn, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english The next datagram to send, and the path it goes on; zero when there is none.
     * \~spanish El siguiente datagrama que mandar, y el camino por el que va; cero cuando no hay.
     * \~
     *
     * \~english @p room is at least the configured largest datagram.
     * \~spanish @p room es al menos el datagrama mas grande configurado.  \~
     */
    size_t next_datagram(quic::Path &path, uint8_t *out, size_t room, uint64_t now_us) noexcept;

    /// \~english When the earliest timer fires; quic::kNever if none.
    /// \~spanish Cuando vence el primer temporizador; quic::kNever si ninguno.  \~
    uint64_t timer() const noexcept;

    /// \~english Runs every timer that has come due by @p now_us.
    /// \~spanish Ejecuta cada temporizador que haya vencido a @p now_us.  \~
    void on_timer(uint64_t now_us) noexcept;

    /// \~english How many connections exist now.  \~spanish Cuantas conexiones existen ahora.  \~
    size_t connections() const noexcept { return live_; }

    const Http3Counts &counts() const noexcept { return counts_; }

    /// \~english How the last connection to go ended.  \~spanish Como acabo la ultima conexion que se fue.  \~
    const Http3End &last_end() const noexcept { return last_end_; }

    /// \~english The acceptor, for its counters.  \~spanish El acceptor, por sus contadores.  \~
    const quic::Acceptor *acceptor() const noexcept { return acceptor_; }

    /// \~english Gives the memory back and forgets every connection.
    /// \~spanish Devuelve la memoria y olvida todas las conexiones.  \~
    void release() noexcept;

  private:
    /// \~english How many IDs route to one connection: its own, plus the client's first.
    /// \~spanish Cuantos identificadores llevan a una conexion: los suyos, mas el primero del cliente.  \~
    static constexpr size_t kRoutes = 9;
    /// \~english Stateless replies waiting to go out.  \~spanish Respuestas sin estado esperando a salir.  \~
    static constexpr size_t kReplies = 32;
    static constexpr uint32_t kNone = 0xFFFFFFFF;

    /// \~english An ID, as bytes: up to twenty (RFC 9000, 17.2).  \~spanish Un identificador, como bytes: hasta veinte (RFC 9000, 17.2).  \~
    struct Cid {
        uint8_t bytes[quic::kMaxConnectionId] = {};
        uint8_t len = 0;
    };

    /// \~english One request being received or answered.  \~spanish Una peticion que se recibe o se contesta.  \~
    struct Work {
        uint64_t stream = ~uint64_t{0};
        bool used = false;
        /// \~english Past max_body: answered 413, the rest is not read.
        /// \~spanish Pasado max_body: contestada 413, el resto no se lee.  \~
        bool refused = false;
        Buffer body;
    };

    struct Slot;

    bool refuse_start(const char *why) noexcept;
    Slot *accept(const quic::Admission &ad, const quic::Path &path, uint8_t *data, size_t n, quic::Ecn ecn,
                 uint64_t now_us) noexcept;
    void touch(uint32_t i, uint64_t now_us) noexcept;
    void pump(Slot &s, uint64_t now_us) noexcept;
    void on_event(Slot &s, const h3::Event &e) noexcept;
    void answer(Slot &s, Work &w) noexcept;
    void respond_status(Slot &s, uint64_t stream, StatusCode status) noexcept;
    void free_slot(uint32_t i) noexcept;

    // \~english A slot's routes in step with its IDs, and the send queue (service_route.cpp).
    // \~spanish Las rutas de una casilla al dia con sus identificadores, y la cola de envio (service_route.cpp).  \~
    void sync_routes(uint32_t i, uint64_t now_us) noexcept;
    void queue_send(uint32_t i) noexcept;

    quic::Crypto &crypto_;
    Handler &handler_;
    Http3Config cfg_;
    const char *why_ = nullptr;
    quic::Acceptor *acceptor_ = nullptr;

    Slot *slots_ = nullptr;
    uint32_t capacity_ = 0;
    uint32_t free_ = kNone;
    size_t live_ = 0;

    /// \~english Which slot each connection ID leads to.  \~spanish A que casilla lleva cada identificador de conexion.  \~
    quic::CidRoutes routes_;
    /// \~english When each slot's timer fires.  \~spanish Cuando vence el temporizador de cada casilla.  \~
    DeadlineHeap timers_;

    uint32_t *send_ = nullptr;
    size_t send_head_ = 0;
    size_t send_count_ = 0;

    struct Reply {
        quic::Path path;
        uint8_t bytes[1200] = {};
        size_t len = 0;
    };
    Reply replies_[kReplies];
    size_t reply_head_ = 0;
    size_t reply_count_ = 0;

    /// \~english Where a handler answers, and where unknown field names are lowered.
    /// \~spanish Donde contesta un manejador, y donde se bajan a minusculas los nombres desconocidos.  \~
    Buffer said_;
    Buffer names_;
    Http3Counts counts_;
    Http3End last_end_;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP3_SERVICE_H
