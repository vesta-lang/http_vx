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
    /**
     * \~english
     * How many open responses (HVX-5) one connection may have at once; one
     * more is answered 503.  The shard's port keeps the shard's limit and not
     * this one, because a datagram service's connections are its own.  At
     * most h3.max_requests: an open response is a request still answering.
     * \~spanish
     * Cuantas respuestas abiertas (HVX-5) puede tener una conexion a la vez; una
     * mas se contesta 503.  La puerta del fragmento lleva el tope del fragmento y
     * no este, porque las conexiones de un servicio de datagramas son suyas.  Como
     * mucho h3.max_requests: una respuesta abierta es una peticion que sigue
     * contestandose.
     * \~
     */
    uint32_t max_open_per_conn = 16;
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
    /// \~english 0-RTT offered by a client and accepted, or refused (RFC 9001, 4.6).
    /// \~spanish 0-RTT ofrecido por un cliente y aceptado, o rechazado (RFC 9001, 4.6).  \~
    uint64_t early_accepted = 0;
    uint64_t early_refused = 0;
    /// \~english Connections gone, by why they ended.  \~spanish Conexiones terminadas, por que acabaron.  \~
    uint64_t ended[static_cast<size_t>(quic::EndReason::kCount)] = {};
    /// \~english Opens refused by max_open_per_conn (the shard counts its own), and requests answered 503 for either.
    /// \~spanish Aperturas rechazadas por max_open_per_conn (el fragmento cuenta las suyas), y peticiones contestadas 503 por cualquiera.  \~
    uint64_t open_limited = 0;
    uint64_t unavailable = 0;
    /// \~english Kicks for a source this service no longer feeds.  \~spanish Avisos a una fuente que este servicio ya no alimenta.  \~
    uint64_t stray_kicks = 0;
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
 *
 * \~english
 * It is the kick target of the responses it opens (HVX-5, 7.3): a kick only
 * marks the stream and queues its connection, and the fill happens when the
 * loop pulls datagrams -- after it drained the kicks -- so what a source
 * writes leaves in the datagram built right after.
 * \~spanish
 * Es el destino de los avisos de las respuestas que abre (HVX-5, 7.3): un aviso
 * solo marca el flujo y pone su conexion en la cola, y el relleno ocurre cuando
 * el bucle saca datagramas -- despues de vaciar los avisos --, asi que lo que
 * escribe una fuente sale en el datagrama que se construye justo despues.
 * \~
 */
class Http3Service final : public KickTarget {
  public:
    Http3Service(quic::Crypto &crypto, Handler &handler) noexcept;
    ~Http3Service() override;
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

    /// \~english Why the last 0-RTT offered was refused; null if none was.
    /// \~spanish Por que se rechazo el ultimo 0-RTT ofrecido; nulo si no se rechazo ninguno.  \~
    const char *last_early_refused() const noexcept { return last_early_refused_; }

    /// \~english The acceptor, for its counters.  \~spanish El acceptor, por sus contadores.  \~
    const quic::Acceptor *acceptor() const noexcept { return acceptor_; }

    /// \~english Gives the memory back and forgets every connection.
    /// \~spanish Devuelve la memoria y olvida todas las conexiones.  \~
    void release() noexcept;

    /**
     * @brief
     * \~english Takes the loop's side of open responses; without one, nothing opens.
     * \~spanish Toma el lado del bucle de las respuestas abiertas; sin el, no se abre nada.
     * \~
     *
     * @param port \~english the shard's port; it outlives every response it opens
     *             \~spanish la puerta del fragmento; vive mas que toda respuesta que abra  \~
     */
    void attach(OpenPort *port) noexcept { port_ = port; }

    /// \~english The loop lets go: every open response ends with GoneReason::Shutdown.
    /// \~spanish El bucle lo suelta todo: cada respuesta abierta acaba con GoneReason::Shutdown.  \~
    void on_shutdown() noexcept;

    /**
     * @brief
     * \~english @p source was kicked: its stream is marked and its connection queued; the fill comes with the next pull.
     * \~spanish Avisaron a @p source: su flujo se marca y su conexion entra en la cola; el relleno llega con el siguiente tiron.
     * \~
     */
    void on_kick(BodySource &source) noexcept override;

    /// \~english How many responses are open now, on every connection.  \~spanish Cuantas respuestas hay abiertas ahora, en todas las conexiones.  \~
    size_t open_now() const noexcept { return open_now_; }

  private:
    /**
     * @brief
     * \~english The port a handler opens through: this service's limit per connection, then the loop's.
     * \~spanish La puerta por la que abre un manejador: el tope por conexion de este servicio, y despues el del bucle.
     * \~
     *
     * \~english
     * The loop's port checks the shard's limit only; the connection's is kept
     * here, and a handler can only meet it through ResponseBuilder::open --
     * so the builder is given this, which refuses past the limit and hands
     * everything else on.
     * \~spanish
     * La puerta del bucle solo comprueba el tope del fragmento; el de la conexion
     * se lleva aqui, y un manejador solo puede toparse con el por
     * ResponseBuilder::open -- asi que al constructor se le da esto, que rechaza
     * pasado el tope y pasa todo lo demas.
     * \~
     */
    class OpenGate final : public OpenPort {
      public:
        explicit OpenGate(Http3Service &service) noexcept : service_(&service) {}
        OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s, KickTarget &target) noexcept override;
        size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override;
        void end(BodySource &s, GoneReason why) noexcept override;

      private:
        Http3Service *service_;
    };

    struct OpenStream;
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

    // \~english A handler's head section, shared by whole and open answers (service_requests.cpp).
    // \~spanish La seccion de cabecera de un manejador, comun a respuestas enteras y abiertas (service_requests.cpp).  \~
    bool send_head(Slot &s, uint64_t stream, const ResponseBuilder &res, bool head_request, bool end) noexcept;

    // \~english Open responses (service_open.cpp).  \~spanish Respuestas abiertas (service_open.cpp).  \~
    ConnHandle handle_of(uint32_t i) const noexcept;
    Slot *slot_of(ConnHandle c) noexcept;
    void start_open(uint32_t i, size_t place, uint64_t stream, const ResponseBuilder &res) noexcept;
    void fill_open(Slot &s, uint32_t place) noexcept;
    void feed_open(Slot &s) noexcept;
    void watch_open(Slot &s) noexcept;
    void end_open(Slot &s, uint32_t place, GoneReason why) noexcept;
    void end_all_open(Slot &s, GoneReason why) noexcept;

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
    const char *last_early_refused_ = nullptr;

    /// \~english The loop's side of open responses, or null: then nothing opens.
    /// \~spanish El lado del bucle de las respuestas abiertas, o nulo: entonces no se abre nada.  \~
    OpenPort *port_ = nullptr;
    OpenGate gate_{*this};
    size_t open_now_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP3_SERVICE_H
