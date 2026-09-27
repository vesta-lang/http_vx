/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h3_connection.h
 * @brief
 * \~english One HTTP/3 connection over a QUIC connection: streams in, messages out (RFC 9114, 4-8).
 * \~spanish Una conexion HTTP/3 sobre una conexion QUIC: entran flujos, salen mensajes (RFC 9114, 4-8).
 * \~
 *
 * \~english
 * HTTP/3 has no byte stream of its own: it is what it puts on QUIC's.  Each
 * endpoint opens three unidirectional streams -- its control stream, which
 * starts with SETTINGS, and QPACK's encoder and decoder streams -- and every
 * request lives on a client-initiated bidirectional stream of its own
 * (6.1, 6.2).  This class keeps them apart and says what happened on them,
 * one event at a time, in the order a caller can act on.
 *
 * **Sans-IO, like the rest.**  It reads and writes the streams of a
 * quic::Connection that someone else feeds and drains; it never touches a
 * socket or a clock of its own.
 *
 * **What is wrong is said, and scoped.**  A stream that breaks a rule of
 * the message -- a malformed request, one cut short -- is a stream error:
 * that stream is reset and the rest go on.  One that breaks the connection's
 * -- a second control stream, DATA before HEADERS, a frame that does not add
 * up -- closes the connection with its code (8).  Both leave the rule in
 * words.
 *
 * **No server push.**  This end never sends MAX_PUSH_ID or PUSH_PROMISE;
 * a push stream or a CANCEL_PUSH aimed at it is the error 4.6 and 7.2.3 name.
 *
 * \~spanish
 * HTTP/3 no tiene flujo de bytes propio: es lo que pone en los de QUIC.  Cada
 * extremo abre tres flujos unidireccionales -- su flujo de control, que empieza
 * con SETTINGS, y los flujos del codificador y del descodificador de QPACK -- y
 * cada peticion vive en un flujo bidireccional propio abierto por el cliente
 * (6.1, 6.2).  Esta clase los separa y dice que paso en ellos, un evento cada
 * vez, en el orden en que quien llama puede actuar.
 *
 * **Sin E/S, como el resto.**  Lee y escribe los flujos de una
 * quic::Connection que otro alimenta y vacia; nunca toca un socket ni un reloj
 * propios.
 *
 * **Lo que esta mal se dice, y con su alcance.**  Un flujo que rompe una regla
 * del mensaje -- una peticion mal formada, una cortada -- es un error de flujo:
 * ese flujo se reinicia y los demas siguen.  Uno que rompe la de la conexion --
 * un segundo flujo de control, DATA antes de HEADERS, una trama que no cuadra --
 * cierra la conexion con su codigo (8).  Los dos dejan la regla en palabras.
 *
 * **Sin server push.**  Este extremo nunca manda MAX_PUSH_ID ni PUSH_PROMISE;
 * un flujo de push o un CANCEL_PUSH dirigido a el es el error que nombran 4.6 y
 * 7.2.3.
 * \~
 */
#ifndef HTTP_VX_H3_CONNECTION_H
#define HTTP_VX_H3_CONNECTION_H

#include "http_vx/buffer.h"
#include "http_vx/h3_frame.h"
#include "http_vx/id_index.h"
#include "http_vx/message.h"
#include "http_vx/qpack_decoder.h"
#include "http_vx/qpack_encoder.h"
#include "http_vx/quic_connection.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h3 {

/**
 * @brief
 * \~english What this end announces and keeps.  \~spanish Lo que anuncia y guarda este extremo.
 * \~
 */
struct Config {
    bool server = true;
    /// \~english Sent in SETTINGS: QPACK's table and blocked streams, and the largest field section taken.
    /// \~spanish Se manda en SETTINGS: la tabla y los flujos bloqueados de QPACK, y la mayor seccion de campos aceptada.  \~
    Settings local;
    /// \~english The most table this end's encoder uses, whatever the peer allows.
    /// \~spanish La mayor tabla que usa el codificador de este extremo, permita lo que permita el otro.  \~
    uint64_t encoder_capacity = 4096;
    /// \~english Request streams followed at once; one more is refused with H3_REQUEST_REJECTED.
    /// \~spanish Flujos de peticion seguidos a la vez; uno mas se rechaza con H3_REQUEST_REJECTED.  \~
    size_t max_requests = 64;
    /// \~english The most a frame other than DATA may hold (10.5).  \~spanish Lo mas que puede guardar una trama distinta de DATA (10.5).  \~
    uint64_t max_held = FrameReader::kDefaultMaxHeld;
};

/**
 * @brief
 * \~english What poll() found.  \~spanish Lo que encontro poll().
 * \~
 */
enum class EventKind : uint8_t {
    None,
    /// \~english Server: a request's header section; request() has it.  \~spanish Servidor: la seccion de cabecera de una peticion; request() la tiene.  \~
    Request,
    /// \~english Client: a response's header section, interim or final; response() has it.
    /// \~spanish Cliente: la seccion de cabecera de una respuesta, provisional o final; response() la tiene.  \~
    Response,
    /// \~english Content bytes: data and len, valid until the next poll().  \~spanish Bytes de contenido: data y len, validos hasta el siguiente poll().  \~
    Body,
    /// \~english A trailer section: its fields joined the message's.  \~spanish Una seccion de remolques: sus campos se unieron a los del mensaje.  \~
    Trailers,
    /// \~english The message is whole: the peer ended the stream cleanly.  \~spanish El mensaje esta entero: el otro acabo el flujo limpiamente.  \~
    End,
    /// \~english The stream ended in error -- reset by the peer, or by this end over a rule; code says which.
    /// \~spanish El flujo acabo en error -- reiniciado por el otro, o por este extremo por una regla; code dice cual.  \~
    Reset,
    /// \~english The peer sent GOAWAY; code is its identifier.  \~spanish El otro mando GOAWAY; code es su identificador.  \~
    GoAway,
    /// \~english The connection failed: failure() says why.  \~spanish La conexion fallo: failure() dice por que.  \~
    Closed,
};

/**
 * @brief
 * \~english One event.  \~spanish Un evento.
 * \~
 */
struct Event {
    EventKind kind = EventKind::None;
    uint64_t stream = 0;
    uint64_t code = 0;
    const uint8_t *data = nullptr;
    size_t len = 0;
    /**
     * \~english
     * For an event of a request stream, which of the Config::max_requests
     * places holds it -- the same one from its Request or Response to its End
     * or Reset, and reused after.  What lets the application keep its own
     * state per request in an array of the same size, reached without a
     * search.  kNoSlot for an event of the connection.
     * \~spanish
     * Para un evento de un flujo de peticion, cual de los Config::max_requests
     * sitios lo guarda -- el mismo desde su Request o Response hasta su End o
     * Reset, y reutilizado despues.  Lo que deja a la aplicacion guardar su
     * propio estado por peticion en un array del mismo tamano, alcanzado sin
     * buscar.  kNoSlot para un evento de la conexion.
     * \~
     */
    size_t slot = kNoSlot;

    static constexpr size_t kNoSlot = ~size_t{0};
};

/**
 * @brief
 * \~english An HTTP/3 connection, either end.  \~spanish Una conexion HTTP/3, de cualquiera de los dos extremos.
 * \~
 */
class Connection {
public:
    explicit Connection(quic::Connection &q) noexcept : q_(q) {}
    ~Connection();
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    /**
     * @brief
     * \~english Ready to run: its own streams are opened as soon as the transport allows (6.2.1, 7.2.4.2).
     * \~spanish Listo para funcionar: sus propios flujos se abren en cuanto el transporte lo permite (6.2.1, 7.2.4.2).
     * \~
     */
    bool start(const Config &cfg) noexcept;

    /**
     * @brief
     * \~english The next thing that happened; None when there is nothing more for now.
     * \~spanish Lo siguiente que paso; None cuando por ahora no hay nada mas.
     * \~
     *
     * \~english
     * Call it after the QUIC connection took datagrams, until it gives None;
     * then let the QUIC connection build its datagrams.  @p now_us is used
     * only to close the connection when it fails.
     * \~spanish
     * Llamarlo despues de que la conexion QUIC tome datagramas, hasta que de
     * None; despues dejar que la conexion QUIC construya sus datagramas.  @p
     * now_us solo se usa para cerrar la conexion cuando falla.
     * \~
     */
    Event poll(uint64_t now_us) noexcept;

    /* \~english
     * A message is read when its event comes: once its stream is gone from
     * QUIC -- both directions over -- the next poll() lets it go.
     * \~spanish
     * Un mensaje se lee cuando llega su evento: cuando su flujo ya no esta en
     * QUIC -- las dos direcciones acabadas -- el siguiente poll() lo suelta.
     * \~ */
    /// \~english Server: the request on @p stream, and the bytes its spans point into; null if none.
    /// \~spanish Servidor: la peticion de @p stream, y los bytes a los que apuntan sus tramos; nulo si no hay.  \~
    const Request *request(uint64_t stream, const Buffer *&bytes) const noexcept;
    /// \~english Client: the last response section on @p stream; null if none.
    /// \~spanish Cliente: la ultima seccion de respuesta de @p stream; nulo si no hay.  \~
    const Response *response(uint64_t stream, const Buffer *&bytes) const noexcept;

    /**
     * @brief
     * \~english Server: a response header section: interim (1xx) any number of times, then one final (4.1).
     * \~spanish Servidor: una seccion de cabecera de respuesta: provisionales (1xx) las que sean, y una final (4.1).
     * \~
     */
    bool respond(uint64_t stream, StatusCode status, const qpack::Line *fields, size_t count, bool end) noexcept;
    /// \~english Content bytes on @p stream, in DATA frames; @p end closes it.  \~spanish Bytes de contenido en @p stream, en tramas DATA; @p end lo cierra.  \~
    bool send_body(uint64_t stream, const uint8_t *p, size_t n, bool end) noexcept;

    /**
     * \~english
     * The DATA frame header of a body filled in place: its type in one byte
     * and its length in two, whatever the length.  Two bytes hold up to 16383
     * and a fill is at most one send chunk, so the width is fixed before the
     * length is known; a length need not be minimal (RFC 9000, 16 -- only a
     * QUIC frame's type must be; RFC 9114, 7.1).
     * \~spanish
     * La cabecera de trama DATA de un cuerpo rellenado en su sitio: su tipo en un
     * byte y su longitud en dos, sea cual sea la longitud.  Dos bytes caben hasta
     * 16383 y un relleno es como mucho un trozo de envio, asi que el ancho se fija
     * antes de saber la longitud; una longitud no tiene por que ser minima (RFC
     * 9000, 16 -- solo el tipo de una trama QUIC tiene que serlo; RFC 9114, 7.1).
     * \~
     */
    static constexpr size_t kFillHead = 3;

    /**
     * \~english
     * The most a stream with an open body keeps written and not yet sent: one
     * chunk.  The transport's credit could let a source fill far more, and all
     * of it would sit in memory until the congestion window let it go; this
     * way what is filled is what is about to leave, and the next fill comes
     * when it has left.
     * \~spanish
     * Lo mas que guarda escrito y sin mandar un flujo con un cuerpo abierto: un
     * trozo.  El credito del transporte podria dejar a una fuente rellenar mucho
     * mas, y todo se quedaria en memoria hasta que la ventana de congestion lo
     * dejara salir; asi lo que se rellena es lo que esta a punto de salir, y el
     * siguiente relleno llega cuando ha salido.
     * \~
     */
    static constexpr size_t kFillAhead = quic::kRecvChunk;

    /// \~english Server: which place holds @p stream's message (Event::slot); Event::kNoSlot if none.
    /// \~spanish Servidor: que sitio guarda el mensaje de @p stream (Event::slot); Event::kNoSlot si ninguno.  \~
    size_t slot_of(uint64_t stream) const noexcept;

    /**
     * @brief
     * \~english Server: where the body of the next DATA frame on @p stream is written, in place; null if there is no room.
     * \~spanish Servidor: donde se escribe el cuerpo de la siguiente trama DATA de @p stream, en su sitio; nulo si no hay sitio.
     * \~
     *
     * \~english
     * The room is the least of the stream's flow control credit, the
     * connection's (less what this stream and this end's control and QPACK
     * streams wrote and have not sent), kFillAhead and what the send side has
     * contiguous, all after the frame header.  None
     * before the final response's header section has gone into the stream, or
     * once the stream is ended or reset.  The pointer is taken by body_commit,
     * which MUST come next.
     * \~spanish
     * El sitio es el menor del credito de control de flujo del flujo, el de la
     * conexion (menos lo que este flujo y los flujos de control y de QPACK de este
     * extremo escribieron y no mandaron), kFillAhead y lo que tiene seguido el
     * lado de envio, todo tras la cabecera de la trama.  Ninguno
     * antes de que la cabecera de la respuesta final haya entrado en el flujo, ni
     * cuando el flujo acabo o se reinicio.  El puntero lo toma body_commit, que
     * DEBE ir justo despues.
     * \~
     *
     * @param room \~english how many body bytes fit there  \~spanish cuantos bytes de cuerpo caben ahi  \~
     */
    uint8_t *body_room(uint64_t stream, size_t &room) noexcept;

    /**
     * @brief
     * \~english Server: the @p n bytes written at body_room become one DATA frame; @p end ends the stream after it.
     * \~spanish Servidor: los @p n bytes escritos en body_room pasan a ser una trama DATA; @p end acaba el flujo tras ella.
     * \~
     *
     * \~english Zero bytes is no frame; with @p end, the stream ends alone.
     * \~spanish Cero bytes es ninguna trama; con @p end, el flujo acaba solo.  \~
     *
     * @return \~english false if this was not the room given, or @p n exceeds it: the connection fails, loudly
     *         \~spanish false si este no era el sitio dado, o @p n lo supera: la conexion falla, en voz alta  \~
     */
    bool body_commit(uint64_t stream, size_t n, bool end) noexcept;

    /// \~english Client: opens a request stream and sends its header section; the stream's ID, or ~0.
    /// \~spanish Cliente: abre un flujo de peticion y manda su seccion de cabecera; el ID del flujo, o ~0.  \~
    uint64_t send_request(const qpack::Line *lines, size_t count, bool end) noexcept;

    /**
     * @brief
     * \~english Abandons @p stream: both directions stop, with @p code (4.1.1).
     * \~spanish Abandona @p stream: se paran las dos direcciones, con @p code (4.1.1).
     * \~
     */
    void cancel(uint64_t stream, uint64_t code) noexcept;

    /**
     * @brief
     * \~english Server: stops reading @p stream's request, keeping the response (4.1.1).
     * \~spanish Servidor: deja de leer la peticion de @p stream, conservando la respuesta (4.1.1).
     * \~
     *
     * \~english
     * For a response that does not need the rest of the request -- a 413, say.
     * The client is asked to stop sending with H3_NO_ERROR, QPACK is told the
     * stream's sections will not be read (RFC 9204, 4.4.2), and nothing more
     * of the request is reported; what still arrives, a reset included, is
     * thrown away.  The response is sent whole: a client MUST NOT discard it
     * for having had its request cut short.  The bytes of a Body event on
     * the stream are gone from here on: copy them first.
     * \~spanish
     * Para una respuesta que no necesita el resto de la peticion -- un 413, por
     * ejemplo.  Se le pide al cliente que deje de mandar con H3_NO_ERROR, se le
     * dice a QPACK que las secciones del flujo no se leeran (RFC 9204, 4.4.2), y
     * no se informa de nada mas de la peticion; lo que siga llegando, un
     * reinicio incluido, se tira.  La respuesta se manda entera: un cliente NO
     * DEBE tirarla por haberse cortado su peticion.  Los bytes de un evento Body
     * del flujo desaparecen desde aqui: copiarlos antes.
     * \~
     */
    bool stop_reading(uint64_t stream) noexcept;

    /// \~english Server: a graceful shutdown -- requests from here on are refused (5.2).
    /// \~spanish Servidor: un cierre ordenado -- las peticiones desde aqui se rechazan (5.2).  \~
    bool goaway() noexcept;

    bool failed() const noexcept { return failure_.code != 0; }
    const Failure &failure() const noexcept { return failure_; }
    /// \~english Why the last stream reset by this end was; null if none.  \~spanish Por que fue el ultimo flujo reiniciado por este extremo; nulo si ninguno.  \~
    const char *stream_why() const noexcept { return stream_why_; }
    bool peer_settings_known() const noexcept { return peer_settings_; }
    const Settings &peer_settings() const noexcept { return peer_; }
    const qpack::Decoder &decoder() const noexcept { return decoder_; }
    const qpack::Encoder &encoder() const noexcept { return encoder_; }

private:
    enum class Phase : uint8_t { Headers, Body, Trailers, Done };

    /// \~english The end of a list of messages.  \~spanish El final de una lista de mensajes.  \~
    static constexpr uint32_t kNoLink = 0xFFFFFFFFu;

    /* \~english One request stream: its frames in, its message, and what waits to go out.
     * \~spanish Un flujo de peticion: sus tramas de entrada, su mensaje, y lo que espera salir.  \~ */
    struct Message {
        uint64_t id = 0;
        bool used = false;
        Phase phase = Phase::Headers;
        FrameReader reader;
        /// \~english A HEADERS payload QPACK could not read yet (2.2.1).  \~spanish Una carga HEADERS que QPACK aun no pudo leer (2.2.1).  \~
        Buffer blocked;
        bool is_blocked = false;
        Request request;
        Response response;
        Buffer fields;
        uint64_t content_length = ~uint64_t{0};
        uint64_t body_seen = 0;
        /// \~english Client: the request was HEAD, so the response has no content (RFC 9110, 6.4.1).
        /// \~spanish Cliente: la peticion fue HEAD, asi que la respuesta no tiene contenido (RFC 9110, 6.4.1).  \~
        bool head_request = false;
        bool final_response = false;
        bool final_sent = false;
        bool end_reported = false;
        Buffer out;
        bool out_fin = false;
        /// \~english Neighbours in the live list, or (next only) in the free list.
        /// \~spanish Vecinos en la lista de vivos, o (solo next) en la lista libre.  \~
        uint32_t prev = kNoLink;
        uint32_t next = kNoLink;
    };

    /* \~english A stream this end opened, or a peer's unidirectional one, and what it is.
     * \~spanish Un flujo que abrio este extremo, o uno unidireccional del otro, y que es.  \~ */
    struct Uni {
        uint64_t id = ~uint64_t{0};
        uint64_t type = ~uint64_t{0};
        bool discard = false;
        /// \~english The stream type, gathered a byte at a time (6.2).  \~spanish El tipo de flujo, juntado byte a byte (6.2).  \~
        uint8_t head[8] = {};
        size_t head_len = 0;
        FrameReader reader;
        Buffer out;
    };

    bool fail(uint64_t code, const char *why) noexcept;
    Event stream_error(Message &m, uint64_t code, const char *why) noexcept;
    bool open_local() noexcept;
    bool read_uni(quic::Stream &s, Uni &u) noexcept;
    bool on_control(Uni &u, quic::Stream &s) noexcept;
    bool on_control_frame(uint64_t type, const uint8_t *p, size_t n) noexcept;
    Event read_message(quic::Stream &s, Message &m) noexcept;
    Event on_headers(Message &m, const uint8_t *p, size_t n) noexcept;
    Event on_trailers(Message &m, const uint8_t *p, size_t n) noexcept;
    Event finish_headers(Message &m, qpack::Outcome o, const char *sink_why) noexcept;
    Message *message(uint64_t id) noexcept;
    const Message *message(uint64_t id) const noexcept;
    Message *adopt(uint64_t id) noexcept;
    void drop(Message &m) noexcept;
    /// \~english Puts message @p i last in the live list.  \~spanish Pone el mensaje @p i el ultimo de la lista de vivos.  \~
    void link_last(uint32_t i) noexcept;
    /// \~english Takes message @p i out of the live list.  \~spanish Saca el mensaje @p i de la lista de vivos.  \~
    void unlink(uint32_t i) noexcept;
    Uni *uni(uint64_t id) noexcept;
    bool encode(Message &m, const qpack::Line *lines, size_t count, bool end) noexcept;
    void flush() noexcept;
    bool flush_one(Buffer &out, bool fin, uint64_t id) noexcept;
    size_t encoder_room() noexcept;

    quic::Connection &q_;
    Config cfg_;
    Failure failure_;
    const char *stream_why_ = nullptr;
    bool started_ = false;
    bool closed_reported_ = false;

    qpack::Decoder decoder_;
    qpack::Encoder encoder_;
    Settings peer_;
    bool peer_settings_ = false;

    /* \~english This end's three streams (control, QPACK encoder, QPACK decoder), then the peer's.
     * \~spanish Los tres flujos de este extremo (control, codificador y descodificador de QPACK), y despues los del otro.  \~ */
    static constexpr size_t kLocalUni = 3;
    static constexpr size_t kPeerUni = 8;
    Uni local_[kLocalUni];
    Uni peer_uni_[kPeerUni];
    bool peer_control_ = false;
    bool peer_encoder_ = false;
    bool peer_decoder_ = false;

    /* \~english
     * The request streams, and the three ways into them, each constant time:
     * by stream ID (the index), the live ones in turn (a list whose head is
     * the next to be read: whoever produced an event goes last), and a free
     * one to take (a list through the same links).  A table walk on every
     * poll and every frame cost the whole table even with one request alive.
     * \~spanish
     * Los flujos de peticion, y las tres formas de llegar a ellos, cada una en
     * tiempo constante: por identificador de flujo (el indice), los vivos por
     * turno (una lista cuya cabeza es el siguiente a leer: quien produjo un
     * evento pasa el ultimo), y uno libre que coger (una lista por los mismos
     * enlaces).  Recorrer la tabla en cada poll y cada trama costaba la tabla
     * entera aunque solo viviera una peticion.
     * \~ */
    Message *messages_ = nullptr;
    IdIndex by_id_;
    uint32_t free_head_ = kNoLink;
    uint32_t live_head_ = kNoLink;
    uint32_t live_tail_ = kNoLink;

    /* \~english Bytes handed out with a Body event, consumed at the next poll.
     * \~spanish Bytes entregados con un evento Body, consumidos en el siguiente poll.  \~ */
    uint64_t defer_stream_ = ~uint64_t{0};
    size_t defer_n_ = 0;

    /* \~english The room body_room gave, and on which stream: what body_commit checks.
     * \~spanish El sitio que dio body_room, y en que flujo: lo que comprueba body_commit.  \~ */
    uint64_t fill_stream_ = ~uint64_t{0};
    size_t fill_room_ = 0;

    /// \~english GOAWAY sent (server: the first stream refused) and received.  \~spanish GOAWAY mandado (servidor: el primer flujo rechazado) y recibido.  \~
    uint64_t goaway_sent_ = ~uint64_t{0};
    uint64_t goaway_received_ = ~uint64_t{0};
    bool goaway_event_ = false;
    uint64_t max_push_id_ = ~uint64_t{0};
    /// \~english Server: the next client request stream not seen yet.  \~spanish Servidor: el siguiente flujo de peticion del cliente aun sin ver.  \~
    uint64_t next_request_ = 0;
    /// \~english The index of the peer's next unidirectional stream not seen yet.
    /// \~spanish El indice del siguiente flujo unidireccional del otro aun sin ver.  \~
    uint64_t next_uni_ = 0;
    /// \~english The time of the last poll, for closing.  \~spanish La hora del ultimo poll, para cerrar.  \~
    uint64_t now_ = 0;
    /* \~english
     * Streams QPACK has let go of and that are not reread yet.  Taking them
     * removes them from QPACK, and a poll returns at the first event -- so
     * the rest of a batch has to be kept here, or those streams stay blocked
     * for good.
     * \~spanish
     * Flujos que QPACK ha soltado y que aun no se han releido.  Cogerlos los
     * quita de QPACK, y un poll vuelve en el primer evento -- asi que el resto
     * de una tanda tiene que guardarse aqui, o esos flujos se quedan
     * bloqueados para siempre.
     * \~ */
    static constexpr size_t kUnblockedBatch = 16;
    uint64_t unblocked_[kUnblockedBatch] = {};
    size_t unblocked_count_ = 0;
    size_t unblocked_at_ = 0;
};

} // namespace h3
} // namespace http_vx

#endif // HTTP_VX_H3_CONNECTION_H
