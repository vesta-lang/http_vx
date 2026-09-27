/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_streams.h
 * @brief
 * \~english The streams of one QUIC connection: who may open what, and how many (RFC 9000, 2-4).
 * \~spanish Los flujos de una conexion QUIC: quien puede abrir que, y cuantos (RFC 9000, 2-4).
 * \~
 *
 * \~english
 * A stream ID says who opened it and whether data goes both ways (2.1), and
 * that is enough to know which frames may name it: the peer cannot send data
 * on a stream that only this end sends on, nor flow control for one that only
 * it sends on.  Every frame that names a stream goes through here first, and
 * comes out as a stream to act on, a stream already closed to ignore, or the
 * transport error that closes the connection.
 *
 * **The table is fixed in size, and the peer cannot grow it.**  The limit
 * this end announces (MAX_STREAMS) moves as "closed so far plus the
 * concurrency allowed", so the streams the peer has open never exceed that
 * concurrency, and everything can be allocated when the connection starts.
 * Opening a stream also opens every lower one of its type (3.2): those take
 * room too, and the limit already counts them.
 *
 * \~spanish
 * El identificador de un flujo dice quien lo abrio y si los datos van en los dos
 * sentidos (2.1), y con eso basta para saber que tramas pueden nombrarlo: el otro
 * extremo no puede mandar datos por un flujo por el que solo manda este extremo,
 * ni control de flujo por uno por el que solo manda el.  Toda trama que nombra un
 * flujo pasa antes por aqui, y sale como un flujo sobre el que actuar, un flujo
 * ya cerrado que ignorar, o el error de transporte que cierra la conexion.
 *
 * **La tabla es de tamano fijo, y el otro extremo no la puede hacer crecer.**  El
 * limite que anuncia este extremo (MAX_STREAMS) se mueve como "cerrados hasta
 * ahora mas la concurrencia permitida", asi que los flujos que tiene abiertos el
 * otro extremo nunca pasan de esa concurrencia, y todo se puede reservar al
 * empezar la conexion.  Abrir un flujo abre tambien todos los de debajo de su
 * tipo (3.2): esos ocupan sitio tambien, y el limite ya los cuenta.
 * \~
 */
#ifndef HTTP_VX_QUIC_STREAMS_H
#define HTTP_VX_QUIC_STREAMS_H

#include "http_vx/id_index.h"
#include "http_vx/quic_ack.h"
#include "http_vx/quic_frame.h"
#include "http_vx/quic_stream_recv.h"
#include "http_vx/quic_stream_send.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english Whether @p id is unidirectional.  \~spanish Si @p id es unidireccional.  \~
inline bool stream_is_uni(uint64_t id) noexcept { return (id & 0x02) != 0; }

/// \~english Whether the server opened @p id.  \~spanish Si @p id lo abrio el servidor.  \~
inline bool stream_is_server_initiated(uint64_t id) noexcept { return (id & 0x01) != 0; }

/// \~english The stream's position among those of its type: 0, 1, 2 ...
/// \~spanish La posicion del flujo entre los de su tipo: 0, 1, 2 ...  \~
inline uint64_t stream_index(uint64_t id) noexcept { return id >> 2; }

/**
 * @brief
 * \~english The limits and windows of a connection's streams, both ends'.
 * \~spanish Los limites y ventanas de los flujos de una conexion, de los dos extremos.
 * \~
 *
 * \~english
 * The window names follow the transport parameters (18.2): "bidi_local" is
 * for the bidirectional streams the endpoint that announces it opened
 * itself, "bidi_remote" for those its peer opened.
 * \~spanish
 * Los nombres de las ventanas siguen a los parametros de transporte (18.2):
 * "bidi_local" es para los flujos bidireccionales que abrio el propio extremo que
 * lo anuncia, "bidi_remote" para los que abrio su otro extremo.
 * \~
 */
struct StreamConfig {
    bool is_server = true;

    /// \~english How many of the peer's streams may be open at once: what MAX_STREAMS keeps ahead.
    /// \~spanish Cuantos flujos del otro extremo pueden estar abiertos a la vez: lo que MAX_STREAMS mantiene por delante.  \~
    uint64_t peer_bidi_concurrency = 100;
    uint64_t peer_uni_concurrency = 3;

    /// \~english How many streams this end may have open that it opened itself.
    /// \~spanish Cuantos flujos abiertos por este extremo puede tener abiertos a la vez.  \~
    uint64_t local_concurrency = 16;

    /// \~english This end's receive windows.  \~spanish Las ventanas de recepcion de este extremo.  \~
    uint64_t window_bidi_local = 1u << 20;
    uint64_t window_bidi_remote = 1u << 20;
    uint64_t window_uni = 1u << 20;

    /// \~english How much each stream may keep written and unacknowledged.
    /// \~spanish Cuanto puede guardar cada flujo escrito y sin confirmar.  \~
    uint64_t send_capacity = 1u << 20;

    /// \~english The peer's transport parameters.  \~spanish Los parametros de transporte del otro extremo.  \~
    uint64_t peer_max_streams_bidi = 0;
    uint64_t peer_max_streams_uni = 0;
    uint64_t peer_window_bidi_local = 0;
    uint64_t peer_window_bidi_remote = 0;
    uint64_t peer_window_uni = 0;
};

/**
 * @brief
 * \~english One stream: its receiving part, its sending part, or both.
 * \~spanish Un flujo: su parte receptora, su parte emisora, o las dos.
 * \~
 */
struct Stream {
    uint64_t id = 0;
    /// \~english Null on a stream this end only sends on.  \~spanish Nulo en un flujo por el que este extremo solo manda.  \~
    RecvStream *recv = nullptr;
    /// \~english Null on a stream this end only receives on.  \~spanish Nulo en un flujo por el que este extremo solo recibe.  \~
    SendStream *send = nullptr;
    /// \~english A MAX_STREAM_DATA for it was lost: the current limit is owed again.
    /// \~spanish Se perdio un MAX_STREAM_DATA suyo: se vuelve a deber el limite actual.  \~
    bool max_stream_data_owed = false;
    /// \~english The limit a STREAM_DATA_BLOCKED was last sent at (kNever: none since).
    /// \~spanish El limite en el que se mando el ultimo STREAM_DATA_BLOCKED (kNever: ninguno desde entonces).  \~
    uint64_t blocked_sent_at = kNever;
    uint64_t blocked_sent_time = 0;
};

/**
 * @brief
 * \~english What looking a stream up for a peer's frame found.
 * \~spanish Lo que encontro buscar un flujo para una trama del otro extremo.
 * \~
 */
enum class StreamLookup : uint8_t {
    Found,
    /// \~english It existed and was closed: the frame is ignored.
    /// \~spanish Existio y se cerro: la trama se ignora.  \~
    Closed,
    /// \~english The frame breaks a rule: see the transport error.
    /// \~spanish La trama rompe una regla: ver el error de transporte.  \~
    Error,
};

/**
 * @brief
 * \~english The streams of one connection.
 * \~spanish Los flujos de una conexion.
 * \~
 */
class StreamTable {
public:
    explicit StreamTable(const StreamConfig &config) noexcept;
    ~StreamTable();

    StreamTable(const StreamTable &) = delete;
    StreamTable &operator=(const StreamTable &) = delete;

    /// \~english Whether the table could be allocated.  \~spanish Si se pudo reservar la tabla.  \~
    bool ready() const noexcept { return slots_ != nullptr; }

    /**
     * @brief
     * \~english The stream a peer's frame of type @p type names, opening it if the rules allow.
     * \~spanish El flujo que nombra una trama del otro extremo de tipo @p type, abriendolo si las reglas lo permiten.
     * \~
     *
     * @param err \~english on `Error`, what closes the connection
     *            \~spanish en `Error`, lo que cierra la conexion  \~
     */
    StreamLookup on_peer_frame(uint64_t id, FrameType type, Stream *&out,
                               TransportError &err) noexcept;

    /**
     * @brief
     * \~english Opens a stream of this end's, or null if the peer's limit or ours is reached.
     * \~spanish Abre un flujo de este extremo, o nulo si se llego al limite del otro extremo o al nuestro.
     * \~
     */
    Stream *open(bool bidirectional) noexcept;

    /// \~english Why `open` returned null: the peer's MAX_STREAMS, so send STREAMS_BLOCKED.
    /// \~spanish Por que `open` devolvio nulo: el MAX_STREAMS del otro extremo, asi que mandar STREAMS_BLOCKED.  \~
    bool blocked_by_peer(bool bidirectional) const noexcept;

    /// \~english An `open` was refused by the peer's limit, and still is: STREAMS_BLOCKED is due (4.6).
    /// \~spanish Un `open` fue negado por el limite del otro, y lo sigue: toca STREAMS_BLOCKED (4.6).  \~
    bool open_refused(bool bidirectional) const noexcept;
    /// \~english The peer's current limit on the streams this end opens.
    /// \~spanish El limite actual del otro sobre los flujos que abre este extremo.  \~
    uint64_t peer_limit(bool bidirectional) const noexcept;

    /// \~english A MAX_STREAMS from the peer; a lower value changes nothing (4.6).
    /// \~spanish Un MAX_STREAMS del otro extremo; un valor menor no cambia nada (4.6).  \~
    void on_max_streams(bool bidirectional, uint64_t maximum) noexcept;

    /**
     * @brief
     * \~english The peer's transport parameters for streams: its stream limits and its initial windows (18.2).
     * \~spanish Los parametros de transporte del otro para los flujos: sus limites de flujos y sus ventanas iniciales (18.2).
     * \~
     *
     * \~english Every stream opened from now on sends within them; the ones already open are raised to them.
     * \~spanish Cada flujo abierto desde ahora manda dentro de ellos; los ya abiertos suben hasta ellos.  \~
     */
    void on_peer_params(uint64_t max_bidi, uint64_t max_uni, uint64_t window_bidi_local,
                        uint64_t window_bidi_remote, uint64_t window_uni) noexcept;

    /**
     * @brief
     * \~english Every stream gone, and the table as it was built: numbering, limits and windows start over.
     * \~spanish Todos los flujos fuera, y la tabla como se construyo: numeracion, limites y ventanas empiezan de nuevo.
     * \~
     *
     * \~english
     * What 0-RTT rejected asks for: "all connection characteristics that the
     * client assumed might be incorrect ... The client therefore MUST reset
     * the state of all streams" (RFC 9001, 4.6.2).
     * \~spanish
     * Lo que pide un 0-RTT rechazado: todo lo que supuso el cliente puede ser
     * incorrecto, asi que DEBE reiniciar el estado de todos los flujos (RFC 9001,
     * 4.6.2).
     * \~
     */
    void reset() noexcept;

    /**
     * @brief
     * \~english Removes every stream whose parts have both finished, and counts it closed.
     * \~spanish Quita cada flujo cuyas partes han terminado las dos, y lo cuenta como cerrado.
     * \~
     *
     * @return \~english how many were removed  \~spanish cuantos se quitaron  \~
     */
    size_t collect() noexcept;

    /// \~english Whether a MAX_STREAMS is worth sending for the peer's streams of a kind.
    /// \~spanish Si merece la pena mandar un MAX_STREAMS para los flujos del otro extremo de una clase.  \~
    bool wants_max_streams(bool bidirectional) const noexcept;

    /// \~english Moves this end's limit to closed plus concurrency, and returns it.
    /// \~spanish Mueve el limite de este extremo a cerrados mas concurrencia, y lo devuelve.  \~
    uint64_t advertise_max_streams(bool bidirectional) noexcept;
    /// \~english What `advertise_max_streams` would announce, without raising the limit: raised once sent.
    /// \~spanish Lo que anunciaria `advertise_max_streams`, sin subir el limite: se sube al mandarlo.  \~
    uint64_t next_max_streams(bool bidirectional) const noexcept;

    /// \~english The limit announced for the peer's streams of a kind.
    /// \~spanish El limite anunciado para los flujos del otro extremo de una clase.  \~
    uint64_t max_streams(bool bidirectional) const noexcept;

    /// \~english The open streams, in no particular order.  \~spanish Los flujos abiertos, sin orden particular.  \~
    size_t count() const noexcept { return index_.size(); }

    /**
     * @brief
     * \~english How many streams of one direction the peer has opened, implicitly opened ones included (RFC 9000, 3.2).
     * \~spanish Cuantos flujos de una direccion ha abierto el otro extremo, incluidos los abiertos implicitamente (RFC 9000, 3.2).
     * \~
     *
     * \~english
     * Streams open in order of their IDs, so the peer's are exactly the
     * indices below this: what lets an application visit each one once, in
     * order, without walking the table.
     * \~spanish
     * Los flujos se abren en el orden de sus identificadores, asi que los del
     * otro son exactamente los indices por debajo de esto: lo que deja a una
     * aplicacion visitar cada uno una vez, en orden, sin recorrer la tabla.
     * \~
     */
    uint64_t peer_opened(bool bidirectional) const noexcept;
    Stream *find(uint64_t id) noexcept;

    /// \~english The i-th slot, possibly empty (id kNever): for walking every stream.
    /// \~spanish La ranura i-esima, quiza vacia (id kNever): para recorrer todos los flujos.  \~
    size_t capacity() const noexcept { return capacity_; }
    Stream *slot(size_t i) noexcept { return slots_[i].id == kNever ? nullptr : &slots_[i]; }

private:
    Stream *create(uint64_t id) noexcept;
    void destroy(size_t slot) noexcept;
    bool is_local(uint64_t id) const noexcept;

    StreamConfig cfg_;
    /// \~english The configuration as given: what reset() goes back to.  \~spanish La configuracion tal como se dio: a lo que vuelve reset().  \~
    StreamConfig base_;

    Stream *slots_ = nullptr;
    uint32_t *free_ = nullptr;
    size_t capacity_ = 0;
    size_t free_count_ = 0;

    /// \~english Which slot holds each open stream.  \~spanish Que ranura tiene cada flujo abierto.  \~
    IdIndex index_;

    /// \~english Per stream type (the two low bits of the ID).  \~spanish Por tipo de flujo (los dos bits bajos del ID).  \~
    uint64_t opened_[4] = {0, 0, 0, 0};
    uint64_t closed_[4] = {0, 0, 0, 0};
    uint64_t limit_[4] = {0, 0, 0, 0};
    /// \~english An open refused by the peer's limit, per direction (uni, bidi).
    /// \~spanish Una apertura negada por el limite del otro, por direccion (uni, bidi).  \~
    bool refused_[2] = {false, false};
    void refused(bool bidirectional) noexcept;
    uint64_t local_open_ = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_STREAMS_H
