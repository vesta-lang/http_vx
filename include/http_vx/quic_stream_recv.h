/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_stream_recv.h
 * @brief
 * \~english The receiving part of a QUIC stream, and receive-side flow control (RFC 9000, 2-4).
 * \~spanish La parte receptora de un flujo QUIC, y el control de flujo del lado receptor (RFC 9000, 2-4).
 * \~
 *
 * \~english
 * A stream's bytes arrive in STREAM frames that may come in any order, twice,
 * overlapping, or with holes that a retransmission fills later; the
 * application has to see them in order (2.2).  So they are kept until the
 * hole before them is filled -- up to the flow control limit this end
 * advertised, and not one byte more.
 *
 * **Memory follows the data, not the window.**  The window is covered by a
 * table of 4 KiB chunks that are allocated when data lands in them and freed
 * as soon as the application has read past them.  A hundred idle streams do
 * not cost a hundred windows; a stream costs what is waiting in it.
 *
 * **Which bytes arrived is a bitmap, not a list of gaps.**  A list of gaps
 * needs a cap, and a peer that sends one-byte fragments reaches any cap -- at
 * which point a receiver either drops data it already acknowledged, which
 * stalls the stream forever, or closes a connection that broke no rule.  A
 * bitmap has no cap to reach: one bit per byte of window, bounded by the
 * window, whatever the peer does.
 *
 * \~spanish
 * Los bytes de un flujo llegan en tramas STREAM que pueden venir en cualquier
 * orden, dos veces, solapadas, o con huecos que una retransmision rellena
 * despues; la aplicacion los tiene que ver en orden (2.2).  Asi que se guardan
 * hasta que se rellena el hueco de delante -- hasta el limite de control de
 * flujo que anuncio este extremo, y ni un byte mas.
 *
 * **La memoria sigue a los datos, no a la ventana.**  La ventana la cubre una
 * tabla de trozos de 4 KiB que se reservan cuando caen datos en ellos y se
 * liberan en cuanto la aplicacion ha leido mas alla.  Cien flujos parados no
 * cuestan cien ventanas; un flujo cuesta lo que espera en el.
 *
 * **Que bytes llegaron es un mapa de bits, no una lista de huecos.**  Una lista
 * de huecos necesita un tope, y un extremo que manda fragmentos de un byte
 * llega a cualquier tope -- y entonces quien recibe o tira datos que ya
 * confirmo, lo que atasca el flujo para siempre, o cierra una conexion que no
 * rompio ninguna regla.  Un mapa de bits no tiene tope al que llegar: un bit por
 * byte de ventana, acotado por la ventana, haga lo que haga el otro extremo.
 * \~
 */
#ifndef HTTP_VX_QUIC_STREAM_RECV_H
#define HTTP_VX_QUIC_STREAM_RECV_H

#include "http_vx/quic_frame.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english The size of a receive chunk.  \~spanish El tamano de un trozo de recepcion.  \~
constexpr size_t kRecvChunk = 4096;

/**
 * @brief
 * \~english Why a stream refused what it was given.
 * \~spanish Por que un flujo rechazo lo que se le dio.
 * \~
 */
enum class StreamError : uint8_t {
    None,
    /// \~english Past the limit this end advertised (4.1).  \~spanish Pasado del limite que anuncio este extremo (4.1).  \~
    FlowControl,
    /// \~english The final size changed, or data beyond it (4.5).  \~spanish El tamano final cambio, o datos mas alla de el (4.5).  \~
    FinalSize,
    /// \~english No memory for a chunk: this end's failure, said aloud.
    /// \~spanish Sin memoria para un trozo: fallo de este extremo, dicho en voz alta.  \~
    OutOfMemory,
};

/// \~english A short name for @p e.  \~spanish Un nombre corto para @p e.  \~
const char *stream_error_name(StreamError e) noexcept;

/// \~english The transport error @p e closes the connection with.
/// \~spanish El error de transporte con el que @p e cierra la conexion.  \~
TransportError transport_error_of(StreamError e) noexcept;

/**
 * @brief
 * \~english The receiving states of RFC 9000, 3.2.
 * \~spanish Los estados de recepcion del RFC 9000, 3.2.
 * \~
 *
 * \~english
 * The two terminal states are reached only when the APPLICATION learns how
 * the stream ended, never by the transport alone: "Data Read" once it has
 * read every byte and been told of the end, "Reset Read" once it has been
 * told of the reset (3.2).  Until then the stream stays in "Data Recvd" or
 * "Reset Recvd", and cannot be collected: a FIN that arrives alone after the
 * application read everything is still an end the application has to hear.
 * \~spanish
 * Los dos estados terminales se alcanzan solo cuando la APLICACION sabe como
 * acabo el flujo, nunca por el transporte solo: "Data Read" cuando ha leido
 * todos los bytes y se le ha dicho el final, "Reset Read" cuando se le ha dicho
 * el reinicio (3.2).  Hasta entonces el flujo sigue en "Data Recvd" o "Reset
 * Recvd", y no se puede recoger: un FIN que llega solo despues de que la
 * aplicacion lo leyera todo sigue siendo un final que la aplicacion tiene que
 * oir.
 * \~
 */
enum class RecvState : uint8_t { Recv, SizeKnown, DataRecvd, DataRead, ResetRecvd, ResetRead };

/**
 * @brief
 * \~english The receiving part of one stream.
 * \~spanish La parte receptora de un flujo.
 * \~
 */
class RecvStream {
public:
    /**
     * @brief
     * \~english A stream whose peer may send @p window bytes ahead of what was read.
     * \~spanish Un flujo cuyo otro extremo puede mandar @p window bytes por delante de lo leido.
     * \~
     *
     * \~english
     * The initial limit is exactly @p window: what `initial_max_stream_data_*`
     * says.  Only the memory is rounded up to whole chunks, and the later
     * limits a MAX_STREAM_DATA sends grow by that rounded window.
     * \~spanish
     * El limite inicial es exactamente @p window: lo que dice
     * `initial_max_stream_data_*`.  Solo la memoria se redondea a trozos
     * enteros, y los limites siguientes que manda un MAX_STREAM_DATA crecen en esa
     * ventana redondeada.
     * \~
     */
    explicit RecvStream(uint64_t window) noexcept;
    ~RecvStream();

    RecvStream(const RecvStream &) = delete;
    RecvStream &operator=(const RecvStream &) = delete;

    /**
     * @brief
     * \~english The data of a STREAM frame.
     * \~spanish Los datos de una trama STREAM.
     * \~
     *
     * @param new_bytes \~english how far this moved the highest offset received: what it costs the connection's window
     *                  \~spanish cuanto movio esto el mayor desplazamiento recibido: lo que le cuesta a la ventana de la conexion  \~
     */
    StreamError on_data(uint64_t offset, const uint8_t *p, size_t len, bool fin,
                        uint64_t &new_bytes) noexcept;

    /**
     * @brief
     * \~english A RESET_STREAM: the peer abandons the stream at @p final_size.
     * \~spanish Un RESET_STREAM: el otro extremo abandona el flujo en @p final_size.
     * \~
     *
     * @param new_bytes \~english as for `on_data`  \~spanish como en `on_data`  \~
     * @param released  \~english bytes counted as received that will never be read: give them back to the connection's window
     *                  \~spanish bytes contados como recibidos que nunca se van a leer: devolverlos a la ventana de la conexion  \~
     */
    StreamError on_reset(uint64_t final_size, uint64_t error_code, uint64_t &new_bytes,
                         uint64_t &released) noexcept;

    /**
     * @brief
     * \~english The bytes ready to read, in order, without copying: zero if none yet.
     * \~spanish Los bytes listos para leer, en orden, sin copiar: cero si aun no hay.
     * \~
     *
     * \~english At most to the end of the current chunk; `consume` then call again.
     * \~spanish Como mucho hasta el final del trozo actual; `consume` y volver a llamar.  \~
     */
    size_t peek(const uint8_t *&p) const noexcept;

    /// \~english The application read @p n bytes of what `peek` gave.
    /// \~spanish La aplicacion leyo @p n bytes de lo que dio `peek`.  \~
    void consume(size_t n) noexcept;

    /**
     * @brief
     * \~english Every byte up to the final size was read: only the end itself is left, or it was read too.
     * \~spanish Se leyo cada byte hasta el tamano final: solo queda el propio final, o tambien se leyo.
     * \~
     *
     * @return \~english true in "Data Recvd" with nothing left to read, and in "Data Read"
     *         \~spanish true en "Data Recvd" sin nada que leer, y en "Data Read"  \~
     */
    bool at_end() const noexcept {
        return (state_ == RecvState::DataRecvd || state_ == RecvState::DataRead) && read_ == final_;
    }

    /**
     * @brief
     * \~english The application takes the end: "Data Recvd" with everything read becomes "Data Read", "Reset Recvd" becomes "Reset Read" (3.2).
     * \~spanish La aplicacion recoge el final: "Data Recvd" con todo leido pasa a "Data Read", "Reset Recvd" a "Reset Read" (3.2).
     * \~
     *
     * \~english
     * The only way into a terminal state, so the end is taken exactly once:
     * true on the call that makes the transition, false before there is an
     * end to take (bytes still unread, or nothing ended) and on every call
     * after.  Only then may the stream be collected.
     * \~spanish
     * La unica entrada a un estado terminal, asi que el final se recoge
     * exactamente una vez: true en la llamada que hace la transicion, false
     * antes de que haya un final que recoger (bytes aun sin leer, o nada acabo)
     * y en cada llamada despues.  Solo entonces se puede recoger el flujo.
     * \~
     *
     * @return \~english whether this call took the end  \~spanish si esta llamada recogio el final  \~
     */
    bool read_end() noexcept;

    RecvState state() const noexcept { return state_; }
    uint64_t read_offset() const noexcept { return read_; }
    uint64_t highest() const noexcept { return highest_; }
    uint64_t limit() const noexcept { return limit_; }
    bool size_known() const noexcept { return size_known_; }
    uint64_t final_size() const noexcept { return final_; }
    uint64_t reset_code() const noexcept { return reset_code_; }

    /// \~english Whether a MAX_STREAM_DATA is worth sending: half the window was read.
    /// \~spanish Si merece la pena mandar un MAX_STREAM_DATA: se leyo media ventana.  \~
    bool wants_update() const noexcept;

    /**
     * @brief
     * \~english The limit an update would announce, WITHOUT raising it yet.
     * \~spanish El limite que anunciaria una actualizacion, SIN subirlo todavia.
     * \~
     *
     * \~english
     * The limit enforced is the limit SENT (4.1): it is raised with
     * `advertise` only once the frame carrying it was written, never before
     * -- a frame that did not fit would otherwise let the peer past a limit
     * it never heard.
     * \~spanish
     * El limite que se hace cumplir es el limite MANDADO (4.1): se sube con
     * `advertise` solo cuando la trama que lo lleva se escribio, nunca antes --
     * si no, una trama que no cupo dejaria al otro pasar de un limite que nunca
     * oyo.
     * \~
     */
    uint64_t next_limit() const noexcept;

    /// \~english Raises the limit to one window past what was read, and returns it.
    /// \~spanish Sube el limite a una ventana por delante de lo leido, y lo devuelve.  \~
    uint64_t advertise() noexcept;

    /// \~english How many chunks hold memory now.  \~spanish Cuantos trozos tienen memoria ahora.  \~
    size_t chunks_held() const noexcept { return held_; }

    /**
     * @brief
     * \~english The application stops reading: a STOP_SENDING with @p code is owed (RFC 9000, 3.5).
     * \~spanish La aplicacion deja de leer: se debe un STOP_SENDING con @p code (RFC 9000, 3.5).
     * \~
     *
     * \~english
     * Only in "Recv" or "Size Known": past them everything or a reset has
     * arrived, and asking is pointless.  What still arrives is still counted
     * for flow control; reading it is up to the application.  The reset that
     * answers it goes straight to "Reset Read": the application already gave
     * the stream up, so there is nobody left to tell (3.5).
     * \~spanish
     * Solo en "Recv" o "Size Known": despues ya llego todo o un reinicio, y pedir
     * no tiene sentido.  Lo que siga llegando cuenta igual para el control de
     * flujo; leerlo es cosa de la aplicacion.  El reinicio que lo contesta pasa
     * directo a "Reset Read": la aplicacion ya abandono el flujo, asi que no
     * queda nadie a quien decirselo (3.5).
     * \~
     *
     * @return \~english false if the stream is past those states, or it was already asked
     *         \~spanish falso si el flujo ya paso esos estados, o ya se pidio  \~
     */
    bool stop(uint64_t code) noexcept;
    /// \~english A STOP_SENDING waits to go out: owed, and still worth sending (3.5).
    /// \~spanish Un STOP_SENDING espera salir: debido, y aun merece la pena mandarlo (3.5).  \~
    bool stop_pending() const noexcept {
        return stop_pending_ && (state_ == RecvState::Recv || state_ == RecvState::SizeKnown);
    }
    bool stopped() const noexcept { return stopped_; }
    uint64_t stop_code() const noexcept { return stop_code_; }
    void on_stop_sent() noexcept { stop_pending_ = false; }
    /// \~english The packet with it was lost: owed again, while it still matters.
    /// \~spanish Se perdio el paquete que lo llevaba: se vuelve a deber, mientras importe.  \~
    void on_stop_lost() noexcept {
        if (stopped_) stop_pending_ = true;
    }

private:
    struct Chunk;

    Chunk *chunk_for(uint64_t index, bool create) noexcept;
    void release_below(uint64_t offset) noexcept;
    void release_all() noexcept;
    bool all_received() const noexcept;

    uint64_t window_;
    uint64_t limit_;
    uint64_t read_ = 0;
    uint64_t highest_ = 0;
    uint64_t final_ = 0;
    uint64_t buffered_ = 0;
    uint64_t reset_code_ = 0;
    uint64_t stop_code_ = 0;
    bool stopped_ = false;
    bool stop_pending_ = false;
    bool size_known_ = false;
    RecvState state_ = RecvState::Recv;

    Chunk **slots_ = nullptr;
    size_t nslots_ = 0;
    size_t held_ = 0;
};

/**
 * @brief
 * \~english Receive-side flow control for the whole connection (MAX_DATA).
 * \~spanish Control de flujo del lado receptor para toda la conexion (MAX_DATA).
 * \~
 *
 * \~english
 * Counted as the RFC counts it: the sum over all streams of the highest
 * offset received, not of the bytes -- a retransmission costs nothing, and
 * a stream reset still costs what its final size says (4.5).
 * \~spanish
 * Contado como lo cuenta el RFC: la suma sobre todos los flujos del mayor
 * desplazamiento recibido, no de los bytes -- una retransmision no cuesta nada,
 * y un flujo reiniciado sigue costando lo que dice su tamano final (4.5).
 * \~
 */
class RecvFlow {
public:
    explicit RecvFlow(uint64_t window) noexcept : window_(window), limit_(window) {}

    /// \~english Charges @p new_bytes; false if that passes the limit: FLOW_CONTROL_ERROR.
    /// \~spanish Carga @p new_bytes; falso si eso pasa del limite: FLOW_CONTROL_ERROR.  \~
    bool on_received(uint64_t new_bytes) noexcept;

    /// \~english The application read, or a reset released, @p n bytes.
    /// \~spanish La aplicacion leyo, o un reinicio libero, @p n bytes.  \~
    void on_consumed(uint64_t n) noexcept { consumed_ += n; }

    bool wants_update() const noexcept { return limit_ - consumed_ < window_ / 2; }
    /// \~english What `advertise` would announce, without raising the limit (see RecvStream).
    /// \~spanish Lo que anunciaria `advertise`, sin subir el limite (ver RecvStream).  \~
    uint64_t next_limit() const noexcept {
        return consumed_ + window_ > limit_ ? consumed_ + window_ : limit_;
    }
    uint64_t advertise() noexcept;

    uint64_t limit() const noexcept { return limit_; }
    uint64_t received() const noexcept { return received_; }
    uint64_t consumed() const noexcept { return consumed_; }

private:
    uint64_t window_;
    uint64_t limit_;
    uint64_t received_ = 0;
    uint64_t consumed_ = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_STREAM_RECV_H
