/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_stream_send.h
 * @brief
 * \~english The sending part of a QUIC stream, and send-side flow control (RFC 9000, 3.1 and 4).
 * \~spanish La parte emisora de un flujo QUIC, y el control de flujo del lado emisor (RFC 9000, 3.1 y 4).
 * \~
 *
 * \~english
 * What the application writes is kept until the peer acknowledges it --
 * because QUIC acknowledges PACKETS, and when a packet is lost the bytes it
 * carried have to be sent again, in whatever packet goes next.  So each byte
 * is in one of three conditions: not yet sent, sent and waiting, or
 * acknowledged; and a byte that was waiting can go back to "to send" when its
 * packet is declared lost.
 *
 * Memory is the same shape as on the receiving side: 4 KiB chunks allocated
 * as the application writes and freed as soon as the acknowledged prefix
 * passes them, and a bitmap per chunk -- here two: what was acknowledged, and
 * what has to be sent again.  How much may wait unacknowledged is the
 * caller's choice, given at construction; `write` takes what fits and says
 * how much.
 *
 * Retransmissions go before new data, and cost no flow control credit: those
 * bytes were paid for when they were first sent (4.1 counts offsets, not
 * transmissions).
 *
 * \~spanish
 * Lo que escribe la aplicacion se guarda hasta que el otro extremo lo confirma
 * -- porque QUIC confirma PAQUETES, y cuando un paquete se pierde los bytes que
 * llevaba se tienen que mandar otra vez, en el paquete que salga despues.  Asi
 * que cada byte esta en una de tres condiciones: sin mandar, mandado y
 * esperando, o confirmado; y un byte que esperaba puede volver a "por mandar"
 * cuando su paquete se declara perdido.
 *
 * La memoria tiene la misma forma que en la parte receptora: trozos de 4 KiB que
 * se reservan segun escribe la aplicacion y se liberan en cuanto el prefijo
 * confirmado pasa de ellos, y un mapa de bits por trozo -- aqui dos: que se
 * confirmo, y que hay que volver a mandar.  Cuanto puede esperar sin confirmar
 * lo elige quien llama, al construir; `write` coge lo que cabe y dice cuanto.
 *
 * Las retransmisiones van antes que los datos nuevos, y no gastan credito de
 * control de flujo: esos bytes se pagaron cuando se mandaron la primera vez
 * (4.1 cuenta desplazamientos, no envios).
 * \~
 */
#ifndef HTTP_VX_QUIC_STREAM_SEND_H
#define HTTP_VX_QUIC_STREAM_SEND_H

#include "http_vx/quic_stream_recv.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english The sending states of RFC 9000, 3.1.  \~spanish Los estados de envio del RFC 9000, 3.1.  \~
enum class SendState : uint8_t { Ready, Send, DataSent, DataRecvd, ResetSent, ResetRecvd };

/**
 * @brief
 * \~english What the next STREAM frame should carry.
 * \~spanish Lo que deberia llevar la siguiente trama STREAM.
 * \~
 */
struct StreamPiece {
    uint64_t offset = 0;
    /// \~english Inside the stream's buffer: valid until the next call that changes it.
    /// \~spanish Dentro del buffer del flujo: valido hasta la siguiente llamada que lo cambie.  \~
    const uint8_t *data = nullptr;
    size_t len = 0;
    bool fin = false;
    /// \~english Sent before: costs no flow control credit.  \~spanish Ya se mando: no gasta credito.  \~
    bool retransmit = false;
};

/**
 * @brief
 * \~english The sending part of one stream.
 * \~spanish La parte emisora de un flujo.
 * \~
 */
class SendStream {
public:
    /**
     * @param capacity   \~english how many bytes may wait unacknowledged
     *                   \~spanish cuantos bytes pueden esperar sin confirmar  \~
     * @param peer_limit \~english the peer's initial MAX_STREAM_DATA for this stream
     *                   \~spanish el MAX_STREAM_DATA inicial del otro extremo para este flujo  \~
     */
    SendStream(uint64_t capacity, uint64_t peer_limit) noexcept;
    ~SendStream();

    SendStream(const SendStream &) = delete;
    SendStream &operator=(const SendStream &) = delete;

    /**
     * @brief
     * \~english Takes as much of @p n bytes as fits; @p accepted says how much.
     * \~spanish Coge de @p n bytes lo que quepa; @p accepted dice cuanto.
     * \~
     *
     * @return \~english OutOfMemory if a chunk could not be had -- @p accepted is then what did fit
     *         \~spanish OutOfMemory si no se pudo tener un trozo -- @p accepted es entonces lo que si cupo  \~
     */
    StreamError write(const uint8_t *p, size_t n, size_t &accepted) noexcept;

    /// \~english No more data: the stream ends where it is written up to.
    /// \~spanish No hay mas datos: el flujo acaba donde esta escrito.  \~
    void finish() noexcept;

    /**
     * @brief
     * \~english The next piece to send, or false if there is none now.
     * \~spanish El siguiente trozo a mandar, o falso si ahora no hay ninguno.
     * \~
     *
     * @param max_len     \~english the most data that fits in the packet
     *                    \~spanish lo maximo de datos que cabe en el paquete  \~
     * @param conn_credit \~english what the connection's flow control still allows for NEW data
     *                    \~spanish lo que el control de flujo de la conexion aun permite para datos NUEVOS  \~
     */
    bool next(StreamPiece &out, size_t max_len, uint64_t conn_credit) const noexcept;

    /// \~english The piece `next` gave went out, exactly as given.
    /// \~spanish El trozo que dio `next` salio, tal cual se dio.  \~
    void on_sent(const StreamPiece &piece) noexcept;

    /// \~english A packet carrying [offset, offset+len) (and FIN if set) was acknowledged.
    /// \~spanish Se confirmo un paquete que llevaba [offset, offset+len) (y FIN si lo lleva).  \~
    void on_acked(uint64_t offset, size_t len, bool fin) noexcept;

    /// \~english A packet carrying it was lost: what was not acknowledged goes out again.
    /// \~spanish Se perdio un paquete que lo llevaba: lo no confirmado sale otra vez.  \~
    void on_lost(uint64_t offset, size_t len, bool fin) noexcept;

    /// \~english A MAX_STREAM_DATA; a lower value changes nothing (4.1).
    /// \~spanish Un MAX_STREAM_DATA; un valor menor no cambia nada (4.1).  \~
    void on_max_stream_data(uint64_t limit) noexcept;

    /// \~english Data is waiting and the stream's limit stops it: send STREAM_DATA_BLOCKED at `limit()`.
    /// \~spanish Hay datos esperando y el limite del flujo los para: mandar STREAM_DATA_BLOCKED en `limit()`.  \~
    bool blocked() const noexcept;

    /**
     * @brief
     * \~english Abandons the stream: nothing more is sent but a RESET_STREAM.
     * \~spanish Abandona el flujo: ya no se manda nada mas que un RESET_STREAM.
     * \~
     */
    void reset(uint64_t error_code) noexcept;

    /// \~english A STOP_SENDING: the stream MUST be reset with its code (3.5).
    /// \~spanish Un STOP_SENDING: el flujo DEBE reiniciarse con su codigo (3.5).  \~
    void on_stop_sending(uint64_t error_code) noexcept;

    /// \~english A RESET_STREAM is owed: final size `final_size()`, code `reset_code()`.
    /// \~spanish Se debe un RESET_STREAM: tamano final `final_size()`, codigo `reset_code()`.  \~
    bool reset_pending() const noexcept { return reset_pending_; }
    void on_reset_sent() noexcept { reset_pending_ = false; }
    void on_reset_lost() noexcept;
    void on_reset_acked() noexcept;

    SendState state() const noexcept { return state_; }
    uint64_t written() const noexcept { return written_; }
    /// \~english The highest offset ever sent.  \~spanish El mayor desplazamiento mandado nunca.  \~
    uint64_t sent() const noexcept { return sent_; }
    /// \~english Everything below this is acknowledged.  \~spanish Todo lo de debajo de esto esta confirmado.  \~
    uint64_t acked() const noexcept { return acked_; }
    uint64_t limit() const noexcept { return limit_; }
    /// \~english What a RESET_STREAM says: the highest offset sent (4.5).
    /// \~spanish Lo que dice un RESET_STREAM: el mayor desplazamiento mandado (4.5).  \~
    uint64_t final_size() const noexcept { return sent_; }
    uint64_t reset_code() const noexcept { return reset_code_; }
    /// \~english Bytes waiting to be sent again.  \~spanish Bytes esperando a mandarse otra vez.  \~
    uint64_t to_resend() const noexcept { return pending_; }
    size_t chunks_held() const noexcept { return held_; }

private:
    struct Chunk;

    Chunk *chunk_for(uint64_t index, bool create) noexcept;
    void free_chunk(uint64_t index) noexcept;
    void release_all() noexcept;
    bool done_or_reset() const noexcept;

    uint64_t capacity_;
    uint64_t limit_;
    uint64_t written_ = 0;
    uint64_t sent_ = 0;
    uint64_t acked_ = 0;
    uint64_t pending_ = 0;
    uint64_t reset_code_ = 0;
    bool finished_ = false;
    bool fin_sent_ = false;
    bool fin_acked_ = false;
    bool fin_pending_ = false;
    bool reset_pending_ = false;
    SendState state_ = SendState::Ready;

    Chunk **slots_ = nullptr;
    size_t nslots_ = 0;
    size_t held_ = 0;
};

/**
 * @brief
 * \~english Send-side flow control for the whole connection (the peer's MAX_DATA).
 * \~spanish Control de flujo del lado emisor para toda la conexion (el MAX_DATA del otro extremo).
 * \~
 */
class SendFlow {
public:
    explicit SendFlow(uint64_t peer_limit) noexcept : limit_(peer_limit) {}

    uint64_t credit() const noexcept { return used_ < limit_ ? limit_ - used_ : 0; }
    /// \~english NEW bytes went out on some stream.  \~spanish Salieron bytes NUEVOS por algun flujo.  \~
    void on_sent(uint64_t n) noexcept { used_ += n; }
    /// \~english A MAX_DATA; a lower value changes nothing.  \~spanish Un MAX_DATA; un valor menor no cambia nada.  \~
    void on_max_data(uint64_t limit) noexcept {
        if (limit > limit_) limit_ = limit;
    }
    /// \~english Send DATA_BLOCKED at `limit()`.  \~spanish Mandar DATA_BLOCKED en `limit()`.  \~
    bool blocked() const noexcept { return used_ >= limit_; }
    uint64_t limit() const noexcept { return limit_; }
    uint64_t used() const noexcept { return used_; }

private:
    uint64_t limit_;
    uint64_t used_ = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_STREAM_SEND_H
