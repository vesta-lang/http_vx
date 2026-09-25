/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_frame.h
 * @brief
 * \~english QUIC frames (RFC 9000, section 19): what a packet carries once it is opened.
 * \~spanish Las tramas de QUIC (RFC 9000, seccion 19): lo que lleva un paquete una vez abierto.
 * \~
 *
 * \~english
 * A reader that hands out one frame at a time, and writers for every frame.
 * Like the packet header, the reader copies nothing: data, tokens, connection
 * IDs and reason phrases come back as spans of the payload they arrived in.
 *
 * **Everything that can be checked without connection state is checked
 * here**, and a frame that breaks a rule stops the reader with the rule's
 * name and the transport error it maps to.  That is: the format; the frame
 * type in its shortest encoding; which frames each packet type may carry
 * (RFC 9000, table 3); frames only a server may send; ACK ranges that do not
 * go below zero; the 2^62 and 2^60 limits; connection IDs of one to twenty
 * bytes; and a packet that carries no frame at all.  What needs state -- a
 * stream that does not exist yet, flow control, a sequence number seen before
 * -- belongs to the layers above, which receive frames this reader has
 * already vouched for.
 *
 * Unlike a malformed packet header, which is dropped in silence, a frame error
 * CLOSES the connection: the packet it came in was authenticated, so only the
 * peer could have written it.
 *
 * \~spanish
 * Un lector que entrega una trama cada vez, y escritores para todas.  Como la
 * cabecera de paquete, el lector no copia nada: los datos, los testigos, los
 * identificadores de conexion y los motivos vuelven como trozos de la carga en
 * la que llegaron.
 *
 * **Todo lo que se puede comprobar sin el estado de la conexion se comprueba
 * aqui**, y una trama que rompe una regla para al lector con el nombre de la
 * regla y el error de transporte que le corresponde.  Es decir: el formato; el
 * tipo de trama en su codificacion mas corta; que tramas puede llevar cada tipo
 * de paquete (RFC 9000, tabla 3); las tramas que solo puede mandar un servidor;
 * rangos de ACK que no bajan de cero; los limites de 2^62 y 2^60;
 * identificadores de conexion de uno a veinte bytes; y un paquete sin ninguna
 * trama.  Lo que necesita estado -- un flujo que aun no existe, el control de
 * flujo, un numero de secuencia ya visto -- es de las capas de encima, que
 * reciben tramas por las que este lector ya respondio.
 *
 * A diferencia de una cabecera de paquete mal formada, que se tira en silencio,
 * un error de trama CIERRA la conexion: el paquete en que llego estaba
 * autenticado, asi que solo pudo escribirlo el otro extremo.
 * \~
 */
#ifndef HTTP_VX_QUIC_FRAME_H
#define HTTP_VX_QUIC_FRAME_H

#include "http_vx/quic_packet.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english Transport error codes (RFC 9000, section 20.1), as sent in CONNECTION_CLOSE.
 * \~spanish Codigos de error de transporte (RFC 9000, seccion 20.1), como se mandan en CONNECTION_CLOSE.
 * \~
 */
enum class TransportError : uint64_t {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    /// \~english Plus a TLS alert, 0x0100 to 0x01ff.  \~spanish Mas una alerta de TLS, de 0x0100 a 0x01ff.  \~
    CryptoError = 0x0100,
};

/**
 * @brief
 * \~english Which frame it is.  The flags some types carry in their low bits are fields of Frame.
 * \~spanish Que trama es.  Los indicadores que algunos tipos llevan en sus bits bajos son campos de Frame.
 * \~
 */
enum class FrameType : uint8_t {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone,
};

/// \~english A short name for @p t, for logs.  \~spanish Un nombre corto para @p t, para los registros.  \~
const char *frame_type_name(FrameType t) noexcept;

/**
 * @brief
 * \~english Which rule a frame broke.
 * \~spanish Que regla rompio una trama.
 * \~
 *
 * \~english
 * One name per rule, not per error code: FRAME_ENCODING_ERROR alone covers
 * half of these, and a log that only said that would not say which half.
 * \~spanish
 * Un nombre por regla, no por codigo de error: FRAME_ENCODING_ERROR cubre por si
 * solo la mitad de estas, y un registro que solo dijera eso no diria que mitad.
 * \~
 */
enum class FrameError : uint8_t {
    None,
    /// \~english The payload ends inside the frame.  \~spanish La carga acaba dentro de la trama.  \~
    Truncated,
    /// \~english A type this end does not know.  \~spanish Un tipo que este extremo no conoce.  \~
    UnknownType,
    /// \~english The type in more bytes than it needs (12.4).  \~spanish El tipo en mas bytes de los que necesita (12.4).  \~
    TypeNotShortest,
    /// \~english Not allowed in this packet type (table 3).  \~spanish No se permite en este tipo de paquete (tabla 3).  \~
    NotAllowedInPacket,
    /// \~english A frame only a server may send, received by a server.
    /// \~spanish Una trama que solo puede mandar un servidor, recibida por un servidor.  \~
    OnlyFromServer,
    /// \~english An ACK range that goes below packet zero.  \~spanish Un rango de ACK que baja del paquete cero.  \~
    AckRangeBelowZero,
    /// \~english Offset plus length past 2^62 - 1.  \~spanish Desplazamiento mas longitud pasado de 2^62 - 1.  \~
    BeyondMaxOffset,
    /// \~english A stream count past 2^60.  \~spanish Una cuenta de flujos pasada de 2^60.  \~
    BeyondMaxStreams,
    /// \~english A connection ID of zero or more than twenty bytes.
    /// \~spanish Un identificador de conexion de cero o mas de veinte bytes.  \~
    BadConnectionIdLength,
    /// \~english Retire Prior To above the Sequence Number.
    /// \~spanish Retire Prior To por encima del numero de secuencia.  \~
    RetireAboveSequence,
    /// \~english A NEW_TOKEN with no token.  \~spanish Un NEW_TOKEN sin testigo.  \~
    EmptyToken,
    /// \~english A packet with no frame in it (12.4).  \~spanish Un paquete sin ninguna trama (12.4).  \~
    EmptyPacket,
};

/// \~english A short name for @p e.  \~spanish Un nombre corto para @p e.  \~
const char *frame_error_name(FrameError e) noexcept;

/// \~english The transport error @p e closes the connection with.
/// \~spanish El error de transporte con el que @p e cierra la conexion.  \~
TransportError transport_error_of(FrameError e) noexcept;

/// \~english The largest offset a stream may reach: 2^62 - 1.
/// \~spanish El mayor desplazamiento al que puede llegar un flujo: 2^62 - 1.  \~
constexpr uint64_t kMaxOffset = (uint64_t{1} << 62) - 1;

/// \~english The most streams of one kind: 2^60.  \~spanish El maximo de flujos de una clase: 2^60.  \~
constexpr uint64_t kMaxStreams = uint64_t{1} << 60;

/// \~english The size of a stateless reset token and of path challenge data.
/// \~spanish El tamano de un testigo de reinicio sin estado y de los datos de un desafio de ruta.  \~
constexpr size_t kResetTokenSize = 16;
constexpr size_t kPathDataSize = 8;

/**
 * @brief
 * \~english One frame, as read.
 * \~spanish Una trama, tal como se leyo.
 * \~
 *
 * \~english
 * A flat record rather than a union: one frame is read at a time, so its size
 * does not multiply, and a flat record cannot be read through the wrong member.
 * Only the fields of `type` are meaningful; the rest are zero.  Spans are
 * offsets from the first byte of the PAYLOAD the reader was given.
 * \~spanish
 * Un registro plano y no una union: se lee una trama cada vez, asi que su tamano
 * no se multiplica, y un registro plano no se puede leer por el miembro
 * equivocado.  Solo significan algo los campos de `type`; el resto son cero.
 * Los trozos son desplazamientos desde el primer byte de la CARGA que se le dio
 * al lector.
 * \~
 */
struct Frame {
    FrameType type = FrameType::Padding;

    /// \~english The type value as it arrived: 0x02 or 0x03, 0x08 to 0x0f, and so on.
    /// \~spanish El valor de tipo tal como llego: 0x02 o 0x03, 0x08 a 0x0f, etc.  \~
    uint64_t wire_type = 0;

    /// \~english Where the frame starts and how long it is, in the payload.
    /// \~spanish Donde empieza la trama y cuanto mide, en la carga.  \~
    Span at = {0, 0};

    uint64_t stream_id = 0;
    /// \~english STREAM and CRYPTO offset.  \~spanish Desplazamiento de STREAM y CRYPTO.  \~
    uint64_t offset = 0;
    /// \~english An application or transport error code.  \~spanish Un codigo de error de aplicacion o de transporte.  \~
    uint64_t error_code = 0;
    /// \~english RESET_STREAM's final size.  \~spanish El tamano final de RESET_STREAM.  \~
    uint64_t final_size = 0;
    /// \~english MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS and the three BLOCKED frames.
    /// \~spanish MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS y las tres tramas BLOCKED.  \~
    uint64_t maximum = 0;
    /// \~english NEW_CONNECTION_ID and RETIRE_CONNECTION_ID.  \~spanish NEW_CONNECTION_ID y RETIRE_CONNECTION_ID.  \~
    uint64_t sequence = 0;
    uint64_t retire_prior_to = 0;
    /// \~english CONNECTION_CLOSE 0x1c: the frame type that caused it.
    /// \~spanish CONNECTION_CLOSE 0x1c: el tipo de trama que lo causo.  \~
    uint64_t trigger_type = 0;

    /// \~english ACK fields.  \~spanish Campos del ACK.  \~
    uint64_t largest = 0;
    uint64_t ack_delay = 0;
    uint64_t range_count = 0;
    uint64_t first_range = 0;
    uint64_t ecn[3] = {0, 0, 0};

    /// \~english STREAM: this frame ends the stream.  \~spanish STREAM: esta trama acaba el flujo.  \~
    bool fin = false;
    /// \~english MAX_STREAMS and STREAMS_BLOCKED: bidirectional or not.
    /// \~spanish MAX_STREAMS y STREAMS_BLOCKED: bidireccional o no.  \~
    bool bidirectional = false;
    /// \~english ACK 0x03.  \~spanish ACK 0x03.  \~
    bool has_ecn = false;
    /// \~english CONNECTION_CLOSE 0x1d: an application's error, not the transport's.
    /// \~spanish CONNECTION_CLOSE 0x1d: un error de la aplicacion, no del transporte.  \~
    bool application = false;

    /**
     * \~english
     * The frame's bytes: STREAM and CRYPTO data, NEW_TOKEN's token, the new
     * connection ID, PATH_CHALLENGE and PATH_RESPONSE data, a reason phrase.
     * For PADDING, the whole run of zeros.
     * \~spanish
     * Los bytes de la trama: los datos de STREAM y CRYPTO, el testigo de
     * NEW_TOKEN, el nuevo identificador de conexion, los datos de PATH_CHALLENGE
     * y PATH_RESPONSE, un motivo.  En PADDING, toda la racha de ceros.
     * \~
     */
    Span data = {0, 0};

    /// \~english NEW_CONNECTION_ID's stateless reset token.
    /// \~spanish El testigo de reinicio sin estado de NEW_CONNECTION_ID.  \~
    Span reset_token = {0, 0};

    /// \~english ACK: the encoded Gap / Range pairs after the first range.
    /// \~spanish ACK: los pares Gap / Range codificados tras el primer rango.  \~
    Span ranges = {0, 0};
};

/**
 * @brief
 * \~english What the reader needs to know that the payload does not say.
 * \~spanish Lo que necesita saber el lector que la carga no dice.
 * \~
 */
struct FrameContext {
    /// \~english The packet the payload came in.  \~spanish El paquete en el que llego la carga.  \~
    PacketType packet = PacketType::OneRtt;
    /// \~english Whether this end is the server.  \~spanish Si este extremo es el servidor.  \~
    bool is_server = true;
};

/**
 * @brief
 * \~english Reads the frames of one payload, one at a time.
 * \~spanish Lee las tramas de una carga, una cada vez.
 * \~
 */
class FrameReader {
public:
    /// \~english What `next` found.  \~spanish Lo que encontro `next`.  \~
    enum class Step : uint8_t { Frame, End, Error };

    FrameReader(const uint8_t *payload, size_t n, const FrameContext &ctx) noexcept
        : p_(payload), n_(n), ctx_(ctx) {}

    /**
     * @brief
     * \~english The next frame, the end of the payload, or the first broken rule.
     * \~spanish La siguiente trama, el final de la carga, o la primera regla rota.
     * \~
     *
     * \~english
     * After `Error` the reader stays there: the connection is closing, and a
     * frame read past a broken one would be read from a position that no
     * longer means anything.
     * \~spanish
     * Tras `Error` el lector se queda ahi: la conexion se esta cerrando, y una
     * trama leida detras de una rota se leeria desde una posicion que ya no
     * significa nada.
     * \~
     */
    Step next(Frame &out) noexcept;

    /// \~english The rule broken, after `Error`.  \~spanish La regla rota, tras `Error`.  \~
    FrameError error() const noexcept { return error_; }

    /// \~english The type of the frame that broke it -- CONNECTION_CLOSE carries it back.
    /// \~spanish El tipo de la trama que la rompio -- CONNECTION_CLOSE lo devuelve.  \~
    uint64_t error_frame_type() const noexcept { return error_type_; }

    /// \~english Where in the payload it was broken.  \~spanish En que punto de la carga se rompio.  \~
    size_t error_at() const noexcept { return error_at_; }

private:
    Step fail(FrameError e, uint64_t type) noexcept;

    const uint8_t *p_;
    size_t n_;
    FrameContext ctx_;
    size_t pos_ = 0;
    size_t start_ = 0;
    size_t frames_ = 0;
    FrameError error_ = FrameError::None;
    uint64_t error_type_ = 0;
    size_t error_at_ = 0;
};

/// \~english One acknowledged range: every packet from smallest to largest, both included.
/// \~spanish Un rango confirmado: todos los paquetes de smallest a largest, los dos incluidos.  \~
struct AckRange {
    uint64_t smallest;
    uint64_t largest;
};

/**
 * @brief
 * \~english Walks the ranges of an ACK the reader already accepted, largest first.
 * \~spanish Recorre los rangos de un ACK que el lector ya acepto, del mayor al menor.
 * \~
 *
 * \~english
 * The reader walked them once to check that none goes below zero, so this
 * one does not check again: it only decodes.  It must be given a frame and
 * payload the reader returned.
 * \~spanish
 * El lector ya los recorrio una vez para comprobar que ninguno baja de cero, asi
 * que este no vuelve a comprobarlo: solo descodifica.  Hay que darle una trama y
 * una carga que devolvio el lector.
 * \~
 */
class AckRangeReader {
public:
    AckRangeReader(const uint8_t *payload, const Frame &ack) noexcept;

    /// \~english The next range, or false when there are no more.
    /// \~spanish El siguiente rango, o falso cuando no quedan.  \~
    bool next(AckRange &out) noexcept;

private:
    const uint8_t *p_;
    size_t pos_;
    size_t end_;
    uint64_t left_;
    uint64_t smallest_ = 0;
    bool first_ = true;
    uint64_t largest_;
    uint64_t first_range_;
};

/* \~english
 * Writers.  Each writes one frame at @p p, with @p room bytes available, and
 * returns how many it wrote -- zero if it does not fit, in which case nothing
 * was written that matters.  CRYPTO and STREAM write only their header: the
 * data goes right after it, put there by the caller, so that it is written
 * once, where it will be sent.
 * \~spanish
 * Escritores.  Cada uno escribe una trama en @p p, con @p room bytes libres, y
 * devuelve cuantos escribio -- cero si no cabe, y entonces no se escribio nada
 * que importe.  CRYPTO y STREAM escriben solo su cabecera: los datos van justo
 * detras, puestos por quien llama, para que se escriban una vez, donde se van a
 * mandar.
 * \~ */

size_t write_padding(uint8_t *p, size_t room, size_t n) noexcept;
size_t write_ping(uint8_t *p, size_t room) noexcept;

/**
 * @brief
 * \~english An ACK of @p count ranges, largest first, disjoint and not adjacent.
 * \~spanish Un ACK de @p count rangos, del mayor al menor, disjuntos y no contiguos.
 * \~
 *
 * @param ecn \~english three counts for an ACK 0x03, or null for 0x02
 *            \~spanish tres cuentas para un ACK 0x03, o nulo para 0x02  \~
 * @return    \~english bytes written, zero if it does not fit or the ranges are not ordered
 *            \~spanish bytes escritos, cero si no cabe o los rangos no estan ordenados  \~
 */
size_t write_ack(uint8_t *p, size_t room, const AckRange *ranges, size_t count,
                 uint64_t ack_delay, const uint64_t *ecn) noexcept;

size_t write_reset_stream(uint8_t *p, size_t room, uint64_t stream_id,
                          uint64_t error_code, uint64_t final_size) noexcept;
size_t write_stop_sending(uint8_t *p, size_t room, uint64_t stream_id,
                          uint64_t error_code) noexcept;

/// \~english CRYPTO's header, for @p len bytes that the caller puts right after it.
/// \~spanish La cabecera de CRYPTO, para @p len bytes que quien llama pone justo detras.  \~
size_t write_crypto_header(uint8_t *p, size_t room, uint64_t offset,
                           uint64_t len) noexcept;

size_t write_new_token(uint8_t *p, size_t room, const uint8_t *token,
                       size_t len) noexcept;

/**
 * @brief
 * \~english STREAM's header, for @p len bytes that the caller puts right after it.
 * \~spanish La cabecera de STREAM, para @p len bytes que quien llama pone justo detras.
 * \~
 *
 * @param with_length \~english false only for the last frame of a packet: the data then runs to its end
 *                    \~spanish falso solo para la ultima trama de un paquete: los datos llegan entonces hasta su final  \~
 */
size_t write_stream_header(uint8_t *p, size_t room, uint64_t stream_id,
                           uint64_t offset, uint64_t len, bool fin,
                           bool with_length) noexcept;

size_t write_max_data(uint8_t *p, size_t room, uint64_t maximum) noexcept;
size_t write_max_stream_data(uint8_t *p, size_t room, uint64_t stream_id,
                             uint64_t maximum) noexcept;
size_t write_max_streams(uint8_t *p, size_t room, bool bidirectional,
                         uint64_t maximum) noexcept;
size_t write_data_blocked(uint8_t *p, size_t room, uint64_t maximum) noexcept;
size_t write_stream_data_blocked(uint8_t *p, size_t room, uint64_t stream_id,
                                 uint64_t maximum) noexcept;
size_t write_streams_blocked(uint8_t *p, size_t room, bool bidirectional,
                             uint64_t maximum) noexcept;
size_t write_new_connection_id(uint8_t *p, size_t room, uint64_t sequence,
                               uint64_t retire_prior_to, const uint8_t *cid,
                               size_t cid_len, const uint8_t *reset_token) noexcept;
size_t write_retire_connection_id(uint8_t *p, size_t room,
                                  uint64_t sequence) noexcept;
size_t write_path_challenge(uint8_t *p, size_t room, const uint8_t *data) noexcept;
size_t write_path_response(uint8_t *p, size_t room, const uint8_t *data) noexcept;

/**
 * @brief
 * \~english CONNECTION_CLOSE: 0x1c for the transport (with @p trigger_type), 0x1d for the application.
 * \~spanish CONNECTION_CLOSE: 0x1c para el transporte (con @p trigger_type), 0x1d para la aplicacion.
 * \~
 */
size_t write_connection_close(uint8_t *p, size_t room, bool application,
                              uint64_t error_code, uint64_t trigger_type,
                              const uint8_t *reason, size_t reason_len) noexcept;

size_t write_handshake_done(uint8_t *p, size_t room) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_FRAME_H
