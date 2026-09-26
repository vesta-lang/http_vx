/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h3_frame.h
 * @brief
 * \~english HTTP/3's frames and stream headers: read as the bytes come, written whole (RFC 9114, 6.2 and 7).
 * \~spanish Las tramas y cabeceras de flujo de HTTP/3: leidas segun llegan los bytes, escritas enteras (RFC 9114, 6.2 y 7).
 * \~
 *
 * \~english
 * A frame is a type, a length and a payload, all over a QUIC stream that
 * delivers bytes in whatever pieces it has them (7.1).  So the reader keeps
 * state per stream, and treats payloads by what they are:
 *
 * - **DATA** goes through as it arrives, never held: content can be of any
 *   size, and the frame layer is not where it should be stored.
 * - **Every other known frame** is held until whole -- a HEADERS for QPACK,
 *   which reads a section only whole; SETTINGS, GOAWAY and the rest because
 *   their fields must be checked against their length exactly (7.1, 10.8).
 *   Holding has a limit, and past it is H3_EXCESSIVE_LOAD (10.5).
 * - **Unknown and reserved types** are skipped without holding a byte (9).
 *
 * What a frame means on a given stream -- DATA on the control stream,
 * SETTINGS twice -- is the connection's to judge; what is wrong with a frame
 * whatever the stream is judged here.
 *
 * \~spanish
 * Una trama es un tipo, una longitud y una carga, todo sobre un flujo QUIC que
 * entrega los bytes en los pedazos que tenga (7.1).  Asi que el lector guarda
 * estado por flujo, y trata las cargas segun lo que son:
 *
 * - **DATA** pasa segun llega, sin guardarse nunca: el contenido puede tener
 *   cualquier tamano, y la capa de tramas no es donde debe almacenarse.
 * - **Cualquier otra trama conocida** se guarda hasta tenerla entera -- un
 *   HEADERS para QPACK, que solo lee una seccion entera; SETTINGS, GOAWAY y el
 *   resto porque sus campos deben casar exactamente con su longitud (7.1,
 *   10.8).  Guardar tiene un limite, y pasarlo es H3_EXCESSIVE_LOAD (10.5).
 * - **Los tipos desconocidos y reservados** se saltan sin guardar un byte (9).
 *
 * Lo que significa una trama en un flujo dado -- DATA en el flujo de control,
 * SETTINGS dos veces -- lo juzga la conexion; lo que esta mal en una trama sea
 * cual sea el flujo se juzga aqui.
 * \~
 */
#ifndef HTTP_VX_H3_FRAME_H
#define HTTP_VX_H3_FRAME_H

#include "http_vx/buffer.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h3 {

/* \~english Frame types (7.2).  \~spanish Tipos de trama (7.2).  \~ */
constexpr uint64_t kData = 0x00;
constexpr uint64_t kHeaders = 0x01;
constexpr uint64_t kCancelPush = 0x03;
constexpr uint64_t kSettings = 0x04;
constexpr uint64_t kPushPromise = 0x05;
constexpr uint64_t kGoaway = 0x07;
constexpr uint64_t kMaxPushId = 0x0d;

/* \~english Unidirectional stream types (6.2).  \~spanish Tipos de flujo unidireccional (6.2).  \~ */
constexpr uint64_t kControlStream = 0x00;
constexpr uint64_t kPushStream = 0x01;

/* \~english Settings (7.2.4.1; RFC 9204, 5).  \~spanish Parametros (7.2.4.1; RFC 9204, 5).  \~ */
constexpr uint64_t kSettingQpackMaxTableCapacity = 0x01;
constexpr uint64_t kSettingMaxFieldSectionSize = 0x06;
constexpr uint64_t kSettingQpackBlockedStreams = 0x07;

/* \~english Error codes (8.1).  \~spanish Codigos de error (8.1).  \~ */
constexpr uint64_t kNoError = 0x0100;
constexpr uint64_t kGeneralProtocolError = 0x0101;
constexpr uint64_t kInternalError = 0x0102;
constexpr uint64_t kStreamCreationError = 0x0103;
constexpr uint64_t kClosedCriticalStream = 0x0104;
constexpr uint64_t kFrameUnexpected = 0x0105;
constexpr uint64_t kFrameError = 0x0106;
constexpr uint64_t kExcessiveLoad = 0x0107;
constexpr uint64_t kIdError = 0x0108;
constexpr uint64_t kSettingsError = 0x0109;
constexpr uint64_t kMissingSettings = 0x010a;
constexpr uint64_t kRequestRejected = 0x010b;
constexpr uint64_t kRequestCancelled = 0x010c;
constexpr uint64_t kRequestIncomplete = 0x010d;
constexpr uint64_t kMessageError = 0x010e;
constexpr uint64_t kConnectError = 0x010f;
constexpr uint64_t kVersionFallback = 0x0110;

/**
 * @brief
 * \~english Whether @p v is 0x1f * N + 0x21: reserved to be ignored, for frames, settings, stream types and errors.
 * \~spanish Si @p v es 0x1f * N + 0x21: reservado para ignorarse, en tramas, parametros, tipos de flujo y errores.
 * \~
 */
constexpr bool is_reserved(uint64_t v) noexcept { return v >= 0x21 && (v - 0x21) % 0x1f == 0; }

/// \~english HTTP/2 frame types with no HTTP/3 meaning: receiving one is H3_FRAME_UNEXPECTED (7.2.8, 11.2.1).
/// \~spanish Tipos de trama de HTTP/2 sin significado en HTTP/3: recibir uno es H3_FRAME_UNEXPECTED (7.2.8, 11.2.1).  \~
constexpr bool is_h2_only_frame(uint64_t t) noexcept { return t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09; }

/**
 * @brief
 * \~english Why a connection or a stream cannot go on: an HTTP/3 error code and the rule, in words.
 * \~spanish Por que una conexion o un flujo no puede seguir: un codigo de error de HTTP/3 y la regla, en palabras.
 * \~
 */
struct Failure {
    uint64_t code = 0;
    const char *why = nullptr;
};

/**
 * @brief
 * \~english What one step of reading gave.  \~spanish Lo que dio un paso de lectura.
 * \~
 */
enum class Step : uint8_t {
    /// \~english Nothing whole yet: more bytes are needed.  \~spanish Nada entero aun: hacen falta mas bytes.  \~
    More,
    /// \~english A whole frame other than DATA: type() and payload().  \~spanish Una trama entera distinta de DATA: type() y payload().  \~
    Frame,
    /// \~english A piece of a DATA payload: data(), and whether the frame ended with it.
    /// \~spanish Un pedazo de la carga de un DATA: data(), y si la trama acabo con el.  \~
    Data,
    /// \~english The frame is not one: failure() says why.  \~spanish La trama no lo es: failure() dice por que.  \~
    Failed,
};

/**
 * @brief
 * \~english Reads the frames of one stream.  \~spanish Lee las tramas de un flujo.
 * \~
 */
class FrameReader {
public:
    /// \~english The most a frame other than DATA may hold, unless told otherwise.  \~spanish Lo mas que puede guardar una trama distinta de DATA, salvo que se diga otra cosa.  \~
    static constexpr uint64_t kDefaultMaxHeld = 64 * 1024;

    FrameReader() noexcept = default;
    FrameReader(const FrameReader &) = delete;
    FrameReader &operator=(const FrameReader &) = delete;

    /// \~english Ready for a stream; @p max_held bounds a held payload.  \~spanish Listo para un flujo; @p max_held acota una carga guardada.  \~
    void reset(uint64_t max_held = kDefaultMaxHeld) noexcept;

    /**
     * @brief
     * \~english Takes what it can from @p n bytes at @p p; @p used says how many.  Call again while it gives Frame or Data.
     * \~spanish Toma lo que puede de los @p n bytes de @p p; @p used dice cuantos.  Volver a llamar mientras de Frame o Data.
     * \~
     */
    Step next(const uint8_t *p, size_t n, size_t &used) noexcept;

    /// \~english The frame's type: after Frame, and during Data.  \~spanish El tipo de la trama: tras Frame, y durante Data.  \~
    uint64_t type() const noexcept { return type_; }
    /// \~english After Frame: the whole payload, valid until the next call.  \~spanish Tras Frame: la carga entera, valida hasta la siguiente llamada.  \~
    const uint8_t *payload(size_t &n) const noexcept;
    /// \~english After Data: this piece; valid until the next call.  \~spanish Tras Data: este pedazo; valido hasta la siguiente llamada.  \~
    const uint8_t *data(size_t &n) const noexcept {
        n = piece_len_;
        return piece_;
    }
    /// \~english After Data: whether the DATA frame ended with this piece.  \~spanish Tras Data: si la trama DATA acabo con este pedazo.  \~
    bool data_done() const noexcept { return left_ == 0; }

    /// \~english Between frames: a stream may end here cleanly (7.1).  \~spanish Entre tramas: un flujo puede acabar aqui limpiamente (7.1).  \~
    bool at_boundary() const noexcept { return state_ == State::Head && head_len_ == 0; }
    /// \~english Frames read whole, skipped, and DATA bytes passed.  \~spanish Tramas leidas enteras, saltadas, y bytes de DATA pasados.  \~
    uint64_t frames() const noexcept { return frames_; }
    uint64_t skipped() const noexcept { return skipped_; }
    const Failure &failure() const noexcept { return failure_; }

    void release() noexcept { held_.release(); }

private:
    enum class State : uint8_t { Head, Hold, Skip, Data, Failed };

    Step fail(uint64_t code, const char *why) noexcept;

    State state_ = State::Head;
    /// \~english The frame head, gathered across pieces: at most two 8-byte varints.
    /// \~spanish La cabecera de la trama, juntada entre pedazos: como mucho dos varints de 8 bytes.  \~
    uint8_t head_[16] = {};
    size_t head_len_ = 0;
    uint64_t type_ = 0;
    uint64_t left_ = 0;
    uint64_t max_held_ = kDefaultMaxHeld;
    Buffer held_;
    const uint8_t *piece_ = nullptr;
    size_t piece_len_ = 0;
    uint64_t frames_ = 0;
    uint64_t skipped_ = 0;
    Failure failure_;
};

/**
 * @brief
 * \~english The settings HTTP/3 and QPACK define, as one end sends them (7.2.4.1).
 * \~spanish Los parametros que definen HTTP/3 y QPACK, como los manda un extremo (7.2.4.1).
 * \~
 */
struct Settings {
    uint64_t qpack_max_table_capacity = 0;
    uint64_t qpack_blocked_streams = 0;
    /// \~english Unlimited by default (7.2.4.1).  \~spanish Sin limite por defecto (7.2.4.1).  \~
    uint64_t max_field_section_size = ~uint64_t{0};
};

/**
 * @brief
 * \~english Reads a SETTINGS payload into @p out; false with @p why on H3_FRAME_ERROR or H3_SETTINGS_ERROR.
 * \~spanish Lee una carga de SETTINGS en @p out; falso con @p why si es H3_FRAME_ERROR o H3_SETTINGS_ERROR.
 * \~
 *
 * \~english
 * Unknown identifiers are ignored (7.2.4); HTTP/2's with no HTTP/3 meaning
 * are an error (7.2.4.1); an identifier twice is refused, as 7.2.4 allows.
 * \~spanish
 * Los identificadores desconocidos se ignoran (7.2.4); los de HTTP/2 sin
 * significado en HTTP/3 son un error (7.2.4.1); un identificador repetido se
 * rechaza, como permite 7.2.4.
 * \~
 */
bool read_settings(const uint8_t *p, size_t n, Settings &out, Failure &why) noexcept;

/// \~english Reads a payload that is exactly one integer (GOAWAY, MAX_PUSH_ID, CANCEL_PUSH).
/// \~spanish Lee una carga que es exactamente un entero (GOAWAY, MAX_PUSH_ID, CANCEL_PUSH).  \~
bool read_id(const uint8_t *p, size_t n, uint64_t &out, Failure &why) noexcept;

/// \~english Appends a frame head for @p type and @p length.  \~spanish Anade una cabecera de trama para @p type y @p length.  \~
bool write_head(Buffer &out, uint64_t type, uint64_t length) noexcept;
/// \~english Appends a SETTINGS frame, with one reserved setting as 7.2.4.1 recommends; defaults are left out.
/// \~spanish Anade una trama SETTINGS, con un parametro reservado como recomienda 7.2.4.1; los valores por defecto se omiten.  \~
bool write_settings(Buffer &out, const Settings &s) noexcept;
/// \~english Appends a frame whose payload is one integer.  \~spanish Anade una trama cuya carga es un entero.  \~
bool write_id(Buffer &out, uint64_t type, uint64_t id) noexcept;
/// \~english Appends a varint (a stream type, a push ID).  \~spanish Anade un varint (un tipo de flujo, un push ID).  \~
bool write_varint(Buffer &out, uint64_t v) noexcept;

} // namespace h3
} // namespace http_vx

#endif // HTTP_VX_H3_FRAME_H
