/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/frame.cpp
 * @brief
 * \~english Reading and writing QUIC frames (RFC 9000, section 19).
 * \~spanish Leer y escribir las tramas de QUIC (RFC 9000, seccion 19).
 * \~
 */

#include "http_vx/quic_frame.h"

#include "http_vx/quic_varint.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace quic {

namespace {

/* \~english
 * Which packet types may carry each frame (RFC 9000, table 3), one bit per
 * type: Initial, Handshake, 0-RTT, 1-RTT.  A table and not a switch because it
 * IS a table in the RFC, and the test compares it against the RFC's own
 * letters, written out independently.
 * \~spanish
 * Que tipos de paquete pueden llevar cada trama (RFC 9000, tabla 3), un bit por
 * tipo: Initial, Handshake, 0-RTT, 1-RTT.  Una tabla y no un switch porque ES
 * una tabla en el RFC, y la prueba la compara con las letras del propio RFC,
 * escritas aparte.
 * \~ */
constexpr uint8_t kI = 1, kH = 2, kZ = 4, kO = 8;

/// \~english The bit of @p t, or zero for packets that carry no frames.
/// \~spanish El bit de @p t, o cero para los paquetes que no llevan tramas.  \~
uint8_t packet_bit(PacketType t) noexcept {
    switch (t) {
    case PacketType::Initial:   return kI;
    case PacketType::Handshake: return kH;
    case PacketType::ZeroRtt:   return kZ;
    case PacketType::OneRtt:    return kO;
    default:                    return 0;
    }
}

/// \~english The packets @p wire_type may appear in; zero if it is not a known frame.
/// \~spanish Los paquetes en los que puede aparecer @p wire_type; cero si no es una trama conocida.  \~
uint8_t allowed_in(uint64_t wire_type) noexcept {
    if (wire_type >= 0x08 && wire_type <= 0x0f) return kZ | kO;  // STREAM
    switch (wire_type) {
    case 0x00: case 0x01:              return kI | kH | kZ | kO;  // PADDING, PING
    case 0x02: case 0x03:              return kI | kH | kO;       // ACK
    case 0x04: case 0x05:              return kZ | kO;            // RESET_STREAM, STOP_SENDING
    case 0x06:                         return kI | kH | kO;       // CRYPTO
    case 0x07:                         return kO;                 // NEW_TOKEN
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x14: case 0x15: case 0x16: case 0x17:
    case 0x18: case 0x19: case 0x1a:   return kZ | kO;
    case 0x1b:                         return kO;                 // PATH_RESPONSE
    case 0x1c:                         return kI | kH | kZ | kO;  // CONNECTION_CLOSE, transport
    case 0x1d:                         return kZ | kO;            // CONNECTION_CLOSE, application
    case 0x1e:                         return kO;                 // HANDSHAKE_DONE
    default:                           return 0;
    }
}

/// \~english The frame a known wire type is.  \~spanish La trama que es un tipo conocido.  \~
FrameType type_of(uint64_t w) noexcept {
    if (w >= 0x08 && w <= 0x0f) return FrameType::Stream;
    switch (w) {
    case 0x00: return FrameType::Padding;
    case 0x01: return FrameType::Ping;
    case 0x02: case 0x03: return FrameType::Ack;
    case 0x04: return FrameType::ResetStream;
    case 0x05: return FrameType::StopSending;
    case 0x06: return FrameType::Crypto;
    case 0x07: return FrameType::NewToken;
    case 0x10: return FrameType::MaxData;
    case 0x11: return FrameType::MaxStreamData;
    case 0x12: case 0x13: return FrameType::MaxStreams;
    case 0x14: return FrameType::DataBlocked;
    case 0x15: return FrameType::StreamDataBlocked;
    case 0x16: case 0x17: return FrameType::StreamsBlocked;
    case 0x18: return FrameType::NewConnectionId;
    case 0x19: return FrameType::RetireConnectionId;
    case 0x1a: return FrameType::PathChallenge;
    case 0x1b: return FrameType::PathResponse;
    case 0x1c: case 0x1d: return FrameType::ConnectionClose;
    default: return FrameType::HandshakeDone;
    }
}

/**
 * @brief
 * \~english A cursor over the payload that knows how to take integers and byte runs.
 * \~spanish Un cursor sobre la carga que sabe coger enteros y tiradas de bytes.
 * \~
 */
struct Cursor {
    const uint8_t *p;
    size_t n;
    size_t &pos;

    bool varint(uint64_t &v) noexcept {
        const size_t len = decode_varint(p + pos, n - pos, v);
        pos += len;
        return len != 0;
    }

    /// \~english @p len bytes as a span, if they are all here.
    /// \~spanish @p len bytes como un trozo, si estan todos.  \~
    bool bytes(uint64_t len, Span &out) noexcept {
        if (len > n - pos) return false;
        out = {static_cast<uint32_t>(pos), static_cast<uint32_t>(len)};
        pos += static_cast<size_t>(len);
        return true;
    }
};

/**
 * @brief
 * \~english A writer that stops being able to write the moment something does not fit.
 * \~spanish Un escritor que deja de poder escribir en cuanto algo no cabe.
 * \~
 */
struct Writer {
    uint8_t *p;
    size_t room;
    size_t pos = 0;
    bool ok = true;

    void varint(uint64_t v) noexcept {
        if (!ok) return;
        const size_t len = encode_varint(p + pos, room - pos, v);
        if (len == 0) ok = false;
        pos += len;
    }

    void byte(uint8_t b) noexcept {
        if (!ok || pos >= room) {
            ok = false;
            return;
        }
        p[pos++] = b;
    }

    void bytes(const uint8_t *src, size_t len) noexcept {
        if (!ok || len > room - pos) {
            ok = false;
            return;
        }
        util::vesta_memcpy(p + pos, src, len);
        pos += len;
    }

    size_t done() const noexcept { return ok ? pos : 0; }
};

} // namespace

const char *frame_type_name(FrameType t) noexcept {
    switch (t) {
    case FrameType::Padding:            return "PADDING";
    case FrameType::Ping:               return "PING";
    case FrameType::Ack:                return "ACK";
    case FrameType::ResetStream:        return "RESET_STREAM";
    case FrameType::StopSending:        return "STOP_SENDING";
    case FrameType::Crypto:             return "CRYPTO";
    case FrameType::NewToken:           return "NEW_TOKEN";
    case FrameType::Stream:             return "STREAM";
    case FrameType::MaxData:            return "MAX_DATA";
    case FrameType::MaxStreamData:      return "MAX_STREAM_DATA";
    case FrameType::MaxStreams:         return "MAX_STREAMS";
    case FrameType::DataBlocked:        return "DATA_BLOCKED";
    case FrameType::StreamDataBlocked:  return "STREAM_DATA_BLOCKED";
    case FrameType::StreamsBlocked:     return "STREAMS_BLOCKED";
    case FrameType::NewConnectionId:    return "NEW_CONNECTION_ID";
    case FrameType::RetireConnectionId: return "RETIRE_CONNECTION_ID";
    case FrameType::PathChallenge:      return "PATH_CHALLENGE";
    case FrameType::PathResponse:       return "PATH_RESPONSE";
    case FrameType::ConnectionClose:    return "CONNECTION_CLOSE";
    case FrameType::HandshakeDone:      return "HANDSHAKE_DONE";
    }
    return "unknown";
}

const char *frame_error_name(FrameError e) noexcept {
    switch (e) {
    case FrameError::None:                  return "none";
    case FrameError::Truncated:             return "truncated";
    case FrameError::UnknownType:           return "unknown-type";
    case FrameError::TypeNotShortest:       return "type-not-shortest";
    case FrameError::NotAllowedInPacket:    return "not-allowed-in-packet";
    case FrameError::OnlyFromServer:        return "only-from-server";
    case FrameError::AckRangeBelowZero:     return "ack-range-below-zero";
    case FrameError::BeyondMaxOffset:       return "beyond-max-offset";
    case FrameError::BeyondMaxStreams:      return "beyond-max-streams";
    case FrameError::BadConnectionIdLength: return "bad-connection-id-length";
    case FrameError::RetireAboveSequence:   return "retire-above-sequence";
    case FrameError::EmptyToken:            return "empty-token";
    case FrameError::EmptyPacket:           return "empty-packet";
    }
    return "unknown";
}

TransportError transport_error_of(FrameError e) noexcept {
    switch (e) {
    case FrameError::None:
        return TransportError::NoError;

    /* \~english
     * The RFC names these four PROTOCOL_VIOLATION (12.4, 19.7, 19.20): a type
     * written longer than needed, a frame in a packet type that may not carry
     * it or from the wrong end, and a packet with no frames.
     * \~spanish
     * El RFC nombra estas cuatro PROTOCOL_VIOLATION (12.4, 19.7, 19.20): un tipo
     * escrito mas largo de lo necesario, una trama en un tipo de paquete que no
     * puede llevarla o del extremo equivocado, y un paquete sin tramas.
     * \~ */
    case FrameError::TypeNotShortest:
    case FrameError::NotAllowedInPacket:
    case FrameError::OnlyFromServer:
    case FrameError::EmptyPacket:
        return TransportError::ProtocolViolation;

    default:
        return TransportError::FrameEncodingError;
    }
}

FrameReader::Step FrameReader::fail(FrameError e, uint64_t type) noexcept {
    error_ = e;
    error_type_ = type;
    error_at_ = start_;
    return Step::Error;
}

FrameReader::Step FrameReader::next(Frame &out) noexcept {
    if (error_ != FrameError::None) return Step::Error;

    start_ = pos_;
    if (pos_ >= n_) {
        // \~english A payload with no frame at all is the peer's error (12.4).
        // \~spanish Una carga sin ninguna trama es error del otro extremo (12.4).  \~
        if (frames_ == 0) return fail(FrameError::EmptyPacket, 0);
        return Step::End;
    }

    Cursor c{p_, n_, pos_};
    uint64_t w = 0;
    const size_t type_len = decode_varint(p_ + pos_, n_ - pos_, w);
    if (type_len == 0) return fail(FrameError::Truncated, 0);

    /* \~english
     * An unknown type first: that one is a MUST (FRAME_ENCODING_ERROR, 12.4),
     * while a type in a longer encoding than needed MAY be a PROTOCOL_VIOLATION
     * -- checked the other way round, an unknown type written long would get
     * the optional error instead of the mandatory one.  The shortest encoding
     * is checked here and not in the varint decoder, which every other field
     * shares and where a longer encoding is legal.
     * \~spanish
     * Primero un tipo desconocido: eso es un DEBE (FRAME_ENCODING_ERROR, 12.4),
     * mientras que un tipo con codificacion mas larga de lo necesario PUEDE ser un
     * PROTOCOL_VIOLATION -- mirado al reves, un tipo desconocido escrito largo
     * recibiria el error opcional en lugar del obligatorio.  La codificacion mas
     * corta se comprueba aqui y no en el descodificador de enteros, que comparten
     * todos los demas campos y donde una mas larga es legal.
     * \~ */
    const uint8_t allowed = allowed_in(w);
    if (allowed == 0) return fail(FrameError::UnknownType, w);
    if (type_len != varint_size(w)) return fail(FrameError::TypeNotShortest, w);
    pos_ += type_len;
    if ((allowed & packet_bit(ctx_.packet)) == 0)
        return fail(FrameError::NotAllowedInPacket, w);

    out = Frame{};
    out.type = type_of(w);
    out.wire_type = w;

    switch (out.type) {
    case FrameType::Padding:
        /* \~english
         * A run of zeros is one frame, not one per byte: an Initial is padded
         * to 1200 bytes, and handing out a thousand frames that say nothing
         * would be the most expensive part of reading it.
         * \~spanish
         * Una racha de ceros es una trama, no una por byte: un Initial se
         * rellena hasta 1200 bytes, y entregar mil tramas que no dicen nada
         * seria lo mas caro de leerlo.
         * \~ */
        while (pos_ < n_ && p_[pos_] == 0) ++pos_;
        out.data = {static_cast<uint32_t>(start_), static_cast<uint32_t>(pos_ - start_)};
        break;

    case FrameType::Ping:
    case FrameType::HandshakeDone:
        break;

    case FrameType::Ack: {
        if (!c.varint(out.largest) || !c.varint(out.ack_delay) ||
            !c.varint(out.range_count) || !c.varint(out.first_range))
            return fail(FrameError::Truncated, w);
        if (out.first_range > out.largest) return fail(FrameError::AckRangeBelowZero, w);

        /* \~english
         * Every range is walked now, once, so that whoever reads them later
         * gets ranges that cannot go below zero -- and so that the end of the
         * frame is known.  The count can say anything; each range takes two
         * bytes at least, so the payload bounds the loop, not the count.
         * \~spanish
         * Se recorren ahora todos los rangos, una vez, para que quien los lea
         * despues reciba rangos que no pueden bajar de cero -- y para saber
         * donde acaba la trama.  La cuenta puede decir cualquier cosa; cada
         * rango ocupa dos bytes por lo menos, asi que el bucle lo acota la
         * carga, no la cuenta.
         * \~ */
        const size_t ranges_at = pos_;
        uint64_t smallest = out.largest - out.first_range;
        for (uint64_t i = 0; i < out.range_count; ++i) {
            uint64_t gap = 0;
            uint64_t len = 0;
            if (!c.varint(gap) || !c.varint(len)) return fail(FrameError::Truncated, w);
            if (smallest < gap + 2) return fail(FrameError::AckRangeBelowZero, w);
            const uint64_t largest = smallest - gap - 2;
            if (len > largest) return fail(FrameError::AckRangeBelowZero, w);
            smallest = largest - len;
        }
        out.ranges = {static_cast<uint32_t>(ranges_at), static_cast<uint32_t>(pos_ - ranges_at)};

        if (w == 0x03) {
            out.has_ecn = true;
            if (!c.varint(out.ecn[0]) || !c.varint(out.ecn[1]) || !c.varint(out.ecn[2]))
                return fail(FrameError::Truncated, w);
        }
        break;
    }

    case FrameType::ResetStream:
        if (!c.varint(out.stream_id) || !c.varint(out.error_code) ||
            !c.varint(out.final_size))
            return fail(FrameError::Truncated, w);
        break;

    case FrameType::StopSending:
        if (!c.varint(out.stream_id) || !c.varint(out.error_code))
            return fail(FrameError::Truncated, w);
        break;

    case FrameType::Crypto: {
        uint64_t len = 0;
        if (!c.varint(out.offset) || !c.varint(len) || !c.bytes(len, out.data))
            return fail(FrameError::Truncated, w);
        if (out.offset + len > kMaxOffset) return fail(FrameError::BeyondMaxOffset, w);
        break;
    }

    case FrameType::NewToken: {
        if (ctx_.is_server) return fail(FrameError::OnlyFromServer, w);
        uint64_t len = 0;
        if (!c.varint(len) || !c.bytes(len, out.data)) return fail(FrameError::Truncated, w);
        if (len == 0) return fail(FrameError::EmptyToken, w);
        break;
    }

    case FrameType::Stream: {
        out.fin = (w & 0x01) != 0;
        if (!c.varint(out.stream_id)) return fail(FrameError::Truncated, w);
        if ((w & 0x04) != 0 && !c.varint(out.offset)) return fail(FrameError::Truncated, w);

        // \~english Without LEN, the data runs to the end of the packet.
        // \~spanish Sin LEN, los datos llegan hasta el final del paquete.  \~
        uint64_t len = n_ - pos_;
        if ((w & 0x02) != 0 && !c.varint(len)) return fail(FrameError::Truncated, w);
        if (!c.bytes(len, out.data)) return fail(FrameError::Truncated, w);

        // \~english Both below 2^62, so the sum cannot wrap a 64-bit integer.
        // \~spanish Los dos por debajo de 2^62, asi que la suma no da la vuelta en 64 bits.  \~
        if (out.offset + len > kMaxOffset) return fail(FrameError::BeyondMaxOffset, w);
        break;
    }

    case FrameType::MaxData:
    case FrameType::DataBlocked:
        if (!c.varint(out.maximum)) return fail(FrameError::Truncated, w);
        break;

    case FrameType::MaxStreamData:
    case FrameType::StreamDataBlocked:
        if (!c.varint(out.stream_id) || !c.varint(out.maximum))
            return fail(FrameError::Truncated, w);
        break;

    case FrameType::MaxStreams:
    case FrameType::StreamsBlocked:
        // \~english The even type of each pair is the bidirectional one.
        // \~spanish El tipo par de cada pareja es el bidireccional.  \~
        out.bidirectional = (w & 0x01) == 0;
        if (!c.varint(out.maximum)) return fail(FrameError::Truncated, w);
        if (out.maximum > kMaxStreams) return fail(FrameError::BeyondMaxStreams, w);
        break;

    case FrameType::NewConnectionId: {
        if (!c.varint(out.sequence) || !c.varint(out.retire_prior_to) || pos_ >= n_)
            return fail(FrameError::Truncated, w);
        const uint8_t len = p_[pos_++];
        if (len < 1 || len > kMaxConnectionId)
            return fail(FrameError::BadConnectionIdLength, w);
        if (!c.bytes(len, out.data) || !c.bytes(kResetTokenSize, out.reset_token))
            return fail(FrameError::Truncated, w);
        if (out.retire_prior_to > out.sequence) return fail(FrameError::RetireAboveSequence, w);
        break;
    }

    case FrameType::RetireConnectionId:
        if (!c.varint(out.sequence)) return fail(FrameError::Truncated, w);
        break;

    case FrameType::PathChallenge:
    case FrameType::PathResponse:
        if (!c.bytes(kPathDataSize, out.data)) return fail(FrameError::Truncated, w);
        break;

    case FrameType::ConnectionClose: {
        out.application = w == 0x1d;
        uint64_t len = 0;
        if (!c.varint(out.error_code) ||
            (!out.application && !c.varint(out.trigger_type)) ||
            !c.varint(len) || !c.bytes(len, out.data))
            return fail(FrameError::Truncated, w);
        break;
    }
    }

    // \~english HANDSHAKE_DONE only ever comes from a server (19.20).
    // \~spanish HANDSHAKE_DONE solo llega desde un servidor (19.20).  \~
    if (out.type == FrameType::HandshakeDone && ctx_.is_server)
        return fail(FrameError::OnlyFromServer, w);

    out.at = {static_cast<uint32_t>(start_), static_cast<uint32_t>(pos_ - start_)};
    ++frames_;
    return Step::Frame;
}

AckRangeReader::AckRangeReader(const uint8_t *payload, const Frame &ack) noexcept
    : p_(payload),
      pos_(ack.ranges.off),
      end_(static_cast<size_t>(ack.ranges.off) + ack.ranges.len),
      left_(ack.range_count),
      largest_(ack.largest),
      first_range_(ack.first_range) {}

bool AckRangeReader::next(AckRange &out) noexcept {
    if (first_) {
        first_ = false;
        out = {largest_ - first_range_, largest_};
        smallest_ = out.smallest;
        return true;
    }
    if (left_ == 0) return false;

    // \~english Already checked by the reader: this only decodes.
    // \~spanish Ya comprobado por el lector: esto solo descodifica.  \~
    uint64_t gap = 0;
    uint64_t len = 0;
    pos_ += decode_varint(p_ + pos_, end_ - pos_, gap);
    pos_ += decode_varint(p_ + pos_, end_ - pos_, len);
    const uint64_t largest = smallest_ - gap - 2;
    out = {largest - len, largest};
    smallest_ = out.smallest;
    --left_;
    return true;
}

size_t write_padding(uint8_t *p, size_t room, size_t n) noexcept {
    if (n > room) return 0;
    util::vesta_memset(p, 0, n);
    return n;
}

size_t write_ping(uint8_t *p, size_t room) noexcept {
    Writer o{p, room};
    o.byte(0x01);
    return o.done();
}

size_t write_ack(uint8_t *p, size_t room, const AckRange *ranges, size_t count,
                 uint64_t ack_delay, const uint64_t *ecn) noexcept {
    if (count == 0) return 0;

    /* \~english
     * The ranges have to be what an ACK can say: each one ordered, and each
     * below the previous with at least one unacknowledged packet between them
     * -- two adjacent ranges would need a gap of minus one.  Refused rather
     * than encoded into a frame the peer would reject as malformed.
     * \~spanish
     * Los rangos tienen que ser lo que puede decir un ACK: cada uno ordenado, y
     * cada uno por debajo del anterior con al menos un paquete sin confirmar en
     * medio -- dos rangos contiguos necesitarian un hueco de menos uno.  Se
     * rechazan en vez de codificarse en una trama que el otro extremo tiraria
     * por mal formada.
     * \~ */
    for (size_t i = 0; i < count; ++i) {
        if (ranges[i].smallest > ranges[i].largest) return 0;
        if (i > 0 && ranges[i].largest + 2 > ranges[i - 1].smallest) return 0;
    }

    Writer o{p, room};
    o.varint(ecn != nullptr ? 0x03 : 0x02);
    o.varint(ranges[0].largest);
    o.varint(ack_delay);
    o.varint(count - 1);
    o.varint(ranges[0].largest - ranges[0].smallest);
    for (size_t i = 1; i < count; ++i) {
        o.varint(ranges[i - 1].smallest - ranges[i].largest - 2);
        o.varint(ranges[i].largest - ranges[i].smallest);
    }
    if (ecn != nullptr) {
        o.varint(ecn[0]);
        o.varint(ecn[1]);
        o.varint(ecn[2]);
    }
    return o.done();
}

size_t write_reset_stream(uint8_t *p, size_t room, uint64_t stream_id,
                          uint64_t error_code, uint64_t final_size) noexcept {
    Writer o{p, room};
    o.varint(0x04);
    o.varint(stream_id);
    o.varint(error_code);
    o.varint(final_size);
    return o.done();
}

size_t write_stop_sending(uint8_t *p, size_t room, uint64_t stream_id,
                          uint64_t error_code) noexcept {
    Writer o{p, room};
    o.varint(0x05);
    o.varint(stream_id);
    o.varint(error_code);
    return o.done();
}

size_t write_crypto_header(uint8_t *p, size_t room, uint64_t offset,
                           uint64_t len) noexcept {
    if (offset > kMaxOffset || len > kMaxOffset - offset) return 0;
    Writer o{p, room};
    o.varint(0x06);
    o.varint(offset);
    o.varint(len);
    return o.done();
}

size_t write_new_token(uint8_t *p, size_t room, const uint8_t *token,
                       size_t len) noexcept {
    if (len == 0) return 0;
    Writer o{p, room};
    o.varint(0x07);
    o.varint(len);
    o.bytes(token, len);
    return o.done();
}

size_t write_stream_header(uint8_t *p, size_t room, uint64_t stream_id,
                           uint64_t offset, uint64_t len, bool fin,
                           bool with_length) noexcept {
    if (offset > kMaxOffset || len > kMaxOffset - offset) return 0;

    // \~english OFF only when there is an offset: a zero offset is implied without it.
    // \~spanish OFF solo cuando hay desplazamiento: sin el, se sobreentiende cero.  \~
    const uint64_t type = 0x08 | (offset != 0 ? 0x04 : 0) | (with_length ? 0x02 : 0) |
                          (fin ? 0x01 : 0);
    Writer o{p, room};
    o.varint(type);
    o.varint(stream_id);
    if (offset != 0) o.varint(offset);
    if (with_length) o.varint(len);
    return o.done();
}

size_t write_max_data(uint8_t *p, size_t room, uint64_t maximum) noexcept {
    Writer o{p, room};
    o.varint(0x10);
    o.varint(maximum);
    return o.done();
}

size_t write_max_stream_data(uint8_t *p, size_t room, uint64_t stream_id,
                             uint64_t maximum) noexcept {
    Writer o{p, room};
    o.varint(0x11);
    o.varint(stream_id);
    o.varint(maximum);
    return o.done();
}

size_t write_max_streams(uint8_t *p, size_t room, bool bidirectional,
                         uint64_t maximum) noexcept {
    if (maximum > kMaxStreams) return 0;
    Writer o{p, room};
    o.varint(bidirectional ? 0x12 : 0x13);
    o.varint(maximum);
    return o.done();
}

size_t write_data_blocked(uint8_t *p, size_t room, uint64_t maximum) noexcept {
    Writer o{p, room};
    o.varint(0x14);
    o.varint(maximum);
    return o.done();
}

size_t write_stream_data_blocked(uint8_t *p, size_t room, uint64_t stream_id,
                                 uint64_t maximum) noexcept {
    Writer o{p, room};
    o.varint(0x15);
    o.varint(stream_id);
    o.varint(maximum);
    return o.done();
}

size_t write_streams_blocked(uint8_t *p, size_t room, bool bidirectional,
                             uint64_t maximum) noexcept {
    if (maximum > kMaxStreams) return 0;
    Writer o{p, room};
    o.varint(bidirectional ? 0x16 : 0x17);
    o.varint(maximum);
    return o.done();
}

size_t write_new_connection_id(uint8_t *p, size_t room, uint64_t sequence,
                               uint64_t retire_prior_to, const uint8_t *cid,
                               size_t cid_len, const uint8_t *reset_token) noexcept {
    if (cid_len < 1 || cid_len > kMaxConnectionId || retire_prior_to > sequence)
        return 0;
    Writer o{p, room};
    o.varint(0x18);
    o.varint(sequence);
    o.varint(retire_prior_to);
    o.byte(static_cast<uint8_t>(cid_len));
    o.bytes(cid, cid_len);
    o.bytes(reset_token, kResetTokenSize);
    return o.done();
}

size_t write_retire_connection_id(uint8_t *p, size_t room,
                                  uint64_t sequence) noexcept {
    Writer o{p, room};
    o.varint(0x19);
    o.varint(sequence);
    return o.done();
}

size_t write_path_challenge(uint8_t *p, size_t room, const uint8_t *data) noexcept {
    Writer o{p, room};
    o.varint(0x1a);
    o.bytes(data, kPathDataSize);
    return o.done();
}

size_t write_path_response(uint8_t *p, size_t room, const uint8_t *data) noexcept {
    Writer o{p, room};
    o.varint(0x1b);
    o.bytes(data, kPathDataSize);
    return o.done();
}

size_t write_connection_close(uint8_t *p, size_t room, bool application,
                              uint64_t error_code, uint64_t trigger_type,
                              const uint8_t *reason, size_t reason_len) noexcept {
    Writer o{p, room};
    o.varint(application ? 0x1d : 0x1c);
    o.varint(error_code);
    if (!application) o.varint(trigger_type);
    o.varint(reason_len);
    o.bytes(reason, reason_len);
    return o.done();
}

size_t write_handshake_done(uint8_t *p, size_t room) noexcept {
    Writer o{p, room};
    o.byte(0x1e);
    return o.done();
}

} // namespace quic
} // namespace http_vx
