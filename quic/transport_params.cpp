/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/transport_params.cpp
 * @brief
 * \~english Encoding and checking QUIC transport parameters (RFC 9000, 7.4 and 18).
 * \~spanish Codificar y comprobar los parametros de transporte de QUIC (RFC 9000, 7.4 y 18).
 * \~
 */

#include "http_vx/quic_transport_params.h"

#include "http_vx/quic_varint.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace quic {

namespace {

/// \~english The identifiers of 18.2.  \~spanish Los identificadores de 18.2.  \~
enum : uint64_t {
    kOriginalDcid = 0x00,
    kMaxIdleTimeout = 0x01,
    kStatelessResetToken = 0x02,
    kMaxUdpPayloadSize = 0x03,
    kInitialMaxData = 0x04,
    kInitialMaxStreamDataBidiLocal = 0x05,
    kInitialMaxStreamDataBidiRemote = 0x06,
    kInitialMaxStreamDataUni = 0x07,
    kInitialMaxStreamsBidi = 0x08,
    kInitialMaxStreamsUni = 0x09,
    kAckDelayExponent = 0x0a,
    kMaxAckDelay = 0x0b,
    kDisableActiveMigration = 0x0c,
    kPreferredAddress = 0x0d,
    kActiveConnectionIdLimit = 0x0e,
    kInitialScid = 0x0f,
    kRetryScid = 0x10,
    kKnownCount = 0x11,
};

/// \~english Writes one parameter: identifier, length, value.  \~spanish Escribe un parametro: identificador, longitud, valor.  \~
struct Out {
    uint8_t *p;
    size_t room;
    size_t used = 0;
    bool failed = false;

    void varint(uint64_t v) noexcept {
        const size_t n = failed ? 0 : encode_varint(p + used, room - used, v);
        if (n == 0) failed = true;
        used += n;
    }
    void bytes(const uint8_t *b, size_t n) noexcept {
        if (failed || room - used < n) {
            failed = true;
            return;
        }
        if (n != 0) util::vesta_memcpy_noinline(p + used, b, n);
        used += n;
    }
    void integer(uint64_t id, uint64_t v) noexcept {
        varint(id);
        varint(varint_size(v));
        varint(v);
    }
    void opaque(uint64_t id, const uint8_t *b, size_t n) noexcept {
        varint(id);
        varint(n);
        bytes(b, n);
    }
};

/// \~english An integer parameter: one varint filling the whole value (18).
/// \~spanish Un parametro entero: un varint que llena todo el valor (18).  \~
bool read_integer(const uint8_t *v, size_t len, uint64_t &out) noexcept {
    return len != 0 && decode_varint(v, len, out) == len;
}

bool read_cid(const uint8_t *v, size_t len, TpConnectionId &out) noexcept {
    if (len > kMaxConnectionId) return false;
    out.present = true;
    out.len = static_cast<uint8_t>(len);
    if (len != 0) util::vesta_memcpy_noinline(out.bytes, v, len);
    return true;
}

uint16_t read16(const uint8_t *p) noexcept {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

} // namespace

const char *tp_error_name(TpError e) noexcept {
    switch (e) {
    case TpError::None:         return "none";
    case TpError::Malformed:    return "malformed";
    case TpError::Duplicate:    return "duplicate";
    case TpError::InvalidValue: return "invalid-value";
    case TpError::ServerOnly:   return "server-only";
    case TpError::Missing:      return "missing";
    }
    return "unknown";
}

size_t encode_transport_params(const TransportParams &tp, uint8_t *out, size_t room) noexcept {
    const TransportParams d;
    Out o{out, room};
    if (tp.original_destination_connection_id.present)
        o.opaque(kOriginalDcid, tp.original_destination_connection_id.bytes, tp.original_destination_connection_id.len);
    if (tp.max_idle_timeout_ms != d.max_idle_timeout_ms) o.integer(kMaxIdleTimeout, tp.max_idle_timeout_ms);
    if (tp.has_stateless_reset_token) o.opaque(kStatelessResetToken, tp.stateless_reset_token, 16);
    if (tp.max_udp_payload_size != d.max_udp_payload_size) o.integer(kMaxUdpPayloadSize, tp.max_udp_payload_size);
    if (tp.initial_max_data != 0) o.integer(kInitialMaxData, tp.initial_max_data);
    if (tp.initial_max_stream_data_bidi_local != 0)
        o.integer(kInitialMaxStreamDataBidiLocal, tp.initial_max_stream_data_bidi_local);
    if (tp.initial_max_stream_data_bidi_remote != 0)
        o.integer(kInitialMaxStreamDataBidiRemote, tp.initial_max_stream_data_bidi_remote);
    if (tp.initial_max_stream_data_uni != 0) o.integer(kInitialMaxStreamDataUni, tp.initial_max_stream_data_uni);
    if (tp.initial_max_streams_bidi != 0) o.integer(kInitialMaxStreamsBidi, tp.initial_max_streams_bidi);
    if (tp.initial_max_streams_uni != 0) o.integer(kInitialMaxStreamsUni, tp.initial_max_streams_uni);
    if (tp.ack_delay_exponent != d.ack_delay_exponent) o.integer(kAckDelayExponent, tp.ack_delay_exponent);
    if (tp.max_ack_delay_ms != d.max_ack_delay_ms) o.integer(kMaxAckDelay, tp.max_ack_delay_ms);
    if (tp.disable_active_migration) o.opaque(kDisableActiveMigration, nullptr, 0);
    if (tp.has_preferred_address) {
        const PreferredAddress &pa = tp.preferred_address;
        uint8_t v[4 + 2 + 16 + 2 + 1 + kMaxConnectionId + 16];
        size_t n = 0;
        util::vesta_memcpy_noinline(v + n, pa.ipv4, 4);
        n += 4;
        v[n++] = static_cast<uint8_t>(pa.ipv4_port >> 8);
        v[n++] = static_cast<uint8_t>(pa.ipv4_port);
        util::vesta_memcpy_noinline(v + n, pa.ipv6, 16);
        n += 16;
        v[n++] = static_cast<uint8_t>(pa.ipv6_port >> 8);
        v[n++] = static_cast<uint8_t>(pa.ipv6_port);
        v[n++] = pa.cid.len;
        util::vesta_memcpy_noinline(v + n, pa.cid.bytes, pa.cid.len);
        n += pa.cid.len;
        util::vesta_memcpy_noinline(v + n, pa.reset_token, 16);
        n += 16;
        o.opaque(kPreferredAddress, v, n);
    }
    if (tp.active_connection_id_limit != d.active_connection_id_limit)
        o.integer(kActiveConnectionIdLimit, tp.active_connection_id_limit);
    if (tp.initial_source_connection_id.present)
        o.opaque(kInitialScid, tp.initial_source_connection_id.bytes, tp.initial_source_connection_id.len);
    if (tp.retry_source_connection_id.present)
        o.opaque(kRetryScid, tp.retry_source_connection_id.bytes, tp.retry_source_connection_id.len);
    return o.failed ? 0 : o.used;
}

TpError decode_transport_params(const uint8_t *in, size_t n, bool from_server, TransportParams &out) noexcept {
    out = TransportParams{};
    bool seen[kKnownCount] = {};
    size_t at = 0;
    while (at < n) {
        uint64_t id = 0;
        uint64_t len = 0;
        size_t k = decode_varint(in + at, n - at, id);
        if (k == 0) return TpError::Malformed;
        at += k;
        k = decode_varint(in + at, n - at, len);
        if (k == 0) return TpError::Malformed;
        at += k;
        if (len > n - at) return TpError::Malformed;
        const uint8_t *v = in + at;
        at += static_cast<size_t>(len);

        // \~english Unknown, reserved ones included: ignored (7.4.2, 18.1).
        // \~spanish Los desconocidos, reservados incluidos: se ignoran (7.4.2, 18.1).  \~
        if (id >= kKnownCount) continue;
        // \~english Twice is TRANSPORT_PARAMETER_ERROR (7.4: SHOULD, taken).
        // \~spanish Dos veces es TRANSPORT_PARAMETER_ERROR (7.4: DEBERIA, se aplica).  \~
        if (seen[id]) return TpError::Duplicate;
        seen[id] = true;
        // \~english A client MUST NOT send these four (18.2).  \~spanish Un cliente NO DEBE mandar estos cuatro (18.2).  \~
        if (!from_server && (id == kOriginalDcid || id == kPreferredAddress || id == kRetryScid ||
                             id == kStatelessResetToken))
            return TpError::ServerOnly;

        const size_t l = static_cast<size_t>(len);
        uint64_t x = 0;
        switch (id) {
        case kOriginalDcid:
            if (!read_cid(v, l, out.original_destination_connection_id)) return TpError::InvalidValue;
            break;
        case kInitialScid:
            if (!read_cid(v, l, out.initial_source_connection_id)) return TpError::InvalidValue;
            break;
        case kRetryScid:
            if (!read_cid(v, l, out.retry_source_connection_id)) return TpError::InvalidValue;
            break;
        case kStatelessResetToken:
            // \~english "a sequence of 16 bytes"  \~spanish "una secuencia de 16 bytes"  \~
            if (l != 16) return TpError::InvalidValue;
            out.has_stateless_reset_token = true;
            util::vesta_memcpy_noinline(out.stateless_reset_token, v, 16);
            break;
        case kDisableActiveMigration:
            // \~english "a zero-length value"  \~spanish "un valor de longitud cero"  \~
            if (l != 0) return TpError::InvalidValue;
            out.disable_active_migration = true;
            break;
        case kPreferredAddress: {
            // \~english Figure 22; a zero-length ID there MUST be refused (18.2).
            // \~spanish Figura 22; un identificador de longitud cero ahi DEBE rechazarse (18.2).  \~
            if (l < 4 + 2 + 16 + 2 + 1 + 16) return TpError::InvalidValue;
            PreferredAddress &pa = out.preferred_address;
            util::vesta_memcpy_noinline(pa.ipv4, v, 4);
            pa.ipv4_port = read16(v + 4);
            util::vesta_memcpy_noinline(pa.ipv6, v + 6, 16);
            pa.ipv6_port = read16(v + 22);
            const size_t cid_len = v[24];
            if (cid_len == 0 || cid_len > kMaxConnectionId || l != 25 + cid_len + 16) return TpError::InvalidValue;
            pa.cid.present = true;
            pa.cid.len = static_cast<uint8_t>(cid_len);
            util::vesta_memcpy_noinline(pa.cid.bytes, v + 25, cid_len);
            util::vesta_memcpy_noinline(pa.reset_token, v + 25 + cid_len, 16);
            out.has_preferred_address = true;
            break;
        }
        default:
            if (!read_integer(v, l, x)) return TpError::InvalidValue;
            switch (id) {
            case kMaxIdleTimeout: out.max_idle_timeout_ms = x; break;
            case kMaxUdpPayloadSize:
                if (x < 1200) return TpError::InvalidValue;  // \~english 18.2  \~spanish 18.2  \~
                out.max_udp_payload_size = x;
                break;
            case kInitialMaxData: out.initial_max_data = x; break;
            case kInitialMaxStreamDataBidiLocal: out.initial_max_stream_data_bidi_local = x; break;
            case kInitialMaxStreamDataBidiRemote: out.initial_max_stream_data_bidi_remote = x; break;
            case kInitialMaxStreamDataUni: out.initial_max_stream_data_uni = x; break;
            case kInitialMaxStreamsBidi:
            case kInitialMaxStreamsUni:
                // \~english Over 2^60 no stream ID could be written (4.6).
                // \~spanish Por encima de 2^60 ningun identificador de flujo se podria escribir (4.6).  \~
                if (x > (uint64_t{1} << 60)) return TpError::InvalidValue;
                (id == kInitialMaxStreamsBidi ? out.initial_max_streams_bidi : out.initial_max_streams_uni) = x;
                break;
            case kAckDelayExponent:
                if (x > 20) return TpError::InvalidValue;  // \~english 18.2  \~spanish 18.2  \~
                out.ack_delay_exponent = x;
                break;
            case kMaxAckDelay:
                if (x >= (uint64_t{1} << 14)) return TpError::InvalidValue;  // \~english 18.2  \~spanish 18.2  \~
                out.max_ack_delay_ms = x;
                break;
            case kActiveConnectionIdLimit:
                if (x < 2) return TpError::InvalidValue;  // \~english 18.2: MUST  \~spanish 18.2: DEBE  \~
                out.active_connection_id_limit = x;
                break;
            default:
                break;
            }
            break;
        }
    }

    // \~english 7.3: initial_source_connection_id from both; original_destination_connection_id from the server.
    // \~spanish 7.3: initial_source_connection_id de los dos; original_destination_connection_id del servidor.  \~
    if (!out.initial_source_connection_id.present) return TpError::Missing;
    if (from_server && !out.original_destination_connection_id.present) return TpError::Missing;
    // \~english A server that chose a zero-length ID MUST NOT provide a preferred address (18.2).
    // \~spanish Un servidor que eligio un identificador de longitud cero NO DEBE dar una direccion preferida (18.2).  \~
    if (out.has_preferred_address && out.initial_source_connection_id.len == 0) return TpError::InvalidValue;
    return TpError::None;
}

} // namespace quic
} // namespace http_vx
