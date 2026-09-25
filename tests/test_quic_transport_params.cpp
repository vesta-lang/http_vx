/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_transport_params.cpp
 * @brief
 * \~english QUIC transport parameters: RFC 9001's client's, a round trip, and every rule of 7.3, 7.4 and 18.2.
 * \~spanish Los parametros de transporte de QUIC: los del cliente del RFC 9001, ida y vuelta, y cada regla de 7.3, 7.4 y 18.2.
 * \~
 */

#include "http_vx/quic_transport_params.h"

#include "tls_rfc8448.h"

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::quic;
using rfc8448::from_hex;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

void expect(TpError got, TpError want, const char *what) {
    if (got == want) return;
    std::fprintf(stderr, "FAIL: %s (got %s, wanted %s)\n", what, tp_error_name(got), tp_error_name(want));
    ++failures;
}

/// \~english A parameter list from hex, decoded as sent by @p from_server.
/// \~spanish Una lista de parametros a partir de hex, decodificada como mandada por @p from_server.  \~
TpError decode_hex(const char *hex, bool from_server, TransportParams &tp) {
    uint8_t b[256];
    const size_t n = from_hex(hex, b, sizeof b);
    return decode_transport_params(b, n, from_server, tp);
}

/// \~english RFC 9001, A.2: the extension_data of the client's quic_transport_parameters.
/// \~spanish RFC 9001, A.2: el extension_data del quic_transport_parameters del cliente.  \~
void test_rfc9001_client() {
    TransportParams tp;
    expect(decode_hex("0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e515708"
                      "06048000ffff",
                      false, tp),
           TpError::None, "RFC 9001's client transport parameters were refused");
    check(tp.initial_max_data == (uint64_t{1} << 62) - 1 && tp.initial_max_stream_data_bidi_local == 0xffff &&
              tp.initial_max_stream_data_bidi_remote == 0xffff && tp.initial_max_stream_data_uni == 0xffff &&
              tp.initial_max_streams_bidi == 16 && tp.initial_max_streams_uni == 16 &&
              tp.max_idle_timeout_ms == 30000,
          "RFC 9001's client values were not read");
    check(tp.initial_source_connection_id.present && tp.initial_source_connection_id.len == 8 &&
              tp.initial_source_connection_id.bytes[0] == 0x83,
          "RFC 9001's initial_source_connection_id was not read");
    // \~english What was absent keeps its default (18.2).  \~spanish Lo que faltaba conserva su valor por defecto (18.2).  \~
    check(tp.ack_delay_exponent == 3 && tp.max_ack_delay_ms == 25 && tp.max_udp_payload_size == 65527 &&
              tp.active_connection_id_limit == 2 && !tp.disable_active_migration,
          "a default was not kept");
}

void test_round_trip() {
    TransportParams s;
    s.original_destination_connection_id.present = true;
    s.original_destination_connection_id.len = 8;
    std::memset(s.original_destination_connection_id.bytes, 0x11, 8);
    s.initial_source_connection_id.present = true;
    s.initial_source_connection_id.len = 0;  // \~english a zero-length ID is sent with a zero-length value (7.3)  \~spanish un identificador de longitud cero se manda con un valor de longitud cero (7.3)  \~
    s.retry_source_connection_id.present = true;
    s.retry_source_connection_id.len = 4;
    std::memset(s.retry_source_connection_id.bytes, 0x22, 4);
    s.has_stateless_reset_token = true;
    std::memset(s.stateless_reset_token, 0x33, 16);
    s.max_idle_timeout_ms = 30000;
    s.max_udp_payload_size = 1472;
    s.initial_max_data = 1 << 20;
    s.initial_max_stream_data_bidi_local = 1000;
    s.initial_max_stream_data_bidi_remote = 2000;
    s.initial_max_stream_data_uni = 3000;
    s.initial_max_streams_bidi = 100;
    s.initial_max_streams_uni = 3;
    s.ack_delay_exponent = 8;
    s.max_ack_delay_ms = 20;
    s.disable_active_migration = true;
    s.active_connection_id_limit = 8;
    uint8_t out[512];
    const size_t n = encode_transport_params(s, out, sizeof out);
    TransportParams r;
    expect(decode_transport_params(out, n, true, r), TpError::None, "a server's own parameters were refused");
    check(r.original_destination_connection_id.len == 8 && r.original_destination_connection_id.bytes[7] == 0x11 &&
              r.initial_source_connection_id.present && r.initial_source_connection_id.len == 0 &&
              r.retry_source_connection_id.len == 4 && r.has_stateless_reset_token &&
              r.stateless_reset_token[15] == 0x33 && r.max_idle_timeout_ms == 30000 &&
              r.max_udp_payload_size == 1472 && r.initial_max_data == (1 << 20) &&
              r.initial_max_stream_data_bidi_local == 1000 && r.initial_max_stream_data_bidi_remote == 2000 &&
              r.initial_max_stream_data_uni == 3000 && r.initial_max_streams_bidi == 100 &&
              r.initial_max_streams_uni == 3 && r.ack_delay_exponent == 8 && r.max_ack_delay_ms == 20 &&
              r.disable_active_migration && r.active_connection_id_limit == 8,
          "a value did not survive the round trip");
    check(encode_transport_params(s, out, 10) == 0, "parameters were written past their room");

    // \~english A preferred address, and what it carries.  \~spanish Una direccion preferida, y lo que lleva.  \~
    TransportParams p;
    p.original_destination_connection_id.present = true;
    p.initial_source_connection_id.present = true;
    p.initial_source_connection_id.len = 8;
    p.has_preferred_address = true;
    p.preferred_address.ipv4[0] = 192;
    p.preferred_address.ipv4_port = 443;
    p.preferred_address.ipv6[15] = 1;
    p.preferred_address.ipv6_port = 8443;
    p.preferred_address.cid.present = true;
    p.preferred_address.cid.len = 8;
    p.preferred_address.cid.bytes[0] = 0x44;
    p.preferred_address.reset_token[0] = 0x55;
    const size_t m = encode_transport_params(p, out, sizeof out);
    expect(decode_transport_params(out, m, true, r), TpError::None, "a preferred address was refused");
    check(r.has_preferred_address && r.preferred_address.ipv4[0] == 192 && r.preferred_address.ipv4_port == 443 &&
              r.preferred_address.ipv6[15] == 1 && r.preferred_address.ipv6_port == 8443 &&
              r.preferred_address.cid.len == 8 && r.preferred_address.cid.bytes[0] == 0x44 &&
              r.preferred_address.reset_token[0] == 0x55,
          "the preferred address did not survive the round trip");
}

void test_rules() {
    TransportParams tp;
    // \~english The client's minimum: its initial_source_connection_id (7.3).  \~spanish El minimo del cliente: su initial_source_connection_id (7.3).  \~
    const char *scid = "0f0401020304";
    expect(decode_hex(scid, false, tp), TpError::None, "a client's minimal parameters were refused");
    expect(decode_hex("", false, tp), TpError::Missing, "no initial_source_connection_id was accepted (7.3)");
    expect(decode_hex(scid, true, tp), TpError::Missing,
           "a server without original_destination_connection_id was accepted (7.3)");

    // \~english 18.2: the four only a server may send.  \~spanish 18.2: los cuatro que solo puede mandar un servidor.  \~
    expect(decode_hex("0f0401020304 0000", false, tp), TpError::ServerOnly,
           "original_destination_connection_id from a client was accepted");
    expect(decode_hex("0f0401020304 1000", false, tp), TpError::ServerOnly,
           "retry_source_connection_id from a client was accepted");
    expect(decode_hex("0f0401020304 0210 00000000000000000000000000000000", false, tp), TpError::ServerOnly,
           "stateless_reset_token from a client was accepted");

    // \~english 7.4: twice.  \~spanish 7.4: dos veces.  \~
    expect(decode_hex("0f0401020304 0f0401020304", false, tp), TpError::Duplicate,
           "initial_source_connection_id twice was accepted");
    expect(decode_hex("0f0401020304 010101 010101", false, tp), TpError::Duplicate, "max_idle_timeout twice was accepted");

    // \~english 18.2: invalid values.  \~spanish 18.2: valores invalidos.  \~
    expect(decode_hex("0f0401020304 0302 4400", false, tp), TpError::InvalidValue,
           "max_udp_payload_size 1024 was accepted (under 1200)");
    expect(decode_hex("0f0401020304 0302 44b0", false, tp), TpError::None, "max_udp_payload_size 1200 was refused");
    expect(decode_hex("0f0401020304 0a0115", false, tp), TpError::InvalidValue, "ack_delay_exponent 21 was accepted");
    expect(decode_hex("0f0401020304 0a0114", false, tp), TpError::None, "ack_delay_exponent 20 was refused");
    expect(decode_hex("0f0401020304 0b02 0500", false, tp), TpError::InvalidValue,
           "a max_ack_delay whose value does not fill its length was accepted");
    expect(decode_hex("0f0401020304 0b04 80004000", false, tp), TpError::InvalidValue,
           "max_ack_delay 2^14 was accepted");
    expect(decode_hex("0f0401020304 0b02 7fff", false, tp), TpError::None, "max_ack_delay 2^14 - 1 was refused");
    expect(decode_hex("0f0401020304 0e0101", false, tp), TpError::InvalidValue,
           "active_connection_id_limit 1 was accepted (MUST be at least 2)");
    expect(decode_hex("0f0401020304 0808 d000000000000000", false, tp), TpError::None,
           "initial_max_streams_bidi 2^60 was refused");
    expect(decode_hex("0f0401020304 0808 d000000000000001", false, tp), TpError::InvalidValue,
           "initial_max_streams_bidi over 2^60 was accepted (4.6)");
    expect(decode_hex("0f0401020304 0c0100", false, tp), TpError::InvalidValue,
           "disable_active_migration with a value was accepted");
    expect(decode_hex("0f15 000102030405060708090a0b0c0d0e0f1011121314", false, tp), TpError::InvalidValue,
           "a 21-byte connection ID was accepted");
    expect(decode_hex("0f0401020304 0200", true, tp), TpError::InvalidValue,
           "a stateless_reset_token that is not 16 bytes was accepted");
    expect(decode_hex("0000 0f0401020304 0211 0000000000000000000000000000000000", true, tp), TpError::InvalidValue,
           "a 17-byte stateless_reset_token was accepted");
    expect(decode_hex("0f0401020304 0100", false, tp), TpError::InvalidValue,
           "an integer parameter with no value was accepted");

    // \~english Unknown and reserved parameters are ignored (7.4.2, 18.1).  \~spanish Los desconocidos y reservados se ignoran (7.4.2, 18.1).  \~
    expect(decode_hex("0f0401020304 1b03 aabbcc 4031 00", false, tp), TpError::None,
           "a reserved or unknown parameter was not ignored");
    // \~english Lengths past the end.  \~spanish Longitudes que pasan del final.  \~
    expect(decode_hex("0f0401020304 0105 01", false, tp), TpError::Malformed, "a length past the end was accepted");

    // \~english 18.2: a preferred address with a zero-length ID, or from a server whose own ID is zero-length.
    // \~spanish 18.2: una direccion preferida con identificador de longitud cero, o de un servidor cuyo identificador lo es.  \~
    const char *pa_zero_cid = "0d29 00000000 0000 00000000000000000000000000000000 0000 00"
                              " 00000000000000000000000000000000";
    char buf[256];
    std::snprintf(buf, sizeof buf, "0000 0f0401020304 %s", pa_zero_cid);
    expect(decode_hex(buf, true, tp), TpError::InvalidValue, "a preferred address with a zero-length ID was accepted");
    expect(decode_hex("0000 0f00 0d2a 00000000 0000 00000000000000000000000000000000 0000 01 aa"
                      " 00000000000000000000000000000000",
                      true, tp),
           TpError::InvalidValue, "a server with a zero-length ID gave a preferred address");
    expect(decode_hex("0000 0f0101 0d2a 00000000 0000 00000000000000000000000000000000 0000 01 aa"
                      " 00000000000000000000000000000000",
                      true, tp),
           TpError::None, "a valid preferred address was refused");
}

} // namespace

int main() {
    test_rfc9001_client();
    test_round_trip();
    test_rules();
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic transport params: OK\n");
    return 0;
}
