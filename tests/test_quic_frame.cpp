/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_frame.cpp
 * @brief
 * \~english QUIC frames: the RFC's own payloads, every writer and reader, every rule, and noise.
 * \~spanish Tramas de QUIC: las cargas del propio RFC, cada escritor y lector, cada regla, y ruido.
 * \~
 *
 * \~english
 * The first two cases read the payloads RFC 9001 appendix A protects: a
 * client's CRYPTO frame padded to 1162 bytes, and a server's ACK and CRYPTO.
 * The table of which frame may travel in which packet is checked against the
 * RFC's own letters, typed out here separately from the implementation's
 * bits -- a table checked against itself would agree with any mistake in it.
 * And the last case is noise, with the property that matters for a parser:
 * whatever it accepts tiles the payload exactly, and no span points outside.
 * \~spanish
 * Los dos primeros casos leen las cargas que protege el apendice A del RFC 9001:
 * la trama CRYPTO de un cliente rellena hasta 1162 bytes, y el ACK y el CRYPTO
 * de un servidor.  La tabla de que trama puede ir en que paquete se comprueba
 * contra las letras del propio RFC, escritas aqui aparte de los bits de la
 * implementacion -- una tabla comprobada contra si misma estaria de acuerdo con
 * cualquier error que tuviera.  Y el ultimo caso es ruido, con la propiedad que
 * importa en un analizador: lo que acepta cubre la carga exactamente, y ningun
 * trozo apunta fuera.
 * \~
 */

#include "http_vx/quic_frame.h"
#include "http_vx/quic_varint.h"

#include <cstdio>
#include <cstring>
#include <random>

namespace {

using namespace http_vx::quic;
using Step = FrameReader::Step;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english Turns hex text into bytes.  \~spanish Convierte texto hexadecimal en bytes.  \~
size_t from_hex(const char *hex, uint8_t *out, size_t room) {
    size_t n = 0;
    while (hex[0] != '\0' && hex[1] != '\0' && n < room) {
        unsigned v = 0;
        std::sscanf(hex, "%2x", &v);
        out[n++] = static_cast<uint8_t>(v);
        hex += 2;
    }
    return n;
}

FrameContext ctx_of(PacketType t, bool is_server) {
    FrameContext c;
    c.packet = t;
    c.is_server = is_server;
    return c;
}

/// \~english RFC 9001 A.2: the client's CRYPTO frame, then zeros to 1162 bytes.
/// \~spanish RFC 9001 A.2: la trama CRYPTO del cliente, y ceros hasta 1162 bytes.  \~
void test_the_rfc_client_payload() {
    uint8_t p[1162] = {};
    const size_t crypto = from_hex(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e0005000501000000000033" "00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1" "5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408" "050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480" "00ffff07048000ffff08011001048000"
        "75300901100f088394c8f03e51570806" "048000ffff",
        p, sizeof p);
    check(crypto == 245, "the RFC's CRYPTO frame is not 245 bytes");

    FrameReader r(p, sizeof p, ctx_of(PacketType::Initial, true));
    Frame f;
    check(r.next(f) == Step::Frame && f.type == FrameType::Crypto && f.offset == 0 &&
              f.data.off == 4 && f.data.len == 241 && p[f.data.off] == 0x01,
          "the RFC's CRYPTO frame did not read as a ClientHello at offset 0");

    // \~english 917 bytes of padding, handed out as ONE frame.
    // \~spanish 917 bytes de relleno, entregados como UNA trama.  \~
    check(r.next(f) == Step::Frame && f.type == FrameType::Padding &&
              f.data.off == 245 && f.data.len == 917,
          "the padding was not one frame covering the rest");
    check(r.next(f) == Step::End, "the payload did not end after the padding");
}

/// \~english RFC 9001 A.3: the server's ACK of packet 0, then its CRYPTO frame.
/// \~spanish RFC 9001 A.3: el ACK del servidor del paquete 0, y su trama CRYPTO.  \~
void test_the_rfc_server_payload() {
    uint8_t p[128];
    const size_t n = from_hex(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
        "020304",
        p, sizeof p);

    FrameReader r(p, n, ctx_of(PacketType::Initial, false));
    Frame f;
    check(r.next(f) == Step::Frame && f.type == FrameType::Ack && f.largest == 0 &&
              f.ack_delay == 0 && f.range_count == 0 && f.first_range == 0 &&
              !f.has_ecn,
          "the RFC's ACK did not read as acknowledging packet 0");
    AckRangeReader ranges(p, f);
    AckRange a;
    check(ranges.next(a) && a.smallest == 0 && a.largest == 0 && !ranges.next(a),
          "the RFC's ACK did not give exactly the range [0, 0]");

    check(r.next(f) == Step::Frame && f.type == FrameType::Crypto && f.offset == 0 &&
              f.data.len == 90 && p[f.data.off] == 0x02,
          "the RFC's server CRYPTO did not read as a ServerHello");
    check(r.next(f) == Step::End, "the server payload did not end after its CRYPTO");
}

/// \~english Reads exactly one frame from @p p, in a 1-RTT packet a client receives.
/// \~spanish Lee exactamente una trama de @p p, en un paquete 1-RTT que recibe un cliente.  \~
bool read_one(const uint8_t *p, size_t n, Frame &f) {
    FrameReader r(p, n, ctx_of(PacketType::OneRtt, false));
    Frame end;
    return r.next(f) == Step::Frame && f.at.off == 0 && f.at.len == n &&
           r.next(end) == Step::End;
}

/// \~english Everything a writer writes, the reader reads back as it was.
/// \~spanish Todo lo que escribe un escritor, el lector lo lee tal como era.  \~
void test_round_trips() {
    uint8_t b[256];
    Frame f;
    size_t n;

    n = write_ping(b, sizeof b);
    check(n == 1 && read_one(b, n, f) && f.type == FrameType::Ping, "PING");

    n = write_padding(b, sizeof b, 30);
    check(n == 30 && read_one(b, n, f) && f.type == FrameType::Padding && f.data.len == 30,
          "PADDING");

    n = write_reset_stream(b, sizeof b, 4, 0x1234, 1u << 20);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::ResetStream &&
              f.stream_id == 4 && f.error_code == 0x1234 && f.final_size == (1u << 20),
          "RESET_STREAM");

    n = write_stop_sending(b, sizeof b, 8, 77);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::StopSending &&
              f.stream_id == 8 && f.error_code == 77,
          "STOP_SENDING");

    // \~english CRYPTO and STREAM: the header, then the data put right behind it.
    // \~spanish CRYPTO y STREAM: la cabecera, y los datos puestos justo detras.  \~
    n = write_crypto_header(b, sizeof b, 1000, 5);
    std::memcpy(b + n, "hello", 5);
    check(n != 0 && read_one(b, n + 5, f) && f.type == FrameType::Crypto &&
              f.offset == 1000 && f.data.len == 5 && std::memcmp(b + f.data.off, "hello", 5) == 0,
          "CRYPTO");

    const uint8_t token[] = {9, 8, 7};
    n = write_new_token(b, sizeof b, token, sizeof token);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::NewToken &&
              f.data.len == 3 && b[f.data.off] == 9,
          "NEW_TOKEN");

    for (int flags = 0; flags < 8; ++flags) {
        const bool fin = (flags & 1) != 0;
        const bool with_length = (flags & 2) != 0;
        const uint64_t offset = (flags & 4) != 0 ? 123456 : 0;
        n = write_stream_header(b, sizeof b, 13, offset, 4, fin, with_length);
        std::memcpy(b + n, "data", 4);
        const bool ok = n != 0 && read_one(b, n + 4, f) && f.type == FrameType::Stream &&
                        f.stream_id == 13 && f.offset == offset && f.fin == fin &&
                        f.data.len == 4 && std::memcmp(b + f.data.off, "data", 4) == 0 &&
                        ((f.wire_type & 0x02) != 0) == with_length &&
                        ((f.wire_type & 0x04) != 0) == (offset != 0);
        if (!ok) {
            std::fprintf(stderr, "FAIL: STREAM with fin=%d len=%d offset=%llu\n", fin,
                         with_length, static_cast<unsigned long long>(offset));
            ++failures;
        }
    }

    n = write_max_data(b, sizeof b, 1u << 30);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::MaxData && f.maximum == (1u << 30),
          "MAX_DATA");
    n = write_max_stream_data(b, sizeof b, 3, 999);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::MaxStreamData &&
              f.stream_id == 3 && f.maximum == 999,
          "MAX_STREAM_DATA");
    n = write_max_streams(b, sizeof b, true, 100);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::MaxStreams &&
              f.bidirectional && f.maximum == 100,
          "MAX_STREAMS bidi");
    n = write_max_streams(b, sizeof b, false, kMaxStreams);
    check(n != 0 && read_one(b, n, f) && !f.bidirectional && f.maximum == kMaxStreams,
          "MAX_STREAMS uni at 2^60");
    n = write_data_blocked(b, sizeof b, 55);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::DataBlocked && f.maximum == 55,
          "DATA_BLOCKED");
    n = write_stream_data_blocked(b, sizeof b, 7, 66);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::StreamDataBlocked &&
              f.stream_id == 7 && f.maximum == 66,
          "STREAM_DATA_BLOCKED");
    n = write_streams_blocked(b, sizeof b, false, 12);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::StreamsBlocked &&
              !f.bidirectional && f.maximum == 12,
          "STREAMS_BLOCKED");

    const uint8_t cid[] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t reset[kResetTokenSize];
    for (size_t i = 0; i < sizeof reset; ++i) reset[i] = static_cast<uint8_t>(0xa0 + i);
    n = write_new_connection_id(b, sizeof b, 5, 2, cid, sizeof cid, reset);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::NewConnectionId &&
              f.sequence == 5 && f.retire_prior_to == 2 && f.data.len == 8 &&
              std::memcmp(b + f.data.off, cid, 8) == 0 && f.reset_token.len == 16 &&
              std::memcmp(b + f.reset_token.off, reset, 16) == 0,
          "NEW_CONNECTION_ID");
    n = write_retire_connection_id(b, sizeof b, 9);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::RetireConnectionId &&
              f.sequence == 9,
          "RETIRE_CONNECTION_ID");

    const uint8_t path[kPathDataSize] = {1, 1, 2, 3, 5, 8, 13, 21};
    n = write_path_challenge(b, sizeof b, path);
    check(n == 9 && read_one(b, n, f) && f.type == FrameType::PathChallenge &&
              std::memcmp(b + f.data.off, path, 8) == 0,
          "PATH_CHALLENGE");
    n = write_path_response(b, sizeof b, path);
    check(n == 9 && read_one(b, n, f) && f.type == FrameType::PathResponse, "PATH_RESPONSE");

    const char why[] = "bye";
    n = write_connection_close(b, sizeof b, false, 0x0a, 0x08,
                               reinterpret_cast<const uint8_t *>(why), 3);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::ConnectionClose &&
              !f.application && f.error_code == 0x0a && f.trigger_type == 0x08 &&
              f.data.len == 3 && std::memcmp(b + f.data.off, why, 3) == 0,
          "CONNECTION_CLOSE transport");
    n = write_connection_close(b, sizeof b, true, 0x0100, 0, nullptr, 0);
    check(n != 0 && read_one(b, n, f) && f.application && f.error_code == 0x0100 &&
              f.data.len == 0,
          "CONNECTION_CLOSE application");

    n = write_handshake_done(b, sizeof b);
    check(n == 1 && read_one(b, n, f) && f.type == FrameType::HandshakeDone, "HANDSHAKE_DONE");

    // \~english A writer given too little room writes nothing that counts.
    // \~spanish Un escritor con poco sitio no escribe nada que cuente.  \~
    check(write_new_connection_id(b, 10, 5, 2, cid, sizeof cid, reset) == 0 &&
              write_crypto_header(b, 2, 1000, 5) == 0 && write_ping(b, 0) == 0,
          "a writer wrote a frame into less room than it needs");
    check(write_new_connection_id(b, sizeof b, 1, 2, cid, sizeof cid, reset) == 0 &&
              write_new_connection_id(b, sizeof b, 1, 0, cid, 0, reset) == 0 &&
              write_new_token(b, sizeof b, token, 0) == 0 &&
              write_max_streams(b, sizeof b, true, kMaxStreams + 1) == 0 &&
              write_stream_header(b, sizeof b, 0, kMaxOffset, 1, false, true) == 0,
          "a writer wrote a frame the reader would refuse");
}

/// \~english ACK ranges, written and read back, and the orders an ACK cannot say.
/// \~spanish Rangos de ACK, escritos y leidos de vuelta, y los ordenes que un ACK no puede decir.  \~
void test_ack_ranges() {
    const AckRange in[] = {{90, 100}, {50, 60}, {40, 48}, {0, 0}};
    const uint64_t ecn[3] = {7, 8, 9};
    uint8_t b[128];
    Frame f;

    size_t n = write_ack(b, sizeof b, in, 4, 25, ecn);
    check(n != 0 && read_one(b, n, f) && f.type == FrameType::Ack && f.has_ecn &&
              f.largest == 100 && f.ack_delay == 25 && f.range_count == 3 &&
              f.ecn[0] == 7 && f.ecn[1] == 8 && f.ecn[2] == 9,
          "an ACK with ranges and ECN did not read back");

    AckRangeReader r(b, f);
    AckRange a;
    size_t i = 0;
    while (r.next(a)) {
        if (i >= 4 || a.smallest != in[i].smallest || a.largest != in[i].largest) {
            check(false, "the ACK ranges came back different");
            break;
        }
        ++i;
    }
    check(i == 4, "the ACK did not give back its four ranges");

    const AckRange adjacent[] = {{10, 20}, {5, 9}};
    const AckRange overlapping[] = {{10, 20}, {5, 12}};
    const AckRange inverted[] = {{20, 10}};
    const AckRange ascending[] = {{0, 5}, {10, 20}};
    check(write_ack(b, sizeof b, adjacent, 2, 0, nullptr) == 0 &&
              write_ack(b, sizeof b, overlapping, 2, 0, nullptr) == 0 &&
              write_ack(b, sizeof b, inverted, 1, 0, nullptr) == 0 &&
              write_ack(b, sizeof b, ascending, 2, 0, nullptr) == 0 &&
              write_ack(b, sizeof b, in, 0, 0, nullptr) == 0,
          "write_ack encoded ranges an ACK cannot express");

    const AckRange one_gap[] = {{10, 20}, {5, 8}};
    n = write_ack(b, sizeof b, one_gap, 2, 0, nullptr);
    check(n != 0 && read_one(b, n, f) && f.range_count == 1,
          "two ranges one packet apart could not be written");
}

/**
 * @brief
 * \~english Table 3 of RFC 9000, checked against its own letters.
 * \~spanish La tabla 3 del RFC 9000, comprobada contra sus propias letras.
 * \~
 */
void test_which_packets_carry_which_frames() {
    struct Row {
        const char *hex;   // \~english a valid frame of this type  \~spanish una trama valida de este tipo  \~
        const char *pkts;  // \~english the RFC's Pkts column  \~spanish la columna Pkts del RFC  \~
    };
    const Row rows[] = {
        {"00", "IH01"},
        {"01", "IH01"},
        {"0200000000", "IH_1"},
        {"0300000000000000", "IH_1"},
        {"04000000", "__01"},
        {"050000", "__01"},
        {"060000", "IH_1"},
        {"0701aa", "___1"},
        {"0800", "__01"},
        {"0900", "__01"},
        {"0a0000", "__01"},
        {"0b0000", "__01"},
        {"0c0000", "__01"},
        {"0d0000", "__01"},
        {"0e000000", "__01"},
        {"0f000000", "__01"},
        {"1000", "__01"},
        {"110000", "__01"},
        {"1200", "__01"},
        {"1300", "__01"},
        {"1400", "__01"},
        {"150000", "__01"},
        {"1600", "__01"},
        {"1700", "__01"},
        {"18000001aa00000000000000000000000000000000", "__01"},
        {"1900", "__01"},
        {"1a0000000000000000", "__01"},
        {"1b0000000000000000", "___1"},
        {"1c000000", "IH01"},  // \~english the "ih" note: only 0x1c  \~spanish la nota "ih": solo 0x1c  \~
        {"1d0000", "__01"},
        {"1e", "___1"},
    };
    const PacketType packets[4] = {PacketType::Initial, PacketType::Handshake,
                                   PacketType::ZeroRtt, PacketType::OneRtt};

    for (const Row &row : rows) {
        uint8_t b[64];
        const size_t n = from_hex(row.hex, b, sizeof b);
        for (int k = 0; k < 4; ++k) {
            const bool expected = row.pkts[k] != '_';
            FrameReader r(b, n, ctx_of(packets[k], false));
            Frame f;
            const Step s = r.next(f);
            const bool accepted = s == Step::Frame;
            const bool refused_right = s == Step::Error &&
                                       r.error() == FrameError::NotAllowedInPacket &&
                                       transport_error_of(r.error()) ==
                                           TransportError::ProtocolViolation;
            if (expected ? !accepted : !refused_right) {
                std::fprintf(stderr, "FAIL: frame %.2s in packet %c: %s\n", row.hex,
                             "IH01"[k], expected ? "refused" : "accepted");
                ++failures;
            }
        }
    }
}

/// \~english One payload, one expected error, and the code it closes with.
/// \~spanish Una carga, un error esperado, y el codigo con el que cierra.  \~
void expect_error(const uint8_t *p, size_t n, FrameContext ctx, FrameError want,
                  TransportError code, const char *what) {
    FrameReader r(p, n, ctx);
    Frame f;
    Step s = r.next(f);
    while (s == Step::Frame) s = r.next(f);
    const bool ok = s == Step::Error && r.error() == want &&
                    transport_error_of(want) == code && r.next(f) == Step::Error;
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s: got %s\n", what,
                     s == Step::Error ? frame_error_name(r.error()) : "no error");
        ++failures;
    }
}

void expect_error_hex(const char *hex, FrameContext ctx, FrameError want,
                      TransportError code, const char *what) {
    uint8_t b[128];
    expect_error(b, from_hex(hex, b, sizeof b), ctx, want, code, what);
}

/// \~english Each rule, and the value right at its edge that must still pass.
/// \~spanish Cada regla, y el valor justo en su borde que tiene que seguir pasando.  \~
void test_each_rule() {
    const FrameContext one = ctx_of(PacketType::OneRtt, false);
    const FrameContext server = ctx_of(PacketType::OneRtt, true);
    const TransportError enc = TransportError::FrameEncodingError;
    const TransportError proto = TransportError::ProtocolViolation;
    uint8_t b[64] = {};
    Frame f;

    expect_error(b, 0, one, FrameError::EmptyPacket, proto, "an empty payload");
    expect_error_hex("1f", one, FrameError::UnknownType, enc, "type 0x1f");
    expect_error_hex("30", one, FrameError::UnknownType, enc, "DATAGRAM, not negotiated");
    expect_error_hex("4001", one, FrameError::TypeNotShortest, proto, "PING in two bytes");
    expect_error_hex("0800", ctx_of(PacketType::Initial, true), FrameError::NotAllowedInPacket,
                     proto, "STREAM in an Initial");
    expect_error_hex("1e", server, FrameError::OnlyFromServer, proto,
                     "HANDSHAKE_DONE sent to a server");
    expect_error_hex("0701aa", server, FrameError::OnlyFromServer, proto,
                     "NEW_TOKEN sent to a server");
    expect_error_hex("0700", one, FrameError::EmptyToken, enc, "an empty NEW_TOKEN");

    // \~english ACK: a first range past zero, a gap past zero, a range past zero.
    // \~spanish ACK: un primer rango pasado de cero, un hueco pasado de cero, un rango pasado de cero.  \~
    expect_error_hex("0205000006", one, FrameError::AckRangeBelowZero, enc, "first range 6 of 5");
    check(read_one(b, from_hex("0205000005", b, sizeof b), f), "first range 5 of 5 refused");
    expect_error_hex("02050001000400", one, FrameError::AckRangeBelowZero, enc,
                     "a gap below zero");
    check(read_one(b, from_hex("02050001000300", b, sizeof b), f),
          "a gap reaching packet 0 exactly refused");
    expect_error_hex("020a0001000009", one, FrameError::AckRangeBelowZero, enc,
                     "a range below zero");
    check(read_one(b, from_hex("020a0001000008", b, sizeof b), f),
          "a range reaching packet 0 exactly refused");

    // \~english 2^62 - 1: offset plus length may reach it, not pass it.
    // \~spanish 2^62 - 1: desplazamiento mas longitud pueden llegar, no pasarse.  \~
    size_t n = 0;
    b[n++] = 0x0e;  // \~english STREAM with OFF and LEN  \~spanish STREAM con OFF y LEN  \~
    b[n++] = 0x00;
    n += encode_varint(b + n, sizeof b - n, kMaxOffset - 1);
    b[n++] = 0x01;
    b[n++] = 0xaa;
    check(read_one(b, n, f) && f.offset + f.data.len == kMaxOffset,
          "a STREAM ending exactly at 2^62 - 1 refused");
    n = 0;
    b[n++] = 0x0e;
    b[n++] = 0x00;
    n += encode_varint(b + n, sizeof b - n, kMaxOffset);
    b[n++] = 0x01;
    b[n++] = 0xaa;
    expect_error(b, n, one, FrameError::BeyondMaxOffset, enc, "a STREAM past 2^62 - 1");
    n = 0;
    b[n++] = 0x06;
    n += encode_varint(b + n, sizeof b - n, kMaxOffset);
    b[n++] = 0x01;
    b[n++] = 0xaa;
    expect_error(b, n, one, FrameError::BeyondMaxOffset, enc, "a CRYPTO past 2^62 - 1");

    n = 0;
    b[n++] = 0x12;
    n += encode_varint(b + n, sizeof b - n, kMaxStreams + 1);
    expect_error(b, n, one, FrameError::BeyondMaxStreams, enc, "MAX_STREAMS past 2^60");
    b[0] = 0x17;
    expect_error(b, n, one, FrameError::BeyondMaxStreams, enc, "STREAMS_BLOCKED past 2^60");

    expect_error_hex("18000000", one, FrameError::BadConnectionIdLength, enc,
                     "a connection ID of zero bytes");
    expect_error_hex("18000015", one, FrameError::BadConnectionIdLength, enc,
                     "a connection ID of 21 bytes");
    expect_error_hex("18010201aa00000000000000000000000000000000", one,
                     FrameError::RetireAboveSequence, enc, "retire prior to 2 of sequence 1");

    /* \~english
     * Every strict prefix of a frame with explicit lengths is truncated -- not
     * a shorter valid frame, not an unknown type, and never a read past the end.
     * \~spanish
     * Cualquier prefijo estricto de una trama con longitudes explicitas esta
     * truncado -- no una trama valida mas corta, no un tipo desconocido, y nunca
     * una lectura pasado el final.
     * \~ */
    const char *whole[] = {
        "03400a00000102030405",       // \~english ACK with ECN, a two-byte largest  \~spanish ACK con ECN  \~
        "02040001000000",             // \~english ACK with one range  \~spanish ACK con un rango  \~
        "04010203", "050102", "060003616263", "0702aabb", "0f0102026162",
        "104000", "110102", "1201", "1401", "150102", "1601",
        "180100084142434445464748000102030405060708090a0b0c0d0e0f",
        "1901", "1a0102030405060708", "1b0102030405060708",
        "1c0a080362796500",           // \~english close with a reason  \~spanish cierre con motivo  \~
        "1d010161",
    };
    for (const char *hex : whole) {
        uint8_t w[64];
        const size_t len = from_hex(hex, w, sizeof w);
        // \~english The whole frame reads; its length is what gets cut below.
        // \~spanish La trama entera se lee; su longitud es lo que se corta abajo.  \~
        FrameReader all(w, len, one);
        Frame g;
        if (all.next(g) != Step::Frame) {
            std::fprintf(stderr, "FAIL: the whole frame %s did not read\n", hex);
            ++failures;
            continue;
        }
        const size_t frame_len = g.at.len;
        for (size_t cut = 1; cut < frame_len; ++cut) {
            FrameReader r(w, cut, one);
            Frame h;
            if (r.next(h) != Step::Error || r.error() != FrameError::Truncated) {
                std::fprintf(stderr, "FAIL: %s cut at %zu was not truncated\n", hex, cut);
                ++failures;
                break;
            }
        }
    }

    // \~english Where it broke, and which frame did: what CONNECTION_CLOSE sends back.
    // \~spanish Donde se rompio, y que trama lo hizo: lo que devuelve CONNECTION_CLOSE.  \~
    FrameReader r(b, from_hex("0101180100000000", b, sizeof b), one);
    Step s = r.next(f);
    s = r.next(f);
    s = r.next(f);
    check(s == Step::Error && r.error() == FrameError::BadConnectionIdLength &&
              r.error_frame_type() == 0x18 && r.error_at() == 2,
          "the error did not say which frame, and where");
}

/**
 * @brief
 * \~english Noise: whatever is accepted tiles the payload, and every span lies inside it.
 * \~spanish Ruido: lo que se acepta cubre la carga, y todos los trozos caen dentro.
 * \~
 */
void test_noise() {
    std::mt19937 rng(9000);
    const PacketType packets[4] = {PacketType::Initial, PacketType::Handshake,
                                   PacketType::ZeroRtt, PacketType::OneRtt};
    uint8_t p[256];

    for (int round = 0; round < 200000; ++round) {
        const size_t n = rng() % sizeof p;
        for (size_t i = 0; i < n; ++i) {
            // \~english Small values mostly, so that frames look like frames.
            // \~spanish Valores pequenos casi siempre, para que las tramas parezcan tramas.  \~
            p[i] = static_cast<uint8_t>((rng() & 3) != 0 ? rng() % 0x20 : rng());
        }
        FrameReader r(p, n, ctx_of(packets[rng() % 4], (rng() & 1) != 0));
        Frame f;
        size_t covered = 0;
        Step s;
        while ((s = r.next(f)) == Step::Frame) {
            const bool inside =
                f.at.off == covered && f.at.len >= 1 && f.at.off + f.at.len <= n &&
                f.data.off + f.data.len <= n && f.ranges.off + f.ranges.len <= n &&
                f.reset_token.off + f.reset_token.len <= n;
            if (!inside) {
                std::fprintf(stderr, "FAIL: a %s frame at %u of a %zu-byte payload points outside\n",
                             frame_type_name(f.type), f.at.off, n);
                ++failures;
                return;
            }
            covered += f.at.len;
            if (f.type == FrameType::Ack) {
                AckRangeReader ar(p, f);
                AckRange a;
                uint64_t below = UINT64_MAX;
                uint64_t count = 0;
                while (ar.next(a)) {
                    if (a.smallest > a.largest || (count > 0 && a.largest + 2 > below)) {
                        check(false, "an accepted ACK gave ranges out of order");
                        return;
                    }
                    below = a.smallest;
                    ++count;
                }
                if (count != f.range_count + 1) {
                    check(false, "an accepted ACK gave the wrong number of ranges");
                    return;
                }
            }
        }
        if (s == Step::End && covered != n) {
            std::fprintf(stderr, "FAIL: the frames of a %zu-byte payload covered %zu\n", n, covered);
            ++failures;
            return;
        }
    }
}

} // namespace

int main() {
    test_the_rfc_client_payload();
    test_the_rfc_server_payload();
    test_round_trips();
    test_ack_ranges();
    test_which_packets_carry_which_frames();
    test_each_rule();
    test_noise();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic frames: OK\n");
    return 0;
}
