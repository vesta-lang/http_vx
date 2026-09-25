/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_transport_params.h
 * @brief
 * \~english QUIC transport parameters: what each end declares in the handshake (RFC 9000, 7.4 and 18).
 * \~spanish Los parametros de transporte de QUIC: lo que declara cada extremo en el saludo (RFC 9000, 7.4 y 18).
 * \~
 *
 * \~english
 * They travel in TLS's quic_transport_parameters extension and are
 * authenticated by the handshake.  Reading checks every rule the RFC gives
 * the values -- an integer that does not fill its length, a value out of
 * range, the same parameter twice, a server-only parameter from a client --
 * and any of them is a TRANSPORT_PARAMETER_ERROR (7.4).  Unknown ones are
 * ignored, reserved ones (31 * N + 27) included (18.1).  Checking that the
 * connection IDs match the ones the packets used (7.3) needs the packets,
 * and is the connection's.
 * \~spanish
 * Viajan en la extension quic_transport_parameters de TLS y los autentica el
 * saludo.  Leer comprueba cada regla que el RFC da a los valores -- un entero
 * que no llena su longitud, un valor fuera de rango, el mismo parametro dos
 * veces, un parametro solo de servidor mandado por un cliente --, y cualquiera
 * de ellas es un TRANSPORT_PARAMETER_ERROR (7.4).  Los desconocidos se ignoran,
 * los reservados (31 * N + 27) incluidos (18.1).  Comprobar que los
 * identificadores de conexion coinciden con los que usaron los paquetes (7.3)
 * necesita los paquetes, y es cosa de la conexion.
 * \~
 */
#ifndef HTTP_VX_QUIC_TRANSPORT_PARAMS_H
#define HTTP_VX_QUIC_TRANSPORT_PARAMS_H

#include "http_vx/quic_packet.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english A connection ID inside a transport parameter.  \~spanish Un identificador de conexion dentro de un parametro de transporte.  \~
struct TpConnectionId {
    bool present = false;
    uint8_t len = 0;
    uint8_t bytes[kMaxConnectionId] = {};
};

/// \~english The server's preferred address (18.2, Figure 22).  \~spanish La direccion preferida del servidor (18.2, figura 22).  \~
struct PreferredAddress {
    uint8_t ipv4[4] = {};
    uint16_t ipv4_port = 0;
    uint8_t ipv6[16] = {};
    uint16_t ipv6_port = 0;
    TpConnectionId cid;
    uint8_t reset_token[16] = {};
};

/**
 * @brief
 * \~english One end's transport parameters, with the RFC's defaults where absent (18.2).
 * \~spanish Los parametros de transporte de un extremo, con los valores por defecto del RFC donde faltan (18.2).
 * \~
 */
struct TransportParams {
    TpConnectionId original_destination_connection_id;
    uint64_t max_idle_timeout_ms = 0;
    bool has_stateless_reset_token = false;
    uint8_t stateless_reset_token[16] = {};
    uint64_t max_udp_payload_size = 65527;
    uint64_t initial_max_data = 0;
    uint64_t initial_max_stream_data_bidi_local = 0;
    uint64_t initial_max_stream_data_bidi_remote = 0;
    uint64_t initial_max_stream_data_uni = 0;
    uint64_t initial_max_streams_bidi = 0;
    uint64_t initial_max_streams_uni = 0;
    uint64_t ack_delay_exponent = 3;
    uint64_t max_ack_delay_ms = 25;
    bool disable_active_migration = false;
    bool has_preferred_address = false;
    PreferredAddress preferred_address;
    uint64_t active_connection_id_limit = 2;
    TpConnectionId initial_source_connection_id;
    TpConnectionId retry_source_connection_id;
};

/// \~english Why a set of transport parameters was refused; every one is TRANSPORT_PARAMETER_ERROR.
/// \~spanish Por que se rechazo un conjunto de parametros de transporte; todos son TRANSPORT_PARAMETER_ERROR.  \~
enum class TpError : uint8_t {
    None,
    /// \~english The sequence or a parameter does not decode.  \~spanish La secuencia o un parametro no se decodifica.  \~
    Malformed,
    /// \~english The same parameter twice (7.4).  \~spanish El mismo parametro dos veces (7.4).  \~
    Duplicate,
    /// \~english A value the RFC calls invalid (18.2, 4.6).  \~spanish Un valor que el RFC llama invalido (18.2, 4.6).  \~
    InvalidValue,
    /// \~english A server-only parameter from a client (18.2).  \~spanish Un parametro solo de servidor enviado por un cliente (18.2).  \~
    ServerOnly,
    /// \~english initial_source_connection_id missing, or the server's original_destination_connection_id (7.3).
    /// \~spanish Falta initial_source_connection_id, o el original_destination_connection_id del servidor (7.3).  \~
    Missing,
};

/// \~english A short name for @p e.  \~spanish Un nombre corto para @p e.  \~
const char *tp_error_name(TpError e) noexcept;

/**
 * @brief
 * \~english Encodes @p tp; only what differs from its default, plus the connection IDs present.
 * \~spanish Codifica @p tp; solo lo que difiere de su valor por defecto, mas los identificadores presentes.
 * \~
 *
 * @return \~english the size, or 0 if it does not fit  \~spanish el tamano, o 0 si no cabe  \~
 */
size_t encode_transport_params(const TransportParams &tp, uint8_t *out, size_t room) noexcept;

/**
 * @brief
 * \~english Decodes a peer's transport parameters and checks every rule the values have.
 * \~spanish Decodifica los parametros de transporte del otro y comprueba cada regla que tienen los valores.
 * \~
 *
 * @param from_server \~english whether the peer is the server: it decides which parameters it may send
 *                    \~spanish si el otro es el servidor: decide que parametros puede mandar  \~
 */
TpError decode_transport_params(const uint8_t *in, size_t n, bool from_server, TransportParams &out) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_TRANSPORT_PARAMS_H
