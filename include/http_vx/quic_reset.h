/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_reset.h
 * @brief
 * \~english Stateless reset (RFC 9000, 10.3): the tokens, and the packet that carries one.
 * \~spanish Reinicio sin estado (RFC 9000, 10.3): los testigos, y el paquete que lleva uno.
 * \~
 *
 * \~english
 * A server that lost a connection's state -- it restarted, or the connection
 * lived on another machine -- can still tell the peer to stop, without any
 * state: the token for a connection ID is computed from the ID and a key only
 * the server holds (10.3.2), so the same answer comes out wherever and
 * whenever it is asked.  The connection hands the token out with each ID it
 * issues; the acceptor recomputes it for a packet nobody owns.
 *
 * The packet is random bytes shaped like a short header, ending in the token.
 * It is always smaller than the packet that caused it, so two ends that both
 * lost their state cannot keep answering each other (10.3.3).
 * \~spanish
 * Un servidor que perdio el estado de una conexion -- se reinicio, o la conexion
 * vivia en otra maquina -- puede decirle al otro extremo que pare igualmente,
 * sin estado: el testigo de un identificador de conexion se calcula a partir del
 * identificador y de una clave que solo tiene el servidor (10.3.2), asi que sale
 * la misma respuesta donde y cuando se pregunte.  La conexion entrega el testigo
 * con cada identificador que emite; el acceptor lo recalcula para un paquete que
 * no es de nadie.
 *
 * El paquete son bytes aleatorios con forma de cabecera corta, acabados en el
 * testigo.  Siempre es mas pequeno que el paquete que lo provoco, asi que dos
 * extremos que perdieron los dos su estado no pueden quedarse contestandose sin
 * fin (10.3.3).
 * \~
 */
#ifndef HTTP_VX_QUIC_RESET_H
#define HTTP_VX_QUIC_RESET_H

#include "http_vx/quic_crypto.h"
#include "http_vx/quic_frame.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english The size of the key reset tokens come from.  \~spanish El tamano de la clave de la que salen los testigos.  \~
constexpr size_t kResetKeySize = 32;

/// \~english The smallest stateless reset: five unpredictable bytes and the token (10.3).
/// \~spanish El reinicio sin estado mas pequeno: cinco bytes impredecibles y el testigo (10.3).  \~
constexpr size_t kMinStatelessReset = 5 + kResetTokenSize;

/**
 * @brief
 * \~english The stateless reset token of @p cid under @p key (10.3.2).
 * \~spanish El testigo de reinicio sin estado de @p cid con @p key (10.3.2).
 * \~
 *
 * \~english
 * HKDF-Expand with the key as its pseudorandom key and the ID in the info:
 * an HMAC keyed by a secret, as 10.3.2 asks, with a label so that the key is
 * never used for anything else by accident.
 * \~spanish
 * HKDF-Expand con la clave como clave pseudoaleatoria y el identificador en la
 * info: un HMAC con clave secreta, como pide 10.3.2, con una etiqueta para que la
 * clave no sirva por accidente para ninguna otra cosa.
 * \~
 */
bool reset_token(Crypto &c, const uint8_t *key, const uint8_t *cid, size_t cid_len,
                 uint8_t *token) noexcept;

/**
 * @brief
 * \~english Writes a stateless reset answering a datagram of @p trigger_len bytes.
 * \~spanish Escribe un reinicio sin estado en respuesta a un datagrama de @p trigger_len bytes.
 * \~
 *
 * @return \~english its size; zero when it could not be both smaller than the trigger and at least 21 bytes
 *         \~spanish su tamano; cero cuando no podia ser a la vez menor que el que lo provoca y de al menos 21 bytes  \~
 */
size_t write_stateless_reset(Crypto &c, const uint8_t *token, size_t trigger_len, uint8_t *out,
                             size_t room) noexcept;

/**
 * @brief
 * \~english Whether @p data ends in @p token: a stateless reset, whatever its header form (10.3).
 * \~spanish Si @p data acaba en @p token: un reinicio sin estado, sea cual sea la forma de su cabecera (10.3).
 * \~
 *
 * \~english Constant time in the token: the comparison must not reveal how much matched (10.3.1).
 * \~spanish Tiempo constante en el testigo: la comparacion no debe delatar cuanto coincidio (10.3.1).  \~
 */
bool is_stateless_reset(const uint8_t *data, size_t n, const uint8_t *token) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_RESET_H
