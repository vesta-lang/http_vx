/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_quic.h
 * @brief
 * \~english The TLS handshake hooked to a QUIC connection: the interface of RFC 9001, 4.1.
 * \~spanish El saludo TLS enganchado a una conexion QUIC: la interfaz del RFC 9001, 4.1.
 * \~
 *
 * \~english
 * Neither side knows the other.  The connection carries CRYPTO bytes per
 * level, installs secrets, discards keys, opens 1-RTT only once confirmed and
 * sends HANDSHAKE_DONE; the session turns bytes into messages and secrets.
 * This moves between them what RFC 9001, 4.1 says moves: bytes that arrived
 * in order, to TLS at the level it reads; what TLS wrote, to the level it
 * belongs; secrets as they appear; the peer's transport parameters, to the
 * connection that checks and applies them; and on the server, completion,
 * which is confirmation (4.1.2).  A client learns confirmation from the
 * HANDSHAKE_DONE its connection reads.
 *
 * Whatever goes wrong closes the connection with its code: an alert as
 * 0x0100 + alert in a CONNECTION_CLOSE of type 0x1c (4.8), or the transport
 * error the RFC names.  Bytes left unread at a level TLS has moved past are
 * a PROTOCOL_VIOLATION (4.1.3).
 *
 * \~spanish
 * Ninguno de los dos lados conoce al otro.  La conexion lleva bytes CRYPTO por
 * nivel, instala secretos, descarta claves, abre 1-RTT solo tras confirmar y
 * manda HANDSHAKE_DONE; la sesion convierte bytes en mensajes y secretos.  Esto
 * mueve entre ellos lo que el RFC 9001, 4.1 dice que se mueve: los bytes que
 * llegaron en orden, a TLS en el nivel en que lee; lo que escribio TLS, al
 * nivel que le toca; los secretos segun aparecen; los parametros de transporte
 * del otro, a la conexion que los comprueba y aplica; y en el servidor, el
 * saludo completo, que es la confirmacion (4.1.2).  Un cliente se entera de la
 * confirmacion por el HANDSHAKE_DONE que lee su conexion.
 *
 * Cualquier cosa que salga mal cierra la conexion con su codigo: una alerta
 * como 0x0100 + alerta en un CONNECTION_CLOSE de tipo 0x1c (4.8), o el error de
 * transporte que nombra el RFC.  Bytes sin leer en un nivel que TLS ya dejo
 * atras son un PROTOCOL_VIOLATION (4.1.3).
 * \~
 */
#ifndef HTTP_VX_TLS_QUIC_H
#define HTTP_VX_TLS_QUIC_H

#include "http_vx/quic_connection.h"
#include "http_vx/tls_session.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

/**
 * @brief
 * \~english One connection's handshake: a Session driven through a Connection.
 * \~spanish El saludo de una conexion: una Session llevada a traves de una Connection.
 * \~
 *
 * \~english
 * The transport parameters are the connection's own
 * (`local_transport_params`), so a server calls `set_original_ids` on its
 * connection before this is built.  Both the connection and the session
 * configuration's pointers outlive it.  `step` is called after each datagram
 * or timer the connection handled, and before asking it for datagrams.
 * \~spanish
 * Los parametros de transporte son los de la propia conexion
 * (`local_transport_params`), asi que un servidor llama a `set_original_ids` en
 * su conexion antes de construir esto.  La conexion y los punteros de la
 * configuracion de la sesion viven mas que esto.  `step` se llama tras cada
 * datagrama o temporizador que atendio la conexion, y antes de pedirle
 * datagramas.
 * \~
 */
class QuicHandshake {
public:
    /// \~english The largest transport parameters this end sends.  \~spanish Los parametros de transporte mas grandes que manda este extremo.  \~
    static constexpr size_t kMaxTransportParams = 256;

    QuicHandshake(Crypto &c, quic::Connection &conn, const SessionConfig &cfg) noexcept;
    QuicHandshake(const QuicHandshake &) = delete;
    QuicHandshake &operator=(const QuicHandshake &) = delete;

    /// \~english Client: the ClientHello goes into the Initial CRYPTO stream.  A server: nothing to do.
    /// \~spanish Cliente: el ClientHello entra en el flujo CRYPTO de Initial.  Un servidor: nada que hacer.  \~
    bool start(uint64_t now_us) noexcept;

    /// \~english Moves everything that can move; false once the connection was closed for it.
    /// \~spanish Mueve todo lo que se pueda mover; falso una vez que la conexion se cerro por ello.  \~
    bool step(uint64_t now_us) noexcept;

    const Session &session() const noexcept { return session_; }
    /// \~english Client: a ticket the server sent, to resume a later connection with (RFC 9001, 4.5).
    /// \~spanish Cliente: un ticket que mando el servidor, para reanudar una conexion posterior (RFC 9001, 4.5).  \~
    bool take_ticket(Ticket &out) noexcept { return session_.take_ticket(out); }
    bool complete() const noexcept { return session_.complete(); }
    /// \~english Why it failed, in words; null while nothing failed.  \~spanish Por que fallo, en palabras; nulo mientras nada fallo.  \~
    const char *why() const noexcept { return why_; }

private:
    bool fail(uint64_t code, const char *why, uint64_t now_us) noexcept;
    bool feed(uint64_t now_us) noexcept;
    bool drain() noexcept;
    bool install(Space s, bool &done, uint64_t now_us) noexcept;

    quic::Connection &conn_;
    uint8_t tp_[kMaxTransportParams] = {};
    size_t tp_len_ = 0;
    SessionConfig cfg_;
    Session session_;
    bool handshake_installed_ = false;
    bool application_installed_ = false;
    bool failed_ = false;
    const char *why_ = nullptr;
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_QUIC_H
