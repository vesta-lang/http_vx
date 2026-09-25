/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_ticket.h
 * @brief
 * \~english Session tickets: what a server seals into them, and what a client keeps (RFC 8446, 4.6.1).
 * \~spanish Tickets de sesion: lo que un servidor sella en ellos, y lo que guarda un cliente (RFC 8446, 4.6.1).
 * \~
 *
 * \~english
 * **The server keeps nothing.**  A ticket is "a self-encrypted and
 * self-authenticated value" (4.6.1): everything resuming needs -- the suite,
 * when it was issued, for how long, its ticket_age_add, the PSK, the
 * protocol -- sealed with the provider's AEAD under a key only the server
 * has.  A ticket that does not open was not ours, or was changed, and is
 * ignored as an unknown PSK should be (4.2.11): the handshake just goes on
 * in full.  One key seals every ticket with a fresh random nonce; rotating
 * it is the owner's business, and a ticket sealed with a retired key simply
 * stops opening.
 *
 * **The client keeps what it needs to offer it**: the ticket as an opaque
 * identity, the PSK it derived, and what the RFC says to check before using
 * it -- its age against its lifetime, its hash, the host name.  A kept
 * ticket holds a secret: its owner wipes it when done.
 *
 * \~spanish
 * **El servidor no guarda nada.**  Un ticket es "un valor autocifrado y
 * autoautenticado" (4.6.1): todo lo que necesita reanudar -- el algoritmo,
 * cuando se emitio, por cuanto tiempo, su ticket_age_add, la PSK, el protocolo
 * -- sellado con el AEAD del proveedor bajo una clave que solo tiene el
 * servidor.  Un ticket que no se abre no era nuestro, o se cambio, y se ignora
 * como debe ignorarse una PSK desconocida (4.2.11): el saludo sigue sin mas,
 * completo.  Una clave sella todos los tickets con un nonce aleatorio nuevo;
 * rotarla es cosa de su dueno, y un ticket sellado con una clave retirada
 * simplemente deja de abrirse.
 *
 * **El cliente guarda lo que necesita para ofrecerlo**: el ticket como
 * identidad opaca, la PSK que derivo, y lo que el RFC dice que se compruebe
 * antes de usarlo -- su edad frente a su vida, su resumen, el nombre del
 * servidor.  Un ticket guardado lleva un secreto: su dueno lo borra al acabar.
 * \~
 */
#ifndef HTTP_VX_TLS_TICKET_H
#define HTTP_VX_TLS_TICKET_H

#include "http_vx/quic_crypto.h"
#include "http_vx/tls_schedule.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

/// \~english The longest a ticket may live: seven days (4.6.1).  \~spanish Lo mas que puede vivir un ticket: siete dias (4.6.1).  \~
constexpr uint32_t kMaxTicketLifetime = 604800;

/**
 * @brief
 * \~english What a server seals into a ticket.
 * \~spanish Lo que un servidor sella en un ticket.
 * \~
 */
struct TicketContents {
    /// \~english The suite of the connection that issued it: its hash is the PSK's (4.2.11).
    /// \~spanish El algoritmo de la conexion que lo emitio: su resumen es el de la PSK (4.2.11).  \~
    uint16_t suite = 0;
    /// \~english When it was issued, on the clock the server's sessions are given, in milliseconds.
    /// \~spanish Cuando se emitio, en el reloj que se da a las sesiones del servidor, en milisegundos.  \~
    uint64_t issued_ms = 0;
    uint32_t lifetime_s = 0;
    uint32_t age_add = 0;
    uint8_t psk[kMaxHash] = {};
    uint8_t psk_len = 0;
    uint8_t alpn[255] = {};
    uint8_t alpn_len = 0;
};

/**
 * @brief
 * \~english Seals and opens a server's tickets with one key.
 * \~spanish Sella y abre los tickets de un servidor con una clave.
 * \~
 *
 * \~english
 * Prepared once and shared by every connection of the server.  A sealed
 * ticket is a twelve-byte nonce, then the sealed contents with their tag.
 * \~spanish
 * Se prepara una vez y lo comparten todas las conexiones del servidor.  Un
 * ticket sellado es un nonce de doce bytes, y luego el contenido sellado con su
 * marca.
 * \~
 */
class TicketSealer {
public:
    /// \~english The key is sixteen bytes: AES-128-GCM, which every provider has.
    /// \~spanish La clave son dieciseis bytes: AES-128-GCM, que tiene todo proveedor.  \~
    static constexpr size_t kKeySize = 16;
    /// \~english The largest sealed ticket.  \~spanish El ticket sellado mas grande.  \~
    static constexpr size_t kMaxSealed = 12 + 128 + 255 + quic::kTagSize;

    TicketSealer(quic::Crypto &c, const uint8_t *key) noexcept;
    ~TicketSealer();
    TicketSealer(const TicketSealer &) = delete;
    TicketSealer &operator=(const TicketSealer &) = delete;

    bool ready() const noexcept { return aead_ != nullptr; }

    /// \~english Seals @p t; the size, or 0 if it could not.  \~spanish Sella @p t; el tamano, o 0 si no pudo.  \~
    size_t seal(const TicketContents &t, uint8_t *out, size_t room) const noexcept;

    /**
     * @brief
     * \~english Opens a ticket; false if it is not one this key sealed, or it was changed.
     * \~spanish Abre un ticket; falso si no es uno que sello esta clave, o se cambio.
     * \~
     */
    bool open(const uint8_t *in, size_t n, TicketContents &t) const noexcept;

private:
    quic::Crypto &c_;
    void *aead_ = nullptr;
};

/**
 * @brief
 * \~english A ticket a client keeps to resume later (4.6.1).
 * \~spanish Un ticket que guarda un cliente para reanudar despues (4.6.1).
 * \~
 */
struct Ticket {
    /// \~english Larger tickets are not kept -- and counted.  \~spanish Los tickets mas grandes no se guardan -- y se cuentan.  \~
    static constexpr size_t kMaxIdentity = 1024;
    uint8_t identity[kMaxIdentity] = {};
    size_t identity_len = 0;
    uint8_t psk[kMaxHash] = {};
    /// \~english The suite of the connection it came from.  \~spanish El algoritmo de la conexion de la que vino.  \~
    uint16_t suite = 0;
    uint32_t age_add = 0;
    uint32_t lifetime_s = 0;
    /// \~english When it arrived, on the clock the client's sessions are given.
    /// \~spanish Cuando llego, en el reloj que se da a las sesiones del cliente.  \~
    uint64_t received_us = 0;
    /// \~english The host name and protocol of that connection.  \~spanish El nombre y el protocolo de aquella conexion.  \~
    uint8_t server_name[255] = {};
    uint8_t server_name_len = 0;
    uint8_t alpn[255] = {};
    uint8_t alpn_len = 0;
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_TICKET_H
