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
    /// \~english The ticket allows 0-RTT (RFC 9001, 4.6.1).  \~spanish El ticket permite 0-RTT (RFC 9001, 4.6.1).  \~
    bool early = false;
    /**
     * \~english
     * SHA-256 of the 0-RTT context when it was issued: what the layers above
     * need to be the same for early data to mean the same (RFC 9001, 4.6.3).
     * \~spanish
     * SHA-256 del contexto de 0-RTT cuando se emitio: lo que las capas de
     * encima necesitan que sea igual para que los datos tempranos signifiquen
     * lo mismo (RFC 9001, 4.6.3).
     * \~
     */
    uint8_t context[32] = {};
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
    static constexpr size_t kMaxSealed = 12 + 128 + 255 + 33 + quic::kTagSize;

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
    /// \~english The server allows 0-RTT with it (RFC 9001, 4.6.1).  \~spanish El servidor permite 0-RTT con el (RFC 9001, 4.6.1).  \~
    bool early_data = false;
    /**
     * \~english
     * The server's transport parameters on that connection, as sent: 0-RTT
     * runs on them until the handshake brings new ones (RFC 9000, 7.4.1).
     * \~spanish
     * Los parametros de transporte del servidor en aquella conexion, tal cual:
     * 0-RTT funciona con ellos hasta que el saludo traiga otros (RFC 9000,
     * 7.4.1).
     * \~
     */
    static constexpr size_t kMaxParams = 256;
    uint8_t params[kMaxParams] = {};
    size_t params_len = 0;
};

/**
 * @brief
 * \~english What decides whether a ClientHello's early data may be accepted: fresh, and never seen (RFC 8446, 8.2, 8.3).
 * \~spanish Lo que decide si se pueden aceptar los datos tempranos de un ClientHello: fresco, y nunca visto (RFC 8446, 8.2, 8.3).
 * \~
 *
 * \~english
 * TLS gives 0-RTT no replay protection of its own (8): this is the server's.
 * A ClientHello is fresh when the arrival its ticket's age predicts is
 * within `window` of now (8.3); a fresh one is remembered, by its validated
 * binder, for as long as it could still be fresh, and a second one with the
 * same binder is a replay (8.2).  Until one window has passed since the
 * guard started nothing is admitted -- a replay of something sent before it
 * started could not be told apart (8.2: SHOULD) -- and a full table admits
 * nothing either.  Every "no" only turns 0-RTT down: the handshake goes on.
 *
 * One guard for everything that can accept the same ticket: that is the
 * "at most once per server instance" of 8.  It is not safe to call from two
 * threads at once.
 * \~spanish
 * TLS no da a 0-RTT ninguna proteccion propia contra repeticiones (8): esta es
 * la del servidor.  Un ClientHello es fresco cuando la llegada que predice la
 * edad de su ticket esta a menos de `window` de ahora (8.3); uno fresco se
 * recuerda, por su binder validado, mientras aun pudiera ser fresco, y un
 * segundo con el mismo binder es una repeticion (8.2).  Hasta que pasa una
 * ventana desde que arranco el guardian no se admite nada -- una repeticion de
 * algo mandado antes de arrancar no se podria distinguir (8.2: DEBERIA) --, y
 * una tabla llena tampoco admite nada.  Cada "no" solo rechaza el 0-RTT: el
 * saludo sigue.
 *
 * Un guardian para todo lo que pueda aceptar el mismo ticket: ese es el "como
 * mucho una vez por instancia de servidor" de 8.  No se puede llamar desde dos
 * hilos a la vez.
 * \~
 */
class ReplayGuard {
public:
    /// \~english Why a ClientHello's early data was or was not admitted.  \~spanish Por que se admitieron o no los datos tempranos de un ClientHello.  \~
    enum class Verdict : uint8_t { Fresh, Replay, Stale, Warming, Full };

    /**
     * @param capacity  \~english how many ClientHellos it remembers at once  \~spanish cuantos ClientHello recuerda a la vez  \~
     * @param window_ms \~english the tolerance of 8.3, and how long each is remembered  \~spanish la tolerancia de 8.3, y cuanto se recuerda cada uno  \~
     * @param start_ms  \~english when it starts, on the sessions' clock  \~spanish cuando arranca, en el reloj de las sesiones  \~
     */
    ReplayGuard(size_t capacity, uint64_t window_ms, uint64_t start_ms) noexcept;
    ~ReplayGuard();
    ReplayGuard(const ReplayGuard &) = delete;
    ReplayGuard &operator=(const ReplayGuard &) = delete;

    bool ready() const noexcept { return slots_ != nullptr; }
    uint64_t window_ms() const noexcept { return window_ms_; }

    /**
     * @brief
     * \~english Admits a ClientHello known by @p key (16 bytes of its validated binder), expected at @p expected_ms.
     * \~spanish Admite un ClientHello conocido por @p key (16 bytes de su binder validado), esperado en @p expected_ms.
     * \~
     */
    Verdict admit(const uint8_t *key, uint64_t expected_ms, uint64_t now_ms) noexcept;

private:
    struct Slot {
        uint8_t key[16];
        uint64_t expires_ms;
        bool used;
    };
    Slot *slots_ = nullptr;
    size_t mask_ = 0;
    uint64_t window_ms_;
    uint64_t start_ms_;
};

/// \~english A short name for @p v.  \~spanish Un nombre corto para @p v.  \~
const char *verdict_name(ReplayGuard::Verdict v) noexcept;

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_TICKET_H
