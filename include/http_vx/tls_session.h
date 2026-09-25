/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_session.h
 * @brief
 * \~english The TLS 1.3 handshake as QUIC drives it: bytes in and out per encryption level, and secrets (RFC 9001, 4).
 * \~spanish El saludo de TLS 1.3 tal como lo lleva QUIC: bytes que entran y salen por nivel de cifrado, y secretos (RFC 9001, 4).
 * \~
 *
 * \~english
 * The piece that puts the others together: the messages of tls_messages.h,
 * the key schedule and transcript of tls_schedule.h, and the provider's key
 * exchange and signatures.  **What one message can show on its own was
 * checked when it was read; what this adds is every rule that needs two** --
 * the version chosen against the ones offered, a suite or a group that was
 * never offered, the same cipher suite after a HelloRetryRequest, the
 * signature against the certificate that came before it, the Finished
 * against everything before that.
 *
 * **It is QUIC's TLS, not TLS over TCP.**  No records: handshake bytes go
 * straight into CRYPTO frames, one flow per encryption level (RFC 9001,
 * 4.1.3).  No middlebox compatibility mode, so the session ID is empty and a
 * server treats a non-empty one as PROTOCOL_VIOLATION (RFC 9001, 8.4).  ALPN
 * is required (8.1) and so is quic_transport_parameters (8.2), which travel
 * as bytes: reading them is the connection's.  No KeyUpdate (6), no
 * EndOfEarlyData (8.3), no post-handshake client authentication (4.4).
 *
 * **Secrets are handed out as they exist, both directions of a level
 * together.**  The server has both 1-RTT secrets once it writes its
 * Finished, and may send with them then; that it MUST NOT open 1-RTT packets
 * before the handshake is complete (RFC 9001, 5.7) is a rule about opening
 * packets, and the connection -- which opens them -- is where it is kept.
 *
 * **A failure says what and why.**  Every refusal leaves the QUIC error code
 * -- 0x0100 plus the alert (RFC 9001, 4.8), or a transport error where RFC
 * 9001 names one -- and a sentence saying which rule was broken.
 *
 * **Resumption is PSK with (EC)DHE, and nothing else** (4.2.9): a resumed
 * connection keeps forward secrecy.  The server's tickets are sealed with a
 * key only it has (tls_ticket.h), so it keeps no state for them; the client
 * keeps what it received, for its owner to take and use once (C.4).
 *
 * What this does not do yet: 0-RTT, and deciding whether to trust the
 * server's certificate -- the chain is kept for whoever does.
 *
 * \~spanish
 * La pieza que junta las demas: los mensajes de tls_messages.h, el calendario
 * de claves y la transcripcion de tls_schedule.h, y el intercambio de claves y
 * las firmas del proveedor.  **Lo que un mensaje puede ensenar por si solo se
 * comprobo al leerlo; lo que anade esto es cada regla que necesita dos** -- la
 * version elegida frente a las ofrecidas, un algoritmo o un grupo que nunca se
 * ofrecio, el mismo algoritmo tras un HelloRetryRequest, la firma frente al
 * certificado que vino antes, el Finished frente a todo lo anterior.
 *
 * **Es el TLS de QUIC, no TLS sobre TCP.**  Sin registros: los bytes del saludo
 * van directos a tramas CRYPTO, un flujo por nivel de cifrado (RFC 9001,
 * 4.1.3).  Sin modo de compatibilidad con cajas intermedias, asi que el
 * identificador de sesion va vacio y un servidor trata uno que no lo este como
 * PROTOCOL_VIOLATION (RFC 9001, 8.4).  ALPN es obligatorio (8.1) y
 * quic_transport_parameters tambien (8.2), que viajan como bytes: leerlos es
 * cosa de la conexion.  Sin KeyUpdate (6), sin EndOfEarlyData (8.3), sin
 * autenticacion del cliente tras el saludo (4.4).
 *
 * **Los secretos se entregan en cuanto existen, las dos direcciones de un nivel
 * juntas.**  El servidor tiene los dos secretos 1-RTT cuando escribe su
 * Finished, y puede mandar con ellos desde entonces; que NO DEBA abrir paquetes
 * 1-RTT antes de que el saludo este completo (RFC 9001, 5.7) es una regla sobre
 * abrir paquetes, y se guarda en la conexion, que es quien los abre.
 *
 * **Un fallo dice que y por que.**  Cada rechazo deja el codigo de error de
 * QUIC -- 0x0100 mas la alerta (RFC 9001, 4.8), o un error de transporte donde
 * el RFC 9001 nombra uno -- y una frase que dice que regla se rompio.
 *
 * **Reanudar es PSK con (EC)DHE, y nada mas** (4.2.9): una conexion reanudada
 * conserva el secreto hacia adelante.  Los tickets del servidor van sellados con
 * una clave que solo tiene el (tls_ticket.h), asi que no guarda estado por
 * ellos; el cliente guarda lo que recibio, para que su dueno lo tome y lo use
 * una vez (C.4).
 *
 * Lo que esto aun no hace: 0-RTT, y decidir si fiarse del certificado del
 * servidor -- la cadena se guarda para quien lo haga.
 * \~
 */
#ifndef HTTP_VX_TLS_SESSION_H
#define HTTP_VX_TLS_SESSION_H

#include "http_vx/quic_crypto.h"
#include "http_vx/quic_recovery.h"
#include "http_vx/tls_messages.h"
#include "http_vx/tls_schedule.h"
#include "http_vx/tls_ticket.h"

#include <cstddef>
#include <cstdint>
#include <new>

namespace http_vx {
namespace tls {

using quic::Aead;
using quic::Group;
using quic::Scheme;
using quic::Space;

/**
 * @brief
 * \~english What one end brings to the handshake.  The pointers are the caller's and outlive the session.
 * \~spanish Lo que trae un extremo al saludo.  Los punteros son de quien llama y viven mas que la sesion.
 * \~
 */
struct SessionConfig {
    bool server = false;

    /// \~english Application protocols: offered (client) or accepted, most preferred first (server).
    /// \~spanish Protocolos de aplicacion: ofrecidos (cliente) o aceptados, el preferido primero (servidor).  \~
    const char *const *alpn = nullptr;
    size_t alpn_count = 0;

    /// \~english This end's transport parameters, already encoded.  \~spanish Los parametros de transporte de este extremo, ya codificados.  \~
    const uint8_t *transport_params = nullptr;
    size_t transport_params_len = 0;

    /// \~english Suites and groups, most preferred first; null means all the provider supports.
    /// \~spanish Algoritmos y grupos, el preferido primero; nulo es todos los que soporta el proveedor.  \~
    const Aead *suites = nullptr;
    size_t suite_count = 0;
    const Group *groups = nullptr;
    size_t group_count = 0;

    /// \~english Client: the host name to send, or null for none.  \~spanish Cliente: el nombre a mandar, o nulo para ninguno.  \~
    const char *server_name = nullptr;
    /// \~english Client: how many key shares the first ClientHello carries; 0 asks the server to choose.
    /// \~spanish Cliente: cuantas claves lleva el primer ClientHello; 0 pide al servidor que elija.  \~
    size_t key_shares = 1;

    /// \~english Server: its chain, end-entity certificate first (DER).  \~spanish Servidor: su cadena, el certificado final primero (DER).  \~
    const uint8_t *const *certificates = nullptr;
    const size_t *certificate_lens = nullptr;
    size_t certificate_count = 0;
    /// \~english Server: the provider's signing key for the first certificate, and its scheme.
    /// \~spanish Servidor: la clave de firma del proveedor para el primer certificado, y su esquema.  \~
    void *signing_key = nullptr;
    Scheme scheme = Scheme::EcdsaSecp256r1Sha256;
    /**
     * \~english
     * Server: ask the client for a certificate (4.3.2).  A client with none
     * answers with an empty one, and the handshake goes on unauthenticated
     * (4.4.2.4 lets the server choose); one that sends a chain has its
     * CertificateVerify checked, and the chain is kept like a server's.
     * \~spanish
     * Servidor: pedir al cliente un certificado (4.3.2).  Un cliente sin ninguno
     * responde con uno vacio, y el saludo sigue sin autenticarlo (4.4.2.4 deja
     * elegir al servidor); uno que manda una cadena ve comprobado su
     * CertificateVerify, y la cadena se guarda como la de un servidor.
     * \~
     */
    bool request_certificate = false;

    /* \~english
     * Resumption (4.6.1, 4.2.11).  A server with a sealer issues
     * `tickets_to_issue` tickets once the handshake is complete -- new ones
     * on every connection, so a client never has to reuse one (C.4) -- and
     * accepts them back.  A client given `resume` offers it, if it is still
     * alive and for the same host name; the ticket is the caller's, used
     * once.  Only PSK with (EC)DHE is offered or accepted: resuming keeps
     * forward secrecy.
     * \~spanish
     * Reanudacion (4.6.1, 4.2.11).  Un servidor con un sellador emite
     * `tickets_to_issue` tickets cuando el saludo esta completo -- nuevos en
     * cada conexion, para que un cliente nunca tenga que reutilizar uno (C.4) --
     * y los acepta de vuelta.  Un cliente al que se le da `resume` lo ofrece, si
     * sigue vivo y es para el mismo nombre de servidor; el ticket es de quien
     * llama, y se usa una vez.  Solo se ofrece o acepta PSK con (EC)DHE:
     * reanudar conserva el secreto hacia adelante.
     * \~ */
    const TicketSealer *tickets = nullptr;
    size_t tickets_to_issue = 2;
    uint32_t ticket_lifetime_s = 86400;
    const Ticket *resume = nullptr;
};

/**
 * @brief
 * \~english Why a handshake ended: the QUIC error code and the rule, in words.
 * \~spanish Por que acabo un saludo: el codigo de error de QUIC y la regla, en palabras.
 * \~
 */
struct SessionFailure {
    /// \~english 0x0100 + alert, or a QUIC transport error; 0 while nothing failed.
    /// \~spanish 0x0100 + alerta, o un error de transporte de QUIC; 0 mientras nada fallo.  \~
    uint64_t code = 0;
    /// \~english The alert, when it was one.  \~spanish La alerta, cuando lo fue.  \~
    Alert alert = Alert::None;
    const char *why = nullptr;
};

/// \~english QUIC's own error codes a handshake can end with (RFC 9000, 20.1).
/// \~spanish Los codigos de error propios de QUIC con los que puede acabar un saludo (RFC 9000, 20.1).  \~
constexpr uint64_t kProtocolViolation = 0x0a;
constexpr uint64_t kCryptoBufferExceeded = 0x0d;
/// \~english Where the alerts start (RFC 9001, 4.8).  \~spanish Donde empiezan las alertas (RFC 9001, 4.8).  \~
constexpr uint64_t kCryptoError = 0x0100;

/**
 * @brief
 * \~english One end of a TLS 1.3 handshake carried by QUIC.
 * \~spanish Un extremo de un saludo TLS 1.3 llevado por QUIC.
 * \~
 *
 * \~english
 * The client calls start() for its ClientHello; after that, both ends are
 * driven the same way: CRYPTO bytes that arrived in order go to receive() at
 * the level they came in, and what output() holds goes out at its level.
 * Only reading() takes bytes: a flow that is ahead is kept by the connection
 * until TLS gets there (RFC 9001, 4.1.3).
 * \~spanish
 * El cliente llama a start() para su ClientHello; despues los dos extremos se
 * llevan igual: los bytes CRYPTO que llegaron en orden van a receive() en el
 * nivel en que vinieron, y lo que tenga output() sale en su nivel.  Solo
 * reading() toma bytes: un flujo que va por delante lo guarda la conexion hasta
 * que TLS llegue alli (RFC 9001, 4.1.3).
 * \~
 */
class Session {
public:
    /// \~english The most a level holds unread, and the largest message: more is CRYPTO_BUFFER_EXCEEDED.
    /// \~spanish Lo maximo que guarda un nivel sin leer, y el mensaje mas grande: mas es CRYPTO_BUFFER_EXCEEDED.  \~
    static constexpr size_t kMaxInput = Transcript::kMaxSize;

    Session(Crypto &c, const SessionConfig &cfg) noexcept;
    ~Session();
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    /// \~english Client: writes the ClientHello.  A server has nothing to start; true.
    /// \~spanish Cliente: escribe el ClientHello.  Un servidor no tiene nada que empezar; cierto.  \~
    bool start() noexcept;

    /**
     * @brief
     * \~english Takes handshake bytes that arrived in order at level @p s; false once the handshake failed.
     * \~spanish Toma bytes del saludo que llegaron en orden en el nivel @p s; falso cuando el saludo fallo.
     * \~
     */
    bool receive(Space s, const uint8_t *data, size_t n) noexcept;

    /// \~english The level TLS reads at now.  \~spanish El nivel en el que lee TLS ahora.  \~
    Space reading() const noexcept { return reading_; }

    /// \~english The bytes waiting to go out at @p s.  \~spanish Los bytes que esperan salir en @p s.  \~
    const uint8_t *output(Space s, size_t &n) const noexcept;
    /// \~english @p n of them handed to the connection.  \~spanish @p n de ellos entregados a la conexion.  \~
    void sent(Space s, size_t n) noexcept;

    /* \~english
     * Secrets, `secret_size()` bytes; null until the level's keys may be used
     * in that direction.  Initial has none here: its secrets come from the
     * connection ID (RFC 9001, 5.2).
     * \~spanish
     * Secretos, `secret_size()` bytes; nulo hasta que las claves del nivel se
     * puedan usar en esa direccion.  Initial no tiene aqui: sus secretos salen del
     * identificador de conexion (RFC 9001, 5.2).
     * \~ */
    const uint8_t *read_secret(Space s) const noexcept;
    const uint8_t *write_secret(Space s) const noexcept;
    Aead aead() const noexcept { return aead_; }
    size_t secret_size() const noexcept { return hash_size(quic::hash_of(aead_)); }

    /// \~english Own Finished sent and the peer's verified (RFC 9001, 4.1.1).
    /// \~spanish Finished propio enviado y el del otro verificado (RFC 9001, 4.1.1).  \~
    bool complete() const noexcept { return complete_; }
    bool failed() const noexcept { return failure_.code != 0; }
    const SessionFailure &failure() const noexcept { return failure_; }

    /// \~english The peer's quic_transport_parameters, as sent; null before they came.
    /// \~spanish Los quic_transport_parameters del otro, tal cual; nulo antes de que lleguen.  \~
    const uint8_t *peer_transport_params(size_t &n) const noexcept;
    /// \~english The protocol ALPN settled on; null before.  \~spanish El protocolo en que se quedo ALPN; nulo antes.  \~
    const uint8_t *alpn(size_t &n) const noexcept;
    /// \~english Server: the host name the client asked for; null if none.  \~spanish Servidor: el nombre que pidio el cliente; nulo si ninguno.  \~
    const uint8_t *server_name(size_t &n) const noexcept;
    /// \~english The peer's certificate @p i (DER), end-entity first; false past the last, or with none.
    /// \~spanish El certificado @p i del otro (DER), el final primero; falso pasado el ultimo, o sin ninguno.  \~
    bool peer_certificate(size_t i, const uint8_t *&cert, size_t &n) const noexcept;

    /// \~english Whether a HelloRetryRequest was part of it.  \~spanish Si hubo un HelloRetryRequest.  \~
    bool retried() const noexcept { return retried_; }
    /// \~english The key exchange group, by its TLS number; 0 before one was chosen.
    /// \~spanish El grupo del intercambio de claves, por su numero de TLS; 0 antes de elegirlo.  \~
    uint16_t group() const noexcept { return group_; }
    /**
     * @brief
     * \~english The time now, for tickets: when one is issued, how old one is (4.6.1, 4.2.11.1).
     * \~spanish La hora de ahora, para los tickets: cuando se emite uno, que edad tiene (4.6.1, 4.2.11.1).
     * \~
     *
     * \~english
     * The same clock for every session of an end -- and, for a server, one
     * that keeps meaning the same as long as its ticket key does.
     * \~spanish
     * El mismo reloj para todas las sesiones de un extremo -- y, en un servidor,
     * uno que siga significando lo mismo mientras dure su clave de tickets.
     * \~
     */
    void set_clock(uint64_t now_us) noexcept { clock_us_ = now_us; }

    /// \~english The handshake resumed a session: a PSK, no certificate.  \~spanish El saludo reanudo una sesion: una PSK, sin certificado.  \~
    bool resumed() const noexcept { return resumed_; }

    /// \~english Client: tickets received and kept, and those that could not be kept.
    /// \~spanish Cliente: tickets recibidos y guardados, y los que no se pudieron guardar.  \~
    size_t tickets() const noexcept { return kept_count_; }
    size_t tickets_dropped() const noexcept { return tickets_dropped_; }
    /// \~english Client: hands over the oldest ticket kept, and forgets it here.  \~spanish Cliente: entrega el ticket guardado mas antiguo, y lo olvida aqui.  \~
    bool take_ticket(Ticket &out) noexcept;
    /// \~english Server: tickets issued.  \~spanish Servidor: tickets emitidos.  \~
    size_t tickets_issued() const noexcept { return tickets_issued_; }

private:
    enum class State : uint8_t {
        Start,
        WaitClientHello,
        WaitSecondClientHello,
        WaitServerHello,
        WaitEncryptedExtensions,
        WaitCertificate,
        WaitCertificateVerify,
        WaitFinished,
        Connected,
        Failed,
    };

    /// \~english A growing byte buffer, wiped when it is freed.  \~spanish Un buffer de bytes que crece, borrado al liberarlo.  \~
    struct Bytes {
        uint8_t *p = nullptr;
        size_t len = 0;
        size_t cap = 0;
    };

    /// \~english A span of the transcript: messages move while they are read, the transcript does not.
    /// \~spanish Un tramo de la transcripcion: los mensajes se mueven mientras se leen, la transcripcion no.  \~
    struct Kept {
        bool present = false;
        size_t at = 0;
        size_t len = 0;
    };

    bool fail(Alert a, const char *why) noexcept;
    bool fail_quic(uint64_t code, const char *why) noexcept;
    bool fail_provider(const char *why) noexcept { return fail(Alert::InternalError, why); }

    bool handle(Handshake type, const uint8_t *m, size_t n) noexcept;

    bool client_hello() noexcept;
    bool on_client_hello(const uint8_t *m, size_t n) noexcept;
    bool on_server_hello(const uint8_t *m, size_t n) noexcept;
    bool on_retry(const uint8_t *m, size_t n, const ServerHello &sh) noexcept;
    bool on_encrypted_extensions(const uint8_t *m, size_t n) noexcept;
    bool on_certificate_request(const uint8_t *m, size_t n) noexcept;
    bool on_certificate(const uint8_t *m, size_t n) noexcept;
    bool on_certificate_verify(const uint8_t *m, size_t n) noexcept;
    bool on_finished(const uint8_t *m, size_t n) noexcept;
    bool on_new_session_ticket(const uint8_t *m, size_t n) noexcept;

    bool server_flight(const uint8_t *m, const ClientHello &ch, size_t share_at, size_t share_len) noexcept;
    bool hello_retry(const ClientHello &ch) noexcept;
    bool server_certificate() noexcept;
    bool client_finished() noexcept;

    bool choose_suite(const uint8_t *m, Span offered, uint16_t &suite) const noexcept;
    bool choose_alpn(const uint8_t *m, Span offered) noexcept;
    static void keep(size_t msg_at, Span s, Kept &k) noexcept;
    bool add(const uint8_t *m, size_t n) noexcept;
    bool begin(Space s, size_t need, Writer &w) noexcept;
    /// \~english @p in_transcript: false for what comes after the handshake (4.4.1).
    /// \~spanish @p in_transcript: falso para lo que viene tras el saludo (4.4.1).  \~
    bool commit(Space s, Writer &w, bool in_transcript = true) noexcept;
    bool binder(const uint8_t *psk, Hash h, const uint8_t *partial, size_t partial_len, uint8_t *out) noexcept;
    bool resume_usable() const noexcept;
    bool accept_psk(const uint8_t *m, const ClientHello &ch, bool check_binder, uint16_t &suite) noexcept;
    bool issue_tickets() noexcept;
    bool set_suite(uint16_t suite) noexcept;
    bool derive_handshake(const uint8_t *shared, size_t shared_len) noexcept;
    bool finished_for(bool client_side, uint8_t *out) noexcept;
    void forget_shares() noexcept;

    Crypto &c_;
    SessionConfig cfg_;
    State state_ = State::Start;
    Space reading_ = Space::Initial;
    SessionFailure failure_;

    /* \~english What this end can do, filtered by what the provider supports.
     * \~spanish Lo que puede hacer este extremo, filtrado por lo que soporta el proveedor.  \~ */
    uint16_t suites_[3] = {};
    size_t suite_count_ = 0;
    uint16_t groups_[2] = {};
    size_t group_count_ = 0;

    Transcript transcript_;
    alignas(KeySchedule) unsigned char schedule_[sizeof(KeySchedule)];
    bool has_schedule_ = false;
    KeySchedule &schedule() noexcept { return *reinterpret_cast<KeySchedule *>(schedule_); }

    uint16_t suite_ = 0;
    Aead aead_ = Aead::Aes128Gcm;
    Hash hash_ = Hash::Sha256;
    uint16_t group_ = 0;
    bool retried_ = false;

    /* \~english Own key shares: the client offers up to two, a server makes one.
     * \~spanish Claves propias: el cliente ofrece hasta dos, un servidor hace una.  \~ */
    void *shares_[2] = {nullptr, nullptr};
    uint16_t share_groups_[2] = {};
    uint8_t share_pubs_[2][quic::kMaxPublicKey] = {};
    size_t share_count_ = 0;

    uint8_t random_[32] = {};
    Kept cookie_;
    /// \~english A CertificateRequest went by: the client answers with an empty Certificate.
    /// \~spanish Paso un CertificateRequest: el cliente responde con un Certificate vacio.  \~
    bool cert_requested_ = false;

    uint8_t hs_client_[kMaxHash] = {};
    uint8_t hs_server_[kMaxHash] = {};
    uint8_t ap_client_[kMaxHash] = {};
    uint8_t ap_server_[kMaxHash] = {};
    uint8_t exporter_[kMaxHash] = {};
    uint8_t resumption_[kMaxHash] = {};
    bool has_handshake_keys_ = false;
    bool has_application_keys_ = false;
    bool complete_ = false;

    Kept peer_tp_;
    Kept alpn_;
    size_t alpn_index_ = 0;
    Kept server_name_;
    Kept certificate_;

    /* \~english Resumption: the PSK in use, whether one was offered and taken, and the tickets kept.
     * \~spanish Reanudacion: la PSK en uso, si se ofrecio y se tomo una, y los tickets guardados.  \~ */
    uint64_t clock_us_ = 0;
    uint8_t psk_[kMaxHash] = {};
    size_t psk_len_ = 0;
    bool psk_offered_ = false;
    bool resumed_ = false;
    static constexpr size_t kKeptTickets = 4;
    Ticket *kept_ = nullptr;
    size_t kept_count_ = 0;
    size_t tickets_dropped_ = 0;
    size_t tickets_issued_ = 0;

    Bytes in_[quic::kSpaces];
    Bytes out_[quic::kSpaces];
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_SESSION_H
