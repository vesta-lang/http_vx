/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_channel.h
 * @brief
 * \~english TLS 1.3 over a byte stream: the handshake of tls_session.h carried in records, and the connection after it (RFC 8446, 5 and 6).
 * \~spanish TLS 1.3 sobre un flujo de bytes: el saludo de tls_session.h llevado en registros, y la conexion despues (RFC 8446, 5 y 6).
 * \~
 *
 * \~english
 * One end of a TLS connection over TCP, client or server.  Bytes come in, and
 * what they were goes three ways: application data to a plaintext buffer for
 * whoever reads the stream, handshake and alerts to this, and whatever TLS
 * has to say back -- the handshake's flights, a KeyUpdate, an alert -- to the
 * output, already in records.
 *
 * **The session's three levels are the three kinds of record.**  Initial is
 * unprotected, Handshake is sealed with the handshake traffic keys,
 * Application with the application ones (7.3).  The session says when it
 * moves; this installs the keys of the level it moved to, one direction at a
 * time, and refuses what RFC 8446 refuses at the seams: a message that spans
 * a key change, handshake bytes interleaved with another kind of record
 * (5.1), a KeyUpdate that is not the last thing in its record (4.6.3).
 *
 * **Everything after the handshake that is TLS's is here too.**  KeyUpdate
 * both ways -- answered once however many asked while this end was silent,
 * and sent on its own before the AEAD's limit (5.5) --, close_notify, the
 * error alerts, and the change_cipher_spec of the compatibility mode (D.4):
 * dropped when it may come, refused when it may not, sent by a server whose
 * client asked for the mode with a session ID.
 *
 * **What it keeps is sized to what it does.**  The session -- transcript,
 * certificate chain, key shares -- lives on the heap only while the handshake
 * does, and a server gives it back once it is over (release_handshake).
 * After that a connection is two RecordKeys and a few flags, in place; a
 * handshake message split across records after the handshake is the only
 * other thing that ever takes memory, and only until its last piece.
 *
 * **0-RTT is not done over TCP.**  A client is never configured for it, a
 * server never accepts it, and early data a client sends anyway is skipped
 * as 4.2.10 says -- by trial decryption, or past a HelloRetryRequest by its
 * outer type -- up to kMaxEarlySkipped bytes, past which it is not early data
 * but an attack on the budget.
 *
 * \~spanish
 * Un extremo de una conexion TLS sobre TCP, cliente o servidor.  Entran bytes, y
 * lo que eran va por tres caminos: los datos de aplicacion a un buffer en claro
 * para quien lea el flujo, el saludo y las alertas a esto, y lo que TLS tenga
 * que contestar -- los vuelos del saludo, un KeyUpdate, una alerta -- a la
 * salida, ya en registros.
 *
 * **Los tres niveles de la sesion son las tres clases de registro.**  Initial va
 * sin proteger, Handshake sellado con las claves de trafico del saludo,
 * Application con las de aplicacion (7.3).  La sesion dice cuando cambia; esto
 * instala las claves del nivel al que paso, una direccion cada vez, y rechaza
 * lo que el RFC 8446 rechaza en las costuras: un mensaje que cruza un cambio de
 * clave, bytes del saludo intercalados con otra clase de registro (5.1), un
 * KeyUpdate que no es lo ultimo de su registro (4.6.3).
 *
 * **Todo lo que es de TLS despues del saludo tambien esta aqui.**  KeyUpdate en
 * los dos sentidos -- contestado una vez por muchos que se pidieran mientras
 * este extremo callaba, y mandado por su cuenta antes del limite del AEAD (5.5)
 * --, close_notify, las alertas de error, y el change_cipher_spec del modo de
 * compatibilidad (D.4): se tira cuando puede venir, se rechaza cuando no, y lo
 * manda un servidor cuyo cliente pidio el modo con un identificador de sesion.
 *
 * **Lo que guarda va a la medida de lo que hace.**  La sesion -- transcripcion,
 * cadena de certificados, claves efimeras -- vive en el monton solo mientras
 * vive el saludo, y un servidor la devuelve cuando acaba (release_handshake).
 * Despues una conexion son dos RecordKeys y unas pocas marcas, en su sitio; un
 * mensaje del saludo partido entre registros tras el saludo es lo unico que
 * vuelve a ocupar memoria, y solo hasta su ultimo trozo.
 *
 * **Sobre TCP no se hace 0-RTT.**  Un cliente nunca se configura para ello, un
 * servidor nunca lo acepta, y los datos tempranos que mande un cliente de todos
 * modos se saltan como dice 4.2.10 -- por descifrado de prueba, o tras un
 * HelloRetryRequest por su tipo exterior -- hasta kMaxEarlySkipped bytes, pasado
 * lo cual no son datos tempranos sino un ataque al presupuesto.
 * \~
 */
#ifndef HTTP_VX_TLS_CHANNEL_H
#define HTTP_VX_TLS_CHANNEL_H

#include "http_vx/buffer.h"
#include "http_vx/tls_record.h"
#include "http_vx/tls_session.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

/// \~english How a call to Channel::receive left the connection.  \~spanish Como dejo la conexion una llamada a Channel::receive.  \~
enum class ChannelStatus : uint8_t {
    /// \~english Going on; whatever is left of @c in is part of a record.  \~spanish Sigue; lo que quede de @c in es parte de un registro.  \~
    Ok,
    /// \~english The peer sent close_notify: nothing more will be read (6.1).  \~spanish El otro mando close_notify: no se leera nada mas (6.1).  \~
    Closed,
    /// \~english An alert ended it, sent or received: @c alert and @c why say which.
    /// \~spanish Una alerta la acabo, mandada o recibida: @c alert y @c why dicen cual.  \~
    Failed,
};

/**
 * @brief
 * \~english One end of a TLS 1.3 connection over a byte stream.
 * \~spanish Un extremo de una conexion TLS 1.3 sobre un flujo de bytes.
 * \~
 *
 * \~english
 * configure(), then -- a client -- start(); after that both ends are driven
 * the same way: what arrived goes to receive(), what the application wants
 * to say to send(), and what either leaves in the output goes to the peer.
 * receive() takes whole records only and leaves a partial one in @c in, so
 * the caller keeps that buffer until more arrives.  Nothing here allocates
 * per record.
 * \~spanish
 * configure(), y luego -- un cliente -- start(); despues los dos extremos se
 * llevan igual: lo que llego va a receive(), lo que la aplicacion quiere decir
 * a send(), y lo que cualquiera de los dos deje en la salida va al otro.
 * receive() toma solo registros enteros y deja uno a medias en @c in, asi que
 * quien llama se queda ese buffer hasta que llegue mas.  Aqui no se reserva
 * nada por registro.
 * \~
 */
class Channel {
public:
    /**
     * @brief
     * \~english After this many records under one key, a KeyUpdate goes first (5.5).
     * \~spanish Tras tantos registros con una clave, va antes un KeyUpdate (5.5).
     * \~
     *
     * \~english
     * 2^24 full records: below AES-GCM's 2^24.5, and ChaCha20-Poly1305's
     * sequence number would wrap long before its own limit, so one number
     * serves every suite.  A KeyUpdate costs one small record.
     * \~spanish
     * 2^24 registros llenos: por debajo de los 2^24.5 de AES-GCM, y el numero de
     * secuencia de ChaCha20-Poly1305 daria la vuelta mucho antes de su propio
     * limite, asi que un numero sirve para todos los algoritmos.  Un KeyUpdate
     * cuesta un registro pequeno.
     * \~
     */
    static constexpr uint64_t kKeyUpdateAfter = uint64_t{1} << 24;
    /**
     * @brief
     * \~english Consecutive records with nothing in them -- change_cipher_spec, empty application data -- that are taken.
     * \~spanish Registros seguidos sin nada dentro -- change_cipher_spec, datos de aplicacion vacios -- que se aceptan.
     * \~
     *
     * \~english
     * RFC 8446 allows both, and each costs its reader a record's work while
     * moving nothing: without a bound, a peer can keep a connection busy
     * forever at no cost to itself.  Past this, unexpected_message.
     * \~spanish
     * El RFC 8446 permite los dos, y cada uno le cuesta al que lee el trabajo de
     * un registro sin mover nada: sin un tope, un extremo puede tener ocupada una
     * conexion para siempre sin que le cueste nada.  Pasado esto,
     * unexpected_message.
     * \~
     */
    static constexpr uint8_t kMaxEmptyRecords = 32;
    /// \~english The most early data a server skips while it turns 0-RTT down (4.2.10).
    /// \~spanish Lo maximo de datos tempranos que salta un servidor mientras rechaza el 0-RTT (4.2.10).  \~
    static constexpr uint32_t kMaxEarlySkipped = 1u << 16;

    Channel() noexcept = default;
    ~Channel();
    Channel(const Channel &) = delete;
    Channel &operator=(const Channel &) = delete;

    /**
     * @brief
     * \~english Which provider and which configuration; forgets any connection before.
     * \~spanish Que proveedor y que configuracion; olvida cualquier conexion anterior.
     * \~
     *
     * \~english
     * @p cfg is the caller's, outlives the channel and has `over_tcp` set;
     * nothing is allocated until the handshake starts -- for a server, until
     * the first record arrives.
     * \~spanish
     * @p cfg es de quien llama, vive mas que el canal y tiene `over_tcp` puesto;
     * no se reserva nada hasta que empiece el saludo -- en un servidor, hasta que
     * llegue el primer registro.
     * \~
     */
    void configure(Crypto &c, const SessionConfig &cfg) noexcept;

    /// \~english Forgets the connection, keeping the configuration.  \~spanish Olvida la conexion, conservando la configuracion.  \~
    void reset() noexcept;

    /// \~english The clock for tickets (tls_session.h); passed on to the session.  \~spanish El reloj de los tickets (tls_session.h); se pasa a la sesion.  \~
    void set_clock(uint64_t now_us) noexcept;

    /// \~english Client: the ClientHello, into @p out.  A server has nothing to start; true.
    /// \~spanish Cliente: el ClientHello, en @p out.  Un servidor no tiene nada que empezar; cierto.  \~
    bool start(Buffer &out) noexcept;

    /**
     * @brief
     * \~english Takes every whole record in @p in: application data to @p plain, answers to @p out.
     * \~spanish Toma cada registro entero de @p in: los datos de aplicacion a @p plain, las respuestas a @p out.
     * \~
     *
     * \~english
     * What a record held is consumed from @p in; a partial record is left.
     * Application data is appended to @p plain, decrypted straight into it.
     * After Closed the rest of @p in is dropped unread (6.1); after Failed,
     * nothing more is taken.
     * \~spanish
     * Lo que tenia un registro se consume de @p in; uno a medias se deja.  Los
     * datos de aplicacion se anaden a @p plain, descifrados directamente en el.
     * Tras Closed el resto de @p in se tira sin leer (6.1); tras Failed ya no se
     * toma nada.
     * \~
     */
    ChannelStatus receive(Buffer &in, Buffer &plain, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Application data, in records of at most 2^14 bytes, into @p out; false before the handshake completed or after closing.
     * \~spanish Datos de aplicacion, en registros de 2^14 bytes como mucho, en @p out; falso antes de completar el saludo o tras cerrar.
     * \~
     */
    bool send(const uint8_t *data, size_t n, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Sends a KeyUpdate and moves this end's writing to the next generation (4.6.3).
     * \~spanish Manda un KeyUpdate y pasa la escritura de este extremo a la generacion siguiente (4.6.3).
     * \~
     * @param request \~english ask the peer to update its own keys too  \~spanish pedir al otro que actualice tambien las suyas  \~
     */
    bool key_update(bool request, Buffer &out) noexcept;

    /// \~english Sends close_notify: nothing more goes out after it (6.1).  \~spanish Manda close_notify: despues no sale nada mas (6.1).  \~
    bool close(Buffer &out) noexcept;

    /**
     * @brief
     * \~english Ends the connection with @p a, for a reason of its owner's: out of memory, shutting down.  Always false.
     * \~spanish Acaba la conexion con @p a, por una razon de su dueno: sin memoria, apagandose.  Siempre falso.
     * \~
     */
    bool abort(Alert a, const char *why, Buffer &out) noexcept { return fail(a, why, out); }

    /**
     * @brief
     * \~english Server: gives the finished handshake's memory back, keeping what the connection needs.
     * \~spanish Servidor: devuelve la memoria del saludo acabado, conservando lo que necesita la conexion.
     * \~
     *
     * \~english
     * Only once complete, and only on a server: a client's tickets are in
     * its session.  The ALPN answer survives, since a server's is its own
     * configuration's; the peer's certificate and name do not.
     * \~spanish
     * Solo cuando esta completo, y solo en un servidor: los tickets de un cliente
     * estan en su sesion.  La respuesta de ALPN sobrevive, porque la de un
     * servidor es de su propia configuracion; el certificado y el nombre del otro
     * no.
     * \~
     */
    bool release_handshake() noexcept;

    /// \~english Records per key before a KeyUpdate goes first; 0 is kKeyUpdateAfter.  \~spanish Registros por clave antes de que vaya un KeyUpdate; 0 es kKeyUpdateAfter.  \~
    void set_key_update_after(uint64_t records) noexcept { update_after_ = records != 0 ? records : kKeyUpdateAfter; }
    /// \~english Pads each protected record's inner plaintext to a multiple of @p block (5.4); 0 pads nothing.
    /// \~spanish Rellena el texto interior de cada registro protegido hasta un multiplo de @p block (5.4); 0 no rellena.  \~
    void set_padding(uint16_t block) noexcept { pad_block_ = block; }

    /// \~english Both Finished exchanged and nothing ended it.  \~spanish Los dos Finished intercambiados y nada lo acabo.  \~
    bool open() const noexcept { return state_ == State::Open; }
    bool complete() const noexcept { return complete_; }
    bool failed() const noexcept { return state_ == State::Failed; }
    bool peer_closed() const noexcept { return state_ == State::Closed; }
    /// \~english This end sent close_notify.  \~spanish Este extremo mando close_notify.  \~
    bool closed() const noexcept { return close_sent_; }
    /// \~english The alert that ended it; @c alert_received says whose.  \~spanish La alerta que la acabo; @c alert_received dice de quien.  \~
    Alert alert() const noexcept { return alert_; }
    bool alert_received() const noexcept { return alert_received_; }
    /// \~english Why it ended, in words; null while it did not.  \~spanish Por que acabo, en palabras; nulo mientras no.  \~
    const char *why() const noexcept { return why_; }
    /// \~english The protocol ALPN settled on; null for none.  \~spanish El protocolo en que se quedo ALPN; nulo si ninguno.  \~
    const uint8_t *alpn(size_t &n) const noexcept;
    /// \~english The handshake, while it is kept.  \~spanish El saludo, mientras se guarde.  \~
    const Session *session() const noexcept { return session_; }
    Session *session() noexcept { return session_; }
    const RecordKeys &read_keys() const noexcept { return read_; }
    const RecordKeys &write_keys() const noexcept { return write_; }
    RecordKeys &write_keys() noexcept { return write_; }
    RecordKeys &read_keys() noexcept { return read_; }
    uint32_t key_updates_received() const noexcept { return updates_received_; }
    uint32_t key_updates_sent() const noexcept { return updates_sent_; }
    /// \~english Bytes of early data skipped (4.2.10).  \~spanish Bytes de datos tempranos saltados (4.2.10).  \~
    uint32_t early_skipped() const noexcept { return early_skipped_; }

private:
    enum class State : uint8_t { Idle, Handshaking, Open, Closed, Failed };

    /// \~english A post-handshake message split across records.  \~spanish Un mensaje tras el saludo partido entre registros.  \~
    struct Pending {
        uint8_t *p = nullptr;
        size_t len = 0;
        size_t cap = 0;
    };

    bool fail(Alert a, const char *why, Buffer &out) noexcept;
    bool fail_session(Buffer &out) noexcept;
    bool make_session() noexcept;
    void drop_session() noexcept;
    bool emit(ContentType type, const uint8_t *p, size_t n, uint16_t version, Buffer &out) noexcept;
    bool send_alert(uint8_t level, uint8_t description, Buffer &out) noexcept;
    bool enter_write(quic::Space level, Buffer &out) noexcept;
    bool enter_read(quic::Space level, Buffer &out) noexcept;
    bool flush(Buffer &out) noexcept;
    bool check_header(const RecordHeader &h, Buffer &out) noexcept;
    bool record(const uint8_t *r, size_t total, const RecordHeader &h, Buffer &plain, Buffer &out) noexcept;
    bool protected_record(const uint8_t *r, size_t total, Buffer &plain, Buffer &out) noexcept;
    bool skip_early(size_t n, Alert refuse, Buffer &out) noexcept;
    bool on_ccs(uint8_t value, Buffer &out) noexcept;
    bool on_alert(const uint8_t *p, size_t n, Buffer &out) noexcept;
    bool on_handshake(const uint8_t *p, size_t n, Buffer &out) noexcept;
    bool after_handshake(const uint8_t *p, size_t n, Buffer &out) noexcept;
    bool post_message(const uint8_t *m, size_t n, bool last, Buffer &out) noexcept;
    bool stash(const uint8_t *p, size_t n, Buffer &out) noexcept;
    void release_pending() noexcept;

    Crypto *c_ = nullptr;
    const SessionConfig *cfg_ = nullptr;
    Session *session_ = nullptr;
    RecordKeys read_;
    RecordKeys write_;
    Pending post_;
    /// \~english A server's ALPN answer, kept past its session: it points into the configuration.
    /// \~spanish La respuesta de ALPN de un servidor, guardada mas alla de su sesion: apunta a la configuracion.  \~
    const uint8_t *alpn_ = nullptr;
    size_t alpn_len_ = 0;
    uint64_t clock_us_ = 0;
    uint64_t update_after_ = kKeyUpdateAfter;
    const char *why_ = nullptr;
    uint32_t early_skipped_ = 0;
    uint32_t updates_received_ = 0;
    uint32_t updates_sent_ = 0;
    uint16_t pad_block_ = 0;
    State state_ = State::Idle;
    quic::Space read_level_ = quic::Space::Initial;
    quic::Space write_level_ = quic::Space::Initial;
    Alert alert_ = Alert::None;
    uint8_t empty_records_ = 0;
    bool server_ = false;
    bool complete_ = false;
    bool alert_received_ = false;
    /// \~english The first ClientHello went by: change_cipher_spec may come from now on (5).
    /// \~spanish Paso el primer ClientHello: desde ahora puede venir change_cipher_spec (5).  \~
    bool hello_seen_ = false;
    bool ccs_sent_ = false;
    bool close_sent_ = false;
    /// \~english The peer asked for a KeyUpdate: one goes before the next application data (4.6.3).
    /// \~spanish El otro pidio un KeyUpdate: sale uno antes de los siguientes datos de aplicacion (4.6.3).  \~
    bool update_owed_ = false;
    /// \~english Early data offered and turned down: records that fail to open are skipped (4.2.10).
    /// \~spanish Datos tempranos ofrecidos y rechazados: los registros que no se abren se saltan (4.2.10).  \~
    bool early_skip_ = false;
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_CHANNEL_H
