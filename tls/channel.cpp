/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/channel.cpp
 * @brief
 * \~english TLS 1.3 over a byte stream, the writing half: keys per level, records out, alerts, KeyUpdate and closing (RFC 8446, 4.6.3, 5, 6).
 * \~spanish TLS 1.3 sobre un flujo de bytes, la mitad que escribe: claves por nivel, registros de salida, alertas, KeyUpdate y cierre (RFC 8446, 4.6.3, 5, 6).
 * \~
 */

#include "http_vx/tls_channel.h"

#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {
namespace tls {

using quic::Space;

namespace {

/// \~english AlertLevel (6): close_notify goes as a warning, every error alert as fatal.
/// \~spanish AlertLevel (6): close_notify va como aviso, toda alerta de error como fatal.  \~
constexpr uint8_t kWarning = 1;
constexpr uint8_t kFatal = 2;

} // namespace

Channel::~Channel() {
    reset();
}

void Channel::configure(Crypto &c, const SessionConfig &cfg) noexcept {
    reset();
    c_ = &c;
    cfg_ = &cfg;
    server_ = cfg.server;
}

void Channel::reset() noexcept {
    drop_session();
    read_.clear();
    write_.clear();
    release_pending();
    alpn_ = nullptr;
    alpn_len_ = 0;
    why_ = nullptr;
    early_skipped_ = 0;
    updates_received_ = 0;
    updates_sent_ = 0;
    state_ = State::Idle;
    read_level_ = Space::Initial;
    write_level_ = Space::Initial;
    alert_ = Alert::None;
    empty_records_ = 0;
    complete_ = false;
    alert_received_ = false;
    hello_seen_ = false;
    ccs_sent_ = false;
    close_sent_ = false;
    update_owed_ = false;
    early_skip_ = false;
}

void Channel::set_clock(uint64_t now_us) noexcept {
    clock_us_ = now_us;
    if (session_ != nullptr) session_->set_clock(now_us);
}

bool Channel::make_session() noexcept {
    if (session_ != nullptr) return true;
    if (c_ == nullptr || cfg_ == nullptr || !cfg_->over_tcp) return false;
    // \~english The handshake's memory, for as long as the handshake lasts.  \~spanish La memoria del saludo, mientras dure el saludo.  \~
    void *mem = util::host_alloc(sizeof(Session));
    if (mem == nullptr) return false;
    session_ = new (mem) Session(*c_, *cfg_);
    session_->set_clock(clock_us_);
    state_ = State::Handshaking;
    return true;
}

void Channel::drop_session() noexcept {
    if (session_ == nullptr) return;
    session_->~Session();
    util::host_free(session_);
    session_ = nullptr;
}

void Channel::release_pending() noexcept {
    if (post_.p == nullptr) return;
    wipe_secret(post_.p, post_.cap);
    util::host_free(post_.p);
    post_ = Pending{};
}

bool Channel::start(Buffer &out) noexcept {
    if (server_) return true;
    if (state_ != State::Idle) return fail(Alert::InternalError, "start() called twice", out);
    if (cfg_ == nullptr || !cfg_->over_tcp) {
        state_ = State::Failed;
        alert_ = Alert::InternalError;
        why_ = "the channel has no configuration for TLS over TCP";
        return false;
    }
    if (!make_session()) return fail(Alert::InternalError, "out of memory for the handshake", out);
    hello_seen_ = true;
    return session_->start() ? flush(out) : fail_session(out);
}

const uint8_t *Channel::alpn(size_t &n) const noexcept {
    if (session_ != nullptr) return session_->alpn(n);
    n = alpn_len_;
    return alpn_;
}

bool Channel::release_handshake() noexcept {
    if (!server_ || !complete_ || session_ == nullptr) return false;
    // \~english A server's answer is one of its configuration's names, which outlive this.
    // \~spanish La respuesta de un servidor es uno de los nombres de su configuracion, que viven mas que esto.  \~
    alpn_ = session_->alpn(alpn_len_);
    drop_session();
    return true;
}

bool Channel::fail(Alert a, const char *why, Buffer &out) noexcept {
    // \~english The first failure is the one said; one alert, and then nothing more (6.2).
    // \~spanish El primer fallo es el que se dice; una alerta, y despues nada mas (6.2).  \~
    if (state_ == State::Failed) return false;
    state_ = State::Failed;
    alert_ = a;
    why_ = why;
    send_alert(kFatal, static_cast<uint8_t>(a), out);
    release_pending();
    return false;
}

bool Channel::fail_session(Buffer &out) noexcept {
    const SessionFailure &f = session_->failure();
    // \~english Over TCP every session failure is an alert; one that is not would be this end's own mistake.
    // \~spanish Sobre TCP cada fallo de la sesion es una alerta; uno que no lo fuera seria un error de este extremo.  \~
    return fail(f.alert != Alert::None ? f.alert : Alert::InternalError,
                f.why != nullptr ? f.why : "the handshake failed without saying why", out);
}

bool Channel::emit(ContentType type, const uint8_t *p, size_t n, uint16_t version, Buffer &out) noexcept {
    // \~english In fragments of at most 2^14, never an empty one (5.1).  \~spanish En fragmentos de 2^14 como mucho, nunca uno vacio (5.1).  \~
    while (n != 0) {
        const size_t take = n < kMaxFragment ? n : kMaxFragment;
        size_t padding = 0;
        if (write_.installed() && pad_block_ != 0) {
            const size_t inner = take + 1;
            padding = (pad_block_ - inner % pad_block_) % pad_block_;
            if (inner + padding > kMaxInnerPlaintext) padding = kMaxInnerPlaintext - inner;
        }
        const size_t room = kRecordOverhead + take + padding;
        uint8_t *at = out.reserve(room);
        if (at == nullptr) return false;
        const size_t made = write_.installed() ? write_.seal(type, p, take, padding, at, room)
                                               : write_plaintext_record(type, version, p, take, at, room);
        if (made == 0) return false;
        out.commit(made);
        p += take;
        n -= take;
    }
    return true;
}

bool Channel::send_alert(uint8_t level, uint8_t description, Buffer &out) noexcept {
    /* \~english
     * Protected as the connection is (6): a client that failed on the
     * server's encrypted flight has handshake keys it has not written with
     * yet, and the server now reads with them, so they are put in first.
     * With keys that can seal nothing more, no alert goes: the peer sees
     * the connection close, which is all it can be told.
     * \~spanish
     * Protegida como lo este la conexion (6): un cliente que fallo con el vuelo
     * cifrado del servidor tiene claves del saludo con las que aun no escribio, y
     * el servidor ya lee con ellas, asi que se ponen antes.  Con claves que ya no
     * pueden sellar nada, no sale alerta: el otro ve cerrarse la conexion, que es
     * todo lo que se le puede decir.
     * \~ */
    if (session_ != nullptr && write_level_ == Space::Initial && session_->write_secret(Space::Handshake) != nullptr &&
        write_.install(*c_, session_->aead(), session_->write_secret(Space::Handshake)))
        write_level_ = Space::Handshake;
    if (write_.installed() && write_.exhausted()) return false;
    const uint8_t alert[2] = {level, description};
    return emit(ContentType::Alert, alert, sizeof alert, kRecordVersion, out);
}

bool Channel::enter_write(Space level, Buffer &out) noexcept {
    if (level == write_level_) return true;
    const uint8_t *secret = session_->write_secret(level);
    if (level < write_level_ || secret == nullptr)
        return fail(Alert::InternalError, "handshake output at a level whose keys this end does not have", out);
    if (!write_.install(*c_, session_->aead(), secret))
        return fail(Alert::InternalError, "the provider could not prepare the write keys", out);
    write_level_ = level;
    return true;
}

bool Channel::enter_read(Space level, Buffer &out) noexcept {
    if (level == read_level_) return true;
    const uint8_t *secret = session_->read_secret(level);
    if (level < read_level_ || secret == nullptr)
        return fail(Alert::InternalError, "the handshake moved to a level whose keys this end does not have", out);
    if (!read_.install(*c_, session_->aead(), secret))
        return fail(Alert::InternalError, "the provider could not prepare the read keys", out);
    read_level_ = level;
    return true;
}

bool Channel::flush(Buffer &out) noexcept {
    /* \~english
     * Each level's bytes in records of their own keys, in order: a message
     * never spans a key change because a level's output never shares a
     * record with the next's (5.1).
     * \~spanish
     * Los bytes de cada nivel en registros con sus propias claves, en orden: un
     * mensaje nunca cruza un cambio de clave porque la salida de un nivel nunca
     * comparte registro con la del siguiente (5.1).
     * \~ */
    static const Space kLevels[] = {Space::Initial, Space::Handshake, Space::Application};
    for (const Space level : kLevels) {
        size_t n = 0;
        const uint8_t *p = session_->output(level, n);
        if (n == 0) continue;
        if (!enter_write(level, out)) return false;
        // \~english A client's first ClientHello goes as 0x0301, a second one as 0x0303 (5.1).
        // \~spanish El primer ClientHello de un cliente va como 0x0301, uno segundo como 0x0303 (5.1).  \~
        const uint16_t version = !server_ && !session_->retried() ? kFirstHelloVersion : kRecordVersion;
        if (!emit(ContentType::Handshake, p, n, version, out))
            return fail(Alert::InternalError, "out of memory for handshake records", out);
        session_->sent(level, n);
        /* \~english
         * A client that sent a session ID asked for the compatibility mode,
         * and then the server MUST send one change_cipher_spec right after
         * its first handshake message -- ServerHello or HelloRetryRequest
         * (D.4).
         * \~spanish
         * Un cliente que mando un identificador de sesion pidio el modo de
         * compatibilidad, y entonces el servidor DEBE mandar un
         * change_cipher_spec justo tras su primer mensaje del saludo --
         * ServerHello o HelloRetryRequest (D.4).
         * \~ */
        size_t id_len = 0;
        session_->legacy_session_id(id_len);
        if (server_ && level == Space::Initial && id_len != 0 && !ccs_sent_) {
            const uint8_t one = 1;
            if (!emit(ContentType::ChangeCipherSpec, &one, 1, kRecordVersion, out))
                return fail(Alert::InternalError, "out of memory for a change_cipher_spec", out);
            ccs_sent_ = true;
        }
    }
    /* \~english
     * Once this end's Finished is out, what it writes next is under the
     * application keys: the peer reads with them from its Finished on.
     * \~spanish
     * En cuanto sale el Finished de este extremo, lo que escriba despues va con
     * las claves de aplicacion: el otro lee con ellas desde ese Finished.
     * \~ */
    if (write_level_ == Space::Handshake && session_->write_secret(Space::Application) != nullptr)
        return enter_write(Space::Application, out);
    return true;
}

bool Channel::key_update(bool request, Buffer &out) noexcept {
    // \~english Only after this end's Finished (4.6.3), and never once closed.  \~spanish Solo tras el Finished de este extremo (4.6.3), y nunca ya cerrado.  \~
    if (state_ != State::Open || close_sent_ || write_level_ != Space::Application) return false;
    const uint8_t msg[5] = {static_cast<uint8_t>(Handshake::KeyUpdate), 0, 0, 1, static_cast<uint8_t>(request ? 1 : 0)};
    // \~english With the old keys, in a record of its own, and then the new ones (4.6.3, 5.1).
    // \~spanish Con las claves viejas, en un registro propio, y luego las nuevas (4.6.3, 5.1).  \~
    if (!emit(ContentType::Handshake, msg, sizeof msg, kRecordVersion, out))
        return fail(Alert::InternalError, "out of memory for a KeyUpdate", out);
    if (!write_.update()) return fail(Alert::InternalError, "the provider could not update the write keys", out);
    ++updates_sent_;
    update_owed_ = false;
    return true;
}

bool Channel::send(const uint8_t *data, size_t n, Buffer &out) noexcept {
    if (state_ != State::Open || close_sent_) return false;
    // \~english The update the peer asked for goes before the next application data (4.6.3).
    // \~spanish La actualizacion que pidio el otro va antes de los siguientes datos de aplicacion (4.6.3).  \~
    if (update_owed_ && !key_update(false, out)) return false;
    while (n != 0) {
        const size_t take = n < kMaxFragment ? n : kMaxFragment;
        // \~english Before the AEAD's limit, and long before the number could wrap (5.3, 5.5).
        // \~spanish Antes del limite del AEAD, y mucho antes de que el numero pudiera dar la vuelta (5.3, 5.5).  \~
        if (write_.sequence() >= update_after_ && !key_update(false, out)) return false;
        if (!emit(ContentType::ApplicationData, data, take, kRecordVersion, out))
            return fail(Alert::InternalError, "application data could not be sealed", out);
        data += take;
        n -= take;
    }
    return true;
}

bool Channel::close(Buffer &out) noexcept {
    if (state_ == State::Failed || state_ == State::Idle) return false;
    if (close_sent_) return true;
    close_sent_ = true;
    // \~english close_notify, before closing the write side (6.1).  \~spanish close_notify, antes de cerrar el lado de escritura (6.1).  \~
    return send_alert(kWarning, 0, out);
}

} // namespace tls
} // namespace http_vx
