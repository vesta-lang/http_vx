/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/channel_read.cpp
 * @brief
 * \~english TLS 1.3 over a byte stream, the reading half: which record may come when, and what it becomes (RFC 8446, 4.2.10, 4.6, 5, 6, D.4).
 * \~spanish TLS 1.3 sobre un flujo de bytes, la mitad que lee: que registro puede venir cuando, y en que se convierte (RFC 8446, 4.2.10, 4.6, 5, 6, D.4).
 * \~
 */

#include "http_vx/tls_channel.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace tls {

using quic::Space;

namespace {

/// \~english user_canceled (6.1): a closure alert, not an error.  \~spanish user_canceled (6.1): una alerta de cierre, no un error.  \~
constexpr uint8_t kUserCanceled = 90;

/// \~english The 24-bit length of the handshake message whose header is at @p p.  \~spanish La longitud de 24 bits del mensaje del saludo cuya cabecera esta en @p p.  \~
size_t message_length(const uint8_t *p) noexcept {
    return size_t{p[1]} << 16 | size_t{p[2]} << 8 | p[3];
}

} // namespace

ChannelStatus Channel::receive(Buffer &in, Buffer &plain, Buffer &out) noexcept {
    if (state_ == State::Failed) return ChannelStatus::Failed;
    // \~english Anything after a close_notify is ignored (6.1).  \~spanish Todo lo que venga tras un close_notify se ignora (6.1).  \~
    if (state_ == State::Closed) {
        in.consume(in.size());
        return ChannelStatus::Closed;
    }
    if (in.empty()) return ChannelStatus::Ok;
    // \~english A server's handshake begins with the first bytes, not with the connection.
    // \~spanish El saludo de un servidor empieza con los primeros bytes, no con la conexion.  \~
    if (state_ == State::Idle) {
        if (!server_) {
            fail(Alert::InternalError, "bytes received before start()", out);
            return ChannelStatus::Failed;
        }
        if (!make_session()) {
            fail(Alert::InternalError, "out of memory for the handshake", out);
            return ChannelStatus::Failed;
        }
    }
    while (in.size() >= kRecordHeader) {
        const uint8_t *r = in.data();
        const RecordHeader h = read_record_header(r);
        // \~english What the header alone can refuse is refused before waiting for the rest.
        // \~spanish Lo que la cabecera sola puede rechazar se rechaza antes de esperar el resto.  \~
        if (!check_header(h, out)) return ChannelStatus::Failed;
        const size_t total = kRecordHeader + h.length;
        if (in.size() < total) break;
        const bool go_on = record(r, total, h, plain, out);
        in.consume(total);
        if (!go_on) break;
    }
    if (state_ == State::Closed) {
        in.consume(in.size());
        return ChannelStatus::Closed;
    }
    if (state_ == State::Failed) return ChannelStatus::Failed;
    // \~english One answer for however many asked while this end was silent (4.6.3).
    // \~spanish Una respuesta por muchas que se pidieran mientras este extremo callaba (4.6.3).  \~
    if (update_owed_ && !close_sent_ && !key_update(false, out) && state_ == State::Failed) return ChannelStatus::Failed;
    return ChannelStatus::Ok;
}

bool Channel::check_header(const RecordHeader &h, Buffer &out) noexcept {
    switch (static_cast<ContentType>(h.type)) {
    case ContentType::ApplicationData:
        if (h.length > kMaxCiphertext) return fail(Alert::RecordOverflow, "a record longer than 2^14 + 256 (RFC 8446, 5.2)", out);
        // \~english Unprotected, it can only be early data being skipped past a HelloRetryRequest (4.2.10).
        // \~spanish Sin proteger, solo pueden ser datos tempranos que se saltan tras un HelloRetryRequest (4.2.10).  \~
        if (!read_.installed() && !early_skip_)
            return fail(Alert::UnexpectedMessage, "application data before the handshake protected it (RFC 8446, 5.1)", out);
        return true;
    case ContentType::ChangeCipherSpec:
        // \~english A single byte, or it is not the compatibility record (5).  \~spanish Un solo byte, o no es el registro de compatibilidad (5).  \~
        if (h.length != 1) return fail(Alert::UnexpectedMessage, "a change_cipher_spec that is not one byte (RFC 8446, 5)", out);
        return true;
    case ContentType::Handshake:
        if (read_.installed())
            return fail(Alert::UnexpectedMessage, "an unprotected handshake record after protection started (RFC 8446, 5.2)", out);
        if (h.length == 0) return fail(Alert::UnexpectedMessage, "a zero-length handshake fragment (RFC 8446, 5.1)", out);
        if (h.length > kMaxFragment) return fail(Alert::RecordOverflow, "a record longer than 2^14 (RFC 8446, 5.1)", out);
        return true;
    case ContentType::Alert:
        /* \~english
         * An unprotected alert is taken while the handshake goes on: a peer
         * that failed before it had keys to seal with can only say so in the
         * clear.  After it, every record is protected (5.2).
         * \~spanish
         * Una alerta sin proteger se acepta mientras dura el saludo: un extremo que
         * fallo antes de tener claves con las que sellar solo puede decirlo en
         * claro.  Despues, todo registro va protegido (5.2).
         * \~ */
        if (read_level_ == Space::Application)
            return fail(Alert::UnexpectedMessage, "an unprotected alert after the handshake (RFC 8446, 5.2)", out);
        if (h.length > kMaxFragment) return fail(Alert::RecordOverflow, "a record longer than 2^14 (RFC 8446, 5.1)", out);
        return true;
    case ContentType::Invalid:
        break;
    }
    return fail(Alert::UnexpectedMessage, "a record of an unknown type (RFC 8446, 5)", out);
}

bool Channel::record(const uint8_t *r, size_t total, const RecordHeader &h, Buffer &plain, Buffer &out) noexcept {
    const uint8_t *body = r + kRecordHeader;
    switch (static_cast<ContentType>(h.type)) {
    case ContentType::ChangeCipherSpec:
        return on_ccs(body[0], out);
    case ContentType::Alert:
        return on_alert(body, h.length, out);
    case ContentType::Handshake:
        empty_records_ = 0;
        return on_handshake(body, h.length, out);
    case ContentType::ApplicationData:
        if (!read_.installed()) return skip_early(h.length, Alert::UnexpectedMessage, out);
        return protected_record(r, total, plain, out);
    case ContentType::Invalid:
        break;
    }
    return fail(Alert::UnexpectedMessage, "a record of an unknown type (RFC 8446, 5)", out);
}

bool Channel::skip_early(size_t n, Alert refuse, Buffer &out) noexcept {
    // \~english Early data turned down is skipped, up to a budget; past it, it is not early data (4.2.10).
    // \~spanish Los datos tempranos rechazados se saltan, hasta un presupuesto; pasado, no son datos tempranos (4.2.10).  \~
    if (!early_skip_ || n > kMaxEarlySkipped - early_skipped_)
        return fail(refuse, refuse == Alert::BadRecordMac ? "a record that does not deprotect (RFC 8446, 5.2)"
                                                          : "application data before the handshake protected it (RFC 8446, 5.1)",
                    out);
    early_skipped_ += static_cast<uint32_t>(n);
    return true;
}

bool Channel::protected_record(const uint8_t *r, size_t total, Buffer &plain, Buffer &out) noexcept {
    // \~english Straight into the plaintext buffer: application data is not copied again.
    // \~spanish Directamente al buffer en claro: los datos de aplicacion no se copian otra vez.  \~
    uint8_t *at = plain.reserve(total - kRecordHeader);
    if (at == nullptr) return fail(Alert::InternalError, "out of memory for a record", out);
    const Opened o = read_.open(r, total, at);
    switch (o.status) {
    case Opened::Status::Ok:
        break;
    case Opened::Status::Forged:
        return skip_early(total - kRecordHeader, Alert::BadRecordMac, out);
    case Opened::Status::Failed:
        return fail(Alert::InternalError, "the provider could not open a record", out);
    case Opened::Status::NoType:
        return fail(Alert::UnexpectedMessage, "a record with no content type, all padding (RFC 8446, 5.4)", out);
    case Opened::Status::Overflow:
        return fail(Alert::RecordOverflow, "a record whose plaintext is longer than 2^14 + 1 (RFC 8446, 5.4)", out);
    case Opened::Status::Exhausted:
        return fail(Alert::UnexpectedMessage, "the peer's sequence number would wrap without a KeyUpdate (RFC 8446, 5.3)", out);
    }
    // \~english The first record that opens is the end of early data (4.2.10).  \~spanish El primer registro que se abre es el fin de los datos tempranos (4.2.10).  \~
    early_skip_ = false;
    const bool mid_message = post_.len != 0 || (session_ != nullptr && session_->buffered() != 0);
    switch (o.type) {
    case ContentType::ApplicationData:
        // \~english Only once the peer's Finished was read, and never inside a handshake message (5.1).
        // \~spanish Solo cuando se leyo el Finished del otro, y nunca dentro de un mensaje del saludo (5.1).  \~
        if (read_level_ != Space::Application)
            return fail(Alert::UnexpectedMessage, "application data before the peer's Finished (RFC 8446, 2)", out);
        if (mid_message)
            return fail(Alert::UnexpectedMessage, "application data inside a split handshake message (RFC 8446, 5.1)", out);
        if (o.len == 0) {
            if (++empty_records_ > kMaxEmptyRecords)
                return fail(Alert::UnexpectedMessage, "too many empty records in a row", out);
            return true;
        }
        empty_records_ = 0;
        plain.commit(o.len);
        return true;
    case ContentType::Handshake:
        if (o.len == 0) return fail(Alert::UnexpectedMessage, "a zero-length handshake record (RFC 8446, 5.4)", out);
        empty_records_ = 0;
        return on_handshake(at, o.len, out);
    case ContentType::Alert:
        return on_alert(at, o.len, out);
    case ContentType::ChangeCipherSpec:
        return fail(Alert::UnexpectedMessage, "a protected change_cipher_spec (RFC 8446, 5)", out);
    case ContentType::Invalid:
        break;
    }
    return fail(Alert::UnexpectedMessage, "a protected record of an unknown type (RFC 8446, 5)", out);
}

bool Channel::on_ccs(uint8_t value, Buffer &out) noexcept {
    if (value != 1) return fail(Alert::UnexpectedMessage, "a change_cipher_spec other than 0x01 (RFC 8446, 5)", out);
    /* \~english
     * Dropped between the first ClientHello and the peer's Finished; before
     * or after that it is an unexpected record type (5).
     * \~spanish
     * Se tira entre el primer ClientHello y el Finished del otro; antes o despues
     * es un tipo de registro inesperado (5).
     * \~ */
    if (!hello_seen_ || read_level_ == Space::Application)
        return fail(Alert::UnexpectedMessage, "a change_cipher_spec outside the handshake (RFC 8446, 5)", out);
    if (++empty_records_ > kMaxEmptyRecords) return fail(Alert::UnexpectedMessage, "too many empty records in a row", out);
    return true;
}

bool Channel::on_alert(const uint8_t *p, size_t n, Buffer &out) noexcept {
    // \~english Exactly one alert per record (5.1), never an empty one (5.4).  \~spanish Exactamente una alerta por registro (5.1), nunca una vacia (5.4).  \~
    if (n == 0) return fail(Alert::UnexpectedMessage, "a zero-length alert record (RFC 8446, 5.4)", out);
    if (n != 2) return fail(Alert::DecodeError, "an alert record that is not exactly one alert (RFC 8446, 5.1)", out);
    const uint8_t description = p[1];
    if (description == 0) {
        // \~english close_notify: the peer will send nothing more (6.1).  \~spanish close_notify: el otro no mandara nada mas (6.1).  \~
        state_ = State::Closed;
        why_ = "the peer sent close_notify";
        return false;
    }
    // \~english user_canceled is a closure alert, which close_notify SHOULD follow (6.1).
    // \~spanish user_canceled es una alerta de cierre, a la que DEBERIA seguir close_notify (6.1).  \~
    if (description == kUserCanceled) return true;
    // \~english Any other, known or not, is fatal whatever its level says; nothing is sent back (6, 6.2).
    // \~spanish Cualquier otra, conocida o no, es fatal diga lo que diga su nivel; no se contesta nada (6, 6.2).  \~
    state_ = State::Failed;
    alert_ = static_cast<Alert>(description);
    alert_received_ = true;
    why_ = "the peer sent a fatal alert";
    release_pending();
    return false;
}

bool Channel::on_handshake(const uint8_t *p, size_t n, Buffer &out) noexcept {
    if (complete_) return after_handshake(p, n, out);
    hello_seen_ = true;
    const Space before = session_->reading();
    const bool retried = session_->retried();
    session_->set_clock(clock_us_);
    if (!session_->receive(before, p, n)) return fail_session(out);
    if (!flush(out)) return false;
    // \~english The session moved on: the peer's next records come under the new level's keys.
    // \~spanish La sesion avanzo: los registros siguientes del otro vienen con las claves del nivel nuevo.  \~
    if (session_->reading() != read_level_ && !enter_read(session_->reading(), out)) return false;
    if (server_ && before == Space::Initial && session_->reading() != Space::Initial) {
        // \~english Early data turned down is skipped -- and after a retry, no ClientHello may offer it again (4.1.2).
        // \~spanish Los datos tempranos rechazados se saltan -- y tras un reintento, ningun ClientHello puede volver a ofrecerlos (4.1.2).  \~
        early_skip_ = !retried && session_->early_offered() && !session_->early_accepted();
    } else if (server_ && !retried && session_->retried()) {
        early_skip_ = session_->early_offered();
    }
    if (session_->complete()) {
        complete_ = true;
        state_ = State::Open;
    }
    return true;
}

bool Channel::after_handshake(const uint8_t *p, size_t n, Buffer &out) noexcept {
    /* \~english
     * Post-handshake messages (4.6), framed here: a KeyUpdate is the
     * channel's own, anything else is the session's -- and a message split
     * across records waits in post_ for its last piece.
     * \~spanish
     * Mensajes tras el saludo (4.6), entramados aqui: un KeyUpdate es del propio
     * canal, cualquier otro es de la sesion -- y un mensaje partido entre
     * registros espera en post_ a su ultimo trozo.
     * \~ */
    const bool joined = post_.len != 0;
    if (joined && !stash(p, n, out)) return false;
    const uint8_t *data = joined ? post_.p : p;
    const size_t len = joined ? post_.len : n;
    size_t at = 0;
    while (len - at >= 4) {
        const uint8_t type = data[at];
        const size_t body = message_length(data + at);
        // \~english What the header alone refuses, before the body is waited for.
        // \~spanish Lo que la cabecera sola rechaza, antes de esperar el cuerpo.  \~
        if (type == static_cast<uint8_t>(Handshake::KeyUpdate)) {
            if (body != 1) return fail(Alert::DecodeError, "a KeyUpdate whose body is not one byte (RFC 8446, 4.6.3)", out);
        } else if (server_ || session_ == nullptr) {
            return fail(Alert::UnexpectedMessage, "a handshake message after the handshake that this end does not take (RFC 8446, 4.6)", out);
        } else if (body > Session::kMaxInput - 4) {
            return fail(Alert::IllegalParameter, "a post-handshake message larger than this end buffers", out);
        }
        if (len - at < 4 + body) break;
        if (!post_message(data + at, 4 + body, at + 4 + body == len, out)) return false;
        at += 4 + body;
    }
    if (joined) {
        // \~english What was used goes; the rest waits.  \~spanish Lo usado se va; el resto espera.  \~
        if (at == post_.len) {
            release_pending();
        } else if (at != 0) {
            util::vesta_memmove(post_.p, post_.p + at, post_.len - at);
            post_.len -= at;
        }
        return true;
    }
    return at == len || stash(p + at, len - at, out);
}

bool Channel::post_message(const uint8_t *m, size_t n, bool last, Buffer &out) noexcept {
    if (m[0] != static_cast<uint8_t>(Handshake::KeyUpdate)) {
        // \~english A client's NewSessionTicket, or whatever else the session refuses by name.
        // \~spanish El NewSessionTicket de un cliente, o lo que la sesion rechace por su nombre.  \~
        session_->set_clock(clock_us_);
        return session_->receive(Space::Application, m, n) ? flush(out) : fail_session(out);
    }
    /* \~english
     * A KeyUpdate precedes a key change, so it ends its record (5.1): what
     * follows it in the same record was sealed with keys it just retired.
     * \~spanish
     * Un KeyUpdate precede a un cambio de clave, asi que acaba su registro
     * (5.1): lo que le siga en el mismo registro se sello con claves que acaba de
     * retirar.
     * \~ */
    if (!last) return fail(Alert::UnexpectedMessage, "a KeyUpdate that does not end its record (RFC 8446, 5.1)", out);
    if (m[4] > 1) return fail(Alert::IllegalParameter, "a KeyUpdate request other than 0 or 1 (RFC 8446, 4.6.3)", out);
    if (!read_.update()) return fail(Alert::InternalError, "the provider could not update the read keys", out);
    ++updates_received_;
    if (m[4] == 1) update_owed_ = true;
    return true;
}

bool Channel::stash(const uint8_t *p, size_t n, Buffer &out) noexcept {
    if (n > Session::kMaxInput - post_.len) return fail(Alert::IllegalParameter, "a post-handshake message larger than this end buffers", out);
    if (post_.cap - post_.len < n) {
        size_t cap = post_.cap == 0 ? 64 : post_.cap;
        while (cap - post_.len < n) cap *= 2;
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Growing, util::AllocFill::Dense);
        uint8_t *grown = static_cast<uint8_t *>(util::host_alloc(cap));
        if (grown == nullptr) return fail(Alert::InternalError, "out of memory for a post-handshake message", out);
        if (post_.len != 0) util::vesta_memcpy(grown, post_.p, post_.len);
        const size_t len = post_.len;
        release_pending();
        post_.p = grown;
        post_.cap = cap;
        post_.len = len;
    }
    util::vesta_memcpy(post_.p + post_.len, p, n);
    post_.len += n;
    return true;
}

} // namespace tls
} // namespace http_vx
