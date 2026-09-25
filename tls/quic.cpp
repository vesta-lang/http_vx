/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/quic.cpp
 * @brief
 * \~english The TLS handshake hooked to a QUIC connection (RFC 9001, 4.1).
 * \~spanish El saludo TLS enganchado a una conexion QUIC (RFC 9001, 4.1).
 * \~
 */

#include "http_vx/tls_quic.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english The frame type a handshake failure is blamed on: CRYPTO (19.6).
/// \~spanish El tipo de trama al que se achaca un fallo del saludo: CRYPTO (19.6).  \~
constexpr uint64_t kCryptoFrame = 0x06;

} // namespace

SessionConfig QuicHandshake::with_params(const SessionConfig &cfg, quic::Connection &conn,
                                         QuicHandshake &self) noexcept {
    // \~english The session carries the connection's own transport parameters.
    // \~spanish La sesion lleva los parametros de transporte de la propia conexion.  \~
    SessionConfig out = cfg;
    self.tp_len_ = conn.local_transport_params(self.tp_, sizeof self.tp_);
    out.transport_params = self.tp_len_ != 0 ? self.tp_ : nullptr;
    out.transport_params_len = self.tp_len_;
    if (cfg.server && cfg.early_data) {
        // \~english The rememberable parameters first, then the caller's own context (RFC 9001, 4.6.3).
        // \~spanish Primero los parametros recordables, y luego el contexto propio de quien llama (RFC 9001, 4.6.3).  \~
        self.context_len_ = conn.early_context(self.context_, sizeof self.context_);
        self.context_fits_ = self.context_len_ != 0 && cfg.early_context_len <= sizeof self.context_ - self.context_len_;
        if (self.context_fits_ && cfg.early_context_len != 0) {
            for (size_t i = 0; i < cfg.early_context_len; ++i) self.context_[self.context_len_ + i] = cfg.early_context[i];
            self.context_len_ += cfg.early_context_len;
        }
        out.early_context = self.context_;
        out.early_context_len = self.context_len_;
    }
    // \~english A client runs 0-RTT on what it remembered; without it there is no 0-RTT (RFC 9000, 7.4.1).
    // \~spanish Un cliente hace 0-RTT con lo que recordo; sin eso no hay 0-RTT (RFC 9000, 7.4.1).  \~
    if (!cfg.server && cfg.early_data && cfg.resume != nullptr && cfg.resume->early_data &&
        !conn.remember_transport_params(cfg.resume->params, cfg.resume->params_len))
        out.early_data = false;
    return out;
}

QuicHandshake::QuicHandshake(Crypto &c, quic::Connection &conn, const SessionConfig &cfg) noexcept
    : conn_(conn), cfg_(with_params(cfg, conn, *this)), session_(c, cfg_) {}

bool QuicHandshake::fail(uint64_t code, const char *why, uint64_t now_us) noexcept {
    if (!failed_) {
        failed_ = true;
        why_ = why;
        conn_.close(code, false, kCryptoFrame, now_us);
    }
    return false;
}

bool QuicHandshake::start(uint64_t now_us) noexcept {
    if (tp_len_ == 0) return fail(kCryptoError + static_cast<uint8_t>(Alert::InternalError),
                                  "this end's transport parameters do not fit", now_us);
    // \~english The connection's clock is the session's: ticket ages are measured on it.
    // \~spanish El reloj de la conexion es el de la sesion: las edades de los tickets se miden con el.  \~
    if (!context_fits_)
        return fail(kCryptoError + static_cast<uint8_t>(Alert::InternalError), "the 0-RTT context does not fit", now_us);
    session_.set_clock(now_us);
    if (!session_.start()) return fail(session_.failure().code, session_.failure().why, now_us);
    // \~english A client that offered 0-RTT seals with its secret from now on (RFC 9001, 4.1.4).
    // \~spanish Un cliente que ofrecio 0-RTT sella con su secreto desde ahora (RFC 9001, 4.1.4).  \~
    const uint8_t *early = session_.early_secret();
    if (early != nullptr && !conn_.install_early_secret(session_.early_aead(), early, session_.early_size(), now_us))
        return fail(kCryptoError + static_cast<uint8_t>(Alert::InternalError),
                    "the connection could not install the 0-RTT secret", now_us);
    return step(now_us);
}

bool QuicHandshake::decide_early(uint64_t now_us) noexcept {
    if (early_decided_) return true;
    if (cfg_.server) {
        // \~english Decided once the ClientHello was taken: keys to open 0-RTT with, or none of it (4.6.2).
        // \~spanish Se decide cuando se tomo el ClientHello: claves para abrir el 0-RTT, o nada de el (4.6.2).  \~
        if (session_.reading() == Space::Initial) return true;
        early_decided_ = true;
        const uint8_t *early = session_.early_secret();
        if (early == nullptr) {
            conn_.reject_early(now_us);
            return true;
        }
        return conn_.install_early_secret(session_.early_aead(), early, session_.early_size(), now_us) ||
               fail(kCryptoError + static_cast<uint8_t>(Alert::InternalError),
                    "the connection could not install the 0-RTT secret", now_us);
    }
    /* \~english
     * A client knows from the server's answer: a retry, or EncryptedExtensions
     * without early_data, turned it down (RFC 9001, 4.6.2).  Applied before
     * the server's new parameters, which the reset would otherwise undo.
     * \~spanish
     * Un cliente lo sabe por la respuesta del servidor: un reintento, o
     * EncryptedExtensions sin early_data, lo rechazaron (RFC 9001, 4.6.2).  Se
     * aplica antes que los parametros nuevos del servidor, que si no el reinicio
     * desharia.
     * \~ */
    if (!session_.early_offered()) return true;
    size_t n = 0;
    if (!session_.retried() && session_.peer_transport_params(n) == nullptr) return true;
    early_decided_ = true;
    if (!session_.early_accepted()) conn_.reject_early(now_us);
    return true;
}

bool QuicHandshake::feed(uint64_t now_us) noexcept {
    /* \~english
     * Only the level TLS reads takes bytes; the others wait in their CRYPTO
     * streams, which is QUIC's buffering (4.1.3).  A level's bytes can move
     * TLS on, and then the next level may already have some waiting.
     * \~spanish
     * Solo el nivel en que lee TLS toma bytes; los demas esperan en sus flujos
     * CRYPTO, que es el almacenaje de QUIC (4.1.3).  Los bytes de un nivel
     * pueden hacer avanzar a TLS, y entonces el siguiente nivel puede tener ya
     * algunos esperando.
     * \~ */
    for (size_t l = 0; l < quic::kSpaces; ++l) {
        const Space s = static_cast<Space>(l);
        for (;;) {
            if (session_.reading() != s) break;
            const uint8_t *p = nullptr;
            const size_t n = conn_.crypto_recv(s).peek(p);
            if (n == 0) break;
            const bool ok = session_.receive(s, p, n);
            conn_.consume_crypto(s, n);
            if (!ok) return fail(session_.failure().code, session_.failure().why, now_us);
        }
    }
    // \~english Data at a level TLS has left behind will never be read (RFC 9001, 4.1.3).
    // \~spanish Los datos de un nivel que TLS dejo atras no se leeran nunca (RFC 9001, 4.1.3).  \~
    for (size_t l = 0; l < static_cast<size_t>(session_.reading()); ++l) {
        const uint8_t *p = nullptr;
        if (conn_.crypto_recv(static_cast<Space>(l)).peek(p) != 0)
            return fail(kProtocolViolation, "handshake data at a level TLS has left behind (RFC 9001, 4.1.3)",
                        now_us);
    }
    return true;
}

bool QuicHandshake::drain() noexcept {
    // \~english What TLS wrote goes to the CRYPTO stream of its level; what does not fit waits.
    // \~spanish Lo que escribio TLS va al flujo CRYPTO de su nivel; lo que no cabe espera.  \~
    for (size_t l = 0; l < quic::kSpaces; ++l) {
        const Space s = static_cast<Space>(l);
        size_t n = 0;
        const uint8_t *p = session_.output(s, n);
        if (n == 0) continue;
        size_t took = 0;
        conn_.crypto_send(s).write(p, n, took);
        session_.sent(s, took);
    }
    return true;
}

bool QuicHandshake::install(Space s, bool &done, uint64_t now_us) noexcept {
    if (done) return true;
    const uint8_t *r = session_.read_secret(s);
    const uint8_t *w = session_.write_secret(s);
    if (r == nullptr || w == nullptr) return true;
    if (!conn_.install_secrets(s, session_.aead(), r, w, session_.secret_size(), now_us))
        return fail(kCryptoError + static_cast<uint8_t>(Alert::InternalError),
                    "the connection could not install the handshake's secrets", now_us);
    done = true;
    return true;
}

bool QuicHandshake::step(uint64_t now_us) noexcept {
    if (failed_) return false;
    if (conn_.state() != quic::ConnState::Active) return false;
    session_.set_clock(now_us);
    if (!feed(now_us)) return false;
    if (!decide_early(now_us)) return false;
    drain();
    if (!install(Space::Handshake, handshake_installed_, now_us) ||
        !install(Space::Application, application_installed_, now_us))
        return false;

    // \~english The peer's parameters, as soon as they came: the connection checks, authenticates and applies them.
    // \~spanish Los parametros del otro, en cuanto llegaron: la conexion los comprueba, autentica y aplica.  \~
    if (!conn_.has_peer_transport_params()) {
        size_t n = 0;
        const uint8_t *p = session_.peer_transport_params(n);
        if (p != nullptr && !conn_.on_peer_transport_params(p, n, now_us)) {
            failed_ = true;
            why_ = "the peer's transport parameters were refused (RFC 9000, 7.3, 7.4)";
            return false;
        }
    }

    // \~english A server's handshake is confirmed when it completes (RFC 9001, 4.1.2).
    // \~spanish El saludo de un servidor se confirma cuando se completa (RFC 9001, 4.1.2).  \~
    if (cfg_.server && session_.complete() && !conn_.is_handshake_confirmed()) conn_.handshake_confirmed(now_us);
    return true;
}

} // namespace tls
} // namespace http_vx
