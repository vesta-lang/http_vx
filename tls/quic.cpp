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

/// \~english The session's configuration, carrying the connection's own transport parameters.
/// \~spanish La configuracion de la sesion, con los parametros de transporte de la propia conexion.  \~
SessionConfig with_params(const SessionConfig &cfg, const quic::Connection &conn, uint8_t *tp, size_t room,
                          size_t &len) noexcept {
    SessionConfig out = cfg;
    len = conn.local_transport_params(tp, room);
    out.transport_params = len != 0 ? tp : nullptr;
    out.transport_params_len = len;
    return out;
}

} // namespace

QuicHandshake::QuicHandshake(Crypto &c, quic::Connection &conn, const SessionConfig &cfg) noexcept
    : conn_(conn), cfg_(with_params(cfg, conn, tp_, sizeof tp_, tp_len_)), session_(c, cfg_) {}

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
    session_.set_clock(now_us);
    if (!session_.start()) return fail(session_.failure().code, session_.failure().why, now_us);
    return step(now_us);
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
