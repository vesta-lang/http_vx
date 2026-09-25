/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/reset.cpp
 * @brief
 * \~english Stateless reset tokens and packets (RFC 9000, 10.3).
 * \~spanish Testigos y paquetes de reinicio sin estado (RFC 9000, 10.3).
 * \~
 */

#include "http_vx/quic_reset.h"

#include "http_vx/quic_packet.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace quic {

namespace {

/// \~english Keeps the reset key for this one use.  \~spanish Reserva la clave de reinicio para este unico uso.  \~
constexpr char kLabel[] = "http_vx stateless reset";

/**
 * \~english
 * A reset larger than this says nothing more: 43 is where 10.3 stops asking
 * for "one byte shorter", and it keeps a flood of large packets from turning
 * into a flood of large answers.
 * \~spanish
 * Un reinicio mayor que esto no dice nada mas: 43 es donde 10.3 deja de pedir
 * "un byte mas corto", y evita que una avalancha de paquetes grandes se convierta
 * en una avalancha de respuestas grandes.
 * \~
 */
constexpr size_t kMaxStatelessReset = 43;

} // namespace

bool reset_token(Crypto &c, const uint8_t *key, const uint8_t *cid, size_t cid_len,
                 uint8_t *token) noexcept {
    if (cid_len > kMaxConnectionId) return false;
    uint8_t info[sizeof kLabel - 1 + kMaxConnectionId];
    util::vesta_memcpy_noinline(info, kLabel, sizeof kLabel - 1);
    util::vesta_memcpy_noinline(info + sizeof kLabel - 1, cid, cid_len);
    return c.expand(Hash::Sha256, key, kResetKeySize, info, sizeof kLabel - 1 + cid_len, token,
                    kResetTokenSize);
}

size_t write_stateless_reset(Crypto &c, const uint8_t *token, size_t trigger_len, uint8_t *out,
                             size_t room) noexcept {
    if (trigger_len <= kMinStatelessReset) return 0;
    size_t n = trigger_len - 1;
    if (n > kMaxStatelessReset) n = kMaxStatelessReset;
    if (n > room) return 0;

    // \~english Unpredictable bytes, then the header form of a short packet: 0, and the fixed bit.
    // \~spanish Bytes impredecibles, y despues la forma de un paquete corto: 0, y el bit fijo.  \~
    if (!c.random(out, n - kResetTokenSize)) return 0;
    out[0] = static_cast<uint8_t>(0x40 | (out[0] & 0x3f));
    util::vesta_memcpy_noinline(out + n - kResetTokenSize, token, kResetTokenSize);
    return n;
}

bool is_stateless_reset(const uint8_t *data, size_t n, const uint8_t *token) noexcept {
    /* \~english
     * Whatever the header form: a reset is SENT as a short header, but "any
     * packet ending in a valid stateless reset token" MUST be taken as one,
     * since other versions may use a long header (10.3).
     * \~spanish
     * Sea cual sea la forma de la cabecera: un reinicio se MANDA como cabecera
     * corta, pero "cualquier paquete que acabe en un testigo valido" DEBE
     * tomarse por uno, porque otras versiones pueden usar cabecera larga (10.3).
     * \~ */
    if (n < kMinStatelessReset) return false;
    const uint8_t *tail = data + n - kResetTokenSize;
    uint8_t diff = 0;
    for (size_t i = 0; i < kResetTokenSize; ++i) diff = static_cast<uint8_t>(diff | (tail[i] ^ token[i]));
    return diff == 0;
}

} // namespace quic
} // namespace http_vx
