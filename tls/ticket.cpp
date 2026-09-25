/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/ticket.cpp
 * @brief
 * \~english Sealing and opening a server's session tickets (RFC 8446, 4.6.1).
 * \~spanish Sellar y abrir los tickets de sesion de un servidor (RFC 8446, 4.6.1).
 * \~
 */

#include "http_vx/tls_ticket.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english The version of what is inside: a change of layout is a new number, and old tickets stop opening.
/// \~spanish La version de lo que va dentro: un cambio de forma es un numero nuevo, y los tickets viejos dejan de abrirse.  \~
constexpr uint8_t kLayout = 1;

/// \~english Bound into every seal: a ticket is only ever opened as a ticket.
/// \~spanish Atado a cada sello: un ticket solo se abre como ticket.  \~
const uint8_t kLabel[] = {'h', 't', 't', 'p', '_', 'v', 'x', ' ', 't', 'i', 'c', 'k', 'e', 't'};

/// \~english The largest contents: layout, suite, times, age_add, the PSK and the protocol, with their lengths.
/// \~spanish El contenido mas grande: forma, algoritmo, tiempos, age_add, la PSK y el protocolo, con sus longitudes.  \~
constexpr size_t kMaxPlain = 1 + 2 + 8 + 4 + 4 + 1 + kMaxHash + 1 + 255;
constexpr size_t kNonce = quic::kNonceSize;

void wipe(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

void put(uint8_t *&p, uint64_t v, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) *p++ = static_cast<uint8_t>(v >> (8 * (n - 1 - i)));
}

uint64_t get(const uint8_t *&p, size_t n) noexcept {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = v << 8 | *p++;
    return v;
}

} // namespace

TicketSealer::TicketSealer(quic::Crypto &c, const uint8_t *key) noexcept
    : c_(c), aead_(c.prepare_aead(quic::Aead::Aes128Gcm, key)) {}

TicketSealer::~TicketSealer() {
    c_.forget(aead_);
}

size_t TicketSealer::seal(const TicketContents &t, uint8_t *out, size_t room) const noexcept {
    if (aead_ == nullptr || t.psk_len > kMaxHash) return 0;
    uint8_t plain[kMaxPlain];
    uint8_t *p = plain;
    put(p, kLayout, 1);
    put(p, t.suite, 2);
    put(p, t.issued_ms, 8);
    put(p, t.lifetime_s, 4);
    put(p, t.age_add, 4);
    put(p, t.psk_len, 1);
    util::vesta_memcpy_noinline(p, t.psk, t.psk_len);
    p += t.psk_len;
    put(p, t.alpn_len, 1);
    util::vesta_memcpy_noinline(p, t.alpn, t.alpn_len);
    p += t.alpn_len;
    const size_t n = static_cast<size_t>(p - plain);
    size_t size = 0;
    // \~english A fresh random nonce each time: one key seals many tickets, and a nonce must never repeat under it.
    // \~spanish Un nonce aleatorio nuevo cada vez: una clave sella muchos tickets, y un nonce no debe repetirse con ella.  \~
    if (room >= kNonce + n + quic::kTagSize && c_.random(out, kNonce) &&
        c_.seal(aead_, out, kLabel, sizeof kLabel, plain, n, out + kNonce))
        size = kNonce + n + quic::kTagSize;
    wipe(plain, sizeof plain);
    return size;
}

bool TicketSealer::open(const uint8_t *in, size_t n, TicketContents &t) const noexcept {
    t = TicketContents{};
    if (aead_ == nullptr || n < kNonce + quic::kTagSize || n > kNonce + kMaxPlain + quic::kTagSize) return false;
    uint8_t plain[kMaxPlain];
    const size_t len = n - kNonce - quic::kTagSize;
    bool ok = c_.open(aead_, in, kLabel, sizeof kLabel, in + kNonce, n - kNonce, plain) == quic::OpenResult::Ok;
    // \~english Every length is checked against what is there: an opened ticket was still ours to read wrong.
    // \~spanish Cada longitud se comprueba contra lo que hay: un ticket abierto aun podria leerse mal.  \~
    const uint8_t *p = plain;
    const uint8_t *end = plain + len;
    if (ok && len >= 21 && get(p, 1) == kLayout) {
        t.suite = static_cast<uint16_t>(get(p, 2));
        t.issued_ms = get(p, 8);
        t.lifetime_s = static_cast<uint32_t>(get(p, 4));
        t.age_add = static_cast<uint32_t>(get(p, 4));
        t.psk_len = static_cast<uint8_t>(get(p, 1));
        ok = t.psk_len <= kMaxHash && static_cast<size_t>(end - p) >= size_t{t.psk_len} + 1;
        if (ok) {
            util::vesta_memcpy_noinline(t.psk, p, t.psk_len);
            p += t.psk_len;
            t.alpn_len = static_cast<uint8_t>(get(p, 1));
            ok = static_cast<size_t>(end - p) == t.alpn_len;
            if (ok) util::vesta_memcpy_noinline(t.alpn, p, t.alpn_len);
        }
    } else {
        ok = false;
    }
    wipe(plain, sizeof plain);
    if (!ok) {
        wipe(&t, sizeof t);
        t = TicketContents{};
    }
    return ok;
}

} // namespace tls
} // namespace http_vx
