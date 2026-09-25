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

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english The version of what is inside: a change of layout is a new number, and old tickets stop opening.
/// \~spanish La version de lo que va dentro: un cambio de forma es un numero nuevo, y los tickets viejos dejan de abrirse.  \~
constexpr uint8_t kLayout = 2;

/// \~english Bound into every seal: a ticket is only ever opened as a ticket.
/// \~spanish Atado a cada sello: un ticket solo se abre como ticket.  \~
const uint8_t kLabel[] = {'h', 't', 't', 'p', '_', 'v', 'x', ' ', 't', 'i', 'c', 'k', 'e', 't'};

/// \~english The largest contents: layout, suite, times, age_add, the PSK, the protocol, and the 0-RTT flag and context.
/// \~spanish El contenido mas grande: forma, algoritmo, tiempos, age_add, la PSK, el protocolo, y la marca y el contexto de 0-RTT.  \~
constexpr size_t kFixed = 1 + 2 + 8 + 4 + 4;
constexpr size_t kMaxPlain = kFixed + 1 + kMaxHash + 1 + 255 + 1 + 32;
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
    put(p, t.early ? 1 : 0, 1);
    util::vesta_memcpy_noinline(p, t.context, sizeof t.context);
    p += sizeof t.context;
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
    if (ok && len >= kFixed + 2 && get(p, 1) == kLayout) {
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
            // \~english The protocol, then the flag and the context: exactly what is left.
            // \~spanish El protocolo, y luego la marca y el contexto: exactamente lo que queda.  \~
            ok = static_cast<size_t>(end - p) == size_t{t.alpn_len} + 1 + sizeof t.context;
            if (ok) {
                util::vesta_memcpy_noinline(t.alpn, p, t.alpn_len);
                p += t.alpn_len;
                const uint64_t flag = get(p, 1);
                ok = flag <= 1;
                t.early = flag == 1;
                util::vesta_memcpy_noinline(t.context, p, sizeof t.context);
            }
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

ReplayGuard::ReplayGuard(size_t capacity, uint64_t window_ms, uint64_t start_ms) noexcept
    : window_ms_(window_ms), start_ms_(start_ms) {
    size_t n = 16;
    while (n < capacity) n *= 2;
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed, util::AllocFill::All);
    slots_ = static_cast<Slot *>(util::host_alloc(n * sizeof(Slot)));
    if (slots_ == nullptr) return;
    util::vesta_memset_noinline(slots_, 0, n * sizeof(Slot));
    mask_ = n - 1;
}

ReplayGuard::~ReplayGuard() {
    if (slots_ != nullptr) util::host_free(slots_);
}

ReplayGuard::Verdict ReplayGuard::admit(const uint8_t *key, uint64_t expected_ms, uint64_t now_ms) noexcept {
    if (slots_ == nullptr) return Verdict::Full;
    // \~english Until a window has passed since starting, a replay of what came before could not be told (8.2).
    // \~spanish Hasta que pasa una ventana desde el arranque, no se distinguiria una repeticion de lo anterior (8.2).  \~
    if (now_ms < start_ms_ + window_ms_) return Verdict::Warming;
    // \~english Fresh: the predicted arrival within the window of now, either way (8.3).
    // \~spanish Fresco: la llegada prevista dentro de la ventana de ahora, en los dos sentidos (8.3).  \~
    const uint64_t skew = expected_ms > now_ms ? expected_ms - now_ms : now_ms - expected_ms;
    if (skew > window_ms_) return Verdict::Stale;

    /* \~english
     * Linear probing where an expired slot is free to reuse but does not end
     * the search: a live copy could sit past it.  Only a never-used slot
     * ends it.  The key is a MAC output, so its first bytes already spread.
     * \~spanish
     * Sondeo lineal donde una ranura caducada se puede reutilizar pero no acaba
     * la busqueda: detras podria haber una copia viva.  Solo una ranura nunca
     * usada la acaba.  La clave es la salida de un MAC, asi que sus primeros
     * bytes ya se reparten.
     * \~ */
    size_t i = (size_t{key[0]} | size_t{key[1]} << 8 | size_t{key[2]} << 16 | size_t{key[3]} << 24) & mask_;
    Slot *free_slot = nullptr;
    for (size_t probes = 0; probes <= mask_; ++probes, i = (i + 1) & mask_) {
        Slot &s = slots_[i];
        if (!s.used) {
            if (free_slot == nullptr) free_slot = &s;
            break;
        }
        const bool live = s.expires_ms > now_ms;
        if (live) {
            uint8_t d = 0;
            for (size_t k = 0; k < 16; ++k) d = static_cast<uint8_t>(d | (s.key[k] ^ key[k]));
            if (d == 0) return Verdict::Replay;
        } else if (free_slot == nullptr) {
            free_slot = &s;
        }
    }
    if (free_slot == nullptr) return Verdict::Full;
    util::vesta_memcpy_noinline(free_slot->key, key, 16);
    // \~english Remembered for as long as it could still be taken as fresh.
    // \~spanish Se recuerda mientras aun pudiera tomarse por fresco.  \~
    free_slot->expires_ms = expected_ms + window_ms_ + 1;
    free_slot->used = true;
    return Verdict::Fresh;
}

const char *verdict_name(ReplayGuard::Verdict v) noexcept {
    switch (v) {
    case ReplayGuard::Verdict::Fresh:   return "fresh";
    case ReplayGuard::Verdict::Replay:  return "replay";
    case ReplayGuard::Verdict::Stale:   return "stale";
    case ReplayGuard::Verdict::Warming: return "warming";
    case ReplayGuard::Verdict::Full:    return "full";
    }
    return "unknown";
}

} // namespace tls
} // namespace http_vx
