/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/schedule.cpp
 * @brief
 * \~english TLS 1.3's key schedule and transcript (RFC 8446, 4.4.1 and 7.1).
 * \~spanish El calendario de claves y la transcripcion de TLS 1.3 (RFC 8446, 4.4.1 y 7.1).
 * \~
 */

#include "http_vx/tls_schedule.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english Clears secret bytes where the compiler cannot drop the store.
/// \~spanish Borra bytes secretos donde el compilador no puede quitar la escritura.  \~
void wipe(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/// \~english The handshake type of the synthetic message after a HelloRetryRequest (4.4.1).
/// \~spanish El tipo de mensaje del mensaje sintetico tras un HelloRetryRequest (4.4.1).  \~
constexpr uint8_t kMessageHash = 254;

} // namespace

size_t hkdf_label(uint8_t *out, size_t room, size_t length, const char *label,
                  const uint8_t *context, size_t context_len) noexcept {
    static const char kPrefix[] = "tls13 ";
    constexpr size_t kPrefixLen = sizeof kPrefix - 1;
    size_t label_len = 0;
    while (label[label_len] != '\0') ++label_len;

    // \~english label<7..255>, context<0..255>, and a uint16 length (7.1).
    // \~spanish label<7..255>, context<0..255>, y una longitud uint16 (7.1).  \~
    const size_t full = kPrefixLen + label_len;
    if (full > 255 || context_len > 255 || length > 0xFFFF) return 0;
    const size_t size = 2 + 1 + full + 1 + context_len;
    if (size > room) return 0;

    out[0] = static_cast<uint8_t>(length >> 8);
    out[1] = static_cast<uint8_t>(length);
    out[2] = static_cast<uint8_t>(full);
    util::vesta_memcpy_noinline(out + 3, kPrefix, kPrefixLen);
    util::vesta_memcpy_noinline(out + 3 + kPrefixLen, label, label_len);
    out[3 + full] = static_cast<uint8_t>(context_len);
    if (context_len != 0) util::vesta_memcpy_noinline(out + 4 + full, context, context_len);
    return size;
}

bool expand_label(Crypto &c, Hash h, const uint8_t *secret, const char *label,
                  const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len) noexcept {
    uint8_t info[2 + 1 + 255 + 1 + 255];
    const size_t n = hkdf_label(info, sizeof info, out_len, label, context, context_len);
    return n != 0 && c.expand(h, secret, hash_size(h), info, n, out, out_len);
}

bool hmac(Crypto &c, Hash h, const uint8_t *key, size_t key_len, const uint8_t *msg, size_t n,
          uint8_t *out) noexcept {
    // \~english RFC 5869, 2.2: PRK = HMAC-Hash(salt, IKM).  \~spanish RFC 5869, 2.2: PRK = HMAC-Hash(sal, IKM).  \~
    return c.extract(h, key, key_len, msg, n, out);
}

bool finished_data(Crypto &c, Hash h, const uint8_t *base_key, const uint8_t *transcript_hash,
                   uint8_t *out) noexcept {
    // \~english finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) (4.4.4).
    // \~spanish finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) (4.4.4).  \~
    uint8_t key[kMaxHash];
    const size_t hl = hash_size(h);
    const bool ok = expand_label(c, h, base_key, "finished", nullptr, 0, key, hl) &&
                    hmac(c, h, key, hl, transcript_hash, hl, out);
    wipe(key, sizeof key);
    return ok;
}

bool ticket_psk(Crypto &c, Hash h, const uint8_t *resumption_master, const uint8_t *nonce,
                size_t nonce_len, uint8_t *out) noexcept {
    // \~english HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length) (4.6.1).
    // \~spanish HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length) (4.6.1).  \~
    return expand_label(c, h, resumption_master, "resumption", nonce, nonce_len, out, hash_size(h));
}

Transcript::~Transcript() {
    if (buf_ == nullptr) return;
    // \~english The messages carry the handshake's secrets' inputs: wiped, not just freed.
    // \~spanish Los mensajes llevan las entradas de los secretos del saludo: se borran, no solo se liberan.  \~
    wipe(buf_, cap_);
    util::host_free(buf_);
}

bool Transcript::add(const uint8_t *msg, size_t n) noexcept {
    if (n > kMaxSize - len_) return false;
    if (len_ + n > cap_) {
        size_t cap = cap_ == 0 ? 2048 : cap_;
        while (cap < len_ + n) cap *= 2;
        if (cap > kMaxSize) cap = kMaxSize;
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Growing,
                                     util::AllocFill::Dense);
        uint8_t *grown = static_cast<uint8_t *>(util::host_alloc(cap));
        if (grown == nullptr) return false;
        if (len_ != 0) util::vesta_memcpy(grown, buf_, len_);
        if (buf_ != nullptr) {
            wipe(buf_, cap_);
            util::host_free(buf_);
        }
        buf_ = grown;
        cap_ = cap;
    }
    if (n != 0) util::vesta_memcpy(buf_ + len_, msg, n);
    len_ += n;
    return true;
}

bool Transcript::hash(Crypto &c, Hash h, uint8_t *out) const noexcept {
    return c.digest(h, buf_, len_, out);
}

bool Transcript::replace_with_message_hash(Crypto &c, Hash h) noexcept {
    // \~english message_hash || 00 00 Hash.length || Hash(ClientHello1) (4.4.1).
    // \~spanish message_hash || 00 00 Hash.length || Hash(ClientHello1) (4.4.1).  \~
    const size_t hl = hash_size(h);
    uint8_t synthetic[4 + kMaxHash];
    if (len_ == 0 || !c.digest(h, buf_, len_, synthetic + 4)) return false;
    synthetic[0] = kMessageHash;
    synthetic[1] = 0;
    synthetic[2] = 0;
    synthetic[3] = static_cast<uint8_t>(hl);
    wipe(buf_, len_);
    len_ = 0;
    return add(synthetic, 4 + hl);
}

KeySchedule::~KeySchedule() {
    wipe(secret_, sizeof secret_);
}

bool KeySchedule::derive(const char *label, const uint8_t *transcript_hash, uint8_t *out) const noexcept {
    const size_t hl = hash_size(h_);
    return expand_label(c_, h_, secret_, label, transcript_hash, hl, out, hl);
}

bool KeySchedule::advance(const uint8_t *ikm, size_t ikm_len) noexcept {
    /* \~english
     * Derive-Secret(., "derived", "") -- the transcript of no messages, so the
     * hash of the empty string -- is the salt of the next HKDF-Extract (7.1).
     * \~spanish
     * Derive-Secret(., "derived", "") -- la transcripcion de ningun mensaje, asi
     * que el resumen de la cadena vacia -- es la sal del siguiente HKDF-Extract
     * (7.1).
     * \~ */
    const size_t hl = hash_size(h_);
    uint8_t empty[kMaxHash];
    uint8_t salt[kMaxHash];
    bool ok = c_.digest(h_, nullptr, 0, empty) && derive("derived", empty, salt) &&
              c_.extract(h_, salt, hl, ikm, ikm_len, secret_);
    wipe(salt, sizeof salt);
    return ok;
}

bool KeySchedule::start(const uint8_t *psk, size_t psk_len) noexcept {
    if (stage_ != Stage::None) return false;
    // \~english No PSK is Hash.length zeros, and the salt of the first extract is zeros too (7.1).
    // \~spanish Sin PSK son Hash.length ceros, y la sal del primer extract tambien son ceros (7.1).  \~
    const size_t hl = hash_size(h_);
    uint8_t zeros[kMaxHash] = {};
    if (psk == nullptr) {
        psk = zeros;
        psk_len = hl;
    }
    if (!c_.extract(h_, zeros, hl, psk, psk_len, secret_)) return false;
    stage_ = Stage::Early;
    return true;
}

bool KeySchedule::binder_key(bool resumption, uint8_t *out) const noexcept {
    if (stage_ != Stage::Early) return false;
    uint8_t empty[kMaxHash];
    return c_.digest(h_, nullptr, 0, empty) && derive(resumption ? "res binder" : "ext binder", empty, out);
}

bool KeySchedule::early_traffic(const uint8_t *client_hello_hash, uint8_t *out) const noexcept {
    return stage_ == Stage::Early && derive("c e traffic", client_hello_hash, out);
}

bool KeySchedule::handshake(const uint8_t *shared, size_t shared_len, const uint8_t *hello_hash,
                            uint8_t *client_out, uint8_t *server_out) noexcept {
    if (stage_ != Stage::Early || !advance(shared, shared_len)) return false;
    stage_ = Stage::Handshake;
    return derive("c hs traffic", hello_hash, client_out) && derive("s hs traffic", hello_hash, server_out);
}

bool KeySchedule::application(const uint8_t *server_finished_hash, uint8_t *client_out, uint8_t *server_out,
                              uint8_t *exporter_out) noexcept {
    if (stage_ != Stage::Handshake) return false;
    const uint8_t zeros[kMaxHash] = {};
    if (!advance(zeros, hash_size(h_))) return false;
    stage_ = Stage::Master;
    return derive("c ap traffic", server_finished_hash, client_out) &&
           derive("s ap traffic", server_finished_hash, server_out) &&
           derive("exp master", server_finished_hash, exporter_out);
}

bool KeySchedule::resumption(const uint8_t *client_finished_hash, uint8_t *out) noexcept {
    if (stage_ != Stage::Master) return false;
    const bool ok = derive("res master", client_finished_hash, out);
    // \~english The last secret out: the Master Secret has nothing left to give (7.1: SHOULD be erased).
    // \~spanish El ultimo secreto: al Master Secret no le queda nada que dar (7.1: DEBERIA borrarse).  \~
    wipe(secret_, sizeof secret_);
    stage_ = Stage::Done;
    return ok;
}

} // namespace tls
} // namespace http_vx
