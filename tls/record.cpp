/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/record.cpp
 * @brief
 * \~english TLS 1.3 records: traffic keys, the per-record nonce, sealing and opening (RFC 8446, 5 and 7.2-7.3).
 * \~spanish Registros de TLS 1.3: claves de trafico, el nonce por registro, sellar y abrir (RFC 8446, 5 y 7.2-7.3).
 * \~
 */

#include "http_vx/tls_record.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english Writes a record header: type, version, length (5.1).  \~spanish Escribe una cabecera de registro: tipo, version, longitud (5.1).  \~
void write_header(uint8_t *out, ContentType type, uint16_t version, size_t length) noexcept {
    out[0] = static_cast<uint8_t>(type);
    out[1] = static_cast<uint8_t>(version >> 8);
    out[2] = static_cast<uint8_t>(version);
    out[3] = static_cast<uint8_t>(length >> 8);
    out[4] = static_cast<uint8_t>(length);
}

} // namespace

size_t write_plaintext_record(ContentType type, uint16_t version, const uint8_t *content, size_t n,
                              uint8_t *out, size_t room) noexcept {
    if (n == 0 || n > kMaxFragment || kRecordHeader + n > room) return 0;
    write_header(out, type, version, n);
    util::vesta_memcpy(out + kRecordHeader, content, n);
    return kRecordHeader + n;
}

RecordKeys::~RecordKeys() {
    clear();
}

void RecordKeys::clear() noexcept {
    if (c_ != nullptr) c_->forget(state_);
    state_ = nullptr;
    seq_ = 0;
    wipe_secret(iv_, sizeof iv_);
    wipe_secret(secret_, sizeof secret_);
}

bool RecordKeys::install(Crypto &c, Aead a, const uint8_t *secret) noexcept {
    clear();
    const Hash h = quic::hash_of(a);
    const size_t hl = hash_size(h);
    // \~english [sender]_write_key and [sender]_write_iv, both with an empty context (7.3).
    // \~spanish [sender]_write_key y [sender]_write_iv, los dos con contexto vacio (7.3).  \~
    uint8_t key[quic::kMaxKey];
    const bool derived = expand_label(c, h, secret, "key", nullptr, 0, key, quic::key_size(a)) &&
                         expand_label(c, h, secret, "iv", nullptr, 0, iv_, sizeof iv_);
    void *state = derived ? c.prepare_aead(a, key) : nullptr;
    wipe_secret(key, sizeof key);
    if (state == nullptr) {
        wipe_secret(iv_, sizeof iv_);
        return false;
    }
    c_ = &c;
    state_ = state;
    aead_ = a;
    seq_ = 0;
    util::vesta_memcpy_noinline(secret_, secret, hl);
    return true;
}

bool RecordKeys::update() noexcept {
    if (!installed()) return false;
    const Hash h = quic::hash_of(aead_);
    uint8_t next[kMaxHash];
    // \~english The secret and its keys are replaced, and the old ones deleted (7.2: SHOULD).
    // \~spanish El secreto y sus claves se sustituyen, y los viejos se borran (7.2: DEBERIA).  \~
    const bool ok = expand_label(*c_, h, secret_, "traffic upd", nullptr, 0, next, hash_size(h)) &&
                    install(*c_, aead_, next);
    wipe_secret(next, sizeof next);
    return ok;
}

void RecordKeys::nonce(uint8_t *out) const noexcept {
    // \~english The 64-bit number, big-endian, padded on the left to the IV's twelve bytes, XORed with it (5.3).
    // \~spanish El numero de 64 bits, big-endian, rellenado por la izquierda hasta los doce bytes del IV, con XOR (5.3).  \~
    util::vesta_memcpy_noinline(out, iv_, quic::kNonceSize);
    for (size_t i = 0; i < 8; ++i)
        out[quic::kNonceSize - 1 - i] = static_cast<uint8_t>(out[quic::kNonceSize - 1 - i] ^ (seq_ >> (8 * i)));
}

size_t RecordKeys::seal(ContentType type, const uint8_t *content, size_t n, size_t padding, uint8_t *out,
                        size_t room) noexcept {
    if (!installed() || exhausted()) return 0;
    const size_t inner = n + 1 + padding;
    if (n > kMaxFragment || inner > kMaxInnerPlaintext) return 0;
    const size_t total = kRecordHeader + inner + quic::kTagSize;
    if (total > room) return 0;
    // \~english The outer type is always application_data and the version 0x0303 (5.2).
    // \~spanish El tipo exterior es siempre application_data y la version 0x0303 (5.2).  \~
    write_header(out, ContentType::ApplicationData, kRecordVersion, inner + quic::kTagSize);
    uint8_t *body = out + kRecordHeader;
    if (n != 0) util::vesta_memcpy(body, content, n);
    body[n] = static_cast<uint8_t>(type);
    // \~english Padding octets MUST be zeros (5.4).  \~spanish Los octetos de relleno DEBEN ser ceros (5.4).  \~
    if (padding != 0) util::vesta_memset(body + n + 1, 0, padding);
    uint8_t iv[quic::kNonceSize];
    nonce(iv);
    // \~english The associated data is the header, the length included (5.2).  \~spanish Los datos asociados son la cabecera, longitud incluida (5.2).  \~
    if (!c_->seal(state_, iv, out, kRecordHeader, body, inner, body)) return 0;
    ++seq_;
    return total;
}

Opened RecordKeys::open(const uint8_t *record, size_t total, uint8_t *out) noexcept {
    Opened o;
    if (!installed()) return o;
    const size_t fragment = total - kRecordHeader;
    if (fragment > kMaxCiphertext) {
        o.status = Opened::Status::Overflow;
        return o;
    }
    /* \~english
     * Shorter than a tag cannot authenticate, whatever the provider would
     * say.  A tag alone can: it is an empty inner plaintext, which has no
     * content type and is unexpected_message (5.4), not bad_record_mac.
     * \~spanish
     * Mas corto que una marca no puede autenticarse, diga lo que diga el
     * proveedor.  Una marca sola si puede: es un texto interior vacio, que no
     * tiene tipo de contenido y es unexpected_message (5.4), no bad_record_mac.
     * \~ */
    if (fragment < quic::kTagSize) {
        o.status = Opened::Status::Forged;
        return o;
    }
    if (exhausted()) {
        o.status = Opened::Status::Exhausted;
        return o;
    }
    uint8_t iv[quic::kNonceSize];
    nonce(iv);
    const quic::OpenResult r = c_->open(state_, iv, record, kRecordHeader, record + kRecordHeader, fragment, out);
    if (r != quic::OpenResult::Ok) {
        o.status = r == quic::OpenResult::Forged ? Opened::Status::Forged : Opened::Status::Failed;
        return o;
    }
    const size_t inner = fragment - quic::kTagSize;
    // \~english The whole TLSInnerPlaintext, padding included, is held to 2^14 + 1 (5.4).
    // \~spanish El TLSInnerPlaintext entero, relleno incluido, no pasa de 2^14 + 1 (5.4).  \~
    if (inner > kMaxInnerPlaintext) {
        o.status = Opened::Status::Overflow;
        return o;
    }
    // \~english From the end toward the beginning, only over what opened (5.4).
    // \~spanish Desde el final hacia el principio, solo sobre lo que se abrio (5.4).  \~
    size_t at = inner;
    while (at != 0 && out[at - 1] == 0) --at;
    if (at == 0) {
        o.status = Opened::Status::NoType;
        return o;
    }
    ++seq_;
    o.status = Opened::Status::Ok;
    o.type = static_cast<ContentType>(out[at - 1]);
    o.len = at - 1;
    return o;
}

} // namespace tls
} // namespace http_vx
