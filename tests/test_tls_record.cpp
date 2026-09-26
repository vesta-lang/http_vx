/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_record.cpp
 * @brief
 * \~english The TLS 1.3 record layer: RFC 8448's records byte for byte, and every way a record can be wrong.
 * \~spanish La capa de registros de TLS 1.3: los registros del RFC 8448 byte a byte, y cada forma en que un registro puede estar mal.
 * \~
 *
 * \~english
 * With a real provider, the section 3 trace's protected records -- the
 * server's flight, the client's Finished, the ticket, the data and the
 * close_notify each way -- are sealed from its secrets and must come out as
 * printed, and opened back.  With the fake one, what the trace cannot show:
 * the nonce's construction, padding, the size limits, a record that does
 * not open, the sequence number at its end, and KeyUpdate's next generation.
 * \~spanish
 * Con un proveedor de verdad, los registros protegidos de la traza de la
 * seccion 3 -- el vuelo del servidor, el Finished del cliente, el ticket, los
 * datos y el close_notify en cada sentido -- se sellan a partir de sus secretos
 * y tienen que salir como estan impresos, y abrirse de vuelta.  Con el de
 * mentira, lo que la traza no puede ensenar: como se hace el nonce, el relleno,
 * los limites de tamano, un registro que no se abre, el numero de secuencia en
 * su final, y la generacion siguiente de KeyUpdate.
 * \~
 */

#include "http_vx/tls_record.h"

#include "fake_crypto.h"
#include "tls_rfc8448.h"
#include "tls_rfc8448_records.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

using namespace http_vx::tls;
using http_vx::quic::Crypto;
using rfc8448::from_hex;

int failures = 0;
const char *where = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", where, what);
    ++failures;
}

/// \~english Hex to a vector.  \~spanish Hexadecimal a un vector.  \~
std::vector<uint8_t> hex(const char *h) {
    std::vector<uint8_t> v(std::strlen(h) / 2 + 1);
    v.resize(from_hex(h, v.data(), v.size()));
    return v;
}

/// \~english A 32-byte secret of one repeated byte, for the fake provider.  \~spanish Un secreto de 32 bytes de un byte repetido, para el proveedor de mentira.  \~
struct Secret {
    uint8_t b[32];
    explicit Secret(uint8_t v) { std::memset(b, v, sizeof b); }
};

/* ------------------------------------------------------------------------- */

void test_plaintext() {
    where = "plaintext";
    const uint8_t hello[3] = {1, 2, 3};
    uint8_t out[16];
    check(write_plaintext_record(ContentType::Handshake, kFirstHelloVersion, hello, 3, out, sizeof out) == 8,
          "a record is header plus content");
    const uint8_t want[8] = {22, 3, 1, 0, 3, 1, 2, 3};
    check(std::memcmp(out, want, 8) == 0, "type, 0x0301, length, content");
    const RecordHeader h = read_record_header(out);
    check(h.type == 22 && h.version == 0x0301 && h.length == 3, "and it reads back");
    check(write_plaintext_record(ContentType::Handshake, kRecordVersion, hello, 0, out, sizeof out) == 0,
          "a zero-length fragment is refused (5.1)");
    check(write_plaintext_record(ContentType::Handshake, kRecordVersion, hello, 3, out, 7) == 0, "no room is refused");
    std::vector<uint8_t> big(kMaxFragment + 1, 7);
    std::vector<uint8_t> room(big.size() + 16);
    check(write_plaintext_record(ContentType::Handshake, kRecordVersion, big.data(), big.size(), room.data(),
                                 room.size()) == 0,
          "a fragment over 2^14 is refused (5.1)");
    check(write_plaintext_record(ContentType::Handshake, kRecordVersion, big.data(), kMaxFragment, room.data(),
                                 room.size()) == kRecordHeader + kMaxFragment,
          "exactly 2^14 is taken");
}

void test_nonce(Crypto &c) {
    where = "nonce";
    RecordKeys k;
    check(!k.installed(), "keys start uninstalled");
    const Secret s(0x11);
    check(k.install(c, Aead::Aes128Gcm, s.b), "installed");
    uint8_t iv[12];
    uint8_t n1[12];
    k.nonce(iv);
    k.set_sequence(0x0102030405060708ull);
    k.nonce(n1);
    // \~english The IV untouched in its first four bytes, XORed big-endian in its last eight (5.3).
    // \~spanish El IV intacto en sus cuatro primeros bytes, con XOR big-endian en los ocho ultimos (5.3).  \~
    bool ok = std::memcmp(iv, n1, 4) == 0;
    for (size_t i = 0; i < 8; ++i) ok = ok && n1[4 + i] == static_cast<uint8_t>(iv[4 + i] ^ (i + 1));
    check(ok, "the sequence number is XORed into the IV's last eight bytes, big-endian");
    k.set_sequence(1);
    k.nonce(n1);
    check(std::memcmp(iv, n1, 11) == 0 && n1[11] == (iv[11] ^ 1), "record 1 changes the last byte only");
}

void test_seal_open(Crypto &c) {
    where = "seal and open";
    const Secret s(0x22);
    RecordKeys w;
    RecordKeys r;
    check(w.install(c, Aead::Aes128Gcm, s.b) && r.install(c, Aead::Aes128Gcm, s.b), "both directions installed");
    const uint8_t msg[5] = {'h', 'e', 'l', 'l', 'o'};
    uint8_t rec[64];
    uint8_t out[64];
    const size_t n = w.seal(ContentType::ApplicationData, msg, 5, 0, rec, sizeof rec);
    check(n == kRecordOverhead + 5, "header, content, type, tag");
    const RecordHeader h = read_record_header(rec);
    check(h.type == 23 && h.version == 0x0303 && h.length == 5 + 1 + 16, "outer type 23, version 0x0303 (5.2)");
    check(w.sequence() == 1, "the write sequence moved on");
    Opened o = r.open(rec, n, out);
    check(o.status == Opened::Status::Ok && o.type == ContentType::ApplicationData && o.len == 5 &&
              std::memcmp(out, msg, 5) == 0,
          "it opens to what was sealed");
    check(r.sequence() == 1, "the read sequence moved on");

    // \~english The same record again: its nonce is gone, so it does not open.
    // \~spanish El mismo registro otra vez: su nonce ya paso, asi que no se abre.  \~
    o = r.open(rec, n, out);
    check(o.status == Opened::Status::Forged, "a replayed record does not open: the nonce is the next number");
    check(r.sequence() == 1, "and a record that did not open does not move the number");

    // \~english A changed header byte: the header is the associated data (5.2).
    // \~spanish Un byte de la cabecera cambiado: la cabecera son los datos asociados (5.2).  \~
    const size_t n2 = w.seal(ContentType::Handshake, msg, 5, 0, rec, sizeof rec);
    rec[2] = 0x04;
    check(r.open(rec, n2, out).status == Opened::Status::Forged, "the header is authenticated");
    rec[2] = 0x03;
    rec[n2 - 1] ^= 1;
    check(r.open(rec, n2, out).status == Opened::Status::Forged, "a changed tag does not open");
    rec[n2 - 1] ^= 1;
    o = r.open(rec, n2, out);
    check(o.status == Opened::Status::Ok && o.type == ContentType::Handshake, "the untouched record still opens");

    // \~english Too short for a type and a tag.  \~spanish Demasiado corto para un tipo y una marca.  \~
    uint8_t tiny[5 + 16] = {23, 3, 3, 0, 16};
    check(r.open(tiny, sizeof tiny, out).status == Opened::Status::Forged, "a fragment shorter than 17 cannot open");

    // \~english Empty application data is allowed (5.4).  \~spanish Los datos de aplicacion vacios se admiten (5.4).  \~
    const size_t n3 = w.seal(ContentType::ApplicationData, nullptr, 0, 0, rec, sizeof rec);
    o = r.open(rec, n3, out);
    check(n3 == kRecordOverhead && o.status == Opened::Status::Ok && o.len == 0 && o.type == ContentType::ApplicationData,
          "a zero-length application data record");
}

void test_padding(Crypto &c) {
    where = "padding";
    const Secret s(0x33);
    RecordKeys w;
    RecordKeys r;
    w.install(c, Aead::ChaCha20Poly1305, s.b);
    r.install(c, Aead::ChaCha20Poly1305, s.b);
    const uint8_t msg[3] = {0, 0, 9};
    std::vector<uint8_t> rec(kRecordHeader + kMaxCiphertext + 64);
    std::vector<uint8_t> out(rec.size());
    // \~english Content ending in zeros is not taken for padding: the type byte stands between (5.4).
    // \~spanish Un contenido que acaba en ceros no se toma por relleno: el byte del tipo esta en medio (5.4).  \~
    const uint8_t zeros[4] = {7, 0, 0, 0};
    size_t n = w.seal(ContentType::ApplicationData, zeros, 4, 100, rec.data(), rec.size());
    Opened o = r.open(rec.data(), n, out.data());
    check(n == kRecordOverhead + 4 + 100 && o.status == Opened::Status::Ok && o.len == 4 &&
              std::memcmp(out.data(), zeros, 4) == 0,
          "padding is stripped, content zeros are kept");
    n = w.seal(ContentType::Alert, msg, 3, 0, rec.data(), rec.size());
    o = r.open(rec.data(), n, out.data());
    check(o.status == Opened::Status::Ok && o.type == ContentType::Alert && o.len == 3, "no padding");

    // \~english The largest inner plaintext: 2^14 of content plus the type (5.4).
    // \~spanish El texto interior mas grande: 2^14 de contenido mas el tipo (5.4).  \~
    std::vector<uint8_t> big(kMaxFragment, 0x5a);
    n = w.seal(ContentType::ApplicationData, big.data(), big.size(), 0, rec.data(), rec.size());
    o = r.open(rec.data(), n, out.data());
    check(n != 0 && o.status == Opened::Status::Ok && o.len == kMaxFragment, "2^14 of content, sealed and opened");
    check(w.seal(ContentType::ApplicationData, big.data(), big.size(), 1, rec.data(), rec.size()) == 0,
          "padding past 2^14 + 1 is refused (5.4)");
    check(w.seal(ContentType::ApplicationData, big.data(), 100, kMaxInnerPlaintext - 100, rec.data(), rec.size()) == 0,
          "padding past 2^14 + 1 is refused, however little the content");
    check(w.seal(ContentType::ApplicationData, big.data(), 100, kMaxInnerPlaintext - 101, rec.data(), rec.size()) != 0,
          "padding up to exactly 2^14 + 1 is taken");
    o = r.open(rec.data(), kRecordHeader + kMaxInnerPlaintext + 16, out.data());
    check(o.status == Opened::Status::Ok && o.len == 100, "and it opens");
    big.push_back(1);
    check(w.seal(ContentType::ApplicationData, big.data(), big.size(), 0, rec.data(), rec.size()) == 0,
          "content past 2^14 is refused");
    check(w.seal(ContentType::ApplicationData, msg, 3, 0, rec.data(), kRecordOverhead + 2) == 0, "no room is refused");
}

/// \~english Seals @p inner as it is, bypassing RecordKeys' own checks: for records a peer could send.
/// \~spanish Sella @p inner tal cual, saltandose las comprobaciones de RecordKeys: para registros que podria mandar un otro.  \~
size_t forge(Crypto &c, RecordKeys &k, void *aead, const uint8_t *inner, size_t n, uint8_t *out) {
    out[0] = 23;
    out[1] = 3;
    out[2] = 3;
    out[3] = static_cast<uint8_t>((n + 16) >> 8);
    out[4] = static_cast<uint8_t>(n + 16);
    uint8_t iv[12];
    k.nonce(iv);
    std::memcpy(out + 5, inner, n);
    c.seal(aead, iv, out, 5, out + 5, n, out + 5);
    k.set_sequence(k.sequence() + 1);
    return 5 + n + 16;
}

void test_bad_records(test_support::FakeCrypto &c) {
    where = "bad records";
    const Secret s(0x44);
    RecordKeys w;
    RecordKeys r;
    w.install(c, Aead::Aes128Gcm, s.b);
    r.install(c, Aead::Aes128Gcm, s.b);
    void *aead = c.prepare_aead(Aead::Aes128Gcm, s.b);
    std::vector<uint8_t> rec(kRecordHeader + kMaxCiphertext + 300);
    std::vector<uint8_t> out(rec.size());

    // \~english All zeros: no content type (5.4).  \~spanish Todo ceros: sin tipo de contenido (5.4).  \~
    const uint8_t zeros[9] = {};
    size_t n = forge(c, w, aead, zeros, sizeof zeros, rec.data());
    check(r.open(rec.data(), n, out.data()).status == Opened::Status::NoType, "all padding is unexpected_message (5.4)");
    check(r.sequence() == 0, "and the number does not move");
    r.set_sequence(1);
    // \~english A tag and nothing else authenticates, and has no type: unexpected_message too, not bad_record_mac.
    // \~spanish Una marca y nada mas se autentica, y no tiene tipo: unexpected_message tambien, no bad_record_mac.  \~
    n = forge(c, w, aead, zeros, 0, rec.data());
    check(r.open(rec.data(), n, out.data()).status == Opened::Status::NoType, "an empty inner plaintext has no type");
    w.set_sequence(1);

    // \~english An inner plaintext of 2^14 + 2: record_overflow, even though it opened (5.4).
    // \~spanish Un texto interior de 2^14 + 2: record_overflow, aunque se abriera (5.4).  \~
    std::vector<uint8_t> inner(kMaxInnerPlaintext + 1, 0);
    inner[0] = 23;
    n = forge(c, w, aead, inner.data(), inner.size(), rec.data());
    check(r.open(rec.data(), n, out.data()).status == Opened::Status::Overflow, "2^14 + 2 inside is record_overflow");
    r.set_sequence(2);
    inner.resize(kMaxInnerPlaintext);
    n = forge(c, w, aead, inner.data(), inner.size(), rec.data());
    check(r.open(rec.data(), n, out.data()).status == Opened::Status::Ok, "2^14 + 1 inside is taken");

    // \~english Past 2^14 + 256 outside: refused before any opening (5.2).
    // \~spanish Pasado 2^14 + 256 fuera: se rechaza antes de abrir nada (5.2).  \~
    check(r.open(rec.data(), kRecordHeader + kMaxCiphertext + 1, out.data()).status == Opened::Status::Overflow,
          "a fragment past 2^14 + 256 is record_overflow");

    // \~english A provider that cannot run is this end's failure, not a forgery.
    // \~spanish Un proveedor que no puede ejecutar es fallo de este extremo, no una falsificacion.  \~
    n = w.seal(ContentType::ApplicationData, zeros, 3, 0, rec.data(), rec.size());
    c.broken = true;
    check(r.open(rec.data(), n, out.data()).status == Opened::Status::Failed, "a broken provider is Failed");
    check(w.seal(ContentType::ApplicationData, zeros, 3, 0, rec.data(), rec.size()) == 0, "and seals nothing");
    c.broken = false;
    c.forget(aead);
}

void test_limits(Crypto &c) {
    where = "sequence limits";
    const Secret s(0x55);
    RecordKeys w;
    RecordKeys r;
    w.install(c, Aead::Aes256Gcm, s.b);
    r.install(c, Aead::Aes256Gcm, s.b);
    uint8_t rec[64];
    uint8_t out[64];
    const uint8_t msg[2] = {1, 2};
    // \~english The last usable number, then none: 2^64 - 1 is given up (5.3).
    // \~spanish El ultimo numero usable, y luego ninguno: 2^64 - 1 se deja sin usar (5.3).  \~
    w.set_sequence(~uint64_t{0} - 1);
    r.set_sequence(~uint64_t{0} - 1);
    const size_t n = w.seal(ContentType::ApplicationData, msg, 2, 0, rec, sizeof rec);
    check(n != 0 && r.open(rec, n, out).status == Opened::Status::Ok, "2^64 - 2 is used");
    check(w.exhausted() && r.exhausted(), "and then both are exhausted");
    check(w.seal(ContentType::ApplicationData, msg, 2, 0, rec, sizeof rec) == 0, "an exhausted writer seals nothing");
    check(r.open(rec, n, out).status == Opened::Status::Exhausted, "an exhausted reader opens nothing");
}

void test_update(Crypto &c) {
    where = "key update";
    const Secret s(0x66);
    RecordKeys w;
    RecordKeys r;
    w.install(c, Aead::Aes128Gcm, s.b);
    r.install(c, Aead::Aes128Gcm, s.b);
    uint8_t rec[64];
    uint8_t out[64];
    const uint8_t msg[3] = {4, 5, 6};
    size_t n = w.seal(ContentType::ApplicationData, msg, 3, 0, rec, sizeof rec);
    check(r.open(rec, n, out).status == Opened::Status::Ok, "generation 0");
    check(w.update(), "the writer moves on");
    check(w.sequence() == 0, "the number starts again at zero with the new key (5.3)");
    n = w.seal(ContentType::ApplicationData, msg, 3, 0, rec, sizeof rec);
    check(r.open(rec, n, out).status == Opened::Status::Forged, "the old reader cannot open generation 1");
    check(r.update(), "the reader moves on");
    check(r.open(rec, n, out).status == Opened::Status::Ok, "and now it opens");

    // \~english The next secret is HKDF-Expand-Label(secret, "traffic upd", "", Hash.length) (7.2).
    // \~spanish El secreto siguiente es HKDF-Expand-Label(secreto, "traffic upd", "", Hash.length) (7.2).  \~
    uint8_t next[32];
    check(expand_label(c, http_vx::quic::Hash::Sha256, s.b, "traffic upd", nullptr, 0, next, 32), "derived by hand");
    RecordKeys by_hand;
    by_hand.install(c, Aead::Aes128Gcm, next);
    uint8_t a[12];
    uint8_t b[12];
    by_hand.nonce(a);
    RecordKeys fresh;
    fresh.install(c, Aead::Aes128Gcm, s.b);
    fresh.update();
    fresh.nonce(b);
    check(std::memcmp(a, b, 12) == 0, "update() is the 7.2 derivation");
    RecordKeys none;
    check(!none.update(), "nothing installed, nothing to update");
    w.clear();
    check(!w.installed() && w.sequence() == 0, "clear forgets");
}

/* ------------------------------------------------------------------------- */

/// \~english Seals @p payload and compares it with @p record; then opens @p record.
/// \~spanish Sella @p payload y lo compara con @p record; luego abre @p record.  \~
void trace_record(Crypto &c, const char *secret, const char *iv, uint64_t seq, ContentType type,
                  const std::vector<uint8_t> &payload, const char *record, const char *what) {
    const std::vector<uint8_t> sec = hex(secret);
    const std::vector<uint8_t> want = hex(record);
    RecordKeys k;
    check(k.install(c, Aead::Aes128Gcm, sec.data()), what);
    uint8_t n0[12];
    k.nonce(n0);
    check(rfc8448::same_as(n0, 12, iv), "the IV is the trace's");
    k.set_sequence(seq);
    std::vector<uint8_t> out(payload.size() + kRecordOverhead + 8);
    const size_t n = k.seal(type, payload.data(), payload.size(), 0, out.data(), out.size());
    const bool same = n == want.size() && std::memcmp(out.data(), want.data(), n) == 0;
    if (!same) std::fprintf(stderr, "  sealed %zu bytes, the trace has %zu\n", n, want.size());
    check(same, what);
    RecordKeys r;
    r.install(c, Aead::Aes128Gcm, sec.data());
    r.set_sequence(seq);
    std::vector<uint8_t> plain(want.size());
    const Opened o = r.open(want.data(), want.size(), plain.data());
    check(o.status == Opened::Status::Ok && o.type == type && o.len == payload.size() &&
              std::memcmp(plain.data(), payload.data(), payload.size()) == 0,
          "the trace's record opens to its payload");
}

std::vector<uint8_t> cat(std::initializer_list<const char *> parts) {
    std::vector<uint8_t> v;
    for (const char *p : parts) {
        const std::vector<uint8_t> b = hex(p);
        v.insert(v.end(), b.begin(), b.end());
    }
    return v;
}

void test_rfc8448(Crypto &c, const char *name) {
    where = name;
    // \~english The unprotected ones first: the ClientHello as 0x0301, the ServerHello as 0x0303 (5.1).
    // \~spanish Primero los que van sin proteger: el ClientHello como 0x0301, el ServerHello como 0x0303 (5.1).  \~
    const std::vector<uint8_t> ch = hex(rfc8448::kClientHello);
    std::vector<uint8_t> out(ch.size() + 8);
    size_t n = write_plaintext_record(ContentType::Handshake, kFirstHelloVersion, ch.data(), ch.size(), out.data(), out.size());
    check(n == 201 && rfc8448::same_as(out.data(), 5, "16030100c4") && std::memcmp(out.data() + 5, ch.data(), ch.size()) == 0,
          "the ClientHello record (201 octets)");
    const std::vector<uint8_t> sh = hex(rfc8448::kServerHello);
    n = write_plaintext_record(ContentType::Handshake, kRecordVersion, sh.data(), sh.size(), out.data(), out.size());
    check(n == 95 && rfc8448::same_as(out.data(), 5, "160303005a"), "the ServerHello record (95 octets)");

    const std::vector<uint8_t> flight = cat({rfc8448::kEncryptedExtensions, rfc8448::kCertificate,
                                             rfc8448::kCertificateVerify, rfc8448::kServerFinished});
    check(flight.size() == 657, "the server's flight is 657 octets");
    trace_record(c, rfc8448::kServerHsSecret, rfc8448::kServerHsIv, 0, ContentType::Handshake, flight,
                 rfc8448::kServerFlightRecord, "the server's encrypted flight (679 octets)");
    trace_record(c, rfc8448::kClientHsSecret, rfc8448::kClientHsIv, 0, ContentType::Handshake,
                 hex(rfc8448::kClientFinished), rfc8448::kClientFinishedRecord, "the client's Finished (58 octets)");
    trace_record(c, rfc8448::kServerApSecret, rfc8448::kServerApIv, 0, ContentType::Handshake,
                 hex(rfc8448::kNewSessionTicket), rfc8448::kTicketRecord, "the NewSessionTicket (227 octets)");
    std::vector<uint8_t> data(50);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    trace_record(c, rfc8448::kClientApSecret, rfc8448::kClientApIv, 0, ContentType::ApplicationData, data,
                 rfc8448::kClientDataRecord, "the client's application data (72 octets)");
    trace_record(c, rfc8448::kServerApSecret, rfc8448::kServerApIv, 1, ContentType::ApplicationData, data,
                 rfc8448::kServerDataRecord, "the server's application data, record 1 (72 octets)");
    const std::vector<uint8_t> close_notify = {1, 0};
    trace_record(c, rfc8448::kClientApSecret, rfc8448::kClientApIv, 1, ContentType::Alert, close_notify,
                 rfc8448::kClientAlertRecord, "the client's close_notify, record 1 (24 octets)");
    trace_record(c, rfc8448::kServerApSecret, rfc8448::kServerApIv, 2, ContentType::Alert, close_notify,
                 rfc8448::kServerAlertRecord, "the server's close_notify, record 2 (24 octets)");
}

} // namespace

int main() {
    test_plaintext();
    test_support::FakeCrypto fake;
    test_nonce(fake);
    test_seal_open(fake);
    test_padding(fake);
    test_bad_records(fake);
    test_limits(fake);
    test_update(fake);

    int providers = 0;
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    test_rfc8448(openssl, "rfc 8448, openssl");
    test_seal_open(openssl);
    test_padding(openssl);
    test_update(openssl);
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    if (cng.ready()) {
        test_rfc8448(cng, "rfc 8448, cng");
        test_seal_open(cng);
        test_padding(cng);
        test_update(cng);
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
    if (providers == 0) std::printf("SKIPPED: no real provider built, RFC 8448 records not checked\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls records, %d provider(s): OK\n", providers);
    return 0;
}
