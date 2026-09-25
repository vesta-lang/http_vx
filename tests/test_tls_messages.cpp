/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_tls_messages.cpp
 * @brief
 * \~english TLS 1.3 handshake messages: RFC 8448's read and rebuilt byte for byte, and every refusal.
 * \~spanish Los mensajes del saludo de TLS 1.3: los del RFC 8448 leidos y reconstruidos byte a byte, y cada rechazo.
 * \~
 *
 * \~english
 * Each message of RFC 8448 is read and its fields compared with what the
 * RFC says they are, then written again with the writer and compared byte
 * for byte -- the extensions this code does not send included, as raw
 * ones, in the RFC's order.  Then one message per rule of 4.1 and 4.2, each
 * breaking that rule alone, and the alert it has to end in.
 * \~spanish
 * Cada mensaje del RFC 8448 se lee y sus campos se comparan con lo que el RFC
 * dice que son, y despues se escribe otra vez con el escritor y se compara byte a
 * byte -- incluidas, en crudo y en el orden del RFC, las extensiones que este
 * codigo no manda.  Despues un mensaje por cada regla de 4.1 y 4.2, cada uno
 * rompiendo solo esa regla, y la alerta en la que tiene que acabar.
 * \~
 */

#include "http_vx/tls_messages.h"

#include "tls_rfc8448.h"

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::tls;
using rfc8448::from_hex;
using rfc8448::same_as;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

void expect(Parsed p, Alert want, const char *what) {
    if (p.alert == want) return;
    std::fprintf(stderr, "FAIL: %s (got %s, wanted %s)\n", what, alert_name(p.alert), alert_name(want));
    ++failures;
}

/// \~english A message from the RFC, as bytes.  \~spanish Un mensaje del RFC, como bytes.  \~
struct Msg {
    uint8_t b[1024];
    size_t n;
    explicit Msg(const char *hex) : n(from_hex(hex, b, sizeof b)) {}
};

bool span_is(const uint8_t *m, Span s, const char *hex) {
    return same_as(m + s.off, s.len, hex);
}

void test_framing() {
    Msg ch(rfc8448::kClientHello);
    Handshake t;
    Span body;
    check(frame_message(ch.b, ch.n, t, body) == ch.n && t == Handshake::ClientHello && body.off == 4 &&
              body.len == ch.n - 4,
          "a whole ClientHello was not framed");
    check(frame_message(ch.b, ch.n - 1, t, body) == 0 && frame_message(ch.b, 3, t, body) == 0,
          "a message not all there yet was framed");
}

void test_client_hello() {
    Msg m(rfc8448::kClientHello);
    ClientHello ch;
    expect(parse_client_hello(m.b, m.n, ch), Alert::None, "RFC 8448's ClientHello was refused");
    check(span_is(m.b, ch.random, "cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62"
                                  " 83 02 4d ec e7") &&
              ch.session_id.len == 0 && span_is(m.b, ch.cipher_suites, "13 01 13 03 13 02"),
          "the ClientHello's random, session id or suites are not the RFC's");
    const Extensions &x = ch.ext;
    check(x.has_server_name && span_is(m.b, x.server_name, "73 65 72 76 65 72"), "server_name is not \"server\"");
    check(x.has_supported_groups && x.supported_groups.len == 18, "supported_groups is not the RFC's nine");
    check(x.has_key_share && x.key_shares.len == 36 && read16(m.b + x.key_shares.off) == group::X25519,
          "key_share is not one x25519 share");
    check(x.has_supported_versions && span_is(m.b, x.versions, "03 04"), "supported_versions is not TLS 1.3");
    check(x.has_signature_algorithms && x.signature_algorithms.len == 30, "signature_algorithms is not fifteen");
    check(x.has_psk_modes && span_is(m.b, x.psk_modes, "01"), "psk_key_exchange_modes is not psk_dhe_ke");
    check(!x.has_pre_shared_key && !x.has_alpn && !x.has_early_data && !x.has_transport_parameters,
          "an extension the ClientHello does not carry was reported");

    // \~english Rebuilt, the three this code does not know included raw, in the RFC's order.
    // \~spanish Reconstruido, con las tres que este codigo no conoce en crudo, en el orden del RFC.  \~
    uint8_t out[1024];
    Writer w(out, sizeof out);
    const size_t msg = w.begin_message(Handshake::ClientHello);
    w.u16(kLegacyVersion);
    w.bytes(m.b + ch.random.off, 32);
    w.u8(0);
    const size_t suites = w.open(2);
    w.u16(suite::Aes128GcmSha256);
    w.u16(suite::ChaCha20Poly1305Sha256);
    w.u16(suite::Aes256GcmSha384);
    w.close(suites, 2);
    w.u8(1);
    w.u8(0);
    const size_t exts = w.open(2);
    write_server_name(w, "server", 6);
    const uint8_t reneg[] = {0x00};
    write_raw_extension(w, 0xff01, reneg, 1);
    const uint16_t groups[] = {0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104};
    write_u16_list(w, ext::SupportedGroups, groups, 9);
    write_raw_extension(w, 0x0023, nullptr, 0);
    const uint8_t *key = m.b + x.key_shares.off + 4;
    const size_t key_len = 32;
    const uint16_t share_group = group::X25519;
    write_key_share_client(w, &share_group, &key, &key_len, 1);
    const uint16_t versions[] = {kTls13};
    write_supported_versions_client(w, versions, 1);
    const uint16_t schemes[] = {0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401,
                                0x0501, 0x0601, 0x0201, 0x0402, 0x0502, 0x0602, 0x0202};
    write_u16_list(w, ext::SignatureAlgorithms, schemes, 15);
    const uint8_t modes[] = {1};
    write_psk_modes(w, modes, 1);
    const uint8_t limit[] = {0x40, 0x01};
    write_raw_extension(w, 0x001c, limit, 2);
    w.close(exts, 2);
    w.end_message(msg);
    check(!w.failed() && w.size() == m.n && std::memcmp(out, m.b, m.n) == 0,
          "the ClientHello rebuilt is not the RFC's, byte for byte");
}

void test_server_messages() {
    // \~english ServerHello: x25519 share and TLS 1.3, not a retry.  \~spanish ServerHello: clave x25519 y TLS 1.3, no un reintento.  \~
    Msg m(rfc8448::kServerHello);
    ServerHello sh;
    expect(parse_server_hello(m.b, m.n, sh), Alert::None, "RFC 8448's ServerHello was refused");
    check(!sh.retry && sh.cipher_suite == suite::Aes128GcmSha256 && sh.ext.has_supported_versions &&
              sh.ext.selected_version == kTls13 && sh.ext.has_key_share && sh.ext.share_group == group::X25519 &&
              span_is(m.b, sh.ext.share_key, "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d"
                                             " f1 dd 69 b1 b0 4e 75 1f 0f"),
          "the ServerHello's fields are not the RFC's");
    uint8_t out[1024];
    Writer w(out, sizeof out);
    size_t msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    w.bytes(m.b + sh.random.off, 32);
    w.u8(0);
    w.u16(suite::Aes128GcmSha256);
    w.u8(0);
    size_t exts = w.open(2);
    write_key_share_server(w, group::X25519, m.b + sh.ext.share_key.off, 32);
    write_supported_versions_server(w, kTls13);
    w.close(exts, 2);
    w.end_message(msg);
    check(!w.failed() && w.size() == m.n && std::memcmp(out, m.b, m.n) == 0,
          "the ServerHello rebuilt is not the RFC's, byte for byte");

    // \~english EncryptedExtensions: supported_groups, record_size_limit (unknown here), empty server_name.
    // \~spanish EncryptedExtensions: supported_groups, record_size_limit (desconocida aqui), server_name vacio.  \~
    Msg e(rfc8448::kEncryptedExtensions);
    EncryptedExtensions ee;
    /* \~english
     * record_size_limit (0x1c) is not an extension this code ever asks for,
     * so in a server's message it is unsupported_extension (4.2) -- as it
     * must be for a client that did not send it.
     * \~spanish
     * record_size_limit (0x1c) no es una extension que este codigo pida nunca,
     * asi que en un mensaje del servidor es unsupported_extension (4.2) -- como
     * debe ser para un cliente que no la mando.
     * \~ */
    expect(parse_encrypted_extensions(e.b, e.n, ee), Alert::UnsupportedExtension,
           "an extension never asked for was accepted in EncryptedExtensions");
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::EncryptedExtensions);
    exts = w.open(2);
    const uint16_t groups[] = {0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104};
    write_u16_list(w, ext::SupportedGroups, groups, 9);
    const uint8_t limit[] = {0x40, 0x01};
    write_raw_extension(w, 0x001c, limit, 2);
    write_empty_extension(w, ext::ServerName);
    w.close(exts, 2);
    w.end_message(msg);
    check(!w.failed() && w.size() == e.n && std::memcmp(out, e.b, e.n) == 0,
          "the EncryptedExtensions rebuilt is not the RFC's, byte for byte");
    // \~english Without it, the rest reads: an empty server_name and the groups.
    // \~spanish Sin ella, el resto se lee: un server_name vacio y los grupos.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::EncryptedExtensions);
    exts = w.open(2);
    write_u16_list(w, ext::SupportedGroups, groups, 9);
    write_empty_extension(w, ext::ServerName);
    const char *h3[] = {"h3"};
    write_alpn(w, h3, 1);
    const uint8_t tp[] = {0x01, 0x02, 0x03};
    write_transport_parameters(w, tp, 3);
    w.close(exts, 2);
    w.end_message(msg);
    expect(parse_encrypted_extensions(out, w.size(), ee), Alert::None, "a plain EncryptedExtensions was refused");
    check(ee.ext.has_server_name && ee.ext.server_name.len == 0 && ee.ext.has_supported_groups &&
              ee.ext.has_alpn && span_is(out, ee.ext.alpn, "02 68 33") && ee.ext.has_transport_parameters &&
              span_is(out, ee.ext.transport_parameters, "01 02 03"),
          "the EncryptedExtensions' fields were not read");

    // \~english Certificate: one entry, empty context.  \~spanish Certificate: una entrada, contexto vacio.  \~
    Msg c(rfc8448::kCertificate);
    CertificateMessage cm;
    expect(parse_certificate(c.b, c.n, cm), Alert::None, "RFC 8448's Certificate was refused");
    uint32_t at = 0;
    Span cert;
    check(cm.context.len == 0 && next_certificate(c.b, cm, at, cert) && cert.len == 0x1b0 &&
              c.b[cert.off] == 0x30 && !next_certificate(c.b, cm, at, cert),
          "the Certificate is not one 432-byte DER certificate");
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::Certificate);
    w.u8(0);
    const size_t list = w.open(3);
    const size_t der = w.open(3);
    w.bytes(c.b + 11, 0x1b0);
    w.close(der, 3);
    w.u16(0);
    w.close(list, 3);
    w.end_message(msg);
    check(!w.failed() && w.size() == c.n && std::memcmp(out, c.b, c.n) == 0,
          "the Certificate rebuilt is not the RFC's, byte for byte");

    // \~english CertificateVerify: rsa_pss_rsae_sha256, 128 bytes.  \~spanish CertificateVerify: rsa_pss_rsae_sha256, 128 bytes.  \~
    Msg v(rfc8448::kCertificateVerify);
    CertificateVerify cv;
    expect(parse_certificate_verify(v.b, v.n, cv), Alert::None, "RFC 8448's CertificateVerify was refused");
    check(cv.scheme == scheme::RsaPssRsaeSha256 && cv.signature.len == 128 && cv.signature.off == 8,
          "the CertificateVerify is not rsa_pss_rsae_sha256 with 128 bytes");

    // \~english NewSessionTicket: 30 s, nonce 00 00, a 178-byte ticket, 1024 bytes of early data.
    // \~spanish NewSessionTicket: 30 s, nonce 00 00, un ticket de 178 bytes, 1024 bytes de datos tempranos.  \~
    Msg t(rfc8448::kNewSessionTicket);
    NewSessionTicket nst;
    expect(parse_new_session_ticket(t.b, t.n, nst), Alert::None, "RFC 8448's NewSessionTicket was refused");
    check(nst.lifetime == 30 && nst.age_add == 0xfad6aac5 && span_is(t.b, nst.nonce, "00 00") &&
              nst.ticket.len == 178 && nst.ext.has_early_data && nst.ext.max_early_data == 1024,
          "the NewSessionTicket's fields are not the RFC's");
}

void test_resumed_hello() {
    // \~english RFC 8448, 4: the binders start where the 477-byte prefix the binder hashes ends (4.2.11.2).
    // \~spanish RFC 8448, 4: los binders empiezan donde acaba el prefijo de 477 bytes que resume el binder (4.2.11.2).  \~
    Msg m(rfc8448::kResumedClientHello);
    ClientHello ch;
    expect(parse_client_hello(m.b, m.n, ch), Alert::None, "RFC 8448's resumed ClientHello was refused");
    check(ch.ext.has_pre_shared_key && ch.ext.psk_binders_at == 477 && ch.ext.psk_binders.len == 33 &&
              ch.ext.has_early_data && ch.ext.psk_identities.len == 0xb8,
          "the resumed ClientHello's PSK is not where the RFC puts it");
}

/* \~english
 * Hand-made ClientHellos, one rule broken in each.  ch_start writes a valid
 * start -- TLS 1.2 legacy version, zero random, no session id, one suite,
 * null compression -- and opens the extensions block.
 * \~spanish
 * ClientHellos hechos a mano, una regla rota en cada uno.  ch_start escribe un
 * principio valido -- version heredada TLS 1.2, random a cero, sin session id,
 * un algoritmo, compresion nula -- y abre el bloque de extensiones.
 * \~ */
size_t ch_start(Writer &w, size_t &msg, const uint8_t *compression = nullptr, size_t compression_len = 0) {
    msg = w.begin_message(Handshake::ClientHello);
    w.u16(kLegacyVersion);
    const uint8_t random[32] = {};
    w.bytes(random, 32);
    w.u8(0);
    const size_t suites = w.open(2);
    w.u16(suite::Aes128GcmSha256);
    w.close(suites, 2);
    if (compression == nullptr) {
        w.u8(1);
        w.u8(0);
    } else {
        w.u8(static_cast<uint8_t>(compression_len));
        w.bytes(compression, compression_len);
    }
    return w.open(2);
}

Parsed ch_end(Writer &w, size_t msg, size_t exts) {
    w.close(exts, 2);
    w.end_message(msg);
    ClientHello ch;
    return parse_client_hello(w.data(), w.size(), ch);
}

void test_client_hello_rules() {
    uint8_t out[512];
    size_t msg;
    const uint16_t versions[] = {kTls13};
    const uint16_t groups[] = {group::X25519, group::Secp256r1};
    const uint8_t key[32] = {1};
    const uint8_t *keys[] = {key, key};
    const size_t lens[] = {32, 32};
    const uint8_t modes[] = {1};

    Writer w(out, sizeof out);
    size_t e = ch_start(w, msg);
    write_supported_versions_client(w, versions, 1);
    const uint8_t grease[] = {9, 9};
    write_raw_extension(w, 0x0a0a, grease, 2);
    expect(ch_end(w, msg, e), Alert::None, "a ClientHello with an unknown extension was refused (MUST ignore)");

    // \~english 4.1.2: legacy_compression_methods is exactly one zero byte.
    // \~spanish 4.1.2: legacy_compression_methods es exactamente un byte a cero.  \~
    const uint8_t one[] = {1};
    const uint8_t two[] = {0, 1};
    w = Writer(out, sizeof out);
    e = ch_start(w, msg, one, 1);
    write_supported_versions_client(w, versions, 1);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "a non-null compression was accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg, two, 2);
    write_supported_versions_client(w, versions, 1);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "two compression methods were accepted");

    // \~english 4.2: the same type twice.  \~spanish 4.2: el mismo tipo dos veces.  \~
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_supported_versions_client(w, versions, 1);
    write_supported_versions_client(w, versions, 1);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "a duplicated extension was accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, 0x0a0a, grease, 2);
    write_raw_extension(w, 0x0a0a, grease, 2);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "a duplicated unknown extension was accepted");

    // \~english 4.2: a recognized extension in the wrong message: oid_filters is CertificateRequest's only.
    // \~spanish 4.2: una extension reconocida en el mensaje equivocado: oid_filters es solo de CertificateRequest.  \~
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, 48, nullptr, 0);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "oid_filters was accepted in a ClientHello");

    // \~english 4.2.11: pre_shared_key last, and one binder per identity; 4.2.9: with its modes.
    // \~spanish 4.2.11: pre_shared_key la ultima, y un binder por identidad; 4.2.9: con sus modos.  \~
    uint8_t psk[64];
    size_t p = 0;
    psk[p++] = 0;
    psk[p++] = 7;  // \~english identities: one of 1 byte + age  \~spanish identidades: una de 1 byte + edad  \~
    psk[p++] = 0;
    psk[p++] = 1;
    psk[p++] = 0xaa;
    for (int i = 0; i < 4; ++i) psk[p++] = 0;
    psk[p++] = 0;
    psk[p++] = 33;  // \~english binders: one of 32 bytes  \~spanish binders: uno de 32 bytes  \~
    psk[p++] = 32;
    for (int i = 0; i < 32; ++i) psk[p++] = 0xbb;
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_psk_modes(w, modes, 1);
    write_raw_extension(w, ext::PreSharedKey, psk, p);
    expect(ch_end(w, msg, e), Alert::None, "a well-formed pre_shared_key was refused");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, ext::PreSharedKey, psk, p);
    write_psk_modes(w, modes, 1);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "a pre_shared_key that is not last was accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, ext::PreSharedKey, psk, p);
    expect(ch_end(w, msg, e), Alert::MissingExtension, "a pre_shared_key without its modes was accepted");
    uint8_t psk2[80];
    std::memcpy(psk2, psk, 9);
    psk2[9] = 0;
    psk2[10] = 66;  // \~english two binders for one identity  \~spanish dos binders para una identidad  \~
    for (int i = 0; i < 2; ++i) {
        psk2[11 + 33 * i] = 32;
        std::memset(psk2 + 12 + 33 * i, 0xbb, 32);
    }
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_psk_modes(w, modes, 1);
    write_raw_extension(w, ext::PreSharedKey, psk2, 11 + 66);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "two binders for one identity were accepted");

    // \~english 4.2.8: key shares in supported_groups, in its order, once each.
    // \~spanish 4.2.8: claves en supported_groups, en su orden, una vez cada una.  \~
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_u16_list(w, ext::SupportedGroups, groups, 2);
    write_key_share_client(w, groups, keys, lens, 2);
    expect(ch_end(w, msg, e), Alert::None, "key shares in supported_groups' order were refused");
    const uint16_t reversed[] = {group::Secp256r1, group::X25519};
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_u16_list(w, ext::SupportedGroups, groups, 2);
    write_key_share_client(w, reversed, keys, lens, 2);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "key shares out of supported_groups' order were accepted");
    const uint16_t twice[] = {group::X25519, group::X25519};
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_u16_list(w, ext::SupportedGroups, groups, 2);
    write_key_share_client(w, twice, keys, lens, 2);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "two shares for one group were accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_u16_list(w, ext::SupportedGroups, groups, 1);
    write_key_share_client(w, reversed, keys, lens, 1);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "a share for a group not offered was accepted");

    // \~english RFC 6066, 3: one host_name only.  RFC 7301: no empty protocol name.
    // \~spanish RFC 6066, 3: un solo host_name.  RFC 7301: ningun nombre de protocolo vacio.  \~
    const uint8_t two_names[] = {0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'};
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, ext::ServerName, two_names, sizeof two_names);
    expect(ch_end(w, msg, e), Alert::IllegalParameter, "two host names were accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    const uint8_t alpn_bad[] = {0, 3, 2, 'h', '3', 0};
    write_raw_extension(w, ext::Alpn, alpn_bad, sizeof alpn_bad);
    expect(ch_end(w, msg, e), Alert::DecodeError, "an ALPN list with trailing bytes was accepted");
    const uint8_t alpn_empty[] = {0, 3, 0, 1, 'x'};
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    write_raw_extension(w, ext::Alpn, alpn_empty, sizeof alpn_empty);
    expect(ch_end(w, msg, e), Alert::DecodeError, "an empty protocol name was accepted");

    // \~english Lengths: an odd suite list, a byte after the extensions.
    // \~spanish Longitudes: una lista de algoritmos impar, un byte tras las extensiones.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::ClientHello);
    w.u16(kLegacyVersion);
    const uint8_t random[32] = {};
    w.bytes(random, 32);
    w.u8(0);
    w.u16(3);
    w.u16(0x1301);
    w.u8(0x13);
    w.u8(1);
    w.u8(0);
    w.u16(0);
    w.end_message(msg);
    ClientHello ch;
    expect(parse_client_hello(w.data(), w.size(), ch), Alert::DecodeError, "an odd cipher suite list was accepted");
    w = Writer(out, sizeof out);
    e = ch_start(w, msg);
    w.close(e, 2);
    w.u8(0);
    w.end_message(msg);
    expect(parse_client_hello(w.data(), w.size(), ch), Alert::DecodeError, "a byte after the extensions was accepted");
}

void test_server_rules() {
    uint8_t out[512];
    ServerHello sh;
    EncryptedExtensions ee;

    // \~english A server message: start of a ServerHello with the given random and compression.
    // \~spanish Un mensaje del servidor: el principio de un ServerHello con el random y la compresion dados.  \~
    Writer w(out, sizeof out);
    size_t msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    w.bytes(kHelloRetryRandom, 32);
    w.u8(0);
    w.u16(suite::Aes128GcmSha256);
    w.u8(0);
    size_t e = w.open(2);
    write_supported_versions_server(w, kTls13);
    write_key_share_retry(w, group::Secp256r1);
    const uint8_t cookie[] = {1, 2, 3};
    write_cookie(w, cookie, 3);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_server_hello(out, w.size(), sh), Alert::None, "a HelloRetryRequest was refused");
    check(sh.retry && sh.ext.share_group == group::Secp256r1 && sh.ext.has_cookie,
          "the special random did not make it a HelloRetryRequest");

    // \~english 4.2: pre_shared_key belongs in a ServerHello, not in a HelloRetryRequest.
    // \~spanish 4.2: pre_shared_key va en un ServerHello, no en un HelloRetryRequest.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    w.bytes(kHelloRetryRandom, 32);
    w.u8(0);
    w.u16(suite::Aes128GcmSha256);
    w.u8(0);
    e = w.open(2);
    write_supported_versions_server(w, kTls13);
    write_psk_server(w, 0);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_server_hello(out, w.size(), sh), Alert::IllegalParameter,
           "a pre_shared_key was accepted in a HelloRetryRequest");

    // \~english 4.1.3: legacy_compression_method MUST be 0.  \~spanish 4.1.3: legacy_compression_method DEBE ser 0.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    const uint8_t random[32] = {7};
    w.bytes(random, 32);
    w.u8(0);
    w.u16(suite::Aes128GcmSha256);
    w.u8(1);
    e = w.open(2);
    write_supported_versions_server(w, kTls13);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_server_hello(out, w.size(), sh), Alert::IllegalParameter, "a ServerHello compression of 1 was accepted");

    // \~english 4.3.1 / 4.2: forbidden or unknown extensions in EncryptedExtensions.
    // \~spanish 4.3.1 / 4.2: extensiones prohibidas o desconocidas en EncryptedExtensions.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::EncryptedExtensions);
    e = w.open(2);
    write_key_share_retry(w, group::X25519);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_encrypted_extensions(out, w.size(), ee), Alert::IllegalParameter,
           "a key_share was accepted in EncryptedExtensions");
    const uint8_t name[] = {0, 1};
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::EncryptedExtensions);
    e = w.open(2);
    write_raw_extension(w, ext::ServerName, name, 2);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_encrypted_extensions(out, w.size(), ee), Alert::DecodeError,
           "a server_name with data was accepted in EncryptedExtensions (RFC 6066: SHALL be empty)");
    const char *two[] = {"h3", "h2"};
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::EncryptedExtensions);
    e = w.open(2);
    write_alpn(w, two, 2);
    w.close(e, 2);
    w.end_message(msg);
    expect(parse_encrypted_extensions(out, w.size(), ee), Alert::IllegalParameter,
           "a server ALPN with two protocols was accepted (RFC 7301: exactly one)");

    // \~english 4.4.2: an entry extension this code never asked for.  \~spanish 4.4.2: una extension de entrada que este codigo no pidio nunca.  \~
    w = Writer(out, sizeof out);
    msg = w.begin_message(Handshake::Certificate);
    w.u8(0);
    const size_t list = w.open(3);
    const size_t der = w.open(3);
    w.u8(0x30);
    w.close(der, 3);
    const size_t x = w.open(2);
    write_empty_extension(w, 5);
    w.close(x, 2);
    w.close(list, 3);
    w.end_message(msg);
    CertificateMessage cm;
    expect(parse_certificate(out, w.size(), cm), Alert::UnsupportedExtension,
           "a certificate entry extension never asked for was accepted");
}

void test_writer() {
    uint8_t out[8];
    Writer w(out, sizeof out);
    w.u32(1);
    w.u32(2);
    w.u8(3);
    check(w.failed(), "the writer went past its room");
    uint8_t big[600];
    Writer v(big, sizeof big);
    const size_t m = v.open(1);
    for (int i = 0; i < 256; ++i) v.u8(0);
    v.close(m, 1);
    check(v.failed(), "a vector longer than its length byte could say was closed");
}

} // namespace

int main() {
    test_framing();
    test_client_hello();
    test_server_messages();
    test_resumed_hello();
    test_client_hello_rules();
    test_server_rules();
    test_writer();
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("tls messages: OK\n");
    return 0;
}
