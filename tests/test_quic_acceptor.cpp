/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_acceptor.cpp
 * @brief
 * \~english The stateless front door: Version Negotiation, Retry, its tokens, and INVALID_TOKEN.
 * \~spanish La puerta de entrada sin estado: Version Negotiation, Retry, sus testigos, e INVALID_TOKEN.
 * \~
 *
 * \~english
 * Every reply is read back the way the other end would read it -- a VN as a
 * list that must echo both IDs, a Retry whose tag is recomputed from the
 * client's original ID, an INVALID_TOKEN close opened with the client's own
 * Initial keys -- so a reply that only looked right would not pass.  And
 * every way a token can fail to hold is tried: another address, past its
 * lifetime, from the future, one bit changed, aimed at another ID.
 * \~spanish
 * Cada respuesta se lee de vuelta como la leeria el otro extremo -- un VN como
 * una lista que tiene que devolver los dos identificadores, un Retry cuya marca
 * se recalcula a partir del identificador original del cliente, un cierre
 * INVALID_TOKEN abierto con las propias claves Initial del cliente --, asi que
 * una respuesta que solo pareciera correcta no pasaria.  Y se prueba cada forma
 * en que un testigo puede no sostenerse: otra direccion, pasado su plazo, del
 * futuro, un bit cambiado, apuntando a otro identificador.
 * \~
 */

#include "http_vx/quic_acceptor.h"
#include "http_vx/quic_frame.h"
#include "http_vx/quic_protection.h"
#include "http_vx/quic_varint.h"

#include "fake_crypto.h"

#if defined(HTTP_VX_HAVE_OPENSSL)
#include "openssl_crypto.h"
#endif
#if defined(HTTP_VX_HAVE_CNG)
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::quic;

int failures = 0;
const char *provider = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", provider, what);
    ++failures;
}

const uint8_t kDcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
const uint8_t kScid[5] = {0xc1, 0x01, 0x02, 0x03, 0x04};
const uint8_t kAddrA[6] = {192, 0, 2, 1, 0x11, 0x5c};
const uint8_t kAddrB[6] = {192, 0, 2, 2, 0x11, 0x5c};

/// \~english A client Initial as far as the acceptor reads it; the payload is filler.
/// \~spanish Un Initial de cliente hasta donde lo lee el acceptor; la carga es relleno.  \~
size_t client_initial(uint8_t *out, size_t total, uint32_t version, const uint8_t *dcid,
                      size_t dcid_len, const uint8_t *token, size_t token_len) {
    size_t p = 0;
    out[p++] = static_cast<uint8_t>(0xc0 | ((version == kVersion2 ? 1 : 0) << 4) | 0x03);
    out[p++] = static_cast<uint8_t>(version >> 24);
    out[p++] = static_cast<uint8_t>(version >> 16);
    out[p++] = static_cast<uint8_t>(version >> 8);
    out[p++] = static_cast<uint8_t>(version);
    out[p++] = static_cast<uint8_t>(dcid_len);
    std::memcpy(out + p, dcid, dcid_len);
    p += dcid_len;
    out[p++] = sizeof kScid;
    std::memcpy(out + p, kScid, sizeof kScid);
    p += sizeof kScid;
    p += encode_varint(out + p, 8, token_len);
    if (token_len) std::memcpy(out + p, token, token_len);
    p += token_len;
    const size_t rest = total - p - 2;
    encode_varint_width(out + p, 2, rest);
    p += 2;
    for (size_t i = 0; i < rest; ++i) out[p + i] = static_cast<uint8_t>(i * 7);
    return total;
}

bool span_is(const uint8_t *base, http_vx::Span s, const uint8_t *want, size_t n) {
    return s.len == n && std::memcmp(base + s.off, want, n) == 0;
}

struct Rig {
    Crypto &c;
    AcceptorConfig cfg;
    uint8_t in[1500];
    uint8_t reply[1500];

    explicit Rig(Crypto &cr) : c(cr) {
        for (size_t i = 0; i < sizeof cfg.token_key; ++i)
            cfg.token_key[i] = static_cast<uint8_t>(0x40 + i);
    }
};

void test_accept_plain(Crypto &c) {
    Rig r(c);
    Acceptor a(c, r.cfg);
    check(a.ready(), "the acceptor is ready");
    const size_t n = client_initial(r.in, 1200, kVersion1, kDcid, 8, nullptr, 0);
    const Admission ad = a.on_datagram(r.in, n, kAddrA, 6, 1000, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Accept && ad.reason == AdmitReason::Accepted,
          "a plain Initial is accepted");
    check(ad.version == kVersion1, "the version is reported");
    check(ad.odcid_len == 8 && std::memcmp(ad.odcid, kDcid, 8) == 0,
          "without a Retry, the original ID is this packet's destination");
    check(ad.dcid_len == 8 && std::memcmp(ad.dcid, kDcid, 8) == 0, "the destination is reported");
    check(ad.scid_len == 5 && std::memcmp(ad.scid, kScid, 5) == 0, "the source is reported");
    check(!ad.address_validated, "no token: the address is not proven");
    check(ad.reply_len == 0, "accepting writes no reply");

    // \~english v2 too, by default.  \~spanish Tambien v2, por defecto.  \~
    client_initial(r.in, 1200, kVersion2, kDcid, 8, nullptr, 0);
    const Admission a2 = a.on_datagram(r.in, 1200, kAddrA, 6, 1000, r.reply, sizeof r.reply);
    check(a2.verdict == Admit::Accept && a2.version == kVersion2, "a v2 Initial is accepted");
    check(a.count(AdmitReason::Accepted) == 2, "both are counted");
}

void test_refusals(Crypto &c) {
    Rig r(c);
    Acceptor a(c, r.cfg);

    client_initial(r.in, 1199, kVersion1, kDcid, 8, nullptr, 0);
    Admission ad = a.on_datagram(r.in, 1199, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::TooSmall,
          "an Initial under 1200 bytes is dropped");

    client_initial(r.in, 1200, kVersion1, kDcid, 7, nullptr, 0);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::ShortDestination,
          "a first destination under 8 bytes is dropped");

    // \~english A Handshake packet: turn the type bits from 0 to 2.
    // \~spanish Un paquete Handshake: los bits de tipo de 0 a 2.  \~
    client_initial(r.in, 1200, kVersion1, kDcid, 8, nullptr, 0);
    r.in[0] = static_cast<uint8_t>((r.in[0] & 0xcf) | 0x20);
    // \~english A Handshake header has no token field: drop the zero length byte.
    // \~spanish Una cabecera Handshake no tiene campo de testigo: fuera el byte de longitud cero.  \~
    std::memmove(r.in + 20, r.in + 21, 1200 - 21);
    encode_varint_width(r.in + 20, 2, 1200 - 1 - 22);
    ad = a.on_datagram(r.in, 1199, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::NotInitial,
          "a Handshake packet with no connection is dropped");

    // \~english With resets switched off, a short header nobody owns is just dropped.
    // \~spanish Con los reinicios apagados, una cabecera corta que no es de nadie simplemente se tira.  \~
    AcceptorConfig no_reset = r.cfg;
    no_reset.send_stateless_reset = false;
    Acceptor quiet(c, no_reset);
    uint8_t shorth[64];
    shorth[0] = 0x41;
    for (size_t i = 1; i < sizeof shorth; ++i) shorth[i] = static_cast<uint8_t>(i);
    ad = quiet.on_datagram(shorth, sizeof shorth, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::UnknownConnection,
          "a short header for no connection was not dropped");
    // \~english Too short to be a packet at all: 1 + 8 + 4 + 16 bytes are needed to sample it.
    // \~spanish Demasiado corto para ser siquiera un paquete: hacen falta 1 + 8 + 4 + 16 bytes para muestrearlo.  \~
    ad = a.on_datagram(shorth, 28, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::BadHeader,
          "a short header too short to be a packet was answered");

    const uint8_t vn[] = {0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb, 0, 0, 0, 1};
    ad = a.on_datagram(vn, sizeof vn, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::VersionNegotiationReceived,
          "a Version Negotiation is never answered");

    const uint8_t junk[] = {0xc0, 0, 0, 0, 1, 30};
    ad = a.on_datagram(junk, sizeof junk, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::BadHeader,
          "an unreadable header is dropped");

    check(a.count(AdmitReason::TooSmall) == 1 && a.count(AdmitReason::ShortDestination) == 1 &&
              a.count(AdmitReason::NotInitial) == 1 &&
              quiet.count(AdmitReason::UnknownConnection) == 1 &&
              a.count(AdmitReason::VersionNegotiationReceived) == 1 &&
              a.count(AdmitReason::BadHeader) == 2,
          "every drop is counted under its reason");
}

/// \~english Checks a VN reply to an Initial of @p version and returns how many versions it lists.
/// \~spanish Comprueba un VN de respuesta a un Initial de @p version y devuelve cuantas versiones lista.  \~
void check_vn(const uint8_t *reply, size_t n, const uint32_t *want, size_t want_n) {
    HeaderContext ctx;
    PacketHeader h;
    check(parse_packet(reply, n, ctx, h) == HeaderError::None, "the VN parses");
    check(h.type == PacketType::VersionNegotiation, "the reply is a Version Negotiation");
    check((reply[0] & 0x80) != 0, "a VN has the long-header bit");
    check(span_is(reply, h.dcid, kScid, sizeof kScid), "the VN is aimed at the client's source ID");
    check(span_is(reply, h.scid, kDcid, 8), "the VN echoes the client's destination ID");
    check(h.versions.len == 4 * (want_n + 1), "the listed versions plus one reserved");
    for (size_t i = 0; i < want_n && h.versions.len >= 4 * (i + 1); ++i) {
        const uint8_t *v = reply + h.versions.off + 4 * i;
        const uint32_t got = static_cast<uint32_t>(v[0]) << 24 | static_cast<uint32_t>(v[1]) << 16 |
                             static_cast<uint32_t>(v[2]) << 8 | v[3];
        check(got == want[i], "the listed version is one the server speaks");
    }
    if (h.versions.len == 4 * (want_n + 1)) {
        const uint8_t *g = reply + h.versions.off + 4 * want_n;
        check((g[0] & 0x0f) == 0x0a && (g[1] & 0x0f) == 0x0a && (g[2] & 0x0f) == 0x0a &&
                  (g[3] & 0x0f) == 0x0a,
              "the last listed version is reserved, 0x?a?a?a?a");
    }
}

void test_version_negotiation(Crypto &c) {
    Rig r(c);
    Acceptor a(c, r.cfg);

    client_initial(r.in, 1200, 0x1a2a3a4b, kDcid, 8, nullptr, 0);
    Admission ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Reply && ad.reason == AdmitReason::SentVersionNegotiation,
          "an unknown version is answered with VN");
    const uint32_t both[2] = {kVersion1, kVersion2};
    check_vn(r.reply, ad.reply_len, both, 2);

    // \~english Small: no reply, or the server would amplify.
    // \~spanish Pequeno: sin respuesta, o el servidor amplificaria.  \~
    ad = a.on_datagram(r.in, 1199, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::TooSmall,
          "a small datagram of an unknown version gets no VN");

    // \~english A version the code knows but the configuration turned off.
    // \~spanish Una version que el codigo conoce pero la configuracion apago.  \~
    AcceptorConfig only1 = r.cfg;
    only1.version_count = 1;
    Acceptor a1(c, only1);
    client_initial(r.in, 1200, kVersion2, kDcid, 8, nullptr, 0);
    ad = a1.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Reply && ad.reason == AdmitReason::SentVersionNegotiation,
          "a version turned off is answered with VN");
    check_vn(r.reply, ad.reply_len, both, 1);

    // \~english No room for the reply: said, not half-written.
    // \~spanish Sin sitio para la respuesta: dicho, no escrito a medias.  \~
    client_initial(r.in, 1200, 0x1a2a3a4b, kDcid, 8, nullptr, 0);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, 10);
    check(ad.verdict == Admit::Drop && ad.reply_len == 0, "no room for a VN: nothing is sent");
}

struct Retried {
    uint8_t token[256];
    size_t token_len = 0;
    uint8_t rscid[kMaxConnectionId];
    size_t rscid_len = 0;
};

/// \~english Sends a first Initial to a Retry-requiring acceptor and checks the Retry as a client would.
/// \~spanish Manda un primer Initial a un acceptor que exige Retry y comprueba el Retry como lo haria un cliente.  \~
bool get_retry(Crypto &c, Acceptor &a, Rig &r, uint32_t version, const uint8_t *addr,
               uint64_t now, Retried &out) {
    client_initial(r.in, 1200, version, kDcid, 8, nullptr, 0);
    const Admission ad = a.on_datagram(r.in, 1200, addr, 6, now, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Reply && ad.reason == AdmitReason::SentRetry,
          "a new client is sent a Retry");
    if (ad.verdict != Admit::Reply) return false;

    HeaderContext ctx;
    PacketHeader h;
    check(parse_packet(r.reply, ad.reply_len, ctx, h) == HeaderError::None, "the Retry parses");
    check(h.type == PacketType::Retry, "the reply is a Retry");
    check(h.version == version, "the Retry keeps the client's version");
    check(span_is(r.reply, h.dcid, kScid, sizeof kScid), "the Retry is aimed at the client's source");
    check(h.scid.len == r.cfg.cid_len, "the Retry's source ID has the server's length");
    check(!span_is(r.reply, h.scid, kDcid, 8), "the Retry's source ID is a new one (17.2.5.1)");
    check(h.token.len > 0 && r.reply[h.token.off] == kRetryTokenMark,
          "the Retry carries a token of this server's");
    check(h.tag.len == kRetryTagSize, "the Retry carries a tag");

    // \~english The tag, recomputed from the client's original ID.
    // \~spanish La marca, recalculada a partir del identificador original del cliente.  \~
    uint8_t scratch[600];
    uint8_t tag[kRetryTagSize];
    check(retry_tag(c, version, kDcid, 8, r.reply, h.tag.off, scratch, sizeof scratch, tag),
          "the tag can be recomputed");
    check(std::memcmp(tag, r.reply + h.tag.off, kRetryTagSize) == 0,
          "the Retry's tag is the one for the client's original ID");

    std::memcpy(out.token, r.reply + h.token.off, h.token.len);
    out.token_len = h.token.len;
    std::memcpy(out.rscid, r.reply + h.scid.off, h.scid.len);
    out.rscid_len = h.scid.len;
    return h.type == PacketType::Retry && h.token.len > 0;
}

/// \~english Opens an INVALID_TOKEN close with the client's keys and checks its frame.
/// \~spanish Abre un cierre INVALID_TOKEN con las claves del cliente y comprueba su trama.  \~
void check_invalid_token(Crypto &c, uint8_t *reply, size_t n, uint32_t version,
                         const uint8_t *dcid, size_t dcid_len) {
    HeaderContext ctx;
    PacketHeader h;
    check(parse_packet(reply, n, ctx, h) == HeaderError::None, "the close parses");
    check(h.type == PacketType::Initial, "the close is an Initial");
    check(h.version == version, "the close keeps the version");
    check(span_is(reply, h.dcid, kScid, sizeof kScid), "the close is aimed at the client");
    PacketKeys rk, wk;
    check(make_initial_keys(c, version, dcid, dcid_len, false, rk, wk),
          "the client's Initial keys");
    Unprotected u;
    const Unprotect up = unprotect_packet(c, rk, reply, h, 0, u);
    check(up == Unprotect::Ok, "the client opens the close with its own Initial keys");
    if (up == Unprotect::Ok) {
        FrameContext fc;
        fc.packet = PacketType::Initial;
        fc.is_server = false;
        FrameReader fr(reply + u.payload.off, u.payload.len, fc);
        Frame f;
        check(fr.next(f) == FrameReader::Step::Frame && f.type == FrameType::ConnectionClose &&
                  !f.application &&
                  f.error_code == static_cast<uint64_t>(TransportError::InvalidToken),
              "the frame is CONNECTION_CLOSE with INVALID_TOKEN");
    }
    forget_keys(c, rk);
    forget_keys(c, wk);
}

void test_retry(Crypto &c, uint32_t version) {
    Rig r(c);
    r.cfg.require_retry = true;
    Acceptor a(c, r.cfg);
    const uint64_t t0 = 5000000;

    Retried rt;
    if (!get_retry(c, a, r, version, kAddrA, t0, rt)) return;

    // \~english The client comes back to the Retry's ID, with the token.
    // \~spanish El cliente vuelve al identificador del Retry, con el testigo.  \~
    client_initial(r.in, 1200, version, rt.rscid, rt.rscid_len, rt.token, rt.token_len);
    Admission ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Accept && ad.reason == AdmitReason::AcceptedWithToken,
          "the token brings the client in");
    check(ad.address_validated, "a token proves the address");
    check(ad.odcid_len == 8 && std::memcmp(ad.odcid, kDcid, 8) == 0,
          "the original ID comes out of the token");
    check(ad.dcid_len == rt.rscid_len && std::memcmp(ad.dcid, rt.rscid, rt.rscid_len) == 0,
          "the destination is the Retry's ID");

    // \~english Exactly at the end of its lifetime it still holds; one microsecond later, not.
    // \~spanish Justo al final de su plazo aun vale; un microsegundo despues, no.  \~
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + r.cfg.token_lifetime_us, r.reply,
                       sizeof r.reply);
    check(ad.verdict == Admit::Accept, "a token at the end of its lifetime holds");
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + r.cfg.token_lifetime_us + 1, r.reply,
                       sizeof r.reply);
    check(ad.verdict == Admit::Reply && ad.reason == AdmitReason::SentInvalidToken,
          "an expired token is refused with INVALID_TOKEN");
    check_invalid_token(c, r.reply, ad.reply_len, version, rt.rscid, rt.rscid_len);

    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 - 1, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentInvalidToken, "a token from the future is refused");

    ad = a.on_datagram(r.in, 1200, kAddrB, 6, t0 + 1000, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentInvalidToken, "a token from another address is refused");

    // \~english Each bit of the token, flipped in turn, after the mark.
    // \~spanish Cada bit del testigo, cambiado por turno, despues de la marca.  \~
    size_t held = 0;
    for (size_t i = 1; i < rt.token_len; ++i) {
        uint8_t bad[256];
        std::memcpy(bad, rt.token, rt.token_len);
        bad[i] ^= static_cast<uint8_t>(1u << (i % 8));
        client_initial(r.in, 1200, version, rt.rscid, rt.rscid_len, bad, rt.token_len);
        if (a.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply).verdict ==
            Admit::Accept)
            ++held;
    }
    check(held == 0, "no token with a bit changed holds");

    // \~english Cut short, or with a byte more.
    // \~spanish Cortado, o con un byte de mas.  \~
    client_initial(r.in, 1200, version, rt.rscid, rt.rscid_len, rt.token, rt.token_len - 1);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentInvalidToken, "a truncated token is refused");
    uint8_t longer[257];
    std::memcpy(longer, rt.token, rt.token_len);
    longer[rt.token_len] = 0;
    client_initial(r.in, 1200, version, rt.rscid, rt.rscid_len, longer, rt.token_len + 1);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentInvalidToken, "a lengthened token is refused");

    // \~english The right token, aimed at another ID: the Retry's ID is bound in.
    // \~spanish El testigo bueno, apuntando a otro identificador: el del Retry va atado.  \~
    uint8_t other[kMaxConnectionId];
    std::memcpy(other, rt.rscid, rt.rscid_len);
    other[0] ^= 1;
    client_initial(r.in, 1200, version, other, rt.rscid_len, rt.token, rt.token_len);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentInvalidToken, "a token aimed at another ID is refused");
    check_invalid_token(c, r.reply, ad.reply_len, version, other, rt.rscid_len);

    // \~english A token of another server's (not ours): treated as none, so another Retry.
    // \~spanish Un testigo de otro servidor (no nuestro): cuenta como ninguno, asi que otro Retry.  \~
    const uint8_t foreign[] = {0x4e, 1, 2, 3, 4, 5, 6, 7};
    client_initial(r.in, 1200, version, kDcid, 8, foreign, sizeof foreign);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, t0, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::SentRetry, "a foreign token is treated as no token");

    // \~english Another server's key does not open this server's tokens.
    // \~spanish La clave de otro servidor no abre los testigos de este.  \~
    AcceptorConfig other_key = r.cfg;
    other_key.token_key[0] ^= 0x80;
    Acceptor stranger(c, other_key);
    client_initial(r.in, 1200, version, rt.rscid, rt.rscid_len, rt.token, rt.token_len);
    ad = stranger.on_datagram(r.in, 1200, kAddrA, 6, t0 + 1000, r.reply, sizeof r.reply);
    if (std::strcmp(c.name(), "fake") != 0)
        check(ad.reason == AdmitReason::SentInvalidToken,
              "a token does not open under another server's key");

    check(a.count(AdmitReason::SentRetry) == 2 && a.count(AdmitReason::AcceptedWithToken) == 2,
          "retries and admissions are counted");
}

void test_token_without_requiring(Crypto &c) {
    // \~english A server that stopped requiring Retry still honours a token it issued.
    // \~spanish Un servidor que dejo de exigir Retry sigue respetando un testigo que emitio.  \~
    Rig r(c);
    r.cfg.require_retry = true;
    Acceptor strict(c, r.cfg);
    Retried rt;
    if (!get_retry(c, strict, r, kVersion1, kAddrA, 100, rt)) return;
    AcceptorConfig lax = r.cfg;
    lax.require_retry = false;
    Acceptor a(c, lax);
    client_initial(r.in, 1200, kVersion1, rt.rscid, rt.rscid_len, rt.token, rt.token_len);
    const Admission ad = a.on_datagram(r.in, 1200, kAddrA, 6, 200, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::AcceptedWithToken && ad.address_validated,
          "a token is honoured even when Retry is not required");
}

/// \~english A short header nobody owns gets a stateless reset the peer can recognise.
/// \~spanish Una cabecera corta que no es de nadie recibe un reinicio sin estado que el otro puede reconocer.  \~
void test_stateless_reset(Crypto &c) {
    Rig r(c);
    for (size_t i = 0; i < kResetKeySize; ++i) r.cfg.reset_key[i] = static_cast<uint8_t>(0x90 + i);
    Acceptor a(c, r.cfg);

    // \~english The token is a function of key and ID: the same twice, different for either change.
    // \~spanish El testigo es funcion de clave e identificador: el mismo dos veces, distinto si cambia cualquiera.  \~
    uint8_t t1[kResetTokenSize], t2[kResetTokenSize], t3[kResetTokenSize], t4[kResetTokenSize];
    uint8_t other_key[kResetKeySize];
    std::memcpy(other_key, r.cfg.reset_key, kResetKeySize);
    other_key[5] ^= 1;
    uint8_t other_cid[8];
    std::memcpy(other_cid, kDcid, 8);
    other_cid[7] ^= 1;
    check(reset_token(c, r.cfg.reset_key, kDcid, 8, t1) && reset_token(c, r.cfg.reset_key, kDcid, 8, t2) &&
              reset_token(c, other_key, kDcid, 8, t3) && reset_token(c, r.cfg.reset_key, other_cid, 8, t4),
          "reset tokens could not be computed");
    check(std::memcmp(t1, t2, kResetTokenSize) == 0, "the same key and ID gave two tokens");
    check(std::memcmp(t1, t3, kResetTokenSize) != 0, "another key gave the same token");
    check(std::memcmp(t1, t4, kResetTokenSize) != 0, "another ID gave the same token");

    // \~english One byte shorter than a small trigger (29 is the smallest short packet with an 8-byte ID);
    // \~english capped for a large one; always ending in the token.
    // \~spanish Un byte mas corto que un paquete pequeno (29 es el paquete corto mas pequeno con un
    // \~spanish identificador de 8 bytes); con tope para uno grande; siempre acabado en el testigo.  \~
    const size_t sizes[3][2] = {{29, 28}, {40, 39}, {1200, 43}};
    for (const auto &sz : sizes) {
        uint8_t in[1200];
        in[0] = 0x43;
        std::memcpy(in + 1, kDcid, 8);
        for (size_t i = 9; i < sz[0]; ++i) in[i] = static_cast<uint8_t>(i * 13);
        const Admission ad = a.on_datagram(in, sz[0], kAddrA, 6, 0, r.reply, sizeof r.reply);
        check(ad.verdict == Admit::Reply && ad.reason == AdmitReason::SentStatelessReset,
              "a short header for no connection was not answered with a reset");
        check(ad.reply_len == sz[1], "the reset does not have the expected size");
        check(ad.reply_len < sz[0], "the reset is not smaller than what caused it");
        check((r.reply[0] & 0xc0) == 0x40, "the reset does not look like a short header");
        check(is_stateless_reset(r.reply, ad.reply_len, t1), "the reset does not end in the ID's token");
        check(!is_stateless_reset(r.reply, ad.reply_len, t4), "the reset matches another ID's token");
    }

    // \~english Recognition: the form matters, and so does every token byte.
    // \~spanish Reconocerlo: la forma importa, y cada byte del testigo tambien.  \~
    uint8_t pkt[43];
    check(write_stateless_reset(c, t1, 44, pkt, sizeof pkt) == 43, "a reset could not be written");
    check(write_stateless_reset(c, t1, kMinStatelessReset, pkt, sizeof pkt) == 0,
          "a reset was written that could not be smaller than its trigger");
    check(write_stateless_reset(c, t1, 44, pkt, 20) == 0, "a reset was written past its room");
    check(write_stateless_reset(c, t1, 44, pkt, sizeof pkt) == 43, "a reset could not be written");
    check(is_stateless_reset(pkt, 43, t1), "a reset was not recognised");
    check(!is_stateless_reset(pkt, kMinStatelessReset - 1, t1), "a datagram under 21 bytes was taken for a reset");
    for (size_t i = 0; i < kResetTokenSize; ++i) {
        uint8_t bad[43];
        std::memcpy(bad, pkt, 43);
        bad[43 - kResetTokenSize + i] ^= 0x10;
        check(!is_stateless_reset(bad, 43, t1), "a reset with one token byte changed was recognised");
    }
    // \~english Sent as a short header, but recognised in any form: other versions may use long ones (10.3).
    // \~spanish Se manda como cabecera corta, pero se reconoce en cualquier forma: otras versiones pueden usar la larga (10.3).  \~
    pkt[0] |= 0x80;
    check(is_stateless_reset(pkt, 43, t1), "a long header ending in the token was not taken for a reset");

    // \~english Switched off, the acceptor answers nothing.
    // \~spanish Apagado, el acceptor no contesta nada.  \~
    AcceptorConfig off = r.cfg;
    off.send_stateless_reset = false;
    Acceptor quiet(c, off);
    uint8_t in[64] = {0x41};
    const Admission ad = quiet.on_datagram(in, sizeof in, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::UnknownConnection,
          "a reset was sent with resets switched off");
}

/**
 * @brief
 * \~english A provider whose random bytes start with a script: to force what chance almost never gives.
 * \~spanish Un proveedor cuyos bytes aleatorios empiezan por un guion: para forzar lo que el azar casi nunca da.
 * \~
 */
class ScriptedRandom final : public Crypto {
public:
    ScriptedRandom(const uint8_t *script, size_t n) : script_(script), left_(n) {}
    test_support::FakeCrypto inner;
    size_t left() const { return left_; }

    const char *name() const noexcept override { return "scripted"; }
    bool supports(Aead a) const noexcept override { return inner.supports(a); }
    bool random(uint8_t *out, size_t n) noexcept override {
        size_t i = 0;
        for (; i < n && left_ != 0; ++i, --left_) out[i] = *script_++;
        return i == n || inner.random(out + i, n - i);
    }
    bool digest(Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept override {
        return inner.digest(h, in, n, out);
    }
    bool extract(Hash h, const uint8_t *s, size_t sl, const uint8_t *k, size_t kl,
                 uint8_t *prk) noexcept override {
        return inner.extract(h, s, sl, k, kl, prk);
    }
    bool expand(Hash h, const uint8_t *prk, size_t pl, const uint8_t *info, size_t il, uint8_t *out,
                size_t ol) noexcept override {
        return inner.expand(h, prk, pl, info, il, out, ol);
    }
    void *prepare_aead(Aead a, const uint8_t *k) noexcept override { return inner.prepare_aead(a, k); }
    void *prepare_hp(Aead a, const uint8_t *k) noexcept override { return inner.prepare_hp(a, k); }
    void forget(void *s) noexcept override { inner.forget(s); }
    bool seal(void *s, const uint8_t *nonce, const uint8_t *ad, size_t al, const uint8_t *in, size_t n,
              uint8_t *out) noexcept override {
        return inner.seal(s, nonce, ad, al, in, n, out);
    }
    OpenResult open(void *s, const uint8_t *nonce, const uint8_t *ad, size_t al, const uint8_t *in, size_t n,
                    uint8_t *out) noexcept override {
        return inner.open(s, nonce, ad, al, in, n, out);
    }
    bool mask(void *s, const uint8_t *sample, uint8_t *out) noexcept override {
        return inner.mask(s, sample, out);
    }
    bool supports(Group g) const noexcept override { return inner.supports(g); }
    void *generate_key(Group g, uint8_t *pub) noexcept override { return inner.generate_key(g, pub); }
    void *import_key(Group g, const uint8_t *priv, size_t pl, const uint8_t *pub) noexcept override {
        return inner.import_key(g, priv, pl, pub);
    }
    Agreed agree(void *k, const uint8_t *peer, size_t pl, uint8_t *shared) noexcept override {
        return inner.agree(k, peer, pl, shared);
    }
    void *signing_key(Scheme s, const uint8_t *p, size_t l) noexcept override { return inner.signing_key(s, p, l); }
    bool sign(void *k, const uint8_t *m, size_t n, uint8_t *sig, size_t room, size_t &len) noexcept override {
        return inner.sign(k, m, n, sig, room, len);
    }
    Verified verify(Scheme s, const uint8_t *c, size_t cl, const uint8_t *m, size_t n, const uint8_t *sig,
                    size_t sl) noexcept override {
        return inner.verify(s, c, cl, m, n, sig, sl);
    }
    void forget_key(void *k) noexcept override { inner.forget_key(k); }

private:
    const uint8_t *script_;
    size_t left_;
};

/// \~english 17.2.5.1: the Retry's source ID "MUST NOT be equal to the Destination Connection ID" the client sent.
/// \~spanish 17.2.5.1: el identificador de origen del Retry "NO DEBE ser igual al Destination Connection ID" del cliente.  \~
void test_retry_id_differs() {
    provider = "scripted";
    ScriptedRandom c(kDcid, sizeof kDcid);
    Rig r(c);
    r.cfg.require_retry = true;
    Acceptor a(c, r.cfg);
    client_initial(r.in, 1200, kVersion1, kDcid, 8, nullptr, 0);
    const Admission ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    HeaderContext hc;
    PacketHeader h;
    check(ad.reason == AdmitReason::SentRetry && parse_packet(r.reply, ad.reply_len, hc, h) == HeaderError::None,
          "no Retry to look at");
    check(c.left() == 0, "the scripted ID was never drawn");
    check(!span_is(r.reply, h.scid, kDcid, 8), "the Retry's source ID equals the client's destination ID");
}

void test_broken_provider() {
    test_support::FakeCrypto c;
    Rig r(c);
    r.cfg.require_retry = true;
    Acceptor a(c, r.cfg);
    c.broken = true;
    client_initial(r.in, 1200, kVersion1, kDcid, 8, nullptr, 0);
    Admission ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::ProviderFailed,
          "a failing provider is said, not sent around");
    client_initial(r.in, 1200, 0x1a2a3a4b, kDcid, 8, nullptr, 0);
    ad = a.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.reason == AdmitReason::ProviderFailed, "and the same for a VN");
}

void test_bad_config(Crypto &c) {
    Rig r(c);
    AcceptorConfig long_id = r.cfg;
    long_id.cid_len = kMaxConnectionId + 1;
    AcceptorConfig no_versions = r.cfg;
    no_versions.version_count = 0;
    AcceptorConfig too_many = r.cfg;
    too_many.version_count = 5;
    Acceptor a1(c, long_id), a2(c, no_versions), a3(c, too_many);
    check(!a1.ready(), "an ID over twenty bytes is refused");
    check(!a2.ready(), "no versions is refused");
    check(!a3.ready(), "more versions than fit is refused");

    // \~english And used anyway, it says so instead of writing past a buffer.
    // \~spanish Y usado de todos modos, lo dice en vez de escribir mas alla de un buffer.  \~
    long_id.require_retry = true;
    Acceptor a4(c, long_id);
    client_initial(r.in, 1200, kVersion1, kDcid, 8, nullptr, 0);
    const Admission ad = a4.on_datagram(r.in, 1200, kAddrA, 6, 0, r.reply, sizeof r.reply);
    check(ad.verdict == Admit::Drop && ad.reason == AdmitReason::NotReady,
          "an acceptor that is not ready drops, and says why");
}

void run_all(Crypto &c) {
    provider = c.name();
    test_bad_config(c);
    test_accept_plain(c);
    test_refusals(c);
    test_version_negotiation(c);
    test_retry(c, kVersion1);
    test_retry(c, kVersion2);
    test_token_without_requiring(c);
    test_stateless_reset(c);
}

} // namespace

int main() {
    test_support::FakeCrypto fake;
    run_all(fake);
    test_broken_provider();
    test_retry_id_differs();

#if defined(HTTP_VX_HAVE_OPENSSL)
    http_vx::OpensslCrypto ossl;
    if (ossl.ready()) run_all(ossl);
    else std::printf("SKIPPED: openssl provider not ready\n");
#else
    std::printf("SKIPPED: openssl provider not built\n");
#endif
#if defined(HTTP_VX_HAVE_CNG)
    http_vx::CngCrypto cng;
    if (cng.ready()) run_all(cng);
    else std::printf("SKIPPED: cng provider not ready (%s)\n", cng.missing());
#else
    std::printf("SKIPPED: cng provider not built\n");
#endif

    if (failures) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::printf("test_quic_acceptor: OK\n");
    return 0;
}
