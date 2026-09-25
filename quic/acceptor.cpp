/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/acceptor.cpp
 * @brief
 * \~english Version Negotiation, Retry and its tokens, and the stateless INVALID_TOKEN close.
 * \~spanish Version Negotiation, Retry y sus testigos, y el cierre INVALID_TOKEN sin estado.
 * \~
 */

#include "http_vx/quic_acceptor.h"

#include "http_vx/quic_frame.h"
#include "http_vx/quic_protection.h"
#include "http_vx/quic_varint.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace quic {

/* \~english
 * Every copy here is of an ID or two -- at most twenty bytes -- and goes
 * through the out-of-line memcpy.  Next to the AEAD each datagram costs, the
 * call is nothing; inlined, the copy's branches for large sizes get analysed
 * against these twenty-byte arrays and warn about writes that cannot happen.
 * \~spanish
 * Todas las copias de aqui son de un identificador o dos -- veinte bytes como
 * mucho -- y van por el memcpy fuera de linea.  Al lado del AEAD que cuesta cada
 * datagrama, la llamada no es nada; en linea, las ramas de la copia para tamanos
 * grandes se analizan contra estos arrays de veinte bytes y avisan de escrituras
 * que no pueden ocurrir.
 * \~ */

namespace {

/// \~english The largest token plaintext: time, two IDs with their lengths.
/// \~spanish El mayor texto claro de un testigo: hora, dos identificadores con sus longitudes.  \~
constexpr size_t kTokenPlainMax = 8 + 1 + kMaxConnectionId + 1 + kMaxConnectionId;
constexpr size_t kTokenOverhead = 1 + kNonceSize + kTagSize;

/// \~english The long-header type bits of Initial and Retry, by version (RFC 9369 renumbers them).
/// \~spanish Los bits de tipo de cabecera larga de Initial y Retry, segun la version (el RFC 9369 los renumera).  \~
uint8_t initial_bits(uint32_t v) noexcept { return v == kVersion2 ? 1 : 0; }
uint8_t retry_bits(uint32_t v) noexcept { return v == kVersion2 ? 0 : 3; }

void put32(uint8_t *p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

bool same(const uint8_t *a, const uint8_t *b, size_t n) noexcept {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d = static_cast<uint8_t>(d | (a[i] ^ b[i]));
    return d == 0;
}

} // namespace

const char *admit_reason_name(AdmitReason r) noexcept {
    switch (r) {
    case AdmitReason::Accepted:                   return "accepted";
    case AdmitReason::AcceptedWithToken:          return "accepted-with-token";
    case AdmitReason::SentVersionNegotiation:     return "sent-version-negotiation";
    case AdmitReason::SentRetry:                  return "sent-retry";
    case AdmitReason::SentInvalidToken:           return "sent-invalid-token";
    case AdmitReason::BadHeader:                  return "bad-header";
    case AdmitReason::UnknownConnection:          return "unknown-connection";
    case AdmitReason::NotInitial:                 return "not-initial";
    case AdmitReason::TooSmall:                   return "too-small";
    case AdmitReason::ShortDestination:           return "short-destination";
    case AdmitReason::VersionNegotiationReceived: return "version-negotiation-received";
    case AdmitReason::ProviderFailed:             return "provider-failed";
    case AdmitReason::NotReady:                   return "not-ready";
    case AdmitReason::kCount:                     break;
    }
    return "unknown";
}

Acceptor::Acceptor(Crypto &crypto, const AcceptorConfig &config) noexcept
    : crypto_(crypto), cfg_(config) {
    // \~english A configuration that does not fit leaves the acceptor not ready: nothing is clamped.
    // \~spanish Una configuracion que no cabe deja el acceptor sin preparar: no se recorta nada.  \~
    const size_t max_versions = sizeof cfg_.versions / sizeof cfg_.versions[0];
    if (cfg_.cid_len > kMaxConnectionId || cfg_.version_count == 0 ||
        cfg_.version_count > max_versions)
        return;
    token_state_ = crypto_.prepare_aead(Aead::Aes128Gcm, cfg_.token_key);
}

Acceptor::~Acceptor() {
    if (token_state_ != nullptr) crypto_.forget(token_state_);
}

bool Acceptor::speaks(uint32_t version) const noexcept {
    for (size_t i = 0; i < cfg_.version_count; ++i)
        if (cfg_.versions[i] == version) return true;
    return false;
}

Admission Acceptor::finish(Admission a) noexcept {
    ++counts_[static_cast<size_t>(a.reason)];
    return a;
}

Admission Acceptor::on_datagram(const uint8_t *data, size_t n, const uint8_t *address,
                                size_t address_len, uint64_t now_us, uint8_t *reply,
                                size_t reply_room) noexcept {
    Admission a;
    if (!ready()) {
        a.reason = AdmitReason::NotReady;
        return finish(a);
    }

    HeaderContext ctx;
    ctx.short_dcid_len = cfg_.cid_len;
    PacketHeader h;
    if (parse_packet(data, n, ctx, h) != HeaderError::None) {
        a.reason = AdmitReason::BadHeader;
        return finish(a);
    }

    /* \~english
     * The parser knows every version this code can speak; the configuration may
     * turn some off.  A version turned off is answered exactly like one never
     * heard of.
     * \~spanish
     * El analizador conoce todas las versiones que este codigo sabe hablar; la
     * configuracion puede apagar algunas.  A una version apagada se le contesta
     * igual que a una que nunca se oyo.
     * \~ */
    PacketType type = h.type;
    if (type != PacketType::OneRtt && type != PacketType::VersionNegotiation &&
        type != PacketType::UnsupportedVersion && !speaks(h.version))
        type = PacketType::UnsupportedVersion;

    switch (type) {
    case PacketType::VersionNegotiation:
        a.reason = AdmitReason::VersionNegotiationReceived;
        return finish(a);

    case PacketType::OneRtt:
        a.reason = AdmitReason::UnknownConnection;
        return finish(a);

    case PacketType::UnsupportedVersion:
        /* \~english
         * Only for a datagram big enough to start a connection in some version
         * this server speaks (5.2.2): a small one answered would be a free
         * reflector.  One VN per datagram (17.2.1).
         * \~spanish
         * Solo para un datagrama lo bastante grande para empezar una conexion en
         * alguna version que hable este servidor (5.2.2): uno pequeno contestado
         * seria un reflector gratis.  Un VN por datagrama (17.2.1).
         * \~ */
        if (n < kMinInitialDatagram) {
            a.reason = AdmitReason::TooSmall;
            return finish(a);
        }
        a.reply_len = write_version_negotiation(data, h, reply, reply_room);
        a.verdict = a.reply_len != 0 ? Admit::Reply : Admit::Drop;
        a.reason = a.reply_len != 0 ? AdmitReason::SentVersionNegotiation : AdmitReason::ProviderFailed;
        return finish(a);

    case PacketType::Initial:
        break;

    default:
        // \~english Handshake, 0-RTT or Retry with no connection: nothing to start from.
        // \~spanish Handshake, 0-RTT o Retry sin conexion: nada desde lo que empezar.  \~
        a.reason = AdmitReason::NotInitial;
        return finish(a);
    }

    if (n < kMinInitialDatagram) {
        a.reason = AdmitReason::TooSmall;
        return finish(a);
    }
    if (h.dcid.len < 8) {
        a.reason = AdmitReason::ShortDestination;
        return finish(a);
    }
    // \~english The parser already enforces this for a version spoken; said again where it is relied on.
    // \~spanish El analizador ya lo exige en una version hablada; se repite donde se depende de ello.  \~
    if (h.dcid.len > kMaxConnectionId || h.scid.len > kMaxConnectionId) {
        a.reason = AdmitReason::BadHeader;
        return finish(a);
    }

    a.version = h.version;
    util::vesta_memcpy_noinline(a.dcid, data + h.dcid.off, h.dcid.len);
    a.dcid_len = h.dcid.len;
    util::vesta_memcpy_noinline(a.scid, data + h.scid.off, h.scid.len);
    a.scid_len = h.scid.len;

    /* \~english
     * A token that looks like ours MUST be validated (8.1.3).  If it holds, the
     * address is proven and the original ID comes out of it; if it does not,
     * the client will not take another Retry, so it is told at once with
     * INVALID_TOKEN (8.1.2).  A token in any other format is treated as none.
     * \~spanish
     * Un testigo con pinta de nuestro DEBE validarse (8.1.3).  Si se sostiene, la
     * direccion queda probada y el identificador original sale de el; si no, el
     * cliente no aceptara otro Retry, asi que se le dice en el acto con
     * INVALID_TOKEN (8.1.2).  Un testigo de cualquier otro formato cuenta como
     * ninguno.
     * \~ */
    if (h.token.len != 0 && data[h.token.off] == kRetryTokenMark) {
        if (open_token(data + h.token.off, h.token.len, address, address_len, now_us,
                       a.dcid, a.dcid_len, a)) {
            a.verdict = Admit::Accept;
            a.reason = AdmitReason::AcceptedWithToken;
            a.address_validated = true;
            return finish(a);
        }
        a.reply_len = write_invalid_token(data, h, reply, reply_room);
        a.verdict = a.reply_len != 0 ? Admit::Reply : Admit::Drop;
        a.reason = a.reply_len != 0 ? AdmitReason::SentInvalidToken : AdmitReason::ProviderFailed;
        return finish(a);
    }

    if (cfg_.require_retry) {
        a.reply_len = write_retry(data, h, address, address_len, now_us, reply, reply_room);
        a.verdict = a.reply_len != 0 ? Admit::Reply : Admit::Drop;
        a.reason = a.reply_len != 0 ? AdmitReason::SentRetry : AdmitReason::ProviderFailed;
        return finish(a);
    }

    // \~english No Retry asked for: the original destination is this packet's.
    // \~spanish Sin Retry: el destino original es el de este paquete.  \~
    util::vesta_memcpy_noinline(a.odcid, a.dcid, a.dcid_len);
    a.odcid_len = a.dcid_len;
    a.verdict = Admit::Accept;
    a.reason = AdmitReason::Accepted;
    return finish(a);
}

size_t Acceptor::write_version_negotiation(const uint8_t *data, const PacketHeader &h,
                                           uint8_t *out, size_t room) noexcept {
    const size_t need = 1 + 4 + 1 + h.scid.len + 1 + h.dcid.len + 4 * (cfg_.version_count + 1);
    if (need > room) return 0;

    uint8_t r[5];
    if (!crypto_.random(r, sizeof r)) return 0;

    // \~english The long-header bit, and 0x40 so it looks like QUIC to a demultiplexer (17.2.1).
    // \~spanish El bit de cabecera larga, y 0x40 para que parezca QUIC a un demultiplexor (17.2.1).  \~
    size_t p = 0;
    out[p++] = static_cast<uint8_t>(0xc0 | (r[0] & 0x3f));
    put32(out + p, 0);
    p += 4;

    // \~english Both IDs echoed, swapped: proof that the Initial was seen.
    // \~spanish Los dos identificadores devueltos, cruzados: prueba de que se vio el Initial.  \~
    out[p++] = static_cast<uint8_t>(h.scid.len);
    util::vesta_memcpy_noinline(out + p, data + h.scid.off, h.scid.len);
    p += h.scid.len;
    out[p++] = static_cast<uint8_t>(h.dcid.len);
    util::vesta_memcpy_noinline(out + p, data + h.dcid.off, h.dcid.len);
    p += h.dcid.len;

    for (size_t i = 0; i < cfg_.version_count; ++i) {
        put32(out + p, cfg_.versions[i]);
        p += 4;
    }

    /* \~english
     * One reserved version, 0x?a?a?a?a, so that clients keep ignoring what they
     * do not know (6.3) -- the habit that lets a new version be introduced.
     * \~spanish
     * Una version reservada, 0x?a?a?a?a, para que los clientes sigan ignorando lo
     * que no conocen (6.3) -- la costumbre que deja introducir una version nueva.
     * \~ */
    const uint32_t grease = ((static_cast<uint32_t>(r[1]) << 24 | static_cast<uint32_t>(r[2]) << 16 |
                              static_cast<uint32_t>(r[3]) << 8 | r[4]) &
                             0xf0f0f0f0u) |
                            0x0a0a0a0au;
    put32(out + p, grease);
    p += 4;
    return p;
}

size_t Acceptor::write_retry(const uint8_t *data, const PacketHeader &h, const uint8_t *address,
                             size_t address_len, uint64_t now_us, uint8_t *out,
                             size_t room) noexcept {
    // \~english Every buffer below is sized for twenty-byte IDs.
    // \~spanish Todos los buffers de abajo estan dimensionados para identificadores de veinte bytes.  \~
    if (cfg_.cid_len > kMaxConnectionId || h.dcid.len > kMaxConnectionId) return 0;

    // \~english A new ID of this server's choosing: the one the client will aim at next.
    // \~spanish Un identificador nuevo elegido por este servidor: al que apuntara el cliente despues.  \~
    uint8_t rscid[kMaxConnectionId];
    uint8_t r[1];
    if (!crypto_.random(rscid, cfg_.cid_len) || !crypto_.random(r, 1)) return 0;

    uint8_t plain[kTokenPlainMax];
    size_t pl = 0;
    for (int i = 7; i >= 0; --i) plain[pl++] = static_cast<uint8_t>(now_us >> (8 * i));
    plain[pl++] = static_cast<uint8_t>(h.dcid.len);
    util::vesta_memcpy_noinline(plain + pl, data + h.dcid.off, h.dcid.len);
    pl += h.dcid.len;
    plain[pl++] = static_cast<uint8_t>(cfg_.cid_len);
    util::vesta_memcpy_noinline(plain + pl, rscid, cfg_.cid_len);
    pl += cfg_.cid_len;

    const size_t token_len = kTokenOverhead + pl;
    const size_t need = 1 + 4 + 1 + h.scid.len + 1 + cfg_.cid_len + token_len + kRetryTagSize;
    if (need > room) return 0;

    size_t p = 0;
    out[p++] = static_cast<uint8_t>(0xc0 | (retry_bits(h.version) << 4) | (r[0] & 0x0f));
    put32(out + p, h.version);
    p += 4;
    out[p++] = static_cast<uint8_t>(h.scid.len);
    util::vesta_memcpy_noinline(out + p, data + h.scid.off, h.scid.len);
    p += h.scid.len;
    out[p++] = static_cast<uint8_t>(cfg_.cid_len);
    util::vesta_memcpy_noinline(out + p, rscid, cfg_.cid_len);
    p += cfg_.cid_len;

    /* \~english
     * The token: mark, nonce, then the plaintext sealed with the client's
     * address as associated data -- so it only opens for that address.
     * \~spanish
     * El testigo: marca, nonce, y el texto claro sellado con la direccion del
     * cliente como datos asociados -- asi que solo abre para esa direccion.
     * \~ */
    uint8_t *tok = out + p;
    tok[0] = kRetryTokenMark;
    if (!crypto_.random(tok + 1, kNonceSize)) return 0;
    if (!crypto_.seal(token_state_, tok + 1, address, address_len, plain, pl,
                      tok + 1 + kNonceSize))
        return 0;
    p += token_len;

    // \~english The integrity tag binds the Retry to the client's original ID (RFC 9001, 5.8).
    // \~spanish La marca de integridad ata el Retry al identificador original del cliente (RFC 9001, 5.8).  \~
    uint8_t scratch[1 + kMaxConnectionId + 512];
    if (!retry_tag(crypto_, h.version, data + h.dcid.off, h.dcid.len, out, p, scratch,
                   sizeof scratch, out + p))
        return 0;
    return p + kRetryTagSize;
}

bool Acceptor::open_token(const uint8_t *token, size_t len, const uint8_t *address,
                          size_t address_len, uint64_t now_us, const uint8_t *dcid,
                          size_t dcid_len, Admission &out) noexcept {
    if (len < kTokenOverhead + 8 + 2 || len > kTokenOverhead + kTokenPlainMax) return false;

    uint8_t plain[kTokenPlainMax];
    const size_t pl = len - kTokenOverhead;
    const OpenResult r = crypto_.open(token_state_, token + 1, address, address_len,
                                      token + 1 + kNonceSize, len - 1 - kNonceSize, plain);
    if (r != OpenResult::Ok) return false;

    uint64_t issued = 0;
    for (int i = 0; i < 8; ++i) issued = (issued << 8) | plain[i];

    /* \~english
     * Not from the future, and not older than its lifetime.  The first test is
     * also implied by the second -- from the future, the unsigned difference
     * wraps to more than any lifetime -- and is written anyway, so the rule
     * does not rest on the wrap.
     * \~spanish
     * No del futuro, y no mas viejo que su plazo.  La primera comprobacion ya la
     * implica la segunda -- desde el futuro, la diferencia sin signo da la
     * vuelta a mas que cualquier plazo -- y se escribe igual, para que la regla
     * no dependa de la vuelta.
     * \~ */
    if (issued > now_us || now_us - issued > cfg_.token_lifetime_us) return false;

    size_t p = 8;
    const size_t olen = plain[p++];
    if (olen > kMaxConnectionId || p + olen + 1 > pl) return false;
    const uint8_t *odcid = plain + p;
    p += olen;
    const size_t rlen = plain[p++];
    if (rlen > kMaxConnectionId || p + rlen != pl) return false;

    // \~english The client must be aiming at the ID the Retry gave it (17.2.5.2).
    // \~spanish El cliente tiene que apuntar al identificador que le dio el Retry (17.2.5.2).  \~
    if (rlen != dcid_len || !same(plain + p, dcid, dcid_len)) return false;

    util::vesta_memcpy_noinline(out.odcid, odcid, olen);
    out.odcid_len = olen;
    return true;
}

size_t Acceptor::write_invalid_token(const uint8_t *data, const PacketHeader &h, uint8_t *out,
                                     size_t room) noexcept {
    /* \~english
     * An Initial with CONNECTION_CLOSE(INVALID_TOKEN), sealed with the Initial
     * keys of this packet's destination ID and then forgotten: the server keeps
     * no state and enters no closing period (8.1.2).
     * \~spanish
     * Un Initial con CONNECTION_CLOSE(INVALID_TOKEN), sellado con las claves
     * Initial del identificador de destino de este paquete y luego olvidadas: el
     * servidor no guarda estado ni entra en periodo de cierre (8.1.2).
     * \~ */
    if (cfg_.cid_len > kMaxConnectionId) return 0;
    PacketKeys rk, wk;
    if (!make_initial_keys(crypto_, h.version, data + h.dcid.off, h.dcid.len, true, rk, wk))
        return 0;

    uint8_t scid[kMaxConnectionId];
    size_t p = 0;
    const size_t need = 1 + 4 + 1 + h.scid.len + 1 + cfg_.cid_len + 1 + 2 + 1 + 4 + kTagSize;
    size_t result = 0;
    if (need <= room && crypto_.random(scid, cfg_.cid_len)) {
        out[p++] = static_cast<uint8_t>(0xc0 | (initial_bits(h.version) << 4));
        put32(out + p, h.version);
        p += 4;
        out[p++] = static_cast<uint8_t>(h.scid.len);
        util::vesta_memcpy_noinline(out + p, data + h.scid.off, h.scid.len);
        p += h.scid.len;
        out[p++] = static_cast<uint8_t>(cfg_.cid_len);
        util::vesta_memcpy_noinline(out + p, scid, cfg_.cid_len);
        p += cfg_.cid_len;
        out[p++] = 0;  // \~english no token  \~spanish sin testigo  \~
        const size_t length_at = p;
        p += 2;
        const size_t pn_offset = p;
        const size_t body = write_connection_close(out + pn_offset + 1,
                                                   room - pn_offset - 1 - kTagSize, false,
                                                   static_cast<uint64_t>(TransportError::InvalidToken),
                                                   0, nullptr, 0);
        encode_varint_width(out + length_at, 2, 1 + body + kTagSize);
        if (body != 0 &&
            protect_packet(crypto_, wk, out, pn_offset, 1, 0, body) == Protect::Ok)
            result = pn_offset + 1 + body + kTagSize;
    }
    forget_keys(crypto_, rk);
    forget_keys(crypto_, wk);
    return result;
}

} // namespace quic
} // namespace http_vx
