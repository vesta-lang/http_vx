/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/messages.cpp
 * @brief
 * \~english Reading and writing TLS 1.3 handshake messages (RFC 8446, 4).
 * \~spanish Leer y escribir los mensajes del saludo de TLS 1.3 (RFC 8446, 4).
 * \~
 */

#include "http_vx/tls_messages.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

const uint8_t kHelloRetryRandom[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

const char *alert_name(Alert a) noexcept {
    switch (a) {
    case Alert::None:                  return "none";
    case Alert::UnexpectedMessage:     return "unexpected_message";
    case Alert::HandshakeFailure:      return "handshake_failure";
    case Alert::BadCertificate:        return "bad_certificate";
    case Alert::IllegalParameter:      return "illegal_parameter";
    case Alert::DecodeError:           return "decode_error";
    case Alert::DecryptError:          return "decrypt_error";
    case Alert::ProtocolVersion:       return "protocol_version";
    case Alert::InternalError:         return "internal_error";
    case Alert::MissingExtension:      return "missing_extension";
    case Alert::UnsupportedExtension:  return "unsupported_extension";
    case Alert::NoApplicationProtocol: return "no_application_protocol";
    }
    return "unknown";
}

namespace {

/// \~english The messages the table of 4.2 has a column for.  \~spanish Los mensajes para los que la tabla de 4.2 tiene columna.  \~
enum Kind : uint8_t { kCH = 1, kSH = 2, kHRR = 4, kEE = 8, kCT = 16, kCR = 32, kNST = 64 };

/**
 * @brief
 * \~english Where each extension of the table in 4.2 may appear (plus RFC 9001's, 8.2); 0 if unknown.
 * \~spanish Donde puede aparecer cada extension de la tabla de 4.2 (mas la del RFC 9001, 8.2); 0 si es desconocida.
 * \~
 */
uint8_t allowed_in(uint16_t type) noexcept {
    switch (type) {
    case 0:  return kCH | kEE;         // server_name
    case 1:  return kCH | kEE;         // max_fragment_length
    case 5:  return kCH | kCR | kCT;   // status_request
    case 10: return kCH | kEE;         // supported_groups
    case 13: return kCH | kCR;         // signature_algorithms
    case 14: return kCH | kEE;         // use_srtp
    case 15: return kCH | kEE;         // heartbeat
    case 16: return kCH | kEE;         // application_layer_protocol_negotiation
    case 18: return kCH | kCR | kCT;   // signed_certificate_timestamp
    case 19: return kCH | kEE;         // client_certificate_type
    case 20: return kCH | kEE;         // server_certificate_type
    case 21: return kCH;               // padding
    case 41: return kCH | kSH;         // pre_shared_key
    case 42: return kCH | kEE | kNST;  // early_data
    case 43: return kCH | kSH | kHRR;  // supported_versions
    case 44: return kCH | kHRR;        // cookie
    case 45: return kCH;               // psk_key_exchange_modes
    case 47: return kCH | kCR;         // certificate_authorities
    case 48: return kCR;               // oid_filters
    case 49: return kCH;               // post_handshake_auth
    case 50: return kCH | kCR;         // signature_algorithms_cert
    case 51: return kCH | kSH | kHRR;  // key_share
    case 0x39: return kCH | kEE;       // quic_transport_parameters (RFC 9001, 8.2)
    default: return 0;
    }
}

/// \~english Reads fields front to back; a read past the end marks it bad.
/// \~spanish Lee campos de delante hacia atras; leer pasado el final lo marca como malo.  \~
struct Cursor {
    const uint8_t *m;
    size_t pos;
    size_t end;
    bool bad = false;

    bool has(size_t n) noexcept {
        if (bad || end - pos < n) {
            bad = true;
            return false;
        }
        return true;
    }
    uint8_t u8() noexcept { return has(1) ? m[pos++] : 0; }
    uint16_t u16() noexcept {
        if (!has(2)) return 0;
        const uint16_t v = read16(m + pos);
        pos += 2;
        return v;
    }
    uint32_t u24() noexcept {
        if (!has(3)) return 0;
        const uint32_t v = uint32_t{m[pos]} << 16 | uint32_t{m[pos + 1]} << 8 | m[pos + 2];
        pos += 3;
        return v;
    }
    uint32_t u32() noexcept {
        if (!has(4)) return 0;
        const uint32_t v = uint32_t{m[pos]} << 24 | uint32_t{m[pos + 1]} << 16 | uint32_t{m[pos + 2]} << 8 |
                           m[pos + 3];
        pos += 4;
        return v;
    }
    /// \~english A vector<min..max> with a length of @p width bytes.  \~spanish Un vector<min..max> con una longitud de @p width bytes.  \~
    Span vec(size_t width, size_t min, size_t max) noexcept {
        Span s;
        const size_t len = width == 1 ? u8() : width == 2 ? u16() : u24();
        if (bad || len < min || len > max || !has(len)) {
            bad = true;
            return s;
        }
        s.off = static_cast<uint32_t>(pos);
        s.len = static_cast<uint32_t>(len);
        pos += len;
        return s;
    }
    /// \~english A cursor over @p s alone.  \~spanish Un cursor solo sobre @p s.  \~
    Cursor inside(Span s) const noexcept { return Cursor{m, s.off, s.off + static_cast<size_t>(s.len)}; }
    bool done() const noexcept { return !bad && pos == end; }
};

/// \~english The extension types seen in one block: 65536 bits, so no input can make the check slow.
/// \~spanish Los tipos de extension vistos en un bloque: 65536 bits, asi que ninguna entrada puede hacer lenta la comprobacion.  \~
struct Seen {
    uint64_t bits[1024];
    Seen() noexcept { util::vesta_memset_noinline(bits, 0, sizeof bits); }
    bool add(uint16_t t) noexcept {
        uint64_t &w = bits[t >> 6];
        const uint64_t b = uint64_t{1} << (t & 63);
        if ((w & b) != 0) return false;
        w |= b;
        return true;
    }
};

/// \~english A list of uint16 values: even length, within bounds.  \~spanish Una lista de valores uint16: longitud par, dentro de los limites.  \~
bool u16_list(Cursor &c, size_t width, size_t min, size_t max, Span &out) noexcept {
    out = c.vec(width, min, max);
    return !c.bad && out.len % 2 == 0;
}

/**
 * @brief
 * \~english Reads one extension's data into @p x, as the message @p kind lays it out.
 * \~spanish Lee los datos de una extension en @p x, como los dispone el mensaje @p kind.
 * \~
 */
Alert read_extension(const uint8_t *m, uint16_t type, Span data, Kind kind, Extensions &x) noexcept {
    Cursor c{m, data.off, data.off + static_cast<size_t>(data.len)};
    switch (type) {
    case ext::ServerName:
        x.has_server_name = true;
        if (kind == kEE) return data.len == 0 ? Alert::None : Alert::DecodeError;  // RFC 6066, 3: SHALL be empty
        {
            // \~english ServerNameList<1..2^16-1>; at most one host_name (RFC 6066, 3).
            // \~spanish ServerNameList<1..2^16-1>; como mucho un host_name (RFC 6066, 3).  \~
            Cursor list = c.inside(c.vec(2, 1, 0xffff));
            bool host = false;
            while (!list.bad && list.pos < list.end) {
                const uint8_t name_type = list.u8();
                const Span name = list.vec(2, 1, 0xffff);
                if (list.bad) break;
                if (name_type != 0) continue;  // \~english future types: 16-bit length, skipped  \~spanish tipos futuros: longitud de 16 bits, se saltan  \~
                if (host) return Alert::IllegalParameter;
                host = true;
                x.server_name = name;
            }
            if (list.bad || !c.done()) return Alert::DecodeError;
        }
        return Alert::None;
    case ext::SupportedGroups:
        x.has_supported_groups = true;
        return u16_list(c, 2, 2, 0xffff, x.supported_groups) && c.done() ? Alert::None : Alert::DecodeError;
    case ext::SignatureAlgorithms:
        x.has_signature_algorithms = true;
        return u16_list(c, 2, 2, 0xfffe, x.signature_algorithms) && c.done() ? Alert::None : Alert::DecodeError;
    case ext::Alpn: {
        // \~english ProtocolNameList<2..2^16-1> of ProtocolName<1..2^8-1> (RFC 7301, 3.1).
        // \~spanish ProtocolNameList<2..2^16-1> de ProtocolName<1..2^8-1> (RFC 7301, 3.1).  \~
        x.has_alpn = true;
        x.alpn = c.vec(2, 2, 0xffff);
        if (!c.done()) return Alert::DecodeError;
        Cursor names = c.inside(x.alpn);
        size_t count = 0;
        while (!names.bad && names.pos < names.end) {
            names.vec(1, 1, 0xff);
            ++count;
        }
        if (names.bad) return Alert::DecodeError;
        // \~english The server's has exactly one (RFC 7301, 3.1).  \~spanish El del servidor tiene exactamente uno (RFC 7301, 3.1).  \~
        return kind == kEE && count != 1 ? Alert::IllegalParameter : Alert::None;
    }
    case ext::PreSharedKey:
        x.has_pre_shared_key = true;
        if (kind == kSH) {
            x.psk_selected = c.u16();
            return c.done() ? Alert::None : Alert::DecodeError;
        }
        {
            // \~english OfferedPsks: identities<7..2^16-1>, binders<33..2^16-1> (4.2.11).
            // \~spanish OfferedPsks: identities<7..2^16-1>, binders<33..2^16-1> (4.2.11).  \~
            x.psk_identities = c.vec(2, 7, 0xffff);
            x.psk_binders_at = static_cast<uint32_t>(c.pos);
            x.psk_binders = c.vec(2, 33, 0xffff);
            if (!c.done()) return Alert::DecodeError;
            size_t identities = 0;
            size_t binders = 0;
            Cursor id = c.inside(x.psk_identities);
            while (!id.bad && id.pos < id.end) {
                id.vec(2, 1, 0xffff);
                id.u32();
                ++identities;
            }
            Cursor b = c.inside(x.psk_binders);
            while (!b.bad && b.pos < b.end) {
                b.vec(1, 32, 0xff);
                ++binders;
            }
            if (id.bad || b.bad) return Alert::DecodeError;
            // \~english One binder per identity, in the same order (4.2.11).
            // \~spanish Un binder por identidad, en el mismo orden (4.2.11).  \~
            return identities == binders ? Alert::None : Alert::IllegalParameter;
        }
    case ext::EarlyData:
        x.has_early_data = true;
        if (kind == kNST) {
            x.max_early_data = c.u32();
            return c.done() ? Alert::None : Alert::DecodeError;
        }
        return data.len == 0 ? Alert::None : Alert::DecodeError;
    case ext::SupportedVersions:
        x.has_supported_versions = true;
        if (kind == kCH) return u16_list(c, 1, 2, 254, x.versions) && c.done() ? Alert::None : Alert::DecodeError;
        x.selected_version = c.u16();
        return c.done() ? Alert::None : Alert::DecodeError;
    case ext::Cookie:
        x.has_cookie = true;
        x.cookie = c.vec(2, 1, 0xffff);
        return c.done() ? Alert::None : Alert::DecodeError;
    case ext::PskKeyExchangeModes:
        x.has_psk_modes = true;
        x.psk_modes = c.vec(1, 1, 0xff);
        return c.done() ? Alert::None : Alert::DecodeError;
    case ext::KeyShare:
        x.has_key_share = true;
        if (kind == kHRR) {
            x.share_group = c.u16();
            return c.done() ? Alert::None : Alert::DecodeError;
        }
        if (kind == kSH) {
            x.share_group = c.u16();
            x.share_key = c.vec(2, 1, 0xffff);
            return c.done() ? Alert::None : Alert::DecodeError;
        }
        {
            x.key_shares = c.vec(2, 0, 0xffff);
            if (!c.done()) return Alert::DecodeError;
            Cursor e = c.inside(x.key_shares);
            while (!e.bad && e.pos < e.end) {
                e.u16();
                e.vec(2, 1, 0xffff);
            }
            return e.bad ? Alert::DecodeError : Alert::None;
        }
    case ext::QuicTransportParameters:
        x.has_transport_parameters = true;
        x.transport_parameters = data;
        return Alert::None;
    default:
        // \~english Known to the table, not read here: its placement was checked, its content is not ours.
        // \~spanish Conocida por la tabla, no se lee aqui: su lugar se comprobo, su contenido no es nuestro.  \~
        return Alert::None;
    }
}

/**
 * @brief
 * \~english Reads an extensions block for message @p kind.
 * \~spanish Lee un bloque de extensiones para el mensaje @p kind.
 * \~
 */
Alert read_extensions(const uint8_t *m, Span block, Kind kind, Extensions &x) noexcept {
    Cursor c{m, block.off, block.off + static_cast<size_t>(block.len)};
    Seen seen;
    /* \~english
     * The client reads what the server sends: it only ever asks for what it
     * knows (4.2).  A CertificateRequest is the server ASKING, and there the
     * client MUST ignore what it does not recognize (4.3.2).
     * \~spanish
     * El cliente lee lo que manda el servidor: solo pide lo que conoce (4.2).  Un
     * CertificateRequest es el servidor PIDIENDO, y ahi el cliente DEBE ignorar
     * lo que no reconoce (4.3.2).
     * \~ */
    const bool tolerate_unknown = kind == kCH || kind == kNST || kind == kCR;
    while (!c.bad && c.pos < c.end) {
        const uint16_t type = c.u16();
        const Span data = c.vec(2, 0, 0xffff);
        if (c.bad) return Alert::DecodeError;
        // \~english One of each type per block (4.2).  \~spanish Una de cada tipo por bloque (4.2).  \~
        if (!seen.add(type)) return Alert::IllegalParameter;
        const uint8_t where = allowed_in(type);
        if (where == 0) {
            if (tolerate_unknown) continue;
            return Alert::UnsupportedExtension;
        }
        // \~english Recognized, but not for this message (4.2: MUST).  \~spanish Reconocida, pero no para este mensaje (4.2: DEBE).  \~
        if ((where & kind) == 0) return Alert::IllegalParameter;
        // \~english pre_shared_key MUST be the ClientHello's last extension (4.2.11).
        // \~spanish pre_shared_key DEBE ser la ultima extension del ClientHello (4.2.11).  \~
        if (type == ext::PreSharedKey && kind == kCH && c.pos != c.end) return Alert::IllegalParameter;
        const Alert a = read_extension(m, type, data, kind, x);
        if (a != Alert::None) return a;
    }
    return c.bad ? Alert::DecodeError : Alert::None;
}

/// \~english Whether the uint16 @p v is in the list at @p s.  \~spanish Si el uint16 @p v esta en la lista de @p s.  \~
bool in_list(const uint8_t *m, Span s, uint16_t v, size_t &index) noexcept {
    for (uint32_t i = 0; i + 1 < s.len; i += 2)
        if (read16(m + s.off + i) == v) {
            index = i / 2;
            return true;
        }
    return false;
}

/**
 * @brief
 * \~english The key_share rules a server MAY check (4.2.8): one share per group, each in supported_groups, in its order.
 * \~spanish Las reglas de key_share que un servidor PUEDE comprobar (4.2.8): una clave por grupo, cada una en supported_groups, en su orden.
 * \~
 */
Alert check_key_shares(const uint8_t *m, const Extensions &x) noexcept {
    Cursor e{m, x.key_shares.off, x.key_shares.off + static_cast<size_t>(x.key_shares.len)};
    size_t last = 0;
    bool first = true;
    while (e.pos < e.end) {
        const uint16_t g = e.u16();
        e.vec(2, 1, 0xffff);
        size_t at = 0;
        if (!x.has_supported_groups || !in_list(m, x.supported_groups, g, at)) return Alert::IllegalParameter;
        // \~english Strictly later in supported_groups: same order, and no group twice.
        // \~spanish Estrictamente despues en supported_groups: mismo orden, y ningun grupo dos veces.  \~
        if (!first && at <= last) return Alert::IllegalParameter;
        last = at;
        first = false;
    }
    return Alert::None;
}

/// \~english The body of a message starts after its four-byte header.  \~spanish El cuerpo de un mensaje empieza tras su cabecera de cuatro bytes.  \~
Cursor body(const uint8_t *m, size_t n) noexcept {
    return Cursor{m, 4, n};
}

} // namespace

size_t frame_message(const uint8_t *data, size_t n, Handshake &type, Span &body_out) noexcept {
    if (n < 4) return 0;
    const size_t len = size_t{data[1]} << 16 | size_t{data[2]} << 8 | data[3];
    if (n - 4 < len) return 0;
    type = static_cast<Handshake>(data[0]);
    body_out.off = 4;
    body_out.len = static_cast<uint32_t>(len);
    return 4 + len;
}

Parsed parse_client_hello(const uint8_t *m, size_t n, ClientHello &out) noexcept {
    Parsed p;
    out = ClientHello{};
    Cursor c = body(m, n);
    c.u16();  // \~english legacy_version: only supported_versions counts (4.2.1)  \~spanish legacy_version: solo cuenta supported_versions (4.2.1)  \~
    if (c.has(32)) {
        out.random.off = static_cast<uint32_t>(c.pos);
        out.random.len = 32;
        c.pos += 32;
    }
    out.session_id = c.vec(1, 0, 32);
    if (!u16_list(c, 2, 2, 0xfffe, out.cipher_suites)) {
        p.alert = Alert::DecodeError;
        return p;
    }
    const Span compression = c.vec(1, 1, 0xff);
    if (c.bad) {
        p.alert = Alert::DecodeError;
        return p;
    }
    // \~english Exactly one byte, zero; anything else MUST be illegal_parameter (4.1.2).
    // \~spanish Exactamente un byte, cero; cualquier otra cosa DEBE ser illegal_parameter (4.1.2).  \~
    if (compression.len != 1 || m[compression.off] != 0) {
        p.alert = Alert::IllegalParameter;
        return p;
    }
    // \~english No extensions at all is a pre-1.3 ClientHello: parsed, and the state machine refuses it.
    // \~spanish Ninguna extension es un ClientHello anterior a 1.3: se lee, y la maquina de estados lo rechaza.  \~
    if (c.pos == c.end) return p;
    const Span exts = c.vec(2, 0, 0xffff);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    p.alert = read_extensions(m, exts, kCH, out.ext);
    if (!p.ok()) return p;
    // \~english A PSK without its modes MUST abort (4.2.9).  \~spanish Una PSK sin sus modos DEBE abortar (4.2.9).  \~
    if (out.ext.has_pre_shared_key && !out.ext.has_psk_modes) {
        p.alert = Alert::MissingExtension;
        return p;
    }
    if (out.ext.has_key_share) p.alert = check_key_shares(m, out.ext);
    return p;
}

Parsed parse_server_hello(const uint8_t *m, size_t n, ServerHello &out) noexcept {
    Parsed p;
    out = ServerHello{};
    Cursor c = body(m, n);
    c.u16();
    if (c.has(32)) {
        out.random.off = static_cast<uint32_t>(c.pos);
        out.random.len = 32;
        c.pos += 32;
    }
    out.session_id = c.vec(1, 0, 32);
    out.cipher_suite = c.u16();
    const uint8_t compression = c.u8();
    const Span exts = c.vec(2, 0, 0xffff);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    // \~english legacy_compression_method MUST be 0 (4.1.3).  \~spanish legacy_compression_method DEBE ser 0 (4.1.3).  \~
    if (compression != 0) {
        p.alert = Alert::IllegalParameter;
        return p;
    }
    // \~english The special random makes it a HelloRetryRequest, and that is looked at FIRST (4.1.3).
    // \~spanish El random especial lo convierte en un HelloRetryRequest, y eso se mira PRIMERO (4.1.3).  \~
    out.retry = true;
    for (size_t i = 0; i < 32; ++i)
        if (m[out.random.off + i] != kHelloRetryRandom[i]) out.retry = false;
    p.alert = read_extensions(m, exts, out.retry ? kHRR : kSH, out.ext);
    return p;
}

Parsed parse_encrypted_extensions(const uint8_t *m, size_t n, EncryptedExtensions &out) noexcept {
    Parsed p;
    out = EncryptedExtensions{};
    Cursor c = body(m, n);
    const Span exts = c.vec(2, 0, 0xffff);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    p.alert = read_extensions(m, exts, kEE, out.ext);
    return p;
}

Parsed parse_certificate(const uint8_t *m, size_t n, CertificateMessage &out) noexcept {
    Parsed p;
    out = CertificateMessage{};
    Cursor c = body(m, n);
    out.context = c.vec(1, 0, 0xff);
    out.entries = c.vec(3, 0, 0xffffff);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    Cursor e = c.inside(out.entries);
    while (!e.bad && e.pos < e.end) {
        e.vec(3, 1, 0xffffff);
        const Span exts = e.vec(2, 0, 0xffff);
        /* \~english
         * Extensions here MUST correspond to ones the peer asked for (4.4.2),
         * and this code asks for none: any is unsupported_extension.
         * \~spanish
         * Las extensiones de aqui DEBEN corresponder a las que pidio el otro
         * (4.4.2), y este codigo no pide ninguna: cualquiera es
         * unsupported_extension.
         * \~ */
        if (!e.bad && exts.len != 0) {
            p.alert = Alert::UnsupportedExtension;
            return p;
        }
    }
    if (e.bad) p.alert = Alert::DecodeError;
    return p;
}

bool next_certificate(const uint8_t *m, const CertificateMessage &c, uint32_t &at, Span &cert) noexcept {
    Cursor e{m, c.entries.off, c.entries.off + static_cast<size_t>(c.entries.len)};
    e.pos = at == 0 ? c.entries.off : at;
    if (e.pos >= e.end) return false;
    cert = e.vec(3, 1, 0xffffff);
    e.vec(2, 0, 0xffff);
    if (e.bad) return false;
    at = static_cast<uint32_t>(e.pos);
    return true;
}

Parsed parse_certificate_request(const uint8_t *m, size_t n, CertificateRequest &out) noexcept {
    Parsed p;
    out = CertificateRequest{};
    Cursor c = body(m, n);
    // \~english context<0..2^8-1>, extensions<2..2^16-1> (4.3.2).  \~spanish context<0..2^8-1>, extensions<2..2^16-1> (4.3.2).  \~
    out.context = c.vec(1, 0, 0xff);
    const Span exts = c.vec(2, 2, 0xffff);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    p.alert = read_extensions(m, exts, kCR, out.ext);
    // \~english signature_algorithms MUST be specified (4.3.2).  \~spanish signature_algorithms DEBE estar (4.3.2).  \~
    if (p.ok() && !out.ext.has_signature_algorithms) p.alert = Alert::MissingExtension;
    return p;
}

Parsed parse_certificate_verify(const uint8_t *m, size_t n, CertificateVerify &out) noexcept {
    Parsed p;
    out = CertificateVerify{};
    Cursor c = body(m, n);
    out.scheme = c.u16();
    out.signature = c.vec(2, 0, 0xffff);
    if (!c.done()) p.alert = Alert::DecodeError;
    return p;
}

Parsed parse_new_session_ticket(const uint8_t *m, size_t n, NewSessionTicket &out) noexcept {
    Parsed p;
    out = NewSessionTicket{};
    Cursor c = body(m, n);
    out.lifetime = c.u32();
    out.age_add = c.u32();
    out.nonce = c.vec(1, 0, 0xff);
    out.ticket = c.vec(2, 1, 0xffff);
    const Span exts = c.vec(2, 0, 0xfffe);
    if (!c.done()) {
        p.alert = Alert::DecodeError;
        return p;
    }
    p.alert = read_extensions(m, exts, kNST, out.ext);
    return p;
}

void Writer::u8(uint8_t v) noexcept {
    if (failed_ || room_ - len_ < 1) {
        failed_ = true;
        return;
    }
    buf_[len_++] = v;
}

void Writer::u16(uint16_t v) noexcept {
    u8(static_cast<uint8_t>(v >> 8));
    u8(static_cast<uint8_t>(v));
}

void Writer::u24(uint32_t v) noexcept {
    u8(static_cast<uint8_t>(v >> 16));
    u16(static_cast<uint16_t>(v));
}

void Writer::u32(uint32_t v) noexcept {
    u16(static_cast<uint16_t>(v >> 16));
    u16(static_cast<uint16_t>(v));
}

void Writer::bytes(const void *p, size_t n) noexcept {
    if (failed_ || room_ - len_ < n) {
        failed_ = true;
        return;
    }
    if (n != 0) util::vesta_memcpy(buf_ + len_, p, n);
    len_ += n;
}

size_t Writer::open(size_t width) noexcept {
    const size_t mark = len_;
    for (size_t i = 0; i < width; ++i) u8(0);
    return mark;
}

void Writer::close(size_t mark, size_t width) noexcept {
    if (failed_) return;
    const size_t len = len_ - mark - width;
    // \~english A vector longer than its length field can say is a failure, never a truncation.
    // \~spanish Un vector mas largo de lo que su campo de longitud puede decir es un fallo, nunca un recorte.  \~
    if (len >> (8 * width) != 0) {
        failed_ = true;
        return;
    }
    for (size_t i = 0; i < width; ++i) buf_[mark + i] = static_cast<uint8_t>(len >> (8 * (width - 1 - i)));
}

size_t Writer::begin_message(Handshake t) noexcept {
    u8(static_cast<uint8_t>(t));
    return open(3);
}

size_t Writer::begin_extension(uint16_t type) noexcept {
    u16(type);
    return open(2);
}

void write_server_name(Writer &w, const char *host, size_t len) noexcept {
    const size_t e = w.begin_extension(ext::ServerName);
    const size_t list = w.open(2);
    w.u8(0);  // \~english host_name  \~spanish host_name  \~
    const size_t name = w.open(2);
    w.bytes(host, len);
    w.close(name, 2);
    w.close(list, 2);
    w.close(e, 2);
}

void write_empty_extension(Writer &w, uint16_t type) noexcept {
    w.close(w.begin_extension(type), 2);
}

void write_u16_list(Writer &w, uint16_t type, const uint16_t *v, size_t count) noexcept {
    const size_t e = w.begin_extension(type);
    const size_t list = w.open(2);
    for (size_t i = 0; i < count; ++i) w.u16(v[i]);
    w.close(list, 2);
    w.close(e, 2);
}

void write_supported_versions_client(Writer &w, const uint16_t *v, size_t count) noexcept {
    const size_t e = w.begin_extension(ext::SupportedVersions);
    const size_t list = w.open(1);
    for (size_t i = 0; i < count; ++i) w.u16(v[i]);
    w.close(list, 1);
    w.close(e, 2);
}

void write_supported_versions_server(Writer &w, uint16_t version) noexcept {
    const size_t e = w.begin_extension(ext::SupportedVersions);
    w.u16(version);
    w.close(e, 2);
}

void write_alpn(Writer &w, const char *const *names, size_t count) noexcept {
    const size_t e = w.begin_extension(ext::Alpn);
    const size_t list = w.open(2);
    for (size_t i = 0; i < count; ++i) {
        size_t len = 0;
        while (names[i][len] != '\0') ++len;
        const size_t name = w.open(1);
        w.bytes(names[i], len);
        w.close(name, 1);
    }
    w.close(list, 2);
    w.close(e, 2);
}

void write_psk_modes(Writer &w, const uint8_t *modes, size_t count) noexcept {
    const size_t e = w.begin_extension(ext::PskKeyExchangeModes);
    const size_t list = w.open(1);
    w.bytes(modes, count);
    w.close(list, 1);
    w.close(e, 2);
}

void write_key_share_client(Writer &w, const uint16_t *groups, const uint8_t *const *keys,
                            const size_t *key_lens, size_t count) noexcept {
    const size_t e = w.begin_extension(ext::KeyShare);
    const size_t list = w.open(2);
    for (size_t i = 0; i < count; ++i) {
        w.u16(groups[i]);
        const size_t key = w.open(2);
        w.bytes(keys[i], key_lens[i]);
        w.close(key, 2);
    }
    w.close(list, 2);
    w.close(e, 2);
}

void write_key_share_server(Writer &w, uint16_t group, const uint8_t *key, size_t key_len) noexcept {
    const size_t e = w.begin_extension(ext::KeyShare);
    w.u16(group);
    const size_t k = w.open(2);
    w.bytes(key, key_len);
    w.close(k, 2);
    w.close(e, 2);
}

void write_key_share_retry(Writer &w, uint16_t group) noexcept {
    const size_t e = w.begin_extension(ext::KeyShare);
    w.u16(group);
    w.close(e, 2);
}

void write_cookie(Writer &w, const uint8_t *cookie, size_t len) noexcept {
    const size_t e = w.begin_extension(ext::Cookie);
    const size_t c = w.open(2);
    w.bytes(cookie, len);
    w.close(c, 2);
    w.close(e, 2);
}

void write_transport_parameters(Writer &w, const uint8_t *tp, size_t len) noexcept {
    write_raw_extension(w, ext::QuicTransportParameters, tp, len);
}

void write_early_data_ticket(Writer &w, uint32_t max_early_data) noexcept {
    const size_t e = w.begin_extension(ext::EarlyData);
    w.u32(max_early_data);
    w.close(e, 2);
}

void write_psk_server(Writer &w, uint16_t selected) noexcept {
    const size_t e = w.begin_extension(ext::PreSharedKey);
    w.u16(selected);
    w.close(e, 2);
}

void write_raw_extension(Writer &w, uint16_t type, const uint8_t *data, size_t len) noexcept {
    const size_t e = w.begin_extension(type);
    w.bytes(data, len);
    w.close(e, 2);
}

} // namespace tls
} // namespace http_vx
