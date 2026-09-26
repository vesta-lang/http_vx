/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/request_builder.cpp
 * @brief
 * \~english The field rules HTTP/2 and HTTP/3 share, applied a line at a time and once at the end.
 * \~spanish Las reglas de campos que comparten HTTP/2 y HTTP/3, aplicadas linea a linea y una vez al final.
 * \~
 */
#include "http_vx/request_builder.h"

#include "http_vx/chars.h"
#include "http_vx/method.h"

namespace http_vx {

namespace {

constexpr uint64_t bit(FieldId id) noexcept { return uint64_t{1} << static_cast<unsigned>(id); }

/* \~english
 * Connection-specific fields: Connection and those with connection-specific
 * semantics -- Proxy-Connection, Keep-Alive, Transfer-Encoding, Upgrade (RFC
 * 9113, 8.2.2; RFC 9114, 4.2).
 * \~spanish
 * Campos propios de la conexion: Connection y los que tienen semantica de
 * conexion -- Proxy-Connection, Keep-Alive, Transfer-Encoding, Upgrade (RFC
 * 9113, 8.2.2; RFC 9114, 4.2).
 * \~ */
constexpr uint64_t kConnectionSpecific = bit(FieldId::Connection) | bit(FieldId::KeepAlive) |
                                         bit(FieldId::TransferEncoding) | bit(FieldId::Upgrade) |
                                         bit(FieldId::ProxyConnection);

bool is(const uint8_t *p, size_t n, const char *s, size_t sn) noexcept {
    if (n != sn) return false;
    for (size_t i = 0; i < n; ++i)
        if (p[i] != static_cast<uint8_t>(s[i])) return false;
    return true;
}

bool same(const uint8_t *a, size_t an, const uint8_t *b, size_t bn) noexcept {
    if (an != bn) return false;
    for (size_t i = 0; i < an; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

} // namespace

void RequestBuilder::start(Request &req, const Options &opt) noexcept {
    req.clear();
    req_ = &req;
    opt_ = opt;
    trailers_ = false;
    seen_field_ = false;
    seen_pseudo_ = 0;
}

void RequestBuilder::start_trailers(Request &req) noexcept {
    req_ = &req;
    trailers_ = true;
    seen_field_ = false;
    seen_pseudo_ = 0;
}

const char *RequestBuilder::add(const uint8_t *base, Span name, Span value, FieldId id) noexcept {
    const uint8_t *n = base + name.off;
    const uint8_t *v = base + value.off;
    if (name.len == 0) return "an empty field name";
    // \~english Values: no NUL, CR or LF, no whitespace at either end -- field-content (RFC 9113, 8.2.1; RFC 9114, 10.3).
    // \~spanish Valores: sin NUL, CR ni LF, sin espacio en ningun extremo -- field-content (RFC 9113, 8.2.1; RFC 9114, 10.3).  \~
    if (!field_value_is_valid(reinterpret_cast<const char *>(v), value.len))
        return "a field value with a character HTTP forbids there (RFC 9113, 8.2.1; RFC 9114, 10.3)";
    if (n[0] == ':') {
        if (trailers_) return "a pseudo-header field in trailers (RFC 9113, 8.1; RFC 9114, 4.3)";
        if (seen_field_) return "a pseudo-header field after the fields (RFC 9113, 8.3; RFC 9114, 4.3)";
        uint8_t which = 0;
        Span *slot = nullptr;
        if (is(n, name.len, ":method", 7)) {
            which = kMethod;
            slot = &req_->method_text;
        } else if (is(n, name.len, ":scheme", 7)) {
            which = kScheme;
            slot = &req_->scheme;
        } else if (is(n, name.len, ":authority", 10)) {
            which = kAuthority;
            slot = &req_->authority;
        } else if (is(n, name.len, ":path", 5)) {
            which = kPath;
            slot = &req_->target;
        } else if (is(n, name.len, ":status", 7)) {
            return "a response pseudo-header field in a request (RFC 9113, 8.3; RFC 9114, 4.3)";
        } else {
            return "an undefined pseudo-header field (RFC 9113, 8.3; RFC 9114, 4.3)";
        }
        if ((seen_pseudo_ & which) != 0) return "a pseudo-header field twice (RFC 9113, 8.3; RFC 9114, 4.3.1)";
        seen_pseudo_ |= which;
        *slot = value;
        if (which == kMethod) {
            // \~english A method is a token (RFC 9110, 9.1).  \~spanish Un metodo es un token (RFC 9110, 9.1).  \~
            if (!token_is_valid(reinterpret_cast<const char *>(v), value.len)) return "a :method that is not a token";
            req_->method = method_id_of(reinterpret_cast<const char *>(v), value.len);
        }
        return nullptr;
    }
    seen_field_ = true;
    // \~english Lower case and a token -- no colon, space or control (RFC 9113, 8.2.1; RFC 9114, 4.2).
    // \~spanish En minusculas y un token -- sin dos puntos, espacio ni control (RFC 9113, 8.2.1; RFC 9114, 4.2).  \~
    for (uint32_t i = 0; i < name.len; ++i) {
        if (n[i] >= 'A' && n[i] <= 'Z') return "an uppercase field name (RFC 9113, 8.2.1; RFC 9114, 4.2)";
        if (!is_tchar(n[i])) return "a field name that is not a token (RFC 9113, 8.2.1; RFC 9114, 10.3)";
    }
    if (id == FieldId::Unknown) id = field_id_of(reinterpret_cast<const char *>(n), name.len);
    if (id != FieldId::Unknown && (kConnectionSpecific & bit(id)) != 0)
        return "a connection-specific field (RFC 9113, 8.2.2; RFC 9114, 4.2)";
    if (id == FieldId::TE && !is(v, value.len, "trailers", 8))
        return "TE other than \"trailers\" (RFC 9113, 8.2.2; RFC 9114, 4.2)";
    // \~english What this server keeps of a field: a length that fits sixteen bits.
    // \~spanish Lo que guarda este servidor de un campo: una longitud que cabe en dieciseis bits.  \~
    if (name.len > 0xffff || value.len > 0xffff) return "a field longer than this server keeps";
    Field f{};
    f.name_off = name.off;
    f.name_len = static_cast<uint16_t>(name.len);
    f.value_off = value.off;
    f.value_len = static_cast<uint16_t>(value.len);
    f.id = id;
    req_->fields.add(f);
    return nullptr;
}

const char *RequestBuilder::finish(const uint8_t *base) noexcept {
    if (trailers_) return nullptr;
    Request &r = *req_;
    const bool connect = (seen_pseudo_ & kMethod) != 0 && r.method == MethodId::Connect;
    if ((seen_pseudo_ & kMethod) == 0) return "no :method (RFC 9113, 8.3.1; RFC 9114, 4.3.1)";
    if (connect) {
        // \~english CONNECT: :authority, and neither :scheme nor :path (RFC 9113, 8.5; RFC 9114, 4.4).
        // \~spanish CONNECT: :authority, y ni :scheme ni :path (RFC 9113, 8.5; RFC 9114, 4.4).  \~
        if ((seen_pseudo_ & (kScheme | kPath)) != 0) return "a CONNECT with :scheme or :path (RFC 9113, 8.5; RFC 9114, 4.4)";
        if ((seen_pseudo_ & kAuthority) == 0 || r.authority.len == 0)
            return "a CONNECT with no :authority (RFC 9113, 8.5; RFC 9114, 4.4)";
        return nullptr;
    }
    if ((seen_pseudo_ & kScheme) == 0 || r.scheme.len == 0) return "no :scheme (RFC 9113, 8.3.1; RFC 9114, 4.3.1)";
    if ((seen_pseudo_ & kPath) == 0) return "no :path (RFC 9113, 8.3.1; RFC 9114, 4.3.1)";
    const uint8_t *scheme = base + r.scheme.off;
    const bool web = is(scheme, r.scheme.len, "http", 4) || is(scheme, r.scheme.len, "https", 5);
    if (!web) return nullptr;
    if (r.target.len == 0) return "an empty :path for http or https (RFC 9113, 8.3.1; RFC 9114, 4.3.1)";
    const uint8_t *authority = base + r.authority.off;
    // \~english No userinfo for http or https: nothing before an '@' (RFC 9113, 8.3.1; RFC 9114, 4.3.1).
    // \~spanish Sin userinfo para http o https: nada antes de una '@' (RFC 9113, 8.3.1; RFC 9114, 4.3.1).  \~
    for (uint32_t i = 0; i < r.authority.len; ++i)
        if (authority[i] == '@') return "userinfo in :authority (RFC 9113, 8.3.1; RFC 9114, 4.3.1)";
    if (!opt_.exact_host) return nullptr;
    // \~english HTTP/3: :authority or Host, never empty, and the same value if both (RFC 9114, 4.3.1).
    // \~spanish HTTP/3: :authority o Host, nunca vacios, y el mismo valor si estan los dos (RFC 9114, 4.3.1).  \~
    const bool has_authority = (seen_pseudo_ & kAuthority) != 0;
    if (has_authority && r.authority.len == 0) return "an empty :authority (RFC 9114, 4.3.1)";
    const Field *host = r.fields.find(FieldId::Host);
    if (!has_authority && host == nullptr) return "neither :authority nor Host (RFC 9114, 4.3.1)";
    for (; host != nullptr; host = r.fields.find_next(host)) {
        if (host->value_len == 0) return "an empty Host (RFC 9114, 4.3.1)";
        if (has_authority && !same(base + host->value_off, host->value_len, authority, r.authority.len))
            return "Host and :authority that differ (RFC 9114, 4.3.1)";
    }
    return nullptr;
}

} // namespace http_vx
