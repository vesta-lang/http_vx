/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/qpack.cpp
 * @brief
 * \~english QPACK's integers, strings and static table (RFC 9204, 4.1 and Appendix A).
 * \~spanish Los enteros, las cadenas y la tabla estatica de QPACK (RFC 9204, 4.1 y apendice A).
 * \~
 */
#include "http_vx/qpack.h"

#include "http_vx/h2_huffman.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace qpack {

namespace {

/* \~english
 * Appendix A, line by line.  Generated from the RFC's own text, rows that
 * wrap joined back -- after a hyphen or a slash with nothing between, and
 * with a space otherwise, which is where the table's formatting broke them.
 * \~spanish
 * El apendice A, linea a linea.  Generada del propio texto del RFC, con las
 * filas partidas unidas de nuevo -- tras un guion o una barra sin nada en
 * medio, y con un espacio en otro caso, que es donde las partio el formato de la
 * tabla.
 * \~ */
const StaticLine kStatic[kStaticLines] = {
    {":authority", 10, "", 0}, // 0
    {":path", 5, "/", 1}, // 1
    {"age", 3, "0", 1}, // 2
    {"content-disposition", 19, "", 0}, // 3
    {"content-length", 14, "0", 1}, // 4
    {"cookie", 6, "", 0}, // 5
    {"date", 4, "", 0}, // 6
    {"etag", 4, "", 0}, // 7
    {"if-modified-since", 17, "", 0}, // 8
    {"if-none-match", 13, "", 0}, // 9
    {"last-modified", 13, "", 0}, // 10
    {"link", 4, "", 0}, // 11
    {"location", 8, "", 0}, // 12
    {"referer", 7, "", 0}, // 13
    {"set-cookie", 10, "", 0}, // 14
    {":method", 7, "CONNECT", 7}, // 15
    {":method", 7, "DELETE", 6}, // 16
    {":method", 7, "GET", 3}, // 17
    {":method", 7, "HEAD", 4}, // 18
    {":method", 7, "OPTIONS", 7}, // 19
    {":method", 7, "POST", 4}, // 20
    {":method", 7, "PUT", 3}, // 21
    {":scheme", 7, "http", 4}, // 22
    {":scheme", 7, "https", 5}, // 23
    {":status", 7, "103", 3}, // 24
    {":status", 7, "200", 3}, // 25
    {":status", 7, "304", 3}, // 26
    {":status", 7, "404", 3}, // 27
    {":status", 7, "503", 3}, // 28
    {"accept", 6, "*/*", 3}, // 29
    {"accept", 6, "application/dns-message", 23}, // 30
    {"accept-encoding", 15, "gzip, deflate, br", 17}, // 31
    {"accept-ranges", 13, "bytes", 5}, // 32
    {"access-control-allow-headers", 28, "cache-control", 13}, // 33
    {"access-control-allow-headers", 28, "content-type", 12}, // 34
    {"access-control-allow-origin", 27, "*", 1}, // 35
    {"cache-control", 13, "max-age=0", 9}, // 36
    {"cache-control", 13, "max-age=2592000", 15}, // 37
    {"cache-control", 13, "max-age=604800", 14}, // 38
    {"cache-control", 13, "no-cache", 8}, // 39
    {"cache-control", 13, "no-store", 8}, // 40
    {"cache-control", 13, "public, max-age=31536000", 24}, // 41
    {"content-encoding", 16, "br", 2}, // 42
    {"content-encoding", 16, "gzip", 4}, // 43
    {"content-type", 12, "application/dns-message", 23}, // 44
    {"content-type", 12, "application/javascript", 22}, // 45
    {"content-type", 12, "application/json", 16}, // 46
    {"content-type", 12, "application/x-www-form-urlencoded", 33}, // 47
    {"content-type", 12, "image/gif", 9}, // 48
    {"content-type", 12, "image/jpeg", 10}, // 49
    {"content-type", 12, "image/png", 9}, // 50
    {"content-type", 12, "text/css", 8}, // 51
    {"content-type", 12, "text/html; charset=utf-8", 24}, // 52
    {"content-type", 12, "text/plain", 10}, // 53
    {"content-type", 12, "text/plain;charset=utf-8", 24}, // 54
    {"range", 5, "bytes=0-", 8}, // 55
    {"strict-transport-security", 25, "max-age=31536000", 16}, // 56
    {"strict-transport-security", 25, "max-age=31536000; includesubdomains", 35}, // 57
    {"strict-transport-security", 25, "max-age=31536000; includesubdomains; preload", 44}, // 58
    {"vary", 4, "accept-encoding", 15}, // 59
    {"vary", 4, "origin", 6}, // 60
    {"x-content-type-options", 22, "nosniff", 7}, // 61
    {"x-xss-protection", 16, "1; mode=block", 13}, // 62
    {":status", 7, "100", 3}, // 63
    {":status", 7, "204", 3}, // 64
    {":status", 7, "206", 3}, // 65
    {":status", 7, "302", 3}, // 66
    {":status", 7, "400", 3}, // 67
    {":status", 7, "403", 3}, // 68
    {":status", 7, "421", 3}, // 69
    {":status", 7, "425", 3}, // 70
    {":status", 7, "500", 3}, // 71
    {"accept-language", 15, "", 0}, // 72
    {"access-control-allow-credentials", 32, "FALSE", 5}, // 73
    {"access-control-allow-credentials", 32, "TRUE", 4}, // 74
    {"access-control-allow-headers", 28, "*", 1}, // 75
    {"access-control-allow-methods", 28, "get", 3}, // 76
    {"access-control-allow-methods", 28, "get, post, options", 18}, // 77
    {"access-control-allow-methods", 28, "options", 7}, // 78
    {"access-control-expose-headers", 29, "content-length", 14}, // 79
    {"access-control-request-headers", 30, "content-type", 12}, // 80
    {"access-control-request-method", 29, "get", 3}, // 81
    {"access-control-request-method", 29, "post", 4}, // 82
    {"alt-svc", 7, "clear", 5}, // 83
    {"authorization", 13, "", 0}, // 84
    {"content-security-policy", 23, "script-src 'none'; object-src 'none'; base-uri 'none'", 53}, // 85
    {"early-data", 10, "1", 1}, // 86
    {"expect-ct", 9, "", 0}, // 87
    {"forwarded", 9, "", 0}, // 88
    {"if-range", 8, "", 0}, // 89
    {"origin", 6, "", 0}, // 90
    {"purpose", 7, "prefetch", 8}, // 91
    {"server", 6, "", 0}, // 92
    {"timing-allow-origin", 19, "*", 1}, // 93
    {"upgrade-insecure-requests", 25, "1", 1}, // 94
    {"user-agent", 10, "", 0}, // 95
    {"x-forwarded-for", 15, "", 0}, // 96
    {"x-frame-options", 15, "deny", 4}, // 97
    {"x-frame-options", 15, "sameorigin", 10}, // 98
};

/// \~english The same @p n bytes.  \~spanish Los mismos @p n bytes.  \~
bool same(const char *a, const uint8_t *b, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i)
        if (static_cast<uint8_t>(a[i]) != b[i]) return false;
    return true;
}

} // namespace

Int read_int(const uint8_t *p, size_t n, unsigned prefix) noexcept {
    Int r;
    if (prefix < 1 || prefix > 8) return r;
    if (n == 0) {
        r.status = Status::Truncated;
        return r;
    }
    const uint64_t mask = (uint64_t{1} << prefix) - 1;
    uint64_t v = p[0] & mask;
    if (v < mask) {
        r.status = Status::Ok;
        r.value = v;
        r.used = 1;
        return r;
    }
    // \~english The prefix is full: seven more bits a byte, least significant first (RFC 7541, 5.1).
    // \~spanish El prefijo esta lleno: siete bits mas por byte, los de menos peso primero (RFC 7541, 5.1).  \~
    unsigned shift = 0;
    for (size_t i = 1;; ++i) {
        if (i >= n) {
            r.status = Status::Truncated;
            return r;
        }
        const uint64_t bits = p[i] & 0x7f;
        // \~english Past 62 bits, even a byte of zeros is refused: nothing after it could bring the value back.
        // \~spanish Pasado de 62 bits, hasta un byte de ceros se rechaza: nada despues podria devolver el valor.  \~
        if (shift > 62 || (bits << shift) >> shift != bits || v + (bits << shift) > kMaxInt) {
            r.status = Status::TooLarge;
            return r;
        }
        v += bits << shift;
        shift += 7;
        if ((p[i] & 0x80) == 0) {
            r.status = Status::Ok;
            r.value = v;
            r.used = i + 1;
            return r;
        }
    }
}

size_t write_int(uint8_t *out, uint64_t value, unsigned prefix, uint8_t high) noexcept {
    if (value > kMaxInt || prefix < 1 || prefix > 8) return 0;
    const uint64_t mask = (uint64_t{1} << prefix) - 1;
    if (value < mask) {
        out[0] = static_cast<uint8_t>(high | value);
        return 1;
    }
    out[0] = static_cast<uint8_t>(high | mask);
    value -= mask;
    size_t i = 1;
    while (value >= 0x80) {
        out[i++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[i++] = static_cast<uint8_t>(value);
    return i;
}

Str read_str(const uint8_t *p, size_t n, unsigned prefix, size_t max, Buffer &out) noexcept {
    Str r;
    if (prefix < 2 || prefix > 8) return r;
    if (n == 0) {
        r.status = Status::Truncated;
        return r;
    }
    const bool huffman = (p[0] & (1u << (prefix - 1))) != 0;
    const Int len = read_int(p, n, prefix - 1);
    if (len.status != Status::Ok) {
        r.status = len.status;
        return r;
    }
    // \~english Too long is known from the length alone: a Huffman symbol is at most 30 bits.
    // \~spanish Demasiado largo se sabe por la longitud sola: un simbolo Huffman mide como mucho 30 bits.  \~
    const uint64_t least = huffman ? len.value * 8 / 30 : len.value;
    if (least > max) {
        r.status = Status::TooLarge;
        return r;
    }
    if (len.value > n - len.used) {
        r.status = Status::Truncated;
        r.used = len.used + static_cast<size_t>(len.value);
        return r;
    }
    const uint8_t *body = p + len.used;
    const size_t body_len = static_cast<size_t>(len.value);
    const size_t at = out.size();
    if (huffman) {
        size_t room = h2::hpack::huffman_max_decoded(body_len);
        if (room > max) room = max;
        uint8_t *dst = room != 0 ? out.reserve(room) : out.tail();
        if (room != 0 && dst == nullptr) {
            r.status = Status::NoMemory;
            return r;
        }
        const h2::hpack::HuffmanResult h = h2::hpack::huffman_decode(dst, room, body, body_len);
        if (h.status == h2::hpack::Status::TooLarge) {
            r.status = Status::TooLarge;
            return r;
        }
        if (h.status != h2::hpack::Status::Ok) {
            r.status = Status::Malformed;
            return r;
        }
        out.commit(h.len);
        r.span.len = static_cast<uint32_t>(h.len);
    } else {
        if (body_len != 0) {
            uint8_t *dst = out.reserve(body_len);
            if (dst == nullptr) {
                r.status = Status::NoMemory;
                return r;
            }
            util::vesta_memcpy(dst, body, body_len);
            out.commit(body_len);
        }
        r.span.len = static_cast<uint32_t>(body_len);
    }
    r.status = Status::Ok;
    r.span.off = static_cast<uint32_t>(at);
    r.used = len.used + body_len;
    return r;
}

size_t str_size(const uint8_t *s, size_t n, unsigned prefix) noexcept {
    const size_t h = h2::hpack::huffman_encoded_length(s, n);
    const size_t len = h < n ? h : n;
    uint8_t tmp[kMaxIntBytes];
    return write_int(tmp, len, prefix - 1, 0) + len;
}

size_t write_str(uint8_t *out, size_t cap, const uint8_t *s, size_t n, unsigned prefix, uint8_t high) noexcept {
    if (prefix < 2 || prefix > 8) return 0;
    const size_t h = h2::hpack::huffman_encoded_length(s, n);
    const bool huffman = h < n;
    const size_t len = huffman ? h : n;
    uint8_t head[kMaxIntBytes];
    const uint8_t flag = huffman ? static_cast<uint8_t>(1u << (prefix - 1)) : uint8_t{0};
    const size_t hn = write_int(head, len, prefix - 1, static_cast<uint8_t>(high | flag));
    if (hn == 0 || hn + len > cap) return 0;
    util::vesta_memcpy_noinline(out, head, hn);
    if (huffman) {
        if (h2::hpack::huffman_encode(out + hn, cap - hn, s, n) != len) return 0;
    } else if (n != 0) {
        util::vesta_memcpy(out + hn, s, n);
    }
    return hn + len;
}

const StaticLine *static_line(uint64_t i) noexcept {
    return i < kStaticLines ? &kStatic[i] : nullptr;
}

StaticMatch find_static(const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) noexcept {
    StaticMatch m;
    for (size_t i = 0; i < kStaticLines; ++i) {
        const StaticLine &l = kStatic[i];
        if (l.name_len != nlen || !same(l.name, name, nlen)) continue;
        if (l.value_len == vlen && same(l.value, value, vlen)) {
            m.index = i;
            m.exact = true;
            return m;
        }
        if (m.index == kStaticLines) m.index = i;
    }
    return m;
}

} // namespace qpack
} // namespace http_vx
