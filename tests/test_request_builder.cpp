/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_request_builder.cpp
 * @brief
 * \~english The message rules HTTP/2 and HTTP/3 share: each one broken on its own, and the requests that keep them.
 * \~spanish Las reglas del mensaje que comparten HTTP/2 y HTTP/3: cada una rota por separado, y las peticiones que las cumplen.
 * \~
 */

#include "http_vx/buffer.h"
#include "http_vx/h2_decoder.h"
#include "http_vx/request_builder.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {

using http_vx::Buffer;
using http_vx::Request;
using http_vx::RequestBuilder;
using http_vx::Span;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

using Lines = std::vector<std::pair<std::string, std::string>>;

/// \~english No option: the shared rules alone.  \~spanish Sin opciones: solo las reglas comunes.  \~
const RequestBuilder::Options kPlain{};
/// \~english What HTTP/2 asks.  \~spanish Lo que pide HTTP/2.  \~
const RequestBuilder::Options kH2 = RequestBuilder::Options::http2();
/// \~english What HTTP/3 asks.  \~spanish Lo que pide HTTP/3.  \~
const RequestBuilder::Options kH3 = RequestBuilder::Options::http3();

/// \~english Runs @p lines through a builder; null if the request is fine, else the reason.
/// \~spanish Pasa @p lines por un constructor; nulo si la peticion esta bien, si no la razon.  \~
const char *run(const Lines &lines, const RequestBuilder::Options &opt, Request &req, Buffer &out) {
    RequestBuilder b;
    b.start(req, opt);
    out.clear();
    for (const auto &l : lines) {
        Span name{static_cast<uint32_t>(out.size()), static_cast<uint32_t>(l.first.size())};
        uint8_t *d = out.reserve(l.first.size() + l.second.size() + 1);
        std::memcpy(d, l.first.data(), l.first.size());
        std::memcpy(d + l.first.size(), l.second.data(), l.second.size());
        out.commit(l.first.size() + l.second.size());
        Span value{name.off + name.len, static_cast<uint32_t>(l.second.size())};
        const char *bad = b.add(out.data(), name, value);
        if (bad != nullptr) return bad;
    }
    return b.finish(out.data());
}

const Lines kGet = {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/"}};

Lines with(Lines l, const char *name, const char *value) {
    l.push_back({name, value});
    return l;
}

void expect_bad(const Lines &lines, const char *part, const char *what, const RequestBuilder::Options &opt = kPlain) {
    Request req;
    Buffer out;
    const char *bad = run(lines, opt, req, out);
    if (bad != nullptr && std::strstr(bad, part) != nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: got %s\n", current, what, bad != nullptr ? bad : "accepted");
    ++failures;
}

void expect_ok(const Lines &lines, const char *what, const RequestBuilder::Options &opt = kPlain) {
    Request req;
    Buffer out;
    const char *bad = run(lines, opt, req, out);
    if (bad == nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: refused, %s\n", current, what, bad);
    ++failures;
}

std::string text(const Buffer &out, Span s) { return std::string(reinterpret_cast<const char *>(out.data()) + s.off, s.len); }

void test_good() {
    section("good requests");
    Request req;
    Buffer out;
    check(run(with(kGet, "accept", "*/*"), kPlain, req, out) == nullptr, "a plain GET");
    check(req.method == http_vx::MethodId::Get && text(out, req.target) == "/" && text(out, req.scheme) == "https" &&
              text(out, req.authority) == "example.com",
          "its pieces land in the request");
    check(req.fields.size() == 1 && req.fields.find(http_vx::FieldId::Accept) != nullptr, "and the field in its fields");
    expect_ok({{":method", "OPTIONS"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "*"}}, "OPTIONS *");
    expect_ok({{":method", "CONNECT"}, {":authority", "example.com:443"}}, "CONNECT: :authority alone (8.5; 4.4)");
    expect_ok({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "example.com"}}, "Host instead of :authority");
    expect_ok(with(kGet, "host", "example.com"), "Host equal to :authority, in HTTP/3", kH3);
    expect_ok(with(kGet, "host", "other.example"), "HTTP/2 does not compare them byte for byte");
    expect_ok({{":method", "GET"}, {":scheme", "foo"}, {":path", ""}}, "an empty :path outside http and https");
    expect_ok(with(kGet, "te", "trailers"), "TE: trailers (8.2.2; 4.2)");
    expect_ok(with(kGet, "x-bin", "\x80\xff"), "obs-text in a value is field-content");
    expect_ok(with(kGet, "x-mid", "a b\tc"), "whitespace inside a value");
    expect_ok(with(kGet, "x-empty", ""), "an empty value");
    expect_ok({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}}, "no authority at all, in HTTP/2");
}

void test_fields() {
    section("fields");
    expect_bad(with(kGet, "", "x"), "empty field name", "an empty name");
    expect_bad(with(kGet, "Accept", "*/*"), "uppercase", "an uppercase name (8.2.1; 4.2)");
    expect_bad(with(kGet, "x y", "1"), "not a token", "a space in a name");
    expect_bad(with(kGet, "x:y", "1"), "not a token", "a colon in a name (8.2.1)");
    const char *values[] = {"a\x00" "b", "a\rb", "a\nb", " a", "a\t", "a\x01" "b", "a\x7f"};
    const size_t lens[] = {3, 3, 3, 2, 2, 3, 2};
    for (size_t i = 0; i < 7; ++i) {
        Lines l = kGet;
        l.push_back({"x-v", std::string(values[i], lens[i])});
        expect_bad(l, "character HTTP forbids", "a value with NUL, CR, LF, a control, or whitespace at an end");
    }
    Lines p = kGet;
    p[3].second = std::string("/\n", 2);
    expect_bad(p, "character HTTP forbids", "a pseudo-header value with LF");
    const char *conn[] = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"};
    for (const char *c : conn) expect_bad(with(kGet, c, "x"), "connection-specific", "a connection-specific field (8.2.2; 4.2)");
    expect_bad(with(kGet, "te", "gzip"), "TE other than", "TE other than trailers");
    Lines big = kGet;
    big.push_back({"x-big", std::string(70000, 'a')});
    expect_bad(big, "longer than this server keeps", "a value past sixteen bits, refused rather than cut");
}

void test_pseudo() {
    section("pseudo-header fields");
    expect_bad(with(kGet, ":protocol", "x"), "undefined pseudo", "an undefined one (8.3; 4.3)");
    expect_bad(with(kGet, ":status", "200"), "response pseudo", ":status in a request");
    expect_bad({{":method", "GET"}, {"accept", "*/*"}, {":scheme", "https"}, {":path", "/"}}, "after the fields",
               "one after a field");
    expect_bad(with(kGet, ":path", "/again"), "twice", "one twice");
    expect_bad({{":method", "G ET"}, {":scheme", "https"}, {":path", "/"}}, "not a token", "a :method that is no token");
    expect_bad({{":scheme", "https"}, {":path", "/"}}, "no :method", "no :method");
    expect_bad({{":method", "GET"}, {":path", "/"}}, "no :scheme", "no :scheme");
    expect_bad({{":method", "GET"}, {":scheme", ""}, {":path", "/"}}, "no :scheme", "an empty :scheme");
    expect_bad({{":method", "GET"}, {":scheme", "https"}}, "no :path", "no :path");
    expect_bad({{":method", "GET"}, {":scheme", "http"}, {":path", ""}}, "empty :path", "an empty :path for http");
    expect_bad({{":method", "CONNECT"}, {":scheme", "https"}, {":authority", "a:1"}}, "CONNECT with :scheme",
               "CONNECT with :scheme (8.5; 4.4)");
    expect_bad({{":method", "CONNECT"}, {":path", "/"}, {":authority", "a:1"}}, "CONNECT with :scheme", "CONNECT with :path");
    expect_bad({{":method", "CONNECT"}}, "no :authority", "CONNECT with no :authority");
    expect_bad({{":method", "CONNECT"}, {":authority", ""}}, "no :authority", "CONNECT with an empty :authority");
    Lines u = kGet;
    u[2].second = "user@example.com";
    expect_bad(u, "userinfo", "userinfo in :authority (8.3.1; 4.3.1)");
}

void test_http3_host() {
    section("HTTP/3 authority and Host");
    Lines e = kGet;
    e[2].second = "";
    expect_bad(e, "empty :authority", "an empty :authority", kH3);
    expect_bad({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}}, "neither :authority nor Host", "neither", kH3);
    expect_bad({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", ""}}, "empty Host", "an empty Host", kH3);
    expect_bad(with(kGet, "host", "other.example"), "differ", "Host and :authority that differ (4.3.1)", kH3);
    expect_bad(with(with(kGet, "host", "example.com"), "host", "evil.example"), "differ", "a second Host that differs", kH3);
    expect_ok({{":method", "GET"}, {":scheme", "foo"}, {":path", "/"}}, "no authority for a scheme that needs none", kH3);
    // \~english Still byte for byte: what HTTP/2 would call the same entity, HTTP/3 calls another value (4.3.1).
    // \~spanish Sigue byte a byte: lo que HTTP/2 llamaria la misma entidad, HTTP/3 lo llama otro valor (4.3.1).  \~
    expect_bad(with(kGet, "host", "Example.com"), "differ", "a case difference is still a difference", kH3);
    expect_bad(with(kGet, "host", "example.com:443"), "differ", "the default port is still a difference", kH3);
    expect_bad(with(kGet, "host", "exa mple.com"), "differ", "no grammar check of its own, only the bytes", kH3);
    check(kH3.exact_host && !kH3.same_host_entity, "HTTP/3 asks the exact value and nothing else");
}

/// \~english host_entity_mismatch() on two literal authorities.  \~spanish host_entity_mismatch() sobre dos autoridades literales.  \~
const char *mismatch(const char *a, const char *b, const char *scheme) {
    return http_vx::host_entity_mismatch(reinterpret_cast<const uint8_t *>(a), std::strlen(a),
                                         reinterpret_cast<const uint8_t *>(b), std::strlen(b),
                                         reinterpret_cast<const uint8_t *>(scheme), std::strlen(scheme));
}

/// \~english The same entity, both ways round.  \~spanish La misma entidad, en los dos sentidos.  \~
void same(const char *a, const char *b, const char *scheme, const char *what) {
    const char *ab = mismatch(a, b, scheme);
    const char *ba = mismatch(b, a, scheme);
    if (ab == nullptr && ba == nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: \"%s\" vs \"%s\" (%s): %s\n", current, what, a, b, scheme,
                 ab != nullptr ? ab : ba);
    ++failures;
}

/// \~english Not the same entity, both ways round, for the reason holding @p part.
/// \~spanish No es la misma entidad, en los dos sentidos, por la razon que contiene @p part.  \~
void differ(const char *a, const char *b, const char *scheme, const char *part, const char *what) {
    const char *ab = mismatch(a, b, scheme);
    const char *ba = mismatch(b, a, scheme);
    if (ab != nullptr && ba != nullptr && std::strstr(ab, part) != nullptr && std::strstr(ba, part) != nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: \"%s\" vs \"%s\" (%s): got %s / %s\n", current, what, a, b, scheme,
                 ab != nullptr ? ab : "same", ba != nullptr ? ba : "same");
    ++failures;
}

void test_host_entity() {
    section("same host entity: the comparison");
    same("example.com", "example.com", "https", "equal");
    same("Example.COM", "example.com", "https", "the host is case-insensitive (RFC 3986, 3.2.2, 6.2.2.1)");
    differ("example.com", "other.example", "https", "different hosts", "another host");
    differ("example.co", "example.com", "https", "different hosts", "a prefix is another host");
    differ("example.com.", "example.com", "https", "different hosts", "a trailing dot is not normalized away");
    differ("examplf.com", "example.com", "https", "different hosts", "one letter apart");

    section("same host entity: ports");
    same("example.com:80", "example.com", "http", "http's default port is no port (RFC 9110, 4.2.1, 4.2.3)");
    same("example.com:443", "example.com", "https", "https's default port is no port (RFC 9110, 4.2.2, 4.2.3)");
    same("example.com:443", "example.com:443", "https", "the same explicit port");
    same("example.com:", "example.com", "https", "an empty port is no port (RFC 3986, 3.2.3, 6.2.3)");
    same("example.com:", "example.com:443", "https", "an empty port is the default one");
    same("example.com:0443", "example.com", "https", "a port is a number: leading zeros do not change it");
    same("example.com:8080", "example.com:08080", "http", "leading zeros on a non-default port");
    same("example.com:80", "EXAMPLE.com", "HTTP", "the scheme is case-insensitive too (RFC 3986, 3.1)");
    differ("example.com:443", "example.com", "http", "different ports", "443 is not http's default");
    differ("example.com:80", "example.com", "https", "different ports", "80 is not https's default");
    differ("example.com:8443", "example.com", "https", "different ports", "a non-default port against none");
    differ("example.com:8443", "example.com:8444", "https", "different ports", "two different ports");
    differ("example.com:80", "example.com:8", "http", "different ports", "a port that is another's prefix");
    differ("example.com:80", "example.com", "httpx", "different ports", "no default for a scheme that only starts like http");
    differ("example.com:80", "example.com", "htt", "different ports", "no default for a scheme that is http cut short");
    differ("example.com:80", "example.com", "", "different ports", "no scheme, no default (CONNECT)");
    same("example.com:", "example.com", "", "an empty port is no port without a scheme too");
    same("a:0", "a:00", "foo", "zero is zero");
    differ("a:0", "a", "foo", "different ports", "port zero is still a port");
    differ("a:0", "a:", "foo", "different ports", "port zero is not an empty port");
    same("", "", "foo", "an empty host is allowed where the scheme allows it (RFC 3986, 3.2.2)");
    differ("", "example.com", "https", "empty host", "an empty host for https (RFC 9110, 4.2.2)");
    differ(":80", "example.com", "http", "empty host", "an empty host with a port, for http (RFC 9110, 4.2.1)");

    section("same host entity: IP literals");
    same("[::1]", "[::1]:443", "https", "a bracketed IPv6 with and without the default port");
    same("[::1]:", "[::1]", "https", "a bracketed IPv6 with an empty port");
    same("[FE80::A]", "[fe80::a]", "https", "IPv6 hex digits are case-insensitive (RFC 3986, 3.2.2)");
    same("[v1.X]", "[V1.x]", "https", "IPvFuture is case-insensitive too");
    same("[::1]:8443", "[::1]:8443", "https", "a bracketed IPv6 with a non-default port");
    differ("[::1]:8443", "[::1]", "https", "different ports", "a bracketed IPv6 with another port");
    differ("[::1]", "[::2]", "https", "different hosts", "another IPv6 address");
    differ("[::1]", "[0::1]", "https", "different hosts", "another spelling of the address is not normalized");
    differ("[::1]", "::1", "https", "port is not decimal", "an IPv6 address without brackets");
    differ("[::1", "[::1]", "https", "no closing", "an IP literal left open");
    differ("[]", "[::1]", "https", "empty IP literal", "an empty IP literal");
    differ("[::1]x", "[::1]", "https", "other than a port", "something after the IP literal that is no port");
    differ("[::1%25eth0]", "[::1]", "https", "IP literal cannot hold", "a zone identifier (RFC 3986 has none)");
    differ("[::1]", "[::1]:x", "https", "port is not decimal", "a port that is not digits after an IP literal");

    section("same host entity: percent-encoding");
    same("%65xample.com", "example.com", "https", "an unreserved letter encoded is the letter (RFC 3986, 2.3, 6.2.2.2)");
    same("%45xample.com", "example.com", "https", "and then compared without case (RFC 3986, 6.2.2.1)");
    same("ex%2Dample.com", "ex-ample.com", "https", "hyphen");
    same("example%2ecom", "example.com", "https", "period, hex digits in lower case");
    same("a%5Fb", "a_b", "https", "underscore");
    same("a%7eb", "a~b", "https", "tilde");
    same("a%31b", "a1b", "https", "digit");
    same("%C3%A9t%C3%A9", "%c3%a9t%c3%a9", "https", "a non-ASCII octet stays encoded, its hex digits without case (RFC 3986, 2.1)");
    differ("a%21b", "a!b", "https", "different hosts", "a sub-delim encoded is not the sub-delim (RFC 3986, 2.2)");
    differ("%C3%A9", "%C3%89", "https", "different hosts", "no case folding beyond ASCII");
    differ("a%21b", "a%22b", "https", "different hosts", "two different encoded octets");
    differ("a%41", "a%41%41", "https", "different hosts", "one more encoded octet");
    differ("a%2", "a", "https", "'%' not followed", "a triplet cut short at the end");
    differ("a%", "a", "https", "'%' not followed", "a lone '%'");
    differ("a%zz", "a", "https", "'%' not followed", "a triplet that is no hex");
    differ("a%4g", "a", "https", "'%' not followed", "a triplet whose second digit is no hex");
    differ("a%g4", "a", "https", "'%' not followed", "a triplet whose first digit is no hex");

    section("same host entity: not an authority");
    differ("exa mple.com", "example.com", "https", "host cannot hold", "a space in a host");
    differ("user@example.com", "example.com", "https", "host cannot hold", "userinfo is not host [\":\" port]");
    differ("a/b", "a", "https", "host cannot hold", "a slash in a host");
    differ("a[b]", "a", "https", "host cannot hold", "a bracket inside a reg-name");
    differ("a:8o", "a:80", "https", "port is not decimal", "a letter in a port");
    differ("a:1:2", "a:1", "https", "port is not decimal", "two colons");
    same("a!$&'()*+,;=", "A!$&'()*+,;=", "https", "every sub-delim is a host character");
    same("a-._~9", "A-._~9", "https", "every unreserved kind is a host character");
}

void test_http2_host() {
    section("HTTP/2 authority and Host");
    check(kH2.same_host_entity && !kH2.exact_host, "HTTP/2 asks the same entity and not the same bytes");
    check(!kPlain.same_host_entity && !kPlain.exact_host, "no option asks nothing");
    expect_ok(with(kGet, "host", "example.com"), "the same value", kH2);
    expect_ok(with(kGet, "host", "EXAMPLE.com:443"), "the same entity, written otherwise (8.3.1)", kH2);
    expect_ok(with(kGet, "host", "example.com:"), "an empty port", kH2);
    expect_bad(with(kGet, "host", "other.example"), "different hosts", "another host (8.3.1)", kH2);
    expect_bad(with(kGet, "host", "example.com:8443"), "different ports", "another port (8.3.1)", kH2);
    expect_bad(with(with(kGet, "host", "example.com"), "host", "evil.example"), "different hosts", "a second Host", kH2);
    expect_bad(with(kGet, "host", "exa mple.com"), "host cannot hold", "a Host that is no authority", kH2);
    expect_ok({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "anything"}},
              "a Host with no :authority has nothing to agree with", kH2);
    Lines http = kGet;
    http[1].second = "http";
    expect_ok(with(http, "host", "example.com:80"), "http's default port", kH2);
    expect_bad(with(http, "host", "example.com:443"), "different ports", "https's port for http", kH2);
    expect_ok({{":method", "CONNECT"}, {":authority", "example.com:443"}, {"host", "EXAMPLE.COM:443"}},
              "CONNECT: the same host and port", kH2);
    expect_bad({{":method", "CONNECT"}, {":authority", "example.com:443"}, {"host", "example.com"}}, "different ports",
               "CONNECT: no scheme, so no default port", kH2);
    expect_bad({{":method", "CONNECT"}, {":authority", "example.com:443"}, {"host", "other.example:443"}},
               "different hosts", "CONNECT: another host", kH2);
    expect_ok({{":method", "GET"}, {":scheme", "foo"}, {":authority", "a"}, {":path", "/"}, {"host", "A"}},
              "another scheme: the same host", kH2);
    expect_bad({{":method", "GET"}, {":scheme", "foo"}, {":authority", "a"}, {":path", "/"}, {"host", "b"}},
               "different hosts", "another scheme: another host", kH2);
    Lines e = kGet;
    e[2].second = "";
    expect_bad(with(e, "host", "example.com"), "empty host", "an empty :authority against a Host, for https", kH2);
    Lines u = kGet;
    u[2].second = "user@example.com";
    expect_bad(with(u, "host", "example.com"), "userinfo", "userinfo is refused as such first", kH2);

    section("HTTP/2 empty host in :authority");
    check(kH2.no_empty_host && !kH3.no_empty_host && !kPlain.no_empty_host, "only HTTP/2 asks it");
    expect_bad(e, "empty host in :authority", "an empty :authority with no Host (RFC 9110, 4.2.2)", kH2);
    Lines p = kGet;
    p[2].second = ":443";
    expect_bad(p, "empty host in :authority", "a port and no host (RFC 9110, 4.2.2)", kH2);
    Lines h = e;
    h[1].second = "http";
    expect_bad(h, "empty host in :authority", "an empty :authority for http (RFC 9110, 4.2.1)", kH2);
    expect_bad({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":authority", ""}, {"accept", "*/*"}},
               "empty host in :authority", "an empty :authority judged by its length, not by the next byte", kH2);
    Lines v6 = kGet;
    v6[2].second = "[::1]:443";
    expect_ok(v6, "an IP literal is a host", kH2);
    Lines one = kGet;
    one[2].second = "a";
    expect_ok(one, "a one-letter host", kH2);
    expect_ok({{":method", "GET"}, {":scheme", "foo"}, {":authority", ""}, {":path", "/"}},
              "another scheme may have an empty host (RFC 3986, 3.2.2)", kH2);
    expect_ok({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}}, "no :authority at all is not an empty one", kH2);
    expect_ok(e, "without the option, as before", kPlain);
    expect_ok(p, "HTTP/3 unchanged: a port with no host is a value, not empty (RFC 9114, 4.3.1)", kH3);
}

/// \~english An HPACK block (RFC 7541, C.3.1) plus a Host literal, through the HTTP/2 decoder; null if accepted, else why.
/// \~spanish Un bloque HPACK (RFC 7541, C.3.1) mas un literal Host, por el decodificador de HTTP/2; nulo si se acepta, si no por que.  \~
const char *h2_decode_with_host(const char *host) {
    // \~english :method GET, :scheme http, :path /, :authority www.example.com; then Host, a literal with a new name.
    // \~spanish :method GET, :scheme http, :path /, :authority www.example.com; luego Host, un literal con nombre nuevo.  \~
    std::vector<uint8_t> block = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a',
                                  'm',  'p',  'l',  'e',  '.',  'c', 'o', 'm', 0x00, 0x04, 'h', 'o', 's', 't'};
    block.push_back(static_cast<uint8_t>(std::strlen(host)));
    for (const char *c = host; *c != '\0'; ++c) block.push_back(static_cast<uint8_t>(*c));
    http_vx::h2::hpack::Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);
    Buffer out;
    Request req;
    if (d.decode(block.data(), block.size(), out, req) == http_vx::h2::ErrorCode::NoError) return nullptr;
    return d.why() != nullptr ? d.why() : "refused without a reason";
}

void test_h2_decoder_asks() {
    section("the HTTP/2 decoder asks for the same entity");
    check(h2_decode_with_host("WWW.Example.com:80") == nullptr, "the same entity, written otherwise, is accepted");
    const char *bad = h2_decode_with_host("other.example");
    check(bad != nullptr && std::strstr(bad, "different hosts") != nullptr, "another host is malformed (RFC 9113, 8.3.1)");
    bad = h2_decode_with_host("www.example.com:443");
    check(bad != nullptr && std::strstr(bad, "different ports") != nullptr, "https's port on http is another entity");
}

/// \~english The helper on an authority shorter than its buffer: nothing past its length is read.
/// \~spanish El auxiliar sobre una autoridad mas corta que su buffer: no se lee nada tras su longitud.  \~
void test_host_entity_bounds() {
    section("same host entity: only the given length");
    const uint8_t *https = reinterpret_cast<const uint8_t *>("https");
    const uint8_t *cut = reinterpret_cast<const uint8_t *>("a%41");
    const uint8_t *whole = reinterpret_cast<const uint8_t *>("aA");
    const char *bad = http_vx::host_entity_mismatch(cut, 3, whole, 2, https, 5);
    check(bad != nullptr && std::strstr(bad, "'%' not followed") != nullptr, "a triplet cut by the length, not by a nul");
    const uint8_t *long_port = reinterpret_cast<const uint8_t *>("a:800");
    bad = http_vx::host_entity_mismatch(long_port, 5, long_port, 4, https, 5);
    check(bad != nullptr && std::strstr(bad, "different ports") != nullptr, "800 against 80, the rest of the buffer unread");
    bad = http_vx::host_entity_mismatch(long_port, 4, long_port, 5, https, 5);
    check(bad != nullptr && std::strstr(bad, "different ports") != nullptr, "80 against 800, the rest of the buffer unread");

    section("same host entity: every kind of character");
    same("a%41:443", "aa", "https", "a triplet then a port");
    same("a:9", "a:09", "foo", "the digit nine is a port digit");
    same("a%2e%2E", "a..", "https", "two encoded octets in a row");
    same("a%2f", "a%2F", "https", "a reserved octet, its hex digit f in either case (RFC 3986, 2.1)");
    same("ZZ.example", "zz.example", "https", "the last letter of the alphabet folds too");
    same("[v1.a!=b]", "[V1.A!=B]", "https", "IPvFuture may hold sub-delims (RFC 3986, 3.2.2)");
}

void test_trailers() {
    section("trailers");
    Request req;
    Buffer out;
    check(run(kGet, kPlain, req, out) == nullptr, "the request first");
    RequestBuilder b;
    b.start_trailers(req);
    const size_t before = req.fields.size();
    Buffer t;
    const char *kv = "x-checksumabc:status200";
    uint8_t *d = t.reserve(23);
    std::memcpy(d, kv, 23);
    t.commit(23);
    check(b.add(t.data(), Span{0, 10}, Span{10, 3}) == nullptr, "a field in trailers");
    check(req.fields.size() == before + 1, "joins the request's fields");
    const char *bad = b.add(t.data(), Span{13, 7}, Span{20, 3});
    check(bad != nullptr && std::strstr(bad, "in trailers") != nullptr, "a pseudo-header field in trailers (8.1; 4.3)");
    check(b.finish(t.data()) == nullptr, "trailers need no pseudo-header field");
}

} // namespace

int main() {
    test_good();
    test_fields();
    test_pseudo();
    test_http3_host();
    test_host_entity();
    test_http2_host();
    test_h2_decoder_asks();
    test_host_entity_bounds();
    test_trailers();
    if (failures != 0) {
        std::fprintf(stderr, "request builder: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("request builder: OK\n");
    return 0;
}
