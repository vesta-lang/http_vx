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

/// \~english Runs @p lines through a builder; null if the request is fine, else the reason.
/// \~spanish Pasa @p lines por un constructor; nulo si la peticion esta bien, si no la razon.  \~
const char *run(const Lines &lines, bool exact_host, Request &req, Buffer &out) {
    RequestBuilder b;
    RequestBuilder::Options opt;
    opt.exact_host = exact_host;
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

void expect_bad(const Lines &lines, const char *part, const char *what, bool exact = false) {
    Request req;
    Buffer out;
    const char *bad = run(lines, exact, req, out);
    if (bad != nullptr && std::strstr(bad, part) != nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: got %s\n", current, what, bad != nullptr ? bad : "accepted");
    ++failures;
}

void expect_ok(const Lines &lines, const char *what, bool exact = false) {
    Request req;
    Buffer out;
    const char *bad = run(lines, exact, req, out);
    if (bad == nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: refused, %s\n", current, what, bad);
    ++failures;
}

std::string text(const Buffer &out, Span s) { return std::string(reinterpret_cast<const char *>(out.data()) + s.off, s.len); }

void test_good() {
    section("good requests");
    Request req;
    Buffer out;
    check(run(with(kGet, "accept", "*/*"), false, req, out) == nullptr, "a plain GET");
    check(req.method == http_vx::MethodId::Get && text(out, req.target) == "/" && text(out, req.scheme) == "https" &&
              text(out, req.authority) == "example.com",
          "its pieces land in the request");
    check(req.fields.size() == 1 && req.fields.find(http_vx::FieldId::Accept) != nullptr, "and the field in its fields");
    expect_ok({{":method", "OPTIONS"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "*"}}, "OPTIONS *");
    expect_ok({{":method", "CONNECT"}, {":authority", "example.com:443"}}, "CONNECT: :authority alone (8.5; 4.4)");
    expect_ok({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "example.com"}}, "Host instead of :authority");
    expect_ok(with(kGet, "host", "example.com"), "Host equal to :authority, in HTTP/3", true);
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
    expect_bad(e, "empty :authority", "an empty :authority", true);
    expect_bad({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}}, "neither :authority nor Host", "neither", true);
    expect_bad({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", ""}}, "empty Host", "an empty Host", true);
    expect_bad(with(kGet, "host", "other.example"), "differ", "Host and :authority that differ (4.3.1)", true);
    expect_bad(with(with(kGet, "host", "example.com"), "host", "evil.example"), "differ", "a second Host that differs", true);
    expect_ok({{":method", "GET"}, {":scheme", "foo"}, {":path", "/"}}, "no authority for a scheme that needs none", true);
}

void test_trailers() {
    section("trailers");
    Request req;
    Buffer out;
    check(run(kGet, false, req, out) == nullptr, "the request first");
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
    test_trailers();
    if (failures != 0) {
        std::fprintf(stderr, "request builder: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("request builder: OK\n");
    return 0;
}
