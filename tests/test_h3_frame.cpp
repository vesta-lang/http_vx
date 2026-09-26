/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h3_frame.cpp
 * @brief
 * \~english HTTP/3's frame layer: every frame read in any split, and every layout rule broken (RFC 9114, 7).
 * \~spanish La capa de tramas de HTTP/3: cada trama leida en cualquier particion, y cada regla de formato rota (RFC 9114, 7).
 * \~
 */

#include "http_vx/h3_frame.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace http_vx::h3;
using http_vx::Buffer;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

/// \~english What a stream of frames read as, one line per event.  \~spanish Lo que dio un flujo de tramas al leerse, una linea por evento.  \~
std::vector<std::string> read_all(FrameReader &r, const uint8_t *p, size_t n, size_t chunk) {
    std::vector<std::string> ev;
    std::string data;
    size_t at = 0;
    while (at < n) {
        const size_t k = n - at < chunk ? n - at : chunk;
        size_t off = 0;
        while (off < k) {
            size_t used = 0;
            const Step s = r.next(p + at + off, k - off, used);
            off += used;
            if (s == Step::Frame) {
                size_t len = 0;
                const uint8_t *pl = r.payload(len);
                ev.push_back("frame " + std::to_string(r.type()) + " " + std::string(reinterpret_cast<const char *>(pl), len));
            } else if (s == Step::Data) {
                size_t len = 0;
                const uint8_t *d = r.data(len);
                data.append(reinterpret_cast<const char *>(d), len);
                if (r.data_done()) {
                    ev.push_back("data " + data);
                    data.clear();
                }
            } else if (s == Step::Failed) {
                ev.push_back("failed");
                return ev;
            } else {
                break;
            }
        }
        at += k;
    }
    return ev;
}

void add(Buffer &b, const char *text) {
    const size_t n = std::strlen(text);
    uint8_t *d = b.reserve(n);
    std::memcpy(d, text, n);
    b.commit(n);
}

void test_reader() {
    section("reader");
    Buffer b;
    Settings s;
    s.qpack_max_table_capacity = 4096;
    s.qpack_blocked_streams = 16;
    check(write_settings(b, s), "SETTINGS written");
    // \~english A reserved type with a payload: skipped.  \~spanish Un tipo reservado con carga: saltado.  \~
    write_head(b, 0x21, 3);
    add(b, "xyz");
    write_head(b, kHeaders, 5);
    add(b, "hello");
    write_head(b, kData, 10);
    add(b, "0123456789");
    write_head(b, kData, 0);
    // \~english An unknown type in eight bytes.  \~spanish Un tipo desconocido en ocho bytes.  \~
    write_head(b, 0x3fffffffffffffffull, 2);
    add(b, "zz");
    write_id(b, kGoaway, 8);
    const size_t splits[] = {1, 2, 3, 7, 4096};
    for (size_t chunk : splits) {
        FrameReader r;
        r.reset();
        const std::vector<std::string> ev = read_all(r, b.data(), b.size(), chunk);
        check(ev.size() == 5, "five events whatever the split");
        if (ev.size() != 5) continue;
        check(ev[0].rfind("frame 4 ", 0) == 0, "SETTINGS first");
        check(ev[1] == "frame 1 hello", "HEADERS held whole");
        check(ev[2] == "data 0123456789", "DATA passed through, the same bytes");
        check(ev[3] == "data ", "an empty DATA frame is still reported");
        check(ev[4] == "frame 7 \x08", "GOAWAY with its identifier");
        check(r.skipped() == 2 && r.frames() == 5, "two skipped, five read");
        check(r.at_boundary(), "and the stream may end here");
    }
    {
        FrameReader r;
        r.reset();
        size_t used = 0;
        const uint8_t half[2] = {0x01, 0x05};
        check(r.next(half, 2, used) == Step::More && used == 2 && !r.at_boundary(), "inside a frame: not a boundary (7.1)");
    }
    {
        FrameReader r;
        r.reset();
        Buffer d;
        write_head(d, kData, 5);
        add(d, "abcde");
        size_t used = 0;
        check(r.next(d.data(), 4, used) == Step::Data && used == 4 && !r.data_done(), "a DATA piece before its end");
        size_t n = 0;
        const uint8_t *p = r.data(n);
        check(n == 2 && std::memcmp(p, "ab", 2) == 0, "is the bytes that came");
        check(r.next(d.data() + 4, 0, used) == Step::More && used == 0, "nothing more: More, not Data");
    }
}

void test_reader_rules() {
    section("reader rules");
    const uint64_t h2_only[] = {0x02, 0x06, 0x08, 0x09};
    for (uint64_t t : h2_only) {
        Buffer b;
        write_head(b, t, 0);
        FrameReader r;
        r.reset();
        size_t used = 0;
        check(r.next(b.data(), b.size(), used) == Step::Failed && r.failure().code == kFrameUnexpected,
              "an HTTP/2-only frame type (7.2.8)");
    }
    {
        Buffer b;
        write_head(b, kHeaders, 101);
        FrameReader r;
        r.reset(100);
        size_t used = 0;
        check(r.next(b.data(), b.size(), used) == Step::Failed && r.failure().code == kExcessiveLoad,
              "a held frame past the limit, refused from its length (10.5)");
        check(r.next(b.data(), b.size(), used) == Step::Failed, "and it stays failed");
    }
    {
        Buffer b;
        write_head(b, kHeaders, 100);
        FrameReader r;
        r.reset(100);
        size_t used = 0;
        check(r.next(b.data(), b.size(), used) == Step::More, "exactly the limit is held");
    }
    {
        // \~english A DATA frame may be of any size: it is never held.  \~spanish Una trama DATA puede ser de cualquier tamano: nunca se guarda.  \~
        Buffer b;
        write_head(b, kData, 1000000);
        add(b, "x");
        FrameReader r;
        r.reset(100);
        size_t used = 0;
        check(r.next(b.data(), b.size(), used) == Step::Data, "a DATA frame past the held limit goes through");
    }
}

void test_settings() {
    section("settings");
    Settings s;
    s.qpack_max_table_capacity = 4096;
    s.qpack_blocked_streams = 100;
    s.max_field_section_size = 16384;
    Buffer b;
    write_settings(b, s);
    FrameReader r;
    r.reset();
    size_t used = 0;
    check(r.next(b.data(), b.size(), used) == Step::Frame && r.type() == kSettings, "a SETTINGS frame");
    size_t n = 0;
    const uint8_t *p = r.payload(n);
    Settings back;
    Failure f;
    check(read_settings(p, n, back, f) && back.qpack_max_table_capacity == 4096 && back.qpack_blocked_streams == 100 &&
              back.max_field_section_size == 16384,
          "round-trips, the reserved setting ignored");
    Buffer d;
    write_settings(d, Settings{});
    check(d.size() == 4, "defaults are left out: only the reserved setting");
    check(read_settings(d.data() + 2, d.size() - 2, back, f) && back.max_field_section_size == ~uint64_t{0},
          "and read back as the defaults");

    const struct {
        const uint8_t bytes[8];
        size_t n;
        uint64_t code;
        const char *what;
    } bad[] = {
        {{0x01, 0x10, 0x01, 0x20}, 4, kSettingsError, "an identifier twice (7.2.4)"},
        {{0x02, 0x00}, 2, kSettingsError, "HTTP/2's ENABLE_PUSH (7.2.4.1)"},
        {{0x00, 0x00}, 2, kSettingsError, "HTTP/2's reserved 0x00 (7.2.4.1)"},
        {{0x05, 0x00}, 2, kSettingsError, "HTTP/2's MAX_FRAME_SIZE (7.2.4.1)"},
        {{0x01}, 1, kFrameError, "a setting with no value (7.1)"},
        {{0x01, 0x40}, 2, kFrameError, "a value cut short (7.1)"},
    };
    for (const auto &c : bad) {
        Failure why;
        check(!read_settings(c.bytes, c.n, back, why) && why.code == c.code, c.what);
    }
    {
        uint8_t ok[4] = {0x06, 0x05, 0x33, 0x01};
        check(read_settings(ok, 4, back, f) && back.max_field_section_size == 5, "an unknown identifier is ignored (7.2.4)");
    }
    {
        // \~english Identifiers 0x100 + i, two-byte varints, value 0.  \~spanish Identificadores 0x100 + i, varints de dos bytes, valor 0.  \~
        uint8_t many[3 * 65];
        for (int i = 0; i < 65; ++i) {
            many[3 * i] = 0x41;
            many[3 * i + 1] = static_cast<uint8_t>(i);
            many[3 * i + 2] = 0;
        }
        Failure why;
        check(read_settings(many, 3 * 64, back, why), "64 distinct unknown settings are fine");
        check(!read_settings(many, 3 * 65, back, why) && why.code == kExcessiveLoad, "65 are more than this end reads");
    }
}

void test_ids() {
    section("identifiers");
    Buffer b;
    check(write_id(b, kMaxPushId, 16383), "MAX_PUSH_ID written");
    uint64_t v = 0;
    Failure f;
    check(read_id(b.data() + 2, b.size() - 2, v, f) && v == 16383, "and read");
    const uint8_t extra[3] = {0x05, 0x00, 0x00};
    check(!read_id(extra, 2, v, f) && f.code == kFrameError, "a byte after the identifier (7.1, 10.8)");
    const uint8_t cut[1] = {0x40};
    check(!read_id(cut, 1, v, f) && f.code == kFrameError, "an identifier cut short (7.1)");
    check(!read_id(cut, 0, v, f) && f.code == kFrameError, "an empty payload (7.1)");
    Buffer c;
    check(!write_id(c, kGoaway, uint64_t{1} << 62) && c.size() == 0, "an identifier past 62 bits is not written, not even its head");
    check(is_reserved(0x21) && is_reserved(0x40) && is_reserved(0x3ffffffffffffffeull) && !is_reserved(0x20) &&
              !is_reserved(0x22),
          "0x1f * N + 0x21 is reserved");
}

} // namespace

int main() {
    test_reader();
    test_reader_rules();
    test_settings();
    test_ids();
    if (failures != 0) {
        std::fprintf(stderr, "h3 frame: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("h3 frame: OK\n");
    return 0;
}
