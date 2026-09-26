/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_qpack.cpp
 * @brief
 * \~english QPACK's decoder against RFC 9204: Appendix B byte for byte, and every rule broken on purpose.
 * \~spanish El descodificador de QPACK contra el RFC 9204: el apendice B byte a byte, y cada regla rota a proposito.
 * \~
 *
 * \~english
 * Appendix B is a conversation between an encoder and a decoder; the
 * decoder's half is played here -- the encoder stream and the field
 * sections go in, and what comes out must be the lines the RFC names, the
 * table sizes it shows, and the decoder stream bytes it prints.  Then each
 * rule of the RFC is broken by a hand-made instruction or section, and must
 * end with its own error code.
 * \~spanish
 * El apendice B es una conversacion entre un codificador y un descodificador;
 * aqui se hace la mitad del descodificador -- entran el flujo del codificador y
 * las secciones de campos, y lo que sale deben ser las lineas que nombra el RFC,
 * los tamanos de tabla que muestra y los bytes del flujo del descodificador que
 * imprime.  Despues cada regla del RFC se rompe con una instruccion o una seccion
 * hecha a mano, y debe acabar con su propio codigo de error.
 * \~
 */

#include "http_vx/qpack.h"
#include "http_vx/qpack_decoder.h"

#include "tls_rfc8448.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace http_vx::qpack;
using http_vx::Buffer;
using http_vx::Span;
using rfc8448::from_hex;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

/// \~english Bytes from hex.  \~spanish Bytes a partir de hex.  \~
struct Hex {
    uint8_t b[512];
    size_t n;
    explicit Hex(const char *hex) : n(from_hex(hex, b, sizeof b)) {}
};

/// \~english Keeps every line as "name=value", with a '!' in front when never indexed.
/// \~spanish Guarda cada linea como "nombre=valor", con un '!' delante si no se indexa nunca.  \~
struct Lines final : FieldSink {
    std::vector<std::string> got;
    size_t refuse_at = ~size_t{0};
    bool field(const Buffer &out, const FieldLine &line) noexcept override {
        if (got.size() == refuse_at) return false;
        std::string s = line.never_indexed ? "!" : "";
        s.append(reinterpret_cast<const char *>(out.data()) + line.name.off, line.name.len);
        s += '=';
        s.append(reinterpret_cast<const char *>(out.data()) + line.value.off, line.value.len);
        got.push_back(s);
        return true;
    }
};

/// \~english Whether the decoder stream holds exactly @p hex, and empties it.
/// \~spanish Si el flujo del descodificador tiene exactamente @p hex, y lo vacia.  \~
bool said(Decoder &d, const char *hex) {
    const Hex want(hex);
    size_t n = 0;
    const uint8_t *p = d.output(n);
    const bool ok = n == want.n && (n == 0 || std::memcmp(p, want.b, n) == 0);
    d.sent(n);
    return ok;
}

/// \~english Feeds encoder stream bytes from hex.  \~spanish Da bytes del flujo del codificador desde hex.  \~
bool feed(Decoder &d, const char *hex) {
    const Hex h(hex);
    return d.on_encoder_stream(h.b, h.n);
}

/// \~english Decodes a section from hex into @p lines.  \~spanish Descodifica una seccion desde hex en @p lines.  \~
Outcome read(Decoder &d, uint64_t stream, const char *hex, Lines &lines) {
    const Hex h(hex);
    Buffer out;
    return d.decode(stream, h.b, h.n, out, lines);
}

DecoderConfig config(uint64_t capacity, uint64_t blocked) {
    DecoderConfig c;
    c.max_table_capacity = capacity;
    c.blocked_streams = blocked;
    return c;
}

void test_integers() {
    section("integers");
    uint8_t b[16];
    // \~english Appendix B.2's capacity, 220 with a 5-bit prefix.  \~spanish La capacidad del apendice B.2, 220 con prefijo de 5 bits.  \~
    check(write_int(b, 220, 5, 0x20) == 3 && b[0] == 0x3f && b[1] == 0xbd && b[2] == 0x01, "220 in 5 bits is 3f bd 01");
    const Int r = read_int(b, 3, 5);
    check(r.status == Status::Ok && r.value == 220 && r.used == 3, "and reads back");
    // \~english Every prefix, at the edges.  \~spanish Cada prefijo, en los bordes.  \~
    const uint64_t values[] = {0, 1, 30, 31, 32, 126, 127, 128, 255, 16383, 16384, kMaxInt - 1, kMaxInt};
    for (unsigned prefix = 1; prefix <= 8; ++prefix)
        for (uint64_t v : values) {
            const size_t k = write_int(b, v, prefix, 0);
            const Int back = read_int(b, k, prefix);
            check(k != 0 && k <= kMaxIntBytes && back.status == Status::Ok && back.value == v && back.used == k,
                  "every value round-trips in every prefix");
            if (k > 1) check(read_int(b, k - 1, prefix).status == Status::Truncated, "and cut short is Truncated");
        }
    check(write_int(b, kMaxInt + 1, 8, 0) == 0, "past 62 bits is not written");
    // \~english 2^62 by hand: prefix full, then 2^62 - 255 in sevens.  \~spanish 2^62 a mano: prefijo lleno, y 2^62 - 255 de siete en siete.  \~
    uint64_t rest = (uint64_t{1} << 62) - 255;
    size_t k = 0;
    b[k++] = 0xff;
    while (rest >= 0x80) {
        b[k++] = static_cast<uint8_t>((rest & 0x7f) | 0x80);
        rest >>= 7;
    }
    b[k++] = static_cast<uint8_t>(rest);
    check(read_int(b, k, 8).status == Status::TooLarge, "2^62 is too large (4.1.1)");
    // \~english A continuation of zeros that never ends is refused before it ends.  \~spanish Una continuacion de ceros que no acaba se rechaza antes de acabar.  \~
    uint8_t zeros[16];
    std::memset(zeros, 0x80, sizeof zeros);
    zeros[0] = 0xff;
    check(read_int(zeros, sizeof zeros, 8).status == Status::TooLarge, "endless zero continuation is too large");
    // \~english Nine continuations fill 63 bits; a tenth, even of zeros, is past 62, ended or not.
    // \~spanish Nueve continuaciones llenan 63 bits; una decima, aunque sea de ceros, pasa de 62, acabe o no.  \~
    zeros[10] = 0x00;
    check(read_int(zeros, 11, 8).status == Status::TooLarge, "a zero past 62 bits that ends the integer is too large");
    check(read_int(b, 0, 8).status == Status::Truncated, "nothing is Truncated");
}

void test_strings() {
    section("strings");
    const char *text = "custom-value";
    const size_t len = std::strlen(text);
    for (unsigned prefix = 2; prefix <= 8; ++prefix) {
        uint8_t w[64];
        const uint8_t high = static_cast<uint8_t>(prefix < 8 ? 0x80 : 0);
        const size_t k = write_str(w, sizeof w, reinterpret_cast<const uint8_t *>(text), len, prefix, high);
        check(k == str_size(reinterpret_cast<const uint8_t *>(text), len, prefix), "str_size is what write_str writes");
        check(k < len + 1, "shorter Huffman-coded, so Huffman it is");
        Buffer out;
        const Str s = read_str(w, k, prefix, 64, out);
        check(s.status == Status::Ok && s.used == k && s.span.len == len &&
                  std::memcmp(out.data() + s.span.off, text, len) == 0,
              "a Huffman string round-trips in every prefix");
        check(read_str(w, k, prefix, len - 1, out).status == Status::TooLarge, "past the limit is TooLarge (7.4)");
        const Str cut = read_str(w, k - 1, prefix, 64, out);
        check(cut.status == Status::Truncated && cut.used == k, "cut short says how much the whole literal needs");
    }
    // \~english A string whose Huffman code is longer goes as it is.  \~spanish Una cadena cuyo codigo Huffman es mas largo va tal cual.  \~
    const uint8_t odd[3] = {0x00, 0x01, 0x02};
    uint8_t w[16];
    const size_t k = write_str(w, sizeof w, odd, 3, 8, 0);
    check(k == 4 && w[0] == 0x03, "a string Huffman would lengthen goes plain");
    check(write_str(w, 3, odd, 3, 8, 0) == 0, "and not at all if it does not fit");
}

void test_static() {
    section("static table");
    check(static_line(0) != nullptr && std::memcmp(static_line(0)->name, ":authority", 10) == 0 &&
              static_line(0)->value_len == 0,
          "0 is :authority, empty");
    check(static_line(17) != nullptr && std::memcmp(static_line(17)->value, "GET", 3) == 0, "17 is :method GET");
    check(static_line(52) != nullptr && static_line(52)->value_len == 24 &&
              std::memcmp(static_line(52)->value, "text/html; charset=utf-8", 24) == 0,
          "52 is text/html; charset=utf-8, rows joined with a space");
    check(static_line(54) != nullptr && std::memcmp(static_line(54)->value, "text/plain;charset=utf-8", 24) == 0,
          "54 is text/plain;charset=utf-8, joined after a slash");
    check(static_line(98) != nullptr && std::memcmp(static_line(98)->value, "sameorigin", 10) == 0, "98 is the last");
    check(static_line(99) == nullptr, "99 is past it");
    const uint8_t name[] = {'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e'};
    const uint8_t png[] = {'i', 'm', 'a', 'g', 'e', '/', 'p', 'n', 'g'};
    const uint8_t bmp[] = {'i', 'm', 'a', 'g', 'e', '/', 'b', 'm', 'p'};
    const StaticMatch exact = find_static(name, sizeof name, png, sizeof png);
    check(exact.exact && exact.index == 50, "content-type image/png is line 50, exactly");
    const StaticMatch by_name = find_static(name, sizeof name, bmp, sizeof bmp);
    check(!by_name.exact && by_name.index == 44, "an unknown type: the first content-type line, by name");
    const StaticMatch none = find_static(png, sizeof png, png, sizeof png);
    check(none.index == kStaticLines, "no name, no line");
}

/**
 * @brief
 * \~english Appendix B, the decoder's half: every section, every table size, every decoder stream byte.
 * \~spanish El apendice B, la mitad del descodificador: cada seccion, cada tamano de tabla, cada byte del flujo del descodificador.
 * \~
 */
void test_appendix_b() {
    Decoder d;
    check(d.reset(config(220, 1)), "the decoder starts");
    Lines l;

    section("B.1");
    check(read(d, 0, "0000510b2f696e6465782e68746d6c", l) == Outcome::Done, "a literal with a static name");
    check(l.got.size() == 1 && l.got[0] == ":path=/index.html", ":path=/index.html");
    check(said(d, ""), "no table, no acknowledgment");

    section("B.2");
    check(feed(d, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"), "capacity and two inserts");
    check(d.table().capacity() == 220 && d.table().size() == 106 && d.table().inserted() == 2, "Size=106");
    l.got.clear();
    check(read(d, 4, "03811011", l) == Outcome::Done, "two post-Base references");
    check(l.got.size() == 2 && l.got[0] == ":authority=www.example.com" && l.got[1] == ":path=/sample/path",
          ":authority and :path from the table");
    check(d.flush() && said(d, "84"), "Section Acknowledgment (stream=4), and no increment: it covered them");
    check(d.known_received() == 2, "known received 2");

    section("B.3");
    check(feed(d, "4a637573746f6d2d6b65790c637573746f6d2d76616c7565"), "insert with a literal name");
    check(d.table().size() == 160, "Size=160");
    check(d.flush() && said(d, "01"), "Insert Count Increment (1)");
    check(d.flush() && said(d, "") && d.known_received() == 3, "and not twice");

    section("B.4");
    // \~english The section arrives before the Duplicate it needs: blocked, then cancelled.
    // \~spanish La seccion llega antes que el Duplicate que necesita: bloqueada, y despues cancelada.  \~
    l.got.clear();
    check(read(d, 8, "050080c181", l) == Outcome::Blocked && d.blocked() == 1, "Required Insert Count 4 with 3 in: blocked");
    d.cancel_stream(8);
    check(said(d, "48") && d.blocked() == 0, "Stream Cancellation (Stream=8)");
    check(feed(d, "02"), "Duplicate (Relative Index = 2)");
    check(d.table().size() == 217 && d.table().inserted() == 4, "Size=217");
    l.got.clear();
    check(read(d, 8, "050080c181", l) == Outcome::Done, "the same section once it can be read");
    check(l.got.size() == 3 && l.got[0] == ":authority=www.example.com" && l.got[1] == ":path=/" &&
              l.got[2] == "custom-key=custom-value",
          "the duplicate, a static line and custom-key");
    check(said(d, "88"), "acknowledged");

    section("B.5");
    check(feed(d, "810d637573746f6d2d76616c756532"), "insert with a dynamic name reference");
    check(d.table().size() == 215 && d.table().inserted() == 5 && d.table().dropped() == 1, "Size=215, entry 0 evicted");
    Buffer out;
    Span s;
    check(d.table().copy_value(4, out, s) && s.len == 13 && std::memcmp(out.data() + s.off, "custom-value2", 13) == 0,
          "custom-key=custom-value2 at absolute 4");
    check(!d.failed(), "nothing failed");
}

/// \~english A decoder fed @p enc, reading @p sec; expects failure @p code.  \~spanish Un descodificador al que se da @p enc, leyendo @p sec; espera el fallo @p code.  \~
void expect_failure(const char *enc, const char *sec, uint64_t code, const char *why, const char *what,
                    uint64_t capacity = 220) {
    Decoder d;
    d.reset(config(capacity, 1));
    Lines l;
    if (enc != nullptr) feed(d, enc);
    if (sec != nullptr && !d.failed()) read(d, 4, sec, l);
    // \~english The code and the rule: two rules can end in one code.  \~spanish El codigo y la regla: dos reglas pueden acabar en un codigo.  \~
    if (d.failed() && d.failure().code == code && std::strstr(d.failure().why, why) != nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: want 0x%llx, got 0x%llx (%s)\n", current, what,
                 static_cast<unsigned long long>(code), static_cast<unsigned long long>(d.failure().code),
                 d.failure().why != nullptr ? d.failure().why : "no failure");
    ++failures;
}

void test_encoder_stream_rules() {
    section("encoder stream rules");
    expect_failure("3fbe01", nullptr, kEncoderStreamError, "above the maximum", "a capacity above the maximum (4.3.1)");
    expect_failure("3fbd01ff2400", nullptr, kEncoderStreamError, "static line that does not exist",
                   "an insert naming static line 99 (3.1)");
    expect_failure("3fbd018000", nullptr, kEncoderStreamError, "naming an entry before the first insert",
                   "an insert naming a dynamic entry before any (3.2.5)");
    expect_failure("3fbd0100", nullptr, kEncoderStreamError, "duplicate of an entry before the first insert",
                   "a duplicate before any insert (3.2.5)");
    // \~english Capacity 32 and an entry of 42, then one of 33: one byte over is over.
    // \~spanish Capacidad 32 y una entrada de 42, y luego una de 33: un byte de mas es de mas.  \~
    expect_failure("3f01c000", nullptr, kEncoderStreamError, "larger than the table's capacity",
                   "an entry larger than the capacity (3.2.2)");
    expect_failure("3f01400141", nullptr, kEncoderStreamError, "larger than the table's capacity",
                   "an entry one byte larger than the capacity (3.2.2)");
    {
        Decoder d;
        d.reset(config(220, 1));
        check(feed(d, "3f014000") && d.table().size() == 32, "an entry exactly the capacity fits");
    }
    // \~english Capacity 64, two entries of 32 and 33: the first goes, and naming it fails.
    // \~spanish Capacidad 64, dos entradas de 32 y 33: la primera se va, y nombrarla falla.  \~
    expect_failure("3f21400040014101", nullptr, kEncoderStreamError, "duplicate of an evicted",
                   "a duplicate of an evicted entry (2.2.3)");
    expect_failure("3fbd0162ffff", nullptr, kEncoderStreamError, "name that does not decode",
                   "a name that does not decode (4.1.2)");

    section("capacity reduced");
    {
        Decoder d;
        d.reset(config(220, 1));
        feed(d, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
        check(feed(d, "3f1b") && d.table().count() == 1 && d.table().dropped() == 1 && d.table().size() == 49,
              "a smaller capacity evicts at once (3.2.2)");
        check(feed(d, "20") && d.table().count() == 0 && d.table().size() == 0, "and zero empties the table");
        check(d.table().inserted() == 2, "but the insert count stays");
    }

    section("encoder stream in pieces");
    const Hex all("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f706174684a637573746f6d2d6b65790c637573746f6d2d76616c7565");
    Decoder d;
    d.reset(config(220, 1));
    for (size_t i = 0; i < all.n; ++i) check(d.on_encoder_stream(all.b + i, 1), "a byte at a time");
    check(d.table().inserted() == 3 && d.table().size() == 160, "is the same table as all at once");
    check(d.flush() && said(d, "03"), "and one increment for all three");

    section("encoder stream cost");
    {
        // \~english A 1000-byte value a byte at a time: read again only once its length is in and all of it is here.
        // \~spanish Un valor de 1000 bytes byte a byte: se vuelve a leer solo cuando su longitud esta y ha llegado entero.  \~
        Decoder e;
        e.reset(config(4096, 1));
        feed(e, "3fe11f");
        const uint8_t head[] = {0x40, 0x7f, 0xe9, 0x06};
        for (uint8_t h : head) e.on_encoder_stream(&h, 1);
        const uint8_t x = 'x';
        for (int i = 0; i < 1000; ++i) e.on_encoder_stream(&x, 1);
        check(e.table().inserted() == 1 && e.table().size() == 1032, "the insert lands");
        check(e.instruction_reads() < 10, "for a handful of reads, not a thousand");
    }

    section("encoder stream limits");
    {
        DecoderConfig c = config(4096, 1);
        c.max_string = 8;
        Decoder e;
        e.reset(c);
        // \~english A 9-byte value, refused from its length before its bytes arrive.
        // \~spanish Un valor de 9 bytes, rechazado por su longitud antes de que lleguen sus bytes.  \~
        const Hex h("3fe11fc009");
        check(!e.on_encoder_stream(h.b, h.n) && e.failure().code == kEncoderStreamError, "a value past max_string (7.4)");
    }
}

void test_section_rules() {
    section("section rules");
    const char *two = "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468";
    expect_failure(two, "0e00", kDecompressionFailed, "no conformant encoder",
                   "an Encoded Insert Count past 2 * MaxEntries (4.5.1.1)");
    // \~english 220 bytes: MaxEntries 6; nothing in, so MaxValue 6, and 8 decodes to 7 -- past it, and not wrappable.
    // \~spanish 220 bytes: MaxEntries 6; nada dentro, asi que MaxValue 6, y 8 da 7 -- pasado, y sin poder envolverse.  \~
    expect_failure(nullptr, "0800", kDecompressionFailed, "no conformant encoder",
                   "an Encoded Insert Count past MaxValue that cannot have wrapped (4.5.1.1)");
    expect_failure(two, "0281", kDecompressionFailed, "negative Base",
                   "a negative Base: sign 1 with Delta Base = RIC (4.5.1.2)");
    expect_failure(nullptr, "0000ff24", kDecompressionFailed, "static line that does not exist", "static line 99 (3.1)");
    expect_failure(two, "030082", kDecompressionFailed, "below the Base's first entry",
                   "a relative index equal to the Base (3.2.5)");
    expect_failure(two, "020010", kDecompressionFailed, "at or past the Required Insert Count",
                   "a reference at the Required Insert Count (2.2.3)");
    expect_failure(two, "0300c1", kDecompressionFailed, "larger than the references need",
                   "a Required Insert Count with only static lines (2.2.1)");
    expect_failure(two, "030081", kDecompressionFailed, "larger than the references need",
                   "a Required Insert Count past the largest dynamic reference (2.2.1)");
    expect_failure(two, "0381", kDecompressionFailed, "larger than the references need",
                   "no line: a Required Insert Count larger than needed (2.2.1)");
    expect_failure(nullptr, "00", kDecompressionFailed, "prefix cut short", "a prefix cut short (4.5.1)");
    expect_failure(nullptr, "00005f", kDecompressionFailed, "line cut short", "a line cut short (4.5)");
    expect_failure(nullptr, "0000510b2f69", kDecompressionFailed, "value cut short", "a value cut short (4.1.2)");
    expect_failure(nullptr, "0100", kDecompressionFailed, "no conformant encoder",
                   "a dynamic reference with no table (4.5.1.1)", 0);
    // \~english Capacity 64: an entry of 33 evicts the first; a section still naming it fails.
    // \~spanish Capacidad 64: una entrada de 33 desaloja la primera; una seccion que aun la nombre falla.  \~
    expect_failure("3f214000400141", "020080", kDecompressionFailed, "evicted entry",
                   "a reference to an evicted entry (2.2.3)", 64);

    section("blocked streams");
    {
        Decoder d;
        d.reset(config(220, 1));
        Lines l;
        check(read(d, 4, "0381 1011", l) == Outcome::Blocked, "one blocked stream is allowed");
        check(read(d, 4, "0381 1011", l) == Outcome::Blocked && d.blocked() == 1, "and the same one again is still one");
        check(read(d, 8, "0381 1011", l) == Outcome::Failed && d.failure().code == kDecompressionFailed,
              "a second is more than announced (2.1.2)");
    }
    {
        Decoder d;
        d.reset(config(220, 2));
        Lines l;
        check(read(d, 4, "03811011", l) == Outcome::Blocked, "blocked before the inserts");
        uint64_t ids[4];
        check(d.take_unblocked(ids, 4) == 0, "nothing to unblock yet");
        feed(d, "3fbd01c00f7777772e6578616d706c652e636f6d");
        check(d.take_unblocked(ids, 4) == 0, "one insert is not enough");
        feed(d, "c10c2f73616d706c652f70617468");
        check(d.take_unblocked(ids, 4) == 1 && ids[0] == 4 && d.blocked() == 0, "the second unblocks stream 4");
        check(read(d, 4, "03811011", l) == Outcome::Done && l.got.size() == 2, "and it reads");
        check(d.flush() && said(d, "84"), "acknowledged, the inserts with it");
    }
    {
        // \~english Handed back without asking take_unblocked: reading it frees its place too.
        // \~spanish Devuelta sin pasar por take_unblocked: leerla tambien libera su sitio.  \~
        Decoder d;
        d.reset(config(220, 1));
        Lines l;
        check(read(d, 4, "03811011", l) == Outcome::Blocked, "blocked");
        feed(d, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
        check(read(d, 4, "03811011", l) == Outcome::Done && d.blocked() == 0, "read once it can be: no longer blocked");
        check(read(d, 8, "05811011", l) == Outcome::Blocked, "so another stream may block");
    }

    section("wrapped Required Insert Count");
    {
        // \~english 4.5.1.1's example: 100 bytes, so modulo 6; ten inserts in, an encoded 4 is 9.
        // \~spanish El ejemplo de 4.5.1.1: 100 bytes, asi que modulo 6; con diez inserciones, un 4 codificado es 9.  \~
        Decoder d;
        d.reset(config(100, 1));
        feed(d, "3f45");
        for (int i = 0; i < 10; ++i) feed(d, "4000");
        Lines l;
        check(read(d, 4, "040080", l) == Outcome::Done && l.got.size() == 1 && l.got[0] == "=",
              "RIC 9, Base 9, relative 0: absolute 8");
        check(said(d, "84"), "acknowledged");
    }

    section("never indexed");
    {
        Decoder d;
        d.reset(config(0, 0));
        Lines l;
        // \~english 4.5.4 with N, and 4.5.6 with N: authorization and a literal name.
        // \~spanish 4.5.4 con N, y 4.5.6 con N: authorization y un nombre literal.  \~
        check(read(d, 0, "00007f4503736563 33782d61017a", l) == Outcome::Done, "two literals with N");
        check(l.got.size() == 2 && l.got[0] == "!authorization=sec" && l.got[1] == "!x-a=z", "the N bit comes out");
    }

    section("limits");
    {
        DecoderConfig c = config(220, 1);
        c.max_section = 64;
        Decoder d;
        d.reset(c);
        feed(d, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
        Lines l;
        // \~english 57 + 49 > 64: the second line is past the limit, read, and thrown away.
        // \~spanish 57 + 49 > 64: la segunda linea pasa el limite, se lee, y se tira.  \~
        check(read(d, 4, "03811011", l) == Outcome::TooLarge && l.got.size() == 1, "a section past max_section");
        check(said(d, "84"), "is still acknowledged: the references are released");
        check(!d.failed(), "and the connection goes on");
    }
    {
        DecoderConfig c = config(0, 0);
        c.max_string = 4;
        Decoder d;
        d.reset(c);
        Lines l;
        check(read(d, 0, "0000510b2f696e6465782e68746d6c", l) == Outcome::StreamFailed && !d.failed(),
              "a value past max_string is a stream error (7.4)");
    }
    {
        Decoder d;
        d.reset(config(220, 1));
        feed(d, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
        Lines l;
        l.refuse_at = 1;
        check(read(d, 4, "03811011", l) == Outcome::Rejected && said(d, ""), "refused above: no acknowledgment");
        d.cancel_stream(4);
        check(said(d, "44"), "the caller cancels the stream");
    }
    {
        Decoder d;
        d.reset(config(0, 0));
        d.cancel_stream(4);
        check(said(d, ""), "no table: the cancellation is left out (2.2.2.2)");
    }
}

} // namespace

int main() {
    test_integers();
    test_strings();
    test_static();
    test_appendix_b();
    test_encoder_stream_rules();
    test_section_rules();
    if (failures != 0) {
        std::fprintf(stderr, "qpack: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("qpack: OK\n");
    return 0;
}
