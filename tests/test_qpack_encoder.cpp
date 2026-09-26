/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_qpack_encoder.cpp
 * @brief
 * \~english QPACK's encoder against this project's decoder, and against every rule of RFC 9204 it keeps.
 * \~spanish El codificador de QPACK contra el descodificador de este proyecto, y contra cada regla del RFC 9204 que cumple.
 * \~
 *
 * \~english
 * The decoder was checked against the RFC's own bytes (test_qpack); here it
 * is the judge.  Every section the encoder writes must come out of it as
 * the lines that went in, whatever order the three streams arrive in.  And
 * each thing the encoder must keep track of -- evictable entries, blocked
 * streams, the Known Received Count, flow control on the encoder stream --
 * is pushed to its edge and looked at.
 * \~spanish
 * El descodificador se comprobo contra los propios bytes del RFC (test_qpack);
 * aqui hace de juez.  Cada seccion que escribe el codificador debe salir de el
 * como las lineas que entraron, lleguen los tres flujos en el orden que lleguen.
 * Y cada cosa que el codificador debe seguir -- entradas desalojables, flujos
 * bloqueados, el Known Received Count, el control de flujo en el flujo del
 * codificador -- se lleva a su limite y se mira.
 * \~
 */

#include "http_vx/qpack_decoder.h"
#include "http_vx/qpack_encoder.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace http_vx::qpack;
using http_vx::Buffer;

int failures = 0;
char current[64] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

void section(const char *name) { std::snprintf(current, sizeof current, "%s", name); }

/// \~english A line from text, "name=value"; a leading '!' asks for Never.  \~spanish Una linea desde texto, "nombre=valor"; un '!' delante pide Never.  \~
struct Text {
    std::string name;
    std::string value;
    Indexing indexing = Indexing::Insert;
};

Text text(const char *s, Indexing ix = Indexing::Insert) {
    Text t;
    std::string all = s;
    const size_t eq = all.find('=');
    t.name = all.substr(0, eq);
    t.value = all.substr(eq + 1);
    t.indexing = ix;
    return t;
}

/// \~english The lines as the decoder gives them back, never-indexed ones with a '!'.
/// \~spanish Las lineas como las devuelve el descodificador, las de nunca indexar con un '!'.  \~
struct Lines final : FieldSink {
    std::vector<std::string> got;
    bool field(const Buffer &out, const FieldLine &line) noexcept override {
        std::string s = line.never_indexed ? "!" : "";
        s.append(reinterpret_cast<const char *>(out.data()) + line.name.off, line.name.len);
        s += '=';
        s.append(reinterpret_cast<const char *>(out.data()) + line.value.off, line.value.len);
        got.push_back(s);
        return true;
    }
};

/// \~english What the decoder should give back for @p in.  \~spanish Lo que el descodificador deberia devolver para @p in.  \~
std::vector<std::string> expected(const std::vector<Text> &in) {
    std::vector<std::string> out;
    for (const Text &t : in) out.push_back((t.indexing == Indexing::Never ? "!" : "") + t.name + "=" + t.value);
    return out;
}

/**
 * @brief
 * \~english An encoder and a decoder, and the three streams between them.
 * \~spanish Un codificador y un descodificador, y los tres flujos entre ellos.
 * \~
 */
struct Pair {
    Encoder enc;
    Decoder dec;

    explicit Pair(uint64_t capacity, uint64_t blocked, uint64_t own = 4096) {
        EncoderConfig ec;
        ec.max_capacity = own;
        enc.reset(ec);
        DecoderConfig dc;
        dc.max_table_capacity = capacity;
        dc.blocked_streams = blocked;
        dec.reset(dc);
    }

    /// \~english Encodes @p lines for @p stream into @p block.  \~spanish Codifica @p lines para @p stream en @p block.  \~
    bool encode(uint64_t stream, const std::vector<Text> &lines, std::vector<uint8_t> &block, size_t room = 1 << 20) {
        std::vector<Line> ls(lines.size());
        for (size_t i = 0; i < lines.size(); ++i) {
            ls[i].name = reinterpret_cast<const uint8_t *>(lines[i].name.data());
            ls[i].name_len = lines[i].name.size();
            ls[i].value = reinterpret_cast<const uint8_t *>(lines[i].value.data());
            ls[i].value_len = lines[i].value.size();
            ls[i].indexing = lines[i].indexing;
        }
        Buffer out;
        const bool ok = enc.encode(stream, ls.data(), ls.size(), out, room);
        block.assign(out.data(), out.data() + out.size());
        return ok;
    }

    /// \~english Up to @p n encoder stream bytes to the decoder.  \~spanish Hasta @p n bytes del flujo del codificador al descodificador.  \~
    size_t to_decoder(size_t n = ~size_t{0}) {
        size_t have = 0;
        const uint8_t *p = enc.output(have);
        const size_t k = have < n ? have : n;
        if (k != 0) dec.on_encoder_stream(p, k);
        enc.sent(k);
        return k;
    }

    /// \~english The decoder stream back to the encoder, after a flush.  \~spanish El flujo del descodificador de vuelta al codificador, tras un flush.  \~
    void to_encoder() {
        dec.flush();
        size_t n = 0;
        const uint8_t *p = dec.output(n);
        if (n != 0) enc.on_decoder_stream(p, n);
        dec.sent(n);
    }

    Outcome decode(uint64_t stream, const std::vector<uint8_t> &block, Lines &l) {
        Buffer out;
        return dec.decode(stream, block.data(), block.size(), out, l);
    }
};

/// \~english The encoder stream right now, as hex.  \~spanish El flujo del codificador ahora mismo, en hex.  \~
std::string pending_hex(Encoder &e) {
    size_t n = 0;
    const uint8_t *p = e.output(n);
    std::string s;
    char b[3];
    for (size_t i = 0; i < n; ++i) {
        std::snprintf(b, sizeof b, "%02x", p[i]);
        s += b;
    }
    return s;
}

void test_no_table() {
    section("no table");
    Pair p(0, 0);
    check(p.enc.on_peer_settings(0, 0), "a peer with no table");
    const std::vector<Text> in = {text(":method=GET"), text(":path=/index.html"), text("x-custom=foo")};
    std::vector<uint8_t> block;
    check(p.encode(0, in, block), "encodes");
    check(block.size() >= 3 && block[0] == 0x00 && block[1] == 0x00 && block[2] == 0xd1,
          "prefix 0, 0; :method GET is static line 17: d1");
    check(pending_hex(p.enc).empty(), "no encoder instruction at all (3.2.3)");
    Lines l;
    check(p.decode(0, block, l) == Outcome::Done && l.got == expected(in), "the decoder gives the lines back");
}

void test_table() {
    section("table");
    Pair p(220, 1);
    check(p.enc.on_peer_settings(220, 1), "a peer with 220 bytes");
    check(pending_hex(p.enc) == "3fbd01", "Set Dynamic Table Capacity=220, as Appendix B.2");
    const std::vector<Text> in = {text(":authority=www.example.com"), text(":path=/sample/path")};
    std::vector<uint8_t> block;
    check(p.encode(4, in, block), "encodes");
    check(p.enc.table().inserted() == 2 && p.enc.pending() == 1, "two inserts, one section waiting");
    p.to_decoder();
    Lines l;
    check(p.decode(4, block, l) == Outcome::Done && l.got == expected(in), "decodes");
    check(p.dec.table().size() == 106, "the decoder's table is Appendix B.2's, Size=106");
    p.to_encoder();
    check(p.enc.pending() == 0 && p.enc.known_received() == 2, "acknowledged: known received 2");

    section("table, again");
    check(p.encode(8, in, block), "the same lines again");
    check(pending_hex(p.enc).empty(), "nothing new on the encoder stream");
    check(block.size() == 4 && block[2] == 0x81 && block[3] == 0x80, "two relative references, one byte each");
    l.got.clear();
    check(p.decode(8, block, l) == Outcome::Done && l.got == expected(in), "decodes at once: nothing to wait for");
}

void test_blocking() {
    section("no blocked streams");
    {
        Pair p(220, 0);
        p.enc.on_peer_settings(220, 0);
        p.to_decoder();
        const std::vector<Text> in = {text("x-a=one")};
        std::vector<uint8_t> block;
        p.encode(4, in, block);
        check(p.enc.table().inserted() == 1, "inserted anyway, for later");
        Lines l;
        check(p.decode(4, block, l) == Outcome::Done && l.got == expected(in),
              "but referenced as a literal: decodes before the insert arrives (2.1.2)");
        p.to_decoder();
        p.to_encoder();
        check(p.enc.known_received() == 1, "the Insert Count Increment arrives");
        p.encode(8, in, block);
        check(block.size() == 3 && block[0] == 0x02 && block[2] == 0x80, "and now it is referenced: RIC 1");
        l.got.clear();
        check(p.decode(8, block, l) == Outcome::Done && l.got == expected(in), "decodes");
    }
    section("unacknowledged, not blockable");
    {
        Pair p(220, 0);
        p.enc.on_peer_settings(220, 0);
        std::vector<uint8_t> b1, b2;
        const std::vector<Text> in = {text("x-a=one")};
        p.encode(4, in, b1);
        p.encode(8, in, b2);
        Lines l;
        check(p.decode(8, b2, l) == Outcome::Done,
              "an entry still in flight is not referenced by a stream that may not block (2.1.2)");
    }
    section("acknowledged sections do not block");
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        const std::vector<Text> a = {text("x-a=one")};
        std::vector<uint8_t> b;
        p.encode(4, a, b);
        p.to_decoder();
        Lines first;
        p.decode(4, b, first);
        p.to_encoder();
        // \~english Stream 4 references an acknowledged entry: it waits for its ack, but it cannot block.
        // \~spanish El flujo 4 referencia una entrada confirmada: espera su confirmacion, pero no puede bloquear.  \~
        std::vector<uint8_t> b4, b8, b4b;
        p.encode(4, a, b4);
        check(p.enc.pending() == 1 && p.enc.blocking_streams() == 0, "a pending section that cannot block");
        p.encode(8, {text("x-b=two")}, b8);
        check(b8.size() >= 1 && b8[0] != 0x00, "so stream 8 may still reference its new entry");
        check(p.enc.blocking_streams() == 1, "and it is the one blocked stream");
        p.encode(4, {text("x-c=three")}, b4b);
        check(p.enc.blocking_streams() == 1, "stream 4 is not blocking, so it may not add a second");
        p.to_decoder(0);
        Lines l;
        check(p.decode(8, b8, l) == Outcome::Blocked && p.decode(4, b4b, l) != Outcome::Failed && !p.dec.failed(),
              "the decoder sees one blocked stream, as allowed");
    }
    section("one blocked stream");
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        p.to_decoder();
        const std::vector<Text> a = {text("x-a=one")};
        const std::vector<Text> b = {text("x-b=two")};
        std::vector<uint8_t> ba, bb;
        p.encode(4, a, ba);
        p.encode(8, b, bb);
        check(p.enc.blocking_streams() == 1, "only one stream may be blocked, and only one is");
        Lines l;
        check(p.decode(4, ba, l) == Outcome::Blocked, "stream 4 references what is still in flight");
        check(p.decode(8, bb, l) == Outcome::Done, "stream 8 had to use a literal");
        p.to_decoder();
        uint64_t ids[2];
        check(p.dec.take_unblocked(ids, 2) == 1 && ids[0] == 4, "the inserts unblock stream 4");
        l.got.clear();
        check(p.decode(4, ba, l) == Outcome::Done && l.got == expected(a), "and it decodes");
        check(!p.dec.failed(), "the decoder never saw more blocked streams than it allows");
    }
}

void test_indexing() {
    section("never indexed");
    Pair p(220, 1);
    p.enc.on_peer_settings(220, 1);
    p.to_decoder();
    const std::vector<Text> in = {text("authorization=secret", Indexing::Never), text("x-t=token", Indexing::Never)};
    std::vector<uint8_t> block;
    p.encode(4, in, block);
    check(p.enc.table().inserted() == 0 && pending_hex(p.enc).empty(), "never inserted (7.1.3)");
    Lines l;
    check(p.decode(4, block, l) == Outcome::Done && l.got == expected(in), "and the 'N' bit comes out");

    section("no insert");
    const std::vector<Text> ni = {text("x-once=abc", Indexing::NoInsert)};
    p.encode(8, ni, block);
    check(p.enc.table().inserted() == 0, "NoInsert inserts nothing");

    section("flow control");
    const std::vector<Text> big = {text("x-big=0123456789")};
    {
        // \~english Room for exactly one of two inserts: the second finds it spent.
        // \~spanish Sitio para exactamente una de dos inserciones: la segunda lo encuentra gastado.  \~
        Pair q(220, 1);
        q.enc.on_peer_settings(220, 1);
        q.to_decoder();
        const std::vector<Text> two = {text("x-one=1"), text("x-two=2")};
        std::vector<uint8_t> b;
        const size_t one = str_size(reinterpret_cast<const uint8_t *>("x-one"), 5, 6) +
                           str_size(reinterpret_cast<const uint8_t *>("1"), 1, 8);
        q.encode(4, two, b, one);
        check(q.enc.table().inserted() == 1, "the room is spent by the first (2.1.3)");
    }
    p.encode(12, big, block, 5);
    check(p.enc.table().inserted() == 0 && pending_hex(p.enc).empty(), "an insert past the room is not written (2.1.3)");
    l.got.clear();
    check(p.decode(12, block, l) == Outcome::Done && l.got == expected(big), "the line goes as a literal");
}

void test_eviction() {
    section("eviction");
    // \~english 100 bytes: two entries of 40 fit, a third needs one out.  \~spanish 100 bytes: caben dos entradas de 40, una tercera necesita sacar una.  \~
    Pair p(100, 4);
    p.enc.on_peer_settings(100, 4);
    const std::vector<Text> first = {text("x-a=12345"), text("x-b=12345")};
    std::vector<uint8_t> b1, b2, b3;
    p.encode(4, first, b1);
    p.to_decoder();
    p.to_encoder();
    check(p.enc.known_received() == 2 && p.enc.pending() == 1, "acknowledged inserts, section 4 still waiting");
    const std::vector<Text> third = {text("x-c=12345")};
    p.encode(8, third, b2);
    check(p.enc.table().inserted() == 2 && p.enc.table().dropped() == 0,
          "an insert that would evict an entry still referenced is not made (2.1.1)");
    Lines l;
    check(p.decode(4, b1, l) == Outcome::Done, "section 4 decodes");
    p.to_encoder();
    check(p.enc.pending() == 0, "and is acknowledged");
    p.encode(12, third, b3);
    check(p.enc.table().inserted() == 3 && p.enc.table().dropped() == 1, "now the oldest may go");
    p.to_decoder();
    l.got.clear();
    check(p.decode(12, b3, l) == Outcome::Done && l.got == expected(third), "and the new entry decodes");

    section("unacknowledged, unreferenced");
    {
        // \~english No blocked streams: the inserts are referenced by nothing, and still may not go before they are acknowledged (2.1.1).
        // \~spanish Sin flujos bloqueados: nada referencia las inserciones, y aun asi no pueden irse antes de confirmarse (2.1.1).  \~
        Pair q(100, 0);
        q.enc.on_peer_settings(100, 0);
        std::vector<uint8_t> b;
        q.encode(4, first, b);
        check(q.enc.table().inserted() == 2 && q.enc.pending() == 0, "two inserts, no section waiting");
        q.encode(8, third, b);
        check(q.enc.table().inserted() == 2 && q.enc.table().dropped() == 0, "the third waits for the acknowledgment");
    }
    section("cancellation");
    {
        Pair q(100, 4);
        q.enc.on_peer_settings(100, 4);
        std::vector<uint8_t> b;
        q.encode(4, first, b);
        q.to_decoder();
        q.dec.cancel_stream(4);
        q.to_encoder();
        check(q.enc.pending() == 0, "a cancelled stream releases its references (4.4.2)");
        check(q.enc.known_received() == 2, "the flush still told the encoder about the inserts");
    }
}

void expect_failure(Encoder &e, const char *hex, const char *why, const char *what) {
    uint8_t b[16];
    size_t n = 0;
    for (const char *h = hex; h[0] != '\0' && h[1] != '\0'; h += 2) {
        unsigned v = 0;
        std::sscanf(h, "%2x", &v);
        b[n++] = static_cast<uint8_t>(v);
    }
    e.on_decoder_stream(b, n);
    if (e.failed() && e.failure().code == kDecoderStreamError && std::strstr(e.failure().why, why) != nullptr) return;
    std::fprintf(stderr, "FAIL [%s]: %s: got 0x%llx (%s)\n", current, what,
                 static_cast<unsigned long long>(e.failure().code), e.failure().why != nullptr ? e.failure().why : "no failure");
    ++failures;
}

void test_decoder_stream_rules() {
    section("decoder stream rules");
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        expect_failure(p.enc, "84", "nothing to acknowledge", "a Section Acknowledgment with nothing pending (4.4.1)");
    }
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        expect_failure(p.enc, "00", "of zero", "an Insert Count Increment of zero (4.4.3)");
    }
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        std::vector<uint8_t> b;
        p.encode(4, {text("x-a=1")}, b);
        expect_failure(p.enc, "02", "past what was inserted", "an Insert Count Increment past the inserts (4.4.3)");
    }
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        std::vector<uint8_t> b;
        p.encode(4, {text("x-a=1")}, b);
        p.to_decoder();
        Lines l;
        p.decode(4, b, l);
        p.to_encoder();
        expect_failure(p.enc, "84", "nothing to acknowledge", "the same section acknowledged twice (4.4.1)");
    }
    section("decoder stream in pieces");
    {
        Pair p(220, 1);
        p.enc.on_peer_settings(220, 1);
        std::vector<uint8_t> b;
        p.encode(200, {text("x-a=1")}, b);
        // \~english Stream 200 needs two bytes: ff 49.  \~spanish El flujo 200 necesita dos bytes: ff 49.  \~
        const uint8_t ack[2] = {0xff, 0x49};
        check(p.enc.on_decoder_stream(ack, 1) && p.enc.pending() == 1, "half an acknowledgment waits");
        check(p.enc.on_decoder_stream(ack + 1, 1) && p.enc.pending() == 0 && p.enc.known_received() == 1,
              "the rest completes it");
    }
}

void test_settings() {
    section("remembered settings");
    {
        Encoder e;
        e.reset(EncoderConfig{});
        check(e.remember_peer_settings(220, 1) && pending_hex(e) == "3fbd01", "0-RTT starts with the remembered table");
        check(e.on_peer_settings(220, 1), "the same capacity comes back");
    }
    {
        Encoder e;
        e.reset(EncoderConfig{});
        e.remember_peer_settings(220, 1);
        check(!e.on_peer_settings(100, 1) && e.failure().code == kDecoderStreamError,
              "a remembered non-zero capacity changed (3.2.3)");
    }
    {
        Encoder e;
        e.reset(EncoderConfig{});
        e.remember_peer_settings(0, 0);
        check(pending_hex(e).empty(), "remembered zero: no table yet");
        check(e.on_peer_settings(220, 1) && pending_hex(e) == "3fbd01", "the server may start one (3.2.3)");
    }
    {
        EncoderConfig c;
        c.max_capacity = 100;
        Encoder e;
        e.reset(c);
        check(e.on_peer_settings(4096, 1) && pending_hex(e) == "3f45", "this end keeps only what it wants: 100");
        check(!e.on_peer_settings(4096, 1), "the settings come once");
    }
    {
        Encoder e;
        e.reset(EncoderConfig{});
        check(e.on_peer_settings(20, 1) && pending_hex(e).empty(), "a table too small for any entry is not started");
    }
}

void test_limits() {
    section("references per section");
    {
        Pair p(4096, 4);
        p.enc.on_peer_settings(4096, 4);
        std::vector<Text> many;
        char buf[32];
        for (int i = 0; i < 20; ++i) {
            std::snprintf(buf, sizeof buf, "x-%02d=v", i);
            many.push_back(text(buf));
        }
        std::vector<uint8_t> b;
        p.encode(4, many, b);
        p.to_decoder();
        p.to_encoder();
        p.encode(8, many, b);
        p.to_decoder();
        Lines l;
        check(p.decode(8, b, l) == Outcome::Done && l.got == expected(many),
              "twenty known lines, sixteen by reference and the rest as literals, all come out");
    }
    section("repeated lines");
    {
        Pair p(4096, 4);
        p.enc.on_peer_settings(4096, 4);
        std::vector<Text> same(17, text("x-same=v"));
        std::vector<uint8_t> b;
        p.encode(4, same, b);
        check(b.size() == 2 + 17, "one entry seventeen times is one reference, not seventeen: all one-byte lines");
    }
    section("references released");
    {
        // \~english 800 bytes: 21 entries of 37.  Past sixteen references the count must still add up.
        // \~spanish 800 bytes: 21 entradas de 37.  Pasadas dieciseis referencias la cuenta debe seguir cuadrando.  \~
        Pair p(800, 4);
        p.enc.on_peer_settings(800, 4);
        std::vector<Text> many, more;
        char buf[32];
        for (int i = 0; i < 20; ++i) {
            std::snprintf(buf, sizeof buf, "x-%02d=v", i);
            many.push_back(text(buf));
            std::snprintf(buf, sizeof buf, "y-%02d=v", i);
            more.push_back(text(buf));
        }
        std::vector<uint8_t> b;
        p.encode(4, many, b);
        p.to_decoder();
        Lines l;
        p.decode(4, b, l);
        p.to_encoder();
        check(p.enc.pending() == 0 && p.enc.known_received() == 20, "acknowledged");
        p.encode(8, more, b);
        check(p.enc.table().dropped() > 0, "so the old entries may be evicted for new ones");
    }
    section("pending sections");
    {
        Pair p(4096, 200);
        p.enc.on_peer_settings(4096, 200);
        std::vector<uint8_t> b;
        for (size_t i = 0; i < Encoder::kPendingSections; ++i) p.encode(4 * i, {text("x-a=1")}, b);
        check(p.enc.pending() == Encoder::kPendingSections, "as many sections waiting as are tracked");
        p.encode(4 * Encoder::kPendingSections, {text("x-a=1")}, b);
        check(b.size() >= 2 && b[0] == 0 && b[1] == 0 && p.enc.pending() == Encoder::kPendingSections,
              "one more goes without the table (7.3)");
    }
}

/// \~english A small deterministic generator.  \~spanish Un generador pequeno y determinista.  \~
struct Rng {
    uint64_t s;
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    size_t below(size_t n) { return static_cast<size_t>(next() % n); }
};

/**
 * @brief
 * \~english Many sections on many streams, the three streams delivered in a shuffled order.
 * \~spanish Muchas secciones en muchos flujos, los tres flujos entregados en un orden barajado.
 * \~
 */
void test_shuffled(uint64_t capacity, uint64_t blocked, uint64_t seed) {
    char name[64];
    std::snprintf(name, sizeof name, "shuffled %llu/%llu", static_cast<unsigned long long>(capacity),
                  static_cast<unsigned long long>(blocked));
    section(name);
    Pair p(capacity, blocked);
    p.enc.on_peer_settings(capacity, blocked);
    Rng r{seed};
    const char *names[] = {"x-user", "x-trace", "cookie", "accept", "x-long-header-name", "content-type"};
    struct Waiting {
        uint64_t stream;
        std::vector<uint8_t> block;
        std::vector<std::string> want;
    };
    std::vector<Waiting> waiting;
    uint64_t stream = 0;
    size_t decoded = 0;
    for (int round = 0; round < 3000 && !p.dec.failed() && !p.enc.failed(); ++round) {
        const size_t action = r.below(6);
        if (action < 2) {
            std::vector<Text> lines;
            const size_t count = 1 + r.below(5);
            for (size_t i = 0; i < count; ++i) {
                Text t;
                t.name = names[r.below(6)];
                t.value = "v" + std::to_string(r.below(12));
                const size_t ix = r.below(10);
                t.indexing = ix == 0 ? Indexing::Never : ix == 1 ? Indexing::NoInsert : Indexing::Insert;
                lines.push_back(t);
            }
            Waiting w;
            w.stream = stream;
            stream += 4;
            p.encode(w.stream, lines, w.block, r.below(4) == 0 ? r.below(40) : 1 << 20);
            w.want = expected(lines);
            waiting.push_back(w);
        } else if (action == 2) {
            p.to_decoder(1 + r.below(30));
        } else if (action == 3) {
            p.to_encoder();
        } else if (!waiting.empty()) {
            const size_t i = r.below(waiting.size());
            Lines l;
            const Outcome o = p.decode(waiting[i].stream, waiting[i].block, l);
            if (o == Outcome::Done) {
                check(l.got == waiting[i].want, "a section comes out as it went in");
                waiting.erase(waiting.begin() + static_cast<long>(i));
                ++decoded;
            } else {
                check(o == Outcome::Blocked, "a section is either read or blocked");
            }
        }
    }
    // \~english Everything delivered in the end, and everything read.  \~spanish Todo entregado al final, y todo leido.  \~
    p.to_decoder();
    for (const Waiting &w : waiting) {
        Lines l;
        check(p.decode(w.stream, w.block, l) == Outcome::Done && l.got == w.want, "the rest come out once all is in");
        ++decoded;
    }
    p.to_encoder();
    check(!p.dec.failed() && !p.enc.failed(), "neither side failed");
    check(p.enc.pending() == 0, "every section acknowledged");
    check(p.enc.known_received() == p.enc.table().inserted(), "every insert known");
    check(decoded > 500, "and there were enough of them");
    check(capacity == 0 || p.enc.table().dropped() > 0 || capacity >= 4096, "small tables evicted along the way");
}

} // namespace

int main() {
    test_no_table();
    test_table();
    test_blocking();
    test_indexing();
    test_eviction();
    test_decoder_stream_rules();
    test_settings();
    test_limits();
    test_shuffled(0, 0, 1);
    test_shuffled(160, 0, 2);
    test_shuffled(160, 3, 3);
    test_shuffled(300, 16, 4);
    test_shuffled(4096, 100, 5);
    if (failures != 0) {
        std::fprintf(stderr, "qpack encoder: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("qpack encoder: OK\n");
    return 0;
}
