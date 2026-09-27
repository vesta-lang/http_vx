/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_open.cpp
 * @brief
 * \~english Open responses in HTTP/2, with no network: DATA frames, both windows, the budget, limits and every gone (HVX-5, 7.2).
 * \~spanish Respuestas abiertas en HTTP/2, sin red: tramas DATA, las dos ventanas, el presupuesto, topes y cada gone (HVX-5, 7.2).
 * \~
 *
 * \~english
 * Two harnesses.  Most cases run a whole shard over the memory backend, so
 * the kick queue, the asking for room and the limits are the real ones.  The
 * cases about exact amounts -- the connection's window, which takes 64 KiB of
 * body to shut and so does not fit the memory backend's record of what was
 * written, and the caller's budget -- drive the service by hand through a
 * port that counts what it is asked.
 * \~spanish
 * Dos arneses.  Casi todos los casos mueven un fragmento entero sobre el backend
 * de memoria, asi que la cola de avisos, pedir sitio y los topes son los de
 * verdad.  Los casos de cantidades exactas -- la ventana de la conexion, que
 * necesita 64 KiB de cuerpo para cerrarse y no cabe en lo que guarda el backend
 * de memoria de lo escrito, y el presupuesto de quien llama -- mueven el
 * servicio a mano con una puerta que cuenta lo que se le pide.
 * \~
 */

#include "http_vx/h2_hpack.h"
#include "http_vx/h2_huffman.h"
#include "http_vx/http2_service.h"
#include "http_vx/kick_queue.h"
#include "http_vx/memory_backend.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

using http_vx::BodySource;
using http_vx::Buffer;
using http_vx::ConnHandle;
using http_vx::GoneReason;
using http_vx::Handler;
using http_vx::Http2Service;
using http_vx::KickQueue;
using http_vx::KickTarget;
using http_vx::MemoryBackend;
using http_vx::OpenResponse;
using http_vx::Request;
using http_vx::ResponseBuilder;
using http_vx::Shard;
using http_vx::ShardConfig;
using http_vx::StreamPort;

using http_vx::h2::FrameType;
using http_vx::h2::kEndHeaders;
using http_vx::h2::kEndStream;
using http_vx::h2::kFrameHeaderSize;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/* ------------------------------------------------------------------------- *
 * \~english The client's side: frames out, frames back.
 * \~spanish El lado del cliente: tramas que salen, tramas que vuelven.
 * \~
 * ------------------------------------------------------------------------- */

/// \~english Bytes a client sends, frame by frame.  \~spanish Bytes que manda un cliente, trama a trama.  \~
struct Wire {
    uint8_t b[4096] = {};
    size_t n = 0;

    void raw(const void *p, size_t len) {
        std::memcpy(b + n, p, len);
        n += len;
    }

    void frame(FrameType type, uint8_t flags, uint32_t id, const uint8_t *p, size_t len) {
        const uint8_t h[9] = {static_cast<uint8_t>(len >> 16), static_cast<uint8_t>(len >> 8),
                              static_cast<uint8_t>(len), static_cast<uint8_t>(type), flags,
                              static_cast<uint8_t>((id >> 24) & 0x7F), static_cast<uint8_t>(id >> 16),
                              static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id)};
        raw(h, sizeof h);
        if (len != 0) raw(p, len);
    }

    /// \~english The preface and an empty SETTINGS.  \~spanish El preambulo y un SETTINGS vacio.  \~
    void hello() {
        raw("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
        frame(FrameType::Settings, 0, 0, nullptr, 0);
    }

    /// \~english The preface and SETTINGS_INITIAL_WINDOW_SIZE = @p window.  \~spanish El preambulo y SETTINGS_INITIAL_WINDOW_SIZE = @p window.  \~
    void hello_window(uint32_t window) {
        raw("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
        const uint8_t s[6] = {0x00, 0x04, static_cast<uint8_t>(window >> 24), static_cast<uint8_t>(window >> 16),
                              static_cast<uint8_t>(window >> 8), static_cast<uint8_t>(window)};
        frame(FrameType::Settings, 0, 0, s, sizeof s);
    }

    /// \~english A literal field nobody is to remember.  \~spanish Una cabecera literal que nadie debe recordar.  \~
    static void field(uint8_t *at, size_t &k, const char *name, const char *value) {
        const size_t nl = std::strlen(name);
        const size_t vl = std::strlen(value);
        at[k++] = 0x00;
        at[k++] = static_cast<uint8_t>(nl);
        std::memcpy(at + k, name, nl);
        k += nl;
        at[k++] = static_cast<uint8_t>(vl);
        std::memcpy(at + k, value, vl);
        k += vl;
    }

    /// \~english A request head on @p id; @p ends if it has no body.  \~spanish Una cabeza de peticion en @p id; @p ends si no tiene cuerpo.  \~
    void request(uint32_t id, const char *method, const char *path, bool ends = true) {
        uint8_t block[256];
        size_t k = 0;
        field(block, k, ":method", method);
        field(block, k, ":scheme", "http");
        field(block, k, ":authority", "example.com");
        field(block, k, ":path", path);
        frame(FrameType::Headers, static_cast<uint8_t>(kEndHeaders | (ends ? kEndStream : 0)), id, block, k);
    }

    void window_update(uint32_t id, uint32_t n) {
        const uint8_t p[4] = {static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
                              static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
        frame(FrameType::WindowUpdate, 0, id, p, sizeof p);
    }

    void reset(uint32_t id) {
        const uint8_t cancel[4] = {0, 0, 0, 0x08};
        frame(FrameType::RstStream, 0, id, cancel, sizeof cancel);
    }

    /// \~english A GOAWAY naming no server stream, with @p code.  \~spanish Un GOAWAY que no nombra ningun flujo del servidor, con @p code.  \~
    void goaway(uint8_t code) {
        const uint8_t p[8] = {0, 0, 0, 0, 0, 0, 0, code};
        frame(FrameType::Goaway, 0, 0, p, sizeof p);
    }
};

/// \~english What came back, frame by frame.  \~spanish Lo que volvio, trama a trama.  \~
struct Frames {
    struct One {
        uint8_t type;
        uint8_t flags;
        uint32_t id;
        size_t len;
        size_t at;
    };

    One f[1024] = {};
    size_t n = 0;
    const uint8_t *p = nullptr;

    void read(const uint8_t *bytes, size_t size) {
        p = bytes;
        size_t at = 0;
        while (at + kFrameHeaderSize <= size && n < 1024) {
            One &o = f[n];
            o.len = (static_cast<size_t>(bytes[at]) << 16) | (static_cast<size_t>(bytes[at + 1]) << 8) | bytes[at + 2];
            o.type = bytes[at + 3];
            o.flags = bytes[at + 4];
            o.id = (static_cast<uint32_t>(bytes[at + 5] & 0x7F) << 24) | (static_cast<uint32_t>(bytes[at + 6]) << 16) |
                   (static_cast<uint32_t>(bytes[at + 7]) << 8) | bytes[at + 8];
            o.at = at + kFrameHeaderSize;
            if (o.at + o.len > size) break;
            ++n;
            at = o.at + o.len;
        }
    }

    size_t count(FrameType t, uint32_t id) const {
        size_t k = 0;
        for (size_t i = 0; i < n; ++i)
            if (f[i].type == static_cast<uint8_t>(t) && f[i].id == id) ++k;
        return k;
    }

    /// \~english The body that went out on @p id, joined.  \~spanish El cuerpo que salio por @p id, junto.  \~
    std::string data(uint32_t id) const {
        std::string s;
        for (size_t i = 0; i < n; ++i)
            if (f[i].type == static_cast<uint8_t>(FrameType::Data) && f[i].id == id)
                s.append(reinterpret_cast<const char *>(p + f[i].at), f[i].len);
        return s;
    }

    /// \~english Whether a frame on @p id carried END_STREAM.  \~spanish Si una trama de @p id llevo END_STREAM.  \~
    bool ended(uint32_t id) const {
        for (size_t i = 0; i < n; ++i)
            if (f[i].id == id && (f[i].flags & kEndStream) != 0) return true;
        return false;
    }

    /// \~english Whether END_STREAM came on the last frame of @p id and on no other.  \~spanish Si END_STREAM vino en la ultima trama de @p id y en ninguna otra.  \~
    bool ended_last(uint32_t id) const {
        size_t last = n;
        size_t ends = 0;
        for (size_t i = 0; i < n; ++i) {
            if (f[i].id != id) continue;
            last = i;
            if ((f[i].flags & kEndStream) != 0) ++ends;
        }
        return last != n && ends == 1 && (f[last].flags & kEndStream) != 0;
    }

    /// \~english The index of the first frame of type @p t on @p id, or @c n.  \~spanish El indice de la primera trama de tipo @p t en @p id, o @c n.  \~
    size_t index(FrameType t, uint32_t id) const {
        for (size_t i = 0; i < n; ++i)
            if (f[i].type == static_cast<uint8_t>(t) && f[i].id == id) return i;
        return n;
    }

    /// \~english The 32-bit word at @p off of the payload of frame @p i.  \~spanish La palabra de 32 bits en @p off de la carga de la trama @p i.  \~
    uint32_t word(size_t i, size_t off) const {
        const uint8_t *b = p + f[i].at + off;
        return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
               (static_cast<uint32_t>(b[2]) << 8) | b[3];
    }

    /// \~english Whether the GOAWAY is the last frame, alone, naming @p last with NO_ERROR.  \~spanish Si el GOAWAY es la ultima trama, solo, nombrando @p last con NO_ERROR.  \~
    bool graceful_goaway_last(uint32_t last) const {
        const size_t g = index(FrameType::Goaway, 0);
        return n != 0 && g == n - 1 && count(FrameType::Goaway, 0) == 1 && f[g].len == 8 && word(g, 0) == last &&
               word(g, 4) == 0;
    }

    /// \~english The largest DATA frame on @p id.  \~spanish La trama DATA mas grande de @p id.  \~
    size_t largest(uint32_t id) const {
        size_t m = 0;
        for (size_t i = 0; i < n; ++i)
            if (f[i].type == static_cast<uint8_t>(FrameType::Data) && f[i].id == id && f[i].len > m) m = f[i].len;
        return m;
    }

    /**
     * @brief
     * \~english The :status of the first HEADERS on @p id: a static index or a literal on index 8, maybe Huffman.
     * \~spanish El :status del primer HEADERS de @p id: un indice estatico o un literal sobre el indice 8, quiza Huffman.
     * \~
     */
    int status(uint32_t id) const {
        static const int indexed[7] = {200, 204, 206, 304, 400, 404, 500};
        for (size_t i = 0; i < n; ++i) {
            if (f[i].type != static_cast<uint8_t>(FrameType::Headers) || f[i].id != id) continue;
            const uint8_t *b = p + f[i].at;
            if ((b[0] & 0x80) != 0) {
                const int idx = b[0] & 0x7F;
                return idx >= 8 && idx <= 14 ? indexed[idx - 8] : -1;
            }
            if ((b[0] & 0x0F) != 8) return -1;
            const bool huffman = (b[1] & 0x80) != 0;
            const size_t len = b[1] & 0x7F;
            char text[8] = {};
            if (huffman) {
                uint8_t tmp[8];
                const http_vx::h2::hpack::HuffmanResult h = http_vx::h2::hpack::huffman_decode(tmp, sizeof tmp, b + 2, len);
                if (h.status != http_vx::h2::hpack::Status::Ok || h.len != 3) return -1;
                std::memcpy(text, tmp, 3);
            } else {
                if (len != 3) return -1;
                std::memcpy(text, b + 2, 3);
            }
            return (text[0] - '0') * 100 + (text[1] - '0') * 10 + (text[2] - '0');
        }
        return -1;
    }
};

/* ------------------------------------------------------------------------- *
 * \~english The application's side: a source fed by hand, and a handler that opens.
 * \~spanish El lado de la aplicacion: una fuente alimentada a mano, y un manejador que abre.
 * \~
 * ------------------------------------------------------------------------- */

/// \~english A source the test feeds by hand.  \~spanish Una fuente que la prueba alimenta a mano.  \~
class Feeder final : public BodySource {
  public:
    size_t fill(OpenResponse, uint8_t *dst, size_t room, bool &done) noexcept override {
        ++fills;
        last_room = room;
        size_t n = 0;
        if (full_fills != 0) {
            --full_fills;
            std::memset(dst, 'x', room);
            n = room;
        } else {
            n = pending.size() < room ? pending.size() : room;
            std::memcpy(dst, pending.data(), n);
            pending.erase(0, n);
        }
        done = finish && pending.empty() && full_fills == 0;
        return n == room ? n + lie : n;
    }

    void gone(OpenResponse, GoneReason why) noexcept override {
        ++gones;
        last = why;
    }

    std::string pending;
    bool finish = false;
    /// \~english How many fills take all the room.  \~spanish Cuantos rellenos usan todo el sitio.  \~
    int full_fills = 0;
    /// \~english Added to what a full fill says it wrote: a source that lies.  \~spanish Se suma a lo que dice un relleno lleno: una fuente que miente.  \~
    size_t lie = 0;
    int fills = 0;
    size_t last_room = 0;
    int gones = 0;
    GoneReason last = GoneReason::Finished;
};

/// \~english Opens on "/open" and "/open2", answers anything else whole.  \~spanish Abre en "/open" y "/open2", contesta lo demas entero.  \~
class Opener final : public Handler {
  public:
    void handle(const Request &req, const uint8_t *head, const uint8_t *, size_t,
                ResponseBuilder &res) noexcept override {
        ++calls;
        const std::string target(reinterpret_cast<const char *>(head + req.target.off), req.target.len);
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/event-stream", 17);
        if (target == "/open" || target == "/open2") {
            const int k = target == "/open" ? 0 : 1;
            if (!before.empty()) res.body(before.data(), before.size());
            opened[k] = res.open(*sources[k]);
        } else {
            res.body("whole", 5);
        }
    }

    Feeder *sources[2] = {};
    std::string before;
    OpenResponse opened[2];
    int calls = 0;
};

/// \~english A whole shard over the memory backend.  \~spanish Un fragmento entero sobre el backend de memoria.  \~
struct Server {
    Opener handler;
    Feeder source;
    Feeder other;
    Http2Service service;
    Shard shard;
    MemoryBackend io;

    Server() : io(shard.buffers()) {
        handler.sources[0] = &source;
        handler.sources[1] = &other;
    }

    bool start(uint32_t max_open = 16, uint16_t per_conn = 16,
               uint32_t opens = Http2Service::kOpenResponses, uint32_t write_size = 65536,
               uint32_t requests = 4) {
        const http_vx::h2::Limits limits;
        if (!service.reset(8, requests, 4096, handler, limits, opens)) return false;

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 16;
        cfg.idle_ticks = 10;
        cfg.wheel_slots = 64;
        cfg.max_open = max_open;
        cfg.max_open_per_conn = per_conn;
        cfg.write_size = write_size;
        return shard.reset(cfg, io, service, 0) && shard.adopt(7, 0).valid();
    }

    void send(const Wire &w) { io.feed(w.b, w.n); }

    void run() {
        for (int i = 0; i < 64; ++i) shard.poll(1, 0);
    }

    Frames frames() const {
        Frames f;
        f.read(io.written(), io.written_size());
        return f;
    }
};

/// \~english The loop's side, by hand: counts what the service asks.  \~spanish El lado del bucle, a mano: cuenta lo que pide el servicio.  \~
class Port final : public StreamPort {
  public:
    Port() noexcept { kicks.reset(nullptr); }

    OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s, KickTarget &target) noexcept override {
        OpenResponse r;
        r.conn = c;
        r.stream = stream;
        kicks.open(s, target, r);
        return r;
    }

    size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override {
        done = false;
        const size_t n = s.fill(s.response(), dst, room, done);
        return n > room ? room : n;
    }

    void end(BodySource &s, GoneReason why) noexcept override { kicks.close(s, why); }
    void want_writable(ConnHandle) noexcept override { ++asked; }
    void hold_reads(ConnHandle, bool) noexcept override {}
    GoneReason closing_reason(ConnHandle) const noexcept override { return GoneReason::ConnectionClosed; }

    KickQueue kicks;
    int asked = 0;
};

/// \~english The service driven by hand on one connection.  \~spanish El servicio movido a mano en una conexion.  \~
struct Bare {
    Opener handler;
    Feeder source;
    Feeder other;
    Port port;
    Http2Service service;
    ConnHandle c;
    Buffer in;
    Buffer out;

    bool start() {
        handler.sources[0] = &source;
        handler.sources[1] = &other;
        const http_vx::h2::Limits limits;
        if (!service.reset(1, 2, 4096, handler, limits, 4)) return false;
        service.attach(&port);
        c.slot = 0;
        c.life = 1;
        service.on_open(c);
        return true;
    }

    bool send(const Wire &w) {
        uint8_t *p = in.reserve(w.n);
        if (p == nullptr) return false;
        std::memcpy(p, w.b, w.n);
        in.commit(w.n);
        return service.on_bytes(c, in, out);
    }

    /// \~english What the shard does when asked: on_writable while asked, with @p budget.  \~spanish Lo que hace el fragmento al pedirselo: on_writable mientras se pida, con @p budget.  \~
    void pump(size_t budget = 65536) {
        for (int i = 0; i < 64 && port.asked != 0; ++i) {
            port.asked = 0;
            service.on_writable(c, out, budget);
        }
    }

    Frames frames() const {
        Frames f;
        f.read(out.data(), out.size());
        return f;
    }
};

/* ------------------------------------------------------------------------- *
 * \~english The cases.
 * \~spanish Los casos.
 * \~
 * ------------------------------------------------------------------------- */

/**
 * @brief
 * \~english HEADERS without END_STREAM, the prefix as the first DATA, a DATA per kick, END_STREAM on the last, gone once.
 * \~spanish HEADERS sin END_STREAM, el prefijo como primer DATA, un DATA por aviso, END_STREAM en el ultimo, gone una vez.
 * \~
 */
void test_open_kick_done() {
    Server s;
    check(s.start(), "the server would not start");
    s.handler.before = "first";

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    Frames f = s.frames();
    check(s.handler.opened[0].valid(), "the response was not opened");
    check(s.handler.opened[0].stream == 1, "the open response names the wrong stream");
    check(f.count(FrameType::Headers, 1) == 1 && f.status(1) == 200, "the head did not go out");
    check(!f.ended(1), "an open response ended its stream at once");
    check(f.data(1) == "first", "what was written before opening is not the first DATA");
    check(s.source.fills == 1, "the source was not asked once on opening");

    s.source.pending = "hello";
    check(s.source.kick(), "the kick was refused");
    s.run();
    check(s.frames().data(1) == "firsthello", "a kick did not become a DATA frame");
    check(s.source.fills == 2, "a kick did not become one fill");

    s.run();
    check(s.source.fills == 2, "the source was asked again with no kick and no room used up");

    s.source.pending = "bye";
    s.source.finish = true;
    s.source.kick();
    s.run();
    f = s.frames();
    check(f.data(1) == "firsthellobye", "the last piece did not go out");
    check(f.ended_last(1), "END_STREAM was not on the last frame, once");
    check(s.source.gones == 1 && s.source.last == GoneReason::Finished, "gone(Finished) did not come once");

    s.source.kick();
    s.run();
    check(s.source.fills == 3 && s.source.gones == 1, "a kick after gone reached the source");

    const http_vx::OpenCounts c = s.shard.open_counts();
    check(c.opened == 1 && c.open_now == 0 && c.fills == 3 && c.filled_bytes == 8, "the counts are wrong");
    check(s.service.open_now() == 0, "the service still holds the entry");
}

/**
 * @brief
 * \~english A done with nothing more is an empty DATA carrying END_STREAM.
 * \~spanish Un done sin nada mas es un DATA vacio con END_STREAM.
 * \~
 */
void test_done_with_nothing_is_an_empty_end() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    s.source.finish = true;
    s.source.kick();
    s.run();

    const Frames f = s.frames();
    check(f.count(FrameType::Data, 1) == 1 && f.data(1).empty(), "the end did not go as one empty DATA");
    check(f.ended_last(1), "the empty DATA did not carry END_STREAM");
    check(s.source.gones == 1 && s.source.last == GoneReason::Finished, "gone(Finished) did not come");
}

/**
 * @brief
 * \~english A shut window means no fill, kicked or not; a WINDOW_UPDATE opens it, and only what wants asking is asked.
 * \~spanish Una ventana cerrada quiere decir ningun relleno, con aviso o sin el; un WINDOW_UPDATE la abre, y solo se pregunta a quien lo quiere.
 * \~
 */
void test_a_window_shuts_and_reopens() {
    Server s;
    check(s.start(), "the server would not start");
    s.source.pending = "0123456789ABCDEF";

    Wire w;
    w.hello_window(10);
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    check(s.source.fills == 1 && s.source.last_room == 10, "the first fill was not offered the stream's window");
    check(s.frames().data(1) == "0123456789", "the first fill did not stop at the window");

    s.source.kick();
    s.run();
    check(s.source.fills == 1, "a source was asked with its window shut");

    Wire more;
    more.window_update(1, 20);
    s.send(more);
    s.run();
    check(s.source.fills == 2 && s.source.last_room == 20, "the window that opened did not become a fill");
    check(s.frames().data(1) == "0123456789ABCDEF", "the rest did not follow the window");

    // \~english That fill gave less than its room: more window alone does not ask it again.
    // \~spanish Ese relleno dio menos que su sitio: mas ventana sola no le vuelve a preguntar.  \~
    Wire again;
    again.window_update(1, 5);
    s.send(again);
    s.run();
    check(s.source.fills == 2, "a source that gave less than its room was asked again without a kick");

    s.source.pending = "xy";
    s.source.kick();
    s.run();
    check(s.source.fills == 3 && s.frames().data(1) == "0123456789ABCDEFxy", "a kick after that did not fill");
}

/**
 * @brief
 * \~english A fill that took all the window is asked again when the window opens, with no kick.
 * \~spanish A un relleno que se llevo toda la ventana se le vuelve a pedir cuando se abre, sin aviso.
 * \~
 */
void test_a_full_window_is_asked_again_on_update() {
    Server s;
    check(s.start(), "the server would not start");
    s.source.full_fills = 2;

    Wire w;
    w.hello_window(10);
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();
    check(s.source.fills == 1, "the first fill did not happen once");

    Wire more;
    more.window_update(1, 7);
    s.send(more);
    s.run();
    check(s.source.fills == 2 && s.source.last_room == 7, "a hungry source was not asked when the window opened");
    check(s.frames().data(1) == std::string(17, 'x'), "the second fill did not go out");
}

/**
 * @brief
 * \~english What was written before opening and does not fit the window waits in the entry, ahead of the source.
 * \~spanish Lo escrito antes de abrir que no cabe en la ventana espera en la entrada, delante de la fuente.
 * \~
 */
void test_a_prefix_waits_for_the_window() {
    Server s;
    check(s.start(), "the server would not start");
    s.handler.before = "prefix-prefix!!";
    s.source.pending = "S";

    Wire w;
    w.hello_window(10);
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();
    check(s.frames().data(1) == "prefix-pre", "the prefix did not stop at the window");
    check(s.source.fills == 0, "the source was asked before the prefix was out");

    Wire more;
    more.window_update(1, 100);
    s.send(more);
    s.run();
    check(s.frames().data(1) == "prefix-prefix!!S", "the rest of the prefix, then the source, did not follow");
    check(s.source.fills == 1, "the first fill did not come after the prefix");
    check(s.service.in_hand() == 0, "the prefix was kept in the request pool");
}

/**
 * @brief
 * \~english A source that fills all the room is asked again without a kick, until it gives less.
 * \~spanish A una fuente que llena todo el sitio se le vuelve a pedir sin aviso, hasta que da menos.
 * \~
 */
void test_a_full_fill_is_asked_again() {
    Server s;
    check(s.start(), "the server would not start");
    s.source.full_fills = 2;

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    const Frames f = s.frames();
    check(s.source.fills == 3, "a source was not asked again exactly while it used all the room");
    check(f.data(1).size() == 2 * Http2Service::kFillRoom, "the full fills did not go out");
    check(f.largest(1) == Http2Service::kFillRoom, "a DATA frame was not one full fill");
    check(s.source.gones == 0, "the open response ended by itself");
    check(s.shard.open_counts().starved == 0, "the pool ran dry for one open response");
}

/**
 * @brief
 * \~english A source that says it wrote more than the room is believed no further than the room.
 * \~spanish A una fuente que dice haber escrito mas que el sitio no se le cree mas alla del sitio.
 * \~
 */
void test_a_source_that_lies_is_clamped() {
    Server s;
    check(s.start(), "the server would not start");
    s.source.full_fills = 1;
    s.source.lie = 5;

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    const Frames f = s.frames();
    check(f.largest(1) == Http2Service::kFillRoom, "a DATA frame announced more than the room");
    check(s.shard.open_counts().filled_bytes == Http2Service::kFillRoom, "more than the room was counted");
    check(!f.count(FrameType::Goaway, 0), "the connection was given up on");
}

/**
 * @brief
 * \~english HEAD does not open; the answer goes whole with its head.
 * \~spanish HEAD no abre; la respuesta sale entera con su cabecera.
 * \~
 */
void test_head_does_not_open() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "HEAD", "/open");
    s.send(w);
    s.run();

    const Frames f = s.frames();
    check(!s.handler.opened[0].valid(), "a HEAD response was opened");
    check(s.source.fills == 0 && s.source.gones == 0, "a refused source was used");
    check(f.count(FrameType::Headers, 1) == 1 && f.ended(1) && f.count(FrameType::Data, 1) == 0,
          "the HEAD answer is not a whole head");
    check(s.shard.open_counts().opened == 0 && s.shard.open_counts().refused == 0, "HEAD reached the limits");
}

/**
 * @brief
 * \~english The shard's limit reached: 503 on that stream, counted, and the connection carries on.
 * \~spanish El tope del fragmento agotado: 503 en ese flujo, contado, y la conexion sigue.
 * \~
 */
void test_the_limit_is_answered_503() {
    Server s;
    check(s.start(16, 1), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.request(3, "GET", "/open2");
    s.send(w);
    s.run();

    Frames f = s.frames();
    check(s.handler.opened[0].valid(), "the first response was not opened");
    check(!s.handler.opened[1].valid(), "the second response was opened past the limit");
    check(f.status(3) == 503 && f.ended(3), "the limit was not answered 503");
    check(s.other.fills == 0 && s.other.gones == 0, "a refused source was used");
    check(s.shard.open_counts().refused == 1, "the refusal was not counted");
    check(f.count(FrameType::Goaway, 0) == 0, "the connection was given up on");

    s.source.pending = "still";
    s.source.kick();
    s.run();
    check(s.frames().data(1) == "still", "the open response did not carry on");
}

/**
 * @brief
 * \~english The service's own table full: 503, counted by the service, the shard never told of an open.
 * \~spanish La tabla propia del servicio llena: 503, contado por el servicio, sin que el fragmento sepa de ninguna apertura.
 * \~
 */
void test_a_full_table_is_answered_503() {
    Server s;
    check(s.start(16, 16, 1), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.request(3, "GET", "/open2");
    s.send(w);
    s.run();

    const Frames f = s.frames();
    check(s.handler.opened[0].valid() && !s.handler.opened[1].valid(), "the table let two open");
    check(f.status(3) == 503, "a full table was not answered 503");
    check(s.service.open_full() == 1, "the full table was not counted");
    check(s.shard.open_counts().opened == 1 && s.shard.open_counts().open_now == 1,
          "the shard counted an open the service could not keep");
    check(s.other.fills == 0 && s.other.gones == 0, "a refused source was used");
}

/**
 * @brief
 * \~english The peer's RST_STREAM ends the open response with PeerReset; the connection carries on.
 * \~spanish El RST_STREAM del otro extremo acaba la respuesta abierta con PeerReset; la conexion sigue.
 * \~
 */
void test_a_reset_is_peer_reset() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    Wire r;
    r.reset(1);
    s.send(r);
    s.run();
    check(s.source.gones == 1 && s.source.last == GoneReason::PeerReset, "a reset did not end it with PeerReset");
    check(s.shard.open_counts().open_now == 0 && s.service.open_now() == 0, "a reset response is still open");

    s.source.kick();
    s.run();
    check(s.source.fills == 1, "a reset source was asked again");

    Wire next;
    next.request(3, "GET", "/plain");
    s.send(next);
    s.run();
    check(s.frames().data(3) == "whole", "the connection did not carry on after the reset");
}

/**
 * @brief
 * \~english Two open streams on one connection take turns, one frame each, within the budget.
 * \~spanish Dos flujos abiertos en una conexion se turnan, una trama cada uno, dentro del presupuesto.
 * \~
 */
void test_two_streams_take_turns() {
    Server s;
    check(s.start(16, 16, Http2Service::kOpenResponses, 100), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.request(3, "GET", "/open2");
    s.send(w);
    s.run();

    s.source.pending = std::string(200, 'a');
    s.other.pending = std::string(200, 'b');
    s.source.kick();
    s.other.kick();
    s.run();

    const Frames f = s.frames();
    check(f.data(1) == std::string(200, 'a') && f.data(3) == std::string(200, 'b'), "the two bodies did not go out");
    check(f.largest(1) == 100 - kFrameHeaderSize && f.largest(3) == 100 - kFrameHeaderSize,
          "a call wrote more than its budget");

    // \~english The DATA frames with bytes, in order: the streams alternate.
    // \~spanish Las tramas DATA con bytes, en orden: los flujos se alternan.  \~
    uint32_t order[16] = {};
    size_t k = 0;
    for (size_t i = 0; i < f.n && k < 16; ++i)
        if (f.f[i].type == static_cast<uint8_t>(FrameType::Data) && f.f[i].len != 0) order[k++] = f.f[i].id;
    bool alternate = k == 6;
    for (size_t i = 1; i < k; ++i)
        if (order[i] == order[i - 1]) alternate = false;
    check(alternate, "one open stream starved the other");
}

/**
 * @brief
 * \~english Other requests are served while a stream is open, and the open one holds no request entry.
 * \~spanish Las demas peticiones se sirven mientras hay un flujo abierto, y el abierto no ocupa ninguna entrada de peticion.
 * \~
 */
void test_other_requests_are_served() {
    Server s;
    check(s.start(16, 16, Http2Service::kOpenResponses, 65536, 1), "the server would not start");

    // \~english A POST with a body takes the one request entry until it is answered.
    // \~spanish Un POST con cuerpo coge la unica entrada de peticion hasta que se contesta.  \~
    Wire w;
    w.hello();
    w.request(1, "POST", "/open", false);
    w.frame(FrameType::Data, kEndStream, 1, reinterpret_cast<const uint8_t *>("up"), 2);
    s.send(w);
    s.run();
    check(s.handler.opened[0].valid(), "the POST did not open");
    check(s.service.in_hand() == 0, "the open response kept its request entry");

    Wire next;
    next.request(3, "POST", "/plain", false);
    next.frame(FrameType::Data, kEndStream, 3, reinterpret_cast<const uint8_t *>("up"), 2);
    next.request(5, "GET", "/plain");
    s.send(next);
    s.run();

    const Frames f = s.frames();
    check(f.count(FrameType::RstStream, 3) == 0, "a request was refused while a stream was open");
    check(f.data(3) == "whole" && f.ended(3), "a request with a body was not served while a stream was open");
    check(f.data(5) == "whole" && f.ended(5), "a request was not served while a stream was open");
    check(s.source.gones == 0, "the open response ended");
}

/**
 * @brief
 * \~english A connection that says nothing for too long ends its open response with IdleTimeout.
 * \~spanish Una conexion que calla demasiado acaba su respuesta abierta con IdleTimeout.
 * \~
 */
void test_idle_timeout() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.request(3, "GET", "/open2");
    s.send(w);
    s.run();

    /* \~english
     * An HTTP/2 connection keeps a read outstanding while a response is open
     * (unlike HTTP/1.1, which holds its reads), and an expired connection
     * leaves when that read comes back (see test_shard.cpp): the end of the
     * stream brings it back.
     * \~spanish
     * Una conexion HTTP/2 mantiene una lectura pendiente mientras hay una
     * respuesta abierta (al contrario que HTTP/1.1, que retiene sus lecturas), y
     * una conexion vencida se va cuando vuelve esa lectura (ver test_shard.cpp):
     * el fin del flujo la hace volver.
     * \~ */
    check(s.shard.expire(100) == 1, "the quiet connection was not expired");
    s.io.end_of_stream();
    s.run();
    check(s.source.gones == 1 && s.source.last == GoneReason::IdleTimeout, "the deadline did not end it with IdleTimeout");
    check(s.other.gones == 1 && s.other.last == GoneReason::IdleTimeout, "the deadline did not end every open response");
    check(s.shard.open_counts().open_now == 0 && s.service.open_now() == 0, "an expired response is still open");
}

/**
 * @brief
 * \~english Letting the shard go ends what is open with Shutdown.
 * \~spanish Soltar el fragmento acaba lo abierto con Shutdown.
 * \~
 */
void test_shutdown() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    s.source.kick();
    s.shard.release();
    check(s.source.gones == 1 && s.source.last == GoneReason::Shutdown, "letting the shard go did not end it with Shutdown");
}

/**
 * @brief
 * \~english A peer that leaves with GOAWAY(NO_ERROR) lets its open response finish, then this end says GOAWAY and closes.
 * \~spanish Un extremo que se va con GOAWAY(NO_ERROR) deja acabar su respuesta abierta, y luego este dice GOAWAY y cierra.
 * \~
 *
 * \~english
 * RFC 9113, 6.8: GOAWAY "allows an endpoint to gracefully stop accepting new
 * streams while still finishing processing of previously established
 * streams".  A request the client sends after its own GOAWAY is served too:
 * the rule not to open streams binds the receiver, which is this server.
 * \~spanish
 * RFC 9113, 6.8: GOAWAY "allows an endpoint to gracefully stop accepting new
 * streams while still finishing processing of previously established
 * streams".  Una peticion que el cliente manda despues de su propio GOAWAY se
 * atiende tambien: la regla de no abrir flujos obliga al que lo recibe, que es
 * este servidor.
 * \~
 */
void test_a_graceful_goaway_lets_it_finish() {
    Server s;
    check(s.start(), "the server would not start");
    s.handler.before = "a";

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();
    check(s.handler.opened[0].valid(), "the response was not opened");

    Wire bye;
    bye.goaway(0);
    bye.request(3, "GET", "/whole");
    s.send(bye);
    s.run();

    Frames f = s.frames();
    check(s.source.gones == 0, "a graceful GOAWAY ended the open response");
    check(s.io.closed() == 0, "a graceful GOAWAY closed the connection with a response open");
    check(f.count(FrameType::Goaway, 0) == 0, "a GOAWAY went out with a response still open");
    check(f.data(3) == "whole" && f.ended(3), "a request sent after the client's GOAWAY was not served");
    check(s.service.graceful_goaways() == 1, "the graceful GOAWAY was not counted");

    s.source.pending = "b";
    s.source.kick();
    s.run();
    check(s.frames().data(1) == "ab" && s.source.gones == 0, "the open response was not filled after the GOAWAY");
    check(s.io.closed() == 0 && s.frames().count(FrameType::Goaway, 0) == 0, "the connection left with a response open");

    s.source.pending = "c";
    s.source.finish = true;
    s.source.kick();
    s.run();

    f = s.frames();
    check(f.data(1) == "abc" && f.ended_last(1), "the open response did not end whole");
    check(s.source.gones == 1 && s.source.last == GoneReason::Finished, "the open response did not end Finished");
    check(f.graceful_goaway_last(3), "the last frame is not GOAWAY(NO_ERROR) naming stream 3");
    check(s.io.closed() == 1, "the connection was not closed after its GOAWAY");
}

/**
 * @brief
 * \~english A GOAWAY with an error takes the open responses with it: ConnectionClosed, and no GOAWAY back.
 * \~spanish Un GOAWAY con error se lleva las respuestas abiertas: ConnectionClosed, y ningun GOAWAY de vuelta.
 * \~
 *
 * \~english
 * ConnectionClosed and not PeerReset: the peer did not refuse this stream, it
 * dropped the whole connection, and the source hears the same as for any
 * other connection that ends under it.
 * \~spanish
 * ConnectionClosed y no PeerReset: el otro no rechazo este flujo, tiro la
 * conexion entera, y la fuente oye lo mismo que con cualquier otra conexion
 * que se acaba debajo de ella.
 * \~
 */
void test_a_goaway_with_an_error_closes() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    s.send(w);
    s.run();

    Wire bye;
    bye.goaway(0x02);
    s.send(bye);
    s.run();
    check(s.source.gones == 1 && s.source.last == GoneReason::ConnectionClosed, "GOAWAY did not end it with ConnectionClosed");
    check(s.frames().count(FrameType::Goaway, 0) == 0, "a GOAWAY with an error was answered with another");
    check(s.io.closed() == 1 && s.service.graceful_goaways() == 0, "the connection was not closed, or counted graceful");
}

/**
 * @brief
 * \~english A GOAWAY with an error after a graceful one ends at once (RFC 9113, 6.8: circumstances may change).
 * \~spanish Un GOAWAY con error detras de uno con calma acaba en el acto (RFC 9113, 6.8: las circunstancias pueden cambiar).
 * \~
 */
void test_an_error_after_a_graceful_goaway_closes() {
    Server s;
    check(s.start(), "the server would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.goaway(0);
    s.send(w);
    s.run();
    check(s.source.gones == 0 && s.io.closed() == 0, "a graceful GOAWAY ended the connection");

    Wire bye;
    bye.goaway(0x01);
    s.send(bye);
    s.run();
    check(s.source.gones == 1 && s.source.last == GoneReason::ConnectionClosed,
          "an error after a graceful GOAWAY did not end it with ConnectionClosed");
    check(s.io.closed() == 1 && s.frames().count(FrameType::Goaway, 0) == 0,
          "an error after a graceful GOAWAY did not close at once, or was answered");
}

/**
 * @brief
 * \~english The connection's window shuts a stream whose own window is wide; its WINDOW_UPDATE opens it again.
 * \~spanish La ventana de la conexion cierra un flujo cuya ventana propia es amplia; su WINDOW_UPDATE la vuelve a abrir.
 * \~
 */
void test_the_connection_window() {
    Bare b;
    check(b.start(), "the service would not start");
    b.source.full_fills = 100;

    Wire w;
    w.hello_window(1000000);
    w.request(1, "GET", "/open");
    check(b.send(w), "the connection ended");
    b.pump();

    // \~english 65535 of connection window: three full fills and one of what was left.
    // \~spanish 65535 de ventana de conexion: tres rellenos llenos y uno de lo que quedaba.  \~
    Frames f = b.frames();
    check(f.data(1).size() == 65535, "the connection's window did not bound what went");
    check(b.source.fills == 4 && b.source.last_room == 65535 - 3 * Http2Service::kFillRoom,
          "the last fill was not offered what the connection had left");
    check(b.port.asked == 0, "room was asked for with the connection's window shut");

    Wire stream_only;
    stream_only.window_update(1, 5);
    check(b.send(stream_only), "the connection ended");
    check(b.port.asked == 0, "room was asked for while the connection's window stayed shut");

    Wire more;
    more.window_update(0, 10);
    check(b.send(more), "the connection ended");
    check(b.port.asked != 0, "the connection's WINDOW_UPDATE did not ask for room");
    b.pump();
    check(b.source.fills == 5 && b.source.last_room == 10, "the reopened window was not what was offered");
    check(b.frames().data(1).size() == 65545, "the reopened window did not become a DATA frame");
}

/**
 * @brief
 * \~english One call writes no more than its budget, frame header included, and what does not fit waits.
 * \~spanish Una llamada no escribe mas que su presupuesto, cabecera de trama incluida, y lo que no cabe espera.
 * \~
 */
void test_the_budget_is_kept() {
    Bare b;
    check(b.start(), "the service would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    check(b.send(w), "the connection ended");
    check(b.source.fills == 1, "the first fill did not happen");

    b.source.full_fills = 3;
    b.source.kick();
    b.port.kicks.drain();
    check(b.port.asked == 1, "a kick did not ask for room");

    b.port.asked = 0;
    size_t was = b.out.size();
    check(b.service.on_writable(b.c, b.out, 100), "on_writable ended the connection");
    check(b.out.size() - was == 100, "a call did not use its budget exactly");
    check(b.source.last_room == 100 - kFrameHeaderSize, "the room did not leave space for the frame header");
    check(b.port.asked != 0, "a full fill was not asked again");

    b.port.asked = 0;
    was = b.out.size();
    check(b.service.on_writable(b.c, b.out, kFrameHeaderSize), "on_writable ended the connection");
    check(b.out.size() == was && b.source.fills == 2, "a budget with no room for a byte was used");
    check(b.port.asked != 0, "what did not fit was not asked again");

    b.port.asked = 0;
    check(b.service.on_writable(b.c, b.out, kFrameHeaderSize + 1), "on_writable ended the connection");
    check(b.out.size() - was == kFrameHeaderSize + 1 && b.source.last_room == 1, "a one-byte budget was not one byte");
}

/**
 * @brief
 * \~english A fill that gave less than its room is not asked for room by a WINDOW_UPDATE; a kick is.
 * \~spanish A un relleno que dio menos que su sitio no le pide sitio un WINDOW_UPDATE; un aviso si.
 * \~
 */
void test_a_short_fill_waits_for_its_kick() {
    Bare b;
    check(b.start(), "the service would not start");
    b.source.pending = "abc";

    Wire w;
    w.hello_window(10);
    w.request(1, "GET", "/open");
    check(b.send(w), "the connection ended");
    check(b.source.fills == 1 && b.frames().data(1) == "abc", "the first fill did not go");
    check(b.port.asked == 0, "room was asked for a source that said it had nothing more");

    Wire more;
    more.window_update(1, 5);
    more.window_update(0, 5);
    check(b.send(more), "the connection ended");
    check(b.port.asked == 0, "a WINDOW_UPDATE asked for room for a source that gave less than its room");

    b.source.kick();
    b.port.kicks.drain();
    check(b.port.asked == 1, "a kick did not ask for room");
}

/**
 * @brief
 * \~english The stream a finished open response ran on is closed: DATA on it afterwards is a connection error.
 * \~spanish El flujo por el que fue una respuesta abierta acabada esta cerrado: un DATA en el despues es un error de conexion.
 * \~
 */
void test_done_closes_the_stream() {
    Bare b;
    check(b.start(), "the service would not start");
    b.source.pending = "end";
    b.source.finish = true;

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    check(b.send(w), "the connection ended");
    check(b.source.gones == 1 && b.source.last == GoneReason::Finished, "the response did not finish on its first fill");
    check(b.frames().ended_last(1), "END_STREAM was not on the last frame");

    // \~english RFC 9113, 5.1: after both ends' END_STREAM the stream is closed, and DATA on it is STREAM_CLOSED.
    // \~spanish RFC 9113, 5.1: tras el END_STREAM de los dos extremos el flujo esta cerrado, y un DATA en el es STREAM_CLOSED.  \~
    Wire late;
    late.frame(FrameType::Data, 0, 1, reinterpret_cast<const uint8_t *>("x"), 1);
    const bool alive = b.send(late);
    const Frames f = b.frames();
    check(!alive && f.count(FrameType::Goaway, 0) == 1, "the finished stream was left open in the table");
}

/**
 * @brief
 * \~english The GOAWAY after the last open response keeps to the budget: one that does not fit waits for the next call.
 * \~spanish El GOAWAY detras de la ultima respuesta abierta cumple el presupuesto: uno que no cabe espera a la llamada siguiente.
 * \~
 */
void test_the_goaway_waits_for_the_budget() {
    Bare b;
    check(b.start(), "the service would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    check(b.send(w), "the connection ended");

    Wire bye;
    bye.goaway(0);
    check(b.send(bye), "a graceful GOAWAY ended the connection with a response open");
    check(b.frames().count(FrameType::Goaway, 0) == 0, "a GOAWAY went out with a response open");

    b.source.pending = "end";
    b.source.finish = true;
    b.source.kick();
    b.port.kicks.drain();
    check(b.port.asked == 1, "a kick did not ask for room");

    // \~english The last DATA takes the whole budget: no room is left for the GOAWAY.
    // \~spanish El ultimo DATA se lleva todo el presupuesto: no queda sitio para el GOAWAY.  \~
    b.port.asked = 0;
    size_t was = b.out.size();
    check(b.service.on_writable(b.c, b.out, kFrameHeaderSize + 3), "the connection ended before its GOAWAY fit");
    check(b.out.size() - was == kFrameHeaderSize + 3 && b.frames().ended_last(1), "the last DATA did not go out");
    check(b.frames().count(FrameType::Goaway, 0) == 0, "a GOAWAY went out past the budget");
    check(b.port.asked != 0, "the GOAWAY that did not fit was not asked for again");

    b.port.asked = 0;
    was = b.out.size();
    check(b.service.on_writable(b.c, b.out, http_vx::h2::kGoawaySize - 1), "the connection ended with no room for its GOAWAY");
    check(b.out.size() == was && b.port.asked != 0, "a budget one byte short took the GOAWAY, or did not ask again");

    check(!b.service.on_writable(b.c, b.out, http_vx::h2::kGoawaySize), "the GOAWAY that fit did not end the connection");
    check(b.out.size() - was == http_vx::h2::kGoawaySize && b.frames().graceful_goaway_last(1),
          "the GOAWAY did not go out alone, naming stream 1");

    check(b.service.graceful_goaways() == 1, "the graceful GOAWAY was not counted");
    check(b.start() && b.service.graceful_goaways() == 0, "a reset service kept the count of graceful GOAWAYs");
}

/**
 * @brief
 * \~english Closing the connection by hand ends what is open with the port's closing reason.
 * \~spanish Cerrar la conexion a mano acaba lo abierto con el motivo de cierre de la puerta.
 * \~
 */
void test_close_ends_what_is_open() {
    Bare b;
    check(b.start(), "the service would not start");

    Wire w;
    w.hello();
    w.request(1, "GET", "/open");
    w.request(3, "GET", "/open2");
    check(b.send(w), "the connection ended");
    check(b.service.open_now() == 2, "two responses did not open");

    b.service.on_close(b.c);
    check(b.source.gones == 1 && b.source.last == GoneReason::ConnectionClosed, "closing did not end the first");
    check(b.other.gones == 1 && b.other.last == GoneReason::ConnectionClosed, "closing did not end the second");
    check(b.service.open_now() == 0, "closing left entries taken");
}

} // namespace

int main() {
    test_open_kick_done();
    test_done_with_nothing_is_an_empty_end();
    test_a_window_shuts_and_reopens();
    test_a_full_window_is_asked_again_on_update();
    test_a_prefix_waits_for_the_window();
    test_a_full_fill_is_asked_again();
    test_a_source_that_lies_is_clamped();
    test_head_does_not_open();
    test_the_limit_is_answered_503();
    test_a_full_table_is_answered_503();
    test_a_reset_is_peer_reset();
    test_two_streams_take_turns();
    test_other_requests_are_served();
    test_idle_timeout();
    test_shutdown();
    test_a_graceful_goaway_lets_it_finish();
    test_a_goaway_with_an_error_closes();
    test_an_error_after_a_graceful_goaway_closes();
    test_the_goaway_waits_for_the_budget();
    test_the_connection_window();
    test_the_budget_is_kept();
    test_a_short_fill_waits_for_its_kick();
    test_done_closes_the_stream();
    test_close_ends_what_is_open();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("h2 open responses: OK\n");
    return 0;
}
