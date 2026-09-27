/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/h3_open_world.h
 * @brief
 * \~english The world the HTTP/3 open response tests run in: sources fed by hand, a handler that opens, a shard, a network.
 * \~spanish El mundo en el que corren las pruebas de respuestas abiertas de HTTP/3: fuentes alimentadas a mano, un manejador que abre, un fragmento, una red.
 * \~
 *
 * \~english
 * The service runs under a real shard, as the datagram side of it, so the
 * port, the kick queue and their counts are the shard's own.  The shard has
 * no socket: the world moves the datagrams, and pulls them after each shard
 * turn -- the order the shard keeps, kicks drained first.
 * \~spanish
 * El servicio corre bajo un fragmento de verdad, como su lado de datagramas, asi
 * que la puerta, la cola de avisos y sus cuentas son las del fragmento.  El
 * fragmento no tiene socket: el mundo mueve los datagramas, y los saca despues
 * de cada vuelta del fragmento -- el orden que sigue el fragmento, primero los
 * avisos vaciados.
 * \~
 */
#ifndef HTTP_VX_TESTS_H3_OPEN_WORLD_H
#define HTTP_VX_TESTS_H3_OPEN_WORLD_H

#include "http_vx/http3_datagrams.h"
#include "http_vx/memory_backend.h"
#include "http_vx/quic_varint.h"
#include "http_vx/shard.h"

#include "h3_test_client.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace h3_open_test {

using namespace h3_test;
using http_vx::BodySource;
using http_vx::GoneReason;
using http_vx::Http3Datagrams;
using http_vx::Http3Service;
using http_vx::MemoryBackend;
using http_vx::OpenResponse;
using http_vx::Shard;

inline uint64_t g_clock = 0;

/**
 * @brief
 * \~english The adapter's clock: the world's.  \~spanish El reloj del adaptador: el del mundo.
 * \~
 *
 * @return \~english the world's time, in microseconds  \~spanish la hora del mundo, en microsegundos  \~
 */
inline uint64_t test_clock() { return g_clock; }

/// \~english A source the test feeds by hand.  \~spanish Una fuente que la prueba alimenta a mano.  \~
class Feed final : public BodySource {
  public:
    size_t fill(OpenResponse, uint8_t *dst, size_t room, bool &done) noexcept override {
        ++fills;
        if (room > max_room) max_room = room;
        size_t n = 0;
        if (full_fills != 0) {
            --full_fills;
            for (size_t i = 0; i < room; ++i) dst[i] = static_cast<uint8_t>('a' + (produced.size() + i) % 26);
            n = room;
        } else {
            n = pending.size() < room ? pending.size() : room;
            std::memcpy(dst, pending.data(), n);
            pending.erase(0, n);
        }
        produced.append(reinterpret_cast<const char *>(dst), n);
        done = finish && pending.empty() && full_fills == 0;
        return n == room ? n + lie : n;
    }

    void gone(OpenResponse, GoneReason why) noexcept override {
        ++gones;
        last = why;
    }

    std::string pending;
    std::string produced;
    bool finish = false;
    /// \~english How many fills take all the room.  \~spanish Cuantos rellenos usan todo el sitio.  \~
    int full_fills = 0;
    /// \~english Added to a full fill's count: a source that lies.  \~spanish Se suma a la cuenta de un relleno lleno: una fuente que miente.  \~
    size_t lie = 0;
    int fills = 0;
    size_t max_room = 0;
    int gones = 0;
    GoneReason last = GoneReason::Finished;
};

constexpr size_t kFeeds = 4;

/// \~english Opens on "/open" with the next source, answers anything else whole.  \~spanish Abre en "/open" con la fuente siguiente, contesta lo demas entero.  \~
class Opener final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &req, const uint8_t *head, const uint8_t *, size_t,
                http_vx::ResponseBuilder &res) noexcept override {
        ++calls;
        const std::string path(reinterpret_cast<const char *>(head) + req.target.off, req.target.len);
        if (path.compare(0, 5, "/open") != 0) {
            res.body("whole", 5);
            return;
        }
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/event-stream", 17);
        if (!before.empty()) res.body(before.data(), before.size());
        // \~english "/open/N" names its source, for requests whose order of arrival is not fixed.
        // \~spanish "/open/N" nombra su fuente, para peticiones cuyo orden de llegada no esta fijado.  \~
        const size_t pick = path.size() == 7 ? static_cast<size_t>(path[6] - '0') : next++;
        last = res.open(feeds[pick % kFeeds]);
    }

    Feed *feeds = nullptr;
    size_t next = 0;
    std::string before;
    OpenResponse last;
    int calls = 0;
};

/**
 * @brief
 * \~english The service under a shard, its clients, and a network that delays every datagram.
 * \~spanish El servicio bajo un fragmento, sus clientes, y una red que retrasa cada datagrama.
 * \~
 */
struct World {
    Crypto &crypto;
    Feed feeds[kFeeds];
    Opener handler;
    Http3Service service;
    Http3Datagrams adapter;
    Shard shard;
    MemoryBackend io;
    std::vector<std::unique_ptr<Client>> clients;
    std::vector<Datagram> air;
    uint64_t now = 0;

    explicit World(Crypto &c) : crypto(c), service(c, handler), adapter(service, test_clock), io(shard.buffers()) {
        handler.feeds = feeds;
    }

    // \~english The shard lets go first, while every source is still here to be told.
    // \~spanish El fragmento suelta primero, mientras cada fuente sigue aqui para que se lo digan.  \~
    ~World() { shard.release(); }

    /**
     * @brief
     * \~english Starts the service and the shard it runs under.
     * \~spanish Arranca el servicio y el fragmento bajo el que corre.
     * \~
     *
     * @param shard_open \~english the shard's limit of open responses  \~spanish el tope de respuestas abiertas del fragmento  \~
     * @return           \~english whether both started  \~spanish si arrancaron los dos  \~
     */
    bool start(const Http3Config &cfg, uint32_t shard_open = 1024) {
        // \~english Long enough that a test's quiet stretches end no connection; the idle test waits past it.
        // \~spanish Lo bastante largo para que los ratos callados de una prueba no acaben ninguna conexion; la prueba de inactividad espera mas.  \~
        Http3Config quiet = cfg;
        quiet.connection.idle_timeout_us = 20000000;
        if (!service.start(quiet)) return false;
        http_vx::ShardConfig sc;
        sc.connections = 4;
        sc.buffers = 16;
        sc.idle_ticks = 10;
        sc.wheel_slots = 64;
        sc.max_open = shard_open;
        return shard.reset(sc, io, 0) && shard.attach_datagrams(adapter, http_vx::DatagramConfig());
    }

    /**
     * @brief
     * \~english A new client, with the windows it gives the server.  \~spanish Un cliente nuevo, con las ventanas que le da al servidor.
     * \~
     *
     * @return \~english the client  \~spanish el cliente  \~
     */
    Client &add(uint64_t window = 0, uint64_t data_window = 0) {
        clients.emplace_back(
            new Client(crypto, static_cast<uint8_t>(clients.size() + 1), kH3, now, nullptr, window, data_window));
        return *clients.back();
    }

    /**
     * @brief
     * \~english Which client a datagram's path leads to, or -2.  \~spanish A que cliente lleva el camino de un datagrama, o -2.
     * \~
     *
     * @return \~english its index  \~spanish su indice  \~
     */
    int client_of(const Path &p) const {
        for (size_t i = 0; i < clients.size(); ++i)
            if (same_address(clients[i]->path.local, p.peer)) return static_cast<int>(i);
        return -2;
    }

    /// \~english Runs until nothing is in the air and no timer is due before @p until.
    /// \~spanish Corre hasta que no quede nada en el aire ni temporizador antes de @p until.  \~
    void run(uint64_t until) {
        for (int step = 0; step < 200000; ++step) {
            g_clock = now;
            uint8_t buf[1500];
            for (auto &c : clients) {
                c->step(now);
                Path sent;
                size_t n;
                while ((n = c->q->build_datagram(sent, buf, sizeof buf, now)) != 0) {
                    Path to_server;
                    to_server.local = c->path.peer;
                    to_server.peer = c->path.local;
                    air.push_back(Datagram{now + kDelay, -1, to_server, std::vector<uint8_t>(buf, buf + n)});
                }
            }
            // \~english The shard's turn drains the kicks; then what the service has to say is pulled.
            // \~spanish La vuelta del fragmento vacia los avisos; despues se saca lo que el servicio tenga que decir.  \~
            shard.poll(0, 0);
            Path out;
            size_t n;
            while ((n = service.next_datagram(out, buf, sizeof buf, now)) != 0)
                air.push_back(Datagram{now + kDelay, client_of(out), out, std::vector<uint8_t>(buf, buf + n)});

            uint64_t next = service.timer();
            for (auto &c : clients)
                if (c->q->timer() < next) next = c->q->timer();
            for (const Datagram &d : air)
                if (d.at < next) next = d.at;
            if (next == kNever || next > until) {
                if (until > now) now = until;
                return;
            }
            if (next > now) now = next;
            for (size_t i = 0; i < air.size();) {
                if (air[i].at > now) {
                    ++i;
                    continue;
                }
                Datagram d = std::move(air[i]);
                air[i] = std::move(air.back());
                air.pop_back();
                if (d.to == -1) {
                    service.on_datagram(d.path, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                } else if (d.to >= 0) {
                    Client &c = *clients[static_cast<size_t>(d.to)];
                    c.q->on_datagram(c.path, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                }
            }
            for (auto &c : clients)
                if (c->q->timer() <= now) c->q->on_timer(now);
            if (service.timer() <= now) service.on_timer(now);
        }
        check(false, "the network did not settle");
    }

    /// \~english Runs two seconds more.  \~spanish Corre dos segundos mas.  \~
    void settle() { run(now + 2000000); }
};

/**
 * @brief
 * \~english Reads one HTTP/3 frame's type and length at @p at, and the width the length took.
 * \~spanish Lee el tipo y la longitud de una trama HTTP/3 en @p at, y el ancho que ocupo la longitud.
 * \~
 *
 * @return \~english false if the frame is not all there  \~spanish false si la trama no esta entera  \~
 */
inline bool read_frame(const uint8_t *p, size_t n, size_t &at, uint64_t &type, uint64_t &len, size_t &width,
                       std::string &payload) {
    const size_t t = decode_varint(p + at, n - at, type);
    if (t == 0) return false;
    width = decode_varint(p + at + t, n - at - t, len);
    if (width == 0 || at + t + width + len > n) return false;
    payload.assign(reinterpret_cast<const char *>(p) + at + t + width, static_cast<size_t>(len));
    at += t + width + static_cast<size_t>(len);
    return true;
}

} // namespace h3_open_test

#endif // HTTP_VX_TESTS_H3_OPEN_WORLD_H
