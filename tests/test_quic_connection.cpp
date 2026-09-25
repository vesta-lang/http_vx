/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_connection.cpp
 * @brief
 * \~english Two whole QUIC connections talking over a simulated network: the transport, working.
 * \~spanish Dos conexiones QUIC enteras hablando por una red simulada: el transporte, funcionando.
 * \~
 *
 * \~english
 * Not a test of one rule: a client and a server, each a complete
 * `Connection`, exchange datagrams over a network that delays, reorders,
 * duplicates and loses them, in simulated time.  They go through a
 * handshake -- simulated, but carried as the real one is: CRYPTO data in
 * Initial, then Handshake, then 1-RTT packets, keys installed at the same
 * points TLS installs them, Initial and Handshake keys discarded when the RFC
 * says -- and then echo several large streams at once.  What the client gets
 * back must be byte for byte what it sent, both ends must confirm, collect
 * every stream, close cleanly, and the server must never have sent more than
 * three times what it received before the client's address was proven.
 *
 * It runs against every provider there is: the fake one always, so that the
 * logic is checked everywhere, and the real ones when they are built, so that
 * keys that do not match would fail here and not only in production.
 *
 * \~spanish
 * No es una prueba de una regla: un cliente y un servidor, cada uno una
 * `Connection` completa, intercambian datagramas por una red que los retrasa,
 * desordena, duplica y pierde, en tiempo simulado.  Pasan por un saludo --
 * simulado, pero llevado como el de verdad: datos CRYPTO en paquetes Initial,
 * luego Handshake, luego 1-RTT, claves instaladas en los mismos puntos en que
 * las instala TLS, claves Initial y Handshake tiradas cuando lo dice el RFC -- y
 * despues hacen eco de varios flujos grandes a la vez.  Lo que recibe el cliente
 * tiene que ser byte a byte lo que mando, los dos extremos tienen que confirmar,
 * recoger todos los flujos, cerrar limpio, y el servidor no puede haber mandado
 * nunca mas de tres veces lo que recibio antes de probarse la direccion del
 * cliente.
 *
 * Corre contra todos los proveedores que haya: el de mentira siempre, para que
 * la logica se compruebe en todas partes, y los de verdad cuando se construyen,
 * para que unas claves que no casan fallen aqui y no solo en produccion.
 * \~
 */

#include "http_vx/quic_connection.h"

#include "fake_crypto.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <vector>

namespace {

using namespace http_vx::quic;

int failures = 0;
char current[96] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

uint8_t pattern_byte(uint64_t seed, uint64_t i) {
    return static_cast<uint8_t>((i * 131 + seed * 7 + (i >> 9)) & 0xff);
}

/// \~english The network's character for one run.  \~spanish El caracter de la red en una corrida.  \~
struct NetShape {
    const char *name;
    unsigned loss_pct;
    unsigned dup_pct;
    uint64_t latency_us;
    uint64_t jitter_us;
    /// \~english Lose the first N datagrams each way: the handshake's own packets.
    /// \~spanish Perder los N primeros datagramas de cada lado: los del propio saludo.  \~
    unsigned lose_first;
    /**
     * \~english
     * Lose everything the server sends for this long, starting the moment it
     * confirms the handshake -- which is the moment it sends HANDSHAKE_DONE.
     * Tied to the event and not to a clock, because a guessed time missed it.
     * \~spanish
     * Perder todo lo que manda el servidor durante este tiempo, empezando en el
     * momento en que confirma el saludo -- que es cuando manda HANDSHAKE_DONE.
     * Atado al suceso y no a un reloj, porque un tiempo adivinado no lo acerto.
     * \~
     */
    uint64_t outage_at_confirm_us;
};

/// \~english Fixed secrets for the simulated handshake, one per direction and level.
/// \~spanish Secretos fijos para el saludo simulado, uno por sentido y nivel.  \~
void secret(uint8_t *out, uint8_t tag) {
    for (int i = 0; i < 32; ++i) out[i] = static_cast<uint8_t>(tag * 17 + i);
}

bool derive(Crypto &c, uint8_t tag, KeyMaterial &m) {
    uint8_t s[32];
    secret(s, tag);
    return derive_key_material(c, kVersion1, Aead::Aes128Gcm, s, 32, m);
}

/// \~english Reads up to @p want bytes of CRYPTO data at a level, consuming them.
/// \~spanish Lee hasta @p want bytes de datos CRYPTO de un nivel, consumiendolos.  \~
size_t read_crypto(Connection &c, Space s, size_t want) {
    size_t got = 0;
    const uint8_t *p = nullptr;
    size_t n;
    while (got < want && (n = c.crypto_recv(s).peek(p)) != 0) {
        if (n > want - got) n = want - got;
        c.consume_crypto(s, n);
        got += n;
    }
    return got;
}

void write_crypto(Connection &c, Space s, size_t n) {
    std::vector<uint8_t> msg(n, static_cast<uint8_t>(0x30 + static_cast<int>(s)));
    size_t took = 0;
    c.crypto_send(s).write(msg.data(), msg.size(), took);
    check(took == n, "a handshake message did not fit its CRYPTO buffer");
}

/**
 * @brief
 * \~english One end: its connection, where it is in the handshake, and its streams' bytes.
 * \~spanish Un extremo: su conexion, en que punto del saludo esta, y los bytes de sus flujos.
 * \~
 */
struct End {
    End(Connection *conn, bool is_server) : c(conn), server(is_server) {}

    Connection *c;
    bool server;
    int stage = 0;
    size_t crypto_got = 0;
    // \~english Per stream: what was received, and (server) how much of it was echoed back.
    // \~spanish Por flujo: lo recibido, y (servidor) cuanto se devolvio.  \~
    std::map<uint64_t, std::vector<uint8_t>> got;
    std::map<uint64_t, size_t> echoed;
};

/**
 * @brief
 * \~english The simulated handshake: CRYPTO messages at the levels TLS 1.3 uses them.
 * \~spanish El saludo simulado: mensajes CRYPTO en los niveles en que los usa TLS 1.3.
 * \~
 *
 * \~english
 * Client: ClientHello (Initial) ... ServerHello arrives -> Handshake keys ...
 * the server's handshake flight arrives -> Finished (Handshake) and 1-RTT keys.
 * Server: ClientHello arrives -> ServerHello (Initial), Handshake keys, its
 * flight (Handshake), 1-RTT keys ... Finished arrives -> confirmed.
 * \~spanish
 * Cliente: ClientHello (Initial) ... llega ServerHello -> claves Handshake ...
 * llega el vuelo del servidor -> Finished (Handshake) y claves 1-RTT.
 * Servidor: llega ClientHello -> ServerHello (Initial), claves Handshake, su vuelo
 * (Handshake), claves 1-RTT ... llega Finished -> confirmado.
 * \~
 */
void drive_handshake(Crypto &cr, End &e, uint64_t now) {
    Connection &c = *e.c;
    KeyMaterial r, w;
    if (!e.server) {
        if (e.stage == 0) {
            write_crypto(c, Space::Initial, 300);
            e.stage = 1;
        }
        if (e.stage == 1 && (e.crypto_got += read_crypto(c, Space::Initial, 100 - e.crypto_got)) == 100) {
            check(derive(cr, 2, r) && derive(cr, 1, w) &&
                      c.install_keys(Space::Handshake, r, w, now),
                  "the client could not install Handshake keys");
            e.crypto_got = 0;
            e.stage = 2;
        }
        if (e.stage == 2 && (e.crypto_got += read_crypto(c, Space::Handshake, 3000 - e.crypto_got)) == 3000) {
            write_crypto(c, Space::Handshake, 50);
            check(derive(cr, 4, r) && derive(cr, 3, w) &&
                      c.install_keys(Space::Application, r, w, now),
                  "the client could not install 1-RTT keys");
            e.stage = 3;
        }
    } else {
        if (e.stage == 0 && (e.crypto_got += read_crypto(c, Space::Initial, 300 - e.crypto_got)) == 300) {
            write_crypto(c, Space::Initial, 100);
            check(derive(cr, 1, r) && derive(cr, 2, w) &&
                      c.install_keys(Space::Handshake, r, w, now),
                  "the server could not install Handshake keys");
            // \~english A flight larger than one datagram: certificates are.
            // \~spanish Un vuelo mayor que un datagrama: los certificados lo son.  \~
            write_crypto(c, Space::Handshake, 3000);
            check(derive(cr, 3, r) && derive(cr, 4, w) &&
                      c.install_keys(Space::Application, r, w, now),
                  "the server could not install 1-RTT keys");
            e.crypto_got = 0;
            e.stage = 1;
        }
        if (e.stage == 1 && (e.crypto_got += read_crypto(c, Space::Handshake, 50 - e.crypto_got)) == 50) {
            c.handshake_confirmed(now);
            e.stage = 2;
        }
    }
}

/// \~english The server echoes every stream; the client collects what comes back.
/// \~spanish El servidor hace eco de cada flujo; el cliente recoge lo que vuelve.  \~
void drive_streams(End &e) {
    Connection &c = *e.c;
    StreamTable &t = c.streams();
    for (size_t i = 0; i < t.capacity(); ++i) {
        Stream *st = t.slot(i);
        if (st == nullptr || st->recv == nullptr) continue;
        std::vector<uint8_t> &buf = e.got[st->id];
        const uint8_t *p = nullptr;
        size_t n;
        while ((n = st->recv->peek(p)) != 0) {
            buf.insert(buf.end(), p, p + n);
            c.consume(*st, n);
        }
        if (e.server && st->send != nullptr) {
            size_t &done = e.echoed[st->id];
            if (done < buf.size()) {
                size_t took = 0;
                st->send->write(buf.data() + done, buf.size() - done, took);
                done += took;
            }
            if (st->recv->state() == RecvState::DataRead && done == buf.size()) st->send->finish();
        }
    }
}

struct Datagram {
    uint64_t at;
    bool to_server;
    std::vector<uint8_t> bytes;
};

/**
 * @brief
 * \~english One full run: handshake, echo of @p streams streams of @p size bytes, close.
 * \~spanish Una corrida entera: saludo, eco de @p streams flujos de @p size bytes, cierre.
 * \~
 */
void run(Crypto &cr, const NetShape &net, uint64_t seed, int streams, size_t size) {
    std::snprintf(current, sizeof current, "%s/%s/seed %llu", cr.name(), net.name,
                  static_cast<unsigned long long>(seed));
    std::mt19937_64 rng(seed);

    ConnectionConfig cc;
    cc.is_server = false;
    for (int i = 0; i < 8; ++i) {
        cc.local_cid[i] = static_cast<uint8_t>(0xc0 + i);
        cc.peer_cid[i] = static_cast<uint8_t>(0x0d + i);  // \~english the original DCID  \~spanish el DCID original  \~
    }
    cc.streams.peer_max_streams_bidi = 100;
    cc.streams.peer_window_bidi_remote = 256 * 1024;
    cc.streams.window_bidi_local = 256 * 1024;
    cc.peer_max_data = 1u << 20;
    cc.data_window = 1u << 20;

    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);
    sc.streams.peer_bidi_concurrency = 100;
    sc.streams.window_bidi_remote = 256 * 1024;
    sc.streams.peer_window_bidi_local = 256 * 1024;
    sc.peer_max_data = 1u << 20;
    sc.data_window = 1u << 20;

    Connection client(cr, cc);
    Connection server(cr, sc);
    check(client.ready() && server.ready(), "a connection could not allocate its tables");
    check(client.set_initial_keys(cc.peer_cid, 8) && server.set_initial_keys(cc.peer_cid, 8),
          "the Initial keys could not be derived");

    End ce{&client, false};
    End se{&server, true};

    std::vector<Datagram> air;
    uint64_t now = 0;
    unsigned sent_each[2] = {0, 0};
    unsigned lost_count = 0;
    uint64_t confirmed_at = kNever;
    bool opened = false;
    std::vector<uint64_t> ids;
    std::map<uint64_t, size_t> written;
    bool closing = false;

    for (int step = 0; step < 400000; ++step) {
        drive_handshake(cr, ce, now);
        drive_handshake(cr, se, now);

        // \~english Once confirmed, the client opens its streams and writes what fits.
        // \~spanish Una vez confirmado, el cliente abre sus flujos y escribe lo que cabe.  \~
        if (client.is_handshake_confirmed() && !opened) {
            for (int k = 0; k < streams; ++k) {
                Stream *st = client.streams().open(true);
                check(st != nullptr, "the client could not open a stream");
                if (st != nullptr) ids.push_back(st->id);
            }
            opened = true;
        }
        for (uint64_t id : ids) {
            Stream *st = client.streams().find(id);
            if (st == nullptr) continue;
            size_t &w = written[id];
            std::vector<uint8_t> chunk;
            while (w < size) {
                const size_t n = std::min<size_t>(size - w, 16384);
                chunk.resize(n);
                for (size_t i = 0; i < n; ++i) chunk[i] = pattern_byte(id, w + i);
                size_t took = 0;
                st->send->write(chunk.data(), n, took);
                w += took;
                if (took < n) break;
            }
            if (w == size) st->send->finish();
        }
        drive_streams(ce);
        drive_streams(se);

        /* \~english
         * Done when every echo came back whole AND both ends collected every
         * stream -- which takes each end's last FIN being acknowledged.  Only
         * then does the client close: closing earlier would abandon streams,
         * which QUIC allows but which would not show they finish.
         * \~spanish
         * Hecho cuando cada eco volvio entero Y los dos extremos recogieron todos
         * los flujos -- lo que exige que se confirme el ultimo FIN de cada uno.
         * Solo entonces cierra el cliente: cerrar antes abandonaria flujos, cosa
         * que QUIC permite pero que no demostraria que terminan.
         * \~ */
        if (opened && !closing) {
            bool all = true;
            for (uint64_t id : ids) all = all && ce.got[id].size() == size;
            all = all && client.streams().count() == 0 && server.streams().count() == 0;
            if (all) {
                client.close(0, true, 0, now);
                closing = true;
            }
        }

        // \~english Both ends send what they have; the network does what networks do.
        // \~spanish Los dos extremos mandan lo que tienen; la red hace lo que hacen las redes.  \~
        for (int who = 0; who < 2; ++who) {
            Connection &c = who == 0 ? client : server;
            uint8_t buf[1500];
            for (int k = 0; k < 64; ++k) {
                const uint64_t in_before = server.bytes_received();
                const bool valid_before = server.address_validated();
                const size_t n = c.build_datagram(buf, sizeof buf, now);
                if (n == 0) break;
                if (who == 1 && !valid_before && server.bytes_sent() > 3 * in_before) {
                    check(false, "the server sent more than three times what it received before validation");
                    return;
                }
                ++sent_each[who];
                if (confirmed_at == kNever && server.is_handshake_confirmed()) confirmed_at = now;
                const bool outage = who == 1 && confirmed_at != kNever &&
                                    now < confirmed_at + net.outage_at_confirm_us;
                const bool lost = outage || sent_each[who] <= net.lose_first ||
                                  rng() % 100 < net.loss_pct;
                if (lost) {
                    ++lost_count;
                    continue;
                }
                Datagram d{now + net.latency_us + (net.jitter_us ? rng() % net.jitter_us : 0),
                           who == 0, std::vector<uint8_t>(buf, buf + n)};
                if (rng() % 100 < net.dup_pct) air.push_back(d);
                air.push_back(d);
            }
        }

        if (client.state() == ConnState::Closed && server.state() == ConnState::Closed) break;

        // \~english The next thing to happen: a delivery or a timer.
        // \~spanish Lo siguiente que pasa: una entrega o un temporizador.  \~
        uint64_t next = std::min(client.timer(), server.timer());
        for (const Datagram &d : air) next = std::min(next, d.at);
        if (next == kNever) {
            check(false, "both ends and the network went quiet before finishing");
            break;
        }
        if (next > now) now = next;

        for (size_t i = 0; i < air.size();) {
            if (air[i].at <= now) {
                Datagram d = air[i];
                air[i] = air.back();
                air.pop_back();
                (d.to_server ? server : client).on_datagram(d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
            } else {
                ++i;
            }
        }
        if (client.timer() <= now) client.on_timer(now);
        if (server.timer() <= now) server.on_timer(now);
    }

    // \~english What must hold at the end.  \~spanish Lo que tiene que cumplirse al final.  \~
    check(client.is_handshake_confirmed() && server.is_handshake_confirmed(),
          "the handshake was not confirmed on both ends");
    for (uint64_t id : ids) {
        const std::vector<uint8_t> &back = ce.got[id];
        bool same = back.size() == size;
        for (size_t i = 0; same && i < size; ++i) same = back[i] == pattern_byte(id, i);
        if (!same) {
            std::fprintf(stderr, "FAIL [%s]: stream %llu echoed %zu bytes of %zu, or other bytes\n",
                         current, static_cast<unsigned long long>(id), back.size(), size);
            ++failures;
        }
    }
    check(client.state() == ConnState::Closed && server.state() == ConnState::Closed,
          "the connections did not end closed");
    check(server.closed_by_peer() && server.close_code() == 0 && server.close_is_application(),
          "the server did not see the client's application close with code 0");
    check(client.drops().forged == 0 && server.drops().forged == 0,
          "packets between two honest ends failed authentication");
    check(client.streams().count() == 0 && server.streams().count() == 0,
          "streams that finished on both sides were not collected");

    /* \~english
     * On a network that loses and reorders nothing, nothing may be declared
     * lost and no probe may fire: a loss there is the transport's own fault
     * -- a packet thrown away by the receiver, or a timer too eager.
     * \~spanish
     * En una red que no pierde ni desordena nada, no se puede declarar nada
     * perdido ni saltar ningun sondeo: una perdida ahi es culpa del propio
     * transporte -- un paquete que tiro quien recibe, o un temporizador con
     * demasiada prisa.
     * \~ */
    if (net.outage_at_confirm_us != 0) {
        // \~english The outage took HANDSHAKE_DONE: it must have gone out again.
        // \~spanish El corte se llevo HANDSHAKE_DONE: tiene que haber salido otra vez.  \~
        check(server.sent().handshake_done >= 2,
              "a lost HANDSHAKE_DONE was not sent again");
    } else if (net.loss_pct == 0 && net.lose_first == 0 && net.jitter_us == 0 && net.dup_pct == 0) {
        check(client.recovery().packets_lost() == 0 && server.recovery().packets_lost() == 0 &&
                  client.recovery().pto_events() == 0 && server.recovery().pto_events() == 0,
              "a clean network saw packets declared lost or probes fired");
        check(client.drops().no_keys == 0 && server.drops().no_keys == 0,
              "a clean network saw packets dropped for lack of keys");
    }

    // \~english What happened, so that a green run shows its evidence.
    // \~spanish Lo que paso, para que una corrida en verde ensene sus pruebas.  \~
    if (seed == 1)
        std::printf("  %-15s %d x %zu bytes echoed in %6.3f s simulated: %u+%u datagrams, "
                    "%u lost, %llu+%llu PTOs, %llu+%llu packets lost, %llu duplicates dropped, "
                    "%llu kept for keys, cwnd %llu/%llu, persistent %llu+%llu\n",
                    net.name, streams, size, static_cast<double>(now) / 1e6, sent_each[0],
                    sent_each[1], lost_count,
                    static_cast<unsigned long long>(client.recovery().pto_events()),
                    static_cast<unsigned long long>(server.recovery().pto_events()),
                    static_cast<unsigned long long>(client.recovery().packets_lost()),
                    static_cast<unsigned long long>(server.recovery().packets_lost()),
                    static_cast<unsigned long long>(client.drops().duplicate + server.drops().duplicate),
                    static_cast<unsigned long long>(client.drops().buffered + server.drops().buffered),
                    static_cast<unsigned long long>(client.recovery().congestion_window()),
                    static_cast<unsigned long long>(server.recovery().congestion_window()),
                    static_cast<unsigned long long>(client.recovery().persistent_congestion_events()),
                    static_cast<unsigned long long>(server.recovery().persistent_congestion_events()));
}

/**
 * @brief
 * \~english A violation crosses the wire: the server closes with the right code, the client hears it.
 * \~spanish Una violacion cruza el cable: el servidor cierra con el codigo justo, el cliente lo oye.
 * \~
 *
 * \~english
 * The client is told the server allows more streams than it does, and opens
 * them: the server must close with STREAM_LIMIT_ERROR, naming the STREAM
 * frame, and the client must end up draining with that code.
 * \~spanish
 * Al cliente se le dice que el servidor permite mas flujos de los que permite, y
 * los abre: el servidor tiene que cerrar con STREAM_LIMIT_ERROR, nombrando la
 * trama STREAM, y el cliente tiene que acabar drenando con ese codigo.
 * \~
 */
void test_violation(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/violation", cr.name());

    ConnectionConfig cc;
    cc.is_server = false;
    for (int i = 0; i < 8; ++i) {
        cc.local_cid[i] = static_cast<uint8_t>(0xc0 + i);
        cc.peer_cid[i] = static_cast<uint8_t>(0x0d + i);
    }
    cc.streams.peer_max_streams_bidi = 10;
    cc.streams.peer_window_bidi_remote = 65536;
    cc.peer_max_data = 1u << 20;

    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);
    sc.streams.peer_bidi_concurrency = 2;
    sc.peer_max_data = 1u << 20;

    Connection client(cr, cc);
    Connection server(cr, sc);
    client.set_initial_keys(cc.peer_cid, 8);
    server.set_initial_keys(cc.peer_cid, 8);
    End ce{&client, false};
    End se{&server, true};

    uint64_t now = 0;
    bool opened = false;
    for (int step = 0; step < 2000; ++step) {
        drive_handshake(cr, ce, now);
        drive_handshake(cr, se, now);
        if (client.is_handshake_confirmed() && !opened) {
            for (int k = 0; k < 3; ++k) {
                Stream *st = client.streams().open(true);
                const uint8_t hi[] = {'h', 'i'};
                size_t took = 0;
                if (st != nullptr) st->send->write(hi, 2, took);
            }
            opened = true;
        }
        uint8_t buf[1500];
        size_t n;
        while ((n = client.build_datagram(buf, sizeof buf, now)) != 0)
            server.on_datagram(buf, n, Ecn::NotEct, now + 1000);
        while ((n = server.build_datagram(buf, sizeof buf, now)) != 0)
            client.on_datagram(buf, n, Ecn::NotEct, now + 1000);
        now += 1000;
        if (client.state() == ConnState::Draining) break;
        if (client.timer() <= now) client.on_timer(now);
        if (server.timer() <= now) server.on_timer(now);
    }

    check(server.state() == ConnState::Closing && !server.closed_by_peer() &&
              server.close_code() == static_cast<uint64_t>(TransportError::StreamLimitError) &&
              server.close_frame() >= 0x08 && server.close_frame() <= 0x0f,
          "the server did not close with STREAM_LIMIT_ERROR naming a STREAM frame");
    check(client.state() == ConnState::Draining && client.closed_by_peer() &&
              client.close_code() == static_cast<uint64_t>(TransportError::StreamLimitError),
          "the client did not hear the server's STREAM_LIMIT_ERROR");
}

/// \~english A connection nobody talks on is gone after the idle timeout, silently (10.1).
/// \~spanish Una conexion por la que no habla nadie desaparece tras el plazo de inactividad, en silencio (10.1).  \~
void test_idle(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/idle", cr.name());
    ConnectionConfig cc;
    cc.is_server = false;
    cc.idle_timeout_us = 5000000;
    Connection client(cr, cc);
    client.set_initial_keys(cc.peer_cid, 8);
    write_crypto(client, Space::Initial, 300);
    uint8_t buf[1500];
    check(client.build_datagram(buf, sizeof buf, 0) >= kMinInitialDatagram,
          "a client's first datagram was not padded to 1200 bytes");

    // \~english Nothing answers: probes go out, then the idle timeout ends it.
    // \~spanish No contesta nadie: salen sondeos, y luego el plazo de inactividad lo acaba.  \~
    uint64_t now = 0;
    for (int i = 0; i < 100 && client.state() != ConnState::Closed; ++i) {
        now = client.timer();
        client.on_timer(now);
        while (client.build_datagram(buf, sizeof buf, now) != 0) {
        }
    }
    check(client.state() == ConnState::Closed && now >= 5000000 && now <= 5000000 + 3000000,
          "a silent connection did not end at its idle timeout");
    check(client.recovery().pto_events() > 0, "no probe went out while waiting");
}

/**
 * @brief
 * \~english A server does not open 1-RTT before the handshake completes: it keeps it (RFC 9001, 5.7).
 * \~spanish Un servidor no abre 1-RTT antes de que acabe el saludo: lo guarda (RFC 9001, 5.7).
 * \~
 */
void test_early_one_rtt(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/early-1rtt", cr.name());

    ConnectionConfig cc;
    cc.is_server = false;
    for (int i = 0; i < 8; ++i) {
        cc.local_cid[i] = static_cast<uint8_t>(0xc0 + i);
        cc.peer_cid[i] = static_cast<uint8_t>(0x50 + i);
    }
    cc.streams.peer_max_streams_bidi = 4;
    cc.streams.peer_window_bidi_remote = 65536;
    cc.peer_max_data = 65536;
    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);

    Connection client(cr, cc);
    Connection server(cr, sc);
    KeyMaterial r, w;
    check(derive(cr, 4, r) && derive(cr, 3, w) && client.install_keys(Space::Application, r, w, 0) &&
              derive(cr, 3, r) && derive(cr, 4, w) && server.install_keys(Space::Application, r, w, 0),
          "the 1-RTT keys could not be installed");

    Stream *st = client.streams().open(true);
    const uint8_t early[] = {'e', 'a', 'r', 'l', 'y'};
    size_t took = 0;
    st->send->write(early, sizeof early, took);
    uint8_t buf[1500];
    const size_t n = client.build_datagram(buf, sizeof buf, 1000);
    check(n != 0, "the client sent no 1-RTT packet");

    server.on_datagram(buf, n, Ecn::NotEct, 2000);
    check(server.streams().count() == 0 && server.drops().forged == 0,
          "the server opened a 1-RTT packet before its handshake completed");

    server.handshake_confirmed(3000);
    Stream *got = server.streams().find(0);
    const uint8_t *p = nullptr;
    check(got != nullptr && got->recv->peek(p) == sizeof early && std::memcmp(p, early, sizeof early) == 0 &&
              server.drops().buffered == 1,
          "the kept 1-RTT packet was not opened once the handshake completed");
}

void run_all(Crypto &cr) {
    std::printf("-- %s --\n", cr.name());
    /* \~english
     * "handshake-done-lost": everything from the server is lost for 150 ms
     * from the moment it confirms, HANDSHAKE_DONE included.  Without
     * retransmitting it the client would never confirm, nor open a stream.
     * \~spanish
     * "handshake-done-lost": todo lo del servidor se pierde durante 150 ms desde
     * el momento en que confirma, HANDSHAKE_DONE incluido.  Sin retransmitirlo el
     * cliente no confirmaria nunca, ni abriria un flujo.
     * \~ */
    const NetShape shapes[] = {
        {"clean", 0, 0, 20000, 0, 0, 0},
        {"lossy", 5, 2, 20000, 10000, 0, 0},
        {"hostile", 20, 5, 30000, 40000, 0, 0},
        {"handshake-lost", 3, 0, 20000, 5000, 2, 0},
        {"handshake-done-lost", 0, 0, 20000, 0, 0, 150000},
    };
    for (const NetShape &net : shapes)
        for (uint64_t seed = 1; seed <= 3; ++seed) run(cr, net, seed, 4, 100000);
    test_violation(cr);
    test_idle(cr);
    test_early_one_rtt(cr);
}

} // namespace

int main() {
    test_support::FakeCrypto fake;
    run_all(fake);

#if HTTP_VX_HAVE_OPENSSL
    {
        http_vx::OpensslCrypto c;
        if (c.ready()) run_all(c);
    }
#endif
#if HTTP_VX_HAVE_CNG
    {
        http_vx::CngCrypto c;
        if (c.ready()) run_all(c);
    }
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic connection: OK\n");
    return 0;
}
