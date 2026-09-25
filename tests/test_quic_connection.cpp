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
 * The server connection does not exist at the start: it is created from what
 * the acceptor admits, as a real server would -- so every run also goes
 * through the stateless front door, and the Retry runs through a Retry and a
 * token first.  Then each rule a client follows about Version Negotiation and
 * Retry is tried on its own, with packets that break exactly that rule.
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
 * La conexion del servidor no existe al principio: se crea a partir de lo que
 * admite el acceptor, como haria un servidor de verdad -- asi que cada corrida
 * pasa tambien por la puerta de entrada sin estado, y las de Retry pasan antes
 * por un Retry y un testigo.  Despues se prueba por separado cada regla que
 * sigue un cliente con Version Negotiation y Retry, con paquetes que rompen
 * justo esa regla.
 *
 * Corre contra todos los proveedores que haya: el de mentira siempre, para que
 * la logica se compruebe en todas partes, y los de verdad cuando se construyen,
 * para que unas claves que no casan fallen aqui y no solo en produccion.
 * \~
 */

#include "http_vx/quic_acceptor.h"
#include "http_vx/quic_connection.h"
#include "http_vx/quic_frame.h"
#include "http_vx/quic_protection.h"

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
#include <memory>
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
    /// \~english The server makes the client prove its address with a Retry first.
    /// \~spanish El servidor hace que el cliente pruebe primero su direccion con un Retry.  \~
    bool retry;
};

const uint8_t kClientAddr[6] = {198, 51, 100, 7, 0x1f, 0x90};

/// \~english The server's acceptor, as every run configures it.
/// \~spanish El acceptor del servidor, como lo configura cada corrida.  \~
AcceptorConfig acceptor_config(bool retry) {
    AcceptorConfig a;
    a.require_retry = retry;
    for (size_t i = 0; i < sizeof a.token_key; ++i) a.token_key[i] = static_cast<uint8_t>(0x71 * i + 3);
    return a;
}

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
    check(client.ready(), "the client could not allocate its tables");
    check(client.set_initial_keys(cc.peer_cid, 8), "the client's Initial keys could not be derived");

    // \~english The server is born from what its acceptor admits.
    // \~spanish El servidor nace de lo que admite su acceptor.  \~
    Acceptor acceptor(cr, acceptor_config(net.retry));
    check(acceptor.ready(), "the acceptor is not ready");
    std::unique_ptr<Connection> srv;

    End ce{&client, false};
    End se{nullptr, true};

    std::vector<Datagram> air;
    uint64_t now = 0;
    unsigned sent_each[2] = {0, 0};
    unsigned lost_count = 0;
    uint64_t confirmed_at = kNever;
    uint64_t admitted_at = kNever;
    bool opened = false;
    std::vector<uint64_t> ids;
    std::map<uint64_t, size_t> written;
    bool closing = false;

    for (int step = 0; step < 400000; ++step) {
        drive_handshake(cr, ce, now);
        if (srv) drive_handshake(cr, se, now);

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
        if (srv) drive_streams(se);

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
            all = all && client.streams().count() == 0 && srv && srv->streams().count() == 0;
            if (all) {
                client.close(0, true, 0, now);
                closing = true;
            }
        }

        // \~english Both ends send what they have; the network does what networks do.
        // \~spanish Los dos extremos mandan lo que tienen; la red hace lo que hacen las redes.  \~
        for (int who = 0; who < 2; ++who) {
            if (who == 1 && !srv) break;
            Connection &c = who == 0 ? client : *srv;
            uint8_t buf[1500];
            for (int k = 0; k < 64; ++k) {
                const uint64_t in_before = srv ? srv->bytes_received() : 0;
                const bool valid_before = srv && srv->address_validated();
                const size_t n = c.build_datagram(buf, sizeof buf, now);
                if (n == 0) break;
                if (who == 1 && !valid_before && srv->bytes_sent() > 3 * in_before) {
                    check(false, "the server sent more than three times what it received before validation");
                    return;
                }
                ++sent_each[who];
                if (confirmed_at == kNever && srv && srv->is_handshake_confirmed()) confirmed_at = now;
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

        if (client.state() == ConnState::Closed && srv && srv->state() == ConnState::Closed) break;

        // \~english The next thing to happen: a delivery or a timer.
        // \~spanish Lo siguiente que pasa: una entrega o un temporizador.  \~
        uint64_t next = client.timer();
        if (srv) next = std::min(next, srv->timer());
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
                if (!d.to_server) {
                    client.on_datagram(d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                } else if (srv) {
                    srv->on_datagram(d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                } else {
                    /* \~english
                     * No connection yet: the acceptor decides.  Its reply
                     * crosses the same network; an admission creates the
                     * server, which then gets the very datagram admitted.
                     * \~spanish
                     * Aun no hay conexion: decide el acceptor.  Su respuesta
                     * cruza la misma red; una admision crea el servidor, que
                     * recibe entonces el mismo datagrama admitido.
                     * \~ */
                    uint8_t reply[1500];
                    const Admission ad = acceptor.on_datagram(d.bytes.data(), d.bytes.size(), kClientAddr,
                                                              sizeof kClientAddr, now, reply, sizeof reply);
                    if (ad.verdict == Admit::Reply) {
                        if (rng() % 100 < net.loss_pct) {
                            ++lost_count;
                        } else {
                            air.push_back(Datagram{now + net.latency_us, false,
                                                   std::vector<uint8_t>(reply, reply + ad.reply_len)});
                        }
                    } else if (ad.verdict == Admit::Accept) {
                        std::memcpy(sc.peer_cid, ad.scid, ad.scid_len);
                        sc.peer_cid_len = ad.scid_len;
                        sc.version = ad.version;
                        srv.reset(new Connection(cr, sc));
                        admitted_at = now;
                        check(srv->ready(), "the server could not allocate its tables");
                        check(srv->set_initial_keys(ad.dcid, ad.dcid_len),
                              "the server's Initial keys could not be derived");
                        if (ad.address_validated) srv->set_address_validated(now);
                        // \~english Checked NOW: by the end, a Handshake packet validates it anyway.
                        // \~spanish Comprobado AHORA: al final, un paquete Handshake lo valida de todos modos.  \~
                        check(srv->address_validated() == ad.address_validated,
                              "the server's view of the address is not what the acceptor proved");
                        se.c = srv.get();
                        srv->on_datagram(d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                    }
                }
            } else {
                ++i;
            }
        }
        if (client.timer() <= now) client.on_timer(now);
        if (srv && srv->timer() <= now) srv->on_timer(now);
    }

    if (!srv) {
        check(false, "the acceptor never admitted the client");
        return;
    }
    Connection &server = *srv;

    // \~english The front door did what the run asked of it.
    // \~spanish La puerta de entrada hizo lo que pedia la corrida.  \~
    if (net.retry) {
        check(client.retried(), "the client did not take the Retry");
        check(acceptor.count(AdmitReason::SentRetry) >= 1 &&
                  acceptor.count(AdmitReason::AcceptedWithToken) == 1 &&
                  acceptor.count(AdmitReason::Accepted) == 0,
              "the acceptor did not admit exactly one client, with a token, after a Retry");
        check(server.address_validated(), "a token did not validate the server's view of the address");
    } else {
        check(!client.retried() && acceptor.count(AdmitReason::Accepted) == 1 &&
                  acceptor.count(AdmitReason::SentRetry) == 0,
              "without Retry the acceptor did not admit the client straight away");
    }
    check(acceptor.count(AdmitReason::SentInvalidToken) == 0, "an honest token was refused");

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
        std::printf("  %-15s %d x %zu bytes echoed in %6.3f s simulated, admitted at %5.1f ms, "
                    "confirmed at %5.1f ms: %u+%u datagrams, "
                    "%u lost, %llu+%llu PTOs, %llu+%llu packets lost, %llu duplicates dropped, "
                    "%llu kept for keys, cwnd %llu/%llu, persistent %llu+%llu\n",
                    net.name, streams, size, static_cast<double>(now) / 1e6,
                    static_cast<double>(admitted_at) / 1e3, static_cast<double>(confirmed_at) / 1e3,
                    sent_each[0],
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

/* \~english
 * Version Negotiation and Retry, rule by rule.  Each case builds a client
 * with its first flight written and hands it one packet crafted to break one
 * rule; the counter of THAT rule has to move, and the connection has to be
 * where the rule says.
 * \~spanish
 * Version Negotiation y Retry, regla a regla.  Cada caso monta un cliente con su
 * primer vuelo escrito y le da un paquete hecho para romper una regla; tiene que
 * moverse el contador de ESA regla, y la conexion tiene que quedar donde dice la
 * regla.
 * \~ */

ConnectionConfig small_client(uint32_t version) {
    ConnectionConfig cc;
    cc.is_server = false;
    cc.version = version;
    for (int i = 0; i < 8; ++i) {
        cc.local_cid[i] = static_cast<uint8_t>(0xc0 + i);
        cc.peer_cid[i] = static_cast<uint8_t>(0x0d + i);
    }
    return cc;
}

ConnectionConfig small_server() {
    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);
    return sc;
}

/// \~english A client with its ClientHello written; @p out gets its first datagram.
/// \~spanish Un cliente con su ClientHello escrito; @p out recibe su primer datagrama.  \~
size_t start_client(Connection &client, const ConnectionConfig &cc, uint8_t *out) {
    client.set_initial_keys(cc.peer_cid, 8);
    write_crypto(client, Space::Initial, 300);
    return client.build_datagram(out, 1500, 0);
}

/// \~english The server reads the ClientHello and answers: its first flight is ready to send.
/// \~spanish El servidor lee el ClientHello y contesta: su primer vuelo queda listo para mandar.  \~
void drive_handshake_server_first(Crypto &cr, Connection &server) {
    End e{&server, true};
    drive_handshake(cr, e, 1000);
}

/// \~english The server an acceptor admits for @p dgram, already fed with it; null if none.
/// \~spanish El servidor que admite un acceptor para @p dgram, ya alimentado con el; nulo si ninguno.  \~
std::unique_ptr<Connection> admit(Crypto &cr, Acceptor &a, uint8_t *dgram, size_t n,
                                  uint64_t now) {
    uint8_t reply[1500];
    const Admission ad = a.on_datagram(dgram, n, kClientAddr, sizeof kClientAddr, now, reply,
                                       sizeof reply);
    if (ad.verdict != Admit::Accept) return nullptr;
    ConnectionConfig sc = small_server();
    std::memcpy(sc.peer_cid, ad.scid, ad.scid_len);
    sc.peer_cid_len = ad.scid_len;
    sc.version = ad.version;
    std::unique_ptr<Connection> s(new Connection(cr, sc));
    s->set_initial_keys(ad.dcid, ad.dcid_len);
    if (ad.address_validated) s->set_address_validated(now);
    s->on_datagram(dgram, n, Ecn::NotEct, now);
    return s;
}

size_t put_u32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
    return 4;
}

size_t craft_vn(const uint8_t *dcid, size_t dcid_len, const uint8_t *scid, size_t scid_len,
                const uint32_t *versions, size_t count, uint8_t *out) {
    size_t p = 0;
    out[p++] = 0xc5;
    p += put_u32(out + p, 0);
    out[p++] = static_cast<uint8_t>(dcid_len);
    std::memcpy(out + p, dcid, dcid_len);
    p += dcid_len;
    out[p++] = static_cast<uint8_t>(scid_len);
    std::memcpy(out + p, scid, scid_len);
    p += scid_len;
    for (size_t i = 0; i < count; ++i) p += put_u32(out + p, versions[i]);
    return p;
}

/// \~english A v1 Retry with a CORRECT tag for @p odcid: only the rule under test is broken.
/// \~spanish Un Retry v1 con una marca CORRECTA para @p odcid: solo se rompe la regla que se prueba.  \~
size_t craft_retry(Crypto &cr, const uint8_t *dcid, const uint8_t *scid, size_t scid_len,
                   const uint8_t *token, size_t token_len, const uint8_t *odcid, uint8_t *out) {
    size_t p = 0;
    out[p++] = 0xf0;
    p += put_u32(out + p, kVersion1);
    out[p++] = 8;
    std::memcpy(out + p, dcid, 8);
    p += 8;
    out[p++] = static_cast<uint8_t>(scid_len);
    std::memcpy(out + p, scid, scid_len);
    p += scid_len;
    if (token_len) std::memcpy(out + p, token, token_len);
    p += token_len;
    uint8_t scratch[600];
    check(retry_tag(cr, kVersion1, odcid, 8, out, p, scratch, sizeof scratch, out + p),
          "a Retry tag could not be computed");
    return p + kRetryTagSize;
}

void test_version_negotiation(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/version-negotiation", cr.name());
    uint8_t first[1500], pkt[1500];

    // \~english A v2 client meets a v1-only server: VN, and the attempt ends.
    // \~spanish Un cliente v2 se encuentra con un servidor solo v1: VN, y el intento acaba.  \~
    {
        const ConnectionConfig cc = small_client(kVersion2);
        Connection client(cr, cc);
        const size_t n = start_client(client, cc, first);
        AcceptorConfig ac = acceptor_config(false);
        ac.version_count = 1;
        Acceptor a(cr, ac);
        const Admission ad = a.on_datagram(first, n, kClientAddr, sizeof kClientAddr, 0, pkt, sizeof pkt);
        check(ad.reason == AdmitReason::SentVersionNegotiation, "the acceptor did not answer with VN");
        client.on_datagram(pkt, ad.reply_len, Ecn::NotEct, 1000);
        uint32_t offered[4] = {};
        const size_t count = client.offered_versions(offered, 4);
        check(client.state() == ConnState::Closed && client.ended_in_version_negotiation(),
              "a VN with no version in common did not end the attempt");
        check(count == 2 && offered[0] == kVersion1 && (offered[1] & 0x0f0f0f0fu) == 0x0a0a0a0au,
              "the offered versions are not what the server listed");
        check(client.build_datagram(pkt, sizeof pkt, 2000) == 0 && client.timer() == kNever,
              "an abandoned attempt still sends or waits");
    }

    const ConnectionConfig cc = small_client(kVersion1);
    const uint32_t other[2] = {0x1a2a3a4a, kVersion2};
    const uint32_t mine[2] = {0x1a2a3a4a, kVersion1};

    // \~english One that lists the version in use contradicts itself.
    // \~spanish Uno que lista la version en uso se contradice.  \~
    {
        Connection client(cr, cc);
        start_client(client, cc, first);
        const size_t n = craft_vn(cc.local_cid, 8, cc.peer_cid, 8, mine, 2, pkt);
        client.on_datagram(pkt, n, Ecn::NotEct, 1000);
        check(client.state() == ConnState::Active && client.drops().version_negotiation == 1 &&
                  !client.ended_in_version_negotiation(),
              "a VN listing the version in use was not ignored");
    }

    // \~english One whose IDs are not the client's, swapped: not an answer to it.
    // \~spanish Uno cuyos identificadores no son los del cliente, cruzados: no le contesta a el.  \~
    {
        Connection client(cr, cc);
        start_client(client, cc, first);
        uint8_t wrong[8];
        std::memcpy(wrong, cc.peer_cid, 8);
        wrong[3] ^= 1;
        size_t n = craft_vn(cc.local_cid, 8, wrong, 8, other, 2, pkt);
        client.on_datagram(pkt, n, Ecn::NotEct, 1000);
        n = craft_vn(wrong, 8, cc.peer_cid, 8, other, 2, pkt);
        client.on_datagram(pkt, n, Ecn::NotEct, 1000);
        check(client.state() == ConnState::Active && client.drops().wrong_cid == 2,
              "a VN that does not echo the client's IDs was believed");
    }

    // \~english After the server has spoken, a VN can only be forged.
    // \~spanish Despues de que hablo el servidor, un VN solo puede ser falsificado.  \~
    {
        Connection client(cr, cc);
        const size_t n = start_client(client, cc, first);
        Acceptor a(cr, acceptor_config(false));
        std::unique_ptr<Connection> server = admit(cr, a, first, n, 1000);
        check(server != nullptr, "the acceptor did not admit the client");
        if (server == nullptr) return;
        drive_handshake_server_first(cr, *server);
        const size_t m = server->build_datagram(pkt, sizeof pkt, 2000);
        client.on_datagram(pkt, m, Ecn::NotEct, 3000);
        const size_t v = craft_vn(cc.local_cid, 8, cc.peer_cid, 8, other, 2, pkt);
        client.on_datagram(pkt, v, Ecn::NotEct, 4000);
        check(client.state() == ConnState::Active && client.drops().version_negotiation == 1,
              "a VN after the server's first packet was believed");
    }
}

void test_retry_rules(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/retry", cr.name());
    const ConnectionConfig cc = small_client(kVersion1);
    uint8_t first[1500], retry[1500], pkt[1500];

    // \~english The genuine article, from an acceptor that requires it.
    // \~spanish El de verdad, de un acceptor que lo exige.  \~
    Connection client(cr, cc);
    const size_t n = start_client(client, cc, first);
    Acceptor a(cr, acceptor_config(true));
    const Admission ad = a.on_datagram(first, n, kClientAddr, sizeof kClientAddr, 0, retry, sizeof retry);
    check(ad.reason == AdmitReason::SentRetry, "the acceptor did not send a Retry");
    HeaderContext hc;
    PacketHeader rh;
    check(parse_packet(retry, ad.reply_len, hc, rh) == HeaderError::None, "the Retry does not parse");

    // \~english One bit of the tag changed: forged, and the client stays as it was.
    // \~spanish Un bit de la marca cambiado: falsificado, y el cliente se queda como estaba.  \~
    std::memcpy(pkt, retry, ad.reply_len);
    pkt[ad.reply_len - 1] ^= 1;
    client.on_datagram(pkt, ad.reply_len, Ecn::NotEct, 1000);
    check(!client.retried() && client.drops().forged == 1, "a Retry with a bad tag was taken");

    std::memcpy(pkt, retry, ad.reply_len);
    client.on_datagram(pkt, ad.reply_len, Ecn::NotEct, 1000);
    check(client.retried(), "a genuine Retry was not taken");
    size_t rlen = 0;
    const uint8_t *rscid = client.retry_source_cid(rlen);
    check(rlen == rh.scid.len && std::memcmp(rscid, retry + rh.scid.off, rlen) == 0,
          "the Retry's source ID was not kept");
    check(client.recovery().packets_lost() == 0, "a Retry was counted as a loss");

    // \~english The next Initial: to the Retry's ID, with the token, numbering on, CRYPTO again.
    // \~spanish El Initial siguiente: al identificador del Retry, con el testigo, numeracion seguida, CRYPTO otra vez.  \~
    const size_t m = client.build_datagram(pkt, sizeof pkt, 2000);
    PacketHeader ih;
    check(m >= kMinInitialDatagram && parse_packet(pkt, m, hc, ih) == HeaderError::None &&
              ih.type == PacketType::Initial,
          "after a Retry the client did not send a full Initial");
    check(ih.dcid.len == rlen && std::memcmp(pkt + ih.dcid.off, rscid, rlen) == 0,
          "the Initial after a Retry is not aimed at the Retry's ID");
    check(ih.token.len == rh.token.len &&
              std::memcmp(pkt + ih.token.off, retry + rh.token.off, rh.token.len) == 0,
          "the Initial after a Retry does not carry its token");
    uint8_t copy[1500];
    std::memcpy(copy, pkt, m);
    PacketKeys sr, sw;
    check(make_initial_keys(cr, kVersion1, rscid, rlen, true, sr, sw), "server keys for the Retry ID");
    Unprotected u;
    const bool opened = unprotect_packet(cr, sr, copy, ih, 0, u) == Unprotect::Ok;
    check(opened, "the Initial after a Retry is not sealed with keys from the Retry's ID");
    if (opened) {
        check(u.pn == 1, "the packet number was reset by the Retry");
        FrameContext fc;
        fc.packet = PacketType::Initial;
        FrameReader fr(copy + u.payload.off, u.payload.len, fc);
        Frame f;
        bool crypto = false;
        while (fr.next(f) == FrameReader::Step::Frame)
            if (f.type == FrameType::Crypto && f.offset == 0 && f.data.len == 300) crypto = true;
        check(crypto, "the ClientHello did not go out again after the Retry");
    }
    forget_keys(cr, sr);
    forget_keys(cr, sw);

    // \~english And the acceptor takes that Initial: the round trip closes.
    // \~spanish Y el acceptor acepta ese Initial: la vuelta se cierra.  \~
    const Admission back = a.on_datagram(pkt, m, kClientAddr, sizeof kClientAddr, 3000, retry, sizeof retry);
    check(back.reason == AdmitReason::AcceptedWithToken && back.odcid_len == 8 &&
              std::memcmp(back.odcid, cc.peer_cid, 8) == 0,
          "the acceptor did not recognise its own token");

    // \~english A second Retry, even genuine, is one too many.
    // \~spanish Un segundo Retry, aunque sea de verdad, es uno de mas.  \~
    const Admission again = a.on_datagram(first, n, kClientAddr, sizeof kClientAddr, 0, retry, sizeof retry);
    client.on_datagram(retry, again.reply_len, Ecn::NotEct, 4000);
    check(client.drops().retry == 1 && std::memcmp(client.retry_source_cid(rlen), rscid, rlen) == 0,
          "a second Retry was taken");

    const uint8_t token[] = {'t', 'o', 'k'};
    const uint8_t fresh[8] = {0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92};

    // \~english An empty token, with a correct tag.
    // \~spanish Un testigo vacio, con una marca correcta.  \~
    {
        Connection c(cr, cc);
        start_client(c, cc, first);
        const size_t k = craft_retry(cr, cc.local_cid, fresh, 8, nullptr, 0, cc.peer_cid, pkt);
        c.on_datagram(pkt, k, Ecn::NotEct, 1000);
        check(!c.retried() && c.drops().retry == 1, "a Retry with an empty token was taken");
    }

    // \~english Naming the very ID it answers, with a correct tag.
    // \~spanish Con el mismo identificador al que contesta, con una marca correcta.  \~
    {
        Connection c(cr, cc);
        start_client(c, cc, first);
        const size_t k = craft_retry(cr, cc.local_cid, cc.peer_cid, 8, token, sizeof token, cc.peer_cid, pkt);
        c.on_datagram(pkt, k, Ecn::NotEct, 1000);
        check(!c.retried() && c.drops().retry == 1, "a Retry naming the ID it answers was taken");
    }

    // \~english Aimed at another client.
    // \~spanish Dirigido a otro cliente.  \~
    {
        Connection c(cr, cc);
        start_client(c, cc, first);
        uint8_t other[8];
        std::memcpy(other, cc.local_cid, 8);
        other[0] ^= 1;
        const size_t k = craft_retry(cr, other, fresh, 8, token, sizeof token, cc.peer_cid, pkt);
        c.on_datagram(pkt, k, Ecn::NotEct, 1000);
        check(!c.retried() && c.drops().wrong_cid == 1, "a Retry for another client was taken");
    }

    // \~english After the server's first packet.
    // \~spanish Despues del primer paquete del servidor.  \~
    {
        Connection c(cr, cc);
        const size_t k0 = start_client(c, cc, first);
        Acceptor plain(cr, acceptor_config(false));
        std::unique_ptr<Connection> server = admit(cr, plain, first, k0, 1000);
        check(server != nullptr, "the acceptor did not admit the client");
        if (server == nullptr) return;
        drive_handshake_server_first(cr, *server);
        const size_t s = server->build_datagram(pkt, sizeof pkt, 2000);
        c.on_datagram(pkt, s, Ecn::NotEct, 3000);
        const size_t k = craft_retry(cr, cc.local_cid, fresh, 8, token, sizeof token, cc.peer_cid, pkt);
        c.on_datagram(pkt, k, Ecn::NotEct, 4000);
        check(!c.retried() && c.drops().retry == 1, "a Retry after the server spoke was taken");
    }
}

/// \~english Once the server gave its ID, a long header with another is dropped (7.2).
/// \~spanish Una vez que el servidor dio su identificador, una cabecera larga con otro se tira (7.2).  \~
void test_changed_source(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/changed-source", cr.name());
    const ConnectionConfig cc = small_client(kVersion1);
    uint8_t first[1500], pkt[1500], copy[1500];
    Connection client(cr, cc);
    const size_t n = start_client(client, cc, first);
    Acceptor a(cr, acceptor_config(false));
    std::unique_ptr<Connection> server = admit(cr, a, first, n, 1000);
    check(server != nullptr, "the acceptor did not admit the client");
    if (server == nullptr) return;
    drive_handshake_server_first(cr, *server);
    const size_t m = server->build_datagram(pkt, sizeof pkt, 2000);
    std::memcpy(copy, pkt, m);
    client.on_datagram(pkt, m, Ecn::NotEct, 3000);

    // \~english The server's Initial: source ID after 1+4+1+8+1 bytes.
    // \~spanish El Initial del servidor: el identificador de origen tras 1+4+1+8+1 bytes.  \~
    copy[15] ^= 0x40;
    client.on_datagram(copy, m, Ecn::NotEct, 4000);
    check(client.drops().changed_source == 1 && client.drops().forged == 0,
          "a packet with another source ID was not dropped for it");
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
        {"clean", 0, 0, 20000, 0, 0, 0, false},
        {"lossy", 5, 2, 20000, 10000, 0, 0, false},
        {"hostile", 20, 5, 30000, 40000, 0, 0, false},
        {"handshake-lost", 3, 0, 20000, 5000, 2, 0, false},
        {"handshake-done-lost", 0, 0, 20000, 0, 0, 150000, false},
        {"retry-clean", 0, 0, 20000, 0, 0, 0, true},
        {"retry-lossy", 5, 2, 20000, 10000, 0, 0, true},
    };
    for (const NetShape &net : shapes)
        for (uint64_t seed = 1; seed <= 3; ++seed) run(cr, net, seed, 4, 100000);
    test_violation(cr);
    test_idle(cr);
    test_early_one_rtt(cr);
    test_version_negotiation(cr);
    test_retry_rules(cr);
    test_changed_source(cr);
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
