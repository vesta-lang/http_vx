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
#include "http_vx/quic_varint.h"

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
#include <string>
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
    /// \~english Both ends update their 1-RTT keys every this many packets (0: only near the AEAD limit).
    /// \~spanish Los dos extremos actualizan sus claves 1-RTT cada tantos paquetes (0: solo cerca del limite del AEAD).  \~
    uint64_t key_update_packets;
    /// \~english The suite the handshake settles on.  \~spanish El algoritmo en el que queda el saludo.  \~
    Aead aead;
    /// \~english Both ends renew their connection IDs mid-transfer.  \~spanish Los dos extremos renuevan sus identificadores a mitad de transferencia.  \~
    bool renew_cids;
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
void secret(uint8_t *out, uint8_t tag, size_t len) {
    for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(tag * 17 + i);
}

size_t secret_len(Aead a) {
    return hash_size(hash_of(a));
}

/// \~english Installs the secrets tagged @p read_tag / @p write_tag for a space.
/// \~spanish Instala los secretos marcados @p read_tag / @p write_tag para un espacio.  \~
bool install(Connection &c, Space s, Aead a, uint8_t read_tag, uint8_t write_tag, uint64_t now) {
    uint8_t r[kMaxSecret], w[kMaxSecret];
    const size_t len = secret_len(a);
    secret(r, read_tag, len);
    secret(w, write_tag, len);
    return c.install_secrets(s, a, r, w, len, now);
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
    Aead aead = Aead::Aes128Gcm;
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
    (void)cr;
    Connection &c = *e.c;
    if (!e.server) {
        if (e.stage == 0) {
            write_crypto(c, Space::Initial, 300);
            e.stage = 1;
        }
        if (e.stage == 1 && (e.crypto_got += read_crypto(c, Space::Initial, 100 - e.crypto_got)) == 100) {
            check(install(c, Space::Handshake, e.aead, 2, 1, now),
                  "the client could not install Handshake keys");
            e.crypto_got = 0;
            e.stage = 2;
        }
        if (e.stage == 2 && (e.crypto_got += read_crypto(c, Space::Handshake, 3000 - e.crypto_got)) == 3000) {
            write_crypto(c, Space::Handshake, 50);
            check(install(c, Space::Application, e.aead, 4, 3, now),
                  "the client could not install 1-RTT keys");
            e.stage = 3;
        }
    } else {
        if (e.stage == 0 && (e.crypto_got += read_crypto(c, Space::Initial, 300 - e.crypto_got)) == 300) {
            write_crypto(c, Space::Initial, 100);
            check(install(c, Space::Handshake, e.aead, 1, 2, now),
                  "the server could not install Handshake keys");
            // \~english A flight larger than one datagram: certificates are.
            // \~spanish Un vuelo mayor que un datagrama: los certificados lo son.  \~
            write_crypto(c, Space::Handshake, 3000);
            check(install(c, Space::Application, e.aead, 3, 4, now),
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
    cc.key_update_packets = net.key_update_packets;

    ConnectionConfig sc;
    sc.is_server = true;
    for (int i = 0; i < 8; ++i) sc.local_cid[i] = static_cast<uint8_t>(0x50 + i);
    sc.streams.peer_bidi_concurrency = 100;
    sc.streams.window_bidi_remote = 256 * 1024;
    sc.streams.peer_window_bidi_local = 256 * 1024;
    sc.peer_max_data = 1u << 20;
    sc.data_window = 1u << 20;
    sc.key_update_packets = net.key_update_packets;

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
    ce.aead = net.aead;
    se.aead = net.aead;

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
    // \~english Datagrams the client sent after closing that the network let through.
    // \~spanish Datagramas que mando el cliente despues de cerrar y que la red dejo pasar.  \~
    unsigned closes_through = 0;
    bool server_renewed = false;
    bool client_renewed = false;

    for (int step = 0; step < 400000; ++step) {
        drive_handshake(cr, ce, now);
        if (srv) drive_handshake(cr, se, now);

        // \~english Renewals mid-transfer: the server 50 ms after confirming, the client 100 ms after.
        // \~spanish Renovaciones a mitad de transferencia: el servidor 50 ms despues de confirmar, el cliente 100 ms despues.  \~
        if (net.renew_cids && confirmed_at != kNever) {
            if (!server_renewed && now >= confirmed_at + 50000) {
                srv->renew_connection_ids();
                server_renewed = true;
            }
            if (!client_renewed && now >= confirmed_at + 100000) {
                client.renew_connection_ids();
                client_renewed = true;
            }
        }

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
                if (who == 0 && closing) ++closes_through;
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

    /* \~english
     * With frequent updates, each end must have rolled its keys forward many
     * times -- starting some and answering others -- while every byte still
     * came back whole and nothing failed authentication.
     * \~spanish
     * Con actualizaciones frecuentes, cada extremo tiene que haber avanzado sus
     * claves muchas veces -- empezando unas y contestando otras -- mientras cada
     * byte volvia entero y nada fallaba la autenticacion.
     * \~ */
    /* \~english
     * Connection IDs: in every run each end hands the other one more than
     * the first and keeps what it gets.  With renewals, each end must have
     * had both old IDs retired by the other, and be sending to a new one.
     * \~spanish
     * Identificadores de conexion: en cada corrida cada extremo le da al otro uno
     * mas que el primero y guarda lo que recibe.  Con renovaciones, a cada extremo
     * el otro le tiene que haber retirado los dos viejos, y tiene que estar
     * mandando a uno nuevo.
     * \~ */
    check(client.cids().issued >= 1 && server.cids().issued >= 1 && client.cids().received >= 1 &&
              server.cids().received >= 1,
          "the ends did not hand each other connection IDs");
    if (net.renew_cids) {
        check(server_renewed && client_renewed, "the renewals did not happen");
        check(client.cids().retired_by_peer >= 2 && server.cids().retired_by_peer >= 2,
              "renewed IDs were not retired by the peer");
        check(client.peer_cid_sequence() >= 2 && server.peer_cid_sequence() >= 2,
              "an end did not move to one of the renewed IDs");
    } else {
        check(client.peer_cid_sequence() == 0 && server.peer_cid_sequence() == 0,
              "an end changed destination ID without being asked to");
    }

    if (net.key_update_packets != 0) {
        const KeyUpdateCounts &kc = client.key_updates();
        const KeyUpdateCounts &ks = server.key_updates();
        // \~english At least one each way: how many fit depends on how long the run lasts (6.5 spaces them).
        // \~spanish Al menos una en cada sentido: cuantas caben depende de lo que dure la corrida (6.5 las espacia).  \~
        check(kc.read_rolled >= 1 && ks.read_rolled >= 1, "the keys were not updated");
        check(kc.initiated + ks.initiated >= 1, "no end started key updates on its own");
        // \~english Each write roll is one read roll on the other side; the very last may go unseen at the close.
        // \~spanish Cada avance de escritura es uno de lectura al otro lado; el ultimo puede no verse al cerrar.  \~
        const uint64_t c_wrote = kc.initiated + kc.answered;
        const uint64_t s_wrote = ks.initiated + ks.answered;
        check(c_wrote >= ks.read_rolled && c_wrote <= ks.read_rolled + 1 &&
                  s_wrote >= kc.read_rolled && s_wrote <= kc.read_rolled + 1,
              "the updates one end made are not the ones the other saw");
    } else {
        check(client.key_updates().read_rolled == 0 && server.key_updates().read_rolled == 0,
              "keys were updated without being asked to");
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

    /* \~english
     * A CONNECTION_CLOSE is not delivered reliably (10.2): a closing end
     * repeats it only in answer to what arrives, and one that never arrives
     * leaves the peer to its idle timeout.  So the test does not ask for
     * luck: if any datagram after the close got through, the server MUST have
     * seen it; if the network took them all, it must have timed out, silently.
     * \~spanish
     * Un CONNECTION_CLOSE no se entrega de forma fiable (10.2): un extremo que
     * cierra lo repite solo en respuesta a lo que llega, y uno que no llega nunca
     * deja al otro a su plazo de inactividad.  Asi que la prueba no pide suerte:
     * si paso algun datagrama despues del cierre, el servidor TIENE que haberlo
     * visto; si la red se los llevo todos, tiene que haber caducado, en silencio.
     * \~ */
    if (closes_through == 0) {
        check(!server.closed_by_peer() && server.close_code() == 0,
              "a server that got no close ended as if it had");
    } else if (!(server.closed_by_peer() && server.close_code() == 0 && server.close_is_application())) {
        std::fprintf(stderr,
                     "FAIL [%s]: the server did not see the client's application close with code 0 "
                     "(client: code 0x%llx by %s; server: code 0x%llx by %s; key update refusals: "
                     "old-after-new %llu+%llu, updated-twice %llu+%llu; reset %d+%d; wrong ID %llu+%llu; "
                     "forged %llu+%llu; closes sent by the client %llu)\n",
                     current, static_cast<unsigned long long>(client.close_code()),
                     client.closed_by_peer() ? "peer" : "itself",
                     static_cast<unsigned long long>(server.close_code()),
                     server.closed_by_peer() ? "peer" : "itself",
                     static_cast<unsigned long long>(client.key_updates().old_after_new),
                     static_cast<unsigned long long>(server.key_updates().old_after_new),
                     static_cast<unsigned long long>(client.key_updates().updated_twice),
                     static_cast<unsigned long long>(server.key_updates().updated_twice),
                     static_cast<int>(client.closed_by_reset()), static_cast<int>(server.closed_by_reset()),
                     static_cast<unsigned long long>(client.drops().wrong_cid),
                     static_cast<unsigned long long>(server.drops().wrong_cid),
                     static_cast<unsigned long long>(client.drops().forged),
                     static_cast<unsigned long long>(server.drops().forged),
                     static_cast<unsigned long long>(client.sent().connection_close));
        ++failures;
    }
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
                    "%llu kept for keys, cwnd %llu/%llu, persistent %llu+%llu, "
                    "key updates %llu+%llu (%llu late opened with old keys), "
                    "IDs issued %llu+%llu retired %llu+%llu, destination seq %llu/%llu\n",
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
                    static_cast<unsigned long long>(server.recovery().persistent_congestion_events()),
                    static_cast<unsigned long long>(client.key_updates().initiated),
                    static_cast<unsigned long long>(server.key_updates().initiated),
                    static_cast<unsigned long long>(client.key_updates().opened_with_old +
                                                    server.key_updates().opened_with_old),
                    static_cast<unsigned long long>(client.cids().issued),
                    static_cast<unsigned long long>(server.cids().issued),
                    static_cast<unsigned long long>(client.cids().retired_by_peer),
                    static_cast<unsigned long long>(server.cids().retired_by_peer),
                    static_cast<unsigned long long>(client.peer_cid_sequence()),
                    static_cast<unsigned long long>(server.peer_cid_sequence()));
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
    check(install(client, Space::Application, Aead::Aes128Gcm, 4, 3, 0) &&
              install(server, Space::Application, Aead::Aes128Gcm, 3, 4, 0),
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

/**
 * @brief
 * \~english An Initial sealed by hand: PING and PADDING up to @p total bytes.
 * \~spanish Un Initial sellado a mano: PING y PADDING hasta @p total bytes.
 * \~
 *
 * \~english Keys from @p key_dcid, as the one who sends it (@p from_server) would derive them.
 * \~spanish Claves de @p key_dcid, como las derivaria quien lo manda (@p from_server).  \~
 */
size_t craft_initial(Crypto &cr, bool from_server, const uint8_t *key_dcid, const uint8_t *dcid,
                     const uint8_t *scid, const uint8_t *token, size_t token_len, uint64_t pn,
                     size_t total, uint8_t *out) {
    PacketKeys rk, wk;
    check(make_initial_keys(cr, kVersion1, key_dcid, 8, from_server, rk, wk), "Initial keys");
    size_t p = 0;
    out[p++] = 0xc0;
    p += put_u32(out + p, kVersion1);
    out[p++] = 8;
    std::memcpy(out + p, dcid, 8);
    p += 8;
    out[p++] = 8;
    std::memcpy(out + p, scid, 8);
    p += 8;
    p += encode_varint(out + p, 8, token_len);
    if (token_len) std::memcpy(out + p, token, token_len);
    p += token_len;
    const size_t length_at = p;
    p += 2;
    const size_t pn_offset = p;
    const size_t body = total - pn_offset - 1 - kTagSize;
    std::memset(out + pn_offset + 1, 0, body);
    out[pn_offset + 1] = 0x01;  // \~english PING  \~spanish PING  \~
    encode_varint_width(out + length_at, 2, 1 + body + kTagSize);
    check(protect_packet(cr, wk, out, pn_offset, 1, pn, body) == Protect::Ok, "an Initial could not be sealed");
    forget_keys(cr, rk);
    forget_keys(cr, wk);
    return total;
}

/**
 * @brief
 * \~english What the RFC says of Initials around Version Negotiation and Retry, checked against its text.
 * \~spanish Lo que dice el RFC de los Initial en torno a Version Negotiation y Retry, contrastado con su texto.
 * \~
 */
void test_initial_rules(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/initial-rules", cr.name());
    const ConnectionConfig cc = small_client(kVersion1);
    uint8_t first[1500], pkt[1500];
    const uint8_t server_cid[8] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57};

    Connection client(cr, cc);
    const size_t n = start_client(client, cc, first);
    Acceptor a(cr, acceptor_config(false));
    std::unique_ptr<Connection> server = admit(cr, a, first, n, 1000);
    check(server != nullptr, "the acceptor did not admit the client");
    if (server == nullptr) return;

    // \~english 14.1: a server MUST discard an Initial in a datagram under 1200 bytes -- only then.
    // \~spanish 14.1: un servidor DEBE descartar un Initial en un datagrama de menos de 1200 bytes -- solo entonces.  \~
    size_t m = craft_initial(cr, false, cc.peer_cid, server_cid, cc.local_cid, nullptr, 0, 5, 1199, pkt);
    server->on_datagram(pkt, m, Ecn::NotEct, 2000);
    check(server->drops().small_initial == 1, "an Initial in a 1199-byte datagram was not dropped");
    m = craft_initial(cr, false, cc.peer_cid, server_cid, cc.local_cid, nullptr, 0, 6, 1200, pkt);
    server->on_datagram(pkt, m, Ecn::NotEct, 2000);
    check(server->drops().small_initial == 1 && server->drops().forged == 0 &&
              server->state() == ConnState::Active,
          "an Initial in a 1200-byte datagram was not taken");

    // \~english 7.2: later Initials with another source ID MUST be discarded by the server too.
    // \~spanish 7.2: los Initial posteriores con otro identificador de origen DEBE descartarlos tambien el servidor.  \~
    uint8_t other[8];
    std::memcpy(other, cc.local_cid, 8);
    other[2] ^= 0x10;
    m = craft_initial(cr, false, cc.peer_cid, server_cid, other, nullptr, 0, 7, 1200, pkt);
    server->on_datagram(pkt, m, Ecn::NotEct, 2000);
    check(server->drops().changed_source == 1, "a server took an Initial from another source ID");

    // \~english 17.2.2: a server's Initial carries no token; a client MUST discard one that does.
    // \~spanish 17.2.2: el Initial de un servidor no lleva testigo; un cliente DEBE descartar uno que lo lleve.  \~
    drive_handshake_server_first(cr, *server);
    uint8_t reply[1500];
    const size_t r = server->build_datagram(reply, sizeof reply, 3000);
    uint8_t copy[1500];
    std::memcpy(copy, reply, r);
    client.on_datagram(reply, r, Ecn::NotEct, 4000);
    const uint8_t token[] = {'t'};
    m = craft_initial(cr, true, cc.peer_cid, cc.local_cid, server_cid, token, 1, 40, 1200, pkt);
    client.on_datagram(pkt, m, Ecn::NotEct, 5000);
    check(client.drops().initial_with_token == 1, "a client took a server Initial carrying a token");

    // \~english 5.2.1: a client MUST discard a packet of another version than it selected.
    // \~spanish 5.2.1: un cliente DEBE descartar un paquete de otra version que la que eligio.  \~
    put_u32(copy + 1, kVersion2);
    client.on_datagram(copy, r, Ecn::NotEct, 5000);
    check(client.drops().wrong_version >= 1, "a client took a packet of another version");

    // \~english 8.1 / 14.1: a client's datagram with an Initial is 1200 bytes, even when it only closes.
    // \~spanish 8.1 / 14.1: un datagrama de cliente con un Initial mide 1200 bytes, aunque solo cierre.  \~
    Connection early(cr, cc);
    start_client(early, cc, first);
    early.close(0x0100, true, 0, 1000);
    m = early.build_datagram(pkt, sizeof pkt, 1000);
    check(m >= kMinInitialDatagram, "a client's closing Initial was not padded to 1200 bytes");
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

/* \~english
 * Key updates, rule by rule (RFC 9001, 6).  Two connections with 1-RTT keys
 * installed directly talk without a network in between; packets that break
 * one rule are made by hand with the keys of the generation that breaks it.
 * \~spanish
 * Actualizaciones de claves, regla a regla (RFC 9001, 6).  Dos conexiones con las
 * claves 1-RTT instaladas directamente hablan sin red de por medio; los paquetes
 * que rompen una regla se hacen a mano con las claves de la generacion que la
 * rompe.
 * \~ */

/// \~english Two confirmed ends with 1-RTT keys; the client writes with tag 3, the server with 4.
/// \~spanish Dos extremos confirmados con claves 1-RTT; el cliente escribe con la marca 3, el servidor con la 4.  \~
struct KeyPair {
    KeyPair(Crypto &cr, Aead a, const ConnectionConfig &cc, const ConnectionConfig &sc)
        : client(cr, cc), server(cr, sc) {
        check(install(client, Space::Application, a, 4, 3, 0) &&
                  install(server, Space::Application, a, 3, 4, 0),
              "the 1-RTT keys could not be installed");
        client.handshake_confirmed(0);
        server.handshake_confirmed(0);
    }
    Connection client;
    Connection server;
    uint64_t now = 1000;
};

ConnectionConfig key_client() {
    ConnectionConfig cc = small_client(kVersion1);
    for (int i = 0; i < 8; ++i) cc.peer_cid[i] = static_cast<uint8_t>(0x50 + i);
    cc.streams.peer_max_streams_bidi = 4;
    cc.streams.peer_window_bidi_remote = 1 << 20;
    cc.peer_max_data = 1 << 20;
    return cc;
}

/// \~english Both ends send all they have, each way, @p rounds times, @p step apart.
/// \~spanish Los dos extremos mandan todo lo que tienen, en los dos sentidos, @p rounds veces, a @p step de distancia.  \~
void pump(KeyPair &k, int rounds, uint64_t step = 5000) {
    uint8_t buf[1500];
    for (int r = 0; r < rounds; ++r) {
        size_t n;
        while ((n = k.client.build_datagram(buf, sizeof buf, k.now)) != 0)
            k.server.on_datagram(buf, n, Ecn::NotEct, k.now);
        while ((n = k.server.build_datagram(buf, sizeof buf, k.now)) != 0)
            k.client.on_datagram(buf, n, Ecn::NotEct, k.now);
        k.now += step;
        if (k.client.timer() <= k.now) k.client.on_timer(k.now);
        if (k.server.timer() <= k.now) k.server.on_timer(k.now);
    }
}

/// \~english Writes @p text on the client's stream 0, opening it the first time.
/// \~spanish Escribe @p text en el flujo 0 del cliente, abriendolo la primera vez.  \~
void say(KeyPair &k, const char *text) {
    Stream *st = k.client.streams().find(0);
    if (st == nullptr) st = k.client.streams().open(true);
    check(st != nullptr, "the client could not open its stream");
    if (st == nullptr) return;
    size_t took = 0;
    st->send->write(reinterpret_cast<const uint8_t *>(text), std::strlen(text), took);
}

/// \~english Everything the server has received on stream 0, read out.
/// \~spanish Todo lo que ha recibido el servidor en el flujo 0, leido.  \~
std::string heard(KeyPair &k) {
    std::string out;
    Stream *st = k.server.streams().find(0);
    if (st == nullptr || st->recv == nullptr) return out;
    const uint8_t *p = nullptr;
    size_t n;
    while ((n = st->recv->peek(p)) != 0) {
        out.append(reinterpret_cast<const char *>(p), n);
        k.server.consume(*st, n);
    }
    return out;
}

/**
 * @brief
 * \~english A 1-RTT PING sealed by hand with the client's keys of generation @p gen.
 * \~spanish Un PING 1-RTT sellado a mano con las claves del cliente de la generacion @p gen.
 * \~
 *
 * \~english
 * Header protection comes from generation 0 whatever @p gen is, as RFC 9001, 6
 * says; @p tag other than 3 gives keys the server never had.
 * \~spanish
 * La proteccion de cabecera sale de la generacion 0 sea cual sea @p gen, como
 * dice el RFC 9001, 6; una @p tag distinta de 3 da claves que el servidor nunca
 * tuvo.
 * \~
 */
size_t craft_one_rtt(Crypto &cr, Aead a, uint8_t tag, int gen, bool phase, uint64_t pn, uint8_t *out,
                     bool to_client = false, const uint8_t *frames = nullptr, size_t frames_len = 0,
                     size_t dcid_len = 8) {
    const size_t len = secret_len(a);
    uint8_t s0[kMaxSecret], s[kMaxSecret];
    secret(s0, tag, len);
    std::memcpy(s, s0, len);
    for (int g = 0; g < gen; ++g) {
        uint8_t n[kMaxSecret];
        check(next_secret(cr, kVersion1, a, s, len, n), "next_secret failed");
        std::memcpy(s, n, len);
    }
    KeyMaterial m0, mg;
    check(derive_key_material(cr, kVersion1, a, s0, len, m0) &&
              derive_key_material(cr, kVersion1, a, s, len, mg),
          "key material could not be derived");
    std::memcpy(mg.hp, m0.hp, sizeof mg.hp);
    PacketKeys k;
    check(prepare_keys(cr, mg, k), "keys could not be prepared");

    size_t p = 0;
    out[p++] = static_cast<uint8_t>(0x40 | (phase ? 0x04 : 0x00));
    for (size_t i = 0; i < dcid_len; ++i) out[p++] = static_cast<uint8_t>((to_client ? 0xc0 : 0x50) + i);
    const size_t pn_offset = p;
    // \~english The frames given, or a PING; then PADDING up to 31 bytes, enough to sample.
    // \~spanish Las tramas dadas, o un PING; despues PADDING hasta 31 bytes, lo bastante para muestrear.  \~
    size_t body = frames_len > 31 ? frames_len : 31;
    std::memset(out + pn_offset + 4, 0, body);
    if (frames != nullptr) {
        std::memcpy(out + pn_offset + 4, frames, frames_len);
    } else {
        out[pn_offset + 4] = 0x01;  // \~english PING  \~spanish PING  \~
    }
    check(protect_packet(cr, k, out, pn_offset, 4, pn, body) == Protect::Ok, "a packet could not be sealed");
    forget_keys(cr, k);
    return pn_offset + 4 + body + kTagSize;
}

/// \~english Checks an update answer, naming the one that came when it is not the one expected.
/// \~spanish Comprueba una respuesta a una actualizacion, nombrando la que llego cuando no es la esperada.  \~
void expect_update(KeyUpdate got, KeyUpdate want, const char *what) {
    if (got == want) return;
    std::fprintf(stderr, "FAIL [%s]: %s (got %s, wanted %s)\n", current, what, key_update_name(got),
                 key_update_name(want));
    ++failures;
}

void test_key_update_rules(Crypto &cr, Aead a) {
    std::snprintf(current, sizeof current, "%s/key-update/%s", cr.name(),
                  a == Aead::Aes128Gcm ? "aes128" : a == Aead::Aes256Gcm ? "aes256" : "chacha20");
    const ConnectionConfig cc = key_client();
    // \~english No long header ever crosses here, so the server is told the client's ID.
    // \~spanish Aqui no cruza nunca una cabecera larga, asi que al servidor se le dice el identificador del cliente.  \~
    ConnectionConfig sc = small_server();
    std::memcpy(sc.peer_cid, cc.local_cid, 8);
    uint8_t pkt[1500];

    // \~english Not without keys, not before the handshake is confirmed (6.1).
    // \~spanish Ni sin claves, ni antes de confirmar el saludo (6.1).  \~
    {
        Connection bare(cr, cc);
        check(bare.update_keys(0) == KeyUpdate::NoKeys, "an update without 1-RTT keys was not refused");
        check(install(bare, Space::Application, a, 4, 3, 0), "1-RTT keys could not be installed");
        check(bare.update_keys(0) == KeyUpdate::NotConfirmed, "an update before confirmation was not refused");
    }

    KeyPair k(cr, a, cc, sc);
    expect_update(k.client.update_keys(k.now), KeyUpdate::Unacknowledged,
                  "an update before any packet was acknowledged was not refused");

    // \~english One packet acknowledged -- after the ACK delay (13.2) --: the update starts, and is answered.
    // \~spanish Un paquete confirmado -- tras el retraso del ACK (13.2) --: la actualizacion empieza, y se contesta.  \~
    say(k, "one ");
    pump(k, 10);
    expect_update(k.client.update_keys(k.now), KeyUpdate::Started, "an update the rules allow did not start");
    check(k.client.key_phase(), "the client did not move to phase 1");
    say(k, "two ");
    pump(k, 10);
    check(k.server.key_updates().answered == 1 && k.server.key_phase() &&
              k.client.key_updates().read_rolled == 1,
          "the server did not answer the update");

    // \~english The old keys are kept for late packets: no new update until they go (6.5).
    // \~spanish Las claves viejas se guardan para paquetes tardios: ninguna actualizacion hasta que se vayan (6.5).  \~
    expect_update(k.client.update_keys(k.now), KeyUpdate::OldKeysKept,
                  "an update while the old keys are kept was not refused");
    pump(k, 20, 200000);
    check(k.client.key_updates().old_discarded == 1 && k.server.key_updates().old_discarded == 1,
          "the old keys were not thrown away after their time");

    // \~english A packet sealed now under phase 1, delivered only after the next update.
    // \~spanish Un paquete sellado ahora con la fase 1, entregado solo despues de la actualizacion siguiente.  \~
    say(k, "late ");
    uint8_t late[1500];
    const size_t late_n = k.client.build_datagram(late, sizeof late, k.now);
    check(late_n != 0, "the late packet was not built");
    expect_update(k.client.update_keys(k.now), KeyUpdate::Started, "the second update did not start");
    check(!k.client.key_phase(), "the client did not move back to phase 0");
    say(k, "three ");
    pump(k, 1);
    k.server.on_datagram(late, late_n, Ecn::NotEct, k.now);
    check(k.server.key_updates().opened_with_old == 1, "a late packet was not opened with the old keys");
    pump(k, 5);
    const std::string got = heard(k);
    check(got == "one two late three ", "the stream did not arrive whole across two updates");

    // \~english A forged packet in the other phase moves nothing.
    // \~spanish Un paquete falsificado en la otra fase no mueve nada.  \~
    {
        const uint64_t forged = k.server.drops().forged;
        const bool phase = k.server.key_phase();
        const size_t n = craft_one_rtt(cr, a, 99, 0, !phase, 100000, pkt);
        k.server.on_datagram(pkt, n, Ecn::NotEct, k.now);
        check(k.server.drops().forged == forged + 1 && k.server.key_phase() == phase &&
                  k.server.state() == ConnState::Active,
              "a forged packet in the other phase was not just dropped");
    }

    // \~english Old keys on a packet numbered after the new ones: KEY_UPDATE_ERROR (6.4).
    // \~spanish Claves viejas en un paquete numerado despues de los de las nuevas: KEY_UPDATE_ERROR (6.4).  \~
    {
        KeyPair v(cr, a, cc, sc);
        const size_t n1 = craft_one_rtt(cr, a, 3, 1, true, 10, pkt);
        v.server.on_datagram(pkt, n1, Ecn::NotEct, v.now);
        check(v.server.key_updates().read_rolled == 1, "a well made update was not taken");
        const size_t n0 = craft_one_rtt(cr, a, 3, 0, false, 11, pkt);
        v.server.on_datagram(pkt, n0, Ecn::NotEct, v.now);
        check(v.server.state() == ConnState::Closing &&
                  v.server.close_code() == static_cast<uint64_t>(TransportError::KeyUpdateError) &&
                  v.server.key_updates().old_after_new == 1,
              "old keys after new ones did not close with KEY_UPDATE_ERROR");
    }
    // \~english ...while the same old packet numbered BEFORE the new ones is just late.
    // \~spanish ...mientras que el mismo paquete viejo numerado ANTES de los nuevos solo llega tarde.  \~
    {
        KeyPair v(cr, a, cc, sc);
        const size_t n1 = craft_one_rtt(cr, a, 3, 1, true, 10, pkt);
        v.server.on_datagram(pkt, n1, Ecn::NotEct, v.now);
        const size_t n0 = craft_one_rtt(cr, a, 3, 0, false, 9, pkt);
        v.server.on_datagram(pkt, n0, Ecn::NotEct, v.now);
        check(v.server.state() == ConnState::Active && v.server.key_updates().opened_with_old == 1,
              "an old packet numbered before the update was refused");
    }

    // \~english A new packet arriving late lowers the line: an old one above it is still a violation (6.4).
    // \~spanish Un paquete nuevo que llega tarde baja la linea: uno viejo por encima sigue siendo una violacion (6.4).  \~
    {
        KeyPair v(cr, a, cc, sc);
        size_t n = craft_one_rtt(cr, a, 3, 1, true, 20, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        n = craft_one_rtt(cr, a, 3, 1, true, 15, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        n = craft_one_rtt(cr, a, 3, 0, false, 17, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        check(v.server.state() == ConnState::Closing && v.server.key_updates().old_after_new == 1,
              "old keys above a late new packet were taken as late");
    }

    // \~english Answered but not acknowledged: the next update waits for an ACK of the new phase (6.5).
    // \~spanish Contestada pero sin confirmar: la siguiente actualizacion espera un ACK de la fase nueva (6.5).  \~
    {
        KeyPair v(cr, a, cc, sc);
        say(v, "go ");
        pump(v, 10);
        expect_update(v.client.update_keys(v.now), KeyUpdate::Started, "the first update did not start");
        say(v, "lost ");
        uint8_t out[1500];
        check(v.client.build_datagram(out, sizeof out, v.now) != 0, "no packet under the new keys");
        // \~english The server's answer, carrying no ACK at all.
        // \~spanish La respuesta del servidor, sin ningun ACK.  \~
        const size_t n = craft_one_rtt(cr, a, 4, 1, true, 1000, pkt, true);
        v.client.on_datagram(pkt, n, Ecn::NotEct, v.now);
        check(v.client.key_updates().read_rolled == 1, "the crafted answer was not taken");
        v.client.on_timer(v.now + 5000000);
        check(v.client.key_updates().old_discarded == 1, "the old keys were not dropped");
        expect_update(v.client.update_keys(v.now + 5000000), KeyUpdate::Unacknowledged,
                      "an update with nothing of the current phase acknowledged was not refused");
    }

    // \~english A low confidentiality limit is per KEY: with updates possible, the connection goes on.
    // \~spanish Un limite de confidencialidad bajo es por CLAVE: con actualizaciones posibles, la conexion sigue.  \~
    {
        ConnectionConfig tc = cc;
        ConnectionConfig ts = sc;
        tc.confidentiality_limit = 10;
        ts.confidentiality_limit = 10;
        KeyPair v(cr, a, tc, ts);
        std::string want;
        for (int i = 0; i < 40; ++i) {
            say(v, "x");
            want += "x";
            pump(v, 1, 200000);
        }
        pump(v, 5);
        check(v.client.state() == ConnState::Active && v.server.state() == ConnState::Active,
              "a connection able to update stopped at a per-key limit");
        check(v.client.key_updates().initiated >= 2, "the per-key limit did not drive updates");
        check(heard(v) == want, "the stream did not arrive whole under a low limit");
    }

    // \~english Two updates in a row, the first never acknowledged: KEY_UPDATE_ERROR (6.2).
    // \~spanish Dos actualizaciones seguidas, la primera sin confirmar: KEY_UPDATE_ERROR (6.2).  \~
    {
        KeyPair v(cr, a, cc, sc);
        size_t n = craft_one_rtt(cr, a, 3, 1, true, 10, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        n = craft_one_rtt(cr, a, 3, 2, false, 11, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        check(v.server.state() == ConnState::Closing &&
                  v.server.close_code() == static_cast<uint64_t>(TransportError::KeyUpdateError) &&
                  v.server.key_updates().updated_twice == 1,
              "a second update without waiting did not close with KEY_UPDATE_ERROR");
    }
    // \~english ...while once the server has acknowledged the first, the second is fine.
    // \~spanish ...mientras que una vez que el servidor confirmo la primera, la segunda vale.  \~
    {
        KeyPair v(cr, a, cc, sc);
        size_t n = craft_one_rtt(cr, a, 3, 1, true, 10, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        uint8_t out[1500];
        check(v.server.build_datagram(out, sizeof out, v.now + 30000) != 0,
              "the server did not acknowledge the update");
        n = craft_one_rtt(cr, a, 3, 2, false, 11, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now + 40000);
        check(v.server.state() == ConnState::Active && v.server.key_updates().read_rolled == 2 &&
                  v.server.key_updates().answered == 2,
              "a second update after the first was acknowledged was refused");
    }

    // \~english Past the integrity limit the connection closes with AEAD_LIMIT_REACHED (6.6).
    // \~spanish Pasado el limite de integridad la conexion se cierra con AEAD_LIMIT_REACHED (6.6).  \~
    {
        ConnectionConfig tight = sc;
        tight.integrity_limit = 3;
        KeyPair v(cr, a, cc, tight);
        for (uint64_t i = 0; i < 4; ++i) {
            const size_t n = craft_one_rtt(cr, a, 99, 0, false, 20 + i, pkt);
            v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
            check(v.server.state() == (i < 3 ? ConnState::Active : ConnState::Closing),
                  "the integrity limit was not applied at exactly its value");
        }
        check(v.server.close_code() == static_cast<uint64_t>(TransportError::AeadLimitReached),
              "the integrity limit did not close with AEAD_LIMIT_REACHED");
    }

    // \~english At the confidentiality limit with no update possible, the connection stops (6.6).
    // \~spanish En el limite de confidencialidad sin actualizacion posible, la conexion se para (6.6).  \~
    {
        ConnectionConfig tight = cc;
        tight.confidentiality_limit = 6;
        KeyPair v(cr, a, tight, sc);
        std::string big(20000, 'x');
        say(v, big.c_str());
        uint8_t out[1500];
        int sent = 0;
        while (v.client.build_datagram(out, sizeof out, v.now) != 0) ++sent;
        check(sent == 6 && v.client.state() == ConnState::Closed &&
                  v.client.close_code() == static_cast<uint64_t>(TransportError::AeadLimitReached),
              "the confidentiality limit did not stop the connection at exactly its value");
        // \~english The last packet the key allowed carried the reason (6.6: close before, RECOMMENDED).
        // \~spanish El ultimo paquete que permitia la clave llevo el motivo (6.6: cerrar antes, RECOMENDADO).  \~
        check(v.client.sent().connection_close == 1,
              "the last packet under the key did not carry AEAD_LIMIT_REACHED");
    }

    // \~english Three PTO after the ACK that confirmed the previous update, not before (6.5).
    // \~spanish Tres PTO despues del ACK que confirmo la actualizacion anterior, no antes (6.5).  \~
    {
        KeyPair v(cr, a, cc, sc);
        // \~english The client starts an update; the server answers it...
        // \~spanish El cliente empieza una actualizacion; el servidor la contesta...  \~
        size_t n = craft_one_rtt(cr, a, 3, 1, true, 10, pkt);
        v.server.on_datagram(pkt, n, Ecn::NotEct, v.now);
        check(v.server.key_updates().answered == 1, "the server did not answer the update");
        expect_update(v.server.update_keys(v.now), KeyUpdate::Unacknowledged,
                      "an update before the answer was acknowledged was not refused");
        uint8_t out[1500];
        check(v.server.build_datagram(out, sizeof out, v.now) != 0, "the server sent no answer");
        // \~english ...its old keys go, and only then does the ACK of its answer come.
        // \~spanish ...sus claves viejas se van, y solo entonces llega el ACK de su respuesta.  \~
        const uint64_t late = v.now + 20000000;
        v.server.on_timer(late);
        check(v.server.key_updates().old_discarded == 1, "the old keys were not dropped");
        const uint8_t ack[] = {0x02, 0x00, 0x00, 0x00, 0x00};  // \~english ACK of packet 0  \~spanish ACK del paquete 0  \~
        n = craft_one_rtt(cr, a, 3, 1, true, 11, pkt, false, ack, sizeof ack);
        v.server.on_datagram(pkt, n, Ecn::NotEct, late);
        expect_update(v.server.update_keys(late), KeyUpdate::TooSoon,
                      "an update right after the confirming ACK was not refused");
        expect_update(v.server.update_keys(late + 600000000), KeyUpdate::Started,
                      "an update long after the confirming ACK was refused");
    }
}

/* \~english
 * Connection IDs and stateless reset, rule by rule (RFC 9000, 5.1, 10.3, 19.15,
 * 19.16).  Frames are sealed by hand into 1-RTT packets from the client.
 * \~spanish
 * Identificadores de conexion y reinicio sin estado, regla a regla (RFC 9000,
 * 5.1, 10.3, 19.15, 19.16).  Las tramas se sellan a mano en paquetes 1-RTT del
 * cliente.
 * \~ */

/// \~english A NEW_CONNECTION_ID for the server; the ID is eight bytes of @p fill.
/// \~spanish Un NEW_CONNECTION_ID para el servidor; el identificador son ocho bytes de @p fill.  \~
size_t new_cid_frame(uint8_t *out, uint64_t seq, uint64_t rpt, uint8_t fill) {
    uint8_t cid[8], token[kResetTokenSize];
    std::memset(cid, fill, sizeof cid);
    std::memset(token, fill ^ 0x5a, sizeof token);
    return write_new_connection_id(out, 64, seq, rpt, cid, sizeof cid, token);
}

/// \~english Delivers @p frames to the server in a client 1-RTT packet numbered @p pn.
/// \~spanish Entrega @p frames al servidor en un paquete 1-RTT del cliente numerado @p pn.  \~
void to_server(Crypto &cr, KeyPair &k, uint64_t pn, const uint8_t *frames, size_t n) {
    uint8_t pkt[1500];
    const size_t len = craft_one_rtt(cr, Aead::Aes128Gcm, 3, 0, false, pn, pkt, false, frames, n);
    k.server.on_datagram(pkt, len, Ecn::NotEct, k.now);
}

/// \~english Checks the server is still active; when not, says how it ended.
/// \~spanish Comprueba que el servidor sigue activo; si no, dice como acabo.  \~
void check_server_active(KeyPair &k, const char *what) {
    if (k.server.state() == ConnState::Active) return;
    std::fprintf(stderr, "FAIL [%s]: %s (server state %d, code 0x%llx, frame 0x%llx)\n", current, what,
                 static_cast<int>(k.server.state()), static_cast<unsigned long long>(k.server.close_code()),
                 static_cast<unsigned long long>(k.server.close_frame()));
    ++failures;
}

/// \~english Whether the server closed with @p e.  \~spanish Si el servidor cerro con @p e.  \~
bool server_closed_with(KeyPair &k, TransportError e) {
    return k.server.state() == ConnState::Closing && !k.server.closed_by_peer() &&
           k.server.close_code() == static_cast<uint64_t>(e);
}

void test_cid_rules(Crypto &cr) {
    std::snprintf(current, sizeof current, "%s/connection-ids", cr.name());
    const ConnectionConfig cc = key_client();
    ConnectionConfig sc = small_server();
    std::memcpy(sc.peer_cid, cc.local_cid, 8);
    uint8_t f[256];
    size_t n;

    // \~english Kept once, and the very same frame again is harmless (a retransmission).
    // \~spanish Se guarda una vez, y la misma trama otra vez es inofensiva (una retransmision).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        n = new_cid_frame(f, 1, 0, 0x11);
        to_server(cr, k, 1, f, n);
        to_server(cr, k, 2, f, n);
        check(k.server.state() == ConnState::Active && k.server.cids().received == 1,
              "a NEW_CONNECTION_ID was not kept exactly once");
    }
    // \~english The same number with another ID, or the same ID with another number: PROTOCOL_VIOLATION.
    // \~spanish El mismo numero con otro identificador, o el mismo identificador con otro numero: PROTOCOL_VIOLATION.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        n = new_cid_frame(f, 1, 0, 0x11);
        to_server(cr, k, 1, f, n);
        n = new_cid_frame(f, 1, 0, 0x22);
        to_server(cr, k, 2, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "one sequence number with two IDs was not a PROTOCOL_VIOLATION");
    }
    {
        // \~english The same ID, with a different token, so that only this rule can catch it.
        // \~spanish El mismo identificador, con otro testigo, para que solo esta regla pueda cazarlo.  \~
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        uint8_t cid[8], t1[kResetTokenSize], t2[kResetTokenSize];
        std::memset(cid, 0x11, sizeof cid);
        std::memset(t1, 0x01, sizeof t1);
        std::memset(t2, 0x02, sizeof t2);
        n = write_new_connection_id(f, sizeof f, 1, 0, cid, 8, t1);
        to_server(cr, k, 1, f, n);
        n = write_new_connection_id(f, sizeof f, 2, 0, cid, 8, t2);
        to_server(cr, k, 2, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "one ID under two sequence numbers was not a PROTOCOL_VIOLATION");
    }
    // \~english More than active_connection_id_limit (4): CONNECTION_ID_LIMIT_ERROR.
    // \~spanish Mas que active_connection_id_limit (4): CONNECTION_ID_LIMIT_ERROR.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        for (uint64_t s = 1; s <= 3; ++s) {
            n = new_cid_frame(f, s, 0, static_cast<uint8_t>(0x10 + s));
            to_server(cr, k, s, f, n);
        }
        check(k.server.state() == ConnState::Active, "IDs up to the limit were refused");
        n = new_cid_frame(f, 4, 0, 0x14);
        to_server(cr, k, 4, f, n);
        check(server_closed_with(k, TransportError::ConnectionIdLimitError),
              "an ID over the limit was not a CONNECTION_ID_LIMIT_ERROR");
    }
    // \~english ...unless its Retire Prior To makes the room: retired first, the limit checked after.
    // \~spanish ...salvo que su Retire Prior To haga el sitio: primero se retira, despues se mira el limite.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        for (uint64_t s = 1; s <= 3; ++s) {
            n = new_cid_frame(f, s, 0, static_cast<uint8_t>(0x10 + s));
            to_server(cr, k, s, f, n);
        }
        n = new_cid_frame(f, 4, 2, 0x14);
        to_server(cr, k, 4, f, n);
        check(k.server.state() == ConnState::Active && k.server.cids().retired == 2,
              "a Retire Prior To did not make room before the limit");
        check(k.server.peer_cid_sequence() == 2, "retiring the ID in use did not move to the lowest left");
        uint8_t out[1500];
        while (k.server.build_datagram(out, sizeof out, k.now) != 0) {
        }
        check(k.server.sent().retire_connection_id == 2, "the two retirements owed were not sent");
        // \~english A number under Retire Prior To arriving late is retired at once, never kept.
        // \~spanish Un numero por debajo de Retire Prior To que llega tarde se retira en el acto, no se guarda.  \~
        n = new_cid_frame(f, 1, 0, 0x31);
        const uint64_t received = k.server.cids().received;
        to_server(cr, k, 5, f, n);
        check(k.server.cids().received == received, "an ID under Retire Prior To was kept");
        while (k.server.build_datagram(out, sizeof out, k.now) != 0) {
        }
        check(k.server.sent().retire_connection_id == 3, "a late ID under Retire Prior To was not retired");
    }
    // \~english A peer with a zero-length ID cannot be given new ones (19.15).
    // \~spanish A un otro extremo con identificador de longitud cero no se le pueden dar nuevos (19.15).  \~
    {
        ConnectionConfig zero = sc;
        zero.peer_cid_len = 0;
        KeyPair k(cr, Aead::Aes128Gcm, cc, zero);
        n = new_cid_frame(f, 1, 0, 0x11);
        to_server(cr, k, 1, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "NEW_CONNECTION_ID to a zero-length peer was not a PROTOCOL_VIOLATION");
    }

    // \~english RETIRE_CONNECTION_ID: a number never issued, or the ID the packet came to, is a violation.
    // \~spanish RETIRE_CONNECTION_ID: un numero nunca emitido, o el identificador al que llego el paquete, es una violacion.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        n = write_retire_connection_id(f, sizeof f, 5);
        to_server(cr, k, 1, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "retiring a number never issued was not a PROTOCOL_VIOLATION");
    }
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        n = write_retire_connection_id(f, sizeof f, 0);
        to_server(cr, k, 1, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "retiring the ID the packet came to was not a PROTOCOL_VIOLATION");
    }
    // \~english Issued but not yet sent: "greater than any previously sent" (19.16).
    // \~spanish Emitido pero aun sin mandar: "mayor que cualquiera mandado" (19.16).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        check(k.server.cids().issued == 1, "the server did not hand out one more ID");
        n = write_retire_connection_id(f, sizeof f, 1);
        to_server(cr, k, 1, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "retiring an ID not yet sent was not a PROTOCOL_VIOLATION");
    }
    {
        // \~english The client speaks first: until then the server may send nothing at all (8.1).
        // \~spanish El cliente habla primero: hasta entonces el servidor no puede mandar nada (8.1).  \~
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        pump(k, 5);
        check(k.server.sent().new_connection_id == 1, "the server did not send its extra ID");
        n = write_retire_connection_id(f, sizeof f, 1);
        to_server(cr, k, 1001, f, n);
        to_server(cr, k, 1002, f, n);
        check_server_active(k, "a valid RETIRE closed the server");
        check(k.server.cids().retired_by_peer == 1 && k.server.cids().issued == 2,
              "a retired ID was not replaced exactly once");
    }
    // \~english An end that gave a zero-length ID takes any RETIRE as a violation (19.16).
    // \~spanish Un extremo que dio un identificador de longitud cero toma cualquier RETIRE como violacion (19.16).  \~
    {
        ConnectionConfig zero = sc;
        zero.local_cid_len = 0;
        KeyPair k(cr, Aead::Aes128Gcm, cc, zero);
        check(k.server.ready(), "a server with a zero-length ID is not ready");
        n = write_retire_connection_id(f, sizeof f, 0);
        uint8_t pkt[1500];
        // \~english Addressed with a zero-length ID: no destination bytes at all.
        // \~spanish Dirigido con identificador de longitud cero: ningun byte de destino.  \~
        const size_t len = craft_one_rtt(cr, Aead::Aes128Gcm, 3, 0, false, 1, pkt, false, f, n, 0);
        k.server.on_datagram(pkt, len, Ecn::NotEct, k.now);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "a RETIRE to an end with a zero-length ID was not a PROTOCOL_VIOLATION");
    }
    // \~english One token for two IDs is a violation (10.3.2).
    // \~spanish Un testigo para dos identificadores es una violacion (10.3.2).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        uint8_t cid1[8], cid2[8], token[kResetTokenSize];
        std::memset(cid1, 0x41, 8);
        std::memset(cid2, 0x42, 8);
        std::memset(token, 0x77, sizeof token);
        n = write_new_connection_id(f, sizeof f, 1, 0, cid1, 8, token);
        to_server(cr, k, 1, f, n);
        n = write_new_connection_id(f, sizeof f, 2, 0, cid2, 8, token);
        to_server(cr, k, 2, f, n);
        check(server_closed_with(k, TransportError::ProtocolViolation),
              "one token for two IDs was not a PROTOCOL_VIOLATION");
    }
    // \~english No ID forgotten without retiring it: past the room for retirements, the connection closes (5.1.2).
    // \~spanish Ningun identificador olvidado sin retirarlo: pasado el sitio para retiradas, la conexion se cierra (5.1.2).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        for (uint64_t s = 1; s <= 16; ++s) {
            n = new_cid_frame(f, s, s, static_cast<uint8_t>(0x20 + s));
            to_server(cr, k, s, f, n);
        }
        check(k.server.state() == ConnState::Active, "sixteen retirements owed were refused");
        n = new_cid_frame(f, 17, 17, 0x60);
        to_server(cr, k, 17, f, n);
        check(server_closed_with(k, TransportError::ConnectionIdLimitError),
              "a seventeenth retirement owed did not close with CONNECTION_ID_LIMIT_ERROR");
    }
    // \~english ...while retirements the peer acknowledged free their room: thirty renewals by the real
    // \~english client make the server retire sixty IDs, far past the sixteen that fit at once.
    // \~spanish ...mientras que las retiradas que confirmo el otro liberan su sitio: treinta renovaciones
    // \~spanish del cliente de verdad hacen que el servidor retire sesenta identificadores, muy por encima de
    // \~spanish los dieciseis que caben a la vez.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        pump(k, 5);
        bool all = true;
        for (int r = 0; r < 30; ++r) {
            all = k.client.renew_connection_ids() && all;
            pump(k, 5);
        }
        check(all, "a renewal was refused although the previous one was fully retired");
        check_server_active(k, "acknowledged retirements did not free their room");
        check(k.server.cids().retired == 60 && k.client.cids().retired_by_peer == 60,
              "not every renewed ID was retired");
    }
    // \~english A renewal is refused while the peer has not retired what the last one asked for (5.1.2).
    // \~spanish Una renovacion se niega mientras el otro no haya retirado lo que pidio la anterior (5.1.2).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        pump(k, 5);
        check(k.client.renew_connection_ids(), "the first renewal was refused");
        check(!k.client.renew_connection_ids(), "a renewal was allowed before the last one was retired");
        pump(k, 5);
        check(k.client.renew_connection_ids(), "a renewal was refused after the last one was retired");
    }

    // \~english Every short packet is at least 22 bytes longer than this end's ID (10.3).
    // \~spanish Cada paquete corto mide al menos 22 bytes mas que el identificador de este extremo (10.3).  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        uint8_t out[1500];
        pump(k, 10);
        size_t smallest = 1500;
        to_server(cr, k, 1000, nullptr, 0);
        for (int i = 0; i < 20; ++i) {
            k.now += 30000;
            size_t m;
            while ((m = k.server.build_datagram(out, sizeof out, k.now)) != 0)
                if (m < smallest) smallest = m;
        }
        check(smallest != 1500 && smallest >= sc.local_cid_len + 22,
              "a short packet was smaller than the ID plus 22 bytes");

        // \~english The smallest there is: a probe carrying only a PING (1 + 8 + 1 + 3 + 16 = 29 unpadded).
        // \~spanish El mas pequeno que hay: un sondeo que solo lleva un PING (1 + 8 + 1 + 3 + 16 = 29 sin relleno).  \~
        say(k, "x");
        check(k.client.build_datagram(out, sizeof out, k.now) != 0, "the client sent nothing");
        const uint64_t t = k.client.timer();
        k.client.on_timer(t);
        const size_t probe = k.client.build_datagram(out, sizeof out, t);
        check(probe == cc.local_cid_len + 22, "a PING-only probe was not padded to the ID plus 22 bytes");
    }

    // \~english Renewing: the peer retires both old IDs, moves to a new one, and data still flows.
    // \~spanish Renovar: el otro retira los dos identificadores viejos, pasa a uno nuevo, y los datos siguen.  \~
    {
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        say(k, "before ");
        pump(k, 10);
        k.server.renew_connection_ids();
        pump(k, 10);
        say(k, "after");
        pump(k, 10);
        check(k.server.cids().retired_by_peer == 2 && k.client.cids().retired == 2 &&
                  k.client.peer_cid_sequence() == 2,
              "a renewal did not end with the old IDs retired and a new one in use");
        check(heard(k) == "before after", "the stream did not survive a renewal");
    }

    // \~english Stateless reset: a used ID's token ends the connection; no other does (10.3.1).
    // \~spanish Reinicio sin estado: el testigo de un identificador usado acaba la conexion; ningun otro (10.3.1).  \~
    {
        for (size_t i = 0; i < kResetKeySize; ++i) sc.reset_key[i] = static_cast<uint8_t>(0xa0 + i);
        ConnectionConfig ccr = cc;
        check(reset_token(cr, sc.reset_key, sc.local_cid, 8, ccr.peer_reset_token), "token");
        ccr.peer_reset_token_known = true;
        KeyPair k(cr, Aead::Aes128Gcm, ccr, sc);

        uint8_t wrong[kResetTokenSize];
        std::memcpy(wrong, ccr.peer_reset_token, kResetTokenSize);
        wrong[0] ^= 1;
        uint8_t pkt[64];
        size_t m = write_stateless_reset(cr, wrong, 60, pkt, sizeof pkt);
        k.client.on_datagram(pkt, m, Ecn::NotEct, k.now);
        check(k.client.state() == ConnState::Active && !k.client.closed_by_reset(),
              "a reset with the wrong token ended the connection");

        // \~english The acceptor, holding the same key, answers for a server that is gone.
        // \~spanish El acceptor, con la misma clave, contesta por un servidor que ya no esta.  \~
        AcceptorConfig ac = acceptor_config(false);
        std::memcpy(ac.reset_key, sc.reset_key, kResetKeySize);
        Acceptor gone(cr, ac);
        say(k, "anyone there?");
        uint8_t out[1500], reply[1500];
        m = k.client.build_datagram(out, sizeof out, k.now);
        const Admission ad = gone.on_datagram(out, m, kClientAddr, sizeof kClientAddr, k.now, reply,
                                              sizeof reply);
        check(ad.reason == AdmitReason::SentStatelessReset, "the acceptor did not answer with a reset");
        k.client.on_datagram(reply, ad.reply_len, Ecn::NotEct, k.now);
        check(k.client.closed_by_reset() && k.client.state() == ConnState::Draining,
              "the client did not recognise the reset for its server");
        check(k.client.build_datagram(out, sizeof out, k.now) == 0, "a reset connection still sends");
    }
    // \~english The token of an ID the client holds but never sent to does not count (10.3.1)...
    // \~spanish El testigo de un identificador que el cliente tiene pero al que nunca mando no cuenta (10.3.1)...  \~
    {
        for (size_t i = 0; i < kResetKeySize; ++i) sc.reset_key[i] = static_cast<uint8_t>(0xa0 + i);
        KeyPair k(cr, Aead::Aes128Gcm, cc, sc);
        pump(k, 10);
        check(k.client.cids().received == 1, "the client did not get the server's extra ID");
        uint64_t seq = 0;
        const uint8_t *cid = nullptr;
        const uint8_t *token = nullptr;
        check(k.server.local_cid(1, seq, cid, token) && seq == 1, "the server's second ID is not listed");
        uint8_t pkt[64];
        size_t m = write_stateless_reset(cr, token, 60, pkt, sizeof pkt);
        k.client.on_datagram(pkt, m, Ecn::NotEct, k.now);
        check(k.client.state() == ConnState::Active, "the token of an ID never sent to ended the connection");

        // \~english Once the client moves to that ID, its token does count -- in any header form (10.3).
        // \~spanish Cuando el cliente pasa a ese identificador, su testigo si cuenta.  \~
        k.server.renew_connection_ids();
        pump(k, 10);
        uint64_t in_use = k.client.peer_cid_sequence();
        const uint8_t *used_token = nullptr;
        for (size_t i = 0; k.server.local_cid(i, seq, cid, token); ++i)
            if (seq == in_use) used_token = token;
        check(used_token != nullptr, "the ID in use is not one the server lists");
        if (used_token != nullptr) {
            m = write_stateless_reset(cr, used_token, 60, pkt, sizeof pkt);
            pkt[0] |= 0x80;
            k.client.on_datagram(pkt, m, Ecn::NotEct, k.now);
            check(k.client.closed_by_reset(), "the token of the ID in use did not end the connection");
        }
    }
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
        {"clean", 0, 0, 20000, 0, 0, 0, false, 0, Aead::Aes128Gcm, false},
        {"lossy", 5, 2, 20000, 10000, 0, 0, false, 0, Aead::Aes128Gcm, false},
        {"hostile", 20, 5, 30000, 40000, 0, 0, false, 0, Aead::Aes128Gcm, false},
        {"handshake-lost", 3, 0, 20000, 5000, 2, 0, false, 0, Aead::Aes128Gcm, false},
        {"handshake-done-lost", 0, 0, 20000, 0, 0, 150000, false, 0, Aead::Aes128Gcm, false},
        {"retry-clean", 0, 0, 20000, 0, 0, 0, true, 0, Aead::Aes128Gcm, false},
        {"retry-lossy", 5, 2, 20000, 10000, 0, 0, true, 0, Aead::Aes128Gcm, false},
        // \~english Keys updated every 40 packets, one suite each: a clean network must not notice.
        // \~spanish Claves actualizadas cada 40 paquetes, un algoritmo en cada una: una red limpia no debe notarlo.  \~
        {"keys-clean", 0, 0, 20000, 0, 0, 0, false, 40, Aead::Aes128Gcm, false},
        {"keys-lossy", 5, 2, 20000, 10000, 0, 0, false, 40, Aead::Aes256Gcm, false},
        {"keys-hostile", 20, 5, 30000, 40000, 0, 0, false, 40, Aead::ChaCha20Poly1305, false},
        // \~english Both ends renew their connection IDs mid-transfer; the peer must retire and move on.
        // \~spanish Los dos extremos renuevan sus identificadores a mitad de transferencia; el otro tiene que retirar y cambiar.  \~
        {"cids-clean", 0, 0, 20000, 0, 0, 0, false, 0, Aead::Aes128Gcm, true},
        {"cids-lossy", 5, 2, 20000, 10000, 0, 0, false, 0, Aead::Aes128Gcm, true},
        {"cids-hostile", 20, 5, 30000, 40000, 0, 0, false, 40, Aead::Aes128Gcm, true},
    };
    for (const NetShape &net : shapes)
        for (uint64_t seed = 1; seed <= 3; ++seed) run(cr, net, seed, 4, 100000);
    test_violation(cr);
    test_idle(cr);
    test_early_one_rtt(cr);
    test_version_negotiation(cr);
    test_retry_rules(cr);
    test_changed_source(cr);
    test_initial_rules(cr);
    test_key_update_rules(cr, Aead::Aes128Gcm);
    test_key_update_rules(cr, Aead::Aes256Gcm);
    test_key_update_rules(cr, Aead::ChaCha20Poly1305);
    test_cid_rules(cr);
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
