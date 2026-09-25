/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_tls.cpp
 * @brief
 * \~english A QUIC connection with a real TLS 1.3 handshake: two connections, an acceptor, datagrams.
 * \~spanish Una conexion QUIC con un saludo TLS 1.3 de verdad: dos conexiones, un acceptor, datagramas.
 * \~
 *
 * \~english
 * Nothing is simulated but the network.  The client's connection and the
 * server's -- born from what the acceptor admits, after a Retry or not --
 * shake hands with TLS and then echo a stream.  Both ends start knowing
 * NONE of the other's limits: no stream may be opened and no byte sent
 * until the transport parameters arrived and were applied, so the echo
 * coming back proves they were.  Then what must fail does: IDs that do not
 * match the Initial packets' (RFC 9000, 7.3), a Retry the server does not
 * own up to, no protocol in common, parameters that do not decode.
 * \~spanish
 * No se simula nada salvo la red.  La conexion del cliente y la del servidor --
 * nacida de lo que admite el acceptor, tras un Retry o no -- se dan la mano con
 * TLS y luego hacen eco de un flujo.  Los dos extremos empiezan sin conocer
 * NINGUNO de los limites del otro: no se puede abrir un flujo ni mandar un byte
 * hasta que llegaron los parametros de transporte y se aplicaron, asi que el
 * eco de vuelta demuestra que se aplicaron.  Despues falla lo que tiene que
 * fallar: identificadores que no casan con los de los paquetes Initial (RFC
 * 9000, 7.3), un Retry que el servidor no reconoce, ningun protocolo en comun,
 * parametros que no se decodifican.
 * \~
 */

#include "http_vx/quic_acceptor.h"
#include "http_vx/quic_connection.h"
#include "http_vx/quic_transport_params.h"
#include "http_vx/quic_varint.h"
#include "http_vx/tls_quic.h"

#include "fake_crypto.h"
#include "tls_rfc8448.h"
#include "tls_test_keys.h"

#if HTTP_VX_HAVE_OPENSSL
#include "openssl_crypto.h"
#endif
#if HTTP_VX_HAVE_CNG
#include "cng_crypto.h"
#endif

#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

namespace {

using namespace http_vx::quic;
using http_vx::tls::QuicHandshake;
using http_vx::tls::SessionConfig;

int failures = 0;
char current[96] = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

const Path kPath{};
Path g_sent;
const uint8_t kClientAddr[6] = {198, 51, 100, 7, 0x1f, 0x90};
const char *const kH3[] = {"h3"};
const char *const kH2[] = {"h2"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};
const uint8_t kHello[] = {'h', 'e', 'l', 'l', 'o', ',', ' ', 'q', 'u', 'i', 'c'};
const uint8_t kTicketKey[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 1, 2, 3, 4, 5, 6, 7, 8};

/// \~english What a run changes.  \~spanish Lo que cambia una corrida.  \~
struct Options {
    bool retry = false;
    /// \~english Lose the first N datagrams each way.  \~spanish Perder los N primeros datagramas de cada lado.  \~
    unsigned lose_first = 0;
    /// \~english The server names a wrong original ID, or hides the Retry.  \~spanish El servidor nombra un identificador original equivocado, o esconde el Retry.  \~
    bool wrong_original = false;
    bool hide_retry = false;
    /// \~english The client offers only h2.  \~spanish El cliente solo ofrece h2.  \~
    bool alpn_mismatch = false;
    /**
     * \~english
     * The server's CRYPTO buffers hold less than its flight, so it has to go
     * out in parts.  The buffers come in whole chunks of kRecvChunk, so the
     * flight is made larger than one with a second certificate of filler: the
     * client checks the signature with the first and only keeps the rest.
     * \~spanish
     * Los buffers CRYPTO del servidor guardan menos que su vuelo, asi que tiene
     * que salir por partes.  Los buffers van en trozos enteros de kRecvChunk,
     * asi que el vuelo se hace mayor que uno con un segundo certificado de
     * relleno: el cliente comprueba la firma con el primero y del resto solo
     * lo guarda.
     * \~
     */
    uint64_t server_crypto_window = 65536;
    size_t filler_certificate = 0;
    /// \~english Once the client completed, the server adds bytes at Handshake that TLS will never read.
    /// \~spanish Cuando el cliente completo, el servidor anade en Handshake bytes que TLS no leera nunca.  \~
    bool junk_late = false;
    /// \~english The server issues tickets; the client resumes with one.  \~spanish El servidor emite tickets; el cliente reanuda con uno.  \~
    const http_vx::tls::TicketSealer *sealer = nullptr;
    const http_vx::tls::Ticket *resume = nullptr;
    /// \~english When the run starts: one clock across runs, as tickets need.  \~spanish Cuando empieza la corrida: un reloj entre corridas, como necesitan los tickets.  \~
    uint64_t start_us = 0;
    /// \~english 0-RTT: the server allows it with this guard and context; the client says hello in it.
    /// \~spanish 0-RTT: el servidor lo permite con este guardian y contexto; el cliente dice hola en el.  \~
    bool early_data = false;
    http_vx::tls::ReplayGuard *guard = nullptr;
    const uint8_t *context = nullptr;
    /// \~english The server's MAX_DATA window; zero leaves the default.  \~spanish La ventana MAX_DATA del servidor; cero deja la de por defecto.  \~
    uint64_t server_data_window = 0;
    uint64_t client_idle_us = 30000000;
    uint64_t server_idle_us = 20000000;
};

/// \~english What a run ended with.  \~spanish Con que acabo una corrida.  \~
struct Outcome {
    bool echoed = false;
    bool client_confirmed = false;
    bool server_confirmed = false;
    ConnState client_state = ConnState::Active;
    uint64_t client_code = 0;
    uint64_t client_frame = 0;
    bool client_closed_by_peer = false;
    uint64_t server_code = 0;
    bool server_exists = false;
    bool retried = false;
    uint64_t peer_streams = 0;
    bool resumed = false;
    size_t tickets = 0;
    http_vx::tls::Ticket ticket;
    uint64_t early_sent = 0;
    uint64_t early_opened = 0;
    uint64_t early_dropped = 0;
    bool early_rejected = false;
    bool hello_in_early = false;
};

struct Datagram {
    uint64_t at;
    bool to_server;
    std::vector<uint8_t> bytes;
};

/// \~english A connection configured to know nothing of the peer's limits.
/// \~spanish Una conexion configurada sin saber nada de los limites del otro.  \~
ConnectionConfig blank(bool server, uint8_t id, uint64_t idle) {
    ConnectionConfig c;
    c.is_server = server;
    for (int i = 0; i < 8; ++i) {
        c.local_cid[i] = static_cast<uint8_t>(id + i);
        c.peer_cid[i] = static_cast<uint8_t>(0x0d + i);
    }
    c.idle_timeout_us = idle;
    c.streams.is_server = server;
    c.streams.peer_max_streams_bidi = 0;
    c.streams.peer_window_bidi_local = 0;
    c.streams.peer_window_bidi_remote = 0;
    c.peer_max_data = 0;
    for (size_t i = 0; i < sizeof c.reset_key; ++i) c.reset_key[i] = static_cast<uint8_t>(id * 3 + i);
    return c;
}

/**
 * @brief
 * \~english One run: handshake over datagrams, then the client says hello and the server says it back.
 * \~spanish Una corrida: saludo por datagramas, y luego el cliente dice hola y el servidor lo repite.
 * \~
 */
Outcome run(Crypto &client_crypto, Crypto &server_crypto, const uint8_t *cert, size_t cert_len, void *key,
            Scheme scheme, const Options &o) {
    Outcome out;
    ConnectionConfig cc = blank(false, 0xc0, o.client_idle_us);
    ConnectionConfig sc = blank(true, 0x50, o.server_idle_us);
    sc.crypto_window = o.server_crypto_window;
    if (o.server_data_window != 0) sc.data_window = o.server_data_window;
    Connection client(client_crypto, cc);
    check(client.ready() && client.set_initial_keys(cc.peer_cid, 8), "the client could not start");

    SessionConfig ccfg;
    ccfg.alpn = o.alpn_mismatch ? kH2 : kH3;
    ccfg.alpn_count = 1;
    ccfg.server_name = "example.com";
    ccfg.trust_any_certificate = true;
    ccfg.resume = o.resume;
    ccfg.early_data = o.early_data;
    QuicHandshake ch(client_crypto, client, ccfg);
    check(ch.start(o.start_us), "the client's handshake did not start");

    std::vector<uint8_t> filler(o.filler_certificate, 0x5a);
    const uint8_t *certs[2] = {cert, filler.data()};
    const size_t lens[2] = {cert_len, filler.size()};
    SessionConfig scfg;
    scfg.server = true;
    scfg.alpn = kH3;
    scfg.alpn_count = 1;
    scfg.certificates = certs;
    scfg.certificate_lens = lens;
    scfg.certificate_count = filler.empty() ? 1 : 2;
    scfg.signing_key = key;
    scfg.scheme = scheme;
    scfg.tickets = o.sealer;
    scfg.early_data = o.early_data;
    scfg.replay = o.guard;
    scfg.early_context = o.context;
    scfg.early_context_len = o.context != nullptr ? 4 : 0;

    AcceptorConfig ac;
    ac.require_retry = o.retry;
    for (size_t i = 0; i < sizeof ac.token_key; ++i) ac.token_key[i] = static_cast<uint8_t>(0x71 * i + 3);
    for (size_t i = 0; i < sizeof ac.reset_key; ++i) ac.reset_key[i] = sc.reset_key[i];
    Acceptor acceptor(server_crypto, ac);
    std::unique_ptr<Connection> srv;
    std::unique_ptr<QuicHandshake> sh;

    std::vector<Datagram> air;
    unsigned sent_each[2] = {0, 0};
    uint64_t now = o.start_us;
    bool opened = false;
    uint64_t stream_id = 0;
    std::vector<uint8_t> back;
    std::vector<uint8_t> at_server;
    size_t echoed = 0;
    bool junk_sent = false;
    bool reopened = false;

    for (int step = 0; step < 20000 && !out.echoed; ++step) {
        ch.step(now);
        if (sh) sh->step(now);

        // \~english Past the server's Finished, in a packet of its own: nothing TLS will ever read (RFC 9001, 4.1.3).
        // \~spanish Despues del Finished del servidor, en un paquete propio: nada que TLS vaya a leer (RFC 9001, 4.1.3).  \~
        if (o.junk_late && !junk_sent && ch.complete() && srv && !srv->is_handshake_confirmed()) {
            const uint8_t junk[] = {0x14, 0x00, 0x00, 0x20};
            size_t took = 0;
            srv->crypto_send(Space::Handshake).write(junk, sizeof junk, took);
            junk_sent = took == sizeof junk;
        }

        /* \~english
         * The client says hello once confirmed -- or at once, in 0-RTT, when
         * it offered it.  Turned down, its stream is gone (RFC 9001, 4.6.2):
         * it says hello again once confirmed.  The server says it back.
         * \~spanish
         * El cliente dice hola en cuanto confirma -- o en el acto, en 0-RTT,
         * cuando lo ofrecio.  Rechazado, su flujo desaparece (RFC 9001, 4.6.2):
         * vuelve a decir hola cuando confirma.  El servidor lo repite.
         * \~ */
        if (opened && client.early_rejected() && !reopened) {
            opened = false;
            reopened = true;
            back.clear();
        }
        const bool early_now = ch.session().early_offered() && !client.early_rejected() && !reopened;
        if (!opened && (client.is_handshake_confirmed() || early_now)) {
            Stream *st = client.streams().open(true);
            if (st != nullptr) {
                size_t took = 0;
                st->send->write(kHello, sizeof kHello, took);
                st->send->finish();
                stream_id = st->id;
                opened = true;
                // \~english The first hello says whether it went early; the one after a rejection never does.
                // \~spanish El primer hola dice si fue temprano; el que sigue a un rechazo nunca lo es.  \~
                if (!reopened) out.hello_in_early = !client.is_handshake_confirmed();
            }
        }
        if (opened) {
            Stream *st = client.streams().find(stream_id);
            const uint8_t *p = nullptr;
            size_t n;
            while (st != nullptr && (n = st->recv->peek(p)) != 0) {
                back.insert(back.end(), p, p + n);
                client.consume(*st, n);
            }
            out.echoed = back.size() == sizeof kHello && std::memcmp(back.data(), kHello, sizeof kHello) == 0;
        }
        if (srv) {
            Stream *st = srv->streams().find(stream_id);
            const uint8_t *p = nullptr;
            size_t n;
            while (st != nullptr && (n = st->recv->peek(p)) != 0) {
                at_server.insert(at_server.end(), p, p + n);
                srv->consume(*st, n);
            }
            if (st != nullptr && echoed < at_server.size()) {
                size_t took = 0;
                st->send->write(at_server.data() + echoed, at_server.size() - echoed, took);
                echoed += took;
                if (echoed == sizeof kHello) st->send->finish();
            }
        }

        for (int who = 0; who < 2; ++who) {
            Connection *c = who == 0 ? &client : srv.get();
            if (c == nullptr) continue;
            uint8_t buf[1500];
            for (int k = 0; k < 64; ++k) {
                const size_t n = c->build_datagram(g_sent, buf, sizeof buf, now);
                if (n == 0) break;
                if (++sent_each[who] <= o.lose_first) continue;
                air.push_back(Datagram{now + 10000, who == 0, std::vector<uint8_t>(buf, buf + n)});
            }
        }
        const bool client_done = client.state() != ConnState::Active;
        const bool server_done = !srv || srv->state() != ConnState::Active;
        if (client_done && server_done && air.empty()) break;

        uint64_t next = client.timer();
        if (srv && srv->timer() < next) next = srv->timer();
        for (const Datagram &d : air)
            if (d.at < next) next = d.at;
        if (next == kNever) break;
        if (next > now) now = next;

        for (size_t i = 0; i < air.size();) {
            if (air[i].at > now) {
                ++i;
                continue;
            }
            Datagram d = air[i];
            air[i] = air.back();
            air.pop_back();
            if (!d.to_server) {
                client.on_datagram(kPath, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
            } else if (srv) {
                srv->on_datagram(kPath, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
            } else {
                uint8_t reply[1500];
                const Admission ad = acceptor.on_datagram(d.bytes.data(), d.bytes.size(), kClientAddr,
                                                          sizeof kClientAddr, now, reply, sizeof reply);
                if (ad.verdict == Admit::Reply) {
                    air.push_back(Datagram{now + 10000, false, std::vector<uint8_t>(reply, reply + ad.reply_len)});
                } else if (ad.verdict == Admit::Accept) {
                    std::memcpy(sc.peer_cid, ad.scid, ad.scid_len);
                    sc.peer_cid_len = ad.scid_len;
                    sc.version = ad.version;
                    srv.reset(new Connection(server_crypto, sc));
                    check(srv->ready() && srv->set_initial_keys(ad.dcid, ad.dcid_len), "the server could not start");
                    if (ad.address_validated) srv->set_address_validated(now);
                    // \~english After a Retry the destination is the Retry's ID, not the first one (7.3).
                    // \~spanish Tras un Retry el destino es el identificador del Retry, no el primero (7.3).  \~
                    const bool retried = ad.odcid_len != ad.dcid_len || std::memcmp(ad.odcid, ad.dcid, ad.dcid_len) != 0;
                    uint8_t odcid[kMaxConnectionId];
                    std::memcpy(odcid, ad.odcid, ad.odcid_len);
                    if (o.wrong_original) odcid[0] ^= 0x01;
                    const bool name_retry = retried && !o.hide_retry;
                    srv->set_original_ids(odcid, ad.odcid_len, name_retry ? ad.dcid : nullptr,
                                          name_retry ? ad.dcid_len : 0);
                    sh.reset(new QuicHandshake(server_crypto, *srv, scfg));
                    sh->start(now);
                    srv->on_datagram(kPath, d.bytes.data(), d.bytes.size(), Ecn::NotEct, now);
                }
            }
        }
        if (client.timer() <= now) client.on_timer(now);
        if (srv && srv->timer() <= now) srv->on_timer(now);
    }

    out.client_confirmed = client.is_handshake_confirmed();
    out.client_state = client.state();
    out.client_code = client.close_code();
    out.client_frame = client.close_frame();
    out.client_closed_by_peer = client.closed_by_peer();
    out.retried = client.retried();
    out.peer_streams = client.streams().peer_limit(true);
    out.resumed = ch.session().resumed();
    out.early_sent = client.early_sent();
    out.early_rejected = client.early_rejected();
    if (srv) {
        out.early_opened = srv->early_opened();
        out.early_dropped = srv->drops().early;
    }
    out.tickets = ch.session().tickets();
    ch.take_ticket(out.ticket);
    if (srv) {
        out.server_exists = true;
        out.server_confirmed = srv->is_handshake_confirmed();
        out.server_code = srv->close_code();
        if (!out.echoed && srv->state() == ConnState::Active && client.state() == ConnState::Active)
            std::fprintf(stderr, "  [%s] client: %s / server: %s\n", current, ch.why() ? ch.why() : "-",
                         sh && sh->why() ? sh->why() : "-");
    }
    return out;
}

/// \~english Handshakes that must work, over one provider pair.  \~spanish Saludos que deben funcionar, sobre un par de proveedores.  \~
void run_good(Crypto &cc, Crypto &sc, const uint8_t *cert, size_t cert_len, void *key, Scheme scheme,
              const char *name) {
    const char *shapes[4] = {"plain", "retry", "retry and loss", "small crypto buffers"};
    for (int i = 0; i < 4; ++i) {
        std::snprintf(current, sizeof current, "%s: %s", name, shapes[i]);
        Options o;
        o.retry = i == 1 || i == 2;
        o.lose_first = i == 2 ? 2 : 0;
        // \~english One chunk against a flight of two: the rest waits in TLS until acknowledgements make room.
        // \~spanish Un trozo frente a un vuelo de dos: el resto espera en TLS hasta que las confirmaciones hacen sitio.  \~
        if (i == 3) {
            o.server_crypto_window = kRecvChunk;
            o.filler_certificate = 6000;
        }
        const Outcome r = run(cc, sc, cert, cert_len, key, scheme, o);
        check(r.client_confirmed && r.server_confirmed, "both ends confirmed");
        check(r.echoed, "the hello came back: the transport parameters were applied");
        check(r.retried == o.retry, "the Retry was taken when asked");
        check(r.peer_streams != 0, "the server's stream limit came with its parameters");
        check(!r.resumed, "no ticket, no resumption");
    }

    // \~english Tickets travel in 1-RTT CRYPTO frames (RFC 9001, 4.5); the next connection resumes.
    // \~spanish Los tickets viajan en tramas CRYPTO de 1-RTT (RFC 9001, 4.5); la siguiente conexion reanuda.  \~
    std::snprintf(current, sizeof current, "%s: resumption", name);
    const http_vx::tls::TicketSealer sealer(sc, kTicketKey);
    Options first;
    first.sealer = &sealer;
    const Outcome a = run(cc, sc, cert, cert_len, key, scheme, first);
    check(a.echoed && a.tickets >= 1 && a.ticket.identity_len != 0, "the first connection leaves a ticket");
    Options second;
    second.sealer = &sealer;
    second.resume = &a.ticket;
    second.retry = true;
    second.start_us = 10000000;
    const Outcome b = run(cc, sc, cert, cert_len, key, scheme, second);
    check(b.echoed && b.resumed, "the second resumes, through a Retry, and says hello");

    /* \~english
     * 0-RTT: the hello goes in 0-RTT packets and comes back.  Turned down --
     * another context -- the client's stream is reset and the hello goes
     * again after the handshake.  Through a Retry, what went before it is
     * sent again (RFC 9000, 17.2.3).
     * \~spanish
     * 0-RTT: el hola va en paquetes 0-RTT y vuelve.  Rechazado -- otro contexto
     * --, el flujo del cliente se reinicia y el hola va otra vez tras el saludo.
     * A traves de un Retry, lo mandado antes se manda otra vez (RFC 9000,
     * 17.2.3).
     * \~ */
    const uint8_t ctx_a[4] = {'c', 't', 'x', 'a'};
    const uint8_t ctx_b[4] = {'c', 't', 'x', 'b'};
    for (int k = 0; k < 4; ++k) {
        // \~english 3: the server's transport parameters changed since the ticket: 0-RTT is refused (7.4.1).
        // \~spanish 3: los parametros de transporte del servidor cambiaron desde el ticket: se rechaza el 0-RTT (7.4.1).  \~
        const char *what[4] = {"0-RTT accepted", "0-RTT turned down", "0-RTT through a Retry",
                               "0-RTT with changed parameters"};
        std::snprintf(current, sizeof current, "%s: %s", name, what[k]);
        http_vx::tls::ReplayGuard guard(64, 10000, 0);
        Options f;
        f.sealer = &sealer;
        f.early_data = true;
        f.guard = &guard;
        f.context = ctx_a;
        f.start_us = 20000000;
        const Outcome t = run(cc, sc, cert, cert_len, key, scheme, f);
        check(t.echoed && t.ticket.early_data, "a ticket that allows 0-RTT");
        Options g = f;
        g.resume = &t.ticket;
        g.start_us = 30000000;
        g.context = k == 1 ? ctx_b : ctx_a;
        g.retry = k == 2;
        if (k == 3) g.server_data_window = 1u << 19;
        const Outcome r = run(cc, sc, cert, cert_len, key, scheme, g);
        check(r.echoed && r.resumed, "resumed, and the hello came back");
        check(r.hello_in_early && r.early_sent != 0, "the hello went in 0-RTT packets");
        if (k == 1 || k == 3) {
            check(r.early_rejected && r.early_opened == 0, "turned down: nothing opened, the client started over");
            check(r.early_dropped != 0, "and the server dropped the 0-RTT packets, counted (RFC 9001, 4.6.2)");
        } else {
            check(!r.early_rejected && r.early_opened != 0, "accepted: the server opened 0-RTT packets");
        }
    }
}

/// \~english What must fail, with the fake provider.  \~spanish Lo que debe fallar, con el proveedor falso.  \~
void run_bad(Crypto &c, void *key) {
    {
        std::snprintf(current, sizeof current, "bad: wrong original id");
        Options o;
        o.wrong_original = true;
        const Outcome r = run(c, c, kFakeCert, sizeof kFakeCert, key, Scheme::EcdsaSecp256r1Sha256, o);
        check(!r.echoed && r.client_state != ConnState::Active && r.client_code == 0x08 && !r.client_closed_by_peer,
              "the client refuses an original_destination_connection_id it did not send (7.3)");
    }
    {
        std::snprintf(current, sizeof current, "bad: hidden retry");
        Options o;
        o.retry = true;
        o.hide_retry = true;
        const Outcome r = run(c, c, kFakeCert, sizeof kFakeCert, key, Scheme::EcdsaSecp256r1Sha256, o);
        check(!r.echoed && r.client_code == 0x08 && !r.client_closed_by_peer,
              "the client refuses a server that does not name the Retry it took (7.3)");
    }
    {
        std::snprintf(current, sizeof current, "bad: no protocol in common");
        Options o;
        o.alpn_mismatch = true;
        const Outcome r = run(c, c, kFakeCert, sizeof kFakeCert, key, Scheme::EcdsaSecp256r1Sha256, o);
        check(r.server_exists && r.server_code == 0x178, "the server closes with no_application_protocol (RFC 9001, 8.1)");
        check(r.client_closed_by_peer && r.client_code == 0x178, "and the client hears it");
        check(r.client_frame == 0x06, "blamed on a CRYPTO frame");
    }
    {
        std::snprintf(current, sizeof current, "bad: late handshake data");
        Options o;
        o.junk_late = true;
        const Outcome r = run(c, c, kFakeCert, sizeof kFakeCert, key, Scheme::EcdsaSecp256r1Sha256, o);
        check(r.client_code == 0x0a && !r.client_closed_by_peer,
              "the client refuses Handshake data after TLS moved on (RFC 9001, 4.1.3)");
    }
}

/// \~english A connection that got its Initial from @p peer_scid: what its parameters check against.
/// \~spanish Una conexion que recibio su Initial de @p peer_scid: contra lo que comprueba sus parametros.  \~
void test_parameters(Crypto &c) {
    std::snprintf(current, sizeof current, "parameters");
    // \~english A server's own: its IDs, and what it runs with.  \~spanish Los de un servidor: sus identificadores, y con lo que funciona.  \~
    ConnectionConfig sc = blank(true, 0x50, 12345678);
    sc.ack.max_ack_delay_us = 20500;
    sc.ack.ack_delay_exponent = 5;
    sc.data_window = 777777;
    sc.streams.window_bidi_local = 1111;
    sc.streams.window_bidi_remote = 2222;
    sc.streams.window_uni = 3333;
    sc.active_cid_limit = 5;
    sc.disable_active_migration = true;
    Connection server(c, sc);
    const uint8_t odcid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    const uint8_t retry[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    check(server.set_initial_keys(retry, sizeof retry) &&
              server.set_original_ids(odcid, sizeof odcid, retry, sizeof retry),
          "the server takes its original IDs");
    uint8_t buf[256];
    const size_t n = server.local_transport_params(buf, sizeof buf);
    TransportParams tp;
    check(n != 0 && decode_transport_params(buf, n, true, tp) == TpError::None, "the server's parameters decode");
    check(tp.initial_source_connection_id.len == 8 && tp.initial_source_connection_id.bytes[0] == 0x50,
          "initial_source_connection_id is the first local ID (7.3)");
    check(tp.original_destination_connection_id.len == 8 &&
              std::memcmp(tp.original_destination_connection_id.bytes, odcid, 8) == 0,
          "original_destination_connection_id is the client's first destination (7.3)");
    check(tp.retry_source_connection_id.present && tp.retry_source_connection_id.len == 5 &&
              std::memcmp(tp.retry_source_connection_id.bytes, retry, 5) == 0,
          "retry_source_connection_id is the Retry's (7.3)");
    uint64_t seq = 0;
    const uint8_t *cid = nullptr;
    const uint8_t *token = nullptr;
    check(server.local_cid(0, seq, cid, token) && tp.has_stateless_reset_token &&
              std::memcmp(tp.stateless_reset_token, token, 16) == 0,
          "the reset token is the first ID's (18.2)");
    check(tp.max_idle_timeout_ms == 12346 && tp.max_ack_delay_ms == 21 && tp.ack_delay_exponent == 5,
          "timings, rounded up to whole milliseconds");
    check(tp.initial_max_data == 777777 && tp.initial_max_stream_data_bidi_local == 1111 &&
              tp.initial_max_stream_data_bidi_remote == 2222 && tp.initial_max_stream_data_uni == 3333,
          "the windows it runs with");
    check(tp.initial_max_streams_bidi == server.streams().max_streams(true) && tp.initial_max_streams_bidi != 0,
          "the stream limit it enforces");
    check(tp.active_connection_id_limit == 5 && tp.disable_active_migration, "the ID limit and migration");

    // \~english A client's own: no server-only parameter.  \~spanish Los de un cliente: ningun parametro solo de servidor.  \~
    ConnectionConfig cc = blank(false, 0xc0, 0);
    Connection client(c, cc);
    client.set_initial_keys(cc.peer_cid, 8);
    const size_t m = client.local_transport_params(buf, sizeof buf);
    check(m != 0 && decode_transport_params(buf, m, false, tp) == TpError::None, "the client's parameters decode as a client's");
    check(!tp.original_destination_connection_id.present && !tp.has_stateless_reset_token &&
              tp.max_idle_timeout_ms == 0,
          "a client sends no server-only parameter; no idle timeout is zero");

    // \~english The peer's, checked against the IDs the Initial packets carried (7.3).
    // \~spanish Los del otro, comprobados contra los identificadores que llevaron los paquetes Initial (7.3).  \~
    TransportParams peer;
    peer.initial_source_connection_id.present = true;
    peer.initial_source_connection_id.len = 8;
    for (int i = 0; i < 8; ++i) peer.initial_source_connection_id.bytes[i] = static_cast<uint8_t>(0x0d + i);
    peer.initial_max_streams_bidi = 7;
    peer.initial_max_data = 5000;
    {
        Connection s2(c, blank(true, 0x60, 0));
        s2.set_initial_keys(odcid, 8);
        size_t k = encode_transport_params(peer, buf, sizeof buf);
        check(s2.on_peer_transport_params(buf, k, 0), "the client's own parameters are taken");
        check(s2.streams().peer_limit(true) == 7, "and applied: the stream limit");
        check(s2.has_peer_transport_params(), "once");
        TransportParams other = peer;
        other.initial_max_streams_bidi = 9;
        k = encode_transport_params(other, buf, sizeof buf);
        check(s2.on_peer_transport_params(buf, k, 0) && s2.streams().peer_limit(true) == 7,
              "a second set changes nothing");
        check(!client.set_original_ids(odcid, 8, nullptr, 0), "a client has no original IDs to set");
    }
    {
        Connection s3(c, blank(true, 0x60, 0));
        s3.set_initial_keys(odcid, 8);
        TransportParams other = peer;
        other.initial_source_connection_id.bytes[7] ^= 1;
        const size_t k = encode_transport_params(other, buf, sizeof buf);
        check(!s3.on_peer_transport_params(buf, k, 0) && s3.close_code() == 0x08,
              "an initial_source_connection_id that is not the Initial's (7.3)");
    }
    {
        Connection s4(c, blank(true, 0x60, 0));
        s4.set_initial_keys(odcid, 8);
        const uint8_t junk[] = {0x04, 0x05, 0x80};
        check(!s4.on_peer_transport_params(junk, sizeof junk, 0) && s4.close_code() == 0x08,
              "parameters that do not decode (7.4)");
    }
    {
        // \~english A client that took no Retry refuses a retry_source_connection_id (7.3).
        // \~spanish Un cliente que no acepto ningun Retry rechaza un retry_source_connection_id (7.3).  \~
        Connection c2(c, blank(false, 0xc0, 0));
        c2.set_initial_keys(cc.peer_cid, 8);
        TransportParams srvp = peer;
        srvp.original_destination_connection_id.present = true;
        srvp.original_destination_connection_id.len = 8;
        for (int i = 0; i < 8; ++i) srvp.original_destination_connection_id.bytes[i] = static_cast<uint8_t>(0x0d + i);
        size_t k = encode_transport_params(srvp, buf, sizeof buf);
        {
            Connection ok(c, blank(false, 0xc0, 0));
            ok.set_initial_keys(cc.peer_cid, 8);
            check(ok.on_peer_transport_params(buf, k, 0), "a server's parameters that match");
        }
        srvp.retry_source_connection_id = srvp.original_destination_connection_id;
        k = encode_transport_params(srvp, buf, sizeof buf);
        check(!c2.on_peer_transport_params(buf, k, 0) && c2.close_code() == 0x08,
              "a retry_source_connection_id with no Retry (7.3)");
    }
}

/// \~english A server's parameters as a client would remember them: @p max_data of MAX_DATA, two streams.
/// \~spanish Los parametros de un servidor como los recordaria un cliente: @p max_data de MAX_DATA, dos flujos.  \~
size_t remembered(uint8_t *out, size_t room, uint64_t max_data) {
    TransportParams tp;
    tp.initial_source_connection_id.present = true;
    tp.initial_source_connection_id.len = 8;
    tp.original_destination_connection_id = tp.initial_source_connection_id;
    tp.initial_max_data = max_data;
    tp.initial_max_streams_bidi = 2;
    tp.initial_max_stream_data_bidi_remote = 1000;
    return encode_transport_params(tp, out, room);
}

/// \~english Whether transport parameter @p id is in @p p.  \~spanish Si el parametro de transporte @p id esta en @p p.  \~
bool has_param(const uint8_t *p, size_t n, uint64_t id) {
    size_t at = 0;
    while (at < n) {
        uint64_t k = 0;
        uint64_t len = 0;
        const size_t a = decode_varint(p + at, n - at, k);
        if (a == 0) return false;
        const size_t b = decode_varint(p + at + a, n - at - a, len);
        if (b == 0) return false;
        if (k == id) return true;
        at += a + b + static_cast<size_t>(len);
    }
    return false;
}

/**
 * @brief
 * \~english The connection's side of 0-RTT, piece by piece, with the fake provider.
 * \~spanish El lado de la conexion del 0-RTT, pieza a pieza, con el proveedor falso.
 * \~
 */
void test_early_connection(Crypto &c) {
    std::snprintf(current, sizeof current, "0-RTT in the connection");
    uint8_t secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<uint8_t>(0x30 + i);
    // \~english Just the hello's worth of credit, and plenty.  \~spanish Credito justo para el hola, y de sobra.  \~
    uint8_t params[256];
    const size_t params_len = remembered(params, sizeof params, sizeof kHello);
    uint8_t wide[256];
    const size_t wide_len = remembered(wide, sizeof wide, 1000);

    // \~english The client: 0-RTT packets on remembered limits, a long header of type 0x01 (17.2.3).
    // \~spanish El cliente: paquetes 0-RTT con los limites recordados, cabecera larga de tipo 0x01 (17.2.3).  \~
    ConnectionConfig cc = blank(false, 0xc0, 0);
    Connection client(c, cc);
    client.set_initial_keys(cc.peer_cid, 8);
    check(client.remember_transport_params(wide, wide_len), "the client remembers the server's parameters");
    check(client.send_credit() == 1000 && client.streams().peer_limit(true) == 2,
          "and runs 0-RTT on them (RFC 9000, 7.4.1)");
    check(client.install_early_secret(Aead::Aes128Gcm, secret, 32, 0) && client.has_early_keys(), "0-RTT keys");
    Stream *st = client.streams().open(true);
    size_t took = 0;
    st->send->write(kHello, sizeof kHello, took);
    uint8_t dgram[1500];
    const size_t n = client.build_datagram(g_sent, dgram, sizeof dgram, 1000);
    check(n != 0 && (dgram[0] & 0x80) != 0 && ((dgram[0] >> 4) & 3) == 1 && dgram[5] == 8 && dgram[6] == 0x0d,
          "a 0-RTT packet: long header, type 1, to the original destination");
    check(client.early_sent() == 1 && client.recovery().early_outstanding() == 1, "counted, and in flight");
    uint8_t copy[1500];

    // \~english Another client never opens it (RFC 9001, 5.6).  \~spanish Otro cliente nunca lo abre (RFC 9001, 5.6).  \~
    {
        ConnectionConfig other = blank(false, 0x0d, 0);
        Connection b(c, other);
        b.set_initial_keys(other.peer_cid, 8);
        b.install_early_secret(Aead::Aes128Gcm, secret, 32, 0);
        std::memcpy(copy, dgram, n);
        b.on_datagram(kPath, copy, n, Ecn::NotEct, 2000);
        check(b.drops().early == 1 && b.early_opened() == 0, "a client discards 0-RTT packets");
    }

    /* \~english
     * A server keeps it until its keys, then opens it (RFC 9001, 4.1.4).
     * Its own ID is the client's first destination: the client never
     * learns another here, and its 1-RTT packets must reach it too.
     * \~spanish
     * Un servidor lo guarda hasta sus claves, y entonces lo abre (RFC 9001,
     * 4.1.4).  Su propio identificador es el primer destino del cliente: aqui el
     * cliente no aprende otro, y sus paquetes 1-RTT tambien tienen que llegarle.
     * \~ */
    {
        ConnectionConfig sc = blank(true, 0x0d, 0);
        Connection s(c, sc);
        s.set_initial_keys(cc.peer_cid, 8);
        std::memcpy(copy, dgram, n);
        s.on_datagram(kPath, copy, n, Ecn::NotEct, 2000);
        check(s.drops().early == 0 && s.early_opened() == 0, "kept while its keys are not there");
        check(s.install_early_secret(Aead::Aes128Gcm, secret, 32, 2500) && s.early_opened() == 1,
              "opened once they are");
        Stream *got = s.streams().find(st->id);
        const uint8_t *p = nullptr;
        check(got != nullptr && got->recv->peek(p) == sizeof kHello && std::memcmp(p, kHello, sizeof kHello) == 0,
              "and its hello is there");

        // \~english Its keys go three PTO after the first 1-RTT packet (RFC 9001, 4.9.3).
        // \~spanish Sus claves se van tres PTO despues del primer paquete 1-RTT (RFC 9001, 4.9.3).  \~
        uint8_t r1[32], w1[32];
        for (int i = 0; i < 32; ++i) {
            r1[i] = static_cast<uint8_t>(i);
            w1[i] = static_cast<uint8_t>(0x80 + i);
        }
        check(s.install_secrets(Space::Application, Aead::Aes128Gcm, r1, w1, 32, 3000) &&
                  client.install_secrets(Space::Application, Aead::Aes128Gcm, w1, r1, 32, 3000),
              "1-RTT keys on both ends");
        check(!client.has_early_keys(), "a client drops its 0-RTT keys with the 1-RTT ones (4.9.3)");
        s.handshake_confirmed(3000);
        client.handshake_confirmed(3000);
        // \~english More of the hello, now in 1-RTT: credit is left.  \~spanish Mas del hola, ahora en 1-RTT: queda credito.  \~
        st->send->write(kHello, sizeof kHello, took);
        const size_t m = client.build_datagram(g_sent, dgram, sizeof dgram, 4000);
        check(m != 0 && (dgram[0] & 0x80) == 0, "a 1-RTT packet from the client");
        s.on_datagram(kPath, dgram, m, Ecn::NotEct, 5000);
        check(s.drops().wrong_cid == 0 && s.drops().no_keys == 0, "the server opened that 1-RTT packet");
        check(s.has_early_keys(), "right after it the server still holds them, for reordered 0-RTT");
        s.on_timer(5001);
        check(s.has_early_keys(), "a moment later too");
        check(s.timer() <= 5000 + 3 * 1100000, "their discard is on the timer");
        s.on_timer(5000 + 10000000);
        check(!s.has_early_keys(), "and three PTO later they are gone");
    }

    // \~english A server that turned it down: kept ones and later ones are dropped, and counted (4.6.2).
    // \~spanish Un servidor que lo rechazo: los guardados y los que lleguen se tiran, y se cuentan (4.6.2).  \~
    {
        ConnectionConfig sc = blank(true, 0x50, 0);
        Connection s(c, sc);
        s.set_initial_keys(cc.peer_cid, 8);
        uint8_t first[1500];
        size_t fn = 0;
        {
            Connection c2(c, cc);
            c2.set_initial_keys(cc.peer_cid, 8);
            c2.remember_transport_params(params, params_len);
            c2.install_early_secret(Aead::Aes128Gcm, secret, 32, 0);
            Stream *x = c2.streams().open(true);
            x->send->write(kHello, sizeof kHello, took);
            fn = c2.build_datagram(g_sent, first, sizeof first, 1000);
        }
        std::memcpy(copy, first, fn);
        s.on_datagram(kPath, copy, fn, Ecn::NotEct, 2000);
        s.reject_early(2100);
        check(s.early_rejected() && s.drops().early == 1, "the kept one is dropped at once, and counted");
        std::memcpy(copy, first, fn);
        s.on_datagram(kPath, copy, fn, Ecn::NotEct, 2200);
        check(s.drops().early == 2 && s.early_opened() == 0, "a later one too, never kept");
        check(!s.install_early_secret(Aead::Aes128Gcm, secret, 32, 2300), "and no keys can come after");
    }

    // \~english A client turned down: its 0-RTT is forgotten, and streams and flow control start over (4.6.2).
    // \~spanish Un cliente rechazado: su 0-RTT se olvida, y flujos y control de flujo empiezan de nuevo (4.6.2).  \~
    {
        Connection c3(c, cc);
        c3.set_initial_keys(cc.peer_cid, 8);
        c3.remember_transport_params(params, params_len);
        c3.install_early_secret(Aead::Aes128Gcm, secret, 32, 0);
        Stream *x = c3.streams().open(true);
        x->send->write(kHello, sizeof kHello, took);
        check(c3.build_datagram(g_sent, dgram, sizeof dgram, 1000) != 0 && c3.send_credit() == 0 &&
                  c3.recovery().bytes_in_flight() != 0,
              "the hello used the whole remembered credit");
        c3.reject_early(2000);
        check(c3.early_rejected() && c3.recovery().early_outstanding() == 0 && c3.recovery().bytes_in_flight() == 0,
              "its 0-RTT packets are out of the flight, never resent (RFC 9002, 6.4)");
        check(c3.streams().count() == 0 && c3.streams().peer_limit(true) == 0 && c3.send_credit() == 0,
              "no stream left, and the limits are the ones it started with");
        check(!c3.has_early_keys() && c3.build_datagram(g_sent, dgram, sizeof dgram, 1500) == 0,
              "and no 0-RTT goes out any more");
        check(c3.remember_transport_params(params, params_len) && c3.send_credit() == sizeof kHello,
              "the credit is whole again: nothing counts as sent");
        Stream *y = c3.streams().open(true);
        check(y != nullptr && y->id == 0, "stream numbering starts over");
    }

    // \~english Remembered values are replaced by the handshake's, never the other way round.
    // \~spanish Los valores recordados los sustituye el saludo, nunca al reves.  \~
    {
        Connection c4(c, cc);
        c4.set_initial_keys(cc.peer_cid, 8);
        TransportParams tp;
        tp.initial_source_connection_id.present = true;
        tp.initial_source_connection_id.len = 8;
        for (int i = 0; i < 8; ++i) tp.initial_source_connection_id.bytes[i] = static_cast<uint8_t>(0x0d + i);
        tp.original_destination_connection_id = tp.initial_source_connection_id;
        uint8_t real[256];
        const size_t rn = encode_transport_params(tp, real, sizeof real);
        check(c4.on_peer_transport_params(real, rn, 0), "the handshake's parameters");
        check(!c4.remember_transport_params(params, params_len), "after them, remembered ones are refused");
        Connection s5(c, blank(true, 0x50, 0));
        check(!s5.remember_transport_params(params, params_len), "and a server remembers nothing");
    }

    // \~english A server's 0-RTT context: its limits, without IDs, token or ACK timing (7.4.1).
    // \~spanish El contexto de 0-RTT de un servidor: sus limites, sin identificadores, testigo ni tiempo de ACK (7.4.1).  \~
    {
        ConnectionConfig sc = blank(true, 0x50, 0);
        sc.ack.max_ack_delay_us = 40000;
        Connection s(c, sc);
        s.set_initial_keys(cc.peer_cid, 8);
        uint8_t ctx[256];
        const size_t cn = s.early_context(ctx, sizeof ctx);
        uint8_t full[256];
        const size_t fn = s.local_transport_params(full, sizeof full);
        check(has_param(full, fn, 0x0f) && has_param(full, fn, 0x00) && has_param(full, fn, 0x02) &&
                  has_param(full, fn, 0x0b),
              "the full parameters carry the IDs, the token and max_ack_delay");
        check(cn != 0 && has_param(ctx, cn, 0x04) && !has_param(ctx, cn, 0x0f) && !has_param(ctx, cn, 0x00) &&
                  !has_param(ctx, cn, 0x02) && !has_param(ctx, cn, 0x0b) && !has_param(ctx, cn, 0x10),
              "the context keeps the limits and none of those");
    }
}

/// \~english A stream opened before the peer's parameters came takes their window (7.4.1).
/// \~spanish Un flujo abierto antes de que llegaran los parametros del otro toma su ventana (7.4.1).  \~
void test_stream_windows() {
    std::snprintf(current, sizeof current, "stream windows");
    StreamConfig s;
    s.is_server = false;
    s.peer_max_streams_bidi = 1;
    StreamTable t(s);
    Stream *st = t.open(true);
    check(st != nullptr && st->send->limit() == 0, "opened with the remembered window, here none");
    t.on_peer_params(4, 2, 100, 5000, 300);
    check(st != nullptr && st->send->limit() == 5000, "raised to the peer's bidi_remote: its window for our streams");
    check(t.peer_limit(true) == 4 && t.peer_limit(false) == 2, "and the stream limits");
    Stream *next = t.open(true);
    check(next != nullptr && next->send->limit() == 5000, "a new stream starts with it");
    t.on_peer_params(4, 2, 100, 10, 300);
    check(st != nullptr && st->send->limit() == 5000, "a window never goes down");
}

} // namespace

int main() {
    test_stream_windows();
    {
        test_support::FakeCrypto fc;
        test_early_connection(fc);
    }
    test_support::FakeCrypto fake;
    void *fake_key = fake.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
    test_parameters(fake);
    run_good(fake, fake, kFakeCert, sizeof kFakeCert, fake_key, Scheme::EcdsaSecp256r1Sha256, "fake");
    run_bad(fake, fake_key);
    fake.forget_key(fake_key);

    int providers = 0;
    uint8_t cert[2048];
    uint8_t pkcs8[2048];
    const size_t cert_len = rfc8448::from_hex(test_keys::kP256Certificate, cert, sizeof cert);
    const size_t key_len = rfc8448::from_hex(test_keys::kP256Pkcs8, pkcs8, sizeof pkcs8);
#if HTTP_VX_HAVE_OPENSSL
    http_vx::OpensslCrypto openssl;
    ++providers;
    void *ok = openssl.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len);
    run_good(openssl, openssl, cert, cert_len, ok, Scheme::EcdsaSecp256r1Sha256, "openssl");
#endif
#if HTTP_VX_HAVE_CNG
    http_vx::CngCrypto cng;
    ++providers;
    void *ck = cng.ready() ? cng.signing_key(Scheme::EcdsaSecp256r1Sha256, pkcs8, key_len) : nullptr;
    if (ck != nullptr) {
        run_good(cng, cng, cert, cert_len, ck, Scheme::EcdsaSecp256r1Sha256, "cng");
    } else {
        std::fprintf(stderr, "FAIL [cng]: the system refused %s\n", cng.missing());
        ++failures;
    }
#endif
#if HTTP_VX_HAVE_OPENSSL && HTTP_VX_HAVE_CNG
    if (ck != nullptr) run_good(openssl, cng, cert, cert_len, ck, Scheme::EcdsaSecp256r1Sha256, "openssl to cng");
    if (ck != nullptr) cng.forget_key(ck);
#endif
#if HTTP_VX_HAVE_OPENSSL
    openssl.forget_key(ok);
#endif
    (void)cert_len;
    (void)key_len;
    if (providers == 0) std::printf("SKIPPED: no real provider built, real handshakes not run\n");
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic tls, %d provider(s): OK\n", providers);
    return 0;
}
