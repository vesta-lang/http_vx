/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h3_open.cpp
 * @brief
 * \~english Open responses in HTTP/3 against real clients: DATA frames, kicks, flow control, limits, and every gone (HVX-5, 7.3).
 * \~spanish Respuestas abiertas en HTTP/3 frente a clientes de verdad: tramas DATA, avisos, control de flujo, topes, y cada gone (HVX-5, 7.3).
 * \~
 *
 * \~english The world they run in -- a real shard, clients, a network -- is h3_open_world.h.
 * \~spanish El mundo en el que corren -- un fragmento de verdad, clientes, una red -- es h3_open_world.h.  \~
 */
#include "fake_crypto.h"
#include "h3_open_world.h"

#include <cstdio>
#include <string>

namespace {

using namespace h3_open_test;

void test_open_kick_done(Crypto &crypto, const Keys &k) {
    section("open, kick, done");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    Feed &f = w.feeds[0];
    w.handler.before = "first";
    const uint64_t id = c.request("GET", "/open");
    w.settle();
    check(w.handler.last.valid() && w.handler.last.stream == id, "the handler opened, on its own stream");
    check(c.at(id).status == 200 && c.at(id).body == "first" && !c.at(id).ended,
          "the head and what was written before opening arrive; the stream stays open");
    check(c.at(id).field("content-type") != nullptr && *c.at(id).field("content-type") == "text/event-stream",
          "with the handler's fields");
    check(f.fills == 1 && f.gones == 0, "the first fill came right after opening, and found nothing");
    check(w.service.open_now() == 1 && w.shard.open_counts().open_now == 1 && w.shard.open_counts().opened == 1,
          "one open, counted on both sides");

    const uint64_t other = c.request("GET", "/");
    w.settle();
    check(c.at(other).status == 200 && c.at(other).body == "whole" && c.at(other).ended,
          "another request on the connection is answered while one is open");
    check(f.fills == 1, "and a source that returned less than its room is not asked without a kick (HVX-5, 4.3)");

    f.pending = "hello";
    check(f.kick(), "a kick is taken");
    w.settle();
    check(c.at(id).body == "firsthello" && !c.at(id).ended && f.fills == 2, "a kick is one fill, sent at once");

    f.pending = "a";
    f.kick();
    f.kick();
    f.kick();
    w.settle();
    check(f.fills == 3 && c.at(id).body == "firsthelloa", "three kicks before the loop turns are one fill (R36)");

    f.pending = "!";
    f.finish = true;
    f.kick();
    w.settle();
    check(c.at(id).body == "firsthelloa!" && c.at(id).ended && !c.at(id).reset,
          "done ends the QUIC stream right after the last piece");
    check(f.gones == 1 && f.last == GoneReason::Finished, "and the source is told Finished, once");
    const http_vx::OpenCounts oc = w.shard.open_counts();
    check(oc.opened == 1 && oc.fills == 4 && oc.filled_bytes == 7 && oc.open_now == 0,
          "every fill went through the shard's port, and was counted");
    check(w.service.open_now() == 0 && w.service.counts().served == 2, "nothing is left open");
    check(!c.h->failed(), "the client saw no error");
}

void test_frames(Crypto &crypto, const Keys &k) {
    section("each fill is one DATA frame");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    Feed &f = w.feeds[0];
    w.handler.before = "first";
    c.hold = true;
    const uint64_t id = c.request("GET", "/open");
    w.settle();
    f.pending = "abc";
    f.kick();
    w.settle();
    f.pending = "de";
    f.kick();
    w.settle();
    // \~english Done with nothing more: the stream ends alone, with no frame.
    // \~spanish Acabada sin nada mas: el flujo acaba solo, sin trama.  \~
    f.finish = true;
    f.kick();
    w.settle();
    check(f.gones == 1 && f.last == GoneReason::Finished && f.fills == 4, "the source is done, Finished");

    // \~english Read where QUIC left the bytes, before HTTP/3 takes them.
    // \~spanish Leido donde QUIC dejo los bytes, antes de que HTTP/3 los coja.  \~
    Stream *st = c.q->streams().find(id);
    const uint8_t *p = nullptr;
    const size_t n = st != nullptr && st->recv != nullptr ? st->recv->peek(p) : 0;
    size_t at = 0;
    uint64_t type = 0;
    uint64_t len = 0;
    size_t width = 0;
    std::string payload;
    check(read_frame(p, n, at, type, len, width, payload) && type == h3::kHeaders, "HEADERS first");
    check(read_frame(p, n, at, type, len, width, payload) && type == h3::kData && payload == "first",
          "then what was written before opening, as one DATA frame");
    check(read_frame(p, n, at, type, len, width, payload) && type == h3::kData && payload == "abc" && width == 2,
          "then one DATA frame per fill, its length in the fixed two bytes");
    check(read_frame(p, n, at, type, len, width, payload) && type == h3::kData && payload == "de" && width == 2,
          "and the next fill, its own frame");
    check(at == n, "and nothing else: the fills that found nothing wrote no frame");
    check(st != nullptr && st->recv->state() == RecvState::DataRecvd && st->recv->size_known() &&
              st->recv->final_size() == n,
          "the stream ended cleanly right after the last frame");

    c.hold = false;
    w.settle();
    check(c.at(id).body == "firstabcde" && c.at(id).ended, "the client reads it all, and the end");
}

void test_flow_control(Crypto &crypto, const Keys &k, bool connection) {
    section(connection ? "flow control: the connection's" : "flow control: the stream's");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    /* \~english
     * The client lets 3000 bytes onto the response's stream, or onto the
     * whole connection, until it reads them.  The connection's also pays for
     * the server's control and QPACK streams, so less is left for the body.
     * \~spanish
     * El cliente deja 3000 bytes en el flujo de la respuesta, o en toda la
     * conexion, hasta que los lee.  La de la conexion paga ademas los flujos de
     * control y de QPACK del servidor, asi que al cuerpo le queda menos.
     * \~ */
    Client &c = connection ? w.add(0, 3000) : w.add(3000);
    const size_t slack = connection ? 400 : h3::Connection::kFillHead;
    w.settle();
    Feed &f = w.feeds[0];
    f.full_fills = 1000000;
    c.hold = true;
    const uint64_t id = c.request("GET", "/open");
    w.settle();
    const int stalled = f.fills;
    check(stalled >= 1 && f.produced.size() < 3000 && f.produced.size() > 2000,
          "a source that always has more fills up to the credit and no further");
    const size_t most = h3::Connection::kFillAhead - h3::Connection::kFillHead;
    check(f.max_room <= most, "and is never offered more than a chunk less the frame's header");
    {
        // \~english Every frame whole inside the credit: the room counted each frame's header.
        // \~spanish Cada trama entera dentro del credito: el sitio conto la cabecera de cada trama.  \~
        Stream *st = c.q->streams().find(id);
        const uint8_t *p = nullptr;
        const size_t n = st != nullptr && st->recv != nullptr ? st->recv->peek(p) : 0;
        size_t at = 0;
        uint64_t type = 0;
        uint64_t len = 0;
        size_t width = 0;
        std::string payload;
        std::string body;
        bool whole = read_frame(p, n, at, type, len, width, payload) && type == h3::kHeaders;
        while (whole && at < n) {
            whole = read_frame(p, n, at, type, len, width, payload) && type == h3::kData;
            body += payload;
        }
        check(whole && at == n && n <= 3000 && n + slack >= 3000 && body == f.produced,
              "the credit is used up, and no frame is cut by it");
    }
    w.run(w.now + 1000000);
    check(f.fills == stalled, "with no credit left it is not asked");
    f.kick();
    w.settle();
    check(f.fills == stalled, "not even when kicked: no room, no fill (R32)");

    // \~english The client reads: MAX_STREAM_DATA or MAX_DATA comes, and the hungry source is filled with no kick.
    // \~spanish El cliente lee: llega MAX_STREAM_DATA o MAX_DATA, y la fuente hambrienta se rellena sin aviso.  \~
    f.full_fills = 12;
    f.finish = true;
    c.hold = false;
    w.settle();
    check(f.fills > stalled + 10, "the credit the peer raised is filled again (HVX-5, 4.3)");
    check(c.at(id).ended && c.at(id).body == f.produced && f.produced.size() > 20000,
          "and everything produced arrives, in order");
    check(f.gones == 1 && f.last == GoneReason::Finished, "ended once");
    check(w.shard.open_counts().filled_bytes == f.produced.size(), "the port counted every byte");
}

void test_ahead(Crypto &crypto, const Keys &k) {
    section("filled no further ahead than the wire");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    Feed &f = w.feeds[0];
    f.full_fills = 1000000;
    c.hold = true;
    const uint64_t id = c.request("GET", "/open");
    /* \~english
     * Watched while it flows: what the source produced and has not reached
     * the client is either in the air or waiting in the server, and what
     * waits is one chunk at most (HVX-5, 8) -- a peer's large window is not a
     * reason to hold its bytes in memory ahead of the congestion window.
     * \~spanish
     * Mirado mientras fluye: lo que produjo la fuente y no ha llegado al cliente
     * o esta en el aire o esperando en el servidor, y lo que espera es un trozo
     * como mucho (HVX-5, 8) -- una ventana grande del otro no es motivo para
     * guardar sus bytes en memoria por delante de la ventana de congestion.
     * \~ */
    bool bounded = true;
    for (int i = 0; i < 60; ++i) {
        w.run(w.now + 3000);
        size_t in_air = 0;
        for (const Datagram &d : w.air)
            if (d.to == 0) in_air += d.bytes.size();
        Stream *st = c.q->streams().find(id);
        const uint64_t got = st != nullptr && st->recv != nullptr ? st->recv->highest() : 0;
        if (f.produced.size() > got + in_air + h3::Connection::kFillAhead) bounded = false;
    }
    check(f.fills > 3 && bounded, "what waits to be sent never exceeds one chunk");
    f.full_fills = 0;
    f.finish = true;
    c.hold = false;
    f.kick();
    w.settle();
    check(c.at(id).ended && c.at(id).body == f.produced, "and it all arrives");
}

void test_hungry(Crypto &crypto, const Keys &k) {
    section("a full fill is asked again");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    Feed &f = w.feeds[0];
    f.full_fills = 3;
    const uint64_t id = c.request("GET", "/open");
    w.settle();
    check(f.fills == 4, "three full fills are each followed by another; the fourth, short, is the last");
    w.run(w.now + 1000000);
    check(f.fills == 4 && !c.at(id).ended, "a short fill waits for its kick");
    check(c.at(id).body == f.produced, "what was filled arrived");
    f.pending = "z";
    f.finish = true;
    f.kick();
    w.settle();
    check(f.fills == 5 && c.at(id).ended && c.at(id).body == f.produced, "the kick brings the end");
}

void test_head(Crypto &crypto, const Keys &k) {
    section("HEAD does not open");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    const uint64_t id = c.request("HEAD", "/open");
    w.settle();
    check(!w.handler.last.valid(), "the handler's open is refused");
    check(w.feeds[0].fills == 0 && w.feeds[0].gones == 0, "and the source is never used");
    check(c.at(id).status == 200 && c.at(id).body.empty() && c.at(id).ended, "the answer goes whole, with no content");
    check(w.shard.open_counts().opened == 0 && w.shard.open_counts().refused == 0, "the port never saw it");
}

void test_limits(Crypto &crypto, const Keys &k) {
    section("limits and shutdown");
    World w(crypto);
    Http3Config cfg = server_config(k);
    cfg.max_open_per_conn = 2;
    check(w.start(cfg), "the service starts under the shard");
    Client &a = w.add();
    Client &b = w.add();
    w.settle();
    const uint64_t one = a.request("GET", "/open");
    const uint64_t two = a.request("GET", "/open");
    w.settle();
    const uint64_t three = a.request("GET", "/open");
    w.settle();
    check(a.at(three).status == 503 && a.at(three).ended, "one past the connection's limit is answered 503");
    check(w.feeds[2].fills == 0 && w.feeds[2].gones == 0, "and its source is never used");
    check(w.service.counts().open_limited == 1 && w.service.counts().unavailable == 1, "counted");
    check(!a.at(one).ended && !a.at(two).ended, "the two open go on");
    const uint64_t four = b.request("GET", "/open");
    w.settle();
    check(!b.at(four).ended && b.at(four).status == 200 && w.service.open_now() == 3,
          "the limit is per connection: another connection opens");

    // \~english The shard lets go: every source hears Shutdown.  \~spanish El fragmento lo suelta todo: cada fuente oye Shutdown.  \~
    w.shard.release();
    check(w.feeds[0].gones == 1 && w.feeds[0].last == GoneReason::Shutdown && w.feeds[1].gones == 1 &&
              w.feeds[1].last == GoneReason::Shutdown && w.feeds[3].gones == 1 &&
              w.feeds[3].last == GoneReason::Shutdown,
          "on_shutdown ends every open response with Shutdown");
    check(w.service.open_now() == 0, "and nothing is left open");
}

void test_shard_limit(Crypto &crypto, const Keys &k) {
    section("the shard's limit");
    World w(crypto);
    check(w.start(server_config(k), 1), "the service starts under a shard that takes one");
    Client &c = w.add();
    w.settle();
    const uint64_t one = c.request("GET", "/open");
    w.settle();
    const uint64_t two = c.request("GET", "/open");
    w.settle();
    check(!c.at(one).ended && c.at(two).status == 503 && c.at(two).ended, "the second is refused by the shard: 503");
    check(w.shard.open_counts().refused == 1 && w.service.counts().open_limited == 0 &&
              w.service.counts().unavailable == 1,
          "counted by the shard, and answered by the service");
}

void test_peer_reset(Crypto &crypto, const Keys &k) {
    section("the peer stops");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    const uint64_t one = c.request("GET", "/open");
    const uint64_t two = c.request("GET", "/open");
    w.settle();
    Stream *st = c.q->streams().find(one);
    check(st != nullptr && st->recv != nullptr && st->recv->stop(h3::kRequestCancelled), "the client stops reading");
    // \~english Half a round trip on: the STOP_SENDING has arrived, the server's reset is not acknowledged yet.
    // \~spanish Media ida y vuelta despues: el STOP_SENDING llego, el reinicio del servidor aun no esta confirmado.  \~
    w.run(w.now + kDelay + kDelay / 2);
    check(w.feeds[0].gones == 1 && w.feeds[0].last == GoneReason::PeerReset,
          "STOP_SENDING ends it at once: PeerReset, not when the stream is gone");
    w.settle();
    check(w.feeds[0].gones == 1, "and once");
    check(!c.at(one).ended, "and the response never ended cleanly");
    check(w.feeds[1].gones == 0 && !c.at(two).ended, "the other goes on");
    // \~english A cancel: RESET_STREAM and STOP_SENDING together (RFC 9114, 4.1.1).
    // \~spanish Una cancelacion: RESET_STREAM y STOP_SENDING juntos (RFC 9114, 4.1.1).  \~
    c.h->cancel(two, h3::kRequestCancelled);
    w.settle();
    check(w.feeds[1].gones == 1 && w.feeds[1].last == GoneReason::PeerReset, "a cancelled request: PeerReset");
    check(w.service.open_now() == 0 && w.shard.open_counts().open_now == 0, "nothing is left open");
    const uint64_t again = c.request("GET", "/open");
    w.settle();
    check(w.service.open_now() == 1 && c.at(again).status == 200, "and the connection opens again");
}

void test_close(Crypto &crypto, const Keys &k) {
    section("the connection ends");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &a = w.add();
    Client &b = w.add();
    w.settle();
    a.request("GET", "/open");
    b.request("GET", "/open");
    w.settle();
    check(w.service.open_now() == 2, "two open");
    a.q->close(0, true, 0, w.now);
    // \~english As soon as the CONNECTION_CLOSE arrives, not when the draining period is over (RFC 9000, 10.2).
    // \~spanish En cuanto llega el CONNECTION_CLOSE, no cuando acaba el periodo de drenaje (RFC 9000, 10.2).  \~
    w.run(w.now + kDelay + kDelay / 2);
    check(w.feeds[0].gones == 1 && w.feeds[0].last == GoneReason::ConnectionClosed,
          "a connection the peer closed: ConnectionClosed, at once");
    w.settle();
    check(w.feeds[0].gones == 1, "and once");
    check(w.feeds[1].gones == 0, "the other connection's goes on");
    // \~english The other client vanishes: past the idle timeout.  \~spanish El otro cliente desaparece: pasado el plazo de inactividad.  \~
    w.clients.clear();
    w.air.clear();
    w.run(w.now + 60000000);
    check(w.feeds[1].gones == 1 && w.feeds[1].last == GoneReason::IdleTimeout, "a connection that idled out: IdleTimeout");
    check(w.service.open_now() == 0 && w.service.connections() == 0, "nothing is left");
}

void test_release(Crypto &crypto, const Keys &k) {
    section("the service lets go first");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    c.request("GET", "/open");
    w.settle();
    check(w.service.open_now() == 1, "one open");
    // \~english Its connections go with it, and what was open on them hears why.
    // \~spanish Sus conexiones se van con el, y lo que estaba abierto en ellas oye por que.  \~
    w.service.release();
    check(w.feeds[0].gones == 1 && w.feeds[0].last == GoneReason::ConnectionClosed,
          "a connection freed with a response open ends it: ConnectionClosed");
    check(w.service.open_now() == 0 && w.shard.open_counts().open_now == 0, "and the shard's count agrees");
}

void test_clamp(Crypto &crypto, const Keys &k) {
    section("a source that lies");
    World w(crypto);
    check(w.start(server_config(k)), "the service starts under the shard");
    Client &c = w.add();
    w.settle();
    Feed &f = w.feeds[0];
    f.full_fills = 2;
    f.lie = 100;
    f.finish = true;
    const uint64_t id = c.request("GET", "/open");
    w.settle();
    check(c.at(id).ended && c.at(id).body == f.produced, "what it said past its room is not believed");
    check(w.shard.open_counts().filled_bytes == f.produced.size(), "nor counted");
    check(!c.h->failed() && w.service.counts().failed == 0, "and nothing broke");
}

} // namespace

int main() {
    test_support::FakeCrypto fake;
    Keys fk{kFakeCert, sizeof kFakeCert, fake.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert)};
    test_open_kick_done(fake, fk);
    test_frames(fake, fk);
    test_flow_control(fake, fk, false);
    test_flow_control(fake, fk, true);
    test_ahead(fake, fk);
    test_hungry(fake, fk);
    test_head(fake, fk);
    test_limits(fake, fk);
    test_shard_limit(fake, fk);
    test_peer_reset(fake, fk);
    test_close(fake, fk);
    test_release(fake, fk);
    test_clamp(fake, fk);
    fake.forget_key(fk.key);
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("http3 open responses: OK\n");
    return 0;
}
