/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_http3_datagrams.cpp
 * @brief
 * \~english The HTTP/3 service as a shard's datagram side: addresses and ECN across, and time translated.
 * \~spanish El servicio HTTP/3 como lado de datagramas de un shard: direcciones y ECN al otro lado, y el tiempo traducido.
 * \~
 *
 * \~english
 * The clock is the test's, so every timer answer can be checked at the exact
 * microsecond: due or not yet in the shard's terms, never "none" while a
 * timer runs, and the loop's wait rounded up so it does not wake early.  The
 * shard's own time, given in ticks, must not matter at all.
 * \~spanish
 * El reloj es de la prueba, asi que cada respuesta del temporizador se puede
 * comprobar al microsegundo: vencido o aun no en los terminos del shard, nunca
 * "ninguno" mientras corre uno, y la espera del bucle redondeada hacia arriba
 * para que no despierte antes.  El tiempo propio del shard, dado en tics, no
 * tiene que importar en absoluto.
 * \~
 */
#include "http_vx/http3_datagrams.h"
#include "http_vx/tls_quic.h"

#include "fake_crypto.h"

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

uint64_t g_now = 1000000;
uint64_t test_clock() { return g_now; }

class Nothing final : public Handler {
  public:
    void handle(const Request &, const uint8_t *, const uint8_t *, size_t, ResponseBuilder &res) noexcept override {
        res.body("ok", 2);
    }
};

const char *const kH3[] = {"h3"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};

Http3Config config(void *key) {
    static const uint8_t *certs[1] = {kFakeCert};
    static const size_t lens[1] = {sizeof kFakeCert};
    Http3Config c;
    for (size_t i = 0; i < sizeof c.connection.reset_key; ++i) {
        c.connection.reset_key[i] = static_cast<uint8_t>(i + 1);
        c.acceptor.reset_key[i] = c.connection.reset_key[i];
    }
    c.connection.is_server = true;
    c.connection.streams.is_server = true;
    c.tls.server = true;
    c.tls.alpn = kH3;
    c.tls.alpn_count = 1;
    c.tls.certificates = certs;
    c.tls.certificate_lens = lens;
    c.tls.certificate_count = 1;
    c.tls.signing_key = key;
    c.tls.scheme = quic::Scheme::EcdsaSecp256r1Sha256;
    c.h3.server = true;
    c.connections = 4;
    return c;
}

NetAddress address(uint8_t last) {
    NetAddress a;
    a.len = 6;
    const uint8_t b[6] = {198, 51, 100, last, 0x1f, 0x90};
    for (int i = 0; i < 6; ++i) a.bytes[i] = b[i];
    return a;
}

void test_idle() {
    // \~english A clock near zero: "no timer" must not turn into arithmetic that wraps round.
    // \~spanish Un reloj cerca de cero: "ningun temporizador" no puede convertirse en una cuenta que de la vuelta.  \~
    g_now = 0;
    test_support::FakeCrypto crypto;
    Nothing handler;
    Http3Service service(crypto, handler);
    Http3Datagrams d(service, test_clock);
    check(d.timer() == kNoDatagramTimer, "no service started, no timer");
    check(d.wait_ms(250) == 250, "and the loop waits its whole bound");
}

void test_addresses_and_time() {
    // \~english Far from the shard's ticks, so a time taken from them would land in the past.
    // \~spanish Lejos de los tics del shard, para que un tiempo tomado de ellos caiga en el pasado.  \~
    g_now = 100000000;
    test_support::FakeCrypto crypto;
    void *key = crypto.signing_key(quic::Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
    Nothing handler;
    Http3Service service(crypto, handler);
    check(service.start(config(key)), "the service starts");
    Http3Datagrams d(service, test_clock);

    // \~english A short header nobody owns: the stateless reset goes back to where it came from.
    // \~spanish Una cabecera corta de nadie: el reinicio sin estado vuelve a donde vino.  \~
    DatagramPath in;
    in.local = address(1);
    in.peer = address(77);
    uint8_t junk[100];
    std::memset(junk, 0x5a, sizeof junk);
    junk[0] = 0x40;
    d.on_datagram(in, junk, sizeof junk, EcnMark::Ect0, 12345);
    DatagramPath out;
    uint8_t reply[1500];
    const size_t n = d.next_datagram(out, reply, sizeof reply, 12345);
    check(n != 0 && out.peer.len == 6 && std::memcmp(out.peer.bytes, in.peer.bytes, 6) == 0,
          "the answer goes to the address it came from, bytes and length");
    check(d.next_datagram(out, reply, sizeof reply, 0) == 0, "and then nothing more");

    // \~english A real client's first datagram: a connection, and its timers.
    // \~spanish El primer datagrama de un cliente de verdad: una conexion, y sus temporizadores.  \~
    quic::ConnectionConfig cc;
    cc.is_server = false;
    for (int i = 0; i < 8; ++i) cc.peer_cid[i] = static_cast<uint8_t>(0x30 + i);
    quic::Connection client(crypto, cc);
    check(client.ready() && client.set_initial_keys(cc.peer_cid, 8), "the client starts");
    tls::SessionConfig tc;
    tc.alpn = kH3;
    tc.alpn_count = 1;
    tc.trust_any_certificate = true;
    tls::QuicHandshake hs(crypto, client, tc);
    check(hs.start(0), "its handshake starts");
    uint8_t first[1500];
    quic::Path sent;
    const size_t fn = client.build_datagram(sent, first, sizeof first, 0);
    // \~english The shard's now is a tick, and nonsense for QUIC: it must be ignored.
    // \~spanish El now del shard es un tic, y para QUIC no significa nada: se tiene que ignorar.  \~
    d.on_datagram(in, first, fn, EcnMark::NotEct, 7);
    check(service.connections() == 1, "the connection is made");
    while (d.next_datagram(out, reply, sizeof reply, 7) != 0) {
    }
    const uint64_t due = service.timer();
    check(due != quic::kNever && due > g_now, "a timer runs, in the future of the adapter's clock");
    check(d.timer() == kNoDatagramTimer - 1, "not due yet: past any tick, and not 'none'");
    g_now = due - 1500;
    check(d.wait_ms(250) == 2, "the wait rounds up: 1.5 ms is 2, not 1");
    check(d.wait_ms(1) == 1, "and never more than the bound");
    g_now = due;
    check(d.timer() == 0 && d.wait_ms(250) == 0, "due: zero, which every tick reaches");
    g_now = due + 5000;
    check(d.wait_ms(250) == 0, "overdue: no wait at all, and no subtraction that wraps round");
    d.on_timer(0);
    check(service.timer() != due, "on_timer ran the service's timer by the adapter's clock, not the tick");
    service.release();
    crypto.forget_key(key);
}

} // namespace

int main() {
    test_idle();
    test_addresses_and_time();
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("http3 datagrams: OK\n");
    return 0;
}
