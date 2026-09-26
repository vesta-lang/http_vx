/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_fuzz.cpp
 * @brief
 * \~english What a stranger reaches before any authentication: Initial packets with mutated contents, against the HTTP/3 service.
 * \~spanish Lo que alcanza un desconocido antes de ninguna autenticacion: paquetes Initial con el contenido mutado, contra el servicio HTTP/3.
 * \~
 *
 * \~english
 * An Initial is protected with keys anyone can derive from its destination
 * ID (RFC 9001, 5.2), so its protection keeps out nobody: whatever is inside
 * reaches the QUIC frame reader and the TLS ClientHello parser of a server
 * that knows nothing about the sender.  Mutating the ciphertext would only
 * test that forgeries are dropped; this mutates the PLAINTEXT -- a real
 * ClientHello in its CRYPTO frame, and frames made up -- and seals it again
 * properly, so every datagram gets all the way in.
 *
 * What must hold whatever arrives:
 *   - nothing crashes, and no datagram takes unbounded work;
 *   - the service never holds more connections than it may, and every one
 *     it took is either live or counted as ended;
 *   - after the idle timeout nothing is left: no connection and no timer.
 *
 * The same file runs under AddressSanitizer and UndefinedBehaviorSanitizer
 * when built with them, which is where a parser that reads a byte too far
 * shows up; a round count may be given as the first argument.
 *
 * \~spanish
 * Un Initial va protegido con claves que cualquiera puede derivar de su
 * identificador de destino (RFC 9001, 5.2), asi que su proteccion no deja
 * fuera a nadie: lo que lleve dentro llega al lector de tramas de QUIC y al
 * analizador del ClientHello de TLS de un servidor que no sabe nada de quien
 * lo manda.  Mutar el texto cifrado solo probaria que se tiran las
 * falsificaciones; esto muta el TEXTO CLARO -- un ClientHello de verdad en su
 * trama CRYPTO, y tramas inventadas -- y lo vuelve a sellar como es debido,
 * asi que cada datagrama llega hasta dentro.
 *
 * Lo que tiene que cumplirse llegue lo que llegue:
 *   - nada revienta, y ningun datagrama cuesta un trabajo sin cota;
 *   - el servicio nunca tiene mas conexiones de las que puede, y cada una que
 *     acepto o esta viva o esta contada como terminada;
 *   - pasado el plazo de inactividad no queda nada: ni conexion ni
 *     temporizador.
 *
 * El mismo fichero corre bajo AddressSanitizer y UndefinedBehaviorSanitizer
 * cuando se compila con ellos, que es donde aparece un analizador que lee un
 * byte de mas; se le puede dar un numero de rondas como primer argumento.
 * \~
 */
#include "http_vx/http3_service.h"
#include "http_vx/quic_protection.h"
#include "http_vx/quic_varint.h"

#include "fake_crypto.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

using namespace http_vx::quic;
using http_vx::Http3Config;
using http_vx::Http3Service;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

uint64_t g_state = 0x9E3779B97F4A7C15ull;
uint64_t next() {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 7;
    g_state ^= g_state << 17;
    return g_state;
}

class Nothing final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &, const uint8_t *, const uint8_t *, size_t,
                http_vx::ResponseBuilder &res) noexcept override {
        res.body("ok", 2);
    }
};

const char *const kH3[] = {"h3"};
const uint8_t kFakeCert[] = {'f', 'a', 'k', 'e', ' ', 'c', 'e', 'r', 't'};
constexpr uint32_t kConnections = 16;

/**
 * @brief
 * \~english The plaintext of a real client's first Initial: its frames, a ClientHello in CRYPTO.
 * \~spanish El texto claro del primer Initial de un cliente de verdad: sus tramas, un ClientHello en CRYPTO.
 * \~
 */
std::vector<uint8_t> real_client_hello(Crypto &crypto) {
    ConnectionConfig cc;
    cc.is_server = false;
    for (int i = 0; i < 8; ++i) cc.peer_cid[i] = static_cast<uint8_t>(0x30 + i);
    Connection client(crypto, cc);
    check(client.ready() && client.set_initial_keys(cc.peer_cid, 8), "the seed client starts");
    http_vx::tls::SessionConfig tls;
    tls.alpn = kH3;
    tls.alpn_count = 1;
    tls.server_name = "example.com";
    tls.trust_any_certificate = true;
    http_vx::tls::QuicHandshake hs(crypto, client, tls);
    check(hs.start(0), "the seed handshake starts");
    uint8_t d[1500];
    Path sent;
    const size_t n = client.build_datagram(sent, d, sizeof d, 0);
    PacketKeys rk;
    PacketKeys wk;
    check(make_initial_keys(crypto, kVersion1, cc.peer_cid, 8, true, rk, wk), "the server's Initial keys");
    HeaderContext hc;
    PacketHeader h;
    Unprotected u;
    std::vector<uint8_t> out;
    if (parse_packet(d, n, hc, h) == HeaderError::None && unprotect_packet(crypto, rk, d, h, 0, u) == Unprotect::Ok)
        out.assign(d + u.payload.off, d + u.payload.off + u.payload.len);
    forget_keys(crypto, rk);
    forget_keys(crypto, wk);
    // \~english Without the padding: the mutations work on what means something.
    // \~spanish Sin el relleno: las mutaciones trabajan sobre lo que significa algo.  \~
    while (!out.empty() && out.back() == 0) out.pop_back();
    check(out.size() > 100, "the seed has a ClientHello in it");
    return out;
}

/// \~english Appends a variable-length integer.  \~spanish Anade un entero de longitud variable.  \~
void put_varint(std::vector<uint8_t> &v, uint64_t x) {
    uint8_t b[8];
    const size_t n = encode_varint(b, sizeof b, x);
    v.insert(v.end(), b, b + n);
}

/**
 * @brief
 * \~english Frames made up: the kinds an Initial may carry, and the kinds it may not, with values that push at limits.
 * \~spanish Tramas inventadas: los tipos que puede llevar un Initial, y los que no, con valores que tientan los limites.
 * \~
 */
std::vector<uint8_t> made_up_frames() {
    std::vector<uint8_t> v;
    const int count = 1 + static_cast<int>(next() % 6);
    for (int i = 0; i < count; ++i) {
        switch (next() % 9) {
        case 0: // PING
            v.push_back(0x01);
            break;
        case 1: { // ACK with ranges that may not fit
            v.push_back(0x02);
            put_varint(v, next() % 1000);
            put_varint(v, next() % 100);
            const uint64_t ranges = next() % 5;
            put_varint(v, ranges);
            put_varint(v, next() % 1000);
            for (uint64_t r = 0; r < ranges; ++r) {
                put_varint(v, next() % 1000);
                put_varint(v, next() % 1000);
            }
            break;
        }
        case 2: { // CRYPTO at any offset, with any length
            v.push_back(0x06);
            put_varint(v, next() % 3 == 0 ? (uint64_t{1} << 62) - 1 - next() % 10 : next() % 70000);
            const uint64_t len = next() % 64;
            put_varint(v, next() % 4 == 0 ? len + next() % 5000 : len);
            for (uint64_t b = 0; b < len; ++b) v.push_back(static_cast<uint8_t>(next()));
            break;
        }
        case 3: // CONNECTION_CLOSE
            v.push_back(0x1c);
            put_varint(v, next() % 0x20);
            put_varint(v, next() % 0x40);
            put_varint(v, next() % 8);
            for (int b = 0; b < 3; ++b) v.push_back(static_cast<uint8_t>(next()));
            break;
        case 4: // STREAM, which an Initial may not carry
            v.push_back(0x0e);
            put_varint(v, next() % 16);
            put_varint(v, next() % 100);
            put_varint(v, 2);
            v.push_back('h');
            v.push_back('i');
            break;
        case 5: // NEW_TOKEN, which a client never sends
            v.push_back(0x07);
            put_varint(v, 4);
            for (int b = 0; b < 4; ++b) v.push_back(static_cast<uint8_t>(next()));
            break;
        case 6: // an unknown type
            put_varint(v, 0x40 + next() % 0x3fff);
            break;
        case 7: // PADDING
            for (uint64_t b = next() % 20; b > 0; --b) v.push_back(0x00);
            break;
        default: // a truncated varint
            v.push_back(0x06);
            v.push_back(0xc0);
            break;
        }
    }
    return v;
}

/// \~english One mutation of @p v, of a kind picked at random.  \~spanish Una mutacion de @p v, de un tipo elegido al azar.  \~
void mutate(std::vector<uint8_t> &v) {
    if (v.empty()) {
        v.push_back(static_cast<uint8_t>(next()));
        return;
    }
    const size_t at = static_cast<size_t>(next() % v.size());
    switch (next() % 7) {
    case 0:
        v[at] ^= static_cast<uint8_t>(1u << (next() % 8));
        break;
    case 1:
        v[at] = static_cast<uint8_t>(next());
        break;
    case 2:
        v.insert(v.begin() + static_cast<long>(at), static_cast<uint8_t>(next()));
        break;
    case 3: {
        const size_t len = 1 + static_cast<size_t>(next() % 16);
        v.erase(v.begin() + static_cast<long>(at), v.begin() + static_cast<long>(at + len < v.size() ? at + len : v.size()));
        break;
    }
    case 4:
        v.resize(at);
        break;
    case 5: {
        const size_t len = 1 + static_cast<size_t>(next() % 32);
        const size_t end = at + len < v.size() ? at + len : v.size();
        std::vector<uint8_t> copy(v.begin() + static_cast<long>(at), v.begin() + static_cast<long>(end));
        v.insert(v.begin() + static_cast<long>(next() % v.size()), copy.begin(), copy.end());
        break;
    }
    default: {
        const std::vector<uint8_t> more = made_up_frames();
        v.insert(v.begin() + static_cast<long>(next() % (v.size() + 1)), more.begin(), more.end());
        break;
    }
    }
}

/**
 * @brief
 * \~english Seals @p frames as a client Initial to a new destination ID, padded to 1200 bytes; its length, or zero.
 * \~spanish Sella @p frames como un Initial de cliente a un identificador de destino nuevo, rellenado a 1200 bytes; su longitud, o cero.
 * \~
 */
size_t seal(Crypto &crypto, const std::vector<uint8_t> &frames, uint8_t *out, size_t room) {
    uint8_t dcid[8];
    uint8_t scid[8];
    for (int i = 0; i < 8; ++i) {
        dcid[i] = static_cast<uint8_t>(next());
        scid[i] = static_cast<uint8_t>(next());
    }
    size_t p = 0;
    out[p++] = 0xc0;
    out[p++] = 0x00;
    out[p++] = 0x00;
    out[p++] = 0x00;
    out[p++] = 0x01;
    out[p++] = 8;
    std::memcpy(out + p, dcid, 8);
    p += 8;
    out[p++] = 8;
    std::memcpy(out + p, scid, 8);
    p += 8;
    out[p++] = 0x00; // no token
    const size_t length_at = p;
    p += 2;
    const size_t pn_offset = p;
    // \~english At least 1200 bytes in all: a smaller client Initial is dropped before anything reads it (RFC 9000, 14.1).
    // \~spanish Al menos 1200 bytes en total: un Initial de cliente menor se tira antes de que nada lo lea (RFC 9000, 14.1).  \~
    const size_t least = kMinInitialDatagram - pn_offset - 1 - kTagSize;
    const size_t body = frames.size() < least ? least : frames.size();
    if (pn_offset + 1 + body + kTagSize > room) return 0;
    std::memset(out + pn_offset + 1, 0, body);
    std::memcpy(out + pn_offset + 1, frames.data(), frames.size());
    encode_varint_width(out + length_at, 2, 1 + body + kTagSize);
    PacketKeys rk;
    PacketKeys wk;
    if (!make_initial_keys(crypto, kVersion1, dcid, 8, false, rk, wk)) return 0;
    const bool ok = protect_packet(crypto, wk, out, pn_offset, 1, next() % 4, body) == Protect::Ok;
    forget_keys(crypto, rk);
    forget_keys(crypto, wk);
    return ok ? pn_offset + 1 + body + kTagSize : 0;
}

Http3Config config(void *key) {
    static const uint8_t *certs[1] = {kFakeCert};
    static const size_t lens[1] = {sizeof kFakeCert};
    Http3Config c;
    for (size_t i = 0; i < sizeof c.connection.reset_key; ++i) {
        c.connection.reset_key[i] = static_cast<uint8_t>(i * 7 + 1);
        c.acceptor.reset_key[i] = c.connection.reset_key[i];
    }
    c.connection.is_server = true;
    c.connection.streams.is_server = true;
    c.connection.idle_timeout_us = 2000000;
    c.tls.server = true;
    c.tls.alpn = kH3;
    c.tls.alpn_count = 1;
    c.tls.certificates = certs;
    c.tls.certificate_lens = lens;
    c.tls.certificate_count = 1;
    c.tls.signing_key = key;
    c.tls.scheme = Scheme::EcdsaSecp256r1Sha256;
    c.h3.server = true;
    c.connections = kConnections;
    return c;
}

/// \~english Every connection taken is live or counted as ended.  \~spanish Cada conexion aceptada esta viva o contada como terminada.  \~
bool accounted(const Http3Service &s) {
    return s.connections() <= kConnections && s.counts().accepted == s.counts().closed + s.connections();
}

} // namespace

int main(int argc, char **argv) {
    const int rounds = argc > 1 ? std::atoi(argv[1]) : 3000;
    test_support::FakeCrypto crypto;
    void *key = crypto.signing_key(Scheme::EcdsaSecp256r1Sha256, kFakeCert, sizeof kFakeCert);
    Nothing handler;
    Http3Service service(crypto, handler);
    check(service.start(config(key)), "the service starts");
    const std::vector<uint8_t> seed = real_client_hello(crypto);

    Path path;
    uint8_t out[1500];
    uint8_t reply[1500];
    uint64_t now = 1000;
    bool held = true;
    for (int r = 0; r < rounds && held; ++r) {
        std::vector<uint8_t> frames = next() % 8 == 0 ? made_up_frames() : seed;
        const int times = 1 + static_cast<int>(next() % 4);
        for (int m = 0; m < times; ++m) mutate(frames);
        const size_t n = seal(crypto, frames, out, sizeof out);
        if (n == 0) continue;
        path.peer.len = 6;
        for (int b = 0; b < 6; ++b) path.peer.bytes[b] = static_cast<uint8_t>(next());
        service.on_datagram(path, out, n, Ecn::NotEct, now);
        // \~english What it answers is taken, all of it: a service that never stops answering is a failure too.
        // \~spanish Lo que contesta se recoge, todo: un servicio que no deja de contestar tambien es un fallo.  \~
        Path to;
        int answered = 0;
        while (service.next_datagram(to, reply, sizeof reply, now) != 0 && answered < 1000) ++answered;
        if (answered >= 1000) {
            check(false, "one datagram in made the service answer without end");
            held = false;
        }
        // \~english A tenth of a second a round: failed handshakes run out their closing time and free their slots.
        // \~spanish Una decima de segundo por ronda: los saludos fallidos agotan su cierre y liberan su casilla.  \~
        now += 100000;
        if (service.timer() <= now) service.on_timer(now);
        if (!accounted(service)) {
            check(false, "every connection taken is live or ended, and never more than allowed");
            held = false;
        }
    }
    // \~english Past every idle timeout: nothing may be left.  \~spanish Pasado todo plazo de inactividad: no puede quedar nada.  \~
    for (int i = 0; i < 100 && service.timer() != kNever; ++i) {
        now = service.timer() > now ? service.timer() : now;
        service.on_timer(now);
        Path to;
        while (service.next_datagram(to, reply, sizeof reply, now) != 0) {
        }
    }
    check(service.connections() == 0 && service.timer() == kNever, "after the idle timeout nothing is left");
    check(accounted(service), "and every connection taken was counted as ended");
    // \~english A fuzzer whose input never gets in tests nothing: most rounds must reach a connection.
    // \~spanish Un fuzzer cuya entrada nunca entra no prueba nada: la mayoria de rondas tienen que llegar a una conexion.  \~
    check(service.counts().accepted > static_cast<uint64_t>(rounds) / 4,
          "the datagrams got in: at least a quarter of the rounds made a connection");
    std::printf("quic fuzz: %d rounds, %llu connections taken, %llu stateless replies, %llu full\n", rounds,
                static_cast<unsigned long long>(service.counts().accepted),
                static_cast<unsigned long long>(service.counts().replies),
                static_cast<unsigned long long>(service.counts().full));
    service.release();
    crypto.forget_key(key);
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic fuzz: OK\n");
    return 0;
}
