/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_packet.cpp
 * @brief
 * \~english QUIC packet headers, from the RFC's own packets and from noise.
 * \~spanish Cabeceras de paquete QUIC, de los paquetes del propio RFC y de ruido.
 * \~
 *
 * \~english
 * Two of the packets here are copied from RFC 9001, appendix A: the client's
 * first Initial and a server's Retry.  They are the bytes every implementation
 * was checked against, so a parser that read them wrong would be wrong in a
 * way this project could not have caught by writing its own cases.
 *
 * The last case is noise: tens of thousands of random datagrams, some made to
 * look like QUIC, and one property for all of them -- whatever the parser
 * accepts, every span it hands back lies inside the packet.  That is the
 * property that matters for a parser whose output is about to be decrypted:
 * a span that pointed past the end is a read of somebody else's memory.
 *
 * \~spanish
 * Dos de los paquetes de aqui estan copiados del apendice A del RFC 9001: el
 * primer Initial del cliente y un Retry del servidor.  Son los bytes contra los
 * que se comprobaron todas las implementaciones, asi que un analizador que los
 * leyera mal estaria mal de una forma que este proyecto no podria haber cogido
 * escribiendo sus propios casos.
 *
 * El ultimo caso es ruido: decenas de miles de datagramas al azar, algunos
 * hechos para parecer QUIC, y una propiedad para todos -- lo que acepte el
 * analizador, todos los trozos que devuelva caen dentro del paquete.  Esa es la
 * propiedad que importa en un analizador cuya salida se va a descifrar: un trozo
 * que apuntara mas alla del final es una lectura de la memoria de otro.
 *
 * \~
 */

#include "http_vx/quic_packet.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::quic::HeaderContext;
using http_vx::quic::HeaderError;
using http_vx::quic::PacketHeader;
using http_vx::quic::PacketType;
using http_vx::quic::parse_packet;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english Turns hex text into bytes.  \~spanish Convierte texto hexadecimal en bytes.  \~
size_t from_hex(const char *hex, uint8_t *out, size_t room) {
    size_t n = 0;
    while (hex[0] != '\0' && hex[1] != '\0' && n < room) {
        unsigned v = 0;
        std::sscanf(hex, "%2x", &v);
        out[n++] = static_cast<uint8_t>(v);
        hex += 2;
    }
    return n;
}

/**
 * @brief
 * \~english The first header of RFC 9001, appendix A.2: a client's Initial.
 * \~spanish La primera cabecera del apendice A.2 del RFC 9001: un Initial de cliente.
 * \~
 *
 * \~english
 * Only the header is taken from the RFC -- eighteen bytes, protected first
 * byte included -- and the rest of the 1200-byte datagram is filled in,
 * because what is being checked is where the parser says things are, and the
 * protected bytes after the header are opaque to it by design.
 * \~spanish
 * Del RFC solo se coge la cabecera -- dieciocho bytes, primer byte protegido
 * incluido -- y el resto del datagrama de 1200 bytes se rellena, porque lo que
 * se comprueba es donde dice el analizador que esta cada cosa, y los bytes
 * protegidos que van detras de la cabecera le son opacos a proposito.
 * \~
 */
void test_the_rfc_client_initial() {
    uint8_t d[1200];
    std::memset(d, 0x5a, sizeof d);

    const size_t head =
        from_hex("c000000001088394c8f03e5157080000449e", d, sizeof d);
    check(head == 18, "the RFC header is not eighteen bytes");

    PacketHeader h;
    HeaderContext ctx;
    const HeaderError e = parse_packet(d, sizeof d, ctx, h);

    check(e == HeaderError::None, "the RFC's own Initial was refused");
    check(h.type == PacketType::Initial, "the RFC's Initial is not an Initial");
    check(h.version == 1, "the RFC's Initial is not version 1");
    check(h.dcid.off == 6 && h.dcid.len == 8,
          "the destination connection id is in the wrong place");
    check(std::memcmp(d + h.dcid.off, "\x83\x94\xc8\xf0\x3e\x51\x57\x08", 8) == 0,
          "the destination connection id is not the RFC's");
    check(h.scid.len == 0, "the RFC's Initial has an empty source id");
    check(h.token.len == 0, "the RFC's Initial has no token");

    /* \~english
     * The Length field is `0x449e`, a two-byte integer worth 1182, and it
     * counts from the packet number on: eighteen bytes of header and 1182 of
     * protected packet make exactly the 1200 a client Initial is padded to.
     * \~spanish
     * El campo Length es `0x449e`, un entero de dos bytes que vale 1182, y cuenta
     * desde el numero de paquete: dieciocho bytes de cabecera y 1182 de paquete
     * protegido son justo los 1200 a los que se rellena un Initial de cliente.
     * \~ */
    check(h.pn_offset == 18, "the packet number does not start after the header");
    check(h.size == 1200, "the packet does not end where the RFC says");
}

/**
 * @brief
 * \~english The Retry of RFC 9001, appendix A.4, whole.
 * \~spanish El Retry del apendice A.4 del RFC 9001, entero.
 * \~
 */
void test_the_rfc_retry() {
    uint8_t d[64];
    const size_t n = from_hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba"
                              "2eff4d829058fb3f0f2496ba",
                              d, sizeof d);

    PacketHeader h;
    HeaderContext ctx;
    check(parse_packet(d, n, ctx, h) == HeaderError::None,
          "the RFC's own Retry was refused");
    check(h.type == PacketType::Retry, "the RFC's Retry is not a Retry");
    check(h.dcid.len == 0, "the Retry's destination id should be empty");
    check(h.scid.len == 8, "the Retry's source id is not eight bytes");
    check(h.token.len == 5 && std::memcmp(d + h.token.off, "token", 5) == 0,
          "the Retry's token is not the RFC's");
    check(h.tag.len == 16 && h.tag.off + 16 == n,
          "the integrity tag is not the last sixteen bytes");
    check(h.size == n, "a Retry does not run to the end of the datagram");
}

/**
 * @brief
 * \~english A version this end does not speak is answered, not dropped.
 * \~spanish A una version que no habla este extremo se le contesta, no se tira.
 * \~
 */
void test_versions_this_end_does_not_speak() {
    /* \~english
     * A reserved "greasing" version, which exists precisely to be unknown,
     * with a 21-byte connection ID -- illegal in version 1 and legal here,
     * because the answer has to echo it back.
     * \~spanish
     * Una version reservada de "engrase", que existe justamente para ser
     * desconocida, con un identificador de 21 bytes -- ilegal en la version 1 y
     * legal aqui, porque la respuesta tiene que devolverlo.
     * \~ */
    uint8_t d[64] = {0xc0, 0x0a, 0x1a, 0x2a, 0x3a, 21};
    size_t n = 6 + 21;
    d[n++] = 0;
    n += 10;

    PacketHeader h;
    HeaderContext ctx;
    check(parse_packet(d, n, ctx, h) == HeaderError::None,
          "an unknown version was dropped instead of answered");
    check(h.type == PacketType::UnsupportedVersion,
          "an unknown version was not recognised as one");
    check(h.dcid.len == 21, "a long id of an unknown version was not kept");

    /* \~english
     * And a Version Negotiation packet: version zero, then a list.
     * \~spanish
     * Y un paquete Version Negotiation: version cero, y luego una lista.
     * \~ */
    const uint8_t vn[] = {0x80, 0,    0,    0,    0,    1,    0xab, 1,
                          0xcd, 0,    0,    0,    1,    0x6b, 0x33, 0x43,
                          0xcf};
    check(parse_packet(vn, sizeof vn, ctx, h) == HeaderError::None,
          "a version negotiation packet was refused");
    check(h.type == PacketType::VersionNegotiation,
          "version zero was not read as negotiation");
    check(h.versions.len == 8, "the version list is not two versions");

    const uint8_t crooked[] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    check(parse_packet(crooked, sizeof crooked, ctx, h) ==
              HeaderError::BadVersionList,
          "a list that is not whole versions was accepted");
}

/**
 * @brief
 * \~english Version 2 renumbers the packet types.
 * \~spanish La version 2 renumera los tipos de paquete.
 * \~
 */
void test_version_two_types() {
    uint8_t d[64] = {};
    const size_t head =
        from_hex("d06b3343cf08aaaaaaaaaaaaaaaa000014", d, sizeof d);
    const size_t n = head + 20;

    PacketHeader h;
    HeaderContext ctx;
    check(parse_packet(d, n, ctx, h) == HeaderError::None,
          "a version 2 Initial was refused");
    check(h.type == PacketType::Initial,
          "type bits 01 under version 2 were not read as an Initial");

    d[0] = 0xc0;
    check(parse_packet(d, n, ctx, h) == HeaderError::None &&
              h.type == PacketType::Retry,
          "type bits 00 under version 2 were not read as a Retry");
}

/**
 * @brief
 * \~english Two packets in one datagram are two packets.
 * \~spanish Dos paquetes en un datagrama son dos paquetes.
 * \~
 *
 * \~english
 * An Initial and a Handshake back to back, which is how a client's first
 * flight often arrives.  The first packet's size says where the second
 * starts, and a parser that ran to the end of the datagram would hand the
 * second packet's header to decryption as the first packet's payload.
 * \~spanish
 * Un Initial y un Handshake seguidos, que es como llega muchas veces el primer
 * vuelo de un cliente.  El tamano del primer paquete dice donde empieza el
 * segundo, y un analizador que llegara hasta el final del datagrama le daria al
 * descifrado la cabecera del segundo paquete como carga del primero.
 * \~
 */
void test_coalesced_packets() {
    uint8_t d[256] = {};
    size_t n = from_hex("c00000000104a1a2a3a404b1b2b3b40014", d, sizeof d);
    n += 20;

    const size_t second = n;
    n += from_hex("e00000000104a1a2a3a404b1b2b3b418", d + n, sizeof d - n);
    n += 24;

    PacketHeader h;
    HeaderContext ctx;
    check(parse_packet(d, n, ctx, h) == HeaderError::None,
          "the first coalesced packet was refused");
    check(h.type == PacketType::Initial, "the first coalesced packet is not an Initial");
    check(h.size == second, "the first packet does not end where the second starts");

    check(parse_packet(d + h.size, n - h.size, ctx, h) == HeaderError::None,
          "the second coalesced packet was refused");
    check(h.type == PacketType::Handshake,
          "the second coalesced packet is not a Handshake");
    check(h.size == n - second, "the second packet does not run to the end");
}

/**
 * @brief
 * \~english A short header, whose connection ID length only the receiver knows.
 * \~spanish Una cabecera corta, cuyo identificador solo sabe cuanto mide quien recibe.
 * \~
 */
void test_a_short_header() {
    uint8_t d[64] = {0x41, 1, 2, 3, 4, 5, 6, 7, 8};

    PacketHeader h;
    HeaderContext ctx;
    ctx.short_dcid_len = 8;

    check(parse_packet(d, 9 + 20, ctx, h) == HeaderError::None,
          "a short header was refused");
    check(h.type == PacketType::OneRtt, "a short header is not 1-RTT");
    check(h.dcid.off == 1 && h.dcid.len == 8,
          "the short header's id is not where the context says");
    check(h.pn_offset == 9, "the packet number does not follow the id");

    check(parse_packet(d, 9 + 19, ctx, h) == HeaderError::TooShortToProtect,
          "a short packet too small to sample was accepted");
}

/**
 * @brief
 * \~english Every way a header can be wrong, each dropped for its own reason.
 * \~spanish Cada forma en que una cabecera puede estar mal, tirada por su motivo.
 * \~
 */
void test_what_is_dropped() {
    uint8_t d[1200];
    std::memset(d, 0x5a, sizeof d);
    from_hex("c000000001088394c8f03e5157080000449e", d, sizeof d);

    PacketHeader h;
    HeaderContext ctx;

    /* \~english
     * Every prefix of the header is truncated -- not accepted, and not read
     * past its end.
     * \~spanish
     * Todo prefijo de la cabecera esta truncado -- ni se acepta ni se lee mas
     * alla de su final.
     * \~ */
    for (size_t n = 1; n < 18; ++n)
        check(parse_packet(d, n, ctx, h) == HeaderError::Truncated,
              "a truncated Initial header was not refused as truncated");

    check(parse_packet(d, 1199, ctx, h) == HeaderError::LengthTooLong,
          "a packet claiming more than the datagram was accepted");

    d[5] = 21;
    check(parse_packet(d, sizeof d, ctx, h) == HeaderError::ConnectionIdTooLong,
          "a 21-byte connection id in version 1 was accepted");
    d[5] = 8;

    d[0] = 0x80;
    check(parse_packet(d, sizeof d, ctx, h) == HeaderError::FixedBitClear,
          "a clear fixed bit was accepted without an agreement");

    ctx.fixed_bit_may_be_clear = true;
    check(parse_packet(d, sizeof d, ctx, h) == HeaderError::None,
          "a clear fixed bit was refused although it was agreed");
    ctx.fixed_bit_may_be_clear = false;
    d[0] = 0xc0;

    /* \~english
     * A Length of 19: one short of what header protection needs to take its
     * sample, so the sample would be read past the end of the packet.
     * \~spanish
     * Un Length de 19: uno menos de lo que necesita la proteccion de cabecera
     * para sacar su muestra, asi que la muestra se leeria pasado el final del
     * paquete.
     * \~ */
    d[16] = 0x40;
    d[17] = 19;
    check(parse_packet(d, sizeof d, ctx, h) == HeaderError::TooShortToProtect,
          "a packet too short to sample was accepted");
}

/**
 * @brief
 * \~english Noise: whatever is accepted stays inside the packet.
 * \~spanish Ruido: lo que se acepta se queda dentro del paquete.
 * \~
 */
void test_noise_never_points_outside() {
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    uint8_t d[1400];
    size_t accepted = 0;

    for (int round = 0; round < 50000; ++round) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;

        const size_t n = 1 + static_cast<size_t>(seed % sizeof d);
        uint64_t s = seed;
        for (size_t i = 0; i < n; ++i) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            d[i] = static_cast<uint8_t>(s);
        }

        /* \~english
         * Half the rounds are made to LOOK like version 1, so that the noise
         * gets past the version check and into the fields that matter.
         * Purely random bytes would almost never name a version this end
         * speaks, and the test would be checking the easy path fifty thousand
         * times.
         * \~spanish
         * La mitad de las vueltas se hacen PARECER version 1, para que el ruido
         * pase la comprobacion de version y llegue a los campos que importan.
         * Bytes puramente al azar casi nunca nombrarian una version que habla
         * este extremo, y la prueba estaria comprobando el camino facil
         * cincuenta mil veces.
         * \~ */
        if ((round & 1) != 0 && n >= 6) {
            d[0] = static_cast<uint8_t>(d[0] | 0xc0);
            d[1] = 0;
            d[2] = 0;
            d[3] = 0;
            d[4] = 1;
            d[5] = static_cast<uint8_t>(d[5] % 21);
        }

        PacketHeader h;
        HeaderContext ctx;
        if (parse_packet(d, n, ctx, h) != HeaderError::None) continue;

        ++accepted;

        const bool inside = h.size <= n && h.dcid.off + h.dcid.len <= h.size &&
                            h.scid.off + h.scid.len <= h.size &&
                            h.token.off + h.token.len <= h.size &&
                            h.tag.off + h.tag.len <= h.size &&
                            h.versions.off + h.versions.len <= h.size &&
                            h.pn_offset <= h.size;
        if (!inside) {
            check(false, "an accepted packet has a span outside it");
            return;
        }

        if (h.pn_offset != 0 &&
            h.size - h.pn_offset < http_vx::quic::kSampleOffset +
                                       http_vx::quic::kSampleSize) {
            check(false, "an accepted packet is too short to sample");
            return;
        }
    }

    check(accepted > 1000,
          "the noise was almost all refused, so the property was hardly tested");
}

} // namespace

int main() {
    test_the_rfc_client_initial();
    test_the_rfc_retry();
    test_versions_this_end_does_not_speak();
    test_version_two_types();
    test_coalesced_packets();
    test_a_short_header();
    test_what_is_dropped();
    test_noise_never_points_outside();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
