/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_protection.cpp
 * @brief
 * \~english QUIC packet protection without any cryptography: the QUIC logic on its own.
 * \~spanish La proteccion de paquetes de QUIC sin criptografia: la logica de QUIC por su cuenta.
 * \~
 *
 * \~english
 * Everything here runs against a fake provider, on purpose.  The QUIC logic --
 * which bits are masked, where the sample is taken, how the nonce is built,
 * what the associated data covers, which failure means what -- is this
 * project's, and it has to be checkable on a machine with no cryptographic
 * library at all.  `test_quic_vectors` checks it again with a real provider
 * against the RFC's full packets; this one is what still runs when there is
 * none.
 *
 * The fake is not a no-op.  Its "AEAD" mixes the nonce into every byte and
 * its tag covers the associated data and the plaintext, so a nonce built from
 * the wrong packet number or a header left out of the associated data fails
 * here just as it would with AES.  And its mask depends on the sample, so a
 * sample taken from the wrong place gives a header that does not come back.
 *
 * \~spanish
 * Todo aqui corre contra un proveedor de mentira, a proposito.  La logica de
 * QUIC -- que bits se enmascaran, de donde se saca la muestra, como se construye
 * el nonce, que cubren los datos asociados, que fallo quiere decir que -- es de
 * este proyecto, y tiene que poder comprobarse en una maquina sin ninguna
 * biblioteca criptografica.  `test_quic_vectors` lo vuelve a comprobar con un
 * proveedor de verdad contra los paquetes enteros del RFC; este es el que sigue
 * corriendo cuando no lo hay.
 *
 * La mentira no es no hacer nada.  Su "AEAD" mezcla el nonce en cada byte y su
 * marca cubre los datos asociados y el texto claro, asi que un nonce hecho con
 * el numero de paquete equivocado o una cabecera que se quedara fuera de los
 * datos asociados falla aqui igual que fallaria con AES.  Y su mascara depende
 * de la muestra, asi que una muestra sacada del sitio equivocado da una cabecera
 * que no vuelve.
 * \~
 */

#include "http_vx/quic_packet.h"
#include "http_vx/quic_protection.h"

#include <cstdio>
#include <cstring>
#include <random>

namespace {

using namespace http_vx::quic;

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

/// \~english Whether @p p holds exactly the bytes of @p hex.
/// \~spanish Si @p p tiene exactamente los bytes de @p hex.  \~
bool same_as(const uint8_t *p, const char *hex) {
    uint8_t want[256];
    const size_t n = from_hex(hex, want, sizeof want);
    return std::memcmp(p, want, n) == 0;
}

/**
 * @brief
 * \~english A provider with no cryptography in it, that still behaves like one where it matters.
 * \~spanish Un proveedor sin criptografia dentro, que aun asi se porta como uno donde importa.
 * \~
 */
class FakeCrypto final : public Crypto {
public:
    /// \~english When set, the mask is this and not a function of the sample.
    /// \~spanish Si se pone, la mascara es esta y no una funcion de la muestra.  \~
    bool fixed_mask = false;
    uint8_t the_mask[kMaskSize] = {};

    /// \~english Makes every primitive fail, as a broken provider would.
    /// \~spanish Hace fallar todas las primitivas, como un proveedor roto.  \~
    bool broken = false;

    /// \~english When set, the mask is refused for any sample but this one.
    /// \~spanish Si se pone, la mascara se niega para cualquier muestra que no sea esta.  \~
    bool check_sample = false;
    uint8_t expected_sample[kSampleSize] = {};

    const char *name() const noexcept override { return "fake"; }

    bool extract(Hash, const uint8_t *, size_t, const uint8_t *, size_t,
                 uint8_t *) noexcept override {
        return false;
    }
    bool expand(Hash, const uint8_t *, size_t, const uint8_t *, size_t,
                uint8_t *, size_t) noexcept override {
        return false;
    }

    // \~english Any non-null pointer will do; nothing is kept behind it.
    // \~spanish Vale cualquier puntero no nulo; detras no se guarda nada.  \~
    void *prepare_aead(Aead, const uint8_t *) noexcept override { return this; }
    void *prepare_hp(Aead, const uint8_t *) noexcept override { return this; }
    void forget(void *) noexcept override {}

    bool seal(void *, const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
              const uint8_t *in, size_t n, uint8_t *out) noexcept override {
        if (broken) return false;
        uint8_t tag[kTagSize];
        make_tag(nonce, ad, ad_len, in, n, tag);
        for (size_t i = 0; i < n; ++i) out[i] = in[i] ^ stream(nonce, i);
        std::memcpy(out + n, tag, kTagSize);
        return true;
    }

    OpenResult open(void *, const uint8_t *nonce, const uint8_t *ad,
                    size_t ad_len, const uint8_t *in, size_t n,
                    uint8_t *out) noexcept override {
        if (broken) return OpenResult::Failed;
        if (n < kTagSize) return OpenResult::Forged;
        const size_t body = n - kTagSize;
        uint8_t got[kTagSize];
        std::memcpy(got, in + body, kTagSize);
        for (size_t i = 0; i < body; ++i) out[i] = in[i] ^ stream(nonce, i);
        uint8_t want[kTagSize];
        make_tag(nonce, ad, ad_len, out, body, want);
        return std::memcmp(got, want, kTagSize) == 0 ? OpenResult::Ok
                                                     : OpenResult::Forged;
    }

    bool mask(void *, const uint8_t *sample, uint8_t *out) noexcept override {
        if (broken) return false;
        if (check_sample && std::memcmp(sample, expected_sample, kSampleSize) != 0)
            return false;
        for (size_t i = 0; i < kMaskSize; ++i)
            out[i] = fixed_mask ? the_mask[i]
                                : static_cast<uint8_t>(sample[i] ^ sample[15 - i] ^ 0xA5);
        return true;
    }

private:
    static uint8_t stream(const uint8_t *nonce, size_t i) {
        return static_cast<uint8_t>(nonce[i % kNonceSize] + 31 * i);
    }

    /// \~english An FNV-style checksum over nonce, associated data and plaintext.
    /// \~spanish Una suma de comprobacion al estilo FNV sobre nonce, datos asociados y texto claro.  \~
    static void make_tag(const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                         const uint8_t *pt, size_t n, uint8_t *tag) {
        uint64_t a = 1469598103934665603ull;
        uint64_t b = 0x9E3779B97F4A7C15ull;
        for (size_t i = 0; i < kNonceSize; ++i) a = (a ^ nonce[i]) * 1099511628211ull;
        for (size_t i = 0; i < ad_len; ++i) a = (a ^ ad[i]) * 1099511628211ull;
        b ^= ad_len;
        for (size_t i = 0; i < n; ++i) b = (b ^ pt[i]) * 1099511628211ull;
        for (size_t i = 0; i < 8; ++i) {
            tag[i] = static_cast<uint8_t>(a >> (8 * i));
            tag[8 + i] = static_cast<uint8_t>(b >> (8 * i));
        }
    }
};

/**
 * @brief
 * \~english The labels RFC 9001 and RFC 9369 print byte by byte.
 * \~spanish Las etiquetas que el RFC 9001 y el RFC 9369 imprimen byte a byte.
 * \~
 */
void test_labels_are_the_rfcs() {
    struct Case {
        const char *label;
        size_t len;
        const char *hex;
    };
    const Case cases[] = {
        {"client in", 32, "00200f746c73313320636c69656e7420696e00"},
        {"server in", 32, "00200f746c7331332073657276657220696e00"},
        {"quic key", 16, "00100e746c7331332071756963206b657900"},
        {"quic iv", 12, "000c0d746c733133207175696320697600"},
        {"quic hp", 16, "00100d746c733133207175696320687000"},
        {"quicv2 key", 16, "001010746c73313320717569637632206b657900"},
        {"quicv2 iv", 12, "000c0f746c7331332071756963763220697600"},
        {"quicv2 hp", 16, "00100f746c7331332071756963763220687000"},
    };

    for (const Case &c : cases) {
        uint8_t got[64];
        uint8_t want[64];
        const size_t n = hkdf_label(got, sizeof got, c.label, c.len);
        const size_t w = from_hex(c.hex, want, sizeof want);
        if (n != w || std::memcmp(got, want, n) != 0) {
            std::fprintf(stderr, "FAIL: the label \"%s\" is not the RFC's\n", c.label);
            ++failures;
        }
    }

    uint8_t small[8];
    check(hkdf_label(small, sizeof small, "client in", 32) == 0,
          "a label was written into a buffer too small for it");
}

/**
 * @brief
 * \~english Packet numbers: RFC 9000's worked examples, and the edges around them.
 * \~spanish Numeros de paquete: los ejemplos resueltos del RFC 9000, y los bordes de alrededor.
 * \~
 */
void test_packet_numbers() {
    // \~english RFC 9000, A.3.  \~spanish RFC 9000, A.3.  \~
    check(decode_packet_number(0xa82f30eb, 0x9b32, 2) == 0xa82f9b32,
          "the RFC's decoding example gives another number");

    check(decode_packet_number(0, 0, 1) == 0, "the first packet is not zero");
    check(decode_packet_number(1, 0xff, 1) == 0xff,
          "early in a connection a number was taken for a negative one");
    check(decode_packet_number(0x1f0, 0x05, 1) == 0x205,
          "a number past the window's wrap came back a window short");
    check(decode_packet_number(0x205, 0xf0, 1) == 0x1f0,
          "a late packet from before the wrap came back a window ahead");

    // \~english RFC 9000, A.2.  \~spanish RFC 9000, A.2.  \~
    check(packet_number_length(0xac5c02, 0xabe8b3, true) == 2,
          "the RFC's first length example is not two bytes");
    check(packet_number_length(0xace8fe, 0xabe8b3, true) == 3,
          "the RFC's second length example is not three bytes");

    check(packet_number_length(0, 0, false) == 1, "the first packet is not one byte");
    check(packet_number_length(127, 0, false) == 1,
          "128 packets unacknowledged do not fit one byte's half window");
    check(packet_number_length(128, 0, false) == 2,
          "129 packets unacknowledged were squeezed into one byte");
    check(packet_number_length(5, 5, true) == 0,
          "a number that was already acknowledged got a length");
    check(packet_number_length(uint64_t{1} << 40, 0, true) == 0,
          "more than 2^31 packets in flight got a length");

    /* \~english
     * Whatever length the sender picks, the receiver -- however far behind,
     * down to the largest acknowledged -- has to decode it back.
     * \~spanish
     * Elija la longitud que elija el emisor, quien recibe -- por muy atrasado
     * que vaya, hasta el mayor confirmado -- lo tiene que descodificar de vuelta.
     * \~ */
    std::mt19937_64 rng(9000);
    for (int i = 0; i < 100000; ++i) {
        const uint64_t acked = rng() % (uint64_t{1} << 40);
        const uint64_t pn = acked + 1 + rng() % (uint64_t{1} << (rng() % 31));
        const size_t len = packet_number_length(pn, acked, true);
        if (len == 0) continue;
        const uint64_t truncated = pn & ((uint64_t{1} << (8 * len)) - 1);
        const uint64_t expected = acked + 1 + rng() % (pn - acked);
        if (decode_packet_number(expected, truncated, len) != pn) {
            std::fprintf(stderr,
                         "FAIL: pn %llu sent in %zu bytes decoded wrong with %llu expected\n",
                         static_cast<unsigned long long>(pn), len,
                         static_cast<unsigned long long>(expected));
            ++failures;
            return;
        }
    }
}

/// \~english The nonces of RFC 9001 A.5 and RFC 9369 A.5.
/// \~spanish Los nonces del RFC 9001 A.5 y del RFC 9369 A.5.  \~
void test_nonces() {
    uint8_t iv[kNonceSize];
    uint8_t nonce[kNonceSize];

    from_hex("e0459b3474bdd0e44a41c144", iv, sizeof iv);
    make_nonce(iv, 654360564, nonce);
    check(same_as(nonce, "e0459b3474bdd0e46d417eb0"), "the version 1 nonce is not the RFC's");

    from_hex("a6b5bc6ab7dafce30ffff5dd", iv, sizeof iv);
    make_nonce(iv, 654360564, nonce);
    check(same_as(nonce, "a6b5bc6ab7dafce328ff4a29"), "the version 2 nonce is not the RFC's");

    /* \~english
     * Both RFC numbers fit in 32 bits, so a nonce that only took the low four
     * bytes of the packet number would pass them -- and reuse a nonce after
     * four billion packets, which with GCM gives the key away.
     * \~spanish
     * Los dos numeros del RFC caben en 32 bits, asi que un nonce que solo
     * cogiera los cuatro bytes bajos del numero de paquete los pasaria -- y
     * repetiria nonce tras cuatro mil millones de paquetes, que con GCM regala
     * la clave.
     * \~ */
    std::memset(iv, 0, sizeof iv);
    make_nonce(iv, 0x3fedcba987654321ull, nonce);
    check(same_as(nonce, "000000003fedcba987654321"),
          "the nonce does not take all of a large packet number");
}

/**
 * @brief
 * \~english The sample is taken where the RFC takes it, from the RFC's own ciphertext.
 * \~spanish La muestra se saca de donde la saca el RFC, del propio texto cifrado del RFC.
 * \~
 *
 * \~english
 * The RFC prints the sample of each packet, and its protected packets carry
 * real ciphertext.  So a provider that answers only when it is handed exactly
 * that sample checks the offset without any cryptography: taken from four
 * bytes past the packet number or not taken at all.
 * \~spanish
 * El RFC imprime la muestra de cada paquete, y sus paquetes protegidos llevan
 * texto cifrado de verdad.  Asi que un proveedor que solo contesta cuando le dan
 * exactamente esa muestra comprueba el desplazamiento sin criptografia: se saca
 * de cuatro bytes detras del numero de paquete o no se saca.
 * \~
 */
void test_sample_is_taken_where_the_rfc_says() {
    struct Case {
        const char *what;
        const char *packet;
        size_t size;
        size_t short_dcid;
        const char *sample;
        const char *mask;
        uint8_t first;
        uint64_t pn;
    };
    const Case cases[] = {
        {"client Initial",
         "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
         "d242b123dc9b",
         1200, 0, "d1b1c98dd7689fb8ec11d242b123dc9b", "437b9aec36", 0xc3, 2},
        {"server Initial",
         "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
         "5816b6394100",
         135, 0, "2cd0991cd25b0aac406a5816b6394100", "2ec0d8356a", 0xc1, 1},
        {"short packet", "4cfe4189655e5cd55c41f69080575d7999c25a5bfb", 21, 0,
         "5e5cd55c41f69080575d7999c25a5bfb", "aefefe7d03", 0x42, 654360564},

        /* \~english
         * RFC 9369's short packet, and not only for version 2: its mask
         * starts 0x97, whose fifth bit is set, while version 1's starts 0xae,
         * whose fifth bit is not -- so only this one tells masking five bits
         * of a short header from masking four.
         * \~spanish
         * El paquete corto del RFC 9369, y no solo por la version 2: su mascara
         * empieza por 0x97, que tiene el quinto bit puesto, mientras la de la
         * version 1 empieza por 0xae, que no lo tiene -- asi que solo este
         * distingue enmascarar cinco bits de una cabecera corta de enmascarar
         * cuatro.
         * \~ */
        {"version 2 short packet", "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba", 21, 0,
         "e7b6b932bc27d786f4bc2bb20f2162ba", "97580e32bf", 0x42, 654360564},
    };

    for (const Case &k : cases) {
        FakeCrypto c;
        c.fixed_mask = true;
        from_hex(k.mask, c.the_mask, kMaskSize);
        from_hex(k.sample, c.expected_sample, kSampleSize);
        c.check_sample = true;

        uint8_t p[1200] = {};
        from_hex(k.packet, p, sizeof p);
        HeaderContext ctx;
        ctx.short_dcid_len = k.short_dcid;
        PacketHeader h;
        Unprotected u;
        const bool ok = parse_packet(p, k.size, ctx, h) == HeaderError::None &&
                        unmask_header(c, &c, p, h, k.pn, u) == Unprotect::Ok &&
                        u.first == k.first && u.pn == k.pn;
        if (!ok) {
            std::fprintf(stderr, "FAIL: the %s's header does not unmask with the RFC's sample\n",
                         k.what);
            ++failures;
        }
    }
}

/**
 * @brief
 * \~english Lays out a long-header packet: header from @p hex, zeros after.
 * \~spanish Dispone un paquete de cabecera larga: la cabecera de @p hex, ceros detras.
 * \~
 */
size_t lay_out(uint8_t *p, size_t room, const char *hex) {
    std::memset(p, 0, room);
    return from_hex(hex, p, room);
}

/**
 * @brief
 * \~english Header protection, given the RFC's masks: the headers come out as printed.
 * \~spanish La proteccion de cabecera, dadas las mascaras del RFC: las cabeceras salen como estan impresas.
 * \~
 *
 * \~english
 * The mask is what AES gives, and that part is the provider's; what is QUIC's
 * is which bits of which bytes it lands on, and that is what these check.
 * \~spanish
 * La mascara es lo que da AES, y esa parte es del proveedor; lo que es de QUIC
 * es en que bits de que bytes cae, y eso es lo que comprueban estos.
 * \~
 */
void test_header_protection_lands_where_the_rfc_says() {
    FakeCrypto c;
    c.fixed_mask = true;
    PacketKeys k;
    k.aead_state = &c;
    k.hp_state = &c;

    // \~english RFC 9001, A.2: a client Initial with a four-byte packet number.
    // \~spanish RFC 9001, A.2: un Initial de cliente con un numero de paquete de cuatro bytes.  \~
    {
        uint8_t p[1200];
        lay_out(p, sizeof p, "c300000001088394c8f03e5157080000449e");
        from_hex("437b9aec36", c.the_mask, kMaskSize);
        check(protect_packet(c, k, p, 18, 4, 2, 1162) == Protect::Ok,
              "the RFC's client Initial could not be protected");
        check(same_as(p, "c000000001088394c8f03e5157080000449e7b9aec34"),
              "the client Initial's protected header is not the RFC's");

        PacketHeader h;
        check(parse_packet(p, sizeof p, HeaderContext{}, h) == HeaderError::None,
              "the protected client Initial does not parse");
        Unprotected u;
        check(unprotect_packet(c, k, p, h, 0, u) == Unprotect::Ok,
              "the protected client Initial does not come back");
        check(u.pn == 2 && u.pn_len == 4 && u.first == 0xc3,
              "the client Initial came back with another number");
        check(u.payload.off == 22 && u.payload.len == 1162,
              "the client Initial's payload is in the wrong place");
    }

    // \~english RFC 9001, A.3: a server Initial with a two-byte packet number.
    // \~spanish RFC 9001, A.3: un Initial de servidor con un numero de paquete de dos bytes.  \~
    {
        uint8_t p[135];
        lay_out(p, sizeof p, "c1000000010008f067a5502a4262b5004075");
        from_hex("2ec0d8356a", c.the_mask, kMaskSize);
        check(protect_packet(c, k, p, 18, 2, 1, 99) == Protect::Ok,
              "the RFC's server Initial could not be protected");
        check(same_as(p, "cf000000010008f067a5502a4262b5004075c0d9"),
              "the server Initial's protected header is not the RFC's");
    }

    // \~english RFC 9001, A.5: a short header, which masks five bits and not four.
    // \~spanish RFC 9001, A.5: una cabecera corta, que enmascara cinco bits y no cuatro.  \~
    {
        uint8_t p[21];
        lay_out(p, sizeof p, "42");
        p[4] = 0x01;
        from_hex("aefefe7d03", c.the_mask, kMaskSize);
        check(protect_packet(c, k, p, 1, 3, 654360564, 1) == Protect::Ok,
              "the RFC's short packet could not be protected");
        check(same_as(p, "4cfe4189"), "the short header is not the RFC's");

        HeaderContext ctx;
        ctx.short_dcid_len = 0;
        PacketHeader h;
        check(parse_packet(p, sizeof p, ctx, h) == HeaderError::None,
              "the smallest possible packet does not parse");
        Unprotected u;
        check(unprotect_packet(c, k, p, h, 654360564, u) == Unprotect::Ok &&
                  u.pn == 654360564 && u.payload.len == 1 && p[u.payload.off] == 0x01,
              "the smallest possible packet does not come back");
    }
}

/// \~english A packet laid out, protected and parsed, ready to be tampered with.
/// \~spanish Un paquete dispuesto, protegido y analizado, listo para manipularlo.  \~
struct Built {
    uint8_t p[200];
    PacketHeader h;
};

/// \~english An Initial with @p first as its first byte, protected by @p c.
/// \~spanish Un Initial con @p first como primer byte, protegido por @p c.  \~
bool build(FakeCrypto &c, const PacketKeys &k, uint8_t first, Built &b) {
    // \~english 18-byte header, 2-byte pn, 60 bytes of payload, tag: Length 78.
    // \~spanish Cabecera de 18 bytes, pn de 2, 60 de carga y marca: Length 78.  \~
    lay_out(b.p, sizeof b.p, "c300000001088394c8f03e5157080000404e");
    b.p[0] = first;
    for (size_t i = 0; i < 60; ++i) b.p[20 + i] = static_cast<uint8_t>(i * 7);
    if (protect_packet(c, k, b.p, 18, 2, 77, 60) != Protect::Ok) return false;
    return parse_packet(b.p, 18 + 2 + 60 + kTagSize, HeaderContext{}, b.h) ==
           HeaderError::None;
}

/**
 * @brief
 * \~english Each failure is told apart from the others.
 * \~spanish Cada fallo se distingue de los demas.
 * \~
 */
void test_each_failure_is_its_own() {
    FakeCrypto c;
    PacketKeys k;
    k.aead_state = &c;
    k.hp_state = &c;
    Unprotected u;

    Built b;
    check(build(c, k, 0xc1, b), "a packet to tamper with could not be built");
    {
        Built t = b;
        check(unprotect_packet(c, k, t.p, t.h, 0, u) == Unprotect::Ok && u.pn == 77,
              "an untouched packet did not come back");
        for (size_t i = 0; i < 60; ++i)
            if (t.p[20 + i] != static_cast<uint8_t>(i * 7)) {
                check(false, "the plaintext did not come back as it went");
                break;
            }
    }

    /* \~english
     * A header byte changed on the path: nothing masks it, so only the
     * associated data can catch it.  A header left out of it would let this
     * through.
     * \~spanish
     * Un byte de la cabecera cambiado en el camino: nada lo enmascara, asi que
     * solo lo pueden coger los datos asociados.  Una cabecera que se quedara
     * fuera de ellos lo dejaria pasar.
     * \~ */
    {
        Built t = b;
        t.p[8] ^= 0x01;
        check(unprotect_packet(c, k, t.p, t.h, 0, u) == Unprotect::Forged,
              "a header changed on the path was not caught");
    }
    {
        Built t = b;
        t.p[40] ^= 0x80;
        check(unprotect_packet(c, k, t.p, t.h, 0, u) == Unprotect::Forged,
              "a payload changed on the path was not caught");
    }

    /* \~english
     * Reserved bits set by the key holder: authenticated, so it is the peer
     * breaking the protocol, not a forgery.
     * \~spanish
     * Bits reservados puestos por quien tiene la clave: autenticado, asi que es
     * el otro extremo rompiendo el protocolo, no una falsificacion.
     * \~ */
    {
        Built t;
        check(build(c, k, 0xc1 | 0x04, t), "a packet with reserved bits could not be built");
        check(unprotect_packet(c, k, t.p, t.h, 0, u) == Unprotect::ReservedBitsSet,
              "reserved bits in an authenticated packet were not reported");
    }

    {
        Built t = b;
        c.broken = true;
        check(unprotect_packet(c, k, t.p, t.h, 0, u) == Unprotect::Failed,
              "a broken provider was taken for a bad packet");
        c.broken = false;
    }

    PacketHeader retry;
    retry.type = PacketType::Retry;
    check(unprotect_packet(c, k, b.p, retry, 0, u) == Unprotect::NotProtected,
          "a Retry was treated as if it had a packet number");

    uint8_t small[64] = {0xc0};
    check(protect_packet(c, k, small, 18, 1, 0, 2) == Protect::TooShortToSample,
          "a packet too short to sample was protected anyway");
    check(protect_packet(c, k, small, 18, 5, 0, 20) == Protect::BadPacketNumberLength,
          "a five-byte packet number was accepted");
}

/**
 * @brief
 * \~english Any packet, any number, any length: what is protected comes back.
 * \~spanish Cualquier paquete, numero y longitud: lo que se protege vuelve.
 * \~
 *
 * \~english
 * With a sample-dependent mask, so that taking the sample from anywhere but
 * four bytes past the packet number -- or unmasking before opening in the
 * wrong order -- shows up as a packet that does not come back.
 * \~spanish
 * Con una mascara que depende de la muestra, para que sacar la muestra de otro
 * sitio que no sea cuatro bytes detras del numero de paquete -- o desenmascarar
 * y abrir en el orden equivocado -- aparezca como un paquete que no vuelve.
 * \~
 */
void test_round_trip_property() {
    FakeCrypto c;
    PacketKeys k;
    k.aead_state = &c;
    k.hp_state = &c;
    std::mt19937_64 rng(9001);

    for (int i = 0; i < 20000; ++i) {
        uint8_t p[400];
        uint8_t plain[300];
        const bool is_short = rng() & 1;
        const size_t pn_len = 1 + rng() % 4;
        const size_t payload = (pn_len >= 4 ? 0 : 4 - pn_len) + rng() % 300;
        const uint64_t pn = rng() % (uint64_t{1} << 40);
        for (size_t j = 0; j < payload; ++j) plain[j] = static_cast<uint8_t>(rng());

        size_t pn_off = 0;
        HeaderContext ctx;
        std::memset(p, 0, sizeof p);
        if (is_short) {
            ctx.short_dcid_len = 8;
            p[0] = static_cast<uint8_t>(0x40 | (rng() & 0x04));
            for (size_t j = 1; j <= 8; ++j) p[j] = static_cast<uint8_t>(rng());
            pn_off = 9;
        } else {
            // \~english A Handshake packet with a two-byte Length.
            // \~spanish Un paquete Handshake con un Length de dos bytes.  \~
            p[0] = 0xe0;
            from_hex("0000000108", p + 1, 5);
            for (size_t j = 6; j < 14; ++j) p[j] = static_cast<uint8_t>(rng());
            p[14] = 0;
            const size_t len = pn_len + payload + kTagSize;
            p[15] = static_cast<uint8_t>(0x40 | (len >> 8));
            p[16] = static_cast<uint8_t>(len);
            pn_off = 17;
        }
        std::memcpy(p + pn_off + pn_len, plain, payload);
        const size_t total = pn_off + pn_len + payload + kTagSize;

        if (protect_packet(c, k, p, pn_off, pn_len, pn, payload) != Protect::Ok) {
            check(false, "a well-formed packet could not be protected");
            return;
        }

        PacketHeader h;
        Unprotected u;
        const bool ok =
            parse_packet(p, total, ctx, h) == HeaderError::None &&
            h.size == total &&
            unprotect_packet(c, k, p, h, pn, u) == Unprotect::Ok &&
            u.pn == pn && u.pn_len == pn_len && u.payload.len == payload &&
            std::memcmp(p + u.payload.off, plain, payload) == 0;
        if (!ok) {
            std::fprintf(stderr, "FAIL: a %s packet, pn %llu in %zu bytes, %zu of payload, did not come back\n",
                         is_short ? "short" : "long",
                         static_cast<unsigned long long>(pn), pn_len, payload);
            ++failures;
            return;
        }
    }
}

} // namespace

int main() {
    test_labels_are_the_rfcs();
    test_packet_numbers();
    test_nonces();
    test_sample_is_taken_where_the_rfc_says();
    test_header_protection_lands_where_the_rfc_says();
    test_each_failure_is_its_own();
    test_round_trip_property();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic protection: OK\n");
    return 0;
}
