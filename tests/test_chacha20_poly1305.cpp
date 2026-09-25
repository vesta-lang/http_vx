/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_chacha20_poly1305.cpp
 * @brief
 * \~english ChaCha20 and Poly1305 against RFC 8439's own vectors.
 * \~spanish ChaCha20 y Poly1305 contra los vectores del propio RFC 8439.
 * \~
 *
 * \~english
 * Cryptography written here has to be checked against bytes that were not
 * written here, and RFC 8439 prints them for each step: the block function,
 * the cipher, Poly1305, and the AEAD that joins them.  Its appendix adds the
 * cases that exist only to break the arithmetic -- a result that lands
 * exactly on 2^130 - 5, a carry out of an all-ones limb, an s that overflows
 * 2^128 -- because those are the places a Poly1305 is wrong in a way no
 * ordinary message shows.
 *
 * Runs on every platform, whether or not a provider there uses this code:
 * code that is only checked where it is used is checked by whoever uses it.
 * \~spanish
 * La criptografia escrita aqui se tiene que comprobar contra bytes que no se
 * escribieron aqui, y el RFC 8439 los imprime para cada paso: la funcion de
 * bloque, el cifrado, Poly1305 y el AEAD que los junta.  Su apendice anade los
 * casos que existen solo para romper la aritmetica -- un resultado que cae justo
 * en 2^130 - 5, un acarreo desde un miembro todo unos, una s que se pasa de
 * 2^128 --, porque son los sitios donde un Poly1305 esta mal de una forma que no
 * ensena ningun mensaje corriente.
 *
 * Corre en todas las plataformas, la use ahi un proveedor o no: un codigo que
 * solo se comprueba donde se usa lo comprueba quien lo usa.
 * \~
 */

#include "chacha20_poly1305.h"

#include <cstdio>
#include <cstring>
#include <random>

namespace {

using namespace http_vx::chacha;

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

bool same_as(const uint8_t *p, size_t n, const char *hex) {
    uint8_t want[256];
    return from_hex(hex, want, sizeof want) == n && std::memcmp(p, want, n) == 0;
}

const char kKey00to1f[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// \~english The sunscreen text of RFC 8439, 2.4.2 and 2.8.2.
/// \~spanish El texto del protector solar del RFC 8439, 2.4.2 y 2.8.2.  \~
const char kSunscreen[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one "
    "tip for the future, sunscreen would be it.";

/// \~english 2.3.2: one block.  \~spanish 2.3.2: un bloque.  \~
void test_block() {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t out[64];
    from_hex(kKey00to1f, key, sizeof key);
    from_hex("000000090000004a00000000", nonce, sizeof nonce);
    block(key, 1, nonce, out);
    check(same_as(out, 64,
                  "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                  "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"),
          "the ChaCha20 block is not RFC 8439's 2.3.2");
}

/// \~english 2.4.2: the cipher over two blocks and a bit.
/// \~spanish 2.4.2: el cifrado sobre dos bloques y un poco.  \~
void test_cipher() {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t buf[114];
    from_hex(kKey00to1f, key, sizeof key);
    from_hex("000000000000004a00000000", nonce, sizeof nonce);
    std::memcpy(buf, kSunscreen, sizeof buf);

    // \~english In place, as the provider uses it.  \~spanish En su sitio, como lo usa el proveedor.  \~
    xor_stream(key, 1, nonce, buf, buf, sizeof buf);
    check(same_as(buf, sizeof buf,
                  "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                  "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                  "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                  "5af90bbf74a35be6b40b8eedf2785e42874d"),
          "the ChaCha20 cipher is not RFC 8439's 2.4.2");
}

/// \~english One-shot Poly1305 of @p msg_hex under @p key_hex.
/// \~spanish Poly1305 de una vez de @p msg_hex bajo @p key_hex.  \~
void mac(const char *key_hex, const uint8_t *msg, size_t n, uint8_t *tag) {
    uint8_t key[32];
    from_hex(key_hex, key, sizeof key);
    Poly1305 p;
    poly1305_init(p, key);
    poly1305_update(p, msg, n);
    poly1305_finish(p, tag);
}

/// \~english 2.5.2 and the edge cases of appendix A.3.
/// \~spanish 2.5.2 y los casos limite del apendice A.3.  \~
void test_poly1305() {
    const char text[] = "Cryptographic Forum Research Group";
    uint8_t tag[16];
    mac("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        reinterpret_cast<const uint8_t *>(text), sizeof text - 1, tag);
    check(same_as(tag, 16, "a8061dc1305136c6c22b8baf0c0127a9"),
          "Poly1305 is not RFC 8439's 2.5.2");

    struct Edge {
        const char *what;
        const char *key;  // r || s
        const char *data;
        const char *tag;
    };
    const Edge edges[] = {
        {"#5, a partially reduced result that is not fully reduced",
         "02000000000000000000000000000000" "00000000000000000000000000000000",
         "ffffffffffffffffffffffffffffffff",
         "03000000000000000000000000000000"},
        {"#6, s overflowing 2^128",
         "02000000000000000000000000000000" "ffffffffffffffffffffffffffffffff",
         "02000000000000000000000000000000",
         "03000000000000000000000000000000"},
        {"#7, an all-ones limb with a carry into it",
         "01000000000000000000000000000000" "00000000000000000000000000000000",
         "ffffffffffffffffffffffffffffffff" "f0ffffffffffffffffffffffffffffff"
         "11000000000000000000000000000000",
         "05000000000000000000000000000000"},
        {"#8, a result of exactly 2^130 - 5",
         "01000000000000000000000000000000" "00000000000000000000000000000000",
         "ffffffffffffffffffffffffffffffff" "fbfefefefefefefefefefefefefefefe"
         "01010101010101010101010101010101",
         "00000000000000000000000000000000"},
        {"#9, a result of exactly 2^130 - 6",
         "02000000000000000000000000000000" "00000000000000000000000000000000",
         "fdffffffffffffffffffffffffffffff",
         "faffffffffffffffffffffffffffffff"},
        {"#10, a 131-bit intermediate",
         "01000000000000000400000000000000" "00000000000000000000000000000000",
         "e33594d7505e43b90000000000000000" "3394d7505e4379cd0100000000000000"
         "00000000000000000000000000000000" "01000000000000000000000000000000",
         "14000000000000005500000000000000"},
        {"#11, a 131-bit final result",
         "01000000000000000400000000000000" "00000000000000000000000000000000",
         "e33594d7505e43b90000000000000000" "3394d7505e4379cd0100000000000000"
         "00000000000000000000000000000000",
         "13000000000000000000000000000000"},
    };
    for (const Edge &e : edges) {
        uint8_t data[64];
        const size_t n = from_hex(e.data, data, sizeof data);
        mac(e.key, data, n, tag);
        if (!same_as(tag, 16, e.tag)) {
            std::fprintf(stderr, "FAIL: Poly1305 edge case %s\n", e.what);
            ++failures;
        }
    }

    /* \~english
     * A state no RFC message reaches, set by hand: folding the top limb back
     * (times five) carries into limb one, which was all ones, leaving it at
     * exactly 2^26 -- one bit too many.  Packed into words as it is, that bit
     * lands on bit 0 of limb two, which is set, and is lost in the OR.  The
     * value is h0 + h1 2^26 + h2 2^52 + h4 2^104 with h4 = 2^26, that is
     * 2^26 - 1 + (2^26 - 1) 2^26 + 2^52 + 5 = 2^53 + 4 modulo 2^130 - 5.
     * \~spanish
     * Un estado al que no llega ningun mensaje del RFC, puesto a mano: devolver
     * el miembro de arriba (por cinco) lleva un acarreo al miembro uno, que
     * estaba todo a unos, y lo deja justo en 2^26 -- un bit de mas.  Empaquetado
     * tal cual en palabras, ese bit cae sobre el bit 0 del miembro dos, que esta
     * puesto, y se pierde en el OR.  El valor es h0 + h1 2^26 + h2 2^52 +
     * h4 2^104 con h4 = 2^26, o sea 2^26 - 1 + (2^26 - 1) 2^26 + 2^52 + 5 =
     * 2^53 + 4 modulo 2^130 - 5.
     * \~ */
    {
        Poly1305 p;
        const uint8_t zero_key[32] = {};
        poly1305_init(p, zero_key);
        p.h[0] = (1u << 26) - 1;
        p.h[1] = (1u << 26) - 1;
        p.h[2] = 1;
        p.h[3] = 0;
        p.h[4] = 1u << 26;
        poly1305_finish(p, tag);
        check(same_as(tag, 16, "04000000000020000000000000000000"),
              "Poly1305 loses a carry that leaves limb one at exactly 2^26");
    }

    /* \~english
     * The same bytes fed in any split give the same tag -- the AEAD feeds
     * associated data, padding and ciphertext separately, so a bug in the
     * half-block carried between calls would only show there.
     * \~spanish
     * Los mismos bytes metidos troceados como sea dan la misma marca -- el AEAD
     * mete por separado los datos asociados, el relleno y el cifrado, asi que un
     * fallo en el medio bloque que se arrastra entre llamadas solo se veria ahi.
     * \~ */
    std::mt19937 rng(8439);
    uint8_t key[32];
    uint8_t msg[300];
    for (int round = 0; round < 2000; ++round) {
        for (uint8_t &b : key) b = static_cast<uint8_t>(rng());
        const size_t n = rng() % sizeof msg;
        for (size_t i = 0; i < n; ++i) msg[i] = static_cast<uint8_t>(rng());

        uint8_t whole[16];
        uint8_t pieces[16];
        Poly1305 a;
        poly1305_init(a, key);
        poly1305_update(a, msg, n);
        poly1305_finish(a, whole);

        Poly1305 b;
        poly1305_init(b, key);
        size_t at = 0;
        while (at < n) {
            const size_t take = 1 + rng() % 40;
            const size_t t = take < n - at ? take : n - at;
            poly1305_update(b, msg + at, t);
            at += t;
        }
        poly1305_finish(b, pieces);
        if (std::memcmp(whole, pieces, 16) != 0) {
            std::fprintf(stderr, "FAIL: Poly1305 of %zu bytes depends on how it was split\n", n);
            ++failures;
            return;
        }
    }
}

/// \~english 2.8.2: the AEAD, sealed and opened, and a forgery refused untouched.
/// \~spanish 2.8.2: el AEAD, sellado y abierto, y una falsificacion rechazada sin tocar.  \~
void test_aead() {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t ad[12];
    uint8_t buf[114 + kTagSize];
    from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, sizeof key);
    from_hex("070000004041424344454647", nonce, sizeof nonce);
    from_hex("50515253c0c1c2c3c4c5c6c7", ad, sizeof ad);
    std::memcpy(buf, kSunscreen, 114);

    seal(key, nonce, ad, sizeof ad, buf, 114, buf);
    check(same_as(buf, sizeof buf,
                  "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                  "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                  "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                  "3ff4def08e4b7a9de576d26586cec64b6116"
                  "1ae10b594f09e26a7e902ecbd0600691"),
          "the AEAD is not RFC 8439's 2.8.2");

    uint8_t saved[sizeof buf];
    std::memcpy(saved, buf, sizeof buf);

    // \~english Every single-bit change, in ciphertext or tag, is refused.
    // \~spanish Cualquier cambio de un bit, en el cifrado o en la marca, se rechaza.  \~
    for (size_t i = 0; i < sizeof buf; ++i) {
        buf[i] ^= 0x10;
        uint8_t out[114];
        std::memset(out, 0x77, sizeof out);
        const bool opened = open(key, nonce, ad, sizeof ad, buf, sizeof buf, out);
        bool untouched = true;
        for (uint8_t b : out) untouched = untouched && b == 0x77;
        if (opened || !untouched) {
            std::fprintf(stderr, "FAIL: a bit flipped at byte %zu was %s\n", i,
                         opened ? "accepted" : "refused but decrypted anyway");
            ++failures;
            return;
        }
        buf[i] ^= 0x10;
    }

    ad[0] ^= 1;
    check(!open(key, nonce, ad, sizeof ad, buf, sizeof buf, buf),
          "associated data changed on the path was not caught");
    ad[0] ^= 1;

    check(open(key, nonce, ad, sizeof ad, buf, sizeof buf, buf) &&
              std::memcmp(buf, kSunscreen, 114) == 0,
          "the sealed text did not open back in place");
    check(std::memcmp(buf + 114, saved + 114, kTagSize) == 0,
          "opening wrote past the plaintext, over the tag");
}

/**
 * @brief
 * \~english What QUIC takes from this: RFC 9001 A.5's header-protection mask.
 * \~spanish Lo que coge QUIC de esto: la mascara de proteccion de cabecera del RFC 9001 A.5.
 * \~
 */
void test_quic_mask() {
    uint8_t hp[32];
    uint8_t sample[16];
    uint8_t out[64];
    from_hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4", hp, sizeof hp);
    from_hex("5e5cd55c41f69080575d7999c25a5bfb", sample, sizeof sample);

    // \~english Counter = the sample's first four bytes, little-endian; nonce = the rest.
    // \~spanish Contador = los cuatro primeros bytes de la muestra, en orden inverso; nonce = el resto.  \~
    const uint32_t counter = static_cast<uint32_t>(sample[0]) |
                             (static_cast<uint32_t>(sample[1]) << 8) |
                             (static_cast<uint32_t>(sample[2]) << 16) |
                             (static_cast<uint32_t>(sample[3]) << 24);
    block(hp, counter, sample + 4, out);
    check(same_as(out, 5, "aefefe7d03"), "the ChaCha20 header mask is not RFC 9001's A.5");
}

} // namespace

int main() {
    test_block();
    test_cipher();
    test_poly1305();
    test_aead();
    test_quic_mask();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("chacha20-poly1305: OK\n");
    return 0;
}
