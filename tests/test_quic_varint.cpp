/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_varint.cpp
 * @brief
 * \~english QUIC's variable-length integers, against the RFC's own examples.
 * \~spanish Los enteros de longitud variable de QUIC, contra los ejemplos del propio RFC.
 * \~
 *
 * \~english
 * The first cases are the four examples in RFC 9000, appendix A.1, byte for
 * byte.  They are not ours: they are what every other implementation was
 * checked against, which is what makes them worth more than cases written
 * here -- a test that only agreed with this project's reading of the RFC would
 * pass whenever the reading was wrong.
 * \~spanish
 * Los primeros casos son los cuatro ejemplos del apendice A.1 del RFC 9000, byte
 * a byte.  No son nuestros: son contra lo que se comprobaron todas las demas
 * implementaciones, que es lo que los hace valer mas que casos escritos aqui --
 * una prueba que solo estuviera de acuerdo con como lee este proyecto el RFC
 * pasaria siempre que la lectura estuviera mal.
 * \~
 */

#include "http_vx/quic_varint.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::quic::decode_varint;
using http_vx::quic::encode_varint;
using http_vx::quic::encode_varint_width;
using http_vx::quic::kVarintMax;
using http_vx::quic::varint_size;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english The four examples of RFC 9000, appendix A.1.
 * \~spanish Los cuatro ejemplos del apendice A.1 del RFC 9000.
 * \~
 */
void test_the_rfc_examples() {
    const uint8_t eight[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    const uint8_t four[] = {0x9d, 0x7f, 0x3e, 0x7d};
    const uint8_t two[] = {0x7b, 0xbd};
    const uint8_t one[] = {0x25};

    uint64_t v = 0;

    check(decode_varint(eight, sizeof eight, v) == 8, "the 8-byte example length");
    check(v == 151288809941952652ULL, "the 8-byte example value");

    check(decode_varint(four, sizeof four, v) == 4, "the 4-byte example length");
    check(v == 494878333ULL, "the 4-byte example value");

    check(decode_varint(two, sizeof two, v) == 2, "the 2-byte example length");
    check(v == 15293, "the 2-byte example value");

    check(decode_varint(one, sizeof one, v) == 1, "the 1-byte example length");
    check(v == 37, "the 1-byte example value");
}

/**
 * @brief
 * \~english A value written longer than it needs to be is still the value.
 * \~spanish Un valor escrito mas largo de lo necesario sigue siendo el valor.
 * \~
 *
 * \~english
 * RFC 9000 uses `0x40 0x25` as its own example of thirty-seven in two bytes.
 * A decoder that refused it would refuse legal traffic; the one field that
 * must be minimal, the frame type, is checked where frames are read.
 * \~spanish
 * El RFC 9000 usa `0x40 0x25` como su propio ejemplo de treinta y siete en dos
 * bytes.  Un descodificador que lo rechazara rechazaria trafico legal; el unico
 * campo que tiene que ser minimo, el tipo de trama, se comprueba donde se leen
 * las tramas.
 * \~
 */
void test_a_long_encoding_is_accepted() {
    const uint8_t two[] = {0x40, 0x25};
    uint64_t v = 0;

    check(decode_varint(two, sizeof two, v) == 2, "a long encoding was refused");
    check(v == 37, "a long encoding decoded to the wrong value");
    check(varint_size(v) == 1,
          "the minimal size of 37 is not one byte, so a frame-type check "
          "could not tell the two apart");

    uint8_t out[2] = {};
    check(encode_varint_width(out, 2, 37), "37 would not go in two bytes");
    check(out[0] == 0x40 && out[1] == 0x25,
          "37 in two bytes is not what the RFC says it is");
}

/**
 * @brief
 * \~english Every boundary between the four sizes, both ways.
 * \~spanish Cada frontera entre los cuatro tamanos, en los dos sentidos.
 * \~
 *
 * \~english
 * The mistakes in an integer format live at the boundaries: the last value
 * that fits in a size and the first that does not.  An off-by-one there
 * writes 64 in one byte, where it reads back as zero.
 * \~spanish
 * Las equivocaciones de un formato de enteros viven en las fronteras: el ultimo
 * valor que cabe en un tamano y el primero que no.  Un error de uno ahi escribe
 * 64 en un byte, donde se vuelve a leer como cero.
 * \~
 */
void test_every_boundary_round_trips() {
    const uint64_t values[] = {0,
                               63,
                               64,
                               16383,
                               16384,
                               (uint64_t{1} << 30) - 1,
                               uint64_t{1} << 30,
                               kVarintMax};
    const size_t sizes[] = {1, 1, 2, 2, 4, 4, 8, 8};

    for (size_t i = 0; i < sizeof values / sizeof values[0]; ++i) {
        check(varint_size(values[i]) == sizes[i], "a boundary has the wrong size");

        uint8_t buf[8] = {};
        const size_t wrote = encode_varint(buf, sizeof buf, values[i]);
        check(wrote == sizes[i], "a boundary was written in the wrong size");

        uint64_t back = 0;
        check(decode_varint(buf, wrote, back) == wrote,
              "a boundary read back in a different size");
        check(back == values[i], "a boundary did not survive the round trip");
    }
}

/**
 * @brief
 * \~english What does not fit is refused, not cut.
 * \~spanish Lo que no cabe se rechaza, no se corta.
 * \~
 */
void test_what_does_not_fit_is_refused() {
    uint8_t buf[8] = {};

    check(varint_size(kVarintMax + 1) == 0, "a value past the maximum has a size");
    check(encode_varint(buf, sizeof buf, kVarintMax + 1) == 0,
          "a value past the maximum was written");

    check(encode_varint(buf, 1, 64) == 0,
          "a two-byte value was written into one byte of room");
    check(!encode_varint_width(buf, 1, 64), "64 was forced into one byte");
    check(!encode_varint_width(buf, 3, 1), "a width of three was accepted");
}

/**
 * @brief
 * \~english An integer that is not all here is not read.
 * \~spanish Un entero que no esta entero no se lee.
 * \~
 */
void test_a_truncated_integer_is_not_read() {
    const uint8_t eight[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    uint64_t v = 12345;

    for (size_t n = 0; n < sizeof eight; ++n)
        check(decode_varint(eight, n, v) == 0,
              "an integer was read from fewer bytes than it takes");

    check(v == 12345, "a refused read changed the value anyway");
}

} // namespace

int main() {
    test_the_rfc_examples();
    test_a_long_encoding_is_accepted();
    test_every_boundary_round_trips();
    test_what_does_not_fit_is_refused();
    test_a_truncated_integer_is_not_read();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
