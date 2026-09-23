/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_huffman.cpp
 * @brief
 * \~english The Huffman code, and what a round trip cannot tell you.
 * \~spanish El codigo Huffman, y lo que un viaje de ida y vuelta no dice.
 * \~
 *
 * \~english
 * **A round trip proves almost nothing here, and it is worth being clear about
 * why.**  The encoder and the decoder read the same table, so a code written
 * down wrong is written down wrong for both of them: what goes out comes back,
 * and every other implementation in the world refuses it.
 *
 * So the table is pinned from three directions instead, and only one of them
 * is the round trip:
 *
 *  - **the structure**, at compile time.  A prefix code fills its tree exactly
 *    and its lengths satisfy Kraft's equality, and neither is true of a table
 *    with a length that is wrong.  Those are asserted where the tree is built,
 *    so they fail the build.
 *  - **the specification's own examples**, byte for byte.  Four strings whose
 *    coded form is written out in RFC 7541 appendix C, which pins the actual
 *    bit patterns of every character they contain.
 *  - **and the round trip**, which is left to catch what the first two cannot:
 *    a shift, a mask, a bit walked the wrong way.
 *
 * What none of them catches is two symbols whose codes were swapped for each
 * other, if neither appears in the examples.  That is worth saying rather than
 * papering over: it is the one hole, it is narrow, and the way to close it
 * would be a fourth source for the same table.
 *
 * \~spanish
 * **Un viaje de ida y vuelta no demuestra casi nada aqui, y conviene decir por
 * que.**  El codificador y el descodificador leen la misma tabla, asi que un
 * codigo mal escrito esta mal escrito para los dos: lo que sale vuelve, y
 * cualquier otra implementacion del mundo lo rechaza.
 *
 * Asi que la tabla se sujeta desde tres sitios, y solo uno es el viaje:
 *
 *  - **la estructura**, al compilar.  Un codigo de prefijo llena su arbol
 *    exactamente y sus longitudes cumplen la igualdad de Kraft, y ninguna de
 *    las dos cosas es cierta en una tabla con una longitud mal.  Se afirman
 *    donde se construye el arbol, asi que rompen la construccion.
 *  - **los ejemplos de la propia especificacion**, byte a byte.  Cuatro
 *    cadenas cuya forma codificada escribe el RFC 7541 apendice C, lo que
 *    sujeta los patrones de bits de todos los caracteres que llevan.
 *  - **y el viaje de ida y vuelta**, que se queda para pillar lo que los dos
 *    primeros no pueden: un desplazamiento, una mascara, un bit recorrido al
 *    reves.
 *
 * Lo que no pilla ninguno es dos simbolos con los codigos intercambiados entre
 * si, si ninguno aparece en los ejemplos.  Merece decirse en vez de taparlo: es
 * el unico hueco, es estrecho, y cerrarlo seria una cuarta fuente de la misma
 * tabla.
 *
 * \~
 */

#include "http_vx/h2_huffman.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::hpack::HuffmanResult;
using http_vx::h2::hpack::Status;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Checks that @p text codes as exactly @p want.
 * \~spanish Comprueba que @p text se codifica exactamente como @p want.
 * \~
 */
void codes_as(const char *text, const uint8_t *want, size_t want_len,
              const char *what) {
    const uint8_t *in = reinterpret_cast<const uint8_t *>(text);
    const size_t n = std::strlen(text);

    check(http_vx::h2::hpack::huffman_encoded_length(in, n) == want_len, what);

    uint8_t out[128];
    const size_t wrote = http_vx::h2::hpack::huffman_encode(out, sizeof(out), in, n);
    check(wrote == want_len, what);
    check(wrote == want_len && std::memcmp(out, want, want_len) == 0, what);

    /* \~english And the other way, from the bytes the specification wrote.
     * \~spanish Y al reves, desde los bytes que escribio la especificacion.  \~ */
    uint8_t back[128];
    const HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), want, want_len);
    check(r.status == Status::Ok, what);
    check(r.len == n, what);
    check(r.len == n && std::memcmp(back, text, n) == 0, what);
}

/**
 * @brief
 * \~english The four strings RFC 7541 writes out coded.
 * \~spanish Las cuatro cadenas que el RFC 7541 escribe codificadas.
 * \~
 *
 * \~english
 * These are what pins the table to the same code everybody else implements.
 * Between them they contain most of the characters a header is made of, and
 * each byte here is a statement about several of them at once: the bits do not
 * line up with the bytes, so one character written wrong moves everything
 * after it.
 *
 * \~spanish
 * Esto es lo que sujeta la tabla al mismo codigo que implementan los demas.
 * Entre las cuatro llevan casi todos los caracteres de los que esta hecha una
 * cabecera, y cada byte de aqui es una afirmacion sobre varios a la vez: los
 * bits no cuadran con los bytes, asi que un caracter mal escrito mueve todo lo
 * que va detras.
 *
 * \~
 */
void test_the_specification_examples() {
    const uint8_t host[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                            0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    codes_as("www.example.com", host, sizeof(host),
             "www.example.com is not coded as the specification writes it");

    const uint8_t cache[] = {0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    codes_as("no-cache", cache, sizeof(cache),
             "no-cache is not coded as the specification writes it");

    const uint8_t key[] = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    codes_as("custom-key", key, sizeof(key),
             "custom-key is not coded as the specification writes it");

    const uint8_t value[] = {0x25, 0xa8, 0x49, 0xe9, 0x5b,
                             0xb8, 0xe8, 0xb4, 0xbf};
    codes_as("custom-value", value, sizeof(value),
             "custom-value is not coded as the specification writes it");
}

/**
 * @brief
 * \~english Every byte there is, alone and in company.
 * \~spanish Todos los bytes que hay, solos y acompanados.
 * \~
 *
 * \~english
 * Alone catches a code whose length is wrong in a way the tree survived.  In
 * company catches the thing a single byte cannot: a symbol that straddles a
 * byte boundary, which is what almost all of them do and what a shift written
 * the wrong way round breaks.
 *
 * \~spanish
 * Solos pillan un codigo con la longitud mal de una forma a la que el arbol
 * sobrevivio.  Acompanados pillan lo que un byte suelto no puede: un simbolo a
 * caballo entre dos bytes, que es lo que hacen casi todos y lo que rompe un
 * desplazamiento escrito al reves.
 *
 * \~
 */
void test_every_byte() {
    for (unsigned v = 0; v < 256; ++v) {
        const uint8_t one = static_cast<uint8_t>(v);

        uint8_t coded[8];
        const size_t n = http_vx::h2::hpack::huffman_encode(coded, sizeof(coded),
                                                            &one, 1);
        check(n != 0 && n <= 4, "a single byte coded to a strange length");

        uint8_t back[8];
        const HuffmanResult r =
            http_vx::h2::hpack::huffman_decode(back, sizeof(back), coded, n);
        check(r.status == Status::Ok, "a single byte did not read back");
        check(r.len == 1 && back[0] == one, "a single byte came back as another");
    }

    /* \~english
     * And all of them at once, which puts every symbol at every offset within
     * a byte that it can reach.
     * \~spanish
     * Y todos a la vez, que pone cada simbolo en todos los desplazamientos
     * dentro de un byte a los que puede llegar.
     * \~ */
    uint8_t all[256];
    for (unsigned v = 0; v < 256; ++v) all[v] = static_cast<uint8_t>(v);

    uint8_t coded[1024];
    const size_t n =
        http_vx::h2::hpack::huffman_encode(coded, sizeof(coded), all, sizeof(all));
    check(n != 0, "every byte at once did not fit");

    uint8_t back[1024];
    const HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), coded, n);
    check(r.status == Status::Ok, "every byte at once did not read back");
    check(r.len == sizeof(all), "every byte at once came back a different length");
    check(r.len == sizeof(all) && std::memcmp(back, all, sizeof(all)) == 0,
          "every byte at once came back changed");
}

/**
 * @brief
 * \~english What the leftover bits at the end may be.
 * \~spanish Lo que pueden ser los bits que sobran al final.
 * \~
 *
 * \~english
 * The padding is a place where nothing is read, which makes it a place to put
 * something.  Two rules close it: it must be all ones -- the beginning of the
 * end-of-string symbol -- and there must be less than a byte of it, because a
 * whole byte of it is a byte the sender did not have to send.
 *
 * A reader that skipped either would accept two different byte strings as the
 * same string, and a pair of them is what one implementation forwards and
 * another does not.
 *
 * \~spanish
 * El relleno es un sitio donde no se lee nada, lo que lo convierte en un sitio
 * donde meter algo.  Dos reglas lo cierran: tiene que ser todo unos -- el
 * principio del simbolo de fin de cadena -- y tiene que haber menos de un byte,
 * porque un byte entero es un byte que quien envia no tenia que mandar.
 *
 * Quien se saltara cualquiera de las dos aceptaria dos cadenas de bytes
 * distintas como la misma cadena, y un par de esas es lo que un programa
 * reenvia y otro no.
 *
 * \~
 */
void test_padding() {
    const uint8_t a = 'a';

    uint8_t coded[8];
    const size_t n = http_vx::h2::hpack::huffman_encode(coded, sizeof(coded), &a, 1);
    check(n == 1, "one letter did not fit in one byte");

    uint8_t back[8];
    HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), coded, n);
    check(r.status == Status::Ok && r.len == 1 && back[0] == 'a',
          "a properly padded letter did not read");

    /* \~english
     * The same letter with a zero in the padding.  It decodes to the same
     * letter and it is refused anyway, which is the point: two ways of writing
     * one string is one string too many.
     * \~spanish
     * La misma letra con un cero en el relleno.  Descodifica a la misma letra y
     * se rechaza igual, que es de lo que se trata: dos formas de escribir una
     * cadena es una cadena de mas.
     * \~ */
    const uint8_t zeroed[] = {static_cast<uint8_t>(coded[0] & 0xF8)};
    r = http_vx::h2::hpack::huffman_decode(back, sizeof(back), zeroed, 1);
    check(r.status == Status::Malformed, "padding with a zero in it was accepted");

    /* \~english
     * And a whole byte of it.  The sender could have stopped and did not.
     * \~spanish
     * Y un byte entero de relleno.  Quien envia podia haber parado y no paro.
     * \~ */
    const uint8_t extra[] = {coded[0], 0xFF};
    r = http_vx::h2::hpack::huffman_decode(back, sizeof(back), extra, 2);
    check(r.status == Status::Malformed, "a whole byte of padding was accepted");
}

/**
 * @brief
 * \~english The symbol that says a string ends, inside a string.
 * \~spanish El simbolo que dice que una cadena acaba, dentro de una cadena.
 * \~
 *
 * \~english
 * A string knows how long it is before it starts, because HPACK writes the
 * length in front of it.  So this symbol has no job, and accepting one would
 * be accepting a second answer to where a string ends -- which is the same
 * mistake as a message with two content lengths, one layer down.
 *
 * \~spanish
 * Una cadena sabe cuanto mide antes de empezar, porque HPACK escribe la
 * longitud delante.  Asi que este simbolo no tiene trabajo, y aceptar uno seria
 * aceptar una segunda respuesta a donde acaba una cadena -- que es la misma
 * equivocacion que un mensaje con dos longitudes de contenido, una capa mas
 * abajo.
 *
 * \~
 */
void test_end_of_string_symbol() {
    /* \~english
     * Thirty ones is the end-of-string symbol, and four bytes of ones is
     * thirty-two of them.
     * \~spanish
     * Treinta unos son el simbolo de fin de cadena, y cuatro bytes de unos son
     * treinta y dos.
     * \~ */
    const uint8_t eos[] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t back[16];
    const HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), eos, sizeof(eos));
    check(r.status == Status::Malformed,
          "the end-of-string symbol was read inside a string");
}

/**
 * @brief
 * \~english Nothing comes out bigger than the bound the header promises.
 * \~spanish Nada sale mas grande que la cota que promete la cabecera.
 * \~
 *
 * \~english
 * The bound is what a caller sizes a buffer from, so it is worth checking
 * against the worst input there is rather than trusting the arithmetic: the
 * shortest code repeated, which is the only way to get the most output per
 * byte of input.
 *
 * \~spanish
 * La cota es de donde saca el tamano de un buffer quien llama, asi que merece
 * comprobarla contra la peor entrada que hay en vez de fiarse de la aritmetica:
 * el codigo mas corto repetido, que es la unica forma de sacar el maximo de
 * salida por byte de entrada.
 *
 * \~
 */
void test_the_growth_bound() {
    /* \~english
     * `0` is five bits of zero, so a string of them is the densest input
     * there is.
     * \~spanish
     * El `0` son cinco bits a cero, asi que una cadena de ellos es la entrada
     * mas densa que hay.
     * \~ */
    uint8_t zeros[200];
    for (size_t i = 0; i < sizeof(zeros); ++i) zeros[i] = '0';

    uint8_t coded[256];
    const size_t n = http_vx::h2::hpack::huffman_encode(coded, sizeof(coded),
                                                        zeros, sizeof(zeros));
    check(n != 0, "the densest string did not fit");

    const size_t bound = http_vx::h2::hpack::huffman_max_decoded(n);
    check(bound >= sizeof(zeros),
          "the bound is smaller than what the densest string produces");

    uint8_t back[512];
    const HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), coded, n);
    check(r.status == Status::Ok && r.len == sizeof(zeros),
          "the densest string did not read back");
    check(r.len <= bound, "something came out larger than the bound promises");

    /* \~english
     * And a buffer one byte short is refused rather than overrun.
     * \~spanish
     * Y un buffer un byte corto se rechaza en vez de desbordarse.
     * \~ */
    const HuffmanResult tight = http_vx::h2::hpack::huffman_decode(
        back, sizeof(zeros) - 1, coded, n);
    check(tight.status == Status::TooLarge,
          "a buffer that was too small was written into anyway");
}

/**
 * @brief
 * \~english Coding is not always shorter, and the length says so first.
 * \~spanish Codificar no siempre acorta, y la longitud lo dice antes.
 * \~
 *
 * \~english
 * The code was measured on HTTP headers, so anything else comes out longer --
 * a token, a hash, anything binary.  HPACK lets a sender choose for each
 * string, and choosing well needs the answer BEFORE the work, which is what
 * the length function is for.
 *
 * \~spanish
 * El codigo se midio sobre cabeceras de HTTP, asi que cualquier otra cosa sale
 * mas larga -- un testigo, un resumen, cualquier cosa binaria.  HPACK deja
 * elegir a quien envia para cada cadena, y elegir bien necesita la respuesta
 * ANTES del trabajo, que es para lo que esta la funcion de longitud.
 *
 * \~
 */
void test_when_it_does_not_help() {
    const uint8_t header[] = "content-type";
    const size_t header_len = sizeof(header) - 1;
    check(http_vx::h2::hpack::huffman_encoded_length(header, header_len) <
              header_len,
          "a header name did not get shorter, which is what the code is for");

    /* \~english
     * And bytes the code was not measured on.  Every one of these costs at
     * least twenty bits, so a handful of them is longer than what was sent.
     * \~spanish
     * Y bytes sobre los que no se midio el codigo.  Cada uno de estos cuesta al
     * menos veinte bits, asi que un punado es mas largo que lo que se mando.
     * \~ */
    const uint8_t binary[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87};
    check(http_vx::h2::hpack::huffman_encoded_length(binary, sizeof(binary)) >
              sizeof(binary),
          "bytes the code was not measured on did not get longer");

    /* \~english
     * The length is what the encoder writes, every time.  A length that
     * disagreed with the writing would be a buffer sized from one number and
     * filled from another.
     * \~spanish
     * La longitud es lo que escribe el codificador, siempre.  Una longitud que
     * discrepara de la escritura seria un buffer dimensionado con un numero y
     * llenado con otro.
     * \~ */
    uint8_t out[64];
    const size_t said =
        http_vx::h2::hpack::huffman_encoded_length(binary, sizeof(binary));
    const size_t wrote =
        http_vx::h2::hpack::huffman_encode(out, sizeof(out), binary, sizeof(binary));
    check(said == wrote, "the length promised is not the length written");

    /* \~english And no room means nothing written, not a partial string.
     * \~spanish Y sin sitio no se escribe nada, no media cadena.  \~ */
    check(http_vx::h2::hpack::huffman_encode(out, said - 1, binary,
                                             sizeof(binary)) == 0,
          "a string was half written into a buffer that was too small");
}

/**
 * @brief
 * \~english Nothing in, nothing out.
 * \~spanish Nada entra, nada sale.
 * \~
 */
void test_empty() {
    uint8_t back[8];
    const HuffmanResult r =
        http_vx::h2::hpack::huffman_decode(back, sizeof(back), nullptr, 0);
    check(r.status == Status::Ok && r.len == 0,
          "an empty string was not read as empty");

    uint8_t out[8];
    check(http_vx::h2::hpack::huffman_encode(out, sizeof(out), nullptr, 0) == 0,
          "an empty string wrote something");
    check(http_vx::h2::hpack::huffman_encoded_length(nullptr, 0) == 0,
          "an empty string has a length");
}

} // namespace

int main() {
    test_the_specification_examples();
    test_every_byte();
    test_padding();
    test_end_of_string_symbol();
    test_the_growth_bound();
    test_when_it_does_not_help();
    test_empty();

    if (failures != 0) {
        std::fprintf(stderr, "test_h2_huffman: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h2_huffman: ok\n");
    return 0;
}
