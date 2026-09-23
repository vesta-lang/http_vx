/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_hpack.cpp
 * @brief
 * \~english HPACK's numbers, and the table both ends are born knowing.
 * \~spanish Los numeros de HPACK, y la tabla que los dos extremos conocen.
 * \~
 *
 * \~english
 * Two things are checked here and they need opposite kinds of test.
 *
 * The numbers are arithmetic, so what matters is the edges: the value that
 * exactly fills the prefix and the one past it, the largest number that fits
 * and the first that does not, and the bytes that add nothing and go on
 * forever.
 *
 * The table is data, so what matters is that it agrees with the OTHER table.
 * Sixty-one entries written by hand can be wrong in a way nothing notices --
 * an index off by one decodes a message that is not the one that was sent --
 * so every row is checked against @c field_id_of rather than against itself.
 *
 * \~spanish
 * Aqui se comprueban dos cosas y necesitan pruebas de clases opuestas.
 *
 * Los numeros son aritmetica, asi que lo que importa son los extremos: el valor
 * que llena exactamente el prefijo y el siguiente, el numero mas grande que
 * cabe y el primero que no, y los bytes que no anaden nada y siguen para
 * siempre.
 *
 * La tabla son datos, asi que lo que importa es que coincida con la OTRA tabla.
 * Sesenta y una entradas escritas a mano pueden estar mal de una forma que no
 * nota nadie -- un indice desplazado en uno descodifica un mensaje que no es el
 * que se mando -- asi que cada fila se comprueba contra @c field_id_of y no
 * contra si misma.
 *
 * \~
 */

#include "http_vx/h2_hpack.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::hpack::IntResult;
using http_vx::h2::hpack::Pseudo;
using http_vx::h2::hpack::Status;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english The examples the specification writes out, byte for byte.
 * \~spanish Los ejemplos que escribe la especificacion, byte a byte.
 * \~
 *
 * \~english
 * RFC 7541 appendix C.1.  Checking the bytes and not only the numbers is what
 * catches an encoder and a decoder that agree with each other and with nobody
 * else: a round trip would pass, and every other implementation would refuse
 * what came out.
 *
 * \~spanish
 * RFC 7541 apendice C.1.  Comprobar los bytes y no solo los numeros es lo que
 * pilla un codificador y un descodificador de acuerdo entre ellos y con nadie
 * mas: un viaje de ida y vuelta pasaria, y cualquier otra implementacion
 * rechazaria lo que saliera.
 *
 * \~
 */
void test_the_specification_examples() {
    uint8_t out[16];

    /* \~english Ten with five bits of prefix: it fits, so it is one byte.
     * \~spanish Diez con cinco bits de prefijo: cabe, asi que es un byte.  \~ */
    size_t n = http_vx::h2::hpack::encode_int(out, 10, 5, 0);
    check(n == 1 && out[0] == 0x0A, "ten with a five-bit prefix is not one byte");

    /* \~english
     * A thousand three hundred and thirty-seven with the same prefix: it does
     * not fit, so the prefix fills with ones and the rest follows.
     * \~spanish
     * Mil trescientos treinta y siete con el mismo prefijo: no cabe, asi que el
     * prefijo se llena de unos y el resto va detras.
     * \~ */
    n = http_vx::h2::hpack::encode_int(out, 1337, 5, 0);
    check(n == 3 && out[0] == 0x1F && out[1] == 0x9A && out[2] == 0x0A,
          "1337 with a five-bit prefix is not what the specification says");

    /* \~english Forty-two with the whole byte.
     * \~spanish Cuarenta y dos con el byte entero.  \~ */
    n = http_vx::h2::hpack::encode_int(out, 42, 8, 0);
    check(n == 1 && out[0] == 0x2A, "42 with an eight-bit prefix is not one byte");

    const uint8_t ten[] = {0x0A};
    IntResult r = http_vx::h2::hpack::decode_int(ten, 1, 5);
    check(r.status == Status::Ok && r.value == 10 && r.used == 1,
          "ten did not read back");

    const uint8_t big[] = {0x1F, 0x9A, 0x0A};
    r = http_vx::h2::hpack::decode_int(big, 3, 5);
    check(r.status == Status::Ok && r.value == 1337 && r.used == 3,
          "1337 did not read back");
}

/**
 * @brief
 * \~english What is above the prefix is not the number, and survives.
 * \~spanish Lo que hay encima del prefijo no es el numero, y sobrevive.
 * \~
 *
 * \~english
 * Those bits say what the number is FOR -- whether the field is being indexed,
 * whether it may be remembered -- so an encoder that wrote over them would
 * change the meaning of a block that decodes perfectly, and a decoder that
 * read them as part of the number would read an index nobody sent.
 *
 * \~spanish
 * Esos bits dicen PARA QUE es el numero -- si la cabecera se esta indexando, si
 * se puede recordar -- asi que un codificador que los pisara cambiaria el
 * significado de un bloque que descodifica perfectamente, y un descodificador
 * que los leyera como parte del numero leeria un indice que no mando nadie.
 *
 * \~
 */
void test_the_bits_above() {
    uint8_t out[16];

    const size_t n = http_vx::h2::hpack::encode_int(out, 2, 6, 0x40);
    check(n == 1 && out[0] == 0x42, "the bits above the prefix were written over");

    const uint8_t indexed[] = {0x82};
    const IntResult r = http_vx::h2::hpack::decode_int(indexed, 1, 7);
    check(r.status == Status::Ok && r.value == 2,
          "the bit above the prefix was read as part of the number");

    /* \~english
     * And the same byte read with a different prefix is a different number,
     * which is why the prefix is an argument and not a constant.
     * \~spanish
     * Y el mismo byte leido con otro prefijo es otro numero, que es la razon de
     * que el prefijo sea un argumento y no una constante.
     * \~ */
    const IntResult six = http_vx::h2::hpack::decode_int(indexed, 1, 6);
    check(six.status == Status::Ok && six.value == 2,
          "six bits of 0x82 is not two");
    const IntResult four = http_vx::h2::hpack::decode_int(indexed, 1, 4);
    check(four.status == Status::Ok && four.value == 2,
          "four bits of 0x82 is not two");
}

/**
 * @brief
 * \~english Out and back, across every prefix and the edges of each.
 * \~spanish De ida y vuelta, por todos los prefijos y los extremos de cada uno.
 * \~
 *
 * \~english
 * The value that exactly fills the prefix is the one an encoder gets wrong: it
 * is one less than the mask that means "there is more", so writing it in the
 * byte would say the opposite of what it means.
 *
 * \~spanish
 * El valor que llena exactamente el prefijo es el que yerra un codificador: es
 * uno menos que la mascara que quiere decir "hay mas", asi que escribirlo en el
 * byte diria lo contrario de lo que significa.
 *
 * \~
 */
void test_round_trip() {
    uint8_t out[16];

    for (uint8_t bits = 1; bits <= 8; ++bits) {
        const uint64_t mask = (uint64_t{1} << bits) - 1;

        const uint64_t values[] = {0,
                                   1,
                                   mask - 1,
                                   mask,
                                   mask + 1,
                                   127,
                                   128,
                                   255,
                                   256,
                                   16383,
                                   16384,
                                   65535,
                                   1337,
                                   0x7FFFFFFFull,
                                   0xFFFFFFFEull,
                                   0xFFFFFFFFull};

        for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
            const uint64_t want = values[i];
            const size_t n = http_vx::h2::hpack::encode_int(out, want, bits, 0);
            check(n <= http_vx::h2::hpack::kMaxIntBytes + 1,
                  "a number took more bytes than the most it can");

            const IntResult r = http_vx::h2::hpack::decode_int(out, n, bits);
            check(r.status == Status::Ok, "a number that was written did not read");
            check(r.value == want, "a number came back as a different one");
            check(r.used == n, "reading it took a different number of bytes");
        }
    }
}

/**
 * @brief
 * \~english The bytes that run out, and the ones that never do.
 * \~spanish Los bytes que se acaban, y los que no se acaban nunca.
 * \~
 */
void test_refusals() {
    /* \~english
     * A prefix full of ones promises more and there is none.  It is not a
     * short read to wait on: a header block arrives whole, so a block that
     * ends inside a number is a block that lies about itself.
     * \~spanish
     * Un prefijo lleno de unos promete mas y no hay.  No es una lectura corta
     * que esperar: un bloque de cabeceras llega entero, asi que uno que acabe
     * dentro de un numero es un bloque que miente sobre si mismo.
     * \~ */
    const uint8_t promise[] = {0x1F};
    IntResult r = http_vx::h2::hpack::decode_int(promise, 1, 5);
    check(r.status == Status::Truncated, "a number that ends nowhere was read");

    const uint8_t more[] = {0x1F, 0x80};
    r = http_vx::h2::hpack::decode_int(more, 2, 5);
    check(r.status == Status::Truncated,
          "a continuation that promises more and ends was read");

    r = http_vx::h2::hpack::decode_int(nullptr, 4, 5);
    check(r.status == Status::Truncated, "nothing at all was read");
    r = http_vx::h2::hpack::decode_int(promise, 0, 5);
    check(r.status == Status::Truncated, "no bytes at all were read");

    /* \~english
     * THE ONE THAT MATTERS.  Every one of these bytes adds nothing to the
     * value -- seven zero bits, shifted somewhere -- so the value never grows
     * and a limit on the value alone never fires.  What grows is how long it
     * takes to read them, and a sender can make that as long as it likes.
     *
     * It is the flood of empty CONTINUATION frames again, one layer down: a
     * limit on how much something is worth does not limit how much of it there
     * is.
     *
     * \~spanish
     * EL QUE IMPORTA.  Ninguno de estos bytes anade nada al valor -- siete bits
     * a cero, desplazados a alguna parte -- asi que el valor no crece y un
     * limite solo sobre el valor no salta nunca.  Lo que crece es lo que se
     * tarda en leerlos, y quien envia puede hacerlo tan largo como quiera.
     *
     * Es otra vez la riada de CONTINUATION vacias, una capa mas abajo: un
     * limite sobre cuanto vale algo no limita cuanto hay de ello.
     *
     * \~ */
    const uint8_t padded[] = {0x1F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
    r = http_vx::h2::hpack::decode_int(padded, sizeof(padded), 5);
    check(r.status == Status::TooLarge,
          "a number padded with bytes that add nothing was read");

    /* \~english And a value that is simply too big for anything it could name.
     * \~spanish Y un valor sencillamente demasiado grande para lo que nombraria.  \~ */
    const uint8_t huge[] = {0x1F, 0xE1, 0xFF, 0xFF, 0xFF, 0x7F};
    r = http_vx::h2::hpack::decode_int(huge, sizeof(huge), 5);
    check(r.status == Status::TooLarge, "a number past four thousand million was read");

    /* \~english
     * A prefix that is not one to eight is a mistake in the code above, and it
     * is refused rather than worked around.
     * \~spanish
     * Un prefijo que no sea de uno a ocho es una equivocacion del codigo de
     * arriba, y se rechaza en vez de arreglarlo.
     * \~ */
    const uint8_t any[] = {0x00};
    check(http_vx::h2::hpack::decode_int(any, 1, 0).status == Status::Malformed,
          "a prefix of zero bits was accepted");
    check(http_vx::h2::hpack::decode_int(any, 1, 9).status == Status::Malformed,
          "a prefix of nine bits was accepted");
}

/**
 * @brief
 * \~english Indices start at one, and stop where the table does.
 * \~spanish Los indices empiezan en uno, y acaban donde acaba la tabla.
 * \~
 *
 * \~english
 * Zero is the one index a block may not use.  An implementation that read it
 * as the first entry -- which is what indexing an array from zero does --
 * would resolve every index in that block one place out, and the block would
 * still decode: into a message nobody sent.
 *
 * \~spanish
 * El cero es el unico indice que un bloque no puede usar.  Una implementacion
 * que lo leyera como la primera entrada -- que es lo que hace indexar un array
 * desde cero -- resolveria todos los indices de ese bloque con un sitio de
 * diferencia, y el bloque se seguiria descodificando: en un mensaje que no
 * mando nadie.
 *
 * \~
 */
void test_static_bounds() {
    using http_vx::h2::hpack::static_entry;

    check(static_entry(0) == nullptr, "index zero named an entry");
    check(static_entry(1) != nullptr, "index one named nothing");
    check(static_entry(http_vx::h2::hpack::kStaticEntries) != nullptr,
          "the last index named nothing");
    check(static_entry(http_vx::h2::hpack::kStaticEntries + 1) == nullptr,
          "one past the last named an entry");
    check(static_entry(~uint64_t{0}) == nullptr, "an enormous index named an entry");

    const http_vx::h2::hpack::StaticEntry *first = static_entry(1);
    check(first != nullptr && std::strcmp(first->name, ":authority") == 0,
          "the first entry is not :authority, so the whole table is shifted");

    const http_vx::h2::hpack::StaticEntry *last =
        static_entry(http_vx::h2::hpack::kStaticEntries);
    check(last != nullptr && std::strcmp(last->name, "www-authenticate") == 0,
          "the last entry is not www-authenticate");

    /* \~english
     * Two entries the specification gives a value as well as a name, which is
     * what makes `GET /` cost two bytes.
     * \~spanish
     * Dos entradas a las que la especificacion da valor ademas de nombre, que
     * es lo que hace que `GET /` cueste dos bytes.
     * \~ */
    const http_vx::h2::hpack::StaticEntry *get = static_entry(2);
    check(get != nullptr && std::strcmp(get->name, ":method") == 0 &&
              std::strcmp(get->value, "GET") == 0,
          "entry two is not the GET method");
    const http_vx::h2::hpack::StaticEntry *root = static_entry(4);
    check(root != nullptr && std::strcmp(root->value, "/") == 0,
          "entry four is not the root path");
}

/**
 * @brief
 * \~english Every row agrees with the other table.
 * \~spanish Todas las filas coinciden con la otra tabla.
 * \~
 *
 * \~english
 * This is the check the static table needs.  Its identifiers are written by
 * hand, and a hand-written identifier can be wrong in a way that decodes
 * perfectly -- a block that says `content-length` and arrives as something
 * else.  So each one is asked of @c field_id_of, which got its answer from a
 * different table written for a different reason.
 *
 * A row that says @c Unknown is checked too, and that half matters more: it is
 * what catches a field this project DOES know that the static table forgot to
 * name, which would send every one of them down the slow path for no reason.
 *
 * \~spanish
 * Esta es la comprobacion que necesita la tabla estatica.  Sus identificadores
 * se escriben a mano, y uno escrito a mano puede estar mal de una forma que
 * descodifica perfectamente -- un bloque que dice `content-length` y llega como
 * otra cosa --.  Asi que cada uno se le pregunta a @c field_id_of, que saco su
 * respuesta de otra tabla escrita por otra razon.
 *
 * Una fila que dice @c Unknown se comprueba tambien, y esa mitad importa mas:
 * es la que pilla una cabecera que este proyecto SI conoce y que la tabla
 * estatica se olvido de nombrar, lo que mandaria todas ellas por el camino
 * lento sin motivo.
 *
 * \~
 */
void test_rows_agree_with_the_field_table() {
    for (uint64_t i = 1; i <= http_vx::h2::hpack::kStaticEntries; ++i) {
        const http_vx::h2::hpack::StaticEntry *e =
            http_vx::h2::hpack::static_entry(i);
        check(e != nullptr, "an entry inside the table is missing");
        if (e == nullptr) continue;

        check(e->name_len == std::strlen(e->name),
              "a stored name length does not match the name");
        check(e->value_len == std::strlen(e->value),
              "a stored value length does not match the value");

        /* \~english
         * Lower case, all of them.  HTTP/2 requires it on the wire, and a
         * static entry with a capital in it would be a name this server sends
         * that the peer must refuse.
         * \~spanish
         * En minusculas, todas.  HTTP/2 lo exige en el cable, y una entrada
         * estatica con una mayuscula seria un nombre que manda este servidor y
         * que el otro extremo tiene que rechazar.
         * \~ */
        for (size_t j = 0; j < e->name_len; ++j)
            check(!(e->name[j] >= 'A' && e->name[j] <= 'Z'),
                  "a static name has a capital letter in it");

        if (e->pseudo != Pseudo::None) {
            check(e->name[0] == ':', "a pseudo-header does not start with a colon");
            check(e->id == http_vx::FieldId::Unknown,
                  "a pseudo-header claims to be an ordinary field as well");
            continue;
        }

        check(e->name[0] != ':', "an ordinary field starts with a colon");
        check(http_vx::field_id_of(e->name, e->name_len) == e->id,
              "a static entry and the field table disagree about what it is");
    }
}

/**
 * @brief
 * \~english The five pieces a pseudo-header turns into.
 * \~spanish Las cinco piezas en las que se convierte una pseudo-cabecera.
 * \~
 *
 * \~english
 * They are not fields and they are not meant to become fields: they are the
 * parts @c Request already holds separately, which it does for this.  A
 * handler reads the same five things whichever version brought them.
 *
 * \~spanish
 * No son cabeceras y no tienen que convertirse en cabeceras: son las partes que
 * @c Request ya guarda aparte, cosa que hace por esto.  Un manejador lee las
 * mismas cinco cosas por la version que le llegaran.
 *
 * \~
 */
void test_pseudo_headers() {
    struct Want {
        uint64_t index;
        Pseudo pseudo;
        const char *name;
    };
    const Want wants[] = {
        {1, Pseudo::Authority, ":authority"}, {2, Pseudo::Method, ":method"},
        {4, Pseudo::Path, ":path"},           {6, Pseudo::Scheme, ":scheme"},
        {8, Pseudo::Status, ":status"},
    };

    for (size_t i = 0; i < sizeof(wants) / sizeof(wants[0]); ++i) {
        const http_vx::h2::hpack::StaticEntry *e =
            http_vx::h2::hpack::static_entry(wants[i].index);
        check(e != nullptr && e->pseudo == wants[i].pseudo,
              "a pseudo-header is not the piece it should be");
        check(e != nullptr && std::strcmp(e->name, wants[i].name) == 0,
              "a pseudo-header is not at the index it should be");
    }

    /* \~english
     * And the first ordinary one, right after them: fourteen pseudo-headers,
     * and the fifteenth entry is a field.
     * \~spanish
     * Y la primera corriente, justo detras: catorce pseudo-cabeceras, y la
     * entrada quince es una cabecera.
     * \~ */
    const http_vx::h2::hpack::StaticEntry *fifteenth =
        http_vx::h2::hpack::static_entry(15);
    check(fifteenth != nullptr && fifteenth->pseudo == Pseudo::None,
          "the fifteenth entry is still a pseudo-header");
    check(fifteenth != nullptr &&
              std::strcmp(fifteenth->name, "accept-charset") == 0,
          "the fifteenth entry is not accept-charset");
}

} // namespace

int main() {
    test_the_specification_examples();
    test_the_bits_above();
    test_round_trip();
    test_refusals();
    test_static_bounds();
    test_rows_agree_with_the_field_table();
    test_pseudo_headers();

    if (failures != 0) {
        std::fprintf(stderr, "test_h2_hpack: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h2_hpack: ok\n");
    return 0;
}
