/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_encoder.cpp
 * @brief
 * \~english Writing a header block, and reading it back with the other half.
 * \~spanish Escribir un bloque de cabeceras, y leerlo con la otra mitad.
 * \~
 *
 * \~english
 * Most of this is a round trip, and that is not laziness about writing
 * expected bytes: the thing that can go wrong here is not a wrong byte, it is
 * TWO TABLES that stop agreeing.  A test that compared bytes would pass on a
 * block that is perfectly well-formed and names the wrong fields, because the
 * bytes of an index are right either way -- what is wrong is what the index
 * points at, and only the other end can say.
 *
 * So the encoder writes and the decoder reads, one of each per connection, for
 * several messages in a row, and the test is that what comes out the far end
 * is what went in.  Shrinking is checked as well: a field written a second
 * time must cost less, because that is the only evidence that the remembering
 * is really happening rather than being quietly skipped.
 *
 * The exceptions are the three places where an exact byte IS the point: a
 * status of 200 in one byte, a whole field from the static table in one byte,
 * and the representation that asks the whole path to forget.
 *
 * \~spanish
 * Casi todo esto es una ida y vuelta, y no por pereza de escribir los bytes
 * esperados: lo que puede salir mal aqui no es un byte equivocado, son DOS
 * TABLAS que dejan de estar de acuerdo.  Una prueba que comparara bytes pasaria
 * con un bloque perfectamente bien formado que nombra otras cabeceras, porque
 * los bytes de un indice estan bien en los dos casos -- lo que esta mal es a
 * que apunta el indice, y eso solo lo puede decir el otro extremo.
 *
 * Asi que el codificador escribe y el descodificador lee, uno de cada por
 * conexion, varios mensajes seguidos, y la prueba es que lo que sale por el
 * otro lado es lo que entro.  Se comprueba ademas el encogimiento: una cabecera
 * escrita por segunda vez tiene que costar menos, porque esa es la unica prueba
 * de que el recordar esta pasando de verdad y no se esta saltando en silencio.
 *
 * Las excepciones son los tres sitios donde el byte exacto SI es lo que
 * importa: un estado 200 en un byte, una cabecera entera de la tabla estatica
 * en un byte, y la representacion que le pide a todo el camino que olvide.
 *
 * \~
 */

#include "http_vx/h2_decoder.h"
#include "http_vx/h2_encoder.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::FieldId;
using http_vx::h2::ErrorCode;
using http_vx::h2::hpack::Decoder;
using http_vx::h2::hpack::Encoder;
using http_vx::h2::hpack::Indexing;
using http_vx::h2::hpack::WriteStatus;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

const uint8_t *bytes_of(const char *s) {
    return reinterpret_cast<const uint8_t *>(s);
}

WriteStatus put(Encoder &e, http_vx::Buffer &out, const char *name,
                const char *value, Indexing how = Indexing::WithoutIndexing) {
    return e.write_field(out, bytes_of(name), std::strlen(name),
                         bytes_of(value), std::strlen(value), how);
}

WriteStatus put(Encoder &e, http_vx::Buffer &out, FieldId id,
                const char *value, Indexing how = Indexing::WithoutIndexing) {
    return e.write_field(out, id, bytes_of(value), std::strlen(value), how);
}

bool span_is(uint32_t off, uint32_t len, const http_vx::Buffer &out,
             const char *want) {
    if (len != std::strlen(want)) return false;
    return std::memcmp(out.data() + off, want, len) == 0;
}

bool field_is(const http_vx::Request &req, const http_vx::Buffer &out, size_t i,
              const char *name, const char *value) {
    if (i >= req.fields.size()) return false;
    const http_vx::Field &f = req.fields.begin()[i];
    return span_is(f.name_off, f.name_len, out, name) &&
           span_is(f.value_off, f.value_len, out, value);
}

/**
 * @brief
 * \~english A status of 200 is one byte, and so is a whole static entry.
 * \~spanish Un estado 200 es un byte, y una entrada estatica entera tambien.
 * \~
 *
 * \~english
 * The exact bytes matter here because these are the cases HPACK exists for:
 * the common answer costs nothing to say.  If either of these ever grows, the
 * static table is not being consulted and every response on the wire got
 * bigger without anything failing.
 *
 * \~spanish
 * Los bytes exactos importan aqui porque estos son los casos para los que
 * existe HPACK: la respuesta corriente no cuesta nada decirla.  Si alguno de
 * estos crece alguna vez, es que no se esta consultando la tabla estatica y
 * todas las respuestas del cable se hicieron mayores sin que fallara nada.
 *
 * \~
 */
void test_the_common_answer_is_one_byte() {
    Encoder e;
    e.reset(4096);

    http_vx::Buffer out;
    check(e.write_status(out, 200) == WriteStatus::Ok,
          "a status of 200 was refused");
    check(out.size() == 1 && out.data()[0] == 0x88,
          "a status of 200 is not one byte naming entry eight");

    out.clear();
    check(e.write_status(out, 404) == WriteStatus::Ok,
          "a status of 404 was refused");
    check(out.size() == 1 && out.data()[0] == 0x8D,
          "a status of 404 is not one byte naming entry thirteen");

    /* \~english
     * Not one of the seven the table has, so the name is an index and the three
     * digits are spelled out: `0f` is the without-indexing form naming entry
     * eight, then a three-byte string.
     * \~spanish
     * No es de los siete que tiene la tabla, asi que el nombre es un indice y
     * las tres cifras se escriben: `0f` es la forma sin indexar nombrando la
     * entrada ocho, y detras una cadena de tres bytes.
     * \~ */
    out.clear();
    check(e.write_status(out, 451) == WriteStatus::Ok,
          "a status of 451 was refused");
    check(out.size() > 1,
          "a status the static table does not have came out in one byte");

    /* \~english
     * `accept-encoding: gzip, deflate` is entry sixteen with its value, so the
     * whole field is one byte.
     * \~spanish
     * `accept-encoding: gzip, deflate` es la entrada dieciseis con su valor, asi
     * que la cabecera entera es un byte.
     * \~ */
    out.clear();
    check(put(e, out, FieldId::AcceptEncoding, "gzip, deflate") ==
              WriteStatus::Ok,
          "accept-encoding was refused");
    check(out.size() == 1 && out.data()[0] == 0x90,
          "accept-encoding: gzip, deflate is not one byte naming entry sixteen");
}

/**
 * @brief
 * \~english What the peer reads is what was written.
 * \~spanish Lo que lee el otro extremo es lo que se escribio.
 * \~
 *
 * \~english
 * One encoder and one decoder, three messages, and the table carried between
 * them.  The second message says the same fields as the first and must be
 * SHORTER -- which is the only way to tell that the first was remembered on
 * both sides and not just on one.
 *
 * \~spanish
 * Un codificador y un descodificador, tres mensajes, y la tabla llevada entre
 * ellos.  El segundo mensaje dice las mismas cabeceras que el primero y tiene
 * que ser MAS CORTO -- que es la unica forma de saber que el primero se recordo
 * en los dos lados y no solo en uno.
 *
 * \~
 */
void test_the_two_tables_stay_in_step() {
    Encoder e;
    e.reset(4096);

    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    size_t first_size = 0;

    for (int round = 0; round < 3; ++round) {
        http_vx::Buffer block;

        check(put(e, block, FieldId::ContentType, "text/html; charset=utf-8",
                  Indexing::Incremental) == WriteStatus::Ok,
              "content-type was refused");
        check(put(e, block, "x-request-id", "abc123def456",
                  Indexing::Incremental) == WriteStatus::Ok,
              "x-request-id was refused");
        check(put(e, block, FieldId::ContentLength, "1024") == WriteStatus::Ok,
              "content-length was refused");

        if (round == 0) {
            first_size = block.size();
        } else {
            check(block.size() < first_size,
                  "saying the same fields again did not cost less");
        }

        http_vx::Buffer out;
        http_vx::Request req;
        const ErrorCode ec = d.decode(block.data(), block.size(), out, req);
        check(ec == ErrorCode::NoError, "the block did not decode");

        check(req.fields.size() == 3, "three fields did not come out");
        check(field_is(req, out, 0, "content-type",
                       "text/html; charset=utf-8"),
              "the first field is not content-type");
        check(field_is(req, out, 1, "x-request-id", "abc123def456"),
              "the second field is not x-request-id");
        check(field_is(req, out, 2, "content-length", "1024"),
              "the third field is not content-length");
    }

    /* \~english
     * The two tables are the same size because they were fed the same fields
     * in the same order.  It is a weaker statement than the round trip above
     * and it is here because it fails EARLIER: a divergence shows up as a
     * different count before it shows up as a wrong field.
     * \~spanish
     * Las dos tablas miden lo mismo porque se les dieron las mismas cabeceras en
     * el mismo orden.  Es una afirmacion mas floja que la ida y vuelta de arriba
     * y esta aqui porque falla ANTES: una discrepancia sale como una cuenta
     * distinta antes de salir como una cabecera equivocada.
     * \~ */
    check(e.table().count() == d.table().count(),
          "the two tables remember a different number of fields");
    check(e.table().size() == d.table().size(),
          "the two tables spend a different number of bytes");
}

/**
 * @brief
 * \~english A credential is refused, not quietly made safe.
 * \~spanish Una credencial se rechaza, no se hace segura por lo bajo.
 * \~
 *
 * \~english
 * And refused by BOTH ways of naming it.  A rule that only applied to the
 * identifier would be a rule with a door left open, and the open door is the
 * one a caller goes through whenever the identifier does not exist -- which is
 * every header this project has not heard of.
 *
 * \~spanish
 * Y rechazada por las DOS formas de nombrarla.  Una regla que solo valiera para
 * el identificador seria una regla con una puerta abierta, y la puerta abierta
 * es por la que pasa quien llama siempre que el identificador no existe -- que
 * son todas las cabeceras de las que este proyecto no ha oido hablar.
 *
 * \~
 */
void test_a_secret_is_never_remembered() {
    Encoder e;
    e.reset(4096);

    http_vx::Buffer out;

    check(put(e, out, FieldId::Authorization, "Bearer s3cr3t",
              Indexing::Incremental) == WriteStatus::MustNotBeIndexed,
          "authorization was allowed to be remembered");
    check(out.size() == 0, "a refused field still wrote bytes");
    check(e.table().count() == 0, "a refused field still went in the table");

    check(put(e, out, "cookie", "session=abc", Indexing::Incremental) ==
              WriteStatus::MustNotBeIndexed,
          "cookie spelled out was allowed to be remembered");
    check(out.size() == 0, "a refused spelled-out field still wrote bytes");

    /* \~english
     * Written the right way it goes out, and the first byte says what it is:
     * `0001` on top is the form that asks every intermediary to forget as well.
     * \~spanish
     * Escrita como toca sale, y el primer byte dice lo que es: `0001` arriba es
     * la forma que le pide tambien a todos los intermediarios que olviden.
     * \~ */
    check(put(e, out, FieldId::Authorization, "Bearer s3cr3t",
              Indexing::Never) == WriteStatus::Ok,
          "authorization was refused in the never-indexed form");
    check(out.size() > 0 && (out.data()[0] & 0xF0) == 0x10,
          "it did not go out in the form nobody remembers");
    check(e.table().count() == 0,
          "the never-indexed form still went in the table");

    /* \~english
     * Sent without being remembered is the ordinary way, and it must not be
     * refused: the caller is allowed to send a credential, it is only not
     * allowed to have it kept.
     * \~spanish
     * Mandarla sin recordarla es lo corriente, y no se puede rechazar: quien
     * llama puede mandar una credencial, lo que no puede es que se guarde.
     * \~ */
    check(put(e, out, FieldId::Authorization, "Bearer s3cr3t") ==
              WriteStatus::Ok,
          "authorization was refused without indexing");
}

/**
 * @brief
 * \~english The code is used when it shortens and not otherwise.
 * \~spanish El codigo se usa cuando acorta y no en otro caso.
 * \~
 *
 * \~english
 * HPACK leaves the choice to the sender, so a sender that always coded would
 * be making some messages bigger AND making the peer pay to decode them.  The
 * top bit of a string's length byte is what says which it was, so the test can
 * read the decision straight off the wire.
 *
 * \~spanish
 * HPACK deja elegir a quien envia, asi que quien codificara siempre estaria
 * agrandando algunos mensajes Y ademas haciendo pagar al otro extremo por
 * descodificarlos.  El bit de arriba del byte de longitud de una cadena es lo
 * que dice cual de las dos fue, asi que la prueba puede leer la decision
 * directamente del cable.
 *
 * \~
 */
void test_huffman_only_when_it_helps() {
    Encoder e;
    e.reset(4096);

    /* \~english
     * Lower-case letters are what the code was measured on, so a value of them
     * comes out shorter coded.
     * \~spanish
     * Las minusculas son sobre lo que se midio el codigo, asi que un valor de
     * ellas sale mas corto codificado.
     * \~ */
    http_vx::Buffer out;
    check(put(e, out, "x-thing", "aaaaaaaaaaaaaaaaaaaaaaaa") ==
              WriteStatus::Ok,
          "a value of letters was refused");

    /* \~english
     * The first byte is the representation, then the name's length, then the
     * name, then the value's length.  The top bit of that last one is the
     * answer.
     *
     * Where the value's length lands is READ and not assumed: the name is a
     * string too, and a name of lower-case letters is coded as well, so the
     * bytes it takes are not the letters it has.  Assuming they were is how
     * the first version of this test looked at the wrong byte and said the
     * encoder was choosing wrong.
     *
     * \~spanish
     * El primer byte es la representacion, luego la longitud del nombre, luego
     * el nombre, y luego la longitud del valor.  El bit de arriba de esa ultima
     * es la respuesta.
     *
     * Donde cae la longitud del valor se LEE y no se supone: el nombre tambien
     * es una cadena, y un nombre de minusculas tambien se codifica, asi que los
     * bytes que ocupa no son las letras que tiene.  Suponer que si es como la
     * primera version de esta prueba miro el byte equivocado y dijo que el
     * codificador elegia mal.
     * \~ */
    const size_t vlen_at = 2 + (out.data()[1] & 0x7F);
    check((out.data()[vlen_at] & 0x80) != 0, "a value of letters was not coded");

    /* \~english
     * Bytes the code was not measured on take more than eight bits each, so
     * coding them would make the value longer.
     * \~spanish
     * Los bytes sobre los que no se midio el codigo ocupan mas de ocho bits cada
     * uno, asi que codificarlos alargaria el valor.
     * \~ */
    uint8_t high[24];
    for (size_t i = 0; i < sizeof high; ++i) high[i] = 0xF8;

    out.clear();
    check(e.write_field(out, bytes_of("x-thing"), std::strlen("x-thing"), high,
                        sizeof high) == WriteStatus::Ok,
          "a binary value was refused");
    check((out.data()[vlen_at] & 0x80) == 0,
          "a binary value was coded, which makes it longer");

    /* \~english
     * And it survives the trip either way, which is what says the choice is
     * only about size.
     * \~spanish
     * Y sobrevive al viaje de las dos formas, que es lo que dice que la eleccion
     * es solo de tamano.
     * \~ */
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer decoded;
    http_vx::Request req;
    check(d.decode(out.data(), out.size(), decoded, req) == ErrorCode::NoError,
          "the block with the binary value did not decode");
    check(req.fields.size() == 1, "one field did not come out");

    const http_vx::Field &f = req.fields.begin()[0];
    check(f.value_len == sizeof high &&
              std::memcmp(decoded.data() + f.value_off, high, sizeof high) == 0,
          "the binary value did not come back the same");
}

/**
 * @brief
 * \~english A field bigger than the table empties it, on both sides.
 * \~spanish Una cabecera mayor que la tabla la vacia, en los dos lados.
 * \~
 *
 * \~english
 * The specification says so in as many words, and it is here because it is the
 * one case where remembering a field makes the table remember LESS.  An
 * encoder that treated it as an error would refuse a message it is allowed to
 * send; one that treated it as an ordinary add would think the peer had an
 * entry the peer threw away.
 *
 * \~spanish
 * La especificacion lo dice con todas las letras, y esta aqui porque es el
 * unico caso en que recordar una cabecera hace que la tabla recuerde MENOS.  Un
 * codificador que lo tratara como un error rechazaria un mensaje que puede
 * mandar; uno que lo tratara como un anadido corriente creeria que el otro
 * extremo tiene una entrada que el otro extremo tiro.
 *
 * \~
 */
void test_a_field_too_big_empties_both() {
    Encoder e;
    e.reset(64);

    Decoder d;
    http_vx::h2::Limits limits;
    limits.header_table_size = 64;
    d.reset(limits);

    http_vx::Buffer block;
    check(put(e, block, "x-small", "v", Indexing::Incremental) ==
              WriteStatus::Ok,
          "the small field was refused");
    check(e.table().count() == 1, "the small field was not remembered");

    char big[128];
    std::memset(big, 'a', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    check(put(e, block, "x-big", big, Indexing::Incremental) ==
              WriteStatus::Ok,
          "a field bigger than the whole table was refused");
    check(e.table().count() == 0,
          "a field bigger than the whole table did not empty it");

    http_vx::Buffer out;
    http_vx::Request req;
    check(d.decode(block.data(), block.size(), out, req) == ErrorCode::NoError,
          "the block did not decode");
    check(field_is(req, out, 0, "x-small", "v"),
          "the small field did not arrive");
    check(field_is(req, out, 1, "x-big", big), "the big field did not arrive");
    check(d.table().count() == 0, "the peer's table was not emptied too");
}

} // namespace

int main() {
    test_the_common_answer_is_one_byte();
    test_the_two_tables_stay_in_step();
    test_a_secret_is_never_remembered();
    test_huffman_only_when_it_helps();
    test_a_field_too_big_empties_both();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
