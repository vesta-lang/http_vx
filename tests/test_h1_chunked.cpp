/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_chunked.cpp
 * @brief
 * \~english Reading a chunked body, and the grammar around each piece.
 * \~spanish Leer un cuerpo troceado, y la gramatica que rodea cada pedazo.
 * \~
 *
 * \~english
 * Every body here is read twice, whole and a byte at a time, and the pieces
 * that come back must be the same bytes in the same order.  It is the same
 * check the head's parser gets and for the same reason, with one addition that
 * is particular to a body: a chunk split across two reads comes back as two
 * pieces rather than one, so the two passes are allowed to differ in HOW MANY
 * pieces they hand over -- and not in a single byte of what those pieces
 * contain.
 *
 * \~spanish
 * Todos los cuerpos de aqui se leen dos veces, enteros y byte a byte, y los
 * pedazos que vuelven tienen que ser los mismos bytes en el mismo orden.  Es la
 * misma comprobacion que recibe el analizador de la cabeza y por lo mismo, con
 * un anadido propio de un cuerpo: un trozo partido entre dos lecturas vuelve
 * como dos pedazos y no como uno, asi que las dos pasadas pueden diferir en
 * CUANTOS pedazos entregan -- y no en un solo byte de lo que esos pedazos
 * llevan dentro.
 *
 * \~
 */

#include "http_vx/h1_chunked.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h1::ChunkError;
using http_vx::h1::ChunkedReader;
using http_vx::h1::ChunkResult;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english What reading one body came to.
 * \~spanish A que llego la lectura de un cuerpo.
 * \~
 */
struct Reading {
    ChunkResult result;
    ChunkError error;
    size_t consumed;
    uint64_t body_bytes;
    size_t trailer_count;
    char body[512];
    size_t body_len;
};

/**
 * @brief
 * \~english Reads @p msg, letting @p step new bytes in at a time.
 * \~spanish Lee @p msg, dejando entrar @p step bytes nuevos cada vez.
 * \~
 *
 * \~english
 * @p step of zero means everything at once.  The pieces are stitched together
 * as they come, which is what a handler that wanted the whole body would do --
 * and doing it here, in the test, is where it belongs: the reader itself never
 * holds more than one piece.
 *
 * \~spanish
 * Un @p step de cero quiere decir todo de una vez.  Los pedazos se cosen segun
 * llegan, que es lo que haria un manejador que quisiera el cuerpo entero -- y
 * hacerlo aqui, en la prueba, es donde corresponde: el lector nunca tiene mas
 * de un pedazo.
 *
 * \~
 */
Reading read_body(const char *msg, size_t step,
                  const http_vx::h1::Limits &limits) {
    Reading out{};
    const uint8_t *d = reinterpret_cast<const uint8_t *>(msg);
    const size_t len = std::strlen(msg);

    ChunkedReader r(limits);
    r.reset(0);
    http_vx::Fields trailers;

    size_t given = step == 0 ? len : 0;
    for (;;) {
        const ChunkResult res = r.read(http_vx::View{d, given, 0}, trailers);

        if (res == ChunkResult::Data) {
            const http_vx::Span s = r.chunk();
            if (out.body_len + s.len <= sizeof(out.body)) {
                std::memcpy(out.body + out.body_len, d + s.off, s.len);
                out.body_len += s.len;
            }
            continue;
        }

        if (res == ChunkResult::NeedMore) {
            if (given == len) {
                out.result = res;
                break;
            }
            given += step == 0 ? len : step;
            if (given > len) given = len;
            continue;
        }

        out.result = res;
        break;
    }

    out.error = r.error();
    out.consumed = static_cast<size_t>(r.consumed());
    out.body_bytes = r.body_bytes();
    out.trailer_count = trailers.size();
    return out;
}

/**
 * @brief
 * \~english Checks that @p msg reads as @p want, whole and in pieces.
 * \~spanish Comprueba que @p msg se lee como @p want, entero y a trozos.
 * \~
 */
void reads_as(const char *msg, const char *want, const char *what) {
    const http_vx::h1::Limits limits;
    const Reading whole = read_body(msg, 0, limits);
    const Reading drip = read_body(msg, 1, limits);

    check(whole.result == ChunkResult::Done, what);
    check(whole.error == ChunkError::None, what);
    check(whole.body_len == std::strlen(want), what);
    check(whole.body_len == std::strlen(want) &&
              std::memcmp(whole.body, want, whole.body_len) == 0,
          what);
    check(whole.consumed == std::strlen(msg), what);
    check(whole.body_bytes == std::strlen(want), what);

    /* \~english
     * And the same body when it arrives a byte at a time, which is where a
     * reader that carries state across calls goes wrong without saying so.
     * \~spanish
     * Y el mismo cuerpo cuando llega byte a byte, que es donde se equivoca sin
     * decirlo un lector que arrastra estado entre llamadas.
     * \~ */
    check(drip.result == whole.result, what);
    check(drip.error == whole.error, what);
    check(drip.consumed == whole.consumed, what);
    check(drip.body_len == whole.body_len, what);
    check(drip.body_len == whole.body_len &&
              std::memcmp(drip.body, whole.body, drip.body_len) == 0,
          what);
}

/**
 * @brief
 * \~english Checks that @p msg is refused for the reason @p why, both ways.
 * \~spanish Comprueba que @p msg se rechaza por @p why, de las dos formas.
 * \~
 */
void refuses(const char *msg, ChunkError why, const char *what) {
    const http_vx::h1::Limits limits;
    const Reading whole = read_body(msg, 0, limits);
    const Reading drip = read_body(msg, 1, limits);

    check(whole.result == ChunkResult::Error, what);
    check(whole.error == why, what);
    check(drip.result == ChunkResult::Error, what);
    check(drip.error == why, what);
}

/**
 * @brief
 * \~english The ordinary bodies.
 * \~spanish Los cuerpos corrientes.
 * \~
 */
void test_ordinary() {
    reads_as("0\r\n\r\n", "", "an empty body was not read as empty");
    reads_as("5\r\nhello\r\n0\r\n\r\n", "hello", "one chunk was not read");
    reads_as("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", "hello world",
             "two chunks were not stitched together");

    /* \~english
     * Hexadecimal, and case does not matter in it.  A reader that took these
     * as decimal would read sixteen bytes as ten and find the next chunk
     * header six bytes into the body.
     * \~spanish
     * Hexadecimal, y en el las mayusculas dan igual.  Un lector que los tomara
     * por decimales leeria dieciseis bytes como diez y encontraria la cabecera
     * del trozo siguiente seis bytes dentro del cuerpo.
     * \~ */
    reads_as("a\r\n0123456789\r\n0\r\n\r\n", "0123456789",
             "a lower-case hex size was not read");
    reads_as("A\r\n0123456789\r\n0\r\n\r\n", "0123456789",
             "an upper-case hex size was not read");

    /* \~english Leading zeros are legal.  \~spanish Los ceros a la izquierda son legales.  \~ */
    reads_as("0005\r\nhello\r\n000\r\n\r\n", "hello",
             "leading zeros in a size were refused");
}

/**
 * @brief
 * \~english Extensions are ignored, and still have to be well formed.
 * \~spanish Las extensiones se ignoran, y aun asi tienen que estar bien formadas.
 * \~
 */
void test_extensions() {
    reads_as("5;a=b\r\nhello\r\n0\r\n\r\n", "hello",
             "a chunk with an extension was not read");
    reads_as("5;a\r\nhello\r\n0;last\r\n\r\n", "hello",
             "an extension without a value was not read");

    /* \~english
     * The size ends at the semicolon.  A reader that kept reading digits
     * through it would read `5;10` as something other than five.
     * \~spanish
     * El tamano acaba en el punto y coma.  Un lector que siguiera leyendo
     * digitos a traves de el leeria `5;10` como algo distinto de cinco.
     * \~ */
    reads_as("5;x=10\r\nhello\r\n0\r\n\r\n", "hello",
             "digits in an extension changed the size");

    refuses("5;a\nb\r\nhello\r\n0\r\n\r\n", ChunkError::BareLineFeed,
            "a line feed inside an extension was accepted");
}

/**
 * @brief
 * \~english The sizes that are not sizes.
 * \~spanish Los tamanos que no son tamanos.
 * \~
 */
void test_bad_sizes() {
    refuses("\r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a chunk with no size was accepted");
    refuses("0x5\r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a size written the C way was accepted");
    refuses("+5\r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a signed size was accepted");
    refuses(" 5\r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a size with a space before it was accepted");
    refuses("5 \r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a size with a space after it was accepted");
    refuses("g\r\nhello\r\n0\r\n\r\n", ChunkError::BadChunkSize,
            "a letter past f was accepted as a digit");

    /* \~english
     * A run of zeros longer than a size can need.  It is legal by the grammar
     * and refused anyway: it names nothing that sixteen digits cannot name,
     * and what it does name is a peer writing forever without sending a chunk.
     * \~spanish
     * Una tirada de ceros mas larga de lo que puede necesitar un tamano.  Es
     * legal por la gramatica y se rechaza igual: no nombra nada que no puedan
     * nombrar dieciseis digitos, y lo que si nombra es un extremo escribiendo
     * sin parar sin mandar un trozo.
     * \~ */
    refuses("00000000000000000\r\n\r\n", ChunkError::ChunkSizeTooLong,
            "seventeen digits of size were accepted");
}

/**
 * @brief
 * \~english The line endings around a chunk.
 * \~spanish Los finales de linea alrededor de un trozo.
 * \~
 */
void test_line_endings() {
    refuses("5\nhello\r\n0\r\n\r\n", ChunkError::BareLineFeed,
            "a size line ending in a bare line feed was accepted");
    refuses("5\r\nhello\n0\r\n\r\n", ChunkError::BareLineFeed,
            "a chunk ending in a bare line feed was accepted");

    /* \~english
     * Data not followed by the ending at all.  It is refused and not
     * resynchronised: a reader that hunts for the next plausible chunk header
     * finds one wherever the sender chose to put it.
     * \~spanish
     * Datos sin el final detras.  Se rechaza y no se resincroniza: un lector
     * que busque la siguiente cabecera de trozo plausible encuentra una donde
     * quien envia la haya querido poner.
     * \~ */
    refuses("5\r\nhelloXX\r\n0\r\n\r\n", ChunkError::BadChunkTerminator,
            "a chunk without its ending was accepted");
    refuses("5\r\nhello\r0\r\n\r\n", ChunkError::BareCarriageReturn,
            "a carriage return without a line feed was accepted");
}

/**
 * @brief
 * \~english The trailers, and the ones that may not be trailers.
 * \~spanish Los remolques, y los que no pueden serlo.
 * \~
 */
void test_trailers() {
    {
        const http_vx::h1::Limits limits;
        const Reading r =
            read_body("5\r\nhello\r\n0\r\nX-Sum: abc\r\nX-Other: 1\r\n\r\n", 0,
                      limits);
        check(r.result == ChunkResult::Done, "a body with trailers was not read");
        check(r.trailer_count == 2, "the trailers were not recorded");
        check(r.body_len == 5, "the trailers were read as body");
    }

    /* \~english
     * And the ones the specification forbids.  A trailer arrives after the
     * decisions these fields drive were taken, so accepting one is accepting
     * an answer to a question that was already answered -- and in the case of
     * the framing fields, a second answer to how long the body just read was.
     * \~spanish
     * Y los que prohibe la especificacion.  Un remolque llega despues de que se
     * tomaran las decisiones que gobiernan estas cabeceras, asi que aceptar uno
     * es aceptar una respuesta a una pregunta ya contestada -- y en el caso de
     * las de troceado, una segunda respuesta a cuanto media el cuerpo que se
     * acaba de leer.
     * \~ */
    refuses("0\r\nContent-Length: 5\r\n\r\n", ChunkError::ForbiddenTrailer,
            "a Content-Length trailer was accepted");
    refuses("0\r\nTransfer-Encoding: chunked\r\n\r\n",
            ChunkError::ForbiddenTrailer,
            "a Transfer-Encoding trailer was accepted");
    refuses("0\r\nHost: elsewhere\r\n\r\n", ChunkError::ForbiddenTrailer,
            "a Host trailer was accepted");
    refuses("0\r\nAuthorization: x\r\n\r\n", ChunkError::ForbiddenTrailer,
            "an Authorization trailer was accepted");

    /* \~english
     * Case does not matter in a field name, here as everywhere: a rule that
     * only catches the canonical spelling is a rule with a spelling that gets
     * around it.
     * \~spanish
     * Las mayusculas no importan en un nombre de cabecera, aqui como en todas
     * partes: una regla que solo pilla la grafia canonica es una regla con una
     * grafia que la rodea.
     * \~ */
    refuses("0\r\ncOnTeNt-LeNgTh: 5\r\n\r\n", ChunkError::ForbiddenTrailer,
            "a differently spelled Content-Length trailer was accepted");

    refuses("0\r\nX: a\r\n Y: b\r\n\r\n", ChunkError::ObsoleteLineFolding,
            "a folded trailer was joined instead of refused");
    refuses("0\r\nX : a\r\n\r\n", ChunkError::BadTrailerName,
            "a trailer with a space before the colon was accepted");
}

/**
 * @brief
 * \~english The limits, and when the body one is checked.
 * \~spanish Los limites, y cuando se comprueba el del cuerpo.
 * \~
 */
void test_limits() {
    {
        /* \~english
         * The body limit is checked against what the chunk ANNOUNCES, before a
         * byte of it is taken.  So a chunk claiming more than the limit is
         * refused even though the bytes behind it never arrive.
         * \~spanish
         * El limite del cuerpo se comprueba contra lo que el trozo ANUNCIA,
         * antes de coger un byte de el.  Asi que un trozo que diga mas que el
         * limite se rechaza aunque los bytes de detras no lleguen nunca.
         * \~ */
        http_vx::h1::Limits limits;
        limits.max_body_bytes = 4;
        const Reading r = read_body("ffffffff\r\n", 0, limits);
        check(r.result == ChunkResult::Error, "an oversized chunk was accepted");
        check(r.error == ChunkError::BodyTooLarge,
              "an oversized chunk was refused for the wrong reason");
        check(r.body_bytes == 0, "bytes were counted before being refused");
    }
    {
        /* \~english
         * And across chunks, because each one on its own may be small.
         * \~spanish
         * Y entre trozos, porque cada uno por su cuenta puede ser pequeno.
         * \~ */
        http_vx::h1::Limits limits;
        limits.max_body_bytes = 8;
        const Reading r =
            read_body("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n", 0, limits);
        check(r.error == ChunkError::BodyTooLarge,
              "two chunks over the limit between them were accepted");
    }
    {
        http_vx::h1::Limits limits;
        limits.max_trailers = 1;
        const Reading r = read_body("0\r\nA: 1\r\nB: 2\r\n\r\n", 0, limits);
        check(r.error == ChunkError::TrailersTooLarge,
              "more trailers than allowed were accepted");
    }
    {
        http_vx::h1::Limits limits;
        limits.max_chunk_extension = 4;
        const Reading r = read_body("5;aaaaaaaaaa\r\nhello\r\n0\r\n\r\n", 0, limits);
        check(r.error == ChunkError::BadChunkExtension,
              "an extension longer than allowed was accepted");
    }
}

/**
 * @brief
 * \~english What the body ends at is where the next message starts.
 * \~spanish Donde acaba el cuerpo es donde empieza el mensaje siguiente.
 * \~
 */
void test_consumed() {
    const http_vx::h1::Limits limits;
    const char *msg = "5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\n";
    const size_t body = std::strlen("5\r\nhello\r\n0\r\n\r\n");

    const Reading r = read_body(msg, 0, limits);
    check(r.result == ChunkResult::Done, "the body was not read");
    check(r.consumed == body, "the body swallowed part of the next message");
    check(r.body_len == 5, "the next message was read as body");
}

/**
 * @brief
 * \~english Which fields may not be trailers, asked directly.
 * \~spanish Que cabeceras no pueden ser remolque, preguntado directamente.
 * \~
 */
void test_forbidden_set() {
    using http_vx::FieldId;
    using http_vx::h1::field_forbidden_in_trailers;

    check(field_forbidden_in_trailers(FieldId::ContentLength), "framing is allowed");
    check(field_forbidden_in_trailers(FieldId::TransferEncoding),
          "framing is allowed");
    check(field_forbidden_in_trailers(FieldId::Host), "routing is allowed");
    check(field_forbidden_in_trailers(FieldId::Connection),
          "connection control is allowed");
    check(field_forbidden_in_trailers(FieldId::CacheControl),
          "cache control is allowed");

    /* \~english
     * And what IS allowed, because a rule that forbids everything is a rule
     * that makes the feature useless: a checksum computed while sending is the
     * reason trailers exist.
     * \~spanish
     * Y lo que SI se permite, porque una regla que lo prohiba todo es una regla
     * que deja la caracteristica sin uso: un resumen calculado mientras se
     * envia es la razon de que existan los remolques.
     * \~ */
    check(!field_forbidden_in_trailers(FieldId::Unknown),
          "an unrecognised trailer is forbidden, which forbids all of them");
    check(!field_forbidden_in_trailers(FieldId::ETag), "an entity tag is forbidden");
    check(!field_forbidden_in_trailers(FieldId::Date), "a date is forbidden");
}

/**
 * @brief
 * \~english What each refusal is answered with.
 * \~spanish Con que se contesta a cada rechazo.
 * \~
 */
void test_status_mapping() {
    using http_vx::h1::chunk_status;
    check(chunk_status(ChunkError::None) == 0, "nothing wrong has a status");
    check(chunk_status(ChunkError::BadChunkSize) == 400, "a bad size is not a 400");
    check(chunk_status(ChunkError::ForbiddenTrailer) == 400,
          "a forbidden trailer is not a 400");
    check(chunk_status(ChunkError::BodyTooLarge) == 413,
          "a body over the limit is not a 413");
    check(chunk_status(ChunkError::TrailersTooLarge) == 431,
          "trailers over the limit are not a 431");
}

} // namespace

int main() {
    test_ordinary();
    test_extensions();
    test_bad_sizes();
    test_line_endings();
    test_trailers();
    test_limits();
    test_consumed();
    test_forbidden_set();
    test_status_mapping();

    if (failures != 0) {
        std::fprintf(stderr, "test_h1_chunked: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h1_chunked: ok\n");
    return 0;
}
