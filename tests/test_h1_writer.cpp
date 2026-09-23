/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_writer.cpp
 * @brief
 * \~english Writing a response, and every way of writing one that lies.
 * \~spanish Escribir una respuesta, y todas las formas de escribir una que miente.
 * \~
 *
 * \~english
 * The bytes are compared in full rather than inspected field by field.  A
 * response is read by somebody else's parser and what it sees is the bytes, so
 * a test that checked "it has a content length somewhere" would pass a
 * response with two of them, or with one in the wrong place, or with the blank
 * line missing.
 *
 * \~spanish
 * Los bytes se comparan enteros y no se inspeccionan cabecera a cabecera.  Una
 * respuesta la lee el analizador de otro y lo que ve son los bytes, asi que una
 * prueba que comprobara "tiene una longitud de contenido en algun sitio"
 * dejaria pasar una respuesta con dos, o con una en el sitio equivocado, o sin
 * la linea en blanco.
 *
 * \~
 */

#include "http_vx/h1_parser.h"
#include "http_vx/h1_writer.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h1::ResponseBody;
using http_vx::h1::ResponseWriter;
using http_vx::h1::WriteError;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Whether the head that was built is exactly @p want.
 * \~spanish Si la cabeza construida es exactamente @p want.
 * \~
 */
void head_is(const ResponseWriter &w, const char *want, const char *what) {
    const size_t len = std::strlen(want);
    if (w.head_size() != len) {
        std::fprintf(stderr, "FAIL: %s\n  wrote: %.*s", what,
                     static_cast<int>(w.head_size()),
                     reinterpret_cast<const char *>(w.head()));
        ++failures;
        return;
    }
    check(std::memcmp(w.head(), want, len) == 0, what);
}

/**
 * @brief
 * \~english An ordinary response, byte for byte.
 * \~spanish Una respuesta corriente, byte a byte.
 * \~
 */
void test_ordinary() {
    ResponseWriter w;
    check(w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get,
                  true) == WriteError::None,
          "an ordinary response could not be started");
    check(w.field(http_vx::FieldId::ContentType, "text/plain", 10) ==
              WriteError::None,
          "an ordinary field could not be written");
    check(w.finish(ResponseBody::Length, 5) == WriteError::None,
          "an ordinary response could not be finished");

    head_is(w,
            "HTTP/1.1 200 OK\r\n"
            "content-type: text/plain\r\n"
            "content-length: 5\r\n"
            "\r\n",
            "the ordinary response is not what it should be");

    check(w.body_follows(), "the body of an ordinary response was suppressed");
    check(!w.closes(), "an ordinary HTTP/1.1 response closes the connection");
    check(!w.body_is_chunked(), "an ordinary response is chunked");
}

/**
 * @brief
 * \~english What this writer produces, read back by this project's parser.
 * \~spanish Lo que produce este escritor, leido por el analizador del proyecto.
 * \~
 *
 * \~english
 * Not a round trip for its own sake.  The two halves were written from the
 * same grammar and the check is that they agree about it: a writer that put
 * one space too many after the colon, or forgot the blank line, produces bytes
 * that look right in a test that reads them as text and do not parse.
 *
 * Reading a RESPONSE with a request parser takes a small lie -- a request line
 * is put in front of the fields -- and it is worth it: what is being checked
 * is the field section and the blank line, which are the same in both.
 *
 * \~spanish
 * No es un viaje de ida y vuelta por el gusto de hacerlo.  Las dos mitades se
 * escribieron de la misma gramatica y lo que se comprueba es que se ponen de
 * acuerdo sobre ella: un escritor que pusiera un espacio de mas tras los dos
 * puntos, o se olvidara de la linea en blanco, produce bytes que parecen bien
 * en una prueba que los lee como texto y no analizan.
 *
 * Leer una RESPUESTA con un analizador de peticiones cuesta una pequena
 * mentira -- se le pone delante una linea de peticion -- y compensa: lo que se
 * comprueba es la seccion de cabeceras y la linea en blanco, que son iguales en
 * las dos.
 *
 * \~
 */
void test_reads_back() {
    ResponseWriter w;
    w.begin(http_vx::Version::Http11, 404, http_vx::MethodId::Get, true);
    w.field(http_vx::FieldId::ContentType, "text/html; charset=utf-8", 24);
    w.field(http_vx::FieldId::Server, "http_vx", 7);
    w.field("X-Custom", 8, "a value with spaces", 19);
    w.finish(ResponseBody::Length, 0);

    char msg[1024];
    const int n = std::snprintf(msg, sizeof(msg), "GET / HTTP/1.1\r\nHost: h\r\n");
    check(n > 0 && static_cast<size_t>(n) + w.head_size() < sizeof(msg),
          "the test's buffer is too small");
    if (n <= 0) return;

    /* \~english
     * Everything after the status line: the fields and the blank line.
     * \~spanish
     * Todo lo que va tras la linea de estado: las cabeceras y la linea vacia.
     * \~ */
    const char *head = reinterpret_cast<const char *>(w.head());
    const char *fields = std::strstr(head, "\r\n") + 2;
    const size_t flen = w.head_size() - static_cast<size_t>(fields - head);
    std::memcpy(msg + n, fields, flen);

    http_vx::h1::RequestParser p;
    http_vx::Request r;
    const http_vx::h1::ParseResult res =
        p.parse(reinterpret_cast<const uint8_t *>(msg),
                static_cast<size_t>(n) + flen, r);

    check(res == http_vx::h1::ParseResult::Done,
          "what the writer produced does not parse");
    check(r.fields.size() == 5,
          "the fields the writer produced were not all read back");
    check(r.fields.has(http_vx::FieldId::ContentLength),
          "the framing field the writer added was not read back");
}

/**
 * @brief
 * \~english A value carrying a line ending is refused, not cleaned up.
 * \~spanish Un valor con un fin de linea se rechaza, no se limpia.
 * \~
 *
 * \~english
 * This is response splitting.  A `Location` built from a query parameter lets
 * whoever wrote that parameter end the field and start another, and enough of
 * them to start another response -- which the client believes, because it
 * arrived on a connection to this server.
 *
 * Refusing rather than cleaning up is the point.  Cleaning up changes what the
 * application meant without telling it, and leaves the bug that produced the
 * value exactly where it was.
 *
 * \~spanish
 * Esto es la particion de respuestas.  Un `Location` construido con un
 * parametro de la consulta deja que quien escribiera ese parametro termine la
 * cabecera y empiece otra, y las suficientes para empezar otra respuesta -- que
 * el cliente se cree, porque llego por una conexion a este servidor.
 *
 * Lo que importa es rechazar y no limpiar.  Limpiar cambia lo que la aplicacion
 * queria decir sin decirselo, y deja el error que produjo el valor justo donde
 * estaba.
 *
 * \~
 */
void test_response_splitting() {
    const char *const poison[] = {
        "/ok\r\nSet-Cookie: admin=1",
        "/ok\rX",
        "/ok\nX",
        "/ok\r\n\r\nHTTP/1.1 200 OK\r\n",
    };

    for (size_t i = 0; i < sizeof(poison) / sizeof(poison[0]); ++i) {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 302, http_vx::MethodId::Get, true);
        const WriteError e = w.field(http_vx::FieldId::Location, poison[i],
                                     std::strlen(poison[i]));
        check(e == WriteError::BadFieldValue,
              "a value that ends the field early was written");
    }

    /* \~english
     * A nul too: anything downstream that treats the value as a C string reads
     * a value that ends before it does.
     * \~spanish
     * Un nulo tambien: cualquier cosa de mas abajo que trate el valor como
     * cadena de C lee un valor que acaba antes de donde acaba.
     * \~ */
    ResponseWriter w;
    w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
    check(w.field(http_vx::FieldId::ETag, "a\0b", 3) == WriteError::BadFieldValue,
          "a value with a nul in it was written");

    /* \~english
     * And the name, which is checked for the same reason: what makes it not a
     * token is what it smuggles into the place the next field goes.
     * \~spanish
     * Y el nombre, que se comprueba por lo mismo: lo que hace que no sea un
     * token es lo que cuela donde va la cabecera siguiente.
     * \~ */
    ResponseWriter w2;
    w2.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
    check(w2.field("X-Bad\r\nY", 8, "v", 1) == WriteError::BadFieldName,
          "a name that is not a token was written");
    ResponseWriter w3;
    w3.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
    check(w3.field("X Bad", 5, "v", 1) == WriteError::BadFieldName,
          "a name with a space was written");
}

/**
 * @brief
 * \~english The framing belongs to the writer, however it is spelled.
 * \~spanish El troceado es del escritor, se escriba como se escriba.
 * \~
 */
void test_framing_is_not_yours() {
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w.field(http_vx::FieldId::ContentLength, "5", 1) ==
                  WriteError::FramingIsNotYours,
              "the application wrote a content length");
    }
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w.field(http_vx::FieldId::TransferEncoding, "chunked", 7) ==
                  WriteError::FramingIsNotYours,
              "the application wrote a transfer encoding");
    }
    {
        /* \~english
         * Spelled out, and in another case, because a rule that only stops the
         * identifier is a rule with a spelling that gets around it.
         * \~spanish
         * Escrita entera, y con otras mayusculas, porque una regla que solo
         * para el identificador es una regla con una grafia que la rodea.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w.field("Content-Length", 14, "5", 1) ==
                  WriteError::FramingIsNotYours,
              "a content length written by name got through");
        ResponseWriter w2;
        w2.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w2.field("CONTENT-LENGTH", 14, "5", 1) ==
                  WriteError::FramingIsNotYours,
              "a content length in upper case got through");
    }
}

/**
 * @brief
 * \~english HEAD: the fields of the GET, and none of its body.
 * \~spanish HEAD: las cabeceras del GET, y nada de su cuerpo.
 * \~
 */
void test_head() {
    ResponseWriter w;
    w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Head, true);
    check(w.finish(ResponseBody::Length, 1234) == WriteError::None,
          "a length for HEAD was refused, which would answer a different "
          "question than the GET");

    head_is(w, "HTTP/1.1 200 OK\r\ncontent-length: 1234\r\n\r\n",
            "the response to HEAD is not the GET's head");

    /* \~english
     * And the one thing that differs: the bytes do not follow.  A caller that
     * asked the status instead of asking here would send them, and the peer
     * reads them as the start of the next response.
     * \~spanish
     * Y lo unico que difiere: los bytes no van detras.  Quien preguntara al
     * estado en vez de preguntar aqui los mandaria, y el otro extremo los lee
     * como el principio de la respuesta siguiente.
     * \~ */
    check(!w.body_follows(), "the body of a HEAD response would be sent");
}

/**
 * @brief
 * \~english The statuses that carry nothing, and refuse to be given anything.
 * \~spanish Los estados que no llevan nada, y se niegan a que les den algo.
 * \~
 */
void test_bodiless_statuses() {
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 204, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::None) == WriteError::None,
              "a 204 with no body was refused");
        head_is(w, "HTTP/1.1 204 No Content\r\n\r\n",
                "a 204 is not written bare");
        check(!w.body_follows(), "a 204 would be followed by a body");
    }
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 204, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Length, 5) == WriteError::BodyNotAllowed,
              "a 204 with a length was accepted");
    }
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 304, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Chunked) == WriteError::BodyNotAllowed,
              "a 304 with chunks was accepted");
    }
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 100, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Length, 0) == WriteError::BodyNotAllowed,
              "a 1xx with a length was accepted");
    }
    {
        /* \~english
         * And a neighbour, to show the rule is three values and not a range.
         * \~spanish
         * Y un vecino, para ensenar que la regla son tres valores y no un
         * rango.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 205, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Length, 0) == WriteError::None,
              "a 205 was taken for a 204");
    }
}

/**
 * @brief
 * \~english What the connection does next, per version.
 * \~spanish Que hace la conexion despues, segun la version.
 * \~
 *
 * \~english
 * The two versions disagree by default, so each announcement is written only
 * when it differs from what the peer already assumes.  Getting it backwards
 * produces no error: it produces a connection one side thinks is still there.
 *
 * \~spanish
 * Las dos versiones discrepan por defecto, asi que cada anuncio se escribe solo
 * cuando difiere de lo que el otro extremo ya supone.  Errarlo al reves no
 * produce ningun error: produce una conexion que una de las partes cree que
 * sigue ahi.
 *
 * \~
 */
void test_connection() {
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, false);
        w.finish(ResponseBody::Length, 0);
        head_is(w,
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                "an HTTP/1.1 response that closes does not say so");
        check(w.closes(), "it does not report that it closes");
    }
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http10, 200, http_vx::MethodId::Get, true);
        w.finish(ResponseBody::Length, 0);
        head_is(w,
                "HTTP/1.0 200 OK\r\ncontent-length: 0\r\n"
                "connection: keep-alive\r\n\r\n",
                "an HTTP/1.0 response that is kept does not say so");
        check(!w.closes(), "it reports that it closes");
    }
    {
        /* \~english
         * Reading until the connection closes ends the connection by
         * definition: the end of the body IS the end of it, so promising to
         * reuse it would be promising a boundary that does not exist.
         * \~spanish
         * Leer hasta que se cierre la conexion termina la conexion por
         * definicion: el final del cuerpo ES el final de ella, asi que prometer
         * reutilizarla seria prometer una frontera que no existe.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http10, 200, http_vx::MethodId::Get, true);
        w.finish(ResponseBody::UntilClose);
        head_is(w, "HTTP/1.0 200 OK\r\nconnection: close\r\n\r\n",
                "a response framed by closing does not close");
        check(w.closes(), "a response framed by closing says it does not");
    }
    {
        /* \~english
         * And if the application wrote the field itself, the writer does not
         * write a second one.  Two answers about a connection is the same
         * mistake as two about a body.
         * \~spanish
         * Y si la aplicacion escribio la cabecera, el escritor no escribe otra.
         * Dos respuestas sobre una conexion son la misma equivocacion que dos
         * sobre un cuerpo.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 101, http_vx::MethodId::Get, false);
        w.field(http_vx::FieldId::Connection, "upgrade", 7);
        w.finish(ResponseBody::None);
        head_is(w, "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\n\r\n",
                "the writer added a second Connection field");
    }
}

/**
 * @brief
 * \~english Chunks are HTTP/1.1's, and the writer says so.
 * \~spanish Los trozos son de HTTP/1.1, y el escritor lo dice.
 * \~
 */
void test_chunked() {
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Chunked) == WriteError::None,
              "chunks were refused to HTTP/1.1");
        head_is(w, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
                "a chunked response is not written as one");
        check(w.body_is_chunked(), "it does not report being chunked");
        check(!w.closes(), "a chunked response closes the connection");
    }
    {
        /* \~english
         * HTTP/1.0 has none.  A client that announced that version reads the
         * chunk headers as body, so writing them is corrupting the answer.
         * \~spanish
         * HTTP/1.0 no los tiene.  Un cliente que anuncio esa version lee las
         * cabeceras de los trozos como cuerpo, asi que escribirlas es corromper
         * la respuesta.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http10, 200, http_vx::MethodId::Get, true);
        check(w.finish(ResponseBody::Chunked) == WriteError::ChunkedNotAvailable,
              "chunks were written to an HTTP/1.0 client");
    }
}

/**
 * @brief
 * \~english The bytes of a chunk, without copying the ones in the middle.
 * \~spanish Los bytes de un trozo, sin copiar los de en medio.
 * \~
 */
void test_chunk_pieces() {
    uint8_t header[http_vx::h1::kChunkHeaderMax];

    size_t n = http_vx::h1::write_chunk_header(header, 5);
    check(n == 3 && std::memcmp(header, "5\r\n", 3) == 0,
          "a small chunk header is wrong");

    n = http_vx::h1::write_chunk_header(header, 255);
    check(n == 4 && std::memcmp(header, "ff\r\n", 4) == 0,
          "a chunk header is not hexadecimal");

    n = http_vx::h1::write_chunk_header(header, 0);
    check(n == 3 && std::memcmp(header, "0\r\n", 3) == 0,
          "a zero chunk header is wrong");

    n = http_vx::h1::write_chunk_header(header, ~uint64_t{0});
    check(n <= http_vx::h1::kChunkHeaderMax,
          "the largest chunk header does not fit the promised buffer");
    check(n == 18 && std::memcmp(header, "ffffffffffffffff\r\n", 18) == 0,
          "the largest chunk header is wrong");
}

/**
 * @brief
 * \~english Head and body go out together, without being joined first.
 * \~spanish La cabeza y el cuerpo salen juntos, sin unirlos antes.
 * \~
 *
 * \~english
 * R14.  What is checked is that the pieces are named separately and add up:
 * the body's bytes are pointed at where they already were, so a body of a
 * gigabyte costs the same list as a body of five bytes.
 *
 * \~spanish
 * R14.  Lo que se comprueba es que los pedazos se nombran por separado y suman:
 * los bytes del cuerpo se apuntan donde ya estaban, asi que un cuerpo de un
 * gigabyte cuesta la misma lista que uno de cinco bytes.
 *
 * \~
 */
void test_gather() {
    ResponseWriter w;
    w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
    w.finish(ResponseBody::Length, 5);

    const uint8_t body[] = {'h', 'e', 'l', 'l', 'o'};

    http_vx::IoList out;
    check(w.gather(out), "the head did not fit the list");
    check(out.push(body, sizeof(body)), "the body did not fit the list");

    check(out.count() == 2, "the head and the body were not kept apart");
    check(out.total() == w.head_size() + sizeof(body),
          "the pieces do not add up to what goes out");
    check(out.slices()[1].data == body,
          "the body was copied instead of pointed at");

    /* \~english
     * A partial write leaves exactly what is left, from where it stopped.  It
     * is arithmetic, and getting it wrong sends a run of bytes twice -- which
     * in a body is corruption and in a head is a second set of fields.
     * \~spanish
     * Una escritura parcial deja exactamente lo que queda, desde donde se paro.
     * Es aritmetica, y errarla manda una tirada de bytes dos veces -- que en un
     * cuerpo es corrupcion y en una cabeza es un segundo juego de cabeceras.
     * \~ */
    const size_t head = w.head_size();
    out.advance(head + 2);
    check(out.count() == 1, "the head was not dropped once it went out");
    check(out.total() == 3, "what is left is not what is left");
    check(out.slices()[0].data == body + 2,
          "what is left does not start where the write stopped");

    out.advance(3);
    check(out.empty(), "something was left after everything went out");
    check(out.total() == 0, "the total survived the write");

    /* \~english
     * An empty run is dropped rather than kept: some systems read a
     * zero-length entry as the end of the list, which would silently drop
     * everything after it.
     * \~spanish
     * Una tirada vacia se descarta en vez de guardarse: algunos sistemas leen
     * una entrada de longitud cero como el final de la lista, lo que se
     * llevaria en silencio todo lo que fuera detras.
     * \~ */
    http_vx::IoList two;
    two.push(body, 0);
    two.push(body, 5);
    check(two.count() == 1, "an empty run took a place in the list");
}

/**
 * @brief
 * \~english Out of order, and after a refusal.
 * \~spanish Fuera de orden, y despues de un rechazo.
 * \~
 */
void test_order() {
    {
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        w.finish(ResponseBody::Length, 0);
        check(w.field(http_vx::FieldId::Server, "x", 1) == WriteError::OutOfOrder,
              "a field was written after the blank line");
        check(w.finish(ResponseBody::Length, 0) == WriteError::OutOfOrder,
              "a response was finished twice");
    }
    {
        /* \~english
         * And once it has refused, it keeps refusing.  A writer that recovered
         * would produce a response missing whatever was refused, and nothing
         * downstream could tell.
         * \~spanish
         * Y una vez ha rechazado, sigue rechazando.  Un escritor que se
         * recuperara produciria una respuesta a la que le falta lo que se
         * rechazo, y nada de mas abajo podria notarlo.
         * \~ */
        ResponseWriter w;
        w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
        check(w.field(http_vx::FieldId::Location, "a\r\nb", 4) ==
                  WriteError::BadFieldValue,
              "a split value was written");
        check(w.field(http_vx::FieldId::Server, "x", 1) == WriteError::OutOfOrder,
              "the writer carried on after refusing");
        check(w.finish(ResponseBody::Length, 0) == WriteError::OutOfOrder,
              "the writer finished a response it had refused to build");
    }
    {
        ResponseWriter w;
        check(w.begin(http_vx::Version::Http11, 99, http_vx::MethodId::Get,
                      true) == WriteError::BadStatus,
              "a status outside the range was accepted");
        check(w.begin(http_vx::Version::Http2, 200, http_vx::MethodId::Get,
                      true) == WriteError::BadStatus,
              "this writer accepted a version it does not write");
    }
}

/**
 * @brief
 * \~english One writer serves the next response.
 * \~spanish Un escritor sirve la respuesta siguiente.
 * \~
 */
void test_reuse() {
    ResponseWriter w;
    w.begin(http_vx::Version::Http11, 200, http_vx::MethodId::Get, true);
    w.field(http_vx::FieldId::Server, "first", 5);
    w.finish(ResponseBody::Length, 1);

    w.begin(http_vx::Version::Http11, 404, http_vx::MethodId::Get, true);
    w.finish(ResponseBody::Length, 0);
    head_is(w, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n",
            "the previous response leaked into this one");

    w.release();
    check(w.head_size() == 0, "releasing left bytes behind");
}

/**
 * @brief
 * \~english A code nobody registered is written, with no phrase.
 * \~spanish Un codigo que nadie registro se escribe, sin frase.
 * \~
 *
 * \~english
 * The phrase is optional and there is nothing to make up.  Making one up would
 * be writing this server's opinion of a status the application chose.
 *
 * \~spanish
 * La frase es opcional y no hay nada que inventar.  Inventarla seria escribir
 * la opinion de este servidor sobre un estado que eligio la aplicacion.
 *
 * \~
 */
void test_unregistered_status() {
    ResponseWriter w;
    check(w.begin(http_vx::Version::Http11, 499, http_vx::MethodId::Get,
                  true) == WriteError::None,
          "an unregistered status was refused");
    w.finish(ResponseBody::Length, 0);
    head_is(w, "HTTP/1.1 499 \r\ncontent-length: 0\r\n\r\n",
            "an unregistered status is not written bare");
}

} // namespace

int main() {
    test_ordinary();
    test_reads_back();
    test_response_splitting();
    test_framing_is_not_yours();
    test_head();
    test_bodiless_statuses();
    test_connection();
    test_chunked();
    test_chunk_pieces();
    test_gather();
    test_order();
    test_reuse();
    test_unregistered_status();

    if (failures != 0) {
        std::fprintf(stderr, "test_h1_writer: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h1_writer: ok\n");
    return 0;
}
