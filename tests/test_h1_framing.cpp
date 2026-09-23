/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_framing.cpp
 * @brief
 * \~english Where the body ends, and the message that says two places.
 * \~spanish Donde acaba el cuerpo, y el mensaje que dice dos sitios.
 * \~
 *
 * \~english
 * These messages are written out in full and parsed, rather than having their
 * fields assembled by hand.  It costs a few lines and it buys the thing that
 * matters: what is checked is what a peer can actually send.  A test that
 * built the fields directly could pass while the parser refused to produce
 * that shape, or -- worse -- while it produced a different one.
 *
 * \~spanish
 * Estos mensajes se escriben enteros y se analizan, en vez de montarles las
 * cabeceras a mano.  Cuesta unas lineas y compra lo que importa: lo que se
 * comprueba es lo que un extremo puede mandar de verdad.  Una prueba que
 * construyera las cabeceras directamente podria pasar mientras el analizador se
 * niega a producir esa forma, o -- peor -- mientras produce otra.
 *
 * \~
 */

#include "http_vx/h1_framing.h"
#include "http_vx/h1_parser.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h1::BodyKind;
using http_vx::h1::Framing;
using http_vx::h1::FramingError;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Parses @p msg and works out where its body would end.
 * \~spanish Analiza @p msg y averigua donde acabaria su cuerpo.
 * \~
 */
Framing frame(const char *msg, bool &parsed) {
    static http_vx::Request r;
    r.clear();

    http_vx::h1::RequestParser p;
    const uint8_t *d = reinterpret_cast<const uint8_t *>(msg);
    parsed = p.parse(d, std::strlen(msg), r) == http_vx::h1::ParseResult::Done;
    if (!parsed) return Framing{BodyKind::None, 0, FramingError::None};
    return http_vx::h1::frame_request_body(r, d);
}

/**
 * @brief
 * \~english Checks that @p msg frames as @p kind with length @p len.
 * \~spanish Comprueba que @p msg se trocea como @p kind con longitud @p len.
 * \~
 */
void frames_as(const char *msg, BodyKind kind, uint64_t len, const char *what) {
    bool parsed = false;
    const Framing f = frame(msg, parsed);
    check(parsed, what);
    if (!parsed) return;
    check(f.error == FramingError::None, what);
    check(f.kind == kind, what);
    check(f.length == len, what);
}

/**
 * @brief
 * \~english Checks that @p msg cannot be framed, for the reason @p why.
 * \~spanish Comprueba que @p msg no se puede trocear, por el motivo @p why.
 * \~
 */
void refuses(const char *msg, FramingError why, const char *what) {
    bool parsed = false;
    const Framing f = frame(msg, parsed);
    check(parsed, what);
    if (!parsed) return;
    check(f.error == why, what);
    check(f.kind == BodyKind::None, what);
}

/**
 * @brief
 * \~english The three ordinary shapes.
 * \~spanish Las tres formas corrientes.
 * \~
 */
void test_ordinary() {
    frames_as("GET / HTTP/1.1\r\nHost: h\r\n\r\n", BodyKind::None, 0,
              "a request with no framing was given a body");

    frames_as("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
              BodyKind::Exact, 5, "a length was not read as a length");

    frames_as("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
              BodyKind::Exact, 0,
              "a length of zero was taken for no framing at all");

    frames_as("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
              BodyKind::Chunked, 0, "chunks were not read as chunks");

    /* \~english
     * Case does not matter in a transfer coding, unlike in a method.  A reader
     * that missed that would answer 501 to a request that is entirely valid.
     * \~spanish
     * Las mayusculas dan igual en una codificacion de transferencia, al reves
     * que en un metodo.  Un lector que no lo viera contestaria 501 a una
     * peticion enteramente valida.
     * \~ */
    frames_as("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n",
              BodyKind::Chunked, 0, "a capitalised chunked was not recognised");
    frames_as("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: CHUNKED\r\n\r\n",
              BodyKind::Chunked, 0, "an upper-case chunked was not recognised");

    /* \~english
     * A coding may carry parameters, and they do not change which coding it is.
     * \~spanish
     * Una codificacion puede llevar parametros, y no cambian cual es.
     * \~ */
    frames_as("POST / HTTP/1.1\r\nHost: h\r\n"
              "Transfer-Encoding: chunked;q=1\r\n\r\n",
              BodyKind::Chunked, 0, "a coding with a parameter was not recognised");
}

/**
 * @brief
 * \~english The message that frames itself twice.
 * \~spanish El mensaje que se trocea dos veces.
 * \~
 *
 * \~english
 * This is the whole reason the file exists.  Each half is a perfectly ordinary
 * request; what is wrong is having both, and the older specification's answer
 * -- "the encoding wins" -- is what left a decade of proxies and servers
 * agreeing to disagree about where a body ended.
 *
 * \~spanish
 * Esta es toda la razon de que el fichero exista.  Cada mitad es una peticion
 * perfectamente corriente; lo que esta mal es tener las dos, y la respuesta de
 * la especificacion anterior -- "gana la codificacion" -- es lo que dejo una
 * decada de intermediarios y servidores de acuerdo en discrepar sobre donde
 * acababa un cuerpo.
 *
 * \~
 */
void test_the_smuggle() {
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            FramingError::LengthAndEncoding,
            "a message framed both ways was accepted");

    /* \~english
     * And the other order, because a reader that decided on the first framing
     * it met would take one of the two and not the other.
     * \~spanish
     * Y al reves, porque un lector que decidiera con el primer troceado que
     * encontrara cogeria uno de los dos y no el otro.
     * \~ */
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
            FramingError::LengthAndEncoding,
            "a message framed both ways, the other way round, was accepted");

    /* \~english
     * Even when the length is zero, which looks harmless and is not: a zero
     * length and a chunked body still end in two different places.
     * \~spanish
     * Incluso con longitud cero, que parece inofensivo y no lo es: una longitud
     * de cero y un cuerpo troceado siguen acabando en dos sitios distintos.
     * \~ */
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            FramingError::LengthAndEncoding,
            "both framings were accepted because the length was zero");
}

/**
 * @brief
 * \~english Chunked must be last, and must be there once.
 * \~spanish Chunked tiene que ser la ultima, y estar una vez.
 * \~
 */
void test_coding_order() {
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: chunked, gzip\r\n\r\n",
            FramingError::ChunkedNotLast,
            "a coding applied after chunked was accepted");

    refuses("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
            FramingError::ChunkedNotLast,
            "an encoding without chunked was accepted, and its body has no end");

    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: chunked, chunked\r\n\r\n",
            FramingError::ChunkedTwice, "chunked applied twice was accepted");

    /* \~english
     * Twice across two fields, which is the same thing written so that a
     * reader looking at one field would not see it.
     * \~spanish
     * Dos veces en dos cabeceras, que es lo mismo escrito de forma que un
     * lector que mirara una cabecera no lo viera.
     * \~ */
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            FramingError::ChunkedTwice,
            "chunked in two separate fields was accepted");

    /* \~english
     * Something under chunked that this server cannot undo.  It answers 501
     * and not 400, because the message is well formed.
     * \~spanish
     * Algo por debajo de chunked que este servidor no puede deshacer.  Contesta
     * 501 y no 400, porque el mensaje esta bien formado.
     * \~ */
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: gzip, chunked\r\n\r\n",
            FramingError::UnsupportedCoding,
            "a coding this server cannot apply was accepted");

    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Transfer-Encoding: chunked, , \r\n\r\n",
            FramingError::ChunkedNotLast,
            "an empty element in the coding list was skipped");
}

/**
 * @brief
 * \~english Chunks from a client that announced HTTP/1.0.
 * \~spanish Trozos de un cliente que anuncio HTTP/1.0.
 * \~
 */
void test_encoding_in_http_10() {
    refuses("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            FramingError::EncodingInHttp10,
            "an HTTP/1.0 client using chunks was accepted");
}

/**
 * @brief
 * \~english What a bad length does to the framing.
 * \~spanish Que le hace una longitud mala al troceado.
 * \~
 */
void test_bad_lengths() {
    refuses("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: abc\r\n\r\n",
            FramingError::MalformedLength, "a length that is not a number framed");
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Content-Length: 5\r\nContent-Length: 6\r\n\r\n",
            FramingError::ConflictingLength, "two different lengths framed");
    refuses("POST / HTTP/1.1\r\nHost: h\r\n"
            "Content-Length: 99999999999999999999999\r\n\r\n",
            FramingError::LengthTooLarge, "a length that does not fit framed");
}

/**
 * @brief
 * \~english What each refusal is answered with.
 * \~spanish Con que se contesta a cada rechazo.
 * \~
 *
 * \~english
 * The mapping is part of the rule rather than the caller's to invent: two
 * callers deciding for themselves would answer differently to the same
 * message, which is the disagreement this whole file is about.
 *
 * \~spanish
 * La correspondencia es parte de la regla y no algo que quien llama invente:
 * dos llamantes decidiendolo por su cuenta contestarian distinto al mismo
 * mensaje, que es la discrepancia de la que habla todo este fichero.
 *
 * \~
 */
void test_status_mapping() {
    using http_vx::h1::framing_status;
    check(framing_status(FramingError::None) == 0, "nothing wrong has a status");
    check(framing_status(FramingError::LengthAndEncoding) == 400,
          "the double framing is not a 400");
    check(framing_status(FramingError::MalformedLength) == 400,
          "a malformed length is not a 400");
    check(framing_status(FramingError::ConflictingLength) == 400,
          "conflicting lengths are not a 400");
    check(framing_status(FramingError::ChunkedNotLast) == 400,
          "chunked out of place is not a 400");
    check(framing_status(FramingError::ChunkedTwice) == 400,
          "chunked twice is not a 400");
    check(framing_status(FramingError::EncodingInHttp10) == 400,
          "chunks in HTTP/1.0 is not a 400");

    check(framing_status(FramingError::LengthTooLarge) == 413,
          "a length that does not fit is not a 413");
    check(framing_status(FramingError::UnsupportedCoding) == 501,
          "a coding we cannot apply is not a 501, which would blame the peer");
}

} // namespace

int main() {
    test_ordinary();
    test_the_smuggle();
    test_coding_order();
    test_encoding_in_http_10();
    test_bad_lengths();
    test_status_mapping();

    if (failures != 0) {
        std::fprintf(stderr, "test_h1_framing: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h1_framing: ok\n");
    return 0;
}
