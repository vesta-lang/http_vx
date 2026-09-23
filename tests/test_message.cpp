/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_message.cpp
 * @brief
 * \~english The message, and what reusing it must not carry over.
 * \~spanish El mensaje, y lo que reutilizarlo no debe arrastrar.
 * \~
 *
 * \~english
 * A connection serves one request after another on the same structure, so the
 * interesting failure is not in filling it but in emptying it.  A span left
 * behind from the previous message does not read as rubbish: it reads as
 * whatever is now at that offset, which is a piece of the request that came
 * after -- a target, an authority, a method -- taken for a piece of the one
 * before.
 *
 * \~spanish
 * Una conexion sirve una peticion tras otra sobre la misma estructura, asi que
 * el fallo interesante no esta en llenarla sino en vaciarla.  Un trozo que
 * quedara del mensaje anterior no se lee como basura: se lee como lo que haya
 * ahora en ese desplazamiento, que es un pedazo de la peticion que vino
 * despues -- un destino, un anfitrion, un metodo -- tomado por uno de la de
 * antes.
 *
 * \~
 */

#include "http_vx/message.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english A span names bytes without holding them.
 * \~spanish Un trozo nombra bytes sin tenerlos.
 * \~
 *
 * \~english
 * The point is the second half: the same span resolved against two different
 * bases gives two different byte ranges, which is exactly what makes it
 * survive a buffer that moved.
 *
 * \~spanish
 * Lo que importa es la segunda mitad: el mismo trozo resuelto contra dos bases
 * distintas da dos rangos de bytes distintos, que es justo lo que hace que
 * sobreviva a un buffer que se movio.
 *
 * \~
 */
void test_span() {
    const uint8_t first[] = "GET /index.html HTTP/1.1";
    const uint8_t second[] = "PUT /index.html HTTP/1.1";

    const http_vx::Span target{4, 11};
    check(!target.empty(), "a span with a length is empty");
    check(std::memcmp(target.at(first), "/index.html", 11) == 0,
          "the span does not name what it should");
    check(std::memcmp(target.at(second), "/index.html", 11) == 0,
          "the span did not follow the base it was given");

    const http_vx::Span nothing{0, 0};
    check(nothing.empty(), "a span with no length is not empty");
}

/**
 * @brief
 * \~english A fresh request names nothing.
 * \~spanish Una peticion recien hecha no nombra nada.
 * \~
 */
void test_fresh() {
    http_vx::Request r;
    check(r.method == http_vx::MethodId::Unknown, "a fresh request has a method");
    check(r.method_text.empty(), "a fresh request has a method spelling");
    check(r.target.empty(), "a fresh request has a target");
    check(r.authority.empty(), "a fresh request has an authority");
    check(r.scheme.empty(), "a fresh request has a scheme");
    check(r.version == http_vx::Version::Unknown, "a fresh request has a version");
    check(r.fields.empty(), "a fresh request has fields");

    http_vx::Response s;
    check(s.status == 0, "a fresh response has a status");
    check(s.version == http_vx::Version::Unknown, "a fresh response has a version");
    check(s.fields.empty(), "a fresh response has fields");
}

/**
 * @brief
 * \~english Emptying leaves nothing of the message before.
 * \~spanish Vaciar no deja nada del mensaje anterior.
 * \~
 */
void test_clear() {
    http_vx::Request r;
    r.method = http_vx::MethodId::Post;
    r.method_text = http_vx::Span{0, 4};
    r.target = http_vx::Span{5, 10};
    r.authority = http_vx::Span{30, 9};
    r.scheme = http_vx::Span{0, 5};
    r.version = http_vx::Version::Http11;

    http_vx::Field f{};
    f.id = http_vx::FieldId::Host;
    r.fields.add(f);

    r.clear();

    check(r.method == http_vx::MethodId::Unknown, "the method survived");
    check(r.method_text.empty(), "the method spelling survived");
    check(r.target.empty(), "the target survived, and now names the next request");
    check(r.authority.empty(), "the authority survived");
    check(r.scheme.empty(), "the scheme survived");
    check(r.version == http_vx::Version::Unknown, "the version survived");
    check(r.fields.empty(), "the fields survived");
    check(!r.fields.has(http_vx::FieldId::Host),
          "the field presence mask survived");

    http_vx::Response s;
    s.status = 404;
    s.version = http_vx::Version::Http2;
    s.fields.add(f);
    s.clear();
    check(s.status == 0, "the status survived");
    check(s.version == http_vx::Version::Unknown, "the response version survived");
    check(s.fields.empty(), "the response fields survived");
}

/**
 * @brief
 * \~english Which versions are written out, and which are not.
 * \~spanish Que versiones se escriben, y cuales no.
 * \~
 */
void test_version() {
    using http_vx::Version;

    check(std::strcmp(http_vx::version_text(Version::Http10), "HTTP/1.0") == 0,
          "HTTP/1.0 is not written as itself");
    check(std::strcmp(http_vx::version_text(Version::Http11), "HTTP/1.1") == 0,
          "HTTP/1.1 is not written as itself");

    /* \~english
     * The other three have nothing to write, and that is the answer rather
     * than a gap: HTTP/2 and HTTP/3 are announced by the connection, and an
     * unknown version has nothing to announce.
     * \~spanish
     * Las otras tres no tienen nada que escribir, y esa es la respuesta y no un
     * hueco: HTTP/2 y HTTP/3 las anuncia la conexion, y una version desconocida
     * no tiene nada que anunciar.
     * \~ */
    check(http_vx::version_text(Version::Http2)[0] == '\0', "HTTP/2 is written out");
    check(http_vx::version_text(Version::Http3)[0] == '\0', "HTTP/3 is written out");
    check(http_vx::version_text(Version::Unknown)[0] == '\0',
          "an unknown version is written out");
    check(http_vx::version_text(static_cast<Version>(200))[0] == '\0',
          "a value past the end is written out");

    check(http_vx::version_is_text(Version::Http10), "HTTP/1.0 is not text");
    check(http_vx::version_is_text(Version::Http11), "HTTP/1.1 is not text");
    check(!http_vx::version_is_text(Version::Http2), "HTTP/2 is text");
    check(!http_vx::version_is_text(Version::Http3), "HTTP/3 is text");
    check(!http_vx::version_is_text(Version::Unknown), "an unknown version is text");
}

} // namespace

int main() {
    test_span();
    test_fresh();
    test_clear();
    test_version();

    if (failures != 0) {
        std::fprintf(stderr, "test_message: %d failures\n", failures);
        return 1;
    }
    std::printf("test_message: ok\n");
    return 0;
}
