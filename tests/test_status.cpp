/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_status.cpp
 * @brief
 * \~english The status codes, and above all the body rule.
 * \~spanish Los codigos de estado, y sobre todo la regla del cuerpo.
 * \~
 *
 * \~english
 * Most of what is checked here is cheap.  One thing is not: whether a response
 * carries a body decides where the next response begins on that connection, so
 * a wrong answer does not produce a wrong response -- it produces a connection
 * on which every later response is misread.  That rule gets its own section
 * and its cases are named one by one.
 *
 * \~spanish
 * Casi todo lo que se comprueba aqui es barato.  Una cosa no lo es: si una
 * respuesta lleva cuerpo decide donde empieza la siguiente en esa conexion, asi
 * que una respuesta equivocada no produce una respuesta mal -- produce una
 * conexion en la que todas las respuestas posteriores se leen mal.  Esa regla
 * tiene seccion propia y sus casos se nombran uno a uno.
 *
 * \~
 */

#include "http_vx/status.h"

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
 * \~english Three digits, and nothing else is a status code.
 * \~spanish Tres cifras, y nada mas es un codigo de estado.
 * \~
 */
void test_range() {
    check(!http_vx::status_is_valid(0), "zero is a status code");
    check(!http_vx::status_is_valid(99), "99 is a status code");
    check(http_vx::status_is_valid(100), "100 is not a status code");
    check(http_vx::status_is_valid(599), "599 is not a status code");
    check(!http_vx::status_is_valid(600), "600 is a status code");
    check(!http_vx::status_is_valid(1000), "1000 is a status code");
}

/**
 * @brief
 * \~english The class, and the fallback that RFC 9110 requires.
 * \~spanish La clase, y el recurso que exige el RFC 9110.
 * \~
 *
 * \~english
 * The point of the fallback is the code nobody registered: a `499` must be
 * handled, and handled as a `400`.  A recipient that refused it would be
 * refusing something the specification says to accept.
 *
 * \~spanish
 * Lo que importa del recurso es el codigo que nadie registro: un `499` hay que
 * manejarlo, y manejarlo como un `400`.  Quien lo rechazara estaria rechazando
 * algo que la especificacion dice que se acepte.
 *
 * \~
 */
void test_class() {
    using http_vx::StatusClass;
    check(http_vx::status_class(100) == StatusClass::Informational, "100 is not 1xx");
    check(http_vx::status_class(200) == StatusClass::Successful, "200 is not 2xx");
    check(http_vx::status_class(302) == StatusClass::Redirection, "302 is not 3xx");
    check(http_vx::status_class(404) == StatusClass::ClientError, "404 is not 4xx");
    check(http_vx::status_class(503) == StatusClass::ServerError, "503 is not 5xx");
    check(http_vx::status_class(42) == StatusClass::Invalid, "42 has a class");
    check(http_vx::status_class(700) == StatusClass::Invalid, "700 has a class");

    check(http_vx::status_class_base(499) == 400, "499 does not fall back to 400");
    check(http_vx::status_class_base(599) == 500, "599 does not fall back to 500");
    check(http_vx::status_class_base(200) == 200, "200 does not fall back to itself");
    check(http_vx::status_class_base(42) == 0, "an invalid code has a fallback");

    /* \~english
     * And an unregistered code is still valid, still classified, and simply
     * has no phrase.
     * \~spanish
     * Y un codigo no registrado sigue siendo valido, sigue clasificado, y
     * simplemente no tiene frase.
     * \~ */
    check(http_vx::status_is_valid(499), "499 was refused");
    check(std::strcmp(http_vx::status_reason(499), "") == 0,
          "an unregistered code has a phrase");
    check(http_vx::status_reason_len(499) == 0,
          "an unregistered code has a phrase length");
}

/**
 * @brief
 * \~english The phrases: found, measured, and absent where there is none.
 * \~spanish Las frases: encontradas, medidas, y ausentes donde no hay.
 * \~
 */
void test_reasons() {
    check(std::strcmp(http_vx::status_reason(200), "OK") == 0, "200 is not OK");
    check(std::strcmp(http_vx::status_reason(404), "Not Found") == 0,
          "404 is not Not Found");
    check(std::strcmp(http_vx::status_reason(100), "Continue") == 0,
          "the first row was not found");
    check(std::strcmp(http_vx::status_reason(511),
                      "Network Authentication Required") == 0,
          "the last row was not found");

    /* \~english
     * The names RFC 9110 changed.  Writing the old ones would not break
     * anything, which is why nobody notices when they stay.
     * \~spanish
     * Los nombres que cambio el RFC 9110.  Escribir los viejos no romperia
     * nada, que es la razon de que nadie note cuando se quedan.
     * \~ */
    check(std::strcmp(http_vx::status_reason(413), "Content Too Large") == 0,
          "413 still carries its old phrase");
    check(std::strcmp(http_vx::status_reason(422), "Unprocessable Content") == 0,
          "422 still carries its old phrase");

    /* \~english
     * The holes in the table: defined and withdrawn, and reserved as a joke.
     * \~spanish
     * Los huecos de la tabla: definido y retirado, y reservado como broma.
     * \~ */
    check(http_vx::status_reason_len(306) == 0, "306 has a phrase");
    check(http_vx::status_reason_len(418) == 0, "418 has a phrase");

    /* \~english
     * Every stored length matches its phrase.  It is checked over the whole
     * range rather than per row, so a row added later cannot get it wrong
     * quietly.
     * \~spanish
     * Todas las longitudes guardadas coinciden con su frase.  Se comprueba
     * sobre el rango entero y no por fila, para que una fila anadida despues no
     * lo pueda errar por lo bajo.
     * \~ */
    for (http_vx::StatusCode c = 100; c <= 599; ++c) {
        const char *r = http_vx::status_reason(c);
        check(http_vx::status_reason_len(c) == std::strlen(r),
              "a stored phrase length does not match the phrase");
    }
}

/**
 * @brief
 * \~english Whether a response carries a body: the rule that outlives the request.
 * \~spanish Si una respuesta lleva cuerpo: la regla que sobrevive a la peticion.
 * \~
 */
void test_body_rule() {
    using http_vx::MethodId;
    using namespace http_vx::status;

    /* \~english The ordinary case.  \~spanish El caso corriente.  \~ */
    check(http_vx::response_can_have_body(MethodId::Get, kOk),
          "a 200 to GET carries no body");
    check(http_vx::response_can_have_body(MethodId::Post, kCreated),
          "a 201 to POST carries no body");
    check(http_vx::response_can_have_body(MethodId::Get, kNotFound),
          "a 404 carries no body, so there is nowhere to explain it");

    /* \~english
     * HEAD, whatever the status.  This is the one that is almost right if the
     * method is left out of the question.
     * \~spanish
     * HEAD, sea cual sea el estado.  Es el que queda casi bien si se deja el
     * metodo fuera de la pregunta.
     * \~ */
    check(!http_vx::response_can_have_body(MethodId::Head, kOk),
          "a 200 to HEAD carries a body");
    check(!http_vx::response_can_have_body(MethodId::Head, kNotFound),
          "a 404 to HEAD carries a body");
    check(!http_vx::response_can_have_body(MethodId::Head, kInternalServerError),
          "a 500 to HEAD carries a body");

    /* \~english The three statuses, whatever the method.  \~spanish Los tres estados, sea cual sea el metodo.  \~ */
    check(!http_vx::response_can_have_body(MethodId::Get, kContinue),
          "a 100 carries a body");
    check(!http_vx::response_can_have_body(MethodId::Get, kEarlyHints),
          "a 103 carries a body");
    check(!http_vx::response_can_have_body(MethodId::Get, kNoContent),
          "a 204 carries a body");
    check(!http_vx::response_can_have_body(MethodId::Get, kNotModified),
          "a 304 carries a body");
    check(!http_vx::response_can_have_body(MethodId::Post, kNoContent),
          "a 204 to POST carries a body");

    /* \~english
     * The tunnel.  A CONNECT that failed is an ordinary response and may
     * explain itself; one that succeeded has given the connection away.
     * \~spanish
     * El tunel.  Un CONNECT que fallo es una respuesta corriente y puede
     * explicarse; uno que triunfo ha entregado la conexion.
     * \~ */
    check(!http_vx::response_can_have_body(MethodId::Connect, kOk),
          "a successful CONNECT is followed by a body");
    check(http_vx::response_can_have_body(MethodId::Connect, kForbidden),
          "a refused CONNECT cannot say why");

    /* \~english
     * And the neighbouring codes are NOT exempt.  A rule written as a range
     * instead of three values takes 203 or 205 with it, and a 205 does carry a
     * body of length zero, which is a different thing from carrying none.
     * \~spanish
     * Y los codigos vecinos NO estan exentos.  Una regla escrita como rango en
     * vez de como tres valores se lleva por delante el 203 o el 205, y un 205
     * si lleva cuerpo, de longitud cero, que es otra cosa que no llevarlo.
     * \~ */
    check(http_vx::response_can_have_body(MethodId::Get, kNonAuthoritative),
          "203 was taken for 204");
    check(http_vx::response_can_have_body(MethodId::Get, kResetContent),
          "205 was taken for 204");
    check(http_vx::response_can_have_body(MethodId::Get, kMultipleChoices),
          "300 was taken for 304");
    check(http_vx::response_can_have_body(MethodId::Get, kUseProxy),
          "305 was taken for 304");

    /* \~english
     * An unregistered code follows its class like any other: a 499 has a body
     * because a 400 has one.
     * \~spanish
     * Un codigo no registrado sigue a su clase como cualquier otro: un 499
     * lleva cuerpo porque un 400 lo lleva.
     * \~ */
    check(http_vx::response_can_have_body(MethodId::Get, 499),
          "an unregistered 4xx carries no body");
    check(!http_vx::response_can_have_body(MethodId::Get, 199),
          "an unregistered 1xx carries a body");
}

} // namespace

int main() {
    test_range();
    test_class();
    test_reasons();
    test_body_rule();

    if (failures != 0) {
        std::fprintf(stderr, "test_status: %d failures\n", failures);
        return 1;
    }
    std::printf("test_status: ok\n");
    return 0;
}
