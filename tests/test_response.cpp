/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_response.cpp
 * @brief
 * \~english What a handler says, before anybody decides how to write it.
 * \~spanish Lo que dice un manejador, antes de que nadie decida como escribirlo.
 * \~
 *
 * \~english
 * There is no HTTP in this file, and that is the whole test.  A status, some
 * fields and a body are what a response MEANS; a status line, colons, CRLFs
 * and a length are how HTTP/1.1 writes it, and a header block and DATA frames
 * are how HTTP/2 does.  If anything version-shaped had to appear here, the cut
 * would be in the wrong place.
 *
 * \~spanish
 * En este fichero no hay HTTP, y esa es toda la prueba.  Un estado, unas
 * cabeceras y un cuerpo son lo que SIGNIFICA una respuesta; una linea de
 * estado, dos puntos, CRLFs y una longitud son como lo escribe HTTP/1.1, y un
 * bloque de cabeceras y tramas DATA como lo hace HTTP/2.  Si aqui tuviera que
 * aparecer algo con forma de version, el corte estaria en el sitio equivocado.
 *
 * \~
 */

#include "http_vx/response.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Buffer;
using http_vx::FieldId;
using http_vx::ResponseBuilder;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

bool value_is(const ResponseBuilder &r, const http_vx::Field &f,
              const char *want) {
    if (f.value_len != std::strlen(want)) return false;
    return std::memcmp(r.bytes() + f.value_off, want, f.value_len) == 0;
}

/**
 * @brief
 * \~english A response holds what it was told, in order.
 * \~spanish Una respuesta guarda lo que le dijeron, en orden.
 * \~
 */
void test_it_holds_what_it_was_told() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.status() == 200, "a response does not start at 200");

    r.status(404);
    check(r.status() == 404, "the status was not kept");

    check(r.field(FieldId::ContentType, "text/plain", 10),
          "a field was refused");
    check(r.field(FieldId::Server, "http_vx", 7), "a field was refused");

    check(r.fields().size() == 2, "the fields were not kept");
    check(r.fields().begin()[0].id == FieldId::ContentType,
          "the fields came back in another order");
    check(value_is(r, r.fields().begin()[0], "text/plain"),
          "the first value is wrong");
    check(value_is(r, r.fields().begin()[1], "http_vx"),
          "the second value is wrong");

    check(r.body("hello", 5), "a body was refused");
    check(r.body().len == 5, "the body is the wrong length");
    check(std::memcmp(r.bytes() + r.body().off, "hello", 5) == 0,
          "the body is not what was written");

    check(!r.failed(), "a response that worked says it failed");
}

/**
 * @brief
 * \~english A name spelled out becomes what it IS.
 * \~spanish Un nombre deletreado se convierte en lo que ES.
 * \~
 *
 * \~english
 * The same rule the parsers follow on the way in, and for the same reason:
 * everything downstream asks what a field IS -- whether it may travel on this
 * version, whether it is already in a compression table, whether it frames the
 * message -- and a caller that spelled a name out should not get a different
 * answer from one that named it.
 *
 * \~spanish
 * La misma regla que siguen los analizadores a la entrada, y por lo mismo: todo
 * lo de despues pregunta que ES una cabecera -- si puede viajar en esta version,
 * si esta ya en una tabla de compresion, si trocea el mensaje -- y quien
 * deletree un nombre no deberia recibir otra respuesta que quien lo nombre.
 *
 * \~
 */
void test_a_spelled_name_is_recognised() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.field("content-type", 12, "text/html", 9),
          "a field by name was refused");
    check(r.fields().begin()[0].id == FieldId::ContentType,
          "a spelled-out known name was not recognised");

    /* \~english
     * And case does not change what it is, because a field name is
     * case-insensitive and that is a fact about the field, not about the
     * version that carried it.
     * \~spanish
     * Y las mayusculas no cambian lo que es, porque un nombre de cabecera no
     * distingue mayusculas y eso es un hecho de la cabecera, no de la version
     * que la trajo.
     * \~ */
    check(r.field("Content-Length", 14, "0", 1), "a field by name was refused");
    check(r.fields().begin()[1].id == FieldId::ContentLength,
          "a known name in another case was not recognised");

    /* \~english
     * One nobody knows keeps its letters, because those are the only letters
     * there are.
     * \~spanish
     * Uno que no conoce nadie se queda con sus letras, porque son las unicas
     * letras que hay.
     * \~ */
    check(r.field("x-made-up", 9, "yes", 3), "a field by name was refused");

    const http_vx::Field &f = r.fields().begin()[2];
    check(f.id == FieldId::Unknown, "an invented name was recognised");
    check(f.name_len == 9 &&
              std::memcmp(r.bytes() + f.name_off, "x-made-up", 9) == 0,
          "an invented name did not keep its letters");
}

/**
 * @brief
 * \~english A body written in pieces is one body.
 * \~spanish Un cuerpo escrito a trozos es un solo cuerpo.
 * \~
 *
 * \~english
 * So a handler can build an answer without knowing how long it will be, which
 * is most of them.
 *
 * \~spanish
 * Para que un manejador pueda construir una respuesta sin saber cuanto va a
 * medir, que son casi todos.
 *
 * \~
 */
void test_a_body_in_pieces_is_one_body() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.body("hello", 5), "the first piece was refused");
    check(r.body(" ", 1), "the second piece was refused");
    check(r.body("world", 5), "the third piece was refused");

    check(r.body().len == 11, "the pieces did not join");
    check(std::memcmp(r.bytes() + r.body().off, "hello world", 11) == 0,
          "the pieces did not join in order");
}

/**
 * @brief
 * \~english A field after the body has started is refused.
 * \~spanish Una cabecera despues de empezar el cuerpo se rechaza.
 * \~
 *
 * \~english
 * The body is one run of bytes at the end, so a field added now would either
 * land inside it or have to move it.  And a response whose head is written
 * after its body is not a response -- which is the same mistake as writing a
 * body down a second path, made inside one object instead of between two.
 *
 * It is REFUSED and the refusal is remembered, rather than quietly dropped: a
 * handler that set a header too late has a bug, and a response that went out
 * missing it would be a bug nobody ever sees.
 *
 * \~spanish
 * El cuerpo es una tirada de bytes al final, asi que una cabecera anadida ahora
 * caeria dentro de el o habria que moverlo.  Y una respuesta cuya cabeza se
 * escribe despues de su cuerpo no es una respuesta -- que es la misma
 * equivocacion que escribir un cuerpo por un segundo camino, hecha dentro de un
 * objeto en vez de entre dos.
 *
 * Se RECHAZA y el rechazo se recuerda, en vez de tirarlo por lo bajo: un
 * manejador que ponga una cabecera demasiado tarde tiene un fallo, y una
 * respuesta que saliera sin ella seria un fallo que no ve nadie nunca.
 *
 * \~
 */
void test_a_field_after_the_body_is_refused() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.field(FieldId::ContentType, "text/plain", 10),
          "a field before the body was refused");
    check(r.body("x", 1), "the body was refused");

    check(!r.field(FieldId::Server, "late", 4),
          "a field after the body was accepted");
    check(!r.field("x-late", 6, "yes", 3),
          "a field by name after the body was accepted");

    check(r.fields().size() == 1, "a late field was added anyway");
    check(r.failed(), "a response that lost a field says it worked");

    /* \~english
     * And the body is untouched: what was refused was refused, not half done.
     * \~spanish
     * Y el cuerpo esta intacto: lo que se rechazo se rechazo, no se hizo a
     * medias.
     * \~ */
    check(r.body().len == 1, "a refused field changed the body");
}

/**
 * @brief
 * \~english A response starts empty, whatever the buffer had in it.
 * \~spanish Una respuesta empieza vacia, tuviera lo que tuviera el buffer.
 * \~
 *
 * \~english
 * The store is reused between requests -- one per service, because a shard is
 * one thread and a response is finished with before the next begins -- so a
 * response that did not start it empty would answer with the tail of the one
 * before it.
 *
 * \~spanish
 * El almacen se reutiliza entre peticiones -- uno por servicio, porque un
 * fragmento es un hilo y con una respuesta se acaba antes de que empiece la
 * siguiente -- asi que una respuesta que no lo empezara vacio contestaria con
 * la cola de la anterior.
 *
 * \~
 */
void test_a_reused_store_starts_empty() {
    Buffer store;

    {
        ResponseBuilder first(store);
        first.field(FieldId::Server, "first", 5);
        first.body("old bytes", 9);
        check(first.body().len == 9, "the first response was not built");
    }

    ResponseBuilder second(store);
    check(second.fields().size() == 0,
          "a new response kept the previous one's fields");
    check(second.body().len == 0,
          "a new response kept the previous one's body");
    check(second.status() == 200, "a new response kept the previous status");

    check(second.body("new", 3), "the body was refused");
    check(second.body().off == 0,
          "a new response did not start at the front of the store");
    check(std::memcmp(second.bytes(), "new", 3) == 0,
          "the store still has the previous response in it");
}

} // namespace

int main() {
    test_it_holds_what_it_was_told();
    test_a_spelled_name_is_recognised();
    test_a_body_in_pieces_is_one_body();
    test_a_field_after_the_body_is_refused();
    test_a_reused_store_starts_empty();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
