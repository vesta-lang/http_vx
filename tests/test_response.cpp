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

/**
 * @brief
 * \~english Nothing is a valid thing to write, and does not start the body.
 * \~spanish Nada es algo valido que escribir, y no empieza el cuerpo.
 * \~
 *
 * \~english
 * An empty value is an ordinary header (`x-empty:`) and an empty body piece is
 * an ordinary call from a handler that had nothing to add.  Neither needs
 * room, so neither can fail for lack of it -- and an empty piece is not "the
 * body has started": a field may still come after it.
 *
 * \~spanish
 * Un valor vacio es una cabecera corriente (`x-empty:`) y un pedazo de cuerpo
 * vacio es una llamada corriente de un manejador que no tenia nada que anadir.
 * Ninguno necesita sitio, asi que ninguno puede fallar por falta de el -- y un
 * pedazo vacio no es "el cuerpo ha empezado": todavia puede venir una
 * cabecera.
 *
 * \~
 */
void test_nothing_needs_no_room() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.field(FieldId::Server, "", 0), "an empty value was refused");
    check(r.field("x-empty", 7, "", 0), "an empty value by name was refused");
    check(!r.failed(), "an empty value made the response fail");
    check(r.fields().size() == 2, "an empty value was not recorded");
    check(r.fields().begin()[0].value_len == 0, "an empty value has a length");

    check(r.body("", 0), "an empty body piece was refused");
    check(r.body().len == 0, "an empty piece made a body");
    check(r.field(FieldId::ContentType, "text/plain", 10),
          "an empty body piece closed the head");
    check(r.fields().size() == 3, "the field after an empty piece was lost");
    check(!r.failed(), "an empty piece made the response fail");
}

/**
 * @brief
 * \~english Every value lands where its offset says, and a failure is remembered.
 * \~spanish Cada valor cae donde dice su desplazamiento, y un fallo se recuerda.
 * \~
 *
 * \~english
 * The offsets are what the writer reads the response back by, so each field
 * is checked at its own offsets rather than only in the order it came out.
 * And the one way the store can refuse -- more than the ceiling -- must fail
 * the call, say so afterwards, and leave what was already stored alone.
 *
 * \~spanish
 * Los desplazamientos son por lo que el escritor vuelve a leer la respuesta,
 * asi que cada cabecera se comprueba en los suyos y no solo en el orden en que
 * salio.  Y la unica forma en que el almacen puede negarse -- mas que el
 * techo -- tiene que hacer fallar la llamada, decirlo despues, y dejar en paz
 * lo que ya estaba guardado.
 *
 * \~
 */
void test_offsets_and_failure() {
    Buffer store;
    ResponseBuilder r(store);

    check(r.field("x-one", 5, "alpha", 5), "the first field was refused");
    check(r.field("x-two", 5, "beta", 4), "the second field was refused");
    check(r.field(FieldId::Server, "gamma", 5), "the third field was refused");

    const http_vx::Field *f = r.fields().begin();
    check(f[0].name_len == 5 && std::memcmp(r.bytes() + f[0].name_off, "x-one", 5) == 0,
          "the first name is not at its offset");
    check(value_is(r, f[0], "alpha"), "the first value is not at its offset");
    check(f[1].name_len == 5 && std::memcmp(r.bytes() + f[1].name_off, "x-two", 5) == 0,
          "the second name is not at its offset");
    check(value_is(r, f[1], "beta"), "the second value is not at its offset");
    check(f[1].name_off != f[1].value_off, "a name and its value share an offset");
    check(value_is(r, f[2], "gamma"), "the third value is not at its offset");
    check(f[2].name_len == 0, "a field by id has a name");

    const size_t stored = store.size();
    const size_t too_much = http_vx::kBufferMaxCapacity + 1;
    check(!r.field(FieldId::Date, "x", too_much), "an impossible value was accepted");
    check(r.failed(), "a value that did not fit did not mark the failure");
    check(r.fields().size() == 3, "a value that did not fit was recorded");
    check(store.size() == stored, "a value that did not fit changed the store");

    Buffer s2;
    ResponseBuilder named(s2);
    check(!named.field("x-big", 5, "x", too_much), "an impossible value by name was accepted");
    check(named.failed(), "an impossible value by name did not mark the failure");
    check(named.fields().size() == 0, "an impossible value by name was recorded");

    Buffer s3;
    ResponseBuilder big_name(s3);
    check(!big_name.field("x", too_much, "v", 1), "an impossible name was accepted");
    check(big_name.failed(), "an impossible name did not mark the failure");

    Buffer s4;
    ResponseBuilder body(s4);
    check(body.body("ok", 2), "a small body was refused");
    check(!body.body("x", too_much), "an impossible body was accepted");
    check(body.failed(), "an impossible body did not mark the failure");
    check(body.body().len == 2, "an impossible body changed the one before");
}

/**
 * @brief
 * \~english A late field marks the failure, by id and by name.
 * \~spanish Una cabecera tardia marca el fallo, por id y por nombre.
 * \~
 */
void test_a_late_field_marks_the_failure_each_way() {
    Buffer a;
    ResponseBuilder by_id(a);
    by_id.body("x", 1);
    check(!by_id.field(FieldId::Server, "late", 4), "a late field by id was accepted");
    check(by_id.failed(), "a late field by id did not mark the failure");

    Buffer b;
    ResponseBuilder by_name(b);
    by_name.body("x", 1);
    check(!by_name.field("x-late", 6, "yes", 3), "a late field by name was accepted");
    check(by_name.failed(), "a late field by name did not mark the failure");
    check(by_name.fields().size() == 0, "a late field by name was recorded");
}

/**
 * @brief
 * \~english A port that records what it was asked, and a source with nothing to say.
 * \~spanish Un puerto que apunta lo que se le pidio, y una fuente sin nada que decir.
 * \~
 */
class RecordingPort : public http_vx::OpenPort {
  public:
    http_vx::OpenResponse open(http_vx::ConnHandle c, uint64_t stream,
                               http_vx::BodySource &s,
                               http_vx::KickTarget &target) noexcept override {
        ++calls;
        seen_conn = c;
        seen_stream = stream;
        seen_source = &s;
        seen_target = &target;
        http_vx::OpenResponse r;
        if (accept) {
            r.conn = c;
            r.stream = stream;
        }
        return r;
    }

    size_t fill(http_vx::BodySource &, uint8_t *, size_t, bool &done) noexcept override {
        done = true;
        return 0;
    }

    void end(http_vx::BodySource &, http_vx::GoneReason) noexcept override {}

    int calls = 0;
    bool accept = true;
    http_vx::ConnHandle seen_conn;
    uint64_t seen_stream = 0;
    http_vx::BodySource *seen_source = nullptr;
    http_vx::KickTarget *seen_target = nullptr;
};

/// \~english A source that has nothing to give.  \~spanish Una fuente sin nada que dar.  \~
class EmptySource : public http_vx::BodySource {
  public:
    size_t fill(http_vx::OpenResponse, uint8_t *, size_t, bool &done) noexcept override {
        done = true;
        return 0;
    }

    void gone(http_vx::OpenResponse, http_vx::GoneReason) noexcept override {}
};

/// \~english A target that ignores kicks.  \~spanish Un destino que ignora los avisos.  \~
class IgnoringTarget : public http_vx::KickTarget {
  public:
    void on_kick(http_vx::BodySource &) noexcept override {}
};

/**
 * @brief
 * \~english Opening: only when allowed, only once, and a refusal sticks.
 * \~spanish Abrir: solo si se permite, solo una vez, y un rechazo se queda.
 * \~
 *
 * \~english
 * Three ways to be told no, and each one has to be told without asking the
 * port again: a service that never allowed it (a `HEAD`), a response that is
 * already open, and a limit that was reached -- which stays reached for the
 * rest of this response, because the answer is 503 whatever else the handler
 * does afterwards.
 *
 * \~spanish
 * Tres formas de que te digan que no, y cada una hay que decirla sin volver a
 * preguntar al puerto: un servicio que nunca lo permitio (un `HEAD`), una
 * respuesta que ya esta abierta, y un tope alcanzado -- que sigue alcanzado
 * durante el resto de esta respuesta, porque la contestacion es 503 haga lo
 * que haga el manejador despues.
 *
 * \~
 */
void test_opening() {
    EmptySource src;
    IgnoringTarget target;
    RecordingPort port;
    http_vx::ConnHandle conn;
    conn.slot = 7;
    conn.life = 3;

    Buffer s0;
    ResponseBuilder never(s0);
    check(!never.open(src).valid(), "a response that was never allowed opened");
    check(!never.open_refused(), "not being allowed was counted as a refusal");
    check(never.opened_source() == nullptr, "a response that was not allowed has a source");

    Buffer s1;
    ResponseBuilder r(s1);
    r.allow_open(port, conn, 42, target);
    check(r.opened_source() == nullptr, "a response not yet opened has a source");
    check(!r.opened().valid(), "a response not yet opened is valid");

    const http_vx::OpenResponse first = r.open(src);
    check(first.valid(), "an allowed response did not open");
    check(first.conn.slot == 7 && first.conn.life == 3 && first.stream == 42,
          "the opened response is not the one the port made");
    check(port.calls == 1, "opening did not ask the port exactly once");
    check(port.seen_conn.slot == 7 && port.seen_conn.life == 3,
          "the port was given another connection");
    check(port.seen_stream == 42, "the port was given another stream");
    check(port.seen_source == &src, "the port was given another source");
    check(port.seen_target == &target, "the port was given another target");
    check(r.opened_source() == &src, "the opened response does not keep its source");
    check(r.opened().valid() && r.opened().stream == 42,
          "the opened response was not kept");
    check(!r.open_refused(), "a response that opened was counted as refused");

    EmptySource other;
    check(!r.open(other).valid(), "a response opened twice");
    check(port.calls == 1, "a second open asked the port again");
    check(r.opened_source() == &src, "a second open replaced the source");
    check(!r.open_refused(), "a second open was counted as a refusal");

    RecordingPort limited;
    limited.accept = false;
    Buffer s2;
    ResponseBuilder refused(s2);
    refused.allow_open(limited, conn, 9, target);
    check(!refused.open(src).valid(), "a refusal from the port opened");
    check(refused.open_refused(), "a refusal from the port was not remembered");
    check(refused.opened_source() == nullptr, "a refused response has a source");
    check(!refused.opened().valid(), "a refused response is valid");
    check(limited.calls == 1, "a refusal asked the port more than once");

    limited.accept = true;
    check(!refused.open(src).valid(), "a refused response opened on a second try");
    check(limited.calls == 1, "a refusal that stuck still asked the port again");
    check(refused.open_refused(), "the refusal was forgotten");
}

} // namespace

int main() {
    test_nothing_needs_no_room();
    test_offsets_and_failure();
    test_a_late_field_marks_the_failure_each_way();
    test_opening();
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
