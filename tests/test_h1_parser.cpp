/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_parser.cpp
 * @brief
 * \~english The request parser: what it reads, what it refuses, and that
 *           arriving in pieces changes neither.
 * \~spanish El analizador de peticiones: que lee, que rechaza, y que llegar a
 *           trozos no cambia ninguna de las dos cosas.
 * \~
 *
 * \~english
 * The test that matters most here is the dullest to describe: **every message
 * is parsed twice, once whole and once a byte at a time, and the two results
 * must be identical.**
 *
 * It is not a thoroughness exercise.  A parser that resumes wrongly does not
 * fail on the message that was split -- it produces a request, with plausible
 * pieces, differing from the one the peer sent.  And how a message is split is
 * not a property of the message: it is a property of the network on the day.
 * So a bug of that kind reaches production having passed every test that fed
 * it whole, and shows up as one request in a hundred thousand that was read as
 * something else.
 *
 * Feeding one byte at a time makes every boundary the worst boundary at once.
 *
 * \~spanish
 * La prueba que mas importa aqui es la mas aburrida de contar: **cada mensaje
 * se analiza dos veces, una entero y otra byte a byte, y los dos resultados
 * tienen que ser identicos.**
 *
 * No es un ejercicio de minuciosidad.  Un analizador que reanuda mal no falla
 * en el mensaje que llego partido: produce una peticion, con piezas plausibles,
 * distinta de la que mando el otro extremo.  Y como se parte un mensaje no es
 * una propiedad del mensaje: es una propiedad de la red ese dia.  Asi que un
 * fallo de esos llega a produccion habiendo pasado todas las pruebas que se lo
 * dieron entero, y aparece como una peticion de cada cien mil que se leyo como
 * otra cosa.
 *
 * Darle un byte cada vez hace que todas las fronteras sean la peor frontera a
 * la vez.
 *
 * \~
 */

#include "http_vx/h1_parser.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h1::ParseError;
using http_vx::h1::ParseResult;
using http_vx::h1::RequestParser;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Feeds @p msg whole and says how it went.
 * \~spanish Le da @p msg entero y dice como fue.
 * \~
 */
ParseResult feed_whole(RequestParser &p, const char *msg, size_t len,
                       http_vx::Request &out) {
    return p.parse(reinterpret_cast<const uint8_t *>(msg), len, out);
}

/**
 * @brief
 * \~english Feeds @p msg one byte at a time and says how it went.
 * \~spanish Le da @p msg byte a byte y dice como fue.
 * \~
 *
 * \~english
 * The parser is handed the whole prefix each time and not only the new byte,
 * which is how a connection uses it: the buffer holds everything received so
 * far and the parser knows where it stopped.
 *
 * \~spanish
 * Al analizador se le da el prefijo entero cada vez y no solo el byte nuevo,
 * que es como lo usa una conexion: el buffer tiene todo lo recibido hasta el
 * momento y el analizador sabe donde se paro.
 *
 * \~
 */
ParseResult feed_dripping(RequestParser &p, const char *msg, size_t len,
                          http_vx::Request &out) {
    const uint8_t *d = reinterpret_cast<const uint8_t *>(msg);
    ParseResult r = ParseResult::NeedMore;
    for (size_t n = 1; n <= len; ++n) {
        r = p.parse(d, n, out);
        if (r != ParseResult::NeedMore) return r;
    }
    return r;
}

/**
 * @brief
 * \~english Whether @p s names exactly @p want inside @p msg.
 * \~spanish Si @p s nombra exactamente @p want dentro de @p msg.
 * \~
 */
bool span_is(const http_vx::Span &s, const char *msg, const char *want) {
    const size_t len = std::strlen(want);
    if (s.len != len) return false;
    return std::memcmp(msg + s.off, want, len) == 0;
}

/**
 * @brief
 * \~english Checks that @p msg is refused for the reason @p why, both ways.
 * \~spanish Comprueba que @p msg se rechaza por @p why, de las dos formas.
 * \~
 */
void refuses(const char *msg, ParseError why, const char *what) {
    const size_t len = std::strlen(msg);
    {
        RequestParser p;
        http_vx::Request r;
        check(feed_whole(p, msg, len, r) == ParseResult::Error, what);
        check(p.error() == why, what);
    }
    {
        RequestParser p;
        http_vx::Request r;
        check(feed_dripping(p, msg, len, r) == ParseResult::Error, what);
        check(p.error() == why, what);
    }
}

/**
 * @brief
 * \~english An ordinary request, read whole and read dripping.
 * \~spanish Una peticion corriente, leida entera y leida gota a gota.
 * \~
 */
void test_simple() {
    const char *msg = "GET /index.html?a=1 HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: something/1.0\r\n"
                      "Accept: */*\r\n"
                      "\r\n";
    const size_t len = std::strlen(msg);

    for (int pass = 0; pass < 2; ++pass) {
        RequestParser p;
        http_vx::Request r;
        const ParseResult res = pass == 0 ? feed_whole(p, msg, len, r)
                                          : feed_dripping(p, msg, len, r);

        check(res == ParseResult::Done, "an ordinary request was not read");
        check(p.error() == ParseError::None, "an ordinary request reported an error");
        check(p.head_size() == len, "the head did not end where the message does");

        check(r.method == http_vx::MethodId::Get, "the method was not recognised");
        check(span_is(r.method_text, msg, "GET"), "the method spelling is wrong");
        check(span_is(r.target, msg, "/index.html?a=1"), "the target is wrong");
        check(r.version == http_vx::Version::Http11, "the version is wrong");

        check(r.fields.size() == 3, "the wrong number of fields was read");
        check(span_is(r.authority, msg, "example.com"),
              "the authority was not taken from Host");

        const http_vx::Field *ua = r.fields.find(http_vx::FieldId::UserAgent);
        check(ua != nullptr, "the user agent was not found");
        if (ua != nullptr) {
            const http_vx::Span v{ua->value_off, ua->value_len};
            check(span_is(v, msg, "something/1.0"), "the user agent value is wrong");
            const http_vx::Span n{ua->name_off, ua->name_len};
            check(span_is(n, msg, "User-Agent"),
                  "the name was not kept as the peer wrote it");
        }
    }
}

/**
 * @brief
 * \~english A body after the head is not part of the head.
 * \~spanish Un cuerpo tras la cabeza no es parte de la cabeza.
 * \~
 *
 * \~english
 * What `consumed` reports is where the body starts, and a parser that ran on
 * past the blank line would be handing the connection a body that begins in
 * the wrong place -- which is where the next request begins too.
 *
 * \~spanish
 * Lo que informa `consumed` es donde empieza el cuerpo, y un analizador que
 * siguiera pasada la linea en blanco le estaria dando a la conexion un cuerpo
 * que empieza en el sitio equivocado -- que es donde empieza tambien la
 * peticion siguiente.
 *
 * \~
 */
void test_head_ends_at_the_blank_line() {
    const char *msg = "POST /submit HTTP/1.1\r\n"
                      "Host: h\r\n"
                      "Content-Length: 5\r\n"
                      "\r\n"
                      "hello";
    const size_t head = std::strlen(msg) - 5;

    RequestParser p;
    http_vx::Request r;
    check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Done,
          "the request was not read");
    check(p.head_size() == head, "the head swallowed part of the body");
    check(r.method == http_vx::MethodId::Post, "the method is wrong");
}

/**
 * @brief
 * \~english The shapes of a field value that are legal.
 * \~spanish Las formas de un valor de cabecera que son legales.
 * \~
 */
void test_field_values() {
    const char *msg = "GET / HTTP/1.1\r\n"
                      "Host: h\r\n"
                      "A:   spaced   \r\n"
                      "B:\r\n"
                      "C: has spaces inside\r\n"
                      "\r\n";

    RequestParser p;
    http_vx::Request r;
    check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Done,
          "the request was not read");
    check(r.fields.size() == 4, "the wrong number of fields was read");

    const http_vx::Field *f = r.fields.begin();
    /* \~english
     * The spacing around a value is not part of it: it comes off both ends.
     * \~spanish
     * El espaciado de alrededor de un valor no es parte de el: se quita por los
     * dos lados.
     * \~ */
    const http_vx::Span spaced{f[1].value_off, f[1].value_len};
    check(span_is(spaced, msg, "spaced"), "the spacing was kept in the value");

    /* \~english
     * An empty value is legal and is not an absent field.
     * \~spanish
     * Un valor vacio es legal y no es una cabecera ausente.
     * \~ */
    check(f[2].value_len == 0, "an empty value was not read as empty");
    check(f[2].name_len == 1, "the empty field lost its name");

    const http_vx::Span inside{f[3].value_off, f[3].value_len};
    check(span_is(inside, msg, "has spaces inside"),
          "interior spacing was not kept");
}

/**
 * @brief
 * \~english A method nobody registered goes through, spelling and all.
 * \~spanish Un metodo que nadie registro pasa, con su grafia y todo.
 * \~
 */
void test_unknown_method() {
    const char *msg = "PROPFIND /d HTTP/1.1\r\nHost: h\r\n\r\n";
    RequestParser p;
    http_vx::Request r;
    check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Done,
          "an unregistered method was refused, which R19 forbids");
    check(r.method == http_vx::MethodId::Unknown, "it was recognised");
    check(span_is(r.method_text, msg, "PROPFIND"),
          "the spelling of an unrecognised method was lost");
}

/**
 * @brief
 * \~english HTTP/1.0 is read, and does not need a Host.
 * \~spanish HTTP/1.0 se lee, y no necesita Host.
 * \~
 */
void test_http_10() {
    const char *msg = "GET / HTTP/1.0\r\n\r\n";
    RequestParser p;
    http_vx::Request r;
    check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Done,
          "an HTTP/1.0 request without a Host was refused");
    check(r.version == http_vx::Version::Http10, "the version is wrong");
    check(r.authority.empty(), "an authority appeared from nowhere");
}

/**
 * @brief
 * \~english The request line, and every way of writing it wrong.
 * \~spanish La linea de peticion, y todas las formas de escribirla mal.
 * \~
 */
void test_bad_request_line() {
    refuses("GET\r\n\r\n", ParseError::BadMethod, "a request line with no target");
    refuses(" GET / HTTP/1.1\r\n\r\n", ParseError::BadMethod,
            "a request line starting with a space");
    /* \~english
     * A space inside what was meant as the method is not a method with a space
     * in it -- there is no such thing.  It is a method, a target, and then
     * something that is not a version, and it is refused there.  The case is
     * kept because what matters is that it is refused, not where.
     * \~spanish
     * Un espacio dentro de lo que se queria que fuera el metodo no es un metodo
     * con un espacio -- eso no existe --.  Es un metodo, un destino, y despues
     * algo que no es una version, y ahi se rechaza.  El caso se conserva porque
     * lo que importa es que se rechace, no donde.
     * \~ */
    refuses("GE T / HTTP/1.1\r\n\r\n", ParseError::BadVersion,
            "a request line with a space inside the method");

    /* \~english
     * Two spaces.  It is refused because a target that may contain one is a
     * target that the next server in the chain splits somewhere else -- and
     * the two halves are a different request.
     * \~spanish
     * Dos espacios.  Se rechaza porque un destino que pueda llevar uno es un
     * destino que el servidor siguiente de la cadena parte en otro sitio -- y
     * las dos mitades son otra peticion.
     * \~ */
    refuses("GET  / HTTP/1.1\r\n\r\n", ParseError::BadTarget,
            "a request line with two spaces after the method");
    refuses("GET /  HTTP/1.1\r\n\r\n", ParseError::BadVersion,
            "a request line with two spaces before the version");

    refuses("GET / HTTP/1.1 extra\r\n\r\n", ParseError::BadVersion,
            "something after the version");
    refuses("GET / HTTPS/1.1\r\n\r\n", ParseError::BadVersion,
            "a protocol that is not HTTP");
    refuses("GET / HTTP/1.x\r\n\r\n", ParseError::BadVersion,
            "a version that is not numbers");

    /* \~english
     * A version that IS one and is not ours answers differently: the message
     * is well formed and the disagreement is about which protocol.
     * \~spanish
     * Una version que SI lo es y no es la nuestra contesta distinto: el mensaje
     * esta bien formado y la discrepancia es sobre que protocolo.
     * \~ */
    refuses("GET / HTTP/2.0\r\n\r\n", ParseError::UnsupportedVersion,
            "a version we do not speak was called malformed");
    refuses("GET / HTTP/0.9\r\n\r\n", ParseError::UnsupportedVersion,
            "HTTP/0.9 was accepted or called malformed");
}

/**
 * @brief
 * \~english The line endings, which is where the smuggling lives.
 * \~spanish Los finales de linea, que es donde vive el contrabando.
 * \~
 */
void test_line_endings() {
    refuses("GET / HTTP/1.1\nHost: h\r\n\r\n", ParseError::BareLineFeed,
            "a request line ending in a bare line feed");
    refuses("GET / HTTP/1.1\r\nHost: h\n\r\n", ParseError::BareLineFeed,
            "a field line ending in a bare line feed");
    refuses("GET / HTTP/1.1\r\nHost: h\r\n\n", ParseError::BareLineFeed,
            "a field section ending in a bare line feed");
    refuses("GET / HTTP/1.1\r\rHost: h\r\n\r\n", ParseError::BareCarriageReturn,
            "a carriage return with another after it");
    refuses("GET / HTTP/1.1\r\nHost: h\r\n\rX", ParseError::BareCarriageReturn,
            "a carriage return ending the section with no line feed");
}

/**
 * @brief
 * \~english The field lines, and the three shapes that must not be repaired.
 * \~spanish Las cabeceras, y las tres formas que no se deben arreglar.
 * \~
 */
void test_bad_fields() {
    refuses("GET / HTTP/1.1\r\nHost : h\r\n\r\n", ParseError::SpaceBeforeColon,
            "a space before the colon was trimmed instead of refused");
    refuses("GET / HTTP/1.1\r\nHost\t: h\r\n\r\n", ParseError::SpaceBeforeColon,
            "a tab before the colon was trimmed instead of refused");

    refuses("GET / HTTP/1.1\r\nHost: h\r\n X: y\r\n\r\n",
            ParseError::ObsoleteLineFolding,
            "a folded line was joined instead of refused");
    refuses("GET / HTTP/1.1\r\nHost: h\r\n\tX: y\r\n\r\n",
            ParseError::ObsoleteLineFolding,
            "a line folded with a tab was joined instead of refused");

    refuses("GET / HTTP/1.1\r\n: h\r\n\r\n", ParseError::BadFieldName,
            "a field with no name");
    refuses("GET / HTTP/1.1\r\nHo(st): h\r\n\r\n", ParseError::BadFieldName,
            "a field name with a separator in it");

    /* \~english
     * And a nul in a value.  It cannot reach a field value by the grammar, and
     * accepting it would hand anything downstream that treats the value as a C
     * string a value that ends before it does.
     * \~spanish
     * Y un nulo en un valor.  Por la gramatica no puede llegar a un valor de
     * cabecera, y aceptarlo le daria a cualquier cosa de mas abajo que trate el
     * valor como cadena de C un valor que acaba antes de donde acaba.
     * \~ */
    const char with_nul[] = "GET / HTTP/1.1\r\nHost: a\0b\r\n\r\n";
    RequestParser p;
    http_vx::Request r;
    check(p.parse(reinterpret_cast<const uint8_t *>(with_nul),
                  sizeof(with_nul) - 1, r) == ParseResult::Error,
          "a nul in a field value was accepted");
    check(p.error() == ParseError::BadFieldValue,
          "a nul in a field value was refused for the wrong reason");
}

/**
 * @brief
 * \~english Host: required by HTTP/1.1, and only one of it.
 * \~spanish Host: obligatorio en HTTP/1.1, y solo uno.
 * \~
 */
void test_host() {
    refuses("GET / HTTP/1.1\r\n\r\n", ParseError::MissingHost,
            "an HTTP/1.1 request without a Host was accepted");
    refuses("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            ParseError::MultipleHosts, "a request naming two hosts was accepted");
    refuses("GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
            ParseError::MultipleHosts,
            "two Host fields were accepted because they agreed");
}

/**
 * @brief
 * \~english An empty line before the request line: off unless asked for.
 * \~spanish Una linea vacia antes de la peticion: apagado salvo que se pida.
 * \~
 */
void test_leading_crlf() {
    const char *msg = "\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n";
    const size_t len = std::strlen(msg);

    {
        RequestParser p;
        http_vx::Request r;
        check(feed_whole(p, msg, len, r) == ParseResult::Error,
              "a leading empty line was accepted by default");
        check(p.error() == ParseError::BadMethod, "it was refused for a strange reason");
    }
    {
        http_vx::h1::Limits limits;
        limits.allow_leading_crlf = true;
        RequestParser p(limits);
        http_vx::Request r;
        check(feed_whole(p, msg, len, r) == ParseResult::Done,
              "a leading empty line was refused when it was asked for");
        check(span_is(r.method_text, msg, "GET"), "the method moved");
    }
    {
        /* \~english
         * One, and only one.  A stream of empty lines is not an old client, it
         * is a connection being held open without a request on it.
         * \~spanish
         * Una, y solo una.  Un chorro de lineas vacias no es un cliente
         * antiguo, es una conexion que se mantiene abierta sin una peticion.
         * \~ */
        http_vx::h1::Limits limits;
        limits.allow_leading_crlf = true;
        RequestParser p(limits);
        http_vx::Request r;
        const char *two = "\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n";
        check(feed_whole(p, two, std::strlen(two), r) == ParseResult::Error,
              "two leading empty lines were accepted");
    }
}

/**
 * @brief
 * \~english The limits, and that they hold however the message arrives.
 * \~spanish Los limites, y que valen llegue el mensaje como llegue.
 * \~
 *
 * \~english
 * Each is checked both whole and dripping, because a limit that is only
 * tested when the input runs out is a limit that applies to requests that came
 * in pieces and not to the ones worth limiting.
 *
 * \~spanish
 * Cada uno se comprueba entero y gota a gota, porque un limite que solo se
 * comprueba al acabarse la entrada es un limite que se aplica a las peticiones
 * que llegaron a trozos y no a las que merece la pena limitar.
 *
 * \~
 */
void test_limits() {
    char msg[2048];

    {
        http_vx::h1::Limits limits;
        limits.max_request_line = 32;
        int n = std::snprintf(msg, sizeof(msg), "GET /");
        for (int i = 0; i < 100; ++i) msg[n++] = 'a';
        n += std::snprintf(msg + n, sizeof(msg) - n, " HTTP/1.1\r\nHost: h\r\n\r\n");

        RequestParser whole(limits);
        http_vx::Request r1;
        check(whole.parse(reinterpret_cast<const uint8_t *>(msg),
                          static_cast<size_t>(n), r1) == ParseResult::Error,
              "a long request line was accepted when given whole");
        check(whole.error() == ParseError::RequestLineTooLong,
              "a long request line was refused for the wrong reason");

        RequestParser drip(limits);
        http_vx::Request r2;
        check(feed_dripping(drip, msg, static_cast<size_t>(n), r2) ==
                  ParseResult::Error,
              "a long request line was accepted when given a byte at a time");
    }
    {
        http_vx::h1::Limits limits;
        limits.max_fields = 2;
        const char *many = "GET / HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\n\r\n";
        RequestParser p(limits);
        http_vx::Request r;
        check(feed_whole(p, many, std::strlen(many), r) == ParseResult::Error,
              "more fields than allowed were accepted");
        check(p.error() == ParseError::TooManyFields,
              "too many fields was refused for the wrong reason");
    }
    {
        http_vx::h1::Limits limits;
        limits.max_header_bytes = 16;
        const char *big = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                          "X: 0123456789abcdef0123456789abcdef\r\n\r\n";
        RequestParser p(limits);
        http_vx::Request r;
        check(feed_whole(p, big, std::strlen(big), r) == ParseResult::Error,
              "a field section larger than allowed was accepted");
        check(p.error() == ParseError::HeadersTooLarge,
              "a large field section was refused for the wrong reason");
    }
}

/**
 * @brief
 * \~english One parser serves the next request after being reset.
 * \~spanish Un analizador sirve la peticion siguiente tras reiniciarlo.
 * \~
 *
 * \~english
 * And the position goes back to zero with it.  A connection consumes the head
 * from its buffer, so the next message starts at offset zero again -- a
 * parser that kept the old position would start reading the second request
 * somewhere in the middle of it.
 *
 * \~spanish
 * Y la posicion vuelve a cero con el.  Una conexion consume la cabeza de su
 * buffer, asi que el mensaje siguiente vuelve a empezar en el desplazamiento
 * cero -- un analizador que conservara la posicion anterior empezaria a leer la
 * segunda peticion por la mitad.
 *
 * \~
 */
void test_reuse() {
    const char *first = "GET /one HTTP/1.1\r\nHost: a\r\n\r\n";
    const char *second = "PUT /two HTTP/1.1\r\nHost: b\r\nX: y\r\n\r\n";

    RequestParser p;
    http_vx::Request r;

    check(feed_whole(p, first, std::strlen(first), r) == ParseResult::Done,
          "the first request was not read");
    check(span_is(r.target, first, "/one"), "the first target is wrong");

    p.reset();
    r.clear();

    check(feed_whole(p, second, std::strlen(second), r) == ParseResult::Done,
          "the second request was not read");
    check(p.head_size() == std::strlen(second),
          "the position did not go back to the start");
    check(r.method == http_vx::MethodId::Put, "the second method is wrong");
    check(span_is(r.target, second, "/two"), "the second target is wrong");
    check(span_is(r.authority, second, "b"),
          "the authority of the first request survived into the second");
    check(r.fields.size() == 2, "fields of the first request survived");
}

/**
 * @brief
 * \~english Once it has answered, it keeps answering the same.
 * \~spanish Una vez ha contestado, sigue contestando lo mismo.
 * \~
 *
 * \~english
 * A caller that calls again after the head is complete -- because more of the
 * body arrived, say -- must not get the parser reading the body as if it were
 * fields.  And one that calls again after a refusal must not get a second,
 * different answer.
 *
 * \~spanish
 * Quien vuelva a llamar tras completarse la cabeza -- porque llego mas cuerpo,
 * por ejemplo -- no debe encontrarse con el analizador leyendo el cuerpo como
 * si fueran cabeceras.  Y quien vuelva a llamar tras un rechazo no debe
 * encontrarse con una segunda respuesta distinta.
 *
 * \~
 */
void test_sticky() {
    {
        const char *msg = "GET / HTTP/1.1\r\nHost: h\r\n\r\nbody";
        RequestParser p;
        http_vx::Request r;
        const size_t len = std::strlen(msg);
        check(feed_whole(p, msg, len, r) == ParseResult::Done, "it was not read");
        const size_t head = p.head_size();
        check(feed_whole(p, msg, len, r) == ParseResult::Done,
              "calling again changed the answer");
        check(p.head_size() == head, "calling again moved past the head");
        check(r.fields.size() == 1, "calling again read the body as fields");
    }
    {
        const char *msg = "GET / HTTP/1.1\r\n\r\n";
        RequestParser p;
        http_vx::Request r;
        check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Error,
              "it was not refused");
        check(feed_whole(p, msg, std::strlen(msg), r) == ParseResult::Error,
              "calling again after a refusal changed the answer");
        check(p.error() == ParseError::MissingHost, "the reason changed");
    }
}

} // namespace

int main() {
    test_simple();
    test_head_ends_at_the_blank_line();
    test_field_values();
    test_unknown_method();
    test_http_10();
    test_bad_request_line();
    test_line_endings();
    test_bad_fields();
    test_host();
    test_leading_crlf();
    test_limits();
    test_reuse();
    test_sticky();

    if (failures != 0) {
        std::fprintf(stderr, "test_h1_parser: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h1_parser: ok\n");
    return 0;
}
