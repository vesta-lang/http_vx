/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_method.cpp
 * @brief
 * \~english The methods: recognising them, and what they impose.
 * \~spanish Los metodos: reconocerlos, y lo que imponen.
 * \~
 *
 * \~english
 * Two things are worth a test here and they fail in opposite ways.
 *
 * Recognition fails loudly enough to find: a method that resolves to the wrong
 * identifier answers the wrong request.  Case is the exception -- folding it
 * would make `head` work, and working is exactly the problem.
 *
 * The properties fail silently.  A `PATCH` that claims to be idempotent
 * authorises a retry that applies it twice, and nothing in the exchange looks
 * wrong; the damage is in the resource.  So every row's properties are named
 * one by one rather than checked in bulk.
 *
 * \~spanish
 * Dos cosas merecen prueba aqui y fallan de formas opuestas.
 *
 * El reconocimiento falla lo bastante alto como para encontrarlo: un metodo que
 * resuelve al identificador equivocado contesta la peticion equivocada.  Las
 * mayusculas son la excepcion -- plegarlas haria que `head` funcionara, y que
 * funcione es justo el problema.
 *
 * Las propiedades fallan en silencio.  Un `PATCH` que diga que es idempotente
 * autoriza un reintento que lo aplica dos veces, y nada del intercambio tiene
 * mal aspecto; el dano esta en el recurso.  Asi que las propiedades de cada
 * fila se nombran una a una en vez de comprobarse en bloque.
 *
 * \~
 */

#include "http_vx/method.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

http_vx::MethodId id_of(const char *s) {
    return http_vx::method_id_of(s, std::strlen(s));
}

/**
 * @brief
 * \~english Every identifier's spelling resolves back to it.
 * \~spanish La grafia de cada identificador resuelve de vuelta a el.
 * \~
 *
 * \~english
 * This is what keeps the table's two directions in step.  A row written under
 * the wrong identifier builds cleanly and answers a different method, and this
 * loop is the only thing that would notice.
 *
 * \~spanish
 * Es lo que mantiene de acuerdo las dos direcciones de la tabla.  Una fila
 * escrita bajo el identificador equivocado construye sin quejarse y contesta
 * otro metodo, y este bucle es lo unico que se daria cuenta.
 *
 * \~
 */
void test_round_trip() {
    using http_vx::MethodId;
    for (unsigned i = 1; i < static_cast<unsigned>(MethodId::Count); ++i) {
        const MethodId id = static_cast<MethodId>(i);
        const char *name = http_vx::method_name(id);
        const uint8_t len = http_vx::method_name_len(id);

        check(len == std::strlen(name),
              "the stored length does not match the spelling");
        check(http_vx::method_id_of(name, len) == id,
              "a spelling does not resolve to its own identifier");
    }
}

/**
 * @brief
 * \~english A method token is case-sensitive.
 * \~spanish Un token de metodo distingue mayusculas.
 * \~
 *
 * \~english
 * RFC 9110 section 9.1.  The temptation to fold case comes from the field
 * names right next door, where folding is required -- which is precisely why
 * this has a test of its own.
 *
 * \~spanish
 * RFC 9110 seccion 9.1.  La tentacion de plegar mayusculas viene de los nombres
 * de cabecera de al lado, donde plegarlas es obligatorio -- que es justo la
 * razon de que esto tenga prueba propia.
 *
 * \~
 */
void test_case_sensitive() {
    using http_vx::MethodId;
    check(id_of("GET") == MethodId::Get, "GET was not recognised");
    check(id_of("get") == MethodId::Unknown, "a lower-case method was folded");
    check(id_of("Get") == MethodId::Unknown, "a mixed-case method was folded");
    check(id_of("HEAD") == MethodId::Head, "HEAD was not recognised");
    check(id_of("head") == MethodId::Unknown,
          "a lower-case HEAD was folded, which would answer without a body");
}

/**
 * @brief
 * \~english An unregistered method is Unknown, not a refusal.
 * \~spanish Un metodo no registrado es Unknown, no un rechazo.
 * \~
 */
void test_unknown_is_normal() {
    using http_vx::MethodId;
    check(id_of("PROPFIND") == MethodId::Unknown, "WebDAV was recognised");
    check(id_of("PURGE") == MethodId::Unknown, "a custom method was recognised");
    check(id_of("") == MethodId::Unknown, "the empty method was recognised");
    check(http_vx::method_id_of(nullptr, 4) == MethodId::Unknown,
          "a null method was recognised");

    /* \~english
     * A long token must not run off the table; and the length is what it says,
     * not where a nul lands.
     * \~spanish
     * Un token largo no debe salirse de la tabla; y la longitud es la que dice,
     * no donde caiga un nulo.
     * \~ */
    check(id_of("AVERYLONGMETHODNAMEINDEED") == MethodId::Unknown,
          "a long token was recognised");
    check(http_vx::method_id_of("GET /path", 3) == MethodId::Get,
          "the length was not respected");
    check(http_vx::method_id_of("GETX", 4) == MethodId::Unknown,
          "a longer token matched a shorter row");
}

/**
 * @brief
 * \~english What each method imposes, named one by one.
 * \~spanish Lo que impone cada metodo, nombrado uno a uno.
 * \~
 */
void test_properties() {
    using http_vx::MethodId;

    check(http_vx::method_is_safe(MethodId::Get), "GET is not safe");
    check(http_vx::method_is_safe(MethodId::Head), "HEAD is not safe");
    check(http_vx::method_is_safe(MethodId::Options), "OPTIONS is not safe");
    check(http_vx::method_is_safe(MethodId::Trace), "TRACE is not safe");
    check(!http_vx::method_is_safe(MethodId::Post), "POST is safe");
    check(!http_vx::method_is_safe(MethodId::Put), "PUT is safe");
    check(!http_vx::method_is_safe(MethodId::Delete), "DELETE is safe");
    check(!http_vx::method_is_safe(MethodId::Patch), "PATCH is safe");
    check(!http_vx::method_is_safe(MethodId::Connect), "CONNECT is safe");

    check(http_vx::method_is_idempotent(MethodId::Put), "PUT is not idempotent");
    check(http_vx::method_is_idempotent(MethodId::Delete),
          "DELETE is not idempotent");
    check(!http_vx::method_is_idempotent(MethodId::Post), "POST is idempotent");
    check(!http_vx::method_is_idempotent(MethodId::Patch),
          "PATCH is idempotent, which authorises applying it twice");

    check(http_vx::method_forbids_response_body(MethodId::Head),
          "HEAD does not forbid the response body");
    check(!http_vx::method_forbids_response_body(MethodId::Get),
          "GET forbids the response body");

    check(http_vx::method_is_tunnel(MethodId::Connect), "CONNECT is not a tunnel");
    check(!http_vx::method_is_tunnel(MethodId::Post), "POST is a tunnel");

    check(http_vx::method_reflects_request(MethodId::Trace),
          "TRACE does not reflect the request");
    check(!http_vx::method_reflects_request(MethodId::Get),
          "GET reflects the request");
}

/**
 * @brief
 * \~english Safe implies idempotent, for every row.
 * \~spanish Seguro implica idempotente, para todas las filas.
 * \~
 *
 * \~english
 * RFC 9110 section 9.2.2.  It is checked over the table rather than per method
 * so that a row added later cannot break it quietly.
 *
 * \~spanish
 * RFC 9110 seccion 9.2.2.  Se comprueba sobre la tabla y no por metodo para que
 * una fila anadida despues no lo pueda romper por lo bajo.
 *
 * \~
 */
void test_safe_implies_idempotent() {
    using http_vx::MethodId;
    for (unsigned i = 0; i < static_cast<unsigned>(MethodId::Count); ++i) {
        const MethodId id = static_cast<MethodId>(i);
        if (http_vx::method_is_safe(id))
            check(http_vx::method_is_idempotent(id),
                  "a safe method is not idempotent");
    }
}

/**
 * @brief
 * \~english Unknown claims nothing, and that is the conservative answer.
 * \~spanish Unknown no afirma nada, y esa es la respuesta conservadora.
 * \~
 *
 * \~english
 * Not knowing whether a method is safe is not knowing that it is not; but the
 * two answers do not cost the same.  Saying yes would let a cache or a retry
 * repeat a method nobody registered, which is the one likeliest to do
 * something.
 *
 * \~spanish
 * No saber si un metodo es seguro no es saber que no lo es; pero las dos
 * respuestas no cuestan lo mismo.  Decir que si dejaria que una cache o un
 * reintento repitieran un metodo que nadie registro, que es el que mas
 * probablemente haga algo.
 *
 * \~
 */
void test_unknown_claims_nothing() {
    using http_vx::MethodId;
    const MethodId u = MethodId::Unknown;
    check(!http_vx::method_is_safe(u), "an unknown method claims to be safe");
    check(!http_vx::method_is_idempotent(u),
          "an unknown method claims to be idempotent");
    check(!http_vx::method_forbids_response_body(u),
          "an unknown method forbids the response body");
    check(!http_vx::method_is_tunnel(u), "an unknown method is a tunnel");
    check(!http_vx::method_reflects_request(u),
          "an unknown method reflects the request");

    check(std::strcmp(http_vx::method_name(u), "") == 0,
          "the unknown method has a spelling");
    check(http_vx::method_name_len(u) == 0,
          "the unknown method has a length");

    /* \~english
     * And a value past the end answers the same instead of reading the table
     * outside it.
     * \~spanish
     * Y un valor pasado el final contesta lo mismo en vez de leer la tabla
     * fuera de ella.
     * \~ */
    const MethodId past = static_cast<MethodId>(200);
    check(!http_vx::method_is_safe(past), "a value past the end claims to be safe");
    check(http_vx::method_name_len(past) == 0,
          "a value past the end has a length");
}

} // namespace

int main() {
    test_round_trip();
    test_case_sensitive();
    test_unknown_is_normal();
    test_properties();
    test_safe_implies_idempotent();
    test_unknown_claims_nothing();

    if (failures != 0) {
        std::fprintf(stderr, "test_method: %d failures\n", failures);
        return 1;
    }
    std::printf("test_method: ok\n");
    return 0;
}
