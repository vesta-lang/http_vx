/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_field.cpp
 * @brief
 * \~english The well-known field table: the two directions agree.
 * \~spanish La tabla de cabeceras conocidas: las dos direcciones coinciden.
 * \~
 *
 * \~english
 * What is checked here is not that the lookup works on a few names somebody
 * thought of, but that **every** identifier resolves back to itself.  A table
 * whose order drifts from the enum does not fail to build: it answers a
 * different name, which is the kind of mistake that survives review.
 *
 * \~spanish
 * Lo que se comprueba aqui no es que la busqueda funcione con unos cuantos
 * nombres que se le ocurrieron a alguien, sino que **cada** identificador
 * resuelve a si mismo.  Una tabla cuyo orden se separe de la enumeracion no
 * falla al construir: contesta otro nombre, que es de los errores que
 * sobreviven a una revision.
 *
 * \~
 */

#include "http_vx/field.h"

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
 * \~english Every identifier resolves back to itself from its own name.
 * \~spanish Cada identificador resuelve a si mismo desde su propio nombre.
 * \~
 */
void test_round_trip() {
    using http_vx::FieldId;
    for (uint16_t i = 1; i < static_cast<uint16_t>(FieldId::Count); ++i) {
        const FieldId id = static_cast<FieldId>(i);
        const char *name = http_vx::field_name(id);
        const uint8_t len = http_vx::field_name_len(id);

        check(name[0] != '\0', "a known identifier has an empty name");
        check(std::strlen(name) == len,
              "the stored length does not match the name");

        const FieldId back = http_vx::field_id_of(name, len);
        if (back != id) {
            std::fprintf(stderr,
                         "FAIL: '%s' resolves to '%s' instead of itself\n",
                         name, http_vx::field_name(back));
            ++failures;
        }
    }
}

/**
 * @brief
 * \~english The canonical spelling is lower case, as h2 and h3 require.
 * \~spanish La grafia canonica esta en minusculas, como exigen h2 y h3.
 * \~
 */
void test_canonical_is_lower() {
    using http_vx::FieldId;
    for (uint16_t i = 1; i < static_cast<uint16_t>(FieldId::Count); ++i) {
        const char *name = http_vx::field_name(static_cast<FieldId>(i));
        for (const char *p = name; *p != '\0'; ++p)
            check(!(*p >= 'A' && *p <= 'Z'),
                  "a canonical name carries an upper-case letter");
    }
}

/**
 * @brief
 * \~english No two identifiers share a name.
 * \~spanish No hay dos identificadores con el mismo nombre.
 * \~
 *
 * \~english
 * A duplicate would make one of the two unreachable through the lookup, and
 * the round-trip test alone would not notice: it would resolve to the first
 * one, which is a valid identifier.
 *
 * \~spanish
 * Un duplicado dejaria a uno de los dos inalcanzable por la busqueda, y la
 * prueba de ida y vuelta por si sola no lo notaria: resolveria al primero, que
 * es un identificador valido.
 *
 * \~
 */
void test_no_duplicates() {
    using http_vx::FieldId;
    const uint16_t n = static_cast<uint16_t>(FieldId::Count);
    for (uint16_t i = 1; i < n; ++i)
        for (uint16_t j = static_cast<uint16_t>(i + 1); j < n; ++j) {
            const char *a = http_vx::field_name(static_cast<FieldId>(i));
            const char *b = http_vx::field_name(static_cast<FieldId>(j));
            if (std::strcmp(a, b) == 0) {
                std::fprintf(stderr, "FAIL: '%s' appears twice\n", a);
                ++failures;
            }
        }
}

/**
 * @brief
 * \~english Case does not matter, as HTTP requires.
 * \~spanish Las mayusculas no importan, como exige HTTP.
 * \~
 */
void test_case_insensitive() {
    using http_vx::FieldId;

    /* \~english
     * A fixed buffer rather than a growing string.  No name reaches this size
     * -- the assert below says so -- and a test that allocates has a second
     * way to go red that has nothing to do with what it is testing.
     * \~spanish
     * Un buffer fijo en vez de una cadena que crece.  Ningun nombre llega a
     * este tamano -- lo dice la comprobacion de abajo -- y una prueba que
     * reserva tiene una segunda forma de ponerse roja que no tiene nada que ver
     * con lo que prueba.
     * \~ */
    char upper[64];

    for (uint16_t i = 1; i < static_cast<uint16_t>(FieldId::Count); ++i) {
        const FieldId id = static_cast<FieldId>(i);
        const char *name = http_vx::field_name(id);
        const size_t len = http_vx::field_name_len(id);

        check(len < sizeof(upper), "a field name does not fit the test's buffer");
        if (len >= sizeof(upper)) continue;

        for (size_t j = 0; j < len; ++j) {
            const char c = name[j];
            upper[j] = c >= 'a' && c <= 'z' ? static_cast<char>(c - 32) : c;
        }

        check(http_vx::field_id_of(upper, len) == id,
              "the upper-case spelling does not resolve to the identifier");
    }
}

/**
 * @brief
 * \~english What is not known comes back as @c Unknown, without reading past.
 * \~spanish Lo que no se conoce vuelve como @c Unknown, sin leer de mas.
 * \~
 *
 * \~english
 * The empty name and the null pointer are checked because they arrive: a
 * malformed request is the normal case for a public server, not the exception.
 *
 * \~spanish
 * El nombre vacio y el puntero nulo se comprueban porque llegan: una peticion
 * malformada es el caso normal de un servidor publico, no la excepcion.
 *
 * \~
 */
void test_unknown() {
    using http_vx::FieldId;
    check(http_vx::field_id_of(nullptr, 0) == FieldId::Unknown,
          "a null name is not Unknown");
    check(http_vx::field_id_of("", 0) == FieldId::Unknown,
          "an empty name is not Unknown");
    check(http_vx::field_id_of("x-made-up", 9) == FieldId::Unknown,
          "a custom name is not Unknown");

    /* \~english
     * A prefix of a known name is not that name: the lookup selects by length
     * first, so this would only fail if it compared until the terminator.
     * \~spanish
     * Un prefijo de un nombre conocido no es ese nombre: la busqueda discrimina
     * primero por longitud, asi que esto solo fallaria si comparara hasta el
     * terminador.
     * \~ */
    check(http_vx::field_id_of("host-", 5) == FieldId::Unknown,
          "a longer name resolved to a known one");
    check(http_vx::field_id_of("hos", 3) == FieldId::Unknown,
          "a prefix resolved to a known one");

    /* \~english
     * And a name that is not nul-terminated: the lookup must respect the
     * length it was given and not one byte more.
     * \~spanish
     * Y un nombre que no termina en nulo: la busqueda tiene que respetar la
     * longitud que le dan y no un byte mas.
     * \~ */
    const char raw[] = {'h', 'o', 's', 't', ':', 'x'};
    check(http_vx::field_id_of(raw, 4) == FieldId::Host,
          "a name without a terminator did not resolve");
}

/**
 * @brief
 * \~english Exactly the four credentials are secrets, whatever compressor asks (RFC 7541, 7.1.3).
 * \~spanish Exactamente las cuatro credenciales son secretos, pregunte el compresor que pregunte (RFC 7541, 7.1.3).
 * \~
 */
void test_secrets() {
    using http_vx::FieldId;
    check(http_vx::field_is_secret(FieldId::Authorization), "authorization is not a secret");
    check(http_vx::field_is_secret(FieldId::ProxyAuthorization), "proxy-authorization is not a secret");
    check(http_vx::field_is_secret(FieldId::Cookie), "cookie is not a secret");
    check(http_vx::field_is_secret(FieldId::SetCookie), "set-cookie is not a secret");
    check(!http_vx::field_is_secret(FieldId::Unknown), "an unknown field was taken for a secret");

    size_t secrets = 0;
    for (uint16_t i = 1; i < static_cast<uint16_t>(FieldId::Count); ++i)
        if (http_vx::field_is_secret(static_cast<FieldId>(i))) ++secrets;
    check(secrets == 4, "the secrets are not exactly the four credentials");
}

} // namespace

int main() {
    test_round_trip();
    test_canonical_is_lower();
    test_no_duplicates();
    test_case_insensitive();
    test_unknown();
    test_secrets();

    if (failures != 0) {
        std::fprintf(stderr, "test_field: %d failures\n", failures);
        return 1;
    }
    std::printf("test_field: ok\n");
    return 0;
}
