/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_chars.cpp
 * @brief
 * \~english The character classes, checked against the grammar.
 * \~spanish Las clases de caracteres, comprobadas contra la gramatica.
 * \~
 *
 * \~english
 * A table that is one bit too generous does not fail: it accepts a message
 * that should have been refused, and the message goes through looking
 * ordinary.  So what is checked here is not that the common bytes work -- they
 * obviously do -- but the edges, one by one: the byte just outside each range,
 * the three that must never be accepted anywhere, and the separators that are
 * the difference between one token and two.
 *
 * \~spanish
 * Una tabla que sea un bit demasiado generosa no falla: acepta un mensaje que
 * habria que haber rechazado, y el mensaje pasa con aspecto corriente.  Asi que
 * lo que se comprueba aqui no es que los bytes corrientes funcionen -- eso es
 * evidente -- sino los extremos, uno a uno: el byte justo fuera de cada rango,
 * los tres que no se deben aceptar nunca en ningun sitio, y los separadores que
 * son la diferencia entre un token y dos.
 *
 * \~
 */

#include "http_vx/chars.h"

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
 * \~english The three bytes that must not be accepted anywhere.
 * \~spanish Los tres bytes que no se deben aceptar en ningun sitio.
 * \~
 *
 * \~english
 * A carriage return or a line feed inside a field value is a header injection:
 * the value is written back out and the recipient reads the rest of it as
 * further fields, or as another message entirely.  A nul is the same trick
 * against anything downstream that treats the value as a C string.
 *
 * \~spanish
 * Un retorno de carro o un salto de linea dentro de un valor de cabecera es una
 * inyeccion de cabeceras: el valor se vuelve a escribir y quien lo recibe lee
 * el resto como mas cabeceras, o como otro mensaje entero.  Un nulo es el mismo
 * truco contra cualquier cosa de mas abajo que trate el valor como cadena de C.
 *
 * \~
 */
void test_the_three_forbidden() {
    const unsigned char bad[] = {'\r', '\n', '\0'};
    for (unsigned char c : bad) {
        check(!http_vx::is_tchar(c), "a forbidden byte is a token character");
        check(!http_vx::is_field_vchar(c),
              "a forbidden byte is a field character");
        check(!http_vx::is_ows(c), "a forbidden byte is whitespace");
    }
}

/**
 * @brief
 * \~english The separators are not token characters.
 * \~spanish Los separadores no son caracteres de token.
 * \~
 *
 * \~english
 * These are what delimit the pieces of a message.  A token allowed to contain
 * one could be read as two, which is how a method or a field name becomes a
 * way of writing something the parser was not meant to see.
 *
 * \~spanish
 * Son lo que delimita las piezas de un mensaje.  Un token al que se le
 * permitiera llevar uno podria leerse como dos, que es como un metodo o un
 * nombre de cabecera se convierte en una forma de escribir algo que el
 * analizador no tenia que ver.
 *
 * \~
 */
void test_separators() {
    const char *seps = "()<>@,;:\\\"/[]?={} \t";
    for (const char *p = seps; *p != '\0'; ++p)
        check(!http_vx::is_tchar(static_cast<unsigned char>(*p)),
              "a separator is accepted inside a token");
}

/**
 * @brief
 * \~english What a token IS: letters, digits and fifteen marks.
 * \~spanish Lo que un token ES: letras, digitos y quince signos.
 * \~
 */
void test_token_characters() {
    for (unsigned char c = 'a'; c <= 'z'; ++c)
        check(http_vx::is_tchar(c), "a lower-case letter is not a token char");
    for (unsigned char c = 'A'; c <= 'Z'; ++c)
        check(http_vx::is_tchar(c), "an upper-case letter is not a token char");
    for (unsigned char c = '0'; c <= '9'; ++c)
        check(http_vx::is_tchar(c), "a digit is not a token char");

    const char *punct = "!#$%&'*+-.^_`|~";
    for (const char *p = punct; *p != '\0'; ++p)
        check(http_vx::is_tchar(static_cast<unsigned char>(*p)),
              "an allowed punctuation mark is not a token char");
    check(std::strlen(punct) == 15, "the grammar lists fifteen marks");
}

/**
 * @brief
 * \~english The edges of the field-value ranges, one byte at a time.
 * \~spanish Los extremos de los rangos del valor de cabecera, byte a byte.
 * \~
 *
 * \~english
 * Three boundaries, and the middle one is the one that gets missed: 0x7F is
 * DEL, it sits between the visible characters and obs-text, and it belongs to
 * neither.  A range written as `>= 0x21` with no upper bound swallows it
 * without anyone noticing.
 *
 * \~spanish
 * Tres fronteras, y la de en medio es la que se escapa: 0x7F es DEL, esta entre
 * los caracteres visibles y obs-text, y no pertenece a ninguno.  Un rango
 * escrito como `>= 0x21` sin cota superior se lo traga sin que nadie se entere.
 *
 * \~
 */
void test_field_value_edges() {
    check(!http_vx::is_field_vchar(0x20), "the space is a visible character");
    check(http_vx::is_field_vchar(0x21), "0x21 is not a visible character");
    check(http_vx::is_field_vchar(0x7E), "0x7E is not a visible character");
    check(!http_vx::is_field_vchar(0x7F), "DEL is accepted in a field value");
    check(http_vx::is_field_vchar(0x80), "obs-text starts later than 0x80");
    check(http_vx::is_field_vchar(0xFF), "obs-text ends before 0xFF");

    check(http_vx::is_ows(' '), "the space is not whitespace");
    check(http_vx::is_ows('\t'), "the tab is not whitespace");
    check(!http_vx::is_ows('a'), "a letter is whitespace");
}

/**
 * @brief
 * \~english Every token character is also a field character.
 * \~spanish Todo caracter de token es tambien caracter de cabecera.
 * \~
 *
 * \~english
 * Not a rule from the specification but a consequence of two that are: a token
 * character is visible, and every visible character may appear in a field
 * value.  It is worth checking because it holds for the whole table at once,
 * so a row built wrong shows up here even if no test names that byte.
 *
 * \~spanish
 * No es una regla de la especificacion sino consecuencia de dos que si lo son:
 * un caracter de token es visible, y todo caracter visible puede aparecer en un
 * valor de cabecera.  Compensa comprobarlo porque vale para la tabla entera de
 * una vez, asi que una fila mal construida aparece aqui aunque ninguna prueba
 * nombre ese byte.
 *
 * \~
 */
void test_token_implies_field_vchar() {
    for (unsigned c = 0; c < 256; ++c) {
        const unsigned char b = static_cast<unsigned char>(c);
        if (http_vx::is_tchar(b))
            check(http_vx::is_field_vchar(b),
                  "a token character is not a field character");
    }
}

/**
 * @brief
 * \~english Whole tokens: empty is not one, and neither is one with a hole.
 * \~spanish Tokens enteros: vacio no lo es, y uno con un hueco tampoco.
 * \~
 */
void test_token_is_valid() {
    check(http_vx::token_is_valid("GET", 3), "GET is not a token");
    check(http_vx::token_is_valid("content-length", 14),
          "a field name is not a token");
    check(http_vx::token_is_valid("X-Custom_1", 10), "a custom name is not a token");

    check(!http_vx::token_is_valid("", 0), "the empty token was accepted");
    check(!http_vx::token_is_valid(nullptr, 3), "a null token was accepted");
    check(!http_vx::token_is_valid("GE T", 4), "a token with a space was accepted");
    check(!http_vx::token_is_valid("GET\r", 4),
          "a token with a carriage return was accepted");
    check(!http_vx::token_is_valid("a:b", 3), "a token with a colon was accepted");

    /* \~english
     * And the length is what it says, not where a nul happens to be: the
     * bytes come from a buffer that holds the whole message.
     * \~spanish
     * Y la longitud es la que dice, no donde haya un nulo: los bytes vienen de
     * un buffer que contiene el mensaje entero.
     * \~ */
    check(http_vx::token_is_valid("GET /path", 3),
          "the length was not respected");
}

/**
 * @brief
 * \~english Whole values: the bytes, and the edges.
 * \~spanish Valores enteros: los bytes, y los extremos.
 * \~
 */
void test_field_value_is_valid() {
    check(http_vx::field_value_is_valid("text/html", 9),
          "an ordinary value was refused");
    check(http_vx::field_value_is_valid("a b", 3),
          "interior whitespace was refused");
    check(http_vx::field_value_is_valid("", 0), "the empty value was refused");
    check(http_vx::field_value_is_valid("\x80\xFF", 2), "obs-text was refused");

    check(!http_vx::field_value_is_valid(" x", 2), "a leading space was accepted");
    check(!http_vx::field_value_is_valid("x ", 2), "a trailing space was accepted");
    check(!http_vx::field_value_is_valid("\tx", 2), "a leading tab was accepted");
    check(!http_vx::field_value_is_valid("x\t", 2), "a trailing tab was accepted");

    check(!http_vx::field_value_is_valid("a\rb", 3),
          "a carriage return was accepted in a value");
    check(!http_vx::field_value_is_valid("a\nb", 3),
          "a line feed was accepted in a value");
    check(!http_vx::field_value_is_valid("a\0b", 3),
          "a nul was accepted in a value");

    /* \~english
     * A single space is both the first and the last byte, so it must be
     * refused by either check.  It is the case that distinguishes a trim that
     * ran from a trim that was supposed to.
     * \~spanish
     * Un espacio solo es a la vez el primer byte y el ultimo, asi que lo tiene
     * que rechazar cualquiera de las dos comprobaciones.  Es el caso que
     * distingue un recorte que corrio de uno que tenia que haber corrido.
     * \~ */
    check(!http_vx::field_value_is_valid(" ", 1), "a lone space was accepted");
}

} // namespace

/**
 * @brief
 * \~english Comparing a token without regard to case: only A to Z are lowered.
 * \~spanish Comparar un token sin atender a mayusculas: solo se bajan de la A a la Z.
 * \~
 */
void test_token_equals() {
    const uint8_t close[] = {'C', 'l', 'O', 's', 'E'};
    check(http_vx::token_equals(close, 5, "close"), "case does not matter");
    check(!http_vx::token_equals(close, 4, "close"), "a prefix is another token");
    const uint8_t closed[] = {'c', 'l', 'o', 's', 'e', 'd'};
    check(!http_vx::token_equals(closed, 6, "close"), "a longer token is another token");
    // \~english CR set with bit 5 would be a hyphen: it must not pass for one.
    // \~spanish CR con el bit 5 puesto seria un guion: no puede pasar por uno.  \~
    const uint8_t cr[] = {'k', 'e', 'e', 'p', '\r', 'a', 'l', 'i', 'v', 'e'};
    check(!http_vx::token_equals(cr, 10, "keep-alive"), "a CR is not a hyphen");
    const uint8_t at[] = {'@'};
    check(!http_vx::token_equals(at, 1, "`"), "only letters are lowered");
    check(http_vx::token_equals(close, 0, ""), "empty equals empty");
}

/**
 * @brief
 * \~english A list walked element by element: trimmed, empty ones included, the last one without a comma.
 * \~spanish Una lista recorrida elemento a elemento: sin espacios, con los vacios, el ultimo sin coma.
 * \~
 */
void test_list_reader() {
    const char *v = " a ,\tb,,  c\t ";
    http_vx::ListReader list(reinterpret_cast<const uint8_t *>(v), std::strlen(v));
    http_vx::ListItem item;
    const char *want[] = {"a", "b", "", "c"};
    int n = 0;
    while (list.next(item)) {
        const bool same = n < 4 && item.len == std::strlen(want[n]) &&
                          std::memcmp(item.p, want[n], item.len) == 0;
        check(same, "each element, trimmed, empty ones kept");
        ++n;
    }
    check(n == 4, "four elements");
    http_vx::ListReader empty(reinterpret_cast<const uint8_t *>(""), 0);
    check(empty.next(item) && item.len == 0 && !empty.next(item), "an empty value is one empty element");
    http_vx::ListReader trailing(reinterpret_cast<const uint8_t *>("a,"), 2);
    n = 0;
    while (trailing.next(item)) ++n;
    check(n == 2, "a trailing comma leaves an empty last element");
}

int main() {
    test_token_equals();
    test_list_reader();
    test_the_three_forbidden();
    test_separators();
    test_token_characters();
    test_field_value_edges();
    test_token_implies_field_vchar();
    test_token_is_valid();
    test_field_value_is_valid();

    if (failures != 0) {
        std::fprintf(stderr, "test_chars: %d failures\n", failures);
        return 1;
    }
    std::printf("test_chars: ok\n");
    return 0;
}
