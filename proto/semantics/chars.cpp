/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/chars.cpp
 * @brief
 * \~english The character table, derived from the ABNF at compile time.
 * \~spanish La tabla de caracteres, derivada de la ABNF al compilar.
 * \~
 */

#include "http_vx/chars.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english The fifteen punctuation marks that are part of a token.
 * \~spanish Los quince signos de puntuacion que forman parte de un token.
 * \~
 *
 * \~english
 * Written as the grammar writes them, so the list can be read against the
 * specification without decoding anything.  What is NOT here is the point:
 * the separators -- `(` `)` `,` `/` `:` `;` `<` `=` `>` `?` `@` `[` `\` `]`
 * `{` `}` `"` and the space -- are what delimit the pieces of a message, and a
 * token that was allowed to contain one could be read as two.
 *
 * \~spanish
 * Escritos como los escribe la gramatica, para que la lista se pueda leer
 * contra la especificacion sin descifrar nada.  Lo que NO esta aqui es lo que
 * importa: los separadores -- `(` `)` `,` `/` `:` `;` `<` `=` `>` `?` `@` `[`
 * `\` `]` `{` `}` `"` y el espacio -- son lo que delimita las piezas de un
 * mensaje, y un token al que se le permitiera llevar uno podria leerse como
 * dos.
 *
 * \~
 */
constexpr char kTokenPunct[] = "!#$%&'*+-.^_`|~";

/**
 * @brief
 * \~english Builds the table from the grammar rules.
 * \~spanish Construye la tabla a partir de las reglas de la gramatica.
 * \~
 */
constexpr CharTable build_chars() noexcept {
    CharTable t{};

    for (unsigned c = 0; c < 256; ++c) {
        uint8_t f = 0;

        /* \~english
         * VCHAR is 0x21 to 0x7E -- every printable character except the space
         * -- and obs-text is 0x80 upwards.  Between them lies 0x7F, DEL, which
         * belongs to neither and is therefore not a field character.
         * \~spanish
         * VCHAR es de 0x21 a 0x7E -- todos los caracteres imprimibles salvo el
         * espacio -- y obs-text de 0x80 en adelante.  Entre los dos queda 0x7F,
         * DEL, que no pertenece a ninguno y por tanto no es caracter de
         * cabecera.
         * \~ */
        if ((c >= 0x21 && c <= 0x7E) || c >= 0x80) f |= kCharFieldVchar;

        if (c == ' ' || c == '\t') f |= kCharOws;

        const bool alnum = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                           (c >= 'a' && c <= 'z');
        if (alnum) f |= kCharToken;

        t.v[c] = f;
    }

    /* \~english
     * And the punctuation, from the list above rather than from a second range
     * check.  The terminating nul is skipped by the loop bound, which is what
     * `sizeof - 1` is doing.
     * \~spanish
     * Y la puntuacion, de la lista de arriba y no de una segunda comprobacion
     * de rangos.  El nulo terminador se lo salta la cota del bucle, que es lo
     * que hace el `sizeof - 1`.
     * \~ */
    for (size_t i = 0; i < sizeof(kTokenPunct) - 1; ++i)
        t.v[static_cast<unsigned char>(kTokenPunct[i])] |= kCharToken;

    return t;
}

} // namespace

/* \~english
 * Constant-initialised, so it is laid out in read-only data at build time and
 * there is no initialisation to run and no order to depend on.
 * \~spanish
 * Inicializada como constante, asi que queda puesta en datos de solo lectura al
 * construir y no hay inicializacion que ejecutar ni orden del que depender.
 * \~ */
const CharTable kChars = build_chars();

bool token_is_valid(const char *s, size_t len) noexcept {
    if (s == nullptr || len == 0) return false;
    for (size_t i = 0; i < len; ++i)
        if (!is_tchar(static_cast<unsigned char>(s[i]))) return false;
    return true;
}

bool field_value_is_valid(const char *s, size_t len) noexcept {
    if (len == 0) return true;
    if (s == nullptr) return false;

    /* \~english
     * The edges first.  It is two comparisons and it is the condition that
     * gets forgotten, so it is worth having it where it cannot be skipped by
     * reading the loop and stopping there.
     * \~spanish
     * Los extremos primero.  Son dos comparaciones y es la condicion que se
     * olvida, asi que compensa tenerla donde no se la pueda saltar uno leyendo
     * el bucle y parando ahi.
     * \~ */
    if (is_ows(static_cast<unsigned char>(s[0]))) return false;
    if (is_ows(static_cast<unsigned char>(s[len - 1]))) return false;

    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (!is_field_vchar(c) && !is_ows(c)) return false;
    }
    return true;
}

bool token_equals(const uint8_t *p, size_t len, const char *lower) noexcept {
    size_t i = 0;
    for (; i < len && lower[i] != '\0'; ++i) {
        const uint8_t c = p[i] >= 'A' && p[i] <= 'Z' ? static_cast<uint8_t>(p[i] + ('a' - 'A')) : p[i];
        if (c != static_cast<uint8_t>(lower[i])) return false;
    }
    return i == len && lower[i] == '\0';
}

bool ListReader::next(ListItem &out) noexcept {
    if (done_) return false;
    size_t n = 0;
    while (n < left_ && v_[n] != ',') ++n;
    const uint8_t *p = v_;
    size_t len = n;
    while (len != 0 && is_ows(*p)) {
        ++p;
        --len;
    }
    while (len != 0 && is_ows(p[len - 1])) --len;
    out.p = p;
    out.len = len;
    // \~english The last element is the one no comma follows.  \~spanish El ultimo elemento es el que no sigue ninguna coma.  \~
    if (n == left_) {
        done_ = true;
    } else {
        v_ += n + 1;
        left_ -= n + 1;
    }
    return true;
}

} // namespace http_vx
