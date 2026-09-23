/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/content_length.cpp
 * @brief
 * \~english Reading the content length, strictly.
 * \~spanish Leer la longitud de contenido, estrictamente.
 * \~
 */

#include "http_vx/content_length.h"

#include "http_vx/chars.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english What reading one list element found.
 * \~spanish Que se encontro al leer un elemento de la lista.
 * \~
 */
struct Element {
    bool ok;
    bool too_large;
    uint64_t value;
};

/**
 * @brief
 * \~english Reads one element: digits, and only digits.
 * \~spanish Lee un elemento: digitos, y solo digitos.
 * \~
 *
 * \~english
 * The spacing around it is dropped first, because a list separates its
 * elements with a comma and allows whitespace on either side of it.  What is
 * left has to be `1*DIGIT` entire -- an element that is empty after the
 * trimming is not a zero, it is a list with a hole in it, and a hole is what a
 * value looks like when one recipient in the chain removed something the next
 * one would have seen.
 *
 * \~spanish
 * El espaciado de alrededor se quita primero, porque una lista separa sus
 * elementos con una coma y permite espacios a ambos lados de ella.  Lo que
 * queda tiene que ser `1*DIGIT` entero -- un elemento que queda vacio tras el
 * recorte no es un cero, es una lista con un hueco, y un hueco es lo que
 * parece un valor cuando un receptor de la cadena quito algo que el siguiente
 * si habria visto.
 *
 * \~
 */
Element read_element(const uint8_t *p, size_t len) noexcept {
    while (len != 0 && is_ows(*p)) {
        ++p;
        --len;
    }
    while (len != 0 && is_ows(p[len - 1])) --len;

    if (len == 0) return Element{false, false, 0};

    uint64_t v = 0;
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = p[i];
        if (c < '0' || c > '9') return Element{false, false, 0};

        const uint64_t d = static_cast<uint64_t>(c - '0');

        /* \~english
         * The check goes BEFORE the multiplication, not after.  Multiplying
         * and then noticing that the result came out smaller is noticing an
         * overflow that already happened, and what it leaves behind is a
         * plausible length: the attacker picks the digits, so the attacker
         * picks what it wraps to.
         *
         * \~spanish
         * La comprobacion va ANTES de multiplicar, no despues.  Multiplicar y
         * darse cuenta luego de que el resultado salio mas pequeno es darse
         * cuenta de un desbordamiento que ya ocurrio, y lo que deja detras es
         * una longitud plausible: el atacante elige los digitos, asi que el
         * atacante elige a que da la vuelta.
         * \~ */
        constexpr uint64_t kMax = ~uint64_t{0};
        if (v > (kMax - d) / 10) return Element{false, true, 0};

        v = v * 10 + d;
    }
    return Element{true, false, v};
}

} // namespace

ContentLength parse_content_length(const Fields &fields,
                                   const uint8_t *base) noexcept {
    const Field *f = fields.find(FieldId::ContentLength);
    if (f == nullptr) return ContentLength{ContentLengthStatus::Absent, 0};

    bool seen = false;
    bool too_large = false;
    uint64_t agreed = 0;

    /* \~english
     * Every occurrence, and every element of every occurrence.  Stopping at
     * the first is the mistake that makes two recipients frame a message
     * differently, so the loop has no early exit for success -- only for the
     * failures, which are final.
     *
     * \~spanish
     * Todas las apariciones, y todos los elementos de cada aparicion.  Parar en
     * la primera es la equivocacion que hace que dos receptores troceen un
     * mensaje de forma distinta, asi que el bucle no tiene salida temprana por
     * exito -- solo por los fallos, que son definitivos.
     * \~ */
    for (; f != nullptr; f = fields.find_next(f)) {
        const uint8_t *v = base + f->value_off;
        size_t left = f->value_len;

        for (;;) {
            size_t n = 0;
            while (n < left && v[n] != ',') ++n;

            const Element e = read_element(v, n);
            if (e.too_large) {
                too_large = true;
            } else if (!e.ok) {
                return ContentLength{ContentLengthStatus::Malformed, 0};
            } else if (!seen) {
                seen = true;
                agreed = e.value;
            } else if (e.value != agreed) {
                return ContentLength{ContentLengthStatus::Conflicting, 0};
            }

            if (n == left) break;
            v += n + 1;
            left -= n + 1;
        }
    }

    /* \~english
     * A value too large to hold is reported after the whole field has been
     * walked, because a message that is ALSO contradictory is contradictory
     * first: the answers differ -- 413 against 400 and a closed connection --
     * and the stricter one is the one that has to win.
     *
     * \~spanish
     * Un valor que no cabe se informa tras recorrer la cabecera entera, porque
     * un mensaje que ADEMAS se contradice se contradice primero: las respuestas
     * son distintas -- 413 frente a 400 y cerrar -- y la que tiene que ganar es
     * la mas estricta.
     * \~ */
    if (too_large) return ContentLength{ContentLengthStatus::TooLarge, 0};

    return ContentLength{ContentLengthStatus::Present, agreed};
}

} // namespace http_vx
