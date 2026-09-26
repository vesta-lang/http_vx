/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/response_lines.cpp
 * @brief
 * \~english A handler's fields checked and lowered for HTTP/2 and HTTP/3; the rules are in response_lines.h.
 * \~spanish Las cabeceras de un manejador comprobadas y en minusculas para HTTP/2 y HTTP/3; las reglas estan en response_lines.h.
 * \~
 */
#include "http_vx/response_lines.h"

#include "http_vx/chars.h"

namespace http_vx {

const char *wire_fields(const ResponseBuilder &res, Buffer &names, WireField *out, size_t room,
                        size_t &count) noexcept {
    count = 0;
    names.clear();
    const uint8_t *bytes = res.bytes();
    const Fields &fields = res.fields();

    /* \~english
     * The room for every unknown name, taken in one go before any is written:
     * a buffer that grows moves, and the names already pointed at would move
     * with it.
     * \~spanish
     * El sitio para todos los nombres desconocidos, cogido de una vez antes de
     * escribir ninguno: un buffer que crece se mueve, y los nombres a los que ya
     * se apunta se moverian con el.
     * \~ */
    size_t lowered = 0;
    for (const Field *f = fields.begin(); f != fields.end(); ++f) {
        if (count == room) return "more fields than a response can carry";
        ++count;
        if (f->id == FieldId::Unknown) lowered += f->name_len;
    }
    count = 0;
    uint8_t *low = lowered != 0 ? names.reserve(lowered) : nullptr;
    if (lowered != 0 && low == nullptr) return "out of memory for the field names";
    size_t at = 0;

    for (const Field *f = fields.begin(); f != fields.end(); ++f) {
        WireField &w = out[count];
        w.id = f->id;
        w.value = bytes + f->value_off;
        w.value_len = f->value_len;
        if (f->id != FieldId::Unknown) {
            // \~english A known field: its canonical name is lower case already.
            // \~spanish Una cabecera conocida: su nombre canonico ya esta en minusculas.  \~
            w.name = reinterpret_cast<const uint8_t *>(field_name(f->id));
            w.name_len = field_name_len(f->id);
        } else {
            const char *n = reinterpret_cast<const char *>(bytes + f->name_off);
            // \~english A token: no colon, space or control -- so no pseudo-header either (RFC 9113, 8.2.1; RFC 9114, 4.2).
            // \~spanish Un token: sin dos puntos, espacio ni control -- asi que tampoco una pseudo-cabecera (RFC 9113, 8.2.1; RFC 9114, 4.2).  \~
            if (!token_is_valid(n, f->name_len)) return "a field name that is not a token (RFC 9110, 5.1)";
            // \~english Lowered before it is encoded (RFC 9113, 8.2; RFC 9114, 4.2).
            // \~spanish En minusculas antes de codificarse (RFC 9113, 8.2; RFC 9114, 4.2).  \~
            for (size_t i = 0; i < f->name_len; ++i) {
                const char c = n[i];
                low[at + i] = static_cast<uint8_t>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            }
            w.name = low + at;
            w.name_len = f->name_len;
            at += f->name_len;
        }
        if (field_is_connection_specific(f->id))
            return "a connection-specific field (RFC 9113, 8.2.2; RFC 9114, 4.2)";
        if (!field_value_is_valid(reinterpret_cast<const char *>(w.value), w.value_len))
            return "a field value with a character HTTP forbids there (RFC 9110, 5.5)";
        ++count;
    }
    if (lowered != 0) names.commit(lowered);
    return nullptr;
}

} // namespace http_vx
