/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/response_lines.h
 * @brief
 * \~english A handler's fields as HTTP/2 and HTTP/3 must write them (RFC 9113, 8.2; RFC 9114, 4.2).
 * \~spanish Las cabeceras de un manejador tal como HTTP/2 y HTTP/3 deben escribirlas (RFC 9113, 8.2; RFC 9114, 4.2).
 * \~
 *
 * \~english
 * A handler names no version, so it spells a field however it likes:
 * `X-Request-Id`, as HTTP/1.1 has always allowed.  The two versions that
 * compress their fields do not: names MUST be converted to lower case before
 * they are encoded, and a message with an uppercase name is malformed at the
 * other end.  Nor may they generate a connection-specific field, or a name or
 * value with the characters HTTP/1.1 reads as delimiters.
 *
 * HTTP/1.1's writer checks names and values on its own, because it writes
 * text.  This is the same check for the two that write field lines, in one
 * place, so that a rule about what may leave this server cannot hold for one
 * version and not for the other.
 *
 * \~spanish
 * Un manejador no nombra ninguna version, asi que escribe una cabecera como
 * quiera: `X-Request-Id`, como HTTP/1.1 ha permitido siempre.  Las dos
 * versiones que comprimen sus cabeceras no: los nombres DEBEN pasarse a
 * minusculas antes de codificarse, y un mensaje con un nombre en mayusculas
 * esta mal formado en el otro extremo.  Tampoco pueden generar un campo propio
 * de la conexion, ni un nombre o un valor con los caracteres que HTTP/1.1 lee
 * como delimitadores.
 *
 * El escritor de HTTP/1.1 comprueba nombres y valores por su cuenta, porque
 * escribe texto.  Esta es la misma comprobacion para las dos que escriben
 * lineas de campo, en un sitio, para que una regla sobre lo que puede salir de
 * este servidor no valga para una version y no para la otra.
 * \~
 */
#ifndef HTTP_VX_RESPONSE_LINES_H
#define HTTP_VX_RESPONSE_LINES_H

#include "http_vx/buffer.h"
#include "http_vx/field.h"
#include "http_vx/response.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english One field of a response, ready to be encoded: lower-case name, checked value.
 * \~spanish Una cabecera de una respuesta, lista para codificarse: nombre en minusculas, valor comprobado.
 * \~
 */
struct WireField {
    const uint8_t *name = nullptr;
    size_t name_len = 0;
    const uint8_t *value = nullptr;
    size_t value_len = 0;
    /// \~english What the field is, or @c Unknown.  \~spanish Que cabecera es, o @c Unknown.  \~
    FieldId id = FieldId::Unknown;
};

/**
 * @brief
 * \~english Turns the fields of @p res into @p out, lowering unknown names into @p names.
 * \~spanish Convierte las cabeceras de @p res en @p out, bajando a minusculas en @p names los nombres desconocidos.
 * \~
 *
 * \~english
 * A known field takes its canonical name, which is lower case already; an
 * unknown one is checked as a token and lowered.  Values are checked as field
 * values.  The pointers in @p out point into @p res's bytes, into the
 * canonical names, or into @p names, which is cleared first and must not be
 * touched until @p out has been used.
 *
 * A field that cannot travel is not dropped: the answer the handler wrote is
 * not the one that would go, so the caller says so -- with a server error,
 * since the fault is this server's.
 *
 * \~spanish
 * Una cabecera conocida toma su nombre canonico, que ya esta en minusculas; una
 * desconocida se comprueba como token y se baja a minusculas.  Los valores se
 * comprueban como valores de campo.  Los punteros de @p out apuntan a los bytes
 * de @p res, a los nombres canonicos, o a @p names, que se vacia primero y no
 * se puede tocar hasta haber usado @p out.
 *
 * Una cabecera que no puede viajar no se tira: la respuesta que escribio el
 * manejador no es la que saldria, asi que quien llama lo dice -- con un error
 * del servidor, porque la culpa es de este servidor.
 * \~
 * @param res   \~english what the handler answered  \~spanish lo que contesto el manejador  \~
 * @param names \~english where unknown names are lowered  \~spanish donde se bajan los nombres desconocidos  \~
 * @param out   \~english the fields, in order  \~spanish las cabeceras, en orden  \~
 * @param room  \~english how many fit in @p out  \~spanish cuantas caben en @p out  \~
 * @param count \~english how many were written  \~spanish cuantas se escribieron  \~
 * @return      \~english null, or the rule a field broke  \~spanish nulo, o la regla que rompio una cabecera  \~
 */
const char *wire_fields(const ResponseBuilder &res, Buffer &names, WireField *out, size_t room,
                        size_t &count) noexcept;

} // namespace http_vx

#endif // HTTP_VX_RESPONSE_LINES_H
