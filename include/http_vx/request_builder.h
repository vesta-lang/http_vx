/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/request_builder.h
 * @brief
 * \~english From decompressed field lines to a Request, with the rules HTTP/2 and HTTP/3 share (RFC 9113, 8.2-8.5; RFC 9114, 4.2-4.4).
 * \~spanish De lineas de campo descomprimidas a un Request, con las reglas que comparten HTTP/2 y HTTP/3 (RFC 9113, 8.2-8.5; RFC 9114, 4.2-4.4).
 * \~
 *
 * \~english
 * HPACK and QPACK decompress differently; what comes out is judged the same.
 * Both RFCs say, nearly word for word: names in lower case, no
 * connection-specific fields, TE only as "trailers", pseudo-header fields
 * only the defined ones, once each and before the fields, values without the
 * characters HTTP/1.1 would read as delimiters, and a request that carries
 * :method, :scheme and :path -- or, for CONNECT, :authority and neither of
 * the others.  A message that breaks one is **malformed**: a stream error,
 * never the connection's.
 *
 * Where the two differ, it is an option, not a copy: HTTP/3 says :authority
 * and Host MUST be the same value (RFC 9114, 4.3.1), HTTP/2 SHOULD compare
 * the entities they name after normalizing (RFC 9113, 8.3.1).
 *
 * Trailers go through the same rules, minus the pseudo-header fields, which
 * MUST NOT appear there.
 *
 * \~spanish
 * HPACK y QPACK descomprimen distinto; lo que sale se juzga igual.  Los dos RFC
 * dicen, casi palabra por palabra: nombres en minusculas, sin campos propios de
 * la conexion, TE solo como "trailers", solo las pseudo-cabeceras definidas,
 * una vez cada una y antes de los campos, valores sin los caracteres que
 * HTTP/1.1 leeria como delimitadores, y una peticion que lleva :method, :scheme
 * y :path -- o, para CONNECT, :authority y ninguna de las otras.  Un mensaje que
 * rompe una esta **mal formado**: un error de flujo, nunca de la conexion.
 *
 * Donde los dos difieren, es una opcion, no una copia: HTTP/3 dice que
 * :authority y Host DEBEN ser el mismo valor (RFC 9114, 4.3.1), HTTP/2 DEBERIA
 * comparar las entidades que nombran tras normalizarlas (RFC 9113, 8.3.1).
 *
 * Los remolques pasan por las mismas reglas, menos las pseudo-cabeceras, que NO
 * DEBEN aparecer ahi.
 * \~
 */
#ifndef HTTP_VX_REQUEST_BUILDER_H
#define HTTP_VX_REQUEST_BUILDER_H

#include "http_vx/field.h"
#include "http_vx/message.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Builds one request, or one trailer section, a field line at a time.
 * \~spanish Construye una peticion, o una seccion de remolques, linea de campo a linea de campo.
 * \~
 */
class RequestBuilder {
public:
    /// \~english What a protocol asks beyond the shared rules.  \~spanish Lo que pide un protocolo ademas de las reglas comunes.  \~
    struct Options {
        /// \~english :authority and Host must be exactly the same value (RFC 9114, 4.3.1).
        /// \~spanish :authority y Host deben ser exactamente el mismo valor (RFC 9114, 4.3.1).  \~
        bool exact_host = false;
    };

    /// \~english Starts a header section into @p req, emptied first.  \~spanish Empieza una seccion de cabecera en @p req, vaciado antes.  \~
    void start(Request &req, const Options &opt) noexcept;
    /// \~english Starts a trailer section: fields into @p req's, no pseudo-header fields.
    /// \~spanish Empieza una seccion de remolques: campos en los de @p req, sin pseudo-cabeceras.  \~
    void start_trailers(Request &req) noexcept;

    /**
     * @brief
     * \~english One field line, its bytes at @p base; null if it is fine, else why the message is malformed.
     * \~spanish Una linea de campo, sus bytes en @p base; nulo si esta bien, si no por que el mensaje esta mal formado.
     * \~
     *
     * @param id \~english what the name is, if the caller already knows; Unknown to have it looked up
     *           \~spanish que es el nombre, si quien llama ya lo sabe; Unknown para que se busque  \~
     */
    const char *add(const uint8_t *base, Span name, Span value, FieldId id = FieldId::Unknown) noexcept;

    /// \~english The section is over, its bytes now at @p base: null if the request is whole, else why it is malformed.
    /// \~spanish La seccion acabo, sus bytes ahora en @p base: nulo si la peticion esta entera, si no por que esta mal formada.  \~
    const char *finish(const uint8_t *base) noexcept;

private:
    enum Pseudo : uint8_t { kMethod = 1, kScheme = 2, kAuthority = 4, kPath = 8 };

    Request *req_ = nullptr;
    Options opt_;
    bool trailers_ = false;
    bool seen_field_ = false;
    uint8_t seen_pseudo_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_REQUEST_BUILDER_H
