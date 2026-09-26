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
        /// \~english Host must name the same entity as :authority, after scheme-based normalization (RFC 9113, 8.3.1).
        /// \~spanish Host debe nombrar la misma entidad que :authority, tras la normalizacion por esquema (RFC 9113, 8.3.1).  \~
        bool same_host_entity = false;
        /// \~english For http or https, an :authority whose host is empty is refused, Host or not (RFC 9110, 4.2.1-4.2.2; RFC 9113, 8.3.1).
        /// \~spanish Para http o https, una :authority con el host vacio se rechaza, haya Host o no (RFC 9110, 4.2.1-4.2.2; RFC 9113, 8.3.1).  \~
        bool no_empty_host = false;

        /// \~english What HTTP/2 asks: the same entity, normalized, and never an empty host (RFC 9113, 8.3.1).
        /// \~spanish Lo que pide HTTP/2: la misma entidad, normalizada, y nunca un host vacio (RFC 9113, 8.3.1).  \~
        static Options http2() noexcept {
            Options o;
            o.same_host_entity = true;
            o.no_empty_host = true;
            return o;
        }
        /// \~english What HTTP/3 asks: the same value, byte for byte (RFC 9114, 4.3.1).
        /// \~spanish Lo que pide HTTP/3: el mismo valor, byte a byte (RFC 9114, 4.3.1).  \~
        static Options http3() noexcept {
            Options o;
            o.exact_host = true;
            return o;
        }
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

    /// \~english Each Host against :authority as entities, if the option asks; null if they agree, else why not.
    /// \~spanish Cada Host contra :authority como entidades, si la opcion lo pide; nulo si coinciden, si no por que no.  \~
    const char *check_host_entity(const uint8_t *base, const uint8_t *scheme, size_t scheme_len) const noexcept;

    Request *req_ = nullptr;
    Options opt_;
    bool trailers_ = false;
    bool seen_field_ = false;
    uint8_t seen_pseudo_ = 0;
};

/**
 * @brief
 * \~english Whether two authorities, host [":" port], name different entities; null if they name the same one, else why.
 * \~spanish Si dos autoridades, host [":" port], nombran entidades distintas; nulo si nombran la misma, si no por que.
 * \~
 *
 * \~english
 * "Identifies the same entity" (RFC 9113, 8.3.1) is read as: the same host and
 * the same port once both are normalized the way RFC 3986, 6.2.2 and 6.2.3 and
 * RFC 9110, 4.2.3 say for the scheme.  What is equal after that is one entity:
 *
 *  - the host is case-insensitive (RFC 3986, 3.2.2 and 6.2.2.1), IP literals
 *    in brackets included -- their hexadecimal digits are case-insensitive;
 *  - a percent-encoded octet that is an unreserved character is that
 *    character (RFC 3986, 2.3 and 6.2.2.2); any other one stays encoded, with
 *    its hexadecimal digits case-insensitive (RFC 3986, 2.1), and is never
 *    equal to the bare character, since decoding a reserved one changes what
 *    the URI means (RFC 3986, 2.2);
 *  - an empty port is no port (RFC 3986, 3.2.3 and 6.2.3), and so is the
 *    default port of the scheme: 80 for http, 443 for https (RFC 9110, 4.2.1,
 *    4.2.2 and 4.2.3).  Another scheme, or none (CONNECT), has no default here;
 *  - a port is a decimal number (RFC 3986, 3.2.3): leading zeros do not make
 *    another port.
 *
 * Nothing else is equated.  A trailing dot, another spelling of the same IPv6
 * address, or letters that differ only in case beyond ASCII are left
 * different: the comparison ladder admits false negatives (RFC 3986, 6.2), and
 * refusing a request its client should never have sent (RFC 9113, 8.3.1) is
 * safer than routing it to a host it did not name.  A value that is not
 * host [":" port] at all is refused as such, and so is an empty host for http
 * or https (RFC 9110, 4.2.1 and 4.2.2).
 *
 * \~spanish
 * "Identifica la misma entidad" (RFC 9113, 8.3.1) se lee como: el mismo host y
 * el mismo puerto una vez normalizados los dos como dicen RFC 3986, 6.2.2 y
 * 6.2.3 y RFC 9110, 4.2.3 para el esquema.  Lo que queda igual tras eso es una
 * entidad:
 *
 *  - el host no distingue mayusculas (RFC 3986, 3.2.2 y 6.2.2.1), incluidos los
 *    literales IP entre corchetes -- sus digitos hexadecimales tampoco;
 *  - un octeto codificado con porcentaje que es un caracter no reservado es ese
 *    caracter (RFC 3986, 2.3 y 6.2.2.2); cualquier otro sigue codificado, con
 *    sus digitos hexadecimales sin distinguir mayusculas (RFC 3986, 2.1), y
 *    nunca es igual al caracter suelto, porque decodificar uno reservado cambia
 *    lo que significa el URI (RFC 3986, 2.2);
 *  - un puerto vacio es ningun puerto (RFC 3986, 3.2.3 y 6.2.3), y tambien lo
 *    es el puerto por defecto del esquema: 80 para http, 443 para https (RFC
 *    9110, 4.2.1, 4.2.2 y 4.2.3).  Otro esquema, o ninguno (CONNECT), no tiene
 *    defecto aqui;
 *  - un puerto es un numero decimal (RFC 3986, 3.2.3): los ceros a la izquierda
 *    no hacen otro puerto.
 *
 * Nada mas se iguala.  Un punto final, otra forma de escribir la misma
 * direccion IPv6, o letras que solo difieren en mayusculas fuera de ASCII se
 * dejan distintas: la escalera de comparacion admite falsos negativos (RFC
 * 3986, 6.2), y rechazar una peticion que su cliente nunca debio enviar (RFC
 * 9113, 8.3.1) es mas seguro que encaminarla a un host que no nombro.  Un valor
 * que no es host [":" port] se rechaza como tal, y tambien un host vacio para
 * http o https (RFC 9110, 4.2.1 y 4.2.2).
 * \~
 *
 * @param a      \~english the first authority  \~spanish la primera autoridad  \~
 * @param an     \~english its length  \~spanish su longitud  \~
 * @param b      \~english the second authority  \~spanish la segunda autoridad  \~
 * @param bn     \~english its length  \~spanish su longitud  \~
 * @param scheme \~english the scheme, which fixes the default port; empty for none
 *               \~spanish el esquema, que fija el puerto por defecto; vacio si no hay  \~
 * @param sn     \~english its length  \~spanish su longitud  \~
 * @return       \~english null if both name the same entity, else why not
 *               \~spanish nulo si las dos nombran la misma entidad, si no por que no  \~
 */
const char *host_entity_mismatch(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, const uint8_t *scheme,
                                 size_t sn) noexcept;

} // namespace http_vx

#endif // HTTP_VX_REQUEST_BUILDER_H
