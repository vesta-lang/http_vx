/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/field.h
 * @brief
 * \~english Well-known header field names, as small integers.
 * \~spanish Los nombres de cabecera CONOCIDOS, como enteros pequenos.
 * \~
 *
 * \~english
 * A header name is compared far more often than it is read.  The same handful
 * of names -- `host`, `content-length`, `accept` -- arrives on every request,
 * and every layer that wants to know whether one of them is present would
 * otherwise compare text, ignoring case, against a list.
 *
 * So the canonical form of a known name is an **identifier**: a small integer
 * a codec resolves once, and everyone downstream compares with `==`.
 *
 * It is not only about speed.  HTTP/2 and HTTP/3 already carry their own
 * tables of frequent names, so a codec for those versions often receives the
 * *index* and never sees text at all.  Without a shared identifier, each
 * version would need its own idea of "this is the content length", and the
 * semantic layer -- which is supposed to be the same for the three -- would
 * end up with three.
 *
 * \~spanish
 * Un nombre de cabecera se compara muchisimas mas veces de las que se lee.  El
 * mismo punado de nombres -- `host`, `content-length`, `accept` -- llega en
 * cada peticion, y cada capa que quiera saber si uno esta presente tendria
 * que comparar texto, sin distinguir mayusculas, contra una lista.
 *
 * Asi que la forma canonica de un nombre conocido es un **identificador**: un
 * entero pequeno que un codec resuelve una vez y que todos los de mas abajo
 * comparan con `==`.
 *
 * Y no es solo por velocidad.  HTTP/2 y HTTP/3 ya llevan sus propias tablas de
 * nombres frecuentes, asi que un codec de esas versiones recibe muchas veces
 * el *indice* y no llega a ver texto.  Sin un identificador comun, cada
 * version necesitaria su propia idea de "esto es la longitud del cuerpo", y la
 * capa semantica -- que se supone que es la misma para las tres -- acabaria
 * con tres.
 *
 * \~
 */
#ifndef HTTP_VX_FIELD_H
#define HTTP_VX_FIELD_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english A well-known header field name.
 * \~spanish Un nombre de cabecera conocido.
 * \~
 *
 * \~english
 * `Unknown` is not a failure: most requests carry names nobody needs to
 * recognise, and they travel as text.  What this enum buys is that the ones
 * that *do* drive decisions -- framing, connection lifetime, body length --
 * are never compared as text after the codec has read them.
 *
 * The numeric values are **not** an ABI: they are assigned by the order of the
 * table and may change.  Only the names are stable.
 *
 * \~spanish
 * `Unknown` no es un fallo: la mayoria de las peticiones traen nombres que
 * nadie necesita reconocer, y esos viajan como texto.  Lo que compra esta
 * enumeracion es que los que SI deciden algo -- el troceado, la vida de la
 * conexion, la longitud del cuerpo -- no se comparen como texto despues de que
 * el codec los haya leido.
 *
 * Los valores numericos **no** son una ABI: salen del orden de la tabla y
 * pueden cambiar.  Lo estable son los nombres.
 *
 * \~
 */
enum class FieldId : uint16_t {
    Unknown = 0,

    // --- Framing and connection lifetime / troceado y vida de la conexion ---
    ContentLength,
    TransferEncoding,
    Connection,
    KeepAlive,
    Upgrade,
    Expect,
    Trailer,
    TE,

    // --- Routing / encaminamiento ---
    Host,
    Origin,
    Referer,

    // --- Content / contenido ---
    ContentType,
    ContentEncoding,
    ContentLanguage,
    ContentRange,
    ContentDisposition,

    // --- Negotiation / negociacion ---
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    AcceptRanges,
    UserAgent,

    // --- Caching / cache ---
    CacheControl,
    ETag,
    Expires,
    IfMatch,
    IfNoneMatch,
    IfModifiedSince,
    IfUnmodifiedSince,
    LastModified,
    Age,
    Vary,
    Pragma,

    // --- Authentication / autenticacion ---
    Authorization,
    ProxyAuthorization,
    WWWAuthenticate,
    Cookie,
    SetCookie,

    // --- Response / respuesta ---
    Server,
    Date,
    Location,
    RetryAfter,
    Allow,

    // --- Range requests / peticiones por rango ---
    Range,
    IfRange,

    /**
     * @brief
     * \~english How many identifiers there are.  Not a field.
     * \~spanish Cuantos identificadores hay.  No es una cabecera.
     * \~
     */
    Count
};

/**
 * @brief
 * \~english The canonical name of @p id, in lower case.
 * \~spanish El nombre canonico de @p id, en minusculas.
 * \~
 *
 * \~english
 * Lower case because HTTP/2 and HTTP/3 require it on the wire: sending an
 * upper-case letter in a field name is a protocol error there.  HTTP/1.1 does
 * not care, so one form serves the three and there is nothing to convert.
 *
 * \~spanish
 * En minusculas porque HTTP/2 y HTTP/3 lo exigen en el cable: mandar una
 * mayuscula en un nombre de cabecera es un error de protocolo ahi.  HTTP/1.1
 * no distingue, asi que una sola forma sirve a las tres y no hay nada que
 * convertir.
 *
 * \~
 * @param id
 *   \~english the identifier  \~spanish el identificador  \~
 * @return
 *   \~english the name, or an empty string for @c Unknown and @c Count
 *   \~spanish el nombre, o cadena vacia para @c Unknown y @c Count
 *   \~
 */
const char *field_name(FieldId id) noexcept;

/**
 * @brief
 * \~english The length of the canonical name of @p id.
 * \~spanish La longitud del nombre canonico de @p id.
 * \~
 *
 * \~english
 * Stored, not measured.  It is needed on every write of a field line and on
 * every lookup, and walking the string to its terminator to learn something
 * already known at compile time is work nobody asked for.
 *
 * \~spanish
 * Guardada, no medida.  Hace falta en cada escritura de una cabecera y en cada
 * busqueda, y recorrer la cadena hasta su terminador para averiguar algo que ya
 * se sabe al compilar es trabajo que nadie pidio.
 *
 * \~
 * @param id
 *   \~english the identifier  \~spanish el identificador  \~
 * @return
 *   \~english how many bytes the name has  \~spanish cuantos bytes tiene el nombre  \~
 */
uint8_t field_name_len(FieldId id) noexcept;

/**
 * @brief
 * \~english Resolves the name in @p name / @p len to an identifier.
 * \~spanish Resuelve el nombre de @p name / @p len a un identificador.
 * \~
 *
 * \~english
 * Case-insensitive, as HTTP requires, and without lowering anything into a
 * buffer: for the character set a field name may use -- letters, digits and
 * `-` -- setting bit 5 lowers the letters and leaves the rest alone, so the
 * comparison is done on the bytes where they are.
 *
 * The lookup does not walk a list.  It selects by length first, which
 * discards nearly everything in one step, and only then compares bytes.
 *
 * \~spanish
 * Sin distinguir mayusculas, como HTTP exige, y sin pasar nada a minusculas en
 * un buffer: para el juego de caracteres que puede llevar un nombre de
 * cabecera -- letras, digitos y `-` --, poner el bit 5 baja las letras y deja
 * el resto igual, asi que la comparacion se hace sobre los bytes donde estan.
 *
 * La busqueda no recorre una lista.  Discrimina primero por longitud, que
 * descarta casi todo de un paso, y solo entonces compara bytes.
 *
 * \~
 * @code
 * const FieldId id = field_id_of("Content-Length", 14);
 * // id == FieldId::ContentLength
 * @endcode
 *
 * @param name
 *   \~english the bytes of the name; it does not need to be nul-terminated
 *   \~spanish los bytes del nombre; no hace falta que termine en nulo
 *   \~
 * @param len
 *   \~english how many bytes  \~spanish cuantos bytes  \~
 * @return
 *   \~english the identifier, or @c FieldId::Unknown
 *   \~spanish el identificador, o @c FieldId::Unknown
 *   \~
 */
FieldId field_id_of(const char *name, size_t len) noexcept;

} // namespace http_vx

#endif // HTTP_VX_FIELD_H
