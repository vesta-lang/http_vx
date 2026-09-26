/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/host_entity.cpp
 * @brief
 * \~english Whether Host and :authority name the same entity: split, normalize and compare (RFC 9113, 8.3.1; RFC 3986, 6.2).
 * \~spanish Si Host y :authority nombran la misma entidad: partir, normalizar y comparar (RFC 9113, 8.3.1; RFC 3986, 6.2).
 * \~
 *
 * \~english
 * Nothing is built: both values are walked side by side, each byte or
 * percent-encoded triplet turned into its normal form on the way.  The rules
 * and why they are these are in request_builder.h, next to the declaration.
 *
 * \~spanish
 * No se construye nada: los dos valores se recorren a la par, cada byte o
 * triplete codificado con porcentaje convertido en su forma normal al pasar.
 * Las reglas y por que son estas estan en request_builder.h, junto a la
 * declaracion.
 * \~
 */
#include "http_vx/request_builder.h"

namespace http_vx {

namespace {

/// \~english One authority split in its host and its port; the port is null if there was no ':'.
/// \~spanish Una autoridad partida en su host y su puerto; el puerto es nulo si no habia ':'.  \~
struct Authority {
    const uint8_t *host = nullptr;
    size_t host_len = 0;
    const uint8_t *port = nullptr;
    size_t port_len = 0;
};

/// \~english unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~" (RFC 3986, 2.3).
/// \~spanish unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~" (RFC 3986, 2.3).  \~
bool is_unreserved(uint8_t c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

/// \~english sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=" (RFC 3986, 2.2).
/// \~spanish sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=" (RFC 3986, 2.2).  \~
bool is_sub_delim(uint8_t c) noexcept {
    return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' ||
           c == ',' || c == ';' || c == '=';
}

/// \~english The value of a HEXDIG, either case (RFC 3986, 2.1); -1 if @p c is none.
/// \~spanish El valor de un HEXDIG, en cualquier caja (RFC 3986, 2.1); -1 si @p c no lo es.  \~
int hex_digit(uint8_t c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// \~english An ASCII letter in lower case; any other byte as it is (RFC 3986, 6.2.2.1).
/// \~spanish Una letra ASCII en minuscula; cualquier otro byte tal cual (RFC 3986, 6.2.2.1).  \~
uint8_t lower(uint8_t c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c - 'A' + 'a') : c; }

/**
 * @brief
 * \~english Splits host [":" port] (RFC 3986, 3.2) and checks each piece's grammar; null if it is one, else why not.
 * \~spanish Parte host [":" port] (RFC 3986, 3.2) y comprueba la gramatica de cada pieza; nulo si lo es, si no por que no.
 * \~
 *
 * \~english
 * The authority carries no userinfo: HTTP forbids it in :authority (RFC 9113,
 * 8.3.1) and Host is uri-host [":" port] (RFC 9110, 7.2), so an '@' is just a
 * character a host cannot hold.
 *
 * \~spanish
 * La autoridad no lleva userinfo: HTTP la prohibe en :authority (RFC 9113,
 * 8.3.1) y Host es uri-host [":" port] (RFC 9110, 7.2), asi que una '@' es solo
 * un caracter que un host no puede llevar.
 * \~
 */
const char *split(const uint8_t *p, size_t n, Authority &out) noexcept {
    size_t i = 0;
    out.host = p;
    if (n > 0 && p[0] == '[') {
        // \~english IP-literal = "[" ( IPv6address / IPvFuture ) "]": only HEXDIG, ':', '.', 'v' and, for IPvFuture,
        // unreserved and sub-delims inside -- never a percent-encoding (RFC 3986, 3.2.2).
        // \~spanish IP-literal = "[" ( IPv6address / IPvFuture ) "]": dentro solo HEXDIG, ':', '.', 'v' y, para
        // IPvFuture, unreserved y sub-delims -- nunca una codificacion con porcentaje (RFC 3986, 3.2.2).  \~
        for (i = 1; i < n && p[i] != ']'; ++i)
            if (!is_unreserved(p[i]) && !is_sub_delim(p[i]) && p[i] != ':')
                return "a Host or :authority with a character an IP literal cannot hold (RFC 3986, 3.2.2)";
        if (i == n) return "a Host or :authority whose IP literal has no closing ']' (RFC 3986, 3.2.2)";
        if (i == 1) return "a Host or :authority with an empty IP literal (RFC 3986, 3.2.2)";
        ++i;
        if (i < n && p[i] != ':') return "a Host or :authority with something other than a port after its IP literal (RFC 3986, 3.2)";
    } else {
        // \~english reg-name = *( unreserved / pct-encoded / sub-delims ), up to the ':' of the port (RFC 3986, 3.2.2).
        // \~spanish reg-name = *( unreserved / pct-encoded / sub-delims ), hasta los ':' del puerto (RFC 3986, 3.2.2).  \~
        for (; i < n && p[i] != ':'; ++i) {
            if (p[i] == '%') {
                if (i + 2 >= n || hex_digit(p[i + 1]) < 0 || hex_digit(p[i + 2]) < 0)
                    return "a Host or :authority with a '%' not followed by two hex digits (RFC 3986, 2.1)";
                i += 2;
            } else if (!is_unreserved(p[i]) && !is_sub_delim(p[i])) {
                return "a Host or :authority with a character a host cannot hold (RFC 3986, 3.2.2)";
            }
        }
    }
    out.host_len = i;
    if (i == n) return nullptr;
    // \~english port = *DIGIT, after the ':' (RFC 3986, 3.2.3).  \~spanish port = *DIGIT, tras los ':' (RFC 3986, 3.2.3).  \~
    out.port = p + i + 1;
    out.port_len = n - i - 1;
    for (size_t j = 0; j < out.port_len; ++j)
        if (out.port[j] < '0' || out.port[j] > '9')
            return "a Host or :authority whose port is not decimal digits (RFC 3986, 3.2.3)";
    return nullptr;
}

/**
 * @brief
 * \~english The next unit of a host in normal form, advancing @p i past it.
 * \~spanish La siguiente unidad de un host en forma normal, avanzando @p i tras ella.
 * \~
 *
 * \~english
 * A byte is itself, in lower case.  A triplet whose octet is unreserved is
 * that character, in lower case too (RFC 3986, 6.2.2.2 and 6.2.2.1).  Any
 * other triplet is 256 plus its octet: equal to the same octet encoded with
 * hex digits of either case (RFC 3986, 2.1), never to a bare byte (RFC 3986,
 * 2.2).  split() has already checked every triplet is whole.
 *
 * \~spanish
 * Un byte es el mismo, en minuscula.  Un triplete cuyo octeto es no reservado
 * es ese caracter, tambien en minuscula (RFC 3986, 6.2.2.2 y 6.2.2.1).
 * Cualquier otro triplete es 256 mas su octeto: igual al mismo octeto
 * codificado con digitos hexadecimales de cualquier caja (RFC 3986, 2.1), nunca
 * a un byte suelto (RFC 3986, 2.2).  split() ya comprobo que cada triplete esta
 * entero.
 * \~
 */
unsigned next_unit(const uint8_t *p, size_t &i) noexcept {
    if (p[i] != '%') return lower(p[i++]);
    const uint8_t octet = static_cast<uint8_t>(hex_digit(p[i + 1]) * 16 + hex_digit(p[i + 2]));
    i += 3;
    if (is_unreserved(octet)) return lower(octet);
    return 256u + octet;
}

/// \~english Whether two hosts are equal in normal form (RFC 3986, 6.2.2).
/// \~spanish Si dos hosts son iguales en forma normal (RFC 3986, 6.2.2).  \~
bool same_host(const Authority &a, const Authority &b) noexcept {
    size_t i = 0;
    size_t j = 0;
    while (i < a.host_len && j < b.host_len)
        if (next_unit(a.host, i) != next_unit(b.host, j)) return false;
    return i == a.host_len && j == b.host_len;
}

/**
 * @brief
 * \~english The port as a number's digits, leading zeros dropped; the default when empty or absent, null if none.
 * \~spanish El puerto como los digitos de un numero, sin ceros a la izquierda; el defecto si esta vacio o falta, nulo si no hay.
 * \~
 *
 * \~english
 * An empty port is no port (RFC 3986, 3.2.3), and no port is the scheme's
 * default (RFC 9110, 4.2.1 and 4.2.2).  Zero loses all its digits and stays a
 * port: a length of zero with a pointer that is not null.
 *
 * \~spanish
 * Un puerto vacio es ningun puerto (RFC 3986, 3.2.3), y ningun puerto es el
 * defecto del esquema (RFC 9110, 4.2.1 y 4.2.2).  El cero pierde todos sus
 * digitos y sigue siendo un puerto: longitud cero con un puntero no nulo.
 * \~
 */
const uint8_t *effective_port(const Authority &a, const char *default_port, size_t &len) noexcept {
    const uint8_t *p = a.port;
    len = a.port_len;
    if (len == 0) {
        if (default_port == nullptr) return nullptr;
        p = reinterpret_cast<const uint8_t *>(default_port);
        len = 0;
        while (default_port[len] != '\0') ++len;
    }
    while (len > 0 && p[0] == '0') {
        ++p;
        --len;
    }
    return p;
}

/// \~english Whether @p s / @p n is @p lit, ignoring the case of ASCII letters (RFC 3986, 3.1).
/// \~spanish Si @p s / @p n es @p lit, sin distinguir mayusculas en letras ASCII (RFC 3986, 3.1).  \~
bool scheme_is(const uint8_t *s, size_t n, const char *lit) noexcept {
    size_t k = 0;
    for (; k < n && lit[k] != '\0'; ++k)
        if (lower(s[k]) != static_cast<uint8_t>(lit[k])) return false;
    return k == n && lit[k] == '\0';
}

} // namespace

const char *host_entity_mismatch(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, const uint8_t *scheme,
                                 size_t sn) noexcept {
    // \~english The default port of the scheme: 80 for http, 443 for https (RFC 9110, 4.2.1 and 4.2.2).
    // \~spanish El puerto por defecto del esquema: 80 para http, 443 para https (RFC 9110, 4.2.1 y 4.2.2).  \~
    const char *default_port = nullptr;
    if (scheme_is(scheme, sn, "http")) default_port = "80";
    else if (scheme_is(scheme, sn, "https")) default_port = "443";
    Authority x;
    Authority y;
    if (const char *why = split(a, an, x)) return why;
    if (const char *why = split(b, bn, y)) return why;
    // \~english http and https forbid an empty host (RFC 9110, 4.2.1 and 4.2.2).
    // \~spanish http y https prohiben un host vacio (RFC 9110, 4.2.1 y 4.2.2).  \~
    if (default_port != nullptr && (x.host_len == 0 || y.host_len == 0))
        return "an empty host for http or https (RFC 9110, 4.2.1 and 4.2.2)";
    if (!same_host(x, y)) return "Host and :authority that name different hosts (RFC 9113, 8.3.1; RFC 3986, 6.2.2)";
    size_t xl = 0;
    size_t yl = 0;
    const uint8_t *xp = effective_port(x, default_port, xl);
    const uint8_t *yp = effective_port(y, default_port, yl);
    if ((xp == nullptr) != (yp == nullptr) || xl != yl)
        return "Host and :authority that name different ports (RFC 9113, 8.3.1; RFC 3986, 6.2.3)";
    for (size_t k = 0; k < xl; ++k)
        if (xp[k] != yp[k]) return "Host and :authority that name different ports (RFC 9113, 8.3.1; RFC 3986, 6.2.3)";
    return nullptr;
}

} // namespace http_vx
