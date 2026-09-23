/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/method.cpp
 * @brief
 * \~english The method table: spelling and properties in the same row.
 * \~spanish La tabla de metodos: grafia y propiedades en la misma fila.
 * \~
 *
 * \~english
 * One table again, and here it buys more than it did for the field names: the
 * spelling and what the method imposes are written on the same line, so a
 * method cannot be added with a name and without its properties.  Two lists
 * would let `PATCH` arrive spelled correctly and quietly claiming to be
 * idempotent, which is the kind of wrong answer that only shows up as a
 * duplicated request under a retry.
 *
 * \~spanish
 * Una tabla otra vez, y aqui compra mas que en los nombres de cabecera: la
 * grafia y lo que el metodo impone se escriben en la misma linea, asi que un
 * metodo no se puede anadir con nombre y sin sus propiedades.  Dos listas
 * dejarian que `PATCH` llegara bien escrito y diciendo por lo bajo que es
 * idempotente, que es de las respuestas equivocadas que solo aparecen como una
 * peticion duplicada bajo un reintento.
 *
 * \~
 */

#include "http_vx/method.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english What a method imposes, one bit each.
 * \~spanish Lo que un metodo impone, un bit cada cosa.
 * \~
 *
 * \~english
 * Internal to this file.  What the rest of the project sees is the predicates,
 * because a call site that reads `method_is_idempotent(m)` says what it wants
 * to know, while one that reads `(props(m) & kIdempotent)` says how it is
 * stored -- and the storage is nobody else's business.
 *
 * \~spanish
 * Interno a este fichero.  Lo que ve el resto del proyecto son los predicados,
 * porque un sitio de llamada que dice `method_is_idempotent(m)` dice lo que
 * quiere saber, mientras que uno que dice `(props(m) & kIdempotent)` dice como
 * esta guardado -- y como esta guardado no es cosa de nadie mas.
 *
 * \~
 */
enum MethodProp : uint8_t {
    kSafe = 1u << 0,
    kIdempotent = 1u << 1,
    kNoResponseBody = 1u << 2,
    kTunnel = 1u << 3,
    kReflects = 1u << 4,
};

/**
 * @brief
 * \~english Safe implies idempotent, so it is written once.
 * \~spanish Seguro implica idempotente, asi que se escribe una vez.
 * \~
 *
 * \~english
 * RFC 9110 section 9.2.2 states the implication.  Writing both bits on every
 * safe row would be repeating a rule in nine places and inviting one of them
 * to disagree.
 *
 * \~spanish
 * El RFC 9110 seccion 9.2.2 enuncia la implicacion.  Escribir los dos bits en
 * cada fila segura seria repetir una regla en nueve sitios e invitar a que uno
 * de ellos discrepe.
 *
 * \~
 */
constexpr uint8_t kSafeAndIdempotent = kSafe | kIdempotent;

/**
 * @brief
 * \~english One row: the spelling, its length and what it imposes.
 * \~spanish Una fila: la grafia, su longitud y lo que impone.
 * \~
 */
struct MethodRow {
    const char *name;
    uint8_t len;
    uint8_t props;
};

/**
 * @brief
 * \~english Builds a row measuring the literal at compile time.
 * \~spanish Construye una fila midiendo el literal al compilar.
 * \~
 */
template <size_t N>
constexpr MethodRow row(const char (&text)[N], uint8_t props) {
    return MethodRow{text, static_cast<uint8_t>(N - 1), props};
}

/**
 * @brief
 * \~english The table, indexed by @c MethodId.
 * \~spanish La tabla, indexada por @c MethodId.
 * \~
 *
 * \~english
 * The order MUST match the enum: the identifier is the index.
 *
 * \~spanish
 * El orden DEBE coincidir con la enumeracion: el identificador es el indice.
 *
 * \~
 */
constexpr MethodRow kMethods[] = {
    row("", 0), // Unknown

    row("GET", kSafeAndIdempotent),

    /* \~english
     * HEAD is safe like GET and additionally forbids the body in the response.
     * \~spanish
     * HEAD es seguro como GET y ademas prohibe el cuerpo en la respuesta.
     * \~ */
    row("HEAD", kSafeAndIdempotent | kNoResponseBody),

    row("POST", 0),
    row("PUT", kIdempotent),
    row("DELETE", kIdempotent),
    row("CONNECT", kTunnel),
    row("OPTIONS", kSafeAndIdempotent),

    /* \~english
     * TRACE is safe -- it changes nothing -- and it is still the one method a
     * server should refuse by default.  The two are not in tension: safe is
     * about the effect on the server, and the danger of TRACE is what it
     * hands back.
     * \~spanish
     * TRACE es seguro -- no cambia nada -- y sigue siendo el unico metodo que
     * un servidor deberia rechazar por defecto.  Las dos cosas no se
     * contradicen: seguro habla del efecto en el servidor, y el peligro de
     * TRACE es lo que devuelve.
     * \~ */
    row("TRACE", kSafeAndIdempotent | kReflects),

    /* \~english
     * PATCH is neither safe nor idempotent: a patch applied twice is not a
     * patch applied once.  RFC 5789 says so explicitly.
     * \~spanish
     * PATCH no es seguro ni idempotente: un parche aplicado dos veces no es un
     * parche aplicado una.  El RFC 5789 lo dice explicitamente.
     * \~ */
    row("PATCH", 0),
};

static_assert(sizeof(kMethods) / sizeof(kMethods[0]) ==
                  static_cast<size_t>(MethodId::Count),
              "the method table and MethodId disagree: every identifier needs "
              "exactly one row, in the same order");

/**
 * @brief
 * \~english The properties of @p id, or none if it is not a method.
 * \~spanish Las propiedades de @p id, o ninguna si no es un metodo.
 * \~
 *
 * \~english
 * @c Unknown lands on the first row, which has no bits set, so every predicate
 * answers false for it without needing a case of its own.
 *
 * \~spanish
 * @c Unknown cae en la primera fila, que no tiene ningun bit, asi que todos los
 * predicados contestan false para el sin necesitar un caso propio.
 *
 * \~
 */
uint8_t props_of(MethodId id) noexcept {
    const size_t i = static_cast<size_t>(id);
    if (i >= static_cast<size_t>(MethodId::Count)) return 0;
    return kMethods[i].props;
}

/**
 * @brief
 * \~english The longest canonical spelling, computed from the table.
 * \~spanish La grafia canonica mas larga, calculada de la tabla.
 * \~
 */
constexpr uint8_t longest_name() noexcept {
    uint8_t m = 0;
    for (const MethodRow &r : kMethods)
        if (r.len > m) m = r.len;
    return m;
}

constexpr uint8_t kLongest = longest_name();

/**
 * @brief
 * \~english Compares @p a with @p b byte for byte, without folding case.
 * \~spanish Compara @p a con @p b byte a byte, sin plegar mayusculas.
 * \~
 *
 * \~english
 * The absence of the `| 0x20` that @c field.cpp uses is the whole point, and
 * it is written as its own function so that it reads as a decision rather than
 * as something left out.
 *
 * \~spanish
 * La ausencia del `| 0x20` que usa @c field.cpp es justo lo que se quiere
 * decir, y se escribe como funcion propia para que se lea como una decision y
 * no como algo que se quedo sin poner.
 *
 * \~
 */
bool same_token(const char *a, const char *b, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

} // namespace

const char *method_name(MethodId id) noexcept {
    const size_t i = static_cast<size_t>(id);
    if (i >= static_cast<size_t>(MethodId::Count)) return "";
    return kMethods[i].name;
}

uint8_t method_name_len(MethodId id) noexcept {
    const size_t i = static_cast<size_t>(id);
    if (i >= static_cast<size_t>(MethodId::Count)) return 0;
    return kMethods[i].len;
}

MethodId method_id_of(const char *name, size_t len) noexcept {
    if (name == nullptr || len == 0 || len > kLongest) return MethodId::Unknown;

    /* \~english
     * By length and first byte before comparing the rest.  With nine rows and
     * lengths from three to seven, that leaves at most two candidates.
     *
     * \~spanish
     * Por longitud y primer byte antes de comparar el resto.  Con nueve filas y
     * longitudes de tres a siete, eso deja dos candidatos como mucho.
     * \~ */
    const char first = name[0];
    for (size_t i = 1; i < static_cast<size_t>(MethodId::Count); ++i) {
        const MethodRow &r = kMethods[i];
        if (r.len != len) continue;
        if (r.name[0] != first) continue;
        if (same_token(name, r.name, len)) return static_cast<MethodId>(i);
    }
    return MethodId::Unknown;
}

bool method_is_safe(MethodId id) noexcept {
    return (props_of(id) & kSafe) != 0;
}

bool method_is_idempotent(MethodId id) noexcept {
    return (props_of(id) & kIdempotent) != 0;
}

bool method_forbids_response_body(MethodId id) noexcept {
    return (props_of(id) & kNoResponseBody) != 0;
}

bool method_is_tunnel(MethodId id) noexcept {
    return (props_of(id) & kTunnel) != 0;
}

bool method_reflects_request(MethodId id) noexcept {
    return (props_of(id) & kReflects) != 0;
}

} // namespace http_vx
