/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/field.cpp
 * @brief
 * \~english The table of well-known field names, and the lookup.
 * \~spanish La tabla de nombres de cabecera conocidos, y la busqueda.
 * \~
 *
 * \~english
 * One table.  The name, its length and its identifier are written once, and
 * both directions -- identifier to name and name to identifier -- are derived
 * from it.  Two hand-written lists would be two things to keep in step, and
 * the way that fails is silent: a name that resolves to an identifier whose
 * canonical spelling is a different one.
 *
 * The table lives here and not in the header on purpose.  A `static` array in
 * a header is **one copy per translation unit** that includes it, which for a
 * table consulted from three codecs is the sort of waste that nobody sees
 * because nothing breaks.
 *
 * \~spanish
 * Una tabla.  El nombre, su longitud y su identificador se escriben una vez, y
 * las dos direcciones -- de identificador a nombre y de nombre a identificador
 * -- salen de ella.  Dos listas escritas a mano serian dos cosas que mantener
 * de acuerdo, y su modo de fallo es mudo: un nombre que resuelve a un
 * identificador cuya grafia canonica es otra.
 *
 * La tabla vive aqui y no en la cabecera a proposito.  Un array `static` en una
 * cabecera es **una copia por unidad de traduccion** que la incluya, que para
 * una tabla consultada desde tres codecs es de los desperdicios que no ve nadie
 * porque no se rompe nada.
 *
 * \~
 */

#include "http_vx/field.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english One row: the identifier and its canonical spelling.
 * \~spanish Una fila: el identificador y su grafia canonica.
 * \~
 */
struct FieldRow {
    const char *name;
    uint8_t len;
};

/**
 * @brief
 * \~english Builds a row measuring the literal at compile time.
 * \~spanish Construye una fila midiendo el literal al compilar.
 * \~
 *
 * \~english
 * The length is deduced from the array, so it cannot disagree with the text.
 * Writing it by hand would be a number to keep in step with a string, and that
 * is a mistake that compiles.
 *
 * \~spanish
 * La longitud se deduce del array, asi que no puede discrepar del texto.
 * Escribirla a mano seria un numero que mantener de acuerdo con una cadena, y
 * esa equivocacion compila.
 *
 * \~
 */
template <size_t N> constexpr FieldRow row(const char (&text)[N]) {
    return FieldRow{text, static_cast<uint8_t>(N - 1)};
}

/**
 * @brief
 * \~english The table, indexed by @c FieldId.
 * \~spanish La tabla, indexada por @c FieldId.
 * \~
 *
 * \~english
 * The order MUST match the enum: the identifier is the index, so there is no
 * search to go from identifier to name.  A test checks the correspondence,
 * because getting it wrong does not break the build -- it answers a different
 * name.
 *
 * \~spanish
 * El orden DEBE coincidir con la enumeracion: el identificador es el indice,
 * asi que ir de identificador a nombre no busca nada.  Una prueba comprueba la
 * correspondencia, porque equivocarse no rompe la construccion: contesta otro
 * nombre.
 *
 * \~
 */
constexpr FieldRow kFields[] = {
    row(""), // Unknown

    row("content-length"),
    row("transfer-encoding"),
    row("connection"),
    row("keep-alive"),
    row("upgrade"),
    row("expect"),
    row("trailer"),
    row("te"),

    row("host"),
    row("origin"),
    row("referer"),

    row("content-type"),
    row("content-encoding"),
    row("content-language"),
    row("content-range"),
    row("content-disposition"),

    row("accept"),
    row("accept-encoding"),
    row("accept-language"),
    row("accept-ranges"),
    row("user-agent"),

    row("cache-control"),
    row("etag"),
    row("expires"),
    row("if-match"),
    row("if-none-match"),
    row("if-modified-since"),
    row("if-unmodified-since"),
    row("last-modified"),
    row("age"),
    row("vary"),
    row("pragma"),

    row("authorization"),
    row("proxy-authorization"),
    row("proxy-connection"),
    row("www-authenticate"),
    row("cookie"),
    row("set-cookie"),

    row("server"),
    row("date"),
    row("location"),
    row("retry-after"),
    row("allow"),

    row("range"),
    row("if-range"),
};

static_assert(sizeof(kFields) / sizeof(kFields[0]) ==
                  static_cast<size_t>(FieldId::Count),
              "the field table and FieldId disagree: every identifier needs "
              "exactly one row, in the same order");

/**
 * @brief
 * \~english Lowers an ASCII letter leaving digits and `-` untouched.
 * \~spanish Baja una letra ASCII dejando digitos y `-` igual.
 * \~
 *
 * \~english
 * Bit 5 is what separates `A` from `a`.  For the character set a field name
 * may use it is enough, and it avoids copying the name into a buffer to
 * compare it -- which for a name that is discarded right away would be the
 * most expensive part of looking at it.
 *
 * \~spanish
 * El bit 5 es lo que separa `A` de `a`.  Para el juego de caracteres que puede
 * llevar un nombre de cabecera basta con eso, y evita copiar el nombre a un
 * buffer para compararlo -- que para un nombre que se descarta acto seguido
 * seria la parte mas cara de mirarlo.
 *
 * \~
 */
constexpr char lower(char c) noexcept {
    return static_cast<char>(static_cast<unsigned char>(c) | 0x20u);
}

/**
 * @brief
 * \~english Compares @p a with the row @p b, ignoring case.
 * \~spanish Compara @p a con la fila @p b, sin distinguir mayusculas.
 * \~
 *
 * \~english
 * The lengths are known to match before getting here, so this only compares
 * bytes.  The right-hand side is already lower case -- it is the canonical
 * spelling -- so only the left needs lowering.
 *
 * \~spanish
 * Las longitudes ya se sabe que coinciden antes de llegar aqui, asi que esto
 * solo compara bytes.  El lado derecho ya esta en minusculas -- es la grafia
 * canonica --, asi que solo hay que bajar el izquierdo.
 *
 * \~
 */
bool same_name(const char *a, const char *b, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i)
        if (lower(a[i]) != b[i]) return false;
    return true;
}

/**
 * @brief
 * \~english The longest canonical name, computed from the table.
 * \~spanish El nombre canonico mas largo, calculado de la tabla.
 * \~
 */
constexpr uint8_t longest_name() noexcept {
    uint8_t m = 0;
    for (const FieldRow &r : kFields)
        if (r.len > m) m = r.len;
    return m;
}

constexpr uint8_t kLongest = longest_name();

} // namespace

const char *field_name(FieldId id) noexcept {
    const size_t i = static_cast<size_t>(id);
    if (i >= static_cast<size_t>(FieldId::Count)) return "";
    return kFields[i].name;
}

uint8_t field_name_len(FieldId id) noexcept {
    const size_t i = static_cast<size_t>(id);
    if (i >= static_cast<size_t>(FieldId::Count)) return 0;
    return kFields[i].len;
}

FieldId field_id_of(const char *name, size_t len) noexcept {
    /* \~english
     * Two checks that cost nothing and discard almost everything: a name
     * longer than the longest known one cannot be known, and neither can an
     * empty one.  A request full of custom headers -- which is the common case
     * -- leaves here without touching the table.
     *
     * \~spanish
     * Dos comprobaciones que no cuestan nada y descartan casi todo: un nombre
     * mas largo que el mas largo conocido no puede ser conocido, y uno vacio
     * tampoco.  Una peticion llena de cabeceras propias -- que es el caso
     * corriente -- sale de aqui sin tocar la tabla.
     * \~ */
    if (name == nullptr || len == 0 || len > kLongest) return FieldId::Unknown;

    /* \~english
     * Then by length and first letter before comparing anything else.  Of the
     * table's rows, only a handful share both, so what looks like a scan
     * settles in two or three byte comparisons.
     *
     * A perfect hash would save those, and it is not worth it here: it would
     * add a generated table to keep in step with this one, which is exactly
     * the second list this file exists to avoid.
     *
     * \~spanish
     * Y despues por longitud y primera letra antes de comparar nada mas.  De
     * las filas de la tabla, solo un punado comparten las dos, asi que lo que
     * parece un recorrido se resuelve en dos o tres comparaciones de bytes.
     *
     * Un hash perfecto las ahorraria, y aqui no compensa: anadiria una tabla
     * generada que mantener de acuerdo con esta, que es justo la segunda lista
     * que este fichero existe para evitar.
     * \~ */
    const char first = lower(name[0]);
    for (size_t i = 1; i < static_cast<size_t>(FieldId::Count); ++i) {
        const FieldRow &r = kFields[i];
        if (r.len != len) continue;
        if (r.name[0] != first) continue;
        if (same_name(name, r.name, len)) return static_cast<FieldId>(i);
    }
    return FieldId::Unknown;
}

} // namespace http_vx
