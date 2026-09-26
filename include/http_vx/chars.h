/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/chars.h
 * @brief
 * \~english Which bytes may appear where, per RFC 9110 section 5.6.
 * \~spanish Que bytes pueden aparecer donde, segun RFC 9110 seccion 5.6.
 * \~
 *
 * \~english
 * This is the smallest file in the project and the one with the most security
 * riding on it.  A field value that is allowed to carry a carriage return is a
 * header injection; a method token that is allowed to carry a space is a
 * request smuggling.  Both are the same mistake -- accepting a byte where the
 * grammar does not allow it -- and both are written the same way: a hand-rolled
 * check that got a range wrong and that nobody noticed, because a wrong range
 * only shows up when someone goes looking for it.
 *
 * So the character classes are **one table**, built from the ABNF at compile
 * time, and every predicate reads it.  There is no second opinion to drift.
 *
 * The table is declared @c extern and defined once in the translation unit.
 * The predicates are @c inline in the header and read it.  That combination is
 * deliberate: a table defined in a header would be one copy per translation
 * unit, and a predicate defined in the source file would be a call per byte in
 * the parser's innermost loop.  This way there is one copy and no call.
 *
 * \~spanish
 * Este es el fichero mas pequeno del proyecto y el que mas seguridad lleva
 * encima.  Un valor de cabecera al que se le permita llevar un retorno de carro
 * es una inyeccion de cabeceras; un token de metodo al que se le permita llevar
 * un espacio es un contrabando de peticiones.  Las dos son la misma
 * equivocacion -- aceptar un byte donde la gramatica no lo permite -- y las dos
 * se escriben igual: una comprobacion hecha a mano que erro un rango y que no
 * vio nadie, porque un rango mal puesto solo aparece cuando alguien va a
 * buscarlo.
 *
 * Asi que las clases de caracteres son **una tabla**, construida de la ABNF al
 * compilar, y todos los predicados la leen.  No hay una segunda opinion de la
 * que separarse.
 *
 * La tabla se declara @c extern y se define una vez en la unidad de traduccion.
 * Los predicados son @c inline en la cabecera y la leen.  Esa combinacion es a
 * proposito: una tabla definida en la cabecera seria una copia por unidad de
 * traduccion, y un predicado definido en el fuente seria una llamada por byte
 * en el bucle mas interno del analizador.  Asi hay una copia y no hay llamada.
 *
 * \~
 */
#ifndef HTTP_VX_CHARS_H
#define HTTP_VX_CHARS_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What a byte may be used for.  One bit each.
 * \~spanish Para que puede servir un byte.  Un bit cada una.
 * \~
 */
enum CharFlag : uint8_t {
    /**
     * \~english
     * @c tchar (RFC 9110 5.6.2): letters, digits and fifteen punctuation
     * marks.  It is what a method name, a field name, a transfer coding and a
     * cache directive are made of.
     * \~spanish
     * @c tchar (RFC 9110 5.6.2): letras, digitos y quince signos de
     * puntuacion.  Es de lo que estan hechos un nombre de metodo, un nombre de
     * cabecera, una codificacion de transferencia y una directiva de cache.
     * \~
     */
    kCharToken = 1u << 0,

    /**
     * \~english
     * @c field-vchar (RFC 9110 5.5): a visible character, or @c obs-text.  It
     * is what a field value may carry apart from the spacing.
     * \~spanish
     * @c field-vchar (RFC 9110 5.5): un caracter visible, u @c obs-text.  Es lo
     * que puede llevar un valor de cabecera aparte del espaciado.
     * \~
     */
    kCharFieldVchar = 1u << 1,

    /**
     * \~english
     * @c OWS (RFC 9110 5.6.3): space or horizontal tab.  Allowed inside a
     * field value, not at its edges.
     * \~spanish
     * @c OWS (RFC 9110 5.6.3): espacio o tabulador horizontal.  Permitido
     * dentro de un valor de cabecera, no en sus extremos.
     * \~
     */
    kCharOws = 1u << 2,
};

/**
 * @brief
 * \~english The table, one entry per byte value.
 * \~spanish La tabla, una entrada por valor de byte.
 * \~
 *
 * \~english
 * It is a struct and not a bare array so that it can be initialised from a
 * @c constexpr function that derives it from the grammar.  A literal array of
 * two hundred and fifty-six numbers would be the hand-written second opinion
 * this file exists to avoid.
 *
 * \~spanish
 * Es una estructura y no un array suelto para poder inicializarla desde una
 * funcion @c constexpr que la deriva de la gramatica.  Un array literal de
 * doscientos cincuenta y seis numeros seria la segunda opinion escrita a mano
 * que este fichero existe para evitar.
 *
 * \~
 */
struct CharTable {
    uint8_t v[256];
};

/// \~english The one copy.  \~spanish La unica copia.  \~
extern const CharTable kChars;

/**
 * @brief
 * \~english Whether @p c may appear in a token.
 * \~spanish Si @p c puede aparecer en un token.
 * \~
 * @param c \~english the byte  \~spanish el byte  \~
 * @return  \~english true if it is a @c tchar  \~spanish true si es un @c tchar  \~
 */
inline bool is_tchar(unsigned char c) noexcept {
    return (kChars.v[c] & kCharToken) != 0;
}

/**
 * @brief
 * \~english Whether @p c may appear in a field value.
 * \~spanish Si @p c puede aparecer en un valor de cabecera.
 * \~
 *
 * \~english
 * The bytes from 0x80 up are included.  They are @c obs-text, which the
 * specification keeps for historical reasons and which a recipient must treat
 * as opaque data rather than as text in any particular encoding.  Rejecting
 * them would refuse messages that are legal.
 *
 * \~spanish
 * Los bytes de 0x80 en adelante estan incluidos.  Son @c obs-text, que la
 * especificacion conserva por razones historicas y que quien recibe debe tratar
 * como datos opacos y no como texto en ninguna codificacion concreta.
 * Rechazarlos seria negarse a mensajes que son legales.
 *
 * \~
 * @param c \~english the byte  \~spanish el byte  \~
 * @return  \~english true if it is a @c field-vchar  \~spanish true si es un @c field-vchar  \~
 */
inline bool is_field_vchar(unsigned char c) noexcept {
    return (kChars.v[c] & kCharFieldVchar) != 0;
}

/**
 * @brief
 * \~english Whether @p c is optional whitespace: space or horizontal tab.
 * \~spanish Si @p c es espaciado opcional: espacio o tabulador horizontal.
 * \~
 * @param c \~english the byte  \~spanish el byte  \~
 * @return  \~english true if it is @c OWS  \~spanish true si es @c OWS  \~
 */
inline bool is_ows(unsigned char c) noexcept {
    return (kChars.v[c] & kCharOws) != 0;
}

/**
 * @brief
 * \~english Whether @p s / @p len is a non-empty token.
 * \~spanish Si @p s / @p len es un token no vacio.
 * \~
 *
 * \~english
 * Empty is not a token: the grammar says `1*tchar`.  It matters because an
 * empty method or an empty field name is exactly what a request line split at
 * the wrong byte produces, and accepting it turns a malformed message into a
 * plausible one.
 *
 * \~spanish
 * Vacio no es un token: la gramatica dice `1*tchar`.  Importa porque un metodo
 * vacio o un nombre de cabecera vacio es justo lo que produce una linea de
 * peticion partida por el byte equivocado, y aceptarlo convierte un mensaje mal
 * formado en uno plausible.
 *
 * \~
 * @param s   \~english the bytes  \~spanish los bytes  \~
 * @param len \~english how many  \~spanish cuantos  \~
 * @return    \~english true if every byte is a @c tchar and there is at least one
 *            \~spanish true si todos los bytes son @c tchar y hay al menos uno  \~
 */
bool token_is_valid(const char *s, size_t len) noexcept;

/**
 * @brief
 * \~english Whether @p s / @p len is a well-formed field value.
 * \~spanish Si @p s / @p len es un valor de cabecera bien formado.
 * \~
 *
 * \~english
 * Two conditions, and the second is the one that is usually left out:
 *
 *  - every byte is a @c field-vchar or @c OWS, which is what keeps a carriage
 *    return, a line feed and a nul out of a value that will later be written
 *    back out;
 *  - and the value neither starts nor ends with @c OWS, because that spacing
 *    is not part of the value and has already been removed by the time anyone
 *    stores it.
 *
 * The empty value is legal and returns true: a field with nothing after the
 * colon is a field with an empty value, not a malformed one.
 *
 * \~spanish
 * Dos condiciones, y la segunda es la que se suele dejar fuera:
 *
 *  - todos los bytes son @c field-vchar u @c OWS, que es lo que mantiene un
 *    retorno de carro, un salto de linea y un nulo fuera de un valor que luego
 *    se va a volver a escribir;
 *  - y el valor no empieza ni acaba en @c OWS, porque ese espaciado no es parte
 *    del valor y ya se quito antes de que nadie lo guarde.
 *
 * El valor vacio es legal y devuelve true: una cabecera sin nada tras los dos
 * puntos es una cabecera con valor vacio, no una mal formada.
 *
 * \~
 * @param s   \~english the bytes  \~spanish los bytes  \~
 * @param len \~english how many  \~spanish cuantos  \~
 * @return    \~english true if it is well formed  \~spanish true si esta bien formado  \~
 */
bool field_value_is_valid(const char *s, size_t len) noexcept;

/**
 * @brief
 * \~english Whether the token @p p / @p len is @p lower, without regard to case.
 * \~spanish Si el token @p p / @p len es @p lower, sin atender a mayusculas.
 * \~
 *
 * \~english
 * For the tokens HTTP compares that way: transfer codings (RFC 9110,
 * 10.1.4), connection options (7.6.1).  Only A to Z are lowered, and nothing
 * else: a trick that sets a bit on every byte would also turn a CR into a
 * hyphen.  @p lower is written in lower case.
 * \~spanish
 * Para los tokens que HTTP compara asi: codificaciones de transferencia (RFC
 * 9110, 10.1.4), opciones de conexion (7.6.1).  Solo se bajan de la A a la Z,
 * y nada mas: un truco que pusiera un bit en cada byte convertiria tambien un
 * CR en un guion.  @p lower va escrito en minusculas.
 * \~
 */
bool token_equals(const uint8_t *p, size_t len, const char *lower) noexcept;

/**
 * @brief
 * \~english One element of a comma-separated list, without the whitespace around it.
 * \~spanish Un elemento de una lista separada por comas, sin el espacio de alrededor.
 * \~
 */
struct ListItem {
    const uint8_t *p = nullptr;
    size_t len = 0;
};

/**
 * @brief
 * \~english Walks a field value that is a list (RFC 9110, 5.6.1), one element at a time.
 * \~spanish Recorre un valor de cabecera que es una lista (RFC 9110, 5.6.1), un elemento cada vez.
 * \~
 *
 * \~english
 * Every element comes out, the empty ones too -- `a,,b` is three -- because
 * what an empty element means is the caller's rule, not the list's: some
 * fields ignore it, as 5.6.1 asks, and some take it as malformed.
 * \~spanish
 * Sale cada elemento, tambien los vacios -- `a,,b` son tres --, porque que
 * signifique un elemento vacio es regla de quien llama, no de la lista: unas
 * cabeceras lo ignoran, como pide 5.6.1, y otras lo toman por mal formado.
 * \~
 */
class ListReader {
  public:
    ListReader(const uint8_t *v, size_t n) noexcept : v_(v), left_(n) {}
    /// \~english The next element; false once there is none.  \~spanish El siguiente elemento; falso cuando no queda ninguno.  \~
    bool next(ListItem &out) noexcept;

  private:
    const uint8_t *v_;
    size_t left_;
    bool done_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_CHARS_H
