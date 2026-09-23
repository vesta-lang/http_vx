/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_hpack.h
 * @brief
 * \~english The pieces HPACK is built from: numbers, and the table everyone has.
 * \~spanish Las piezas de las que esta hecho HPACK: numeros, y la tabla que
 *           tiene todo el mundo.
 * \~
 *
 * \~english
 * HTTP/1.1 sends `user-agent: ...` on every request of a connection, and the
 * bytes are identical every time.  HPACK is what stops that: the fields both
 * ends already know are sent as a NUMBER, and the ones they do not are sent
 * once and remembered.
 *
 * Which means a header block is not text, and this is where the split between
 * what a message MEANS and how it is written stops being a claim.  The
 * semantic layer has never read a byte of HTTP/1.1 and it will never read a
 * byte of this: what reaches it is a @c FieldId and a pair of spans, and where
 * those came from -- a name spelled out in text, an index into a table, a
 * Huffman code -- is this file's business and nobody else's.
 *
 * Two things live here and neither needs any state, which is why they come
 * first: **the integers** everything else is measured in, and **the table**
 * both ends are born knowing.
 *
 * \~spanish
 * HTTP/1.1 manda `user-agent: ...` en cada peticion de una conexion, y los
 * bytes son identicos todas las veces.  HPACK es lo que lo corta: las cabeceras
 * que los dos extremos ya conocen se mandan como un NUMERO, y las que no se
 * mandan una vez y se recuerdan.
 *
 * Lo que quiere decir que un bloque de cabeceras no es texto, y aqui es donde
 * el corte entre lo que un mensaje SIGNIFICA y como se escribe deja de ser una
 * afirmacion.  La capa semantica no ha leido nunca un byte de HTTP/1.1 y no va
 * a leer un byte de esto: lo que le llega es un @c FieldId y un par de trozos,
 * y de donde salieron -- un nombre escrito en texto, un indice de una tabla, un
 * codigo Huffman -- es cosa de este fichero y de nadie mas.
 *
 * Aqui viven dos cosas y ninguna necesita estado, que es la razon de que vayan
 * primero: **los enteros** en los que se mide todo lo demas, y **la tabla** que
 * los dos extremos conocen de nacimiento.
 *
 * \~
 */
#ifndef HTTP_VX_H2_HPACK_H
#define HTTP_VX_H2_HPACK_H

#include "http_vx/field.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {
namespace hpack {

/**
 * @brief
 * \~english How reading a piece of a header block went.
 * \~spanish Como fue leer un pedazo de un bloque de cabeceras.
 * \~
 *
 * \~english
 * There is no "it is not here yet" that is also a refusal.  A header block
 * arrives whole -- the frame layer above does not hand one over until its last
 * CONTINUATION -- so running out of bytes in the middle of one is not a short
 * read, it is a block that lies about its own contents.
 *
 * \~spanish
 * No hay ningun "todavia no ha llegado" que sea ademas un rechazo.  Un bloque
 * de cabeceras llega entero -- la capa de tramas de arriba no entrega uno hasta
 * su ultima CONTINUATION -- asi que quedarse sin bytes en mitad de uno no es
 * una lectura corta, es un bloque que miente sobre su propio contenido.
 *
 * \~
 */
enum class Status : uint8_t {
    /// \~english It read.  \~spanish Se leyo.  \~
    Ok,
    /// \~english The bytes ran out inside it.  \~spanish Se acabaron los bytes dentro.  \~
    Truncated,
    /// \~english It is not one.  \~spanish No lo es.  \~
    Malformed,
    /**
     * \~english
     * It is one, and it is larger than anything this could be about.  Told
     * apart from @c Malformed because it is the shape of an attack rather than
     * of a mistake: a number nobody needs, sent to see what overflows.
     * \~spanish
     * Lo es, y es mayor que cualquier cosa de la que pudiera hablar.  Se
     * distingue de @c Malformed porque tiene forma de ataque y no de
     * equivocacion: un numero que nadie necesita, mandado a ver que desborda.
     * \~
     */
    TooLarge,
};

/**
 * @brief
 * \~english What reading a number found.
 * \~spanish Que se encontro al leer un numero.
 * \~
 */
struct IntResult {
    Status status;
    uint64_t value;
    /// \~english How many bytes it took.  \~spanish Cuantos bytes ocupo.  \~
    size_t used;
};

/**
 * @brief
 * \~english The largest number this accepts.
 * \~spanish El numero mas grande que esto acepta.
 * \~
 *
 * \~english
 * Every integer in a header block is one of three things: an index into a
 * table, the length of a string, or the size of a table.  All three are
 * bounded by limits this server announced, and all three fit in
 * thirty-two bits with room to spare.  A number larger than that is not a
 * header block this could be about -- so it is refused where it is read,
 * rather than carried around to be refused by whatever eventually tries to
 * allocate it.
 *
 * \~spanish
 * Todos los enteros de un bloque de cabeceras son una de tres cosas: un indice
 * de una tabla, la longitud de una cadena, o el tamano de una tabla.  Las tres
 * las acotan limites que anuncio este servidor, y las tres caben en treinta y
 * dos bits con holgura.  Un numero mayor no es un bloque de cabeceras del que
 * esto pueda hablar -- asi que se rechaza donde se lee, en vez de llevarlo de
 * paseo para que lo rechace lo que acabe intentando reservarlo.
 *
 * \~
 */
constexpr uint64_t kMaxInt = 0xFFFFFFFFull;

/**
 * @brief
 * \~english How many bytes may follow the first one of a number.
 * \~spanish Cuantos bytes pueden seguir al primero de un numero.
 * \~
 *
 * \~english
 * Five, because seven bits each is thirty-five and the value stops at
 * thirty-two.  And it is a SECOND limit, next to the one on the value, because
 * they catch different things: a sender can write `0x80 0x80 0x80 ...` for as
 * long as it likes and every one of those bytes adds NOTHING to the value, so
 * the value never grows and the limit on it never fires.  What grows is the
 * time spent reading them.
 *
 * It is the same shape as the flood of empty CONTINUATION frames, one layer
 * down: a limit on how much something is worth does not limit how much of it
 * there is.
 *
 * \~spanish
 * Cinco, porque siete bits cada uno son treinta y cinco y el valor se para en
 * treinta y dos.  Y es un SEGUNDO limite, al lado del del valor, porque pillan
 * cosas distintas: quien envia puede escribir `0x80 0x80 0x80 ...` todo lo que
 * quiera y cada uno de esos bytes no anade NADA al valor, asi que el valor no
 * crece y su limite no salta nunca.  Lo que crece es el tiempo de leerlos.
 *
 * Es la misma forma que la riada de CONTINUATION vacias, una capa mas abajo: un
 * limite sobre cuanto vale algo no limita cuanto hay de ello.
 *
 * \~
 */
constexpr size_t kMaxIntBytes = 5;

/**
 * @brief
 * \~english Reads a number written with @p prefix_bits in its first byte.
 * \~spanish Lee un numero escrito con @p prefix_bits en su primer byte.
 * \~
 *
 * \~english
 * HPACK writes a number in whatever room is left over in a byte whose top bits
 * already mean something else.  If it fits in that room it is there; if it
 * does not, the room is filled with ones and the rest follows, seven bits per
 * byte, with the top bit set on every byte but the last.
 *
 * The prefix bits are NOT masked off for the caller: what they meant is the
 * caller's business and this only reads the number under them.
 *
 * \~spanish
 * HPACK escribe un numero en el sitio que sobre de un byte cuyos bits de arriba
 * ya significan otra cosa.  Si cabe en ese sitio esta ahi; si no cabe, el sitio
 * se llena de unos y el resto va detras, siete bits por byte, con el bit de
 * arriba puesto en todos menos en el ultimo.
 *
 * Los bits del prefijo NO se le quitan a quien llama: lo que significaran es
 * cosa suya y esto solo lee el numero que hay debajo.
 *
 * \~
 * @code
 * // 5 bits de prefijo, valor 10: cabe, y va en el propio byte.
 * // 5 bits de prefijo, valor 1337: no cabe -> 0x1F 0x9A 0x0A
 * @endcode
 *
 * @param p           \~english the bytes  \~spanish los bytes  \~
 * @param n           \~english how many are there  \~spanish cuantos hay  \~
 * @param prefix_bits \~english how many bits of the first byte are the number,
 *                    from one to eight
 *                    \~spanish cuantos bits del primer byte son el numero, de
 *                    uno a ocho  \~
 * @return            \~english what was found  \~spanish lo que se encontro  \~
 */
IntResult decode_int(const uint8_t *p, size_t n, uint8_t prefix_bits) noexcept;

/**
 * @brief
 * \~english Writes @p value with @p prefix_bits, keeping @p keep above them.
 * \~spanish Escribe @p value con @p prefix_bits, conservando @p keep encima.
 * \~
 *
 * \~english
 * The bits above the prefix say what the number is for, and they are given
 * here rather than written by the caller afterwards: a caller that wrote them
 * afterwards would have to know that the first byte is the one to write them
 * into, which is true and is exactly the kind of thing that stops being true.
 *
 * \~spanish
 * Los bits de encima del prefijo dicen para que es el numero, y se dan aqui en
 * vez de escribirlos despues quien llama: quien los escribiera despues tendria
 * que saber que el byte donde van es el primero, que es cierto y es justo de
 * las cosas que dejan de serlo.
 *
 * \~
 * @param out         \~english where to write; at least @c kMaxIntBytes + 1
 *                    \~spanish donde escribir; al menos @c kMaxIntBytes + 1  \~
 * @param value       \~english the number  \~spanish el numero  \~
 * @param prefix_bits \~english how many bits of the first byte it may use
 *                    \~spanish cuantos bits del primer byte puede usar  \~
 * @param keep        \~english the bits above the prefix, already in place
 *                    \~spanish los bits de encima del prefijo, ya en su sitio  \~
 * @return            \~english how many bytes were written
 *                    \~spanish cuantos bytes se escribieron  \~
 */
size_t encode_int(uint8_t *out, uint64_t value, uint8_t prefix_bits,
                  uint8_t keep) noexcept;

/**
 * @brief
 * \~english Which piece of a request a field is, when it is not a field.
 * \~spanish Que pieza de una peticion es una cabecera, cuando no es una cabecera.
 * \~
 *
 * \~english
 * HTTP/2 carries the method, the target, the host and the scheme as field
 * names beginning with a colon -- which is why they are not in @c FieldId: a
 * colon is not a token character, so they are not field names in the sense the
 * rest of this project uses.  What they are is the four pieces @c Request
 * already holds separately, for exactly this reason.
 *
 * So this is the other half of the join.  A pseudo-header does not become a
 * field; it becomes the part of the request it always was, and the handler
 * reads the same five things it reads from an HTTP/1.1 request line.
 *
 * \~spanish
 * HTTP/2 lleva el metodo, el destino, el anfitrion y el esquema como nombres de
 * cabecera que empiezan por dos puntos -- que es la razon de que no esten en
 * @c FieldId: los dos puntos no son un caracter de token, asi que no son
 * nombres de cabecera en el sentido que usa el resto del proyecto.  Lo que son
 * es las cuatro piezas que @c Request ya guarda aparte, justo por esto.
 *
 * Asi que esta es la otra mitad de la union.  Una pseudo-cabecera no se
 * convierte en una cabecera; se convierte en la parte de la peticion que
 * siempre fue, y el manejador lee las mismas cinco cosas que lee de una linea
 * de peticion de HTTP/1.1.
 *
 * \~
 */
enum class Pseudo : uint8_t {
    /// \~english An ordinary field.  \~spanish Una cabecera corriente.  \~
    None = 0,
    /// \~english `:authority`, which is what `Host` was.
    /// \~spanish `:authority`, que es lo que era `Host`.  \~
    Authority,
    /// \~english `:method`.  \~spanish `:method`.  \~
    Method,
    /// \~english `:path`, which is the request target.
    /// \~spanish `:path`, que es el destino de la peticion.  \~
    Path,
    /// \~english `:scheme`, which HTTP/1.1 never wrote down.
    /// \~spanish `:scheme`, que HTTP/1.1 no escribia nunca.  \~
    Scheme,
    /// \~english `:status`, which only a response carries.
    /// \~spanish `:status`, que solo lleva una respuesta.  \~
    Status,
};

/**
 * @brief
 * \~english One row of the table both ends are born knowing.
 * \~spanish Una fila de la tabla que los dos extremos conocen de nacimiento.
 * \~
 */
struct StaticEntry {
    const char *name;
    const char *value;
    uint16_t name_len;
    uint16_t value_len;
    /// \~english What it is, when it is an ordinary field.
    /// \~spanish Que es, cuando es una cabecera corriente.  \~
    FieldId id;
    /// \~english What it is, when it is not.  \~spanish Que es, cuando no lo es.  \~
    Pseudo pseudo;
};

/**
 * @brief
 * \~english How many entries the static table has.
 * \~spanish Cuantas entradas tiene la tabla estatica.
 * \~
 *
 * \~english
 * Sixty-one, fixed by the specification and never any other number.  It is not
 * a limit and it cannot be configured: both ends count from it, so a server
 * that thought it was sixty-two would resolve every dynamic index one place
 * out.
 *
 * \~spanish
 * Sesenta y una, fijadas por la especificacion y nunca ningun otro numero.  No
 * es un limite y no se puede configurar: los dos extremos cuentan a partir de
 * ella, asi que un servidor que creyera que son sesenta y dos resolveria todos
 * los indices dinamicos con un sitio de diferencia.
 *
 * \~
 */
constexpr size_t kStaticEntries = 61;

/**
 * @brief
 * \~english The entry at @p index, or null if there is none.
 * \~spanish La entrada de @p index, o nulo si no hay.
 * \~
 *
 * \~english
 * **Indices start at one.**  Zero is not the first entry, it is not an entry
 * at all, and a block that uses it as one is refused rather than read as the
 * first -- which is what an implementation that indexed an array from zero
 * would do, and it would resolve every index in the block one place out.
 *
 * \~spanish
 * **Los indices empiezan en uno.**  El cero no es la primera entrada, no es
 * ninguna entrada, y un bloque que lo use como una se rechaza en vez de leerlo
 * como la primera -- que es lo que haria una implementacion que indexara un
 * array desde cero, y resolveria todos los indices del bloque con un sitio de
 * diferencia.
 *
 * \~
 * @param index \~english the index, from one to @c kStaticEntries
 *              \~spanish el indice, de uno a @c kStaticEntries  \~
 * @return      \~english the entry, or null  \~spanish la entrada, o nulo  \~
 */
const StaticEntry *static_entry(uint64_t index) noexcept;

} // namespace hpack
} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_HPACK_H
