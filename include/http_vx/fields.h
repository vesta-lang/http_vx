/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/fields.h
 * @brief
 * \~english The header fields of a message, as offsets into its buffer.
 * \~spanish Las cabeceras de un mensaje, como desplazamientos en su buffer.
 * \~
 *
 * \~english
 * Two decisions shape this file, and the second is the one that matters.
 *
 * A field is stored as **offsets, not pointers**.  The obvious gain is size --
 * sixteen bytes against the forty that two views would take -- but the real
 * reason is that headers arrive across several reads, and a buffer that grows
 * to hold them moves.  Pointers taken before the move keep pointing at memory
 * that is no longer the message, and nothing says so: the field is read, it
 * has plausible content, and it is the wrong content.  An offset survives.
 *
 * And **which known fields are present is a bit mask**, so asking whether a
 * message carries a content length is a bit test and not a walk.  It is worth
 * it because that question is asked of every message, several times, by
 * layers that do not care about the rest of the headers.
 *
 * \~spanish
 * Dos decisiones dan forma a este fichero, y la segunda es la que importa.
 *
 * Una cabecera se guarda como **desplazamientos, no punteros**.  La ganancia
 * evidente es el tamano -- dieciseis bytes contra los cuarenta que ocuparian
 * dos vistas --, pero la razon de fondo es que las cabeceras llegan en varias
 * lecturas, y un buffer que crece para recogerlas se mueve.  Los punteros
 * tomados antes del movimiento siguen apuntando a memoria que ya no es el
 * mensaje, y nada lo dice: la cabecera se lee, tiene contenido plausible, y es
 * el contenido equivocado.  Un desplazamiento sobrevive.
 *
 * Y **que cabeceras conocidas hay es una mascara de bits**, asi que preguntar
 * si un mensaje trae longitud de cuerpo es probar un bit y no recorrer nada.
 * Compensa porque esa pregunta se le hace a cada mensaje, varias veces, desde
 * capas a las que el resto de cabeceras no les importa.
 *
 * \~
 */
#ifndef HTTP_VX_FIELDS_H
#define HTTP_VX_FIELDS_H

#include "http_vx/field.h"

#include "util/alloc/small_vector.h"

namespace http_vx {

/**
 * @brief
 * \~english One header field, located inside the message buffer.
 * \~spanish Una cabecera, situada dentro del buffer del mensaje.
 * \~
 *
 * \~english
 * When @c id is not @c FieldId::Unknown the name is still recorded: it is what
 * the peer actually wrote, and a proxy that forwards the message must write
 * back what it received, not the canonical spelling.
 *
 * \~spanish
 * Cuando @c id no es @c FieldId::Unknown el nombre se guarda igual: es lo que
 * el otro extremo escribio de verdad, y un intermediario que reenvie el
 * mensaje tiene que escribir lo que recibio, no la grafia canonica.
 *
 * \~
 */
struct Field {
    /// \~english where the name starts  \~spanish donde empieza el nombre  \~
    uint32_t name_off;
    /// \~english where the value starts  \~spanish donde empieza el valor  \~
    uint32_t value_off;
    /// \~english how many bytes the name has  \~spanish cuantos bytes tiene el nombre  \~
    uint16_t name_len;
    /// \~english how many bytes the value has  \~spanish cuantos bytes tiene el valor  \~
    uint16_t value_len;
    /// \~english the identifier, or @c Unknown  \~spanish el identificador, o @c Unknown  \~
    FieldId id;
    /// \~english keeps the size at sixteen  \~spanish mantiene el tamano en dieciseis  \~
    uint16_t reserved;
};

static_assert(sizeof(Field) == 16,
              "a field must stay at sixteen bytes: it is the unit that a "
              "message repeats, and its size is what a request full of "
              "headers costs");

/**
 * @brief
 * \~english How many fields fit without leaving the object.
 * \~spanish Cuantas cabeceras caben sin salir del objeto.
 * \~
 *
 * \~english
 * Sixteen covers the ordinary request with room to spare, so the common case
 * allocates nothing at all.  What goes past that is rare and goes to the
 * allocator, which is the right trade: paying for the rare case in every
 * message would be paying it a million times.
 *
 * \~spanish
 * Dieciseis cubre la peticion corriente con holgura, asi que el caso comun no
 * reserva nada.  Lo que pase de ahi es raro y va al asignador, que es el
 * cambio correcto: pagar el caso raro en cada mensaje seria pagarlo un millon
 * de veces.
 *
 * \~
 */
constexpr size_t kInlineFields = 16;

/**
 * @brief
 * \~english The fields of one message.
 * \~spanish Las cabeceras de un mensaje.
 * \~
 */
class Fields {
  public:
    /**
     * @brief
     * \~english Records a field.
     * \~spanish Anota una cabecera.
     * \~
     *
     * \~english
     * The caller has already resolved the identifier, because it is the codec
     * that knows how the name arrived: HTTP/1.1 reads text and looks it up,
     * while HTTP/2 and HTTP/3 often receive an index and never see text.
     * Resolving it here would force the two of them to produce text they do
     * not have.
     *
     * \~spanish
     * Quien llama ya resolvio el identificador, porque es el codec el que sabe
     * como llego el nombre: HTTP/1.1 lee texto y lo busca, mientras que HTTP/2
     * y HTTP/3 reciben muchas veces un indice y no llegan a ver texto.
     * Resolverlo aqui obligaria a esos dos a producir un texto que no tienen.
     *
     * \~
     * @param f  \~english the field  \~spanish la cabecera  \~
     */
    void add(const Field &f);

    /**
     * @brief
     * \~english Whether a known field is present.  A bit test.
     * \~spanish Si una cabecera conocida esta presente.  Prueba de un bit.
     * \~
     *
     * \~english
     * This is what the mask is for.  Most of the time the answer is no, and
     * answering it without touching the field array keeps a cache line free
     * for something that matters.
     *
     * \~spanish
     * Para esto esta la mascara.  Casi siempre la respuesta es no, y darla sin
     * tocar el array de cabeceras deja una linea de cache libre para algo que
     * importe.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @return   \~english true if it appears at least once
     *           \~spanish true si aparece al menos una vez  \~
     */
    bool has(FieldId id) const noexcept;

    /**
     * @brief
     * \~english The first field with that identifier, or null.
     * \~spanish La primera cabecera con ese identificador, o nulo.
     * \~
     *
     * \~english
     * It checks the mask before walking, so a lookup for something absent
     * costs the bit test and nothing else.
     *
     * \~spanish
     * Mira la mascara antes de recorrer, asi que buscar algo que no esta
     * cuesta la prueba del bit y nada mas.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @return   \~english the field, or null  \~spanish la cabecera, o nulo  \~
     */
    const Field *find(FieldId id) const noexcept;

    /**
     * @brief
     * \~english The next field with the same identifier after @p from.
     * \~spanish La siguiente cabecera con el mismo identificador tras @p from.
     * \~
     *
     * \~english
     * Repetition is not an anomaly: `set-cookie` arrives several times by
     * design, and so may others.  A reader that assumed one would silently
     * drop the rest.
     *
     * \~spanish
     * Que se repita no es una anomalia: `set-cookie` llega varias veces por
     * diseno, y otras pueden hacerlo.  Un lector que supusiera una sola
     * perderia el resto en silencio.
     *
     * \~
     * @param from \~english the field already found  \~spanish la cabecera ya encontrada  \~
     * @return     \~english the next one, or null  \~spanish la siguiente, o nulo  \~
     */
    const Field *find_next(const Field *from) const noexcept;

    /// \~english How many fields there are.  \~spanish Cuantas cabeceras hay.  \~
    size_t size() const noexcept { return v_.size(); }
    /// \~english Whether there is none.  \~spanish Si no hay ninguna.  \~
    bool empty() const noexcept { return v_.empty(); }

    /// \~english The first field.  \~spanish La primera cabecera.  \~
    const Field *begin() const noexcept { return v_.data(); }
    /// \~english One past the last.  \~spanish Una detras de la ultima.  \~
    const Field *end() const noexcept { return v_.data() + v_.size(); }

    /**
     * @brief
     * \~english Empties it to serve another message on the same connection.
     * \~spanish La vacia para servir otro mensaje de la misma conexion.
     * \~
     *
     * \~english
     * It keeps whatever room it already took.  A connection that is reused
     * serves messages of a similar shape, so giving the memory back to ask for
     * it again on the next one would be work with nothing to show.
     *
     * \~spanish
     * Conserva el sitio que ya hubiera tomado.  Una conexion que se reutiliza
     * sirve mensajes parecidos, asi que devolver la memoria para volver a
     * pedirla en el siguiente seria trabajo sin nada que ensenar.
     *
     * \~
     */
    void clear() noexcept;

  private:
    /**
     * \~english
     * Which known identifiers are present, one bit each.  Sixty-four is not an
     * arbitrary ceiling: it is what one register holds, and the moment the
     * table outgrows it the answer is another word, not a walk.  The assert
     * below is there so that day fails loudly.
     *
     * \~spanish
     * Que identificadores conocidos hay, un bit cada uno.  Sesenta y cuatro no
     * es un techo arbitrario: es lo que cabe en un registro, y el dia que la
     * tabla lo pase la respuesta es otra palabra, no un recorrido.  La
     * comprobacion de abajo esta para que ese dia falle en voz alta.
     * \~
     */
    uint64_t known_ = 0;
    util::SmallVector<Field, kInlineFields> v_;
};

static_assert(static_cast<size_t>(FieldId::Count) <= 64,
              "the known-field bitmask holds sixty-four identifiers: adding "
              "more needs a second word, not a linear search");

} // namespace http_vx

#endif // HTTP_VX_FIELDS_H
