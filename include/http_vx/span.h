/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/span.h
 * @brief
 * \~english A piece of a buffer, named by where it is rather than by address.
 * \~spanish Un trozo de un buffer, nombrado por donde esta y no por direccion.
 * \~
 *
 * \~english
 * The type is two numbers, and it exists so that the reason for them being
 * numbers is written down once instead of in every structure that holds a
 * piece of a message.
 *
 * A buffer moves while a message is still arriving -- it grows to make room,
 * and it slides its leftovers to the front -- and both of those move the
 * bytes.  A pair of pointers taken before one of those keeps pointing at
 * memory that is no longer the message: it reads, it has plausible content,
 * and the content is wrong.  An offset does not, because the thing offsets are
 * measured from moves with them.
 *
 * It carries no pointer to the buffer either, which is the second half of the
 * same decision.  Storing one would be storing the thing that expires, and
 * a span is repeated enough times per message that eight bytes against
 * twenty-four is worth counting.
 *
 * \~spanish
 * El tipo son dos numeros, y existe para que la razon de que sean numeros este
 * escrita una vez y no en cada estructura que guarde un trozo de un mensaje.
 *
 * Un buffer se mueve mientras el mensaje todavia esta llegando -- crece para
 * hacer sitio, y desliza lo que sobra hacia delante -- y las dos cosas mueven
 * los bytes.  Un par de punteros tomados antes de una de ellas sigue apuntando
 * a memoria que ya no es el mensaje: se lee, tiene contenido plausible, y el
 * contenido es el equivocado.  Un desplazamiento no, porque aquello desde lo
 * que se miden los desplazamientos se mueve con ellos.
 *
 * Tampoco lleva un puntero al buffer, que es la segunda mitad de la misma
 * decision.  Guardarlo seria guardar justo lo que caduca, y un trozo se repite
 * bastantes veces por mensaje como para que ocho bytes contra veinticuatro
 * merezcan contarse.
 *
 * \~
 */
#ifndef HTTP_VX_SPAN_H
#define HTTP_VX_SPAN_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Where something is inside a message, and how long it is.
 * \~spanish Donde esta algo dentro de un mensaje, y cuanto mide.
 * \~
 *
 * \~english
 * Thirty-two bits each, which is not a shortcut.  A single message is held to
 * far less than four gigabytes long before this would matter -- see
 * @c kBufferMaxCapacity -- so the wider type would buy a range that no message
 * can reach at the cost of doubling something that a message repeats.
 *
 * \~spanish
 * Treinta y dos bits cada uno, que no es un atajo.  Un mensaje suelto se
 * mantiene muy por debajo de los cuatro gigabytes mucho antes de que esto
 * importara -- ver @c kBufferMaxCapacity --, asi que el tipo mas ancho
 * compraria un rango al que ningun mensaje llega a cambio de doblar algo que
 * un mensaje repite.
 *
 * \~
 */
struct Span {
    /// \~english Where it starts, from the message's first byte.
    /// \~spanish Donde empieza, desde el primer byte del mensaje.  \~
    uint32_t off;
    /// \~english How many bytes it has.  \~spanish Cuantos bytes tiene.  \~
    uint32_t len;

    /// \~english Whether there is nothing there.  \~spanish Si no hay nada ahi.  \~
    bool empty() const noexcept { return len == 0; }

    /**
     * @brief
     * \~english The bytes, resolved against @p base.
     * \~spanish Los bytes, resueltos contra @p base.
     * \~
     *
     * \~english
     * The base is passed in at the moment of reading and never kept, which is
     * what makes the span survive whatever happened to the buffer in between.
     *
     * \~spanish
     * La base se pasa en el momento de leer y no se guarda nunca, que es lo que
     * hace que el trozo sobreviva a lo que le pasara al buffer entretanto.
     *
     * \~
     * @param base \~english the message's first byte, which is
     *             @c Buffer::data()
     *             \~spanish el primer byte del mensaje, que es
     *             @c Buffer::data()  \~
     * @return     \~english where the bytes are now
     *             \~spanish donde estan los bytes ahora  \~
     */
    const uint8_t *at(const uint8_t *base) const noexcept { return base + off; }
};

static_assert(sizeof(Span) == 8,
              "a span must stay at eight bytes: a message holds several and "
              "its fields hold one each");

} // namespace http_vx

#endif // HTTP_VX_SPAN_H
