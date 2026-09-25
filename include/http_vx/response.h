/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/response.h
 * @brief
 * \~english An answer, said once, in no version of the protocol.
 * \~spanish Una respuesta, dicha una vez, en ninguna version del protocolo.
 * \~
 *
 * \~english
 * The whole project rests on one claim: what a message MEANS is the same in
 * all three versions, and only how it is written differs.  `proto/semantics/`
 * is that claim for what comes IN -- a @c Request built from a line of text
 * and one built from HPACK are the same structure -- and this is the same
 * claim for what goes OUT.
 *
 * **It exists because the first version of the handler interface broke it.**
 * A handler was handed an `h1::ResponseWriter`, which named a version in its
 * type: a handler written against it could not answer an HTTP/2 request
 * without being rewritten, and the claim that the cut was in the right place
 * would have been quietly false at the one seam where anybody would notice.
 *
 * So a handler says a status, some fields and a body, and says them once.  The
 * service that asked for the answer is the one that knows whether that becomes
 * a line of text and CRLFs or a header block and DATA frames.
 *
 * \~spanish
 * Todo el proyecto se apoya en una afirmacion: lo que un mensaje SIGNIFICA es
 * lo mismo en las tres versiones, y solo cambia como se escribe.
 * `proto/semantics/` es esa afirmacion para lo que ENTRA -- un @c Request
 * construido de una linea de texto y uno construido de HPACK son la misma
 * estructura -- y esto es la misma afirmacion para lo que SALE.
 *
 * **Existe porque la primera version de la interfaz de manejador la rompia.**
 * Al manejador se le daba un `h1::ResponseWriter`, que nombra una version en su
 * tipo: un manejador escrito contra eso no podria contestar una peticion de
 * HTTP/2 sin reescribirlo, y la afirmacion de que el corte estaba en el sitio
 * correcto habria sido falsa por lo bajo justo en la costura donde se nota.
 *
 * Asi que un manejador dice un estado, unas cabeceras y un cuerpo, y los dice
 * una vez.  El servicio que le pidio la respuesta es el que sabe si eso se
 * convierte en una linea de texto con CRLFs o en un bloque de cabeceras y
 * tramas DATA.
 *
 * \~
 */
#ifndef HTTP_VX_RESPONSE_H
#define HTTP_VX_RESPONSE_H

#include "http_vx/buffer.h"
#include "http_vx/fields.h"
#include "http_vx/span.h"
#include "http_vx/status.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What a handler says, before anybody decides how to write it.
 * \~spanish Lo que dice un manejador, antes de que nadie decida como escribirlo.
 * \~
 *
 * \~english
 * The bytes go in a buffer somebody else owns and the structure holds spans
 * into it, which is the same arrangement a @c Request has and for the same
 * reason: what is being described is where things are, not copies of them.
 *
 * \~spanish
 * Los bytes van a un buffer de otro y la estructura guarda trozos sobre el, que
 * es la misma disposicion que tiene un @c Request y por lo mismo: lo que se
 * describe es donde estan las cosas, no copias de ellas.
 *
 * \~
 *
 * @note
 * \~english
 * Not to be confused with @c Response in `message.h`, which is a response that
 * was READ: a plain structure a parser fills, the twin of @c Request.  This is
 * the other direction -- a response being made -- and it is a class rather
 * than a structure because making one is appending to a buffer, which has an
 * order and can run out of room.  The same split as @c RequestParser and
 * @c Request, seen from the writing side.
 *
 * \~spanish
 * No confundir con @c Response de `message.h`, que es una respuesta LEIDA: una
 * estructura pelada que rellena un analizador, la gemela de @c Request.  Esto es
 * el otro sentido -- una respuesta que se esta haciendo -- y es una clase y no
 * una estructura porque hacer una es ir anadiendo a un buffer, que tiene un
 * orden y se puede quedar sin sitio.  El mismo reparto que @c RequestParser y
 * @c Request, visto desde el lado de escribir.
 * \~
 */
class ResponseBuilder {
  public:
    /**
     * @brief
     * \~english Makes one that keeps its bytes in @p store.
     * \~spanish Hace una que guarda sus bytes en @p store.
     * \~
     *
     * \~english
     * @p store is emptied, and it is the caller's: a response is a thing a
     * service asks a handler for, and the service already has somewhere to put
     * bytes.  Giving the response its own buffer would be one more allocation
     * per request, which is the thing R10 is about.
     *
     * \~spanish
     * @p store se vacia, y es de quien llama: una respuesta es algo que un
     * servicio le pide a un manejador, y el servicio ya tiene donde poner bytes.
     * Darle a la respuesta un buffer propio seria una reserva mas por peticion,
     * que es de lo que va la R10.
     *
     * \~
     * @param store \~english where the bytes go  \~spanish donde van los bytes  \~
     */
    explicit ResponseBuilder(Buffer &store) noexcept : store_(&store) {
        store.clear();
    }

    ResponseBuilder(const ResponseBuilder &) = delete;
    ResponseBuilder &operator=(const ResponseBuilder &) = delete;

    /// \~english Says what happened.  \~spanish Dice que paso.  \~
    void status(StatusCode s) noexcept { status_ = s; }

    /**
     * @brief
     * \~english Adds a field this project knows the name of.
     * \~spanish Anade una cabecera cuyo nombre conoce este proyecto.
     * \~
     *
     * \~english
     * The NAME is not stored, only which field it is.  Whoever writes it out
     * knows how to spell it -- as lower-case text with a colon, or as an index
     * into a table both ends share -- and a name kept here would be a second
     * spelling that only one of the two would use.
     *
     * \~spanish
     * El NOMBRE no se guarda, solo que cabecera es.  Quien la escriba sabe como
     * se deletrea -- como texto en minusculas con dos puntos, o como un indice
     * de una tabla que comparten los dos extremos -- y un nombre guardado aqui
     * seria una segunda grafia que solo usaria uno de los dos.
     *
     * \~
     * @param id \~english which field  \~spanish que cabecera  \~
     * @param v  \~english its value  \~spanish su valor  \~
     * @param n  \~english how many bytes  \~spanish cuantos bytes  \~
     * @return   \~english false if there was no room
     *           \~spanish false si no habia sitio  \~
     */
    bool field(FieldId id, const char *v, size_t n) noexcept;

    /**
     * @brief
     * \~english Adds a field by name.
     * \~spanish Anade una cabecera por su nombre.
     * \~
     *
     * \~english
     * The name is kept as it is given.  It is NOT lowered here, because
     * lowering is a decision about how a version writes a name: HTTP/2 requires
     * lower case and HTTP/1.1 does not care, so doing it here would be one
     * version's rule applied to a structure that belongs to neither.
     *
     * \~spanish
     * El nombre se guarda tal como se da.  NO se baja a minusculas aqui, porque
     * bajarlo es una decision sobre como escribe un nombre una version: HTTP/2
     * exige minusculas y a HTTP/1.1 le da igual, asi que hacerlo aqui seria la
     * regla de una version aplicada a una estructura que no es de ninguna.
     *
     * \~
     * @param name \~english the name  \~spanish el nombre  \~
     * @param nlen \~english how many bytes  \~spanish cuantos bytes  \~
     * @param v    \~english its value  \~spanish su valor  \~
     * @param vlen \~english how many bytes  \~spanish cuantos bytes  \~
     * @return     \~english false if there was no room
     *             \~spanish false si no habia sitio  \~
     */
    bool field(const char *name, size_t nlen, const char *v,
               size_t vlen) noexcept;

    /**
     * @brief
     * \~english Adds @p n bytes to the body.
     * \~spanish Anade @p n bytes al cuerpo.
     * \~
     *
     * \~english
     * It may be called more than once and the pieces join, which is what lets
     * a handler build an answer in parts without knowing how long it will be.
     * What it may NOT be interleaved with is @c field: the body is one run of
     * bytes at the end, and a field added after a body has started would be a
     * field the writing cannot put anywhere.
     *
     * The bytes are COPIED into the store, and that is the one copy in
     * answering a request.  A body that lives somewhere of its own -- a file,
     * a static asset -- should not go through here: R14 says a response must
     * be writable as head and body from different places, and this is the
     * concatenation it exists to avoid.  That path does not exist yet, and
     * HVX-4 says so.
     *
     * \~spanish
     * Se puede llamar mas de una vez y los pedazos se juntan, que es lo que
     * permite a un manejador construir una respuesta a trozos sin saber cuanto
     * va a medir.  Con lo que NO se puede alternar es con @c field: el cuerpo es
     * una tirada de bytes al final, y una cabecera anadida despues de empezar un
     * cuerpo seria una cabecera que no se puede poner en ningun sitio.
     *
     * Los bytes se COPIAN al almacen, y esa es la unica copia de contestar una
     * peticion.  Un cuerpo que vive en un sitio propio -- un fichero, un recurso
     * estatico -- no deberia pasar por aqui: la R14 dice que una respuesta tiene
     * que poder escribirse con cabeza y cuerpo desde sitios distintos, y esto es
     * la concatenacion que existe para evitar.  Ese camino todavia no existe, y
     * el HVX-4 lo dice.
     *
     * \~
     * @param p \~english the bytes  \~spanish los bytes  \~
     * @param n \~english how many  \~spanish cuantos  \~
     * @return  \~english false if there was no room or a field came after
     *          \~spanish false si no habia sitio o vino una cabecera despues  \~
     */
    bool body(const void *p, size_t n) noexcept;

    /// \~english What happened.  \~spanish Que paso.  \~
    StatusCode status() const noexcept { return status_; }

    /// \~english The fields, in the order they were added.
    /// \~spanish Las cabeceras, en el orden en que se anadieron.  \~
    const Fields &fields() const noexcept { return fields_; }

    /// \~english Where the body is.  \~spanish Donde esta el cuerpo.  \~
    Span body() const noexcept { return body_; }

    /// \~english What every span here points into.
    /// \~spanish A lo que apuntan todos los trozos de aqui.  \~
    const uint8_t *bytes() const noexcept { return store_->data(); }

    /// \~english Whether anything could not be stored.
    /// \~spanish Si algo no se pudo guardar.  \~
    bool failed() const noexcept { return failed_; }

  private:
    bool put(const void *p, size_t n, Span &where) noexcept;

    Buffer *store_;
    Fields fields_;
    Span body_ = {0, 0};
    StatusCode status_ = 200;
    bool started_body_ = false;
    bool failed_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_RESPONSE_H
