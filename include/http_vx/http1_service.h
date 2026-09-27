/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/http1_service.h
 * @brief
 * \~english HTTP/1.1 behind the loop: bytes in, requests out, answers back.
 * \~spanish HTTP/1.1 detras del bucle: entran bytes, salen peticiones, vuelven respuestas.
 * \~
 *
 * \~english
 * The join.  Everything under `proto/h1/` was written and tested against
 * arrays of bytes with no loop anywhere near it, and everything under
 * `reactor/` was written and tested against a backend with no protocol
 * anywhere near it.  This is the file where the two find out whether the cut
 * between them was in the right place -- and it is short, which is the answer.
 *
 * **What it owns is the state a connection has BETWEEN reads**, and that is
 * the whole reason it exists.  A parser that has seen half a head has to be
 * the same parser when the rest arrives; a body that is half here has to
 * remember how much is left.  The loop knows nothing about either -- it knows
 * about buffers and deadlines -- so the per-connection protocol state lives
 * here, indexed by the same slot the loop uses.
 *
 * \~spanish
 * La union.  Todo lo que hay bajo `proto/h1/` se escribio y se probo contra
 * arrays de bytes sin ningun bucle cerca, y todo lo que hay bajo `reactor/` se
 * escribio y se probo contra un backend sin ningun protocolo cerca.  Este es el
 * fichero donde los dos averiguan si el corte estaba en el sitio correcto -- y
 * es corto, que es la respuesta.
 *
 * **Lo que posee es el estado que tiene una conexion ENTRE lecturas**, y esa es
 * toda la razon de que exista.  Un analizador que ha visto media cabeza tiene
 * que ser el mismo analizador cuando llegue el resto; un cuerpo que esta a
 * medias tiene que acordarse de cuanto falta.  El bucle no sabe nada de ninguna
 * de las dos cosas -- sabe de buffers y de plazos -- asi que el estado de
 * protocolo por conexion vive aqui, indexado por la misma casilla que usa el
 * bucle.
 *
 * \~
 */
#ifndef HTTP_VX_HTTP1_SERVICE_H
#define HTTP_VX_HTTP1_SERVICE_H

#include "http_vx/h1_chunked.h"
#include "http_vx/h1_framing.h"
#include "http_vx/h1_limits.h"
#include "http_vx/h1_parser.h"
#include "http_vx/h1_writer.h"
#include "http_vx/response.h"
#include "http_vx/shard.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What answers a request.
 * \~spanish Lo que contesta una peticion.
 * \~
 *
 * \~english
 * It is given the request and its body and a writer, and it says what the
 * answer is.  It is never given a socket, a buffer pool or a connection
 * handle, because none of those are anything to do with answering a request
 * -- and a handler that could reach them would be a handler that could be
 * written to depend on them.
 *
 * \~spanish
 * Se le da la peticion, su cuerpo y un escritor, y dice cual es la respuesta.
 * No se le da nunca un socket, un pozo de buffers ni una referencia de conexion,
 * porque ninguna de esas cosas tiene nada que ver con contestar una peticion --
 * y un manejador que pudiera llegar a ellas seria un manejador que se podria
 * escribir para depender de ellas.
 *
 * \~
 */
class Handler {
  public:
    virtual ~Handler();

    Handler() noexcept = default;
    Handler(const Handler &) = delete;
    Handler &operator=(const Handler &) = delete;

    /**
     * @brief
     * \~english Answers @p req.
     * \~spanish Contesta a @p req.
     * \~
     *
     * \~english
     * @p body is a VIEW into the connection's read buffer -- R13, the body is
     * not copied -- so it is valid for this call and not after it.  A handler
     * that needs to keep it keeps its own copy, deliberately, rather than
     * being handed one it did not ask for.
     *
     * @p head is where the request's own bytes live: the spans in @p req are
     * offsets into it, not pointers, so this is what turns one into the other.
     *
     * \~spanish
     * @p body es una VISTA del buffer de lectura de la conexion -- R13, el
     * cuerpo no se copia -- asi que vale durante esta llamada y no despues.  Un
     * manejador que necesite guardarlo se guarda su propia copia, a proposito,
     * en vez de que le den una que no pidio.
     *
     * @p head es donde viven los bytes de la propia peticion: los trozos de
     * @p req son desplazamientos sobre el, no punteros, asi que esto es lo que
     * convierte unos en otros.
     *
     * \~
     * **And what it answers into names no version.**  A handler says a status,
     * some fields and a body; whether that becomes a line of text with CRLFs
     * or a header block and DATA frames is decided by whoever asked, which is
     * the service, which is the only piece that knows.
     *
     * The first version of this interface handed over an `h1::ResponseWriter`
     * and got that wrong: a handler written against it could not answer an
     * HTTP/2 request without being rewritten, which would have made the
     * project's central claim false at the one seam where it is visible.
     *
     * \~spanish
     * **Y aquello en lo que contesta no nombra ninguna version.**  Un manejador
     * dice un estado, unas cabeceras y un cuerpo; si eso se convierte en una
     * linea de texto con CRLFs o en un bloque de cabeceras y tramas DATA lo
     * decide quien se lo pidio, que es el servicio, que es la unica pieza que lo
     * sabe.
     *
     * La primera version de esta interfaz entregaba un `h1::ResponseWriter` y se
     * equivocaba en eso: un manejador escrito contra ella no podria contestar
     * una peticion de HTTP/2 sin reescribirlo, lo que habria hecho falsa la
     * afirmacion central del proyecto justo en la costura donde se ve.
     *
     * \~
     * @param req  \~english the request  \~spanish la peticion  \~
     * @param head \~english the bytes its spans point into
     *             \~spanish los bytes a los que apuntan sus trozos  \~
     * @param body \~english its body, or null  \~spanish su cuerpo, o nulo  \~
     * @param n    \~english how long the body is
     *             \~spanish cuanto mide el cuerpo  \~
     * @param res  \~english where the answer goes  \~spanish donde va la respuesta  \~
     */
    virtual void handle(const Request &req, const uint8_t *head,
                        const uint8_t *body, size_t n,
                        ResponseBuilder &res) noexcept = 0;
};

/**
 * @brief
 * \~english Reads HTTP/1.1 off a connection and writes the answers back.
 * \~spanish Lee HTTP/1.1 de una conexion y escribe las respuestas.
 * \~
 */
class Http1Service final : public Service, public KickTarget {
  public:
    Http1Service() noexcept = default;
    ~Http1Service() override;

    /**
     * @brief
     * \~english Makes room for @p connections, answering with @p handler.
     * \~spanish Hace sitio para @p connections, contestando con @p handler.
     * \~
     *
     * \~english
     * One parser per connection, made up front and never grown, for the same
     * reason the connection table is: an index into it is a slot, and a table
     * that moved would break every one of them.
     *
     * It is per CONNECTION and not per active request, which is worth being
     * honest about: a parser between messages is holding nothing, and at a
     * million connections this is the second biggest thing the server keeps.
     * Pooling it the way buffers are pooled would be the same trick again and
     * is the obvious next thing to do to this file -- what stops it being done
     * now is that nothing has measured it.
     *
     * \~spanish
     * Un analizador por conexion, hecho por delante y sin crecer nunca, por lo
     * mismo que la tabla de conexiones: un indice suyo es una casilla, y una
     * tabla que se moviera romperia todos ellos.
     *
     * Es por CONEXION y no por peticion activa, y merece decirse: un analizador
     * entre mensajes no guarda nada, y al millon de conexiones esto es la
     * segunda cosa mas grande que tiene el servidor.  Ponerlo en un pozo como
     * los buffers seria el mismo truco otra vez y es lo siguiente evidente que
     * hacerle a este fichero -- lo que impide hacerlo ahora es que nadie lo ha
     * medido.
     *
     * \~
     * @param connections \~english how many at once
     *                    \~spanish cuantas a la vez  \~
     * @param handler     \~english what answers  \~spanish lo que contesta  \~
     * @param limits      \~english what this server accepts
     *                    \~spanish lo que acepta este servidor  \~
     * @return            \~english false if the memory could not be had
     *                    \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t connections, Handler &handler,
               const h1::Limits &limits) noexcept;

    bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override;
    void on_open(ConnHandle c) noexcept override;
    void on_close(ConnHandle c) noexcept override;
    void attach(StreamPort *port) noexcept override { port_ = port; }
    bool on_writable(ConnHandle c, Buffer &out) noexcept override;
    void on_kick(BodySource &source) noexcept override;

    /**
     * \~english
     * The most body one fill is offered.  What bounds it is the buffer an
     * open response writes into, not the source: a source that has more waits
     * for the next room (HVX-5, 4.3).
     * \~spanish
     * Lo mas de cuerpo que se ofrece en un relleno.  Lo que lo acota es el
     * buffer en el que escribe una respuesta abierta, no la fuente: una fuente
     * que tenga mas espera al sitio siguiente (HVX-5, 4.3).
     * \~
     */
    static constexpr size_t kFillRoom = 16384;

    /// \~english How many whole requests have been answered.
    /// \~spanish Cuantas peticiones enteras se han contestado.  \~
    size_t served() const noexcept { return served_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /**
     * \~english
     * Where a connection is in the one message it is reading.
     * \~spanish
     * En que punto del unico mensaje que esta leyendo va una conexion.
     * \~
     */
    enum class Phase : uint8_t {
        /// \~english Reading the head.  \~spanish Leyendo la cabeza.  \~
        Head,
        /// \~english Reading a body whose length was announced.
        /// \~spanish Leyendo un cuerpo cuya longitud se anuncio.  \~
        Body,
        /// \~english Reading a body that announces itself in pieces.
        /// \~spanish Leyendo un cuerpo que se anuncia a trozos.  \~
        Chunks,
    };

    struct State {
        h1::RequestParser parser;
        h1::ChunkedReader chunks;
        Request req;
        uint64_t left;
        size_t head_size;

        /**
         * \~english
         * How much of a chunked body has been un-framed so far.
         *
         * A chunked body's bytes are not next to each other: each piece is
         * announced by a size line and followed by a break, so what the
         * message MEANS is interleaved with how it is written.  The pieces are
         * moved down over the framing as they are read, so that by the time
         * the body is whole it is contiguous where a body belongs -- right
         * after the head.
         *
         * That move is a copy, and it is the one copy in this path.  It cannot
         * be avoided: the bytes to be handed over are not adjacent until
         * something makes them so, and the cheapest somewhere to make them
         * adjacent is where they already are.
         *
         * \~spanish
         * Cuanto se lleva desentramado de un cuerpo por trozos.
         *
         * Los bytes de un cuerpo por trozos no estan seguidos: cada pedazo lo
         * anuncia una linea de tamano y lo sigue un salto, asi que lo que el
         * mensaje SIGNIFICA va intercalado con como esta escrito.  Los pedazos
         * se mueven hacia abajo sobre el troceado segun se leen, para que cuando
         * el cuerpo este entero este seguido donde le toca a un cuerpo: justo
         * detras de la cabeza.
         *
         * Ese movimiento es una copia, y es la unica copia de este camino.  No
         * se puede evitar: los bytes que hay que entregar no son contiguos hasta
         * que algo los hace contiguos, y el sitio mas barato para hacerlos
         * contiguos es donde ya estan.
         * \~
         */
        size_t decoded;

        /**
         * \~english
         * The source of the response open on this connection, or null.  While
         * there is one, the requests behind it wait (HVX-5, 7.1).
         * \~spanish
         * La fuente de la respuesta abierta en esta conexion, o nulo.  Mientras
         * haya una, las peticiones de detras esperan (HVX-5, 7.1).
         * \~
         */
        BodySource *open;

        Phase phase;
        bool keep_alive;

        /// \~english The open response goes in chunks; false is HTTP/1.0, ended by closing.
        /// \~spanish La respuesta abierta va por trozos; false es HTTP/1.0, que acaba cerrando.  \~
        bool chunked;

        /// \~english Kicked since its last fill.  \~spanish Avisada desde su ultimo relleno.  \~
        bool kicked;

        /// \~english Its last fill took all the room: asked again when there is more (HVX-5, 4.3).
        /// \~spanish Su ultimo relleno uso todo el sitio: se le vuelve a pedir cuando haya mas (HVX-5, 4.3).  \~
        bool hungry;
    };

    /**
     * @brief
     * \~english Writes the head of an opened response and its first fill into @p out.
     * \~spanish Escribe la cabecera de una respuesta abierta y su primer relleno en @p out.
     * \~
     *
     * @return \~english false to end the connection  \~spanish false para acabar la conexion  \~
     */
    bool start_open(ConnHandle c, State &s, const ResponseBuilder &res, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Asks the open source for one piece and frames it into @p out.
     * \~spanish Le pide un trozo a la fuente abierta y lo enmarca en @p out.
     * \~
     *
     * @return \~english false to end the connection  \~spanish false para acabar la conexion  \~
     */
    bool fill_open(ConnHandle c, State &s, Buffer &out) noexcept;

    /// \~english Ends the open response of @p s with @p why.  \~spanish Acaba la respuesta abierta de @p s con @p why.  \~
    void end_open(State &s, GoneReason why) noexcept;

    /// \~english Answers 503 and carries on: a limit on open responses was reached.
    /// \~spanish Contesta 503 y sigue: se agoto un tope de respuestas abiertas.  \~
    bool unavailable(const Request &req, bool keep_alive, Buffer &out) noexcept;

    /// \~english Answers @p status and ends the connection.
    /// \~spanish Contesta @p status y acaba la conexion.  \~
    bool refuse(StatusCode status, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Writes @p res as HTTP/1.1 into @p out.
     * \~spanish Escribe @p res como HTTP/1.1 en @p out.
     * \~
     *
     * \~english
     * Where the version comes back in, and the only place it does.  What the
     * handler said is a status, some fields and a body; what goes out is a
     * status line, names with colons, CRLFs and a length -- and an HTTP/2
     * service given the same response would write the same meaning as a header
     * block and DATA frames without the handler knowing either way.
     *
     * \~spanish
     * Donde vuelve a aparecer la version, y el unico sitio donde aparece.  Lo
     * que dijo el manejador es un estado, unas cabeceras y un cuerpo; lo que
     * sale es una linea de estado, nombres con dos puntos, CRLFs y una longitud
     * -- y un servicio de HTTP/2 al que le dieran la misma respuesta escribiria
     * el mismo significado como un bloque de cabeceras y tramas DATA sin que el
     * manejador se enterara de ninguna de las dos cosas.
     *
     * \~
     * @param res        \~english what the handler said
     *                   \~spanish lo que dijo el manejador  \~
     * @param req        \~english the request it answers
     *                   \~spanish la peticion que contesta  \~
     * @param keep_alive \~english whether the connection carries on
     *                   \~spanish si la conexion sigue  \~
     * @param out        \~english where the bytes go
     *                   \~spanish donde van los bytes  \~
     * @return           \~english false if it could not be written
     *                   \~spanish false si no se pudo escribir  \~
     */
    bool render(const ResponseBuilder &res, const Request &req,
                bool keep_alive, Buffer &out) noexcept;

    /// \~english Writes the handler's fields; the one loop for a whole response and an open one.
    /// \~spanish Escribe las cabeceras del manejador; el unico bucle para una respuesta entera y una abierta.  \~
    void put_fields(h1::ResponseWriter &w, const ResponseBuilder &res) noexcept;

    /// \~english Puts what the writer made into @p out.
    /// \~spanish Pone lo que hizo el escritor en @p out.  \~
    bool flush(h1::ResponseWriter &w, Buffer &out) noexcept;

    /**
     * \~english
     * Where a handler's answer is collected before it is written.  One per
     * service and reused, because a shard is one thread and a response is
     * finished with before the next one starts.
     * \~spanish
     * Donde se recoge la respuesta de un manejador antes de escribirla.  Uno por
     * servicio y reutilizado, porque un fragmento es un hilo y con una respuesta
     * se acaba antes de que empiece la siguiente.
     * \~
     */
    Buffer said_;

    /**
     * \~english
     * The writer, kept.  It was made and thrown away on every request, and a
     * writer owns a buffer -- so answering cost an allocation and a free of
     * four kilobytes per response, on the one path every request takes.
     *
     * Nothing was wrong with the code that did it: @c begin already empties the
     * writer and resets its state, so a fresh one and a reused one produce the
     * same bytes.  What made the difference invisible is that a buffer
     * allocates lazily and frees quietly, and neither shows up as anything but
     * time.
     *
     * One per service and reused, for the same reason @c said_ is: a shard is
     * one thread, and a response is finished with before the next one starts.
     *
     * \~spanish
     * El escritor, guardado.  Se hacia y se tiraba en cada peticion, y un
     * escritor es dueno de un buffer -- asi que contestar costaba una reserva y
     * una liberacion de cuatro kilobytes por respuesta, en el unico camino por el
     * que pasan todas las peticiones.
     *
     * El codigo que lo hacia no tenia nada malo: @c begin ya vacia el escritor y
     * reinicia su estado, asi que uno nuevo y uno reutilizado producen los mismos
     * bytes.  Lo que hacia invisible la diferencia es que un buffer reserva tarde
     * y libera callado, y ninguna de las dos cosas se ve como otra cosa que
     * tiempo.
     *
     * Uno por servicio y reutilizado, por lo mismo que @c said_: un fragmento es
     * un hilo, y con una respuesta se acaba antes de que empiece la siguiente.
     * \~
     */
    h1::ResponseWriter writer_;

    State *state_ = nullptr;
    uint32_t capacity_ = 0;

    Handler *handler_ = nullptr;
    h1::Limits limits_;
    size_t served_ = 0;

    /// \~english The shard's side of open responses, or null: then nothing opens.
    /// \~spanish El lado del fragmento de las respuestas abiertas, o nulo: entonces no se abre nada.  \~
    StreamPort *port_ = nullptr;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP1_SERVICE_H
