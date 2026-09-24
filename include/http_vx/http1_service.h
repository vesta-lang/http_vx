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
     * @param req  \~english the request  \~spanish la peticion  \~
     * @param head \~english the bytes its spans point into
     *             \~spanish los bytes a los que apuntan sus trozos  \~
     * @param body \~english its body, or null  \~spanish su cuerpo, o nulo  \~
     * @param n    \~english how long the body is
     *             \~spanish cuanto mide el cuerpo  \~
     * @param w    \~english where the answer goes  \~spanish donde va la respuesta  \~
     */
    virtual void handle(const Request &req, const uint8_t *head,
                        const uint8_t *body, size_t n,
                        h1::ResponseWriter &w) noexcept = 0;
};

/**
 * @brief
 * \~english Reads HTTP/1.1 off a connection and writes the answers back.
 * \~spanish Lee HTTP/1.1 de una conexion y escribe las respuestas.
 * \~
 */
class Http1Service final : public Service {
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

        Phase phase;
        bool keep_alive;
    };

    /// \~english Answers @p status and ends the connection.
    /// \~spanish Contesta @p status y acaba la conexion.  \~
    bool refuse(StatusCode status, Buffer &out) noexcept;

    /// \~english Puts what the writer made into @p out.
    /// \~spanish Pone lo que hizo el escritor en @p out.  \~
    bool flush(h1::ResponseWriter &w, Buffer &out) noexcept;

    State *state_ = nullptr;
    uint32_t capacity_ = 0;

    Handler *handler_ = nullptr;
    h1::Limits limits_;
    size_t served_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP1_SERVICE_H
