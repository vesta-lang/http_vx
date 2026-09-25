/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/http2_service.h
 * @brief
 * \~english HTTP/2 behind the same loop, answering with the same handler.
 * \~spanish HTTP/2 detras del mismo bucle, contestando con el mismo manejador.
 * \~
 *
 * \~english
 * The claim, tested.  Everything under `proto/h2/` was written against arrays
 * of bytes; the loop was written against a backend; and the handler was
 * written against a status, some fields and a body.  This file puts the three
 * together, and the test of whether the cuts were in the right place is that
 * **the handler does not change** -- the same one that answers HTTP/1.1
 * answers this, unrecompiled and unaware.
 *
 * Two things are genuinely different from HTTP/1.1 and neither is a detail:
 *
 *  - **a request is not alone on its connection.**  A body arrives in DATA
 *    frames that may be separated by nine bytes of framing and by whole
 *    requests for other streams, so what one message MEANS is interleaved with
 *    both how it is written and with somebody else's message.  HTTP/1.1 could
 *    keep one parser per connection because there was one message at a time;
 *    here the state that belongs to a message has to belong to the MESSAGE;
 *  - **an answer may not fit.**  A response is bounded by two windows the peer
 *    controls, and one that does not fit WAITS -- it is not truncated and the
 *    request is not refused.  What is left of it goes out when that stream's
 *    window opens, which may be several reads later.
 *
 * \~spanish
 * La afirmacion, probada.  Todo lo que hay bajo `proto/h2/` se escribio contra
 * arrays de bytes; el bucle se escribio contra un backend; y el manejador se
 * escribio contra un estado, unas cabeceras y un cuerpo.  Este fichero junta los
 * tres, y la prueba de si los cortes estaban en el sitio correcto es que **el
 * manejador no cambia** -- el mismo que contesta HTTP/1.1 contesta esto, sin
 * recompilarse y sin enterarse.
 *
 * Dos cosas son de verdad distintas de HTTP/1.1 y ninguna es un detalle:
 *
 *  - **una peticion no esta sola en su conexion.**  Un cuerpo llega en tramas
 *    DATA que pueden ir separadas por nueve bytes de troceado y por peticiones
 *    enteras de otros flujos, asi que lo que un mensaje SIGNIFICA va
 *    intercalado tanto con como esta escrito como con el mensaje de otro.
 *    HTTP/1.1 podia tener un analizador por conexion porque habia un mensaje a
 *    la vez; aqui el estado que es de un mensaje tiene que ser DEL MENSAJE;
 *  - **una respuesta puede no caber.**  Una respuesta la acotan dos ventanas
 *    que controla el otro extremo, y una que no cabe ESPERA -- no se trunca y
 *    la peticion no se rechaza --.  Lo que quede de ella sale cuando se abra la
 *    ventana de ese flujo, que puede ser varias lecturas despues.
 *
 * \~
 */
#ifndef HTTP_VX_HTTP2_SERVICE_H
#define HTTP_VX_HTTP2_SERVICE_H

#include "http_vx/buffer_pool.h"
#include "http_vx/h2_connection.h"
#include "http_vx/h2_writer.h"
#include "http_vx/http1_service.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What names no piece of work.
 * \~spanish Lo que no nombra ningun trabajo.
 * \~
 */
constexpr uint32_t kNoWork = 0xFFFFFFFF;

/**
 * @brief
 * \~english Reads HTTP/2 off a connection and writes the answers back.
 * \~spanish Lee HTTP/2 de una conexion y escribe las respuestas.
 * \~
 */
class Http2Service final : public Service {
  public:
    Http2Service() noexcept = default;
    ~Http2Service() override;

    /**
     * @brief
     * \~english Makes room for @p connections, answering with @p handler.
     * \~spanish Hace sitio para @p connections, contestando con @p handler.
     * \~
     *
     * \~english
     * @p requests is the second number and it is the interesting one.  A
     * connection may carry a hundred and twenty-eight streams at once, so one
     * piece of state per possible stream would be a hundred and twenty-eight
     * times a million -- a number with no upper bound worth writing down.  What
     * actually bounds this server is how many requests are BEING WORKED ON at
     * once, which is a property of the machine and not of the peers, so the
     * per-request state is pooled the way buffers are.
     *
     * Running out is answered with @c RefusedStream, which is the one code that
     * tells a client the request may simply be sent again.  It is backpressure
     * and not a failure: the alternative is a server whose memory is chosen by
     * whoever connects to it.
     *
     * \~spanish
     * @p requests es el segundo numero y es el interesante.  Una conexion puede
     * llevar ciento veintiocho flujos a la vez, asi que un estado por flujo
     * posible serian ciento veintiocho por un millon -- un numero sin ninguna
     * cota que merezca escribirse --.  Lo que acota de verdad a este servidor es
     * cuantas peticiones se estan ATENDIENDO a la vez, que es una propiedad de la
     * maquina y no de los extremos, asi que el estado por peticion va en un pozo
     * como el de los buffers.
     *
     * Quedarse sin se contesta con @c RefusedStream, que es el unico codigo que
     * le dice a un cliente que puede volver a mandar la peticion tal cual.  Es
     * contrapresion y no un fallo: la alternativa es un servidor cuya memoria la
     * elige quien se conecte a el.
     *
     * \~
     * @param connections \~english how many at once
     *                    \~spanish cuantas a la vez  \~
     * @param requests    \~english how many requests may be in hand at once
     *                    \~spanish cuantas peticiones pueden estar en mano a la vez  \~
     * @param max_body    \~english the largest request body this server takes
     *                    \~spanish el cuerpo de peticion mas grande que acepta este servidor  \~
     * @param handler     \~english what answers  \~spanish lo que contesta  \~
     * @param limits      \~english what this server accepts
     *                    \~spanish lo que acepta este servidor  \~
     * @return            \~english false if the memory could not be had
     *                    \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t connections, uint32_t requests, size_t max_body,
               Handler &handler, const h2::Limits &limits) noexcept;

    bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override;
    void on_open(ConnHandle c) noexcept override;
    void on_close(ConnHandle c) noexcept override;

    /// \~english How many whole requests have been answered.
    /// \~spanish Cuantas peticiones enteras se han contestado.  \~
    size_t served() const noexcept { return served_; }

    /// \~english How many requests are in hand right now.
    /// \~spanish Cuantas peticiones hay en mano ahora mismo.  \~
    size_t in_hand() const noexcept { return in_hand_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /**
     * \~english
     * One request that is not finished with, and the two halves of its life.
     *
     * A stream needs somewhere to keep bytes at exactly two moments, and they
     * never overlap: while its body is arriving in pieces, and while its answer
     * is waiting for a window.  The first ends when the handler is called and
     * the second cannot begin before that, so ONE buffer does for both -- which
     * is not a trick to save memory but the observation that a stream is either
     * still being asked or being answered, never both.
     *
     * \~spanish
     * Una peticion sin acabar, y las dos mitades de su vida.
     *
     * Un flujo necesita donde guardar bytes en dos momentos exactos, y no se
     * solapan nunca: mientras su cuerpo llega a pedazos, y mientras su respuesta
     * espera una ventana.  El primero acaba cuando se llama al manejador y el
     * segundo no puede empezar antes, asi que UN buffer sirve para los dos -- lo
     * que no es un truco para ahorrar memoria sino la observacion de que a un
     * flujo o se le sigue preguntando o se le esta contestando, nunca las dos
     * cosas.
     * \~
     */
    struct Work {
        /**
         * \~english
         * The request, with its spans measured into @c buffer.  It is copied
         * out of the connection's own decoding slot the moment it turns out to
         * need a body, because the next header block that arrives -- for
         * another stream, on the same connection -- overwrites that slot.
         * \~spanish
         * La peticion, con sus trozos medidos sobre @c buffer.  Se copia de la
         * ranura de descodificacion de la conexion en cuanto resulta que
         * necesita un cuerpo, porque el bloque de cabeceras siguiente -- de otro
         * flujo, por la misma conexion -- pisa esa ranura.
         * \~
         */
        Request req;

        /// \~english Which pooled buffer holds its bytes.
        /// \~spanish Que buffer del pozo tiene sus bytes.  \~
        uint32_t buffer;

        /// \~english Which stream it is.  \~spanish Que flujo es.  \~
        uint32_t stream;

        /// \~english The next piece of work of the same connection, or the next
        /// free one.  \~spanish El trabajo siguiente de la misma conexion, o el
        /// libre siguiente.  \~
        uint32_t next;

        /// \~english Where the body starts in @c buffer.
        /// \~spanish Donde empieza el cuerpo en @c buffer.  \~
        size_t head_size;

        /// \~english How much of the answer has gone out.
        /// \~spanish Cuanto de la respuesta ha salido.  \~
        size_t sent;

        /**
         * \~english
         * Which half of its life it is in.  Not derived from the other fields,
         * because "the buffer holds the request" and "the buffer holds what is
         * left of the answer" are two states that look identical from the
         * outside -- and a reader that guessed would hand a handler its own
         * response back.
         * \~spanish
         * En que mitad de su vida esta.  No se deduce de los otros campos, porque
         * "el buffer tiene la peticion" y "el buffer tiene lo que queda de la
         * respuesta" son dos estados que desde fuera se ven iguales -- y quien lo
         * adivinara le daria a un manejador su propia respuesta.
         * \~
         */
        bool answering;
    };

    struct State {
        h2::Connection conn;

        /**
         * \~english
         * Where a header block being decoded puts its names and values, and the
         * request built from them.  One per CONNECTION and not per stream: a
         * header block cannot be interrupted by another frame, so only one is
         * ever being decoded -- and a request that outlives its block moves
         * into a @c Work, which is what that copy is for.
         * \~spanish
         * Donde pone sus nombres y valores un bloque de cabeceras que se esta
         * descodificando, y la peticion construida con ellos.  Uno por CONEXION y
         * no por flujo: un bloque de cabeceras no lo puede interrumpir otra
         * trama, asi que solo hay uno descodificandose -- y una peticion que
         * sobreviva a su bloque se muda a un @c Work, que es para lo que esta esa
         * copia.
         * \~
         */
        Buffer headers;
        Request req;

        /// \~english The requests of this connection that are not finished with.
        /// \~spanish Las peticiones de esta conexion sin acabar.  \~
        uint32_t works;
    };

    /// \~english Takes a piece of work for @p stream, or says there is none.
    /// \~spanish Coge un trabajo para @p stream, o dice que no hay.  \~
    Work *take_work(State &s, uint32_t stream) noexcept;

    /// \~english Gives @p w back, buffer and all.
    /// \~spanish Devuelve @p w, con buffer y todo.  \~
    void drop_work(State &s, Work *w) noexcept;

    /// \~english The work of @p stream, or null.
    /// \~spanish El trabajo de @p stream, o nulo.  \~
    Work *find_work(State &s, uint32_t stream) noexcept;

    /// \~english Puts what the connection owes into @p out.
    /// \~spanish Pone lo que debe la conexion en @p out.  \~
    bool flush_control(State &s, Buffer &out) noexcept;

    /// \~english Puts the frames of @p list into @p out.
    /// \~spanish Pone las tramas de @p list en @p out.  \~
    bool put_list(const IoList &list, Buffer &out) noexcept;

    /// \~english Asks the handler and writes what it said.
    /// \~spanish Le pregunta al manejador y escribe lo que dijo.  \~
    bool answer(State &s, uint32_t stream, const Request &req,
                const uint8_t *head, const uint8_t *body, size_t n,
                Work *w, Buffer &out) noexcept;

    /// \~english Writes @p res as HTTP/2, keeping what does not fit.
    /// \~spanish Escribe @p res como HTTP/2, guardando lo que no quepa.  \~
    bool deliver(State &s, uint32_t stream, const ResponseBuilder &res,
                 Work *w, Buffer &out) noexcept;

    /// \~english Sends what the windows allow of a waiting answer.
    /// \~spanish Manda lo que dejen las ventanas de una respuesta que espera.  \~
    bool resume(State &s, Work *w, Buffer &out) noexcept;

    /// \~english Says the response is over and forgets the stream.
    /// \~spanish Dice que la respuesta se acabo y olvida el flujo.  \~
    bool finish(State &s, uint32_t stream, Buffer &out) noexcept;

    /// \~english Sends as much of a body as the windows allow.
    /// \~spanish Manda de un cuerpo lo que dejen las ventanas.  \~
    bool push_body(State &s, uint32_t stream, h2::Stream &st, const uint8_t *p,
                   size_t n, size_t &at, Buffer &out) noexcept;

    /// \~english Tries every waiting answer again.
    /// \~spanish Vuelve a intentar cada respuesta que espera.  \~
    bool drain(State &s, Buffer &out) noexcept;

    /// \~english Answers @p status with nothing else to say.
    /// \~spanish Contesta @p status sin nada mas que decir.  \~
    bool refuse(State &s, uint32_t stream, StatusCode status, Work *w,
                Buffer &out) noexcept;

    State *state_ = nullptr;
    uint32_t capacity_ = 0;

    Work *works_ = nullptr;
    uint32_t work_count_ = 0;
    uint32_t free_work_ = kNoWork;
    size_t in_hand_ = 0;

    /**
     * \~english
     * The buffers those pieces of work keep their bytes in.  One pool for the
     * service, the same size as the work pool, because a piece of work holds
     * exactly one buffer for exactly as long as it exists.
     * \~spanish
     * Los buffers donde esos trabajos guardan sus bytes.  Un pozo para el
     * servicio, del mismo tamano que el de trabajos, porque un trabajo tiene
     * exactamente un buffer exactamente mientras existe.
     * \~
     */
    BufferPool bodies_;

    /// \~english Where a handler's answer is collected before it is framed.
    /// \~spanish Donde se recoge la respuesta antes de entramarla.  \~
    Buffer said_;

    /// \~english Where a header block is built.
    /// \~spanish Donde se construye un bloque de cabeceras.  \~
    Buffer block_;

    Handler *handler_ = nullptr;
    h2::Limits limits_;
    size_t max_body_ = 0;
    size_t served_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP2_SERVICE_H
