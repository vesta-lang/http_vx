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
#include "http_vx/h2_open.h"
#include "http_vx/h2_writer.h"
#include "http_vx/http1_service.h"
#include "http_vx/response_lines.h"

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
class Http2Service final : public Service, public KickTarget {
  public:
    Http2Service() noexcept = default;
    ~Http2Service() override;

    /**
     * \~english
     * How many responses may be open at once when @c reset is not told.  The
     * same number as the shard's own default limit, so neither runs out
     * before the other unless somebody sizes one of them.
     * \~spanish
     * Cuantas respuestas pueden estar abiertas a la vez cuando a @c reset no se
     * le dice.  El mismo numero que el tope por defecto del fragmento, para que
     * ninguno se agote antes que el otro salvo que alguien le de tamano a uno.
     * \~
     */
    static constexpr uint32_t kOpenResponses = 1024;

    /**
     * \~english
     * The most body one fill is offered.  What bounds it is the buffer an open
     * response writes into, like @c Http1Service::kFillRoom; the windows, the
     * peer's frame size and the caller's budget may bound it further.
     * \~spanish
     * Lo mas de cuerpo que se ofrece en un relleno.  Lo que lo acota es el
     * buffer en el que escribe una respuesta abierta, como
     * @c Http1Service::kFillRoom; las ventanas, el tamano de trama del otro
     * extremo y el presupuesto de quien llama pueden acotarlo mas.
     * \~
     */
    static constexpr size_t kFillRoom = 16384;

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
     * @param opens       \~english how many responses may be open at once; their own table, apart from @p requests (HVX-5, 7.2)
     *                    \~spanish cuantas respuestas pueden estar abiertas a la vez; su propia tabla, aparte de @p requests (HVX-5, 7.2)  \~
     * @return            \~english false if the memory could not be had
     *                    \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t connections, uint32_t requests, size_t max_body,
               Handler &handler, const h2::Limits &limits,
               uint32_t opens = kOpenResponses) noexcept;

    bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override;
    void on_open(ConnHandle c) noexcept override;
    void on_close(ConnHandle c) noexcept override;
    void attach(StreamPort *port) noexcept override { port_ = port; }
    bool on_writable(ConnHandle c, Buffer &out, size_t budget) noexcept override;
    void on_kick(BodySource &source) noexcept override;

    /**
     * @brief
     * \~english How many opens were answered 503 because this service's own table of open responses was full.
     * \~spanish Cuantas aperturas se contestaron 503 porque la tabla propia de respuestas abiertas de este servicio estaba llena.
     * \~
     *
     * \~english
     * Apart from the shard's @c OpenCounts::refused, which counts its own
     * limits: this is the service's table being smaller than the shard allows.
     * \~spanish
     * Aparte de @c OpenCounts::refused del fragmento, que cuenta sus propios
     * topes: esto es la tabla del servicio siendo mas pequena de lo que deja el
     * fragmento.
     * \~
     */
    size_t open_full() const noexcept { return open_full_; }

    /// \~english How many responses are open right now.  \~spanish Cuantas respuestas estan abiertas ahora mismo.  \~
    uint32_t open_now() const noexcept { return opens_.in_use(); }

    /// \~english How many whole requests have been answered.
    /// \~spanish Cuantas peticiones enteras se han contestado.  \~
    size_t served() const noexcept { return served_; }

    /// \~english How many requests are in hand right now.
    /// \~spanish Cuantas peticiones hay en mano ahora mismo.  \~
    size_t in_hand() const noexcept { return in_hand_; }

    /**
     * @brief
     * \~english How many handler answers could not travel as written, and went out as 500.
     * \~spanish Cuantas respuestas de un manejador no podian viajar tal como se escribieron, y salieron como 500.
     * \~
     *
     * \~english
     * A handler that failed to build its answer, or one whose fields HTTP/2
     * may not carry: a connection-specific field, a name that is not a token,
     * a value with a character HTTP forbids (RFC 9113, 8.2.1, 8.2.2), or more
     * fields than @c kMostFields.  Counted because the 500 alone says this
     * server failed and not where; the count is what tells a handler bug from
     * a network one.
     * \~spanish
     * Un manejador que no consiguio construir su respuesta, o uno cuyas
     * cabeceras no puede llevar HTTP/2: un campo propio de la conexion, un
     * nombre que no es un token, un valor con un caracter que HTTP prohibe
     * (RFC 9113, 8.2.1, 8.2.2), o mas cabeceras que @c kMostFields.  Se cuenta
     * porque el 500 solo dice que este servidor fallo y no donde; la cuenta es
     * lo que distingue un fallo del manejador de uno de la red.
     * \~
     */
    size_t bad_answers() const noexcept { return bad_answers_; }

    /// \~english The rule the last bad answer broke, or null if there has been none.
    /// \~spanish La regla que rompio la ultima respuesta mala, o nulo si no ha habido ninguna.  \~
    const char *last_bad_answer() const noexcept { return last_bad_answer_; }

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

        /// \~english Which connection this is, with its life: what an open response is opened on.
        /// \~spanish Que conexion es, con su vida: sobre lo que se abre una respuesta abierta.  \~
        ConnHandle handle;

        /// \~english The open responses of this connection, in the order they are served.
        /// \~spanish Las respuestas abiertas de esta conexion, en el orden en que se atienden.  \~
        h2::OpenList opens;
    };

    /**
     * @brief
     * \~english What the handler is given to open with: the shard's port, behind this service's own table.
     * \~spanish Lo que se le da al manejador para abrir: la puerta del fragmento, detras de la tabla propia de este servicio.
     * \~
     *
     * \~english
     * The shard checks its limits; this checks that the service has an entry
     * to keep the response in, BEFORE the shard counts it open -- so a full
     * table is a refusal the handler sees and the client gets as a 503, never
     * a response opened and then dropped.
     * \~spanish
     * El fragmento comprueba sus topes; esto comprueba que el servicio tenga una
     * entrada donde guardar la respuesta, ANTES de que el fragmento la cuente
     * abierta -- asi que una tabla llena es un rechazo que ve el manejador y que
     * el cliente recibe como 503, nunca una respuesta abierta y luego tirada.
     * \~
     */
    class OpenGate final : public OpenPort {
      public:
        explicit OpenGate(Http2Service &service) noexcept : service_(&service) {}

        OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s,
                          KickTarget &target) noexcept override;
        size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override;
        void end(BodySource &s, GoneReason why) noexcept override;

      private:
        Http2Service *service_;
    };

    /// \~english How writing a header block went.  \~spanish Como fue escribir un bloque de cabeceras.  \~
    enum class HeadWrite : uint8_t {
        /// \~english It is in the output.  \~spanish Esta en la salida.  \~
        Written,
        /// \~english It could not be written; the stream is to be reset.  \~spanish No se pudo escribir; hay que reiniciar el flujo.  \~
        StreamFailed,
        /// \~english The connection must end.  \~spanish La conexion tiene que acabar.  \~
        ConnectionFailed,
    };

    /// \~english What asking an open response for one frame left behind.  \~spanish Lo que dejo pedirle una trama a una respuesta abierta.  \~
    enum class Feed : uint8_t {
        /// \~english Still open, to be kept in its connection's list.  \~spanish Sigue abierta, se guarda en la lista de su conexion.  \~
        Kept,
        /// \~english Over, its entry given back.  \~spanish Acabada, con su entrada devuelta.  \~
        Ended,
        /// \~english No memory for the output: the connection must end.  \~spanish Sin memoria para la salida: la conexion tiene que acabar.  \~
        Failed,
    };

    /**
     * @brief
     * \~english Writes the header block of @p res on @p stream into @p out.
     * \~spanish Escribe el bloque de cabeceras de @p res en @p stream en @p out.
     * \~
     *
     * @param head       \~english whether it answers a HEAD  \~spanish si contesta a un HEAD  \~
     * @param end_stream \~english whether the block ends the stream  \~spanish si el bloque acaba el flujo  \~
     * @return           \~english how it went  \~spanish como fue  \~
     */
    HeadWrite put_head(State &s, uint32_t stream, const ResponseBuilder &res,
                       size_t count, bool head, bool end_stream, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Writes the head of an opened response, what was written before opening, and its first fill.
     * \~spanish Escribe la cabecera de una respuesta abierta, lo escrito antes de abrir, y su primer relleno.
     * \~
     *
     * @return \~english false if the connection must end  \~spanish false si la conexion tiene que acabar  \~
     */
    bool start_open(State &s, uint32_t stream, const ResponseBuilder &res,
                    size_t count, Work *w, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Asks open response @p i for what it has, one DATA frame at most (the kept prefix may take a few).
     * \~spanish Le pide a la respuesta abierta @p i lo que tenga, una trama DATA como mucho (el prefijo guardado puede llevar varias).
     * \~
     *
     * @param left \~english the budget left, spent by what is written  \~spanish el presupuesto que queda, que gasta lo que se escribe  \~
     * @return     \~english what it left behind  \~spanish lo que dejo  \~
     */
    Feed feed_open(State &s, uint32_t i, Buffer &out, size_t &left) noexcept;

    /**
     * @brief
     * \~english The body one DATA frame of @p st may carry now: zero if a window is shut or @p left takes no frame.
     * \~spanish El cuerpo que puede llevar ahora una trama DATA de @p st: cero si una ventana esta cerrada o @p left no admite una trama.
     * \~
     */
    size_t open_room(State &s, const h2::Stream &st, size_t left) noexcept;

    /**
     * @brief
     * \~english Sends @p p from @p at in DATA frames without END_STREAM, while the room lasts.
     * \~spanish Manda @p p desde @p at en tramas DATA sin END_STREAM, mientras dure el sitio.
     * \~
     *
     * @return \~english false if the output could not grow  \~spanish false si la salida no pudo crecer  \~
     */
    bool put_prefix(State &s, h2::Stream &st, uint32_t stream, const uint8_t *p,
                    size_t n, size_t &at, Buffer &out, size_t &left) noexcept;

    /// \~english Asks for room on the connection if an open response wants it and the windows have some.
    /// \~spanish Pide sitio en la conexion si una respuesta abierta lo quiere y las ventanas tienen.  \~
    void wake_open(State &s) noexcept;

    /// \~english Ends open response @p i, which is in no list, with @p why, and gives its entry back.
    /// \~spanish Acaba la respuesta abierta @p i, que no esta en ninguna lista, con @p why, y devuelve su entrada.  \~
    void drop_open(uint32_t i, GoneReason why) noexcept;

    /// \~english Ends the open response of @p stream, if there is one, with @p why.
    /// \~spanish Acaba la respuesta abierta de @p stream, si la hay, con @p why.  \~
    void end_stream_open(State &s, uint32_t stream, GoneReason why) noexcept;

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

    /// \~english Moves the trailer section just read into @p w: its bytes after the body, its fields into the request.
    /// \~spanish Muda la seccion de remolques recien leida a @p w: sus bytes detras del cuerpo, sus campos a la peticion.  \~
    bool add_trailers(State &s, Work &w, Buffer &keep) noexcept;

    /**
     * @brief
     * \~english Writes @p res as HTTP/2, keeping what does not fit.
     * \~spanish Escribe @p res como HTTP/2, guardando lo que no quepa.
     * \~
     *
     * @param s      \~english the connection  \~spanish la conexion  \~
     * @param stream \~english which stream  \~spanish que flujo  \~
     * @param res    \~english the answer  \~spanish la respuesta  \~
     * @param count  \~english how many of @c lines_ are its fields, checked by @c wire_fields
     *               \~spanish cuantas de @c lines_ son sus cabeceras, comprobadas por @c wire_fields  \~
     * @param head   \~english whether it answers a HEAD: the fields and no content (RFC 9110, 9.3.2)
     *               \~spanish si contesta a un HEAD: las cabeceras y ningun contenido (RFC 9110, 9.3.2)  \~
     * @param w      \~english the stream's work, or null  \~spanish el trabajo del flujo, o nulo  \~
     * @param out    \~english where the frames go  \~spanish donde van las tramas  \~
     * @return       \~english false if the connection must end
     *               \~spanish false si la conexion tiene que acabar  \~
     */
    bool deliver(State &s, uint32_t stream, const ResponseBuilder &res,
                 size_t count, bool head, Work *w, Buffer &out) noexcept;

    /**
     * @brief
     * \~english Ends @p stream with @p code, making room for the RST_STREAM if there is none.
     * \~spanish Acaba @p stream con @p code, haciendo sitio para el RST_STREAM si no lo hay.
     * \~
     *
     * \~english
     * The room is made by moving what the connection owes into @p out --
     * sending it now instead of later -- because a reset that is not written
     * is a stream the table forgot and the peer did not: it keeps the stream
     * open, and waits.  If even @p out cannot take it, false, and the
     * connection ends like any other that cannot be answered.
     * \~spanish
     * El sitio se hace pasando a @p out lo que debe la conexion -- mandandolo
     * ahora en vez de despues --, porque un reinicio que no se escribe es un
     * flujo que la tabla olvido y el otro extremo no: lo sigue teniendo abierto,
     * y espera.  Si ni @p out lo acepta, false, y la conexion se acaba como
     * cualquier otra a la que no se puede contestar.
     * \~
     */
    bool send_reset(State &s, uint32_t stream, h2::ErrorCode code, Buffer &out) noexcept;

    /// \~english Gives back @p n bytes of window on @p stream, making room the way @c send_reset does.
    /// \~spanish Devuelve @p n bytes de ventana en @p stream, haciendo sitio como @c send_reset.  \~
    bool give_window(State &s, uint32_t stream, size_t n, Buffer &out) noexcept;

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

    /// \~english Answers @p status with nothing else to say, and asks a peer still sending to stop.
    /// \~spanish Contesta @p status sin nada mas que decir, y le pide a un extremo que sigue mandando que pare.  \~
    bool refuse(State &s, uint32_t stream, StatusCode status, Work *w,
                Buffer &out) noexcept;

    /**
     * \~english
     * The most fields an answer carries.  HTTP/2 itself has no count, only the
     * peer's advisory SETTINGS_MAX_HEADER_LIST_SIZE; this is the room
     * @c wire_fields gets, and an answer with more is a 500 counted in
     * @c bad_answers -- never one with some of its fields dropped.
     * \~spanish
     * Las cabeceras mas que lleva una respuesta.  HTTP/2 no tiene cuenta, solo
     * el SETTINGS_MAX_HEADER_LIST_SIZE orientativo del otro extremo; este es el
     * sitio que recibe @c wire_fields, y una respuesta con mas es un 500 contado
     * en @c bad_answers -- nunca una a la que se le quitan cabeceras.
     * \~
     */
    static constexpr size_t kMostFields = 64;

    /// \~english The fields of the answer being written, lowered and checked.
    /// \~spanish Las cabeceras de la respuesta que se escribe, en minusculas y comprobadas.  \~
    WireField lines_[kMostFields];

    /// \~english Where the unknown names of @c lines_ are lowered.
    /// \~spanish Donde se bajan a minusculas los nombres desconocidos de @c lines_.  \~
    Buffer names_;

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
    size_t bad_answers_ = 0;
    const char *last_bad_answer_ = nullptr;

    /// \~english The open responses, apart from @c works_ and @c bodies_ (HVX-5, 7.2).
    /// \~spanish Las respuestas abiertas, aparte de @c works_ y @c bodies_ (HVX-5, 7.2).  \~
    h2::OpenTable opens_;

    /// \~english The shard's side of open responses, or null: then nothing opens.
    /// \~spanish El lado del fragmento de las respuestas abiertas, o nulo: entonces no se abre nada.  \~
    StreamPort *port_ = nullptr;

    OpenGate gate_{*this};
    size_t open_full_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP2_SERVICE_H
