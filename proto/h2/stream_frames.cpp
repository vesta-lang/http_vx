/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/stream_frames.cpp
 * @brief
 * \~english What the stream table says about each frame of a request: HEADERS, DATA, trailers.
 * \~spanish Lo que dice la tabla de flujos de cada trama de una peticion: HEADERS, DATA, remolques.
 * \~
 */

#include "http_vx/h2_stream.h"

#include "stream_verdicts.h"

namespace http_vx {
namespace h2 {

Outcome StreamSet::open(uint32_t id, bool end_stream) noexcept {
    /* \~english
     * Zero is the connection and not a stream, and an even number is one this
     * server would have opened.  Either one means the two ends disagree about
     * who numbers what, and nothing after it can be taken to mean what it says.
     * \~spanish
     * El cero es la conexion y no un flujo, y un numero par es uno que habria
     * abierto este servidor.  Cualquiera de los dos quiere decir que los dos
     * extremos discrepan sobre quien numera que, y nada de lo que venga detras
     * se puede dar por lo que dice.
     * \~ */
    if (id == 0 || (id & 1) == 0)
        return connection_error(ErrorCode::ProtocolError,
                                "a HEADERS on stream 0 or on an even "
                                "identifier, which a client never opens (RFC "
                                "9113, 5.1.1)");

    /* \~english
     * At or below the highest already seen: never a new stream.  What it is
     * instead depends on how that identifier ended, which is kept only for
     * the recent ones and in two bits each (@c RecentStreams) -- a list of
     * every identifier ever used is the memory this rule exists to avoid --
     * and @c headers_on_closed decides.
     *
     * Note that a stream still OPEN with this identifier lands here too -- a
     * second HEADERS on a live stream is trailers, and that is a different
     * question asked elsewhere, not an opening.
     *
     * \~spanish
     * Igual o por debajo del mayor ya visto: nunca un flujo nuevo.  Lo que es
     * en cambio depende de como acabo ese identificador, que se guarda solo de
     * los recientes y en dos bits cada uno (@c RecentStreams) -- una lista de
     * todos los identificadores usados es la memoria que esta regla existe para
     * evitar --, y lo decide @c headers_on_closed.
     *
     * Fijarse en que un flujo todavia ABIERTO con este identificador tambien cae
     * aqui -- un segundo HEADERS sobre un flujo vivo son trailers, y esa es otra
     * pregunta que se hace en otro sitio, no una apertura.
     * \~ */
    if (id <= highest_) return headers_on_closed(id);

    /* \~english
     * The number goes up whether or not the stream is accepted.  A refused
     * stream is still a stream the peer opened, and letting the peer try the
     * same identifier again after a refusal would be letting it reuse one.
     * \~spanish
     * El numero sube se acepte el flujo o no.  Un flujo rechazado es un flujo
     * que el otro extremo abrio igual, y dejarle intentar el mismo
     * identificador otra vez despues de un rechazo seria dejarle reutilizar uno.
     * \~ */
    highest_ = id;
    recent_.opened(id);

    /* \~english
     * More at once than this server holds.  The peer did nothing wrong, so it
     * is a stream error with the one code that means "send it again" -- and a
     * connection error here would turn a busy moment into a dropped connection
     * for every other request on it.
     * \~spanish
     * Mas a la vez de los que guarda este servidor.  El otro extremo no ha hecho
     * nada mal, asi que es un error de flujo con el unico codigo que quiere
     * decir "mandalo otra vez" -- y un error de conexion aqui convertiria un
     * momento de mucho trabajo en una conexion caida para todas las demas
     * peticiones que van por ella.
     * \~ */
    if (count_ >= max_streams_) return too_many();

    if (!make_room())
        return connection_error(ErrorCode::InternalError,
                                "no memory for the stream table");
    if (count_ >= cap_) return too_many();

    Stream &s = streams_[count_];
    s.id = id;
    s.send = Window(peer_initial_);
    s.recv = Window(own_initial_);
    s.state = end_stream ? StreamState::HalfClosedRemote : StreamState::Open;
    s.counted = false;
    s.content_left = 0;
    ++count_;

    return ok();
}

Outcome StreamSet::headers_on_closed(uint32_t id) noexcept {
    /* \~english
     * Still in the table: a HEADERS on a live stream is its trailers, asked
     * through @c on_trailers, so reaching here with one is an opening that
     * reuses a number in use.
     * \~spanish
     * Todavia en la tabla: un HEADERS de un flujo vivo son sus remolques, que
     * se preguntan por @c on_trailers, asi que llegar aqui con uno es una
     * apertura que reutiliza un numero en uso.
     * \~ */
    if (find(id) != nullptr)
        return connection_error(ErrorCode::ProtocolError,
                                "a HEADERS opening an identifier already in "
                                "use (RFC 9113, 5.1.1)");

    const Past p = recent_.past(id);

    /* \~english
     * This end reset it: the peer sent the HEADERS before it read the reset,
     * and "MUST minimally process and then discard" it -- the caller still
     * decodes the block, because the table is the connection's (RFC 9113,
     * 5.1).
     * \~spanish
     * Lo reinicio este extremo: el otro mando el HEADERS antes de leer el
     * reinicio, y "MUST minimally process and then discard" -- quien llama
     * descodifica igual el bloque, porque la tabla es de la conexion (RFC
     * 9113, 5.1).
     * \~ */
    if (is_late(p)) return late();

    /* \~english
     * Closed some other way, so the peer knew: a connection error of type
     * STREAM_CLOSED, which RFC 9113, 5.1 allows for any frame on a closed
     * stream.
     * \~spanish
     * Cerrado de otra forma, asi que el otro lo sabia: error de conexion de
     * tipo STREAM_CLOSED, que el RFC 9113, 5.1 permite para cualquier trama de
     * un flujo cerrado.
     * \~ */
    if (p == Past::Closed)
        return connection_error(ErrorCode::StreamClosed,
                                "a HEADERS on a stream that had closed (RFC "
                                "9113, 5.1)");

    /* \~english
     * Never opened: skipped over when a higher one was.  A HEADERS for it is
     * a stream opened out of order, and RFC 9113, 5.1.1 is the more specific
     * rule for a frame that opens.
     * \~spanish
     * No se abrio nunca: se salto cuando se abrio uno mayor.  Un HEADERS suyo
     * es un flujo abierto fuera de orden, y el RFC 9113, 5.1.1 es la regla mas
     * concreta para una trama que abre.
     * \~ */
    return connection_error(ErrorCode::ProtocolError,
                            "a HEADERS on an identifier below one already "
                            "opened (RFC 9113, 5.1.1)");
}

Outcome StreamSet::on_data(uint32_t id, uint32_t len, uint32_t content,
                           bool end_stream) noexcept {
    if (id == 0)
        return connection_error(ErrorCode::ProtocolError,
                                "DATA on stream 0 (RFC 9113, 6.1)");

    Stream *s = find(id);
    if (s == nullptr) {
        /* \~english
         * Above the highest seen, or even, means the peer sent data for a
         * stream it never opened, which is a connection error -- there is no
         * request to attach it to and no way to answer.  At or below means the
         * stream finished, and then it depends on who finished it: late if
         * this end reset it, and a peer that knew otherwise (RFC 9113, 5.1).
         * \~spanish
         * Por encima del mayor visto, o par, quiere decir que el otro extremo
         * mando datos de un flujo que no abrio nunca, que es un error de
         * conexion -- no hay peticion a la que pegarlos ni forma de contestar.
         * Igual o por debajo quiere decir que el flujo termino, y entonces
         * depende de quien lo termino: tarde si lo reinicio este extremo, y un
         * extremo que lo sabia si no (RFC 9113, 5.1).
         * \~ */
        if (never_opened(id))
            return connection_error(ErrorCode::ProtocolError,
                                    "DATA on an idle stream (RFC 9113, 5.1)");
        if (is_late(recent_.past(id))) return late();
        return connection_error(ErrorCode::StreamClosed,
                                "DATA on a stream that had closed (RFC 9113, "
                                "5.1)");
    }

    /* \~english
     * Data after the peer said it had finished.  This one IS the peer
     * misbehaving -- it told this end there would be no more and then sent more
     * -- and it is a stream error rather than a connection one because only
     * this request is confused.
     * \~spanish
     * Datos despues de que el otro extremo dijera que habia acabado.  Este SI es
     * el otro portandose mal -- le dijo a este que no habria mas y luego mando
     * mas -- y es un error de flujo y no de conexion porque la unica confundida
     * es esta peticion.
     * \~ */
    if (s->state == StreamState::HalfClosedRemote)
        return stream_error(ErrorCode::StreamClosed,
                            "DATA after the stream had ended (RFC 9113, 5.1)");

    /* \~english
     * More than this end said it would take.  A flow-control error on the
     * stream, and it is the check that makes the announced window a promise
     * rather than a suggestion: without it, the limit this server publishes is
     * a number nobody enforces.
     * \~spanish
     * Mas de lo que dijo este extremo que aceptaria.  Un error de control de
     * flujo del flujo, y es la comprobacion que hace de la ventana anunciada una
     * promesa y no una sugerencia: sin ella, el limite que publica este servidor
     * es un numero que no hace cumplir nadie.
     * \~ */
    if (!s->recv.take(len))
        return stream_error(ErrorCode::FlowControlError,
                            "DATA past the stream's flow-control window (RFC "
                            "9113, 6.9.1)");

    if (s->counted) {
        /* \~english
         * More content than the request declared, refused on the frame that
         * crosses the line: waiting for the end would be reading bytes the
         * request already said do not exist (RFC 9113, 8.1.1).
         * \~spanish
         * Mas contenido del que declaro la peticion, rechazado en la trama que
         * pasa de la raya: esperar al final seria leer bytes que la propia
         * peticion ya dijo que no existen (RFC 9113, 8.1.1).
         * \~ */
        if (content > s->content_left)
            return malformed("more DATA than content-length (RFC 9113, 8.1.1)");
        s->content_left -= content;

        /* \~english
         * And less, found out on the frame that ends the content.
         * \~spanish
         * Y menos, descubierto en la trama que acaba el contenido.
         * \~ */
        if (end_stream && s->content_left != 0)
            return malformed("less DATA than content-length (RFC 9113, 8.1.1)");
    }

    if (end_stream) end_remote(s);

    return ok();
}

Outcome StreamSet::expect_content(uint32_t id, uint64_t n) noexcept {
    Stream *s = find(id);

    /* \~english
     * Not in the table means the stream was refused or is over, and a length
     * for it has nothing left to be compared with.
     * \~spanish
     * Si no esta en la tabla es que el flujo se rechazo o acabo, y una
     * longitud suya ya no tiene con que compararse.
     * \~ */
    if (s == nullptr) return late();

    /* \~english
     * A HEADERS that already ended the stream: the content is empty, so the
     * only length that equals it is zero (RFC 9113, 8.1.1).  A request is
     * never one of the messages "defined as having no content" -- those are
     * responses (RFC 9110, 6.4.1) -- so the exception does not apply here.
     * \~spanish
     * Un HEADERS que ya acabo el flujo: el contenido esta vacio, asi que la
     * unica longitud que es igual a el es cero (RFC 9113, 8.1.1).  Una
     * peticion no es nunca uno de los mensajes "definidos como sin contenido"
     * -- esos son respuestas (RFC 9110, 6.4.1) --, asi que la excepcion no
     * vale aqui.
     * \~ */
    if (s->state == StreamState::HalfClosedRemote) {
        if (n != 0)
            return malformed("a content-length other than 0 on a request "
                             "with no DATA (RFC 9113, 8.1.1)");
        return ok();
    }

    s->counted = true;
    s->content_left = n;
    return ok();
}

Outcome StreamSet::on_trailers(uint32_t id, bool end_stream) noexcept {
    Stream *s = find(id);
    if (s == nullptr) return late();

    /* \~english
     * The peer already said it had finished, and a HEADERS is not one of the
     * frames still allowed after that (RFC 9113, 5.1, half-closed (remote)).
     * This is also where a THIRD HEADERS lands: the trailers ended the stream.
     * \~spanish
     * El otro extremo ya dijo que habia acabado, y un HEADERS no es de las
     * tramas que se permiten todavia despues (RFC 9113, 5.1, half-closed
     * (remote)).  Aqui cae tambien un TERCER HEADERS: los remolques acabaron el
     * flujo.
     * \~ */
    if (s->state == StreamState::HalfClosedRemote)
        return Outcome{Verdict::StreamError, ErrorCode::StreamClosed,
                       "a HEADERS after the stream had ended (RFC 9113, 5.1)"};

    /* \~english
     * A HEADERS after the one that opened the request, without END_STREAM:
     * malformed (RFC 9113, 8.1).
     * \~spanish
     * Un HEADERS detras del que abrio la peticion, sin END_STREAM: mal formada
     * (RFC 9113, 8.1).
     * \~ */
    if (!end_stream)
        return malformed("a second HEADERS without END_STREAM (RFC 9113, 8.1)");

    /* \~english
     * The trailers end the content, so what was declared has to have arrived
     * by now (RFC 9113, 8.1.1).
     * \~spanish
     * Los remolques acaban el contenido, asi que lo declarado tiene que haber
     * llegado ya (RFC 9113, 8.1.1).
     * \~ */
    if (s->counted && s->content_left != 0)
        return malformed("less DATA than content-length (RFC 9113, 8.1.1)");

    end_remote(s);
    return ok();
}

} // namespace h2
} // namespace http_vx
