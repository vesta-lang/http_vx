/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/connection_request.cpp
 * @brief
 * \~english The frames that carry a request: HEADERS and CONTINUATION, and DATA.
 * \~spanish Las tramas que llevan una peticion: HEADERS y CONTINUATION, y DATA.
 * \~
 */

#include "http_vx/h2_connection.h"

#include "http_vx/content_length.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h2 {

const char *Connection::expect_content(const Buffer &headers,
                                       const http_vx::Request &req) noexcept {
    /* \~english
     * The field is read by the same code HTTP/1.1 reads it with (RFC 9110,
     * 8.6): every occurrence, every list element, digits only.  A value that
     * is not a length at all cannot equal the content, whatever the content
     * turns out to be, so it is malformed now rather than later (RFC 9113,
     * 8.1.1).
     * \~spanish
     * La cabecera se lee con el mismo codigo con que la lee HTTP/1.1 (RFC 9110,
     * 8.6): todas las apariciones, todos los elementos de la lista, solo
     * digitos.  Un valor que no es una longitud no puede ser igual al
     * contenido, sea el contenido el que sea, asi que esta mal formado ahora y
     * no mas tarde (RFC 9113, 8.1.1).
     * \~ */
    const ContentLength cl = parse_content_length(req.fields, headers.data());

    if (cl.status == ContentLengthStatus::Absent) return nullptr;

    if (cl.status == ContentLengthStatus::Present) {
        const Outcome o = streams_.expect_content(block_stream_, cl.value);
        return o.verdict == Verdict::StreamError ? o.why : nullptr;
    }

    if (cl.status == ContentLengthStatus::Conflicting)
        return "content-length values that disagree (RFC 9110, 8.6; RFC 9113, "
               "8.1.1)";

    if (cl.status == ContentLengthStatus::Malformed)
        return "a content-length that is not a number (RFC 9110, 8.6; RFC "
               "9113, 8.1.1)";

    /* \~english
     * Too large to hold: the DATA this end counts could never add up to it,
     * so the equality RFC 9113, 8.1.1 asks for cannot be checked -- and a rule
     * that cannot be checked is refused, not waved through.
     * \~spanish
     * Demasiado grande para guardarla: los DATA que cuenta este extremo no
     * podrian sumarla nunca, asi que la igualdad que pide RFC 9113, 8.1.1 no se
     * puede comprobar -- y una regla que no se puede comprobar se rechaza, no se
     * deja pasar.
     * \~ */
    return "a content-length larger than this end can count (RFC 9113, 8.1.1)";
}

Event Connection::on_headers(const View &v, Buffer &headers,
                             http_vx::Request &req) noexcept {
    const FrameHeader &h = reader_.header();
    const Span p = reader_.payload();
    const uint8_t *at = v.at(v.origin + p.off);

    const bool first = h.type == static_cast<uint8_t>(FrameType::Headers);
    const bool last = (h.flags & kEndHeaders) != 0;

    /* \~english
     * Which stream the block is for, and whether the request ends with it, are
     * remembered from the HEADERS.  They cannot be read off the frame in hand
     * when the block ends on a CONTINUATION: `END_STREAM` is a fact about the
     * stream and it was stated once, on the first frame, and a CONTINUATION
     * has no such flag.
     *
     * The stream is opened HERE and not when the block ends, because opening
     * is about the identifier and the identifier arrived with the first frame.
     * Waiting would let a peer send a megabyte of CONTINUATIONs for a stream
     * that was going to be refused.
     *
     * \~spanish
     * De que flujo es el bloque, y si la peticion se acaba con el, se recuerdan
     * del HEADERS.  No se pueden leer de la trama que se tiene cuando el bloque
     * acaba en una CONTINUATION: `END_STREAM` es un hecho del flujo y se dijo
     * una vez, en la primera trama, y una CONTINUATION no tiene esa bandera.
     *
     * El flujo se abre AQUI y no cuando acaba el bloque, porque abrir va del
     * identificador y el identificador llego con la primera trama.  Esperar
     * dejaria a un extremo mandar un megabyte de CONTINUATIONs de un flujo que
     * iba a ser rechazado.
     * \~ */
    if (first) {
        block_stream_ = h.stream_id;
        block_ends_ = (h.flags & kEndStream) != 0;

        /* \~english
         * A HEADERS for a stream still in the table does not open anything:
         * it is the trailer section of the request already there (RFC 9113,
         * 8.1), and what it may be is a question for that stream.  One for a
         * stream that is not in the table goes on being an opening, and the
         * identifier rules there refuse whatever is not.
         * \~spanish
         * Un HEADERS de un flujo que sigue en la tabla no abre nada: es la
         * seccion de remolques de la peticion que ya esta (RFC 9113, 8.1), y lo
         * que pueda ser es cosa de ese flujo.  Uno de un flujo que no esta en la
         * tabla sigue siendo una apertura, y las reglas del identificador de
         * alli rechazan lo que no lo sea.
         * \~ */
        block_trailers_ = streams_.find(block_stream_) != nullptr;

        const Outcome o = block_trailers_
                              ? streams_.on_trailers(block_stream_, block_ends_)
                              : streams_.open(block_stream_, block_ends_);
        if (o.verdict == Verdict::ConnectionError)
            return fail(o.error, o.why);

        block_refused_ =
            o.verdict == Verdict::StreamError ? o.error : ErrorCode::NoError;
        block_why_ = o.why;

        /* \~english
         * @c Discard is a stream this end already reset: the block is still
         * decoded below, and then nothing at all is said about it -- not a
         * request, and not a second RST_STREAM (RFC 9113, 5.1).
         * \~spanish
         * @c Discard es un flujo que este extremo ya reinicio: el bloque se
         * descodifica igual abajo, y despues no se dice nada de el -- ni una
         * peticion, ni un segundo RST_STREAM (RFC 9113, 5.1).
         * \~ */
        block_dropped_ = o.verdict == Verdict::Discard;
    }

    /* \~english
     * The ordinary case, and it does not copy: one HEADERS that ends the block
     * is already contiguous where it lies, so the decoder reads it out of the
     * connection buffer.  Only a block the peer chose to SPLIT has to be put
     * back together, and then the copy is paid by the connection that asked
     * for it.
     *
     * \~spanish
     * El caso corriente, y no copia: un solo HEADERS que acaba el bloque ya esta
     * seguido donde esta, asi que el descodificador lo lee del buffer de la
     * conexion.  Solo un bloque que el otro extremo decidio PARTIR hay que
     * volver a juntarlo, y entonces la copia la paga la conexion que la pidio.
     * \~ */
    const uint8_t *block = at;
    size_t block_len = p.len;

    if (first && last) {
        block_.clear();
    } else {
        if (first) block_.clear();

        uint8_t *room = block_.reserve(p.len);
        if (room == nullptr)
            return fail(ErrorCode::InternalError,
                        "no memory to join a split field block (RFC 9113, "
                        "4.3)");
        util::vesta_memcpy(room, at, p.len);
        block_.commit(p.len);

        if (!last) return Event{};

        block = block_.data();
        block_len = block_.size();
    }

    /* \~english
     * **A refused stream's block is decoded anyway.**  It looks like waste and
     * it is the opposite: the table is the CONNECTION's, and a block left
     * undecoded leaves this end's table out of step with the peer's -- from
     * then on every index names a different field, on a connection that keeps
     * working.  Skipping the work of a refused request would cost the
     * connection every request after it.
     *
     * \~spanish
     * **El bloque de un flujo rechazado se descodifica igual.**  Parece
     * desperdicio y es lo contrario: la tabla es de la CONEXION, y un bloque sin
     * descodificar deja la tabla de este extremo desacompasada de la del otro
     * -- a partir de ahi cada indice nombra otra cabecera, en una conexion que
     * sigue funcionando --.  Saltarse el trabajo de una peticion rechazada le
     * costaria a la conexion todas las peticiones siguientes.
     * \~ */
    ErrorCode de = ErrorCode::NoError;
    if (block_trailers_) {
        /* \~english
         * Trailers are ADDED: to the request passed in and after what the
         * header buffer holds, so that a caller that kept the stream's head
         * there sees one request, head and trailers, over one base.
         * \~spanish
         * Los remolques se ANADEN: a la peticion que se paso y detras de lo que
         * tenga el buffer de cabeceras, para que quien guardo ahi la cabecera
         * del flujo vea una peticion, cabecera y remolques, sobre una base.
         * \~ */
        de = decoder_.decode_trailers(block, block_len, headers, req);
    } else {
        headers.clear();
        de = decoder_.decode(block, block_len, headers, req);
    }
    block_.clear();

    /* \~english
     * A compression error is always the CONNECTION, whatever the stream's
     * verdict was: the table cannot be put back, so there is nothing to carry
     * on with.  Running out of memory halfway through the block is the same
     * thing seen from here -- the rest of it never reached the table.
     * \~spanish
     * Un error de compresion es siempre la CONEXION, fuera cual fuera el
     * veredicto del flujo: la tabla no se puede recomponer, asi que no hay con
     * que seguir.  Quedarse sin memoria a mitad del bloque es lo mismo visto
     * desde aqui -- el resto no llego nunca a la tabla.
     * \~ */
    if (de == ErrorCode::CompressionError || de == ErrorCode::InternalError)
        return fail(de, decoder_.why());

    if (block_dropped_) return Event{};

    /* \~english
     * Too large, and otherwise a stream this end would have served: the caller
     * answers 431 on it (RFC 9113, 10.5.1) rather than this end resetting it.
     * A stream the table had already refused is not one -- it is not open, so
     * there is nothing to answer on -- and it is reset below, with the size,
     * like any block that broke a rule on a stream that was refused.
     * \~spanish
     * Demasiado grande, y por lo demas un flujo que este extremo habria
     * atendido: quien llama contesta 431 en el (RFC 9113, 10.5.1) en vez de
     * reiniciarlo este extremo.  Un flujo que la tabla ya habia rechazado no lo
     * es -- no esta abierto, asi que no hay donde contestar --, y se reinicia
     * abajo, por el tamano, como cualquier bloque que rompio una regla en un
     * flujo rechazado.
     * \~ */
    if (de == ErrorCode::EnhanceYourCalm && block_refused_ == ErrorCode::NoError) {
        why_ = decoder_.why();
        Event e;
        e.kind = EventKind::HeadersTooLarge;
        e.stream_id = block_stream_;
        e.error = de;
        e.ends = block_ends_;
        return e;
    }

    if (de != ErrorCode::NoError)
        return refuse(block_stream_, de, decoder_.why());

    if (block_refused_ != ErrorCode::NoError)
        return refuse(block_stream_, block_refused_, block_why_);

    if (block_trailers_) {
        Event e;
        e.kind = EventKind::Trailers;
        e.stream_id = block_stream_;
        e.ends = true;
        return e;
    }

    /* \~english
     * The head is whole, so its content-length is known: from here on every
     * DATA of the stream is counted against it (RFC 9113, 8.1.1).
     * \~spanish
     * La cabecera esta entera, asi que se conoce su content-length: desde aqui
     * cada DATA del flujo se cuenta contra ella (RFC 9113, 8.1.1).
     * \~ */
    const char *bad = expect_content(headers, req);
    if (bad != nullptr)
        return refuse(block_stream_, ErrorCode::ProtocolError, bad);

    Event e;
    e.kind = EventKind::Request;
    e.stream_id = block_stream_;
    e.ends = block_ends_;
    return e;
}

Event Connection::on_data(const View &v) noexcept {
    const FrameHeader &h = reader_.header();

    /* \~english
     * The connection's window is spent on the WHOLE payload, padding and
     * all, and it is spent even when the stream refuses the frame.  The
     * peer counted those bytes when it sent them, so an end that did not
     * count them would be a little further ahead on every padded or
     * discarded frame -- and the two would drift apart until the
     * connection stopped.
     *
     * \~spanish
     * La ventana de la conexion se gasta con la carga ENTERA, relleno
     * incluido, y se gasta aunque el flujo rechace la trama.  El otro
     * extremo conto esos bytes al mandarlos, asi que un extremo que no los
     * contara iria un poco por delante en cada trama rellenada o descartada
     * -- y los dos se separarian hasta que la conexion se parara.
     * \~ */
    if (!recv_.take(h.length))
        return fail(ErrorCode::FlowControlError,
                    "DATA past the connection's flow-control window (RFC "
                    "9113, 6.9.1)");

    const bool end_stream = (h.flags & kEndStream) != 0;

    /* \~english
     * Two lengths: the whole payload is what the windows are charged, and
     * what is left once the reader took the padding off is the content a
     * content-length is compared with (RFC 9113, 6.1 and 8.1.1).
     * \~spanish
     * Dos longitudes: la carga entera es lo que se cobra a las ventanas, y
     * lo que queda cuando el lector quito el relleno es el contenido con el
     * que se compara una content-length (RFC 9113, 6.1 y 8.1.1).
     * \~ */
    const Span p = reader_.payload();
    const Outcome o =
        streams_.on_data(h.stream_id, h.length, p.len, end_stream);

    if (o.verdict == Verdict::ConnectionError) return fail(o.error, o.why);

    /* \~english
     * A frame nobody is going to read still has to give its allowance
     * back, and it has to give it back HERE.  There is no stream to credit
     * -- it is over, which is why the frame is being refused -- and no
     * caller to ask, because a caller is only told about bytes it is being
     * handed.  Skipping it loses a little window on every reset stream, and
     * enough of them stop the connection for good.
     *
     * \~spanish
     * Una trama que no va a leer nadie tiene que devolver su credito igual, y
     * tiene que devolverlo AQUI.  No hay flujo al que abonarlo -- esta
     * terminado, que es la razon de que la trama se rechace -- ni a quien
     * llama a quien pedirselo, porque a quien llama solo se le habla de los
     * bytes que se le dan.  Saltarselo pierde un poco de ventana en cada
     * flujo abortado, y con bastantes la conexion se para para siempre.
     * \~ */
    if (o.verdict == Verdict::StreamError) {
        const Event e = refuse(h.stream_id, o.error, o.why);
        if (e.kind == EventKind::Closed) return e;
        if (!credit_connection(h.length)) return no_room();
        return e;
    }

    if (o.verdict == Verdict::Discard) {
        if (!credit_connection(h.length)) return no_room();
        return Event{};
    }

    /* \~english
     * And the padding, which the reader took off and the peer paid for.
     * The bytes are charged to both windows and reach nobody, so both are
     * credited -- which is what @c release_window does, and the stream is
     * still open here, so it is the right call rather than a near one.
     *
     * \~spanish
     * Y el relleno, que el lector quito y el otro extremo pago.  Los bytes se
     * cobran a las dos ventanas y no llegan a nadie, asi que se abonan las dos
     * -- que es lo que hace @c release_window, y aqui el flujo sigue abierto,
     * asi que es la llamada correcta y no una parecida.
     * \~ */
    if (h.length > p.len &&
        !release_window(h.stream_id, static_cast<uint32_t>(h.length - p.len)))
        return no_room();

    Event e;
    e.kind = EventKind::Body;
    e.stream_id = h.stream_id;
    e.ends = end_stream;
    e.data = p.len == 0 ? nullptr : v.at(v.origin + p.off);
    e.size = p.len;
    return e;
}

} // namespace h2
} // namespace http_vx
