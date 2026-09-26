/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service_answer.cpp
 * @brief
 * \~english The HTTP/2 service's answers: the handler asked, its answer checked and written as HTTP/2 needs it.
 * \~spanish Las respuestas del servicio HTTP/2: se le pregunta al manejador, y su respuesta se comprueba y se escribe como la necesita HTTP/2.
 * \~
 */

#include "http_vx/http2_service.h"

#include "http_vx/content_length.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

bool Http2Service::deliver(State &s, uint32_t stream,
                           const ResponseBuilder &res, size_t count, bool head,
                           Work *w, Buffer &out) noexcept {
    h2::Stream *st = s.conn.streams().find(stream);

    /* \~english
     * The stream may have gone while the handler was working: the peer is
     * allowed to cancel, and a RST_STREAM read in the same batch would have
     * ended it.  Writing the answer anyway would be frames for a stream that no
     * longer exists, which the peer answers by ending the connection.
     * \~spanish
     * El flujo puede haberse ido mientras trabajaba el manejador: el otro extremo
     * puede cancelar, y un RST_STREAM leido en la misma tanda lo habria acabado.
     * Escribir la respuesta igual serian tramas de un flujo que ya no existe, que
     * el otro extremo contesta terminando la conexion.
     * \~ */
    if (st == nullptr) {
        if (w != nullptr) drop_work(s, w);
        return true;
    }

    const uint8_t *bytes = res.bytes();
    const Span body = res.body();

    /* \~english
     * What goes out as content.  For HEAD, nothing: "the server MUST NOT send
     * content in the response" (RFC 9110, 9.3.2), whatever the handler wrote --
     * it answers HEAD as it answers GET, and that is how the fields come out
     * the same.  With no content the header block ends the stream and nothing
     * waits for a window.
     * \~spanish
     * Lo que sale como contenido.  Para HEAD, nada: "the server MUST NOT send
     * content in the response" (RFC 9110, 9.3.2), escribiera lo que escribiera
     * el manejador -- contesta a HEAD como a GET, y asi salen iguales las
     * cabeceras --.  Sin contenido el bloque de cabeceras acaba el flujo y nada
     * espera una ventana.
     * \~ */
    const size_t content = head ? 0 : body.len;
    const bool empty = content == 0;

    /* \~english
     * Whether the whole body can go right now, asked BEFORE a byte of the
     * answer is written.  What is left of a response that does not fit has to
     * outlive @c said_, which the next request reuses, so it needs somewhere to
     * live -- and finding out there is nowhere AFTER half a response has gone
     * out would mean resetting a stream the peer did nothing to deserve.
     *
     * \~spanish
     * Si el cuerpo entero puede salir ahora mismo, preguntado ANTES de escribir
     * un byte de la respuesta.  Lo que quede de una respuesta que no quepa tiene
     * que sobrevivir a @c said_, que reutiliza la peticion siguiente, asi que
     * necesita donde vivir -- y enterarse de que no hay sitio DESPUES de que haya
     * salido media respuesta seria abortar un flujo que el otro extremo no ha
     * hecho nada para merecer.
     * \~ */
    int64_t room = st->send.left();
    if (s.conn.send_window().left() < room) room = s.conn.send_window().left();

    const bool fits =
        empty || (room >= 0 && static_cast<uint64_t>(room) >= content);

    /* \~english
     * Nowhere to keep what does not fit.  The handler has already run, so this
     * is INTERNAL_ERROR and never REFUSED_STREAM: that one tells the client
     * nothing was processed and the request may simply be sent again (RFC 9113,
     * 8.7), and a request sent again after its handler ran is a POST done
     * twice.
     * \~spanish
     * No hay donde guardar lo que no cabe.  El manejador ya se ejecuto, asi que
     * esto es INTERNAL_ERROR y nunca REFUSED_STREAM: ese le dice al cliente que
     * no se proceso nada y que puede volver a mandar la peticion tal cual (RFC
     * 9113, 8.7), y una peticion mandada otra vez despues de ejecutarse su
     * manejador es un POST hecho dos veces.
     * \~ */
    if (!fits && w == nullptr) {
        w = take_work(s, stream);
        if (w == nullptr)
            return send_reset(s, stream, h2::ErrorCode::InternalError, out);
    }

    /* \~english
     * The header block, from the fields @c wire_fields checked and lowered:
     * names in lower case (RFC 9113, 8.2), nothing connection-specific (8.2.2)
     * and no value HTTP forbids (8.2.1).  Secrets go never indexed, which asks
     * every hop on the way not to remember them (RFC 7541, 7.1.3); the rest
     * is written without indexing, which is never wrong.
     *
     * No `content-length` is added for a response with content, and that is
     * not an omission: in HTTP/2 the frames say where the body ends, so a
     * length here would be a second statement of the same fact -- and the
     * failure of two statements of one fact is that they disagree, which in a
     * response body is where one message ends inside another.  HEAD is the
     * exception, because there the frames say nothing: the length is the one
     * GET would have had, unless the handler said its own (RFC 9110, 9.3.2;
     * RFC 9113, 8.1.1 lets a response with no content carry it).
     *
     * \~spanish
     * El bloque de cabeceras, con las cabeceras que comprobo y bajo a
     * minusculas @c wire_fields: nombres en minusculas (RFC 9113, 8.2), nada
     * propio de la conexion (8.2.2) y ningun valor que HTTP prohiba (8.2.1).
     * Los secretos van como no indexables nunca, que le pide a cada salto del
     * camino que no los recuerde (RFC 7541, 7.1.3); el resto se escribe sin
     * indexar, que nunca esta mal.
     *
     * No se anade `content-length` a una respuesta con contenido, y no es un
     * olvido: en HTTP/2 las tramas dicen donde acaba el cuerpo, asi que una
     * longitud aqui seria una segunda afirmacion del mismo hecho -- y el modo de
     * fallar de dos afirmaciones de un hecho es que discrepen, que en un cuerpo
     * de respuesta es donde un mensaje acaba dentro de otro.  HEAD es la
     * excepcion, porque ahi las tramas no dicen nada: la longitud es la que
     * habria tenido GET, salvo que el manejador diga la suya (RFC 9110, 9.3.2;
     * RFC 9113, 8.1.1 deja que la lleve una respuesta sin contenido).
     * \~ */
    block_.clear();

    h2::hpack::Encoder &enc = s.conn.encoder();
    h2::hpack::WriteStatus ws = enc.write_status(block_, res.status());
    bool has_length = false;

    for (size_t i = 0; i < count && ws == h2::hpack::WriteStatus::Ok; ++i) {
        const WireField &f = lines_[i];
        const h2::hpack::Indexing how = field_is_secret(f.id)
                                            ? h2::hpack::Indexing::Never
                                            : h2::hpack::Indexing::WithoutIndexing;
        if (f.id == FieldId::ContentLength) has_length = true;

        if (f.id != FieldId::Unknown)
            ws = enc.write_field(block_, f.id, f.value, f.value_len, how);
        else
            ws = enc.write_field(block_, f.name, f.name_len, f.value,
                                 f.value_len, how);
    }

    if (head && !has_length && ws == h2::hpack::WriteStatus::Ok) {
        uint8_t digits[kContentLengthDigits];
        const size_t n = write_content_length(digits, body.len);
        ws = enc.write_field(block_, FieldId::ContentLength, digits, n);
    }

    /* \~english
     * A field that could not be stored ends the CONNECTION and not the stream.
     * The encoder says why in the header: a write that ran out of memory may
     * have left the peer's table out of step with this end's, and from then on
     * every index names a different field on a connection that keeps working.
     * \~spanish
     * Una cabecera que no se pudo guardar acaba la CONEXION y no el flujo.  El
     * codificador dice por que en su cabecera: una escritura que se quedo sin
     * memoria puede haber dejado la tabla del otro extremo desacompasada de la de
     * este, y a partir de ahi cada indice nombra otra cabecera en una conexion
     * que sigue funcionando.
     * \~ */
    if (ws == h2::hpack::WriteStatus::OutOfMemory) return false;

    if (ws != h2::hpack::WriteStatus::Ok) {
        if (w != nullptr) drop_work(s, w);
        return send_reset(s, stream, h2::ErrorCode::InternalError, out);
    }

    h2::HeaderFramer framer;
    IoList list;

    const h2::FrameError fe =
        framer.frame(list, stream, block_.data(), block_.size(),
                     s.conn.peer().max_frame_size, empty);

    /* \~english
     * A block too large to be written in one go is this server's own output
     * being unreasonable, not the peer's input: it takes more frames than one
     * write holds, which at the smallest legal frame size is a hundred and
     * twenty-eight kilobytes of COMPRESSED header.  It is said out loud and the
     * stream ends, because the alternative is half a header block on the wire
     * and a peer waiting for a CONTINUATION that is not coming.
     *
     * \~spanish
     * Un bloque demasiado grande para escribirlo de una vez es la salida de este
     * servidor pasandose, no la entrada del otro extremo: lleva mas tramas de las
     * que cabe una escritura, que al tamano de trama legal mas pequeno son ciento
     * veintiocho kilobytes de cabecera COMPRIMIDA.  Se dice en voz alta y el
     * flujo se acaba, porque la alternativa es medio bloque de cabeceras en el
     * cable y un extremo esperando una CONTINUATION que no va a llegar.
     * \~ */
    if (fe != h2::FrameError::Ok) {
        if (w != nullptr) drop_work(s, w);
        return send_reset(s, stream, h2::ErrorCode::InternalError, out);
    }

    if (!put_list(list, out)) return false;

    /* \~english
     * An empty body is over with the header block, which already carried
     * `END_STREAM`.  A zero-length DATA frame afterwards would be a second
     * ending for a stream that has one.
     * \~spanish
     * Un cuerpo vacio se acaba con el bloque de cabeceras, que ya llevaba
     * `END_STREAM`.  Una trama DATA de longitud cero detras seria un segundo
     * final de un flujo que ya tiene uno.
     * \~ */
    if (empty) {
        s.conn.streams().finish(stream);
        if (w != nullptr) drop_work(s, w);
        return true;
    }

    size_t at = 0;
    if (!push_body(s, stream, *st, bytes + body.off, content, at, out))
        return false;

    if (at == content) {
        if (!finish(s, stream, out)) return false;
        if (w != nullptr) drop_work(s, w);
        return true;
    }

    /* \~english
     * Something is left, so the windows were shut -- which is what @c fits said
     * and what the work was taken for.  If there is no work here, the belief
     * that the two agree was wrong, and it is said rather than assumed: a
     * remainder with nowhere to live would be a response silently cut short,
     * and a stream reset is at least a peer that knows.
     *
     * \~spanish
     * Queda algo, asi que las ventanas estaban cerradas -- que es lo que dijo
     * @c fits y para lo que se cogio el trabajo --.  Si aqui no hay trabajo, la
     * creencia de que los dos coinciden era falsa, y se dice en vez de suponerse:
     * un resto sin donde vivir seria una respuesta cortada en silencio, y un
     * flujo abortado es al menos un extremo que se entera.
     * \~ */
    if (w == nullptr) return send_reset(s, stream, h2::ErrorCode::InternalError, out);

    Buffer *keep = bodies_.at(w->buffer);
    if (keep == nullptr) return false;

    keep->clear();

    const size_t left = content - at;
    uint8_t *place = keep->reserve(left);
    if (place == nullptr) return false;

    util::vesta_memcpy(place, bytes + body.off + at, left);
    keep->commit(left);

    w->stream = stream;
    w->sent = 0;
    w->head_size = 0;
    w->answering = true;

    return true;
}

bool Http2Service::refuse(State &s, uint32_t stream, StatusCode status, Work *w,
                          Buffer &out) noexcept {
    ResponseBuilder res(said_);
    res.status(status);

    if (!deliver(s, stream, res, 0, false, w, out)) return false;

    /* \~english
     * And a peer still sending is asked to stop.  A refusal answered while a
     * body is still arriving leaves the client uploading megabytes to a stream
     * that has already been told no, and RST_STREAM with NO_ERROR after a
     * complete response is exactly the way to say so -- it ends the request
     * without saying the response was wrong (RFC 9113, 8.1).
     *
     * Only then.  The answer carried END_STREAM, so a stream still in the table
     * is one the peer has not finished (half-closed local).  One that is gone
     * was already over -- the request had ended, or the peer or @c deliver
     * reset it -- and it is closed: "an endpoint MUST NOT send frames other
     * than PRIORITY on a closed stream" (RFC 9113, 5.1).
     *
     * \~spanish
     * Y a un extremo que sigue mandando se le pide que pare.  Un rechazo
     * contestado mientras todavia llega un cuerpo deja al cliente subiendo
     * megabytes a un flujo al que ya se le ha dicho que no, y un RST_STREAM con
     * NO_ERROR detras de una respuesta completa es justamente la forma de
     * decirlo: acaba la peticion sin decir que la respuesta estuviera mal (RFC
     * 9113, 8.1).
     *
     * Solo entonces.  La respuesta llevaba END_STREAM, asi que un flujo que
     * sigue en la tabla es uno que el otro no ha acabado (semicerrado local).
     * Uno que ya no esta estaba acabado -- la peticion habia terminado, o lo
     * reinicio el otro o @c deliver -- y esta cerrado: "an endpoint MUST NOT
     * send frames other than PRIORITY on a closed stream" (RFC 9113, 5.1).
     * \~ */
    if (s.conn.streams().find(stream) == nullptr) return true;
    return send_reset(s, stream, h2::ErrorCode::NoError, out);
}

bool Http2Service::add_trailers(State &s, Work &w, Buffer &keep) noexcept {
    /* \~english
     * The trailers were read into the connection's decoding slot, emptied
     * before the read, so everything in it is theirs.  The bytes go after the
     * body, which is already whole -- the trailers ended the stream -- and the
     * fields are moved over by the distance they travelled, so that one base
     * serves the head, the body and the trailers alike.
     * \~spanish
     * Los remolques se leyeron en la ranura de descodificacion de la conexion,
     * vaciada antes de la lectura, asi que todo lo que hay en ella es suyo.  Los
     * bytes van detras del cuerpo, que ya esta entero -- los remolques acabaron
     * el flujo --, y los campos se desplazan lo que se movieron, para que una
     * base sirva igual a la cabecera, al cuerpo y a los remolques.
     * \~ */
    const size_t base = keep.size();
    const size_t n = s.headers.size();

    if (n != 0) {
        uint8_t *room = keep.reserve(n);
        if (room == nullptr) return false;
        util::vesta_memcpy(room, s.headers.data(), n);
        keep.commit(n);
    }

    for (const Field *f = s.req.fields.begin(); f != s.req.fields.end(); ++f) {
        Field moved = *f;
        moved.name_off += static_cast<uint32_t>(base);
        moved.value_off += static_cast<uint32_t>(base);
        w.req.fields.add(moved);
    }

    return true;
}

bool Http2Service::answer(State &s, uint32_t stream, const Request &req,
                          const uint8_t *head, const uint8_t *body, size_t n,
                          Work *w, Buffer &out) noexcept {
    ResponseBuilder res(said_);
    handler_->handle(req, head, body, n, res);

    ++served_;

    /* \~english
     * A handler that could not say what it meant gets a `500` written for it,
     * and the difference matters: the request was understood and this end
     * failed, which is not the same thing as refusing the request.  So does
     * one that said something HTTP/2 cannot carry as written -- a
     * connection-specific field, a name that is not a token, a value with CR
     * or LF: changing the answer quietly would send what the handler did not
     * write, and dropping the field would hide the fault.  The rule is the
     * one HTTP/3 applies, from the same function (response_lines.h), and the
     * count says it happened.
     * \~spanish
     * A un manejador que no pudo decir lo que queria se le escribe un `500`, y la
     * diferencia importa: la peticion se entendio y este extremo fallo, que no es
     * lo mismo que rechazar la peticion.  Igual a uno que dijo algo que HTTP/2 no
     * puede llevar tal cual -- un campo propio de la conexion, un nombre que no
     * es un token, un valor con CR o LF --: cambiar la respuesta por lo bajo
     * mandaria lo que el manejador no escribio, y tirar la cabecera esconderia
     * el fallo.  La regla es la que aplica HTTP/3, de la misma funcion
     * (response_lines.h), y la cuenta dice que paso.
     * \~ */
    size_t count = 0;
    const char *bad = res.failed() ? "the handler could not build its answer"
                                   : wire_fields(res, names_, lines_, kMostFields, count);
    if (bad != nullptr) {
        ++bad_answers_;
        last_bad_answer_ = bad;
        return refuse(s, stream, status::kInternalServerError, w, out);
    }

    return deliver(s, stream, res, count, req.method == MethodId::Head, w, out);
}

} // namespace http_vx
