/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service.cpp
 * @brief
 * \~english Turning a connection's frames into requests, and answers into frames.
 * \~spanish Convertir las tramas de una conexion en peticiones, y las respuestas en tramas.
 * \~
 */

#include "http_vx/http2_service.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <new>
#include <utility>

namespace http_vx {

Http2Service::~Http2Service() { release(); }

void Http2Service::release() noexcept {
    if (state_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) state_[i].~State();
        util::host_free(state_);
        state_ = nullptr;
    }
    capacity_ = 0;

    if (works_ != nullptr) {
        for (uint32_t i = 0; i < work_count_; ++i) works_[i].~Work();
        util::host_free(works_);
        works_ = nullptr;
    }
    work_count_ = 0;
    free_work_ = kNoWork;
    in_hand_ = 0;

    bodies_.release_all();
    said_.release();
    block_.release();
}

bool Http2Service::reset(uint32_t connections, uint32_t requests,
                         size_t max_body, Handler &handler,
                         const h2::Limits &limits) noexcept {
    release();

    if (connections == 0 || requests == 0) return false;

    handler_ = &handler;
    limits_ = limits;
    max_body_ = max_body;
    served_ = 0;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    state_ = static_cast<State *>(
        util::host_alloc(static_cast<size_t>(connections) * sizeof(State)));
    if (state_ == nullptr) return false;

    capacity_ = connections;
    for (uint32_t i = 0; i < capacity_; ++i) {
        new (&state_[i]) State();
        state_[i].works = kNoWork;
    }

    works_ = static_cast<Work *>(
        util::host_alloc(static_cast<size_t>(requests) * sizeof(Work)));
    if (works_ == nullptr) {
        release();
        return false;
    }

    work_count_ = requests;
    for (uint32_t i = 0; i < work_count_; ++i) {
        new (&works_[i]) Work();
        works_[i].buffer = kNoBuffer;
        works_[i].next = i + 1 == work_count_ ? kNoWork : i + 1;
    }
    free_work_ = 0;

    /* \~english
     * One buffer per piece of work and no more, because a piece of work holds
     * exactly one for exactly as long as it exists.  Two pools of the same size
     * rather than one structure holding both, so that the buffer's own rule --
     * a buffer that grew past the ceiling gives its memory back instead of
     * being kept -- goes on applying without being written a second time.
     *
     * \~spanish
     * Un buffer por trabajo y ninguno mas, porque un trabajo tiene exactamente
     * uno exactamente mientras existe.  Dos pozos del mismo tamano en vez de una
     * estructura con las dos cosas, para que la regla propia del buffer -- uno
     * que crecio por encima del techo devuelve su memoria en vez de quedarse --
     * siga valiendo sin escribirla otra vez.
     *
     * \~english
     * The ceiling is the ordinary buffer size and not the body limit on
     * purpose: one large upload makes one buffer large, and a pool that kept it
     * would let every slot creep up to the biggest thing that ever went through
     * it -- so the memory would converge on the peak times the count, on a
     * server that never looked like it was leaking.
     *
     * \~spanish
     * El techo es el tamano corriente de un buffer y no el limite de cuerpo a
     * proposito: una subida grande hace grande un buffer, y un pozo que se lo
     * quedara dejaria que todas las plazas subieran hasta lo mas grande que haya
     * pasado por ellas -- asi que la memoria tenderia al pico por el numero, en un
     * servidor que no pareceria tener ninguna fuga.
     * \~ */
    if (!bodies_.reset(requests, kBufferInitialCapacity)) {
        release();
        return false;
    }

    return true;
}

void Http2Service::on_open(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    State &s = state_[c.slot];

    /* \~english
     * The connection's opening SETTINGS is written here and goes out on the
     * first flush, which is the first time there are bytes to answer.  Nothing
     * is lost by that: a client sends its preface the moment it connects, so
     * the first read always comes before the first byte of a request -- and
     * this layer has no socket of its own to write to anyway.
     * \~spanish
     * El SETTINGS de apertura de la conexion se escribe aqui y sale en el primer
     * vaciado, que es la primera vez que hay bytes que contestar.  Con eso no se
     * pierde nada: un cliente manda su preambulo en cuanto se conecta, asi que la
     * primera lectura llega siempre antes del primer byte de una peticion -- y
     * esta capa no tiene ningun socket propio en el que escribir.
     * \~ */
    s.conn.reset(limits_);
    s.headers.recycle();
    s.req.clear();
    s.works = kNoWork;
}

void Http2Service::on_close(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    State &s = state_[c.slot];

    /* \~english
     * Everything this connection was in the middle of goes back to the pools.
     * A request whose answer never finished is not an error to report here --
     * the connection is gone and there is nobody to report it to -- but its
     * buffer is one that another connection is waiting for.
     * \~spanish
     * Todo lo que esta conexion tuviera a medias vuelve a los pozos.  Una
     * peticion cuya respuesta no acabo no es un error del que informar aqui -- la
     * conexion se fue y no hay a quien -- pero su buffer es uno que esta
     * esperando otra conexion.
     * \~ */
    while (s.works != kNoWork) drop_work(s, &works_[s.works]);

    s.conn.release();
    s.headers.release();
    s.req.clear();
}

Http2Service::Work *Http2Service::take_work(State &s,
                                            uint32_t stream) noexcept {
    if (free_work_ == kNoWork) return nullptr;

    const uint32_t buffer = bodies_.acquire();
    if (buffer == kNoBuffer) return nullptr;

    const uint32_t i = free_work_;
    Work *w = &works_[i];
    free_work_ = w->next;

    w->req.clear();
    w->buffer = buffer;
    w->stream = stream;
    w->head_size = 0;
    w->sent = 0;
    w->answering = false;

    w->next = s.works;
    s.works = i;
    ++in_hand_;

    return w;
}

void Http2Service::drop_work(State &s, Work *w) noexcept {
    const uint32_t i = static_cast<uint32_t>(w - works_);

    /* \~english
     * Unlinked by walking, because a connection's list is short -- one entry in
     * the ordinary case and never more than the pool -- and a doubly linked one
     * would be two more fields kept in step for a walk of two.
     * \~spanish
     * Se desenlaza recorriendo, porque la lista de una conexion es corta -- una
     * entrada en el caso corriente y nunca mas que el pozo -- y una doblemente
     * enlazada serian dos campos mas que mantener de acuerdo para un recorrido de
     * dos.
     * \~ */
    if (s.works == i) {
        s.works = w->next;
    } else {
        uint32_t at = s.works;
        while (at != kNoWork && works_[at].next != i) at = works_[at].next;
        if (at != kNoWork) works_[at].next = w->next;
    }

    if (w->buffer != kNoBuffer) bodies_.release(w->buffer);
    w->buffer = kNoBuffer;
    w->stream = 0;
    w->answering = false;
    w->req.clear();

    w->next = free_work_;
    free_work_ = i;
    --in_hand_;
}

Http2Service::Work *Http2Service::find_work(State &s,
                                            uint32_t stream) noexcept {
    for (uint32_t i = s.works; i != kNoWork; i = works_[i].next)
        if (works_[i].stream == stream) return &works_[i];
    return nullptr;
}

bool Http2Service::flush_control(State &s, Buffer &out) noexcept {
    const size_t n = s.conn.pending_size();
    if (n == 0) return true;

    uint8_t *room = out.reserve(n);
    if (room == nullptr) return false;

    util::vesta_memcpy(room, s.conn.pending(), n);
    out.commit(n);
    s.conn.flushed(n);
    return true;
}

bool Http2Service::put_list(const IoList &list, Buffer &out) noexcept {
    const size_t n = list.total();
    if (n == 0) return true;

    /* \~english
     * And here is the copy R14 exists to avoid.  The writer produced a list of
     * places precisely so that a head and a body in different memory could go
     * out as one scatter write, and this gathers them into one buffer instead
     * -- because what is on the other side today is a @c Buffer and not a
     * socket.
     *
     * It is written as one reservation and a run of copies, so that the day the
     * accepting backend lands there is one function to change and not a habit
     * spread over a file.  HVX-4 says the scatter path is missing; this is
     * where the missing shows.
     *
     * \~spanish
     * Y aqui esta la copia que la R14 existe para evitar.  El escritor produjo
     * una lista de sitios justamente para que una cabeza y un cuerpo en memorias
     * distintas salieran como una escritura dispersa, y esto los junta en un
     * buffer -- porque lo que hay hoy al otro lado es un @c Buffer y no un
     * socket.
     *
     * Se escribe como una reserva y una tirada de copias, para que el dia que
     * llegue el backend que acepta conexiones haya una funcion que cambiar y no
     * una costumbre repartida por un fichero.  El HVX-4 dice que falta el camino
     * disperso; aqui es donde se ve que falta.
     * \~ */
    uint8_t *room = out.reserve(n);
    if (room == nullptr) return false;

    size_t at = 0;
    for (size_t i = 0; i < list.count(); ++i) {
        util::vesta_memcpy(room + at, list.slices()[i].data,
                           list.slices()[i].len);
        at += list.slices()[i].len;
    }

    out.commit(n);
    return true;
}

bool Http2Service::push_body(State &s, uint32_t stream, h2::Stream &st,
                             const uint8_t *p, size_t n, size_t &at,
                             Buffer &out) noexcept {
    while (at < n) {
        IoList list;
        uint8_t head[h2::kFrameHeaderSize];
        size_t sent = 0;

        const h2::FrameError fe = h2::frame_body(
            list, head, stream, p + at, n - at, s.conn.peer().max_frame_size,
            st.send, s.conn.send_window(), sent);

        /* \~english
         * Anything but @c Ok means nothing went out and nothing was spent, so
         * stopping here leaves the answer exactly where it was.  The ordinary
         * reason is @c WouldBlock, which is not a failure at all: it is the
         * peer saying "wait", and what waits is the rest of this body.
         * \~spanish
         * Cualquier cosa que no sea @c Ok quiere decir que no salio nada y no se
         * gasto nada, asi que parar aqui deja la respuesta exactamente donde
         * estaba.  La razon corriente es @c WouldBlock, que no es ningun fallo: es
         * el otro extremo diciendo "espera", y lo que espera es el resto de este
         * cuerpo.
         * \~ */
        if (fe != h2::FrameError::Ok) break;

        if (!put_list(list, out)) return false;
        at += sent;
    }

    return true;
}

bool Http2Service::finish(State &s, uint32_t stream, Buffer &out) noexcept {
    IoList list;
    uint8_t head[h2::kFrameHeaderSize];

    if (!h2::frame_end_of_body(list, head, stream)) return false;
    if (!put_list(list, out)) return false;

    s.conn.streams().finish(stream);
    return true;
}

bool Http2Service::deliver(State &s, uint32_t stream,
                           const ResponseBuilder &res, Work *w,
                           Buffer &out) noexcept {
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
    const bool empty = body.len == 0;

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
        empty || (room >= 0 && static_cast<uint64_t>(room) >= body.len);

    if (!fits && w == nullptr) {
        w = take_work(s, stream);
        if (w == nullptr) {
            s.conn.reset_stream(stream, h2::ErrorCode::RefusedStream);
            return true;
        }
    }

    /* \~english
     * The header block.  No `content-length` is written, and that is not an
     * omission: in HTTP/2 the frames say where the body ends, so a length here
     * would be a second statement of the same fact -- and the failure of two
     * statements of one fact is that they disagree, which in a response body is
     * where one message ends inside another.
     *
     * \~spanish
     * El bloque de cabeceras.  No se escribe `content-length`, y no es un olvido:
     * en HTTP/2 las tramas dicen donde acaba el cuerpo, asi que una longitud aqui
     * seria una segunda afirmacion del mismo hecho -- y el modo de fallar de dos
     * afirmaciones de un hecho es que discrepen, que en un cuerpo de respuesta es
     * donde un mensaje acaba dentro de otro.
     * \~ */
    block_.clear();

    h2::hpack::Encoder &enc = s.conn.encoder();
    h2::hpack::WriteStatus ws = enc.write_status(block_, res.status());

    for (const Field *f = res.fields().begin();
         f != res.fields().end() && ws == h2::hpack::WriteStatus::Ok; ++f) {
        const uint8_t *value = bytes + f->value_off;

        if (f->id != FieldId::Unknown)
            ws = enc.write_field(block_, f->id, value, f->value_len);
        else
            ws = enc.write_field(block_, bytes + f->name_off, f->name_len,
                                 value, f->value_len);
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
        s.conn.reset_stream(stream, h2::ErrorCode::InternalError);
        if (w != nullptr) drop_work(s, w);
        return true;
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
        s.conn.reset_stream(stream, h2::ErrorCode::InternalError);
        if (w != nullptr) drop_work(s, w);
        return true;
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
    if (!push_body(s, stream, *st, bytes + body.off, body.len, at, out))
        return false;

    if (at == body.len) {
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
    if (w == nullptr) {
        s.conn.reset_stream(stream, h2::ErrorCode::InternalError);
        return true;
    }

    Buffer *keep = bodies_.at(w->buffer);
    if (keep == nullptr) return false;

    keep->clear();

    const size_t left = body.len - at;
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

bool Http2Service::resume(State &s, Work *w, Buffer &out) noexcept {
    h2::Stream *st = s.conn.streams().find(w->stream);
    if (st == nullptr) {
        drop_work(s, w);
        return true;
    }

    Buffer *keep = bodies_.at(w->buffer);
    if (keep == nullptr) return false;

    if (!push_body(s, w->stream, *st, keep->data(), keep->size(), w->sent, out))
        return false;

    if (w->sent < keep->size()) return true;

    if (!finish(s, w->stream, out)) return false;
    drop_work(s, w);
    return true;
}

bool Http2Service::drain(State &s, Buffer &out) noexcept {
    uint32_t i = s.works;

    while (i != kNoWork) {
        Work *w = &works_[i];

        /* \~english
         * Where it goes next is read BEFORE the work may be given back, because
         * a work that finishes is unlinked and its @c next becomes the free
         * list's -- which would carry this walk into somebody else's.
         * \~spanish
         * Donde sigue se lee ANTES de que el trabajo pueda devolverse, porque uno
         * que acaba se desenlaza y su @c next pasa a ser el de la lista de libres
         * -- que llevaria este recorrido a la de otro.
         * \~ */
        const uint32_t next = w->next;

        if (w->answering && !resume(s, w, out)) return false;

        i = next;
    }

    return true;
}

bool Http2Service::refuse(State &s, uint32_t stream, StatusCode status, Work *w,
                          Buffer &out) noexcept {
    ResponseBuilder res(said_);
    res.status(status);

    if (!deliver(s, stream, res, w, out)) return false;

    /* \~english
     * And the peer is asked to stop sending.  A refusal answered while a body
     * is still arriving leaves the client uploading megabytes to a stream that
     * has already been told no, and RST_STREAM with NO_ERROR after a complete
     * response is exactly the way to say so -- it ends the request without
     * saying the response was wrong.
     * \~spanish
     * Y se le pide al otro extremo que deje de mandar.  Un rechazo contestado
     * mientras todavia llega un cuerpo deja al cliente subiendo megabytes a un
     * flujo al que ya se le ha dicho que no, y un RST_STREAM con NO_ERROR detras
     * de una respuesta completa es justamente la forma de decirlo: acaba la
     * peticion sin decir que la respuesta estuviera mal.
     * \~ */
    s.conn.reset_stream(stream, h2::ErrorCode::NoError);
    return true;
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
     * failed, which is not the same thing as refusing the request.
     * \~spanish
     * A un manejador que no pudo decir lo que queria se le escribe un `500`, y la
     * diferencia importa: la peticion se entendio y este extremo fallo, que no es
     * lo mismo que rechazar la peticion.
     * \~ */
    if (res.failed()) return refuse(s, stream, 500, w, out);

    return deliver(s, stream, res, w, out);
}

bool Http2Service::on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept {
    if (c.slot >= capacity_ || handler_ == nullptr) return false;

    State &s = state_[c.slot];
    bool alive = true;

    /* \~english
     * One event at a time until there are no more, and the answers are moved
     * out between them.  Moving them out is not tidiness: the connection reads
     * nothing it cannot answer, so a read that left the control buffer full
     * would stop reading frames that are already here.
     * \~spanish
     * Un suceso cada vez hasta que no haya mas, y las respuestas se sacan entre
     * medias.  Sacarlas no es limpieza: la conexion no lee nada que no pueda
     * contestar, asi que una lectura que dejara lleno el buffer de control
     * dejaria de leer tramas que ya estan aqui.
     * \~ */
    for (;;) {
        if (!flush_control(s, out)) return false;

        const uint64_t was = s.conn.consumed();

        /* \~english
         * The slot is emptied before every read, because a trailer section is
         * ADDED to what it holds rather than replacing it.  A head empties it
         * anyway; trailers must find nothing there but what they bring, or
         * they would carry along the fields of whatever request was read last.
         * \~spanish
         * La ranura se vacia antes de cada lectura, porque una seccion de
         * remolques se ANADE a lo que tenga en vez de sustituirlo.  Una cabecera
         * la vacia igual; los remolques no pueden encontrar ahi mas que lo que
         * traen, o arrastrarian los campos de la ultima peticion leida.
         * \~ */
        s.headers.clear();
        s.req.clear();
        const h2::Event e = s.conn.read(in.view(), s.headers, s.req);

        /* \~english
         * @c None does not mean there is nothing left, and reading it as if it
         * did stops the connection dead.  Most of HTTP/2 is answering things,
         * and a SETTINGS acknowledged, a PING echoed or a frame discarded are
         * all whole frames dealt with that have nothing to tell a caller -- so
         * what says whether to go round again is not the event, it is whether a
         * frame WENT.
         *
         * The first version of this loop broke on @c None, and what it produced
         * was a server that answered a client's opening SETTINGS and then never
         * looked at the request behind it.
         *
         * \~spanish
         * @c None no quiere decir que no quede nada, y leerlo como si lo dijera
         * para la conexion en seco.  Casi todo HTTP/2 es contestar cosas, y un
         * SETTINGS confirmado, un PING devuelto o una trama descartada son tramas
         * enteras atendidas que no tienen nada que contarle a quien llama -- asi
         * que lo que dice si hay que dar otra vuelta no es el suceso, es si se fue
         * una trama.
         *
         * La primera version de este bucle cortaba con @c None, y lo que producia
         * era un servidor que contestaba al SETTINGS de apertura de un cliente y
         * ya no volvia a mirar la peticion que venia detras.
         * \~ */
        if (e.kind == h2::EventKind::None) {
            if (s.conn.consumed() == was) break;
            continue;
        }

        if (e.kind == h2::EventKind::Closed) {
            alive = false;
            break;
        }

        if (e.kind == h2::EventKind::StreamEnded) {
            Work *w = find_work(s, e.stream_id);
            if (w != nullptr) drop_work(s, w);
            continue;
        }

        if (e.kind == h2::EventKind::Request) {
            /* \~english
             * A request that is already whole is answered where it stands, out
             * of the connection's own decoding slot.  Nothing is copied and
             * nothing is kept: this is the `GET`, which is most of them.
             * \~spanish
             * Una peticion que ya esta entera se contesta donde esta, de la propia
             * ranura de descodificacion de la conexion.  No se copia nada ni se
             * guarda nada: este es el `GET`, que son la mayoria.
             * \~ */
            if (e.ends) {
                if (!answer(s, e.stream_id, s.req, s.headers.data(), nullptr, 0,
                            nullptr, out))
                    return false;
                continue;
            }

            /* \~english
             * One that is waiting for a body has to move out of that slot, and
             * this is the reason the slot cannot simply be kept: the next
             * header block on this connection is for ANOTHER stream, and it
             * overwrites both the names and the request built from them.  The
             * bytes move by swapping the whole buffer with an empty one, which
             * costs three pointers; the request is copied, which is the one
             * copy a body costs before its first byte arrives.
             *
             * \~spanish
             * Una que espera un cuerpo tiene que salir de esa ranura, y esta es la
             * razon de que la ranura no se pueda guardar sin mas: el bloque de
             * cabeceras siguiente de esta conexion es de OTRO flujo, y pisa tanto
             * los nombres como la peticion construida con ellos.  Los bytes se
             * mudan intercambiando el buffer entero por uno vacio, que cuesta tres
             * punteros; la peticion se copia, que es la unica copia que cuesta un
             * cuerpo antes de que llegue su primer byte.
             * \~ */
            Work *w = take_work(s, e.stream_id);
            if (w == nullptr) {
                s.conn.reset_stream(e.stream_id, h2::ErrorCode::RefusedStream);
                continue;
            }

            Buffer *keep = bodies_.at(w->buffer);
            if (keep == nullptr) return false;

            std::swap(s.headers, *keep);
            w->req = s.req;
            w->head_size = keep->size();
            continue;
        }

        if (e.kind == h2::EventKind::Trailers) {
            /* \~english
             * The trailer section ends the request (RFC 9113, 8.1), so this is
             * where a body that was waiting for more is answered.  The same
             * refusal as a body frame for a stream nothing is gathering for.
             * \~spanish
             * La seccion de remolques acaba la peticion (RFC 9113, 8.1), asi que
             * aqui se contesta un cuerpo que estaba esperando mas.  El mismo
             * rechazo que una trama de cuerpo de un flujo para el que no se
             * junta nada.
             * \~ */
            Work *w = find_work(s, e.stream_id);
            if (w == nullptr || w->answering) {
                s.conn.reset_stream(e.stream_id, h2::ErrorCode::StreamClosed);
                continue;
            }

            Buffer *keep = bodies_.at(w->buffer);
            if (keep == nullptr) return false;

            // \~english The body is measured BEFORE the trailers go after it.
            // \~spanish El cuerpo se mide ANTES de que los remolques vayan detras.  \~
            const size_t n = keep->size() - w->head_size;
            if (!add_trailers(s, *w, *keep)) return false;

            if (!answer(s, e.stream_id, w->req, keep->data(),
                        n == 0 ? nullptr : keep->data() + w->head_size, n, w,
                        out))
                return false;
            continue;
        }

        /* \~english
         * Body bytes.  A stream nothing is gathering for is one that was
         * refused or has already been answered, and the peer is told rather
         * than ignored: bytes sent to a stream that is over are bytes it will
         * go on sending until somebody says otherwise.
         * \~spanish
         * Bytes de cuerpo.  Un flujo para el que no se esta juntando nada es uno
         * que se rechazo o al que ya se contesto, y al otro extremo se le dice en
         * vez de ignorarlo: los bytes mandados a un flujo terminado son bytes que
         * va a seguir mandando hasta que alguien diga lo contrario.
         * \~ */
        Work *w = find_work(s, e.stream_id);
        if (w == nullptr || w->answering) {
            s.conn.reset_stream(e.stream_id, h2::ErrorCode::StreamClosed);
            continue;
        }

        Buffer *keep = bodies_.at(w->buffer);
        if (keep == nullptr) return false;

        const size_t have = keep->size() - w->head_size;

        /* \~english
         * A body larger than this server takes is refused, and the allowance
         * for the frame that crossed the line goes back first.  The stream is
         * about to be told to stop and will not be credited after that, so
         * skipping it here would lose the connection a little window for every
         * upload anybody ever tried -- and losing enough of it stops the
         * connection with nothing to point at.
         * \~spanish
         * Un cuerpo mayor de lo que acepta este servidor se rechaza, y el credito
         * de la trama que paso de la raya se devuelve antes.  Al flujo se le va a
         * decir que pare y despues de eso no se le abona nada, asi que saltarselo
         * aqui le costaria a la conexion un poco de ventana por cada subida que
         * intentara nadie -- y perder bastante para la conexion sin nada a lo que
         * senalar.
         * \~ */
        if (have + e.size > max_body_) {
            s.conn.release_window(e.stream_id, static_cast<uint32_t>(e.size));
            if (!refuse(s, e.stream_id, 413, w, out)) return false;
            continue;
        }

        /* \~english
         * **A body that arrived in one frame is never copied.**  It is whole
         * and contiguous where the connection read it, so the handler is given
         * a view of it -- R13 -- and the only thing kept from the header block
         * is the block itself, which was already moved.
         *
         * A body the peer SPLIT is a different matter: its pieces are nine
         * bytes of framing apart and may have another stream's request between
         * them, so they are joined as they arrive.  The copy is paid by the
         * connection that asked for it, which is the same bargain a header
         * block split across CONTINUATIONs makes.
         *
         * \~spanish
         * **Un cuerpo que llego en una sola trama no se copia nunca.**  Esta
         * entero y seguido donde lo leyo la conexion, asi que al manejador se le
         * da una vista de el -- R13 -- y lo unico que se guarda del bloque de
         * cabeceras es el bloque mismo, que ya se mudo.
         *
         * Un cuerpo que el otro extremo PARTIO es otra cosa: sus pedazos estan a
         * nueve bytes de troceado unos de otros y pueden llevar en medio la
         * peticion de otro flujo, asi que se juntan segun llegan.  La copia la
         * paga la conexion que la pidio, que es el mismo trato que hace un bloque
         * de cabeceras partido en CONTINUATIONs.
         * \~ */
        if (e.ends && have == 0) {
            if (!answer(s, e.stream_id, w->req, keep->data(), e.data, e.size, w,
                        out))
                return false;

            /* \~english
             * And the window goes back AFTER the handler, not when the bytes
             * arrived.  Giving it back on arrival says "keep sending" to a peer
             * whose data is piling up unread; giving it back here says it to
             * one whose data has been dealt with.
             * \~spanish
             * Y la ventana se devuelve DESPUES del manejador, no cuando llegaron
             * los bytes.  Devolverla al llegar le dice "sigue mandando" a un
             * extremo cuyos datos se amontonan sin leer; devolverla aqui se lo dice
             * a uno cuyos datos ya se han atendido.
             * \~ */
            s.conn.release_window(e.stream_id, static_cast<uint32_t>(e.size));
            continue;
        }

        if (e.size != 0) {
            uint8_t *room = keep->reserve(e.size);
            if (room == nullptr) return false;

            util::vesta_memcpy(room, e.data, e.size);
            keep->commit(e.size);

            s.conn.release_window(e.stream_id, static_cast<uint32_t>(e.size));
        }

        if (!e.ends) continue;

        const size_t n = keep->size() - w->head_size;

        if (!answer(s, e.stream_id, w->req, keep->data(),
                    n == 0 ? nullptr : keep->data() + w->head_size, n, w, out))
            return false;
    }

    if (!flush_control(s, out)) return false;

    /* \~english
     * And every answer that was waiting on a window is tried again, because a
     * WINDOW_UPDATE read in this batch is exactly the event that unblocks one
     * -- and nothing else is going to come and ask.
     * \~spanish
     * Y se vuelve a intentar cada respuesta que estuviera esperando una ventana,
     * porque un WINDOW_UPDATE leido en esta tanda es justo el suceso que
     * desbloquea una -- y no va a venir nadie mas a preguntar.
     * \~ */
    if (!drain(s, out)) return false;
    if (!flush_control(s, out)) return false;

    const uint64_t done = s.conn.consumed();
    if (done > in.origin()) in.consume(static_cast<size_t>(done - in.origin()));

    return alive;
}

} // namespace http_vx
