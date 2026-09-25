/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/service.cpp
 * @brief
 * \~english Turning a connection's bytes into requests, and answers into bytes.
 * \~spanish Convertir los bytes de una conexion en peticiones, y las respuestas en bytes.
 * \~
 */

#include "http_vx/http1_service.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <new>

namespace http_vx {

Handler::~Handler() = default;

Http1Service::~Http1Service() { release(); }

void Http1Service::release() noexcept {
    if (state_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) state_[i].~State();
        util::host_free(state_);
        state_ = nullptr;
    }
    capacity_ = 0;
    said_.release();
    writer_.release();
}

bool Http1Service::reset(uint32_t connections, Handler &handler,
                         const h1::Limits &limits) noexcept {
    release();

    if (connections == 0) return false;

    handler_ = &handler;
    limits_ = limits;
    served_ = 0;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    state_ = static_cast<State *>(
        util::host_alloc(static_cast<size_t>(connections) * sizeof(State)));
    if (state_ == nullptr) return false;

    capacity_ = connections;
    for (uint32_t i = 0; i < capacity_; ++i) new (&state_[i]) State();

    return true;
}

void Http1Service::on_open(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    State &s = state_[c.slot];
    s.parser = h1::RequestParser(limits_);
    s.req = Request();
    s.left = 0;
    s.head_size = 0;
    s.decoded = 0;
    s.phase = Phase::Head;
    s.keep_alive = true;
}

void Http1Service::on_close(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    /* \~english
     * The parser is reset on the way OUT as well as on the way in.  A
     * connection that left mid-message would otherwise leave its half behind
     * for whoever takes the slot next -- and that one would start reading a
     * message it never received.  Doing it in both places is not the belt and
     * braces the buffer pool was told off for: this one is about a slot being
     * reused, and the open is about a slot being used for the first time.
     * \~spanish
     * El analizador se reinicia tambien al SALIR, no solo al entrar.  Una
     * conexion que se fuera a mitad de mensaje dejaria si no su mitad para quien
     * coja la casilla despues -- y ese empezaria leyendo un mensaje que no
     * recibio nunca --.  Hacerlo en los dos sitios no es el cinturon y tirantes
     * por el que se rino al pozo de buffers: este va de una casilla que se
     * reutiliza, y el de abrir va de una casilla que se usa por primera vez.
     * \~ */
    State &s = state_[c.slot];
    s.parser.reset();
    s.phase = Phase::Head;
    s.left = 0;
    s.decoded = 0;
}

bool Http1Service::flush(h1::ResponseWriter &w, Buffer &out) noexcept {
    const size_t n = w.head_size();
    if (n == 0) return true;

    uint8_t *room = out.reserve(n);
    if (room == nullptr) return false;

    util::vesta_memcpy(room, w.head(), n);
    out.commit(n);
    return true;
}

bool Http1Service::render(const ResponseBuilder &res, const Request &req,
                          bool keep_alive, Buffer &out) noexcept {
    if (res.failed()) return refuse(500, out);

    h1::ResponseWriter &w = writer_;
    w.begin(req.version, res.status(), req.method, keep_alive);

    const uint8_t *bytes = res.bytes();

    for (const Field *f = res.fields().begin(); f != res.fields().end(); ++f) {
        const char *value = reinterpret_cast<const char *>(bytes + f->value_off);

        /* \~english
         * A field the project knows is written by its identifier, so the one
         * table that says how a name is spelled is the one that spells it.  A
         * field it does not is written by the letters the handler gave -- and
         * those are the letters, because nobody else has any.
         * \~spanish
         * Una cabecera que el proyecto conoce se escribe por su identificador,
         * asi que la unica tabla que dice como se deletrea un nombre es la que
         * lo deletrea.  Una que no conoce se escribe con las letras que dio el
         * manejador -- y esas son las letras, porque no las tiene nadie mas.
         * \~ */
        if (f->id != FieldId::Unknown) {
            w.field(f->id, value, f->value_len);
        } else {
            w.field(reinterpret_cast<const char *>(bytes + f->name_off),
                    f->name_len, value, f->value_len);
        }
    }

    const Span b = res.body();

    /* \~english
     * The framing is decided from what there is, not asked of the handler.  A
     * handler that had to say how long its own body was would be a handler
     * that could say a number that did not match it -- and a response whose
     * length disagrees with its bytes is where one message ends inside
     * another.
     * \~spanish
     * El troceado se decide con lo que hay, no se le pregunta al manejador.  Un
     * manejador que tuviera que decir cuanto mide su propio cuerpo seria uno que
     * puede decir un numero que no cuadra -- y una respuesta cuya longitud
     * discrepa de sus bytes es donde un mensaje acaba dentro de otro.
     * \~ */
    w.finish(h1::ResponseBody::Length, b.len);

    if (b.len != 0) w.body(bytes + b.off, b.len);

    /* \~english
     * And the writer is NOT released.  Its memory is what answering the next
     * request would ask for again, and @c begin empties it -- so keeping it is
     * the whole of the saving and costs one buffer per service.
     * \~spanish
     * Y el escritor NO se libera.  Su memoria es la que volveria a pedir
     * contestar la peticion siguiente, y @c begin lo vacia -- asi que guardarlo es
     * todo el ahorro y cuesta un buffer por servicio.
     * \~ */
    return flush(w, out);
}

bool Http1Service::refuse(StatusCode status, Buffer &out) noexcept {
    /* \~english
     * A refusal is answered and then the connection ends.  Not answering at
     * all is worse than it looks: a client whose socket simply dies cannot
     * tell a bad request from a server that fell over, so it retries -- and a
     * request that is refused every time becomes a request that is sent every
     * time.
     * \~spanish
     * Un rechazo se contesta y despues la conexion se acaba.  No contestar nada
     * es peor de lo que parece: un cliente cuyo socket se muere sin mas no puede
     * distinguir una peticion mala de un servidor que se cayo, asi que
     * reintenta -- y una peticion que se rechaza siempre se convierte en una
     * peticion que se manda siempre.
     * \~ */
    h1::ResponseWriter &w = writer_;
    w.begin(Version::Http11, status, MethodId::Get, false);
    w.finish(h1::ResponseBody::Length, 0);
    flush(w, out);
    return false;
}

bool Http1Service::on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept {
    if (c.slot >= capacity_ || handler_ == nullptr) return false;

    State &s = state_[c.slot];

    /* \~english
     * As many whole messages as are here.  A client may pipeline -- send the
     * next request without waiting for the answer to this one -- so a read
     * that brought two requests has to produce two answers, and a service that
     * handled one and left the other would leave a request sitting in the
     * buffer that nothing would ever come back for.
     * \~spanish
     * Tantos mensajes enteros como haya.  Un cliente puede encadenar -- mandar
     * la peticion siguiente sin esperar la respuesta a esta -- asi que una
     * lectura que trajo dos peticiones tiene que producir dos respuestas, y un
     * servicio que atendiera una y dejara la otra dejaria una peticion en el
     * buffer a la que no volveria nadie.
     * \~ */
    for (;;) {
        if (in.empty()) return true;

        if (s.phase == Phase::Head) {
            const h1::ParseResult r = s.parser.parse(in.data(), in.size(), s.req);

            /* \~english
             * Not all here yet, and that is the ordinary case rather than a
             * corner: nothing is consumed, the buffer keeps what arrived, and
             * the rest lands after it.
             * \~spanish
             * Todavia no esta entera, y ese es el caso corriente y no una
             * esquina: no se consume nada, el buffer se queda lo que llego, y
             * el resto cae detras.
             * \~ */
            if (r == h1::ParseResult::NeedMore) return true;

            if (r == h1::ParseResult::Error) return refuse(400, out);

            s.head_size = s.parser.head_size();

            /* \~english
             * How the body is framed is asked BEFORE any of it is read, and it
             * is the question that decides where this message ends and the
             * next begins.  A message that frames itself two ways at once is
             * refused here rather than guessed at -- guessing is what lets two
             * implementations disagree about where the boundary was, which is
             * request smuggling in one sentence.
             * \~spanish
             * Como se trocea el cuerpo se pregunta ANTES de leer nada de el, y
             * es la pregunta que decide donde acaba este mensaje y empieza el
             * siguiente.  Un mensaje que se trocea de dos formas a la vez se
             * rechaza aqui en vez de adivinarlo -- adivinar es lo que permite
             * que dos implementaciones discrepen sobre donde estaba la frontera,
             * que es el contrabando de peticiones en una frase.
             * \~ */
            const h1::Framing f = h1::frame_request_body(s.req, in.data());
            if (f.error != h1::FramingError::None)
                return refuse(h1::framing_status(f.error), out);

            s.keep_alive = s.req.version != Version::Http10;

            if (f.kind == h1::BodyKind::Chunked) {
                s.phase = Phase::Chunks;
                s.chunks.reset(in.origin() + s.head_size);
            } else {
                s.phase = Phase::Body;
                s.left = f.kind == h1::BodyKind::Exact ? f.length : 0;

                if (s.left > limits_.max_body_bytes) return refuse(413, out);
            }
        }

        /* \~english
         * The head and the body have to be here TOGETHER before the handler is
         * called, because the handler is given the body as a view and a view
         * of half a body is not one.  Waiting is not a copy and not a stall:
         * the bytes are already in the buffer the connection is reading into.
         * \~spanish
         * La cabeza y el cuerpo tienen que estar aqui JUNTOS antes de llamar al
         * manejador, porque al manejador se le da el cuerpo como una vista y una
         * vista de medio cuerpo no lo es.  Esperar no es una copia ni un atasco:
         * los bytes ya estan en el buffer en el que lee la conexion.
         * \~ */
        size_t body_len = 0;

        if (s.phase == Phase::Body) {
            if (s.left > limits_.max_body_bytes) return refuse(413, out);
            if (in.size() < s.head_size + s.left) return true;
            body_len = static_cast<size_t>(s.left);
        } else {
            /* \~english
             * The pieces are moved down over the framing as they arrive, so
             * that a body which was written interleaved with its own sizes
             * ends up contiguous right after the head -- which is where a body
             * belongs and the only shape a view of one can have.
             *
             * Moving DOWN is what makes it safe to do in place: every piece
             * lands where framing bytes already read used to be, so it never
             * overwrites anything the reader has not passed.  And it is a move
             * and not a copy out, because the destination overlaps the source.
             *
             * \~spanish
             * Los pedazos se mueven hacia abajo sobre el troceado segun llegan,
             * para que un cuerpo escrito intercalado con sus propios tamanos
             * acabe seguido justo detras de la cabeza -- que es donde le toca a
             * un cuerpo y la unica forma que puede tener una vista de uno.
             *
             * Mover hacia ABAJO es lo que hace seguro hacerlo en el sitio: cada
             * pedazo cae donde estaban unos bytes de troceado ya leidos, asi que
             * no pisa nunca nada por lo que el lector no haya pasado.  Y es un
             * movimiento y no una copia fuera, porque el destino se solapa con
             * el origen.
             * \~ */
            for (;;) {
                const View v = in.view();
                const h1::ChunkResult r = s.chunks.read(v, s.req.fields);

                if (r == h1::ChunkResult::NeedMore) return true;
                if (r == h1::ChunkResult::Error) return refuse(400, out);
                if (r == h1::ChunkResult::Done) break;

                const Span p = s.chunks.chunk();
                if (p.len == 0) continue;

                if (s.decoded + p.len > limits_.max_body_bytes)
                    return refuse(413, out);

                uint8_t *at = in.writable() + s.head_size + s.decoded;
                util::vesta_memmove(at, in.data() + p.off, p.len);
                s.decoded += p.len;
            }

            body_len = s.decoded;
        }

        const uint8_t *body =
            body_len == 0 ? nullptr : in.data() + s.head_size;

        /* \~english
         * The handler says what it means, and the rendering below is the only
         * place that turns it into HTTP/1.1.  The request is kept to hand to
         * the rendering as well, because two things about how a response is
         * written are facts about the REQUEST: which version to answer in, and
         * that a `HEAD` gets the fields of a `GET` and none of its bytes.
         *
         * \~spanish
         * El manejador dice lo que significa, y el escribir de abajo es el unico
         * sitio que lo convierte en HTTP/1.1.  La peticion se guarda para
         * pasarsela tambien, porque dos cosas de como se escribe una respuesta
         * son hechos de la PETICION: en que version contestar, y que a un `HEAD`
         * le tocan las cabeceras de un `GET` y ninguno de sus bytes.
         * \~ */
        ResponseBuilder res(said_);
        handler_->handle(s.req, in.data(), body, body_len, res);

        if (!render(res, s.req, s.keep_alive, out)) return false;

        ++served_;

        /* \~english
         * And the message is consumed -- all of it, head and body, by what it
         * MEASURED and not by what it meant.  Consuming the decoded length of
         * a chunked body would leave its framing bytes in the buffer, and the
         * next parse would read a chunk header as a request line.
         * \~spanish
         * Y el mensaje se consume -- entero, cabeza y cuerpo, por lo que MIDIO y
         * no por lo que significaba.  Consumir la longitud descodificada de un
         * cuerpo por trozos dejaria sus bytes de troceado en el buffer, y el
         * analisis siguiente leeria una cabecera de trozo como una linea de
         * peticion.
         * \~ */
        const size_t whole =
            s.phase == Phase::Chunks
                ? static_cast<size_t>(s.chunks.consumed() - in.origin())
                : s.head_size + body_len;

        in.consume(whole);

        s.parser.reset();
        s.req = Request();
        s.phase = Phase::Head;
        s.left = 0;
        s.head_size = 0;
        s.decoded = 0;

        if (!s.keep_alive) return false;
    }
}

} // namespace http_vx
