/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/stream.cpp
 * @brief
 * \~english Keeping track of the requests in flight on one connection.
 * \~spanish Llevar la cuenta de las peticiones en vuelo de una conexion.
 * \~
 */

#include "http_vx/h2_stream.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {
namespace h2 {

namespace {

/**
 * @brief
 * \~english The verdict for a frame that is simply late.
 * \~spanish El veredicto de una trama que solo llega tarde.
 * \~
 *
 * \~english
 * Written once because it is said from three places and it is the one that is
 * easy to write as an error by mistake.  A frame for a stream that finished is
 * not the peer misbehaving: it left before the peer could know, and the only
 * thing owed for it is the connection window.
 *
 * \~spanish
 * Escrito una vez porque se dice desde tres sitios y es el que es facil poner
 * como error por equivocacion.  Una trama de un flujo terminado no es el otro
 * extremo portandose mal: salio antes de que el otro pudiera saberlo, y lo
 * unico que se debe por ella es la ventana de la conexion.
 *
 * \~
 */
constexpr Outcome late() noexcept {
    return Outcome{Verdict::Discard, ErrorCode::NoError};
}

constexpr Outcome ok() noexcept {
    return Outcome{Verdict::Accept, ErrorCode::NoError};
}

constexpr Outcome stream_error(ErrorCode e) noexcept {
    return Outcome{Verdict::StreamError, e};
}

constexpr Outcome connection_error(ErrorCode e) noexcept {
    return Outcome{Verdict::ConnectionError, e};
}

} // namespace

StreamSet::~StreamSet() { release(); }

void StreamSet::reset(const Limits &limits) noexcept {
    count_ = 0;
    highest_ = 0;
    max_streams_ = limits.max_concurrent_streams;
    own_initial_ = limits.initial_window_size;

    /* \~english
     * The peer's initial window stays at the specification's default until the
     * peer says otherwise.  It is not this server's number and it must not be
     * seeded from this server's limits -- a connection that started both at its
     * own value would be spending an allowance the peer never offered.
     * \~spanish
     * La ventana inicial del otro extremo se queda en el valor por defecto de la
     * especificacion hasta que el otro diga otra cosa.  No es un numero de este
     * servidor y no se puede sembrar con sus limites -- una conexion que
     * empezara las dos con su propio valor estaria gastando un credito que el
     * otro extremo no ofrecio nunca.
     * \~ */
    peer_initial_ = 65535;
}

void StreamSet::release() noexcept {
    if (streams_ != nullptr) {
        util::host_free(streams_);
        streams_ = nullptr;
    }
    cap_ = 0;
    count_ = 0;
}

bool StreamSet::make_room() noexcept {
    if (streams_ != nullptr) return true;

    /* \~english
     * The whole table at once, sized by what was announced.  It is not grown:
     * the ceiling is what this server told the peer, so a table that could grow
     * past it would be a table with room for streams this server said it would
     * refuse -- and growing is a copy at the worst moment, which is when the
     * connection is busiest.
     *
     * The scope says what this is: it lives as long as the connection, it never
     * changes size, and there is one per connection rather than one per
     * request.
     *
     * \~spanish
     * La tabla entera de una vez, dimensionada por lo que se anuncio.  No se
     * hace crecer: el techo es lo que este servidor le dijo al otro extremo, asi
     * que una tabla que pudiera pasarse seria una con sitio para flujos que este
     * servidor dijo que rechazaria -- y crecer es una copia en el peor momento,
     * que es cuando la conexion tiene mas trabajo.
     *
     * El alcance dice lo que es esto: vive lo que la conexion, no cambia de
     * tamano nunca, y hay uno por conexion y no uno por peticion.
     * \~ */
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    const size_t want = max_streams_ == 0 ? 1 : max_streams_;
    streams_ = static_cast<Stream *>(util::host_alloc(want * sizeof(Stream)));
    if (streams_ == nullptr) return false;

    cap_ = want;
    return true;
}

Stream *StreamSet::find(uint32_t id) noexcept {
    for (size_t i = 0; i < count_; ++i)
        if (streams_[i].id == id) return &streams_[i];
    return nullptr;
}

void StreamSet::drop(size_t i) noexcept {
    /* \~english
     * The last one moves into the hole.  Order does not mean anything here --
     * what says which request came first is the identifier, and it is in the
     * entry -- so keeping the array in order would be moving bytes to preserve
     * something nobody reads.
     * \~spanish
     * El ultimo se mete en el hueco.  Aqui el orden no significa nada -- lo que
     * dice que peticion vino antes es el identificador, y esta en la entrada --
     * asi que mantener el array ordenado seria mover bytes para conservar algo
     * que no lee nadie.
     * \~ */
    streams_[i] = streams_[count_ - 1];
    --count_;
}

ErrorCode StreamSet::adjust_send_windows(int64_t delta) noexcept {
    for (size_t i = 0; i < count_; ++i) {
        const ErrorCode e = streams_[i].send.adjust(delta);
        if (e != ErrorCode::NoError) return e;
    }
    return ErrorCode::NoError;
}

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
        return connection_error(ErrorCode::ProtocolError);

    /* \~english
     * At or below the highest already seen.  Two different things end up here
     * and both are refused: a number going backwards, and a number used twice.
     * They are not told apart because the answer is the same and because
     * telling them apart would mean remembering every identifier ever used,
     * which is the memory this rule exists to avoid.
     *
     * Note that a stream still OPEN with this identifier lands here too -- a
     * second HEADERS on a live stream is trailers, and that is a different
     * question asked elsewhere, not an opening.
     *
     * \~spanish
     * Igual o por debajo del mayor ya visto.  Aqui acaban dos cosas distintas y
     * las dos se rechazan: un numero que va hacia atras, y un numero usado dos
     * veces.  No se distinguen porque la respuesta es la misma y porque
     * distinguirlas obligaria a recordar todos los identificadores usados, que
     * es la memoria que esta regla existe para evitar.
     *
     * Fijarse en que un flujo todavia ABIERTO con este identificador tambien cae
     * aqui -- un segundo HEADERS sobre un flujo vivo son trailers, y esa es otra
     * pregunta que se hace en otro sitio, no una apertura.
     * \~ */
    if (id <= highest_) return connection_error(ErrorCode::ProtocolError);

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
    if (count_ >= max_streams_) return stream_error(ErrorCode::RefusedStream);

    if (!make_room()) return connection_error(ErrorCode::InternalError);
    if (count_ >= cap_) return stream_error(ErrorCode::RefusedStream);

    Stream &s = streams_[count_];
    s.id = id;
    s.send = Window(peer_initial_);
    s.recv = Window(own_initial_);
    s.state = end_stream ? StreamState::HalfClosedRemote : StreamState::Open;
    ++count_;

    return ok();
}

Outcome StreamSet::on_data(uint32_t id, uint32_t len,
                           bool end_stream) noexcept {
    if (id == 0) return connection_error(ErrorCode::ProtocolError);

    Stream *s = find(id);
    if (s == nullptr) {
        /* \~english
         * Above the highest seen means the peer sent data for a stream it never
         * opened, which is a connection error -- there is no request to attach
         * it to and no way to answer.  At or below means the stream finished,
         * and the frame is merely late.
         * \~spanish
         * Por encima del mayor visto quiere decir que el otro extremo mando
         * datos de un flujo que no abrio nunca, que es un error de conexion --
         * no hay peticion a la que pegarlos ni forma de contestar.  Igual o por
         * debajo quiere decir que el flujo termino, y la trama solo llega tarde.
         * \~ */
        if (id > highest_) return connection_error(ErrorCode::ProtocolError);
        (void)len;
        return late();
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
        return stream_error(ErrorCode::StreamClosed);

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
    if (!s->recv.take(len)) return stream_error(ErrorCode::FlowControlError);

    if (end_stream) {
        if (s->state == StreamState::HalfClosedLocal) {
            drop(static_cast<size_t>(s - streams_));
            return ok();
        }
        s->state = StreamState::HalfClosedRemote;
    }

    return ok();
}

Outcome StreamSet::on_reset(uint32_t id) noexcept {
    if (id == 0) return connection_error(ErrorCode::ProtocolError);

    Stream *s = find(id);
    if (s == nullptr) {
        /* \~english
         * A reset for a stream that never existed is a connection error; for
         * one that already finished it is the two ends giving up at the same
         * time, which is ordinary.
         * \~spanish
         * Un reinicio de un flujo que no existio nunca es un error de conexion;
         * de uno ya terminado es que los dos extremos se rindieron a la vez, que
         * es lo corriente.
         * \~ */
        if (id > highest_) return connection_error(ErrorCode::ProtocolError);
        return late();
    }

    drop(static_cast<size_t>(s - streams_));
    return ok();
}

void StreamSet::finish(uint32_t id) noexcept {
    Stream *s = find(id);
    if (s == nullptr) return;

    /* \~english
     * If the peer had already finished, the stream is over and is forgotten.
     * If it had not, this end is done answering and the peer may still be
     * sending -- and the entry has to stay, because the data that is still
     * coming has a window that still has to be counted.
     * \~spanish
     * Si el otro extremo ya habia acabado, el flujo se termina y se olvida.  Si
     * no, este extremo ha acabado de contestar y el otro puede seguir mandando
     * -- y la entrada tiene que quedarse, porque los datos que siguen llegando
     * tienen una ventana que hay que seguir contando.
     * \~ */
    if (s->state == StreamState::HalfClosedRemote) {
        drop(static_cast<size_t>(s - streams_));
        return;
    }

    s->state = StreamState::HalfClosedLocal;
}

} // namespace h2
} // namespace http_vx
