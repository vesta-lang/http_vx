/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/stream.cpp
 * @brief
 * \~english Keeping track of the requests in flight on one connection: the table itself, and how streams leave it.
 * \~spanish Llevar la cuenta de las peticiones en vuelo de una conexion: la tabla misma, y como salen de ella los flujos.
 * \~
 *
 * \~english
 * What the table says about each frame of a request -- the opening HEADERS,
 * DATA, trailers -- is in stream_frames.cpp.
 * \~spanish
 * Lo que dice la tabla de cada trama de una peticion -- el HEADERS que abre,
 * los DATA, los remolques -- esta en stream_frames.cpp.
 * \~
 */

#include "http_vx/h2_stream.h"

#include "stream_verdicts.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {
namespace h2 {

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
    recent_.reset();
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

void StreamSet::end_remote(Stream *s) noexcept {
    if (s->state == StreamState::HalfClosedLocal) {
        drop(static_cast<size_t>(s - streams_));
        return;
    }
    s->state = StreamState::HalfClosedRemote;
}

Outcome StreamSet::on_reset(uint32_t id) noexcept {
    if (id == 0)
        return connection_error(ErrorCode::ProtocolError,
                                "RST_STREAM on stream 0 (RFC 9113, 6.4)");

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
        if (never_opened(id))
            return connection_error(ErrorCode::ProtocolError,
                                    "RST_STREAM on an idle stream (RFC 9113, "
                                    "5.1)");
        return late();
    }

    drop(static_cast<size_t>(s - streams_));
    return ok();
}

void StreamSet::on_reset_sent(uint32_t id) noexcept {
    Stream *s = find(id);
    if (s != nullptr) drop(static_cast<size_t>(s - streams_));

    /* \~english
     * Kept whether or not the stream was in the table: a stream refused at
     * the door never got an entry, and it is exactly the one whose trailers
     * and body are still on their way.
     * \~spanish
     * Se guarda estuviera o no el flujo en la tabla: un flujo rechazado en la
     * puerta nunca tuvo entrada, y es justo aquel cuyos remolques y cuerpo
     * siguen de camino.
     * \~ */
    recent_.reset_here(id);
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
