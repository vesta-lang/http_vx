/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service_open.cpp
 * @brief
 * \~english Open responses in HTTP/2: DATA frames filled in place, as the two windows allow (HVX-5, 7.2).
 * \~spanish Respuestas abiertas en HTTP/2: tramas DATA rellenadas en su sitio, segun dejen las dos ventanas (HVX-5, 7.2).
 * \~
 *
 * \~english
 * The head goes without END_STREAM; each fill is ONE DATA frame whose nine
 * bytes of header are kept in the output before the source writes, and
 * written once the length is known -- so no byte of body is copied.  The
 * room a fill is offered is the smallest of the stream's window, the
 * connection's, the peer's SETTINGS_MAX_FRAME_SIZE, @c kFillRoom and what the
 * caller's budget leaves after the header.  A window that is shut means no
 * fill at all: the pressure is the absence of a call (HVX-5, 3).
 * \~spanish
 * La cabecera sale sin END_STREAM; cada relleno es UNA trama DATA cuyos nueve
 * bytes de cabecera se guardan en la salida antes de que escriba la fuente, y
 * se escriben cuando se sabe la longitud -- asi que no se copia ningun byte de
 * cuerpo.  El sitio que se le ofrece a un relleno es el menor de la ventana del
 * flujo, la de la conexion, el SETTINGS_MAX_FRAME_SIZE del otro extremo,
 * @c kFillRoom y lo que deja el presupuesto de quien llama tras la cabecera.
 * Una ventana cerrada quiere decir ningun relleno: la contrapresion es la
 * ausencia de una llamada (HVX-5, 3).
 * \~
 */

#include "http_vx/http2_service.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

namespace {

/**
 * @brief
 * \~english Writes the header of a DATA frame of @p n bytes on @p stream at @p at.
 * \~spanish Escribe la cabecera de una trama DATA de @p n bytes en @p stream en @p at.
 * \~
 *
 * @param at     \~english nine bytes kept in front of the payload  \~spanish nueve bytes guardados delante de la carga  \~
 * @param stream \~english which stream  \~spanish que flujo  \~
 * @param n      \~english how long the payload is  \~spanish cuanto mide la carga  \~
 * @param end    \~english whether it carries END_STREAM  \~spanish si lleva END_STREAM  \~
 */
void put_data_header(uint8_t *at, uint32_t stream, size_t n, bool end) noexcept {
    h2::FrameHeader h;
    h.length = static_cast<uint32_t>(n);
    h.stream_id = stream;
    h.type = static_cast<uint8_t>(h2::FrameType::Data);
    h.flags = end ? static_cast<uint8_t>(h2::kEndStream) : static_cast<uint8_t>(0);
    h2::encode_frame_header(at, h);
}

/**
 * @brief
 * \~english Spends @p n bytes of both windows: what was sent, never what was offered.
 * \~spanish Gasta @p n bytes de las dos ventanas: lo que se mando, nunca lo que se ofrecio.
 * \~
 *
 * \~english
 * @p n is never more than the room, and the room never more than either
 * window, so both takes succeed.
 * \~spanish
 * @p n nunca pasa del sitio, y el sitio nunca pasa de ninguna de las dos
 * ventanas, asi que las dos tomas salen bien.
 * \~
 *
 * @param stream     \~english the stream's window  \~spanish la ventana del flujo  \~
 * @param connection \~english the connection's  \~spanish la de la conexion  \~
 * @param n          \~english how many bytes went  \~spanish cuantos bytes salieron  \~
 */
void spend(h2::Window &stream, h2::Window &connection, size_t n) noexcept {
    stream.take(static_cast<uint32_t>(n));
    connection.take(static_cast<uint32_t>(n));
}

} // namespace

OpenResponse Http2Service::OpenGate::open(ConnHandle c, uint64_t stream, BodySource &s,
                                          KickTarget &target) noexcept {
    Http2Service &svc = *service_;

    // \~english No entry to keep it in: refused, counted, and answered 503 like any limit.
    // \~spanish Sin entrada donde guardarla: rechazada, contada, y contestada 503 como cualquier tope.  \~
    if (svc.opens_.full()) {
        ++svc.open_full_;
        return OpenResponse();
    }
    return svc.port_->open(c, stream, s, target);
}

size_t Http2Service::OpenGate::fill(BodySource &s, uint8_t *dst, size_t room,
                                    bool &done) noexcept {
    return service_->port_->fill(s, dst, room, done);
}

void Http2Service::OpenGate::end(BodySource &s, GoneReason why) noexcept {
    service_->port_->end(s, why);
}

size_t Http2Service::open_room(State &s, const h2::Stream &st, size_t left) noexcept {
    const int32_t own = st.send.left();
    const int32_t all = s.conn.send_window().left();

    /* \~english
     * Either window may be negative -- a stream in debt after the peer lowered
     * its initial window -- and either one shut means nothing goes (RFC 9113,
     * 5.2).  A budget that cannot take a frame header and a byte is shut too.
     * \~spanish
     * Cualquiera de las dos ventanas puede ser negativa -- un flujo en deuda
     * despues de que el otro bajara su ventana inicial -- y cualquiera cerrada
     * quiere decir que no sale nada (RFC 9113, 5.2).  Un presupuesto que no
     * admite una cabecera de trama y un byte tambien esta cerrado.
     * \~ */
    if (own <= 0 || all <= 0 || left <= h2::kFrameHeaderSize) return 0;

    size_t room = kFillRoom;
    if (static_cast<size_t>(own) < room) room = static_cast<size_t>(own);
    if (static_cast<size_t>(all) < room) room = static_cast<size_t>(all);
    if (s.conn.peer().max_frame_size < room) room = s.conn.peer().max_frame_size;
    if (left - h2::kFrameHeaderSize < room) room = left - h2::kFrameHeaderSize;
    return room;
}

bool Http2Service::put_prefix(State &s, h2::Stream &st, uint32_t stream,
                              const uint8_t *p, size_t n, size_t &at, Buffer &out,
                              size_t &left) noexcept {
    while (at < n) {
        size_t k = open_room(s, st, left);
        if (k == 0) return true;
        if (k > n - at) k = n - at;

        uint8_t *base = out.reserve(h2::kFrameHeaderSize + k);
        if (base == nullptr) return false;

        put_data_header(base, stream, k, false);
        util::vesta_memcpy(base + h2::kFrameHeaderSize, p + at, k);
        spend(st.send, s.conn.send_window(), k);
        out.commit(h2::kFrameHeaderSize + k);

        left -= h2::kFrameHeaderSize + k;
        at += k;
    }
    return true;
}

Http2Service::Feed Http2Service::feed_open(State &s, uint32_t i, Buffer &out,
                                           size_t &left) noexcept {
    h2::OpenStream &e = opens_.at(i);

    /* \~english
     * Every way a stream leaves the table while its response is open comes
     * with a StreamEnded event, which ends the response there.  One that is
     * gone anyway is ended here rather than written to: frames on a closed
     * stream are a connection error at the peer (RFC 9113, 5.1).
     * \~spanish
     * Toda forma de que un flujo salga de la tabla mientras su respuesta esta
     * abierta viene con un suceso StreamEnded, que acaba ahi la respuesta.  Uno
     * que no este igualmente se acaba aqui en vez de escribirle: tramas en un
     * flujo cerrado son un error de conexion para el otro extremo (RFC 9113,
     * 5.1).
     * \~ */
    h2::Stream *st = s.conn.streams().find(e.stream);
    if (st == nullptr) {
        drop_open(i, GoneReason::PeerReset);
        return Feed::Ended;
    }

    // \~english What the handler wrote before opening goes first, and the source waits behind it.
    // \~spanish Lo que escribio el manejador antes de abrir va primero, y la fuente espera detras.  \~
    if (!e.prefix.empty()) {
        size_t at = 0;
        if (!put_prefix(s, *st, e.stream, e.prefix.data(), e.prefix.size(), at, out, left))
            return Feed::Failed;
        e.prefix.consume(at);
        if (!e.prefix.empty()) return Feed::Kept;
        e.prefix.release();
    }

    if (!e.kicked && !e.hungry) return Feed::Kept;

    // \~english No room: the kick, or the hunger, stays for when there is (HVX-5, 4.3).
    // \~spanish Sin sitio: el aviso, o el hambre, se queda para cuando lo haya (HVX-5, 4.3).  \~
    const size_t room = open_room(s, *st, left);
    if (room == 0) return Feed::Kept;

    uint8_t *base = out.reserve(h2::kFrameHeaderSize + room);
    if (base == nullptr) return Feed::Failed;

    /* \~english
     * The kick is cleared BEFORE the source is asked: one that arrives while
     * it fills marks it again instead of being lost.  The port is the one
     * place the source is asked from, and it clamps what comes back to the
     * room, so the header below never announces bytes nobody wrote.
     * \~spanish
     * El aviso se limpia ANTES de preguntarle a la fuente: uno que llegue
     * mientras rellena la vuelve a marcar en vez de perderse.  La puerta es el
     * unico sitio desde el que se le pregunta a la fuente, y recorta al sitio lo
     * que vuelve, asi que la cabecera de abajo nunca anuncia bytes que no
     * escribio nadie.
     * \~ */
    e.kicked = false;
    bool done = false;
    const size_t n = port_->fill(*e.source, base + h2::kFrameHeaderSize, room, done);

    // \~english Nothing now, and not over: no frame, and not asked again until kicked.
    // \~spanish Nada ahora, y sin acabar: ninguna trama, y no se le vuelve a pedir hasta que la avisen.  \~
    if (n == 0 && !done) {
        e.hungry = false;
        return Feed::Kept;
    }

    // \~english A done with no bytes is an empty DATA carrying END_STREAM, which costs no window.
    // \~spanish Un done sin bytes es un DATA vacio con END_STREAM, que no cuesta ventana.  \~
    put_data_header(base, e.stream, n, done);
    spend(st->send, s.conn.send_window(), n);
    out.commit(h2::kFrameHeaderSize + n);
    left -= h2::kFrameHeaderSize + n;

    if (done) {
        s.conn.streams().finish(e.stream);
        drop_open(i, GoneReason::Finished);
        return Feed::Ended;
    }

    e.hungry = n == room;
    return Feed::Kept;
}

bool Http2Service::start_open(State &s, uint32_t stream, const ResponseBuilder &res,
                              size_t count, Work *w, Buffer &out) noexcept {
    BodySource &src = *res.opened_source();

    // \~english The peer cancelled while the handler was working: the source is told, and nothing is written.
    // \~spanish El otro extremo cancelo mientras trabajaba el manejador: se le dice a la fuente, y no se escribe nada.  \~
    h2::Stream *st = s.conn.streams().find(stream);
    if (st == nullptr) {
        if (w != nullptr) drop_work(s, w);
        port_->end(src, GoneReason::PeerReset);
        return true;
    }

    /* \~english
     * The gate checked there was an entry before the shard counted the
     * response open, and nothing has taken one since -- so this is never
     * full.  If it were, it is said: counted, the source ended, and a 503.
     * \~spanish
     * La puerta comprobo que habia una entrada antes de que el fragmento
     * contara abierta la respuesta, y nada ha cogido una desde entonces -- asi
     * que esto nunca esta lleno.  Si lo estuviera, se dice: contado, la fuente
     * acabada, y un 503.
     * \~ */
    const uint32_t i = opens_.take(src, stream);
    if (i == h2::kNoOpen) {
        ++open_full_;
        port_->end(src, GoneReason::ConnectionClosed);
        return refuse(s, stream, status::kServiceUnavailable, w, out);
    }

    // \~english The head, without END_STREAM: the body is still to come.
    // \~spanish La cabecera, sin END_STREAM: el cuerpo esta por venir.  \~
    const HeadWrite hw = put_head(s, stream, res, count, false, false, out);
    if (hw != HeadWrite::Written) {
        drop_open(i, GoneReason::ConnectionClosed);
        if (hw == HeadWrite::ConnectionFailed) return false;
        if (w != nullptr) drop_work(s, w);
        return send_reset(s, stream, h2::ErrorCode::InternalError, out);
    }

    /* \~english
     * The request is answered, and an open response keeps nothing of it: the
     * piece of work and its buffer go back to the request pool now, so a long
     * stream never holds one (HVX-5, 7.2).
     * \~spanish
     * La peticion esta contestada, y una respuesta abierta no guarda nada de
     * ella: el trabajo y su buffer vuelven ahora al pozo de peticiones, asi que
     * un flujo largo nunca ocupa uno (HVX-5, 7.2).
     * \~ */
    if (w != nullptr) drop_work(s, w);

    /* \~english
     * What the handler wrote before opening is the first piece: what the
     * windows take goes now, straight from where the handler wrote it, and
     * only the rest is kept -- in the entry, never in the request pool.
     * \~spanish
     * Lo que escribio el manejador antes de abrir es el primer trozo: lo que
     * admitan las ventanas sale ya, directamente de donde lo escribio el
     * manejador, y solo el resto se guarda -- en la entrada, nunca en el pozo de
     * peticiones.
     * \~ */
    h2::OpenStream &e = opens_.at(i);
    const Span b = res.body();
    const uint8_t *first = res.bytes() + b.off;
    size_t left = kNoBudget;
    size_t at = 0;

    if (!put_prefix(s, *st, stream, first, b.len, at, out, left)) {
        drop_open(i, GoneReason::ConnectionClosed);
        return false;
    }

    if (at < b.len) {
        const size_t rest = b.len - at;
        uint8_t *keep = e.prefix.reserve(rest);
        if (keep == nullptr) {
            drop_open(i, GoneReason::ConnectionClosed);
            return false;
        }
        util::vesta_memcpy(keep, first + at, rest);
        e.prefix.commit(rest);
    }

    // \~english And the first fill, right away if there is room: asked as if room had just come (HVX-5, 4.3).
    // \~spanish Y el primer relleno, ya si hay sitio: se pide como si acabara de llegar sitio (HVX-5, 4.3).  \~
    e.hungry = true;
    const Feed f = feed_open(s, i, out, left);
    if (f == Feed::Failed) {
        drop_open(i, GoneReason::ConnectionClosed);
        return false;
    }
    if (f == Feed::Kept) opens_.push(s.opens, i);
    return true;
}

bool Http2Service::on_writable(ConnHandle c, Buffer &out, size_t budget) noexcept {
    if (c.slot >= capacity_ || port_ == nullptr) return true;

    State &s = state_[c.slot];
    size_t left = budget;

    /* \~english
     * Each open response is taken from the front and, still open, put at the
     * back: one frame each per call, and a budget that runs out leaves the
     * ones not reached at the front for the next call.  One stream with a lot
     * to say cannot starve the others of its connection.
     * \~spanish
     * Cada respuesta abierta se coge del principio y, si sigue abierta, se pone
     * al final: una trama cada una por llamada, y un presupuesto que se acaba
     * deja delante para la llamada siguiente las que no alcanzo.  Un flujo con
     * mucho que decir no puede dejar sin turno a los demas de su conexion.
     * \~ */
    for (uint32_t turns = s.opens.count; turns != 0 && left > h2::kFrameHeaderSize; --turns) {
        const uint32_t i = opens_.pop(s.opens);
        const Feed f = feed_open(s, i, out, left);
        if (f == Feed::Failed) {
            drop_open(i, GoneReason::ConnectionClosed);
            return false;
        }
        if (f == Feed::Kept) opens_.push(s.opens, i);
    }

    // \~english Whoever still wants room and has it -- a full fill, a kick the budget did not reach -- is asked again.
    // \~spanish A quien aun quiere sitio y lo tiene -- un relleno lleno, un aviso al que no llego el presupuesto -- se le vuelve a pedir.  \~
    if (s.opens.count != 0) wake_open(s);

    // \~english The last open response of a peer that is leaving may just have finished (RFC 9113, 6.8).
    // \~spanish La ultima respuesta abierta de un extremo que se va puede acabar de terminar (RFC 9113, 6.8).  \~
    return still_needed(s, out, left);
}

void Http2Service::on_kick(BodySource &source) noexcept {
    const OpenResponse r = source.response();
    if (r.conn.slot >= capacity_ || port_ == nullptr) return;

    State &s = state_[r.conn.slot];
    if (s.handle.life != r.conn.life) return;

    const uint32_t i = opens_.find(s.opens, &source);
    if (i == h2::kNoOpen) return;

    opens_.at(i).kicked = true;
    port_->want_writable(r.conn);
}

void Http2Service::wake_open(State &s) noexcept {
    if (port_ == nullptr || s.conn.send_window().left() <= 0) return;

    /* \~english
     * Asked only for one that wants to be: kicked, hungry after a full fill,
     * or with a prefix still to send.  One whose last fill gave less than its
     * room has said it has nothing more, and waits for its kick (HVX-5, 4.3).
     * \~spanish
     * Se pide solo por una que quiera: avisada, con hambre tras un relleno
     * lleno, o con un prefijo por mandar.  Una cuyo ultimo relleno dio menos que
     * su sitio ha dicho que no tiene mas, y espera su aviso (HVX-5, 4.3).
     * \~ */
    for (uint32_t i = s.opens.head; i != h2::kNoOpen; i = opens_.at(i).next) {
        const h2::OpenStream &e = opens_.at(i);
        if (!e.kicked && !e.hungry && e.prefix.empty()) continue;

        const h2::Stream *st = s.conn.streams().find(e.stream);
        if (st == nullptr || st->send.left() > 0) {
            port_->want_writable(s.handle);
            return;
        }
    }
}

void Http2Service::drop_open(uint32_t i, GoneReason why) noexcept {
    /* \~english
     * The entry is given back BEFORE the source is told: its @c gone may free
     * it, and after that nothing here may name it.
     * \~spanish
     * La entrada se devuelve ANTES de decirselo a la fuente: su @c gone puede
     * liberarla, y despues de eso nada de aqui puede nombrarla.
     * \~ */
    BodySource *src = opens_.at(i).source;
    opens_.give_back(i);
    if (src != nullptr && port_ != nullptr) port_->end(*src, why);
}

void Http2Service::end_stream_open(State &s, uint32_t stream, GoneReason why) noexcept {
    const uint32_t i = opens_.find(s.opens, stream);
    if (i == h2::kNoOpen) return;

    opens_.unlink(s.opens, i);
    drop_open(i, why);
}

} // namespace http_vx
