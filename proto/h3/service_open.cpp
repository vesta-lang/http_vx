/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service_open.cpp
 * @brief
 * \~english Open responses in HTTP/3: DATA frames filled in place in the QUIC stream, as credit allows (HVX-5, 7.3).
 * \~spanish Respuestas abiertas en HTTP/3: tramas DATA rellenadas en su sitio en el flujo QUIC, segun deje el credito (HVX-5, 7.3).
 * \~
 *
 * \~english
 * The header section goes without ending the stream, what the handler wrote
 * before opening is the first DATA frame, and every fill after is one more,
 * written by the source straight into the stream's send chunk
 * (h3::Connection::body_room).  Nothing is filled without room: the room is
 * the stream's and the connection's flow control credit and what the send
 * side takes, so a peer that does not read holds this server to nothing.
 *
 * A kick marks and queues; the fill runs in next_datagram, which the loop
 * calls after draining the kicks.  A stream whose last fill took all its room
 * is filled there again with no kick, as soon as there is room (HVX-5, 4.3).
 *
 * \~spanish
 * La seccion de cabecera sale sin acabar el flujo, lo que escribio el manejador
 * antes de abrir es la primera trama DATA, y cada relleno despues es una mas,
 * escrita por la fuente directamente en el trozo de envio del flujo
 * (h3::Connection::body_room).  No se rellena nada sin sitio: el sitio es el
 * credito de control de flujo del flujo y de la conexion y lo que admite el lado
 * de envio, asi que un otro extremo que no lee no retiene nada de este servidor.
 *
 * Un aviso marca y pone en la cola; el relleno corre en next_datagram, al que
 * el bucle llama despues de vaciar los avisos.  Un flujo cuyo ultimo relleno uso
 * todo su sitio se vuelve a rellenar ahi sin aviso, en cuanto hay sitio (HVX-5,
 * 4.3).
 * \~
 */
#include "service_slot.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {

namespace {

/**
 * @brief
 * \~english Whether the peer abandoned @p s: stopped reading the response, or reset the request.
 * \~spanish Si el otro extremo abandono @p s: dejo de leer la respuesta, o reinicio la peticion.
 * \~
 *
 * \~english
 * A STOP_SENDING resets the sending part in QUIC itself (RFC 9000, 3.5).  A
 * RESET_STREAM that arrives once the whole request was read changes nothing
 * there -- the RFC makes that transition optional -- so it only shows while
 * the request is still being received.
 * \~spanish
 * Un STOP_SENDING reinicia la parte emisora en el propio QUIC (RFC 9000, 3.5).
 * Un RESET_STREAM que llega cuando ya se leyo la peticion entera no cambia nada
 * ahi -- el RFC hace opcional esa transicion --, asi que solo se ve mientras la
 * peticion se sigue recibiendo.
 * \~
 *
 * @param s \~english the QUIC stream, or null if it is gone  \~spanish el flujo QUIC, o nulo si ya no esta  \~
 * @return  \~english true if the response cannot go on  \~spanish true si la respuesta no puede seguir  \~
 */
bool abandoned(const quic::Stream *s) noexcept {
    if (s == nullptr || s->send == nullptr) return true;
    const quic::SendState tx = s->send->state();
    if (tx == quic::SendState::ResetSent || tx == quic::SendState::ResetRecvd) return true;
    if (s->recv == nullptr) return false;
    const quic::RecvState rx = s->recv->state();
    return rx == quic::RecvState::ResetRecvd || rx == quic::RecvState::ResetRead;
}

} // namespace

/**
 * @brief
 * \~english The handle of slot @p i's connection, with its life.
 * \~spanish El asa de la conexion de la casilla @p i, con su vida.
 * \~
 *
 * @param i \~english the slot  \~spanish la casilla  \~
 * @return  \~english the handle  \~spanish el asa  \~
 */
ConnHandle Http3Service::handle_of(uint32_t i) const noexcept {
    ConnHandle c;
    c.slot = i;
    c.life = slots_[i].life;
    return c;
}

/**
 * @brief
 * \~english The live slot @p c names, or null for one gone or reused.
 * \~spanish La casilla viva que nombra @p c, o nulo si se fue o se reutilizo.
 * \~
 *
 * @param c \~english the handle  \~spanish el asa  \~
 * @return  \~english the slot, or null  \~spanish la casilla, o nulo  \~
 */
Http3Service::Slot *Http3Service::slot_of(ConnHandle c) noexcept {
    if (slots_ == nullptr || c.slot >= capacity_) return nullptr;
    Slot &s = slots_[c.slot];
    if (s.quic == nullptr || s.life != c.life) return nullptr;
    return &s;
}

OpenResponse Http3Service::OpenGate::open(ConnHandle c, uint64_t stream, BodySource &src,
                                          KickTarget &target) noexcept {
    Http3Service &sv = *service_;
    Slot *s = sv.slot_of(c);
    if (sv.port_ == nullptr || s == nullptr) return OpenResponse();

    /* \~english
     * The connection's table is made at its first open, so a connection that
     * never opens pays nothing for it (R39).  Past the limit, or with no
     * memory for the table, the open is refused and counted; the handler's
     * answer becomes a 503.
     * \~spanish
     * La tabla de la conexion se hace en su primera apertura, asi que una
     * conexion que nunca abre no paga nada por ella (R39).  Pasado el tope, o sin
     * memoria para la tabla, la apertura se rechaza y se cuenta; la respuesta del
     * manejador pasa a ser un 503.
     * \~ */
    if (s->open_count >= sv.cfg_.max_open_per_conn) {
        ++sv.counts_.open_limited;
        return OpenResponse();
    }
    if (s->opens == nullptr) {
        const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
        s->opens = static_cast<OpenStream *>(util::host_alloc(sv.cfg_.h3.max_requests * sizeof(OpenStream)));
        if (s->opens == nullptr) {
            ++sv.counts_.open_limited;
            return OpenResponse();
        }
        for (size_t k = 0; k < sv.cfg_.h3.max_requests; ++k) new (&s->opens[k]) OpenStream();
    }
    return sv.port_->open(c, stream, src, target);
}

size_t Http3Service::OpenGate::fill(BodySource &src, uint8_t *dst, size_t room, bool &done) noexcept {
    return service_->port_->fill(src, dst, room, done);
}

void Http3Service::OpenGate::end(BodySource &src, GoneReason why) noexcept { service_->port_->end(src, why); }

/**
 * @brief
 * \~english Sends the head of an opened response and its first piece, and marks it to be filled.
 * \~spanish Manda la cabecera de una respuesta abierta y su primer trozo, y la marca para rellenarla.
 * \~
 *
 * @param i      \~english the connection's slot  \~spanish la casilla de la conexion  \~
 * @param place  \~english the request's place in HTTP/3 (h3::Event::slot)  \~spanish el sitio de la peticion en HTTP/3 (h3::Event::slot)  \~
 * @param stream \~english the request stream  \~spanish el flujo de la peticion  \~
 * @param res    \~english what the handler said  \~spanish lo que dijo el manejador  \~
 */
void Http3Service::start_open(uint32_t i, size_t place, uint64_t stream, const ResponseBuilder &res) noexcept {
    Slot &s = slots_[i];
    BodySource &src = *res.opened_source();

    /* \~english
     * A head that cannot travel is not sent half-opened: the source is ended
     * and the answer is a 500, as for any answer that could not be written.
     * \~spanish
     * Una cabecera que no puede viajar no se manda medio abierta: la fuente se
     * acaba y la respuesta es un 500, como toda respuesta que no se pudo
     * escribir.
     * \~ */
    if (place >= cfg_.h3.max_requests || s.opens == nullptr || !send_head(s, stream, res, false, false)) {
        ++counts_.bad_answers;
        port_->end(src, GoneReason::ConnectionClosed);
        respond_status(s, stream, 500);
        return;
    }

    /* \~english
     * What the handler wrote before opening is the first DATA frame.  It is
     * copied once, like the body of any whole answer: it is already bytes in
     * the builder's store, not something a source produces into the stream.
     * \~spanish
     * Lo que escribio el manejador antes de abrir es la primera trama DATA.  Se
     * copia una vez, como el cuerpo de cualquier respuesta entera: ya son bytes en
     * el almacen del constructor, no algo que una fuente produzca en el flujo.
     * \~ */
    const Span first = res.body();
    if (first.len != 0 && !s.h3->send_body(stream, res.bytes() + first.off, first.len, false)) {
        port_->end(src, GoneReason::ConnectionClosed);
        return;
    }

    const uint32_t k = static_cast<uint32_t>(place);
    OpenStream &o = s.opens[k];
    o.source = &src;
    o.stream = stream;
    o.kicked = false;
    o.hungry = true;
    o.prev = kNone;
    o.next = s.open_head;
    if (s.open_head != kNone) s.opens[s.open_head].prev = k;
    s.open_head = k;
    ++s.open_count;
    ++open_now_;
    ++counts_.served;

    /* \~english
     * And the first fill, if there is room (HVX-5, 4.3): it is hungry, never
     * asked, so the pull that builds the datagram carrying this head fills it
     * first -- the connection is queued by the datagram that brought the
     * request.  Filling here as well would be a second path to the same fill.
     * \~spanish
     * Y el primer relleno, si hay sitio (HVX-5, 4.3): esta hambrienta, nunca se
     * le pregunto, asi que el tiron que construye el datagrama que lleva esta
     * cabecera la rellena antes -- la conexion la pone en la cola el datagrama
     * que trajo la peticion.  Rellenar tambien aqui seria un segundo camino al
     * mismo relleno.
     * \~ */
}

/**
 * @brief
 * \~english Asks one open source for one DATA frame, if its stream has room; ends it when it says done.
 * \~spanish Le pide una trama DATA a una fuente abierta, si su flujo tiene sitio; la acaba cuando dice done.
 * \~
 *
 * @param s     \~english its connection  \~spanish su conexion  \~
 * @param place \~english its place  \~spanish su sitio  \~
 */
void Http3Service::fill_open(Slot &s, uint32_t place) noexcept {
    OpenStream &o = s.opens[place];
    size_t room = 0;
    uint8_t *dst = s.h3->body_room(o.stream, room);
    // \~english No room: nothing is asked, and the marks stay for when there is (R32).
    // \~spanish Sin sitio: no se pide nada, y las marcas se quedan para cuando lo haya (R32).  \~
    if (dst == nullptr) return;

    o.kicked = false;
    bool done = false;
    const size_t n = port_->fill(*o.source, dst, room, done);
    if (!s.h3->body_commit(o.stream, n, done)) {
        end_open(s, place, GoneReason::ConnectionClosed);
        return;
    }
    if (done) {
        end_open(s, place, GoneReason::Finished);
        return;
    }
    // \~english Less than the room says "no more for now": asked again when kicked.
    // \~spanish Menos que el sitio dice "por ahora no hay mas": se le vuelve a pedir cuando la avisen.  \~
    o.hungry = n == room;
}

/**
 * @brief
 * \~english Before a datagram is built: drops what the peer abandoned, and fills what is kicked or hungry.
 * \~spanish Antes de construir un datagrama: quita lo que abandono el otro extremo, y rellena lo avisado o hambriento.
 * \~
 *
 * @param s \~english the connection, with something open  \~spanish la conexion, con algo abierto  \~
 */
void Http3Service::feed_open(Slot &s) noexcept {
    watch_open(s);
    for (uint32_t k = s.open_head; k != kNone;) {
        const uint32_t next = s.opens[k].next;
        if (s.opens[k].kicked || s.opens[k].hungry) fill_open(s, k);
        k = next;
    }
}

/**
 * @brief
 * \~english Ends what cannot go on: all of it when the connection is closing, a stream the peer abandoned.
 * \~spanish Acaba lo que no puede seguir: todo cuando la conexion se esta cerrando, un flujo que abandono el otro.
 * \~
 *
 * \~english
 * Walks the connection's open list only: a connection with nothing open is
 * never looked at.
 * \~spanish
 * Recorre solo la lista de abiertas de la conexion: una conexion sin nada
 * abierto no se mira nunca.
 * \~
 *
 * @param s \~english the connection  \~spanish la conexion  \~
 */
void Http3Service::watch_open(Slot &s) noexcept {
    if (s.quic->state() != quic::ConnState::Active) {
        const bool idle = s.quic->end_reason() == quic::EndReason::IdleTimeout;
        end_all_open(s, idle ? GoneReason::IdleTimeout : GoneReason::ConnectionClosed);
        return;
    }
    for (uint32_t k = s.open_head; k != kNone;) {
        const uint32_t next = s.opens[k].next;
        /* \~english
         * Nothing more to do on the wire: QUIC answered the STOP_SENDING with
         * a RESET_STREAM itself (RFC 9000, 3.5), and the request direction was
         * read whole before the handler ran, so there is nothing left of it to
         * stop.
         * \~spanish
         * Nada mas que hacer en la red: QUIC contesto al STOP_SENDING con un
         * RESET_STREAM el mismo (RFC 9000, 3.5), y la direccion de la peticion se
         * leyo entera antes de que corriera el manejador, asi que no queda nada de
         * ella que parar.
         * \~ */
        if (abandoned(s.quic->streams().find(s.opens[k].stream))) end_open(s, k, GoneReason::PeerReset);
        k = next;
    }
}

/**
 * @brief
 * \~english Takes an open response off its connection and tells the loop why it ended.
 * \~spanish Quita una respuesta abierta de su conexion y le dice al bucle por que acabo.
 * \~
 *
 * @param s     \~english its connection  \~spanish su conexion  \~
 * @param place \~english its place  \~spanish su sitio  \~
 * @param why   \~english the reason its source is given  \~spanish el motivo que se le da a su fuente  \~
 */
void Http3Service::end_open(Slot &s, uint32_t place, GoneReason why) noexcept {
    OpenStream &o = s.opens[place];
    BodySource *src = o.source;
    if (src == nullptr) return;
    if (o.prev != kNone)
        s.opens[o.prev].next = o.next;
    else
        s.open_head = o.next;
    if (o.next != kNone) s.opens[o.next].prev = o.prev;
    o = OpenStream();
    --s.open_count;
    --open_now_;
    if (port_ != nullptr) port_->end(*src, why);
}

/**
 * @brief
 * \~english Ends every response open on @p s with @p why.
 * \~spanish Acaba cada respuesta abierta en @p s con @p why.
 * \~
 *
 * @param s   \~english the connection  \~spanish la conexion  \~
 * @param why \~english the reason  \~spanish el motivo  \~
 */
void Http3Service::end_all_open(Slot &s, GoneReason why) noexcept {
    while (s.open_head != kNone) end_open(s, s.open_head, why);
}

void Http3Service::on_kick(BodySource &source) noexcept {
    const OpenResponse r = source.response();
    Slot *s = slot_of(r.conn);
    const size_t place = s == nullptr || s->opens == nullptr ? h3::Event::kNoSlot : s->h3->slot_of(r.stream);
    // \~english A kick that finds nothing of its own is counted, never followed somewhere else.
    // \~spanish Un aviso que no encuentra nada suyo se cuenta, nunca se sigue a otro sitio.  \~
    if (place >= cfg_.h3.max_requests || s->opens[place].source != &source) {
        ++counts_.stray_kicks;
        return;
    }
    s->opens[place].kicked = true;
    queue_send(r.conn.slot);
}

void Http3Service::on_shutdown() noexcept {
    // \~english Once, when the loop lets go: every slot is looked at, and only then.
    // \~spanish Una vez, cuando el bucle lo suelta todo: se mira cada casilla, y solo entonces.  \~
    for (uint32_t i = 0; i < capacity_; ++i)
        if (slots_[i].quic != nullptr && slots_[i].open_head != kNone) end_all_open(slots_[i], GoneReason::Shutdown);
}

} // namespace http_vx
