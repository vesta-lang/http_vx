/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/connection_control.cpp
 * @brief
 * \~english The frames about the connection rather than a request: SETTINGS, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY.
 * \~spanish Las tramas que hablan de la conexion y no de una peticion: SETTINGS, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY.
 * \~
 */

#include "http_vx/h2_connection.h"

namespace http_vx {
namespace h2 {

namespace {

/**
 * @brief
 * \~english Which rule a WINDOW_UPDATE broke, from the code @c Window::give answered.
 * \~spanish Que regla rompio un WINDOW_UPDATE, por el codigo que contesto @c Window::give.
 * \~
 *
 * @param e \~english what the window said  \~spanish lo que dijo la ventana  \~
 * @return  \~english the rule  \~spanish la regla  \~
 */
const char *window_why(ErrorCode e) noexcept {
    if (e == ErrorCode::ProtocolError)
        return "a WINDOW_UPDATE of zero (RFC 9113, 6.9)";
    return "a WINDOW_UPDATE past 2^31-1 (RFC 9113, 6.9.1)";
}

/**
 * @brief
 * \~english Which rule a SETTINGS broke, from the code @c apply_settings answered.
 * \~spanish Que regla rompio un SETTINGS, por el codigo que contesto @c apply_settings.
 * \~
 *
 * @param e \~english what the settings said  \~spanish lo que dijeron los ajustes  \~
 * @return  \~english the rule  \~spanish la regla  \~
 */
const char *settings_why(ErrorCode e) noexcept {
    if (e == ErrorCode::FrameSizeError)
        return "a SETTINGS payload that is not a whole number of settings "
               "(RFC 9113, 6.5)";
    if (e == ErrorCode::FlowControlError)
        return "a SETTINGS_INITIAL_WINDOW_SIZE past 2^31-1 (RFC 9113, 6.5.2)";
    return "a SETTINGS value outside its range (RFC 9113, 6.5.2)";
}

} // namespace

Event Connection::on_settings(const View &v) noexcept {
    const FrameHeader &h = reader_.header();

    /* \~english
     * An acknowledgement is not a settings frame with nothing in it: it is a
     * different message that happens to share a type, and it must carry no
     * payload at all.  One that did would be a peer announcing settings and
     * calling it an answer, which is two meanings in one frame.
     * \~spanish
     * Una confirmacion no es un SETTINGS sin nada dentro: es otro mensaje que
     * resulta compartir tipo, y no puede llevar ninguna carga.  Uno que la
     * llevara seria un extremo anunciando ajustes y llamandolo una respuesta,
     * que son dos significados en una trama.
     * \~ */
    if ((h.flags & kAck) != 0) {
        if (h.length != 0)
            return fail(ErrorCode::FrameSizeError,
                        "a SETTINGS acknowledgement with a payload (RFC 9113, "
                        "6.5)");
        return Event{};
    }

    const Span p = reader_.payload();
    const uint8_t *at = v.at(v.origin + p.off);

    const SettingsChange c = apply_settings(at, p.len, peer_);
    if (c.error != ErrorCode::NoError)
        return fail(c.error, settings_why(c.error));

    /* \~english
     * A changed initial window says two things, and both have to happen: what
     * a stream opened from now on starts at, and how far the ones already open
     * move.  Doing only the first leaves this end out of step with its peer in
     * a way that shows up as a stall much later.
     * \~spanish
     * Una ventana inicial cambiada dice dos cosas, y las dos tienen que pasar:
     * en cuanto empieza un flujo que se abra a partir de ahora, y cuanto se
     * mueven los que ya estan abiertos.  Hacer solo la primera deja a este
     * extremo desacompasado del otro de una forma que sale como un atasco mucho
     * despues.
     * \~ */
    if (c.window_delta != 0) {
        const ErrorCode e = streams_.adjust_send_windows(c.window_delta);
        if (e != ErrorCode::NoError)
            return fail(e, "a new initial window that takes an open stream "
                           "past 2^31-1 (RFC 9113, 6.9.2)");
    }
    streams_.set_peer_initial_window(peer_.initial_window_size);

    /* \~english
     * The encoder's table follows the peer's announcement, because it is the
     * peer that has to hold what this end asks it to remember -- and the
     * encoder takes care of telling it, which it must, at the start of the
     * next block.
     * \~spanish
     * La tabla del codificador sigue el anuncio del otro extremo, porque es el
     * otro el que tiene que guardar lo que este le pide que recuerde -- y el
     * codificador se encarga de decirselo, que es obligatorio, al principio del
     * bloque siguiente.
     * \~ */
    encoder_.set_table_size(peer_.header_table_size);

    if (!put_frame(FrameType::Settings, kAck, 0, nullptr, 0)) return no_room();
    return Event{};
}

Event Connection::on_ping(const View &v) noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length != 8)
        return fail(ErrorCode::FrameSizeError,
                    "a PING that is not eight bytes (RFC 9113, 6.7)");

    /* \~english
     * An answer is not answered.  Without this a pair of servers that both
     * echoed everything would ping each other forever at the speed of the
     * network, which is a loop neither of them is doing anything wrong in.
     * \~spanish
     * A una respuesta no se le contesta.  Sin esto, dos servidores que
     * devolvieran todo se harian ping el uno al otro para siempre a la
     * velocidad de la red, que es un bucle en el que ninguno de los dos hace
     * nada mal.
     * \~ */
    if ((h.flags & kAck) != 0) return Event{};

    const Span p = reader_.payload();
    if (!put_frame(FrameType::Ping, kAck, 0, v.at(v.origin + p.off), p.len)) return no_room();
    return Event{};
}

Event Connection::on_window_update(const View &v) noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length != 4)
        return fail(ErrorCode::FrameSizeError,
                    "a WINDOW_UPDATE that is not four bytes (RFC 9113, 6.9)");

    const Span p = reader_.payload();
    const uint32_t n = window_increment(v.at(v.origin + p.off));

    if (h.stream_id == 0) {
        const ErrorCode e = send_.give(n);
        if (e != ErrorCode::NoError) return fail(e, window_why(e));
        return Event{};
    }

    Stream *s = streams_.find(h.stream_id);
    if (s == nullptr) {
        /* \~english
         * For a stream that finished it is merely late, however it finished
         * (RFC 9113, 6.9: "A receiver MUST NOT treat this as an error"); for
         * one that was never opened it is the peer offering allowance on a
         * request that does not exist.
         * \~spanish
         * De un flujo terminado solo llega tarde, acabara como acabara (RFC
         * 9113, 6.9: "A receiver MUST NOT treat this as an error"); de uno que
         * no se abrio nunca es el otro extremo ofreciendo credito sobre una
         * peticion que no existe.
         * \~ */
        if (streams_.never_opened(h.stream_id))
            return fail(ErrorCode::ProtocolError,
                        "a WINDOW_UPDATE on an idle stream (RFC 9113, 5.1)");
        return Event{};
    }

    /* \~english
     * An increment this stream cannot hold ends the STREAM and not the
     * connection: the two ends have lost count of one request between them,
     * and the hundreds of others on the connection are unaffected.
     * \~spanish
     * Un incremento que este flujo no puede guardar acaba el FLUJO y no la
     * conexion: los dos extremos han perdido la cuenta de una peticion, y las
     * otras cientos de la conexion no tienen nada que ver.
     * \~ */
    const ErrorCode e = s->send.give(n);
    if (e != ErrorCode::NoError) return refuse(h.stream_id, e, window_why(e));

    return Event{};
}

Event Connection::on_rst_stream() noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length != 4)
        return fail(ErrorCode::FrameSizeError,
                    "a RST_STREAM that is not four bytes (RFC 9113, 6.4)");

    const Outcome o = streams_.on_reset(h.stream_id);
    if (o.verdict == Verdict::ConnectionError) return fail(o.error, o.why);
    if (o.verdict == Verdict::Discard) return Event{};

    Event e;
    e.kind = EventKind::StreamEnded;
    e.stream_id = h.stream_id;
    e.error = ErrorCode::Cancel;
    return e;
}

Event Connection::on_goaway(const View &v) noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length < 8)
        return fail(ErrorCode::FrameSizeError,
                    "a GOAWAY shorter than eight bytes (RFC 9113, 6.8)");

    const Span p = reader_.payload();
    const ErrorCode code = static_cast<ErrorCode>(be32(v.at(v.origin + p.off) + 4));

    /* \~english
     * NO_ERROR is a graceful shutdown, and the connection carries on: GOAWAY
     * "allows an endpoint to gracefully stop accepting new streams while
     * still finishing processing of previously established streams" (RFC
     * 9113, 6.8).  Its last stream identifier is "the last peer-initiated
     * stream" from the SENDER's side -- here, a stream this server would have
     * opened -- and this server opens none, so it cancels nothing.
     *
     * Streams the client opens AFTER its own GOAWAY are still served.  The
     * RFC binds the RECEIVER: "Receivers of a GOAWAY frame MUST NOT open
     * additional streams" -- and the receiver is this end, which opens none
     * anyway.  Nothing forbids the sender from opening one (a request already
     * in flight when it decided to leave is the ordinary case), and refusing
     * it would lose a request the client sent in good faith.  So nothing
     * about reading changes; only the end does, see @c may_leave.
     *
     * A second GOAWAY(NO_ERROR) says the same again.  One with any other code
     * -- first or after a graceful one ("an endpoint that sends GOAWAY with
     * NO_ERROR during graceful shutdown could subsequently encounter a
     * condition that requires immediate termination", 6.8) -- ends the
     * connection at once, and this end writes no GOAWAY of its own: the peer
     * has stopped listening.
     * \~spanish
     * NO_ERROR es un apagado con calma, y la conexion sigue: GOAWAY "allows
     * an endpoint to gracefully stop accepting new streams while still
     * finishing processing of previously established streams" (RFC 9113,
     * 6.8).  Su ultimo identificador de flujo es "the last peer-initiated
     * stream" visto desde quien lo MANDA -- aqui, un flujo que habria abierto
     * este servidor -- y este servidor no abre ninguno, asi que no cancela
     * nada.
     *
     * Los flujos que abre el cliente DESPUES de su propio GOAWAY se siguen
     * atendiendo.  El RFC obliga al que lo RECIBE: "Receivers of a GOAWAY
     * frame MUST NOT open additional streams" -- y el que lo recibe es este
     * extremo, que no abre ninguno igualmente.  Nada le prohibe abrir uno al
     * que lo manda (una peticion ya en vuelo cuando decidio irse es el caso
     * corriente), y rechazarla perderia una peticion que el cliente mando de
     * buena fe.  Asi que la lectura no cambia; solo cambia el final, ver
     * @c may_leave.
     *
     * Un segundo GOAWAY(NO_ERROR) dice lo mismo otra vez.  Uno con cualquier
     * otro codigo -- el primero o detras de uno con calma ("an endpoint that
     * sends GOAWAY with NO_ERROR during graceful shutdown could subsequently
     * encounter a condition that requires immediate termination", 6.8) --
     * acaba la conexion en el acto, y este extremo no escribe GOAWAY propio:
     * el otro ha dejado de escuchar.
     * \~ */
    Event e;
    e.error = code;
    if (code == ErrorCode::NoError) {
        peer_leaving_ = true;
        e.kind = EventKind::PeerLeaving;
        return e;
    }

    closed_ = true;
    e.kind = EventKind::Closed;
    return e;
}

void Connection::put_goaway(ErrorCode code) noexcept {
    /* \~english
     * A GOAWAY carries the last stream this end actually looked at, so the
     * peer knows which of its requests were seen and which it may send again
     * on a new connection.  Reporting zero -- or the highest possible -- would
     * be telling it either that nothing was served or that everything was, and
     * both are answers it would act on.
     * \~spanish
     * Un GOAWAY lleva el ultimo flujo que este extremo llego a mirar, para que
     * el otro sepa cuales de sus peticiones se vieron y cuales puede volver a
     * mandar por una conexion nueva.  Decir cero -- o el mayor posible -- seria
     * decirle o que no se sirvio nada o que se sirvio todo, y las dos son
     * respuestas sobre las que actuaria.
     * \~ */
    uint8_t payload[kGoawaySize - kFrameHeaderSize];
    put_be32(payload, streams_.highest_seen());
    put_be32(payload + 4, static_cast<uint32_t>(code));

    /* \~english
     * Both callers end the connection whatever happens here, and both made
     * sure of the room first; if it was not there, the peer loses only the
     * courtesy of the reason (see @c fail).
     * \~spanish
     * Los dos que llaman acaban la conexion pase lo que pase aqui, y los dos se
     * aseguraron antes del sitio; si no estaba, el otro solo pierde la
     * cortesia del motivo (ver @c fail).
     * \~ */
    static_cast<void>(put_frame(FrameType::Goaway, 0, 0, payload, sizeof payload));
}

bool Connection::may_leave() const noexcept {
    return peer_leaving_ && !closed_ && streams_.count() == 0 &&
           !reader_.awaiting_continuation();
}

void Connection::leave() noexcept {
    closed_ = true;
    put_goaway(ErrorCode::NoError);
}

} // namespace h2
} // namespace http_vx
