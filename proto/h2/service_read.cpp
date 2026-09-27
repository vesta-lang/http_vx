/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service_read.cpp
 * @brief
 * \~english The HTTP/2 service's way in: a connection's events turned into requests, bodies and refusals.
 * \~spanish La entrada del servicio HTTP/2: los sucesos de una conexion convertidos en peticiones, cuerpos y rechazos.
 * \~
 */

#include "http_vx/http2_service.h"

#include "util/mem/vesta_memcpy.h"

#include <utility>

namespace http_vx {

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

            /* \~english
             * An open response on it ends with it.  The peer reset it, or broke
             * a rule on it and this end reset it: either way it is the peer
             * that stopped the stream, and its source is told so.
             * \~spanish
             * Una respuesta abierta en el acaba con el.  El otro extremo lo
             * reinicio, o rompio una regla en el y este lo reinicio: en los dos
             * casos es el otro el que paro el flujo, y a su fuente se le dice.
             * \~ */
            if (s.opens.count != 0) end_stream_open(s, e.stream_id, GoneReason::PeerReset);
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
            // \~english Nothing has been processed yet, so REFUSED_STREAM is true: it may be sent again (RFC 9113, 8.7).
            // \~spanish Todavia no se ha procesado nada, asi que REFUSED_STREAM es verdad: puede volver a mandarse (RFC 9113, 8.7).  \~
            Work *w = take_work(s, e.stream_id);
            if (w == nullptr) {
                if (!send_reset(s, e.stream_id, h2::ErrorCode::RefusedStream, out)) return false;
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
                if (!send_reset(s, e.stream_id, h2::ErrorCode::StreamClosed, out)) return false;
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

        if (e.kind == h2::EventKind::HeadersTooLarge) {
            /* \~english
             * More header than this server takes, head or trailers: answered
             * 431 on its stream, which a client can show, rather than reset
             * with ENHANCE_YOUR_CALM, which it can only log (RFC 9113,
             * 10.5.1).  The handler is not asked -- what was decoded is not
             * the request -- and a body being gathered for it is let go by
             * the refusal.  A peer still sending is asked to stop.
             * \~spanish
             * Mas cabecera de la que acepta este servidor, cabecera o remolques:
             * se contesta 431 en su flujo, que un cliente puede ensenar, en vez de
             * reiniciarlo con ENHANCE_YOUR_CALM, que solo puede anotar (RFC 9113,
             * 10.5.1).  Al manejador no se le pregunta -- lo descodificado no es
             * la peticion -- y el cuerpo que se estuviera juntando lo suelta el
             * rechazo.  A un extremo que sigue mandando se le pide que pare.
             * \~ */
            Work *w = find_work(s, e.stream_id);
            if (w != nullptr && w->answering) {
                if (!send_reset(s, e.stream_id, h2::ErrorCode::StreamClosed, out)) return false;
                continue;
            }
            if (!refuse(s, e.stream_id, status::kHeaderFieldsTooLarge, w, out)) return false;
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
            if (!send_reset(s, e.stream_id, h2::ErrorCode::StreamClosed, out)) return false;
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
            if (!give_window(s, e.stream_id, e.size, out)) return false;
            if (!refuse(s, e.stream_id, status::kContentTooLarge, w, out)) return false;
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
            if (!give_window(s, e.stream_id, e.size, out)) return false;
            continue;
        }

        if (e.size != 0) {
            uint8_t *room = keep->reserve(e.size);
            if (room == nullptr) return false;

            util::vesta_memcpy(room, e.data, e.size);
            keep->commit(e.size);

            if (!give_window(s, e.stream_id, e.size, out)) return false;
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

    /* \~english
     * The same event may unblock an open response: one that wants to be asked
     * and now has room asks the shard for it (HVX-5, 4.3).
     * \~spanish
     * El mismo suceso puede desbloquear una respuesta abierta: una que quiere
     * que se le pregunte y ahora tiene sitio se lo pide al fragmento (HVX-5,
     * 4.3).
     * \~ */
    if (s.opens.count != 0) wake_open(s);

    const uint64_t done = s.conn.consumed();
    if (done > in.origin()) in.consume(static_cast<size_t>(done - in.origin()));

    return alive;
}

} // namespace http_vx
