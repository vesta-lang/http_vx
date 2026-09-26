/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service_write.cpp
 * @brief
 * \~english The HTTP/2 service's way out: frames into the output, bodies as the windows allow, and what the connection owes.
 * \~spanish La salida del servicio HTTP/2: tramas a la salida, cuerpos segun dejen las ventanas, y lo que debe la conexion.
 * \~
 */

#include "http_vx/http2_service.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

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

bool Http2Service::send_reset(State &s, uint32_t stream, h2::ErrorCode code,
                              Buffer &out) noexcept {
    if (s.conn.reset_stream(stream, code)) return true;

    /* \~english
     * No room in the connection's answers.  Not reachable today -- every event
     * is read after a flush, and the most a caller adds to one is a RST_STREAM
     * and two WINDOW_UPDATEs, far below the kilobyte -- and that is exactly why
     * it is not assumed: the day the sum changes, what fails is a flush that
     * happens early, and not a reset that never goes.
     * \~spanish
     * No hay sitio en las respuestas de la conexion.  Hoy no se llega aqui --
     * cada suceso se lee despues de un vaciado, y lo mas que anade quien llama a
     * uno es un RST_STREAM y dos WINDOW_UPDATE, muy por debajo del kilobyte --, y
     * justo por eso no se supone: el dia que cambie la cuenta, lo que pasa es un
     * vaciado que llega antes, y no un reinicio que no sale nunca.
     * \~ */
    return flush_control(s, out) && s.conn.reset_stream(stream, code);
}

bool Http2Service::give_window(State &s, uint32_t stream, size_t n,
                               Buffer &out) noexcept {
    const uint32_t k = static_cast<uint32_t>(n);
    if (s.conn.release_window(stream, k)) return true;

    // \~english The same as @c send_reset: the window owed goes out, now or never.
    // \~spanish Lo mismo que @c send_reset: la ventana que se debe sale, ahora o nunca.  \~
    return flush_control(s, out) && s.conn.release_window(stream, k);
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

} // namespace http_vx
