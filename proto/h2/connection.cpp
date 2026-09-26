/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/connection.cpp
 * @brief
 * \~english Driving one connection: the answers it owes, how it ends, and which frame goes where.
 * \~spanish Mover una conexion: las respuestas que debe, como acaba, y que trama va adonde.
 * \~
 *
 * \~english
 * The frames themselves are read in two other files: the ones about the
 * connection in connection_control.cpp, the ones that carry a request in
 * connection_request.cpp.
 * \~spanish
 * Las tramas mismas se leen en otros dos ficheros: las que hablan de la
 * conexion en connection_control.cpp, las que llevan una peticion en
 * connection_request.cpp.
 * \~
 */

#include "http_vx/h2_connection.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h2 {

namespace {

/**
 * @brief
 * \~english The largest answer this end ever writes in one go.
 * \~spanish La respuesta mas grande que escribe este extremo de una vez.
 * \~
 *
 * \~english
 * A DATA frame for a stream that is over, which is the frame that provokes the
 * MOST: a RST_STREAM saying so, and two WINDOW_UPDATEs giving back an
 * allowance nobody is going to consume.  It is the number the room check is
 * made against before reading a frame, so that a frame is never read whose
 * answer cannot be written -- which would mean either dropping the answer or
 * growing the buffer, and the second is what the fixed buffer exists to rule
 * out.
 *
 * It was a PING echo -- seventeen bytes -- until the frames that give window
 * back were written, and that was not a tight estimate that got tighter: an
 * answer the room was not checked for is an answer that is quietly dropped,
 * and the one being dropped here would have been the allowance that keeps the
 * connection moving.
 *
 * \~spanish
 * Una trama DATA de un flujo ya terminado, que es la que provoca MAS: un
 * RST_STREAM diciendolo, y dos WINDOW_UPDATE devolviendo un credito que no va a
 * consumir nadie.  Es el numero contra el que se comprueba el sitio antes de
 * leer una trama, para no leer nunca una cuya respuesta no se pueda escribir --
 * que seria o tirar la respuesta o hacer crecer el buffer, y lo segundo es lo
 * que el buffer fijo existe para descartar.
 *
 * Era el eco de un PING -- diecisiete bytes -- hasta que se escribieron las
 * tramas que devuelven ventana, y eso no fue una estimacion justa que se quedo
 * mas justa: una respuesta para la que no se comprobo el sitio es una respuesta
 * que se tira por lo bajo, y la que se estaria tirando aqui es el credito que
 * mantiene la conexion en marcha.
 *
 * \~
 */
constexpr size_t kLargestAnswer =
    (kFrameHeaderSize + 4) + 2 * (kFrameHeaderSize + 4);

} // namespace

void Connection::reset(const Limits &limits) noexcept {
    limits_ = limits;
    closed_ = false;

    reader_ = FrameReader(limits);
    reader_.reset(0, true);

    decoder_.reset(limits);
    encoder_.reset(peer_.header_table_size);
    streams_.reset(limits);

    peer_ = Settings();

    /* \~english
     * The two connection windows start at the specification's default and NOT
     * at this server's announced initial window.  That setting is about
     * STREAMS: the connection's own window is fixed at 65535 until a
     * WINDOW_UPDATE moves it, and a server that seeded it from its own limits
     * would believe it could receive more than it said, or send more than it
     * was offered.
     *
     * \~spanish
     * Las dos ventanas de la conexion empiezan en el valor por defecto de la
     * especificacion y NO en la ventana inicial que anuncia este servidor.  Ese
     * ajuste habla de los FLUJOS: la ventana propia de la conexion se queda en
     * 65535 hasta que un WINDOW_UPDATE la mueva, y un servidor que la sembrara
     * con sus limites creeria que puede recibir mas de lo que dijo, o mandar mas
     * de lo que le ofrecieron.
     * \~ */
    send_ = Window(65535);
    recv_ = Window(65535);

    control_len_ = 0;
    block_.clear();
    block_trailers_ = false;
    block_why_ = nullptr;
    block_dropped_ = false;
    why_ = nullptr;

    /* \~english
     * And this end speaks first.  The peer may start sending requests the
     * moment it has written its preface, and every one of them would be read
     * under limits it has not been told about if this SETTINGS waited for it.
     * \~spanish
     * Y este extremo habla primero.  El otro puede empezar a mandar peticiones
     * en cuanto haya escrito su preambulo, y todas ellas se leerian con unos
     * limites de los que no le han hablado si este SETTINGS esperara a que
     * hablara el.
     * \~ */
    uint8_t payload[kSettingSize * 6];
    const size_t n = write_settings(payload, sizeof payload, limits_);
    // \~english Into a buffer emptied above: fifty-odd bytes of a kilobyte always fit.
    // \~spanish En un buffer vaciado arriba: cincuenta y pico bytes de un kilobyte caben siempre.  \~
    static_cast<void>(put_frame(FrameType::Settings, 0, 0, payload, n));
}

void Connection::release() noexcept {
    decoder_.release();
    encoder_.release();
    streams_.release();
    block_.release();
    control_len_ = 0;
}

bool Connection::put_frame(FrameType type, uint8_t flags, uint32_t id,
                           const uint8_t *payload, size_t n) noexcept {
    if (!control_room(kFrameHeaderSize + n)) return false;

    FrameHeader h;
    h.length = static_cast<uint32_t>(n);
    h.type = static_cast<uint8_t>(type);
    h.flags = flags;
    h.stream_id = id;

    encode_frame_header(control_ + control_len_, h);
    control_len_ += kFrameHeaderSize;

    if (n != 0) {
        util::vesta_memcpy(control_ + control_len_, payload, n);
        control_len_ += n;
    }

    return true;
}

void Connection::flushed(size_t n) noexcept {
    if (n >= control_len_) {
        control_len_ = 0;
        return;
    }

    /* \~english
     * What is left moves to the front.  A kilobyte moved on a partial write is
     * nothing next to the write itself, and the alternative -- a ring, or a
     * read offset -- would mean @c pending could not hand out one contiguous
     * piece, which is the whole point of it.
     * \~spanish
     * Lo que queda se mueve al principio.  Mover un kilobyte en una escritura
     * parcial no es nada al lado de la escritura misma, y la alternativa -- un
     * anillo, o un desplazamiento de lectura -- haria que @c pending no pudiera
     * entregar un solo pedazo seguido, que es para lo que esta.
     * \~ */
    control_len_ -= n;
    util::vesta_memmove(control_, control_ + n, control_len_);
}

bool Connection::release_window(uint32_t id, uint32_t n) noexcept {
    if (n == 0) return true;

    /* \~english
     * A stream no longer in the table is closed -- answered and ended, or
     * reset -- and "an endpoint MUST NOT send frames other than PRIORITY on a
     * closed stream" (RFC 9113, 5.1).  The caller gives the window back after
     * the handler, which is often after the answer that closed the stream, so
     * this is the ordinary case and not a corner: only the CONNECTION's window
     * goes back, which is the one still counting.
     * \~spanish
     * Un flujo que ya no esta en la tabla esta cerrado -- contestado y acabado,
     * o reiniciado -- y "an endpoint MUST NOT send frames other than PRIORITY on
     * a closed stream" (RFC 9113, 5.1).  Quien llama devuelve la ventana
     * despues del manejador, que muchas veces es despues de la respuesta que
     * cerro el flujo, asi que este es el caso corriente y no una esquina: solo
     * vuelve la ventana de la CONEXION, que es la que sigue contando.
     * \~ */
    Stream *s = streams_.find(id);
    if (s == nullptr) return credit_connection(n);

    if (!control_room(2 * (kFrameHeaderSize + 4))) return false;

    uint8_t payload[4];
    put_be32(payload, n);

    /* \~english
     * Both, and the room for both was checked before either went in.  Writing
     * one and finding there was no space for the other would leave the peer
     * given back allowance on the stream and not on the connection, which
     * stalls just as surely -- only later, and for no reason anybody can see.
     * \~spanish
     * Los dos, y el sitio para los dos se comprobo antes de meter ninguno.
     * Escribir uno y encontrarse sin sitio para el otro dejaria al otro extremo
     * con el credito devuelto en el flujo y no en la conexion, que atasca igual
     * de seguro -- solo que mas tarde, y sin que nadie pueda ver por que.
     * \~ */
    put_frame(FrameType::WindowUpdate, 0, 0, payload, sizeof payload);
    put_frame(FrameType::WindowUpdate, 0, id, payload, sizeof payload);

    recv_.give(n);
    s->recv.give(n);

    return true;
}

bool Connection::credit_connection(uint32_t n) noexcept {
    if (n == 0) return true;
    if (!control_room(kFrameHeaderSize + 4)) return false;

    uint8_t payload[4];
    put_be32(payload, n);

    put_frame(FrameType::WindowUpdate, 0, 0, payload, sizeof payload);
    recv_.give(n);
    return true;
}

bool Connection::reset_stream(uint32_t id, ErrorCode code) noexcept {
    uint8_t payload[4];
    put_be32(payload, static_cast<uint32_t>(code));

    if (!put_frame(FrameType::RstStream, 0, id, payload, sizeof payload))
        return false;

    /* \~english
     * Not @c on_reset, which is the PEER's reset: after this one the peer may
     * still send anything it had queued, and the stream table has to know
     * that those frames are late and not wrong (RFC 9113, 5.1).
     * \~spanish
     * No @c on_reset, que es el reinicio del OTRO: despues de este el otro
     * puede seguir mandando lo que tuviera encolado, y la tabla de flujos tiene
     * que saber que esas tramas llegan tarde y no mal (RFC 9113, 5.1).
     * \~ */
    streams_.on_reset_sent(id);
    return true;
}

Event Connection::fail(ErrorCode code, const char *why) noexcept {
    closed_ = true;
    why_ = why;

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
    uint8_t payload[8];
    put_be32(payload, streams_.highest_seen());
    put_be32(payload + 4, static_cast<uint32_t>(code));

    /* \~english
     * The room was kept by @c read, so this goes in.  If it did not -- which
     * is @c no_room's case -- nothing is lost that a return could save: the
     * connection is over either way and the caller is told so below, with
     * @c why; the peer only loses the courtesy of the reason.
     * \~spanish
     * El sitio lo guardo @c read, asi que esto entra.  Si no entrara -- que es
     * el caso de @c no_room -- no se pierde nada que un retorno pudiera salvar:
     * la conexion se acaba igual y a quien llama se le dice abajo, con @c why;
     * el otro extremo solo pierde la cortesia del motivo.
     * \~ */
    static_cast<void>(put_frame(FrameType::Goaway, 0, 0, payload, sizeof payload));

    Event e;
    e.kind = EventKind::Closed;
    e.error = code;
    return e;
}

Event Connection::no_room() noexcept {
    return fail(ErrorCode::InternalError,
                "no room to answer a frame, which the room check before "
                "reading rules out (kLargestAnswer is too small)");
}

Event Connection::refuse(uint32_t id, ErrorCode code, const char *why) noexcept {
    /* \~english
     * It cannot fail: this is only reached from @c read, which checked there
     * was room for @c kLargestAnswer before reading the frame, and no frame
     * provokes more.  If it did anyway, the stream table would say the stream
     * is over while the peer, never told, kept it open -- so a failure here is
     * this end's own arithmetic being wrong, and it ends the connection saying
     * so rather than carrying on with the two ends disagreeing.
     * \~spanish
     * No puede fallar: solo se llega desde @c read, que comprobo que habia sitio
     * para @c kLargestAnswer antes de leer la trama, y ninguna trama provoca
     * mas.  Si aun asi fallara, la tabla de flujos diria que el flujo se acabo
     * mientras el otro extremo, al que nadie avisa, lo seguiria teniendo
     * abierto -- asi que un fallo aqui es la propia cuenta de este extremo
     * saliendo mal, y acaba la conexion diciendolo en vez de seguir con los dos
     * extremos en desacuerdo.
     * \~ */
    if (!reset_stream(id, code)) return no_room();
    why_ = why;

    Event e;
    e.kind = EventKind::StreamEnded;
    e.stream_id = id;
    e.error = code;
    return e;
}

Event Connection::read(const View &v, Buffer &headers,
                       http_vx::Request &req) noexcept {
    why_ = nullptr;
    if (closed_) return Event{};

    /* \~english
     * Nothing is read that cannot be answered.  This is the whole of the
     * backpressure: a peer that asks for answers faster than its own socket
     * takes them does not make this end hold more, it makes this end stop
     * reading -- and the memory spent on it never depends on how much it sent.
     *
     * \~spanish
     * No se lee nada que no se pueda contestar.  Esto es toda la contrapresion:
     * un extremo que pida respuestas mas deprisa de lo que las acepta su propio
     * socket no hace que este extremo guarde mas, hace que este extremo deje de
     * leer -- y la memoria que se gasta en ello no depende nunca de cuanto
     * mando.
     * \~ */
    if (!control_room(kLargestAnswer)) return Event{};

    const ReadResult r = reader_.read(v);
    if (r == ReadResult::NeedMore) return Event{};
    if (r == ReadResult::Error) return fail(reader_.error(), nullptr);

    const FrameHeader &h = reader_.header();

    switch (static_cast<FrameType>(h.type)) {
    case FrameType::Settings:
        return on_settings(v);

    case FrameType::Ping:
        return on_ping(v);

    case FrameType::WindowUpdate:
        return on_window_update(v);

    case FrameType::Headers:
    case FrameType::Continuation:
        return on_headers(v, headers, req);

    case FrameType::Data:
        return on_data(v);

    case FrameType::RstStream:
        return on_rst_stream();

    case FrameType::Goaway:
        return on_goaway(v);

    case FrameType::PushPromise:
        /* \~english
         * Only a server pushes, so one arriving here is a client claiming to
         * be one.  There is no stream to refuse it on -- the identifier it
         * carries is one this end would have opened -- so it ends the
         * connection.
         * \~spanish
         * Solo empuja un servidor, asi que uno que llegue aqui es un cliente
         * diciendo que lo es.  No hay flujo sobre el que rechazarlo -- el
         * identificador que lleva es uno que habria abierto este extremo -- asi
         * que acaba la conexion.
         * \~ */
        return fail(ErrorCode::ProtocolError,
                    "a PUSH_PROMISE from a client (RFC 9113, 8.4)");

    case FrameType::Priority:
        /* \~english
         * Read and dropped.  RFC 9113 deprecated the scheme it belonged to,
         * and a peer is still allowed to send it -- so refusing would close
         * connections over a frame that means nothing, and acting on it would
         * be implementing a thing the specification withdrew.
         * \~spanish
         * Se lee y se tira.  El RFC 9113 retiro el esquema al que pertenecia, y
         * un extremo la puede mandar igual -- asi que rechazarla cerraria
         * conexiones por una trama que no significa nada, y atenderla seria
         * implementar algo que la especificacion retiro.
         * \~ */
        return Event{};
    }

    /* \~english
     * A type nobody here knows.  Dropped for the same reason an unknown
     * setting is: it belongs to a version this end does not speak, and the way
     * the protocol is extended is that an implementation which does not know a
     * frame carries on.
     * \~spanish
     * Un tipo que aqui no conoce nadie.  Se tira por lo mismo que un ajuste
     * desconocido: es de una version que este extremo no habla, y la forma en
     * que se extiende el protocolo es que una implementacion que no conozca una
     * trama siga adelante.
     * \~ */
    return Event{};
}

} // namespace h2
} // namespace http_vx
