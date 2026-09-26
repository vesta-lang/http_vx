/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/connection.cpp
 * @brief
 * \~english Driving one connection: the frames, the streams and the answers.
 * \~spanish Mover una conexion: las tramas, los flujos y las respuestas.
 * \~
 */

#include "http_vx/h2_connection.h"

#include "http_vx/content_length.h"

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
    put_frame(FrameType::Settings, 0, 0, payload, n);
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
    Stream *s = streams_.find(id);
    if (s != nullptr) s->recv.give(n);

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

    streams_.on_reset(id);
    return true;
}

Event Connection::fail(ErrorCode code) noexcept {
    closed_ = true;

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
    put_frame(FrameType::Goaway, 0, 0, payload, sizeof payload);

    Event e;
    e.kind = EventKind::Closed;
    e.error = code;
    return e;
}

Event Connection::refuse(uint32_t id, ErrorCode code, const char *why) noexcept {
    reset_stream(id, code);
    why_ = why;

    Event e;
    e.kind = EventKind::StreamEnded;
    e.stream_id = id;
    e.error = code;
    return e;
}

const char *Connection::expect_content(const Buffer &headers,
                                       const http_vx::Request &req) noexcept {
    /* \~english
     * The field is read by the same code HTTP/1.1 reads it with (RFC 9110,
     * 8.6): every occurrence, every list element, digits only.  A value that
     * is not a length at all cannot equal the content, whatever the content
     * turns out to be, so it is malformed now rather than later (RFC 9113,
     * 8.1.1).
     * \~spanish
     * La cabecera se lee con el mismo codigo con que la lee HTTP/1.1 (RFC 9110,
     * 8.6): todas las apariciones, todos los elementos de la lista, solo
     * digitos.  Un valor que no es una longitud no puede ser igual al
     * contenido, sea el contenido el que sea, asi que esta mal formado ahora y
     * no mas tarde (RFC 9113, 8.1.1).
     * \~ */
    const ContentLength cl = parse_content_length(req.fields, headers.data());

    if (cl.status == ContentLengthStatus::Absent) return nullptr;

    if (cl.status == ContentLengthStatus::Present) {
        const Outcome o = streams_.expect_content(block_stream_, cl.value);
        return o.verdict == Verdict::StreamError ? o.why : nullptr;
    }

    if (cl.status == ContentLengthStatus::Conflicting)
        return "content-length values that disagree (RFC 9110, 8.6; RFC 9113, "
               "8.1.1)";

    if (cl.status == ContentLengthStatus::Malformed)
        return "a content-length that is not a number (RFC 9110, 8.6; RFC "
               "9113, 8.1.1)";

    /* \~english
     * Too large to hold: the DATA this end counts could never add up to it,
     * so the equality RFC 9113, 8.1.1 asks for cannot be checked -- and a rule
     * that cannot be checked is refused, not waved through.
     * \~spanish
     * Demasiado grande para guardarla: los DATA que cuenta este extremo no
     * podrian sumarla nunca, asi que la igualdad que pide RFC 9113, 8.1.1 no se
     * puede comprobar -- y una regla que no se puede comprobar se rechaza, no se
     * deja pasar.
     * \~ */
    return "a content-length larger than this end can count (RFC 9113, 8.1.1)";
}

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
        if (h.length != 0) return fail(ErrorCode::FrameSizeError);
        return Event{};
    }

    const Span p = reader_.payload();
    const uint8_t *at = v.at(v.origin + p.off);

    const SettingsChange c = apply_settings(at, p.len, peer_);
    if (c.error != ErrorCode::NoError) return fail(c.error);

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
        if (e != ErrorCode::NoError) return fail(e);
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

    put_frame(FrameType::Settings, kAck, 0, nullptr, 0);
    return Event{};
}

Event Connection::on_ping(const View &v) noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length != 8) return fail(ErrorCode::FrameSizeError);

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
    put_frame(FrameType::Ping, kAck, 0, v.at(v.origin + p.off), p.len);
    return Event{};
}

Event Connection::on_window_update(const View &v) noexcept {
    const FrameHeader &h = reader_.header();
    if (h.length != 4) return fail(ErrorCode::FrameSizeError);

    const Span p = reader_.payload();
    const uint32_t n = window_increment(v.at(v.origin + p.off));

    if (h.stream_id == 0) {
        const ErrorCode e = send_.give(n);
        if (e != ErrorCode::NoError) return fail(e);
        return Event{};
    }

    Stream *s = streams_.find(h.stream_id);
    if (s == nullptr) {
        /* \~english
         * For a stream that finished it is merely late; for one that was never
         * opened it is the peer offering allowance on a request that does not
         * exist.
         * \~spanish
         * De un flujo terminado solo llega tarde; de uno que no se abrio nunca
         * es el otro extremo ofreciendo credito sobre una peticion que no
         * existe.
         * \~ */
        if (h.stream_id > streams_.highest_seen())
            return fail(ErrorCode::ProtocolError);
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
    if (e != ErrorCode::NoError) {
        reset_stream(h.stream_id, e);

        Event ev;
        ev.kind = EventKind::StreamEnded;
        ev.stream_id = h.stream_id;
        ev.error = e;
        return ev;
    }

    return Event{};
}

Event Connection::on_headers(const View &v, Buffer &headers,
                             http_vx::Request &req) noexcept {
    const FrameHeader &h = reader_.header();
    const Span p = reader_.payload();
    const uint8_t *at = v.at(v.origin + p.off);

    const bool first = h.type == static_cast<uint8_t>(FrameType::Headers);
    const bool last = (h.flags & kEndHeaders) != 0;

    /* \~english
     * Which stream the block is for, and whether the request ends with it, are
     * remembered from the HEADERS.  They cannot be read off the frame in hand
     * when the block ends on a CONTINUATION: `END_STREAM` is a fact about the
     * stream and it was stated once, on the first frame, and a CONTINUATION
     * has no such flag.
     *
     * The stream is opened HERE and not when the block ends, because opening
     * is about the identifier and the identifier arrived with the first frame.
     * Waiting would let a peer send a megabyte of CONTINUATIONs for a stream
     * that was going to be refused.
     *
     * \~spanish
     * De que flujo es el bloque, y si la peticion se acaba con el, se recuerdan
     * del HEADERS.  No se pueden leer de la trama que se tiene cuando el bloque
     * acaba en una CONTINUATION: `END_STREAM` es un hecho del flujo y se dijo
     * una vez, en la primera trama, y una CONTINUATION no tiene esa bandera.
     *
     * El flujo se abre AQUI y no cuando acaba el bloque, porque abrir va del
     * identificador y el identificador llego con la primera trama.  Esperar
     * dejaria a un extremo mandar un megabyte de CONTINUATIONs de un flujo que
     * iba a ser rechazado.
     * \~ */
    if (first) {
        block_stream_ = h.stream_id;
        block_ends_ = (h.flags & kEndStream) != 0;

        /* \~english
         * A HEADERS for a stream still in the table does not open anything:
         * it is the trailer section of the request already there (RFC 9113,
         * 8.1), and what it may be is a question for that stream.  One for a
         * stream that is not in the table goes on being an opening, and the
         * identifier rules there refuse whatever is not.
         * \~spanish
         * Un HEADERS de un flujo que sigue en la tabla no abre nada: es la
         * seccion de remolques de la peticion que ya esta (RFC 9113, 8.1), y lo
         * que pueda ser es cosa de ese flujo.  Uno de un flujo que no esta en la
         * tabla sigue siendo una apertura, y las reglas del identificador de
         * alli rechazan lo que no lo sea.
         * \~ */
        block_trailers_ = streams_.find(block_stream_) != nullptr;

        const Outcome o = block_trailers_
                              ? streams_.on_trailers(block_stream_, block_ends_)
                              : streams_.open(block_stream_, block_ends_);
        if (o.verdict == Verdict::ConnectionError) return fail(o.error);

        block_refused_ =
            o.verdict == Verdict::StreamError ? o.error : ErrorCode::NoError;
        block_why_ = o.why;
    }

    /* \~english
     * The ordinary case, and it does not copy: one HEADERS that ends the block
     * is already contiguous where it lies, so the decoder reads it out of the
     * connection buffer.  Only a block the peer chose to SPLIT has to be put
     * back together, and then the copy is paid by the connection that asked
     * for it.
     *
     * \~spanish
     * El caso corriente, y no copia: un solo HEADERS que acaba el bloque ya esta
     * seguido donde esta, asi que el descodificador lo lee del buffer de la
     * conexion.  Solo un bloque que el otro extremo decidio PARTIR hay que
     * volver a juntarlo, y entonces la copia la paga la conexion que la pidio.
     * \~ */
    const uint8_t *block = at;
    size_t block_len = p.len;

    if (first && last) {
        block_.clear();
    } else {
        if (first) block_.clear();

        uint8_t *room = block_.reserve(p.len);
        if (room == nullptr) return fail(ErrorCode::InternalError);
        util::vesta_memcpy(room, at, p.len);
        block_.commit(p.len);

        if (!last) return Event{};

        block = block_.data();
        block_len = block_.size();
    }

    /* \~english
     * **A refused stream's block is decoded anyway.**  It looks like waste and
     * it is the opposite: the table is the CONNECTION's, and a block left
     * undecoded leaves this end's table out of step with the peer's -- from
     * then on every index names a different field, on a connection that keeps
     * working.  Skipping the work of a refused request would cost the
     * connection every request after it.
     *
     * \~spanish
     * **El bloque de un flujo rechazado se descodifica igual.**  Parece
     * desperdicio y es lo contrario: la tabla es de la CONEXION, y un bloque sin
     * descodificar deja la tabla de este extremo desacompasada de la del otro
     * -- a partir de ahi cada indice nombra otra cabecera, en una conexion que
     * sigue funcionando --.  Saltarse el trabajo de una peticion rechazada le
     * costaria a la conexion todas las peticiones siguientes.
     * \~ */
    ErrorCode de = ErrorCode::NoError;
    if (block_trailers_) {
        /* \~english
         * Trailers are ADDED: to the request passed in and after what the
         * header buffer holds, so that a caller that kept the stream's head
         * there sees one request, head and trailers, over one base.
         * \~spanish
         * Los remolques se ANADEN: a la peticion que se paso y detras de lo que
         * tenga el buffer de cabeceras, para que quien guardo ahi la cabecera
         * del flujo vea una peticion, cabecera y remolques, sobre una base.
         * \~ */
        de = decoder_.decode_trailers(block, block_len, headers, req);
    } else {
        headers.clear();
        de = decoder_.decode(block, block_len, headers, req);
    }
    block_.clear();

    /* \~english
     * A compression error is always the CONNECTION, whatever the stream's
     * verdict was: the table cannot be put back, so there is nothing to carry
     * on with.
     * \~spanish
     * Un error de compresion es siempre la CONEXION, fuera cual fuera el
     * veredicto del flujo: la tabla no se puede recomponer, asi que no hay con
     * que seguir.
     * \~ */
    if (de == ErrorCode::CompressionError) return fail(de);

    if (de != ErrorCode::NoError)
        return refuse(block_stream_, de, decoder_.why());

    if (block_refused_ != ErrorCode::NoError)
        return refuse(block_stream_, block_refused_, block_why_);

    if (block_trailers_) {
        Event e;
        e.kind = EventKind::Trailers;
        e.stream_id = block_stream_;
        e.ends = true;
        return e;
    }

    /* \~english
     * The head is whole, so its content-length is known: from here on every
     * DATA of the stream is counted against it (RFC 9113, 8.1.1).
     * \~spanish
     * La cabecera esta entera, asi que se conoce su content-length: desde aqui
     * cada DATA del flujo se cuenta contra ella (RFC 9113, 8.1.1).
     * \~ */
    const char *bad = expect_content(headers, req);
    if (bad != nullptr)
        return refuse(block_stream_, ErrorCode::ProtocolError, bad);

    Event e;
    e.kind = EventKind::Request;
    e.stream_id = block_stream_;
    e.ends = block_ends_;
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
    if (r == ReadResult::Error) return fail(reader_.error());

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

    case FrameType::Data: {
        /* \~english
         * The connection's window is spent on the WHOLE payload, padding and
         * all, and it is spent even when the stream refuses the frame.  The
         * peer counted those bytes when it sent them, so an end that did not
         * count them would be a little further ahead on every padded or
         * discarded frame -- and the two would drift apart until the
         * connection stopped.
         *
         * \~spanish
         * La ventana de la conexion se gasta con la carga ENTERA, relleno
         * incluido, y se gasta aunque el flujo rechace la trama.  El otro
         * extremo conto esos bytes al mandarlos, asi que un extremo que no los
         * contara iria un poco por delante en cada trama rellenada o descartada
         * -- y los dos se separarian hasta que la conexion se parara.
         * \~ */
        if (!recv_.take(h.length)) return fail(ErrorCode::FlowControlError);

        const bool end_stream = (h.flags & kEndStream) != 0;

        /* \~english
         * Two lengths: the whole payload is what the windows are charged, and
         * what is left once the reader took the padding off is the content a
         * content-length is compared with (RFC 9113, 6.1 and 8.1.1).
         * \~spanish
         * Dos longitudes: la carga entera es lo que se cobra a las ventanas, y
         * lo que queda cuando el lector quito el relleno es el contenido con el
         * que se compara una content-length (RFC 9113, 6.1 y 8.1.1).
         * \~ */
        const Span p = reader_.payload();
        const Outcome o =
            streams_.on_data(h.stream_id, h.length, p.len, end_stream);

        if (o.verdict == Verdict::ConnectionError) return fail(o.error);

        /* \~english
         * A frame nobody is going to read still has to give its allowance
         * back, and it has to give it back HERE.  There is no stream to credit
         * -- it is over, which is why the frame is being refused -- and no
         * caller to ask, because a caller is only told about bytes it is being
         * handed.  Skipping it loses a little window on every reset stream, and
         * enough of them stop the connection for good.
         *
         * \~spanish
         * Una trama que no va a leer nadie tiene que devolver su credito igual, y
         * tiene que devolverlo AQUI.  No hay flujo al que abonarlo -- esta
         * terminado, que es la razon de que la trama se rechace -- ni a quien
         * llama a quien pedirselo, porque a quien llama solo se le habla de los
         * bytes que se le dan.  Saltarselo pierde un poco de ventana en cada
         * flujo abortado, y con bastantes la conexion se para para siempre.
         * \~ */
        if (o.verdict == Verdict::StreamError) {
            reset_stream(h.stream_id, o.error);
            credit_connection(h.length);
            why_ = o.why;

            Event e;
            e.kind = EventKind::StreamEnded;
            e.stream_id = h.stream_id;
            e.error = o.error;
            return e;
        }

        if (o.verdict == Verdict::Discard) {
            credit_connection(h.length);
            return Event{};
        }

        /* \~english
         * And the padding, which the reader took off and the peer paid for.
         * The bytes are charged to both windows and reach nobody, so both are
         * credited -- which is what @c release_window does, and the stream is
         * still open here, so it is the right call rather than a near one.
         *
         * \~spanish
         * Y el relleno, que el lector quito y el otro extremo pago.  Los bytes se
         * cobran a las dos ventanas y no llegan a nadie, asi que se abonan las dos
         * -- que es lo que hace @c release_window, y aqui el flujo sigue abierto,
         * asi que es la llamada correcta y no una parecida.
         * \~ */
        if (h.length > p.len)
            release_window(h.stream_id,
                           static_cast<uint32_t>(h.length - p.len));

        Event e;
        e.kind = EventKind::Body;
        e.stream_id = h.stream_id;
        e.ends = end_stream;
        e.data = p.len == 0 ? nullptr : v.at(v.origin + p.off);
        e.size = p.len;
        return e;
    }

    case FrameType::RstStream: {
        if (h.length != 4) return fail(ErrorCode::FrameSizeError);

        const Outcome o = streams_.on_reset(h.stream_id);
        if (o.verdict == Verdict::ConnectionError) return fail(o.error);
        if (o.verdict == Verdict::Discard) return Event{};

        Event e;
        e.kind = EventKind::StreamEnded;
        e.stream_id = h.stream_id;
        e.error = ErrorCode::Cancel;
        return e;
    }

    case FrameType::Goaway: {
        if (h.length < 8) return fail(ErrorCode::FrameSizeError);

        /* \~english
         * The peer is leaving.  This end does not answer a GOAWAY -- there is
         * nothing to say and the peer has already stopped listening -- so the
         * connection ends without one being written, which is why this does
         * not go through @c fail.
         * \~spanish
         * El otro extremo se va.  Este no contesta a un GOAWAY -- no hay nada
         * que decir y el otro ya ha dejado de escuchar -- asi que la conexion se
         * acaba sin escribir ninguno, que es la razon de que esto no pase por
         * @c fail.
         * \~ */
        closed_ = true;

        const Span p = reader_.payload();
        Event e;
        e.kind = EventKind::Closed;
        e.error = static_cast<ErrorCode>(be32(v.at(v.origin + p.off) + 4));
        return e;
    }

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
        return fail(ErrorCode::ProtocolError);

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
