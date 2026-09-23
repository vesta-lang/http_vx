/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/writer.cpp
 * @brief
 * \~english Cutting a response into the frames the peer will take.
 * \~spanish Partir una respuesta en las tramas que aceptara el otro extremo.
 * \~
 */

#include "http_vx/h2_writer.h"

namespace http_vx {
namespace h2 {

namespace {

/**
 * @brief
 * \~english Puts a frame header and its payload in the list.
 * \~spanish Pone una cabecera de trama y su carga en la lista.
 * \~
 *
 * \~english
 * Both or neither.  A header pushed without its payload is a frame that
 * promises bytes that are not coming, and the peer would read whatever came
 * next as those bytes -- which is a desynchronised connection rather than a
 * short write.
 *
 * \~spanish
 * Las dos o ninguna.  Una cabecera metida sin su carga es una trama que promete
 * bytes que no van a llegar, y el otro extremo leeria como esos bytes lo que
 * viniera detras -- que es una conexion desincronizada y no una escritura
 * corta.
 *
 * \~
 */
bool push_frame(IoList &out, uint8_t *head, const FrameHeader &h,
                const uint8_t *payload) noexcept {
    if (h.length != 0 && out.count() + 2 > kMaxIoSlices) return false;
    if (h.length == 0 && out.full()) return false;

    encode_frame_header(head, h);
    if (!out.push(head, kFrameHeaderSize)) return false;
    if (h.length != 0 && !out.push(payload, h.length)) return false;
    return true;
}

} // namespace

FrameError HeaderFramer::frame(IoList &out, uint32_t id, const uint8_t *block,
                               size_t n, uint32_t max_frame,
                               bool end_stream) noexcept {
    pieces_ = 0;

    if (max_frame == 0) return FrameError::BadFrameSize;

    /* \~english
     * How many frames this will take, worked out BEFORE anything is written.
     * A block that needs more pieces than the list holds must be refused with
     * nothing written at all -- half a header block on the wire stops the
     * peer's decompressor waiting for a CONTINUATION, and there is no way back
     * from that except closing the connection.
     *
     * A block of zero bytes is one frame and not none: an empty header block is
     * a legal response -- a `204` with nothing to say about itself -- and
     * sending no frame at all would be sending no response.
     *
     * \~spanish
     * Cuantas tramas va a llevar esto, calculado ANTES de escribir nada.  Un
     * bloque que necesite mas pedazos de los que guarda la lista hay que
     * rechazarlo sin escribir absolutamente nada -- medio bloque de cabeceras en
     * el cable deja al descompresor del otro extremo esperando una CONTINUATION,
     * y de ahi no se vuelve mas que cerrando la conexion --.
     *
     * Un bloque de cero bytes es una trama y no ninguna: un bloque de cabeceras
     * vacio es una respuesta legal -- un `204` que no tiene nada que decir de si
     * mismo -- y no mandar ninguna trama seria no mandar respuesta.
     * \~ */
    const size_t needed = n == 0 ? 1 : (n + max_frame - 1) / max_frame;
    if (needed > kMaxPieces) return FrameError::TooManyPieces;
    if (out.count() + needed * 2 > kMaxIoSlices)
        return FrameError::TooManyPieces;

    size_t at = 0;
    for (size_t i = 0; i < needed; ++i) {
        const size_t take = n - at < max_frame ? n - at : max_frame;

        FrameHeader h;
        h.length = static_cast<uint32_t>(take);
        h.stream_id = id;
        h.flags = 0;

        /* \~english
         * The first piece is a HEADERS and the rest are CONTINUATIONs, and the
         * two flags go in different places for different reasons:
         *
         *  - `END_HEADERS` is about the BLOCK, so it goes on the last piece;
         *  - `END_STREAM` is about the STREAM, so it goes on the first -- on
         *    the HEADERS frame, even when six CONTINUATIONs follow it.  A
         *    CONTINUATION has no such flag to put it on.
         *
         * \~spanish
         * El primer pedazo es un HEADERS y el resto CONTINUATIONs, y las dos
         * banderas van en sitios distintos por razones distintas:
         *
         *  - `END_HEADERS` habla del BLOQUE, asi que va en el ultimo pedazo;
         *  - `END_STREAM` habla del FLUJO, asi que va en el primero -- en la
         *    trama HEADERS, aunque detras vayan seis CONTINUATIONs --.  Una
         *    CONTINUATION no tiene esa bandera donde ponerla.
         * \~ */
        if (i == 0) {
            h.type = static_cast<uint8_t>(FrameType::Headers);
            if (end_stream) h.flags |= kEndStream;
        } else {
            h.type = static_cast<uint8_t>(FrameType::Continuation);
        }

        if (i + 1 == needed) h.flags |= kEndHeaders;

        if (!push_frame(out, heads_ + i * kFrameHeaderSize, h, block + at))
            return FrameError::TooManyPieces;

        at += take;
        ++pieces_;
    }

    return FrameError::Ok;
}

FrameError frame_body(IoList &out, uint8_t *head, uint32_t id,
                      const uint8_t *body, size_t n, uint32_t max_frame,
                      Window &stream, Window &connection,
                      size_t &sent) noexcept {
    sent = 0;

    if (max_frame == 0) return FrameError::BadFrameSize;
    if (n == 0) return FrameError::WouldBlock;

    /* \~english
     * The smallest of four bounds: what is left to send, what a frame may
     * hold, what this stream may still send, and what the connection may.  The
     * two windows may be NEGATIVE -- a stream can be in debt after the peer
     * lowered its initial window -- so they are compared as signed and a
     * non-positive one means nothing goes out at all.
     *
     * \~spanish
     * La menor de cuatro cotas: lo que queda por mandar, lo que puede llevar una
     * trama, lo que puede mandar todavia este flujo, y lo que puede la conexion.
     * Las dos ventanas pueden ser NEGATIVAS -- un flujo puede estar en deuda
     * despues de que el otro extremo bajara su ventana inicial -- asi que se
     * comparan con signo y que una no sea positiva quiere decir que no sale
     * nada.
     * \~ */
    if (stream.left() <= 0 || connection.left() <= 0)
        return FrameError::WouldBlock;

    size_t take = n;
    if (take > max_frame) take = max_frame;
    if (static_cast<int64_t>(take) > stream.left())
        take = static_cast<size_t>(stream.left());
    if (static_cast<int64_t>(take) > connection.left())
        take = static_cast<size_t>(connection.left());

    FrameHeader h;
    h.length = static_cast<uint32_t>(take);
    h.type = static_cast<uint8_t>(FrameType::Data);
    h.flags = 0;
    h.stream_id = id;

    /* \~english
     * The list is filled BEFORE the windows are spent.  A full list is a
     * caller that has to write what it has and come back, and spending the
     * windows first would have charged the connection for bytes that never
     * left -- an allowance nothing gives back, because a WINDOW_UPDATE returns
     * what the peer RECEIVED.
     *
     * \~spanish
     * La lista se llena ANTES de gastar las ventanas.  Una lista llena es quien
     * llama teniendo que escribir lo que tiene y volver, y gastar las ventanas
     * antes le habria cobrado a la conexion unos bytes que no salieron -- un
     * credito que no devuelve nadie, porque un WINDOW_UPDATE devuelve lo que el
     * otro extremo RECIBIO --.
     * \~ */
    if (!push_frame(out, head, h, body)) return FrameError::TooManyPieces;

    /* \~english
     * And now both, together.  Neither can fail here: `take` was cut down to
     * fit both windows above, so this is the spending of an amount already
     * known to fit.  It is still written as two checked calls rather than two
     * subtractions, because the checking is what the class is for and a
     * subtraction that bypassed it would be the one place the invariant is not
     * enforced.
     *
     * \~spanish
     * Y ahora las dos, juntas.  Aqui no puede fallar ninguna: `take` se recorto
     * arriba para caber en las dos ventanas, asi que esto es gastar una cantidad
     * que ya se sabe que cabe.  Se escribe igualmente como dos llamadas
     * comprobadas y no como dos restas, porque la comprobacion es para lo que
     * esta la clase y una resta que se la saltara seria el unico sitio donde el
     * invariante no se hace cumplir.
     * \~ */
    stream.take(static_cast<uint32_t>(take));
    connection.take(static_cast<uint32_t>(take));

    sent = take;
    return FrameError::Ok;
}

bool frame_end_of_body(IoList &out, uint8_t *head, uint32_t id) noexcept {
    FrameHeader h;
    h.length = 0;
    h.type = static_cast<uint8_t>(FrameType::Data);
    h.flags = kEndStream;
    h.stream_id = id;

    return push_frame(out, head, h, nullptr);
}

} // namespace h2
} // namespace http_vx
