/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/codec_invariants.cpp
 * @brief
 * \~english Checking the parser's properties against arbitrary bytes.
 * \~spanish Comprobar las propiedades del analizador contra bytes cualesquiera.
 * \~
 */

#include "codec_invariants.h"

#include "http_vx/h1_chunked.h"
#include "http_vx/h1_parser.h"
#include "http_vx/h2_reader.h"

namespace http_vx {
namespace fuzz {
namespace {

/**
 * @brief
 * \~english What one pass over the bytes came to.
 * \~spanish A que llego una pasada sobre los bytes.
 * \~
 */
struct Outcome {
    h1::ParseResult result;
    h1::ParseError error;
    size_t consumed;
};

/**
 * @brief
 * \~english Whether @p s lies inside the first @p limit bytes.
 * \~spanish Si @p s cae dentro de los primeros @p limit bytes.
 * \~
 *
 * \~english
 * The addition is done in the wider type before comparing, because the
 * obvious `off + len <= limit` is the check that a span with a huge offset
 * passes: the sum wraps and comes back small, and the piece that was about to
 * be read from outside the message is declared to be inside it.
 *
 * \~spanish
 * La suma se hace en el tipo ancho antes de comparar, porque el evidente
 * `off + len <= limit` es la comprobacion que pasa un trozo con un
 * desplazamiento enorme: la suma da la vuelta y vuelve pequena, y la pieza que
 * se iba a leer de fuera del mensaje queda declarada dentro.
 *
 * \~
 */
bool inside(const Span &s, size_t limit) noexcept {
    const uint64_t off = s.off;
    const uint64_t len = s.len;
    return off + len <= static_cast<uint64_t>(limit);
}

/**
 * @brief
 * \~english Runs one pass and checks what it can on its own.
 * \~spanish Corre una pasada y comprueba lo que puede por su cuenta.
 * \~
 *
 * \~english
 * @p step is how many new bytes each call may see.  Zero means all of them at
 * once; one means a byte at a time.
 *
 * \~spanish
 * @p step es cuantos bytes nuevos puede ver cada llamada.  Cero quiere decir
 * todos de una vez; uno, un byte cada vez.
 *
 * \~
 */
Breach run(const uint8_t *data, size_t size, size_t step, Request &req,
           Outcome &out) noexcept {
    h1::RequestParser p;
    h1::ParseResult r = h1::ParseResult::NeedMore;

    size_t given = step == 0 ? size : 0;
    for (;;) {
        if (step != 0) {
            given += step;
            if (given > size) given = size;
        }

        r = p.parse(data, given, req);

        if (r == h1::ParseResult::NeedMore) {
            /* \~english
             * Asking for more is only honest when there is no more to look at.
             * A parser that asks while it still holds unread bytes has a state
             * that did not advance, and the other way that shows up is a
             * connection that waits for a request it already received.
             * \~spanish
             * Pedir mas solo es honesto cuando no queda nada que mirar.  Un
             * analizador que pide teniendo todavia bytes sin leer tiene un
             * estado que no avanzo, y la otra forma en que eso se manifiesta es
             * una conexion que espera una peticion que ya recibio.
             * \~ */
            if (p.head_size() != given) return Breach::AskedForMoreWithInputLeft;
            if (given == size) break;
            continue;
        }
        break;
    }

    out.result = r;
    out.error = p.error();
    out.consumed = p.head_size();

    if (out.consumed > size) return Breach::ConsumedPastTheEnd;

    if (r == h1::ParseResult::Done) {
        if (out.error != h1::ParseError::None) return Breach::DoneWithAReason;

        /* \~english
         * Every piece of the request must name bytes of the request.  The
         * limit is what the head took and not what was given: a span reaching
         * into the body would be naming bytes that belong to the next thing
         * the connection reads.
         * \~spanish
         * Todas las piezas de la peticion tienen que nombrar bytes de la
         * peticion.  El limite es lo que ocupo la cabeza y no lo que se dio: un
         * trozo que llegara al cuerpo estaria nombrando bytes que son de lo
         * siguiente que lea la conexion.
         * \~ */
        const size_t limit = out.consumed;
        if (!inside(req.method_text, limit)) return Breach::PieceOutsideTheMessage;
        if (!inside(req.target, limit)) return Breach::PieceOutsideTheMessage;
        if (!inside(req.authority, limit)) return Breach::PieceOutsideTheMessage;
        if (!inside(req.scheme, limit)) return Breach::PieceOutsideTheMessage;

        for (const Field *f = req.fields.begin(); f != req.fields.end(); ++f) {
            const Span name{f->name_off, f->name_len};
            const Span value{f->value_off, f->value_len};
            if (!inside(name, limit)) return Breach::PieceOutsideTheMessage;
            if (!inside(value, limit)) return Breach::PieceOutsideTheMessage;
        }
    }

    if (r == h1::ParseResult::Error && out.error == h1::ParseError::None)
        return Breach::RefusedWithoutAReason;

    return Breach::None;
}

} // namespace

const char *breach_name(Breach b) noexcept {
    switch (b) {
    case Breach::None:
        return "none";
    case Breach::AskedForMoreWithInputLeft:
        return "asked for more input while it still had some";
    case Breach::ConsumedPastTheEnd:
        return "reported a head longer than the bytes it was given";
    case Breach::DoneWithAReason:
        return "finished and reported a reason for refusing";
    case Breach::RefusedWithoutAReason:
        return "refused without saying why";
    case Breach::PieceOutsideTheMessage:
        return "a piece of the request names bytes outside it";
    case Breach::SplittingChangedTheAnswer:
        return "the same bytes answered differently whole and in pieces";
    case Breach::PieceWentBackwards:
        return "a piece of the body starts before the previous one ended";
    case Breach::BodyLengthDisagrees:
        return "the body length does not match the pieces handed over";
    }
    return "unknown";
}

Breach check_parse(const uint8_t *data, size_t size) noexcept {
    Request whole_req;
    Outcome whole{};
    const Breach a = run(data, size, 0, whole_req, whole);
    if (a != Breach::None) return a;

    Request drip_req;
    Outcome drip{};
    const Breach b = run(data, size, 1, drip_req, drip);
    if (b != Breach::None) return b;

    if (whole.result != drip.result || whole.error != drip.error ||
        whole.consumed != drip.consumed)
        return Breach::SplittingChangedTheAnswer;

    /* \~english
     * And when both finished, they must have found the same request.  The
     * pieces are compared and not only the verdict: two passes can agree that
     * a message was valid and disagree about where its target was, which is
     * the difference between serving one resource and serving another.
     * \~spanish
     * Y cuando las dos terminaron, tienen que haber encontrado la misma
     * peticion.  Se comparan las piezas y no solo el veredicto: dos pasadas
     * pueden coincidir en que un mensaje era valido y discrepar en donde estaba
     * su destino, que es la diferencia entre servir un recurso y servir otro.
     * \~ */
    if (whole.result == h1::ParseResult::Done) {
        if (whole_req.method != drip_req.method ||
            whole_req.version != drip_req.version ||
            whole_req.fields.size() != drip_req.fields.size())
            return Breach::SplittingChangedTheAnswer;

        if (whole_req.target.off != drip_req.target.off ||
            whole_req.target.len != drip_req.target.len ||
            whole_req.method_text.off != drip_req.method_text.off ||
            whole_req.method_text.len != drip_req.method_text.len ||
            whole_req.authority.off != drip_req.authority.off ||
            whole_req.authority.len != drip_req.authority.len)
            return Breach::SplittingChangedTheAnswer;
    }

    return Breach::None;
}

namespace {

/**
 * @brief
 * \~english What one pass over a chunked body came to.
 * \~spanish A que llego una pasada sobre un cuerpo troceado.
 * \~
 *
 * \~english
 * The body is summarised and not kept.  A hash and a count say whether two
 * passes delivered the same bytes without either pass having to hold them,
 * which is the property the reader itself is built around: nothing here needs
 * a whole body at once, and a check that needed one would be checking a
 * different program.
 *
 * \~spanish
 * El cuerpo se resume y no se guarda.  Un resumen y una cuenta dicen si las dos
 * pasadas entregaron los mismos bytes sin que ninguna tenga que tenerlos, que
 * es la propiedad sobre la que esta construido el propio lector: aqui nada
 * necesita un cuerpo entero de una vez, y una comprobacion que lo necesitara
 * estaria comprobando otro programa.
 *
 * \~
 */
struct BodyOutcome {
    h1::ChunkResult result;
    h1::ChunkError error;
    size_t consumed;
    uint64_t reported;
    uint64_t delivered;
    uint64_t hash;
};

/**
 * @brief
 * \~english Folds @p n bytes into @p h.  FNV-1a.
 * \~spanish Mezcla @p n bytes en @p h.  FNV-1a.
 * \~
 */
void fold(uint64_t &h, const uint8_t *p, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ull;
    }
}

Breach run_body(const uint8_t *data, size_t size, size_t step,
                BodyOutcome &out) noexcept {
    h1::ChunkedReader r;
    r.reset(0);
    Fields trailers;

    out.hash = 0xCBF29CE484222325ull;
    out.delivered = 0;

    size_t given = step == 0 ? size : 0;
    size_t last_end = 0;

    for (;;) {
        const h1::ChunkResult res = r.read(View{data, given, 0}, trailers);

        if (res == h1::ChunkResult::Data) {
            const Span s = r.chunk();
            if (!inside(s, given)) return Breach::PieceOutsideTheMessage;
            if (s.off < last_end) return Breach::PieceWentBackwards;
            last_end = static_cast<size_t>(s.off) + s.len;
            fold(out.hash, data + s.off, s.len);
            out.delivered += s.len;
            continue;
        }

        if (res == h1::ChunkResult::NeedMore) {
            /* \~english
             * Against what it has LOOKED at and not against what it has
             * finished: those part company once the trailers begin, and it is
             * the reading that has to keep moving.
             * \~spanish
             * Contra lo que ha MIRADO y no contra lo que ha terminado: los dos
             * se separan en cuanto empiezan los remolques, y es la lectura la
             * que tiene que seguir avanzando.
             * \~ */
            if (r.position() != given) return Breach::AskedForMoreWithInputLeft;
            if (given == size) {
                out.result = res;
                break;
            }
            given += step == 0 ? size : step;
            if (given > size) given = size;
            continue;
        }

        out.result = res;
        break;
    }

    out.error = r.error();
    out.consumed = r.consumed();
    out.reported = r.body_bytes();

    if (out.consumed > size) return Breach::ConsumedPastTheEnd;
    if (out.result == h1::ChunkResult::Done &&
        out.error != h1::ChunkError::None)
        return Breach::DoneWithAReason;
    if (out.result == h1::ChunkResult::Error &&
        out.error == h1::ChunkError::None)
        return Breach::RefusedWithoutAReason;

    /* \~english
     * What it says it read and what it handed over are two numbers a handler
     * can act on, and nothing downstream can tell which of them is the body.
     * \~spanish
     * Lo que dice haber leido y lo que entrego son dos numeros sobre los que
     * puede actuar un manejador, y nada de mas abajo puede decir cual de los
     * dos es el cuerpo.
     * \~ */
    if (out.reported != out.delivered) return Breach::BodyLengthDisagrees;

    return Breach::None;
}

} // namespace

Breach check_chunked(const uint8_t *data, size_t size) noexcept {
    BodyOutcome whole{};
    const Breach a = run_body(data, size, 0, whole);
    if (a != Breach::None) return a;

    BodyOutcome drip{};
    const Breach b = run_body(data, size, 1, drip);
    if (b != Breach::None) return b;

    if (whole.result != drip.result || whole.error != drip.error ||
        whole.consumed != drip.consumed)
        return Breach::SplittingChangedTheAnswer;

    /* \~english
     * And the same bytes, which is not the same as the same pieces: a chunk
     * split across two reads comes back as two, so the division may differ and
     * the content may not.
     * \~spanish
     * Y los mismos bytes, que no es lo mismo que los mismos pedazos: un trozo
     * partido entre dos lecturas vuelve como dos, asi que la division puede
     * diferir y el contenido no.
     * \~ */
    if (whole.delivered != drip.delivered || whole.hash != drip.hash)
        return Breach::SplittingChangedTheAnswer;

    return Breach::None;
}

namespace {

/**
 * @brief
 * \~english What one pass over an HTTP/2 connection came to.
 * \~spanish A que llego una pasada sobre una conexion HTTP/2.
 * \~
 */
struct FrameOutcome {
    h2::ReadResult result;
    h2::ErrorCode error;
    size_t consumed;
    uint64_t frames;
    uint64_t hash;
};

Breach run_frames(const uint8_t *data, size_t size, size_t step,
                  FrameOutcome &out) noexcept {
    h2::FrameReader r;
    r.reset(0, true);

    out.hash = 0xCBF29CE484222325ull;
    out.frames = 0;

    size_t given = step == 0 ? size : 0;
    size_t last_end = 0;

    for (;;) {
        const h2::ReadResult res = r.read(View{data, given, 0});

        if (res == h2::ReadResult::Frame) {
            const Span s = r.payload();
            if (!inside(s, given)) return Breach::PieceOutsideTheMessage;
            if (s.off < last_end) return Breach::PieceWentBackwards;
            last_end = static_cast<size_t>(s.off) + s.len;

            /* \~english
             * The header goes into the summary as well as the payload.  Two
             * passes that handed over the same bytes under different headers
             * would be two passes that read the same connection as different
             * messages, and the bytes alone would not show it.
             * \~spanish
             * La cabecera entra en el resumen ademas de la carga.  Dos pasadas
             * que entregaran los mismos bytes bajo cabeceras distintas serian
             * dos pasadas que leen la misma conexion como mensajes distintos, y
             * los bytes solos no lo ensenarian.
             * \~ */
            const uint8_t head[4] = {
                r.header().type, r.header().flags,
                static_cast<uint8_t>(r.header().stream_id >> 8),
                static_cast<uint8_t>(r.header().stream_id)};
            fold(out.hash, head, sizeof(head));
            fold(out.hash, data + s.off, s.len);
            ++out.frames;
            continue;
        }

        if (res == h2::ReadResult::NeedMore) {
            /* \~english
             * The property is not the text readers'.  Those advance byte by
             * byte as they scan, so asking for more while holding any is a
             * stall; this one advances only at a frame boundary, because it is
             * waiting for a WHOLE frame and a position inside a partial one
             * would be a position it has to come back from.
             *
             * So what must not happen is asking for more while a whole frame
             * is sitting there.  Which is checked by reading the header at the
             * position it stopped at and seeing whether the frame it describes
             * has all arrived -- and only once the preface is behind it,
             * because until then those bytes are not a frame header at all.
             *
             * \~spanish
             * La propiedad no es la de los lectores de texto.  Aquellos avanzan
             * byte a byte segun recorren, asi que pedir mas teniendo algo es un
             * atasco; este avanza solo en frontera de trama, porque esta
             * esperando una trama ENTERA y una posicion dentro de una a medias
             * seria una posicion de la que tiene que volver.
             *
             * Asi que lo que no puede pasar es pedir mas teniendo ahi una trama
             * entera.  Y eso se comprueba leyendo la cabecera en la posicion
             * donde se paro y viendo si la trama que describe llego entera -- y
             * solo cuando ya paso el preambulo, porque hasta entonces esos
             * bytes no son ninguna cabecera de trama.
             * \~ */
            const size_t left = given - r.consumed();
            if (r.consumed() >= sizeof(h2::kClientPreface) &&
                left >= h2::kFrameHeaderSize) {
                h2::FrameHeader ahead{};
                h2::decode_frame_header(data + r.consumed(), ahead);
                if (h2::kFrameHeaderSize + ahead.length <= left)
                    return Breach::AskedForMoreWithInputLeft;
            }

            if (given == size) {
                out.result = res;
                break;
            }
            given += step == 0 ? size : step;
            if (given > size) given = size;
            continue;
        }

        out.result = res;
        break;
    }

    out.error = r.error();
    out.consumed = r.consumed();

    if (out.consumed > size) return Breach::ConsumedPastTheEnd;
    if (out.result == h2::ReadResult::Error &&
        out.error == h2::ErrorCode::NoError)
        return Breach::RefusedWithoutAReason;

    return Breach::None;
}

} // namespace

Breach check_frames(const uint8_t *data, size_t size) noexcept {
    FrameOutcome whole{};
    const Breach a = run_frames(data, size, 0, whole);
    if (a != Breach::None) return a;

    FrameOutcome drip{};
    const Breach b = run_frames(data, size, 1, drip);
    if (b != Breach::None) return b;

    if (whole.result != drip.result || whole.error != drip.error ||
        whole.consumed != drip.consumed || whole.frames != drip.frames ||
        whole.hash != drip.hash)
        return Breach::SplittingChangedTheAnswer;

    return Breach::None;
}

} // namespace fuzz
} // namespace http_vx
