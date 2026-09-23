/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/h1_invariants.cpp
 * @brief
 * \~english Checking the parser's properties against arbitrary bytes.
 * \~spanish Comprobar las propiedades del analizador contra bytes cualesquiera.
 * \~
 */

#include "h1_invariants.h"

#include "http_vx/h1_parser.h"

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
            if (p.consumed() != given) return Breach::AskedForMoreWithInputLeft;
            if (given == size) break;
            continue;
        }
        break;
    }

    out.result = r;
    out.error = p.error();
    out.consumed = p.consumed();

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

} // namespace fuzz
} // namespace http_vx
