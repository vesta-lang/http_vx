/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/service_open.cpp
 * @brief
 * \~english Open responses in HTTP/1.1: chunks filled in place, and the requests behind them waiting (HVX-5, 7.1).
 * \~spanish Respuestas abiertas en HTTP/1.1: trozos rellenados en su sitio, y las peticiones de detras esperando (HVX-5, 7.1).
 * \~
 */

#include "http_vx/http1_service.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

void Http1Service::end_open(State &s, GoneReason why) noexcept {
    BodySource *src = s.open;
    s.open = nullptr;
    s.kicked = false;
    s.hungry = false;
    if (src != nullptr && port_ != nullptr) port_->end(*src, why);
}

bool Http1Service::unavailable(const Request &req, bool keep_alive, Buffer &out) noexcept {
    h1::ResponseWriter &w = writer_;
    w.begin(req.version, 503, req.method, keep_alive);
    w.finish(h1::ResponseBody::Length, 0);
    return flush(w, out);
}

bool Http1Service::start_open(ConnHandle c, State &s, const ResponseBuilder &res,
                              Buffer &out) noexcept {
    s.open = res.opened_source();
    s.kicked = false;
    s.hungry = false;

    /* \~english
     * HTTP/1.1 goes in chunks.  HTTP/1.0 has none, so its body ends when the
     * connection does (RFC 9112, 6.3): it is not kept alive.
     * \~spanish
     * HTTP/1.1 va por trozos.  HTTP/1.0 no los tiene, asi que su cuerpo acaba
     * cuando acaba la conexion (RFC 9112, 6.3): no se mantiene viva.
     * \~ */
    s.chunked = s.req.version == Version::Http11;
    if (!s.chunked) s.keep_alive = false;

    h1::ResponseWriter &w = writer_;
    w.begin(s.req.version, res.status(), s.req.method, s.keep_alive);
    put_fields(w, res);

    /* \~english
     * A head that cannot be written -- a status with no body, like 204, or a
     * field that did not fit -- is not sent half-opened: the source is ended
     * and the answer is a 500, as for any response that could not be written.
     * \~spanish
     * Una cabecera que no se puede escribir -- un estado sin cuerpo, como el 204,
     * o una cabecera que no cupo -- no se manda medio abierta: la fuente se acaba
     * y la respuesta es un 500, como toda respuesta que no se pudo escribir.
     * \~ */
    const h1::ResponseBody kind = s.chunked ? h1::ResponseBody::Chunked : h1::ResponseBody::UntilClose;
    if (res.failed() || w.finish(kind) != h1::WriteError::None || !flush(w, out)) {
        end_open(s, GoneReason::ConnectionClosed);
        return refuse(500, out);
    }

    // \~english What the handler wrote before opening is the first piece.
    // \~spanish Lo que escribio el manejador antes de abrir es el primer trozo.  \~
    const Span b = res.body();
    if (b.len != 0) {
        const size_t frame = s.chunked ? h1::kChunkHeaderMax + sizeof h1::kChunkEnd : 0;
        uint8_t *room = out.reserve(frame + b.len);
        if (room == nullptr) {
            end_open(s, GoneReason::ConnectionClosed);
            return false;
        }
        size_t at = s.chunked ? h1::write_chunk_header(room, b.len) : 0;
        util::vesta_memcpy(room + at, res.bytes() + b.off, b.len);
        at += b.len;
        if (s.chunked) {
            util::vesta_memcpy(room + at, h1::kChunkEnd, sizeof h1::kChunkEnd);
            at += sizeof h1::kChunkEnd;
        }
        out.commit(at);
    }

    // \~english And the first fill, since there is room right now (HVX-5, 4.3).
    // \~spanish Y el primer relleno, porque ahora mismo hay sitio (HVX-5, 4.3).  \~
    if (!fill_open(c, s, out)) return false;

    // \~english Still open: nothing behind it is read until it ends.
    // \~spanish Sigue abierta: no se lee nada de detras hasta que acabe.  \~
    if (s.open != nullptr) port_->hold_reads(c, true);
    return true;
}

bool Http1Service::fill_open(ConnHandle c, State &s, Buffer &out) noexcept {
    /* \~english
     * The room for the framing is kept in front and behind, the source writes
     * its bytes where they will leave from, and the size goes in front once
     * it is known -- in a width fixed beforehand, which is why the chunk
     * header is written with zeros in front.  No byte is copied.
     * \~spanish
     * El sitio del enmarcado se guarda delante y detras, la fuente escribe sus
     * bytes donde van a salir, y el tamano va delante cuando se sabe -- con un
     * ancho fijado antes, que es por lo que la cabecera del trozo se escribe con
     * ceros delante.  No se copia ningun byte.
     * \~ */
    const size_t digits = s.chunked ? h1::chunk_size_digits(kFillRoom) : 0;
    const size_t front = s.chunked ? digits + 2 : 0;
    const size_t back = s.chunked ? sizeof h1::kChunkEnd + sizeof h1::kLastChunk : 0;

    uint8_t *base = out.reserve(front + kFillRoom + back);
    if (base == nullptr) {
        end_open(s, GoneReason::ConnectionClosed);
        return false;
    }

    bool done = false;
    const size_t n = port_->fill(*s.open, base + front, kFillRoom, done);

    size_t used = 0;
    if (!s.chunked) {
        used = n;
    } else {
        if (n != 0) {
            h1::write_chunk_header_fixed(base, n, digits);
            util::vesta_memcpy(base + front + n, h1::kChunkEnd, sizeof h1::kChunkEnd);
            used = front + n + sizeof h1::kChunkEnd;
        }
        if (done) {
            util::vesta_memcpy(base + used, h1::kLastChunk, sizeof h1::kLastChunk);
            used += sizeof h1::kLastChunk;
        }
    }
    out.commit(used);

    if (done) {
        /* \~english
         * Over: the source is told, and the requests that waited behind it
         * are handed over again.
         * \~spanish
         * Acabada: se le dice a la fuente, y las peticiones que esperaron detras
         * se vuelven a entregar.
         * \~ */
        end_open(s, GoneReason::Finished);
        port_->hold_reads(c, false);
        return true;
    }

    // \~english All the room taken: it may have more, and is asked again when there is room.
    // \~spanish Uso todo el sitio: puede tener mas, y se le vuelve a pedir cuando haya sitio.  \~
    s.hungry = n == kFillRoom;
    if (s.hungry) port_->want_writable(c);
    return true;
}

bool Http1Service::on_writable(ConnHandle c, Buffer &out) noexcept {
    if (c.slot >= capacity_ || port_ == nullptr) return true;

    State &s = state_[c.slot];
    if (s.open == nullptr || (!s.kicked && !s.hungry)) return true;

    s.kicked = false;
    if (!fill_open(c, s, out)) return false;

    // \~english An HTTP/1.0 body ends with the connection.
    // \~spanish Un cuerpo de HTTP/1.0 acaba con la conexion.  \~
    return s.open != nullptr || s.keep_alive;
}

void Http1Service::on_kick(BodySource &source) noexcept {
    const OpenResponse r = source.response();
    if (r.conn.slot >= capacity_ || port_ == nullptr) return;

    State &s = state_[r.conn.slot];
    if (s.open != &source) return;

    s.kicked = true;
    port_->want_writable(r.conn);
}

} // namespace http_vx
