/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/connection_fill.cpp
 * @brief
 * \~english A response body filled in place: one DATA frame written where QUIC keeps the stream's bytes (HVX-5, 7.3).
 * \~spanish Un cuerpo de respuesta rellenado en su sitio: una trama DATA escrita donde QUIC guarda los bytes del flujo (HVX-5, 7.3).
 * \~
 *
 * \~english
 * send_body copies twice: into the message's buffer, and from there into the
 * stream.  An open response cannot afford that on every piece, so here the
 * body is written straight into the stream's send chunk, behind three bytes
 * kept for the frame header, and the header is written once the length is
 * known.  Nothing of the body is copied.
 * \~spanish
 * send_body copia dos veces: al buffer del mensaje, y de ahi al flujo.  Una
 * respuesta abierta no se lo puede permitir en cada trozo, asi que aqui el
 * cuerpo se escribe directamente en el trozo de envio del flujo, detras de tres
 * bytes guardados para la cabecera de la trama, y la cabecera se escribe cuando
 * se sabe la longitud.  No se copia nada del cuerpo.
 * \~
 */
#include "http_vx/h3_connection.h"

#include "http_vx/quic_varint.h"

namespace http_vx {
namespace h3 {

namespace {

constexpr uint64_t kNoStream = ~uint64_t{0};

// \~english One fill is one chunk at most, and its length has to fit two varint bytes.
// \~spanish Un relleno es un trozo como mucho, y su longitud tiene que caber en dos bytes de varint.  \~
static_assert(quic::kRecvChunk <= 16383, "a fill's length must fit a two-byte varint");

inline uint64_t least(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }

} // namespace

size_t Connection::slot_of(uint64_t stream) const noexcept {
    const uint32_t at = by_id_.find(stream);
    return at == IdIndex::kAbsent ? Event::kNoSlot : static_cast<size_t>(at);
}

uint8_t *Connection::body_room(uint64_t stream, size_t &room) noexcept {
    room = 0;
    fill_stream_ = kNoStream;
    fill_room_ = 0;
    Message *m = message(stream);
    // \~english After the final header section, before the end; and behind nothing still waiting in the message.
    // \~spanish Tras la seccion de cabecera final, antes del final; y detras de nada que siga esperando en el mensaje.  \~
    if (!cfg_.server || m == nullptr || failed() || !m->final_sent || m->out_fin || !m->out.empty()) return nullptr;
    quic::Stream *s = q_.streams().find(stream);
    if (s == nullptr || s->send == nullptr) return nullptr;
    quic::SendStream &tx = *s->send;

    /* \~english
     * The stream's credit counts offsets, so what is written and not yet sent
     * already uses it.  The connection's counts what went out, so what waits
     * to go is taken off it: this stream's, and that of this end's control
     * and QPACK streams -- three lookups.  Those matter most: QPACK's
     * instructions for this very header section wait there, and a body that
     * took their credit would leave the peer unable to decode the section,
     * so never reading the body, so never raising the credit.  Other request
     * streams' bytes are not counted (that would be a walk over them); what
     * that over-promises is a frame whose tail waits for the peer's next
     * MAX_DATA, in this stream's chunk, bounded by kFillAhead.
     * \~spanish
     * El credito del flujo cuenta desplazamientos, asi que lo escrito y aun sin
     * mandar ya lo usa.  El de la conexion cuenta lo que salio, asi que se le
     * quita lo que espera a salir: lo de este flujo, y lo de los flujos de control
     * y de QPACK de este extremo -- tres busquedas.  Esos importan mas que nada:
     * ahi esperan las instrucciones de QPACK de esta misma seccion de cabecera, y
     * un cuerpo que se llevara su credito dejaria al otro sin poder descodificar
     * la seccion, asi que sin leer el cuerpo, asi que sin subir nunca el credito.
     * Los bytes de otros flujos de peticion no se cuentan (seria recorrerlos); lo
     * que eso prometa de mas es una trama cuya cola espera al siguiente MAX_DATA
     * del otro, en el trozo de este flujo, acotada por kFillAhead.
     * \~ */
    const uint64_t written = tx.written();
    const uint64_t unsent = written - tx.sent();
    uint64_t waiting = unsent;
    for (const Uni &u : local_) {
        if (u.id == kNoStream) continue;
        const quic::Stream *ls = q_.streams().find(u.id);
        if (ls != nullptr && ls->send != nullptr) waiting += ls->send->written() - ls->send->sent();
        waiting += u.out.size();
    }
    const uint64_t stream_credit = tx.limit() > written ? tx.limit() - written : 0;
    const uint64_t conn_credit = q_.send_credit() > waiting ? q_.send_credit() - waiting : 0;
    const uint64_t ahead = unsent < kFillAhead ? kFillAhead - unsent : 0;
    const uint64_t credit = least(least(stream_credit, conn_credit), ahead);
    if (credit <= kFillHead) return nullptr;

    size_t contiguous = 0;
    uint8_t *dst = tx.reserve(kFillHead, contiguous);
    if (dst == nullptr) return nullptr;
    room = static_cast<size_t>(least(credit - kFillHead, contiguous));
    fill_stream_ = stream;
    fill_room_ = room;
    return dst;
}

bool Connection::body_commit(uint64_t stream, size_t n, bool end) noexcept {
    const bool given = fill_stream_ == stream;
    const size_t room = fill_room_;
    fill_stream_ = kNoStream;
    fill_room_ = 0;
    // \~english A commit with no room behind it, or past it, would put bytes nobody wrote on the wire.
    // \~spanish Un commit sin sitio detras, o pasado de el, pondria en la red bytes que no escribio nadie.  \~
    if (!given) return fail(kInternalError, "a body committed without the room it was written in");
    if (n > room) return fail(kInternalError, "a body longer than the room it was given");
    Message *m = message(stream);
    quic::Stream *s = q_.streams().find(stream);
    if (m == nullptr || s == nullptr || s->send == nullptr) return fail(kInternalError, "a body committed to a stream gone");
    quic::SendStream &tx = *s->send;

    quic::StreamError e = quic::StreamError::None;
    if (n == 0) {
        e = tx.commit(nullptr, 0, 0);
    } else {
        uint8_t head[kFillHead];
        quic::encode_varint_width(head, 1, kData);
        quic::encode_varint_width(head + 1, kFillHead - 1, n);
        e = tx.commit(head, kFillHead, n);
    }
    if (e != quic::StreamError::None) return fail(kInternalError, "out of memory for a DATA frame's header");
    if (end) {
        m->out_fin = true;
        tx.finish();
    }
    return true;
}

} // namespace h3
} // namespace http_vx
