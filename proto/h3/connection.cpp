/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/connection.cpp
 * @brief
 * \~english The HTTP/3 connection: stream types, the control stream, request streams, and what goes out (RFC 9114).
 * \~spanish La conexion HTTP/3: tipos de flujo, el flujo de control, los flujos de peticion, y lo que sale (RFC 9114).
 * \~
 */
#include "http_vx/h3_connection.h"

#include "http_vx/chars.h"
#include "http_vx/content_length.h"
#include "http_vx/quic_varint.h"
#include "http_vx/request_builder.h"
#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <new>

namespace http_vx {
namespace h3 {

namespace {

constexpr uint64_t kNone = ~uint64_t{0};

/* \~english Which end opened a stream, and which way it goes (RFC 9000, 2.1).
 * \~spanish Que extremo abrio un flujo, y en que sentido va (RFC 9000, 2.1).  \~ */
bool is_uni(uint64_t id) noexcept { return (id & 2) != 0; }
bool by_client(uint64_t id) noexcept { return (id & 1) == 0; }

/// \~english The most one DATA or HEADERS frame of this end carries.  \~spanish Lo mas que lleva una trama DATA o HEADERS de este extremo.  \~
constexpr size_t kMostLines = 64;

bool is_text(const uint8_t *p, size_t n, const char *s, size_t sn) noexcept {
    if (n != sn) return false;
    for (size_t i = 0; i < n; ++i)
        if (p[i] != static_cast<uint8_t>(s[i])) return false;
    return true;
}

/**
 * @brief
 * \~english Server: QPACK's lines into a request, through the rules HTTP/2 shares (RFC 9114, 4.2-4.3).
 * \~spanish Servidor: las lineas de QPACK en una peticion, por las reglas que comparte HTTP/2 (RFC 9114, 4.2-4.3).
 * \~
 */
struct RequestSink final : qpack::FieldSink {
    RequestBuilder builder;
    const char *why = nullptr;
    bool field(const Buffer &out, const qpack::FieldLine &line) noexcept override {
        why = builder.add(out.data(), line.name, line.value);
        return why == nullptr;
    }
};

/**
 * @brief
 * \~english Client: QPACK's lines into a response: :status alone, first, three digits (RFC 9114, 4.3.2).
 * \~spanish Cliente: las lineas de QPACK en una respuesta: :status sola, primero, tres digitos (RFC 9114, 4.3.2).
 * \~
 */
struct ResponseSink final : qpack::FieldSink {
    Response *response = nullptr;
    bool trailers = false;
    bool seen_status = false;
    bool seen_field = false;
    const char *why = nullptr;
    bool field(const Buffer &out, const qpack::FieldLine &line) noexcept override {
        const uint8_t *n = out.data() + line.name.off;
        const uint8_t *v = out.data() + line.value.off;
        if (line.name.len == 0) return refuse("an empty field name");
        if (!field_value_is_valid(reinterpret_cast<const char *>(v), line.value.len))
            return refuse("a field value with a character HTTP forbids there (RFC 9114, 10.3)");
        if (n[0] == ':') {
            if (trailers) return refuse("a pseudo-header field in trailers (RFC 9114, 4.3)");
            if (seen_field) return refuse("a pseudo-header field after the fields (RFC 9114, 4.3)");
            if (!is_text(n, line.name.len, ":status", 7))
                return refuse("a pseudo-header field a response does not have (RFC 9114, 4.3.2)");
            if (seen_status) return refuse(":status twice (RFC 9114, 4.3.2)");
            if (line.value.len != 3) return refuse("a :status that is not three digits (RFC 9110, 15)");
            unsigned code = 0;
            for (uint32_t i = 0; i < 3; ++i) {
                if (v[i] < '0' || v[i] > '9') return refuse("a :status that is not three digits (RFC 9110, 15)");
                code = code * 10 + (v[i] - '0');
            }
            if (code < 100) return refuse("a :status below 100 (RFC 9110, 15)");
            seen_status = true;
            response->status = static_cast<StatusCode>(code);
            return true;
        }
        seen_field = true;
        for (uint32_t i = 0; i < line.name.len; ++i) {
            if (n[i] >= 'A' && n[i] <= 'Z') return refuse("an uppercase field name (RFC 9114, 4.2)");
            if (!is_tchar(n[i])) return refuse("a field name that is not a token (RFC 9114, 10.3)");
        }
        const FieldId id = field_id_of(reinterpret_cast<const char *>(n), line.name.len);
        if (id == FieldId::Connection || id == FieldId::KeepAlive || id == FieldId::TransferEncoding ||
            id == FieldId::Upgrade || id == FieldId::ProxyConnection)
            return refuse("a connection-specific field (RFC 9114, 4.2)");
        if (line.name.len > 0xffff || line.value.len > 0xffff) return refuse("a field longer than this end keeps");
        Field f{};
        f.name_off = line.name.off;
        f.name_len = static_cast<uint16_t>(line.name.len);
        f.value_off = line.value.off;
        f.value_len = static_cast<uint16_t>(line.value.len);
        f.id = id;
        response->fields.add(f);
        return true;
    }
    bool refuse(const char *w) noexcept {
        why = w;
        return false;
    }
};

} // namespace

Connection::~Connection() {
    if (messages_ != nullptr) {
        for (size_t i = 0; i < cfg_.max_requests; ++i) messages_[i].~Message();
        util::host_free(messages_);
    }
}

bool Connection::fail(uint64_t code, const char *why) noexcept {
    if (failure_.code == 0) {
        failure_.code = code;
        failure_.why = why;
        q_.close(code, true, 0, now_);
    }
    return false;
}

bool Connection::start(const Config &cfg) noexcept {
    if (started_) return fail(kInternalError, "an HTTP/3 connection started twice");
    cfg_ = cfg;
    started_ = true;
    qpack::DecoderConfig dc;
    dc.max_table_capacity = cfg.local.qpack_max_table_capacity;
    dc.blocked_streams = cfg.local.qpack_blocked_streams;
    // \~english Unlimited announced is still bounded here: a 431 is always an answer (4.2.2).
    // \~spanish Sin limite anunciado sigue acotado aqui: un 431 siempre es una respuesta (4.2.2).  \~
    dc.max_section = cfg.local.max_field_section_size == kNone ? (uint64_t{1} << 20) : cfg.local.max_field_section_size;
    if (!decoder_.reset(dc)) return fail(kInternalError, decoder_.failure().why);
    qpack::EncoderConfig ec;
    ec.max_capacity = cfg.encoder_capacity;
    if (!encoder_.reset(ec)) return fail(kInternalError, encoder_.failure().why);
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    messages_ = static_cast<Message *>(util::host_alloc(cfg.max_requests * sizeof(Message)));
    if (messages_ == nullptr) return fail(kInternalError, "out of memory for request streams");
    for (size_t i = 0; i < cfg.max_requests; ++i) new (&messages_[i]) Message();
    // \~english Each stream starts with its type; the control stream then SETTINGS, its first frame (6.2, 6.2.1).
    // \~spanish Cada flujo empieza con su tipo; el de control despues con SETTINGS, su primera trama (6.2, 6.2.1).  \~
    const uint64_t types[kLocalUni] = {kControlStream, qpack::kEncoderStreamType, qpack::kDecoderStreamType};
    for (size_t i = 0; i < kLocalUni; ++i) {
        local_[i].type = types[i];
        if (!write_varint(local_[i].out, types[i])) return fail(kInternalError, "out of memory for a stream header");
    }
    if (!write_settings(local_[0].out, cfg.local)) return fail(kInternalError, "the SETTINGS could not be written");
    open_local();
    flush();
    return !failed();
}

bool Connection::open_local() noexcept {
    // \~english As soon as the transport allows: settings MUST NOT wait for the peer (7.2.4.2).
    // \~spanish En cuanto el transporte lo permita: los parametros NO DEBEN esperar al otro (7.2.4.2).  \~
    for (size_t i = 0; i < kLocalUni; ++i) {
        if (local_[i].id != kNone) continue;
        quic::Stream *s = q_.streams().open(false);
        if (s == nullptr) return false;
        local_[i].id = s->id;
    }
    return true;
}

Connection::Uni *Connection::uni(uint64_t id) noexcept {
    for (Uni &u : peer_uni_)
        if (u.id == id) return &u;
    for (Uni &u : peer_uni_)
        if (u.id == kNone) {
            u.id = id;
            u.type = kNone;
            u.discard = false;
            u.head_len = 0;
            u.reader.reset(cfg_.max_held);
            return &u;
        }
    return nullptr;
}

Connection::Message *Connection::message(uint64_t id) noexcept {
    for (size_t i = 0; i < cfg_.max_requests; ++i)
        if (messages_[i].used && messages_[i].id == id) return &messages_[i];
    return nullptr;
}

const Connection::Message *Connection::message(uint64_t id) const noexcept {
    for (size_t i = 0; i < cfg_.max_requests; ++i)
        if (messages_[i].used && messages_[i].id == id) return &messages_[i];
    return nullptr;
}

Connection::Message *Connection::adopt(uint64_t id) noexcept {
    for (size_t i = 0; i < cfg_.max_requests; ++i) {
        Message &m = messages_[i];
        if (m.used) continue;
        m.used = true;
        m.id = id;
        m.phase = Phase::Headers;
        m.reader.reset(cfg_.max_held);
        m.blocked.clear();
        m.is_blocked = false;
        m.request.clear();
        m.response = Response{};
        m.fields.clear();
        m.content_length = kNone;
        m.body_seen = 0;
        m.head_request = false;
        m.final_response = false;
        m.final_sent = false;
        m.end_reported = false;
        m.out.clear();
        m.out_fin = false;
        return &m;
    }
    return nullptr;
}

void Connection::drop(Message &m) noexcept {
    m.used = false;
    m.blocked.clear();
    m.fields.clear();
    m.out.clear();
}

Event Connection::stream_error(Message &m, uint64_t code, const char *why) noexcept {
    stream_why_ = why;
    quic::Stream *s = q_.streams().find(m.id);
    if (s != nullptr) {
        // \~english Both directions: reset what is sent, stop what is received (4.1.1; RFC 9000, 3.5).
        // \~spanish Las dos direcciones: reiniciar lo que se manda, parar lo que se recibe (4.1.1; RFC 9000, 3.5).  \~
        if (s->send != nullptr && s->send->state() != quic::SendState::DataRecvd) s->send->reset(code);
        if (s->recv != nullptr) s->recv->stop(code);
    }
    // \~english QPACK learns the stream's references are released (RFC 9204, 2.2.2.2).
    // \~spanish QPACK sabe que las referencias del flujo quedan liberadas (RFC 9204, 2.2.2.2).  \~
    decoder_.cancel_stream(m.id);
    m.phase = Phase::Done;
    m.end_reported = true;
    m.out.clear();
    m.out_fin = false;
    Event e;
    e.kind = EventKind::Reset;
    e.stream = m.id;
    e.code = code;
    return e;
}

void Connection::cancel(uint64_t stream, uint64_t code) noexcept {
    Message *m = message(stream);
    if (m != nullptr) stream_error(*m, code, "cancelled by the application");
}

bool Connection::stop_reading(uint64_t stream) noexcept {
    Message *m = message(stream);
    // \~english Only a request already reported: nothing can stop what it has not been told of.
    // \~spanish Solo una peticion ya informada: nadie puede parar aquello de lo que no se le ha dicho nada.  \~
    if (!cfg_.server || m == nullptr || failed() || m->phase == Phase::Headers || m->phase == Phase::Done) return false;
    quic::Stream *s = q_.streams().find(stream);
    if (s == nullptr || s->recv == nullptr) return false;
    // \~english A trailer section waiting for QPACK, or any still to come, will not be read (RFC 9204, 4.4.2).
    // \~spanish Una seccion de remolques esperando a QPACK, o las que falten, no se leeran (RFC 9204, 4.4.2).  \~
    m->is_blocked = false;
    m->blocked.clear();
    decoder_.cancel_stream(m->id);
    // \~english Done and reported: read_message throws away what still arrives, and says nothing more.
    // \~spanish Acabado e informado: read_message tira lo que siga llegando, y no dice nada mas.  \~
    m->phase = Phase::Done;
    m->end_reported = true;
    s->recv->stop(kNoError);
    flush();
    return !failed();
}

bool Connection::flush_one(Buffer &out, bool fin, uint64_t id) noexcept {
    quic::Stream *s = q_.streams().find(id);
    if (s == nullptr || s->send == nullptr) return true;
    if (!out.empty()) {
        size_t accepted = 0;
        if (s->send->write(out.data(), out.size(), accepted) != quic::StreamError::None)
            return fail(kInternalError, "out of memory writing a stream");
        out.consume(accepted);
    }
    if (out.empty() && fin) s->send->finish();
    return true;
}

void Connection::flush() noexcept {
    if (!started_) return;
    // \~english QPACK's instructions onto their streams, once the streams exist (RFC 9204, 4.2).
    // \~spanish Las instrucciones de QPACK a sus flujos, cuando los flujos existen (RFC 9204, 4.2).  \~
    decoder_.flush();
    size_t n = 0;
    const uint8_t *p = encoder_.output(n);
    if (n != 0 && local_[1].id != kNone) {
        uint8_t *d = local_[1].out.reserve(n);
        if (d == nullptr) {
            fail(kInternalError, "out of memory for the encoder stream");
            return;
        }
        util::vesta_memcpy(d, p, n);
        local_[1].out.commit(n);
        encoder_.sent(n);
    }
    p = decoder_.output(n);
    if (n != 0 && local_[2].id != kNone) {
        uint8_t *d = local_[2].out.reserve(n);
        if (d == nullptr) {
            fail(kInternalError, "out of memory for the decoder stream");
            return;
        }
        util::vesta_memcpy(d, p, n);
        local_[2].out.commit(n);
        decoder_.sent(n);
    }
    for (Uni &u : local_)
        if (u.id != kNone) flush_one(u.out, false, u.id);
    for (size_t i = 0; i < cfg_.max_requests; ++i)
        if (messages_[i].used) flush_one(messages_[i].out, messages_[i].out_fin, messages_[i].id);
}

size_t Connection::encoder_room() noexcept {
    if (local_[1].id == kNone) return 0;
    const quic::Stream *s = q_.streams().find(local_[1].id);
    if (s == nullptr || s->send == nullptr) return 0;
    size_t pending = 0;
    encoder_.output(pending);
    // \~english What flow control lets through, minus what already waits (RFC 9204, 2.1.3).
    // \~spanish Lo que deja pasar el control de flujo, menos lo que ya espera (RFC 9204, 2.1.3).  \~
    const uint64_t used = s->send->written() + local_[1].out.size() + pending;
    return used >= s->send->limit() ? 0 : static_cast<size_t>(s->send->limit() - used);
}

bool Connection::on_control_frame(uint64_t type, const uint8_t *p, size_t n) noexcept {
    Failure why;
    uint64_t id = 0;
    switch (type) {
    case kSettings: {
        if (peer_settings_) return fail(kFrameUnexpected, "a second SETTINGS (7.2.4)");
        Settings s;
        if (!read_settings(p, n, s, why)) return fail(why.code, why.why);
        peer_ = s;
        peer_settings_ = true;
        // \~english The peer's decoder limits this end's encoder (RFC 9204, 3.2.3).
        // \~spanish El descodificador del otro limita al codificador de este extremo (RFC 9204, 3.2.3).  \~
        if (!encoder_.on_peer_settings(s.qpack_max_table_capacity, s.qpack_blocked_streams))
            return fail(encoder_.failure().code, encoder_.failure().why);
        return true;
    }
    case kHeaders:
    case kPushPromise:
        return fail(kFrameUnexpected, "a HEADERS or PUSH_PROMISE on the control stream (7.2.2, 7.2.5)");
    case kGoaway:
        if (!read_id(p, n, id, why)) return fail(why.code, why.why);
        if (!cfg_.server && (!by_client(id) || is_uni(id)))
            return fail(kIdError, "a GOAWAY naming a stream that is not a client request stream (7.2.6)");
        if (goaway_received_ != kNone && id > goaway_received_)
            return fail(kIdError, "a GOAWAY larger than the one before (5.2)");
        goaway_received_ = id;
        goaway_event_ = true;
        return true;
    case kMaxPushId:
        if (!cfg_.server) return fail(kFrameUnexpected, "a MAX_PUSH_ID from a server (7.2.7)");
        if (!read_id(p, n, id, why)) return fail(why.code, why.why);
        if (max_push_id_ != kNone && id < max_push_id_) return fail(kIdError, "a MAX_PUSH_ID that lowers the limit (7.2.7)");
        max_push_id_ = id;
        return true;
    case kCancelPush:
        if (!read_id(p, n, id, why)) return fail(why.code, why.why);
        // \~english This end never promises a push, and never allows one (4.6, 7.2.3).
        // \~spanish Este extremo nunca promete un push, ni permite ninguno (4.6, 7.2.3).  \~
        return fail(kIdError, cfg_.server ? "a CANCEL_PUSH for a push never promised (7.2.3)"
                                          : "a CANCEL_PUSH past the push IDs allowed (7.2.3)");
    default:
        return true;
    }
}

bool Connection::on_control(Uni &u, quic::Stream &s) noexcept {
    for (;;) {
        const uint8_t *p = nullptr;
        const size_t n = s.recv->peek(p);
        if (n == 0) return true;
        size_t used = 0;
        const Step step = u.reader.next(p, n, used);
        q_.consume(s, used);
        if (step == Step::Failed) return fail(u.reader.failure().code, u.reader.failure().why);
        // \~english SETTINGS first, before anything -- an unknown frame included (6.2.1, 9).
        // \~spanish SETTINGS primero, antes que nada -- una trama desconocida incluida (6.2.1, 9).  \~
        if (!peer_settings_ && (u.reader.skipped() != 0 || step == Step::Data ||
                                (step == Step::Frame && u.reader.type() != kSettings)))
            return fail(kMissingSettings, "the control stream does not start with SETTINGS (6.2.1)");
        if (step == Step::Data) return fail(kFrameUnexpected, "DATA on the control stream (7.2.1)");
        if (step == Step::Frame) {
            size_t len = 0;
            const uint8_t *payload = u.reader.payload(len);
            if (!on_control_frame(u.reader.type(), payload, len)) return false;
        }
    }
}

bool Connection::read_uni(quic::Stream &s, Uni &u) noexcept {
    for (;;) {
        const uint8_t *p = nullptr;
        const size_t n = s.recv->peek(p);
        if (n == 0) break;
        if (u.discard) {
            q_.consume(s, n);
            continue;
        }
        if (u.type == kNone) {
            // \~english The stream type, a varint, may come a byte at a time (6.2).
            // \~spanish El tipo de flujo, un varint, puede llegar byte a byte (6.2).  \~
            u.head[u.head_len++] = p[0];
            q_.consume(s, 1);
            if (u.head_len < quic::varint_length(u.head[0])) continue;
            uint64_t type = 0;
            quic::decode_varint(u.head, u.head_len, type);
            u.type = type;
            if (type == kControlStream) {
                if (peer_control_) return fail(kStreamCreationError, "a second control stream (6.2.1)");
                peer_control_ = true;
            } else if (type == kPushStream) {
                if (cfg_.server) return fail(kStreamCreationError, "a push stream from a client (6.2.2)");
                return fail(kIdError, "a push stream with no MAX_PUSH_ID sent (4.6)");
            } else if (type == qpack::kEncoderStreamType) {
                if (peer_encoder_) return fail(kStreamCreationError, "a second QPACK encoder stream (RFC 9204, 4.2)");
                peer_encoder_ = true;
            } else if (type == qpack::kDecoderStreamType) {
                if (peer_decoder_) return fail(kStreamCreationError, "a second QPACK decoder stream (RFC 9204, 4.2)");
                peer_decoder_ = true;
            } else {
                // \~english Unknown or reserved: never an error; reading stops (6.2, 9).
                // \~spanish Desconocido o reservado: nunca un error; se deja de leer (6.2, 9).  \~
                u.discard = true;
                s.recv->stop(kStreamCreationError);
            }
            continue;
        }
        if (u.type == kControlStream) {
            if (!on_control(u, s)) return false;
            // \~english Everything read: what is left is whether the stream ended.
            // \~spanish Todo leido: lo que queda es si el flujo acabo.  \~
            break;
        }
        if (u.type == qpack::kEncoderStreamType) {
            if (!decoder_.on_encoder_stream(p, n)) return fail(decoder_.failure().code, decoder_.failure().why);
        } else if (!encoder_.on_decoder_stream(p, n)) {
            return fail(encoder_.failure().code, encoder_.failure().why);
        }
        q_.consume(s, n);
    }
    // \~english The critical streams never end: closing one closes the connection (6.2.1; RFC 9204, 4.2).
    // \~spanish Los flujos criticos no acaban nunca: cerrar uno cierra la conexion (6.2.1; RFC 9204, 4.2).  \~
    const quic::RecvState st = s.recv->state();
    const bool ended = st == quic::RecvState::ResetRecvd || st == quic::RecvState::ResetRead ||
                       st == quic::RecvState::DataRead ||
                       (s.recv->size_known() && s.recv->read_offset() == s.recv->final_size());
    const bool critical =
        u.type == kControlStream || u.type == qpack::kEncoderStreamType || u.type == qpack::kDecoderStreamType;
    if (ended && critical) return fail(kClosedCriticalStream, "a control or QPACK stream was closed (6.2.1; RFC 9204, 4.2)");
    return true;
}

Event Connection::finish_headers(Message &m, qpack::Outcome o, const char *sink_why) noexcept {
    Event none;
    switch (o) {
    case qpack::Outcome::Blocked:
        return none;
    case qpack::Outcome::Failed:
        fail(decoder_.failure().code, decoder_.failure().why);
        return none;
    case qpack::Outcome::StreamFailed:
        return stream_error(m, kMessageError, decoder_.section_why());
    case qpack::Outcome::Rejected:
        return stream_error(m, kMessageError, sink_why);
    case qpack::Outcome::TooLarge:
        if (cfg_.server) {
            // \~english Larger than this end takes: answered 431, the rest of the request not read (4.2.2, 4.1).
            // \~spanish Mayor de lo que acepta este extremo: se contesta 431, el resto de la peticion sin leer (4.2.2, 4.1).  \~
            stream_why_ = "a header section larger than this end takes, answered 431 (4.2.2)";
            m.phase = Phase::Done;
            m.end_reported = true;
            respond(m.id, 431, nullptr, 0, true);
            quic::Stream *s = q_.streams().find(m.id);
            if (s != nullptr && s->recv != nullptr) s->recv->stop(kNoError);
            return none;
        }
        return stream_error(m, kMessageError, "a response header section larger than this end takes (4.2.2)");
    case qpack::Outcome::Done:
        break;
    }
    const ContentLength cl = parse_content_length(cfg_.server ? m.request.fields : m.response.fields, m.fields.data());
    if (cl.status != ContentLengthStatus::Absent && cl.status != ContentLengthStatus::Present)
        return stream_error(m, kMessageError, "a Content-Length that is not one number (RFC 9110, 8.6)");
    m.content_length = cl.status == ContentLengthStatus::Present ? cl.value : kNone;
    Event e;
    e.stream = m.id;
    if (cfg_.server) {
        m.request.version = Version::Http3;
        m.phase = Phase::Body;
        e.kind = EventKind::Request;
        return e;
    }
    m.response.version = Version::Http3;
    // \~english Interim responses precede the final one, and have no content (4.1).
    // \~spanish Las respuestas provisionales van antes de la final, y no tienen contenido (4.1).  \~
    if (m.response.status >= 200) {
        m.phase = Phase::Body;
        m.final_response = true;
        // \~english No content, whatever Content-Length says: HEAD, 204, 304 (RFC 9110, 6.4.1; 4.1.2).
        // \~spanish Sin contenido, diga lo que diga Content-Length: HEAD, 204, 304 (RFC 9110, 6.4.1; 4.1.2).  \~
        if (m.head_request || m.response.status == 204 || m.response.status == 304) m.content_length = kNone;
    }
    e.kind = EventKind::Response;
    return e;
}

Event Connection::on_headers(Message &m, const uint8_t *p, size_t n) noexcept {
    m.fields.clear();
    qpack::Outcome o;
    const char *why = nullptr;
    if (cfg_.server) {
        RequestSink sink;
        RequestBuilder::Options opt;
        opt.exact_host = true;
        sink.builder.start(m.request, opt);
        o = decoder_.decode(m.id, p, n, m.fields, sink);
        why = sink.why;
        if (o == qpack::Outcome::Done) {
            const char *bad = sink.builder.finish(m.fields.data());
            if (bad != nullptr) return stream_error(m, kMessageError, bad);
        }
    } else {
        ResponseSink sink;
        m.response = Response{};
        sink.response = &m.response;
        o = decoder_.decode(m.id, p, n, m.fields, sink);
        why = sink.why;
        if (o == qpack::Outcome::Done && !sink.seen_status)
            return stream_error(m, kMessageError, "a response with no :status (4.3.2)");
    }
    if (o == qpack::Outcome::Blocked) {
        // \~english Kept whole until the inserts it needs arrive; the stream is not read meanwhile (2.2.1).
        // \~spanish Guardada entera hasta que lleguen las inserciones que necesita; el flujo no se lee mientras (2.2.1).  \~
        if (p != m.blocked.data()) {
            m.blocked.clear();
            uint8_t *d = m.blocked.reserve(n);
            if (d == nullptr) {
                fail(kInternalError, "out of memory keeping a blocked header section");
                return Event{};
            }
            util::vesta_memcpy(d, p, n);
            m.blocked.commit(n);
        }
        m.is_blocked = true;
        return Event{};
    }
    m.is_blocked = false;
    return finish_headers(m, o, why);
}

Event Connection::on_trailers(Message &m, const uint8_t *p, size_t n) noexcept {
    const char *why = nullptr;
    qpack::Outcome o;
    if (cfg_.server) {
        RequestSink sink;
        sink.builder.start_trailers(m.request);
        o = decoder_.decode(m.id, p, n, m.fields, sink);
        why = sink.why;
    } else {
        ResponseSink sink;
        sink.response = &m.response;
        sink.trailers = true;
        o = decoder_.decode(m.id, p, n, m.fields, sink);
        why = sink.why;
    }
    if (o == qpack::Outcome::Blocked) {
        // \~english Trailers may wait for inserts too; kept, and reread when unblocked.
        // \~spanish Los remolques tambien pueden esperar inserciones; se guardan, y se releen al desbloquearse.  \~
        if (p != m.blocked.data()) {
            m.blocked.clear();
            uint8_t *d = m.blocked.reserve(n);
            if (d == nullptr) {
                fail(kInternalError, "out of memory keeping blocked trailers");
                return Event{};
            }
            util::vesta_memcpy(d, p, n);
            m.blocked.commit(n);
        }
        m.is_blocked = true;
        return Event{};
    }
    m.is_blocked = false;
    if (o != qpack::Outcome::Done) {
        if (o == qpack::Outcome::Failed) {
            fail(decoder_.failure().code, decoder_.failure().why);
            return Event{};
        }
        return stream_error(m, kMessageError, why != nullptr ? why : decoder_.section_why());
    }
    Event e;
    e.kind = EventKind::Trailers;
    e.stream = m.id;
    return e;
}

Event Connection::read_message(quic::Stream &s, Message &m) noexcept {
    Event none;
    if (s.recv == nullptr) return none;
    if (m.is_blocked) {
        // \~english Waiting for QPACK: the stream is not read -- unless the peer reset it, which ends the wait (RFC 9204, 2.2.2.2).
        // \~spanish Esperando a QPACK: el flujo no se lee -- salvo que el otro lo reinicie, que acaba la espera (RFC 9204, 2.2.2.2).  \~
        const quic::RecvState st = s.recv->state();
        if (st != quic::RecvState::ResetRecvd && st != quic::RecvState::ResetRead) return none;
        m.is_blocked = false;
        m.blocked.clear();
        decoder_.cancel_stream(m.id);
        m.phase = Phase::Done;
        m.end_reported = true;
        Event e;
        e.kind = EventKind::Reset;
        e.stream = m.id;
        e.code = s.recv->reset_code();
        return e;
    }
    for (;;) {
        const uint8_t *p = nullptr;
        const size_t n = s.recv->peek(p);
        if (m.phase == Phase::Done) {
            // \~english A stream this end is done with: what still arrives is read and thrown away.
            // \~spanish Un flujo con el que este extremo acabo: lo que siga llegando se lee y se tira.  \~
            if (n != 0) {
                q_.consume(s, n);
                continue;
            }
            return none;
        }
        if (n == 0) {
            const quic::RecvState st = s.recv->state();
            if (st == quic::RecvState::ResetRecvd || st == quic::RecvState::ResetRead) {
                // \~english Reset by the peer before the end: QPACK is told the stream is gone (RFC 9204, 2.2.2.2).
                // \~spanish Reiniciado por el otro antes del final: se le dice a QPACK que el flujo ya no esta (RFC 9204, 2.2.2.2).  \~
                decoder_.cancel_stream(m.id);
                m.phase = Phase::Done;
                m.end_reported = true;
                Event e;
                e.kind = EventKind::Reset;
                e.stream = m.id;
                e.code = s.recv->reset_code();
                return e;
            }
            const bool ended = st == quic::RecvState::DataRead ||
                               (s.recv->size_known() && s.recv->read_offset() == s.recv->final_size());
            if (!ended) return none;
            if (!m.reader.at_boundary()) {
                fail(kFrameError, "a stream that ends inside a frame (7.1)");
                return none;
            }
            if (m.phase == Phase::Headers) {
                return stream_error(m, cfg_.server ? kRequestIncomplete : kMessageError,
                                    cfg_.server ? "a request stream that ended before its header section (4.1)"
                                                : "a response stream that ended before a final response (4.1)");
            }
            // \~english Content-Length against the sum of DATA (4.1.2).  \~spanish Content-Length contra la suma de los DATA (4.1.2).  \~
            if (m.content_length != kNone && m.body_seen != m.content_length)
                return stream_error(m, kMessageError, "content that does not match Content-Length (4.1.2)");
            m.phase = Phase::Done;
            m.end_reported = true;
            Event e;
            e.kind = EventKind::End;
            e.stream = m.id;
            return e;
        }
        size_t used = 0;
        const Step step = m.reader.next(p, n, used);
        if (step == Step::Failed) {
            q_.consume(s, used);
            fail(m.reader.failure().code, m.reader.failure().why);
            return none;
        }
        if (step == Step::More) {
            q_.consume(s, used);
            continue;
        }
        if (step == Step::Data) {
            if (m.phase != Phase::Body) {
                q_.consume(s, used);
                fail(kFrameUnexpected, m.phase == Phase::Headers ? "DATA before HEADERS (4.1)" : "DATA after the trailers (4.1)");
                return none;
            }
            size_t len = 0;
            const uint8_t *d = m.reader.data(len);
            m.body_seen += len;
            if (m.content_length != kNone && m.body_seen > m.content_length) {
                q_.consume(s, used);
                return stream_error(m, kMessageError, "more content than Content-Length (4.1.2)");
            }
            if (len == 0) {
                q_.consume(s, used);
                continue;
            }
            // \~english The bytes stay in the stream until the next poll: no copy.
            // \~spanish Los bytes se quedan en el flujo hasta el siguiente poll: sin copia.  \~
            defer_stream_ = m.id;
            defer_n_ = used;
            Event e;
            e.kind = EventKind::Body;
            e.stream = m.id;
            e.data = d;
            e.len = len;
            return e;
        }
        q_.consume(s, used);
        size_t len = 0;
        const uint8_t *payload = m.reader.payload(len);
        switch (m.reader.type()) {
        case kHeaders:
            if (m.phase == Phase::Headers) {
                Event e = on_headers(m, payload, len);
                if (e.kind != EventKind::None || m.is_blocked || failed()) return e;
                continue;
            }
            if (m.phase == Phase::Body) {
                m.phase = Phase::Trailers;
                return on_trailers(m, payload, len);
            }
            fail(kFrameUnexpected, "a HEADERS after the trailers (4.1)");
            return none;
        case kPushPromise:
            if (cfg_.server) fail(kFrameUnexpected, "a PUSH_PROMISE from a client (7.2.5)");
            else fail(kIdError, "a PUSH_PROMISE with no MAX_PUSH_ID sent (7.2.5)");
            return none;
        default:
            fail(kFrameUnexpected, "a control frame on a request stream (7.2.3-7.2.7)");
            return none;
        }
    }
}

Event Connection::poll(uint64_t now_us) noexcept {
    now_ = now_us;
    Event none;
    if (!started_) return none;
    if (failed()) {
        if (closed_reported_) return none;
        closed_reported_ = true;
        Event e;
        e.kind = EventKind::Closed;
        e.code = failure_.code;
        return e;
    }
    if (defer_n_ != 0) {
        quic::Stream *s = q_.streams().find(defer_stream_);
        if (s != nullptr && s->recv != nullptr) q_.consume(*s, defer_n_);
        defer_n_ = 0;
    }
    open_local();
    quic::StreamTable &t = q_.streams();
    // \~english The peer's unidirectional streams first: SETTINGS and QPACK's inserts shape the rest.
    // \~spanish Primero los flujos unidireccionales del otro: SETTINGS y las inserciones de QPACK dan forma al resto.  \~
    for (size_t i = 0; i < t.capacity() && !failed(); ++i) {
        quic::Stream *s = t.slot(i);
        if (s == nullptr || !is_uni(s->id) || s->recv == nullptr) continue;
        Uni *u = uni(s->id);
        if (u == nullptr) {
            s->recv->stop(kStreamCreationError);
            continue;
        }
        read_uni(*s, *u);
    }
    if (goaway_event_ && !failed()) {
        goaway_event_ = false;
        Event e;
        e.kind = EventKind::GoAway;
        e.code = goaway_received_;
        return e;
    }
    // \~english Sections QPACK can read now.  \~spanish Secciones que QPACK ya puede leer.  \~
    for (;;) {
        if (failed()) break;
        if (unblocked_at_ == unblocked_count_) {
            unblocked_at_ = 0;
            unblocked_count_ = decoder_.take_unblocked(unblocked_, kUnblockedBatch);
            if (unblocked_count_ == 0) break;
        }
        Message *m = message(unblocked_[unblocked_at_++]);
        if (m == nullptr || !m->is_blocked) continue;
        Buffer kept;
        kept.clear();
        const size_t n = m->blocked.size();
        uint8_t *d = kept.reserve(n);
        if (d == nullptr) {
            fail(kInternalError, "out of memory rereading a header section");
            break;
        }
        util::vesta_memcpy(d, m->blocked.data(), n);
        kept.commit(n);
        m->blocked.clear();
        m->is_blocked = false;
        Event e = m->phase == Phase::Headers ? on_headers(*m, kept.data(), n) : on_trailers(*m, kept.data(), n);
        if (e.kind != EventKind::None) {
            e.slot = static_cast<size_t>(m - messages_);
            flush();
            return e;
        }
    }
    if (failed()) return poll(now_us);
    /* \~english
     * Server: every client request stream not seen yet, in order of ID (6.1).
     * QUIC opens a peer's streams in order, implicitly the lower ones first
     * (RFC 9000, 3.2), so the new ones are exactly the indices from
     * next_request_ to what the peer opened -- each visited once.  Walking
     * the table instead visited them in the order of its slots, and a stream
     * found before a lower one moved next_request_ past the lower one, which
     * was then never read.
     * \~spanish
     * Servidor: cada flujo de peticion del cliente aun sin ver, en orden de ID
     * (6.1).  QUIC abre los flujos del otro en orden, implicitamente los
     * menores primero (RFC 9000, 3.2), asi que los nuevos son exactamente los
     * indices desde next_request_ hasta lo que abrio el otro -- cada uno
     * visitado una vez.  Recorrer la tabla en su lugar los visitaba en el orden
     * de sus casillas, y un flujo encontrado antes que otro menor adelantaba
     * next_request_ por encima del menor, que ya no se leia nunca.
     * \~ */
    const uint64_t opened = t.peer_opened(true);
    if (!cfg_.server) {
        if (opened != 0) fail(kStreamCreationError, "a server-initiated bidirectional stream (6.1)");
    } else {
        for (; next_request_ / 4 < opened && !failed(); next_request_ += 4) {
            quic::Stream *s = t.find(next_request_);
            // \~english Gone before it was seen: there is nothing left of it to read.
            // \~spanish Ido antes de verlo: no queda nada de el que leer.  \~
            if (s == nullptr) continue;
            // \~english After GOAWAY, and past what this end follows, a request is refused before it is read (5.2, 4.1.1).
            // \~spanish Tras GOAWAY, y pasado lo que sigue este extremo, una peticion se rechaza antes de leerla (5.2, 4.1.1).  \~
            Message *m = (goaway_sent_ != kNone && s->id >= goaway_sent_) ? nullptr : adopt(s->id);
            if (m == nullptr) {
                if (s->send != nullptr) s->send->reset(kRequestRejected);
                if (s->recv != nullptr) s->recv->stop(kRequestRejected);
            }
        }
    }
    if (failed()) return poll(now_us);
    for (size_t step = 0; step < cfg_.max_requests; ++step) {
        Message &m = messages_[(cursor_ + step) % cfg_.max_requests];
        if (!m.used) continue;
        quic::Stream *s = t.find(m.id);
        if (s == nullptr) {
            drop(m);
            continue;
        }
        Event e = read_message(*s, m);
        if (failed()) return poll(now_us);
        if (e.kind != EventKind::None) {
            e.slot = static_cast<size_t>(&m - messages_);
            cursor_ = (cursor_ + step + 1) % cfg_.max_requests;
            flush();
            return e;
        }
    }
    flush();
    if (failed()) return poll(now_us);
    return none;
}

const Request *Connection::request(uint64_t stream, const Buffer *&bytes) const noexcept {
    const Message *m = message(stream);
    if (m == nullptr || !cfg_.server || m->phase == Phase::Headers) return nullptr;
    bytes = &m->fields;
    return &m->request;
}

const Response *Connection::response(uint64_t stream, const Buffer *&bytes) const noexcept {
    const Message *m = message(stream);
    if (m == nullptr || cfg_.server || m->response.status == 0) return nullptr;
    bytes = &m->fields;
    return &m->response;
}

bool Connection::encode(Message &m, const qpack::Line *lines, size_t count, bool end) noexcept {
    // \~english The peer's limit on a field section: SHOULD NOT be exceeded (4.2.2).
    // \~spanish El limite del otro a una seccion de campos: NO DEBERIA superarse (4.2.2).  \~
    uint64_t size = 0;
    for (size_t i = 0; i < count; ++i) size += lines[i].name_len + lines[i].value_len + qpack::kEntryOverhead;
    if (peer_settings_ && size > peer_.max_field_section_size) {
        stream_why_ = "a field section larger than the peer takes (4.2.2)";
        return false;
    }
    flush();
    Buffer block;
    if (!encoder_.encode(m.id, lines, count, block, encoder_room()))
        return fail(encoder_.failure().code, encoder_.failure().why);
    if (!write_head(m.out, kHeaders, block.size())) return fail(kInternalError, "out of memory for a HEADERS frame");
    uint8_t *d = m.out.reserve(block.size());
    if (d == nullptr) return fail(kInternalError, "out of memory for a HEADERS frame");
    util::vesta_memcpy(d, block.data(), block.size());
    m.out.commit(block.size());
    if (end) m.out_fin = true;
    flush();
    return !failed();
}

bool Connection::respond(uint64_t stream, StatusCode status, const qpack::Line *fields, size_t count, bool end) noexcept {
    Message *m = message(stream);
    if (!cfg_.server || m == nullptr || failed()) return false;
    // \~english One final response, after any interim ones; none once the stream is done (4.1).
    // \~spanish Una respuesta final, tras las provisionales que haya; ninguna cuando el flujo acabo (4.1).  \~
    if (m->final_sent || m->out_fin) return false;
    if (m->phase == Phase::Done && !m->end_reported) return false;
    // \~english No 101 in HTTP/3 (4.5); an interim response has no content and cannot end the stream (4.1).
    // \~spanish Sin 101 en HTTP/3 (4.5); una respuesta provisional no tiene contenido y no puede acabar el flujo (4.1).  \~
    if (status < 100 || status > 999 || status == 101 || (status < 200 && end) || count + 1 > kMostLines) return false;
    qpack::Line lines[kMostLines];
    char code[3] = {static_cast<char>('0' + status / 100), static_cast<char>('0' + status / 10 % 10),
                    static_cast<char>('0' + status % 10)};
    lines[0].name = reinterpret_cast<const uint8_t *>(":status");
    lines[0].name_len = 7;
    lines[0].value = reinterpret_cast<const uint8_t *>(code);
    lines[0].value_len = 3;
    for (size_t i = 0; i < count; ++i) lines[i + 1] = fields[i];
    if (!encode(*m, lines, count + 1, end)) return false;
    if (status >= 200) m->final_sent = true;
    return true;
}

bool Connection::send_body(uint64_t stream, const uint8_t *p, size_t n, bool end) noexcept {
    Message *m = message(stream);
    if (m == nullptr || failed() || m->out_fin) return false;
    // \~english Content only after the final response's header section (4.1); a client's after its request's.
    // \~spanish Contenido solo tras la cabecera de la respuesta final (4.1); el de un cliente tras la de su peticion.  \~
    if (cfg_.server && !m->final_sent) return false;
    if (n != 0) {
        if (!write_head(m->out, kData, n)) return fail(kInternalError, "out of memory for a DATA frame");
        uint8_t *d = m->out.reserve(n);
        if (d == nullptr) return fail(kInternalError, "out of memory for a DATA frame");
        util::vesta_memcpy(d, p, n);
        m->out.commit(n);
    }
    if (end) m->out_fin = true;
    flush();
    return !failed();
}

uint64_t Connection::send_request(const qpack::Line *lines, size_t count, bool end) noexcept {
    if (cfg_.server || failed() || !started_) return kNone;
    // \~english No new request after the peer's GOAWAY (5.2).  \~spanish Ninguna peticion nueva tras el GOAWAY del otro (5.2).  \~
    if (goaway_received_ != kNone) return kNone;
    quic::Stream *s = q_.streams().open(true);
    if (s == nullptr) return kNone;
    Message *m = adopt(s->id);
    if (m == nullptr) {
        s->send->reset(kRequestCancelled);
        return kNone;
    }
    for (size_t i = 0; i < count; ++i)
        if (is_text(lines[i].name, lines[i].name_len, ":method", 7) &&
            is_text(lines[i].value, lines[i].value_len, "HEAD", 4))
            m->head_request = true;
    if (!encode(*m, lines, count, end)) {
        drop(*m);
        return kNone;
    }
    return s->id;
}

bool Connection::goaway() noexcept {
    if (!cfg_.server || failed() || !started_) return false;
    // \~english The first request stream not processed; never more than a GOAWAY before (5.2).
    // \~spanish El primer flujo de peticion sin procesar; nunca mas que un GOAWAY anterior (5.2).  \~
    uint64_t id = next_request_;
    if (goaway_sent_ != kNone && id > goaway_sent_) id = goaway_sent_;
    goaway_sent_ = id;
    if (!write_id(local_[0].out, kGoaway, id)) return fail(kInternalError, "out of memory for a GOAWAY");
    flush();
    return !failed();
}

} // namespace h3
} // namespace http_vx
