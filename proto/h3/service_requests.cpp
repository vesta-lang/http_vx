/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service_requests.cpp
 * @brief
 * \~english The HTTP/3 service's requests: from HTTP/3's events to the handler and back.
 * \~spanish Las peticiones del servicio HTTP/3: de los eventos de HTTP/3 al manejador y de vuelta.
 * \~
 *
 * \~english
 * A body arrives in pieces and is kept until the request ends, because the
 * handler takes a request whole -- the same contract it has with the other
 * two versions.  Past max_body it is not kept at all: the answer is 413 and
 * the rest of the request is not read (RFC 9114, 4.1.1).
 *
 * The answer is the handler's, written as HTTP/3 needs it: names lowered and
 * checked by the rule the three versions share (response_lines.h), secrets
 * never inserted into QPACK's table, and for HEAD the fields of the response
 * with none of its content -- its length said in Content-Length, as it would
 * have been for GET (RFC 9110, 9.3.2).
 *
 * \~spanish
 * Un cuerpo llega a pedazos y se guarda hasta que acaba la peticion, porque el
 * manejador toma una peticion entera -- el mismo contrato que tiene con las
 * otras dos versiones --.  Pasado max_body no se guarda en absoluto: la
 * respuesta es 413 y el resto de la peticion no se lee (RFC 9114, 4.1.1).
 *
 * La respuesta es la del manejador, escrita como la necesita HTTP/3: nombres en
 * minusculas y comprobados con la regla que comparten las tres versiones
 * (response_lines.h), secretos nunca insertados en la tabla de QPACK, y para
 * HEAD las cabeceras de la respuesta sin nada de su contenido -- su longitud
 * dicha en Content-Length, como lo habria sido para GET (RFC 9110, 9.3.2).
 * \~
 */
#include "service_slot.h"

#include "http_vx/content_length.h"
#include "http_vx/response_lines.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {

namespace {

/// \~english The most fields an answer carries: h3::Connection takes 64 lines, one is :status and one Content-Length.
/// \~spanish Las cabeceras mas que lleva una respuesta: h3::Connection acepta 64 lineas, una es :status y otra Content-Length.  \~
constexpr size_t kMostFields = 62;

} // namespace

void Http3Service::pump(Slot &s, uint64_t now_us) noexcept {
    s.tls->step(now_us);
    for (;;) {
        const h3::Event e = s.h3->poll(now_us);
        if (e.kind == h3::EventKind::None) break;
        on_event(s, e);
    }
    if (s.h3->failed() && !s.failure_counted) {
        s.failure_counted = true;
        ++counts_.failed;
    }
}

void Http3Service::on_event(Slot &s, const h3::Event &e) noexcept {
    if (e.slot >= cfg_.h3.max_requests) return;
    Work &w = s.works[e.slot];
    switch (e.kind) {
    case h3::EventKind::Request:
        // \~english A new request in this place: whatever was here before is over.
        // \~spanish Una peticion nueva en este sitio: lo que hubiera antes se acabo.  \~
        w.used = true;
        w.stream = e.stream;
        w.refused = false;
        w.body.clear();
        break;
    case h3::EventKind::Body: {
        if (!w.used || w.stream != e.stream || w.refused) break;
        if (w.body.size() + e.len > cfg_.max_body) {
            // \~english Too large: answered now, and the rest is not read (RFC 9114, 4.1.1).
            // \~spanish Demasiado grande: se contesta ya, y el resto no se lee (RFC 9114, 4.1.1).  \~
            w.refused = true;
            w.body.release();
            ++counts_.too_large;
            respond_status(s, e.stream, 413);
            s.h3->stop_reading(e.stream);
            break;
        }
        uint8_t *d = w.body.reserve(e.len);
        if (d == nullptr) {
            w.refused = true;
            w.body.release();
            respond_status(s, e.stream, 503);
            s.h3->stop_reading(e.stream);
            break;
        }
        util::vesta_memcpy(d, e.data, e.len);
        w.body.commit(e.len);
        break;
    }
    case h3::EventKind::End:
        if (w.used && w.stream == e.stream && !w.refused) answer(s, w);
        w.used = false;
        w.body.clear();
        break;
    case h3::EventKind::Reset:
        w.used = false;
        w.body.clear();
        break;
    default:
        // \~english Trailers joined the request's fields; the rest is the connection's, not a request's.
        // \~spanish Los remolques se unieron a las cabeceras de la peticion; el resto es de la conexion, no de una peticion.  \~
        break;
    }
}

void Http3Service::answer(Slot &s, Work &w) noexcept {
    const Buffer *head = nullptr;
    const Request *req = s.h3->request(w.stream, head);
    if (req == nullptr) return;
    const uint8_t *body = w.body.empty() ? nullptr : w.body.data();
    ResponseBuilder res(said_);
    handler_.handle(*req, head->data(), body, w.body.size(), res);

    WireField wf[kMostFields];
    size_t count = 0;
    // \~english An answer that cannot travel as written is this server's fault: 500, never a changed answer.
    // \~spanish Una respuesta que no puede viajar tal como se escribio es culpa de este servidor: 500, nunca una respuesta cambiada.  \~
    if (res.failed() || wire_fields(res, names_, wf, kMostFields, count) != nullptr) {
        ++counts_.bad_answers;
        respond_status(s, w.stream, 500);
        return;
    }
    qpack::Line lines[kMostFields + 1];
    bool has_length = false;
    for (size_t i = 0; i < count; ++i) {
        lines[i].name = wf[i].name;
        lines[i].name_len = wf[i].name_len;
        lines[i].value = wf[i].value;
        lines[i].value_len = wf[i].value_len;
        lines[i].indexing = field_is_secret(wf[i].id) ? qpack::Indexing::Never : qpack::Indexing::Insert;
        if (wf[i].id == FieldId::ContentLength) has_length = true;
    }
    const Span content = res.body();
    const bool head_request = req->method == MethodId::Head;
    // \~english HEAD: the length GET would have had, and no content (RFC 9110, 9.3.2).
    // \~spanish HEAD: la longitud que habria tenido GET, y sin contenido (RFC 9110, 9.3.2).  \~
    uint8_t length[kContentLengthDigits];
    if (head_request && !has_length) {
        lines[count].name = reinterpret_cast<const uint8_t *>(field_name(FieldId::ContentLength));
        lines[count].name_len = field_name_len(FieldId::ContentLength);
        lines[count].value = length;
        lines[count].value_len = write_content_length(length, content.len);
        ++count;
    }
    const bool end_now = head_request || content.len == 0;
    if (!s.h3->respond(w.stream, res.status(), lines, count, end_now)) {
        ++counts_.bad_answers;
        respond_status(s, w.stream, 500);
        return;
    }
    if (!end_now) s.h3->send_body(w.stream, res.bytes() + content.off, content.len, true);
    ++counts_.served;
}

void Http3Service::respond_status(Slot &s, uint64_t stream, StatusCode status) noexcept {
    // \~english Even that may not go -- the peer's limits, a stream gone: then the stream ends in error.
    // \~spanish Ni eso puede salir -- los limites del otro, un flujo que ya no esta --: entonces el flujo acaba en error.  \~
    if (!s.h3->respond(stream, status, nullptr, 0, true)) s.h3->cancel(stream, h3::kInternalError);
}

} // namespace http_vx
