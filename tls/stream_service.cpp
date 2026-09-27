/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/stream_service.cpp
 * @brief
 * \~english The TLS stream service: a channel per connection, ALPN to choose the inner service, plaintext lent by the call.
 * \~spanish El servicio de flujo TLS: un canal por conexion, ALPN para elegir el servicio de dentro, texto en claro prestado por llamada.
 * \~
 */

#include "http_vx/tls_service.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {

namespace {

/// \~english The ALPN names (RFC 9113, 3.2; RFC 7301, 6).  \~spanish Los nombres de ALPN (RFC 9113, 3.2; RFC 7301, 6).  \~
const char kH2[] = "h2";
const char kHttp11[] = "http/1.1";

/// \~english Whether the @p n bytes at @p p are the name @p want.  \~spanish Si los @p n bytes de @p p son el nombre @p want.  \~
bool is_name(const uint8_t *p, size_t n, const char *want) noexcept {
    size_t i = 0;
    for (; i < n && want[i] != '\0'; ++i)
        if (p[i] != static_cast<uint8_t>(want[i])) return false;
    return i == n && want[i] == '\0';
}

} // namespace

/**
 * @brief
 * \~english What one connection keeps here, between calls.
 * \~spanish Lo que guarda aqui una conexion, entre llamadas.
 * \~
 */
struct TlsService::Slot {
    tls::Channel channel;
    /// \~english Where the plaintext stream is: the origin a fresh buffer is rebased to.
    /// \~spanish Por donde va el flujo en claro: el origen al que se reubica un buffer nuevo.  \~
    uint64_t plain_at = 0;
    /// \~english Chosen by ALPN once the handshake completed; null before.  \~spanish Elegido por ALPN cuando se completo el saludo; nulo antes.  \~
    Service *inner = nullptr;
    /// \~english The plaintext buffer lent, or kNoBuffer.  \~spanish El buffer en claro prestado, o kNoBuffer.  \~
    uint32_t plain = kNoBuffer;
};

TlsService::~TlsService() {
    release();
}

size_t TlsService::slot_size() noexcept {
    return sizeof(Slot);
}

void TlsService::release() noexcept {
    if (slots_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) slots_[i].~Slot();
        util::host_free(slots_);
        slots_ = nullptr;
    }
    capacity_ = 0;
    plain_.release_all();
    scratch_.release();
}

bool TlsService::reset(uint32_t connections, const TlsServiceConfig &cfg) noexcept {
    release();
    why_ = nullptr;
    // \~english Asked for TLS and cannot give it: said now, never served in the clear (R24).
    // \~spanish Se pidio TLS y no se puede dar: se dice ahora, nunca se sirve en claro (R24).  \~
    if (cfg.crypto == nullptr) {
        why_ = "no cryptographic provider: TLS cannot be served, and it is not served in the clear instead";
        return false;
    }
    if (cfg.http1 == nullptr && cfg.http2 == nullptr) {
        why_ = "no inner service to hand the plaintext to";
        return false;
    }
    if (cfg.certificate_count == 0 || cfg.certificates == nullptr || cfg.signing_key == nullptr) {
        why_ = "no certificate or no signing key to authenticate with";
        return false;
    }
    cfg_ = cfg;

    // \~english h2 first when both are here: the server's preference decides among what the client lists (RFC 7301, 3.2).
    // \~spanish h2 primero cuando estan los dos: la preferencia del servidor decide entre lo que lista el cliente (RFC 7301, 3.2).  \~
    size_t names = 0;
    if (cfg.http2 != nullptr) alpn_[names++] = kH2;
    if (cfg.http1 != nullptr) alpn_[names++] = kHttp11;
    session_ = tls::SessionConfig{};
    session_.server = true;
    session_.over_tcp = true;
    session_.alpn = alpn_;
    session_.alpn_count = names;
    // \~english HTTP/2 over TLS MUST be negotiated (RFC 9113, 3.2): with no HTTP/1.1 to fall back to, no ALPN is refused.
    // \~spanish HTTP/2 sobre TLS DEBE negociarse (RFC 9113, 3.2): sin HTTP/1.1 al que volver, sin ALPN se rechaza.  \~
    session_.require_alpn = cfg.http1 == nullptr;
    session_.certificates = cfg.certificates;
    session_.certificate_lens = cfg.certificate_lens;
    session_.certificate_count = cfg.certificate_count;
    session_.signing_key = cfg.signing_key;
    session_.scheme = cfg.scheme;
    session_.tickets = cfg.tickets;

    if (!plain_.reset(cfg.buffers, cfg.buffer_ceiling)) {
        why_ = "no memory for the plaintext buffers";
        return false;
    }
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    slots_ = static_cast<Slot *>(util::host_alloc(static_cast<size_t>(connections) * sizeof(Slot)));
    if (slots_ == nullptr) {
        plain_.release_all();
        why_ = "no memory for the connections";
        return false;
    }
    capacity_ = connections;
    for (uint32_t i = 0; i < capacity_; ++i) new (&slots_[i]) Slot();
    return true;
}

const tls::Channel *TlsService::channel(ConnHandle c) const noexcept {
    return c.slot < capacity_ ? &slots_[c.slot].channel : nullptr;
}

void TlsService::on_open(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;
    Slot &s = slots_[c.slot];
    // \~english Nothing allocated yet: the handshake takes memory when its first record comes.
    // \~spanish Todavia nada reservado: el saludo toma memoria cuando llega su primer registro.  \~
    s.channel.configure(*cfg_.crypto, session_);
    s.inner = nullptr;
    s.plain_at = 0;
    s.plain = kNoBuffer;
}

void TlsService::on_close(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;
    Slot &s = slots_[c.slot];
    if (s.inner != nullptr) s.inner->on_close(c);
    s.inner = nullptr;
    if (s.plain != kNoBuffer) plain_.release(s.plain);
    s.plain = kNoBuffer;
    // \~english The keys are wiped with the connection (6).  \~spanish Las claves se borran con la conexion (6).  \~
    s.channel.reset();
}

void TlsService::give_back(Slot &s) noexcept {
    Buffer *b = s.plain != kNoBuffer ? plain_.at(s.plain) : nullptr;
    if (b == nullptr || !b->empty()) return;
    // \~english Empty: what the next one lent must carry on from (R1).  \~spanish Vacio: desde donde debe seguir el siguiente que se preste (R1).  \~
    s.plain_at = b->origin();
    plain_.release(s.plain);
    s.plain = kNoBuffer;
}

bool TlsService::route(ConnHandle c, Slot &s) noexcept {
    size_t n = 0;
    const uint8_t *name = s.channel.alpn(n);
    // \~english No ALPN is HTTP/1.1; the session already refused it when HTTP/1.1 is not served.
    // \~spanish Sin ALPN es HTTP/1.1; la sesion ya lo rechazo cuando no se sirve HTTP/1.1.  \~
    if (name == nullptr || is_name(name, n, kHttp11)) {
        s.inner = cfg_.http1;
    } else if (is_name(name, n, kH2)) {
        s.inner = cfg_.http2;
    }
    if (s.inner == nullptr) return false;
    s.inner->on_open(c);
    ++handshakes_;
    // \~english The handshake's memory goes back now; the connection keeps only its keys.
    // \~spanish La memoria del saludo se devuelve ya; la conexion guarda solo sus claves.  \~
    s.channel.release_handshake();
    return true;
}

bool TlsService::finish(ConnHandle, Slot &s, Buffer &out, bool keep) noexcept {
    if (s.channel.failed()) {
        ++failures_;
        last_alert_ = s.channel.alert();
        last_received_ = s.channel.alert_received();
        last_why_ = s.channel.why();
        keep = false;
    } else if (!keep || s.channel.peer_closed()) {
        // \~english Every end sends close_notify before closing its write side (6.1).
        // \~spanish Todo extremo manda close_notify antes de cerrar su lado de escritura (6.1).  \~
        s.channel.close(out);
        keep = false;
    }
    give_back(s);
    return keep;
}

bool TlsService::on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept {
    if (c.slot >= capacity_) return false;
    Slot &s = slots_[c.slot];
    if (s.plain == kNoBuffer) {
        s.plain = plain_.acquire();
        Buffer *fresh = s.plain != kNoBuffer ? plain_.at(s.plain) : nullptr;
        if (fresh == nullptr) {
            // \~english Out of buffers is said, to the peer and in the count (section 12).
            // \~spanish Quedarse sin buffers se dice, al otro y en la cuenta (seccion 12).  \~
            ++starved_;
            s.plain = kNoBuffer;
            s.channel.abort(tls::Alert::InternalError, "out of plaintext buffers", out);
            return false;
        }
        // \~english A recycled buffer starts at zero; the stream does not (R1 against the position).
        // \~spanish Un buffer reciclado empieza en cero; el flujo no (la R1 frente a la posicion).  \~
        fresh->rebase(s.plain_at);
    }
    Buffer &plain = *plain_.at(s.plain);

    s.channel.set_clock(clock_us_);
    const tls::ChannelStatus st = s.channel.receive(in, plain, out);
    if (st == tls::ChannelStatus::Failed) return finish(c, s, out, false);
    if (s.inner == nullptr && s.channel.complete() && !route(c, s)) {
        // \~english Cannot happen with the configuration reset() checked; said if it does.
        // \~spanish No puede pasar con la configuracion que comprobo reset(); se dice si pasa.  \~
        ++failures_;
        last_alert_ = tls::Alert::InternalError;
        last_received_ = false;
        last_why_ = "the protocol ALPN chose has no service";
        give_back(s);
        return false;
    }

    /* \~english
     * Handed over whenever there is plaintext, not only when some came now:
     * what waited behind an open HTTP/1.1 response is already decrypted here,
     * and resuming calls with nothing new (HVX-5, 5.1).
     * \~spanish
     * Se entrega siempre que haya texto en claro, no solo cuando acaba de llegar:
     * lo que espero detras de una respuesta abierta de HTTP/1.1 ya esta
     * descifrado aqui, y reanudar llama sin nada nuevo (HVX-5, 5.1).
     * \~ */
    bool keep = true;
    if (s.inner != nullptr && !plain.empty()) {
        scratch_.clear();
        keep = s.inner->on_bytes(c, plain, scratch_);
        // \~english The answer goes out even when the inner service ends the connection: it is usually why.
        // \~spanish La respuesta sale aunque el servicio de dentro acabe la conexion: suele ser el porque.  \~
        if (!scratch_.empty() && !s.channel.send(scratch_.data(), scratch_.size(), out)) keep = false;
        if (scratch_.capacity() > cfg_.buffer_ceiling) scratch_.release();
    }
    return finish(c, s, out, keep);
}

void TlsService::attach(StreamPort *port) noexcept {
    // \~english The inner services open responses; TLS only seals what they write.
    // \~spanish Los servicios de dentro abren respuestas; TLS solo sella lo que escriben.  \~
    if (cfg_.http1 != nullptr) cfg_.http1->attach(port);
    if (cfg_.http2 != nullptr) cfg_.http2->attach(port);
}

bool TlsService::on_writable(ConnHandle c, Buffer &out, size_t budget) noexcept {
    if (c.slot >= capacity_) return false;
    Slot &s = slots_[c.slot];
    if (s.inner == nullptr) return true;

    /* \~english
     * One record per call into the inner service, written where it will be
     * sealed: the header is kept, the service writes at most 2^14 bytes
     * right behind it, and the record is sealed in place -- no copy of the
     * body (HVX-5, 7.4).  Asked again while it writes and a whole record
     * still fits the budget.
     * \~spanish
     * Un registro por llamada al servicio de dentro, escrito donde se va a
     * sellar: se guarda la cabecera, el servicio escribe como mucho 2^14 bytes
     * justo detras, y el registro se sella en su sitio -- sin copiar el cuerpo
     * (HVX-5, 7.4).  Se le vuelve a pedir mientras escriba y quepa entero otro
     * registro en el presupuesto.
     * \~ */
    const size_t start = out.size();
    bool keep = true;
    while (keep && out.size() - start + tls::kRecordOverhead + tls::kMaxFragment <= budget) {
        if (!s.channel.begin_in_place(out)) return finish(c, s, out, false);

        const size_t record_at = out.size();
        if (out.reserve(tls::kRecordHeader) == nullptr) return finish(c, s, out, false);
        out.commit(tls::kRecordHeader);

        keep = s.inner->on_writable(c, out, tls::kMaxFragment);
        if (out.size() == record_at + tls::kRecordHeader) {
            out.uncommit(tls::kRecordHeader);
            break;
        }
        if (!s.channel.seal_in_place(out, record_at)) return finish(c, s, out, false);
    }
    return finish(c, s, out, keep);
}

} // namespace http_vx
