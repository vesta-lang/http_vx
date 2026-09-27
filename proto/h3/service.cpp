/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service.cpp
 * @brief
 * \~english The HTTP/3 service's connections: starting, routing datagrams, sending, timers, ending.
 * \~spanish Las conexiones del servicio HTTP/3: arrancar, enrutar datagramas, mandar, temporizadores, acabar.
 * \~
 *
 * \~english
 * Requests are in service_requests.cpp, and the tables that keep every step
 * from walking every connection in service_route.cpp.
 * \~spanish
 * Las peticiones estan en service_requests.cpp, y las tablas que evitan que
 * cada paso recorra todas las conexiones en service_route.cpp.
 * \~
 */
#include "service_slot.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <new>

namespace http_vx {

namespace {

/**
 * @brief
 * \~english Where the destination ID is, by the headers every version shares (RFC 9000, 17.2, 17.3).
 * \~spanish Donde esta el identificador de destino, segun las cabeceras que comparten todas las versiones (RFC 9000, 17.2, 17.3).
 * \~
 *
 * \~english
 * Only the destination ID, and nothing else of the packet: a packet that
 * fails any other check still belongs to the connection it names, which is
 * the one that counts it and drops it.  Handing it to the acceptor instead
 * would answer a live connection's packet with a stateless reset.
 * \~spanish
 * Solo el identificador de destino, y nada mas del paquete: un paquete que
 * falla cualquier otra comprobacion sigue siendo de la conexion que nombra, que
 * es la que lo cuenta y lo tira.  Pasarselo al acceptor en su lugar contestaria
 * con un reinicio sin estado al paquete de una conexion viva.
 * \~
 */
bool destination_id(const uint8_t *p, size_t n, size_t short_len, const uint8_t *&cid, size_t &len) noexcept {
    if (n == 0) return false;
    if ((p[0] & 0x80) != 0) {
        // \~english Long: flags, version (4), then the ID's length and the ID.
        // \~spanish Larga: banderas, version (4), y luego la longitud del identificador y el identificador.  \~
        if (n < 6 || n < 6 + static_cast<size_t>(p[5])) return false;
        cid = p + 6;
        len = p[5];
        return true;
    }
    if (n < 1 + short_len) return false;
    cid = p + 1;
    len = short_len;
    return true;
}

/// \~english Whether the ALPN list accepts HTTP/3 (RFC 9114, 3.1).  \~spanish Si la lista ALPN acepta HTTP/3 (RFC 9114, 3.1).  \~
bool accepts_h3(const tls::SessionConfig &t) noexcept {
    for (size_t i = 0; i < t.alpn_count; ++i) {
        const char *a = t.alpn[i];
        if (a != nullptr && a[0] == 'h' && a[1] == '3' && a[2] == '\0') return true;
    }
    return false;
}

template <typename T> void destroy(T *&p) noexcept {
    if (p == nullptr) return;
    p->~T();
    util::host_free(p);
    p = nullptr;
}

} // namespace

Http3Service::Http3Service(quic::Crypto &crypto, Handler &handler) noexcept : crypto_(crypto), handler_(handler) {}

Http3Service::~Http3Service() { release(); }

bool Http3Service::refuse_start(const char *why) noexcept {
    release();
    why_ = why;
    return false;
}

bool Http3Service::start(const Http3Config &cfg) noexcept {
    release();
    cfg_ = cfg;
    why_ = nullptr;
    // \~english Each refusal says which rule; nothing is chosen in silence.  \~spanish Cada rechazo dice que regla; nada se elige en silencio.  \~
    if (cfg.connections == 0) return refuse_start("no room for a single connection");
    if (!cfg.connection.is_server || !cfg.tls.server || !cfg.h3.server)
        return refuse_start("a client's configuration given to a server");
    if (cfg.acceptor.cid_len != cfg.connection.local_cid_len)
        return refuse_start("the acceptor and the connections hand out IDs of different lengths");
    for (size_t i = 0; i < quic::kResetKeySize; ++i)
        if (cfg.acceptor.reset_key[i] != cfg.connection.reset_key[i])
            return refuse_start("the acceptor and the connections answer stateless resets with different keys (RFC 9000, 10.3)");
    if (!accepts_h3(cfg.tls)) return refuse_start("the TLS configuration does not accept \"h3\" (RFC 9114, 3.1)");
    if (cfg.h3.max_requests == 0) return refuse_start("no room for a single request");
    if (cfg.max_open_per_conn > cfg.h3.max_requests)
        return refuse_start("more open responses per connection than requests a connection follows");

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    acceptor_ = static_cast<quic::Acceptor *>(util::host_alloc(sizeof(quic::Acceptor)));
    if (acceptor_ == nullptr) return refuse_start("out of memory for the acceptor");
    new (acceptor_) quic::Acceptor(crypto_, cfg_.acceptor);
    if (!acceptor_->ready()) return refuse_start("the acceptor could not start");

    capacity_ = cfg.connections;
    slots_ = static_cast<Slot *>(util::host_alloc(static_cast<size_t>(capacity_) * sizeof(Slot)));
    send_ = static_cast<uint32_t *>(util::host_alloc(static_cast<size_t>(capacity_) * sizeof(uint32_t)));
    if (slots_ == nullptr || send_ == nullptr || !timers_.reset(capacity_))
        return refuse_start("out of memory for the connections");
    for (uint32_t i = 0; i < capacity_; ++i) {
        new (&slots_[i]) Slot();
        slots_[i].next_free = i + 1 == capacity_ ? kNone : i + 1;
    }
    free_ = 0;
    // \~english A secret of this service's for the route hash: see quic_routes.h.
    // \~spanish Un secreto de este servicio para el hash de rutas: ver quic_routes.h.  \~
    uint8_t key[quic::CidRoutes::kKeySize];
    if (!crypto_.random(key, sizeof key) || !routes_.reset(static_cast<size_t>(capacity_) * kRoutes, key))
        return refuse_start("the route table could not be made");
    return true;
}

void Http3Service::release() noexcept {
    if (slots_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) {
            if (slots_[i].quic != nullptr) free_slot(i);
            slots_[i].~Slot();
        }
        util::host_free(slots_);
        slots_ = nullptr;
    }
    routes_.release();
    timers_.release();
    if (send_ != nullptr) util::host_free(send_);
    send_ = nullptr;
    send_head_ = send_count_ = 0;
    destroy(acceptor_);
    capacity_ = 0;
    free_ = kNone;
    live_ = 0;
    reply_head_ = reply_count_ = 0;
    said_.release();
    names_.release();
}

void Http3Service::on_datagram(const quic::Path &path, uint8_t *data, size_t n, quic::Ecn ecn,
                               uint64_t now_us) noexcept {
    if (acceptor_ == nullptr) return;
    const uint8_t *cid = nullptr;
    size_t len = 0;
    if (destination_id(data, n, cfg_.connection.local_cid_len, cid, len)) {
        const uint32_t i = routes_.find(cid, len);
        if (i != kNone) {
            slots_[i].quic->on_datagram(path, data, n, ecn, now_us);
            touch(i, now_us);
            return;
        }
    }
    // \~english Nobody's: the acceptor decides, keeping nothing (RFC 9000, 5.2.2).
    // \~spanish De nadie: decide el acceptor, sin guardar nada (RFC 9000, 5.2.2).  \~
    uint8_t scratch[sizeof(Reply::bytes)];
    Reply *r = reply_count_ < kReplies ? &replies_[(reply_head_ + reply_count_) % kReplies] : nullptr;
    uint8_t *out = r != nullptr ? r->bytes : scratch;
    const quic::Admission ad =
        acceptor_->on_datagram(data, n, path.peer.bytes, path.peer.len, now_us, out, sizeof(Reply::bytes));
    if (ad.verdict == quic::Admit::Reply) {
        if (r == nullptr) {
            ++counts_.replies_dropped;
            return;
        }
        r->path = path;
        r->len = ad.reply_len;
        ++reply_count_;
        ++counts_.replies;
    } else if (ad.verdict == quic::Admit::Accept) {
        accept(ad, path, data, n, ecn, now_us);
    }
}

Http3Service::Slot *Http3Service::accept(const quic::Admission &ad, const quic::Path &path, uint8_t *data,
                                         size_t n, quic::Ecn ecn, uint64_t now_us) noexcept {
    // \~english Full: the client retries its Initial, and one may be free by then.
    // \~spanish Lleno: el cliente repite su Initial, y para entonces puede haber una libre.  \~
    if (free_ == kNone) {
        ++counts_.full;
        return nullptr;
    }
    const uint32_t i = free_;
    Slot &s = slots_[i];
    free_ = s.next_free;
    s.next_free = kNone;
    ++live_;
    ++counts_.accepted;

    quic::ConnectionConfig cc = cfg_.connection;
    for (size_t b = 0; b < ad.scid_len; ++b) cc.peer_cid[b] = ad.scid[b];
    cc.peer_cid_len = ad.scid_len;
    cc.version = ad.version;
    cc.path = path;
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed, util::AllocFill::Sparse);
    s.quic = static_cast<quic::Connection *>(util::host_alloc(sizeof(quic::Connection)));
    s.tls = static_cast<tls::QuicHandshake *>(util::host_alloc(sizeof(tls::QuicHandshake)));
    s.h3 = static_cast<h3::Connection *>(util::host_alloc(sizeof(h3::Connection)));
    s.works = static_cast<Work *>(util::host_alloc(cfg_.h3.max_requests * sizeof(Work)));
    // \~english A random ID of this server's: nothing about the client in it (RFC 9000, 5.1).
    // \~spanish Un identificador aleatorio de este servidor: nada del cliente en el (RFC 9000, 5.1).  \~
    if (s.quic == nullptr || s.tls == nullptr || s.h3 == nullptr || s.works == nullptr ||
        !crypto_.random(cc.local_cid, cc.local_cid_len)) {
        if (s.quic != nullptr) util::host_free(s.quic);
        if (s.tls != nullptr) util::host_free(s.tls);
        if (s.h3 != nullptr) util::host_free(s.h3);
        if (s.works != nullptr) util::host_free(s.works);
        s.quic = nullptr;
        s.tls = nullptr;
        s.h3 = nullptr;
        s.works = nullptr;
        s.next_free = free_;
        free_ = i;
        --live_;
        return nullptr;
    }
    for (size_t k = 0; k < cfg_.h3.max_requests; ++k) new (&s.works[k]) Work();
    new (s.quic) quic::Connection(crypto_, cc);
    quic::Connection &q = *s.quic;
    bool ok = q.ready() && q.set_initial_keys(ad.dcid, ad.dcid_len);
    if (ok && ad.address_validated) q.set_address_validated(now_us);
    // \~english After a Retry the destination is the Retry's ID and the first one is the original (RFC 9000, 7.3).
    // \~spanish Tras un Retry el destino es el identificador del Retry y el primero es el original (RFC 9000, 7.3).  \~
    bool retried = ad.odcid_len != ad.dcid_len;
    for (size_t b = 0; b < ad.dcid_len && !retried; ++b) retried = ad.odcid[b] != ad.dcid[b];
    ok = ok && q.set_original_ids(ad.odcid, ad.odcid_len, retried ? ad.dcid : nullptr, retried ? ad.dcid_len : 0);
    new (s.tls) tls::QuicHandshake(crypto_, q, cfg_.tls);
    new (s.h3) h3::Connection(q);
    ok = ok && s.tls->start(now_us) && s.h3->start(cfg_.h3);
    for (size_t b = 0; b < ad.dcid_len; ++b) s.first.bytes[b] = ad.dcid[b];
    s.first.len = static_cast<uint8_t>(ad.dcid_len);
    if (!ok) {
        free_slot(i);
        return nullptr;
    }
    q.on_datagram(path, data, n, ecn, now_us);
    touch(i, now_us);
    return &s;
}

void Http3Service::touch(uint32_t i, uint64_t now_us) noexcept {
    Slot &s = slots_[i];
    /* \~english
     * What the datagram did to open responses is looked at BEFORE HTTP/3
     * runs: a stream the peer stopped may be gone from QUIC, and HTTP/3 would
     * give its message's place to the next request.  After, too: HTTP/3
     * failing closes the connection.  A connection with none open pays one
     * comparison (R39).
     * \~spanish
     * Lo que el datagrama le hizo a las respuestas abiertas se mira ANTES de que
     * corra HTTP/3: un flujo que el otro paro puede haberse ido de QUIC, y HTTP/3
     * daria el sitio de su mensaje a la peticion siguiente.  Despues tambien: que
     * falle HTTP/3 cierra la conexion.  Una conexion sin ninguna abierta paga una
     * comparacion (R39).
     * \~ */
    if (s.open_head != kNone) watch_open(s);
    pump(s, now_us);
    if (s.open_head != kNone) watch_open(s);
    // \~english Gone for good: its IDs, its timer and its memory go with it.
    // \~spanish Terminada del todo: sus identificadores, su temporizador y su memoria se van con ella.  \~
    if (s.quic->state() == quic::ConnState::Closed) {
        free_slot(i);
        return;
    }
    sync_routes(i, now_us);
    timers_.set(i, s.quic->timer());
    queue_send(i);
}

size_t Http3Service::next_datagram(quic::Path &path, uint8_t *out, size_t room, uint64_t now_us) noexcept {
    if (reply_count_ != 0) {
        const Reply &r = replies_[reply_head_];
        if (room < r.len) return 0;
        util::vesta_memcpy(out, r.bytes, r.len);
        path = r.path;
        reply_head_ = (reply_head_ + 1) % kReplies;
        --reply_count_;
        return r.len;
    }
    while (send_count_ != 0) {
        const uint32_t i = send_[send_head_];
        send_head_ = (send_head_ + 1) % capacity_;
        --send_count_;
        Slot &s = slots_[i];
        if (s.quic != nullptr) {
            /* \~english
             * Open responses are filled here, right before the datagram that
             * carries them is built: the loop drained its kicks before
             * pulling, and room freed by acknowledgements or a raised limit is
             * seen now (HVX-5, 4.3).
             * \~spanish
             * Las respuestas abiertas se rellenan aqui, justo antes de construir
             * el datagrama que las lleva: el bucle vacio sus avisos antes de
             * tirar, y el sitio liberado por confirmaciones o un limite subido se
             * ve ahora (HVX-5, 4.3).
             * \~ */
            if (s.open_head != kNone) feed_open(s);
            const size_t n = s.quic->build_datagram(path, out, room, now_us);
            if (n != 0) {
                // \~english To the back of the queue: one connection with much to say does not starve the rest.
                // \~spanish Al final de la cola: una conexion con mucho que decir no deja sin turno a las demas.  \~
                send_[(send_head_ + send_count_) % capacity_] = i;
                ++send_count_;
                timers_.set(i, s.quic->timer());
                return n;
            }
        }
        s.queued = false;
    }
    return 0;
}

static_assert(DeadlineHeap::kNever == quic::kNever, "a connection's 'no timer' must mean no deadline");

uint64_t Http3Service::timer() const noexcept { return timers_.next(); }

void Http3Service::on_timer(uint64_t now_us) noexcept {
    // \~english Each connection at most once per call: one whose timer does not move cannot hold the loop.
    // \~spanish Cada conexion como mucho una vez por llamada: una cuyo temporizador no se mueva no puede retener el bucle.  \~
    size_t budget = live_;
    while (budget != 0 && timers_.next() <= now_us) {
        --budget;
        const uint32_t i = timers_.top();
        slots_[i].quic->on_timer(now_us);
        touch(i, now_us);
    }
}

void Http3Service::free_slot(uint32_t i) noexcept {
    Slot &s = slots_[i];
    // \~english Why it ended, read before the layers go: counted, and kept for whoever asks.
    // \~spanish Por que acabo, leido antes de que se vayan las capas: contado, y guardado para quien pregunte.  \~
    if (s.quic != nullptr) {
        last_end_.reason = s.quic->end_reason();
        last_end_.code = s.quic->close_code();
        last_end_.application = s.quic->close_is_application();
        last_end_.why = nullptr;
        if (s.h3 != nullptr && s.h3->failed())
            last_end_.why = s.h3->failure().why;
        else if (s.tls != nullptr)
            last_end_.why = s.tls->why();
        ++counts_.ended[static_cast<size_t>(last_end_.reason)];
    }
    // \~english What is still open goes with the connection, each source told why.
    // \~spanish Lo que siga abierto se va con la conexion, y a cada fuente se le dice por que.  \~
    if (s.open_head != kNone) {
        const bool idle = s.quic != nullptr && s.quic->end_reason() == quic::EndReason::IdleTimeout;
        end_all_open(s, idle ? GoneReason::IdleTimeout : GoneReason::ConnectionClosed);
    }
    if (s.opens != nullptr) {
        for (size_t k = 0; k < cfg_.h3.max_requests; ++k) s.opens[k].~OpenStream();
        util::host_free(s.opens);
        s.opens = nullptr;
    }
    ++s.life;
    for (size_t r = 0; r < s.route_count; ++r) routes_.remove(s.routes[r].bytes, s.routes[r].len);
    s.route_count = 0;
    s.first.len = 0;
    timers_.remove(i);
    if (s.works != nullptr) {
        for (size_t k = 0; k < cfg_.h3.max_requests; ++k) s.works[k].~Work();
        util::host_free(s.works);
        s.works = nullptr;
    }
    // \~english The reverse of building: HTTP/3 and the handshake hold the transport.
    // \~spanish Al reves que al construir: HTTP/3 y el saludo sujetan el transporte.  \~
    destroy(s.h3);
    destroy(s.tls);
    destroy(s.quic);
    s.failure_counted = false;
    s.early_counted = false;
    // \~english Left in the send queue if it is there: the entry is skipped, or serves whoever takes the slot next.
    // \~spanish Se queda en la cola de envio si esta: la entrada se salta, o sirve a quien coja la casilla despues.  \~
    s.next_free = free_;
    free_ = i;
    --live_;
    ++counts_.closed;
}

} // namespace http_vx
