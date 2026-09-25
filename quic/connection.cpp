/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/connection.cpp
 * @brief
 * \~english A QUIC connection: unprotecting, dispatching, composing and protecting.
 * \~spanish Una conexion QUIC: desproteger, repartir, componer y proteger.
 * \~
 */

#include "http_vx/quic_connection.h"

#include "http_vx/quic_varint.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

#include <new>

namespace http_vx {
namespace quic {

namespace {

/// \~english What a packet record says was carried.  \~spanish Lo que un registro de paquete dice que se llevaba.  \~
enum : uint8_t {
    kRecStream = 1,
    kRecCrypto,
    kRecResetStream,
    kRecMaxData,
    kRecMaxStreams,
    kRecMaxStreamData,
    kRecHandshakeDone,
};

/// \~english The smallest datagram that may carry an Initial (14.1).
/// \~spanish El datagrama mas pequeno que puede llevar un Initial (14.1).  \~
constexpr size_t kMinInitial = kMinInitialDatagram;

inline uint64_t min64(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }
inline uint64_t max64(uint64_t a, uint64_t b) noexcept { return a > b ? a : b; }

inline size_t idx(Space s) noexcept { return static_cast<size_t>(s); }

AckPolicy handshake_policy(const AckPolicy &base) noexcept {
    AckPolicy p = base;
    p.immediate = true;
    return p;
}

RecoveryConfig recovery_config(const ConnectionConfig &c) noexcept {
    RecoveryConfig r = c.recovery;
    r.is_server = c.is_server;
    r.max_datagram_size = static_cast<uint32_t>(c.max_datagram);
    return r;
}

StreamConfig stream_config(const ConnectionConfig &c) noexcept {
    StreamConfig s = c.streams;
    s.is_server = c.is_server;
    return s;
}

/// \~english The long-header type bits of a space, by version (RFC 9369 renumbers them).
/// \~spanish Los bits de tipo de cabecera larga de un espacio, segun la version (el RFC 9369 los renumera).  \~
uint8_t long_type_bits(Space s, uint32_t version) noexcept {
    const bool v2 = version == kVersion2;
    if (s == Space::Initial) return v2 ? 1 : 0;
    return v2 ? 3 : 2;
}

/// \~english Whether @p n bytes are equal.  \~spanish Si @p n bytes son iguales.  \~
bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t n) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

/// \~english A receiving part on our allocator.  \~spanish Una parte receptora en nuestro asignador.  \~
RecvStream *make_recv(uint64_t window) noexcept {
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    void *mem = util::host_alloc(sizeof(RecvStream));
    return mem == nullptr ? nullptr : new (mem) RecvStream(window);
}

/// \~english A sending part on our allocator.  \~spanish Una parte emisora en nuestro asignador.  \~
SendStream *make_send(uint64_t capacity, uint64_t limit) noexcept {
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    void *mem = util::host_alloc(sizeof(SendStream));
    return mem == nullptr ? nullptr : new (mem) SendStream(capacity, limit);
}

template <typename T>
void drop_from_heap(T *p) noexcept {
    if (p == nullptr) return;
    p->~T();
    util::host_free(p);
}

} // namespace

Connection::Connection(Crypto &crypto, const ConnectionConfig &config) noexcept
    : crypto_(crypto),
      cfg_(config),
      acks_{AckTracker(handshake_policy(config.ack)), AckTracker(handshake_policy(config.ack)),
            AckTracker(config.ack)},
      recovery_(recovery_config(config)),
      streams_(stream_config(config)),
      recv_flow_(config.data_window),
      send_flow_(config.peer_max_data) {
    for (size_t s = 0; s < kSpaces; ++s) {
        // \~english CRYPTO is not flow controlled by MAX_DATA; its bound is the buffer.
        // \~spanish CRYPTO no lo controla MAX_DATA; su limite es el buffer.  \~
        crypto_recv_[s] = make_recv(cfg_.crypto_window);
        crypto_send_[s] = make_send(cfg_.crypto_window, kMaxOffset);
    }

    // \~english One record per packet the recovery rings can remember.
    // \~spanish Un registro por cada paquete que pueden recordar los anillos de la recuperacion.  \~
    record_cap_ = static_cast<size_t>(cfg_.recovery.capacity[0]) + cfg_.recovery.capacity[1] +
                  cfg_.recovery.capacity[2];
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);
    records_ = static_cast<PacketRecord *>(util::host_alloc(record_cap_ * sizeof(PacketRecord)));
    if (records_ != nullptr)
        for (size_t i = 0; i < record_cap_; ++i) records_[i].tag = 0;

    if (!cfg_.is_server) validated_ = true;
}

Connection::~Connection() {
    for (Keys &k : keys_) {
        if (k.have) {
            forget_keys(crypto_, k.read);
            forget_keys(crypto_, k.write);
        }
    }
    for (size_t s = 0; s < kSpaces; ++s) {
        drop_from_heap(crypto_recv_[s]);
        drop_from_heap(crypto_send_[s]);
    }
    if (records_ != nullptr) util::host_free(records_);
    if (pending_ != nullptr) util::host_free(pending_);
}

bool Connection::ready() const noexcept {
    for (size_t s = 0; s < kSpaces; ++s)
        if (crypto_recv_[s] == nullptr || crypto_send_[s] == nullptr) return false;
    return records_ != nullptr && recovery_.ready() && streams_.ready();
}

bool Connection::set_initial_keys(const uint8_t *odcid, size_t len) noexcept {
    if (len > kMaxConnectionId) return false;
    util::vesta_memcpy(odcid_, odcid, len);
    odcid_len_ = len;
    Keys &k = keys_[idx(Space::Initial)];
    k.have = make_initial_keys(crypto_, cfg_.version, odcid, len, cfg_.is_server, k.read, k.write);
    return k.have;
}

bool Connection::install_keys(Space s, KeyMaterial &read, KeyMaterial &write,
                              uint64_t now_us) noexcept {
    Keys &k = keys_[idx(s)];
    if (k.have) return false;
    if (!prepare_keys(crypto_, read, k.read)) return false;
    if (!prepare_keys(crypto_, write, k.write)) {
        forget_keys(crypto_, k.read);
        return false;
    }
    k.have = true;
    if (s == Space::Handshake) recovery_.set_has_handshake_keys(now_us);

    // \~english Whatever arrived before these keys can be opened now.
    // \~spanish Lo que llego antes que estas claves ya se puede abrir.  \~
    replay(s, now_us);
    return true;
}

void Connection::discard_keys(Space s, uint64_t now_us) noexcept {
    Keys &k = keys_[idx(s)];
    if (!k.have) return;
    forget_keys(crypto_, k.read);
    forget_keys(crypto_, k.write);
    k.have = false;
    discarded_[idx(s)] = true;
    recovery_.discard_space(s, now_us);

    // \~english Packets kept for this space will never be opened.
    // \~spanish Los paquetes guardados para este espacio no se abriran nunca.  \~
    if (pending_ != nullptr)
        for (size_t i = 0; i < kPendingPackets; ++i)
            if (pending_[i].used && pending_[i].space == static_cast<uint8_t>(s)) {
                pending_[i].used = false;
                ++drops_.no_keys;
            }
}

void Connection::handshake_confirmed(uint64_t now_us) noexcept {
    if (confirmed_) return;
    confirmed_ = true;
    recovery_.set_handshake_confirmed(now_us);
    if (cfg_.is_server) handshake_done_owed_ = true;

    // \~english Handshake keys MUST go once the handshake is confirmed (RFC 9001, 4.9.2).
    // \~spanish Las claves de Handshake DEBEN irse en cuanto se confirma el saludo (RFC 9001, 4.9.2).  \~
    discard_keys(Space::Handshake, now_us);

    // \~english 1-RTT packets held back until now can be opened (RFC 9001, 5.7).
    // \~spanish Los paquetes 1-RTT retenidos hasta ahora ya se pueden abrir (RFC 9001, 5.7).  \~
    replay(Space::Application, now_us);
}

void Connection::consume(Stream &s, size_t n) noexcept {
    if (s.recv == nullptr) return;
    s.recv->consume(n);
    recv_flow_.on_consumed(n);
}

void Connection::consume_crypto(Space s, size_t n) noexcept {
    RecvStream *r = crypto_recv_[idx(s)];
    r->consume(n);
    r->advertise();
}

uint64_t Connection::pto_duration() const noexcept {
    return recovery_.smoothed_rtt() + max64(4 * recovery_.rttvar(), kGranularityUs) +
           cfg_.recovery.max_ack_delay_us;
}

bool Connection::can_open(Space s) const noexcept {
    if (!keys_[idx(s)].have) return false;

    // \~english A server MUST NOT open 1-RTT packets before the handshake completes (RFC 9001, 5.7).
    // \~spanish Un servidor NO DEBE abrir paquetes 1-RTT antes de que acabe el saludo (RFC 9001, 5.7).  \~
    return !(cfg_.is_server && s == Space::Application && !confirmed_);
}

bool Connection::keep_for_later(const uint8_t *p, size_t n, Space s, Ecn ecn) noexcept {
    if (n > sizeof(Pending::bytes)) return false;
    if (pending_ == nullptr) {
        const util::AllocScope scope(util::AllocUse::Instant, util::AllocShape::Fixed,
                                     util::AllocFill::Sparse);
        pending_ = static_cast<Pending *>(util::host_alloc(kPendingPackets * sizeof(Pending)));
        if (pending_ == nullptr) return false;
        for (size_t i = 0; i < kPendingPackets; ++i) pending_[i].used = false;
    }
    for (size_t i = 0; i < kPendingPackets; ++i) {
        Pending &q = pending_[i];
        if (q.used) continue;
        util::vesta_memcpy(q.bytes, p, n);
        q.len = static_cast<uint16_t>(n);
        q.space = static_cast<uint8_t>(s);
        q.ecn = ecn;
        q.used = true;
        return true;
    }
    return false;
}

void Connection::replay(Space s, uint64_t now_us) noexcept {
    if (pending_ == nullptr || !can_open(s)) return;

    HeaderContext ctx;
    ctx.short_dcid_len = cfg_.local_cid_len;
    for (size_t i = 0; i < kPendingPackets; ++i) {
        Pending &q = pending_[i];
        if (!q.used || q.space != static_cast<uint8_t>(s)) continue;

        // \~english Freed first: processing it may keep another one in its place.
        // \~spanish Se libera antes: procesarlo puede guardar otro en su sitio.  \~
        q.used = false;
        PacketHeader h;
        if (parse_packet(q.bytes, q.len, ctx, h) != HeaderError::None) continue;
        ++drops_.buffered;
        process_packet(q.bytes, h, q.ecn, now_us);
    }
}

void Connection::restart_idle(uint64_t now_us) noexcept {
    // \~english Never shorter than three PTOs, or a slow path would time out mid-recovery (10.1).
    // \~spanish Nunca menos de tres PTO, o un camino lento caducaria en plena recuperacion (10.1).  \~
    idle_deadline_ = now_us + max64(cfg_.idle_timeout_us, 3 * pto_duration());
}

size_t Connection::amplification_budget() const noexcept {
    // \~english 8.1: until the client's address is proven, three times what came from it.
    // \~spanish 8.1: hasta probar la direccion del cliente, tres veces lo que llego de el.  \~
    if (validated_) return static_cast<size_t>(-1);
    const uint64_t allowed = 3 * bytes_in_;
    return allowed > bytes_out_ ? static_cast<size_t>(allowed - bytes_out_) : 0;
}

void Connection::close(uint64_t code, bool application, uint64_t trigger_frame,
                       uint64_t now_us) noexcept {
    if (state_ != ConnState::Active) return;
    state_ = ConnState::Closing;
    close_code_ = code;
    close_app_ = application;
    close_frame_ = trigger_frame;
    close_owed_ = true;
    close_deadline_ = now_us + 3 * pto_duration();
}

void Connection::fail(TransportError e, uint64_t frame_type, uint64_t now_us) noexcept {
    close(static_cast<uint64_t>(e), false, frame_type, now_us);
}

void Connection::add_record(PacketRecord &rec, uint8_t kind, uint64_t id, uint64_t offset,
                            size_t len, bool fin) noexcept {
    FrameRecord &f = rec.frames[rec.count++];
    f.kind = kind;
    f.id = id;
    f.offset = offset;
    f.len = static_cast<uint16_t>(len);
    f.fin = fin;
}

Connection::PacketRecord *Connection::record_for(uint64_t tag) noexcept {
    if (records_ == nullptr || tag == 0) return nullptr;
    PacketRecord *r = &records_[tag % record_cap_];
    return r->tag == tag ? r : nullptr;
}

void Connection::on_acked(Space space, const SentPacket &p) noexcept {
    // \~english The peer saw the ACK this packet carried: stop repeating what it covered (13.2.4).
    // \~spanish El otro extremo vio el ACK que llevaba este paquete: dejar de repetir lo que cubria (13.2.4).  \~
    if (p.ack_largest != kNever) acks_[idx(space)].on_ack_acknowledged(p.ack_largest);

    PacketRecord *rec = record_for(p.tag);
    if (rec == nullptr) return;
    for (uint8_t i = 0; i < rec->count; ++i) {
        const FrameRecord &f = rec->frames[i];
        Stream *st = (f.kind == kRecStream || f.kind == kRecResetStream) ? streams_.find(f.id) : nullptr;
        switch (f.kind) {
        case kRecStream:
            if (st != nullptr && st->send != nullptr) st->send->on_acked(f.offset, f.len, f.fin);
            break;
        case kRecCrypto:
            crypto_send_[idx(space)]->on_acked(f.offset, f.len, false);
            break;
        case kRecResetStream:
            if (st != nullptr && st->send != nullptr) st->send->on_reset_acked();
            break;
        default:
            break;
        }
    }
    rec->tag = 0;
}

void Connection::on_lost(Space space, const SentPacket &p) noexcept {
    PacketRecord *rec = record_for(p.tag);
    if (rec == nullptr) return;

    /* \~english
     * What was lost is sent again -- but control frames as their CURRENT
     * value, not the one lost: a MAX_DATA that was overtaken by a larger one
     * would only take the limit back.
     * \~spanish
     * Lo perdido se manda otra vez -- pero las tramas de control con su valor
     * ACTUAL, no con el que se perdio: un MAX_DATA al que ya adelanto otro mayor
     * solo haria retroceder el limite.
     * \~ */
    for (uint8_t i = 0; i < rec->count; ++i) {
        const FrameRecord &f = rec->frames[i];
        Stream *st = nullptr;
        if (f.kind == kRecStream || f.kind == kRecResetStream || f.kind == kRecMaxStreamData)
            st = streams_.find(f.id);
        switch (f.kind) {
        case kRecStream:
            if (st != nullptr && st->send != nullptr) st->send->on_lost(f.offset, f.len, f.fin);
            break;
        case kRecCrypto:
            crypto_send_[idx(space)]->on_lost(f.offset, f.len, false);
            break;
        case kRecResetStream:
            if (st != nullptr && st->send != nullptr) st->send->on_reset_lost();
            break;
        case kRecMaxData:
            max_data_owed_ = true;
            break;
        case kRecMaxStreams:
            max_streams_owed_[f.id != 0 ? 1 : 0] = true;
            break;
        case kRecMaxStreamData:
            if (st != nullptr) st->max_stream_data_owed = true;
            break;
        case kRecHandshakeDone:
            handshake_done_owed_ = true;
            break;
        default:
            break;
        }
    }
    rec->tag = 0;
}

void Connection::on_datagram(uint8_t *data, size_t n, Ecn ecn, uint64_t now_us) noexcept {
    if (state_ == ConnState::Closed) return;

    // \~english Every byte counts toward what a server may send back, processed or not (8.1).
    // \~spanish Cada byte cuenta para lo que un servidor puede devolver, se procese o no (8.1).  \~
    bytes_in_ += n;
    if (state_ == ConnState::Draining) {
        ++drops_.after_close;
        return;
    }

    HeaderContext ctx;
    ctx.short_dcid_len = cfg_.local_cid_len;

    size_t pos = 0;
    while (pos < n && state_ != ConnState::Closed && state_ != ConnState::Draining) {
        PacketHeader h;
        if (parse_packet(data + pos, n - pos, ctx, h) != HeaderError::None) {
            // \~english Without a header there is no way to find the next packet: the rest goes too.
            // \~spanish Sin cabecera no hay forma de encontrar el paquete siguiente: se va tambien el resto.  \~
            ++drops_.bad_header;
            break;
        }
        process_packet(data + pos, h, ecn, now_us);
        pos += h.size;
    }

    if (!validated_) recovery_.set_amplification_blocked(amplification_budget() == 0, now_us);
    streams_.collect();
}

bool Connection::process_packet(uint8_t *p, const PacketHeader &h, Ecn ecn,
                                uint64_t now_us) noexcept {
    Space s;
    switch (h.type) {
    case PacketType::Initial:   s = Space::Initial; break;
    case PacketType::Handshake: s = Space::Handshake; break;
    case PacketType::OneRtt:    s = Space::Application; break;
    default:
        // \~english 0-RTT, Retry and Version Negotiation come in later steps.
        // \~spanish 0-RTT, Retry y Version Negotiation llegan en pasos posteriores.  \~
        ++drops_.unsupported;
        return false;
    }

    // \~english Addressed to this connection: our ID, or the original one on a client's Initial.
    // \~spanish Dirigido a esta conexion: nuestro identificador, o el original en un Initial del cliente.  \~
    const uint8_t *dcid = p + h.dcid.off;
    const bool ours = h.dcid.len == cfg_.local_cid_len &&
                      bytes_equal(dcid, cfg_.local_cid, h.dcid.len);
    const bool original = cfg_.is_server && s == Space::Initial && h.dcid.len == odcid_len_ &&
                          bytes_equal(dcid, odcid_, odcid_len_);
    if (!ours && !original) {
        ++drops_.wrong_cid;
        return false;
    }

    Keys &k = keys_[idx(s)];
    if (!can_open(s)) {
        // \~english Keys still to come: keep it (few, bounded).  Keys gone: it is late.
        // \~spanish Claves aun por llegar: se guarda (pocos, acotado).  Claves ya tiradas: llega tarde.  \~
        if (discarded_[idx(s)] || !keep_for_later(p, h.size, s, ecn)) ++drops_.no_keys;
        return false;
    }

    // \~english Closing: every packet gets the CONNECTION_CLOSE again, and nothing else (10.2.1).
    // \~spanish Cerrando: cada paquete recibe otra vez el CONNECTION_CLOSE, y nada mas (10.2.1).  \~
    if (state_ == ConnState::Closing) {
        close_owed_ = true;
        ++drops_.after_close;
        return false;
    }

    Unprotected u;
    const Unprotect r = unprotect_packet(crypto_, k.read, p, h, acks_[idx(s)].expected_pn(), u);
    if (r == Unprotect::Forged) {
        ++drops_.forged;
        return false;
    }
    if (r == Unprotect::Failed) {
        fail(TransportError::InternalError, 0, now_us);
        return false;
    }
    if (r == Unprotect::ReservedBitsSet) {
        fail(TransportError::ProtocolViolation, 0, now_us);
        return false;
    }
    if (acks_[idx(s)].classify(u.pn) != Receipt::New) {
        ++drops_.duplicate;
        return false;
    }

    // \~english The peer's real ID comes with its first long header.
    // \~spanish El identificador de verdad del otro extremo llega con su primera cabecera larga.  \~
    if (!peer_cid_known_ && s != Space::Application && h.scid.len <= kMaxConnectionId) {
        util::vesta_memcpy(cfg_.peer_cid, p + h.scid.off, h.scid.len);
        cfg_.peer_cid_len = h.scid.len;
        peer_cid_known_ = true;
    }

    bool eliciting = false;
    if (!process_frames(s, p + u.payload.off, u.payload.len, h.type, eliciting, now_us))
        return false;

    acks_[idx(s)].on_received(u.pn, eliciting, ecn, now_us);
    restart_idle(now_us);
    sent_eliciting_since_receipt_ = false;

    /* \~english
     * A Handshake packet proves the client's address: only an end that saw
     * the server's Initial could have sealed it (8.1).  And the server stops
     * using Initial keys once it has one (RFC 9001, 4.9.1).
     * \~spanish
     * Un paquete Handshake prueba la direccion del cliente: solo pudo sellarlo un
     * extremo que vio el Initial del servidor (8.1).  Y el servidor deja de usar
     * las claves Initial en cuanto tiene uno (RFC 9001, 4.9.1).
     * \~ */
    if (cfg_.is_server && s == Space::Handshake) {
        if (!validated_) {
            validated_ = true;
            recovery_.set_amplification_blocked(false, now_us);
        }
        discard_keys(Space::Initial, now_us);
    }
    return true;
}

bool Connection::process_frames(Space s, const uint8_t *payload, size_t n, PacketType type,
                                bool &eliciting, uint64_t now_us) noexcept {
    FrameContext ctx;
    ctx.packet = type;
    ctx.is_server = cfg_.is_server;
    FrameReader reader(payload, n, ctx);
    Frame f;

    for (;;) {
        const FrameReader::Step step = reader.next(f);
        if (step == FrameReader::Step::End) return true;
        if (step == FrameReader::Step::Error) {
            fail(transport_error_of(reader.error()), reader.error_frame_type(), now_us);
            return false;
        }

        if (f.type != FrameType::Ack && f.type != FrameType::Padding &&
            f.type != FrameType::ConnectionClose)
            eliciting = true;

        switch (f.type) {
        case FrameType::Padding:
        case FrameType::Ping:
        case FrameType::DataBlocked:
        case FrameType::StreamsBlocked:
        case FrameType::NewToken:
        case FrameType::NewConnectionId:
        case FrameType::PathResponse:
            break;

        case FrameType::Ack:
            if (recovery_.on_ack_received(s, f, payload, now_us, *this) != AckResult::Ok) {
                fail(TransportError::ProtocolViolation, f.wire_type, now_us);
                return false;
            }
            // \~english A client's address is proven once a Handshake packet is acknowledged.
            // \~spanish La direccion de un cliente queda probada al confirmarse un paquete Handshake.  \~
            if (!cfg_.is_server && s == Space::Handshake) recovery_.set_peer_address_validated(now_us);
            break;

        case FrameType::Crypto: {
            uint64_t fresh = 0;
            const StreamError e = crypto_recv_[idx(s)]->on_data(
                f.offset, payload + f.data.off, f.data.len, false, fresh);
            if (e == StreamError::FlowControl) {
                fail(TransportError::CryptoBufferExceeded, f.wire_type, now_us);
                return false;
            }
            if (e != StreamError::None) {
                fail(transport_error_of(e), f.wire_type, now_us);
                return false;
            }
            break;
        }

        case FrameType::Stream:
        case FrameType::ResetStream:
        case FrameType::StreamDataBlocked:
        case FrameType::MaxStreamData:
        case FrameType::StopSending: {
            Stream *st = nullptr;
            TransportError te;
            const StreamLookup look = streams_.on_peer_frame(f.stream_id, f.type, st, te);
            if (look == StreamLookup::Error) {
                fail(te, f.wire_type, now_us);
                return false;
            }
            if (look == StreamLookup::Closed) break;

            uint64_t fresh = 0;
            uint64_t released = 0;
            StreamError e = StreamError::None;
            if (f.type == FrameType::Stream) {
                e = st->recv->on_data(f.offset, payload + f.data.off, f.data.len, f.fin, fresh);
            } else if (f.type == FrameType::ResetStream) {
                e = st->recv->on_reset(f.final_size, f.error_code, fresh, released);
            } else if (f.type == FrameType::MaxStreamData) {
                st->send->on_max_stream_data(f.maximum);
            } else if (f.type == FrameType::StopSending) {
                st->send->on_stop_sending(f.error_code);
            }
            if (e != StreamError::None) {
                fail(transport_error_of(e), f.wire_type, now_us);
                return false;
            }

            // \~english The connection's window pays for new offsets and gets back what a reset released.
            // \~spanish La ventana de la conexion paga los desplazamientos nuevos y recupera lo que libero un reinicio.  \~
            if (!recv_flow_.on_received(fresh)) {
                fail(TransportError::FlowControlError, f.wire_type, now_us);
                return false;
            }
            recv_flow_.on_consumed(released);
            break;
        }

        case FrameType::MaxData:
            send_flow_.on_max_data(f.maximum);
            data_blocked_sent_ = false;
            break;

        case FrameType::MaxStreams:
            streams_.on_max_streams(f.bidirectional, f.maximum);
            break;

        case FrameType::RetireConnectionId:
            // \~english Only sequence 0 was ever issued here: retiring more is a violation (19.16).
            // \~spanish Aqui solo se emitio la secuencia 0: retirar mas es una violacion (19.16).  \~
            if (f.sequence > 0) {
                fail(TransportError::ProtocolViolation, f.wire_type, now_us);
                return false;
            }
            break;

        case FrameType::PathChallenge:
            // \~english MUST be answered with the same data (19.17); the latest wins.
            // \~spanish DEBE contestarse con los mismos datos (19.17); gana el ultimo.  \~
            util::vesta_memcpy(path_response_, payload + f.data.off, kPathDataSize);
            path_response_owed_ = true;
            break;

        case FrameType::ConnectionClose:
            // \~english The peer closed: drain, send nothing (10.2.2).
            // \~spanish El otro extremo cerro: drenar, no mandar nada (10.2.2).  \~
            closed_by_peer_ = true;
            close_code_ = f.error_code;
            close_app_ = f.application;
            close_frame_ = f.trigger_type;
            state_ = ConnState::Draining;
            close_deadline_ = now_us + 3 * pto_duration();
            return false;

        case FrameType::HandshakeDone:
            // \~english The server says the handshake is confirmed (RFC 9001, 4.1.2).
            // \~spanish El servidor dice que el saludo esta confirmado (RFC 9001, 4.1.2).  \~
            if (!confirmed_) {
                confirmed_ = true;
                recovery_.set_handshake_confirmed(now_us);
                recovery_.set_peer_address_validated(now_us);
                discard_keys(Space::Handshake, now_us);
            }
            break;
        }
    }
}

size_t Connection::write_frames(Space s, uint8_t *p, size_t room, PacketRecord &rec,
                                bool &eliciting, uint64_t &ack_largest,
                                uint64_t now_us) noexcept {
    size_t used = 0;
    AckTracker &acks = acks_[idx(s)];

    // \~english Closing: the CONNECTION_CLOSE and nothing else.
    // \~spanish Cerrando: el CONNECTION_CLOSE y nada mas.  \~
    if (state_ == ConnState::Closing) {
        /* \~english
         * An application close may only travel in 1-RTT; in an earlier space it
         * becomes a transport close with APPLICATION_ERROR (19.19).
         * \~spanish
         * Un cierre de aplicacion solo puede ir en 1-RTT; en un espacio anterior
         * pasa a ser un cierre de transporte con APPLICATION_ERROR (19.19).
         * \~ */
        const bool app = close_app_ && s == Space::Application;
        const uint64_t code = close_app_ && !app ? static_cast<uint64_t>(TransportError::ApplicationError)
                                                 : close_code_;
        const size_t n = write_connection_close(p, room, app, code, close_frame_, nullptr, 0);
        if (n != 0) ++sent_.connection_close;
        return n;
    }

    // \~english An ACK when one is owed: at once, or its delay is up.
    // \~spanish Un ACK cuando se debe: al momento, o se acabo su plazo.  \~
    const uint64_t deadline = acks.ack_deadline();
    if (acks.ranges() != 0 && deadline != kNever && deadline <= now_us) {
        const size_t n = acks.write_ack(p, room, now_us);
        if (n != 0) {
            ack_largest = acks.range(0).largest;
            acks.on_ack_sent();
            used += n;
        }
    }

    // \~english Anything else elicits an ACK and counts against the congestion window.
    // \~spanish Todo lo demas pide confirmacion y cuenta contra la ventana de congestion.  \~
    if (!recovery_.window_allows(cfg_.max_datagram)) return used;

    size_t n = 0;

    if (s == Space::Application) {
        if (handshake_done_owed_ && !full(rec) && (n = write_handshake_done(p + used, room - used)) != 0) {
            used += n;
            eliciting = true;
            handshake_done_owed_ = false;
            ++sent_.handshake_done;
            add_record(rec, kRecHandshakeDone, 0, 0, 0, false);
        }
        if (path_response_owed_ && (n = write_path_response(p + used, room - used, path_response_)) != 0) {
            // \~english Never retransmitted: a new challenge brings a new response (8.2.2).
            // \~spanish No se retransmite nunca: un desafio nuevo trae una respuesta nueva (8.2.2).  \~
            used += n;
            eliciting = true;
            path_response_owed_ = false;
            ++sent_.path_response;
        }
        if ((recv_flow_.wants_update() || max_data_owed_) && !full(rec)) {
            n = write_max_data(p + used, room - used, recv_flow_.advertise());
            if (n != 0) {
                used += n;
                eliciting = true;
                max_data_owed_ = false;
                ++sent_.max_data;
                add_record(rec, kRecMaxData, 0, 0, 0, false);
            }
        }
        for (int bidi = 1; bidi >= 0; --bidi) {
            if ((streams_.wants_max_streams(bidi != 0) || max_streams_owed_[bidi]) && !full(rec)) {
                n = write_max_streams(p + used, room - used, bidi != 0,
                                      streams_.advertise_max_streams(bidi != 0));
                if (n != 0) {
                    used += n;
                    eliciting = true;
                    max_streams_owed_[bidi] = false;
                    ++sent_.max_streams;
                    add_record(rec, kRecMaxStreams, static_cast<uint64_t>(bidi), 0, 0, false);
                }
            }
        }
        for (size_t i = 0; i < streams_.capacity() && !full(rec); ++i) {
            Stream *st = streams_.slot(i);
            if (st == nullptr) continue;
            if (st->recv != nullptr && (st->recv->wants_update() || st->max_stream_data_owed)) {
                n = write_max_stream_data(p + used, room - used, st->id, st->recv->advertise());
                if (n != 0) {
                    used += n;
                    eliciting = true;
                    st->max_stream_data_owed = false;
                    ++sent_.max_stream_data;
                    add_record(rec, kRecMaxStreamData, st->id, 0, 0, false);
                }
            }
            if (st->send != nullptr && st->send->reset_pending() && !full(rec)) {
                n = write_reset_stream(p + used, room - used, st->id, st->send->reset_code(),
                                       st->send->final_size());
                if (n != 0) {
                    used += n;
                    eliciting = true;
                    st->send->on_reset_sent();
                    ++sent_.reset_stream;
                    add_record(rec, kRecResetStream, st->id, 0, 0, false);
                }
            }
        }
    }

    // \~english CRYPTO, in every space: not flow controlled, never counted against MAX_DATA.
    // \~spanish CRYPTO, en todos los espacios: sin control de flujo, nunca cuenta contra MAX_DATA.  \~
    SendStream &cs = *crypto_send_[idx(s)];
    while (!full(rec) && room - used > 16) {
        StreamPiece piece;
        if (!cs.next(piece, room - used - 16, kNever)) break;
        if (piece.len == 0) break;
        n = write_crypto_header(p + used, room - used, piece.offset, piece.len);
        if (n == 0 || n + piece.len > room - used) break;
        util::vesta_memcpy(p + used + n, piece.data, piece.len);
        used += n + piece.len;
        cs.on_sent(piece);
        eliciting = true;
        add_record(rec, kRecCrypto, 0, piece.offset, piece.len, false);
    }

    // \~english Stream data, taking turns so that one stream cannot starve the rest.
    // \~spanish Datos de flujos, por turnos, para que un flujo no deje sin nada a los demas.  \~
    if (s == Space::Application) {
        const size_t cap = streams_.capacity();
        for (size_t k = 0; k < cap && !full(rec) && room - used > 24; ++k) {
            Stream *st = streams_.slot((round_robin_ + k) % cap);
            if (st == nullptr || st->send == nullptr) continue;
            StreamPiece piece;
            while (!full(rec) && room - used > 24 &&
                   st->send->next(piece, room - used - 24, send_flow_.credit())) {
                n = write_stream_header(p + used, room - used, st->id, piece.offset, piece.len,
                                        piece.fin, true);
                if (n == 0 || n + piece.len > room - used) break;
                if (piece.len != 0) util::vesta_memcpy(p + used + n, piece.data, piece.len);
                used += n + piece.len;
                if (!piece.retransmit) send_flow_.on_sent(piece.len);
                st->send->on_sent(piece);
                eliciting = true;
                add_record(rec, kRecStream, st->id, piece.offset, piece.len, piece.fin);
                if (piece.fin && piece.len == 0) break;
            }
        }
        round_robin_ = cap != 0 ? (round_robin_ + 1) % cap : 0;
    }

    // \~english A probe with nothing else to carry is a PING (6.2.4).
    // \~spanish Un sondeo sin nada mas que llevar es un PING (6.2.4).  \~
    if (probe_owed_[idx(s)]) {
        if (!eliciting && (n = write_ping(p + used, room - used)) != 0) {
            used += n;
            eliciting = true;
            ++sent_.ping;
        }
        if (eliciting) probe_owed_[idx(s)] = false;
    }
    return used;
}

size_t Connection::build_packet(Space s, uint8_t *out, size_t room, Pad pad, bool &padded,
                                uint64_t now_us) noexcept {
    padded = false;
    if (!recovery_.can_record(s) && state_ != ConnState::Closing) return 0;

    const size_t i = idx(s);
    const uint64_t pn = next_pn_[i];
    const uint64_t la = recovery_.largest_acked(s);
    size_t pn_len = packet_number_length(pn, la == kNever ? 0 : la, la != kNever);
    if (pn_len == 0) pn_len = 4;

    // \~english The header, up to the packet number.
    // \~spanish La cabecera, hasta el numero de paquete.  \~
    size_t h = 0;
    size_t length_at = 0;
    const bool is_long = s != Space::Application;
    if (room < 64) return 0;
    if (is_long) {
        out[h++] = static_cast<uint8_t>(0xc0 | (long_type_bits(s, cfg_.version) << 4));
        out[h++] = static_cast<uint8_t>(cfg_.version >> 24);
        out[h++] = static_cast<uint8_t>(cfg_.version >> 16);
        out[h++] = static_cast<uint8_t>(cfg_.version >> 8);
        out[h++] = static_cast<uint8_t>(cfg_.version);
        out[h++] = static_cast<uint8_t>(cfg_.peer_cid_len);
        util::vesta_memcpy(out + h, cfg_.peer_cid, cfg_.peer_cid_len);
        h += cfg_.peer_cid_len;
        out[h++] = static_cast<uint8_t>(cfg_.local_cid_len);
        util::vesta_memcpy(out + h, cfg_.local_cid, cfg_.local_cid_len);
        h += cfg_.local_cid_len;
        if (s == Space::Initial) out[h++] = 0;  // \~english no token  \~spanish sin testigo  \~
        length_at = h;
        h += 2;
    } else {
        out[h++] = 0x40;
        util::vesta_memcpy(out + h, cfg_.peer_cid, cfg_.peer_cid_len);
        h += cfg_.peer_cid_len;
    }
    const size_t pn_offset = h;
    const size_t overhead = pn_offset + pn_len + kTagSize;
    if (room <= overhead + 4) return 0;

    PacketRecord rec;
    rec.tag = next_tag_;
    rec.count = 0;
    bool eliciting = false;
    uint64_t ack_largest = kNever;
    uint8_t *payload = out + pn_offset + pn_len;
    const size_t payload_room = room - overhead;

    size_t len = write_frames(s, payload, payload_room, rec, eliciting, ack_largest, now_us);
    if (len == 0) return 0;

    // \~english Padding to a full datagram where 14.1 requires it.
    // \~spanish Relleno hasta un datagrama entero donde lo exige 14.1.  \~
    if (pad == Pad::Always || (pad == Pad::IfEliciting && eliciting)) {
        const size_t total = overhead + len;
        if (total < kMinInitial) {
            const size_t extra = kMinInitial - total;
            if (extra > payload_room - len) return 0;  // \~english cannot reach 1200: send nothing  \~spanish no llega a 1200: no se manda nada  \~
            util::vesta_memset(payload + len, 0, extra);
            len += extra;
        }
        padded = true;
    }

    // \~english The header-protection sample needs four bytes after the packet number start.
    // \~spanish La muestra de la proteccion de cabecera necesita cuatro bytes tras el numero de paquete.  \~
    if (pn_len + len < 4) {
        util::vesta_memset(payload + len, 0, 4 - pn_len - len);
        len = 4 - pn_len;
    }

    if (is_long) encode_varint_width(out + length_at, 2, pn_len + len + kTagSize);

    if (protect_packet(crypto_, keys_[i].write, out, pn_offset, pn_len, pn, len) != Protect::Ok) {
        fail(TransportError::InternalError, 0, now_us);
        return 0;
    }

    const size_t size = overhead + len;
    ++next_pn_[i];
    bytes_out_ += size;

    if (state_ != ConnState::Closing) {
        // \~english PADDING keeps a packet in flight even without an ack-eliciting frame.
        // \~spanish PADDING mantiene un paquete en vuelo aunque no lleve tramas que pidan confirmacion.  \~
        const bool in_flight = eliciting || padded;
        records_[rec.tag % record_cap_] = rec;
        ++next_tag_;
        recovery_.on_packet_sent(s, pn, static_cast<uint32_t>(size), eliciting, in_flight,
                                 rec.tag, ack_largest, now_us);
        /* \~english
         * Sending restarts the idle timer only for the first ack-eliciting
         * packet since the last receipt (10.1): otherwise the probes of a
         * connection nobody answers would keep it alive forever.
         * \~spanish
         * Mandar solo reinicia el plazo de inactividad con el primer paquete que
         * pide confirmacion desde la ultima recepcion (10.1): si no, los sondeos
         * de una conexion a la que no contesta nadie la mantendrian viva para
         * siempre.
         * \~ */
        if (eliciting && !sent_eliciting_since_receipt_) {
            restart_idle(now_us);
            sent_eliciting_since_receipt_ = true;
        }
    }

    // \~english A client stops using Initial keys once it sends a Handshake packet (RFC 9001, 4.9.1).
    // \~spanish Un cliente deja las claves Initial en cuanto manda un paquete Handshake (RFC 9001, 4.9.1).  \~
    if (!cfg_.is_server && s == Space::Handshake) discard_keys(Space::Initial, now_us);
    return size;
}

size_t Connection::build_datagram(uint8_t *out, size_t room, uint64_t now_us) noexcept {
    if (state_ == ConnState::Closed || state_ == ConnState::Draining) return 0;
    streams_.collect();

    room = static_cast<size_t>(min64(room, cfg_.max_datagram));
    const size_t budget = amplification_budget();
    if (budget < room) room = budget;
    if (room < 64) {
        if (!validated_) recovery_.set_amplification_blocked(true, now_us);
        return 0;
    }

    bool padded = false;
    if (state_ == ConnState::Closing) {
        if (!close_owed_) return 0;
        // \~english In the highest space this end can still write.
        // \~spanish En el espacio mas alto en el que este extremo aun puede escribir.  \~
        for (int s = 2; s >= 0; --s) {
            if (!keys_[s].have) continue;
            close_owed_ = false;
            return build_packet(static_cast<Space>(s), out, room, Pad::Never, padded, now_us);
        }
        return 0;
    }

    size_t total = 0;
    for (size_t s = 0; s < kSpaces; ++s) {
        if (!keys_[s].have) continue;
        const Space sp = static_cast<Space>(s);

        /* \~english
         * A datagram with an Initial is padded to 1200 bytes: always from a
         * client, when ack-eliciting from a server (14.1).  Such an Initial
         * goes alone, padded itself, rather than guessing what else will fit.
         * \~spanish
         * Un datagrama con un Initial se rellena hasta 1200 bytes: siempre desde
         * un cliente, cuando pide confirmacion desde un servidor (14.1).  Ese
         * Initial va solo, rellenado el, en vez de adivinar que mas cabra.
         * \~ */
        const Pad pad = sp != Space::Initial ? Pad::Never
                        : cfg_.is_server     ? Pad::IfEliciting
                                             : Pad::Always;
        const size_t n = build_packet(sp, out + total, room - total, pad, padded, now_us);
        total += n;
        if (padded || state_ != ConnState::Active) break;
    }
    return total;
}

uint64_t Connection::timer() const noexcept {
    if (state_ == ConnState::Closed) return kNever;
    if (state_ != ConnState::Active) return close_deadline_;

    uint64_t t = min64(idle_deadline_, recovery_.timer());

    /* \~english
     * An ACK that cannot be sent is no reason to wake: a server at its
     * amplification limit can send nothing until more arrives, and a timer
     * stuck at "now" would spin.
     * \~spanish
     * Un ACK que no se puede mandar no es motivo para despertar: un servidor en
     * su limite de amplificacion no puede mandar nada hasta que llegue mas, y un
     * temporizador clavado en "ahora" daria vueltas sin fin.
     * \~ */
    if (amplification_budget() < 64) return t;
    for (size_t s = 0; s < kSpaces; ++s)
        if (keys_[s].have) t = min64(t, acks_[s].ack_deadline());
    return t;
}

void Connection::on_timer(uint64_t now_us) noexcept {
    if (state_ == ConnState::Closed) return;

    if (state_ != ConnState::Active) {
        if (now_us >= close_deadline_) state_ = ConnState::Closed;
        return;
    }

    // \~english Silence past the idle timeout: the connection is gone, without a word (10.1).
    // \~spanish Silencio pasado el plazo de inactividad: la conexion desaparece, sin decir nada (10.1).  \~
    if (idle_deadline_ != kNever && now_us >= idle_deadline_) {
        state_ = ConnState::Closed;
        return;
    }

    if (recovery_.timer() <= now_us) {
        const TimeoutAction a = recovery_.on_timeout(now_us, *this);
        if (a.kind == TimeoutAction::Probe) probe_owed_[idx(a.space)] = true;
    }
}

} // namespace quic
} // namespace http_vx
