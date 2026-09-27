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

#include "http_vx/quic_transport_params.h"
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
    kRecNewCid,
    kRecRetireCid,
    kRecDataBlocked,
    kRecStreamDataBlocked,
    kRecStreamsBlocked,
    kRecStopSending,
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

    /* \~english
     * The handshake's path.  A client's peer address needs no proof: the
     * server's answers prove it (8.1), and the anti-amplification limit never
     * binds a client (21.1.1.1).
     * \~spanish
     * El camino del saludo.  La direccion del otro de un cliente no necesita
     * prueba: la prueban las respuestas del servidor (8.1), y el limite
     * antiamplificacion nunca ata a un cliente (21.1.1.1).
     * \~ */
    PathState &first = paths_[0];
    first.addr = cfg_.path;
    first.used = true;
    first.validated = !cfg_.is_server;
    first.peer_seq = 0;
    first.local_seq_seen = 0;

    /* \~english
     * Sequence 0 on each side is the ID the handshake already uses.  Ours
     * gets its reset token like any other; the peer's has one only if it was
     * given (a server's comes in its transport parameters).
     * \~spanish
     * La secuencia 0 de cada lado es el identificador que ya usa el saludo.  El
     * nuestro recibe su testigo de reinicio como cualquier otro; el del otro solo
     * lo tiene si se dio (el de un servidor llega en sus parametros de
     * transporte).
     * \~ */
    LocalCid &l = local_cids_[0];
    util::vesta_memcpy_noinline(l.cid, cfg_.local_cid, cfg_.local_cid_len);
    l.active = cfg_.local_cid_len <= kMaxConnectionId &&
               reset_token(crypto_, cfg_.reset_key, cfg_.local_cid, cfg_.local_cid_len, l.token);
    PeerCid &p = peer_cids_[0];
    learn_peer_cid(cfg_.peer_cid, cfg_.peer_cid_len);
    p.active = true;
    p.used = true;
    p.has_token = cfg_.peer_reset_token_known;
    util::vesta_memcpy_noinline(p.token, cfg_.peer_reset_token, kResetTokenSize);
    draw_spin_bit();
}

Connection::~Connection() {
    for (Keys &k : keys_) {
        if (k.have) {
            forget_keys(crypto_, k.read);
            forget_keys(crypto_, k.write);
        }
    }
    forget_one_rtt();
    forget_early();
    for (size_t s = 0; s < kSpaces; ++s) {
        drop_from_heap(crypto_recv_[s]);
        drop_from_heap(crypto_send_[s]);
    }
    if (records_ != nullptr) util::host_free(records_);
    if (pending_ != nullptr) util::host_free(pending_);
    if (token_ != nullptr) util::host_free(token_);
}

bool Connection::ready() const noexcept {
    for (size_t s = 0; s < kSpaces; ++s)
        if (crypto_recv_[s] == nullptr || crypto_send_[s] == nullptr) return false;
    // \~english Limits that do not fit the fixed tables are refused, not clamped (18.2: at least 2).
    // \~spanish Los limites que no caben en las tablas fijas se rechazan, no se recortan (18.2: al menos 2).  \~
    if (cfg_.active_cid_limit < 2 || cfg_.active_cid_limit > kMaxCids || cfg_.peer_active_cid_limit < 2)
        return false;
    return records_ != nullptr && recovery_.ready() && streams_.ready() && local_cids_[0].active;
}

bool Connection::set_initial_keys(const uint8_t *odcid, size_t len) noexcept {
    if (len > kMaxConnectionId) return false;
    util::vesta_memcpy(odcid_, odcid, len);
    odcid_len_ = len;
    return derive_initial_keys(odcid, len);
}

bool Connection::derive_initial_keys(const uint8_t *dcid, size_t len) noexcept {
    // \~english The old keys first: re-deriving must not leak the states behind them.
    // \~spanish Primero las claves viejas: volver a derivar no debe perder los estados de detras.  \~
    Keys &k = keys_[idx(Space::Initial)];
    if (k.have) {
        forget_keys(crypto_, k.read);
        forget_keys(crypto_, k.write);
    }
    k.have = make_initial_keys(crypto_, cfg_.version, dcid, len, cfg_.is_server, k.read, k.write);
    return k.have;
}

void Connection::set_address_validated(uint64_t now_us) noexcept {
    paths_[active_].validated = true;
    recovery_.set_amplification_blocked(false, now_us);
}

const char *migration_name(Migration m) noexcept {
    switch (m) {
    case Migration::Started:        return "started";
    case Migration::NotClient:      return "not-client";
    case Migration::NotConfirmed:   return "not-confirmed";
    case Migration::Disabled:       return "disabled";
    case Migration::ZeroLengthId:   return "zero-length-id";
    case Migration::UnknownServer:  return "unknown-server";
    case Migration::SamePath:       return "same-path";
    case Migration::NoConnectionId: return "no-connection-id";
    case Migration::Failed:         return "failed";
    }
    return "unknown";
}

const char *end_reason_name(EndReason r) noexcept {
    switch (r) {
    case EndReason::None:                 return "none";
    case EndReason::Closed:               return "closed";
    case EndReason::PeerClosed:           return "peer-closed";
    case EndReason::StatelessReset:       return "stateless-reset";
    case EndReason::IdleTimeout:          return "idle-timeout";
    case EndReason::VersionNegotiation:   return "version-negotiation";
    case EndReason::PacketNumbers:        return "packet-numbers";
    case EndReason::ConfidentialityLimit: return "confidentiality-limit";
    case EndReason::NoValidatedPath:      return "no-validated-path";
    case EndReason::kCount:               break;
    }
    return "unknown";
}

size_t Connection::offered_versions(uint32_t *out, size_t room) const noexcept {
    const size_t kept = offered_count_ < kOfferedVersions ? offered_count_ : kOfferedVersions;
    for (size_t i = 0; i < kept && i < room; ++i) out[i] = offered_[i];
    return offered_count_;
}

bool Connection::install_secrets(Space s, Aead a, const uint8_t *read_secret,
                                 const uint8_t *write_secret, size_t len, uint64_t now_us) noexcept {
    Keys &k = keys_[idx(s)];
    if (k.have || len > kMaxSecret) return false;

    KeyMaterial m;
    if (!derive_key_material(crypto_, cfg_.version, a, read_secret, len, m) ||
        !prepare_keys(crypto_, m, k.read)) {
        util::vesta_memset_noinline(&m, 0, sizeof m);
        return false;
    }
    if (!derive_key_material(crypto_, cfg_.version, a, write_secret, len, m) ||
        !prepare_keys(crypto_, m, k.write)) {
        forget_keys(crypto_, k.read);
        util::vesta_memset_noinline(&m, 0, sizeof m);
        return false;
    }

    /* \~english
     * 1-RTT keeps the secrets: every later phase comes from them (6.1).  And
     * the next read keys are made now, so that a peer's update never waits
     * for -- or reveals through its timing -- a derivation (6.3).
     * \~spanish
     * 1-RTT guarda los secretos: de ellos sale cada fase posterior (6.1).  Y las
     * claves de lectura siguientes se hacen ya, para que la actualizacion del
     * otro extremo nunca espere a una derivacion -- ni la delate por su tiempo
     * (6.3).
     * \~ */
    if (s == Space::Application) {
        one_rtt_.aead = a;
        one_rtt_.secret_len = len;
        // \~english Out of line: once per phase, at most 48 bytes.
        // \~spanish Fuera de linea: una vez por fase, como mucho 48 bytes.  \~
        util::vesta_memcpy_noinline(one_rtt_.read_secret, read_secret, len);
        util::vesta_memcpy_noinline(one_rtt_.write_secret, write_secret, len);
        uint8_t next[kMaxSecret];
        const bool ok = next_secret(crypto_, cfg_.version, a, read_secret, len, next) &&
                        make_generation(next, one_rtt_.read_next);
        util::vesta_memset_noinline(next, 0, sizeof next);
        if (!ok) {
            forget_keys(crypto_, k.read);
            forget_keys(crypto_, k.write);
            forget_one_rtt();
            return false;
        }
    }
    k.have = true;
    // \~english A client's 0-RTT keys have no use once it has 1-RTT ones (RFC 9001, 4.9.3: SHOULD).
    // \~spanish Las claves 0-RTT de un cliente no sirven para nada cuando tiene las 1-RTT (RFC 9001, 4.9.3: DEBERIA).  \~
    if (s == Space::Application && !cfg_.is_server && early_have_) forget_early();
    // \~english With 1-RTT keys, NEW_CONNECTION_ID can travel: hand out as many IDs as the peer takes.
    // \~spanish Con claves 1-RTT, NEW_CONNECTION_ID puede viajar: repartir tantos identificadores como acepte el otro.  \~
    if (s == Space::Application) top_up_cids();
    if (s == Space::Handshake) recovery_.set_has_handshake_keys(now_us);

    // \~english Whatever arrived before these keys can be opened now.
    // \~spanish Lo que llego antes que estas claves ya se puede abrir.  \~
    replay(s, now_us);
    return true;
}

bool Connection::set_original_ids(const uint8_t *odcid, size_t odcid_len, const uint8_t *retry_scid,
                                  size_t retry_len) noexcept {
    if (!cfg_.is_server || odcid_len > kMaxConnectionId || retry_len > kMaxConnectionId) return false;
    util::vesta_memcpy_noinline(original_dcid_, odcid, odcid_len);
    original_dcid_len_ = odcid_len;
    util::vesta_memcpy_noinline(retry_scid_, retry_scid, retry_len);
    retry_scid_len_ = retry_len;
    original_known_ = true;
    return true;
}

namespace {

/// \~english Copies an ID into a transport parameter.  \~spanish Copia un identificador en un parametro de transporte.  \~
void set_tp_cid(TpConnectionId &t, const uint8_t *cid, size_t len) noexcept {
    t.present = true;
    t.len = static_cast<uint8_t>(len);
    util::vesta_memcpy_noinline(t.bytes, cid, len);
}

/// \~english Whether a transport parameter names exactly this ID.  \~spanish Si un parametro de transporte nombra exactamente este identificador.  \~
bool tp_names(const TpConnectionId &t, const uint8_t *cid, size_t len) noexcept {
    if (!t.present || t.len != len) return false;
    uint8_t d = 0;
    for (size_t i = 0; i < len; ++i) d = static_cast<uint8_t>(d | (t.bytes[i] ^ cid[i]));
    return d == 0;
}

} // namespace

size_t Connection::local_transport_params(uint8_t *out, size_t room) const noexcept {
    TransportParams tp;
    own_params(tp);
    return encode_transport_params(tp, out, room);
}

size_t Connection::early_context(uint8_t *out, size_t room) const noexcept {
    /* \~english
     * What a client may remember for 0-RTT (7.4.1): this end's parameters
     * without the IDs, the reset token or the ACK timing.  Equal to what a
     * ticket was issued with means no limit went down (7.4.1: MUST NOT).
     * \~spanish
     * Lo que un cliente puede recordar para 0-RTT (7.4.1): los parametros de este
     * extremo sin los identificadores, el testigo ni el tiempo de ACK.  Igual a
     * aquello con lo que se emitio un ticket significa que ningun limite bajo
     * (7.4.1: NO DEBE).
     * \~ */
    TransportParams tp;
    own_params(tp);
    const TransportParams defaults;
    tp.original_destination_connection_id.present = false;
    tp.initial_source_connection_id.present = false;
    tp.retry_source_connection_id.present = false;
    tp.has_stateless_reset_token = false;
    tp.max_ack_delay_ms = defaults.max_ack_delay_ms;
    tp.ack_delay_exponent = defaults.ack_delay_exponent;
    return encode_transport_params(tp, out, room);
}

void Connection::own_params(TransportParams &tp) const noexcept {
    // \~english The source ID of this end's first Initial (7.3): the first local ID.
    // \~spanish El identificador de origen del primer Initial de este extremo (7.3): el primer identificador local.  \~
    set_tp_cid(tp.initial_source_connection_id, local_cids_[0].cid, cfg_.local_cid_len);
    if (cfg_.is_server) {
        // \~english The client's first destination, before any Retry, and the Retry's source (7.3).
        // \~spanish El primer destino del cliente, antes de cualquier Retry, y el origen del Retry (7.3).  \~
        if (original_known_) {
            set_tp_cid(tp.original_destination_connection_id, original_dcid_, original_dcid_len_);
            if (retry_scid_len_ != 0) set_tp_cid(tp.retry_source_connection_id, retry_scid_, retry_scid_len_);
        } else {
            set_tp_cid(tp.original_destination_connection_id, odcid_, odcid_len_);
        }
        // \~english The token of the ID the handshake used: only a server sends one (18.2).
        // \~spanish El testigo del identificador que uso el saludo: solo un servidor lo manda (18.2).  \~
        if (cfg_.local_cid_len != 0) {
            tp.has_stateless_reset_token = true;
            util::vesta_memcpy_noinline(tp.stateless_reset_token, local_cids_[0].token, kResetTokenSize);
        }
        tp.disable_active_migration = cfg_.disable_active_migration;
    }
    // \~english Milliseconds on the wire: rounded up, so the promise is never shorter than what is kept (18.2).
    // \~spanish Milisegundos en el cable: redondeado hacia arriba, para que la promesa nunca sea mas corta que lo que se cumple (18.2).  \~
    tp.max_idle_timeout_ms = (cfg_.idle_timeout_us + 999) / 1000;
    tp.max_ack_delay_ms = (cfg_.ack.max_ack_delay_us + 999) / 1000;
    tp.ack_delay_exponent = cfg_.ack.ack_delay_exponent;
    tp.initial_max_data = cfg_.data_window;
    tp.initial_max_stream_data_bidi_local = cfg_.streams.window_bidi_local;
    tp.initial_max_stream_data_bidi_remote = cfg_.streams.window_bidi_remote;
    tp.initial_max_stream_data_uni = cfg_.streams.window_uni;
    tp.initial_max_streams_bidi = streams_.max_streams(true);
    tp.initial_max_streams_uni = streams_.max_streams(false);
    tp.active_connection_id_limit = cfg_.active_cid_limit;
}

bool Connection::on_peer_transport_params(const uint8_t *data, size_t n, uint64_t now_us) noexcept {
    if (peer_params_known_) return state_ == ConnState::Active;
    TransportParams tp;
    // \~english A server's parameters are what a client reads, and the other way round.
    // \~spanish Los parametros de un servidor son lo que lee un cliente, y al reves.  \~
    if (decode_transport_params(data, n, !cfg_.is_server, tp) != TpError::None) {
        fail(TransportError::TransportParameterError, 0, now_us);
        return false;
    }

    /* \~english
     * 7.3: the IDs are the ones the Initial packets carried.  The peer's
     * source ID is the first one it gave, still entry 0; a client also
     * checks the destination it first chose, and the Retry it took or did
     * not take.
     * \~spanish
     * 7.3: los identificadores son los que llevaron los paquetes Initial.  El
     * identificador de origen del otro es el primero que dio, aun la entrada 0;
     * un cliente comprueba ademas el destino que eligio primero, y el Retry que
     * acepto o no.
     * \~ */
    bool ids = tp_names(tp.initial_source_connection_id, peer_cids_[0].cid, peer_cids_[0].len);
    if (!cfg_.is_server) {
        ids = ids && tp_names(tp.original_destination_connection_id, odcid_, odcid_len_);
        ids = ids && (retried_ ? tp_names(tp.retry_source_connection_id, retry_scid_, retry_scid_len_)
                               : !tp.retry_source_connection_id.present);
    }
    if (!ids) {
        fail(TransportError::TransportParameterError, 0, now_us);
        return false;
    }
    peer_params_known_ = true;

    // \~english The peer's ACK timing: recovery, and the PTO this end computes (RFC 9002, A.3).
    // \~spanish El tiempo de ACK del otro: la recuperacion, y el PTO que calcula este extremo (RFC 9002, A.3).  \~
    cfg_.recovery.max_ack_delay_us = tp.max_ack_delay_ms * 1000;
    recovery_.set_peer_ack_params(tp.max_ack_delay_ms * 1000, static_cast<uint8_t>(tp.ack_delay_exponent), now_us);

    // \~english The idle timeout is the smaller of the two, or the only one that is not zero (10.1).
    // \~spanish El plazo de inactividad es el menor de los dos, o el unico que no es cero (10.1).  \~
    const uint64_t peer_idle = tp.max_idle_timeout_ms * 1000;
    if (peer_idle != 0 && (cfg_.idle_timeout_us == 0 || peer_idle < cfg_.idle_timeout_us))
        cfg_.idle_timeout_us = peer_idle;
    restart_idle(now_us);

    // \~english No datagram larger than the peer is willing to receive (18.2); 1200 is the least it may say.
    // \~spanish Ningun datagrama mayor de lo que el otro esta dispuesto a recibir (18.2); 1200 es lo minimo que puede decir.  \~
    if (tp.max_udp_payload_size < cfg_.max_datagram) cfg_.max_datagram = static_cast<size_t>(tp.max_udp_payload_size);

    send_flow_.on_max_data(tp.initial_max_data);
    streams_.on_peer_params(tp.initial_max_streams_bidi, tp.initial_max_streams_uni,
                            tp.initial_max_stream_data_bidi_local, tp.initial_max_stream_data_bidi_remote,
                            tp.initial_max_stream_data_uni);

    // \~english How many IDs this end may have handed out: never past its own table (5.1.1).
    // \~spanish Cuantos identificadores puede tener repartidos este extremo: nunca mas que su propia tabla (5.1.1).  \~
    cfg_.peer_active_cid_limit =
        static_cast<size_t>(tp.active_connection_id_limit < kMaxCids ? tp.active_connection_id_limit : kMaxCids);
    if (keys_[idx(Space::Application)].have) top_up_cids();

    if (!cfg_.is_server) {
        // \~english The server's first ID gets its reset token (10.3); and it may forbid moving (9).
        // \~spanish El primer identificador del servidor recibe su testigo (10.3); y puede prohibir moverse (9).  \~
        if (tp.has_stateless_reset_token) {
            util::vesta_memcpy_noinline(peer_cids_[0].token, tp.stateless_reset_token, kResetTokenSize);
            peer_cids_[0].has_token = true;
        }
        cfg_.peer_disable_active_migration = tp.disable_active_migration;
    }
    return true;
}

bool Connection::remember_transport_params(const uint8_t *data, size_t n) noexcept {
    if (cfg_.is_server || peer_params_known_) return false;
    TransportParams tp;
    if (decode_transport_params(data, n, true, tp) != TpError::None) return false;
    /* \~english
     * 7.4.1: never the ACK timing, the IDs, preferred_address or the reset
     * token -- those are the new connection's own.  The rest is what 0-RTT
     * runs on, and the handshake's values replace it.
     * \~spanish
     * 7.4.1: nunca el tiempo de ACK, los identificadores, preferred_address ni el
     * testigo -- esos son de la conexion nueva.  El resto es con lo que funciona
     * el 0-RTT, y los valores del saludo lo sustituyen.
     * \~ */
    const uint64_t idle = tp.max_idle_timeout_ms * 1000;
    if (idle != 0 && (cfg_.idle_timeout_us == 0 || idle < cfg_.idle_timeout_us)) cfg_.idle_timeout_us = idle;
    if (tp.max_udp_payload_size < cfg_.max_datagram) cfg_.max_datagram = static_cast<size_t>(tp.max_udp_payload_size);
    send_flow_.on_max_data(tp.initial_max_data);
    streams_.on_peer_params(tp.initial_max_streams_bidi, tp.initial_max_streams_uni,
                            tp.initial_max_stream_data_bidi_local, tp.initial_max_stream_data_bidi_remote,
                            tp.initial_max_stream_data_uni);
    cfg_.peer_disable_active_migration = tp.disable_active_migration;
    return true;
}

bool Connection::install_early_secret(Aead a, const uint8_t *secret, size_t len, uint64_t now_us) noexcept {
    if (early_have_ || early_gone_ || len > kMaxSecret) return false;
    KeyMaterial m;
    const bool ok = derive_key_material(crypto_, cfg_.version, a, secret, len, m) && prepare_keys(crypto_, m, early_keys_);
    util::vesta_memset_noinline(&m, 0, sizeof m);
    if (!ok) return false;
    early_have_ = true;
    // \~english A server may have kept some that came first (RFC 9001, 4.1.4).
    // \~spanish Un servidor puede haber guardado alguno que llego antes (RFC 9001, 4.1.4).  \~
    if (cfg_.is_server) replay(Space::Application, now_us, true);
    return true;
}

void Connection::forget_early() noexcept {
    if (early_have_) forget_keys(crypto_, early_keys_);
    early_have_ = false;
    early_gone_ = true;
    early_discard_at_ = kNever;
}

void Connection::reject_early(uint64_t now_us) noexcept {
    if (early_rejected_) return;
    early_rejected_ = true;
    forget_early();
    // \~english Kept 0-RTT packets will never be opened (4.6.2: MUST NOT process any).
    // \~spanish Los paquetes 0-RTT guardados no se abriran nunca (4.6.2: NO DEBE procesar ninguno).  \~
    if (pending_ != nullptr)
        for (size_t i = 0; i < kPendingPackets; ++i)
            if (pending_[i].used && pending_[i].early) {
                pending_[i].used = false;
                ++drops_.early;
            }
    if (cfg_.is_server) return;
    /* \~english
     * The client: what it sent in 0-RTT is gone for good (RFC 9002, 6.4), and
     * everything it assumed may be wrong -- streams and flow control start
     * over (RFC 9001, 4.6.2), on the handshake's parameters.
     * \~spanish
     * El cliente: lo que mando en 0-RTT se perdio para siempre (RFC 9002, 6.4), y
     * todo lo que supuso puede estar mal -- flujos y control de flujo empiezan de
     * nuevo (RFC 9001, 4.6.2), con los parametros del saludo.
     * \~ */
    recovery_.drop_early(now_us, nullptr);
    streams_.reset();
    send_flow_.reset(cfg_.peer_max_data);
}

const char *key_update_name(KeyUpdate k) noexcept {
    switch (k) {
    case KeyUpdate::Started:        return "started";
    case KeyUpdate::NoKeys:         return "no-keys";
    case KeyUpdate::NotConfirmed:   return "not-confirmed";
    case KeyUpdate::Unacknowledged: return "unacknowledged";
    case KeyUpdate::OldKeysKept:    return "old-keys-kept";
    case KeyUpdate::TooSoon:        return "too-soon";
    case KeyUpdate::Failed:         return "provider-failed";
    }
    return "unknown";
}

bool Connection::make_generation(const uint8_t *secret, PacketKeys &out) noexcept {
    // \~english Only the AEAD key and the IV: header protection never changes (6).
    // \~spanish Solo la clave AEAD y el IV: la proteccion de cabecera no cambia nunca (6).  \~
    KeyMaterial m;
    bool ok = derive_key_material(crypto_, cfg_.version, one_rtt_.aead, secret,
                                  one_rtt_.secret_len, m);
    if (ok) {
        out.aead = one_rtt_.aead;
        out.aead_state = crypto_.prepare_aead(one_rtt_.aead, m.key);
        out.hp_state = nullptr;
        util::vesta_memcpy(out.iv, m.iv, kNonceSize);
        ok = out.aead_state != nullptr;
    }
    util::vesta_memset_noinline(&m, 0, sizeof m);
    return ok;
}

void Connection::drop_generation(PacketKeys &k) noexcept {
    if (k.aead_state != nullptr) crypto_.forget(k.aead_state);
    k.aead_state = nullptr;
    util::vesta_memset_noinline(k.iv, 0, sizeof k.iv);
}

void Connection::forget_one_rtt() noexcept {
    drop_generation(one_rtt_.read_next);
    drop_generation(one_rtt_.read_prev);
    one_rtt_.prev_until = kNever;
    util::vesta_memset_noinline(one_rtt_.read_secret, 0, sizeof one_rtt_.read_secret);
    util::vesta_memset_noinline(one_rtt_.write_secret, 0, sizeof one_rtt_.write_secret);
}

uint64_t Connection::confidentiality_limit() const noexcept {
    if (cfg_.confidentiality_limit != 0) return cfg_.confidentiality_limit;
    // \~english 6.6: 2^23 packets for AES-GCM; ChaCha20-Poly1305's is beyond any packet count.
    // \~spanish 6.6: 2^23 paquetes para AES-GCM; el de ChaCha20-Poly1305 esta mas alla de cualquier cuenta.  \~
    return one_rtt_.aead == Aead::ChaCha20Poly1305 ? (uint64_t{1} << 62) : (uint64_t{1} << 23);
}

uint64_t Connection::integrity_limit() const noexcept {
    if (cfg_.integrity_limit != 0) return cfg_.integrity_limit;
    // \~english 6.6: 2^52 forgeries for AES-GCM, 2^36 for ChaCha20-Poly1305.
    // \~spanish 6.6: 2^52 falsificaciones para AES-GCM, 2^36 para ChaCha20-Poly1305.  \~
    return one_rtt_.aead == Aead::ChaCha20Poly1305 ? (uint64_t{1} << 36) : (uint64_t{1} << 52);
}

bool Connection::roll_read(uint64_t pn, uint64_t now_us) noexcept {
    // \~english The generation after the new one, made now: failing here is said, before anything moves.
    // \~spanish La generacion siguiente a la nueva, hecha ya: fallar aqui se dice antes de mover nada.  \~
    uint8_t current[kMaxSecret];
    uint8_t after[kMaxSecret];
    PacketKeys next;
    const size_t len = one_rtt_.secret_len;
    bool ok = next_secret(crypto_, cfg_.version, one_rtt_.aead, one_rtt_.read_secret, len, current) &&
              next_secret(crypto_, cfg_.version, one_rtt_.aead, current, len, after) &&
              make_generation(after, next);
    if (ok) {
        PacketKeys &cur = keys_[idx(Space::Application)].read;
        drop_generation(one_rtt_.read_prev);
        one_rtt_.read_prev.aead = cur.aead;
        one_rtt_.read_prev.aead_state = cur.aead_state;
        util::vesta_memcpy(one_rtt_.read_prev.iv, cur.iv, kNonceSize);
        cur.aead_state = one_rtt_.read_next.aead_state;
        util::vesta_memcpy(cur.iv, one_rtt_.read_next.iv, kNonceSize);
        one_rtt_.read_next = next;
        util::vesta_memcpy_noinline(one_rtt_.read_secret, current, len);

        one_rtt_.read_phase = !one_rtt_.read_phase;
        one_rtt_.first_recv_pn = pn;
        // \~english Late packets under the old keys have three PTO to arrive (6.5).
        // \~spanish Los paquetes tardios con las claves viejas tienen tres PTO para llegar (6.5).  \~
        one_rtt_.prev_until = now_us + 3 * pto_duration();
        ++key_counts_.read_rolled;
    }
    util::vesta_memset_noinline(current, 0, sizeof current);
    util::vesta_memset_noinline(after, 0, sizeof after);
    return ok;
}

bool Connection::roll_write() noexcept {
    uint8_t secret[kMaxSecret];
    PacketKeys gen;
    const size_t len = one_rtt_.secret_len;
    const bool ok = next_secret(crypto_, cfg_.version, one_rtt_.aead, one_rtt_.write_secret, len, secret) &&
                    make_generation(secret, gen);
    if (ok) {
        PacketKeys &cur = keys_[idx(Space::Application)].write;
        crypto_.forget(cur.aead_state);
        cur.aead_state = gen.aead_state;
        util::vesta_memcpy(cur.iv, gen.iv, kNonceSize);
        util::vesta_memcpy_noinline(one_rtt_.write_secret, secret, len);
        one_rtt_.write_phase = !one_rtt_.write_phase;
        one_rtt_.first_sent_pn = kNever;
        one_rtt_.phase_acked_at = kNever;
        one_rtt_.sealed = 0;
    }
    util::vesta_memset_noinline(secret, 0, sizeof secret);
    return ok;
}

KeyUpdate Connection::update_keys(uint64_t now_us) noexcept {
    if (!keys_[idx(Space::Application)].have) return KeyUpdate::NoKeys;
    if (!confirmed_) return KeyUpdate::NotConfirmed;

    /* \~english
     * 6.5: only once a packet sealed with the current keys was acknowledged
     * -- which, since the peer acknowledges with ITS keys of the same phase,
     * also means the previous update is complete -- and once the old read
     * keys are gone, so that the peer has had its time to drop them too.
     * \~spanish
     * 6.5: solo cuando se confirmo un paquete sellado con las claves actuales --
     * lo que, como el otro extremo confirma con SUS claves de la misma fase,
     * tambien quiere decir que la actualizacion anterior acabo -- y cuando ya no
     * estan las claves de lectura viejas, para que el otro extremo haya tenido su
     * tiempo de tirarlas tambien.
     * \~ */
    const uint64_t acked = recovery_.largest_acked(Space::Application);
    if (one_rtt_.read_phase != one_rtt_.write_phase || one_rtt_.first_sent_pn == kNever ||
        acked == kNever || acked < one_rtt_.first_sent_pn)
        return KeyUpdate::Unacknowledged;
    if (one_rtt_.read_prev.aead_state != nullptr) return KeyUpdate::OldKeysKept;

    /* \~english
     * 6.5: "Endpoints SHOULD wait three times the PTO before initiating a key
     * update after receiving an acknowledgment that confirms that the previous
     * key update was received" -- the peer may still hold its old keys, and
     * could not open the packets that start the new one.  Only after an
     * update: the first one has no previous to wait for.
     * \~spanish
     * 6.5: los extremos DEBERIAN esperar tres PTO antes de empezar una
     * actualizacion tras recibir el ACK que confirma que llego la anterior -- el
     * otro puede tener aun sus claves viejas, y no podria abrir los paquetes que
     * empiezan la nueva.  Solo tras una actualizacion: la primera no tiene
     * anterior a la que esperar.
     * \~ */
    if (key_counts_.initiated + key_counts_.answered != 0 &&
        (one_rtt_.phase_acked_at == kNever || now_us < one_rtt_.phase_acked_at + 3 * pto_duration()))
        return KeyUpdate::TooSoon;

    if (!roll_write()) return KeyUpdate::Failed;
    ++key_counts_.initiated;
    // \~english The peer's next change of phase will be its answer to this one, not an update of its own.
    // \~spanish El siguiente cambio de fase del otro extremo sera su respuesta a esta, no una actualizacion suya.  \~
    one_rtt_.unanswered_pn = kNever;
    return KeyUpdate::Started;
}

Connection::Opened Connection::open_one_rtt(uint8_t *p, const PacketHeader &h, Unprotected &u,
                                            uint64_t now_us) noexcept {
    PacketKeys &cur = keys_[idx(Space::Application)].read;
    const Unprotect m = unmask_header(crypto_, cur.hp_state, p, h,
                                      acks_[idx(Space::Application)].expected_pn(), u);
    if (m != Unprotect::Ok) return Opened::Failed;

    // \~english The key phase bit, readable only now that the header is unmasked.
    // \~spanish El bit de fase de clave, legible solo ahora que la cabecera esta desenmascarada.  \~
    const bool phase = (u.first & 0x04) != 0;
    Unprotect r;
    if (phase == one_rtt_.read_phase) {
        r = open_payload(crypto_, cur, p, h, u, p + u.payload.off);
        if (r == Unprotect::Ok && u.pn < one_rtt_.first_recv_pn) one_rtt_.first_recv_pn = u.pn;
    } else if (one_rtt_.read_prev.aead_state != nullptr && u.pn < one_rtt_.first_recv_pn) {
        // \~english Numbered before the update: a late packet under the old keys (6.5).
        // \~spanish Numerado antes de la actualizacion: un paquete tardio con las claves viejas (6.5).  \~
        r = open_payload(crypto_, one_rtt_.read_prev, p, h, u, p + u.payload.off);
        if (r == Unprotect::Ok) ++key_counts_.opened_with_old;
    } else {
        /* \~english
         * The other phase, numbered after everything under the current keys:
         * the peer updated (6.2) -- or sealed a newer packet with keys it had
         * already left behind (6.4).  Opened aside, because a failed attempt
         * may leave the bytes it touched, and then the old keys may be tried.
         * \~spanish
         * La otra fase, numerada despues de todo lo de las claves actuales: el
         * otro extremo actualizo (6.2) -- o sello un paquete mas nuevo con claves
         * que ya habia dejado (6.4).  Se abre aparte, porque un intento fallido
         * puede dejar tocados los bytes, y entonces se pueden probar las viejas.
         * \~ */
        uint8_t scratch[1500];
        if (u.payload.len > sizeof scratch) return Opened::Forged;
        r = open_payload(crypto_, one_rtt_.read_next, p, h, u, scratch);
        if (r == Unprotect::Ok) {
            /* \~english
             * Who moved first: with both phases equal the peer started this
             * update; otherwise this is its answer to ours.  Only an update the
             * peer STARTED can be its second without waiting (6.2) -- an answer
             * never is, however soon it comes.
             * \~spanish
             * Quien se movio primero: con las dos fases iguales, esta
             * actualizacion la empezo el otro extremo; si no, es su respuesta a la
             * nuestra.  Solo una actualizacion que EMPEZO el otro puede ser la
             * segunda sin esperar (6.2) -- una respuesta nunca lo es, por pronto
             * que llegue.
             * \~ */
            const bool peer_started = one_rtt_.write_phase == one_rtt_.read_phase;
            if (peer_started && one_rtt_.unanswered_pn != kNever) {
                ++key_counts_.updated_twice;
                return Opened::KeyUpdateViolation;
            }
            util::vesta_memcpy(p + u.payload.off, scratch, u.payload.len);
            if (!roll_read(u.pn, now_us)) return Opened::Failed;
            // \~english An update this end did not start is answered with new write keys (6.2).
            // \~spanish Una actualizacion que no empezo este extremo se contesta con claves de escritura nuevas (6.2).  \~
            if (peer_started) {
                if (!roll_write()) return Opened::Failed;
                ++key_counts_.answered;
                one_rtt_.unanswered_pn = u.pn;
            }
        } else if (r == Unprotect::Forged && one_rtt_.read_prev.aead_state != nullptr &&
                   open_payload(crypto_, one_rtt_.read_prev, p, h, u, scratch) == Unprotect::Ok) {
            ++key_counts_.old_after_new;
            return Opened::KeyUpdateViolation;
        }
    }

    if (r == Unprotect::Ok) return Opened::Ok;
    if (r == Unprotect::Forged) return Opened::Forged;
    if (r == Unprotect::ReservedBitsSet) return Opened::ReservedBits;
    return Opened::Failed;
}

bool Connection::owns_cid(const uint8_t *cid, size_t len) const noexcept {
    if (len != cfg_.local_cid_len) return false;
    for (const LocalCid &l : local_cids_)
        if (l.active && bytes_equal(l.cid, cid, len)) return true;
    return false;
}

void Connection::draw_spin_bit() noexcept {
    uint8_t r = 0;
    // \~english A provider that cannot draw leaves it at 0: still a valid, disabled spin bit.
    // \~spanish Un proveedor que no puede sortear lo deja en 0: sigue siendo un bit de espin valido y apagado.  \~
    spin_bit_ = crypto_.random(&r, 1) && (r & 1) != 0;
}

bool Connection::local_cid(size_t i, uint64_t &seq, const uint8_t *&cid,
                           const uint8_t *&token) const noexcept {
    for (const LocalCid &l : local_cids_) {
        if (!l.active) continue;
        if (i-- != 0) continue;
        seq = l.seq;
        cid = l.cid;
        token = l.token;
        return true;
    }
    return false;
}

void Connection::learn_peer_cid(const uint8_t *cid, size_t len) noexcept {
    // \~english Only while the first ID is the one in use: later ones come by NEW_CONNECTION_ID.
    // \~spanish Solo mientras el primer identificador es el que se usa: los siguientes llegan por NEW_CONNECTION_ID.  \~
    if (peer_seq_in_use_ != 0 || len > kMaxConnectionId) return;
    if (cid != cfg_.peer_cid) util::vesta_memcpy_noinline(cfg_.peer_cid, cid, len);
    cfg_.peer_cid_len = len;
    util::vesta_memcpy_noinline(peer_cids_[0].cid, cid, len);
    peer_cids_[0].len = static_cast<uint8_t>(len);
}

void Connection::top_up_cids() noexcept {
    /* \~english
     * As many live IDs as the peer allows -- counting only those not being
     * retired, since a Retire Prior To may briefly exceed the limit (5.1.1) --
     * and never more than half the table, so a renewal always has room.
     * \~spanish
     * Tantos identificadores vivos como permita el otro -- contando solo los que
     * no se estan retirando, porque un Retire Prior To puede pasarse del limite
     * un momento (5.1.1) -- y nunca mas de media tabla, para que una renovacion
     * tenga siempre sitio.
     * \~ */
    if (cfg_.local_cid_len == 0) return;
    size_t target = cfg_.peer_active_cid_limit;
    if (target > kMaxCids / 2) target = kMaxCids / 2;
    size_t live = 0;
    for (const LocalCid &l : local_cids_)
        if (l.active && l.seq >= local_retire_prior_to_) ++live;

    for (LocalCid &slot : local_cids_) {
        if (live >= target) break;
        if (slot.active) continue;
        LocalCid fresh;
        do {
            if (!crypto_.random(fresh.cid, cfg_.local_cid_len)) return;
        } while (owns_cid(fresh.cid, cfg_.local_cid_len));
        if (!reset_token(crypto_, cfg_.reset_key, fresh.cid, cfg_.local_cid_len, fresh.token)) return;
        fresh.seq = next_local_seq_++;
        fresh.active = true;
        fresh.owed = true;
        slot = fresh;
        ++live;
        ++cid_counts_.issued;
    }
}

bool Connection::renew_connection_ids() noexcept {
    // \~english Not before the peer retired all the previous Retire Prior To asked for (5.1.2).
    // \~spanish No antes de que el otro retire todo lo que pidio el Retire Prior To anterior (5.1.2).  \~
    for (const LocalCid &l : local_cids_)
        if (l.active && l.seq < local_retire_prior_to_) return false;
    local_retire_prior_to_ = next_local_seq_;
    top_up_cids();
    return true;
}

Connection::PeerCid *Connection::peer_cid_by_seq(uint64_t seq) noexcept {
    for (PeerCid &c : peer_cids_)
        if (c.active && c.seq == seq) return &c;
    return nullptr;
}

bool Connection::owe_retire(uint64_t seq) noexcept {
    for (size_t i = 0; i < retire_owed_count_; ++i)
        if (retire_owed_[i] == seq) return true;
    /* \~english
     * An ID MUST NOT be forgotten without retiring it (5.1.2): a peer that
     * makes this end owe more retirements than there is room for is closed
     * with CONNECTION_ID_LIMIT_ERROR, which that section allows -- never
     * dropped quietly.
     * \~spanish
     * Un identificador NO DEBE olvidarse sin retirarlo (5.1.2): a un otro extremo
     * que hace que este deba mas retiradas de las que caben se le cierra con
     * CONNECTION_ID_LIMIT_ERROR, que esa seccion permite -- nunca se tira en
     * silencio.
     * \~ */
    if (retire_outstanding_ >= sizeof retire_owed_ / sizeof retire_owed_[0]) return false;
    ++retire_outstanding_;
    retire_owed_[retire_owed_count_++] = seq;
    return true;
}

void Connection::requeue_retire(uint64_t seq) noexcept {
    // \~english Lost in flight: it still counts as outstanding, so it always fits.
    // \~spanish Perdido en vuelo: sigue contando como pendiente, asi que siempre cabe.  \~
    for (size_t i = 0; i < retire_owed_count_; ++i)
        if (retire_owed_[i] == seq) return;
    if (retire_owed_count_ < sizeof retire_owed_ / sizeof retire_owed_[0])
        retire_owed_[retire_owed_count_++] = seq;
}

bool Connection::use_peer_cid(PeerCid &c) noexcept {
    util::vesta_memcpy_noinline(cfg_.peer_cid, c.cid, c.len);
    cfg_.peer_cid_len = c.len;
    peer_seq_in_use_ = c.seq;
    paths_[active_].peer_seq = c.seq;
    c.used = true;
    ++cid_counts_.switched;
    draw_spin_bit();
    return true;
}

bool Connection::on_new_connection_id(const Frame &f, const uint8_t *payload, uint64_t now_us) noexcept {
    // \~english A peer using a zero-length ID has nowhere to be sent a new one (19.15).
    // \~spanish Un otro extremo con identificador de longitud cero no tiene a donde recibir uno nuevo (19.15).  \~
    if (cfg_.peer_cid_len == 0) {
        fail(TransportError::ProtocolViolation, f.wire_type, now_us);
        return false;
    }
    const uint8_t *cid = payload + f.data.off;
    const uint8_t *token = payload + f.reset_token.off;

    /* \~english
     * The same sequence number again: harmless if it is the same frame
     * retransmitted, a violation if anything differs; and an ID already known
     * under another number is a violation too (19.15).
     * \~spanish
     * El mismo numero de secuencia otra vez: inofensivo si es la misma trama
     * retransmitida, una violacion si algo cambia; y un identificador ya conocido
     * con otro numero tambien es una violacion (19.15).
     * \~ */
    for (const PeerCid &c : peer_cids_) {
        if (!c.active) continue;
        const bool same_cid = c.len == f.data.len && bytes_equal(c.cid, cid, c.len);
        const bool same_token = c.has_token && bytes_equal(c.token, token, kResetTokenSize);
        if (c.seq == f.sequence) {
            if (same_cid && (!c.has_token || same_token)) return true;
            fail(TransportError::ProtocolViolation, f.wire_type, now_us);
            return false;
        }
        // \~english One token for two IDs: 10.3.2 says it MUST NOT happen and MAY be a violation.
        // \~spanish Un testigo para dos identificadores: 10.3.2 dice que NO DEBE pasar y PUEDE ser una violacion.  \~
        if (same_cid || same_token) {
            fail(TransportError::ProtocolViolation, f.wire_type, now_us);
            return false;
        }
    }

    if (f.sequence < peer_retire_prior_to_) {
        // \~english Already retired by an earlier Retire Prior To: retire it at once (19.15).
        // \~spanish Ya retirado por un Retire Prior To anterior: se retira en el acto (19.15).  \~
        if (!owe_retire(f.sequence)) {
            fail(TransportError::ConnectionIdLimitError, f.wire_type, now_us);
            return false;
        }
        return true;
    }

    /* \~english
     * An increased Retire Prior To: the IDs below it stop being used and are
     * retired BEFORE the new one is added (5.1.2) -- which is what lets the
     * peer replace every ID without ever exceeding the limit.
     * \~spanish
     * Un Retire Prior To mayor: los identificadores por debajo dejan de usarse y
     * se retiran ANTES de anadir el nuevo (5.1.2) -- que es lo que deja al otro
     * reemplazarlos todos sin pasarse nunca del limite.
     * \~ */
    bool lost_current = false;
    if (f.retire_prior_to > peer_retire_prior_to_) {
        peer_retire_prior_to_ = f.retire_prior_to;
        for (PeerCid &c : peer_cids_) {
            if (!c.active || c.seq >= peer_retire_prior_to_) continue;
            if (c.seq == peer_seq_in_use_) lost_current = true;
            // \~english Another path that sent with it needs a new one before it sends again.
            // \~spanish Otro camino que mandaba con el necesita uno nuevo antes de volver a mandar.  \~
            for (PathState &path : paths_)
                if (path.used && path.peer_seq == c.seq) path.peer_seq = kNever;
            c.active = false;
            ++cid_counts_.retired;
            if (!owe_retire(c.seq)) {
                fail(TransportError::ConnectionIdLimitError, f.wire_type, now_us);
                return false;
            }
        }
    }

    PeerCid *slot = nullptr;
    for (PeerCid &c : peer_cids_)
        if (!c.active) {
            slot = &c;
            break;
        }
    if (slot == nullptr) {
        fail(TransportError::ConnectionIdLimitError, f.wire_type, now_us);
        return false;
    }
    slot->seq = f.sequence;
    slot->len = static_cast<uint8_t>(f.data.len);
    util::vesta_memcpy_noinline(slot->cid, cid, f.data.len);
    util::vesta_memcpy_noinline(slot->token, token, kResetTokenSize);
    slot->has_token = true;
    slot->used = false;
    slot->active = true;
    ++cid_counts_.received;

    /* \~english
     * The one in use was retired: move to one no other path has used (9.5),
     * or, if there is none, to the lowest that is left.
     * \~spanish
     * Se retiro el que estaba en uso: se pasa a uno que no haya usado ningun
     * otro camino (9.5), o, si no hay, al mas bajo que quede.
     * \~ */
    if (lost_current) {
        PeerCid *next = unused_peer_cid();
        if (next == nullptr)
            for (PeerCid &c : peer_cids_)
                if (c.active && (next == nullptr || c.seq < next->seq)) next = &c;
        if (next != nullptr) use_peer_cid(*next);
    }

    // \~english After adding and retiring, the peer may not have handed out more than allowed (5.1.1).
    // \~spanish Tras anadir y retirar, el otro no puede haber repartido mas de lo permitido (5.1.1).  \~
    size_t active = 0;
    for (const PeerCid &c : peer_cids_)
        if (c.active) ++active;
    if (active > cfg_.active_cid_limit) {
        fail(TransportError::ConnectionIdLimitError, f.wire_type, now_us);
        return false;
    }
    return true;
}

bool Connection::on_retire_connection_id(const Frame &f, uint64_t now_us) noexcept {
    /* \~english
     * 19.16: an end that gave a zero-length ID MUST take any RETIRE as a
     * violation; so is a number above any sent to the peer -- SENT, not just
     * issued: one still waiting to go out cannot be retired yet -- and the ID
     * this very packet came to.
     * \~spanish
     * 19.16: un extremo que dio un identificador de longitud cero DEBE tomar
     * cualquier RETIRE como violacion; tambien un numero por encima de todos los
     * mandados al otro -- MANDADOS, no solo emitidos: uno que aun espera salir no
     * se puede retirar todavia -- y el identificador al que llego este mismo
     * paquete.
     * \~ */
    if (cfg_.local_cid_len == 0 || f.sequence > max_sent_local_seq_) {
        fail(TransportError::ProtocolViolation, f.wire_type, now_us);
        return false;
    }
    for (LocalCid &l : local_cids_) {
        if (!l.active || l.seq != f.sequence) continue;
        if (packet_dcid_ != nullptr && packet_dcid_len_ == cfg_.local_cid_len &&
            bytes_equal(l.cid, packet_dcid_, packet_dcid_len_)) {
            fail(TransportError::ProtocolViolation, f.wire_type, now_us);
            return false;
        }
        l.active = false;
        l.owed = false;
        ++cid_counts_.retired_by_peer;
        top_up_cids();
        return true;
    }
    // \~english Already retired: a retransmission.  \~spanish Ya retirado: una retransmision.  \~
    return true;
}

bool Connection::check_stateless_reset(const uint8_t *tail, const Address &from) const noexcept {
    /* \~english
     * Only the tokens of IDs packets were sent to, not retired, and sent to
     * the address this datagram came from: 10.3.1 compares "with all
     * stateless reset tokens associated with the remote address on which the
     * datagram was received".
     * \~spanish
     * Solo los testigos de identificadores a los que se mandaron paquetes, sin
     * retirar, y mandados a la direccion de la que llego este datagrama: 10.3.1
     * compara "con todos los testigos asociados a la direccion remota por la que
     * se recibio el datagrama".
     * \~ */
    // \~english Every candidate compared in full, in constant time: no early exit to time.
    // \~spanish Cada candidato comparado entero, en tiempo constante: sin salida temprana que medir.  \~
    bool hit = false;
    for (const PeerCid &c : peer_cids_) {
        if (!c.active || !c.used || !c.has_token) continue;
        bool sent_there = false;
        for (const PathState &p : paths_)
            if (p.used && p.peer_seq == c.seq && same_address(p.addr.peer, from)) sent_there = true;
        if (sent_there) hit = bytes_equal(c.token, tail, kResetTokenSize) || hit;
    }
    return hit;
}

void Connection::discard_keys(Space s, uint64_t now_us) noexcept {
    Keys &k = keys_[idx(s)];
    if (!k.have) return;
    forget_keys(crypto_, k.read);
    forget_keys(crypto_, k.write);
    if (s == Space::Application) forget_one_rtt();
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
    // \~english Only what was really read: an abandoned stream gave its bytes back already.
    // \~spanish Solo lo que de verdad se leyo: un flujo abandonado ya devolvio sus bytes.  \~
    recv_flow_.on_consumed(s.recv->consume(n));
}

bool Connection::stop_receiving(Stream &s, uint64_t code) noexcept {
    if (s.recv == nullptr) return false;
    uint64_t released = 0;
    const bool owed = s.recv->stop(code, released);
    recv_flow_.on_consumed(released);
    return owed;
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

bool Connection::keep_for_later(const uint8_t *p, size_t n, Space s, Ecn ecn, bool early) noexcept {
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
        q.path = rx_addr_;
        q.arrived_us = arrival_us_;
        q.len = static_cast<uint16_t>(n);
        q.space = static_cast<uint8_t>(s);
        q.ecn = ecn;
        q.early = early;
        q.used = true;
        return true;
    }
    return false;
}

void Connection::replay(Space s, uint64_t now_us, bool early) noexcept {
    if (pending_ == nullptr || !(early ? early_have_ : can_open(s))) return;

    HeaderContext ctx;
    ctx.short_dcid_len = cfg_.local_cid_len;
    // \~english Kept packets passed the size check when they arrived; their datagram is gone.
    // \~spanish Los paquetes guardados pasaron la comprobacion de tamano al llegar; su datagrama ya no esta.  \~
    datagram_len_ = static_cast<size_t>(-1);
    for (size_t i = 0; i < kPendingPackets; ++i) {
        Pending &q = pending_[i];
        if (!q.used || q.space != static_cast<uint8_t>(s) || q.early != early) continue;

        // \~english Freed first: processing it may keep another one in its place.
        // \~spanish Se libera antes: procesarlo puede guardar otro en su sitio.  \~
        q.used = false;
        PacketHeader h;
        if (parse_packet(q.bytes, q.len, ctx, h) != HeaderError::None) continue;
        ++drops_.buffered;
        // \~english Its ACK Delay counts from when it arrived, not from now (13.2.5).
        // \~spanish Su ACK Delay cuenta desde que llego, no desde ahora (13.2.5).  \~
        arrival_us_ = q.arrived_us;
        rx_addr_ = q.path;
        rx_path_ = find_path(q.path);
        process_packet(q.bytes, h, q.ecn, now_us);
    }
}

void Connection::restart_idle(uint64_t now_us) noexcept {
    // \~english Never shorter than three PTOs, or a slow path would time out mid-recovery (10.1).
    // \~spanish Nunca menos de tres PTO, o un camino lento caducaria en plena recuperacion (10.1).  \~
    // \~english Zero is no timeout at all: "if a max_idle_timeout is specified" (10.1), and 0 specifies none.
    // \~spanish Cero es ningun plazo: "si se especifica un max_idle_timeout" (10.1), y 0 no especifica ninguno.  \~
    if (cfg_.idle_timeout_us == 0) {
        idle_deadline_ = kNever;
        return;
    }
    idle_deadline_ = now_us + max64(cfg_.idle_timeout_us, 3 * pto_duration());
}

size_t Connection::amplification_budget(size_t path) const noexcept {
    /* \~english
     * 8: until an address is proven, three times what came from it -- per
     * address, so a migrated peer starts again from zero (9.3.1).  Never a
     * client's limit: it applies to answering an unproven address, not to
     * starting a connection or a migration (21.1.1.1).
     * \~spanish
     * 8: hasta probar una direccion, tres veces lo que llego de ella -- por
     * direccion, asi que un otro que migra empieza otra vez de cero (9.3.1).
     * Nunca es el limite de un cliente: se aplica a contestar a una direccion sin
     * probar, no a empezar una conexion ni una migracion (21.1.1.1).
     * \~ */
    const PathState &p = paths_[path];
    if (!cfg_.is_server || p.validated) return static_cast<size_t>(-1);
    const uint64_t allowed = 3 * p.bytes_in;
    return allowed > p.bytes_out ? static_cast<size_t>(allowed - p.bytes_out) : 0;
}

size_t Connection::find_path(const Path &p) const noexcept {
    for (size_t i = 0; i < kMaxPaths; ++i)
        if (paths_[i].used && same_path(paths_[i].addr, p)) return i;
    return kNoPath;
}

size_t Connection::claim_path(const Path &p, uint64_t now_us) noexcept {
    // \~english A free slot, or else the least recently used one that is neither in use nor the fallback.
    // \~spanish Un hueco libre, o si no el usado hace mas tiempo que no este en uso ni sea el de respaldo.  \~
    size_t pick = kNoPath;
    for (size_t i = 0; i < kMaxPaths && pick == kNoPath; ++i)
        if (!paths_[i].used) pick = i;
    if (pick == kNoPath)
        for (size_t i = 0; i < kMaxPaths; ++i) {
            if (i == active_ || i == fallback_) continue;
            if (pick == kNoPath || paths_[i].last_used < paths_[pick].last_used) pick = i;
        }
    free_path(pick);
    PathState &slot = paths_[pick];
    slot.addr = p;
    slot.used = true;
    slot.last_used = now_us;
    return pick;
}

void Connection::free_path(size_t i) noexcept {
    /* \~english
     * The peer's ID it sent with is retired, unless another path still uses
     * it: once sent to this address it may not go to another (9.5), so
     * keeping it would only use up the peer's room.
     * \~spanish
     * El identificador del otro con el que mandaba se retira, salvo que otro
     * camino lo siga usando: mandado ya a esta direccion no puede ir a otra
     * (9.5), asi que guardarlo solo gastaria el sitio del otro.
     * \~ */
    const uint64_t seq = paths_[i].peer_seq;
    bool shared = false;
    for (size_t j = 0; j < kMaxPaths; ++j)
        if (j != i && paths_[j].used && paths_[j].peer_seq == seq) shared = true;
    PeerCid *c = seq == kNever ? nullptr : peer_cid_by_seq(seq);
    if (c != nullptr && !shared && seq != peer_seq_in_use_ && owe_retire(seq)) {
        c->active = false;
        ++cid_counts_.retired;
    }
    if (i == fallback_) fallback_ = kNoPath;
    paths_[i] = PathState{};
}

Connection::PeerCid *Connection::unused_peer_cid() noexcept {
    PeerCid *best = nullptr;
    for (PeerCid &c : peer_cids_)
        if (c.active && !c.used && (best == nullptr || c.seq < best->seq)) best = &c;
    return best;
}

bool Connection::assign_peer_cid(size_t i, bool may_share) noexcept {
    PathState &p = paths_[i];
    // \~english A zero-length ID is the same everywhere: there is nothing to choose.
    // \~spanish Un identificador de longitud cero es el mismo en todas partes: no hay nada que elegir.  \~
    if (cfg_.peer_cid_len == 0) {
        p.peer_seq = peer_seq_in_use_;
        return true;
    }
    /* \~english
     * 9.5: a peer that reached this end on a new address with the same ID
     * it used before -- a NAT rebinding, not a move -- MAY go on being sent
     * that path's ID.  Anything else gets one never used anywhere.
     * \~spanish
     * 9.5: a un otro que llego a este extremo desde una direccion nueva con el
     * mismo identificador que antes -- un cambio de NAT, no una mudanza -- PUEDE
     * seguir mandandosele el identificador de aquel camino.  Cualquier otro caso
     * recibe uno no usado en ningun sitio.
     * \~ */
    if (may_share && p.local_seq_seen != kNever)
        for (size_t j = 0; j < kMaxPaths; ++j) {
            const PathState &q = paths_[j];
            if (j == i || !q.used || q.peer_seq == kNever || q.local_seq_seen != p.local_seq_seen) continue;
            p.peer_seq = q.peer_seq;
            return true;
        }
    PeerCid *c = unused_peer_cid();
    if (c == nullptr) return false;
    c->used = true;
    p.peer_seq = c->seq;
    return true;
}

uint64_t Connection::local_seq_of(const uint8_t *cid, size_t len) const noexcept {
    if (len != cfg_.local_cid_len) return kNever;
    for (const LocalCid &l : local_cids_)
        if (l.active && bytes_equal(l.cid, cid, len)) return l.seq;
    return kNever;
}

uint64_t Connection::initial_pto() const noexcept {
    // \~english The PTO of a path with no sample yet: kInitialRtt (RFC 9002, 6.2.2).
    // \~spanish El PTO de un camino aun sin muestra: kInitialRtt (RFC 9002, 6.2.2).  \~
    return kInitialRttUs + max64(4 * (kInitialRttUs / 2), kGranularityUs) + cfg_.recovery.max_ack_delay_us;
}

bool Connection::start_validation(size_t i, uint64_t now_us) noexcept {
    /* \~english
     * 8.2.4: abandoned after three times the larger of the current PTO and
     * a new path's; challenges repeated no faster than the PTO, doubling
     * each time (8.2.1, 9.4).  Each challenge carries new data.
     * \~spanish
     * 8.2.4: se abandona tras tres veces el mayor del PTO actual y el de un
     * camino nuevo; los desafios se repiten no mas deprisa que el PTO, doblando
     * cada vez (8.2.1, 9.4).  Cada desafio lleva datos nuevos.
     * \~ */
    PathState &p = paths_[i];
    const uint64_t pto = max64(pto_duration(), initial_pto());
    p.challenging = true;
    p.challenge_owed = true;
    p.challenges = 0;
    p.challenge_interval = pto;
    p.next_challenge_at = kNever;
    p.validation_deadline = now_us + 3 * pto;
    return true;
}

void Connection::on_path_response(const uint8_t *data, uint64_t now_us) noexcept {
    // \~english An answer on any path validates the path its challenge went on (8.2.3).
    // \~spanish Una respuesta por cualquier camino valida el camino por el que fue su desafio (8.2.3).  \~
    for (size_t i = 0; i < kMaxPaths; ++i) {
        PathState &p = paths_[i];
        if (!p.used || !p.challenging) continue;
        const size_t kept = p.challenges < kChallengesKept ? p.challenges : kChallengesKept;
        for (size_t k = 0; k < kept; ++k)
            if (bytes_equal(p.challenge[k], data, kPathDataSize)) {
                path_validated(i, p.challenge_full[k], now_us);
                return;
            }
    }
    // \~english 19.18 allows PROTOCOL_VIOLATION; a late answer to an abandoned check is not worth it.
    // \~spanish 19.18 permite PROTOCOL_VIOLATION; una respuesta tardia a una comprobacion abandonada no lo merece.  \~
    ++path_counts_.stray_responses;
}

void Connection::path_validated(size_t i, bool full, uint64_t now_us) noexcept {
    PathState &p = paths_[i];
    p.validated = true;
    p.challenging = false;
    p.challenge_owed = false;
    p.challenges = 0;
    p.next_challenge_at = kNever;
    p.validation_deadline = kNever;
    ++path_counts_.validated;

    // \~english An answer to a challenge under 1200 bytes proves the address, not the MTU: once more, full size (8.2.3).
    // \~spanish La respuesta a un desafio de menos de 1200 bytes prueba la direccion, no la MTU: otra vez, a tamano completo (8.2.3).  \~
    if (!full) {
        ++path_counts_.revalidated_mtu;
        start_validation(i, now_us);
    }

    if (i != active_) return;
    recovery_.set_amplification_blocked(false, now_us);
    // \~english The peer's new address is proven: congestion control and RTT start over on it (9.4).
    // \~spanish La direccion nueva del otro esta probada: control de congestion y RTT empiezan de cero en ella (9.4).  \~
    if (cc_path_ != i) {
        recovery_.on_new_path(now_us);
        cc_path_ = i;
        ++path_counts_.congestion_resets;
    }
}

void Connection::switch_to(size_t i, uint64_t now_us) noexcept {
    const size_t old = active_;
    if (i == old) return;
    // \~english The last proven path is where to go back if this one is not proven (9.3.2).
    // \~spanish El ultimo camino probado es a donde volver si este no se prueba (9.3.2).  \~
    if (paths_[old].validated) fallback_ = old;
    active_ = i;
    PathState &p = paths_[i];

    if (p.peer_seq == kNever && !assign_peer_cid(i, cfg_.is_server)) ++path_counts_.no_connection_id;
    if (p.peer_seq != kNever)
        if (PeerCid *c = peer_cid_by_seq(p.peer_seq)) use_peer_cid(*c);

    if (!p.validated && !p.challenging) start_validation(i, now_us);
    if (p.validated && cc_path_ != i) {
        recovery_.on_new_path(now_us);
        cc_path_ = i;
        ++path_counts_.congestion_resets;
    }
    const size_t budget = amplification_budget(i);
    recovery_.set_amplification_blocked(budget != static_cast<size_t>(-1) && budget < 64, now_us);
}

void Connection::run_path_timers(uint64_t now_us) noexcept {
    for (size_t i = 0; i < kMaxPaths; ++i) {
        PathState &p = paths_[i];
        if (!p.used || !p.challenging) continue;
        if (now_us < p.validation_deadline) {
            if (!p.challenge_owed && p.next_challenge_at <= now_us) {
                p.challenge_owed = true;
                p.next_challenge_at = kNever;
            }
            continue;
        }

        // \~english Time is up: the path is unusable (8.2.4).
        // \~spanish Se acabo el tiempo: el camino no sirve (8.2.4).  \~
        p.challenging = false;
        p.challenge_owed = false;
        p.challenges = 0;
        p.next_challenge_at = kNever;
        p.validation_deadline = kNever;
        ++path_counts_.abandoned;

        /* \~english
         * An address proven before and only checked again -- its MTU, or the
         * old path after a migration (9.3.3) -- stays proven: it is still
         * "the last validated peer address" 9.3.2 falls back to.
         * \~spanish
         * Una direccion probada antes y solo comprobada otra vez -- su MTU, o el
         * camino viejo tras una migracion (9.3.3) -- sigue probada: sigue siendo
         * "la ultima direccion validada del otro" a la que vuelve 9.3.2.
         * \~ */
        if (p.validated) continue;
        if (i == active_) {
            /* \~english
             * 9.3.2: back to the last validated peer address -- or, with none,
             * close silently, discarding all state.
             * \~spanish
             * 9.3.2: de vuelta a la ultima direccion validada del otro -- o, si no
             * hay ninguna, cerrar en silencio, tirando todo el estado.
             * \~ */
            if (fallback_ == kNoPath || !paths_[fallback_].validated) {
                ended(EndReason::NoValidatedPath);
                state_ = ConnState::Closed;
                return;
            }
            ++path_counts_.reverted;
            const size_t back = fallback_;
            fallback_ = kNoPath;
            switch_to(back, now_us);
        }
        free_path(i);
    }
}

uint64_t Connection::path_timer() const noexcept {
    uint64_t t = kNever;
    for (const PathState &p : paths_) {
        if (!p.used || !p.challenging) continue;
        t = min64(t, p.validation_deadline);
        if (!p.challenge_owed) t = min64(t, p.next_challenge_at);
    }
    return t;
}

Migration Connection::check_migration(const Path &p) const noexcept {
    if (cfg_.is_server) return Migration::NotClient;
    if (!confirmed_) return Migration::NotConfirmed;
    if (cfg_.peer_disable_active_migration) return Migration::Disabled;
    if (cfg_.peer_cid_len == 0) return Migration::ZeroLengthId;
    if (!same_address(p.peer, paths_[active_].addr.peer)) return Migration::UnknownServer;
    if (same_path(p, paths_[active_].addr)) return Migration::SamePath;
    return Migration::Started;
}

Migration Connection::probe_path(const Path &path, uint64_t now_us) noexcept {
    const Migration m = check_migration(path);
    if (m != Migration::Started) return m;
    size_t i = find_path(path);
    if (i == kNoPath) {
        // \~english A new local address needs an ID of the peer's never used before (9.5).
        // \~spanish Una direccion local nueva necesita un identificador del otro nunca usado antes (9.5).  \~
        if (unused_peer_cid() == nullptr) return Migration::NoConnectionId;
        i = claim_path(path, now_us);
        assign_peer_cid(i, false);
    }
    if (!paths_[i].challenging) start_validation(i, now_us);
    return Migration::Started;
}

Migration Connection::migrate(const Path &path, uint64_t now_us) noexcept {
    const Migration m = check_migration(path);
    if (m != Migration::Started) return m;
    size_t i = find_path(path);
    if (i == kNoPath) {
        if (unused_peer_cid() == nullptr) return Migration::NoConnectionId;
        i = claim_path(path, now_us);
    }
    if (paths_[i].peer_seq == kNever && !assign_peer_cid(i, false)) return Migration::NoConnectionId;
    ++path_counts_.migrations;
    switch_to(i, now_us);
    return Migration::Started;
}

void Connection::close(uint64_t code, bool application, uint64_t trigger_frame,
                       uint64_t now_us) noexcept {
    if (state_ != ConnState::Active) return;
    ended(EndReason::Closed);
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
        case kRecRetireCid:
            // \~english The peer has the retirement: it no longer counts against the room (5.1.2).
            // \~spanish El otro tiene la retirada: ya no cuenta contra el sitio (5.1.2).  \~
            if (retire_outstanding_ != 0) --retire_outstanding_;
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
        if (f.kind == kRecStream || f.kind == kRecResetStream || f.kind == kRecMaxStreamData ||
            f.kind == kRecStopSending)
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
        case kRecStopSending:
            // \~english Another one is expected if it was lost (3.5); stop_pending() decides if it still matters.
            // \~spanish Se espera otro si se perdio (3.5); stop_pending() decide si aun importa.  \~
            if (st != nullptr && st->recv != nullptr) st->recv->on_stop_lost();
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
        case kRecNewCid:
            // \~english Sent again only if the ID is still live: one retired meanwhile needs nothing.
            // \~spanish Se manda otra vez solo si el identificador sigue vivo: uno retirado entretanto no necesita nada.  \~
            for (LocalCid &l : local_cids_)
                if (l.active && l.seq == f.id) l.owed = true;
            break;
        case kRecRetireCid:
            requeue_retire(f.id);
            break;
        // \~english A lost *_BLOCKED is said again if still blocked: forgetting it was sent is enough.
        // \~spanish Un *_BLOCKED perdido se repite si sigue bloqueado: basta con olvidar que se mando.  \~
        case kRecDataBlocked:
            data_blocked_at_ = kNever;
            break;
        case kRecStreamDataBlocked:
            if (Stream *b = streams_.find(f.id)) b->blocked_sent_at = kNever;
            break;
        case kRecStreamsBlocked:
            streams_blocked_at_[f.id != 0 ? 1 : 0] = kNever;
            break;
        default:
            break;
        }
    }
    rec->tag = 0;
}

void Connection::on_datagram(const Path &path, uint8_t *data, size_t n, Ecn ecn,
                             uint64_t now_us) noexcept {
    if (state_ == ConnState::Closed) return;
    bytes_in_ += n;
    rx_addr_ = path;
    rx_path_ = find_path(path);

    if (rx_path_ == kNoPath) {
        /* \~english
         * An address never seen.  A client MUST discard it: the server does
         * not move (9, 9.6).  A server lets the peer move once the handshake
         * is confirmed -- the addresses are stable until then (9) -- and not
         * at all if it said so (disable_active_migration), dropping without a
         * stateless reset in both cases (9).  The datagram only gets a path if
         * one of its packets opens: bytes nobody can authenticate take no
         * place in the table.
         * \~spanish
         * Una direccion nunca vista.  Un cliente DEBE descartarla: el servidor no
         * se mueve (9, 9.6).  Un servidor deja moverse al otro en cuanto se
         * confirma el saludo -- hasta entonces las direcciones son estables (9) --,
         * y nunca si dijo que no (disable_active_migration), tirando sin reinicio
         * sin estado en los dos casos (9).  El datagrama solo recibe un camino si
         * se abre alguno de sus paquetes: bytes que nadie puede autenticar no
         * ocupan sitio en la tabla.
         * \~ */
        if (!cfg_.is_server) {
            ++path_counts_.unknown_address;
            return;
        }
        if (!confirmed_) {
            ++path_counts_.before_confirmed;
            return;
        }
        if (cfg_.disable_active_migration) {
            ++path_counts_.migration_disabled;
            return;
        }
        if (state_ != ConnState::Active) {
            ++drops_.after_close;
            return;
        }
    } else {
        // \~english Every byte counts toward what may be sent back to that address, processed or not (8).
        // \~spanish Cada byte cuenta para lo que se puede devolver a esa direccion, se procese o no (8).  \~
        paths_[rx_path_].bytes_in += n;
    }
    if (state_ == ConnState::Draining) {
        ++drops_.after_close;
        return;
    }

    HeaderContext ctx;
    ctx.short_dcid_len = cfg_.local_cid_len;

    /* \~english
     * A stateless reset looks like a packet that fails.  Its tail is kept
     * before processing -- unprotecting works in place -- and compared when
     * the packet could not be associated or decrypted, which is when 10.3.1
     * says it MUST be; whatever the header form, since any datagram ending in
     * a valid token is a reset (10.3).
     * \~spanish
     * Un reinicio sin estado parece un paquete que falla.  Su cola se guarda
     * antes de procesar -- desproteger trabaja en su sitio -- y se compara cuando
     * el paquete no se pudo asociar ni descifrar, que es cuando 10.3.1 dice que
     * DEBE hacerse; sea cual sea la forma de la cabecera, porque todo datagrama
     * que acaba en un testigo valido es un reinicio (10.3).
     * \~ */
    const bool maybe_reset = n >= kMinStatelessReset;
    datagram_len_ = n;
    uint8_t tail[kResetTokenSize];
    if (maybe_reset) util::vesta_memcpy(tail, data + n - kResetTokenSize, kResetTokenSize);
    // \~english Whether the first packet failed -- for any reason: it is what makes the comparison a MUST (10.3.1).
    // \~spanish Si el primer paquete fallo -- por la razon que sea: es lo que hace de la comparacion un DEBE (10.3.1).  \~
    bool first_failed = true;
    arrival_us_ = now_us;

    size_t pos = 0;
    const uint8_t *first_dcid = nullptr;
    size_t first_dcid_len = 0;
    while (pos < n && state_ != ConnState::Closed && state_ != ConnState::Draining) {
        PacketHeader h;
        if (parse_packet(data + pos, n - pos, ctx, h) != HeaderError::None) {
            // \~english Without a header there is no way to find the next packet: the rest goes too.
            // \~spanish Sin cabecera no hay forma de encontrar el paquete siguiente: se va tambien el resto.  \~
            ++drops_.bad_header;
            break;
        }
        /* \~english
         * 12.2: "Receivers SHOULD ignore any subsequent packets with a
         * different Destination Connection ID than the first packet in the
         * datagram" -- a sender MUST NOT coalesce them, so one that does is
         * not the peer.
         * \~spanish
         * 12.2: los receptores DEBERIAN ignorar los paquetes siguientes con un
         * Destination Connection ID distinto del primero del datagrama -- un
         * emisor NO DEBE pegarlos, asi que uno que lo hace no es el otro extremo.
         * \~ */
        const uint8_t *dcid = data + pos + h.dcid.off;
        if (first_dcid == nullptr) {
            first_dcid = dcid;
            first_dcid_len = h.dcid.len;
        } else if (h.dcid.len != first_dcid_len || !bytes_equal(dcid, first_dcid, first_dcid_len)) {
            ++drops_.wrong_cid;
            pos += h.size;
            continue;
        }
        const bool processed = process_packet(data + pos, h, ecn, now_us);
        if (pos == 0) first_failed = !processed;
        pos += h.size;
    }

    // \~english The peer has no such connection: drain, and send nothing more (10.3.1).
    // \~spanish El otro no tiene esta conexion: drenar, y no mandar nada mas (10.3.1).  \~
    if (maybe_reset && first_failed && check_stateless_reset(tail, path.peer)) {
        closed_by_reset_ = true;
        ended(EndReason::StatelessReset);
        state_ = ConnState::Draining;
        close_deadline_ = now_us + 3 * pto_duration();
        return;
    }

    const size_t budget = amplification_budget(active_);
    if (budget != static_cast<size_t>(-1)) recovery_.set_amplification_blocked(budget == 0, now_us);

    /* \~english
     * RFC 9002, 6.2.2.1: when what arrived unblocks a server at its
     * amplification limit, "if the PTO timer is then set to a time in the
     * past, it is executed immediately" -- not left for whenever the host
     * next calls on_timer.
     * \~spanish
     * RFC 9002, 6.2.2.1: cuando lo que llego desbloquea a un servidor en su
     * limite de amplificacion, si el temporizador de PTO queda en el pasado, se
     * ejecuta en el acto -- no se deja para cuando el anfitrion llame a
     * on_timer.
     * \~ */
    if (state_ == ConnState::Active) run_loss_timer(now_us);
    streams_.collect();
}

void Connection::run_loss_timer(uint64_t now_us) noexcept {
    if (recovery_.timer() > now_us) return;
    const TimeoutAction a = recovery_.on_timeout(now_us, *this);
    if (a.kind == TimeoutAction::Probe) probe_owed_[idx(a.space)] = true;
}

bool Connection::process_packet(uint8_t *p, const PacketHeader &h, Ecn ecn,
                                uint64_t now_us) noexcept {
    /* \~english
     * 5.2.1: a client MUST discard a packet of another version than it
     * selected; a server committed to the client's version when it accepted
     * the Initial (5.2.2).  Before looking at the type: the type bits mean
     * different things in different versions (RFC 9369 renumbers them).
     * \~spanish
     * 5.2.1: un cliente DEBE descartar un paquete de otra version que la que
     * eligio; un servidor se comprometio con la version del cliente al aceptar el
     * Initial (5.2.2).  Antes de mirar el tipo: los bits de tipo significan cosas
     * distintas en versiones distintas (el RFC 9369 los renumera).
     * \~ */
    if (h.type != PacketType::OneRtt && h.type != PacketType::VersionNegotiation &&
        h.type != PacketType::UnsupportedVersion && h.version != cfg_.version) {
        ++drops_.wrong_version;
        return false;
    }

    Space s;
    bool early = false;
    switch (h.type) {
    case PacketType::Initial:   s = Space::Initial; break;
    case PacketType::Handshake: s = Space::Handshake; break;
    case PacketType::OneRtt:    s = Space::Application; break;
    case PacketType::ZeroRtt:
        // \~english A client never opens one (RFC 9001, 5.6): it MUST discard them.
        // \~spanish Un cliente nunca abre uno (RFC 9001, 5.6): DEBE descartarlos.  \~
        if (!cfg_.is_server) {
            ++drops_.early;
            return false;
        }
        // \~english 0-RTT and 1-RTT share the application space's numbering (17.2.3).
        // \~spanish 0-RTT y 1-RTT comparten la numeracion del espacio de aplicacion (17.2.3).  \~
        s = Space::Application;
        early = true;
        break;
    case PacketType::VersionNegotiation:
        process_version_negotiation(p, h);
        return false;
    case PacketType::Retry:
        process_retry(p, h, now_us);
        return false;
    default:
        // \~english An unknown version is the acceptor's business.  \~spanish Una version desconocida es cosa del acceptor.  \~
        ++drops_.unsupported;
        return false;
    }

    // \~english Addressed to this connection: our ID, or the original one on a client's Initial or 0-RTT.
    // \~spanish Dirigido a esta conexion: nuestro identificador, o el original en un Initial o 0-RTT del cliente.  \~
    const uint8_t *dcid = p + h.dcid.off;
    const bool ours = owns_cid(dcid, h.dcid.len);
    const bool original = cfg_.is_server && (s == Space::Initial || early) && h.dcid.len == odcid_len_ &&
                          bytes_equal(dcid, odcid_, odcid_len_);
    if (!ours && !original) {
        ++drops_.wrong_cid;
        return false;
    }

    /* \~english
     * 7.2: once the ID is set from the first long header, one naming another
     * source is dropped -- by a client for any packet ("any subsequent packet
     * ... with a different Source Connection ID"), by a server for Initials
     * ("if subsequent Initial packets include a different Source Connection
     * ID, they MUST be discarded").
     * \~spanish
     * 7.2: una vez fijado el identificador por la primera cabecera larga, una que
     * nombra otro origen se tira -- un cliente, cualquier paquete; un servidor,
     * los Initial ("si Initial posteriores incluyen un Source Connection ID
     * distinto, DEBEN descartarse").
     * \~ */
    if (peer_cid_known_ && s != Space::Application && (!cfg_.is_server || s == Space::Initial) &&
        (h.scid.len != peer_cids_[0].len ||
         !bytes_equal(p + h.scid.off, peer_cids_[0].cid, peer_cids_[0].len))) {
        ++drops_.changed_source;
        return false;
    }

    // \~english 14.1: a server MUST discard an Initial in a datagram under 1200 bytes.
    // \~spanish 14.1: un servidor DEBE descartar un Initial en un datagrama de menos de 1200 bytes.  \~
    if (cfg_.is_server && s == Space::Initial && datagram_len_ < kMinInitial) {
        ++drops_.small_initial;
        return false;
    }
    // \~english 17.2.2: a server's Initial carries no token; a client MUST discard one that does.
    // \~spanish 17.2.2: el Initial de un servidor no lleva testigo; un cliente DEBE descartar uno que lo lleve.  \~
    if (!cfg_.is_server && s == Space::Initial && h.token.len != 0) {
        ++drops_.initial_with_token;
        return false;
    }

    /* \~english
     * Closing: a packet attributed to the connection gets the
     * CONNECTION_CLOSE again, and nothing else (10.2.1) -- before looking at
     * keys, since a packet this end can no longer open is still the peer
     * asking.  At a limited rate (10.2.1, SHOULD): the 1st, 2nd, 4th, 8th...
     * packet is answered, so a peer that keeps sending cannot make this end
     * answer each one.
     * \~spanish
     * Cerrando: un paquete atribuido a la conexion recibe otra vez el
     * CONNECTION_CLOSE, y nada mas (10.2.1) -- antes de mirar las claves, porque
     * un paquete que este extremo ya no puede abrir sigue siendo el otro
     * preguntando.  A ritmo limitado (10.2.1, DEBERIA): se contesta al 1o, 2o, 4o,
     * 8o... paquete, asi que un otro que sigue mandando no consigue que este
     * extremo le conteste a cada uno.
     * \~ */
    if (state_ == ConnState::Closing) {
        ++close_rx_;
        if ((close_rx_ & (close_rx_ - 1)) == 0) close_owed_ = true;
        ++drops_.after_close;
        return false;
    }

    Keys &k = keys_[idx(s)];
    if (early && !early_have_) {
        // \~english 0-RTT keys still to come: kept like any other.  Turned down, or gone: never opened (4.6.2, 4.9.3).
        // \~spanish Claves 0-RTT aun por llegar: se guarda como cualquier otro.  Rechazado, o ya sin claves: nunca se abre (4.6.2, 4.9.3).  \~
        if (early_gone_ || !keep_for_later(p, h.size, s, ecn, true)) ++drops_.early;
        return false;
    }
    if (!early && !can_open(s)) {
        // \~english Keys still to come: keep it (few, bounded).  Keys gone: it is late.
        // \~spanish Claves aun por llegar: se guarda (pocos, acotado).  Claves ya tiradas: llega tarde.  \~
        if (discarded_[idx(s)] || !keep_for_later(p, h.size, s, ecn)) ++drops_.no_keys;
        return false;
    }

    Unprotected u;
    Opened r;
    if (early) {
        const Unprotect x =
            unprotect_packet(crypto_, early_keys_, p, h, acks_[idx(Space::Application)].expected_pn(), u);
        r = x == Unprotect::Ok                ? Opened::Ok
            : x == Unprotect::Forged          ? Opened::Forged
            : x == Unprotect::ReservedBitsSet ? Opened::ReservedBits
                                              : Opened::Failed;
    } else if (s == Space::Application) {
        r = open_one_rtt(p, h, u, now_us);
    } else {
        const Unprotect x = unprotect_packet(crypto_, k.read, p, h, acks_[idx(s)].expected_pn(), u);
        r = x == Unprotect::Ok                ? Opened::Ok
            : x == Unprotect::Forged          ? Opened::Forged
            : x == Unprotect::ReservedBitsSet ? Opened::ReservedBits
                                              : Opened::Failed;
    }
    if (r == Opened::Forged) {
        /* \~english
         * Every failed authentication counts against the AEAD's integrity
         * limit, across all keys; past it the connection MUST close and open
         * nothing more (RFC 9001, 6.6).
         * \~spanish
         * Cada autenticacion fallida cuenta contra el limite de integridad del
         * AEAD, entre todas las claves; pasado el, la conexion DEBE cerrarse y no
         * abrir nada mas (RFC 9001, 6.6).
         * \~ */
        if (++drops_.forged > integrity_limit()) fail(TransportError::AeadLimitReached, 0, now_us);
        return false;
    }
    if (r == Opened::Failed) {
        fail(TransportError::InternalError, 0, now_us);
        return false;
    }
    if (r == Opened::ReservedBits) {
        fail(TransportError::ProtocolViolation, 0, now_us);
        return false;
    }
    if (r == Opened::KeyUpdateViolation) {
        fail(TransportError::KeyUpdateError, 0, now_us);
        return false;
    }
    if (acks_[idx(s)].classify(u.pn) != Receipt::New) {
        ++drops_.duplicate;
        return false;
    }
    received_any_ = true;

    // \~english The peer's real ID comes with its first long header.
    // \~spanish El identificador de verdad del otro extremo llega con su primera cabecera larga.  \~
    if (!peer_cid_known_ && s != Space::Application && h.scid.len <= kMaxConnectionId) {
        learn_peer_cid(p + h.scid.off, h.scid.len);
        peer_cid_known_ = true;
    }

    // \~english RETIRE_CONNECTION_ID may not name the ID this packet came to (19.16).
    // \~spanish RETIRE_CONNECTION_ID no puede nombrar el identificador al que llego este paquete (19.16).  \~
    packet_dcid_ = dcid;
    packet_dcid_len_ = h.dcid.len;

    // \~english An authenticated packet from a new address: now it gets a path, with what came on it (8).
    // \~spanish Un paquete autenticado desde una direccion nueva: ahora recibe un camino, con lo que llego por el (8).  \~
    if (rx_path_ == kNoPath) {
        rx_path_ = claim_path(rx_addr_, now_us);
        if (datagram_len_ != static_cast<size_t>(-1)) paths_[rx_path_].bytes_in += datagram_len_;
    }

    bool eliciting = false;
    bool probing = true;
    if (!process_frames(s, p + u.payload.off, u.payload.len, h.type, eliciting, probing, now_us))
        return false;
    if (!on_packet_path(s, u.pn, probing, dcid, h.dcid.len, now_us)) return false;

    acks_[idx(s)].on_received(u.pn, eliciting, ecn, arrival_us_);
    restart_idle(now_us);
    sent_eliciting_since_receipt_ = false;

    /* \~english
     * 0-RTT keys at a server: kept a while after the first 1-RTT packet, for
     * 0-RTT ones reordered behind it, and gone three PTO later (RFC 9001,
     * 4.9.3).
     * \~spanish
     * Claves 0-RTT en un servidor: se guardan un rato tras el primer paquete
     * 1-RTT, para los 0-RTT reordenados detras, y se van tres PTO despues (RFC
     * 9001, 4.9.3).
     * \~ */
    if (early) ++early_opened_;
    if (!early && s == Space::Application && early_have_ && early_discard_at_ == kNever)
        early_discard_at_ = now_us + 3 * pto_duration();

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
        if (!paths_[rx_path_].validated) {
            paths_[rx_path_].validated = true;
            recovery_.set_amplification_blocked(false, now_us);
        }
        discard_keys(Space::Initial, now_us);
    }
    return true;
}

bool Connection::on_packet_path(Space s, uint64_t pn, bool probing, const uint8_t *dcid,
                                size_t dcid_len, uint64_t now_us) noexcept {
    PathState &p = paths_[rx_path_];
    p.last_used = now_us;
    // \~english Paths change only in 1-RTT: the handshake's addresses are fixed (9).
    // \~spanish Los caminos solo cambian en 1-RTT: las direcciones del saludo son fijas (9).  \~
    if (s != Space::Application) return true;
    const uint64_t seq = local_seq_of(dcid, dcid_len);
    if (seq != kNever) p.local_seq_seen = seq;

    if (probing) {
        // \~english 9.6.3: a server SHOULD validate a client address a probe came from.
        // \~spanish 9.6.3: un servidor DEBERIA validar la direccion de cliente de la que llego un sondeo.  \~
        if (cfg_.is_server && rx_path_ != active_ && !p.validated && !p.challenging)
            start_validation(rx_path_, now_us);
        return true;
    }

    // \~english Only the highest-numbered non-probing packet counts: a reordered one moves nothing (9.3).
    // \~spanish Solo cuenta el paquete no de sondeo de numero mas alto: uno reordenado no mueve nada (9.3).  \~
    if (largest_nonprobing_pn_ != kNever && pn <= largest_nonprobing_pn_) return true;
    largest_nonprobing_pn_ = pn;
    if (rx_path_ == active_ || !cfg_.is_server) return true;

    /* \~english
     * The client moved (9.3): everything goes to the new address from now
     * on, which is validated unless it already was -- and so is the one it
     * left, because an attacker forwarding copies looks exactly like this
     * and a challenge on the old path is what brings the real peer back
     * (9.3.3).
     * \~spanish
     * El cliente se movio (9.3): todo va a la direccion nueva desde ahora, que se
     * valida salvo que ya lo estuviera -- y tambien la que dejo, porque un
     * atacante que reenvia copias se ve exactamente asi y un desafio en el camino
     * viejo es lo que trae de vuelta al otro de verdad (9.3.3).
     * \~ */
    const size_t old = active_;
    ++path_counts_.peer_migrations;
    switch_to(rx_path_, now_us);
    if (paths_[old].used && !paths_[old].challenging) start_validation(old, now_us);
    return true;
}

void Connection::process_version_negotiation(const uint8_t *p, const PacketHeader &h) noexcept {
    // \~english Only a client starts a connection, so only a client is answered with one.
    // \~spanish Solo un cliente empieza una conexion, asi que solo a un cliente se le contesta con uno.  \~
    if (cfg_.is_server) {
        ++drops_.unsupported;
        return;
    }

    /* \~english
     * Believed only before anything else from the server (6.2): after that,
     * the server has shown it speaks this version, and a VN can only be
     * forged -- one that ended the connection would be an attack.
     * \~spanish
     * Solo se cree antes de cualquier otra cosa del servidor (6.2): despues, el
     * servidor ya demostro que habla esta version, y un VN solo puede ser
     * falsificado -- uno que acabara con la conexion seria un ataque.
     * \~ */
    if (received_any_ || retried_) {
        ++drops_.version_negotiation;
        return;
    }

    // \~english Both IDs echoed, swapped: an off-path attacker never saw them.
    // \~spanish Los dos identificadores devueltos, cruzados: un atacante fuera del camino no los vio.  \~
    if (h.dcid.len != cfg_.local_cid_len || !bytes_equal(p + h.dcid.off, cfg_.local_cid, h.dcid.len) ||
        h.scid.len != odcid_len_ || !bytes_equal(p + h.scid.off, odcid_, odcid_len_)) {
        ++drops_.wrong_cid;
        return;
    }

    const uint8_t *v = p + h.versions.off;
    const size_t count = h.versions.len / 4;
    for (size_t i = 0; i < count; ++i) {
        const uint32_t offered = static_cast<uint32_t>(v[4 * i]) << 24 |
                                 static_cast<uint32_t>(v[4 * i + 1]) << 16 |
                                 static_cast<uint32_t>(v[4 * i + 2]) << 8 | v[4 * i + 3];
        // \~english Listing the version in use contradicts itself: ignored (6.2).
        // \~spanish Listar la version en uso se contradice: se ignora (6.2).  \~
        if (offered == cfg_.version) {
            ++drops_.version_negotiation;
            offered_count_ = 0;
            return;
        }
        if (offered_count_ < kOfferedVersions) offered_[offered_count_] = offered;
        ++offered_count_;
    }

    // \~english No version in common: the attempt is abandoned, without a word (6.2).
    // \~spanish Ninguna version en comun: se abandona el intento, sin decir nada (6.2).  \~
    vn_received_ = true;
    ended(EndReason::VersionNegotiation);
    state_ = ConnState::Closed;
}

void Connection::process_retry(const uint8_t *p, const PacketHeader &h, uint64_t now_us) noexcept {
    if (cfg_.is_server) {
        ++drops_.unsupported;
        return;
    }

    // \~english One Retry per attempt, and none once the server has spoken (17.2.5.2).
    // \~spanish Un Retry por intento, y ninguno una vez que hablo el servidor (17.2.5.2).  \~
    if (received_any_ || retried_ || h.version != cfg_.version) {
        ++drops_.retry;
        return;
    }
    if (h.dcid.len != cfg_.local_cid_len || !bytes_equal(p + h.dcid.off, cfg_.local_cid, h.dcid.len)) {
        ++drops_.wrong_cid;
        return;
    }

    // \~english An empty token, or the server naming the ID being answered: not a Retry (17.2.5.2).
    // \~spanish Un testigo vacio, o el servidor con el identificador al que contesta: no es un Retry (17.2.5.2).  \~
    if (h.token.len == 0 || h.scid.len > kMaxConnectionId ||
        (h.scid.len == cfg_.peer_cid_len && bytes_equal(p + h.scid.off, cfg_.peer_cid, h.scid.len))) {
        ++drops_.retry;
        return;
    }

    // \~english The tag proves the server saw the first Initial (RFC 9001, 5.8).
    // \~spanish La marca prueba que el servidor vio el primer Initial (RFC 9001, 5.8).  \~
    uint8_t scratch[1 + kMaxConnectionId + 1500];
    uint8_t tag[kRetryTagSize];
    if (!retry_tag(crypto_, cfg_.version, odcid_, odcid_len_, p, h.tag.off, scratch, sizeof scratch,
                   tag)) {
        fail(TransportError::InternalError, 0, now_us);
        return;
    }
    if (!bytes_equal(tag, p + h.tag.off, kRetryTagSize)) {
        ++drops_.forged;
        return;
    }

    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::Dense);
    token_ = static_cast<uint8_t *>(util::host_alloc(h.token.len));
    if (token_ == nullptr) {
        fail(TransportError::InternalError, 0, now_us);
        return;
    }
    util::vesta_memcpy(token_, p + h.token.off, h.token.len);
    token_len_ = h.token.len;

    /* \~english
     * From now on the client speaks to the Retry's ID, and the Initial keys
     * come from it; the original ID stays for the transport parameters.
     * Whatever was sent goes out again, with the token.
     * \~spanish
     * Desde ahora el cliente le habla al identificador del Retry, y las claves
     * Initial salen de el; el original se queda para los parametros de
     * transporte.  Lo que se mando sale otra vez, con el testigo.
     * \~ */
    // \~english Out of line: at most once per connection, and at most twenty bytes.
    // \~spanish Fuera de linea: como mucho una vez por conexion, y como mucho veinte bytes.  \~
    util::vesta_memcpy_noinline(retry_scid_, p + h.scid.off, h.scid.len);
    retry_scid_len_ = h.scid.len;
    learn_peer_cid(p + h.scid.off, h.scid.len);
    if (!derive_initial_keys(retry_scid_, retry_scid_len_)) {
        fail(TransportError::InternalError, 0, now_us);
        return;
    }
    retried_ = true;
    recovery_.on_retry(now_us, *this);
    // \~english 0-RTT sent before the Retry was thrown away by the server: sent again, with new numbers (17.2.3).
    // \~spanish El 0-RTT mandado antes del Retry lo tiro el servidor: se manda otra vez, con numeros nuevos (17.2.3).  \~
    recovery_.drop_early(now_us, this);
}

bool Connection::process_frames(Space s, const uint8_t *payload, size_t n, PacketType type,
                                bool &eliciting, bool &probing, uint64_t now_us) noexcept {
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
        // \~english 9.1: these four are probing frames; a packet with any other is non-probing.
        // \~spanish 9.1: estas cuatro son tramas de sondeo; un paquete con cualquier otra no es de sondeo.  \~
        if (f.type != FrameType::PathChallenge && f.type != FrameType::PathResponse &&
            f.type != FrameType::NewConnectionId && f.type != FrameType::Padding)
            probing = false;

        switch (f.type) {
        case FrameType::Padding:
        case FrameType::Ping:
        case FrameType::DataBlocked:
        case FrameType::StreamsBlocked:
        case FrameType::NewToken:
            break;

        case FrameType::PathResponse:
            on_path_response(payload + f.data.off, now_us);
            break;

        case FrameType::NewConnectionId:
            if (!on_new_connection_id(f, payload, now_us)) return false;
            break;

        case FrameType::Ack:
            if (recovery_.on_ack_received(s, f, payload, now_us, *this) != AckResult::Ok) {
                fail(TransportError::ProtocolViolation, f.wire_type, now_us);
                return false;
            }
            // \~english A client's address is proven once a Handshake packet is acknowledged.
            // \~spanish La direccion de un cliente queda probada al confirmarse un paquete Handshake.  \~
            if (!cfg_.is_server && s == Space::Handshake) recovery_.set_peer_address_validated(now_us);
            // \~english The first ACK of a packet of this write phase: the clock of 6.5 starts here.
            // \~spanish El primer ACK de un paquete de esta fase de escritura: aqui empieza el reloj de 6.5.  \~
            if (s == Space::Application && one_rtt_.phase_acked_at == kNever &&
                one_rtt_.first_sent_pn != kNever &&
                recovery_.largest_acked(Space::Application) != kNever &&
                recovery_.largest_acked(Space::Application) >= one_rtt_.first_sent_pn)
                one_rtt_.phase_acked_at = now_us;
            break;

        case FrameType::Crypto: {
            uint64_t fresh = 0;
            // \~english The handshake never abandons its stream: nothing is ever released here.
            // \~spanish El saludo nunca abandona su flujo: aqui nunca se libera nada.  \~
            uint64_t unused = 0;
            const StreamError e = crypto_recv_[idx(s)]->on_data(
                f.offset, payload + f.data.off, f.data.len, false, fresh, unused);
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
                e = st->recv->on_data(f.offset, payload + f.data.off, f.data.len, f.fin, fresh, released);
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

            /* \~english
             * The connection's window pays for new offsets, then gets back what
             * a reset, or data on an abandoned stream, released: charged first,
             * so bytes past the limit are an error even when thrown away (3.5).
             * \~spanish
             * La ventana de la conexion paga los desplazamientos nuevos, y luego
             * recupera lo que libero un reinicio, o datos de un flujo
             * abandonado: cobrado primero, asi que bytes pasado el limite son un
             * error aunque se tiren (3.5).
             * \~ */
            if (!recv_flow_.on_received(fresh)) {
                fail(TransportError::FlowControlError, f.wire_type, now_us);
                return false;
            }
            recv_flow_.on_consumed(released);
            break;
        }

        case FrameType::MaxData:
            send_flow_.on_max_data(f.maximum);
            break;

        case FrameType::MaxStreams:
            streams_.on_max_streams(f.bidirectional, f.maximum);
            break;

        case FrameType::RetireConnectionId:
            if (!on_retire_connection_id(f, now_us)) return false;
            break;

        case FrameType::PathChallenge: {
            /* \~english
             * MUST be answered with the same data (19.17), on the path it came
             * on (8.2.2).  A peer sending more than fit before the next
             * datagram gets its latest answered; it sends more as needed.
             * \~spanish
             * DEBE contestarse con los mismos datos (19.17), por el camino por el
             * que llego (8.2.2).  A un otro que manda mas de los que caben antes
             * del siguiente datagrama se le contesta el ultimo; manda mas si hace
             * falta.
             * \~ */
            PathState &path = paths_[rx_path_];
            if (path.responses == kResponsesOwed) {
                --path.responses;
                ++path_counts_.responses_dropped;
            }
            util::vesta_memcpy(path.response[path.responses++], payload + f.data.off, kPathDataSize);
            // \~english On the path in use it also gets a non-probing packet back (9.3.3).
            // \~spanish Por el camino en uso recibe ademas un paquete no de sondeo (9.3.3).  \~
            if (rx_path_ == active_) nonprobing_owed_ = true;
            break;
        }

        case FrameType::ConnectionClose:
            // \~english The peer closed: drain, send nothing (10.2.2).
            // \~spanish El otro extremo cerro: drenar, no mandar nada (10.2.2).  \~
            closed_by_peer_ = true;
            ended(EndReason::PeerClosed);
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
                                uint64_t now_us, bool early) noexcept {
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

    // \~english An ACK when one is owed: at once, or its delay is up.  Never in 0-RTT (12.5, 17.2.3).
    // \~spanish Un ACK cuando se debe: al momento, o se acabo su plazo.  Nunca en 0-RTT (12.5, 17.2.3).  \~
    const uint64_t deadline = acks.ack_deadline();
    bool acked = early;
    if (!early && acks.ranges() != 0 && deadline != kNever && deadline <= now_us) {
        const size_t n = acks.write_ack(p, room, now_us);
        if (n != 0) {
            ack_largest = acks.range(0).largest;
            acks.on_ack_sent();
            used += n;
            acked = true;
        }
    }

    // \~english Anything else elicits an ACK and counts against the congestion window.
    // \~spanish Todo lo demas pide confirmacion y cuenta contra la ventana de congestion.  \~
    if (!recovery_.window_allows(cfg_.max_datagram)) return used;

    size_t n = 0;

    /* \~english
     * Control frames only in 1-RTT.  HANDSHAKE_DONE and RETIRE_CONNECTION_ID
     * are never possible in 0-RTT (12.5); the rest would be allowed, and wait
     * the one round trip until 1-RTT: in 0-RTT goes stream data and nothing
     * this end has to take back if 0-RTT is turned down.
     * \~spanish
     * Tramas de control solo en 1-RTT.  HANDSHAKE_DONE y RETIRE_CONNECTION_ID
     * nunca son posibles en 0-RTT (12.5); el resto estaria permitido, y espera el
     * viaje de ida y vuelta hasta 1-RTT: en 0-RTT van datos de flujos y nada que
     * este extremo tenga que deshacer si se rechaza el 0-RTT.
     * \~ */
    if (s == Space::Application && !early) {
        if (handshake_done_owed_ && !full(rec) && (n = write_handshake_done(p + used, room - used)) != 0) {
            used += n;
            eliciting = true;
            handshake_done_owed_ = false;
            ++sent_.handshake_done;
            add_record(rec, kRecHandshakeDone, 0, 0, 0, false);
        }
        // \~english Connection IDs owed to the peer, and retirements owed to it (19.15, 19.16).
        // \~spanish Identificadores que se le deben al otro, y retiradas que se le deben (19.15, 19.16).  \~
        for (LocalCid &l : local_cids_) {
            if (!l.active || !l.owed || full(rec)) continue;
            n = write_new_connection_id(p + used, room - used, l.seq, local_retire_prior_to_, l.cid,
                                        cfg_.local_cid_len, l.token);
            if (n == 0) break;
            used += n;
            eliciting = true;
            l.owed = false;
            if (l.seq > max_sent_local_seq_) max_sent_local_seq_ = l.seq;
            ++sent_.new_connection_id;
            add_record(rec, kRecNewCid, l.seq, 0, 0, false);
        }
        while (retire_owed_count_ != 0 && !full(rec)) {
            const uint64_t seq = retire_owed_[retire_owed_count_ - 1];
            n = write_retire_connection_id(p + used, room - used, seq);
            if (n == 0) break;
            used += n;
            eliciting = true;
            --retire_owed_count_;
            ++sent_.retire_connection_id;
            add_record(rec, kRecRetireCid, seq, 0, 0, false);
        }
        /* \~english
         * New limits are computed first and COMMITTED only once their frame is
         * written: what is enforced is what was sent (4.1, 19.9, 19.10, 19.11),
         * so a frame that did not fit must not have raised anything.
         * \~spanish
         * Los limites nuevos se calculan primero y se COMPROMETEN solo cuando su
         * trama se escribio: lo que se hace cumplir es lo que se mando (4.1, 19.9,
         * 19.10, 19.11), asi que una trama que no cupo no debe haber subido nada.
         * \~ */
        if ((recv_flow_.wants_update() || max_data_owed_) && !full(rec)) {
            n = write_max_data(p + used, room - used, recv_flow_.next_limit());
            if (n != 0) {
                recv_flow_.advertise();
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
                                      streams_.next_max_streams(bidi != 0));
                if (n != 0) {
                    streams_.advertise_max_streams(bidi != 0);
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
            // \~english A lost one is owed again -- but only while the stream takes credit: in "Recv", not abandoned (3.2, 3.5).
            // \~spanish Uno perdido se vuelve a deber -- pero solo mientras el flujo acepte credito: en "Recv", sin abandonar (3.2, 3.5).  \~
            if (st->recv != nullptr &&
                (st->recv->wants_update() || (st->max_stream_data_owed && st->recv->takes_credit()))) {
                n = write_max_stream_data(p + used, room - used, st->id, st->recv->next_limit());
                if (n != 0) {
                    st->recv->advertise();
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
            // \~english The application stopped reading: ask the peer to stop sending (3.5, 19.5).
            // \~spanish La aplicacion dejo de leer: pedir al otro que deje de mandar (3.5, 19.5).  \~
            if (st->recv != nullptr && st->recv->stop_pending() && !full(rec)) {
                n = write_stop_sending(p + used, room - used, st->id, st->recv->stop_code());
                if (n != 0) {
                    used += n;
                    eliciting = true;
                    st->recv->on_stop_sent();
                    ++sent_.stop_sending;
                    add_record(rec, kRecStopSending, st->id, 0, 0, false);
                }
            }
        }
    }

    // \~english CRYPTO, in every space: not flow controlled, never counted against MAX_DATA.
    // \~spanish CRYPTO, en todos los espacios: sin control de flujo, nunca cuenta contra MAX_DATA.  \~
    SendStream &cs = *crypto_send_[idx(s)];
    while (!early && !full(rec) && room - used > 16) {
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
        write_blocked(p, room, used, rec, eliciting, now_us);
    }

    /* \~english
     * 13.2.1: "An endpoint SHOULD send an ACK frame with other frames when
     * there are new ack-eliciting packets to acknowledge" -- so a packet
     * already going out takes the owed ACK along instead of leaving it to
     * its deadline and a packet of its own.
     * \~spanish
     * 13.2.1: un extremo DEBERIA mandar un ACK junto con otras tramas cuando hay
     * paquetes nuevos que piden confirmacion -- asi que un paquete que ya sale se
     * lleva el ACK que se debe en vez de dejarlo a su plazo y a un paquete propio.
     * \~ */
    if (!acked && eliciting && acks.ranges() != 0 && acks.ack_deadline() != kNever) {
        const size_t n = acks.write_ack(p + used, room - used, now_us);
        if (n != 0) {
            ack_largest = acks.range(0).largest;
            acks.on_ack_sent();
            used += n;
            acked = true;
        }
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

    // \~english Any 1-RTT packet on the path in use is non-probing; a PING if there is nothing else (9.3.3).
    // \~spanish Cualquier paquete 1-RTT por el camino en uso es no de sondeo; un PING si no hay nada mas (9.3.3).  \~
    if (s == Space::Application && nonprobing_owed_) {
        if (used == 0 && (n = write_ping(p, room)) != 0) {
            used += n;
            eliciting = true;
            ++sent_.ping;
        }
        if (used != 0) nonprobing_owed_ = false;
    }
    return used;
}

size_t Connection::write_probe_frames(PathState &path, uint8_t *p, size_t room, bool full) noexcept {
    size_t used = 0;
    size_t n;
    // \~english Each response exactly once, never retransmitted: a new challenge brings a new one (8.2.2, 13.3).
    // \~spanish Cada respuesta exactamente una vez, nunca retransmitida: un desafio nuevo trae otra (8.2.2, 13.3).  \~
    while (path.responses != 0 && (n = write_path_response(p + used, room - used, path.response[0])) != 0) {
        used += n;
        --path.responses;
        if (path.responses != 0) util::vesta_memcpy(path.response[0], path.response[1], kPathDataSize);
        ++path_counts_.responses_sent;
    }
    // \~english At most one challenge per packet (8.2.1), with data nobody can predict.
    // \~spanish Como mucho un desafio por paquete (8.2.1), con datos que nadie pueda predecir.  \~
    if (path.challenge_owed) {
        const size_t k = path.challenges % kChallengesKept;
        uint8_t data[kPathDataSize];
        if (crypto_.random(data, sizeof data) &&
            (n = write_path_challenge(p + used, room - used, data)) != 0) {
            util::vesta_memcpy(path.challenge[k], data, kPathDataSize);
            path.challenge_full[k] = full;
            if (path.challenges < 0xff) ++path.challenges;
            used += n;
            path.challenge_owed = false;
            ++path_counts_.challenges_sent;
        }
    }
    return used;
}

size_t Connection::build_probe(size_t i, uint8_t *out, size_t room, uint64_t now_us) noexcept {
    PathState &p = paths_[i];
    // \~english The path's own ID of the peer's (9.5); without one nothing can go there.
    // \~spanish El identificador del otro propio del camino (9.5); sin el no puede ir nada alli.  \~
    if (p.peer_seq == kNever && !assign_peer_cid(i, cfg_.is_server)) {
        ++path_counts_.no_connection_id;
        path_counts_.responses_dropped += p.responses;
        p.responses = 0;
        p.challenge_owed = false;
        return 0;
    }
    const PeerCid *dest = peer_cid_by_seq(p.peer_seq);
    if (dest == nullptr) return 0;

    /* \~english
     * Expanded to 1200 bytes (8.2.1, 8.2.2) -- unless the address is not
     * proven and that would pass three times what came from it: then a
     * response goes as it is, and a challenge too, whose path's MTU is then
     * checked again once the address is proven.  Not even that: a response
     * is dropped, and said.
     * \~spanish
     * Ampliado a 1200 bytes (8.2.1, 8.2.2) -- salvo que la direccion no este
     * probada y eso pase de tres veces lo que llego de ella: entonces una
     * respuesta va tal cual, y un desafio tambien, y la MTU de su camino se
     * comprueba otra vez cuando la direccion este probada.  Ni siquiera eso:
     * la respuesta se tira, y se dice.
     * \~ */
    size_t r = static_cast<size_t>(min64(room, cfg_.max_datagram));
    const size_t budget = amplification_budget(i);
    if (budget < r) r = budget;
    if (r < 64) {
        path_counts_.responses_dropped += p.responses;
        p.responses = 0;
        return 0;
    }
    const bool full = r >= kMinInitial;
    bool padded = false;
    return build_packet(Space::Application, out, r, full ? Pad::Always : Pad::Never, padded, now_us, &p,
                        dest);
}

void Connection::write_blocked(uint8_t *p, size_t room, size_t &used, PacketRecord &rec,
                               bool &eliciting, uint64_t now_us) noexcept {
    /* \~english
     * 4.1: a sender blocked by flow control SHOULD say so with DATA_BLOCKED /
     * STREAM_DATA_BLOCKED, and SHOULD say it again periodically while it has
     * no ack-eliciting packet in flight -- here, once per PTO -- or the peer
     * may take the silence for an idle connection.  4.6: one that cannot open
     * a stream because of the peer's limit SHOULD send STREAMS_BLOCKED.  Each
     * once per limit; a new limit is a new reason to say it.
     * \~spanish
     * 4.1: un emisor bloqueado por el control de flujo DEBERIA decirlo con
     * DATA_BLOCKED / STREAM_DATA_BLOCKED, y DEBERIA repetirlo de vez en cuando
     * mientras no tenga ningun paquete que pida confirmacion en vuelo -- aqui,
     * una vez por PTO --, o el otro puede tomar el silencio por una conexion
     * inactiva.  4.6: uno que no puede abrir un flujo por el limite del otro
     * DEBERIA mandar STREAMS_BLOCKED.  Cada uno una vez por limite; un limite
     * nuevo es un motivo nuevo para decirlo.
     * \~ */
    const bool quiet = recovery_.bytes_in_flight() == 0;
    size_t n = 0;

    bool waiting = false;
    for (size_t i = 0; i < streams_.capacity() && !waiting; ++i) {
        const Stream *st = streams_.slot(i);
        if (st != nullptr && st->send != nullptr && st->send->written() > st->send->sent()) waiting = true;
    }
    if (waiting && send_flow_.blocked() && !full(rec)) {
        const uint64_t lim = send_flow_.limit();
        const bool again = data_blocked_at_ == lim && quiet && now_us >= data_blocked_time_ + pto_duration();
        if ((data_blocked_at_ != lim || again) && (n = write_data_blocked(p + used, room - used, lim)) != 0) {
            used += n;
            eliciting = true;
            data_blocked_at_ = lim;
            data_blocked_time_ = now_us;
            ++sent_.data_blocked;
            add_record(rec, kRecDataBlocked, 0, 0, 0, false);
        }
    }

    for (size_t i = 0; i < streams_.capacity() && !full(rec); ++i) {
        Stream *st = streams_.slot(i);
        if (st == nullptr || st->send == nullptr || !st->send->blocked()) continue;
        const uint64_t lim = st->send->limit();
        const bool again = st->blocked_sent_at == lim && quiet && now_us >= st->blocked_sent_time + pto_duration();
        if (st->blocked_sent_at == lim && !again) continue;
        n = write_stream_data_blocked(p + used, room - used, st->id, lim);
        if (n == 0) break;
        used += n;
        eliciting = true;
        st->blocked_sent_at = lim;
        st->blocked_sent_time = now_us;
        ++sent_.stream_data_blocked;
        add_record(rec, kRecStreamDataBlocked, st->id, 0, 0, false);
    }

    for (int bidi = 1; bidi >= 0 && !full(rec); --bidi) {
        if (!streams_.open_refused(bidi != 0)) continue;
        const uint64_t lim = streams_.peer_limit(bidi != 0);
        if (streams_blocked_at_[bidi] == lim) continue;
        n = write_streams_blocked(p + used, room - used, bidi != 0, lim);
        if (n == 0) break;
        used += n;
        eliciting = true;
        streams_blocked_at_[bidi] = lim;
        ++sent_.streams_blocked;
        add_record(rec, kRecStreamsBlocked, static_cast<uint64_t>(bidi), 0, 0, false);
    }
}

size_t Connection::build_packet(Space s, uint8_t *out, size_t room, Pad pad, bool &padded,
                                uint64_t now_us, PathState *probe, const PeerCid *dest, bool early) noexcept {
    padded = false;
    if (!recovery_.can_record(s) && state_ != ConnState::Closing) return 0;

    /* \~english
     * A packet that must be padded to 1200 bytes and cannot be is not built
     * at all -- decided HERE, before any frame is written.  Writing the frames
     * marks their data as sent; dropping the packet after that would leave
     * bytes counted as in flight that never left and that nothing would ever
     * retransmit.
     * \~spanish
     * Un paquete que hay que rellenar a 1200 bytes y no se puede no se construye
     * -- decidido AQUI, antes de escribir ninguna trama.  Escribir las tramas
     * marca sus datos como mandados; tirar el paquete despues dejaria bytes
     * contados en vuelo que nunca salieron y que nada retransmitiria nunca.
     * \~ */
    if (pad != Pad::Never && room < kMinInitial) return 0;

    const size_t i = idx(s);
    const uint64_t pn = next_pn_[i];

    // \~english 12.3: at 2^62-1 the sender MUST close without a CONNECTION_CLOSE or anything else.
    // \~spanish 12.3: en 2^62-1 el emisor DEBE cerrar sin CONNECTION_CLOSE ni nada mas.  \~
    if (pn >= (uint64_t{1} << 62) - 1) {
        ended(EndReason::PacketNumbers);
        state_ = ConnState::Closed;
        return 0;
    }
    const uint64_t la = recovery_.largest_acked(s);
    size_t pn_len = packet_number_length(pn, la == kNever ? 0 : la, la != kNever);
    if (pn_len == 0) pn_len = 4;

    // \~english The header, up to the packet number.
    // \~spanish La cabecera, hasta el numero de paquete.  \~
    size_t h = 0;
    size_t length_at = 0;
    const bool is_long = s != Space::Application || early;
    if (room < 64) return 0;
    // \~english After a Retry an Initial header carries the token: it has to fit first.
    // \~spanish Tras un Retry la cabecera de un Initial lleva el testigo: primero tiene que caber.  \~
    const size_t token_room = s == Space::Initial ? varint_size(token_len_) + token_len_ : 0;
    if (token_room + 64 > room) return 0;
    if (is_long) {
        // \~english 0-RTT's type: 0x01 in version 1 (17.2.3), 0b10 in version 2 (RFC 9369, 3.2).
        // \~spanish El tipo de 0-RTT: 0x01 en la version 1 (17.2.3), 0b10 en la version 2 (RFC 9369, 3.2).  \~
        const uint8_t type = early ? (cfg_.version == kVersion2 ? 2 : 1) : long_type_bits(s, cfg_.version);
        out[h++] = static_cast<uint8_t>(0xc0 | (type << 4));
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
        if (s == Space::Initial) {
            h += encode_varint(out + h, room - h, token_len_);
            if (token_len_ != 0) util::vesta_memcpy(out + h, token_, token_len_);
            h += token_len_;
        }
        length_at = h;
        h += 2;
    } else {
        /* \~english
         * The confidentiality limit (RFC 9001, 6.6): no packet past it with one
         * key.  An update comes well before; if none could be made, the
         * connection stops being used -- not even a CONNECTION_CLOSE, which
         * would be one packet more under the same key.
         * \~spanish
         * El limite de confidencialidad (RFC 9001, 6.6): ningun paquete pasado el
         * con una misma clave.  Una actualizacion llega mucho antes; si no se pudo
         * hacer ninguna, la conexion deja de usarse -- ni siquiera un
         * CONNECTION_CLOSE, que seria un paquete mas con la misma clave.
         * \~ */
        if (one_rtt_.sealed >= confidentiality_limit()) {
            ended(EndReason::ConfidentialityLimit);
            state_ = ConnState::Closed;
            close_code_ = static_cast<uint64_t>(TransportError::AeadLimitReached);
            close_app_ = false;
            return 0;
        }
        /* \~english
         * One packet left under this key, and no update possible: 6.6
         * RECOMMENDS closing with AEAD_LIMIT_REACHED before reaching the
         * state where no update can be made -- so this last packet carries
         * the CONNECTION_CLOSE, and the peer learns why instead of timing out.
         * \~spanish
         * Queda un paquete con esta clave, y no se puede actualizar: 6.6
         * RECOMIENDA cerrar con AEAD_LIMIT_REACHED antes de llegar al estado en
         * que no cabe ninguna actualizacion -- asi que este ultimo paquete lleva el
         * CONNECTION_CLOSE, y el otro sabe por que en vez de caducar.
         * \~ */
        if (state_ == ConnState::Active && one_rtt_.sealed + 1 >= confidentiality_limit() &&
            update_keys(now_us) != KeyUpdate::Started)
            close(static_cast<uint64_t>(TransportError::AeadLimitReached), false, 0, now_us);
        // \~english The fixed bit, and the key phase this end seals with (17.3.1).
        // \~spanish El bit fijo, y la fase de clave con la que sella este extremo (17.3.1).  \~
        /* \~english
         * The spin bit (17.4) is not used, and then "it is RECOMMENDED that
         * endpoints set the spin bit to a random value": one per connection
         * ID, drawn again whenever the ID changes, so it links nothing.
         * \~spanish
         * El bit de espin (17.4) no se usa, y entonces SE RECOMIENDA ponerlo a un
         * valor aleatorio: uno por identificador de conexion, sorteado otra vez
         * cada vez que cambia el identificador, asi que no enlaza nada.
         * \~ */
        // \~english A probe goes with its path's ID, and a spin bit drawn for it alone.
        // \~spanish Un sondeo va con el identificador de su camino, y un bit de espin sorteado solo para el.  \~
        bool spin = spin_bit_;
        if (probe != nullptr) {
            uint8_t r = 0;
            spin = crypto_.random(&r, 1) && (r & 1) != 0;
        }
        out[h++] = static_cast<uint8_t>(0x40 | (spin ? 0x20 : 0x00) |
                                        (one_rtt_.write_phase ? 0x04 : 0x00));
        const uint8_t *dcid = dest != nullptr ? dest->cid : cfg_.peer_cid;
        const size_t dcid_len = dest != nullptr ? dest->len : cfg_.peer_cid_len;
        util::vesta_memcpy(out + h, dcid, dcid_len);
        h += dcid_len;
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

    size_t len = 0;
    if (probe != nullptr) {
        len = write_probe_frames(*probe, payload, payload_room, pad == Pad::Always);
        eliciting = len != 0;
        // \~english The next challenge no sooner than the interval, which doubles (8.2.1, 9.4).
        // \~spanish El siguiente desafio no antes del intervalo, que se dobla (8.2.1, 9.4).  \~
        if (len != 0 && probe->challenging && !probe->challenge_owed && probe->next_challenge_at == kNever) {
            probe->next_challenge_at = now_us + probe->challenge_interval;
            probe->challenge_interval *= 2;
        }
    } else {
        len = write_frames(s, payload, payload_room, rec, eliciting, ack_largest, now_us, early);
    }
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

    /* \~english
     * 10.3: every short packet at least 22 bytes longer than the ID the peer
     * puts in its packets to us.  A peer's stateless reset is always smaller
     * than what triggered it; this keeps it from being told apart from a
     * valid packet by its size.
     * \~spanish
     * 10.3: cada paquete corto al menos 22 bytes mas largo que el identificador
     * que el otro pone en sus paquetes hacia nosotros.  Un reinicio sin estado del
     * otro siempre es mas pequeno que lo que lo provoco; esto evita que se le
     * distinga de un paquete valido por su tamano.
     * \~ */
    if (!is_long && overhead + len < cfg_.local_cid_len + 22) {
        const size_t extra = cfg_.local_cid_len + 22 - overhead - len;
        if (extra <= payload_room - len) {
            util::vesta_memset(payload + len, 0, extra);
            len += extra;
        }
    }

    if (is_long) encode_varint_width(out + length_at, 2, pn_len + len + kTagSize);

    if (protect_packet(crypto_, early ? early_keys_ : keys_[i].write, out, pn_offset, pn_len, pn, len) !=
        Protect::Ok) {
        fail(TransportError::InternalError, 0, now_us);
        return 0;
    }

    const size_t size = overhead + len;
    ++next_pn_[i];
    bytes_out_ += size;
    (probe != nullptr ? *probe : paths_[active_]).bytes_out += size;
    if (early) ++early_sent_;

    if (s == Space::Application && !early) {
        OneRtt &o = one_rtt_;
        ++o.sealed;
        if (o.first_sent_pn == kNever) o.first_sent_pn = pn;
        // \~english The peer's update is answered once an ACK for it goes out under the new keys (6.2).
        // \~spanish La actualizacion del otro extremo queda contestada cuando sale un ACK de ella con las claves nuevas (6.2).  \~
        if (o.unanswered_pn != kNever && o.write_phase == o.read_phase && ack_largest != kNever &&
            ack_largest >= o.unanswered_pn)
            o.unanswered_pn = kNever;
        // \~english Half-way to the limit an update starts on its own; until it can, it is asked again.
        // \~spanish A mitad de camino del limite empieza sola una actualizacion; hasta que pueda, se vuelve a pedir.  \~
        const uint64_t every = cfg_.key_update_packets != 0 ? cfg_.key_update_packets
                                                            : confidentiality_limit() / 2;
        if (o.sealed >= every) update_keys(now_us);
    }

    if (state_ != ConnState::Closing) {
        /* \~english
         * PADDING keeps a packet in flight even without an ack-eliciting
         * frame.  Path probes do not count at all: 9.4 lets their loss be
         * detected on its own -- by the path's challenge timer -- rather than
         * shrink the window of the path in use.
         * \~spanish
         * PADDING mantiene un paquete en vuelo aunque no lleve tramas que pidan
         * confirmacion.  Los sondeos de camino no cuentan en absoluto: 9.4 deja
         * que su perdida se detecte aparte -- con el temporizador de desafios del
         * camino -- en vez de encoger la ventana del camino en uso.
         * \~ */
        const bool in_flight = eliciting || padded;
        records_[rec.tag % record_cap_] = rec;
        ++next_tag_;
        recovery_.on_packet_sent(s, pn, static_cast<uint32_t>(size), eliciting, in_flight, probe != nullptr,
                                 rec.tag, ack_largest, now_us, early);
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

size_t Connection::build_datagram(Path &path, uint8_t *out, size_t room, uint64_t now_us) noexcept {
    if (state_ == ConnState::Closed || state_ == ConnState::Draining) return 0;
    streams_.collect();

    /* \~english
     * Path validation first, each path its own datagram: a PATH_RESPONSE
     * MUST NOT wait (8.2.2), and a challenge that is due has already waited
     * its interval.  Only probing frames go there: a path that is not the
     * one in use gets no non-probing packet until the peer sends one on it
     * (9).
     * \~spanish
     * Primero la validacion de caminos, cada camino con su propio datagrama: un
     * PATH_RESPONSE NO DEBE esperar (8.2.2), y un desafio que toca ya espero su
     * intervalo.  Alli solo van tramas de sondeo: un camino que no es el que esta
     * en uso no recibe ningun paquete no de sondeo hasta que el otro mande uno
     * por el (9).
     * \~ */
    if (state_ == ConnState::Active && keys_[idx(Space::Application)].have) {
        for (size_t i = 0; i < kMaxPaths; ++i) {
            PathState &p = paths_[i];
            if (!p.used || (p.responses == 0 && !p.challenge_owed)) continue;
            const size_t n = build_probe(i, out, room, now_us);
            if (n != 0) {
                path = p.addr;
                return n;
            }
        }
    }

    // \~english Everything else, on the path in use -- with its own ID of the peer's, or not at all (9.5).
    // \~spanish Todo lo demas, por el camino en uso -- con su propio identificador del otro, o nada (9.5).  \~
    if (paths_[active_].peer_seq == kNever) return 0;
    path = paths_[active_].addr;
    room = static_cast<size_t>(min64(room, cfg_.max_datagram));
    const size_t budget = amplification_budget(active_);
    if (budget < room) room = budget;
    if (room < 64) {
        if (budget != static_cast<size_t>(-1)) recovery_.set_amplification_blocked(true, now_us);
        return 0;
    }

    bool padded = false;
    if (state_ == ConnState::Closing) {
        if (!close_owed_) return 0;
        close_owed_ = false;
        /* \~english
         * 10.2.3: once the handshake is confirmed, the close goes in 1-RTT
         * (MUST) -- the only keys left then.  Before it, the peer may not be
         * able to open the highest level yet, so a copy goes at every level
         * this end still has keys for, coalesced lowest first (SHOULD).
         * \~spanish
         * 10.2.3: con el saludo confirmado, el cierre va en 1-RTT (DEBE) -- las
         * unicas claves que quedan entonces.  Antes, puede que el otro aun no
         * pueda abrir el nivel mas alto, asi que va una copia en cada nivel para
         * el que este extremo aun tiene claves, pegadas de la mas baja a la mas
         * alta (DEBERIA).
         * \~ */
        size_t total = 0;
        for (int s = confirmed_ ? 2 : 0; s <= 2; ++s) {
            if (!keys_[s].have) continue;
            // \~english A client knows the server has Handshake keys once it has them itself (10.2.3).
            // \~spanish Un cliente sabe que el servidor tiene claves Handshake en cuanto las tiene el (10.2.3).  \~
            if (!cfg_.is_server && s == 0 && keys_[1].have) continue;
            // \~english A client's datagram with an Initial is 1200 bytes, a close included (8.1, 14.1).
            // \~spanish Un datagrama de cliente con un Initial mide 1200 bytes, tambien con un cierre (8.1, 14.1).  \~
            const Pad pad = !cfg_.is_server && s == 0 ? Pad::Always : Pad::Never;
            total += build_packet(static_cast<Space>(s), out + total, room - total, pad, padded, now_us);
            if (padded) break;
        }
        return total;
    }

    size_t total = 0;
    for (size_t s = 0; s < kSpaces; ++s) {
        const Space sp = static_cast<Space>(s);
        // \~english A client's application data before 1-RTT keys goes in 0-RTT packets (RFC 9001, 5.6).
        // \~spanish Los datos de aplicacion de un cliente antes de las claves 1-RTT van en paquetes 0-RTT (RFC 9001, 5.6).  \~
        const bool early = sp == Space::Application && !keys_[s].have && early_have_ && !cfg_.is_server;
        if (early) {
            total += build_packet(sp, out + total, room - total, Pad::Never, padded, now_us, nullptr, nullptr, true);
            break;
        }
        if (!keys_[s].have) continue;

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

    /* \~english
     * RFC 9002, 7.8: if the window still has room when this call stops, it
     * was not the window that stopped it -- too little to send, or flow
     * control -- and the window SHOULD NOT grow on the acknowledgements.
     * \~spanish
     * RFC 9002, 7.8: si la ventana aun tiene sitio cuando esta llamada para, no
     * fue la ventana lo que la paro -- poco que mandar, o el control de flujo -- y
     * la ventana NO DEBERIA crecer con las confirmaciones.
     * \~ */
    recovery_.set_app_limited(recovery_.window_allows(static_cast<uint32_t>(cfg_.max_datagram)));
    return total;
}

uint64_t Connection::timer() const noexcept {
    if (state_ == ConnState::Closed) return kNever;
    if (state_ != ConnState::Active) return close_deadline_;

    uint64_t t = min64(min64(idle_deadline_, recovery_.timer()), one_rtt_.prev_until);
    t = min64(t, path_timer());
    t = min64(t, early_discard_at_);

    /* \~english
     * An ACK that cannot be sent is no reason to wake: a server at its
     * amplification limit can send nothing until more arrives, and a timer
     * stuck at "now" would spin.
     * \~spanish
     * Un ACK que no se puede mandar no es motivo para despertar: un servidor en
     * su limite de amplificacion no puede mandar nada hasta que llegue mas, y un
     * temporizador clavado en "ahora" daria vueltas sin fin.
     * \~ */
    if (amplification_budget(active_) < 64) return t;
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
        ended(EndReason::IdleTimeout);
        state_ = ConnState::Closed;
        return;
    }

    // \~english The previous read keys have had their time (RFC 9001, 6.5).
    // \~spanish Las claves de lectura anteriores ya tuvieron su tiempo (RFC 9001, 6.5).  \~
    if (one_rtt_.prev_until <= now_us) {
        drop_generation(one_rtt_.read_prev);
        one_rtt_.prev_until = kNever;
        ++key_counts_.old_discarded;
    }
    // \~english A server's 0-RTT keys have had their three PTO since the first 1-RTT packet (RFC 9001, 4.9.3).
    // \~spanish Las claves 0-RTT de un servidor ya tuvieron sus tres PTO desde el primer paquete 1-RTT (RFC 9001, 4.9.3).  \~
    if (early_discard_at_ <= now_us) forget_early();

    run_path_timers(now_us);
    if (state_ != ConnState::Active) return;
    run_loss_timer(now_us);
}

} // namespace quic
} // namespace http_vx
