/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tls/session.cpp
 * @brief
 * \~english The TLS 1.3 handshake state machine, client and server, as QUIC carries it (RFC 8446, 4; RFC 9001, 4 and 8).
 * \~spanish La maquina de estados del saludo de TLS 1.3, cliente y servidor, tal como la lleva QUIC (RFC 8446, 4; RFC 9001, 4 y 8).
 * \~
 */

#include "http_vx/tls_session.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

/// \~english Clears secret bytes where the compiler cannot drop the store.
/// \~spanish Borra bytes secretos donde el compilador no puede quitar la escritura.  \~
void wipe(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/// \~english A suite's TLS number (B.4).  \~spanish El numero de TLS de un algoritmo (B.4).  \~
uint16_t suite_of(Aead a) noexcept {
    switch (a) {
    case Aead::Aes128Gcm:        return suite::Aes128GcmSha256;
    case Aead::Aes256Gcm:        return suite::Aes256GcmSha384;
    case Aead::ChaCha20Poly1305: return suite::ChaCha20Poly1305Sha256;
    }
    return 0;
}

/// \~english The AEAD of a suite this code offers.  \~spanish El AEAD de un algoritmo que ofrece este codigo.  \~
Aead aead_of(uint16_t s) noexcept {
    return s == suite::Aes256GcmSha384 ? Aead::Aes256Gcm
         : s == suite::ChaCha20Poly1305Sha256 ? Aead::ChaCha20Poly1305
                                              : Aead::Aes128Gcm;
}

/// \~english A group's TLS number (4.2.7).  \~spanish El numero de TLS de un grupo (4.2.7).  \~
uint16_t group_number(Group g) noexcept {
    return g == Group::X25519 ? group::X25519 : group::Secp256r1;
}

/// \~english The group of a TLS number this code offers.  \~spanish El grupo de un numero de TLS que ofrece este codigo.  \~
Group group_of(uint16_t g) noexcept {
    return g == group::X25519 ? Group::X25519 : Group::Secp256r1;
}

/// \~english The signature schemes a client offers: the ones every provider checks.
/// \~spanish Los esquemas de firma que ofrece un cliente: los que comprueba todo proveedor.  \~
const uint16_t kSchemes[] = {scheme::EcdsaSecp256r1Sha256, scheme::RsaPssRsaeSha256};
constexpr size_t kSchemeCount = sizeof kSchemes / sizeof kSchemes[0];

/// \~english Whether @p v is in @p list of @p count.  \~spanish Si @p v esta en la lista @p list de @p count.  \~
bool listed(const uint16_t *list, size_t count, uint16_t v) noexcept {
    for (size_t i = 0; i < count; ++i)
        if (list[i] == v) return true;
    return false;
}

/// \~english Whether the uint16 @p v is in the list at @p s of @p m.  \~spanish Si el uint16 @p v esta en la lista de @p s en @p m.  \~
bool listed_in(const uint8_t *m, Span s, uint16_t v) noexcept {
    for (uint32_t i = 0; i + 1 < s.len; i += 2)
        if (read16(m + s.off + i) == v) return true;
    return false;
}

/// \~english Compares without stopping at the first difference: a Finished is a MAC.
/// \~spanish Compara sin pararse en la primera diferencia: un Finished es un MAC.  \~
bool same(const uint8_t *a, const uint8_t *b, size_t n) noexcept {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d = static_cast<uint8_t>(d | (a[i] ^ b[i]));
    return d == 0;
}

/// \~english The context strings of a CertificateVerify (4.4.3), 33 bytes each.
/// \~spanish Las cadenas de contexto de un CertificateVerify (4.4.3), 33 bytes cada una.  \~
const char kServerContext[] = "TLS 1.3, server CertificateVerify";
const char kClientContext[] = "TLS 1.3, client CertificateVerify";
constexpr size_t kContextLen = sizeof kServerContext - 1;
constexpr size_t kMaxSigned = 64 + kContextLen + 1 + kMaxHash;

/**
 * @brief
 * \~english What a CertificateVerify signs: 64 spaces, the context, a zero byte, the transcript hash (4.4.3).
 * \~spanish Lo que firma un CertificateVerify: 64 espacios, el contexto, un byte cero, el resumen de la transcripcion (4.4.3).
 * \~
 *
 * @param by_server \~english whose signature: the context string tells them apart
 *                  \~spanish de quien es la firma: la cadena de contexto las distingue  \~
 */
size_t signed_content(bool by_server, const uint8_t *transcript_hash, size_t hl, uint8_t *out) noexcept {
    util::vesta_memset_noinline(out, 0x20, 64);
    util::vesta_memcpy_noinline(out + 64, by_server ? kServerContext : kClientContext, kContextLen);
    out[64 + kContextLen] = 0;
    util::vesta_memcpy_noinline(out + 64 + kContextLen + 1, transcript_hash, hl);
    return 64 + kContextLen + 1 + hl;
}

/// \~english Makes room for @p need more bytes.  \~spanish Hace sitio para @p need bytes mas.  \~
template <typename B>
bool reserve(B &b, size_t need) noexcept {
    if (b.cap - b.len >= need) return true;
    size_t cap = b.cap == 0 ? 1024 : b.cap;
    while (cap - b.len < need) cap *= 2;
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Growing, util::AllocFill::Dense);
    uint8_t *grown = static_cast<uint8_t *>(util::host_alloc(cap));
    if (grown == nullptr) return false;
    if (b.len != 0) util::vesta_memcpy(grown, b.p, b.len);
    if (b.p != nullptr) {
        // \~english Handshake bytes carry key shares and secrets' inputs.  \~spanish Los bytes del saludo llevan claves y entradas de secretos.  \~
        wipe(b.p, b.cap);
        util::host_free(b.p);
    }
    b.p = grown;
    b.cap = cap;
    return true;
}

/// \~english Drops the first @p n bytes.  \~spanish Quita los primeros @p n bytes.  \~
template <typename B>
void drop_front(B &b, size_t n) noexcept {
    if (n >= b.len) {
        b.len = 0;
        return;
    }
    util::vesta_memmove(b.p, b.p + n, b.len - n);
    b.len -= n;
}

/// \~english Frees a buffer, wiped.  \~spanish Libera un buffer, borrado.  \~
template <typename B>
void release(B &b) noexcept {
    if (b.p == nullptr) return;
    wipe(b.p, b.cap);
    util::host_free(b.p);
    b = B{};
}

} // namespace

Session::Session(Crypto &c, const SessionConfig &cfg) noexcept : c_(c), cfg_(cfg) {
    // \~english What is offered is what the provider can run (R23: ask, do not assume).
    // \~spanish Lo que se ofrece es lo que el proveedor sabe ejecutar (R23: preguntar, no suponer).  \~
    static const Aead kAllSuites[] = {Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305};
    static const Group kAllGroups[] = {Group::X25519, Group::Secp256r1};
    const Aead *suites = cfg.suites != nullptr ? cfg.suites : kAllSuites;
    const size_t suite_count = cfg.suites != nullptr ? cfg.suite_count : 3;
    for (size_t i = 0; i < suite_count && suite_count_ < 3; ++i)
        if (c_.supports(suites[i]) && !listed(suites_, suite_count_, suite_of(suites[i])))
            suites_[suite_count_++] = suite_of(suites[i]);
    const Group *groups = cfg.groups != nullptr ? cfg.groups : kAllGroups;
    const size_t group_count = cfg.groups != nullptr ? cfg.group_count : 2;
    for (size_t i = 0; i < group_count && group_count_ < 2; ++i)
        if (c_.supports(groups[i]) && !listed(groups_, group_count_, group_number(groups[i])))
            groups_[group_count_++] = group_number(groups[i]);
    state_ = cfg.server ? State::WaitClientHello : State::Start;
}

Session::~Session() {
    forget_shares();
    if (has_schedule_) schedule().~KeySchedule();
    wipe(hs_client_, sizeof hs_client_);
    wipe(hs_server_, sizeof hs_server_);
    wipe(ap_client_, sizeof ap_client_);
    wipe(ap_server_, sizeof ap_server_);
    wipe(exporter_, sizeof exporter_);
    wipe(resumption_, sizeof resumption_);
    for (size_t i = 0; i < quic::kSpaces; ++i) {
        release(in_[i]);
        release(out_[i]);
    }
}

bool Session::fail(Alert a, const char *why) noexcept {
    // \~english An alert is a QUIC error: 0x0100 plus its value (RFC 9001, 4.8).
    // \~spanish Una alerta es un error de QUIC: 0x0100 mas su valor (RFC 9001, 4.8).  \~
    const bool first = failure_.code == 0;
    fail_quic(kCryptoError + static_cast<uint8_t>(a), why);
    if (first) failure_.alert = a;
    return false;
}

bool Session::fail_quic(uint64_t code, const char *why) noexcept {
    // \~english The first failure is the one that counts; what follows it is consequence.
    // \~spanish El primer fallo es el que cuenta; lo que viene despues es consecuencia.  \~
    if (failure_.code == 0) {
        failure_.code = code;
        failure_.alert = Alert::None;
        failure_.why = why;
    }
    state_ = State::Failed;
    return false;
}

void Session::forget_shares() noexcept {
    for (size_t i = 0; i < 2; ++i) {
        c_.forget_key(shares_[i]);
        shares_[i] = nullptr;
    }
    share_count_ = 0;
}

void Session::keep(size_t msg_at, Span s, Kept &k) noexcept {
    k.present = true;
    k.at = msg_at + s.off;
    k.len = s.len;
}

bool Session::add(const uint8_t *m, size_t n) noexcept {
    if (n > Transcript::kMaxSize - transcript_.size())
        return fail_quic(kCryptoBufferExceeded, "the handshake is larger than this end keeps");
    return transcript_.add(m, n) || fail_provider("out of memory for the transcript");
}

bool Session::begin(Space s, size_t need, Writer &w) noexcept {
    Bytes &b = out_[static_cast<size_t>(s)];
    if (!reserve(b, need)) return fail_provider("out of memory for handshake output");
    w = Writer(b.p + b.len, b.cap - b.len);
    return true;
}

bool Session::commit(Space s, Writer &w) noexcept {
    if (w.failed()) return fail_provider("a handshake message did not fit where it was written");
    Bytes &b = out_[static_cast<size_t>(s)];
    // \~english Every message sent is part of the transcript (4.4.1).  \~spanish Cada mensaje enviado es parte de la transcripcion (4.4.1).  \~
    if (!add(b.p + b.len, w.size())) return false;
    b.len += w.size();
    return true;
}

bool Session::set_suite(uint16_t s) noexcept {
    if (has_schedule_) return true;
    suite_ = s;
    aead_ = aead_of(s);
    hash_ = quic::hash_of(aead_);
    new (schedule_) KeySchedule(c_, hash_);
    has_schedule_ = true;
    return true;
}

bool Session::derive_handshake(const uint8_t *shared, size_t shared_len) noexcept {
    // \~english No PSK: the Early Secret from zeros, then the (EC)DHE secret over ClientHello..ServerHello (7.1).
    // \~spanish Sin PSK: el Early Secret de ceros, y luego el secreto (EC)DHE sobre ClientHello..ServerHello (7.1).  \~
    uint8_t th[kMaxHash];
    if (!schedule().start(nullptr, 0) || !transcript_.hash(c_, hash_, th) ||
        !schedule().handshake(shared, shared_len, th, hs_client_, hs_server_))
        return fail_provider("the provider could not derive the handshake secrets");
    has_handshake_keys_ = true;
    return true;
}

bool Session::finished_for(bool client_side, uint8_t *out) noexcept {
    uint8_t th[kMaxHash];
    return (transcript_.hash(c_, hash_, th) &&
            finished_data(c_, hash_, client_side ? hs_client_ : hs_server_, th, out)) ||
           fail_provider("the provider could not compute a Finished");
}

bool Session::choose_suite(const uint8_t *m, Span offered, uint16_t &s) const noexcept {
    // \~english The server's preference; what it does not know it ignores (4.1.2).
    // \~spanish La preferencia del servidor; lo que no conoce lo ignora (4.1.2).  \~
    for (size_t i = 0; i < suite_count_; ++i)
        if (listed_in(m, offered, suites_[i])) {
            s = suites_[i];
            return true;
        }
    return false;
}

bool Session::choose_alpn(const uint8_t *m, Span offered) noexcept {
    // \~english The server's most preferred protocol the client also advertised (RFC 7301, 3.2).
    // \~spanish El protocolo preferido del servidor que el cliente tambien anuncio (RFC 7301, 3.2).  \~
    for (size_t i = 0; i < cfg_.alpn_count; ++i) {
        const char *want = cfg_.alpn[i];
        size_t want_len = 0;
        while (want[want_len] != '\0') ++want_len;
        for (size_t at = 0; at < offered.len;) {
            const size_t len = m[offered.off + at];
            if (len == want_len && same(m + offered.off + at + 1, reinterpret_cast<const uint8_t *>(want), len)) {
                alpn_index_ = i;
                alpn_.present = true;
                return true;
            }
            at += 1 + len;
        }
    }
    return false;
}

bool Session::start() noexcept {
    if (cfg_.server) return true;
    if (state_ != State::Start) return fail(Alert::InternalError, "start() called twice");
    if (suite_count_ == 0 || group_count_ == 0)
        return fail(Alert::InternalError, "the provider supports no suite or no group to offer");
    if (cfg_.alpn_count == 0) return fail(Alert::InternalError, "no application protocol to offer: QUIC requires ALPN");
    if (cfg_.transport_params == nullptr)
        return fail(Alert::InternalError, "no transport parameters to send: QUIC requires them");
    if (!c_.random(random_, sizeof random_)) return fail_provider("the provider gave no random bytes");
    // \~english The first shares, in the order of supported_groups (4.2.8); at most two.
    // \~spanish Las primeras claves, en el orden de supported_groups (4.2.8); como mucho dos.  \~
    const size_t shares = cfg_.key_shares < group_count_ ? cfg_.key_shares : group_count_;
    for (size_t i = 0; i < shares; ++i) {
        shares_[i] = c_.generate_key(group_of(groups_[i]), share_pubs_[i]);
        if (shares_[i] == nullptr) return fail_provider("the provider could not make a key share");
        share_groups_[i] = groups_[i];
        share_count_ = i + 1;
    }
    return client_hello();
}

bool Session::client_hello() noexcept {
    size_t name_len = 0;
    if (cfg_.server_name != nullptr)
        while (cfg_.server_name[name_len] != '\0') ++name_len;
    size_t alpn_total = 0;
    for (size_t i = 0; i < cfg_.alpn_count; ++i) {
        size_t len = 0;
        while (cfg_.alpn[i][len] != '\0') ++len;
        alpn_total += 1 + len;
    }
    const size_t need = 512 + cfg_.transport_params_len + name_len + alpn_total +
                        2 * (4 + quic::kMaxPublicKey) + cookie_.len;
    Writer w(nullptr, 0);
    if (!begin(Space::Initial, need, w)) return false;

    const size_t msg = w.begin_message(Handshake::ClientHello);
    w.u16(kLegacyVersion);
    // \~english The same random in both ClientHellos: the second is the first, changed only where 4.1.2 says.
    // \~spanish El mismo random en los dos ClientHello: el segundo es el primero, cambiado solo donde dice 4.1.2.  \~
    w.bytes(random_, sizeof random_);
    // \~english An empty legacy_session_id: no compatibility mode in QUIC (RFC 9001, 8.4).
    // \~spanish Un legacy_session_id vacio: sin modo de compatibilidad en QUIC (RFC 9001, 8.4).  \~
    w.u8(0);
    const size_t suites = w.open(2);
    for (size_t i = 0; i < suite_count_; ++i) w.u16(suites_[i]);
    w.close(suites, 2);
    w.u8(1);  // \~english legacy_compression_methods: only null (4.1.2)  \~spanish legacy_compression_methods: solo la nula (4.1.2)  \~
    w.u8(0);
    const size_t exts = w.open(2);
    if (name_len != 0) write_server_name(w, cfg_.server_name, name_len);
    write_u16_list(w, ext::SupportedGroups, groups_, group_count_);
    write_u16_list(w, ext::SignatureAlgorithms, kSchemes, kSchemeCount);
    write_alpn(w, cfg_.alpn, cfg_.alpn_count);
    const uint16_t version = kTls13;
    write_supported_versions_client(w, &version, 1);
    const uint8_t *keys[2] = {share_pubs_[0], share_pubs_[1]};
    size_t lens[2] = {0, 0};
    for (size_t i = 0; i < share_count_; ++i) lens[i] = quic::public_key_size(group_of(share_groups_[i]));
    write_key_share_client(w, share_groups_, keys, lens, share_count_);
    // \~english The HelloRetryRequest's cookie goes back as it came (4.2.2).  \~spanish La cookie del HelloRetryRequest vuelve tal como vino (4.2.2).  \~
    if (cookie_.present) write_cookie(w, transcript_.bytes() + cookie_.at, cookie_.len);
    write_transport_parameters(w, cfg_.transport_params, cfg_.transport_params_len);
    w.close(exts, 2);
    w.end_message(msg);
    if (!commit(Space::Initial, w)) return false;
    state_ = State::WaitServerHello;
    return true;
}

bool Session::receive(Space s, const uint8_t *data, size_t n) noexcept {
    if (failed()) return false;
    if (n == 0) return true;
    // \~english Bytes of another level are the connection's to keep until TLS gets there (RFC 9001, 4.1.3).
    // \~spanish Los bytes de otro nivel los guarda la conexion hasta que TLS llegue alli (RFC 9001, 4.1.3).  \~
    if (s != reading_) return fail_quic(kProtocolViolation, "handshake bytes at a level TLS is not reading");
    Bytes &in = in_[static_cast<size_t>(s)];
    if (n > kMaxInput - in.len) return fail_quic(kCryptoBufferExceeded, "more handshake bytes than this end buffers");
    if (!reserve(in, n)) return fail_provider("out of memory for handshake input");
    util::vesta_memcpy(in.p + in.len, data, n);
    in.len += n;

    for (;;) {
        Handshake type;
        Span body;
        const size_t used = frame_message(in.p, in.len, type, body);
        if (used == 0) {
            // \~english A message that could never fit is refused now, not after waiting for it.
            // \~spanish Un mensaje que nunca podria caber se rechaza ya, no despues de esperarlo.  \~
            if (in.len >= 4 && (size_t{in.p[1]} << 16 | size_t{in.p[2]} << 8 | in.p[3]) > kMaxInput - 4)
                return fail_quic(kCryptoBufferExceeded, "a handshake message larger than this end buffers");
            return true;
        }
        if (!handle(type, in.p, used)) return false;
        drop_front(in, used);
        /* \~english
         * TLS moved on: whatever is left at the old level was never going to
         * be read, and that is a PROTOCOL_VIOLATION (RFC 9001, 4.1.3).
         * \~spanish
         * TLS paso de nivel: lo que quede en el nivel viejo ya nunca se iba a
         * leer, y eso es un PROTOCOL_VIOLATION (RFC 9001, 4.1.3).
         * \~ */
        if (reading_ != s) {
            if (in.len != 0)
                return fail_quic(kProtocolViolation, "handshake bytes left at a level TLS has finished with");
            return true;
        }
    }
}

const uint8_t *Session::output(Space s, size_t &n) const noexcept {
    const Bytes &b = out_[static_cast<size_t>(s)];
    n = b.len;
    return b.len != 0 ? b.p : nullptr;
}

void Session::sent(Space s, size_t n) noexcept {
    drop_front(out_[static_cast<size_t>(s)], n);
}

bool Session::handle(Handshake type, const uint8_t *m, size_t n) noexcept {
    // \~english QUIC has its own key update: a TLS one is 0x010a (RFC 9001, 6).
    // \~spanish QUIC tiene su propia actualizacion de claves: una de TLS es 0x010a (RFC 9001, 6).  \~
    if (type == Handshake::KeyUpdate)
        return fail(Alert::UnexpectedMessage, "a TLS KeyUpdate: QUIC updates keys itself (RFC 9001, 6)");
    switch (state_) {
    case State::WaitClientHello:
    case State::WaitSecondClientHello:
        if (type == Handshake::ClientHello) return on_client_hello(m, n);
        break;
    case State::WaitServerHello:
        if (type == Handshake::ServerHello) return on_server_hello(m, n);
        break;
    case State::WaitEncryptedExtensions:
        if (type == Handshake::EncryptedExtensions) return on_encrypted_extensions(m, n);
        break;
    case State::WaitCertificate:
        if (!cfg_.server && type == Handshake::CertificateRequest && !cert_requested_)
            return on_certificate_request(m, n);
        if (type == Handshake::Certificate) return on_certificate(m, n);
        break;
    case State::WaitCertificateVerify:
        if (type == Handshake::CertificateVerify) return on_certificate_verify(m, n);
        break;
    case State::WaitFinished:
        if (type == Handshake::Finished) return on_finished(m, n);
        break;
    case State::Connected:
        if (!cfg_.server && type == Handshake::NewSessionTicket) return on_new_session_ticket(m, n);
        // \~english No post-handshake client authentication in QUIC (RFC 9001, 4.4).
        // \~spanish Sin autenticacion del cliente tras el saludo en QUIC (RFC 9001, 4.4).  \~
        if (!cfg_.server && type == Handshake::CertificateRequest)
            return fail_quic(kProtocolViolation, "a CertificateRequest after the handshake (RFC 9001, 4.4)");
        break;
    default:
        break;
    }
    return fail(Alert::UnexpectedMessage, "a handshake message this end does not expect now (RFC 8446, 4)");
}

bool Session::on_client_hello(const uint8_t *m, size_t n) noexcept {
    const bool second = state_ == State::WaitSecondClientHello;
    ClientHello ch;
    const Parsed p = parse_client_hello(m, n, ch);
    if (!p.ok()) return fail(p.alert, "the ClientHello does not parse (RFC 8446, 4.1.2)");
    if (suite_count_ == 0 || group_count_ == 0)
        return fail(Alert::InternalError, "the provider supports no suite or no group to accept");
    if (cfg_.certificate_count == 0 || cfg_.signing_key == nullptr)
        return fail(Alert::InternalError, "the server has no certificate to authenticate with");
    if (!ch.ext.has_supported_versions || !listed_in(m, ch.ext.versions, kTls13))
        return fail(Alert::ProtocolVersion, "the client does not offer TLS 1.3 (RFC 9001, 4.2)");
    if (ch.session_id.len != 0)
        return fail_quic(kProtocolViolation, "a non-empty legacy_session_id: no compatibility mode in QUIC (RFC 9001, 8.4)");
    if (ch.ext.has_supported_groups != ch.ext.has_key_share)
        return fail(Alert::MissingExtension, "supported_groups and key_share go together (RFC 8446, 9.2)");
    if (!ch.ext.has_supported_groups || !ch.ext.has_signature_algorithms) {
        // \~english With a PSK they may be absent (9.2), but resumption is not done yet: nothing to agree on.
        // \~spanish Con una PSK pueden faltar (9.2), pero la reanudacion aun no esta: no hay en que ponerse de acuerdo.  \~
        if (ch.ext.has_pre_shared_key)
            return fail(Alert::HandshakeFailure, "a ClientHello that relies on a PSK, and resumption is not supported");
        return fail(Alert::MissingExtension, "no signature_algorithms or supported_groups without a PSK (RFC 8446, 9.2)");
    }
    if (!ch.ext.has_transport_parameters)
        return fail(Alert::MissingExtension, "no quic_transport_parameters (RFC 9001, 8.2)");
    if (second) {
        if (!same(m + ch.random.off, random_, sizeof random_))
            return fail(Alert::IllegalParameter, "the second ClientHello changed its random (RFC 8446, 4.1.2)");
        if (ch.ext.has_early_data)
            return fail(Alert::IllegalParameter, "early_data after a HelloRetryRequest (RFC 8446, 4.1.2)");
    }

    uint16_t chosen = suite_;
    if (second) {
        // \~english The same suite as the HelloRetryRequest (4.1.4).  \~spanish El mismo algoritmo que el HelloRetryRequest (4.1.4).  \~
        if (!listed_in(m, ch.cipher_suites, suite_))
            return fail(Alert::IllegalParameter, "the second ClientHello dropped the suite of the HelloRetryRequest (RFC 8446, 4.1.4)");
    } else if (!choose_suite(m, ch.cipher_suites, chosen)) {
        return fail(Alert::HandshakeFailure, "no cipher suite in common (RFC 8446, 4.1.1)");
    }
    if (!listed_in(m, ch.ext.signature_algorithms, static_cast<uint16_t>(cfg_.scheme)))
        return fail(Alert::HandshakeFailure, "the client accepts no signature this certificate makes (RFC 8446, 4.1.1)");
    if (!ch.ext.has_alpn) return fail(Alert::NoApplicationProtocol, "no ALPN: QUIC requires it (RFC 9001, 8.1)");
    if (!choose_alpn(m, ch.ext.alpn))
        return fail(Alert::NoApplicationProtocol, "no application protocol in common (RFC 7301, 3.2)");

    // \~english The client's first share in a group this end supports (4.2.8: in client preference order).
    // \~spanish La primera clave del cliente en un grupo que soporta este extremo (4.2.8: en orden de preferencia del cliente).  \~
    size_t share_at = 0;
    size_t share_len = 0;
    size_t entries = 0;
    uint16_t share_group = 0;
    for (size_t at = ch.ext.key_shares.off; at + 4 <= size_t{ch.ext.key_shares.off} + ch.ext.key_shares.len;) {
        const uint16_t g = read16(m + at);
        const size_t len = read16(m + at + 2);
        ++entries;
        if (share_len == 0 && listed(groups_, group_count_, g)) {
            share_group = g;
            share_at = at + 4;
            share_len = len;
        }
        at += 4 + len;
    }
    if (second && (entries != 1 || share_group != group_))
        return fail(Alert::IllegalParameter, "the second ClientHello must carry one share, for the group asked (RFC 8446, 4.1.2)");

    const size_t msg_at = transcript_.size();
    if (!add(m, n)) return false;
    if (share_len == 0) {
        // \~english No usable share: a group both support, or nothing (4.1.1), and then a HelloRetryRequest.
        // \~spanish Ninguna clave usable: un grupo que soporten los dos, o nada (4.1.1), y entonces un HelloRetryRequest.  \~
        for (uint32_t i = 0; i + 1 < ch.ext.supported_groups.len && share_group == 0; i += 2) {
            const uint16_t g = read16(m + ch.ext.supported_groups.off + i);
            if (listed(groups_, group_count_, g)) share_group = g;
        }
        if (share_group == 0) return fail(Alert::HandshakeFailure, "no key exchange group in common (RFC 8446, 4.1.1)");
        group_ = share_group;
        set_suite(chosen);
        if (!transcript_.replace_with_message_hash(c_, hash_))
            return fail_provider("the provider could not hash the first ClientHello");
        util::vesta_memcpy_noinline(random_, m + ch.random.off, sizeof random_);
        retried_ = true;
        alpn_.present = false;
        return hello_retry(ch);
    }
    group_ = share_group;
    set_suite(chosen);
    keep(msg_at, ch.ext.transport_parameters, peer_tp_);
    if (ch.ext.has_server_name && ch.ext.server_name.len != 0) keep(msg_at, ch.ext.server_name, server_name_);
    return server_flight(m, ch, share_at, share_len);
}

bool Session::hello_retry(const ClientHello &) noexcept {
    Writer w(nullptr, 0);
    if (!begin(Space::Initial, 128, w)) return false;
    // \~english A ServerHello with the special random, the suite, the version and the group wanted (4.1.4).
    // \~spanish Un ServerHello con el random especial, el algoritmo, la version y el grupo que se quiere (4.1.4).  \~
    const size_t msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    w.bytes(kHelloRetryRandom, 32);
    w.u8(0);
    w.u16(suite_);
    w.u8(0);
    const size_t exts = w.open(2);
    write_supported_versions_server(w, kTls13);
    write_key_share_retry(w, group_);
    w.close(exts, 2);
    w.end_message(msg);
    if (!commit(Space::Initial, w)) return false;
    state_ = State::WaitSecondClientHello;
    return true;
}

bool Session::server_flight(const uint8_t *m, const ClientHello &, size_t share_at, size_t share_len) noexcept {
    const Group g = group_of(group_);
    shares_[0] = c_.generate_key(g, share_pubs_[0]);
    if (shares_[0] == nullptr) return fail_provider("the provider could not make a key share");
    share_count_ = 1;
    uint8_t shared[quic::kMaxShared];
    const quic::Agreed agreed = c_.agree(shares_[0], m + share_at, share_len, shared);
    if (agreed == quic::Agreed::BadPeerKey)
        return fail(Alert::IllegalParameter, "the client's key share is not a valid key (RFC 8446, 4.2.8.2)");
    if (agreed != quic::Agreed::Ok) return fail_provider("the provider could not agree on a secret");
    uint8_t server_random[32];
    if (!c_.random(server_random, sizeof server_random)) {
        wipe(shared, sizeof shared);
        return fail_provider("the provider gave no random bytes");
    }

    // \~english ServerHello: only what the key exchange and the version need (4.1.3).
    // \~spanish ServerHello: solo lo que necesitan el intercambio de claves y la version (4.1.3).  \~
    Writer w(nullptr, 0);
    bool ok = begin(Space::Initial, 256, w);
    if (ok) {
        const size_t msg = w.begin_message(Handshake::ServerHello);
        w.u16(kLegacyVersion);
        w.bytes(server_random, sizeof server_random);
        w.u8(0);  // \~english the client's empty legacy_session_id, echoed  \~spanish el legacy_session_id vacio del cliente, devuelto  \~
        w.u16(suite_);
        w.u8(0);
        const size_t exts = w.open(2);
        write_supported_versions_server(w, kTls13);
        write_key_share_server(w, group_, share_pubs_[0], quic::public_key_size(g));
        w.close(exts, 2);
        w.end_message(msg);
        ok = commit(Space::Initial, w) && derive_handshake(shared, quic::kMaxShared);
    }
    wipe(shared, sizeof shared);
    forget_shares();
    if (!ok) return false;
    reading_ = Space::Handshake;

    // \~english EncryptedExtensions: the protocol chosen and the transport parameters (RFC 9001, 8.1 and 8.2).
    // \~spanish EncryptedExtensions: el protocolo elegido y los parametros de transporte (RFC 9001, 8.1 y 8.2).  \~
    if (!begin(Space::Handshake, 64 + 255 + cfg_.transport_params_len, w)) return false;
    size_t msg = w.begin_message(Handshake::EncryptedExtensions);
    size_t exts = w.open(2);
    write_alpn(w, cfg_.alpn + alpn_index_, 1);
    write_transport_parameters(w, cfg_.transport_params, cfg_.transport_params_len);
    w.close(exts, 2);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;

    if (cfg_.request_certificate) {
        // \~english CertificateRequest: an empty context in the handshake, and the schemes accepted (4.3.2).
        // \~spanish CertificateRequest: un contexto vacio en el saludo, y los esquemas aceptados (4.3.2).  \~
        if (!begin(Space::Handshake, 32, w)) return false;
        msg = w.begin_message(Handshake::CertificateRequest);
        w.u8(0);
        exts = w.open(2);
        write_u16_list(w, ext::SignatureAlgorithms, kSchemes, kSchemeCount);
        w.close(exts, 2);
        w.end_message(msg);
        if (!commit(Space::Handshake, w)) return false;
        cert_requested_ = true;
    }

    // \~english Certificate: no request context, the chain, no extensions per entry (4.4.2).
    // \~spanish Certificate: sin contexto de peticion, la cadena, sin extensiones por entrada (4.4.2).  \~
    size_t need = 16;
    for (size_t i = 0; i < cfg_.certificate_count; ++i) need += 5 + cfg_.certificate_lens[i];
    if (!begin(Space::Handshake, need, w)) return false;
    msg = w.begin_message(Handshake::Certificate);
    w.u8(0);
    const size_t list = w.open(3);
    for (size_t i = 0; i < cfg_.certificate_count; ++i) {
        const size_t entry = w.open(3);
        w.bytes(cfg_.certificates[i], cfg_.certificate_lens[i]);
        w.close(entry, 3);
        w.u16(0);
    }
    w.close(list, 3);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;

    // \~english CertificateVerify over the transcript up to the Certificate (4.4.3).
    // \~spanish CertificateVerify sobre la transcripcion hasta el Certificate (4.4.3).  \~
    const size_t hl = hash_size(hash_);
    uint8_t th[kMaxHash];
    uint8_t content[kMaxSigned];
    uint8_t sig[quic::kMaxSignature];
    size_t sig_len = 0;
    if (!transcript_.hash(c_, hash_, th) ||
        !c_.sign(cfg_.signing_key, content, signed_content(true, th, hl, content), sig, sizeof sig, sig_len))
        return fail_provider("the provider could not sign the CertificateVerify");
    if (!begin(Space::Handshake, 16 + sig_len, w)) return false;
    msg = w.begin_message(Handshake::CertificateVerify);
    w.u16(static_cast<uint16_t>(cfg_.scheme));
    const size_t signature = w.open(2);
    w.bytes(sig, sig_len);
    w.close(signature, 2);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;

    // \~english Finished, and with it the application secrets (4.4.4, 7.1).
    // \~spanish Finished, y con el los secretos de aplicacion (4.4.4, 7.1).  \~
    uint8_t fin[kMaxHash];
    if (!finished_for(false, fin) || !begin(Space::Handshake, 4 + hl, w)) return false;
    msg = w.begin_message(Handshake::Finished);
    w.bytes(fin, hl);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;
    if (!transcript_.hash(c_, hash_, th) || !schedule().application(th, ap_client_, ap_server_, exporter_))
        return fail_provider("the provider could not derive the application secrets");
    has_application_keys_ = true;
    state_ = cert_requested_ ? State::WaitCertificate : State::WaitFinished;
    return true;
}

bool Session::on_server_hello(const uint8_t *m, size_t n) noexcept {
    ServerHello sh;
    const Parsed p = parse_server_hello(m, n, sh);
    if (!p.ok()) return fail(p.alert, "the ServerHello does not parse (RFC 8446, 4.1.3)");
    // \~english What a HelloRetryRequest shares with a ServerHello is checked the same (4.1.4).
    // \~spanish Lo que un HelloRetryRequest comparte con un ServerHello se comprueba igual (4.1.4).  \~
    if (sh.session_id.len != 0)
        return fail(Alert::IllegalParameter, "the server did not echo the empty legacy_session_id (RFC 8446, 4.1.3)");
    if (!listed(suites_, suite_count_, sh.cipher_suite))
        return fail(Alert::IllegalParameter, "the server chose a cipher suite that was not offered (RFC 8446, 4.1.3)");
    if (!sh.ext.has_supported_versions)
        return fail(Alert::ProtocolVersion, "the server did not negotiate TLS 1.3 (RFC 9001, 4.2)");
    if (sh.ext.selected_version != kTls13)
        return fail(Alert::IllegalParameter, "the server chose a version that was not offered (RFC 8446, 4.2.1)");
    if (sh.retry) return on_retry(m, n, sh);

    if (retried_ && sh.cipher_suite != suite_)
        return fail(Alert::IllegalParameter, "the ServerHello changed the suite of the HelloRetryRequest (RFC 8446, 4.1.4)");
    if (sh.ext.has_pre_shared_key)
        return fail(Alert::UnsupportedExtension, "a pre_shared_key that was never offered (RFC 8446, 4.2)");
    if (!sh.ext.has_key_share)
        return fail(Alert::MissingExtension, "no key_share, and no PSK was offered (RFC 8446, 4.1.3)");
    size_t mine = share_count_;
    for (size_t i = 0; i < share_count_; ++i)
        if (share_groups_[i] == sh.ext.share_group) mine = i;
    // \~english The group of one of the client's shares -- after a retry, the one asked for (4.2.8).
    // \~spanish El grupo de una de las claves del cliente -- tras un reintento, el pedido (4.2.8).  \~
    if (mine == share_count_)
        return fail(Alert::IllegalParameter, "the server's key share is not in a group the client sent one for (RFC 8446, 4.2.8)");

    set_suite(sh.cipher_suite);
    uint8_t shared[quic::kMaxShared];
    const quic::Agreed agreed = c_.agree(shares_[mine], m + sh.ext.share_key.off, sh.ext.share_key.len, shared);
    if (agreed == quic::Agreed::BadPeerKey)
        return fail(Alert::IllegalParameter, "the server's key share is not a valid key (RFC 8446, 4.2.8.2)");
    if (agreed != quic::Agreed::Ok) return fail_provider("the provider could not agree on a secret");
    group_ = sh.ext.share_group;
    const bool ok = add(m, n) && derive_handshake(shared, quic::kMaxShared);
    wipe(shared, sizeof shared);
    forget_shares();
    if (!ok) return false;
    reading_ = Space::Handshake;
    state_ = State::WaitEncryptedExtensions;
    return true;
}

bool Session::on_retry(const uint8_t *m, size_t n, const ServerHello &sh) noexcept {
    if (retried_) return fail(Alert::UnexpectedMessage, "a second HelloRetryRequest (RFC 8446, 4.1.4)");
    bool changes = sh.ext.has_cookie;
    if (sh.ext.has_key_share) {
        const uint16_t g = sh.ext.share_group;
        if (!listed(groups_, group_count_, g))
            return fail(Alert::IllegalParameter, "the HelloRetryRequest asks for a group that was not offered (RFC 8446, 4.2.8)");
        if (listed(share_groups_, share_count_, g))
            return fail(Alert::IllegalParameter, "the HelloRetryRequest asks for a group that already had a share (RFC 8446, 4.2.8)");
        changes = true;
    }
    if (!changes) return fail(Alert::IllegalParameter, "a HelloRetryRequest that would change nothing (RFC 8446, 4.1.4)");

    // \~english ClientHello1 becomes its hash, then the HelloRetryRequest follows (4.4.1).
    // \~spanish ClientHello1 pasa a ser su resumen, y luego sigue el HelloRetryRequest (4.4.1).  \~
    set_suite(sh.cipher_suite);
    if (!transcript_.replace_with_message_hash(c_, hash_))
        return fail_provider("the provider could not hash the first ClientHello");
    const size_t msg_at = transcript_.size();
    if (!add(m, n)) return false;
    if (sh.ext.has_cookie) keep(msg_at, sh.ext.cookie, cookie_);
    retried_ = true;
    if (sh.ext.has_key_share) {
        // \~english One share, of the group asked for, instead of the first ones (4.1.2).
        // \~spanish Una clave, del grupo pedido, en lugar de las primeras (4.1.2).  \~
        forget_shares();
        shares_[0] = c_.generate_key(group_of(sh.ext.share_group), share_pubs_[0]);
        if (shares_[0] == nullptr) return fail_provider("the provider could not make a key share");
        share_groups_[0] = sh.ext.share_group;
        share_count_ = 1;
    }
    return client_hello();
}

bool Session::on_encrypted_extensions(const uint8_t *m, size_t n) noexcept {
    EncryptedExtensions ee;
    const Parsed p = parse_encrypted_extensions(m, n, ee);
    if (!p.ok()) return fail(p.alert, "the EncryptedExtensions do not parse (RFC 8446, 4.3.1)");
    if (!ee.ext.has_transport_parameters)
        return fail(Alert::MissingExtension, "no quic_transport_parameters (RFC 9001, 8.2)");
    // \~english No answer to what was not asked (4.2).  \~spanish Ninguna respuesta a lo que no se pregunto (4.2).  \~
    if (ee.ext.has_server_name && cfg_.server_name == nullptr)
        return fail(Alert::UnsupportedExtension, "a server_name answer to a ClientHello without one (RFC 8446, 4.2)");
    if (ee.ext.has_early_data)
        return fail(Alert::UnsupportedExtension, "early_data that was never offered (RFC 8446, 4.2)");
    if (!ee.ext.has_alpn)
        return fail(Alert::NoApplicationProtocol, "the server chose no application protocol (RFC 9001, 8.1)");
    // \~english Exactly one name, checked when read: its length byte, then the name.
    // \~spanish Exactamente un nombre, comprobado al leerlo: su byte de longitud, y luego el nombre.  \~
    const Span name{ee.ext.alpn.off + 1, ee.ext.alpn.len - 1u};
    bool offered = false;
    for (size_t i = 0; i < cfg_.alpn_count && !offered; ++i) {
        size_t len = 0;
        while (cfg_.alpn[i][len] != '\0') ++len;
        offered = len == name.len && same(m + name.off, reinterpret_cast<const uint8_t *>(cfg_.alpn[i]), len);
    }
    if (!offered)
        return fail(Alert::NoApplicationProtocol, "the server chose a protocol that was not offered (RFC 9001, 8.1)");
    const size_t msg_at = transcript_.size();
    if (!add(m, n)) return false;
    keep(msg_at, ee.ext.transport_parameters, peer_tp_);
    keep(msg_at, name, alpn_);
    state_ = State::WaitCertificate;
    return true;
}

bool Session::on_certificate_request(const uint8_t *m, size_t n) noexcept {
    CertificateRequest cr;
    const Parsed p = parse_certificate_request(m, n, cr);
    if (!p.ok()) return fail(p.alert, "the CertificateRequest does not parse (RFC 8446, 4.3.2)");
    if (cr.context.len != 0)
        return fail(Alert::IllegalParameter, "a CertificateRequest context in the handshake SHALL be empty (RFC 8446, 4.3.2)");
    if (!add(m, n)) return false;
    // \~english No certificate to send: an empty Certificate, and no CertificateVerify (4.4.2, 4.4.3).
    // \~spanish Ningun certificado que mandar: un Certificate vacio, y ningun CertificateVerify (4.4.2, 4.4.3).  \~
    cert_requested_ = true;
    return true;
}

bool Session::on_certificate(const uint8_t *m, size_t n) noexcept {
    CertificateMessage ct;
    const Parsed p = parse_certificate(m, n, ct);
    if (!p.ok()) return fail(p.alert, "the Certificate does not parse (RFC 8446, 4.4.2)");
    // \~english A server's is empty; a client's echoes the request's, which in the handshake is empty (4.4.2, 4.3.2).
    // \~spanish El de un servidor va vacio; el de un cliente repite el de la peticion, que en el saludo va vacio (4.4.2, 4.3.2).  \~
    if (ct.context.len != 0)
        return fail(Alert::IllegalParameter, "a Certificate whose request context is not the one asked (RFC 8446, 4.4.2)");
    const size_t msg_at = transcript_.size();
    if (ct.entries.len == 0) {
        if (!cfg_.server) return fail(Alert::DecodeError, "an empty server Certificate (RFC 8446, 4.4.2.4)");
        // \~english A client with nothing to show: the server MAY go on without authenticating it (4.4.2.4).
        // \~spanish Un cliente sin nada que ensenar: el servidor PUEDE seguir sin autenticarlo (4.4.2.4).  \~
        if (!add(m, n)) return false;
        state_ = State::WaitFinished;
        return true;
    }
    if (!add(m, n)) return false;
    certificate_.present = true;
    certificate_.at = msg_at;
    certificate_.len = n;
    state_ = State::WaitCertificateVerify;
    return true;
}

bool Session::on_certificate_verify(const uint8_t *m, size_t n) noexcept {
    CertificateVerify cv;
    const Parsed p = parse_certificate_verify(m, n, cv);
    if (!p.ok()) return fail(p.alert, "the CertificateVerify does not parse (RFC 8446, 4.4.3)");
    if (!listed(kSchemes, kSchemeCount, cv.scheme))
        return fail(Alert::IllegalParameter, "a CertificateVerify in a scheme that was not offered (RFC 8446, 4.4.3)");
    const uint8_t *leaf = nullptr;
    size_t leaf_len = 0;
    if (!peer_certificate(0, leaf, leaf_len)) return fail(Alert::InternalError, "the kept Certificate lost its first entry");
    const size_t hl = hash_size(hash_);
    uint8_t th[kMaxHash];
    uint8_t content[kMaxSigned];
    if (!transcript_.hash(c_, hash_, th)) return fail_provider("the provider could not hash the transcript");
    // \~english The peer's signature carries the peer's context string.  \~spanish La firma del otro lleva la cadena de contexto del otro.  \~
    const quic::Verified v = c_.verify(static_cast<Scheme>(cv.scheme), leaf, leaf_len, content,
                                       signed_content(!cfg_.server, th, hl, content), m + cv.signature.off,
                                       cv.signature.len);
    if (v == quic::Verified::Bad)
        return fail(Alert::DecryptError, "the peer's CertificateVerify does not verify (RFC 8446, 4.4.3)");
    // \~english A scheme the certificate's key cannot make: the field contradicts the certificate (6.2).
    // \~spanish Un esquema que la clave del certificado no puede hacer: el campo contradice al certificado (6.2).  \~
    if (v == quic::Verified::WrongKey)
        return fail(Alert::IllegalParameter, "the signature scheme does not fit the certificate's key (RFC 8446, 4.4.3)");
    if (v != quic::Verified::Ok) return fail_provider("the provider could not check the signature");
    if (!add(m, n)) return false;
    state_ = State::WaitFinished;
    return true;
}

bool Session::on_finished(const uint8_t *m, size_t n) noexcept {
    const size_t hl = hash_size(hash_);
    if (n - 4 != hl) return fail(Alert::DecodeError, "a Finished of the wrong length (RFC 8446, 4.4.4)");
    // \~english The peer's Finished uses the peer's base key (4.4).  \~spanish El Finished del otro usa la clave base del otro (4.4).  \~
    uint8_t want[kMaxHash];
    if (!finished_for(cfg_.server, want)) return false;
    const bool match = same(want, m + 4, hl);
    wipe(want, sizeof want);
    if (!match) return fail(Alert::DecryptError, "the peer's Finished does not match (RFC 8446, 4.4.4)");
    if (!add(m, n)) return false;
    uint8_t th[kMaxHash];
    if (cfg_.server) {
        if (!transcript_.hash(c_, hash_, th) || !schedule().resumption(th, resumption_))
            return fail_provider("the provider could not derive the resumption secret");
        complete_ = true;
        reading_ = Space::Application;
        state_ = State::Connected;
        return true;
    }
    if (!transcript_.hash(c_, hash_, th) || !schedule().application(th, ap_client_, ap_server_, exporter_))
        return fail_provider("the provider could not derive the application secrets");
    has_application_keys_ = true;
    return client_finished();
}

bool Session::client_finished() noexcept {
    Writer w(nullptr, 0);
    if (cert_requested_) {
        if (!begin(Space::Handshake, 16, w)) return false;
        const size_t msg = w.begin_message(Handshake::Certificate);
        w.u8(0);
        w.close(w.open(3), 3);
        w.end_message(msg);
        if (!commit(Space::Handshake, w)) return false;
    }
    const size_t hl = hash_size(hash_);
    uint8_t fin[kMaxHash];
    if (!finished_for(true, fin) || !begin(Space::Handshake, 4 + hl, w)) return false;
    const size_t msg = w.begin_message(Handshake::Finished);
    w.bytes(fin, hl);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;
    uint8_t th[kMaxHash];
    if (!transcript_.hash(c_, hash_, th) || !schedule().resumption(th, resumption_))
        return fail_provider("the provider could not derive the resumption secret");
    complete_ = true;
    reading_ = Space::Application;
    state_ = State::Connected;
    return true;
}

bool Session::on_new_session_ticket(const uint8_t *m, size_t n) noexcept {
    NewSessionTicket nst;
    const Parsed p = parse_new_session_ticket(m, n, nst);
    if (!p.ok()) return fail(p.alert, "the NewSessionTicket does not parse (RFC 8446, 4.6.1)");
    // \~english QUIC repurposes max_early_data_size as a flag: 0xffffffff or absent (RFC 9001, 4.6.1).
    // \~spanish QUIC reutiliza max_early_data_size como marca: 0xffffffff o ausente (RFC 9001, 4.6.1).  \~
    if (nst.ext.has_early_data && nst.ext.max_early_data != 0xffffffffu)
        return fail_quic(kProtocolViolation, "a NewSessionTicket early_data other than 0xffffffff (RFC 9001, 4.6.1)");
    ++tickets_;
    return true;
}

const uint8_t *Session::read_secret(Space s) const noexcept {
    if (s == Space::Handshake && has_handshake_keys_) return cfg_.server ? hs_client_ : hs_server_;
    if (s != Space::Application) return nullptr;
    // \~english A server reads no 1-RTT before the handshake is complete (RFC 9001, 5.7).
    // \~spanish Un servidor no lee 1-RTT antes de que el saludo este completo (RFC 9001, 5.7).  \~
    if (cfg_.server) return complete_ ? ap_client_ : nullptr;
    return has_application_keys_ ? ap_server_ : nullptr;
}

const uint8_t *Session::write_secret(Space s) const noexcept {
    if (s == Space::Handshake && has_handshake_keys_) return cfg_.server ? hs_server_ : hs_client_;
    // \~english Application secrets exist once this end's Finished is written: the server's first flight, the client's last.
    // \~spanish Los secretos de aplicacion existen cuando el Finished propio esta escrito: el primer vuelo del servidor, el ultimo del cliente.  \~
    if (s != Space::Application || !has_application_keys_) return nullptr;
    return cfg_.server ? ap_server_ : ap_client_;
}

const uint8_t *Session::peer_transport_params(size_t &n) const noexcept {
    n = peer_tp_.len;
    return peer_tp_.present ? transcript_.bytes() + peer_tp_.at : nullptr;
}

const uint8_t *Session::alpn(size_t &n) const noexcept {
    n = 0;
    if (!alpn_.present) return nullptr;
    if (!cfg_.server) {
        n = alpn_.len;
        return transcript_.bytes() + alpn_.at;
    }
    const char *name = cfg_.alpn[alpn_index_];
    while (name[n] != '\0') ++n;
    return reinterpret_cast<const uint8_t *>(name);
}

const uint8_t *Session::server_name(size_t &n) const noexcept {
    n = server_name_.len;
    return server_name_.present ? transcript_.bytes() + server_name_.at : nullptr;
}

bool Session::peer_certificate(size_t i, const uint8_t *&cert, size_t &n) const noexcept {
    if (!certificate_.present) return false;
    const uint8_t *m = transcript_.bytes() + certificate_.at;
    CertificateMessage ct;
    if (!parse_certificate(m, certificate_.len, ct).ok()) return false;
    uint32_t at = 0;
    Span s;
    for (size_t k = 0; k <= i; ++k)
        if (!next_certificate(m, ct, at, s)) return false;
    cert = m + s.off;
    n = s.len;
    return true;
}

} // namespace tls
} // namespace http_vx
