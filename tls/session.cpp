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
#include "http_vx/wipe.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace tls {

namespace {

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
        wipe_secret(b.p, b.cap);
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
    wipe_secret(b.p, b.cap);
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
    wipe_secret(hs_client_, sizeof hs_client_);
    wipe_secret(hs_server_, sizeof hs_server_);
    wipe_secret(ap_client_, sizeof ap_client_);
    wipe_secret(ap_server_, sizeof ap_server_);
    wipe_secret(exporter_, sizeof exporter_);
    wipe_secret(resumption_, sizeof resumption_);
    wipe_secret(psk_, sizeof psk_);
    wipe_secret(early_secret_, sizeof early_secret_);
    wipe_secret(binder_key_, sizeof binder_key_);
    if (kept_ != nullptr) {
        wipe_secret(kept_, kKeptTickets * sizeof(Ticket));
        util::host_free(kept_);
    }
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
        /* \~english
         * Over TCP there are no QUIC errors, only alerts.  Bytes left at a
         * level TLS moved past are a message that spans a key change:
         * unexpected_message (RFC 8446, 5.1).  A message larger than this end
         * buffers is the peer's field out of what is accepted:
         * illegal_parameter, as the reference implementations answer it.
         * \~spanish
         * Sobre TCP no hay errores de QUIC, solo alertas.  Bytes que quedan en un
         * nivel que TLS ya dejo atras son un mensaje que cruza un cambio de clave:
         * unexpected_message (RFC 8446, 5.1).  Un mensaje mayor de lo que guarda
         * este extremo es un campo del otro fuera de lo aceptado:
         * illegal_parameter, como lo contestan las implementaciones de referencia.
         * \~ */
        if (cfg_.over_tcp && code < kCryptoError) {
            const Alert a = code == kProtocolViolation ? Alert::UnexpectedMessage : Alert::IllegalParameter;
            failure_.code = kCryptoError + static_cast<uint8_t>(a);
            failure_.alert = a;
        }
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

bool Session::commit(Space s, Writer &w, bool in_transcript) noexcept {
    if (w.failed()) return fail_provider("a handshake message did not fit where it was written");
    Bytes &b = out_[static_cast<size_t>(s)];
    // \~english Every handshake message sent is part of the transcript (4.4.1).  \~spanish Cada mensaje del saludo enviado es parte de la transcripcion (4.4.1).  \~
    if (in_transcript && !add(b.p + b.len, w.size())) return false;
    b.len += w.size();
    return true;
}

bool Session::binder(const uint8_t *psk, Hash h, const uint8_t *partial, size_t partial_len, uint8_t *out) noexcept {
    /* \~english
     * A Finished whose base key is the binder key, over the transcript so
     * far followed by the ClientHello up to its binders (4.2.11.2): after a
     * HelloRetryRequest the transcript already holds message_hash and the
     * retry.  Hashed in one piece, like every transcript here.
     * \~spanish
     * Un Finished cuya clave base es la del binder, sobre la transcripcion hasta
     * ahora seguida del ClientHello hasta sus binders (4.2.11.2): tras un
     * HelloRetryRequest la transcripcion ya lleva message_hash y el reintento.
     * Resumido de una pieza, como todas las transcripciones de aqui.
     * \~ */
    const size_t total = transcript_.size() + partial_len;
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed, util::AllocFill::All);
    uint8_t *buf = static_cast<uint8_t *>(util::host_alloc(total));
    if (buf == nullptr) return fail_provider("out of memory for a PSK binder");
    if (transcript_.size() != 0) util::vesta_memcpy(buf, transcript_.bytes(), transcript_.size());
    util::vesta_memcpy(buf + transcript_.size(), partial, partial_len);
    KeySchedule ks(c_, h);
    uint8_t key[kMaxHash];
    uint8_t th[kMaxHash];
    const bool ok = ks.start(psk, hash_size(h)) && ks.binder_key(true, key) && c_.digest(h, buf, total, th) &&
                    finished_data(c_, h, key, th, out);
    wipe_secret(buf, total);
    util::host_free(buf);
    wipe_secret(key, sizeof key);
    return ok || fail_provider("the provider could not compute a PSK binder");
}

bool Session::take_ticket(Ticket &out) noexcept {
    if (kept_count_ == 0) return false;
    out = kept_[0];
    for (size_t i = 1; i < kept_count_; ++i) kept_[i - 1] = kept_[i];
    --kept_count_;
    // \~english The slot freed held a PSK.  \~spanish La ranura liberada tenia una PSK.  \~
    wipe_secret(&kept_[kept_count_], sizeof(Ticket));
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
    // \~english The Early Secret, then the (EC)DHE secret over ClientHello..ServerHello (7.1).
    // \~spanish El Early Secret, y luego el secreto (EC)DHE sobre ClientHello..ServerHello (7.1).  \~
    uint8_t th[kMaxHash];
    // \~english A resumed handshake starts from the PSK instead of zeros (7.1).
    // \~spanish Un saludo reanudado empieza desde la PSK en lugar de ceros (7.1).  \~
    if (!schedule().start(resumed_ ? psk_ : nullptr, resumed_ ? psk_len_ : 0) || !transcript_.hash(c_, hash_, th) ||
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
    if (cfg_.over_tcp) {
        // \~english Over TCP: no transport parameters (RFC 9001, 8.2), and 0-RTT is not done.
        // \~spanish Sobre TCP: sin parametros de transporte (RFC 9001, 8.2), y 0-RTT no se hace.  \~
        if (cfg_.transport_params != nullptr)
            return fail(Alert::InternalError, "transport parameters over TCP: they are QUIC's (RFC 9001, 8.2)");
        if (cfg_.early_data) return fail(Alert::InternalError, "0-RTT over TCP is not supported by this end");
    } else {
        if (cfg_.alpn_count == 0) return fail(Alert::InternalError, "no application protocol to offer: QUIC requires ALPN");
        if (cfg_.transport_params == nullptr)
            return fail(Alert::InternalError, "no transport parameters to send: QUIC requires them");
    }
    // \~english A server's chain is always checked, or not checked on purpose; never by default.
    // \~spanish La cadena de un servidor siempre se comprueba, o se deja sin comprobar a proposito; nunca por defecto.  \~
    if (cfg_.verifier == nullptr && !cfg_.trust_any_certificate)
        return fail(Alert::InternalError, "no certificate verifier, and trust_any_certificate not set");
    if (cfg_.verifier != nullptr && cfg_.trust_any_certificate)
        return fail(Alert::InternalError, "a certificate verifier and trust_any_certificate: one or the other");
    if (cfg_.verifier != nullptr && cfg_.server_name == nullptr)
        return fail(Alert::InternalError, "a certificate verifier and no server_name to check the certificate against");
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
                        2 * (4 + quic::kMaxPublicKey) + cookie_.len +
                        (cfg_.resume != nullptr ? cfg_.resume->identity_len + 64 : 0);
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
    if (cfg_.alpn_count != 0) write_alpn(w, cfg_.alpn, cfg_.alpn_count);
    const uint16_t version = kTls13;
    write_supported_versions_client(w, &version, 1);
    const uint8_t *keys[2] = {share_pubs_[0], share_pubs_[1]};
    size_t lens[2] = {0, 0};
    for (size_t i = 0; i < share_count_; ++i) lens[i] = quic::public_key_size(group_of(share_groups_[i]));
    write_key_share_client(w, share_groups_, keys, lens, share_count_);
    // \~english The HelloRetryRequest's cookie goes back as it came (4.2.2).  \~spanish La cookie del HelloRetryRequest vuelve tal como vino (4.2.2).  \~
    if (cookie_.present) write_cookie(w, transcript_.bytes() + cookie_.at, cookie_.len);
    if (!cfg_.over_tcp) write_transport_parameters(w, cfg_.transport_params, cfg_.transport_params_len);

    /* \~english
     * A ticket, if one is usable: after a retry only if its hash is the
     * suite's (4.1.4).  psk_key_exchange_modes goes with it (4.2.9), and
     * pre_shared_key goes last (4.2.11), its binder written once the
     * message around it is complete.
     * \~spanish
     * Un ticket, si hay uno usable: tras un reintento solo si su resumen es el
     * del algoritmo (4.1.4).  psk_key_exchange_modes va con el (4.2.9), y
     * pre_shared_key va la ultima (4.2.11), con su binder escrito cuando el
     * mensaje que lo rodea esta completo.
     * \~ */
    psk_offered_ = retried_ ? psk_offered_ && quic::hash_of(aead_of(cfg_.resume->suite)) == hash_
                            : resume_usable();
    size_t binders_at = 0;
    Hash psk_hash = Hash::Sha256;
    // \~english Early data only with a ticket that allows it, and never after a retry (4.1.2).
    // \~spanish Datos tempranos solo con un ticket que los permita, y nunca tras un reintento (4.1.2).  \~
    const bool offer_early = !retried_ && psk_offered_ && cfg_.early_data && cfg_.resume->early_data;
    if (!retried_) early_offered_ = offer_early;
    if (psk_offered_) {
        const Ticket &t = *cfg_.resume;
        psk_hash = quic::hash_of(aead_of(t.suite));
        const uint8_t dhe = 1;  // \~english psk_dhe_ke only  \~spanish solo psk_dhe_ke  \~
        write_psk_modes(w, &dhe, 1);
        if (offer_early) write_empty_extension(w, ext::EarlyData);
        // \~english The age in milliseconds plus ticket_age_add, modulo 2^32 (4.2.11.1).
        // \~spanish La edad en milisegundos mas ticket_age_add, modulo 2^32 (4.2.11.1).  \~
        const uint32_t age = static_cast<uint32_t>((clock_us_ - t.received_us) / 1000) + t.age_add;
        const size_t e = w.begin_extension(ext::PreSharedKey);
        const size_t ids = w.open(2);
        const size_t id = w.open(2);
        w.bytes(t.identity, t.identity_len);
        w.close(id, 2);
        w.u32(age);
        w.close(ids, 2);
        binders_at = w.size();
        const size_t list = w.open(2);
        const size_t entry = w.open(1);
        const uint8_t zeros[kMaxHash] = {};
        w.bytes(zeros, hash_size(psk_hash));
        w.close(entry, 1);
        w.close(list, 2);
        w.close(e, 2);
    }
    w.close(exts, 2);
    w.end_message(msg);
    if (psk_offered_ && !w.failed() &&
        !binder(cfg_.resume->psk, psk_hash, w.data(), binders_at, w.data() + binders_at + 3))
        return false;
    if (!commit(Space::Initial, w)) return false;
    // \~english With the ClientHello in the transcript, the secret 0-RTT goes out with; the ticket's suite (4.2.10).
    // \~spanish Con el ClientHello en la transcripcion, el secreto con el que sale el 0-RTT; el algoritmo del ticket (4.2.10).  \~
    if (offer_early) {
        if (!derive_early(cfg_.resume->psk, psk_hash)) return false;
        early_aead_ = aead_of(cfg_.resume->suite);
    }
    state_ = State::WaitServerHello;
    return true;
}

const uint8_t *Session::early_secret() const noexcept {
    return (cfg_.server ? early_accepted_ : early_offered_) ? early_secret_ : nullptr;
}

bool Session::resume_usable() const noexcept {
    if (cfg_.server || cfg_.resume == nullptr) return false;
    const Ticket &t = *cfg_.resume;
    if (t.identity_len == 0 || t.identity_len > Ticket::kMaxIdentity || t.lifetime_s == 0) return false;
    // \~english A suite of its hash must be one this end offers (4.6.1).  \~spanish Un algoritmo de su resumen tiene que ser uno que ofrece este extremo (4.6.1).  \~
    if (!listed(suites_, suite_count_, t.suite)) return false;
    // \~english Not past its lifetime, and never past seven days (4.2.11.1, 4.6.1).
    // \~spanish No pasado su vida, y nunca pasados siete dias (4.2.11.1, 4.6.1).  \~
    if (clock_us_ < t.received_us) return false;
    const uint64_t age_s = (clock_us_ - t.received_us) / 1000000;
    if (age_s >= t.lifetime_s || age_s >= kMaxTicketLifetime) return false;
    // \~english Only for the host name it came from (4.6.1: SHOULD).  \~spanish Solo para el nombre del que vino (4.6.1: DEBERIA).  \~
    size_t name_len = 0;
    if (cfg_.server_name != nullptr)
        while (cfg_.server_name[name_len] != '\0') ++name_len;
    return name_len == t.server_name_len &&
           (name_len == 0 || same(reinterpret_cast<const uint8_t *>(cfg_.server_name), t.server_name, name_len));
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
    // \~english Over TCP a KeyUpdate is the channel's, and one that reaches the handshake came before a Finished (4.6.3).
    // \~spanish Sobre TCP un KeyUpdate es del canal, y uno que llega al saludo vino antes de un Finished (4.6.3).  \~
    if (type == Handshake::KeyUpdate)
        return fail(Alert::UnexpectedMessage, cfg_.over_tcp ? "a KeyUpdate before the Finished (RFC 8446, 4.6.3)"
                                                            : "a TLS KeyUpdate: QUIC updates keys itself (RFC 9001, 6)");
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
        // \~english Over TCP: post_handshake_auth was never offered (RFC 8446, 4.6.2).
        // \~spanish Sobre TCP: nunca se ofrecio post_handshake_auth (RFC 8446, 4.6.2).  \~
        if (!cfg_.server && type == Handshake::CertificateRequest)
            return cfg_.over_tcp
                       ? fail(Alert::UnexpectedMessage, "a CertificateRequest without post_handshake_auth (RFC 8446, 4.6.2)")
                       : fail_quic(kProtocolViolation, "a CertificateRequest after the handshake (RFC 9001, 4.4)");
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
    if (cfg_.request_certificate && cfg_.verifier == nullptr && !cfg_.trust_any_certificate)
        return fail(Alert::InternalError, "a client certificate asked for, no verifier, and trust_any_certificate not set");
    if (cfg_.verifier != nullptr && cfg_.trust_any_certificate)
        return fail(Alert::InternalError, "a certificate verifier and trust_any_certificate: one or the other");
    if (cfg_.require_client_certificate && !cfg_.request_certificate)
        return fail(Alert::InternalError, "a client certificate required but never asked for");
    // \~english 0-RTT without replay protection is not offered quietly: it is refused out loud (RFC 8446, 8).
    // \~spanish 0-RTT sin proteccion contra repeticiones no se ofrece en silencio: se rechaza en voz alta (RFC 8446, 8).  \~
    if (cfg_.early_data && (cfg_.replay == nullptr || !cfg_.replay->ready() || cfg_.tickets == nullptr))
        return fail(Alert::InternalError, "0-RTT needs tickets and a replay guard (RFC 8446, 8)");
    if (cfg_.early_data && cfg_.over_tcp) return fail(Alert::InternalError, "0-RTT over TCP is not supported by this end");
    if (cfg_.over_tcp && cfg_.transport_params != nullptr)
        return fail(Alert::InternalError, "transport parameters over TCP: they are QUIC's (RFC 9001, 8.2)");
    if (!ch.ext.has_supported_versions || !listed_in(m, ch.ext.versions, kTls13))
        return fail(Alert::ProtocolVersion, "the client does not offer TLS 1.3 (RFC 9001, 4.2)");
    if (!cfg_.over_tcp && ch.session_id.len != 0)
        return fail_quic(kProtocolViolation, "a non-empty legacy_session_id: no compatibility mode in QUIC (RFC 9001, 8.4)");
    // \~english The second ClientHello keeps the first one's session ID: 4.1.2 lets it change nothing else.
    // \~spanish El segundo ClientHello conserva el identificador de sesion del primero: 4.1.2 no le deja cambiar nada mas.  \~
    if (second && (ch.session_id.len != session_id_len_ ||
                   !same(m + ch.session_id.off, session_id_, session_id_len_)))
        return fail(Alert::IllegalParameter, "the second ClientHello changed its legacy_session_id (RFC 8446, 4.1.2)");
    // \~english Echoed as it came, whether or not it means anything to this end (4.1.3).
    // \~spanish Se devuelve tal como vino, signifique algo para este extremo o no (4.1.3).  \~
    session_id_len_ = static_cast<uint8_t>(ch.session_id.len);
    util::vesta_memcpy_noinline(session_id_, m + ch.session_id.off, session_id_len_);
    if (!second) early_offered_ = ch.ext.has_early_data;
    if (ch.ext.has_supported_groups != ch.ext.has_key_share)
        return fail(Alert::MissingExtension, "supported_groups and key_share go together (RFC 8446, 9.2)");
    if (!ch.ext.has_supported_groups) {
        // \~english Without groups only psk_ke is left, and this end resumes only with (EC)DHE (4.2.9).
        // \~spanish Sin grupos solo queda psk_ke, y este extremo solo reanuda con (EC)DHE (4.2.9).  \~
        if (ch.ext.has_pre_shared_key)
            return fail(Alert::HandshakeFailure, "a ClientHello that offers only psk_ke: this end resumes with (EC)DHE");
        return fail(Alert::MissingExtension, "no supported_groups without a PSK (RFC 8446, 9.2)");
    }
    if (!ch.ext.has_signature_algorithms && !ch.ext.has_pre_shared_key)
        return fail(Alert::MissingExtension, "no signature_algorithms without a PSK (RFC 8446, 9.2)");
    if (cfg_.over_tcp && ch.ext.has_transport_parameters)
        return fail(Alert::UnsupportedExtension, "quic_transport_parameters over TCP (RFC 9001, 8.2)");
    if (!cfg_.over_tcp && !ch.ext.has_transport_parameters)
        return fail(Alert::MissingExtension, "no quic_transport_parameters (RFC 9001, 8.2)");
    if (second) {
        if (!same(m + ch.random.off, random_, sizeof random_))
            return fail(Alert::IllegalParameter, "the second ClientHello changed its random (RFC 8446, 4.1.2)");
        if (ch.ext.has_early_data)
            return fail(Alert::IllegalParameter, "early_data after a HelloRetryRequest (RFC 8446, 4.1.2)");
    }

    uint16_t chosen = suite_;
    // \~english A ticket that opens and is alive steers the suite: one of its hash (4.2.11).
    // \~spanish Un ticket que se abre y sigue vivo guia el algoritmo: uno de su resumen (4.2.11).  \~
    uint16_t ticket_suite = second ? suite_ : 0;
    const bool may_resume = accept_psk(m, ch, false, ticket_suite);
    if (second) {
        // \~english The same suite as the HelloRetryRequest (4.1.4).  \~spanish El mismo algoritmo que el HelloRetryRequest (4.1.4).  \~
        if (!listed_in(m, ch.cipher_suites, suite_))
            return fail(Alert::IllegalParameter, "the second ClientHello dropped the suite of the HelloRetryRequest (RFC 8446, 4.1.4)");
    } else if (may_resume) {
        chosen = ticket_suite;
    } else if (!choose_suite(m, ch.cipher_suites, chosen)) {
        return fail(Alert::HandshakeFailure, "no cipher suite in common (RFC 8446, 4.1.1)");
    }
    // \~english Over TCP a client may offer no ALPN, and the server then chooses none -- unless it needs one.
    // \~spanish Sobre TCP un cliente puede no ofrecer ALPN, y entonces el servidor no elige ninguno -- salvo que le haga falta.  \~
    if (!ch.ext.has_alpn && cfg_.over_tcp && cfg_.require_alpn)
        return fail(Alert::NoApplicationProtocol, "no ALPN, and this server serves only protocols chosen by it (RFC 7301, 3.2)");
    if (!ch.ext.has_alpn && !cfg_.over_tcp)
        return fail(Alert::NoApplicationProtocol, "no ALPN: QUIC requires it (RFC 9001, 8.1)");
    if (ch.ext.has_alpn && !choose_alpn(m, ch.ext.alpn))
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

    /* \~english
     * With a share there is no retry, so this is the ClientHello the PSK is
     * accepted on -- after its binder, over the transcript before it
     * (4.2.11.2).  A binder that does not match ends the handshake; a
     * ticket that cannot be used just means no resumption.
     * \~spanish
     * Con una clave no hay reintento, asi que este es el ClientHello en el que
     * se acepta la PSK -- tras su binder, sobre la transcripcion anterior a el
     * (4.2.11.2).  Un binder que no casa acaba el saludo; un ticket que no se
     * puede usar solo significa que no se reanuda.
     * \~ */
    if (share_len != 0 && may_resume && !accept_psk(m, ch, true, chosen) && failed()) return false;
    // \~english A certificate is only needed without a PSK -- and on a retry, the second ClientHello decides.
    // \~spanish Un certificado solo hace falta sin PSK -- y en un reintento, decide el segundo ClientHello.  \~
    if (!resumed_ && !(share_len == 0 && may_resume)) {
        if (!ch.ext.has_signature_algorithms)
            return fail(Alert::MissingExtension, "no signature_algorithms and no PSK accepted (RFC 8446, 9.2)");
        if (!listed_in(m, ch.ext.signature_algorithms, static_cast<uint16_t>(cfg_.scheme)))
            return fail(Alert::HandshakeFailure, "the client accepts no signature this certificate makes (RFC 8446, 4.1.1)");
    }

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
    if (ch.ext.has_transport_parameters) keep(msg_at, ch.ext.transport_parameters, peer_tp_);
    if (ch.ext.has_server_name && ch.ext.server_name.len != 0) keep(msg_at, ch.ext.server_name, server_name_);
    // \~english Decided with the ClientHello alone in the transcript: its early secret is over it (7.1).
    // \~spanish Se decide con el ClientHello solo en la transcripcion: su secreto temprano es sobre el (7.1).  \~
    if (ch.ext.has_early_data) {
        decide_early(ch);
        if (failed()) return false;
    }
    return server_flight(m, ch, share_at, share_len);
}

bool Session::accept_psk(const uint8_t *m, const ClientHello &ch, bool check_binder, uint16_t &suite) noexcept {
    if (cfg_.tickets == nullptr || !ch.ext.has_pre_shared_key || !ch.ext.has_psk_modes) return false;
    // \~english Only psk_dhe_ke is accepted: never a mode the client did not list (4.2.9).
    // \~spanish Solo se acepta psk_dhe_ke: nunca un modo que el cliente no listo (4.2.9).  \~
    bool dhe = false;
    for (uint32_t i = 0; i < ch.ext.psk_modes.len; ++i) dhe = dhe || m[ch.ext.psk_modes.off + i] == 1;
    if (!dhe) return false;

    // \~english The first identity alone: one PSK chosen, one binder checked (4.2.11).
    // \~spanish Solo la primera identidad: se elige una PSK y se comprueba un binder (4.2.11).  \~
    const uint8_t *id = m + ch.ext.psk_identities.off;
    TicketContents t;
    if (!cfg_.tickets->open(id + 2, read16(id), t)) return false;
    const uint64_t now_ms = clock_us_ / 1000;
    const Hash h = quic::hash_of(aead_of(t.suite));
    bool usable = listed(suites_, suite_count_, t.suite) && t.issued_ms <= now_ms &&
                  now_ms - t.issued_ms < uint64_t{t.lifetime_s} * 1000;
    // \~english Choosing: its own suite, if the client offers it.  Accepting: the suite chosen has the PSK's hash (4.2.11).
    // \~spanish Al elegir: su propio algoritmo, si el cliente lo ofrece.  Al aceptar: el algoritmo elegido tiene el resumen de la PSK (4.2.11).  \~
    if (usable && !check_binder && suite == 0) {
        usable = listed_in(m, ch.cipher_suites, t.suite);
        suite = t.suite;
    }
    if (usable && check_binder) usable = quic::hash_of(aead_of(suite)) == h;
    if (usable && check_binder) {
        const size_t hl = hash_size(h);
        const uint8_t *b = m + ch.ext.psk_binders.off;
        if (b[0] != hl) {
            wipe_secret(&t, sizeof t);
            return fail(Alert::DecryptError, "a PSK binder of the wrong length (RFC 8446, 4.2.11.2)");
        }
        uint8_t want[kMaxHash];
        const bool computed = binder(t.psk, h, m, ch.ext.psk_binders_at, want);
        const bool match = computed && same(want, b + 1, hl);
        wipe_secret(want, sizeof want);
        if (!computed) {
            wipe_secret(&t, sizeof t);
            return false;
        }
        if (!match) {
            wipe_secret(&t, sizeof t);
            return fail(Alert::DecryptError, "the PSK binder does not match (RFC 8446, 4.2.11.2)");
        }
        util::vesta_memcpy_noinline(psk_, t.psk, hl);
        psk_len_ = hl;
        resumed_ = true;
        // \~english What 0-RTT is decided on: the ticket without its PSK, its age, and the binder that was checked.
        // \~spanish Sobre lo que se decide el 0-RTT: el ticket sin su PSK, su edad, y el binder que se comprobo.  \~
        taken_ = t;
        wipe_secret(taken_.psk, sizeof taken_.psk);
        const uint8_t *age = id + 2 + read16(id);
        obfuscated_age_ = uint32_t{age[0]} << 24 | uint32_t{age[1]} << 16 | uint32_t{age[2]} << 8 | age[3];
        util::vesta_memcpy_noinline(binder_key_, b + 1, sizeof binder_key_);
    }
    wipe_secret(&t, sizeof t);
    return usable;
}

bool Session::context_digest(uint8_t *out) noexcept {
    // \~english SHA-256 whatever the suite: the ticket holds it, and it is compared, never derived from.
    // \~spanish SHA-256 sea cual sea el algoritmo: lo guarda el ticket, y se compara, nunca se deriva de el.  \~
    return c_.digest(Hash::Sha256, cfg_.early_context, cfg_.early_context_len, out) ||
           fail_provider("the provider could not hash the 0-RTT context");
}

bool Session::derive_early(const uint8_t *psk, Hash h) noexcept {
    // \~english client_early_traffic_secret: the PSK's Early Secret over the ClientHello (7.1).
    // \~spanish client_early_traffic_secret: el Early Secret de la PSK sobre el ClientHello (7.1).  \~
    KeySchedule ks(c_, h);
    uint8_t th[kMaxHash];
    return (ks.start(psk, hash_size(h)) && transcript_.hash(c_, h, th) && ks.early_traffic(th, early_secret_)) ||
           fail_provider("the provider could not derive the early secret");
}

void Session::decide_early(const ClientHello &) noexcept {
    /* \~english
     * Every condition of 4.2.10 and RFC 9001, 4.6.3, then the replay guard
     * (8).  Any "no" only turns early data down, with the reason kept: the
     * handshake goes on, resumed or not.
     * \~spanish
     * Cada condicion de 4.2.10 y del RFC 9001, 4.6.3, y luego el guardian
     * contra repeticiones (8).  Cualquier "no" solo rechaza los datos tempranos,
     * guardando el motivo: el saludo sigue, reanudado o no.
     * \~ */
    size_t alpn_len = 0;
    const uint8_t *alpn_name = alpn(alpn_len);
    uint8_t context[32];
    if (!cfg_.early_data) {
        early_refused_ = "0-RTT is not enabled on this server";
    } else if (!resumed_) {
        early_refused_ = "no PSK was accepted (RFC 8446, 4.2.10)";
    } else if (!taken_.early) {
        early_refused_ = "the ticket does not allow 0-RTT";
    } else if (suite_ != taken_.suite) {
        early_refused_ = "another cipher suite than the ticket's (RFC 8446, 4.2.10)";
    } else if (alpn_name == nullptr || alpn_len != taken_.alpn_len || !same(alpn_name, taken_.alpn, alpn_len)) {
        early_refused_ = "another application protocol than the ticket's (RFC 8446, 4.2.10)";
    } else if (!context_digest(context)) {
        return;
    } else if (!same(context, taken_.context, sizeof context)) {
        early_refused_ = "the 0-RTT context changed since the ticket (RFC 9001, 4.6.3)";
    } else {
        // \~english expected_arrival_time = creation_time + the client's ticket age (8.3).
        // \~spanish expected_arrival_time = creation_time + la edad del ticket segun el cliente (8.3).  \~
        const uint32_t client_age = obfuscated_age_ - taken_.age_add;
        const ReplayGuard::Verdict v =
            cfg_.replay->admit(binder_key_, taken_.issued_ms + client_age, clock_us_ / 1000);
        switch (v) {
        case ReplayGuard::Verdict::Fresh:
            break;
        case ReplayGuard::Verdict::Replay:
            early_refused_ = "a replayed ClientHello (RFC 8446, 8.2)";
            break;
        case ReplayGuard::Verdict::Stale:
            early_refused_ = "the ticket's age does not match its arrival (RFC 8446, 8.3)";
            break;
        case ReplayGuard::Verdict::Warming:
            early_refused_ = "the replay guard started less than a window ago (RFC 8446, 8.2)";
            break;
        case ReplayGuard::Verdict::Full:
            early_refused_ = "the replay guard is full";
            break;
        }
        if (v == ReplayGuard::Verdict::Fresh && derive_early(psk_, hash_)) {
            early_aead_ = aead_;
            early_accepted_ = true;
        }
    }
}

bool Session::hello_retry(const ClientHello &) noexcept {
    Writer w(nullptr, 0);
    if (!begin(Space::Initial, 128, w)) return false;
    // \~english A ServerHello with the special random, the suite, the version and the group wanted (4.1.4).
    // \~spanish Un ServerHello con el random especial, el algoritmo, la version y el grupo que se quiere (4.1.4).  \~
    const size_t msg = w.begin_message(Handshake::ServerHello);
    w.u16(kLegacyVersion);
    w.bytes(kHelloRetryRandom, 32);
    w.u8(session_id_len_);
    w.bytes(session_id_, session_id_len_);
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
        wipe_secret(shared, sizeof shared);
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
        // \~english The client's legacy_session_id, echoed: empty in QUIC, maybe not over TCP (4.1.3).
        // \~spanish El legacy_session_id del cliente, devuelto: vacio en QUIC, quiza no sobre TCP (4.1.3).  \~
        w.u8(session_id_len_);
        w.bytes(session_id_, session_id_len_);
        w.u16(suite_);
        w.u8(0);
        const size_t exts = w.open(2);
        write_supported_versions_server(w, kTls13);
        write_key_share_server(w, group_, share_pubs_[0], quic::public_key_size(g));
        // \~english The PSK taken: the first identity, the only one looked at (4.2.11).
        // \~spanish La PSK tomada: la primera identidad, la unica que se miro (4.2.11).  \~
        if (resumed_) write_psk_server(w, 0);
        w.close(exts, 2);
        w.end_message(msg);
        ok = commit(Space::Initial, w) && derive_handshake(shared, quic::kMaxShared);
    }
    wipe_secret(shared, sizeof shared);
    forget_shares();
    if (!ok) return false;
    reading_ = Space::Handshake;

    // \~english EncryptedExtensions: the protocol chosen and the transport parameters (RFC 9001, 8.1 and 8.2).
    // \~spanish EncryptedExtensions: el protocolo elegido y los parametros de transporte (RFC 9001, 8.1 y 8.2).  \~
    if (!begin(Space::Handshake, 64 + 255 + cfg_.transport_params_len, w)) return false;
    size_t msg = w.begin_message(Handshake::EncryptedExtensions);
    size_t exts = w.open(2);
    if (alpn_.present) write_alpn(w, cfg_.alpn + alpn_index_, 1);
    if (!cfg_.over_tcp) write_transport_parameters(w, cfg_.transport_params, cfg_.transport_params_len);
    // \~english Accepting early data is saying so here (4.2.10; RFC 9001, 4.6.2).
    // \~spanish Aceptar los datos tempranos es decirlo aqui (4.2.10; RFC 9001, 4.6.2).  \~
    if (early_accepted_) write_empty_extension(w, ext::EarlyData);
    w.close(exts, 2);
    w.end_message(msg);
    if (!commit(Space::Handshake, w)) return false;

    // \~english A PSK or a certificate, never both (4.4); and no CertificateRequest with a PSK (4.3.2).
    // \~spanish Una PSK o un certificado, nunca los dos (4.4); y ningun CertificateRequest con una PSK (4.3.2).  \~
    if (!resumed_ && !server_certificate()) return false;

    // \~english Finished, and with it the application secrets (4.4.4, 7.1).
    // \~spanish Finished, y con el los secretos de aplicacion (4.4.4, 7.1).  \~
    const size_t hl = hash_size(hash_);
    uint8_t th[kMaxHash];
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

bool Session::server_certificate() noexcept {
    Writer w(nullptr, 0);
    size_t msg = 0;
    if (cfg_.request_certificate) {
        // \~english CertificateRequest: an empty context in the handshake, and the schemes accepted (4.3.2).
        // \~spanish CertificateRequest: un contexto vacio en el saludo, y los esquemas aceptados (4.3.2).  \~
        if (!begin(Space::Handshake, 32, w)) return false;
        msg = w.begin_message(Handshake::CertificateRequest);
        w.u8(0);
        const size_t exts = w.open(2);
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
    return commit(Space::Handshake, w);
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
    if (sh.ext.has_pre_shared_key) {
        if (!psk_offered_)
            return fail(Alert::UnsupportedExtension, "a pre_shared_key that was never offered (RFC 8446, 4.2)");
        // \~english One identity was offered; its hash is the suite's; and psk_dhe_ke needs a share (4.2.11).
        // \~spanish Se ofrecio una identidad; su resumen es el del algoritmo; y psk_dhe_ke necesita una clave (4.2.11).  \~
        if (sh.ext.psk_selected != 0)
            return fail(Alert::IllegalParameter, "a selected_identity out of the range offered (RFC 8446, 4.2.11)");
        if (quic::hash_of(aead_of(sh.cipher_suite)) != quic::hash_of(aead_of(cfg_.resume->suite)))
            return fail(Alert::IllegalParameter, "a suite whose hash is not the PSK's (RFC 8446, 4.2.11)");
        if (!sh.ext.has_key_share)
            return fail(Alert::IllegalParameter, "no key_share, and only psk_dhe_ke was offered (RFC 8446, 4.2.11)");
        psk_len_ = hash_size(quic::hash_of(aead_of(cfg_.resume->suite)));
        util::vesta_memcpy_noinline(psk_, cfg_.resume->psk, psk_len_);
        resumed_ = true;
    }
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
    wipe_secret(shared, sizeof shared);
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
    if (cfg_.over_tcp && ee.ext.has_transport_parameters)
        return fail(Alert::UnsupportedExtension, "quic_transport_parameters over TCP (RFC 9001, 8.2)");
    if (!cfg_.over_tcp && !ee.ext.has_transport_parameters)
        return fail(Alert::MissingExtension, "no quic_transport_parameters (RFC 9001, 8.2)");
    // \~english No answer to what was not asked (4.2).  \~spanish Ninguna respuesta a lo que no se pregunto (4.2).  \~
    if (ee.ext.has_alpn && cfg_.alpn_count == 0)
        return fail(Alert::UnsupportedExtension, "an ALPN answer to a ClientHello without one (RFC 8446, 4.2)");
    if (ee.ext.has_server_name && cfg_.server_name == nullptr)
        return fail(Alert::UnsupportedExtension, "a server_name answer to a ClientHello without one (RFC 8446, 4.2)");
    if (ee.ext.has_early_data) {
        // \~english An answer to an offer that was made, after a PSK was accepted (4.2, 4.2.10).
        // \~spanish Una respuesta a una oferta que se hizo, tras aceptarse una PSK (4.2, 4.2.10).  \~
        if (!early_offered_ || retried_)
            return fail(Alert::UnsupportedExtension, "early_data that was never offered (RFC 8446, 4.2)");
        if (!resumed_)
            return fail(Alert::IllegalParameter, "early_data accepted without the PSK (RFC 8446, 4.2.10)");
        early_accepted_ = true;
    }
    // \~english Over TCP a server may choose none: whether the client can live with that is its owner's to say.
    // \~spanish Sobre TCP un servidor puede no elegir ninguno: si el cliente puede vivir con eso lo dice su dueno.  \~
    if (!ee.ext.has_alpn && !cfg_.over_tcp)
        return fail(Alert::NoApplicationProtocol, "the server chose no application protocol (RFC 9001, 8.1)");
    // \~english Exactly one name, checked when read: its length byte, then the name.
    // \~spanish Exactamente un nombre, comprobado al leerlo: su byte de longitud, y luego el nombre.  \~
    const Span name{ee.ext.alpn.off + 1, ee.ext.has_alpn ? ee.ext.alpn.len - 1u : 0u};
    bool offered = !ee.ext.has_alpn;
    for (size_t i = 0; i < cfg_.alpn_count && !offered; ++i) {
        size_t len = 0;
        while (cfg_.alpn[i][len] != '\0') ++len;
        offered = len == name.len && same(m + name.off, reinterpret_cast<const uint8_t *>(cfg_.alpn[i]), len);
    }
    if (!offered)
        return fail(Alert::NoApplicationProtocol, "the server chose a protocol that was not offered (RFC 9001, 8.1)");
    const size_t msg_at = transcript_.size();
    if (!add(m, n)) return false;
    if (ee.ext.has_transport_parameters) keep(msg_at, ee.ext.transport_parameters, peer_tp_);
    if (ee.ext.has_alpn) keep(msg_at, name, alpn_);
    // \~english Resumed: no certificate, straight to the Finished (4.4).  \~spanish Reanudado: sin certificado, directo al Finished (4.4).  \~
    state_ = resumed_ ? State::WaitFinished : State::WaitCertificate;
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
        // \~english A client with nothing to show: the server MAY go on without authenticating it, or abort (4.4.2.4).
        // \~spanish Un cliente sin nada que ensenar: el servidor PUEDE seguir sin autenticarlo, o abortar (4.4.2.4).  \~
        if (cfg_.require_client_certificate)
            return fail(Alert::CertificateRequired, "the client sent no certificate, and one is required (RFC 8446, 4.4.2.4)");
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
    // \~english The peer holds the leaf's key; whether the leaf is to be trusted is the verifier's to say.
    // \~spanish El otro tiene la clave de la hoja; si hay que fiarse de la hoja lo dice el verificador.  \~
    if (!check_chain()) return false;
    if (!add(m, n)) return false;
    state_ = State::WaitFinished;
    return true;
}

bool Session::check_chain() noexcept {
    if (cfg_.verifier == nullptr) return true;
    const uint8_t *m = transcript_.bytes() + certificate_.at;
    CertificateMessage ct;
    if (!parse_certificate(m, certificate_.len, ct).ok()) return fail(Alert::InternalError, "the kept Certificate no longer parses");
    const uint8_t *certs[kMaxChain];
    size_t lens[kMaxChain];
    Chain chain;
    uint32_t at = 0;
    Span s;
    while (next_certificate(m, ct, at, s)) {
        // \~english Past what this end follows: refused, and said -- never cut short quietly.
        // \~spanish Pasado lo que sigue este extremo: se rechaza, y se dice -- nunca se recorta en silencio.  \~
        if (chain.count == kMaxChain)
            return fail(Alert::CertificateUnknown, "a certificate chain longer than this end follows");
        certs[chain.count] = m + s.off;
        lens[chain.count] = s.len;
        ++chain.count;
    }
    chain.certs = certs;
    chain.lens = lens;
    // \~english A client checks the server against the name it asked for; a server has no name to check a client by.
    // \~spanish Un cliente comprueba al servidor contra el nombre que pidio; un servidor no tiene nombre con el que comprobar a un cliente.  \~
    trust_ = cfg_.verifier->verify(chain, cfg_.server ? Role::Client : Role::Server,
                                   cfg_.server ? nullptr : cfg_.server_name);
    if (trust_.trust == Trust::Trusted) return true;
    switch (trust_.trust) {
    case Trust::UnknownIssuer: return fail(trust_alert(trust_.trust), "the peer's certificate chain leads to no trusted anchor (RFC 8446, 6.2)");
    case Trust::Expired: return fail(trust_alert(trust_.trust), "a certificate in the peer's chain expired or is not valid yet (RFC 8446, 6.2)");
    case Trust::Revoked: return fail(trust_alert(trust_.trust), "a certificate in the peer's chain was revoked (RFC 8446, 6.2)");
    case Trust::RevocationUnknown: return fail(trust_alert(trust_.trust), "the revocation of the peer's chain could not be found out");
    case Trust::NameMismatch: return fail(trust_alert(trust_.trust), "the server's certificate is not for the name asked for");
    case Trust::WrongUsage: return fail(trust_alert(trust_.trust), "the peer's certificate chain is not for this use");
    case Trust::BadSignature: return fail(trust_alert(trust_.trust), "a signature in the peer's chain does not verify or is too weak (RFC 8446, 4.4.2.4)");
    case Trust::Invalid: return fail(trust_alert(trust_.trust), "a certificate in the peer's chain is corrupt (RFC 8446, 6.2)");
    case Trust::Unsupported: return fail(trust_alert(trust_.trust), "a certificate in the peer's chain is of a kind this end does not handle (RFC 8446, 6.2)");
    case Trust::Rejected: return fail(trust_alert(trust_.trust), "the verifier rejected the peer's certificate chain");
    case Trust::Trusted:
    case Trust::Failed: break;
    }
    return fail(Alert::InternalError, "the certificate verifier failed");
}

bool Session::on_finished(const uint8_t *m, size_t n) noexcept {
    const size_t hl = hash_size(hash_);
    if (n - 4 != hl) return fail(Alert::DecodeError, "a Finished of the wrong length (RFC 8446, 4.4.4)");
    // \~english The peer's Finished uses the peer's base key (4.4).  \~spanish El Finished del otro usa la clave base del otro (4.4).  \~
    uint8_t want[kMaxHash];
    if (!finished_for(cfg_.server, want)) return false;
    const bool match = same(want, m + 4, hl);
    wipe_secret(want, sizeof want);
    if (!match) return fail(Alert::DecryptError, "the peer's Finished does not match (RFC 8446, 4.4.4)");
    if (!add(m, n)) return false;
    uint8_t th[kMaxHash];
    if (cfg_.server) {
        if (!transcript_.hash(c_, hash_, th) || !schedule().resumption(th, resumption_))
            return fail_provider("the provider could not derive the resumption secret");
        complete_ = true;
        reading_ = Space::Application;
        state_ = State::Connected;
        // \~english Tickets only once the client's Finished is in: they come from its transcript (4.6.1).
        // \~spanish Tickets solo cuando esta el Finished del cliente: salen de su transcripcion (4.6.1).  \~
        return issue_tickets();
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
    // \~english Over TCP it is a real size, and moot: this end does no 0-RTT over TCP.
    // \~spanish Sobre TCP es un tamano de verdad, y no importa: este extremo no hace 0-RTT sobre TCP.  \~
    if (!cfg_.over_tcp && nst.ext.has_early_data && nst.ext.max_early_data != 0xffffffffu)
        return fail_quic(kProtocolViolation, "a NewSessionTicket early_data other than 0xffffffff (RFC 9001, 4.6.1)");
    // \~english A lifetime of zero: discarded at once (4.6.1).  \~spanish Una vida de cero: se tira en el acto (4.6.1).  \~
    if (nst.lifetime == 0) return true;
    // \~english Past what this end keeps: not kept, and counted -- never silently.
    // \~spanish Pasado lo que guarda este extremo: no se guarda, y se cuenta -- nunca en silencio.  \~
    if (nst.ticket.len > Ticket::kMaxIdentity || kept_count_ == kKeptTickets) {
        ++tickets_dropped_;
        return true;
    }
    if (kept_ == nullptr) {
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed, util::AllocFill::All);
        kept_ = static_cast<Ticket *>(util::host_alloc(kKeptTickets * sizeof(Ticket)));
        if (kept_ == nullptr) return fail_provider("out of memory for session tickets");
        for (size_t i = 0; i < kKeptTickets; ++i) new (&kept_[i]) Ticket();
    }
    Ticket &t = kept_[kept_count_];
    t = Ticket{};
    // \~english The PSK: HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce) (4.6.1).
    // \~spanish La PSK: HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce) (4.6.1).  \~
    if (!ticket_psk(c_, hash_, resumption_, m + nst.nonce.off, nst.nonce.len, t.psk))
        return fail_provider("the provider could not derive a ticket's PSK");
    util::vesta_memcpy_noinline(t.identity, m + nst.ticket.off, nst.ticket.len);
    t.identity_len = nst.ticket.len;
    t.suite = suite_;
    t.age_add = nst.age_add;
    t.lifetime_s = nst.lifetime;
    t.received_us = clock_us_;
    // \~english The host name and the protocol: resuming checks the first (4.6.1), 0-RTT the second.
    // \~spanish El nombre y el protocolo: reanudar comprueba el primero (4.6.1), 0-RTT el segundo.  \~
    size_t name_len = 0;
    if (cfg_.server_name != nullptr)
        while (cfg_.server_name[name_len] != '\0' && name_len < sizeof t.server_name) ++name_len;
    util::vesta_memcpy_noinline(t.server_name, cfg_.server_name, name_len);
    t.server_name_len = static_cast<uint8_t>(name_len);
    size_t alpn_len = 0;
    const uint8_t *alpn_name = alpn(alpn_len);
    if (alpn_name != nullptr && alpn_len <= sizeof t.alpn) {
        util::vesta_memcpy_noinline(t.alpn, alpn_name, alpn_len);
        t.alpn_len = static_cast<uint8_t>(alpn_len);
    }
    /* \~english
     * 0-RTT with it needs the server's transport parameters, remembered as
     * they came (RFC 9000, 7.4.1): without room for them, no 0-RTT.
     * \~spanish
     * 0-RTT con el necesita los parametros de transporte del servidor,
     * recordados tal como llegaron (RFC 9000, 7.4.1): sin sitio para ellos, sin
     * 0-RTT.
     * \~ */
    size_t tp_len = 0;
    const uint8_t *tp = peer_transport_params(tp_len);
    if (nst.ext.has_early_data && tp != nullptr && tp_len <= sizeof t.params) {
        util::vesta_memcpy_noinline(t.params, tp, tp_len);
        t.params_len = tp_len;
        t.early_data = true;
    }
    ++kept_count_;
    return true;
}

bool Session::issue_tickets() noexcept {
    if (cfg_.tickets == nullptr || cfg_.ticket_lifetime_s == 0) return true;
    const size_t hl = hash_size(hash_);
    size_t alpn_len = 0;
    const uint8_t *alpn_name = alpn(alpn_len);
    for (size_t i = 0; i < cfg_.tickets_to_issue && i < 256; ++i) {
        TicketContents t;
        t.suite = suite_;
        t.issued_ms = clock_us_ / 1000;
        // \~english Never more than seven days (4.6.1).  \~spanish Nunca mas de siete dias (4.6.1).  \~
        t.lifetime_s = cfg_.ticket_lifetime_s < kMaxTicketLifetime ? cfg_.ticket_lifetime_s : kMaxTicketLifetime;
        // \~english A fresh ticket_age_add per ticket, and a nonce unique on this connection (4.6.1).
        // \~spanish Un ticket_age_add nuevo por ticket, y un nonce unico en esta conexion (4.6.1).  \~
        uint8_t add[4];
        if (!c_.random(add, sizeof add)) return fail_provider("the provider gave no random bytes");
        t.age_add = uint32_t{add[0]} << 24 | uint32_t{add[1]} << 16 | uint32_t{add[2]} << 8 | add[3];
        const uint8_t nonce = static_cast<uint8_t>(i);
        if (!ticket_psk(c_, hash_, resumption_, &nonce, 1, t.psk)) return fail_provider("the provider could not derive a ticket's PSK");
        t.psk_len = static_cast<uint8_t>(hl);
        if (alpn_name != nullptr && alpn_len <= sizeof t.alpn) {
            util::vesta_memcpy_noinline(t.alpn, alpn_name, alpn_len);
            t.alpn_len = static_cast<uint8_t>(alpn_len);
        }
        // \~english 0-RTT with it, if this server allows it, bound to today's context (RFC 9001, 4.6.3).
        // \~spanish 0-RTT con el, si este servidor lo permite, atado al contexto de hoy (RFC 9001, 4.6.3).  \~
        t.early = cfg_.early_data;
        if (t.early && !context_digest(t.context)) return false;
        uint8_t sealed[TicketSealer::kMaxSealed];
        const size_t n = cfg_.tickets->seal(t, sealed, sizeof sealed);
        const uint32_t lifetime = t.lifetime_s;
        const uint32_t age_add = t.age_add;
        wipe_secret(&t, sizeof t);
        if (n == 0) return fail_provider("a ticket could not be sealed");

        Writer w(nullptr, 0);
        if (!begin(Space::Application, 32 + n, w)) return false;
        const size_t msg = w.begin_message(Handshake::NewSessionTicket);
        w.u32(lifetime);
        w.u32(age_add);
        w.u8(1);
        w.u8(nonce);
        const size_t ticket = w.open(2);
        w.bytes(sealed, n);
        w.close(ticket, 2);
        const size_t exts = w.open(2);
        // \~english QUIC's sentinel: 0-RTT allowed, and its amount is the transport's (RFC 9001, 4.6.1).
        // \~spanish La marca de QUIC: 0-RTT permitido, y su cantidad es cosa del transporte (RFC 9001, 4.6.1).  \~
        if (cfg_.early_data) write_early_data_ticket(w, 0xffffffffu);
        w.close(exts, 2);
        w.end_message(msg);
        // \~english After the handshake: not part of the transcript (4.4.1).  \~spanish Tras el saludo: no es parte de la transcripcion (4.4.1).  \~
        if (!commit(Space::Application, w, false)) return false;
        ++tickets_issued_;
    }
    return true;
}

const uint8_t *Session::read_secret(Space s) const noexcept {
    if (s == Space::Handshake && has_handshake_keys_) return cfg_.server ? hs_client_ : hs_server_;
    if (s != Space::Application || !has_application_keys_) return nullptr;
    return cfg_.server ? ap_client_ : ap_server_;
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
