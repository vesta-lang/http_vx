/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service_datagrams.cpp
 * @brief
 * \~english The HTTP/3 service as a shard's datagram side; why time is translated is in http3_datagrams.h.
 * \~spanish El servicio HTTP/3 como lado de datagramas de un shard; por que se traduce el tiempo esta en http3_datagrams.h.
 * \~
 */
#include "http_vx/http3_datagrams.h"

namespace http_vx {

namespace {

// \~english The two sides agree on these by construction; if one changes, this stops compiling.
// \~spanish Los dos lados coinciden en esto por construccion; si uno cambia, esto deja de compilar.  \~
static_assert(sizeof(NetAddress::bytes) == quic::kMaxAddress, "a reactor address and a QUIC address hold the same bytes");
static_assert(static_cast<int>(EcnMark::NotEct) == static_cast<int>(quic::Ecn::NotEct) &&
                  static_cast<int>(EcnMark::Ect0) == static_cast<int>(quic::Ecn::Ect0) &&
                  static_cast<int>(EcnMark::Ect1) == static_cast<int>(quic::Ecn::Ect1) &&
                  static_cast<int>(EcnMark::Ce) == static_cast<int>(quic::Ecn::Ce),
              "the ECN marks are in the same order");
static_assert(kNoDatagramTimer == quic::kNever, "no timer means the same on both sides");

void to_quic(const NetAddress &from, quic::Address &to) noexcept {
    for (size_t i = 0; i < from.len; ++i) to.bytes[i] = from.bytes[i];
    to.len = from.len;
}

void to_reactor(const quic::Address &from, NetAddress &to) noexcept {
    for (size_t i = 0; i < from.len; ++i) to.bytes[i] = from.bytes[i];
    to.len = from.len;
}

} // namespace

void Http3Datagrams::on_datagram(const DatagramPath &path, uint8_t *data, size_t n, EcnMark ecn,
                                 uint64_t) noexcept {
    quic::Path p;
    to_quic(path.local, p.local);
    to_quic(path.peer, p.peer);
    service_.on_datagram(p, data, n, static_cast<quic::Ecn>(ecn), now_us_());
}

size_t Http3Datagrams::next_datagram(DatagramPath &path, uint8_t *out, size_t room, uint64_t) noexcept {
    quic::Path p;
    const size_t n = service_.next_datagram(p, out, room, now_us_());
    if (n == 0) return 0;
    to_reactor(p.local, path.local);
    to_reactor(p.peer, path.peer);
    return n;
}

uint64_t Http3Datagrams::timer() const noexcept {
    const uint64_t t = service_.timer();
    if (t == quic::kNever) return kNoDatagramTimer;
    // \~english Due: zero, which every tick reaches.  Not yet: past any tick, and not "none".
    // \~spanish Vencido: cero, al que llega cualquier tic.  Aun no: mas alla de cualquier tic, y no "ninguno".  \~
    return t <= now_us_() ? 0 : kNoDatagramTimer - 1;
}

void Http3Datagrams::on_timer(uint64_t) noexcept { service_.on_timer(now_us_()); }

int Http3Datagrams::wait_ms(int cap_ms) const noexcept {
    const uint64_t t = service_.timer();
    if (t == quic::kNever) return cap_ms;
    const uint64_t now = now_us_();
    if (t <= now) return 0;
    // \~english Rounded up: waking a millisecond early would find the timer not yet due and sleep again.
    // \~spanish Redondeado hacia arriba: despertar un milisegundo antes encontraria el temporizador sin vencer y volveria a dormir.  \~
    const uint64_t ms = (t - now + 999) / 1000;
    return ms < static_cast<uint64_t>(cap_ms) ? static_cast<int>(ms) : cap_ms;
}

} // namespace http_vx
