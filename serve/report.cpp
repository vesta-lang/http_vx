/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/report.cpp
 * @brief
 * \~english What the runnable server says about connections that went wrong; what counts as wrong is in report.h.
 * \~spanish Lo que dice el servidor ejecutable de las conexiones que fueron mal; que cuenta como mal esta en report.h.
 * \~
 */
#include "serve/report.h"

#include "http_vx/h3_frame.h"
#include "http_vx/tls_messages.h"

#include <cstdio>

namespace serve {

using http_vx::quic::EndReason;

void Report::tls(const http_vx::TlsService &s) noexcept {
    const size_t now = s.failures();
    if (now == tls_failures_) return;
    const size_t more = now - tls_failures_;
    tls_failures_ = now;
    std::fprintf(stderr, "http_vx: tls: %zu handshake%s failed; last: %s (alert %s, %s)\n", more, more == 1 ? "" : "s",
                 s.last_failure() != nullptr ? s.last_failure() : "no reason kept",
                 http_vx::tls::alert_name(s.last_alert()), s.last_alert_received() ? "received" : "sent");
}

void Report::h3(const http_vx::Http3Service &s) noexcept {
    const http_vx::Http3Counts &c = s.counts();
    // \~english The ordinary endings are counted, and nothing is said of them.
    // \~spanish Los finales corrientes se cuentan, y de ellos no se dice nada.  \~
    uint64_t unusual = 0;
    for (size_t r = 0; r < static_cast<size_t>(EndReason::kCount); ++r) {
        const uint64_t more = c.ended[r] - h3_ended_[r];
        h3_ended_[r] = c.ended[r];
        if (r != static_cast<size_t>(EndReason::IdleTimeout) && r != static_cast<size_t>(EndReason::PeerClosed))
            unusual += more;
    }
    const http_vx::Http3End &end = s.last_end();
    // \~english The peer closing with an error is not ordinary either (H3_NO_ERROR, or QUIC's NO_ERROR, is).
    // \~spanish Que el otro cierre con un error tampoco es corriente (H3_NO_ERROR, o el NO_ERROR de QUIC, si).  \~
    const bool peer_error = end.reason == EndReason::PeerClosed && end.code != 0 && end.code != http_vx::h3::kNoError;
    if (c.closed != h3_closed_ && peer_error) ++unusual;
    h3_closed_ = c.closed;
    if (unusual != 0) {
        std::fprintf(stderr, "http_vx: h3: %llu connection%s ended badly; last: %s, code 0x%llx%s%s\n",
                     static_cast<unsigned long long>(unusual), unusual == 1 ? "" : "s",
                     http_vx::quic::end_reason_name(end.reason), static_cast<unsigned long long>(end.code),
                     end.why != nullptr ? ", " : "", end.why != nullptr ? end.why : "");
    }
    if (c.early_refused != early_refused_) {
        std::fprintf(stderr, "http_vx: h3: 0-RTT refused %llu time%s; last: %s\n",
                     static_cast<unsigned long long>(c.early_refused - early_refused_),
                     c.early_refused - early_refused_ == 1 ? "" : "s",
                     s.last_early_refused() != nullptr ? s.last_early_refused() : "no reason kept");
        early_refused_ = c.early_refused;
    }
}

} // namespace serve
