/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/report.h
 * @brief
 * \~english What the runnable server says about connections that went wrong.
 * \~spanish Lo que dice el servidor ejecutable de las conexiones que fueron mal.
 * \~
 *
 * \~english
 * The services count every failure and keep the last one's reason; nothing
 * printed them, so a handshake that failed was a number going up.  This
 * prints each one as it happens: for TLS over TCP, the reason and the alert
 * and who sent it; for HTTP/3, every connection that did not end the
 * ordinary way -- an idle timeout, or the peer closing without an error --
 * and every 0-RTT turned down, with why.  Several ending between two looks
 * are all counted, and the last is the one described.
 * \~spanish
 * Los servicios cuentan cada fallo y guardan el motivo del ultimo; nada los
 * imprimia, asi que un saludo fallido era un numero que subia.  Esto imprime
 * cada uno cuando pasa: para TLS sobre TCP, el motivo, la alerta y quien la
 * mando; para HTTP/3, cada conexion que no acabo de la forma corriente -- por
 * inactividad, o porque el otro cerro sin error -- y cada 0-RTT rechazado, con
 * el porque.  Si acaban varias entre dos miradas se cuentan todas, y se
 * describe la ultima.
 * \~
 */
#ifndef HTTP_VX_SERVE_REPORT_H
#define HTTP_VX_SERVE_REPORT_H

#include "http_vx/http3_service.h"
#include "http_vx/tls_service.h"

#include <cstddef>
#include <cstdint>

namespace serve {

/**
 * @brief
 * \~english Prints what changed since the last look.
 * \~spanish Imprime lo que cambio desde la ultima mirada.
 * \~
 */
class Report {
  public:
    /// \~english Each TLS handshake failure since the last call.  \~spanish Cada fallo de saludo TLS desde la ultima llamada.  \~
    void tls(const http_vx::TlsService &s) noexcept;
    /// \~english Each HTTP/3 connection that ended badly, and each 0-RTT refused.
    /// \~spanish Cada conexion HTTP/3 que acabo mal, y cada 0-RTT rechazado.  \~
    void h3(const http_vx::Http3Service &s) noexcept;

  private:
    size_t tls_failures_ = 0;
    uint64_t h3_ended_[static_cast<size_t>(http_vx::quic::EndReason::kCount)] = {};
    uint64_t h3_closed_ = 0;
    uint64_t early_refused_ = 0;
};

} // namespace serve

#endif // HTTP_VX_SERVE_REPORT_H
