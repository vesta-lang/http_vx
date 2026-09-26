/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/h3_setup.h
 * @brief
 * \~english HTTP/3 for the runnable server: the service, its configuration from the TLS setup, and the shard's datagram side.
 * \~spanish HTTP/3 para el servidor ejecutable: el servicio, su configuracion a partir del TLS, y el lado de datagramas del shard.
 * \~
 *
 * \~english
 * The certificate, key, provider and ticket sealer are the ones HTTP/1.1 and
 * HTTP/2 use over TCP (tls_setup.h): one identity, whatever the transport.
 * 0-RTT is accepted over QUIC, where RFC 9001 defines how, with a replay
 * guard (RFC 8446, 8) -- which refuses early data for its first window after
 * the process starts, because a server just started cannot know which
 * ClientHellos it saw before.
 * \~spanish
 * El certificado, la clave, el proveedor y el sellador de tickets son los que
 * usan HTTP/1.1 y HTTP/2 sobre TCP (tls_setup.h): una identidad, sea cual sea
 * el transporte.  El 0-RTT se acepta sobre QUIC, donde el RFC 9001 define
 * como, con un guardian contra repeticiones (RFC 8446, 8) -- que rechaza los
 * datos tempranos durante su primera ventana tras arrancar el proceso, porque
 * un servidor recien arrancado no puede saber que ClientHello vio antes.
 * \~
 */
#ifndef HTTP_VX_SERVE_H3_SETUP_H
#define HTTP_VX_SERVE_H3_SETUP_H

#include "serve/tls_setup.h"

#include "http_vx/http1_service.h"
#include "http_vx/http3_datagrams.h"
#include "http_vx/http3_service.h"
#include "http_vx/tls_ticket.h"

#include <cstdint>

namespace serve {

/**
 * @brief
 * \~english The HTTP/3 service of the runnable server.
 * \~spanish El servicio HTTP/3 del servidor ejecutable.
 * \~
 */
class H3Setup {
  public:
    /// \~english How long the replay guard remembers a ClientHello, and its tolerance (RFC 8446, 8.3).
    /// \~spanish Cuanto recuerda un ClientHello el guardian contra repeticiones, y su tolerancia (RFC 8446, 8.3).  \~
    static constexpr uint64_t kReplayWindowMs = 10000;

    explicit H3Setup(http_vx::Http3Datagrams::Clock now_us) noexcept : now_us_(now_us) {}
    ~H3Setup();
    H3Setup(const H3Setup &) = delete;
    H3Setup &operator=(const H3Setup &) = delete;

    /**
     * @brief
     * \~english Starts the service with @p tls's identity, answering with @p handler; false, with why(), if it cannot.
     * \~spanish Arranca el servicio con la identidad de @p tls, contestando con @p handler; falso, con why(), si no puede.
     * \~
     */
    bool start(const TlsSetup &tls, http_vx::Handler &handler, uint32_t connections) noexcept;

    const char *why() const noexcept { return why_; }
    http_vx::Http3Service &service() noexcept { return *service_; }
    http_vx::Http3Datagrams &datagrams() noexcept { return *datagrams_; }

  private:
    http_vx::Http3Datagrams::Clock now_us_;
    http_vx::Http3Service *service_ = nullptr;
    http_vx::Http3Datagrams *datagrams_ = nullptr;
    http_vx::tls::ReplayGuard *guard_ = nullptr;
    const char *why_ = nullptr;
};

} // namespace serve

#endif // HTTP_VX_SERVE_H3_SETUP_H
