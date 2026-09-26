/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/h3_setup.cpp
 * @brief
 * \~english HTTP/3 for the runnable server; what it takes from the TLS setup is in h3_setup.h.
 * \~spanish HTTP/3 para el servidor ejecutable; lo que toma del TLS esta en h3_setup.h.
 * \~
 */
#include "serve/h3_setup.h"

#include <new>

namespace serve {

namespace {

const char *const kH3[] = {"h3"};

} // namespace

H3Setup::~H3Setup() {
    // \~english The adapter holds the service, and the service the guard: gone in that order.
    // \~spanish El adaptador sujeta el servicio, y el servicio el guardian: se van en ese orden.  \~
    delete datagrams_;
    delete service_;
    delete guard_;
}

bool H3Setup::start(const TlsSetup &tls, http_vx::Handler &handler, uint32_t connections) noexcept {
    http_vx::quic::Crypto *crypto = tls.crypto();
    if (crypto == nullptr) {
        why_ = "HTTP/3 needs the TLS setup loaded first";
        return false;
    }
    guard_ = new (std::nothrow) http_vx::tls::ReplayGuard(4096, kReplayWindowMs, now_us_() / 1000);
    service_ = new (std::nothrow) http_vx::Http3Service(*crypto, handler);
    if (guard_ == nullptr || service_ == nullptr || !guard_->ready()) {
        why_ = "no memory for HTTP/3";
        return false;
    }
    datagrams_ = new (std::nothrow) http_vx::Http3Datagrams(*service_, now_us_);
    if (datagrams_ == nullptr) {
        why_ = "no memory for HTTP/3";
        return false;
    }

    http_vx::Http3Config c;
    // \~english One stateless reset key, given to both: a token a connection hands out is the one the acceptor answers with.
    // \~spanish Una clave de reinicio sin estado, dada a los dos: el testigo que entrega una conexion es con el que contesta el acceptor.  \~
    if (!crypto->random(c.connection.reset_key, sizeof c.connection.reset_key) ||
        !crypto->random(c.acceptor.token_key, sizeof c.acceptor.token_key)) {
        why_ = "the provider gave no random bytes";
        return false;
    }
    for (size_t i = 0; i < sizeof c.acceptor.reset_key; ++i) c.acceptor.reset_key[i] = c.connection.reset_key[i];
    c.connection.is_server = true;
    c.connection.streams.is_server = true;
    c.tls.server = true;
    c.tls.alpn = kH3;
    c.tls.alpn_count = 1;
    c.tls.certificates = tls.certificates();
    c.tls.certificate_lens = tls.certificate_lens();
    c.tls.certificate_count = tls.certificate_count();
    c.tls.signing_key = tls.signing_key();
    c.tls.scheme = tls.scheme();
    c.tls.tickets = tls.tickets();
    c.tls.early_data = tls.tickets() != nullptr;
    c.tls.replay = guard_;
    c.h3.server = true;
    c.h3.local.qpack_max_table_capacity = 4096;
    c.h3.local.qpack_blocked_streams = 16;
    c.connections = connections;
    if (!service_->start(c)) {
        why_ = service_->why();
        return false;
    }
    return true;
}

} // namespace serve
