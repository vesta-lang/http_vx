/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/options.cpp
 * @brief
 * \~english Reading the command line, strictly.
 * \~spanish Leer la linea de ordenes, sin adivinar.
 * \~
 */
#include "serve/options.h"
#include "serve/tls_setup.h"

#include <cstring>

namespace serve {

namespace {

/// \~english A port from 0 to 65535, written as digits and nothing else.
/// \~spanish Un puerto de 0 a 65535, escrito con cifras y nada mas.  \~
bool read_port(const char *text, uint16_t &port) noexcept {
    if (text[0] == '\0') return false;

    uint32_t value = 0;
    for (const char *p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
        value = value * 10 + static_cast<uint32_t>(*p - '0');
        if (value > 65535) return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

/// \~english Whether @p arg is option @p name.  \~spanish Si @p arg es la opcion @p name.  \~
bool is(const char *arg, const char *name) noexcept { return std::strcmp(arg, name) == 0; }

} // namespace

void Options::parse(int argc, char **argv) noexcept {
    size_t positional = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];

        if (is(arg, "--help") || is(arg, "-h")) {
            help = true;
        } else if (is(arg, "--tls")) {
            if (i + 2 >= argc) {
                error = "--tls needs a certificate file and a key file";
                return;
            }
            cert = argv[++i];
            key = argv[++i];
        } else if (is(arg, "--tls-provider")) {
            if (i + 1 >= argc) {
                error = "--tls-provider needs a name";
                return;
            }
            provider = argv[++i];
        } else if (is(arg, "--h3")) {
            h3 = true;
        } else if (arg[0] == '-') {
            error = "unknown option";
            culprit = arg;
            return;
        } else if (positional == 0) {
            host = arg;
            ++positional;
        } else if (positional == 1) {
            if (!read_port(arg, port)) {
                error = "the port must be a number from 0 to 65535";
                culprit = arg;
                return;
            }
            ++positional;
        } else if (positional == 2) {
            backend = arg;
            ++positional;
        } else {
            error = "too many arguments";
            culprit = arg;
            return;
        }
    }

    if (provider != nullptr && cert == nullptr) error = "--tls-provider without --tls";
    // \~english HTTP/3 is always encrypted: QUIC carries TLS 1.3 inside it (RFC 9001).
    // \~spanish HTTP/3 va siempre cifrado: QUIC lleva TLS 1.3 dentro (RFC 9001).  \~
    if (h3 && cert == nullptr) error = "--h3 needs --tls: QUIC has no unencrypted form";
}

Endpoint endpoint(const char *host, uint16_t port) noexcept {
    Endpoint e;
    const bool v6 = std::strchr(host, ':') != nullptr;
    std::snprintf(e.text, sizeof e.text, v6 ? "[%s]:%u" : "%s:%u", host,
                  static_cast<unsigned>(port));
    return e;
}

void print_usage(std::FILE *out, const Reactors &reactors) noexcept {
    std::fprintf(out,
                 "usage: http_vx_listen [--tls CERT KEY [--tls-provider NAME] [--h3]]\n"
                 "                      [HOST [PORT [BACKEND]]]\n"
                 "  HOST            the address to listen on (default 127.0.0.1)\n"
                 "  PORT            0 to 65535, 0 for any (default 8080)\n"
                 "  BACKEND         one of: ");
    reactors.print_names(out);
    std::fprintf(out, " (default %s)\n"
                      "  --tls           serve HTTPS: TLS 1.3, HTTP/2 or HTTP/1.1 by ALPN\n"
                      "  --tls-provider  whose cryptography, one of: ",
                 reactors.default_name());
    TlsSetup::print_names(out);
    std::fprintf(out, " (default: the first)\n"
                      "  --h3            also serve HTTP/3 on UDP, same address and port\n");
}

} // namespace serve
