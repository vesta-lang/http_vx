/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/host_notes.cpp
 * @brief
 * \~english Reading the one kernel setting the multi-shard listen depends on.
 * \~spanish Leer el unico ajuste del nucleo del que depende escuchar con varios fragmentos.
 * \~
 */
#include "serve/host_notes.h"

namespace serve {

bool warn_if_no_migrate_req(std::FILE *out) noexcept {
#ifdef _WIN32
    (void)out;
    return false;
#else
    std::FILE *f = std::fopen("/proc/sys/net/ipv4/tcp_migrate_req", "r");
    if (f == nullptr) {
        std::fprintf(out,
                     "http_vx: warning: net.ipv4.tcp_migrate_req cannot be read (kernel before 5.14?): "
                     "stopping a shard would abort the connections queued on its listening socket\n");
        return true;
    }

    int value = -1;
    const int got = std::fscanf(f, "%d", &value);
    std::fclose(f);

    if (got == 1 && value != 0) return false;

    std::fprintf(out,
                 "http_vx: warning: net.ipv4.tcp_migrate_req is 0: stopping a shard would abort the "
                 "connections queued on its listening socket (sysctl -w net.ipv4.tcp_migrate_req=1)\n");
    return true;
#endif
}

} // namespace serve
