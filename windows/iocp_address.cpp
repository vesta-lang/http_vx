/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_address.cpp
 * @brief
 * \~english Reading a host of either family, once for TCP and UDP.
 * \~spanish Leer un anfitrion de cualquiera de las dos familias, una vez para TCP y UDP.
 * \~
 *
 * \~english
 * The listening socket used to read its host as IPv4 only, while the
 * datagram side read either family: a server asked for `::1` served HTTP/3
 * and refused HTTP/1.1 and HTTP/2.  One reader now, for both.
 * \~spanish
 * El socket de escucha leia su anfitrion solo como IPv4, mientras el lado de
 * datagramas leia cualquiera de las dos familias: un servidor al que se pedia
 * `::1` servia HTTP/3 y rechazaba HTTP/1.1 y HTTP/2.  Un lector ahora, para los
 * dos.
 * \~
 */
#include "iocp_context.h"

#include "util/mem/vesta_memset.h"

namespace http_vx {

bool win_address(const char *host, uint16_t port, WinAddress &out) noexcept {
    util::vesta_memset(&out.raw, 0, sizeof out.raw);
    if (host == nullptr) return false;

    if (InetPtonA(AF_INET, host, &out.raw.v4.sin_addr) == 1) {
        out.raw.v4.sin_family = AF_INET;
        out.raw.v4.sin_port = htons(port);
        out.family = AF_INET;
        out.len = sizeof out.raw.v4;
        return true;
    }
    if (InetPtonA(AF_INET6, host, &out.raw.v6.sin6_addr) == 1) {
        out.raw.v6.sin6_family = AF_INET6;
        out.raw.v6.sin6_port = htons(port);
        out.family = AF_INET6;
        out.len = sizeof out.raw.v6;
        return true;
    }
    return false;
}

} // namespace http_vx
