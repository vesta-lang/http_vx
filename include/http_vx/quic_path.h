/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_path.h
 * @brief
 * \~english A network path: the pair of addresses a datagram travels between (RFC 9000, 8.2).
 * \~spanish Un camino de red: el par de direcciones entre las que viaja un datagrama (RFC 9000, 8.2).
 * \~
 *
 * \~english
 * QUIC validates, limits and migrates by path, "the 2-tuple of IP address
 * and port" at each end.  The connection does not interpret an address: it
 * only needs to know whether two are the same, so an address is the bytes
 * the host gives it -- a sockaddr, or anything that identifies the endpoint
 * as well.  The host puts the path on every datagram it hands in and sends
 * every datagram it is handed to the path that comes with it.
 * \~spanish
 * QUIC valida, limita y migra por camino, "la tupla de direccion IP y puerto"
 * de cada extremo.  La conexion no interpreta una direccion: solo necesita
 * saber si dos son la misma, asi que una direccion son los bytes que le da el
 * anfitrion -- un sockaddr, o cualquier cosa que identifique igual al extremo.
 * El anfitrion pone el camino en cada datagrama que entrega y manda cada
 * datagrama que recibe al camino que viene con el.
 * \~
 */
#ifndef HTTP_VX_QUIC_PATH_H
#define HTTP_VX_QUIC_PATH_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english Room for the largest socket address, an IPv6 one.  \~spanish Sitio para la direccion de socket mas grande, una IPv6.  \~
constexpr size_t kMaxAddress = 28;

/**
 * @brief
 * \~english One endpoint's address, as opaque bytes.
 * \~spanish La direccion de un extremo, como bytes opacos.
 * \~
 */
struct Address {
    uint8_t bytes[kMaxAddress] = {};
    uint8_t len = 0;
};

/**
 * @brief
 * \~english The address of this end and the peer's, as one datagram sees them.
 * \~spanish La direccion de este extremo y la del otro, tal como las ve un datagrama.
 * \~
 */
struct Path {
    Address local;
    Address peer;
};

/// \~english Whether two addresses are the same.  \~spanish Si dos direcciones son la misma.  \~
inline bool same_address(const Address &a, const Address &b) noexcept {
    if (a.len != b.len) return false;
    for (size_t i = 0; i < a.len; ++i)
        if (a.bytes[i] != b.bytes[i]) return false;
    return true;
}

/// \~english Whether two paths are the same.  \~spanish Si dos caminos son el mismo.  \~
inline bool same_path(const Path &a, const Path &b) noexcept {
    return same_address(a.local, b.local) && same_address(a.peer, b.peer);
}

/**
 * @brief
 * \~english Builds an address from @p n bytes; false if they do not fit.
 * \~spanish Construye una direccion a partir de @p n bytes; falso si no caben.
 * \~
 */
inline bool make_address(const void *bytes, size_t n, Address &out) noexcept {
    if (n > kMaxAddress) return false;
    const uint8_t *b = static_cast<const uint8_t *>(bytes);
    for (size_t i = 0; i < n; ++i) out.bytes[i] = b[i];
    out.len = static_cast<uint8_t>(n);
    return true;
}

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_PATH_H
