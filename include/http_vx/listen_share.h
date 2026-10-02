/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/listen_share.h
 * @brief
 * \~english Whether a listening socket may share its address with the listening sockets of other shards.
 * \~spanish Si un socket de escucha puede compartir su direccion con los sockets de escucha de otros fragmentos.
 * \~
 *
 * \~english
 * HVX-6, 4.1.  On Linux every shard opens its own listening socket on the same
 * address with `SO_REUSEPORT`, and the kernel spreads incoming connections
 * across them by a hash of the connection's four-tuple.  Every socket of the
 * group must ask for it BEFORE binding, the first included, which is why it
 * is a property of the listen call and not something done afterwards.
 * \~spanish
 * HVX-6, 4.1.  En Linux cada fragmento abre su propio socket de escucha en la
 * misma direccion con `SO_REUSEPORT`, y el nucleo reparte las conexiones
 * entrantes entre ellos por un hash de la cuadrupla de la conexion.  Todos los
 * sockets del grupo deben pedirlo ANTES de atarse, el primero incluido, y por
 * eso es una propiedad de la llamada a listen y no algo que se haga despues.
 * \~
 */
#ifndef HTTP_VX_LISTEN_SHARE_H
#define HTTP_VX_LISTEN_SHARE_H

#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Whether the address of a listening socket is shared.
 * \~spanish Si la direccion de un socket de escucha se comparte.
 * \~
 */
enum class ListenShare : uint8_t {
    /// \~english Only this socket listens there (the default).  \~spanish Solo este socket escucha ahi (el valor por defecto).  \~
    Alone = 0,
    /// \~english Other sockets of the same program may listen on the same address (`SO_REUSEPORT`).  \~spanish Otros sockets del mismo programa pueden escuchar en la misma direccion (`SO_REUSEPORT`).  \~
    SharedPort = 1,
};

} // namespace http_vx

#endif // HTTP_VX_LISTEN_SHARE_H
