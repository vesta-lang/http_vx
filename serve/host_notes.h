/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/host_notes.h
 * @brief
 * \~english What the runnable server says at start about the system it runs on, when that changes what it can promise.
 * \~spanish Lo que dice el servidor ejecutable al arrancar del sistema en que corre, cuando eso cambia lo que puede prometer.
 * \~
 */
#ifndef HTTP_VX_SERVE_HOST_NOTES_H
#define HTTP_VX_SERVE_HOST_NOTES_H

#include <cstdio>

namespace serve {

/**
 * @brief
 * \~english Warns, on Linux, when `net.ipv4.tcp_migrate_req` is off (HVX-6, 4.1).
 * \~spanish Avisa, en Linux, cuando `net.ipv4.tcp_migrate_req` esta apagado (HVX-6, 4.1).
 * \~
 *
 * \~english
 * With one listening socket per shard, closing a listening socket aborts the
 * connections it had queued unless the kernel migrates them to another socket
 * of the group; so stopping one shard would lose connections.  A kernel that
 * does not have the setting (before 5.14) is said too: it cannot migrate.
 * \~spanish
 * Con un socket de escucha por fragmento, cerrar uno aborta las conexiones que
 * tuviera en cola salvo que el nucleo las migre a otro socket del grupo; asi
 * que parar un fragmento perderia conexiones.  Un nucleo que no tiene el ajuste
 * (anterior a 5.14) tambien se dice: no puede migrar.
 * \~
 *
 * @param out \~english where the warning goes  \~spanish a donde va el aviso  \~
 * @return    \~english true if a warning was printed  \~spanish true si se imprimio un aviso  \~
 */
bool warn_if_no_migrate_req(std::FILE *out) noexcept;

} // namespace serve

#endif // HTTP_VX_SERVE_HOST_NOTES_H
