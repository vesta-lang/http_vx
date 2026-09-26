/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/epoll_waiting.h
 * @brief
 * \~english What epoll remembers per descriptor (private to linux/).
 * \~spanish Lo que recuerda epoll por descriptor (privado de linux/).
 * \~
 *
 * \~english
 * Its own header because two files read it: the stream operations in
 * `epoll_backend.cpp` and the datagram ones in `epoll_datagram.cpp`.
 * \~spanish
 * Cabecera propia porque la leen dos ficheros: las operaciones de flujo en
 * `epoll_backend.cpp` y las de datagramas en `epoll_datagram.cpp`.
 * \~
 */
#ifndef HTTP_VX_LINUX_EPOLL_WAITING_H
#define HTTP_VX_LINUX_EPOLL_WAITING_H

#include "http_vx/epoll_backend.h"

namespace http_vx {

/**
 * @brief
 * \~english What one socket is waiting for, in each direction.
 * \~spanish Lo que espera un socket, en cada sentido.
 * \~
 */
struct EpollBackend::Waiting {
    Op read;
    Op write;

    bool has_read;
    bool has_write;

    /**
     * \~english
     * What the queue was last told about this socket, so that it is only told
     * again when it changed.  An `epoll_ctl` per operation would be a syscall
     * bought for nothing on every read of a connection that was already being
     * read from.
     * \~spanish
     * Lo ultimo que se le dijo a la cola sobre este socket, para decirselo solo
     * cuando cambie.  Un `epoll_ctl` por operacion seria una llamada al sistema
     * comprada para nada en cada lectura de una conexion de la que ya se estaba
     * leyendo.
     * \~
     */
    uint32_t armed;

    bool known;

    /**
     * \~english
     * Which datagram socket this descriptor is, or -1 for a stream.  A
     * datagram socket keeps its operations in queues of its own, and the two
     * notes above stay empty for it.
     * \~spanish
     * Que socket de datagramas es este descriptor, o -1 para un flujo.  Un
     * socket de datagramas guarda sus operaciones en colas propias, y las dos
     * notas de arriba se quedan vacias para el.
     * \~
     */
    int8_t dgram;
};

} // namespace http_vx

#endif // HTTP_VX_LINUX_EPOLL_WAITING_H
