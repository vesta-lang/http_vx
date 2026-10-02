/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/reactors.cpp
 * @brief
 * \~english Making the backend that was named, and nothing else.
 * \~spanish Hacer el backend que se nombro, y ningun otro.
 * \~
 */
#include "serve/reactors.h"

#include <cstring>

namespace serve {

#ifdef _WIN32
Reactors::Reactors() noexcept : all_{&iocp_} {}
#else
Reactors::Reactors() noexcept : all_{&epoll_, &uring_} {}
#endif

bool Reactors::has(const char *want) const noexcept {
    for (size_t i = 0; i < kBackends; ++i)
        if (std::strcmp(want, all_[i]->name()) == 0) return true;
    return false;
}

void Reactors::print_names(std::FILE *out) const noexcept {
    for (size_t i = 0; i < kBackends; ++i)
        std::fprintf(out, "%s%s", i == 0 ? "" : ", ", all_[i]->name());
}

bool Reactors::make(const char *want, http_vx::BufferPool &pool,
                    uint32_t connections, const char *host, uint16_t on,
                    Listening listening) noexcept {
#ifdef _WIN32
    (void)want;

    /* \~english
     * Windows has no way to share an address between listening sockets (HVX-6,
     * 4.2): one shard listens and hands the sockets it accepts to the others.
     * Asking for a shared one is a request this system cannot meet, and it is
     * refused rather than turned into something else.
     * \~spanish
     * Windows no tiene forma de compartir una direccion entre sockets de
     * escucha (HVX-6, 4.2): un fragmento escucha y pasa los sockets que acepta a
     * los demas.  Pedir uno compartido es una peticion que este sistema no puede
     * cumplir, y se rechaza en vez de convertirla en otra cosa.
     * \~ */
    if (listening == Listening::Shared) {
        error_ = 50; // ERROR_NOT_SUPPORTED
        return false;
    }

    /* \~english
     * The ceiling is on OPERATIONS here, because a completion port holds one
     * record per thing the kernel is doing.
     * \~spanish
     * Aqui el techo es de OPERACIONES, porque un puerto de finalizacion guarda
     * un registro por cosa que este haciendo el nucleo.
     * \~ */
    if (!iocp_.reset(pool, connections * 2 + 64)) {
        error_ = iocp_.last_error();
        return false;
    }
    if (listening == Listening::Alone && !iocp_.listen(host, on)) {
        error_ = iocp_.last_error();
        return false;
    }
    port_ = listening == Listening::Alone ? iocp_.port() : on;
    io_ = &iocp_;
    return true;
#else
    const http_vx::ListenShare share =
        listening == Listening::Shared ? http_vx::ListenShare::SharedPort : http_vx::ListenShare::Alone;
    const bool listens = listening != Listening::Off;

    if (std::strcmp(want, uring_.name()) == 0) {
        /* \~english
         * The ceiling is on RING ENTRIES, which is neither of the other two:
         * it bounds what is waiting to be handed over, and the kernel makes
         * the completion ring twice as large for what is in flight.
         * \~spanish
         * El techo es de ENTRADAS DEL ANILLO, que no es ninguno de los otros
         * dos: acota lo que espera a entregarse, y el nucleo hace el anillo de
         * finalizaciones del doble para lo que esta en vuelo.
         * \~ */
        if (!uring_.reset(pool, 1024) || (listens && !uring_.listen(host, on, 512, share))) {
            error_ = uring_.last_error();
            return false;
        }
        port_ = listens ? uring_.port() : on;
        io_ = &uring_;
        return true;
    }

    /* \~english
     * The ceiling is on DESCRIPTORS, because readiness holds a note per socket
     * and nothing per operation.
     * \~spanish
     * El techo es de DESCRIPTORES, porque la disponibilidad guarda una nota por
     * socket y nada por operacion.
     * \~ */
    if (!epoll_.reset(pool, connections + 64) || (listens && !epoll_.listen(host, on, 512, share))) {
        error_ = epoll_.last_error();
        return false;
    }
    port_ = listens ? epoll_.port() : on;
    io_ = &epoll_;
    return true;
#endif
}

int32_t Reactors::open_udp(const char *host, uint16_t on,
                           http_vx::NetAddress &bound) noexcept {
#ifdef _WIN32
    const int32_t fd = iocp_.open_datagram(host, on, bound);
    if (fd < 0) error_ = iocp_.last_error();
#else
    int32_t fd = -1;
    if (io_ == &uring_) {
        fd = uring_.open_datagram(host, on, bound);
        if (fd < 0) error_ = uring_.last_error();
    } else {
        fd = epoll_.open_datagram(host, on, bound);
        if (fd < 0) error_ = epoll_.last_error();
    }
#endif
    return fd;
}

} // namespace serve
