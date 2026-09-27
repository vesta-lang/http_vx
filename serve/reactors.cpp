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
                    uint32_t connections, const char *host, uint16_t on) noexcept {
#ifdef _WIN32
    (void)want;

    /* \~english
     * The ceiling is on OPERATIONS here, because a completion port holds one
     * record per thing the kernel is doing.
     * \~spanish
     * Aqui el techo es de OPERACIONES, porque un puerto de finalizacion guarda
     * un registro por cosa que este haciendo el nucleo.
     * \~ */
    if (!iocp_.reset(pool, connections * 2 + 64) || !iocp_.listen(host, on)) {
        error_ = iocp_.last_error();
        return false;
    }
    port_ = iocp_.port();
    io_ = &iocp_;
    return true;
#else
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
        if (!uring_.reset(pool, 1024) || !uring_.listen(host, on)) {
            error_ = uring_.last_error();
            return false;
        }
        port_ = uring_.port();
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
    if (!epoll_.reset(pool, connections + 64) || !epoll_.listen(host, on)) {
        error_ = epoll_.last_error();
        return false;
    }
    port_ = epoll_.port();
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
