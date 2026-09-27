/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/reactors.h
 * @brief
 * \~english Every backend this build has, chosen by name, and the one that was chosen.
 * \~spanish Todos los backends que tiene esta construccion, elegidos por nombre, y el que se eligio.
 * \~
 *
 * \~english
 * R8 says the backend is chosen in CONFIGURATION, and that is what this is for.
 * The requirement is not about having two: it is about neither of them being a
 * path nobody runs, and the first thing that needs is for whoever runs the
 * server to be able to say which one and to be TOLD which one they got.
 *
 * A server that fell back silently -- io_uring if the kernel has it, epoll if
 * not, or whatever this build has for a name it does not -- would be one where
 * nobody can tell what they measured.  So a name is looked for among the
 * backends' own names (@c Backend::name, their only owner) and a name that is
 * not there is refused, with the list of the ones that are.
 *
 * \~spanish
 * La R8 dice que el backend se elige en CONFIGURACION, y para eso esta esto.  El
 * requisito no va de tener dos: va de que ninguno de los dos sea un camino que no
 * corre nadie, y lo primero que hace falta para eso es que quien ejecute el
 * servidor pueda decir cual y que le DIGAN cual le toco.
 *
 * Un servidor que se cayera a otro en silencio -- io_uring si el nucleo lo
 * tiene, epoll si no, o el que tenga esta construccion para un nombre que no
 * tiene -- seria uno donde nadie puede saber que midio.  Asi que un nombre se
 * busca entre los nombres de los propios backends (@c Backend::name, su unico
 * dueno) y uno que no este se rechaza, con la lista de los que si.
 * \~
 */
#ifndef HTTP_VX_SERVE_REACTORS_H
#define HTTP_VX_SERVE_REACTORS_H

#ifdef _WIN32
#include "http_vx/iocp_backend.h"
#else
#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"
#endif

#include "http_vx/buffer_pool.h"
#include "http_vx/datagram.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace serve {

/**
 * @brief
 * \~english The backends of this build, and the one made.
 * \~spanish Los backends de esta construccion, y el que se hizo.
 * \~
 */
class Reactors {
  public:
    Reactors() noexcept;

    Reactors(const Reactors &) = delete;
    Reactors &operator=(const Reactors &) = delete;

    /**
     * @brief
     * \~english The backend used when none is named.
     * \~spanish El backend que se usa cuando no se nombra ninguno.
     * \~
     *
     * \~english
     * epoll on Linux and not the newest one, on purpose: a default that took
     * io_uring wherever it exists would mean the epoll path only ever runs on
     * the kernels nobody develops on.
     * \~spanish
     * epoll en Linux y no el mas nuevo, a proposito: uno que cogiera io_uring
     * donde exista haria que el camino de epoll solo corriera en los nucleos en
     * los que no desarrolla nadie.
     * \~
     */
    const char *default_name() const noexcept { return all_[0]->name(); }

    /// \~english Whether this build has a backend called @p want.
    /// \~spanish Si esta construccion tiene un backend llamado @p want.  \~
    bool has(const char *want) const noexcept;

    /// \~english Writes the names this build has, separated by ", ".
    /// \~spanish Escribe los nombres que tiene esta construccion, separados por ", ".  \~
    void print_names(std::FILE *out) const noexcept;

    /**
     * @brief
     * \~english Makes the backend @p want names and listens on it.
     * \~spanish Hace el backend que nombra @p want y escucha en el.
     * \~
     *
     * @param want        \~english a name @c has accepted  \~spanish un nombre que @c has acepto  \~
     * @param pool        \~english the shard's buffers  \~spanish los buffers del fragmento  \~
     * @param connections \~english how many connections the shard holds  \~spanish cuantas conexiones tiene el fragmento  \~
     * @param host        \~english the address  \~spanish la direccion  \~
     * @param on          \~english the port, zero for any  \~spanish el puerto, cero para cualquiera  \~
     * @return            \~english false, with @c error set, if it could not
     *                    \~spanish false, con @c error puesto, si no se pudo  \~
     */
    bool make(const char *want, http_vx::BufferPool &pool, uint32_t connections,
              const char *host, uint16_t on) noexcept;

    /// \~english A UDP socket on the backend made, for HTTP/3; -1, with @c error, if it cannot be had.
    /// \~spanish Un socket UDP en el backend hecho, para HTTP/3; -1, con @c error, si no se puede tener.  \~
    int32_t open_udp(const char *host, uint16_t on, http_vx::NetAddress &bound) noexcept;

    /// \~english The backend made, or null.  \~spanish El backend hecho, o nulo.  \~
    http_vx::Backend *io() const noexcept { return io_; }

    /// \~english The port it got.  \~spanish El puerto que le toco.  \~
    uint16_t port() const noexcept { return port_; }

    /// \~english What the system said last.  \~spanish Lo ultimo que dijo el sistema.  \~
    int32_t error() const noexcept { return error_; }

  private:
#ifdef _WIN32
    http_vx::IocpBackend iocp_;
    static constexpr size_t kBackends = 1;
#else
    http_vx::EpollBackend epoll_;
    http_vx::UringBackend uring_;
    static constexpr size_t kBackends = 2;
#endif

    /// \~english Every backend, the default first.  \~spanish Todos los backends, el de por defecto primero.  \~
    http_vx::Backend *all_[kBackends];

    http_vx::Backend *io_ = nullptr;
    uint16_t port_ = 0;
    int32_t error_ = 0;
};

} // namespace serve

#endif // HTTP_VX_SERVE_REACTORS_H
