/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/options.h
 * @brief
 * \~english What the command line of the runnable server asked for, or why it cannot be read.
 * \~spanish Lo que pidio la linea de ordenes del servidor ejecutable, o por que no se puede leer.
 * \~
 *
 * \~english
 * Nothing on the command line is guessed.  An option this program does not
 * know is an error and not a host; a port that is not a number from 0 to
 * 65535 is an error and not zero -- which would mean "any port", a server
 * listening somewhere nobody asked for.
 * \~spanish
 * Nada de la linea de ordenes se adivina.  Una opcion que este programa no
 * conoce es un error y no un anfitrion; un puerto que no es un numero de 0 a
 * 65535 es un error y no un cero -- que querria decir "cualquier puerto", un
 * servidor escuchando donde nadie pidio.
 * \~
 */
#ifndef HTTP_VX_SERVE_OPTIONS_H
#define HTTP_VX_SERVE_OPTIONS_H

#include "serve/reactors.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace serve {

/**
 * @brief
 * \~english The host, port and backend, TLS and HTTP/3, as asked for.
 * \~spanish El anfitrion, el puerto y el backend, TLS y HTTP/3, segun se pidieron.
 * \~
 */
struct Options {
    /// \~english Where to listen; loopback unless said.  \~spanish Donde escuchar; bucle local salvo que se diga.  \~
    const char *host = "127.0.0.1";
    /// \~english The port; zero asks for any.  \~spanish El puerto; cero pide cualquiera.  \~
    uint16_t port = 8080;
    /// \~english The backend's name, or null for the build's default.  \~spanish El nombre del backend, o nulo para el de la construccion.  \~
    const char *backend = nullptr;

    const char *cert = nullptr;
    const char *key = nullptr;
    const char *provider = nullptr;
    /// \~english HTTP/3 on UDP, same address and port.  \~spanish HTTP/3 sobre UDP, misma direccion y puerto.  \~
    bool h3 = false;
    /// \~english The usage was asked for.  \~spanish Se pidio el uso.  \~
    bool help = false;

    /// \~english What is wrong, or null.  \~spanish Lo que esta mal, o nulo.  \~
    const char *error = nullptr;
    /// \~english The argument it is about, or null.  \~spanish El argumento del que se trata, o nulo.  \~
    const char *culprit = nullptr;

    /**
     * @brief
     * \~english Reads @p argv; anything that cannot be read is an error, said.
     * \~spanish Lee @p argv; lo que no se puede leer es un error, que se dice.
     * \~
     *
     * @param argc \~english how many arguments  \~spanish cuantos argumentos  \~
     * @param argv \~english the arguments  \~spanish los argumentos  \~
     */
    void parse(int argc, char **argv) noexcept;
};

/// \~english Prints how the server is run, with the backends of this build.
/// \~spanish Imprime como se ejecuta el servidor, con los backends de esta construccion.  \~
void print_usage(std::FILE *out, const Reactors &reactors) noexcept;

} // namespace serve

#endif // HTTP_VX_SERVE_OPTIONS_H
