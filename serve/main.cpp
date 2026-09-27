/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/main.cpp
 * @brief
 * \~english A server you can run, with no network anywhere in it.
 * \~spanish Un servidor que se puede ejecutar, y sin red por ningun sitio.
 * \~
 *
 * \~english
 * Everything the project has built, wired together and given a `main`.  It
 * reads a request from its standard input and writes the response to its
 * standard output, which is a real transport and not a stand-in: HTTP over a
 * pipe is how the Docker daemon is spoken to and how gRPC runs between
 * containers.
 *
 * @code
 * printf 'GET /hello HTTP/1.1\r\nHost: a\r\n\r\n' | http_vx_serve
 * @endcode
 *
 * **What it is for is being the thing that runs.**  A test says a piece
 * behaves; this says the pieces are a server.  Everything in it -- the
 * parser, the framing, the writer, the connection table, the buffer pool, the
 * deadlines, the loop -- is the same code that will run on a socket, and the
 * only line that would change is which backend is made.
 *
 * \~spanish
 * Todo lo que ha construido el proyecto, junto y con un `main`.  Lee una
 * peticion de su entrada estandar y escribe la respuesta en su salida estandar,
 * que es un transporte de verdad y no un sustituto: HTTP por una tuberia es como
 * se le habla al demonio de Docker y como corre gRPC entre contenedores.
 *
 * @code
 * printf 'GET /hello HTTP/1.1\r\nHost: a\r\n\r\n' | http_vx_serve
 * @endcode
 *
 * **Para lo que sirve es para ser lo que se ejecuta.**  Una prueba dice que una
 * pieza se comporta; esto dice que las piezas son un servidor.  Todo lo que hay
 * dentro -- el analizador, el troceado, el escritor, la tabla de conexiones, el
 * pozo de buffers, los plazos, el bucle -- es el mismo codigo que correra sobre
 * un socket, y la unica linea que cambiaria es cual backend se hace.
 *
 * \~
 */

#include "http_vx/stdio_backend.h"
#include "serve/greeting.h"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

using serve::Greeting;

/**
 * @brief
 * \~english Puts the standard streams in binary mode where that is a thing.
 * \~spanish Pone los flujos estandar en modo binario donde eso existe.
 * \~
 *
 * \~english
 * On Windows a descriptor opened in text mode turns every `\n` it writes into
 * `\r\n` and every `\r\n` it reads into `\n`.  HTTP's line endings are part of
 * the protocol, so a server whose streams did that would be one that produced
 * `\r\r\n` and could not parse a request it had just been sent.
 *
 * \~spanish
 * En Windows un descriptor abierto en modo texto convierte cada `\n` que
 * escribe en `\r\n` y cada `\r\n` que lee en `\n`.  Los finales de linea de
 * HTTP son parte del protocolo, asi que un servidor cuyos flujos hicieran eso
 * produciria `\r\r\n` y no sabria analizar una peticion que le acababan de
 * mandar.
 *
 * \~
 */
void make_binary() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
}

} // namespace

/**
 * @brief
 * \~english Serves one connection from the standard input.
 * \~spanish Sirve una conexion desde la entrada estandar.
 * \~
 *
 * @return \~english zero if it served, one if it could not start
 *         \~spanish cero si sirvio, uno si no pudo arrancar  \~
 */
int main() {
    make_binary();

    Greeting greeting;
    http_vx::Http1Service service;
    http_vx::Shard shard;

    http_vx::h1::Limits h1;
    if (!service.reset(4, greeting, h1)) {
        std::fprintf(stderr, "http_vx: no memory for the service\n");
        return 1;
    }

    http_vx::StdioBackend io(shard.buffers(), 0, 1);
    if (!io.ready()) {
        std::fprintf(stderr, "http_vx: cannot make the stdio backend's wake (error %d)\n",
                     static_cast<int>(io.wake_error()));
        return 1;
    }

    http_vx::ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 4;
    cfg.idle_ticks = 30;
    cfg.wheel_slots = 64;

    if (!shard.reset(cfg, io, service, 0)) {
        std::fprintf(stderr, "http_vx: no memory for the shard\n");
        return 1;
    }

    /* \~english
     * One connection, because there is one standard input.  The shard is the
     * same shard that would hold a million -- nothing in it was told this is a
     * small case.
     * \~spanish
     * Una conexion, porque hay una entrada estandar.  El fragmento es el mismo
     * que tendria un millon -- a nada de lo que hay dentro se le ha dicho que
     * este es un caso pequeno.
     * \~ */
    const http_vx::ConnHandle c = shard.adopt(0, 0);
    if (!c.valid()) {
        std::fprintf(stderr, "http_vx: no room for the connection\n");
        return 1;
    }

    /* \~english
     * Round until the connection is gone.  What ends it is the peer closing
     * its end, an error, or the service deciding not to carry on -- and the
     * loop finds all three out the same way, which is a completion coming
     * back.
     * \~spanish
     * Vueltas hasta que la conexion se va.  Lo que la acaba es que el otro
     * extremo cierre su lado, un error, o que el servicio decida no seguir -- y
     * el bucle se entera de las tres de la misma forma, que es una finalizacion
     * que vuelve.
     * \~ */
    while (shard.conns().alive(c)) {
        if (shard.poll(0, -1) == 0) break;
    }

    shard.release();
    service.release();
    return 0;
}
