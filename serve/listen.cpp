/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/listen.cpp
 * @brief
 * \~english The same server, on a port.
 * \~spanish El mismo servidor, en un puerto.
 * \~
 *
 * \~english
 * Its neighbour in this directory speaks HTTP down a pipe and says, at the end
 * of its own file, that the only line which would change to put it on a socket
 * is which backend is made.  This is that line, and nothing else in the server
 * moved: the same handler, the same service, the same loop, the same
 * connection table, the same buffer pool, the same deadlines.
 *
 * @code
 * http_vx_listen 127.0.0.1 8080
 * curl http://127.0.0.1:8080/hello
 * @endcode
 *
 * **Until this file there was no program in the project that opened a port.**
 * The backends were written and the tests drove them, and a test is a good
 * place to find out whether a socket works and a bad place to find out what a
 * server costs -- it serves five requests and exits, so nothing in it ever
 * runs long enough to profile, to leak, or to run out of anything.
 *
 * What it answers is a greeting and not a file, and that is not a placeholder
 * standing in for a real server: serving files needs a response whose body
 * lives somewhere other than the response, which is R14, and R14 needs a
 * scatter write, which is written in the interface and not yet in the loop.
 * When that lands, this file gains a handler and loses nothing else.
 *
 * \~spanish
 * Su vecino de este directorio habla HTTP por una tuberia y dice, al final de su
 * propio fichero, que la unica linea que cambiaria para ponerlo en un socket es
 * cual backend se hace.  Esta es esa linea, y no se movio nada mas del servidor:
 * el mismo manejador, el mismo servicio, el mismo bucle, la misma tabla de
 * conexiones, el mismo pozo de buffers, los mismos plazos.
 *
 * @code
 * http_vx_listen 127.0.0.1 8080
 * curl http://127.0.0.1:8080/hola
 * @endcode
 *
 * **Hasta este fichero no habia en el proyecto ningun programa que abriera un
 * puerto.**  Los backends estaban escritos y los movian las pruebas, y una
 * prueba es un buen sitio para averiguar si un socket funciona y uno malo para
 * averiguar lo que cuesta un servidor -- sirve cinco peticiones y termina, asi
 * que nada de lo que hay dentro corre lo suficiente como para perfilarlo, para
 * que pierda memoria, ni para que se quede sin nada.
 *
 * Lo que contesta es un saludo y no un fichero, y eso no es un relleno que
 * sustituya a un servidor de verdad: servir ficheros necesita una respuesta cuyo
 * cuerpo viva en otro sitio que la respuesta, que es la R14, y la R14 necesita
 * una escritura dispersa, que esta escrita en la interfaz y todavia no en el
 * bucle.  Cuando eso llegue, este fichero gana un manejador y no pierde nada
 * mas.
 *
 * \~
 */

#include "serve/greeting.h"

#ifdef _WIN32
#include "http_vx/iocp_backend.h"
#else
#include "http_vx/epoll_backend.h"
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace {

using serve::Greeting;

#ifdef _WIN32

using Reactor = http_vx::IocpBackend;

/**
 * \~english
 * The ceiling is on OPERATIONS here, because a completion port holds one
 * record per thing the kernel is doing.  On epoll it is on descriptors, which
 * is the same number counted from the other side, and the two do not have to
 * agree -- which is why this is per platform and not a number in the
 * configuration.
 * \~spanish
 * Aqui el techo es de OPERACIONES, porque un puerto de finalizacion guarda un
 * registro por cosa que este haciendo el nucleo.  En epoll es de descriptores,
 * que es el mismo numero contado desde el otro lado, y los dos no tienen por que
 * coincidir -- que es la razon de que esto sea por plataforma y no un numero de
 * la configuracion.
 * \~
 */
bool make_reactor(Reactor &io, http_vx::BufferPool &pool,
                  uint32_t connections) {
    return io.reset(pool, connections * 2 + 64);
}

#else

using Reactor = http_vx::EpollBackend;

bool make_reactor(Reactor &io, http_vx::BufferPool &pool,
                  uint32_t connections) {
    return io.reset(pool, connections + 64);
}

#endif

/**
 * @brief
 * \~english What tick it is, counted in seconds since the server started.
 * \~spanish En que tic se esta, contado en segundos desde que arranco el servidor.
 * \~
 *
 * \~english
 * A second, because that is the unit deadlines are talked about in: a
 * connection that says nothing for thirty seconds is a connection to hang up
 * on, and a wheel with a thousand slots then covers a quarter of an hour.
 *
 * It is a STEADY clock and not the wall one.  The wall clock jumps -- it is
 * corrected, it changes for the summer -- and a deadline measured against
 * something that can go backwards is a connection that either never times out
 * or times out at once, twice a year, on a server that worked all the other
 * days.
 *
 * \~spanish
 * Un segundo, porque es la unidad en la que se habla de los plazos: una conexion
 * que lleva treinta segundos callada es una a la que colgarle, y una rueda de
 * mil casillas cubre entonces un cuarto de hora.
 *
 * Es un reloj ESTABLE y no el de pared.  El de pared da saltos -- se corrige,
 * cambia en verano -- y un plazo medido contra algo que puede ir hacia atras es
 * una conexion que o no vence nunca o vence en el acto, dos veces al ano, en un
 * servidor que funciono todos los demas dias.
 * \~
 */
uint64_t now_ticks() {
    using Clock = std::chrono::steady_clock;
    static const Clock::time_point start = Clock::now();

    const auto since = Clock::now() - start;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(since).count());
}

} // namespace

/**
 * @brief
 * \~english Serves until it is stopped.
 * \~spanish Sirve hasta que lo paren.
 * \~
 *
 * @param argc \~english how many arguments  \~spanish cuantos argumentos  \~
 * @param argv \~english the host and the port
 *             \~spanish el anfitrion y el puerto  \~
 * @return     \~english one if it could not start
 *             \~spanish uno si no pudo arrancar  \~
 */
int main(int argc, char **argv) {
    /* \~english
     * Loopback by default, and it is a decision rather than an example.  A
     * server that bound every interface the moment it was run would be one
     * that put itself on the network of whoever tried it, and the difference
     * between the two is one argument that the person typing it has read.
     * \~spanish
     * Bucle local por defecto, y es una decision y no un ejemplo.  Un servidor
     * que se atara a todas las interfaces nada mas ejecutarlo seria uno que se
     * pone solo en la red de quien lo probo, y la diferencia entre las dos cosas
     * es un argumento que ha leido quien lo teclea.
     * \~ */
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const uint16_t port =
        argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 8080;

    http_vx::ShardConfig cfg;
    cfg.connections = 1024;
    cfg.buffers = 128;
    cfg.idle_ticks = 30;
    cfg.wheel_slots = 1024;

    /* \~english
     * And it accepts, which is the one setting a listening server must change:
     * a shard accepts nothing by default, because how accepting is spread
     * across shards is the platform's answer and not the shard's.  With one
     * shard there is nothing to spread.
     * \~spanish
     * Y acepta, que es el unico ajuste que tiene que cambiar un servidor a la
     * escucha: un fragmento no acepta nada por defecto, porque como se reparte
     * aceptar entre fragmentos es la respuesta de la plataforma y no del
     * fragmento.  Con un fragmento no hay nada que repartir.
     * \~ */
    cfg.accepts = 8;

    Greeting greeting;
    http_vx::Http1Service service;
    http_vx::Shard shard;
    Reactor io;

    http_vx::h1::Limits h1;
    if (!service.reset(cfg.connections, greeting, h1)) {
        std::fprintf(stderr, "http_vx: no memory for the service\n");
        return 1;
    }

    if (!make_reactor(io, shard.buffers(), cfg.connections)) {
        std::fprintf(stderr, "http_vx: no reactor (error %d)\n",
                     io.last_error());
        return 1;
    }

    if (!io.listen(host, port)) {
        std::fprintf(stderr, "http_vx: cannot listen on %s:%u (error %d)\n",
                     host, static_cast<unsigned>(port), io.last_error());
        return 1;
    }

    if (!shard.reset(cfg, io, service, now_ticks())) {
        std::fprintf(stderr, "http_vx: no memory for the shard\n");
        return 1;
    }

    std::fprintf(stderr, "http_vx: listening on %s:%u, %s backend\n", host,
                 static_cast<unsigned>(io.port()), io.name());

    uint64_t last = now_ticks();

    for (;;) {
        /* \~english
         * The wait is BOUNDED rather than endless, and the bound is what makes
         * deadlines happen.  A loop that waited for ever would notice a
         * connection had gone quiet only when some OTHER connection woke it
         * up, so a server with nothing to do would never hang up on anybody --
         * and a server with nothing to do is exactly when the connections
         * piling up are the ones that stopped talking.
         *
         * \~spanish
         * La espera esta ACOTADA y no es infinita, y la cota es lo que hace que
         * los plazos ocurran.  Un bucle que esperara para siempre se enteraria de
         * que una conexion se ha callado solo cuando lo despertara OTRA, asi que
         * un servidor sin nada que hacer no le colgaria nunca a nadie -- y un
         * servidor sin nada que hacer es justo cuando las conexiones que se
         * amontonan son las que dejaron de hablar.
         * \~ */
        shard.poll(now_ticks(), 250);

        const uint64_t now = now_ticks();
        if (now != last) {
            shard.expire(now);
            last = now;
        }
    }
}
