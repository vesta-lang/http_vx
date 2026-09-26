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
 * With `--tls CERT KEY` it serves HTTPS instead: TLS 1.3, and HTTP/2 or
 * HTTP/1.1 as ALPN chooses (tls_service.h), with `--tls-provider cng|openssl`
 * to say whose primitives.  A build with no provider refuses to start rather
 * than serve in the clear (R24).  No 0-RTT over TCP.
 *
 * @code
 * http_vx_listen --tls cert.pem key.pem 127.0.0.1 8443
 * curl -k --http2 https://127.0.0.1:8443/hello
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
 * Con `--tls CERT CLAVE` sirve HTTPS en su lugar: TLS 1.3, y HTTP/2 o HTTP/1.1
 * segun elija ALPN (tls_service.h), con `--tls-provider cng|openssl` para decir
 * de quien son las primitivas.  Una construccion sin proveedor se niega a
 * arrancar en vez de servir en claro (R24).  Sin 0-RTT sobre TCP.
 *
 * @code
 * http_vx_listen --tls cert.pem clave.pem 127.0.0.1 8443
 * curl -k --http2 https://127.0.0.1:8443/hola
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
#include "serve/h3_setup.h"
#include "serve/report.h"
#include "serve/tls_setup.h"

#include "http_vx/http2_service.h"
#include "http_vx/tls_service.h"

#ifdef _WIN32
#include "http_vx/iocp_backend.h"
#else
#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

using serve::Greeting;

/**
 * @brief
 * \~english Every backend this build has, and the one that was chosen.
 * \~spanish Todos los backends que tiene esta construccion, y el que se eligio.
 * \~
 *
 * \~english
 * R8 says the backend is chosen in CONFIGURATION, and that is what this is for.
 * The requirement is not about having two: it is about neither of them being a
 * path nobody runs, and the first thing that needs is for whoever runs the
 * server to be able to say which one and to be TOLD which one they got.
 *
 * A server that fell back silently -- io_uring if the kernel has it, epoll if
 * not -- would be one where nobody can tell what they measured, and the epoll
 * path would go untested on every machine that has a modern kernel.
 *
 * \~spanish
 * La R8 dice que el backend se elige en CONFIGURACION, y para eso esta esto.  El
 * requisito no va de tener dos: va de que ninguno de los dos sea un camino que no
 * corre nadie, y lo primero que hace falta para eso es que quien ejecute el
 * servidor pueda decir cual y que le DIGAN cual le toco.
 *
 * Un servidor que se cayera a otro en silencio -- io_uring si el nucleo lo
 * tiene, epoll si no -- seria uno donde nadie puede saber que midio, y el camino
 * de epoll se quedaria sin probar en todas las maquinas con un nucleo moderno.
 * \~
 */
struct Reactors {
#ifdef _WIN32
    http_vx::IocpBackend iocp;
#else
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
#endif

    http_vx::Backend *io = nullptr;
    uint16_t port = 0;
    int32_t error = 0;

    /// \~english Makes the one @p want names, or says why not.
    /// \~spanish Hace el que nombra @p want, o dice por que no.  \~
    bool make(const char *want, http_vx::BufferPool &pool,
              uint32_t connections, const char *host, uint16_t on) {
#ifdef _WIN32
        (void)want;

        /* \~english
         * The ceiling is on OPERATIONS here, because a completion port holds
         * one record per thing the kernel is doing.
         * \~spanish
         * Aqui el techo es de OPERACIONES, porque un puerto de finalizacion
         * guarda un registro por cosa que este haciendo el nucleo.
         * \~ */
        if (!iocp.reset(pool, connections * 2 + 64)) {
            error = iocp.last_error();
            return false;
        }
        if (!iocp.listen(host, on)) {
            error = iocp.last_error();
            return false;
        }
        port = iocp.port();
        io = &iocp;
        return true;
#else
        if (std::strcmp(want, "io_uring") == 0) {
            /* \~english
             * The ceiling is on RING ENTRIES, which is neither of the other
             * two: it bounds what is waiting to be handed over, and the kernel
             * makes the completion ring twice as large for what is in flight.
             * \~spanish
             * El techo es de ENTRADAS DEL ANILLO, que no es ninguno de los otros
             * dos: acota lo que espera a entregarse, y el nucleo hace el anillo de
             * finalizaciones del doble para lo que esta en vuelo.
             * \~ */
            if (!uring.reset(pool, 1024)) {
                error = uring.last_error();
                return false;
            }
            if (!uring.listen(host, on)) {
                error = uring.last_error();
                return false;
            }
            port = uring.port();
            io = &uring;
            return true;
        }

        /* \~english
         * The ceiling is on DESCRIPTORS, because readiness holds a note per
         * socket and nothing per operation.
         * \~spanish
         * El techo es de DESCRIPTORES, porque la disponibilidad guarda una nota
         * por socket y nada por operacion.
         * \~ */
        if (!epoll.reset(pool, connections + 64)) {
            error = epoll.last_error();
            return false;
        }
        if (!epoll.listen(host, on)) {
            error = epoll.last_error();
            return false;
        }
        port = epoll.port();
        io = &epoll;
        return true;
#endif
    }

    /// \~english A UDP socket on the backend chosen, for HTTP/3; -1, with error, if it cannot be had.
    /// \~spanish Un socket UDP en el backend elegido, para HTTP/3; -1, con error, si no se puede tener.  \~
    int32_t open_udp(const char *host, uint16_t on, http_vx::NetAddress &bound) {
#ifdef _WIN32
        const int32_t fd = iocp.open_datagram(host, on, bound);
        if (fd < 0) error = iocp.last_error();
#else
        int32_t fd = -1;
        if (io == &uring) {
            fd = uring.open_datagram(host, on, bound);
            if (fd < 0) error = uring.last_error();
        } else {
            fd = epoll.open_datagram(host, on, bound);
            if (fd < 0) error = epoll.last_error();
        }
#endif
        return fd;
    }
};

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

/// \~english The same steady clock in microseconds: ticket ages are measured in milliseconds.
/// \~spanish El mismo reloj estable en microsegundos: las edades de los tickets se miden en milisegundos.  \~
uint64_t now_us() {
    using Clock = std::chrono::steady_clock;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count());
}

/**
 * @brief
 * \~english What the command line asked for: the positional host, port and backend, and TLS.
 * \~spanish Lo que pidio la linea de ordenes: el anfitrion, el puerto y el backend posicionales, y TLS.
 * \~
 */
struct Options {
    const char *positional[3] = {nullptr, nullptr, nullptr};
    size_t count = 0;
    const char *cert = nullptr;
    const char *key = nullptr;
    const char *provider = nullptr;
    /// \~english HTTP/3 on UDP, same address and port.  \~spanish HTTP/3 sobre UDP, misma direccion y puerto.  \~
    bool h3 = false;
    const char *error = nullptr;

    /// \~english Reads @p argv; a flag without its values is an error, said.
    /// \~spanish Lee @p argv; una bandera sin sus valores es un error, que se dice.  \~
    void parse(int argc, char **argv) {
        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--tls") == 0) {
                if (i + 2 >= argc) {
                    error = "--tls needs a certificate file and a key file";
                    return;
                }
                cert = argv[++i];
                key = argv[++i];
            } else if (std::strcmp(argv[i], "--tls-provider") == 0) {
                if (i + 1 >= argc) {
                    error = "--tls-provider needs a name: cng or openssl";
                    return;
                }
                provider = argv[++i];
            } else if (std::strcmp(argv[i], "--h3") == 0) {
                h3 = true;
            } else if (count < 3) {
                positional[count++] = argv[i];
            } else {
                error = "too many arguments";
                return;
            }
        }
        if (provider != nullptr && cert == nullptr) error = "--tls-provider without --tls";
        // \~english HTTP/3 is always encrypted: QUIC carries TLS 1.3 inside it (RFC 9001).
        // \~spanish HTTP/3 va siempre cifrado: QUIC lleva TLS 1.3 dentro (RFC 9001).  \~
        if (h3 && cert == nullptr) error = "--h3 needs --tls: QUIC has no unencrypted form";
    }
};

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
    Options opt;
    opt.parse(argc, argv);
    if (opt.error != nullptr) {
        std::fprintf(stderr, "http_vx: %s\n", opt.error);
        return 1;
    }
    const char *host = opt.count > 0 ? opt.positional[0] : "127.0.0.1";
    const uint16_t port =
        opt.count > 1 ? static_cast<uint16_t>(std::atoi(opt.positional[1])) : 8080;

    /* \~english
     * And WHICH backend, which is what R8 means by choosing it in
     * configuration.  The default is epoll and not the newest one on purpose:
     * a default that took io_uring wherever it exists would mean the epoll
     * path only ever runs on the kernels nobody develops on, which is how a
     * backend becomes a path nobody tests.
     *
     * A name this build does not have is not silently swapped for one it does.
     * It fails, and says so.
     *
     * \~spanish
     * Y CUAL backend, que es lo que quiere decir la R8 con elegirlo en
     * configuracion.  El valor por defecto es epoll y no el mas nuevo a
     * proposito: uno que cogiera io_uring donde exista haria que el camino de
     * epoll solo corriera en los nucleos en los que no desarrolla nadie, que es
     * como un backend se convierte en un camino que no prueba nadie.
     *
     * Un nombre que esta construccion no tiene no se cambia en silencio por uno
     * que si.  Falla, y lo dice.
     * \~ */
    const char *want = opt.count > 2 ? opt.positional[2] : "epoll";

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
    Reactors reactors;

    http_vx::h1::Limits h1;
    if (!service.reset(cfg.connections, greeting, h1)) {
        std::fprintf(stderr, "http_vx: no memory for the service\n");
        return 1;
    }

    /* \~english
     * HTTPS, when asked for: the same handler behind HTTP/1.1 and HTTP/2, and
     * TLS in front choosing between them.  Asked for and impossible is a
     * server that does not start -- never one that serves in the clear (R24).
     * \~spanish
     * HTTPS, cuando se pide: el mismo manejador detras de HTTP/1.1 y HTTP/2, y
     * TLS delante eligiendo entre ellos.  Pedido e imposible es un servidor que
     * no arranca -- nunca uno que sirve en claro (R24).
     * \~ */
    serve::TlsSetup tls_setup;
    http_vx::Http2Service h2_service;
    http_vx::TlsService tls_service;
    http_vx::Service *front = &service;
    if (opt.cert != nullptr) {
        if (!tls_setup.load(opt.provider, opt.cert, opt.key)) {
            std::fprintf(stderr, "http_vx: cannot serve TLS: %s\n", tls_setup.why());
            return 1;
        }
        const http_vx::h2::Limits h2;
        http_vx::TlsServiceConfig tcfg;
        tcfg.crypto = tls_setup.crypto();
        tcfg.http1 = &service;
        tcfg.http2 = &h2_service;
        tcfg.certificates = tls_setup.certificates();
        tcfg.certificate_lens = tls_setup.certificate_lens();
        tcfg.certificate_count = tls_setup.certificate_count();
        tcfg.signing_key = tls_setup.signing_key();
        tcfg.scheme = tls_setup.scheme();
        tcfg.tickets = tls_setup.tickets();
        tcfg.buffers = cfg.buffers;
        if (!h2_service.reset(cfg.connections, 256, 1 << 20, greeting, h2) ||
            !tls_service.reset(cfg.connections, tcfg)) {
            std::fprintf(stderr, "http_vx: cannot serve TLS: %s\n",
                         tls_service.why() != nullptr ? tls_service.why() : "no memory for HTTP/2");
            return 1;
        }
        tls_service.set_clock(now_us());
        front = &tls_service;
        std::fprintf(stderr, "http_vx: TLS 1.3 with the %s provider, h2 and http/1.1 by ALPN, no 0-RTT\n",
                     tls_setup.crypto()->name());
    }

    if (!reactors.make(want, shard.buffers(), cfg.connections, host, port)) {
        std::fprintf(stderr,
                     "http_vx: cannot listen on %s:%u with %s (error %d)\n",
                     host, static_cast<unsigned>(port), want, reactors.error);
        return 1;
    }

    if (!shard.reset(cfg, *reactors.io, *front, now_ticks())) {
        std::fprintf(stderr, "http_vx: no memory for the shard\n");
        return 1;
    }

    std::fprintf(stderr, "http_vx: listening on %s:%u, %s backend\n", host,
                 static_cast<unsigned>(reactors.port), reactors.io->name());

    // \~english HTTP/3: the same identity as TLS over TCP, on UDP at the port TCP got.
    // \~spanish HTTP/3: la misma identidad que TLS sobre TCP, sobre UDP en el puerto que obtuvo TCP.  \~
    serve::H3Setup h3(now_us);
    if (opt.h3) {
        http_vx::NetAddress bound;
        const int32_t udp = reactors.open_udp(host, reactors.port, bound);
        if (udp < 0) {
            std::fprintf(stderr, "http_vx: cannot open UDP on %s:%u (error %d)\n", host,
                         static_cast<unsigned>(reactors.port), reactors.error);
            return 1;
        }
        http_vx::DatagramConfig dcfg;
        dcfg.receives = 16;
        if (!h3.start(tls_setup, greeting, cfg.connections) || !shard.attach_datagrams(h3.datagrams(), dcfg) ||
            !shard.add_datagram_socket(udp, bound)) {
            std::fprintf(stderr, "http_vx: cannot serve HTTP/3: %s\n",
                         h3.why() != nullptr ? h3.why() : "the shard would not take the datagram side");
            return 1;
        }
        std::fprintf(stderr, "http_vx: HTTP/3 on udp %s:%u, 0-RTT after the replay window (%llu s)\n", host,
                     static_cast<unsigned>(reactors.port),
                     static_cast<unsigned long long>(serve::H3Setup::kReplayWindowMs / 1000));
    }
    serve::Report report;

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
        tls_service.set_clock(now_us());
        // \~english QUIC's timers are finer than a tick: the wait ends when the next one is due.
        // \~spanish Los temporizadores de QUIC son mas finos que un tic: la espera acaba cuando vence el siguiente.  \~
        shard.poll(now_ticks(), opt.h3 ? h3.datagrams().wait_ms(250) : 250);
        if (opt.cert != nullptr) report.tls(tls_service);
        if (opt.h3) report.h3(h3.service());

        const uint64_t now = now_ticks();
        if (now != last) {
            shard.expire(now);
            last = now;
        }
    }
}
