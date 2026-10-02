/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/listen.cpp
 * @brief
 * \~english The same server, on a port, on as many threads as asked for.
 * \~spanish El mismo servidor, en un puerto, en tantos hilos como se pidan.
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
 * With `--shards N` the server is N threads, each pinned to a CPU and each
 * serving the connections it accepts (HVX-6): the program is the one place
 * that decides how many, and the library only offers the shard.  This file
 * reads the command line, checks what only needs checking once, and hands the
 * rest to @c ShardGroup.  One shard is the server as it always was.
 *
 * What it answers is a greeting and not a file, and that is not a placeholder
 * standing in for a real server: serving files needs a response whose body
 * lives somewhere other than the response, which is R14, and R14 needs a
 * scatter write, which is written in the interface and not yet in the loop.
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
 * Con `--shards N` el servidor son N hilos, cada uno fijado a una CPU y cada uno
 * sirviendo las conexiones que acepta (HVX-6): el programa es el unico sitio que
 * decide cuantos, y la biblioteca solo ofrece el fragmento.  Este fichero lee la
 * linea de ordenes, comprueba lo que solo hay que comprobar una vez, y deja el
 * resto a @c ShardGroup.  Un fragmento es el servidor de siempre.
 *
 * Lo que contesta es un saludo y no un fichero, y eso no es un relleno que
 * sustituya a un servidor de verdad: servir ficheros necesita una respuesta cuyo
 * cuerpo viva en otro sitio que la respuesta, que es la R14, y la R14 necesita
 * una escritura dispersa, que esta escrita en la interfaz y todavia no en el
 * bucle.
 *
 * \~
 */

#include "serve/clock.h"
#include "serve/cpu_affinity.h"
#include "serve/host_notes.h"
#include "serve/options.h"
#include "serve/reactors.h"
#include "serve/shard_group.h"
#include "serve/tls_setup.h"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>

namespace {

/// \~english Set by the signal handler: the server was asked to stop.  \~spanish Lo pone el manejador de la senal: se le pidio parar al servidor.  \~
volatile std::sig_atomic_t g_stop = 0;

/// \~english The signal handler: only sets the flag, which is all a handler may safely do.  \~spanish El manejador de la senal: solo pone la bandera, que es lo unico que un manejador puede hacer con seguridad.  \~
void on_stop_signal(int) { g_stop = 1; }

/**
 * @brief
 * \~english Says what the chosen number of shards means on this system, when it is not simply "N shards".
 * \~spanish Dice que significa en este sistema el numero de fragmentos elegido, cuando no es simplemente "N fragmentos".
 * \~
 */
void say_what_shards_mean(const serve::Options &opt, uint32_t count) {
    if (count == 1) return;

#ifdef _WIN32
    std::fprintf(stderr,
                 "http_vx: %u shards: Windows cannot share a listening address; TCP is accepted on shard 0 only and "
                 "shards 1..%u wait idle until the acceptor that hands them sockets exists (--shards 1 serves the same)\n",
                 static_cast<unsigned>(count), static_cast<unsigned>(count - 1));
#else
    std::fprintf(stderr, "http_vx: %u shards, each with its own listening socket (SO_REUSEPORT)\n",
                 static_cast<unsigned>(count));
    serve::warn_if_no_migrate_req(stderr);
#endif

    if (opt.h3)
        std::fprintf(stderr,
                     "http_vx: HTTP/3: the UDP socket and its service live on shard 0 only for now; "
                     "its connection ids stay random\n");
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
     * Everything this server says goes to stderr, and it has to get there when
     * it is said.  Windows' C runtime buffers stderr when it is not a console,
     * so a server writing to a log file said nothing until it exited -- and a
     * server that is killed never exits.
     * \~spanish
     * Todo lo que dice este servidor va a stderr, y tiene que llegar cuando se
     * dice.  El runtime de C de Windows pone stderr en un buffer cuando no es una
     * consola, asi que un servidor que escribia a un fichero de registro no decia
     * nada hasta salir -- y a un servidor al que se mata no sale nunca.
     * \~ */
    std::setvbuf(stderr, nullptr, _IONBF, 0);

    serve::Options opt;
    serve::Reactors reactors;
    opt.parse(argc, argv);
    if (opt.help) {
        serve::print_usage(stdout, reactors);
        return 0;
    }
    if (opt.error != nullptr) {
        if (opt.culprit != nullptr)
            std::fprintf(stderr, "http_vx: %s: %s\n", opt.error, opt.culprit);
        else
            std::fprintf(stderr, "http_vx: %s\n", opt.error);
        serve::print_usage(stderr, reactors);
        return 1;
    }

    /* \~english
     * And WHICH backend, which is what R8 means by choosing it in
     * configuration.  A name this build does not have is not silently swapped
     * for one it does: it fails, and says which ones there are.
     * \~spanish
     * Y CUAL backend, que es lo que quiere decir la R8 con elegirlo en
     * configuracion.  Un nombre que esta construccion no tiene no se cambia en
     * silencio por uno que si: falla, y dice cuales hay.
     * \~ */
    const char *want = opt.backend != nullptr ? opt.backend : reactors.default_name();
    if (!reactors.has(want)) {
        std::fprintf(stderr, "http_vx: this build has no backend named %s; it has: ", want);
        reactors.print_names(stderr);
        std::fprintf(stderr, "\n");
        return 1;
    }

    // \~english Fixes the clock's start before any shard reads it.
    // \~spanish Fija el comienzo del reloj antes de que lo lea ningun fragmento.  \~
    (void)serve::now_ticks();

    serve::Events events;
    if (!events.start()) {
        std::fprintf(stderr, "http_vx: cannot start the event thread\n");
        return 1;
    }

    /* \~english
     * TLS is checked ONCE, here: the provider named, the certificate and the key
     * read.  Asked for and impossible is a server that does not start -- never
     * one that serves in the clear (R24) -- and it is found out before any
     * thread exists.  Each shard then loads its own copy (its memory is its
     * own), with the ticket key made here so that a ticket one shard issues is
     * opened by the next.
     * \~spanish
     * TLS se comprueba UNA vez, aqui: el proveedor nombrado, el certificado y la
     * clave leidos.  Pedido e imposible es un servidor que no arranca -- nunca
     * uno que sirve en claro (R24) -- y se averigua antes de que exista ningun
     * hilo.  Despues cada fragmento carga su propia copia (su memoria es suya),
     * con la clave de tickets hecha aqui para que un ticket que emite un
     * fragmento lo abra el siguiente.
     * \~ */
    serve::TlsSetup master;
    if (opt.cert != nullptr) {
        if (opt.provider != nullptr && !serve::TlsSetup::has(opt.provider)) {
            std::fprintf(stderr, "http_vx: this build has no provider named %s; it has: ", opt.provider);
            serve::TlsSetup::print_names(stderr);
            std::fprintf(stderr, "\n");
            return 1;
        }
        if (!master.load(opt.provider, opt.cert, opt.key)) {
            std::fprintf(stderr, "http_vx: cannot serve TLS: %s\n", master.why());
            return 1;
        }
        std::fprintf(stderr, "http_vx: TLS 1.3 with the %s provider, h2 and http/1.1 by ALPN, no 0-RTT\n",
                     master.crypto()->name());
    }

    const uint32_t count = opt.shards != 0 ? opt.shards : serve::usable_cpus();
    say_what_shards_mean(opt, count);

    serve::GroupPlan plan;
    plan.options = &opt;
    plan.backend = want;
    plan.count = count;
    plan.events = &events;
    plan.ticket_key = opt.cert != nullptr ? master.ticket_key() : nullptr;

    serve::ShardGroup group;
    if (!group.start(plan)) {
        std::fprintf(stderr, "http_vx: cannot listen on %s with %s: %s\n", serve::endpoint(opt.host, opt.port).text, want,
                     group.why());
        events.stop();
        return 1;
    }

    if (count == 1)
        std::fprintf(stderr, "http_vx: listening on %s, %s backend\n", serve::endpoint(opt.host, group.port()).text,
                     group.backend_name());
    else
        std::fprintf(stderr, "http_vx: listening on %s, %s backend, %u shards\n",
                     serve::endpoint(opt.host, group.port()).text, group.backend_name(), static_cast<unsigned>(count));

    // \~english The main thread has nothing left to serve: it waits to be told to stop.
    // \~spanish El hilo principal ya no tiene nada que servir: espera a que le digan que pare.  \~
    std::signal(SIGINT, on_stop_signal);
    std::signal(SIGTERM, on_stop_signal);
    while (g_stop == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    group.stop();
    events.stop();
    return 0;
}
