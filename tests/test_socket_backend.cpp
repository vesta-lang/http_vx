/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_socket_backend.cpp
 * @brief
 * \~english The server answering over a real socket, on whichever system this is.
 * \~spanish El servidor contestando por un socket de verdad, en el sistema que sea.
 * \~
 *
 * \~english
 * Every other test in this project runs without a network on purpose, and that
 * is what made them worth writing: a bug driven by a real network happens once
 * every few thousand runs, in an order nobody chose.  This one is the opposite
 * and it is needed for exactly one reason -- **the things a memory backend
 * cannot be wrong about.**
 *
 * There is no socket in a memory backend, so nothing in it can leak one, refuse
 * to bind, or hand back a descriptor that belongs to somebody else.  A shard
 * that never closed a socket passed every test there was, because there was no
 * socket.
 *
 * **And it is one file for both systems, which is R8.**  That requirement is
 * about epoll not being a path nobody tests, and the way to make that true is
 * not to write a second test for it: it is for the SAME cases, the same
 * assertions and the same client to run against whichever backend this system
 * has.  Two test files would be two sets of cases, and the one that drifted
 * would be the one on the machine nobody builds on.
 *
 * What differs here is the four lines that name a socket type and the one that
 * makes the backend.  Everything below that -- the loop, the service, the
 * handler, what is checked -- is the same text on both.
 *
 * **The client is one thread on purpose.**  A client in a second thread would
 * put the ordering back in the hands of the scheduler, which is the property
 * this whole project gave up threads to avoid.  This one is a socket that does
 * not block, driven round the same loop as the server, so every run does the
 * same thing in the same order.
 *
 * \~spanish
 * Todas las demas pruebas de este proyecto corren sin red a proposito, y eso es
 * lo que hizo que merecieran la pena: un fallo movido por una red de verdad
 * ocurre una vez cada varios miles de corridas, en un orden que no eligio nadie.
 * Esta es lo contrario y hace falta por exactamente una razon -- **las cosas en
 * las que un backend de memoria no puede equivocarse.**
 *
 * En un backend de memoria no hay ningun socket, asi que nada de el puede
 * perder uno, negarse a atarse, ni devolver un descriptor que es de otro.  Un
 * fragmento que no cerrara ningun socket pasaba todas las pruebas que habia,
 * porque no habia ningun socket.
 *
 * **Y es un fichero para los dos sistemas, que es la R8.**  Ese requisito va de
 * que epoll no sea un camino que no prueba nadie, y la forma de que eso sea
 * cierto no es escribirle una segunda prueba: es que los MISMOS casos, las
 * mismas comprobaciones y el mismo cliente corran contra el backend que tenga
 * este sistema.  Dos ficheros de prueba serian dos juegos de casos, y el que se
 * quedara atras seria el de la maquina en la que no construye nadie.
 *
 * Lo que cambia aqui son las cuatro lineas que nombran un tipo de socket y la
 * que hace el backend.  Todo lo de debajo -- el bucle, el servicio, el
 * manejador, lo que se comprueba -- es el mismo texto en los dos.
 *
 * **El cliente es de un solo hilo a proposito.**  Uno en un segundo hilo
 * devolveria el orden a manos del planificador, que es justo la propiedad por la
 * que este proyecto renuncio a los hilos.  Este es un socket que no bloquea,
 * movido por el mismo bucle que el servidor, asi que todas las corridas hacen lo
 * mismo en el mismo orden.
 *
 * \~
 */

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <winsock2.h>

#include <ws2tcpip.h>

#include "http_vx/iocp_backend.h"

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "http_vx/epoll_backend.h"

#endif

#include "http_vx/http1_service.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::ConnHandle;
using http_vx::Handler;
using http_vx::Http1Service;
using http_vx::Request;
using http_vx::Shard;
using http_vx::ShardConfig;

/* ------------------------------------------------------------------------- *
 * \~english The part that names a system, and nothing below it does.
 * \~spanish La parte que nombra un sistema, y nada de lo de debajo lo hace.
 * \~
 * ------------------------------------------------------------------------- */

#ifdef _WIN32

using Backend = http_vx::IocpBackend;
using Sock = SOCKET;

constexpr Sock kNoSock = INVALID_SOCKET;

bool make_backend(Backend &io, http_vx::BufferPool &pool) {
    return io.reset(pool, 64);
}

void unmake(Sock s) { closesocket(s); }

void dont_block(Sock s) {
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
}

bool connecting(int r) {
    return r == 0 || WSAGetLastError() == WSAEWOULDBLOCK;
}

void breathe() { Sleep(1); }

#else

using Backend = http_vx::EpollBackend;
using Sock = int;

constexpr Sock kNoSock = -1;

/**
 * \~english
 * The ceiling is on descriptors here rather than on operations, which is what
 * readiness costs: there is nothing the kernel is holding to count, so what
 * gets counted is sockets.  A few hundred is far more than a test opens and is
 * what a shard of eight connections would ever reach.
 * \~spanish
 * Aqui el techo es de descriptores y no de operaciones, que es lo que cuesta la
 * disponibilidad: no hay nada que tenga el nucleo que contar, asi que lo que se
 * cuenta son sockets.  Unos cientos son mucho mas de lo que abre una prueba y es
 * a lo que llegaria un fragmento de ocho conexiones.
 * \~
 */
bool make_backend(Backend &io, http_vx::BufferPool &pool) {
    return io.reset(pool, 1024);
}

void unmake(Sock s) { ::close(s); }

void dont_block(Sock s) {
    (void)s;
}

bool connecting(int r) { return r == 0 || errno == EINPROGRESS; }

void breathe() { usleep(1000); }

#endif

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english The same handler as everywhere else, naming nothing about sockets.
 * \~spanish El mismo manejador que en todas partes, sin nombrar nada de sockets.
 * \~
 */
class Hello final : public Handler {
  public:
    void handle(const Request &req, const uint8_t *head, const uint8_t *body,
                size_t n, http_vx::ResponseBuilder &res) noexcept override {
        (void)body;
        (void)n;
        ++calls;

        if (req.target.len < sizeof last_target) {
            std::memcpy(last_target, head + req.target.off, req.target.len);
            last_target[req.target.len] = '\0';
        }

        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body("hello", 5);

        /* \~english
         * And, when asked, a great deal more.  The size is not decoration: it
         * has to be past what the two ends will hold between them without
         * anybody reading, or the write finishes at once and the case that
         * needs a write WAITING never happens.
         * \~spanish
         * Y, cuando se le pide, muchisimo mas.  El tamano no es adorno: tiene que
         * pasar de lo que se guarden los dos extremos entre los dos sin que lea
         * nadie, o la escritura acaba en el acto y el caso que necesita una
         * escritura ESPERANDO no ocurre nunca.
         * \~ */
        if (!wordy) return;

        char chunk[1024];
        std::memset(chunk, 'x', sizeof chunk);

        for (int i = 0; i < 8 * 1024; ++i) res.body(chunk, sizeof chunk);
    }

    int calls = 0;
    bool wordy = false;
    char last_target[256] = {};
};

/**
 * @brief
 * \~english A client that does not block, so it can share a thread with the server.
 * \~spanish Un cliente que no bloquea, para poder compartir hilo con el servidor.
 * \~
 */
struct Client {
    Sock sock = kNoSock;
    char got[4096] = {};
    size_t got_len = 0;
    bool ended = false;

    ~Client() { shut(); }

    void shut() {
        if (sock != kNoSock) {
            unmake(sock);
            sock = kNoSock;
        }
    }

    bool open(uint16_t port) {
#ifdef _WIN32
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
        sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
#endif
        if (sock == kNoSock) return false;

        dont_block(sock);

        sockaddr_in to;
        std::memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);

        /* \~english
         * A connect that does not block reports that it has not finished, and
         * that is the ordinary answer rather than a failure: the handshake
         * happens while the loop runs, which is the point of doing it this way.
         * \~spanish
         * Un connect que no bloquea dice que no ha terminado, y esa es la
         * respuesta corriente y no un fallo: el saludo ocurre mientras corre el
         * bucle, que es para lo que se hace asi.
         * \~ */
        const int r =
            connect(sock, reinterpret_cast<sockaddr *>(&to), sizeof to);
        return connecting(r);
    }

    /// \~english Tries to send @p s, and says whether all of it went.
    /// \~spanish Intenta mandar @p s, y dice si salio entero.  \~
    bool say(const char *s) {
        const int n = static_cast<int>(std::strlen(s));
        const int sent = static_cast<int>(send(sock, s, n, 0));
        return sent == n;
    }

    /// \~english Takes whatever has arrived.
    /// \~spanish Coge lo que haya llegado.  \~
    void listen_once() {
        if (ended) return;

        const int n = static_cast<int>(
            recv(sock, got + got_len, sizeof got - got_len - 1, 0));

        if (n > 0) {
            got_len += static_cast<size_t>(n);
            got[got_len] = '\0';
            return;
        }

        /* \~english
         * Zero is the server closing its end, which is a result and not a
         * failure -- and on one of these paths it is the result being checked.
         * \~spanish
         * Cero es el servidor cerrando su lado, que es un resultado y no un fallo
         * -- y en uno de estos caminos es el resultado que se comprueba.
         * \~ */
        if (n == 0) ended = true;
    }

    bool has(const char *what) const {
        return std::strstr(got, what) != nullptr;
    }
};

/**
 * @brief
 * \~english A server on a real port, with everything it is made of.
 * \~spanish Un servidor en un puerto de verdad, con todo de lo que esta hecho.
 * \~
 */
struct Server {
    Hello handler;
    Http1Service service;
    Shard shard;
    Backend io;

    bool start() {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;
        if (!make_backend(io, shard.buffers())) return false;
        if (!io.listen("127.0.0.1", 0)) return false;

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.idle_ticks = 1000;
        cfg.wheel_slots = 4096;
        cfg.accepts = 4;
        return shard.reset(cfg, io, service, 0);
    }

    uint16_t port() const { return io.port(); }
};

/**
 * @brief
 * \~english Runs the server and the client until @p want is true, or gives up.
 * \~spanish Corre el servidor y el cliente hasta que @p want, o se rinde.
 * \~
 *
 * \~english
 * Bounded, and the bound is what makes a failure a red rather than a test that
 * never finishes.  What is being waited for is a real network, so it takes as
 * many turns as it takes -- but a turn that never comes is a bug, and a bug has
 * to be able to say so.
 *
 * \~spanish
 * Acotado, y la cota es lo que hace que un fallo sea un rojo y no una prueba que
 * no termina nunca.  Lo que se espera es una red de verdad, asi que lleva las
 * vueltas que lleve -- pero una vuelta que no llega nunca es un fallo, y un
 * fallo tiene que poder decirlo.
 * \~
 */
bool pump(Server &s, Client &c, bool (*want)(const Client &)) {
    for (int i = 0; i < 2000; ++i) {
        s.shard.poll(1, 0);
        c.listen_once();

        if (want(c)) return true;

        breathe();
    }

    return false;
}

/// \~english Keeps trying to send until it goes, running the server meanwhile.
/// \~spanish Sigue intentando mandar hasta que salga, corriendo el servidor mientras.  \~
bool insist(Server &s, Client &c, const char *what) {
    for (int i = 0; i < 2000; ++i) {
        s.shard.poll(1, 0);
        if (c.say(what)) return true;
        breathe();
    }

    return false;
}

bool answered(const Client &c) { return c.has("hello"); }
bool hung_up(const Client &c) { return c.ended; }
bool answered_twice(const Client &c) {
    const char *first = std::strstr(c.got, "hello");
    return first != nullptr && std::strstr(first + 5, "hello") != nullptr;
}

/**
 * @brief
 * \~english A request sent over a socket is answered over the same socket.
 * \~spanish Una peticion mandada por un socket se contesta por el mismo socket.
 * \~
 *
 * \~english
 * The whole chain at once: a port that binds, an accept that produces a socket
 * the loop adopts, a read that lands in a pooled buffer, the parser, the
 * handler, the writer, and a send that goes back out.  Nothing here is standing
 * in for anything.
 *
 * \~spanish
 * La cadena entera de una vez: un puerto que se ata, una aceptacion que produce
 * un socket que adopta el bucle, una lectura que cae en un buffer del pozo, el
 * analizador, el manejador, el escritor, y un envio que vuelve a salir.  Aqui no
 * hay nada sustituyendo a nada.
 * \~
 */
void test_a_request_over_a_socket() {
    Server s;
    check(s.start(), "the server would not start");
    check(s.port() != 0, "no port was bound");

    Client c;
    check(c.open(s.port()), "the client could not connect");

    check(insist(s, c, "GET /over-a-socket HTTP/1.1\r\nHost: localhost\r\n\r\n"),
          "the request never went out");
    check(pump(s, c, answered), "the answer never came back");

    check(s.handler.calls == 1, "the handler was not called");
    check(std::strcmp(s.handler.last_target, "/over-a-socket") == 0,
          "the handler was given the wrong target");

    check(c.has("HTTP/1.1 200 OK\r\n"), "the status line is not right");
    check(c.has("content-type: text/plain\r\n"),
          "the field the handler wrote did not go out");
    check(c.has("content-length: 5\r\n"), "the response did not frame itself");
}

/**
 * @brief
 * \~english A connection that ends closes its socket.
 * \~spanish Una conexion que acaba cierra su socket.
 * \~
 *
 * \~english
 * The one a memory backend could never have caught, because a backend with no
 * operating system in it has no socket to leak.  The shard let go of the
 * connection -- slot, buffers, deadline, all of it -- and simply never asked
 * for the socket to be shut, and every test passed.  On a real port that is a
 * descriptor lost per connection served: a server that works perfectly and
 * stops accepting after some hours.
 *
 * What is checked is what a client can see, which is the only thing that
 * proves it: the peer reads zero, which is the server having closed its end.
 *
 * \~spanish
 * El que un backend de memoria no podria haber cogido nunca, porque uno sin
 * ningun sistema operativo dentro no tiene ningun socket que perder.  El
 * fragmento soltaba la conexion -- casilla, buffers, plazo, todo -- y
 * sencillamente no pedia nunca que se cerrara el socket, y todas las pruebas
 * pasaban.  En un puerto de verdad eso es un descriptor perdido por conexion
 * servida: un servidor que funciona perfectamente y deja de aceptar al cabo de
 * unas horas.
 *
 * Lo que se comprueba es lo que puede ver un cliente, que es lo unico que lo
 * demuestra: el otro extremo lee cero, que es el servidor habiendo cerrado su
 * lado.
 * \~
 */
void test_a_finished_connection_closes_its_socket() {
    Server s;
    check(s.start(), "the server would not start");

    Client c;
    check(c.open(s.port()), "the client could not connect");

    check(insist(s, c, "GET /bye HTTP/1.0\r\n\r\n"),
          "the request never went out");

    check(pump(s, c, answered), "the answer never came back");
    check(pump(s, c, hung_up), "the server never closed its end");
}

/**
 * @brief
 * \~english One socket serves more than one request.
 * \~spanish Un socket sirve mas de una peticion.
 * \~
 *
 * \~english
 * Which is what keep-alive is, and over a socket it exercises the thing the
 * buffer's stream position exists for: the connection gives its buffer back
 * between messages, and the next one it is lent has to carry on counting from
 * where the connection is rather than from zero.
 *
 * \~spanish
 * Que es lo que es keep-alive, y por un socket ejercita aquello para lo que
 * existe la posicion de flujo del buffer: la conexion devuelve su buffer entre
 * mensajes, y el siguiente que le presten tiene que seguir contando desde donde
 * va la conexion y no desde cero.
 * \~
 */
void test_two_requests_on_one_socket() {
    Server s;
    check(s.start(), "the server would not start");

    Client c;
    check(c.open(s.port()), "the client could not connect");

    check(insist(s, c, "GET /one HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the first request never went out");
    check(pump(s, c, answered), "the first answer never came back");

    check(insist(s, c, "GET /two HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the second request never went out");
    check(pump(s, c, answered_twice), "the second answer never came back");

    check(s.handler.calls == 2, "both requests were not served");
    check(std::strcmp(s.handler.last_target, "/two") == 0,
          "the second request was read as something else");
}

/**
 * @brief
 * \~english Several sockets at once are all served.
 * \~spanish Varios sockets a la vez se sirven todos.
 * \~
 *
 * \~english
 * Which is the difference between a server and a program that answers a
 * request.  It is also the case where a backend that kept ONE note per socket
 * instead of one per direction would show: four connections reading and
 * writing at the same time is four reads and four writes outstanding, and an
 * adaptation that lost any of them would leave a client waiting for ever with
 * nothing wrong on the wire.
 *
 * \~spanish
 * Que es la diferencia entre un servidor y un programa que contesta una
 * peticion.  Es ademas el caso donde se veria un backend que guardara UNA nota
 * por socket en vez de una por sentido: cuatro conexiones leyendo y escribiendo
 * a la vez son cuatro lecturas y cuatro escrituras pendientes, y una adaptacion
 * que perdiera cualquiera de ellas dejaria a un cliente esperando para siempre
 * sin que hubiera nada mal en el cable.
 * \~
 */
void test_four_sockets_at_once() {
    Server s;
    check(s.start(), "the server would not start");

    Client c[4];

    for (int i = 0; i < 4; ++i)
        check(c[i].open(s.port()), "a client could not connect");

    for (int i = 0; i < 4; ++i)
        check(insist(s, c[i], "GET /many HTTP/1.1\r\nHost: a\r\n\r\n"),
              "a request never went out");

    for (int round = 0; round < 2000; ++round) {
        s.shard.poll(1, 0);

        int done = 0;
        for (int i = 0; i < 4; ++i) {
            c[i].listen_once();
            if (answered(c[i])) ++done;
        }

        if (done == 4) break;
        breathe();
    }

    for (int i = 0; i < 4; ++i)
        check(answered(c[i]), "one of the four was never answered");

    check(s.handler.calls == 4, "the four requests were not all served");
}

/**
 * @brief
 * \~english A socket being read from while an answer is still going out.
 * \~spanish Un socket del que se lee mientras todavia sale una respuesta.
 * \~
 *
 * \~english
 * The ordinary state of a server under load, and the one the other cases here
 * cannot reach.  Over loopback with a short answer a write never has to wait:
 * it is taken whole the moment it is asked for, so the two directions are never
 * outstanding at the same time and a backend that could only remember ONE
 * operation per socket would pass every test in this file.
 *
 * It was not a guess.  The note-per-direction was written, the note-per-socket
 * mistake was injected into it, and the suite went on saying `ok` -- which is a
 * test agreeing with a bug because it never went that way.
 *
 * So this one makes the write wait: an answer far larger than the two ends will
 * hold between them, and a client that does not read a byte of it until it has
 * sent its NEXT request.  From there the connection has a read and a write in
 * the air at once, which is what the case is for.
 *
 * \~spanish
 * El estado corriente de un servidor con trabajo, y al que no llegan los otros
 * casos de aqui.  Por bucle local y con una respuesta corta, una escritura no
 * tiene que esperar nunca: se la llevan entera en cuanto se pide, asi que los dos
 * sentidos no estan pendientes nunca a la vez y un backend que solo pudiera
 * recordar UNA operacion por socket pasaria todas las pruebas de este fichero.
 *
 * No fue una conjetura.  Se escribio la nota por sentido, se le inyecto la
 * equivocacion de la nota por socket, y la suite siguio diciendo `ok` -- que es
 * una prueba dandole la razon a un fallo porque no paso nunca por ahi.
 *
 * Asi que esta hace esperar a la escritura: una respuesta mucho mayor de lo que
 * se guarden los dos extremos entre los dos, y un cliente que no lee ni un byte
 * de ella hasta haber mandado su peticion SIGUIENTE.  A partir de ahi la conexion
 * tiene una lectura y una escritura en el aire a la vez, que es para lo que esta
 * el caso.
 * \~
 */
void test_both_directions_at_once_over_a_socket() {
    Server s;
    s.handler.wordy = true;

    check(s.start(), "the server would not start");

    Client c;
    check(c.open(s.port()), "the client could not connect");

    check(insist(s, c, "GET /wordy HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the first request never went out");

    /* \~english
     * The server is run WITHOUT the client reading, which is what fills the
     * sockets and leaves the answer half out.
     * \~spanish
     * El servidor se corre SIN que el cliente lea, que es lo que llena los
     * sockets y deja la respuesta a medias.
     * \~ */
    for (int i = 0; i < 200; ++i) {
        s.shard.poll(1, 0);
        breathe();
    }

    check(s.handler.calls == 1, "the first request was not served");

    check(insist(s, c, "GET /second HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the second request never went out");

    /* \~english
     * And now both at once: the rest of the first answer going out while the
     * second request comes in.
     * \~spanish
     * Y ahora las dos a la vez: el resto de la primera respuesta saliendo
     * mientras entra la segunda peticion.
     * \~ */
    size_t want = 8u * 1024u * 1024u;
    size_t seen = 0;

    for (int i = 0; i < 20000 && seen < want; ++i) {
        s.shard.poll(1, 0);

        char sink[16384];
        const int n = static_cast<int>(recv(c.sock, sink, sizeof sink, 0));
        if (n > 0) seen += static_cast<size_t>(n);
        if (n == 0) break;
    }

    check(seen >= want, "the answer that had to wait never finished");
    check(s.handler.calls == 2,
          "the request that arrived mid-answer was never served");
}

} // namespace

int main() {
#ifdef _WIN32
    /* \~english
     * Winsock has to be started before a socket is named, and the backend does
     * it for itself -- but the CLIENT in this file is not the backend's, and a
     * test that relied on the server having gone first would be a test that
     * depends on the order of its own lines.
     * \~spanish
     * Winsock hay que arrancarlo antes de nombrar un socket, y el backend lo hace
     * por su cuenta -- pero el CLIENTE de este fichero no es del backend, y una
     * prueba que se fiara de que el servidor fue primero seria una prueba que
     * depende del orden de sus propias lineas.
     * \~ */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    test_a_request_over_a_socket();
    test_a_finished_connection_closes_its_socket();
    test_two_requests_on_one_socket();
    test_four_sockets_at_once();
    test_both_directions_at_once_over_a_socket();

#ifdef _WIN32
    WSACleanup();
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
