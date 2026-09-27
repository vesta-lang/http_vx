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
#include "http_vx/uring_backend.h"

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

using Sock = SOCKET;

constexpr Sock kNoSock = INVALID_SOCKET;

/// \~english Which backend a run is against.
/// \~spanish Contra que backend va una corrida.  \~
enum class Which { Iocp };

const char *which_name(Which) { return http_vx::IocpBackend::kName; }

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

using Sock = int;

constexpr Sock kNoSock = -1;

/**
 * \~english
 * Which backend a run is against -- and on Linux there are TWO, because R8
 * says io_uring and epoll are both first-class.  The point of naming them here
 * is that the same cases run against both: a second test file would be a
 * second set of cases, and the one that drifted would be the one on the kernel
 * nobody has.
 * \~spanish
 * Contra que backend va una corrida -- y en Linux hay DOS, porque la R8 dice que
 * io_uring y epoll son los dos de primera.  Nombrarlos aqui sirve para que los
 * mismos casos corran contra los dos: un segundo fichero de prueba serian dos
 * juegos de casos, y el que se quedara atras seria el del nucleo que no tiene
 * nadie.
 * \~
 */
enum class Which { Epoll, Uring };

const char *which_name(Which w) {
    return w == Which::Epoll ? http_vx::EpollBackend::kName : http_vx::UringBackend::kName;
}

void unmake(Sock s) { ::close(s); }

void dont_block(Sock s) {
    (void)s;
}

bool connecting(int r) { return r == 0 || errno == EINPROGRESS; }

void breathe() { usleep(1000); }

#endif

int failures = 0;

/**
 * \~english
 * Which backend the run in progress is against, so that a failure says so.
 * Without it a red on Linux would not tell epoll from io_uring, and the first
 * thing anybody would have to do is run it again twice to find out.
 * \~spanish
 * Contra que backend va la corrida en curso, para que un fallo lo diga.  Sin
 * esto, un rojo en Linux no distinguiria epoll de io_uring, y lo primero que
 * tendria que hacer cualquiera es volver a correrlo dos veces para averiguarlo.
 * \~
 */
const char *against = "?";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
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

    /* \~english
     * Every backend this system has, and only one of them started.  They are
     * held by value rather than made behind a pointer because what a test needs
     * from one is more than the interface offers -- binding a port and being
     * asked which port it got are not things a reactor does -- and a backend
     * that has not been reset holds nothing.
     * \~spanish
     * Todos los backends que tiene este sistema, y solo uno arrancado.  Se tienen
     * por valor y no se hacen detras de un puntero porque lo que una prueba
     * necesita de uno es mas de lo que ofrece la interfaz -- atarse a un puerto y
     * que le pregunten cual le toco no son cosas que haga un reactor -- y un
     * backend sin arrancar no tiene nada.
     * \~ */
#ifdef _WIN32
    http_vx::IocpBackend iocp;
#else
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
#endif

    http_vx::Backend *io = nullptr;
    uint16_t bound = 0;

    bool start(Which which) {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;

#ifdef _WIN32
        (void)which;
        if (!iocp.reset(shard.buffers(), 64)) return false;
        if (!iocp.listen("127.0.0.1", 0)) return false;
        bound = iocp.port();
        io = &iocp;
#else
        if (which == Which::Epoll) {
            /* \~english
             * The ceiling is on DESCRIPTORS for epoll and on ring entries for
             * io_uring, which is the difference between the two models showing
             * through: one remembers a note per socket, the other holds an
             * entry per operation the kernel is doing.
             * \~spanish
             * El techo es de DESCRIPTORES en epoll y de entradas del anillo en
             * io_uring, que es la diferencia entre los dos modelos asomando: uno
             * recuerda una nota por socket y el otro tiene una entrada por
             * operacion que este haciendo el nucleo.
             * \~ */
            if (!epoll.reset(shard.buffers(), 1024)) return false;
            if (!epoll.listen("127.0.0.1", 0)) return false;
            bound = epoll.port();
            io = &epoll;
        } else {
            if (!uring.reset(shard.buffers(), 256)) return false;
            if (!uring.listen("127.0.0.1", 0)) return false;
            bound = uring.port();
            io = &uring;
        }
#endif

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.idle_ticks = 1000;
        cfg.wheel_slots = 4096;
        cfg.accepts = 4;
        return shard.reset(cfg, *io, service, 0);
    }

    uint16_t port() const { return bound; }
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
void test_a_request_over_a_socket(Which which) {
    Server s;
    check(s.start(which), "the server would not start");
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
void test_a_finished_connection_closes_its_socket(Which which) {
    Server s;
    check(s.start(which), "the server would not start");

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
void test_two_requests_on_one_socket(Which which) {
    Server s;
    check(s.start(which), "the server would not start");

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
void test_four_sockets_at_once(Which which) {
    Server s;
    check(s.start(which), "the server would not start");

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
 * \~english A connection between requests holds no buffer, over a real socket.
 * \~spanish Una conexion entre peticiones no tiene buffer, por un socket de verdad.
 * \~
 *
 * \~english
 * R1, end to end and on a real port.  The connection is open, the client is
 * still there, the server will answer the moment it says something -- and the
 * pool is untouched.  That is the sentence the whole design is built around:
 * sixteen kilobytes times a million is sixteen gigabytes, and a server that
 * held one per open connection could not make the claim this project makes.
 *
 * It is worth having over a socket as well as in memory because the two halves
 * are asked with a real system call here: a receive of zero bytes on Windows,
 * a descriptor watched with nothing to write into on Linux.  What the memory
 * backend proves is that the LOOP does the right thing; what this proves is
 * that the right thing is a thing an operating system will actually do.
 *
 * \~spanish
 * La R1, de punta a punta y en un puerto de verdad.  La conexion esta abierta, el
 * cliente sigue ahi, el servidor contestara en cuanto diga algo -- y el pozo esta
 * intacto.  Esa es la frase alrededor de la que esta construido todo el diseno:
 * dieciseis kilobytes por un millon son dieciseis gigabytes, y un servidor que
 * tuviera uno por conexion abierta no podria hacer la afirmacion que hace este
 * proyecto.
 *
 * Merece tenerlo por un socket ademas de en memoria porque aqui las dos mitades
 * se piden con una llamada al sistema de verdad: una recepcion de cero bytes en
 * Windows, un descriptor vigilado sin nada donde escribir en Linux.  Lo que
 * demuestra el backend de memoria es que el BUCLE hace lo correcto; lo que
 * demuestra esto es que lo correcto es algo que un sistema operativo va a hacer.
 * \~
 */
void test_an_idle_socket_holds_no_buffer(Which which) {
    Server s;
    check(s.start(which), "the server would not start");

    Client c;
    check(c.open(s.port()), "the client could not connect");

    check(insist(s, c, "GET /idle HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the request never went out");
    check(pump(s, c, answered), "the answer never came back");

    /* \~english
     * A few more turns so the answer's own buffer comes back -- it is the
     * operating system's until the write completes, and giving it back before
     * then is the mistake the whole handle design exists to prevent.
     * \~spanish
     * Unas vueltas mas para que vuelva el buffer de la propia respuesta -- es del
     * sistema operativo hasta que acabe la escritura, y devolverlo antes es la
     * equivocacion que existe para evitar todo el diseno de las referencias.
     * \~ */
    for (int i = 0; i < 100; ++i) {
        s.shard.poll(1, 0);
        breathe();
    }

    check(s.shard.conns().count() == 1,
          "the connection did not stay open");
    check(s.shard.buffers().lent() == 0,
          "a connection waiting for its next request is holding a buffer");

    /* \~english
     * And it is still a connection: it answers the next one.
     * \~spanish
     * Y sigue siendo una conexion: contesta a la siguiente.
     * \~ */
    check(insist(s, c, "GET /again HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the second request never went out");
    check(pump(s, c, answered_twice),
          "a connection that held no buffer could not be served again");
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
void test_both_directions_at_once_over_a_socket(Which which) {
    Server s;
    s.handler.wordy = true;

    check(s.start(which), "the server would not start");

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

#ifndef _WIN32

/**
 * @brief
 * \~english Many operations, and far fewer trips into the kernel.
 * \~spanish Muchas operaciones, y muchisimos menos viajes al nucleo.
 * \~
 *
 * \~english
 * The claim io_uring exists for, counted instead of argued about.  Serving a
 * request takes three operations -- be told, read, write -- so four
 * connections served a few times over is dozens of them; if each one cost a
 * trip into the kernel this backend would be epoll with extra steps.
 *
 * It is a COUNT and not a time on purpose.  A count has no noise, it does not
 * depend on how fast the machine is or what else it was doing, and it fails
 * the same way on every run -- which is what the rest of the measurements in
 * this project do for the same reason.
 *
 * The bound is deliberately generous.  What it exists to catch is not a few
 * extra trips, it is the shape being wrong: a backend that entered the kernel
 * once per operation would blow past it by an order of magnitude, and one
 * that batched properly comes in far under.
 *
 * \~spanish
 * La afirmacion para la que existe io_uring, contada en vez de discutida.
 * Servir una peticion lleva tres operaciones -- que te avisen, leer, escribir --
 * asi que cuatro conexiones servidas unas cuantas veces son decenas de ellas; si
 * cada una costara un viaje al nucleo, este backend seria epoll con pasos de
 * mas.
 *
 * Es una CUENTA y no un tiempo a proposito.  Una cuenta no tiene ruido, no
 * depende de lo rapida que sea la maquina ni de que mas estuviera haciendo, y
 * falla igual en todas las corridas -- que es lo que hacen las demas medidas de
 * este proyecto por lo mismo.
 *
 * La cota es generosa a proposito.  Lo que existe para coger no son unos viajes
 * de mas, es que la forma este mal: un backend que entrara al nucleo una vez por
 * operacion se la pasaria por un orden de magnitud, y uno que agrupa bien se
 * queda muy por debajo.
 * \~
 */
void test_a_batch_costs_one_trip(Which which) {
    if (which != Which::Uring) return;

    Server s;
    check(s.start(which), "the server would not start");

    Client c[4];

    for (int i = 0; i < 4; ++i)
        check(c[i].open(s.port()), "a client could not connect");

    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 4; ++i)
            check(insist(s, c[i], "GET /batch HTTP/1.1\r\nHost: a\r\n\r\n"),
                  "a request never went out");

        /* \~english
         * Waited for by what the SERVER did, not by how many bytes the client
         * has.  The first version counted bytes against a threshold that the
         * previous round had already passed, so every round after the first
         * finished instantly and the last four requests were never served --
         * a test that hurried past the thing it was measuring.
         * \~spanish
         * Se espera por lo que hizo el SERVIDOR, no por cuantos bytes tiene el
         * cliente.  La primera version contaba bytes contra un umbral que la ronda
         * anterior ya habia pasado, asi que todas las rondas menos la primera
         * acababan en el acto y las ultimas cuatro peticiones no se servian nunca
         * -- una prueba corriendo por delante de lo que media.
         * \~ */
        const int want = (round + 1) * 4;

        for (int turn = 0; turn < 2000 && s.handler.calls < want; ++turn) {
            s.shard.poll(1, 0);
            for (int i = 0; i < 4; ++i) c[i].listen_once();
            breathe();
        }
    }

    check(s.handler.calls == 12, "the twelve requests were not all served");

    /* \~english
     * Twelve requests is at least thirty-six operations, plus the accepts.
     * Anything near that many trips would mean the ring is being entered per
     * operation, which is the one thing it is for not doing.
     * \~spanish
     * Doce peticiones son por lo menos treinta y seis operaciones, mas las
     * aceptaciones.  Cualquier numero de viajes cercano a ese querria decir que
     * se esta entrando al anillo por operacion, que es justo lo que existe para
     * no hacer.
     * \~ */
    /* \~english
     * And the number is PRINTED, not just checked.  It is the figure that
     * justifies this backend existing, so a run that merely said "ok" would be
     * hiding the evidence for its own conclusion -- and the day it creeps
     * towards the bound, seeing it drift is what tells anybody, long before
     * the bound is crossed.
     * \~spanish
     * Y el numero se IMPRIME, no solo se comprueba.  Es la cifra que justifica
     * que este backend exista, asi que una corrida que solo dijera "ok" estaria
     * escondiendo la prueba de su propia conclusion -- y el dia que empiece a
     * subir hacia la cota, verlo moverse es lo que avisa a alguien mucho antes
     * de que la cruce.
     * \~ */
    std::printf("     12 requests, >=36 operations, %zu trips into the kernel\n",
                s.uring.enters());

    check(s.uring.enters() < 36,
          "the ring is being entered about once per operation");
}

#endif

/**
 * @brief
 * \~english Runs every case against @p which.
 * \~spanish Corre todos los casos contra @p which.
 * \~
 *
 * \~english
 * One list, so that a backend cannot be the one with fewer cases.  That is the
 * whole of R8 made mechanical: what stops epoll from being a path nobody tests
 * is not a promise, it is that skipping it would mean deleting a line here.
 *
 * \~spanish
 * Una lista, para que un backend no pueda ser el que tiene menos casos.  Eso es
 * toda la R8 hecha mecanica: lo que impide que epoll sea un camino que no prueba
 * nadie no es una promesa, es que saltarselo seria borrar una linea de aqui.
 * \~
 */
void run_every_case(Which which) {
    against = which_name(which);
    std::printf("  -- %s --\n", against);

    test_a_request_over_a_socket(which);
    test_a_finished_connection_closes_its_socket(which);
    test_two_requests_on_one_socket(which);
    test_four_sockets_at_once(which);
    test_an_idle_socket_holds_no_buffer(which);
    test_both_directions_at_once_over_a_socket(which);

#ifndef _WIN32
    test_a_batch_costs_one_trip(which);
#endif
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

    run_every_case(Which::Iocp);

    WSACleanup();
#else
    run_every_case(Which::Epoll);

    /* \~english
     * And io_uring, if this kernel has one.  It is ASKED rather than deduced
     * from a version: a kernel can be built without it, a container can forbid
     * it with seccomp and an administrator can switch it off.
     *
     * A kernel without it SKIPS, and says so.  A skip that printed nothing
     * would be a suite that goes green on a machine where half the backends
     * never ran -- which is the failure R8 is about, arriving by the back
     * door.
     *
     * \~spanish
     * Y io_uring, si este nucleo tiene.  Se PREGUNTA en vez de deducirlo de una
     * version: un nucleo se puede construir sin el, un contenedor lo puede
     * prohibir con seccomp y un administrador lo puede apagar.
     *
     * Un nucleo sin el SALTA, y lo dice.  Un salto que no imprimiera nada seria
     * una suite que sale verde en una maquina donde la mitad de los backends no
     * corrio -- que es el fallo del que va la R8, entrando por la puerta de
     * atras.
     * \~ */
    if (http_vx::uring_available()) {
        run_every_case(Which::Uring);
    } else {
        std::printf("  -- io_uring: SKIPPED, this kernel gives no ring --\n");
    }
#endif

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
