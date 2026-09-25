/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_iocp_backend.cpp
 * @brief
 * \~english The first time this server answers over a socket.
 * \~spanish La primera vez que este servidor contesta por un socket.
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
 * to bind, or hand back a handle that belongs to a different completion port.
 * A shard that never closed a socket passed every test there was, because there
 * was no socket.  What runs here is the same loop, the same service and the
 * same handler as everywhere else; the only new thing is that the bytes come
 * from the operating system.
 *
 * **It is one thread on purpose.**  A client in a second thread would put the
 * ordering back in the hands of the scheduler, which is the property this whole
 * project gave up threads to avoid.  The client here is a socket that does not
 * block, driven round the same loop as the server, so every run does the same
 * thing in the same order.
 *
 * \~spanish
 * Todas las demas pruebas de este proyecto corren sin red a proposito, y eso es
 * lo que hizo que merecieran la pena: un fallo movido por una red de verdad
 * ocurre una vez cada varios miles de corridas, en un orden que no eligio nadie.
 * Esta es lo contrario y hace falta por exactamente una razon -- **las cosas en
 * las que un backend de memoria no puede equivocarse.**
 *
 * En un backend de memoria no hay ningun socket, asi que nada de el puede
 * perder uno, negarse a atarse, ni devolver una referencia que es de otro puerto
 * de finalizacion.  Un fragmento que no cerrara ningun socket pasaba todas las
 * pruebas que habia, porque no habia ningun socket.  Lo que corre aqui es el
 * mismo bucle, el mismo servicio y el mismo manejador que en todas partes; lo
 * unico nuevo es que los bytes vienen del sistema operativo.
 *
 * **Es de un solo hilo a proposito.**  Un cliente en un segundo hilo devolveria
 * el orden a manos del planificador, que es justo la propiedad por la que este
 * proyecto renuncio a los hilos.  El cliente de aqui es un socket que no
 * bloquea, movido por el mismo bucle que el servidor, asi que todas las corridas
 * hacen lo mismo en el mismo orden.
 *
 * \~
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <winsock2.h>

#include <ws2tcpip.h>

#include "http_vx/http1_service.h"
#include "http_vx/iocp_backend.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::ConnHandle;
using http_vx::Handler;
using http_vx::Http1Service;
using http_vx::IocpBackend;
using http_vx::Request;
using http_vx::Shard;
using http_vx::ShardConfig;

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
    }

    int calls = 0;
    char last_target[256] = {};
};

/**
 * @brief
 * \~english A client that does not block, so it can share a thread with the server.
 * \~spanish Un cliente que no bloquea, para poder compartir hilo con el servidor.
 * \~
 */
struct Client {
    SOCKET sock = INVALID_SOCKET;
    char got[4096] = {};
    size_t got_len = 0;
    bool ended = false;

    ~Client() { shut(); }

    void shut() {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }

    bool open(uint16_t port) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

        u_long on = 1;
        ioctlsocket(sock, FIONBIO, &on);

        sockaddr_in to;
        ZeroMemory(&to, sizeof to);
        to.sin_family = AF_INET;
        to.sin_port = htons(port);
        InetPtonA(AF_INET, "127.0.0.1", &to.sin_addr);

        /* \~english
         * A connect that does not block reports that it has not finished, and
         * that is the ordinary answer rather than a failure: the handshake
         * happens while the loop runs, which is the point of doing it this way.
         * \~spanish
         * Un connect que no bloquea dice que no ha terminado, y esa es la
         * respuesta corriente y no un fallo: el saludo ocurre mientras corre el
         * bucle, que es para lo que se hace asi.
         * \~ */
        if (connect(sock, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0)
            return true;

        return WSAGetLastError() == WSAEWOULDBLOCK;
    }

    /// \~english Tries to send @p s, and says whether all of it went.
    /// \~spanish Intenta mandar @p s, y dice si salio entero.  \~
    bool say(const char *s) {
        const int n = static_cast<int>(std::strlen(s));
        const int sent = send(sock, s, n, 0);
        return sent == n;
    }

    /// \~english Takes whatever has arrived.
    /// \~spanish Coge lo que haya llegado.  \~
    void listen_once() {
        if (ended) return;

        const int n = recv(sock, got + got_len,
                           static_cast<int>(sizeof got - got_len - 1), 0);

        if (n > 0) {
            got_len += static_cast<size_t>(n);
            got[got_len] = '\0';
            return;
        }

        /* \~english
         * Zero is the server closing its end, which is a result and not a
         * failure -- and on this path it is the result being checked.
         * \~spanish
         * Cero es el servidor cerrando su lado, que es un resultado y no un fallo
         * -- y en este camino es el resultado que se comprueba.
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
    IocpBackend io;

    bool start() {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;
        if (!io.reset(shard.buffers(), 64)) return false;
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

        Sleep(1);
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

    bool sent = false;
    for (int i = 0; i < 2000 && !sent; ++i) {
        s.shard.poll(1, 0);
        sent = c.say("GET /over-a-socket HTTP/1.1\r\nHost: localhost\r\n\r\n");
        if (!sent) Sleep(1);
    }
    check(sent, "the request never went out");

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

    bool sent = false;
    for (int i = 0; i < 2000 && !sent; ++i) {
        s.shard.poll(1, 0);
        sent = c.say("GET /bye HTTP/1.0\r\n\r\n");
        if (!sent) Sleep(1);
    }
    check(sent, "the request never went out");

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

    bool sent = false;
    for (int i = 0; i < 2000 && !sent; ++i) {
        s.shard.poll(1, 0);
        sent = c.say("GET /one HTTP/1.1\r\nHost: a\r\n\r\n");
        if (!sent) Sleep(1);
    }
    check(sent, "the first request never went out");
    check(pump(s, c, answered), "the first answer never came back");

    check(c.say("GET /two HTTP/1.1\r\nHost: a\r\n\r\n"),
          "the second request never went out");
    check(pump(s, c, answered_twice), "the second answer never came back");

    check(s.handler.calls == 2, "both requests were not served");
    check(std::strcmp(s.handler.last_target, "/two") == 0,
          "the second request was read as something else");
}

} // namespace

int main() {
    test_a_request_over_a_socket();
    test_a_finished_connection_closes_its_socket();
    test_two_requests_on_one_socket();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
