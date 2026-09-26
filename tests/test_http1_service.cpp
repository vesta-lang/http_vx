/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_http1_service.cpp
 * @brief
 * \~english A whole server: HTTP in one end, HTTP out the other, no socket.
 * \~spanish Un servidor entero: HTTP por un lado, HTTP por el otro, sin socket.
 * \~
 *
 * \~english
 * This is the one that says whether the cut was in the right place.  The
 * parsers were written and tested against arrays of bytes with no loop near
 * them; the loop was written and tested against a backend with no protocol
 * near it.  Here they are wired together for the first time, and what goes in
 * is what a client puts on a socket.
 *
 * The cases are the ones where the seam between the two would show: a request
 * that arrives in pieces (the loop has to keep what the parser did not use), a
 * connection that serves several (the parser has to be reset without the
 * connection being), two requests in one read (the service has to answer both
 * or one is lost), and a chunked body (what the message MEASURES and what it
 * MEANS are two different numbers, and consuming the wrong one desynchronises
 * the connection).
 *
 * \~spanish
 * Esta es la que dice si el corte estaba en el sitio correcto.  Los analizadores
 * se escribieron y se probaron contra arrays de bytes sin ningun bucle cerca; el
 * bucle se escribio y se probo contra un backend sin ningun protocolo cerca.
 * Aqui se juntan por primera vez, y lo que entra es lo que un cliente pone en un
 * socket.
 *
 * Los casos son aquellos donde se notaria la costura entre los dos: una peticion
 * que llega a trozos (el bucle tiene que guardar lo que el analizador no uso),
 * una conexion que sirve varias (el analizador hay que reiniciarlo sin reiniciar
 * la conexion), dos peticiones en una lectura (el servicio tiene que contestar
 * las dos o se pierde una), y un cuerpo por trozos (lo que MIDE el mensaje y lo
 * que SIGNIFICA son dos numeros distintos, y consumir el equivocado
 * desincroniza la conexion).
 *
 * \~
 */

#include "http_vx/http1_service.h"
#include "http_vx/memory_backend.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

using http_vx::Buffer;
using http_vx::ConnHandle;
using http_vx::Handler;
using http_vx::Http1Service;
using http_vx::MemoryBackend;
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
 * \~english A handler that says back what it was asked.
 * \~spanish Un manejador que dice lo que le preguntaron.
 * \~
 */
class Echo final : public Handler {
  public:
    void handle(const Request &req, const uint8_t *head, const uint8_t *body,
                size_t n, http_vx::ResponseBuilder &res) noexcept override {
        ++calls;
        last_body_size = n;

        if (n != 0 && n < sizeof last_body) {
            std::memcpy(last_body, body, n);
            last_body[n] = '\0';
        } else {
            last_body[0] = '\0';
        }

        if (req.target.len < sizeof last_target) {
            std::memcpy(last_target, head + req.target.off, req.target.len);
            last_target[req.target.len] = '\0';
        }

        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
    }

    int calls = 0;
    size_t last_body_size = 0;
    char last_body[256] = {};
    char last_target[256] = {};
};

/**
 * @brief
 * \~english A server made of all of it, with nothing standing in for anything.
 * \~spanish Un servidor hecho de todo ello, y sin nada que sustituya a nada.
 * \~
 */
struct Server {
    Echo handler;
    Http1Service service;
    Shard shard;
    MemoryBackend io;

    Server() : io(shard.buffers()) {}

    bool start() {
        http_vx::h1::Limits limits;
        if (!service.reset(8, handler, limits)) return false;

        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = 8;
        cfg.idle_ticks = 10;
        cfg.wheel_slots = 64;
        return shard.reset(cfg, io, service, 0);
    }

    /// \~english Sends @p s as a client would.
    /// \~spanish Manda @p s como lo haria un cliente.  \~
    void send(const char *s) {
        io.feed(reinterpret_cast<const uint8_t *>(s), std::strlen(s));
    }

    /// \~english Runs until nothing more happens.
    /// \~spanish Corre hasta que no pasa nada mas.  \~
    void run() {
        for (int i = 0; i < 64; ++i) shard.poll(1, 0);
    }

    /// \~english What went back to the client.
    /// \~spanish Lo que volvio al cliente.  \~
    const char *out() const {
        return reinterpret_cast<const char *>(io.written());
    }

    bool out_has(const char *what) const {
        const size_t n = io.written_size();
        const size_t m = std::strlen(what);
        if (m > n) return false;

        for (size_t i = 0; i + m <= n; ++i)
            if (std::memcmp(out() + i, what, m) == 0) return true;
        return false;
    }
};

/**
 * @brief
 * \~english One request in, one response out.
 * \~spanish Entra una peticion, sale una respuesta.
 * \~
 */
void test_a_request_is_answered() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n");
    s.run();

    check(s.handler.calls == 1, "the handler was not called");
    check(std::strcmp(s.handler.last_target, "/hello") == 0,
          "the handler was given the wrong target");
    check(s.service.served() == 1, "the service did not count the request");

    check(s.out_has("HTTP/1.1 200 OK\r\n"), "the status line is not right");
    check(s.out_has("content-type: text/plain\r\n"),
          "the field the handler wrote did not go out");
    check(s.out_has("content-length: 0\r\n"),
          "the response did not frame itself");
    check(s.out_has("\r\n\r\n"), "the head did not end");
}

/**
 * @brief
 * \~english A request that arrives in pieces is still one request.
 * \~spanish Una peticion que llega a trozos sigue siendo una peticion.
 * \~
 *
 * \~english
 * The seam.  The parser says it has not got a whole head and consumes
 * nothing; the loop has to keep what arrived in the same buffer so the rest
 * lands after it.  Either half of that being wrong makes every request that
 * crosses a packet boundary unanswerable -- which is most of the ones with
 * cookies in them.
 *
 * \~spanish
 * La costura.  El analizador dice que no tiene una cabeza entera y no consume
 * nada; el bucle tiene que guardar lo que llego en el mismo buffer para que el
 * resto caiga detras.  Que cualquiera de las dos mitades este mal hace que no se
 * pueda contestar a ninguna peticion que cruce una frontera de paquete -- que
 * son casi todas las que llevan cookies.
 *
 * \~
 */
void test_a_request_in_pieces() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("GET /split HT");
    s.run();
    check(s.handler.calls == 0, "half a request was answered");
    check(s.io.written_size() == 0, "half a request produced bytes");

    s.send("TP/1.1\r\nHost: ex");
    s.run();
    check(s.handler.calls == 0, "a request without its fields was answered");

    s.send("ample.com\r\n\r\n");
    s.run();

    check(s.handler.calls == 1, "the request was not put back together");
    check(std::strcmp(s.handler.last_target, "/split") == 0,
          "the target did not survive being split");
    check(s.out_has("HTTP/1.1 200 OK\r\n"), "no answer went out");
}

/**
 * @brief
 * \~english Two requests in one read are two answers.
 * \~spanish Dos peticiones en una lectura son dos respuestas.
 * \~
 *
 * \~english
 * A client may pipeline, and a read that brought two requests has to produce
 * two answers.  A service that handled one and stopped would leave a request
 * sitting in the buffer that nothing ever comes back for -- and the client
 * would wait for an answer that was already in the server's hands.
 *
 * \~spanish
 * Un cliente puede encadenar, y una lectura que trajo dos peticiones tiene que
 * producir dos respuestas.  Un servicio que atendiera una y parara dejaria una
 * peticion en el buffer a la que no vuelve nadie -- y el cliente esperaria una
 * respuesta que el servidor ya tenia en la mano.
 *
 * \~
 */
void test_two_requests_in_one_read() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("GET /one HTTP/1.1\r\nHost: a\r\n\r\n"
           "GET /two HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    check(s.handler.calls == 2, "both requests were not answered");
    check(std::strcmp(s.handler.last_target, "/two") == 0,
          "the second request was not the second one read");
    check(s.service.served() == 2, "the service did not count both");
}

/**
 * @brief
 * \~english A connection serves several requests in a row.
 * \~spanish Una conexion sirve varias peticiones seguidas.
 * \~
 *
 * \~english
 * Keep-alive, which is what makes the parser's state and the connection's
 * state two different things: the parser is reset between messages and the
 * connection is not.  A service that reset the wrong one would either lose the
 * connection after one request or read the second request through the first
 * one's parser.
 *
 * \~spanish
 * Mantener viva la conexion, que es lo que hace que el estado del analizador y
 * el de la conexion sean dos cosas distintas: el analizador se reinicia entre
 * mensajes y la conexion no.  Un servicio que reiniciara el equivocado o
 * perderia la conexion tras una peticion o leeria la segunda con el analizador
 * de la primera.
 *
 * \~
 */
void test_a_connection_serves_several() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    for (int i = 0; i < 5; ++i) {
        s.send("GET /again HTTP/1.1\r\nHost: a\r\n\r\n");
        s.run();
    }

    check(s.handler.calls == 5, "the connection did not serve five requests");
    check(s.shard.conns().alive(c),
          "the connection did not survive being reused");
}

/**
 * @brief
 * \~english A body is handed over whole, and only once it is whole.
 * \~spanish Un cuerpo se entrega entero, y solo cuando esta entero.
 * \~
 */
void test_a_body_arrives_whole() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("POST /put HTTP/1.1\r\nHost: a\r\ncontent-length: 11\r\n\r\nhello ");
    s.run();
    check(s.handler.calls == 0, "half a body was handed over");

    s.send("world");
    s.run();

    check(s.handler.calls == 1, "the body was not handed over");
    check(s.handler.last_body_size == 11, "the body is the wrong length");
    check(std::strcmp(s.handler.last_body, "hello world") == 0,
          "the body is not what was sent");
}

/**
 * @brief
 * \~english A chunked body is un-framed, and the connection stays in step.
 * \~spanish Un cuerpo por trozos se desentrama, y la conexion sigue acompasada.
 * \~
 *
 * \~english
 * Two things at once, and the second is the dangerous one.
 *
 * The body has to reach the handler as the bytes it MEANT, with the size lines
 * that carried it gone.  And the connection has to consume what the message
 * MEASURED -- which is a bigger number -- or the framing bytes stay in the
 * buffer and the next parse reads a chunk header as a request line.  That is
 * two ends disagreeing about where one message ended, which is request
 * smuggling: the test proves it did not happen by sending a second, ordinary
 * request behind it and checking it was read as itself.
 *
 * \~spanish
 * Dos cosas a la vez, y la segunda es la peligrosa.
 *
 * El cuerpo tiene que llegarle al manejador como los bytes que SIGNIFICABA, sin
 * las lineas de tamano que lo llevaban.  Y la conexion tiene que consumir lo que
 * el mensaje MIDIO -- que es un numero mayor -- o los bytes de troceado se
 * quedan en el buffer y el analisis siguiente lee una cabecera de trozo como una
 * linea de peticion.  Eso son dos extremos discrepando sobre donde acabo un
 * mensaje, que es el contrabando de peticiones: la prueba demuestra que no pasa
 * mandando detras una segunda peticion corriente y comprobando que se leyo como
 * ella misma.
 *
 * \~
 */
void test_a_chunked_body_is_unframed() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("POST /chunks HTTP/1.1\r\n"
           "Host: a\r\n"
           "transfer-encoding: chunked\r\n"
           "\r\n"
           "5\r\nhello\r\n"
           "1\r\n \r\n"
           "5\r\nworld\r\n"
           "0\r\n\r\n");
    s.run();

    check(s.handler.calls == 1, "the chunked request was not answered");
    check(s.handler.last_body_size == 11,
          "the body is not the length it decoded to");
    check(std::strcmp(s.handler.last_body, "hello world") == 0,
          "the body still has its framing in it");

    /* \~english
     * And the connection is still in step: an ordinary request behind it is
     * read as an ordinary request.  If the chunked message had been consumed
     * by what it meant instead of what it measured, this would be read
     * starting from somewhere in the middle of the last chunk's framing.
     * \~spanish
     * Y la conexion sigue acompasada: una peticion corriente detras se lee como
     * una peticion corriente.  Si el mensaje por trozos se hubiera consumido por
     * lo que significaba en vez de por lo que midio, esta se leeria empezando
     * en algun punto del troceado del ultimo pedazo.
     * \~ */
    s.send("GET /after HTTP/1.1\r\nHost: a\r\n\r\n");
    s.run();

    check(s.handler.calls == 2, "the request after the chunked one was lost");
    check(std::strcmp(s.handler.last_target, "/after") == 0,
          "the connection was left out of step by the chunked body");
}

/**
 * @brief
 * \~english A message framed two ways at once is refused and answered.
 * \~spanish Un mensaje troceado de dos formas a la vez se rechaza y se contesta.
 * \~
 *
 * \~english
 * Content-Length and Transfer-Encoding together is the classic way to make two
 * implementations disagree about where a message ends.  It is refused rather
 * than guessed at -- and it is ANSWERED before the connection goes, because a
 * client whose socket simply dies cannot tell a bad request from a server that
 * fell over, so it retries, and a request refused every time becomes a request
 * sent every time.
 *
 * \~spanish
 * Content-Length y Transfer-Encoding juntos es la forma clasica de hacer que dos
 * implementaciones discrepen sobre donde acaba un mensaje.  Se rechaza en vez de
 * adivinarlo -- y se CONTESTA antes de que la conexion se vaya, porque un
 * cliente cuyo socket se muere sin mas no puede distinguir una peticion mala de
 * un servidor caido, asi que reintenta, y una peticion rechazada siempre se
 * convierte en una peticion mandada siempre.
 *
 * \~
 */
void test_a_smuggled_message_is_refused() {
    Server s;
    check(s.start(), "the server would not start");

    const ConnHandle c = s.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    s.send("POST /x HTTP/1.1\r\n"
           "Host: a\r\n"
           "content-length: 5\r\n"
           "transfer-encoding: chunked\r\n"
           "\r\n"
           "0\r\n\r\n");
    s.run();

    check(s.handler.calls == 0, "a message framed two ways was handed over");
    check(s.out_has("HTTP/1.1 400 Bad Request\r\n"),
          "the refusal was not answered");
    check(!s.shard.conns().alive(c),
          "the connection carried on after a framing refusal");
}

} // namespace

/**
 * @brief
 * \~english The version and the Connection field decide whether the connection goes on (RFC 9112, 9.3, 9.6).
 * \~spanish La version y la cabecera Connection deciden si la conexion sigue (RFC 9112, 9.3, 9.6).
 * \~
 *
 * \~english
 * Each case sends a second request behind the first: when the first said
 * "close", the server MUST NOT process the second -- the client promised
 * not to send it, and anything that follows is not its to answer.
 * \~spanish
 * Cada caso manda una segunda peticion detras de la primera: cuando la
 * primera dijo "close", el servidor NO DEBE procesar la segunda -- el cliente
 * prometio no mandarla, y lo que venga detras no le toca contestarlo.
 * \~
 */
void test_the_connection_options() {
    struct Case {
        const char *head;
        bool persists;
        const char *said;
        const char *what;
    };
    const Case cases[] = {
        {"GET /c HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", false, "onnection: close",
         "HTTP/1.1 with close: the connection ends after the answer"},
        {"GET /c HTTP/1.1\r\nHost: a\r\nConnection: Keep-Alive, CLOSE\r\n\r\n", false, "onnection: close",
         "close in any case, anywhere in the list"},
        {"GET /c HTTP/1.1\r\nHost: a\r\nConnection: foo\r\nConnection: , ,close\r\n\r\n", false, "onnection: close",
         "close in a second Connection field, after empty elements"},
        {"GET /c HTTP/1.1\r\nHost: a\r\nConnection: closed\r\n\r\n", true, "HTTP/1.1 200",
         "an option that only starts like close is another option"},
        {"GET /c HTTP/1.1\r\nHost: a\r\n\r\n", true, "HTTP/1.1 200", "HTTP/1.1 alone persists"},
        {"GET /c HTTP/1.0\r\nHost: a\r\n\r\n", false, "onnection: close", "HTTP/1.0 alone does not persist"},
        {"GET /c HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n", true, "onnection: keep-alive",
         "HTTP/1.0 with keep-alive persists, and says so"},
        {"GET /c HTTP/1.0\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n", false, "onnection: close",
         "close wins over keep-alive"},
    };
    for (const Case &k : cases) {
        Server s;
        check(s.start(), "the server would not start");
        const ConnHandle c = s.shard.adopt(7, 0);
        std::string both = std::string(k.head) + "GET /after HTTP/1.1\r\nHost: a\r\n\r\n";
        s.send(both.c_str());
        s.run();
        if (s.shard.conns().alive(c) != k.persists || s.handler.calls != (k.persists ? 2 : 1) || !s.out_has(k.said)) {
            std::fprintf(stderr, "FAIL: %s (alive %d, calls %d)\n", k.what, static_cast<int>(s.shard.conns().alive(c)),
                         s.handler.calls);
            ++failures;
        }
    }
}

int main() {
    test_the_connection_options();
    test_a_request_is_answered();
    test_a_request_in_pieces();
    test_two_requests_in_one_read();
    test_a_connection_serves_several();
    test_a_body_arrives_whole();
    test_a_chunked_body_is_unframed();
    test_a_smuggled_message_is_refused();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
