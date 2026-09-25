/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_stdio_backend.cpp
 * @brief
 * \~english The whole server over descriptors, which is a transport and not a socket.
 * \~spanish El servidor entero sobre descriptores, que es un transporte y no un socket.
 * \~
 *
 * \~english
 * The SECOND backend, and that is what this is for.  An interface with one
 * implementation might be the shape of that implementation; this one is what
 * says whether @c Backend describes what a shard needs from an operating
 * system, or only what the in-memory one happened to do.
 *
 * What is being exercised is everything at once -- the parser, the framing,
 * the writer, the connection table, the buffer pool, the deadlines, the loop
 * -- over a transport that reads and writes real file descriptors.  HTTP over
 * a pipe is not a rehearsal for HTTP over a socket: it is how the Docker
 * daemon is spoken to and how gRPC runs between containers.
 *
 * The bytes are written here in C++ rather than kept in a file, and that is
 * not fussiness: HTTP's line endings are part of the protocol, and a fixture
 * in the repository is a file whose CRLFs git may rewrite when it is cloned.
 * A test that passed or failed depending on where the code was downloaded from
 * would be the worst kind.
 *
 * \~spanish
 * El SEGUNDO backend, y para eso esta.  Una interfaz con una sola
 * implementacion puede ser la forma de esa implementacion; esta es la que dice
 * si @c Backend describe lo que necesita un fragmento de un sistema operativo, o
 * solo lo que resulto que hacia el de memoria.
 *
 * Lo que se ejercita es todo a la vez -- el analizador, el troceado, el
 * escritor, la tabla de conexiones, el pozo de buffers, los plazos, el bucle --
 * sobre un transporte que lee y escribe descriptores de verdad.  HTTP por una
 * tuberia no es un ensayo de HTTP por un socket: es como se le habla al demonio
 * de Docker y como corre gRPC entre contenedores.
 *
 * Los bytes se escriben aqui en C++ y no se guardan en un fichero, y no es
 * remilgo: los finales de linea de HTTP son parte del protocolo, y un fichero de
 * apoyo en el repositorio es un fichero al que git le puede reescribir los CRLF
 * al clonar.  Una prueba que pasara o fallara segun de donde se bajo el codigo
 * seria de la peor clase.
 *
 * \~
 */

#include "http_vx/http1_service.h"
#include "http_vx/stdio_backend.h"

#include <cstdio>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#define HTTP_VX_OPEN_READ(p) _open(p, _O_RDONLY | _O_BINARY)
#define HTTP_VX_OPEN_WRITE(p) _open(p, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, 0600)
#define HTTP_VX_CLOSE _close
#define HTTP_VX_PIPE(fds) _pipe(fds, 65536, _O_BINARY)
#define HTTP_VX_READ _read
#define HTTP_VX_WRITE _write
#else
#include <fcntl.h>
#include <unistd.h>
#define HTTP_VX_OPEN_READ(p) ::open(p, O_RDONLY)
#define HTTP_VX_OPEN_WRITE(p) ::open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600)
#define HTTP_VX_CLOSE ::close
#define HTTP_VX_PIPE(fds) ::pipe(fds)
#define HTTP_VX_READ ::read
#define HTTP_VX_WRITE ::write
#endif

namespace {

using http_vx::ConnHandle;
using http_vx::Shard;
using http_vx::ShardConfig;
using http_vx::StdioBackend;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Answers with the target it was asked for.
 * \~spanish Contesta con el destino que le pidieron.
 * \~
 */
class Greeting final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &req, const uint8_t *head,
                const uint8_t *body, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        (void)body;
        ++calls;

        char text[256];
        const int len = std::snprintf(
            text, sizeof text, "saw %.*s with %zu\n",
            static_cast<int>(req.target.len),
            reinterpret_cast<const char *>(head) + req.target.off, n);

        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body(text, static_cast<size_t>(len));
    }

    int calls = 0;
};

/**
 * @brief
 * \~english Writes @p bytes to @p path, exactly.
 * \~spanish Escribe @p bytes en @p path, exactamente.
 * \~
 */
bool put_file(const char *path, const char *bytes) {
    std::FILE *f = std::fopen(path, "wb");
    if (f == nullptr) return false;

    const size_t n = std::strlen(bytes);
    const bool ok = std::fwrite(bytes, 1, n, f) == n;
    std::fclose(f);
    return ok;
}

/**
 * @brief
 * \~english Reads @p path into @p out.
 * \~spanish Lee @p path en @p out.
 * \~
 */
size_t get_file(const char *path, char *out, size_t cap) {
    std::FILE *f = std::fopen(path, "rb");
    if (f == nullptr) return 0;

    const size_t n = std::fread(out, 1, cap - 1, f);
    std::fclose(f);
    out[n] = '\0';
    return n;
}

/**
 * @brief
 * \~english Serves @p request over descriptors and returns what came back.
 * \~spanish Sirve @p request sobre descriptores y devuelve lo que volvio.
 * \~
 *
 * \~english
 * The same server the runnable binary is, assembled the same way.  Files
 * rather than a pipe because a pipe needs a second process and files do not,
 * and the backend cannot tell the difference -- which is itself worth knowing.
 *
 * \~spanish
 * El mismo servidor que es el binario ejecutable, montado igual.  Ficheros en
 * vez de una tuberia porque una tuberia necesita un segundo proceso y los
 * ficheros no, y el backend no nota la diferencia -- que ya es algo que merece
 * saberse.
 *
 * \~
 */
size_t serve(const char *request, char *answer, size_t cap, int *calls) {
    const char *in_path = "test_stdio_in.tmp";
    const char *out_path = "test_stdio_out.tmp";

    if (!put_file(in_path, request)) return 0;

    const int in_fd = HTTP_VX_OPEN_READ(in_path);
    const int out_fd = HTTP_VX_OPEN_WRITE(out_path);
    if (in_fd < 0 || out_fd < 0) return 0;

    {
        Greeting greeting;
        http_vx::Http1Service service;
        Shard shard;

        http_vx::h1::Limits h1;
        service.reset(4, greeting, h1);

        StdioBackend io(shard.buffers(), in_fd, out_fd);

        ShardConfig cfg;
        cfg.connections = 4;
        cfg.buffers = 4;
        cfg.idle_ticks = 30;
        cfg.wheel_slots = 64;
        shard.reset(cfg, io, service, 0);

        const ConnHandle c = shard.adopt(in_fd, 0);

        while (shard.conns().alive(c)) {
            if (shard.poll(0, -1) == 0) break;
        }

        if (calls != nullptr) *calls = greeting.calls;

        shard.release();
        service.release();
    }

    HTTP_VX_CLOSE(in_fd);
    HTTP_VX_CLOSE(out_fd);

    return get_file(out_path, answer, cap);
}

bool has(const char *haystack, const char *needle) {
    return std::strstr(haystack, needle) != nullptr;
}

/**
 * @brief
 * \~english A request over a descriptor is answered over a descriptor.
 * \~spanish Una peticion por un descriptor se contesta por un descriptor.
 * \~
 */
void test_a_request_over_descriptors() {
    char answer[4096];
    int calls = 0;

    const size_t n =
        serve("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n", answer,
              sizeof answer, &calls);

    check(n != 0, "nothing came back");
    check(calls == 1, "the handler was not called");
    check(has(answer, "HTTP/1.1 200 OK\r\n"), "the status line is not right");
    check(has(answer, "content-type: text/plain\r\n"),
          "the field the handler wrote did not go out");
    check(has(answer, "saw /hello with 0"), "the body is not the answer");

    /* \~english
     * And in ORDER.  The head before the body is not a detail: the other way
     * round is not a response at all, and it is exactly what the example
     * handler did when it wrote its body down a second path instead of through
     * the writer.
     * \~spanish
     * Y en ORDEN.  La cabeza antes que el cuerpo no es un detalle: al reves no
     * es una respuesta, y es justo lo que hacia el manejador de ejemplo cuando
     * escribia su cuerpo por un segundo camino en vez de por el escritor.
     * \~ */
    const char *head = std::strstr(answer, "HTTP/1.1 200 OK");
    const char *body = std::strstr(answer, "saw /hello");
    check(head != nullptr && body != nullptr && head < body,
          "the body came out before the head");
}

/**
 * @brief
 * \~english One descriptor serves several requests.
 * \~spanish Un descriptor sirve varias peticiones.
 * \~
 */
void test_several_over_one_descriptor() {
    char answer[8192];
    int calls = 0;

    const size_t n = serve("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                           "GET /bb HTTP/1.1\r\nHost: x\r\n\r\n"
                           "GET /ccc HTTP/1.1\r\nHost: x\r\n\r\n",
                           answer, sizeof answer, &calls);

    check(n != 0, "nothing came back");
    check(calls == 3, "the three requests were not all answered");
    check(has(answer, "saw /a with 0"), "the first answer is missing");
    check(has(answer, "saw /bb with 0"), "the second answer is missing");
    check(has(answer, "saw /ccc with 0"), "the third answer is missing");

    /* \~english
     * And in the order they were asked, which is the one thing a connection
     * carrying several messages has to get right.
     * \~spanish
     * Y en el orden en que se pidieron, que es lo unico que tiene que acertar
     * una conexion que lleva varios mensajes.
     * \~ */
    const char *a = std::strstr(answer, "saw /a with");
    const char *b = std::strstr(answer, "saw /bb with");
    const char *c = std::strstr(answer, "saw /ccc with");
    check(a < b && b < c, "the answers came back out of order");
}

/**
 * @brief
 * \~english A body arrives over a descriptor like anything else.
 * \~spanish Un cuerpo llega por un descriptor como cualquier otra cosa.
 * \~
 */
void test_a_body_over_descriptors() {
    char answer[4096];
    int calls = 0;

    serve("POST /put HTTP/1.1\r\nHost: x\r\ncontent-length: 11\r\n\r\n"
          "hello world",
          answer, sizeof answer, &calls);

    check(calls == 1, "the request with a body was not answered");
    check(has(answer, "saw /put with 11"), "the body length did not arrive");
}

/**
 * @brief
 * \~english A chunked body is un-framed over a descriptor too.
 * \~spanish Un cuerpo por trozos tambien se desentrama por un descriptor.
 * \~
 *
 * \~english
 * The same case the in-memory backend covers, run again over a different
 * transport.  It is not repetition: what it says is that the un-framing and
 * the consuming are the protocol's and not the backend's, which is only
 * provable by changing the backend.
 *
 * \~spanish
 * El mismo caso que cubre el backend de memoria, corrido otra vez sobre otro
 * transporte.  No es repeticion: lo que dice es que el desentramado y el consumo
 * son del protocolo y no del backend, que solo se puede demostrar cambiando el
 * backend.
 *
 * \~
 */
void test_chunked_over_descriptors() {
    char answer[4096];
    int calls = 0;

    serve("POST /c HTTP/1.1\r\nHost: x\r\ntransfer-encoding: chunked\r\n\r\n"
          "5\r\nhello\r\n"
          "6\r\n world\r\n"
          "0\r\n\r\n"
          "GET /after HTTP/1.1\r\nHost: x\r\n\r\n",
          answer, sizeof answer, &calls);

    check(calls == 2, "the request after the chunked one was lost");
    check(has(answer, "saw /c with 11"), "the chunked body was not un-framed");
    check(has(answer, "saw /after with 0"),
          "the connection was left out of step by the chunked body");
}

/**
 * @brief
 * \~english A refusal is answered before the connection goes.
 * \~spanish Un rechazo se contesta antes de que se vaya la conexion.
 * \~
 */
void test_a_refusal_over_descriptors() {
    char answer[4096];
    int calls = 0;

    serve("POST /x HTTP/1.1\r\nHost: x\r\n"
          "content-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
          answer, sizeof answer, &calls);

    check(calls == 0, "a message framed two ways was handed over");
    check(has(answer, "HTTP/1.1 400 Bad Request\r\n"),
          "the refusal did not reach the client");
}

/**
 * @brief
 * \~english An answer goes out while the peer is still holding the pipe open.
 * \~spanish Una respuesta sale mientras el otro extremo tiene la tuberia abierta.
 * \~
 *
 * \~english
 * The one case files cannot show, and the reason the backend finishes WRITES
 * before reads.
 *
 * On a file a read never waits: at the end it returns zero and the loop gets
 * on with things, so the order the two are finished in makes no difference.
 * On a pipe it makes all of it.  A peer that has sent a request and is waiting
 * for the answer has not closed anything, so a read on it BLOCKS -- and a
 * backend that finished the read first would sit in that read holding an
 * answer that is written and ready, while the peer sits waiting for exactly
 * that answer before it says anything else.  Both ends waiting for each other
 * is a deadlock, and it would be one the backend invented.
 *
 * So this test is a real peer in a real thread on a real pipe, and it does
 * what a peer does: it writes, and then it waits.  With the ordering right it
 * finishes in microseconds; with the ordering wrong nothing happens at all,
 * which is why the test is registered with a timeout -- a test that hangs
 * has still told you something, as long as somebody is counting.
 *
 * \~spanish
 * El unico caso que no pueden ensenar los ficheros, y la razon de que el backend
 * acabe las ESCRITURAS antes que las lecturas.
 *
 * En un fichero una lectura no espera nunca: al final devuelve cero y el bucle
 * sigue, asi que el orden en que se acaben las dos da igual.  En una tuberia lo
 * es todo.  Un extremo que ha mandado una peticion y espera la respuesta no ha
 * cerrado nada, asi que una lectura sobre el BLOQUEA -- y un backend que acabara
 * la lectura primero se quedaria dentro de ella guardando una respuesta escrita
 * y lista, mientras el otro extremo espera justo esa respuesta antes de decir
 * nada mas.  Los dos extremos esperandose es un abrazo mortal, y seria uno que
 * se invento el backend.
 *
 * Asi que esta prueba es un extremo de verdad en un hilo de verdad sobre una
 * tuberia de verdad, y hace lo que hace un extremo: escribe, y luego espera.
 * Con el orden bien acaba en microsegundos; con el orden mal no pasa nada, que
 * es la razon de que la prueba este registrada con un plazo -- una prueba que se
 * cuelga ha dicho algo igual, mientras alguien lleve la cuenta.
 *
 * \~
 */
void test_an_answer_goes_out_while_the_peer_waits() {
    int to_server[2];
    int to_client[2];

    if (HTTP_VX_PIPE(to_server) != 0 || HTTP_VX_PIPE(to_client) != 0) {
        check(false, "the pipes could not be made");
        return;
    }

    Greeting greeting;
    http_vx::Http1Service service;
    Shard shard;

    http_vx::h1::Limits h1;
    service.reset(4, greeting, h1);

    StdioBackend io(shard.buffers(), to_server[0], to_client[1]);

    ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 4;
    cfg.idle_ticks = 30;
    cfg.wheel_slots = 64;
    shard.reset(cfg, io, service, 0);

    char got[1024] = {};

    /* \~english
     * The peer: writes a request, keeps its end open -- which is what makes
     * the server's next read block -- and waits for the answer.  Only when it
     * has one does it close, which is what lets the server finish.
     * \~spanish
     * El otro extremo: escribe una peticion, deja su lado abierto -- que es lo
     * que hace que bloquee la lectura siguiente del servidor -- y espera la
     * respuesta.  Solo cuando la tiene cierra, que es lo que deja acabar al
     * servidor.
     * \~ */
    std::thread peer([&] {
        const char *req = "GET /waiting HTTP/1.1\r\nHost: x\r\n\r\n";
        HTTP_VX_WRITE(to_server[1], req, static_cast<unsigned>(std::strlen(req)));

        size_t have = 0;
        while (have + 1 < sizeof got) {
            const auto n = HTTP_VX_READ(to_client[0], got + have,
                                        static_cast<unsigned>(sizeof got - 1 - have));
            if (n <= 0) break;
            have += static_cast<size_t>(n);

            if (std::strstr(got, "saw /waiting") != nullptr) break;
        }

        HTTP_VX_CLOSE(to_server[1]);
    });

    const ConnHandle c = shard.adopt(to_server[0], 0);
    while (shard.conns().alive(c)) {
        if (shard.poll(0, -1) == 0) break;
    }

    peer.join();

    shard.release();
    service.release();

    HTTP_VX_CLOSE(to_server[0]);
    HTTP_VX_CLOSE(to_client[0]);
    HTTP_VX_CLOSE(to_client[1]);

    check(greeting.calls == 1, "the request over the pipe was not answered");
    check(has(got, "HTTP/1.1 200 OK\r\n"),
          "the peer did not get a status line");
    check(has(got, "saw /waiting with 0"),
          "the peer did not get the answer while it was still waiting");
}

} // namespace

int main() {
    test_an_answer_goes_out_while_the_peer_waits();
    test_a_request_over_descriptors();
    test_several_over_one_descriptor();
    test_a_body_over_descriptors();
    test_chunked_over_descriptors();
    test_a_refusal_over_descriptors();

    std::remove("test_stdio_in.tmp");
    std::remove("test_stdio_out.tmp");

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
