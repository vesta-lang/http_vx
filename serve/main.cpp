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

#include "http_vx/http1_service.h"
#include "http_vx/stdio_backend.h"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

/**
 * @brief
 * \~english Answers every request with what it asked for.
 * \~spanish Contesta cada peticion con lo que pidio.
 * \~
 *
 * \~english
 * Deliberately the smallest handler that is still a handler: it reads the
 * request, decides a status, writes fields and a body.  What it does NOT do is
 * reach for a socket, a buffer or a connection -- it cannot, because it is not
 * given any.
 *
 * \~spanish
 * A proposito el manejador mas pequeno que sigue siendo un manejador: lee la
 * peticion, decide un estado, escribe cabeceras y un cuerpo.  Lo que NO hace es
 * buscar un socket, un buffer ni una conexion -- no puede, porque no se le da
 * ninguno.
 *
 * \~
 */
class Greeting final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &req, const uint8_t *head,
                const uint8_t *body, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        (void)body;

        char text[512];
        const int len = std::snprintf(
            text, sizeof text,
            "you asked for %.*s and sent %zu bytes of body\n",
            static_cast<int>(req.target.len),
            reinterpret_cast<const char *>(head) + req.target.off, n);

        if (len <= 0) {
            res.status(500);
            return;
        }

        /* \~english
         * Nothing here names a version, and nothing here has to.  There is no
         * status line, no colon, no CRLF and no length: those are how HTTP/1.1
         * writes a status, a field and a body, and the same three things
         * written as HTTP/2 would be a header block and a DATA frame.  Which
         * one this becomes is decided by the service, downstream, and this
         * handler would not notice either way.
         *
         * The body goes through the response and not to the output, which is
         * the other thing this handler got wrong once: writing it itself put
         * it on the wire BEFORE the head, because the head goes out through
         * the loop, later, and two write paths have no ordering between them.
         *
         * \~spanish
         * Aqui no se nombra ninguna version, y no hace falta.  No hay linea de
         * estado, ni dos puntos, ni CRLF, ni longitud: eso es como escribe
         * HTTP/1.1 un estado, una cabecera y un cuerpo, y esas mismas tres cosas
         * escritas como HTTP/2 serian un bloque de cabeceras y una trama DATA.
         * En cual se convierte lo decide el servicio, mas abajo, y este
         * manejador no lo notaria de ninguna de las dos formas.
         *
         * El cuerpo pasa por la respuesta y no por la salida, que es la otra
         * cosa que este manejador hizo mal una vez: escribirlo el mismo lo ponia
         * en el cable ANTES que la cabeza, porque la cabeza sale por el bucle,
         * mas tarde, y dos caminos de escritura no tienen orden entre ellos.
         * \~ */
        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body(text, static_cast<size_t>(len));
    }
};

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
