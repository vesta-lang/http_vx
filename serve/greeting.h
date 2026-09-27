/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/greeting.h
 * @brief
 * \~english The handler both servers answer with, and the reason it is one file.
 * \~spanish El manejador con el que contestan los dos servidores, y por que es un fichero.
 * \~
 *
 * \~english
 * There are two programs in this directory: one that speaks HTTP down a pipe
 * and one that speaks it on a socket.  They share this, and sharing it is the
 * point rather than a saving: the claim the project makes is that a handler
 * does not know what is underneath it, and two copies of a handler would let
 * that claim be false in one of them without anybody noticing.
 *
 * What it does NOT reach for is a socket, a buffer or a connection.  It cannot,
 * because it is not given any.
 *
 * \~spanish
 * En este directorio hay dos programas: uno que habla HTTP por una tuberia y
 * otro que lo habla por un socket.  Comparten esto, y compartirlo es lo que
 * importa y no el ahorro: la afirmacion que hace el proyecto es que un manejador
 * no sabe lo que tiene debajo, y dos copias de un manejador dejarian que esa
 * afirmacion fuera falsa en una de ellas sin que se enterara nadie.
 *
 * Lo que NO hace es buscar un socket, un buffer ni una conexion.  No puede,
 * porque no se le da ninguno.
 *
 * \~
 */
#ifndef HTTP_VX_SERVE_GREETING_H
#define HTTP_VX_SERVE_GREETING_H

#include "http_vx/http1_service.h"
#include "serve/events.h"

#include <cstdio>
#include <cstring>

namespace serve {

/**
 * @brief
 * \~english Answers every request with what it asked for.
 * \~spanish Contesta cada peticion con lo que pidio.
 * \~
 */
class Greeting final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &req, const uint8_t *head,
                const uint8_t *body, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        (void)body;

        // \~english The event stream, opened and fed from another thread (serve/events.h).
        // \~spanish El flujo de eventos, abierto y alimentado desde otro hilo (serve/events.h).  \~
        static const char kEvents[] = "/events";
        if (events != nullptr && req.target.len == sizeof kEvents - 1 &&
            std::memcmp(head + req.target.off, kEvents, sizeof kEvents - 1) == 0) {
            events->answer(res);
            return;
        }

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

    /// \~english The event streams `/events` answers with, or null: then it is greeted like the rest.
    /// \~spanish Los flujos de eventos con los que contesta `/events`, o nulo: entonces se saluda como al resto.  \~
    Events *events = nullptr;
};

} // namespace serve

#endif // HTTP_VX_SERVE_GREETING_H
