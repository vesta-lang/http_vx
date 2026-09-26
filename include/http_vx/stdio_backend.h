/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/stdio_backend.h
 * @brief
 * \~english A backend over two ordinary streams, so a server needs no network.
 * \~spanish Un backend sobre dos flujos corrientes, para que un servidor no necesite red.
 * \~
 *
 * \~english
 * HTTP does not require a socket.  What it requires is a pair of byte streams
 * that keep their order, and a pipe is one -- which is how the Docker daemon
 * is spoken to, how gRPC runs between containers, and how anything that talks
 * HTTP to the process next door avoids the network stack entirely.
 *
 * So this is a real backend and not a demonstration of one: it takes
 * operations, finishes them against `stdin` and `stdout`, and hands back
 * completions.  A server built on it serves requests.
 *
 * **And it is the second implementation, which is the point.**  An interface
 * with one implementation is an interface that might be the shape of that
 * implementation.  Writing this one is what says whether @c Backend describes
 * what a shard needs from an operating system, or only what the in-memory one
 * happened to do -- and it cost no change to a single line above it.
 *
 * Two things are true of it that are not true of a socket, and neither is a
 * shortcoming of the design:
 *
 *  - **it blocks.**  `fread` waits, because that is what reading a pipe is
 *    when nobody has asked the operating system for anything else.  A
 *    completion interface over a blocking call is still a completion
 *    interface -- the operation is submitted, and it finishes later;
 *  - **it is one connection.**  There is one `stdin`, so there is one peer.
 *    A shard sized for a million connections runs it perfectly well with one.
 *
 * \~spanish
 * HTTP no necesita un socket.  Lo que necesita es un par de flujos de bytes que
 * conserven el orden, y una tuberia lo es -- que es como se le habla al demonio
 * de Docker, como corre gRPC entre contenedores, y como cualquier cosa que hable
 * HTTP con el proceso de al lado se salta la pila de red entera.
 *
 * Asi que este es un backend de verdad y no una demostracion de uno: coge
 * operaciones, las acaba contra `stdin` y `stdout`, y devuelve finalizaciones.
 * Un servidor hecho sobre el sirve peticiones.
 *
 * **Y es la segunda implementacion, que es de lo que se trata.**  Una interfaz
 * con una sola implementacion es una interfaz que puede ser la forma de esa
 * implementacion.  Escribir esta es lo que dice si @c Backend describe lo que
 * necesita un fragmento de un sistema operativo, o solo lo que resulto que hacia
 * el de memoria -- y no costo cambiar ni una linea de lo que hay por encima.
 *
 * Dos cosas son ciertas de el que no lo son de un socket, y ninguna es un
 * defecto del diseno:
 *
 *  - **bloquea.**  `fread` espera, porque eso es leer una tuberia cuando nadie
 *    le ha pedido otra cosa al sistema operativo.  Una interfaz por
 *    finalizacion sobre una llamada que bloquea sigue siendo una interfaz por
 *    finalizacion -- la operacion se entrega, y acaba despues;
 *  - **es una conexion.**  Hay un `stdin`, asi que hay un extremo.  Un
 *    fragmento dimensionado para un millon de conexiones lo corre
 *    perfectamente con una.
 *
 * \~
 */
#ifndef HTTP_VX_STDIO_BACKEND_H
#define HTTP_VX_STDIO_BACKEND_H

#include "http_vx/buffer_pool.h"
#include "http_vx/reactor_ops.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace http_vx {

/**
 * @brief
 * \~english How many operations may be outstanding here at once.
 * \~spanish Cuantas operaciones pueden estar pendientes aqui a la vez.
 * \~
 */
constexpr size_t kStdioPending = 32;

/**
 * @brief
 * \~english A backend that finishes operations against two streams.
 * \~spanish Un backend que acaba operaciones contra dos flujos.
 * \~
 */
class StdioBackend final : public Backend {
  public:
    /**
     * @brief
     * \~english Makes one reading @p in, writing @p out, through @p pool.
     * \~spanish Hace uno que lee @p in, escribe @p out, a traves de @p pool.
     * \~
     *
     * \~english
     * The streams are given rather than assumed to be `stdin` and `stdout`,
     * which costs nothing and means the same backend serves a pipe, a pair of
     * files, or a test that wants to look at what came out.
     *
     * \~spanish
     * Los flujos se dan en vez de darse por hecho que son `stdin` y `stdout`,
     * lo que no cuesta nada y quiere decir que el mismo backend sirve una
     * tuberia, un par de ficheros, o una prueba que quiera mirar lo que salio.
     *
     * \~
     * They are DESCRIPTORS and not buffered streams, and that is not a
     * preference: a buffered read waits until it has all it was asked for, so
     * asking for sixteen kilobytes of a request that is forty bytes long
     * would wait for the peer to send the next one -- and a peer waiting for
     * the answer to this one would wait for ever.  A descriptor read gives
     * back whatever has arrived, which is the only shape that works on a pipe.
     *
     * \~spanish
     * Son DESCRIPTORES y no flujos con buffer, y no es una preferencia: una
     * lectura con buffer espera hasta tener todo lo que le pidieron, asi que
     * pedir dieciseis kilobytes de una peticion de cuarenta bytes esperaria a
     * que el otro extremo mandara la siguiente -- y un extremo que espera la
     * respuesta a esta esperaria para siempre.  Una lectura de descriptor
     * devuelve lo que haya llegado, que es la unica forma que funciona en una
     * tuberia.
     *
     * \~
     * @param pool \~english where the buffers are  \~spanish donde estan los buffers  \~
     * @param in   \~english what the peer says  \~spanish lo que dice el otro extremo  \~
     * @param out  \~english where the answers go  \~spanish donde van las respuestas  \~
     */
    StdioBackend(BufferPool &pool, int in, int out) noexcept
        : pool_(&pool), in_(in), out_(out) {}

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *done, size_t cap, int timeout_ms) noexcept override;
    const char *name() const noexcept override { return "stdio"; }

    /// \~english Whether the peer has closed its end.
    /// \~spanish Si el otro extremo ha cerrado su lado.  \~
    bool ended() const noexcept { return ended_; }

    /// \~english How many are waiting to finish.
    /// \~spanish Cuantas esperan para acabar.  \~
    size_t pending() const noexcept { return count_; }

    /**
     * \~english
     * How many datagram operations were refused.  A pipe carries a stream and
     * has no datagrams and no addresses, so a @c RecvFrom or a @c SendTo here
     * FAILS -- it used to be read and written as a stream, which delivered
     * bytes with no peer as if they were a datagram from nobody.
     * \~spanish
     * Cuantas operaciones de datagramas se rechazaron.  Una tuberia lleva un
     * flujo y no tiene ni datagramas ni direcciones, asi que un @c RecvFrom o un
     * @c SendTo aqui FALLA -- antes se leia y escribia como un flujo, que
     * entregaba bytes sin otro extremo como si fueran un datagrama de nadie.
     * \~
     */
    size_t refused_datagrams() const noexcept { return refused_datagrams_; }

  private:
    Completion finish(const Op &op) noexcept;

    BufferPool *pool_ = nullptr;
    int in_ = -1;
    int out_ = -1;

    Op pending_[kStdioPending];
    size_t head_ = 0;
    size_t count_ = 0;

    size_t refused_datagrams_ = 0;

    bool ended_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_STDIO_BACKEND_H
