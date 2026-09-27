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

#include <atomic>
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
    StdioBackend(BufferPool &pool, int in, int out) noexcept;
    ~StdioBackend() override;

    /**
     * @brief
     * \~english Whether it can be used: its wake mechanism was made.
     * \~spanish Si se puede usar: se hizo su mecanismo de despertar.
     * \~
     *
     * @return \~english false, with @c wake_error set, if not  \~spanish false, con @c wake_error puesto, si no  \~
     */
    bool ready() const noexcept;

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *done, size_t cap, int timeout_ms) noexcept override;
    const char *name() const noexcept override { return "stdio"; }

    /**
     * @brief
     * \~english Ends a read that is waiting for the peer, or the next one; any thread (HVX-5, 6.4).
     * \~spanish Acaba una lectura que espera al otro extremo, o la siguiente; cualquier hilo (HVX-5, 6.4).
     * \~
     *
     * \~english
     * A pipe read blocks until the peer says something, so waking this
     * backend is ending THAT read without losing it: the read stays pending
     * and is made again on the next wait.  How is the platform's (linux/ and
     * windows/ stdio_wake.cpp).
     * \~spanish
     * Una lectura de tuberia bloquea hasta que el otro extremo dice algo, asi
     * que despertar este backend es acabar ESA lectura sin perderla: la lectura
     * sigue pendiente y se vuelve a hacer en la espera siguiente.  El como es de
     * cada plataforma (stdio_wake.cpp de linux/ y de windows/).
     * \~
     */
    bool wake() noexcept override;

    /// \~english What the system said when the wake mechanism failed.  \~spanish Lo que dijo el sistema cuando fallo el mecanismo de despertar.  \~
    int32_t wake_error() const noexcept { return wake_error_.load(std::memory_order_relaxed); }

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
    /**
     * @brief
     * \~english Finishes @p op into @p c; false if a wake ended its read first.
     * \~spanish Acaba @p op en @p c; false si un despertar acabo antes su lectura.
     * \~
     */
    bool finish(const Op &op, Completion &c, int timeout_ms) noexcept;

    /**
     * @brief
     * \~english Reads what has arrived, unless a wake comes first; the platform's.
     * \~spanish Lee lo que haya llegado, salvo que llegue antes un despertar; de cada plataforma.
     * \~
     *
     * \~english
     * @p timeout_ms is honoured as a wait's is: zero never blocks, a negative
     * one blocks until something happens.  A shard that has kicks waiting
     * asks for zero, and a read that blocked anyway would leave those kicks
     * waiting behind a peer that says nothing -- a kick lost.
     * \~spanish
     * @p timeout_ms se respeta como el de una espera: cero no bloquea nunca, uno
     * negativo bloquea hasta que pase algo.  Un fragmento con avisos esperando
     * pide cero, y una lectura que bloqueara igualmente dejaria esos avisos
     * esperando detras de un extremo que no dice nada -- un aviso perdido.
     * \~
     *
     * @param woken \~english set, with nothing read, if a wake or the deadline ended the wait
     *              \~spanish puesto, sin leer nada, si un despertar o el plazo acabo la espera  \~
     * @return      \~english bytes read, zero at the end of the stream, -1 on error
     *              \~spanish bytes leidos, cero al final del flujo, -1 en error  \~
     */
    long read_or_wake(uint8_t *room, uint32_t n, int timeout_ms, bool &woken) noexcept;

    /**
     * @brief
     * \~english Waits with nothing pending: until a wake or the deadline; the platform's.
     * \~spanish Espera sin nada pendiente: hasta un despertar o el plazo; de cada plataforma.
     * \~
     *
     * \~english
     * A shard with no operation here -- its connection held behind an open
     * response, say -- still has to sleep until a kick, not turn: a wait
     * that came back at once would spin a core.
     * \~spanish
     * Un fragmento sin ninguna operacion aqui -- con su conexion retenida detras
     * de una respuesta abierta, por ejemplo -- tiene que dormir igualmente hasta
     * un aviso, no dar vueltas: una espera que volviera en el acto gastaria un
     * nucleo.
     * \~
     */
    void idle(int timeout_ms) noexcept;

    /**
     * @brief
     * \~english Gives up a read the platform has in flight, and waits until its buffer is free; the platform's.
     * \~spanish Abandona una lectura que la plataforma tenga en vuelo, y espera a que su buffer quede libre; de cada plataforma.
     * \~
     */
    void abandon_read() noexcept;

    /// \~english The socket a cancelled read is left with: it completes as a failure.
    /// \~spanish El socket con el que se queda una lectura cancelada: acaba como fallo.  \~
    static constexpr int32_t kCancelledFd = -0x7FFFFFFF - 1;

    /* \~english
     * The wake mechanism's state, in types that name no platform.  Linux: the
     * eventfd.  Windows: the helper thread that is the ONLY reader of the
     * input pipe, the read it has been handed (where, how much, what came
     * of it), and three events -- a wake, "read this", "read done".
     * \~spanish
     * El estado del mecanismo de despertar, en tipos que no nombran ninguna
     * plataforma.  Linux: el eventfd.  Windows: el hilo auxiliar que es el UNICO
     * lector de la tuberia de entrada, la lectura que se le ha dado (donde,
     * cuanto, en que quedo), y tres sucesos -- un despertar, "lee esto",
     * "lectura hecha".
     * \~ */
    int wake_fd_ = -1;
    void *wake_event_ = nullptr;
    void *request_event_ = nullptr;
    void *done_event_ = nullptr;
    void *helper_ = nullptr;
    uint8_t *read_room_ = nullptr;
    uint32_t read_len_ = 0;
    long read_result_ = 0;
    bool read_in_flight_ = false;
    std::atomic<bool> stopping_{false};
    std::atomic<int32_t> wake_error_{0};

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
