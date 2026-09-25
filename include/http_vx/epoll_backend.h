/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/epoll_backend.h
 * @brief
 * \~english The backend that has to be adapted, and the one R8 is about.
 * \~spanish El backend que hay que adaptar, y del que va la R8.
 * \~
 *
 * \~english
 * R7 chose completion, and the reason given was that it makes IOCP and
 * io_uring thin translations and leaves only epoll needing adaptation.  This is
 * that adaptation, and it is worth being exact about what it costs, because
 * "needs adaptation" is doing a lot of work in that sentence.
 *
 * **epoll says a socket is READY; this interface says an operation is DONE.**
 * They are one syscall apart, and the whole file is about who makes it and
 * when:
 *
 *  - @c submit does not hand anything to the kernel, because with readiness
 *    there is nothing to hand it.  It TRIES the operation, and what happens
 *    next is either a completion that is already true or a note to come back;
 *  - @c wait asks epoll which sockets are ready and then does the operations
 *    they were waiting for, which is where the rest of the completions come
 *    from.
 *
 * **Trying first is not an optimisation.**  A socket with bytes already in its
 * receive queue is the ordinary case on a busy server, and a backend that
 * registered interest and waited for epoll to say what it could have found out
 * by asking would be paying two syscalls for every read that R15 says should
 * cost one.  What it costs is that a completion can be true before anybody
 * asked for it, which is why there is a queue of them here.
 *
 * **And an outstanding operation is a note to self, not memory the kernel
 * holds.**  That is the one place this is EASIER than a completion port: a
 * buffer named by a pending operation here is not being written to by anybody,
 * so the rule that makes IOCP delicate -- do not touch it, do not move it, do
 * not give it back -- is not load-bearing.  It is still obeyed, because the
 * loop above cannot know which backend it is talking to, and a loop that
 * behaved differently per backend would be two loops.
 *
 * \~spanish
 * La R7 eligio finalizacion, y la razon que se dio es que eso hace de IOCP e
 * io_uring traducciones finas y deja que solo epoll necesite adaptacion.  Esta
 * es esa adaptacion, y merece ser exacto sobre lo que cuesta, porque "necesita
 * adaptacion" esta trabajando mucho en esa frase.
 *
 * **epoll dice que un socket esta LISTO; esta interfaz dice que una operacion
 * esta HECHA.**  Estan a una llamada al sistema de distancia, y el fichero
 * entero va de quien la hace y cuando:
 *
 *  - @c submit no le entrega nada al nucleo, porque con disponibilidad no hay
 *    nada que entregarle.  INTENTA la operacion, y lo que pasa despues es o una
 *    finalizacion que ya es cierta o una nota para volver;
 *  - @c wait le pregunta a epoll que sockets estan listos y hace entonces las
 *    operaciones que esperaban, que es de donde salen las demas finalizaciones.
 *
 * **Intentarlo primero no es una optimizacion.**  Un socket con bytes ya en su
 * cola de recepcion es el caso corriente en un servidor con trabajo, y un
 * backend que registrara interes y esperara a que epoll le dijera lo que podia
 * haber averiguado preguntando estaria pagando dos llamadas al sistema por cada
 * lectura de las que la R15 dice que deberian costar una.  Lo que cuesta es que
 * una finalizacion puede ser cierta antes de que la pida nadie, que es la razon
 * de que aqui haya una cola de ellas.
 *
 * **Y una operacion pendiente es una nota para uno mismo, no una memoria que
 * tenga el nucleo.**  Ese es el unico sitio donde esto es MAS FACIL que un
 * puerto de finalizacion: un buffer que nombre una operacion pendiente de aqui
 * no se lo esta escribiendo nadie, asi que la regla que hace delicado a IOCP --
 * no tocarlo, no moverlo, no devolverlo -- no sujeta nada.  Se cumple igual,
 * porque el bucle de encima no puede saber con que backend habla, y un bucle que
 * se portara distinto segun el backend serian dos bucles.
 *
 * \~
 */
#ifndef HTTP_VX_EPOLL_BACKEND_H
#define HTTP_VX_EPOLL_BACKEND_H

#include "http_vx/buffer_pool.h"
#include "http_vx/reactor_ops.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english A backend that talks to a Linux readiness queue.
 * \~spanish Un backend que habla con una cola de disponibilidad de Linux.
 * \~
 */
class EpollBackend final : public Backend {
  public:
    EpollBackend() noexcept = default;
    ~EpollBackend() override;

    /**
     * @brief
     * \~english Makes the queue and room for sockets numbered below @p max_fds.
     * \~spanish Hace la cola y sitio para sockets numerados por debajo de @p max_fds.
     * \~
     *
     * \~english
     * The ceiling is on DESCRIPTORS and not on operations, which is the shape
     * of readiness showing through: what has to be remembered is one note per
     * socket -- at most a read and a write, because those are the two
     * directions -- and not one record per thing the kernel is holding, because
     * the kernel is holding nothing.
     *
     * A flat array indexed by the descriptor, because Linux hands out the
     * lowest free one: the numbers are dense from zero, so the array is the
     * lookup and there is nothing to hash.  A descriptor above the ceiling is
     * refused loudly rather than ignored -- it would be a server past the limit
     * it was configured with, and that is worth saying rather than working
     * around.
     *
     * \~spanish
     * El techo es de DESCRIPTORES y no de operaciones, que es la forma de la
     * disponibilidad asomando: lo que hay que recordar es una nota por socket --
     * como mucho una lectura y una escritura, porque son las dos direcciones --
     * y no un registro por cosa que tenga el nucleo, porque el nucleo no tiene
     * nada.
     *
     * Un array plano indexado por el descriptor, porque Linux da el menor libre:
     * los numeros son densos desde cero, asi que el array es la busqueda y no hay
     * nada que aplicar un hash.  Un descriptor por encima del techo se rechaza en
     * voz alta y no se ignora -- seria un servidor pasado del limite con el que
     * se configuro, y eso merece decirse en vez de apanarse.
     *
     * \~
     * @param pool    \~english where the buffers are
     *                \~spanish donde estan los buffers  \~
     * @param max_fds \~english the highest descriptor this will handle, plus one
     *                \~spanish el descriptor mayor que atendera, mas uno  \~
     * @return        \~english false if the queue or the memory could not be had
     *                \~spanish false si no se pudo conseguir la cola o la memoria  \~
     */
    bool reset(BufferPool &pool, uint32_t max_fds) noexcept;

    /**
     * @brief
     * \~english Starts listening on @p host and @p port.
     * \~spanish Empieza a escuchar en @p host y @p port.
     * \~
     *
     * @param host    \~english the address to bind, as text
     *                \~spanish la direccion donde atarse, como texto  \~
     * @param port    \~english the port, or zero for any
     *                \~spanish el puerto, o cero para cualquiera  \~
     * @param backlog \~english how many may wait to be accepted
     *                \~spanish cuantas pueden esperar a que las acepten  \~
     * @return        \~english false if it could not listen
     *                \~spanish false si no pudo escuchar  \~
     */
    bool listen(const char *host, uint16_t port, int backlog = 512) noexcept;

    /// \~english Which port it is listening on.
    /// \~spanish En que puerto esta escuchando.  \~
    uint16_t port() const noexcept { return port_; }

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *out, size_t cap, int timeout_ms) noexcept override;
    const char *name() const noexcept override { return "epoll"; }

    /// \~english What the system said last time something failed.
    /// \~spanish Lo que dijo el sistema la ultima vez que algo fallo.  \~
    int32_t last_error() const noexcept { return last_error_; }

    /// \~english How many operations are waiting for a socket to be ready.
    /// \~spanish Cuantas operaciones esperan a que un socket este listo.  \~
    size_t in_flight() const noexcept { return in_flight_; }

    /// \~english Gives everything back and stops listening.
    /// \~spanish Devuelve todo y deja de escuchar.  \~
    void release() noexcept;

  private:
    /**
     * \~english
     * What one socket is waiting for.  Two operations at most and they are the
     * two DIRECTIONS: a connection being read from while its answer is going
     * out is the ordinary state of a server, and a record that held one
     * operation would serialise the two halves of every exchange.
     * \~spanish
     * Lo que espera un socket.  Dos operaciones como mucho, y son los dos
     * SENTIDOS: una conexion de la que se lee mientras sale su respuesta es el
     * estado corriente de un servidor, y un registro que guardara una sola
     * operacion pondria en fila las dos mitades de cada intercambio.
     * \~
     */
    struct Waiting;

    /// \~english Does what @p op asked, now, if the socket lets it.
    /// \~spanish Hace lo que pide @p op, ahora, si el socket deja.  \~
    int try_now(const Op &op) noexcept;

    /// \~english Remembers a completion that is already true.
    /// \~spanish Recuerda una finalizacion que ya es cierta.  \~
    bool remember(const Op &op, int32_t result, int32_t fd) noexcept;

    /// \~english Keeps @p op until its socket is ready.
    /// \~spanish Guarda @p op hasta que su socket este listo.  \~
    bool park(const Op &op) noexcept;

    /// \~english Tells the queue what @p fd is waited on for now.
    /// \~spanish Le dice a la cola por que se espera a @p fd ahora mismo.  \~
    bool arm(int32_t fd) noexcept;

    /// \~english Forgets everything about @p fd.
    /// \~spanish Olvida todo lo de @p fd.  \~
    void forget(int32_t fd) noexcept;

    int queue_ = -1;
    int listener_ = -1;

    Waiting *waiting_ = nullptr;
    uint32_t max_fds_ = 0;
    size_t in_flight_ = 0;

    BufferPool *pool_ = nullptr;

    /**
     * \~english
     * The completions that were already true when they were asked for.  Fixed,
     * and when it is full the operation is parked instead of tried -- which
     * costs a turn of the loop and cannot be wrong, rather than costing a
     * completion that nobody would ever be told about.
     * \~spanish
     * Las finalizaciones que ya eran ciertas cuando se pidieron.  Fija, y cuando
     * esta llena la operacion se guarda en vez de intentarse -- lo que cuesta una
     * vuelta del bucle y no puede estar mal, en vez de costar una finalizacion de
     * la que no se enteraria nadie.
     * \~
     */
    Completion ready_[256];
    size_t ready_count_ = 0;

    uint16_t port_ = 0;
    int32_t last_error_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_EPOLL_BACKEND_H
