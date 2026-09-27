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
#include "http_vx/datagram.h"
#include "http_vx/reactor_ops.h"

#include <atomic>
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

    /**
     * @brief
     * \~english Opens a UDP socket bound to @p host and @p port, v4 or v6 by what @p host is.
     * \~spanish Abre un socket UDP atado a @p host y @p port, v4 o v6 segun lo que sea @p host.
     * \~
     *
     * \~english
     * Kept and closed by the backend.  Receives waiting on it are answered
     * together, by one `recvmmsg` when the socket becomes readable; sends are
     * gathered and go out together, by one `sendmmsg`, when the backend next
     * waits.  v6 sockets are v6 only; packet information and the traffic
     * class are switched on, so every datagram says where it was sent and
     * with which ECN mark.
     * \~spanish
     * Lo guarda y lo cierra el backend.  Las recepciones que esperan en el se
     * contestan juntas, con un `recvmmsg` cuando el socket tiene algo; los envios
     * se juntan y salen juntos, con un `sendmmsg`, la proxima vez que espera el
     * backend.  Los sockets v6 son solo v6; se encienden la informacion del
     * paquete y la clase de trafico, asi que cada datagrama dice a donde se mando
     * y con que marca ECN.
     * \~
     *
     * @return \~english the socket, or -1 with @c last_error set
     *         \~spanish el socket, o -1 con @c last_error puesto  \~
     */
    int32_t open_datagram(const char *host, uint16_t port,
                          NetAddress &bound) noexcept;

    /// \~english What happened to datagrams.  \~spanish Lo que les paso a los datagramas.  \~
    const DatagramCounts &datagrams() const noexcept { return dgram_counts_; }

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *out, size_t cap, int timeout_ms) noexcept override;
    /// \~english The name it is chosen by; the only place it is written.
    /// \~spanish El nombre por el que se elige; el unico sitio donde esta escrito.  \~
    static constexpr const char *kName = "epoll";

    const char *name() const noexcept override { return kName; }

    /// \~english What the system said last time something failed.
    /// \~spanish Lo que dijo el sistema la ultima vez que algo fallo.  \~
    int32_t last_error() const noexcept { return last_error_; }

    /// \~english How many operations are waiting for a socket to be ready.
    /// \~spanish Cuantas operaciones esperan a que un socket este listo.  \~
    size_t in_flight() const noexcept { return in_flight_; }

    /**
     * @brief
     * \~english How many submissions were refused because the memory to complete them could not be had.
     * \~spanish Cuantas entregas se rechazaron porque no se pudo conseguir la memoria para acabarlas.
     * \~
     *
     * \~english
     * The only refusal that is not a caller's mistake or a socket's answer,
     * and so counted apart: a server where this moves is out of memory.
     * \~spanish
     * El unico rechazo que no es un error de quien llama ni la respuesta de un
     * socket, y por eso contado aparte: un servidor donde esto se mueve se ha
     * quedado sin memoria.
     * \~
     */
    uint64_t refused() const noexcept { return refused_; }

    /// \~english Gives everything back and stops listening.
    /// \~spanish Devuelve todo y deja de escuchar.  \~
    void release() noexcept;

    /// \~english Signals the wake eventfd; any thread (HVX-5, 6.4).  \~spanish Senala el eventfd de despertar; cualquier hilo (HVX-5, 6.4).  \~
    bool wake() noexcept override;

    /// \~english What the system said when a wake failed.  \~spanish Lo que dijo el sistema cuando fallo un despertar.  \~
    int32_t wake_error() const noexcept { return wake_error_.load(std::memory_order_relaxed); }

  private:
    /// \~english Opens the wake eventfd and puts it on the queue, edge-triggered.
    /// \~spanish Abre el eventfd de despertar y lo pone en la cola, por flanco.  \~
    bool wake_open() noexcept;

    /// \~english Closes the wake eventfd.  \~spanish Cierra el eventfd de despertar.  \~
    void wake_close() noexcept;

    /// \~english The wake eventfd, or -1.  \~spanish El eventfd de despertar, o -1.  \~
    int wake_fd_ = -1;
    std::atomic<int32_t> wake_error_{0};

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

    /// \~english Remembers a completion that is already true; there is always room (see @c ready_).
    /// \~spanish Recuerda una finalizacion que ya es cierta; siempre hay sitio (ver @c ready_).  \~
    void remember(const Op &op, int32_t result, int32_t fd) noexcept;

    /// \~english Keeps @p op until its socket is ready.
    /// \~spanish Guarda @p op hasta que su socket este listo.  \~
    bool park(const Op &op) noexcept;

    /// \~english Tells the queue what @p fd is waited on for now.
    /// \~spanish Le dice a la cola por que se espera a @p fd ahora mismo.  \~
    bool arm(int32_t fd) noexcept;

    /// \~english Forgets everything about @p fd.
    /// \~spanish Olvida todo lo de @p fd.  \~
    void forget(int32_t fd) noexcept;

    /// \~english Moves what is ready into @p out; how many now.
    /// \~spanish Pasa lo que ya esta listo a @p out; cuantas hay ahora.  \~
    size_t take_ready(Completion *out, size_t cap, size_t made) noexcept;

    /**
     * @brief
     * \~english One datagram socket and the operations waiting on it.
     * \~spanish Un socket de datagramas y las operaciones que esperan en el.
     * \~
     *
     * \~english
     * Queues and not one note per direction, because a datagram socket is
     * shared by every peer: many receives wait on it at once, which is what
     * lets one `recvmmsg` answer them together, and many sends wait for the
     * next `sendmmsg`.  Two datagrams in two buffers cannot be reordered into
     * a wrong stream, so the rule that forbids two reads on a stream socket
     * does not apply.
     * \~spanish
     * Colas y no una nota por sentido, porque un socket de datagramas lo
     * comparten todos los extremos: muchas recepciones esperan en el a la vez,
     * que es lo que deja que un `recvmmsg` las conteste juntas, y muchos envios
     * esperan al `sendmmsg` siguiente.  Dos datagramas en dos buffers no se
     * pueden desordenar en un flujo equivocado, asi que la regla que prohibe dos
     * lecturas en un socket de flujo no se aplica.
     * \~
     */
    struct DgramSocket;

    /// \~english Takes a datagram operation on socket @p i.
    /// \~spanish Coge una operacion de datagramas sobre el socket @p i.  \~
    bool dgram_submit(const Op &op, int32_t i) noexcept;

    /// \~english The events socket @p i wants.  \~spanish Los sucesos que quiere el socket @p i.  \~
    uint32_t dgram_events(int32_t i) const noexcept;

    /// \~english Sends what waits on socket @p i, completions into the ready list.
    /// \~spanish Manda lo que espera en el socket @p i, finalizaciones a la lista de listas.  \~
    void dgram_flush(int32_t i) noexcept;

    /// \~english Answers what socket @p i can answer now; how many went into @p out.
    /// \~spanish Contesta lo que puede contestar ya el socket @p i; cuantas fueron a @p out.  \~
    size_t dgram_ready(int32_t i, bool readable, bool writable, Completion *out,
                       size_t room) noexcept;

    /// \~english Fails everything waiting on socket @p i, which stays open.
    /// \~spanish Hace fallar todo lo que espera en el socket @p i, que sigue abierto.  \~
    void dgram_fail(int32_t i) noexcept;

    /// \~english Fails everything waiting on socket @p i and forgets it.
    /// \~spanish Hace fallar todo lo que espera en el socket @p i y lo olvida.  \~
    void dgram_close(int32_t i) noexcept;

    /// \~english Makes room for the datagram sockets.
    /// \~spanish Hace sitio para los sockets de datagramas.  \~
    bool dgram_reset() noexcept;

    /// \~english Closes every datagram socket and gives the room back.
    /// \~spanish Cierra todos los sockets de datagramas y devuelve el sitio.  \~
    void dgram_release() noexcept;

    DgramSocket *dgram_ = nullptr;
    DatagramCounts dgram_counts_;

    int queue_ = -1;
    int listener_ = -1;

    Waiting *waiting_ = nullptr;
    uint32_t max_fds_ = 0;
    size_t in_flight_ = 0;

    BufferPool *pool_ = nullptr;

    /**
     * \~english
     * The completions that are true and not yet handed out, as a ring.
     *
     * **It always has room for every operation this backend has accepted**:
     * the ones already in it plus every one still waiting (@c in_flight_).
     * The room is made when an operation is ACCEPTED -- the one moment a
     * refusal can still be said, by @c submit returning false with nothing
     * done -- and never when a completion has to be written.  A fixed list
     * that could fill up lost completions exactly when it mattered most: a
     * datagram socket closed with a hundred receives waiting answered them
     * into a list with no room, and each one lost was a pooled buffer that
     * never came back.
     * \~spanish
     * Las finalizaciones que son ciertas y no se han entregado, en anillo.
     *
     * **Siempre tiene sitio para toda operacion que este backend ha aceptado**:
     * las que ya estan en el mas todas las que siguen esperando
     * (@c in_flight_).  El sitio se hace cuando se ACEPTA una operacion -- el
     * unico momento en que todavia se puede decir que no, con un @c submit que
     * devuelve false sin haber hecho nada -- y nunca cuando hay que escribir una
     * finalizacion.  Una lista fija que se podia llenar perdia finalizaciones
     * justo cuando mas importaba: un socket de datagramas cerrado con cien
     * recepciones esperando las contestaba en una lista sin sitio, y cada una
     * perdida era un buffer del pozo que no volvia nunca.
     * \~
     */
    Completion *ready_ = nullptr;
    size_t ready_room_ = 0;
    size_t ready_head_ = 0;
    size_t ready_count_ = 0;

    /// \~english Submissions refused because no room could be had.
    /// \~spanish Entregas rechazadas porque no se pudo conseguir sitio.  \~
    uint64_t refused_ = 0;

    /**
     * @brief
     * \~english Makes sure one more accepted operation has room to complete.
     * \~spanish Se asegura de que una operacion aceptada mas tiene sitio para acabar.
     * \~
     *
     * @return \~english false, counted and with @c last_error set, if the memory could not be had
     *         \~spanish false, contado y con @c last_error puesto, si no se pudo conseguir la memoria  \~
     */
    bool make_room() noexcept;

    /// \~english Gives the ready list back.  \~spanish Devuelve la lista de listas.  \~
    void drop_ready() noexcept;

    /**
     * @brief
     * \~english Fails whatever still waits on stream socket @p fd.
     * \~spanish Hace fallar lo que todavia espera en el socket de flujo @p fd.
     * \~
     *
     * \~english
     * For when the queue refused to watch @p fd: an operation left waiting on
     * a socket nobody watches would wait for ever.
     * \~spanish
     * Para cuando la cola se nego a vigilar @p fd: una operacion que se quedara
     * esperando en un socket que no vigila nadie esperaria para siempre.
     * \~
     */
    void fail_waiting(int32_t fd) noexcept;

    uint16_t port_ = 0;
    int32_t last_error_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_EPOLL_BACKEND_H
