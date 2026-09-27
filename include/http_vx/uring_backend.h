/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/uring_backend.h
 * @brief
 * \~english The backend where an operation costs no system call at all.
 * \~spanish El backend donde una operacion no cuesta ninguna llamada al sistema.
 * \~
 *
 * \~english
 * R8 asks for this one by name: `linux/` must offer io_uring AND epoll as
 * first-class backends.  Not because two are better than one -- because the
 * one that is only there for old kernels is the one nobody runs, and a path
 * nobody runs is a path that is broken and does not know it.
 *
 * **And it is the backend the measurements asked for.**  Serving a request
 * over a socket spends about eighty per cent of its time in the kernel and
 * under two per cent in the parser, so what decides this server's cost is how
 * many times it crosses into the kernel.  epoll got that down from five
 * crossings per request to three.  Here it goes to nearly NONE:
 *
 * **`submit` writes into a shared ring and returns.**  The operation is handed
 * over by storing it where the kernel can see it, not by asking the kernel to
 * take it, so a batch of a hundred connections' reads and writes costs a
 * hundred ring entries and ONE `io_uring_enter` -- which is the same call that
 * collects the completions.  That is R18 in one sentence, and it is the reason
 * the interface was made completion-based in the first place (R7): here there
 * is nothing to adapt, because this IS the interface.
 *
 * **Nothing is linked for it.**  `liburing` is a convenience wrapper, and this
 * project has an assembler, a linker and an archiver of its own -- taking a
 * dependency to avoid three system calls and two memory barriers would be out
 * of character and, more to the point, would make the build depend on what a
 * machine happens to have installed.  The kernel's own header carries the
 * structures and the opcodes, and that is all a ring needs.
 *
 * \~spanish
 * La R8 pide este por su nombre: `linux/` debe ofrecer io_uring Y epoll como
 * backends de primera.  No porque dos sean mejor que uno -- porque el que solo
 * esta para los nucleos viejos es el que no corre nadie, y un camino que no
 * corre nadie es un camino que esta roto y no lo sabe.
 *
 * **Y es el backend que pidieron las medidas.**  Servir una peticion por un
 * socket se pasa el ochenta por ciento del tiempo en el nucleo y menos del dos
 * por ciento en el analizador, asi que lo que decide lo que cuesta este servidor
 * es cuantas veces cruza al nucleo.  epoll lo bajo de cinco cruces por peticion
 * a tres.  Aqui se va a casi NINGUNO:
 *
 * **`submit` escribe en un anillo compartido y vuelve.**  La operacion se
 * entrega poniendola donde el nucleo la ve, no pidiendole al nucleo que la coja,
 * asi que un lote con las lecturas y escrituras de cien conexiones cuesta cien
 * entradas del anillo y UN `io_uring_enter` -- que es ademas la llamada que
 * recoge las finalizaciones.  Eso es la R18 en una frase, y es la razon por la
 * que la interfaz se hizo por finalizacion (R7): aqui no hay nada que adaptar,
 * porque esto ES la interfaz.
 *
 * **No se enlaza nada para ello.**  `liburing` es una envoltura de comodidad, y
 * este proyecto tiene ensamblador, enlazador y archivador propios -- coger una
 * dependencia para ahorrarse tres llamadas al sistema y dos barreras de memoria
 * seria impropio y, sobre todo, haria que la construccion dependiera de lo que
 * tenga instalado una maquina.  La cabecera del propio nucleo trae las
 * estructuras y los opcodes, y eso es todo lo que necesita un anillo.
 *
 * \~
 */
#ifndef HTTP_VX_URING_BACKEND_H
#define HTTP_VX_URING_BACKEND_H

#include "http_vx/buffer_pool.h"
#include "http_vx/datagram.h"
#include "http_vx/id_index.h"
#include "http_vx/reactor_ops.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Whether this kernel has a usable ring.
 * \~spanish Si este nucleo tiene un anillo utilizable.
 * \~
 *
 * \~english
 * Asked, not assumed from a version number.  io_uring is a thing a kernel can
 * be built without, a container can forbid with seccomp and an administrator
 * can switch off -- so the only answer that means anything is what happens
 * when a ring is actually asked for, and this asks for one and gives it back.
 *
 * It exists so that a server can CHOOSE, which is what R8 means by the backend
 * being chosen in configuration: a program that fell back silently would be a
 * program where nobody can tell which path they are on, and that is the
 * failure R8 describes rather than the one it prevents.
 *
 * \~spanish
 * Se pregunta, no se deduce de un numero de version.  io_uring es algo sin lo
 * que se puede construir un nucleo, que un contenedor puede prohibir con seccomp
 * y que un administrador puede apagar -- asi que la unica respuesta que
 * significa algo es lo que pasa cuando se pide un anillo de verdad, y esto pide
 * uno y lo devuelve.
 *
 * Existe para que un servidor pueda ELEGIR, que es lo que quiere decir la R8 con
 * que el backend se elija en configuracion: un programa que se cayera a otro en
 * silencio seria uno donde nadie puede saber en que camino esta, y ese es el
 * fallo que describe la R8 y no el que evita.
 * \~
 *
 * @return \~english true if a ring could be made  \~spanish true si se pudo hacer un anillo  \~
 */
bool uring_available() noexcept;

/**
 * @brief
 * \~english A backend that hands operations over through shared memory.
 * \~spanish Un backend que entrega operaciones por memoria compartida.
 * \~
 */
class UringBackend final : public Backend {
  public:
    UringBackend() noexcept = default;
    ~UringBackend() override;

    /**
     * @brief
     * \~english Makes a ring of @p entries and room for that many operations.
     * \~spanish Hace un anillo de @p entries y sitio para esas operaciones.
     * \~
     *
     * \~english
     * @p entries is rounded UP to a power of two by the kernel, and it bounds
     * how many operations may be waiting to be handed over at once -- not how
     * many may be in flight, which is larger and is bounded by the completion
     * ring the kernel makes twice as big for exactly this reason.
     *
     * \~spanish
     * @p entries lo redondea el nucleo hacia ARRIBA a una potencia de dos, y
     * acota cuantas operaciones pueden estar esperando a entregarse a la vez --
     * no cuantas pueden estar en vuelo, que son mas y las acota el anillo de
     * finalizaciones, que el nucleo hace del doble justamente por esto.
     *
     * \~
     * @param pool    \~english where the buffers are
     *                \~spanish donde estan los buffers  \~
     * @param entries \~english how many operations fit in the ring
     *                \~spanish cuantas operaciones caben en el anillo  \~
     * @return        \~english false if the ring or the memory could not be had
     *                \~spanish false si no se pudo conseguir el anillo o la memoria  \~
     */
    bool reset(BufferPool &pool, uint32_t entries) noexcept;

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
     * Kept and closed by the backend.  Each receive is an `IORING_OP_RECVMSG`
     * and each send an `IORING_OP_SENDMSG`, one datagram each; the batch is
     * the ring's, every entry written since the last enter handed over in
     * one.  Here @c DatagramCounts::receive_calls and @c send_calls stay at
     * zero, because no call is made per datagram: the calls are @c enters.
     * Multishot receive with provided buffers, which R26 names, is not used --
     * it hands the kernel a pool of its own, and the pool here is the shard's.
     * \~spanish
     * Lo guarda y lo cierra el backend.  Cada recepcion es un
     * `IORING_OP_RECVMSG` y cada envio un `IORING_OP_SENDMSG`, un datagrama
     * cada uno; el lote es el del anillo, todas las entradas escritas desde la
     * ultima entrada entregadas en una.  Aqui @c DatagramCounts::receive_calls y
     * @c send_calls se quedan en cero, porque no se hace ninguna llamada por
     * datagrama: las llamadas son @c enters.  La recepcion multishot con buffers
     * provistos, que nombra la R26, no se usa -- le da al nucleo un pozo propio,
     * y el pozo de aqui es el del fragmento.
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
    static constexpr const char *kName = "io_uring";

    const char *name() const noexcept override { return kName; }

    /// \~english What the system said last time something failed.
    /// \~spanish Lo que dijo el sistema la ultima vez que algo fallo.  \~
    int32_t last_error() const noexcept { return last_error_; }

    /// \~english How many operations the kernel is holding.
    /// \~spanish Cuantas operaciones tiene el nucleo.  \~
    size_t in_flight() const noexcept { return in_flight_; }

    /**
     * @brief
     * \~english How many times this has actually entered the kernel.
     * \~spanish Cuantas veces ha entrado de verdad en el nucleo.
     * \~
     *
     * \~english
     * The number this backend exists to make small, so it is counted rather
     * than argued about.  Divided by requests served it is what R18 asks for,
     * and it is the one figure that tells a batch of a hundred operations in
     * one call apart from a hundred calls.
     *
     * \~spanish
     * El numero que este backend existe para hacer pequeno, asi que se cuenta en
     * vez de discutirse.  Dividido por peticiones servidas es lo que pide la
     * R18, y es la unica cifra que distingue un lote de cien operaciones en una
     * llamada de cien llamadas.
     * \~
     */
    size_t enters() const noexcept { return enters_; }

    /// \~english Gives everything back and stops listening.
    /// \~spanish Devuelve todo y deja de escuchar.  \~
    void release() noexcept;

    /// \~english Signals the wake eventfd; any thread (HVX-5, 6.4).  \~spanish Senala el eventfd de despertar; cualquier hilo (HVX-5, 6.4).  \~
    bool wake() noexcept override;

    /// \~english What the system said when a wake failed.  \~spanish Lo que dijo el sistema cuando fallo un despertar.  \~
    int32_t wake_error() const noexcept { return wake_error_.load(std::memory_order_relaxed); }

  private:
    /**
     * \~english
     * The ring carries this back for the wake eventfd's read: no slot has it,
     * because slots are numbered from zero up to the completion ring's size.
     * \~spanish
     * El anillo devuelve esto para la lectura del eventfd de despertar: ninguna
     * casilla lo tiene, porque las casillas van de cero al tamano del anillo de
     * finalizaciones.
     * \~
     */
    static constexpr uint64_t kWakeData = ~uint64_t{0};

    /**
     * \~english
     * The ring carries this back for a cancel's own answer, which is
     * swallowed: the cancel completes as nothing, and what it ended comes
     * back through that operation's own slot.  No slot has it either -- a
     * slot's number has its index in the low half, and no ring has this many
     * entries.
     * \~spanish
     * El anillo devuelve esto para la respuesta propia de una cancelacion, que
     * se traga: la cancelacion acaba como nada, y lo que acabo vuelve por la
     * casilla de esa operacion.  Tampoco lo tiene ninguna casilla -- el numero
     * de una casilla lleva su indice en la mitad baja, y ningun anillo tiene
     * tantas entradas.
     * \~
     */
    static constexpr uint64_t kCancelData = ~uint64_t{0} - 1;

    /**
     * @brief
     * \~english Asks the kernel to end the read outstanding on @p op.fd.
     * \~spanish Le pide al nucleo que acabe la lectura pendiente en @p op.fd.
     * \~
     *
     * \~english
     * An `IORING_OP_ASYNC_CANCEL` naming the read's exact number, found in
     * @c reads_ without a scan.  The read then completes through its own
     * slot, with `-ECANCELED` -- or normally, if it won the race, and both
     * are what the contract allows.  No read outstanding is nothing to do.
     * \~spanish
     * Un `IORING_OP_ASYNC_CANCEL` que nombra el numero exacto de la lectura,
     * encontrado en @c reads_ sin recorrer nada.  La lectura acaba entonces por
     * su propia casilla, con `-ECANCELED` -- o normalmente, si gano la carrera,
     * y las dos cosas son lo que permite el contrato.  Sin lectura pendiente no
     * hay nada que hacer.
     * \~
     *
     * @param op \~english the @c Cancel  \~spanish el @c Cancel  \~
     * @return   \~english false if the ring had no room to ask
     *           \~spanish false si el anillo no tenia sitio para pedirlo  \~
     */
    bool submit_cancel(const Op &op) noexcept;

    /**
     * \~english
     * The slot of the read -- @c Ready or @c Recv -- outstanding on each
     * socket, by descriptor.  What turns "end the read on this socket" into
     * the number the kernel needs, in constant time; one entry per read, so
     * never more than there are slots.  An entry goes when its read's
     * completion is taken, or when its socket is closed.
     * \~spanish
     * La casilla de la lectura -- @c Ready o @c Recv -- pendiente en cada
     * socket, por descriptor.  Lo que convierte "acaba la lectura de este
     * socket" en el numero que necesita el nucleo, en tiempo constante; una
     * entrada por lectura, asi que nunca mas que casillas.  Una entrada se va
     * cuando se recoge la finalizacion de su lectura, o cuando se cierra su
     * socket.
     * \~
     */
    IdIndex reads_;

    /// \~english Opens the wake eventfd.  \~spanish Abre el eventfd de despertar.  \~
    bool wake_open() noexcept;

    /// \~english Closes it, once the ring can no longer write into its buffer.  \~spanish Lo cierra, cuando el anillo ya no puede escribir en su buffer.  \~
    void wake_close() noexcept;

    /**
     * @brief
     * \~english Puts a read of the wake eventfd in the ring, if none is there.
     * \~spanish Pone en el anillo una lectura del eventfd de despertar, si no hay ninguna.
     * \~
     *
     * \~english
     * The ring wakes only for what completes; this read completes when
     * another thread writes.  It is armed again after every completion --
     * without that, the next wake would be lost without a sound.
     * \~spanish
     * El anillo solo despierta por lo que acaba; esta lectura acaba cuando otro
     * hilo escribe.  Se vuelve a armar tras cada finalizacion -- sin eso, el
     * siguiente despertar se perderia sin un ruido.
     * \~
     */
    void arm_wake() noexcept;

    int wake_fd_ = -1;
    /// \~english Where the wake read lands.  \~spanish Donde cae la lectura de despertar.  \~
    uint64_t wake_buf_ = 0;
    bool wake_armed_ = false;
    std::atomic<int32_t> wake_error_{0};

    /**
     * \~english
     * One operation the kernel is holding, found again by the number the ring
     * carries back.  The entry in the ring is NOT this: a submission slot is
     * reused the moment the kernel has read it, and what has to outlive that
     * is which connection and which buffer the operation was for.
     * \~spanish
     * Una operacion que tiene el nucleo, encontrada otra vez por el numero que
     * devuelve el anillo.  La entrada del anillo NO es esto: una ranura de
     * entrega se reutiliza en cuanto el nucleo la ha leido, y lo que tiene que
     * sobrevivir a eso es de que conexion y de que buffer era la operacion.
     * \~
     */
    struct Slot;

    /// \~english The rings and the numbers that address them.
    /// \~spanish Los anillos y los numeros que los direccionan.  \~
    struct Ring;

    /// \~english Takes a place to remember an operation, or says there is none.
    /// \~spanish Coge un sitio donde recordar una operacion, o dice que no hay.  \~
    Slot *take() noexcept;

    /// \~english Gives @p s back.  \~spanish Devuelve @p s.  \~
    void give(Slot *s) noexcept;

    /// \~english Remembers a completion for an operation that never started.
    /// \~spanish Recuerda una finalizacion de una operacion que no empezo.  \~
    bool remember(const Op &op, int32_t result, int32_t fd) noexcept;

    /**
     * @brief
     * \~english Hands over what is waiting and takes back what is done.
     * \~spanish Entrega lo que espera y recoge lo que esta hecho.
     * \~
     *
     * \~english
     * One call for both, which is the whole shape of this backend: asking to
     * be given completions is also when the kernel is told about everything
     * submitted since the last time.
     * \~spanish
     * Una llamada para las dos cosas, que es toda la forma de este backend: pedir
     * que le den a uno finalizaciones es tambien cuando se le habla al nucleo de
     * todo lo entregado desde la ultima vez.
     * \~
     *
     * @param want       \~english how many completions to wait for
     *                   \~spanish cuantas finalizaciones esperar  \~
     * @param timeout_ms \~english how long; negative is for ever
     *                   \~spanish cuanto; negativo es para siempre  \~
     * @return           \~english what the system said
     *                   \~spanish lo que dijo el sistema  \~
     */
    int enter(uint32_t want, int timeout_ms) noexcept;

    /// \~english The message of a datagram in flight, one per slot.
    /// \~spanish El mensaje de un datagrama en vuelo, uno por sitio.  \~
    struct DgramMsg;

    /**
     * @brief
     * \~english Fills the ring entry @p sqe for datagram operation @p op in slot @p slot.
     * \~spanish Rellena la entrada del anillo @p sqe para la operacion de datagramas @p op en el sitio @p slot.
     * \~
     *
     * @return \~english false if it cannot be asked for  \~spanish false si no se puede pedir  \~
     */
    bool prep_datagram(const Op &op, void *sqe, uint32_t slot) noexcept;

    /// \~english What a datagram operation came to, from the kernel's @p res.
    /// \~spanish En que quedo una operacion de datagramas, por el @p res del nucleo.  \~
    int32_t finish_datagram(const Op &op, int32_t res, uint32_t slot) noexcept;

    /// \~english Closes every datagram socket and gives their messages back.
    /// \~spanish Cierra todos los sockets de datagramas y devuelve sus mensajes.  \~
    void release_datagrams() noexcept;

    DatagramSockets dgram_;

    /// \~english Allocated with the first datagram socket.
    /// \~spanish Se reserva con el primer socket de datagramas.  \~
    DgramMsg *msgs_ = nullptr;

    DatagramCounts dgram_counts_;

    Ring *ring_ = nullptr;

    int fd_ = -1;
    int listener_ = -1;

    Slot *slots_ = nullptr;
    uint32_t slot_count_ = 0;
    uint32_t free_head_ = 0xFFFFFFFF;
    size_t in_flight_ = 0;
    size_t enters_ = 0;

    /// \~english How many entries are written and not yet handed over.
    /// \~spanish Cuantas entradas hay escritas y sin entregar todavia.  \~
    uint32_t waiting_ = 0;

    BufferPool *pool_ = nullptr;

    /// \~english The completions of operations that failed before they began.
    /// \~spanish Las finalizaciones de operaciones que fallaron antes de empezar.  \~
    Completion failed_[64];
    size_t failed_count_ = 0;

    uint16_t port_ = 0;
    int32_t last_error_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_URING_BACKEND_H
