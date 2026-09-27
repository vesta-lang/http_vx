/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/iocp_backend.h
 * @brief
 * \~english The first backend with an operating system in it.
 * \~spanish El primer backend con un sistema operativo dentro.
 * \~
 *
 * \~english
 * Everything above this has been written and tested without a socket anywhere
 * near it, which was the point of R6 and of the memory backend.  This is where
 * that stops: a listening socket, real clients, and bytes that arrive when
 * somebody else decides.
 *
 * **And it is a thin translation, which is what R7 bought.**  A completion port
 * is the interface this project already has: an operation is handed over with
 * somewhere to put the result, and the result comes back later in a batch.
 * Nothing here emulates anything.  The whole file is names -- `WSARecv` for a
 * @c Recv, `AcceptEx` for an @c Accept -- plus the bookkeeping that keeps a
 * pending operation's memory alive until its completion arrives.
 *
 * That bookkeeping is the only difficult part and it is the one R7 warned
 * about: **between submitting and completing, a buffer belongs to the
 * kernel.**  The room for a read is reserved when the read is asked for,
 * because the address has to exist before there is anything to put in it, and
 * it is committed when the completion says how much arrived.  Anything that
 * moved that buffer in between would be handing the kernel an address that no
 * longer means what it meant.
 *
 * **No Windows header appears here.**  The types that would need them -- the
 * port, the sockets, the pointer to `AcceptEx` -- are held as the plainest
 * thing that can hold them, and everything that needs to know what they really
 * are is in the translation unit.  It is not tidiness: this header is included
 * by whoever builds a server, and a header that pulled in `winsock2.h` would
 * put the operating system back into every file that names a backend.
 *
 * \~spanish
 * Todo lo que hay por encima de esto se ha escrito y probado sin ningun socket
 * cerca, que era de lo que iban la R6 y el backend de memoria.  Aqui es donde eso
 * se acaba: un socket de escucha, clientes de verdad, y bytes que llegan cuando
 * lo decide otro.
 *
 * **Y es una traduccion fina, que es lo que compro la R7.**  Un puerto de
 * finalizacion es la interfaz que ya tiene este proyecto: se entrega una
 * operacion con donde poner el resultado, y el resultado vuelve despues en un
 * lote.  Aqui no se emula nada.  El fichero entero son nombres -- `WSARecv` para
 * un @c Recv, `AcceptEx` para un @c Accept -- mas la contabilidad que mantiene
 * viva la memoria de una operacion pendiente hasta que llega su finalizacion.
 *
 * Esa contabilidad es la unica parte dificil y es la que avisaba la R7: **entre
 * entregar y acabar, un buffer es del nucleo.**  El sitio de una lectura se
 * reserva cuando se pide la lectura, porque la direccion tiene que existir antes
 * de que haya nada que poner en ella, y se confirma cuando la finalizacion dice
 * cuanto llego.  Cualquier cosa que moviera ese buffer en medio seria darle al
 * nucleo una direccion que ya no significa lo que significaba.
 *
 * **Aqui no aparece ninguna cabecera de Windows.**  Los tipos que las
 * necesitarian -- el puerto, los sockets, el puntero a `AcceptEx` -- se guardan
 * en lo mas pelado que pueda guardarlos, y todo lo que necesita saber lo que son
 * de verdad esta en la unidad de traduccion.  No es limpieza: esta cabecera la
 * incluye quien construya un servidor, y una que arrastrara `winsock2.h`
 * devolveria el sistema operativo a todos los ficheros que nombren un backend.
 *
 * \~
 */
#ifndef HTTP_VX_IOCP_BACKEND_H
#define HTTP_VX_IOCP_BACKEND_H

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
 * \~english A backend that talks to a Windows completion port.
 * \~spanish Un backend que habla con un puerto de finalizacion de Windows.
 * \~
 */
class IocpBackend final : public Backend {
  public:
    IocpBackend() noexcept = default;
    ~IocpBackend() override;

    /**
     * @brief
     * \~english Makes the port and room for @p pending operations at once.
     * \~spanish Hace el puerto y sitio para @p pending operaciones a la vez.
     * \~
     *
     * \~english
     * @p pending is a hard ceiling and not a hint.  Every operation in flight
     * holds a record here -- its `OVERLAPPED`, which the kernel writes into --
     * and those records may not move or be reused while the kernel has them,
     * so they are made once and lent out.  Running out is answered by
     * @c submit refusing, which is a shard at its limit and not a shard in
     * trouble.
     *
     * \~spanish
     * @p pending es un techo duro y no una sugerencia.  Toda operacion en vuelo
     * tiene un registro aqui -- su `OVERLAPPED`, en el que escribe el nucleo --
     * y esos registros no se pueden mover ni reutilizar mientras los tenga el
     * nucleo, asi que se hacen una vez y se prestan.  Quedarse sin se contesta
     * con un @c submit que rechaza, que es un fragmento en su limite y no un
     * fragmento con un problema.
     *
     * \~
     * @param pool    \~english where the buffers are
     *                \~spanish donde estan los buffers  \~
     * @param pending \~english how many operations may be in flight
     *                \~spanish cuantas operaciones pueden estar en vuelo  \~
     * @return        \~english false if the port or the memory could not be had
     *                \~spanish false si no se pudo conseguir el puerto o la memoria  \~
     */
    bool reset(BufferPool &pool, uint32_t pending) noexcept;

    /**
     * @brief
     * \~english Starts listening on @p host and @p port.
     * \~spanish Empieza a escuchar en @p host y @p port.
     * \~
     *
     * \~english
     * A @p port of zero asks the system for a free one, and @c port says which
     * it gave.  That is what a test wants: a fixed number is a test that fails
     * when anything else on the machine is using it, which is a red that says
     * nothing about the code.
     *
     * \~spanish
     * Un @p port de cero le pide al sistema uno libre, y @c port dice cual dio.
     * Eso es lo que quiere una prueba: un numero fijo es una prueba que falla
     * cuando cualquier otra cosa de la maquina lo este usando, que es un rojo que
     * no dice nada del codigo.
     *
     * \~
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
     * The backend keeps it and closes it on @c release.  A v6 socket is v6
     * ONLY: a dual-stack one would hand up v4 peers as mapped v6 addresses,
     * and the same peer would then have two spellings depending on the socket
     * it came through.  Packet information is switched on, so that every
     * datagram says which local address it was sent to, and so is not being
     * told on a later receive that an earlier send hit a closed port -- which
     * Windows does by default and which would fail a receive over a datagram
     * that had nothing to do with it.
     * \~spanish
     * El backend se lo queda y lo cierra en @c release.  Un socket v6 es SOLO v6:
     * uno de doble pila entregaria los extremos v4 como direcciones v6 mapeadas,
     * y el mismo extremo tendria entonces dos grafias segun el socket por el que
     * llegara.  Se enciende la informacion del paquete, para que cada datagrama
     * diga a que direccion local se mando, y se apaga que una recepcion posterior
     * cuente que un envio anterior dio con un puerto cerrado -- que Windows hace
     * por defecto y que haria fallar una recepcion por un datagrama que no tenia
     * nada que ver.
     * \~
     *
     * @param host  \~english the address, as text  \~spanish la direccion, como texto  \~
     * @param port  \~english the port, or zero for any  \~spanish el puerto, o cero para cualquiera  \~
     * @param bound \~english where the address it got goes
     *              \~spanish donde va la direccion que le toco  \~
     * @return      \~english the socket, or -1 with @c last_error set
     *              \~spanish el socket, o -1 con @c last_error puesto  \~
     */
    int32_t open_datagram(const char *host, uint16_t port,
                          NetAddress &bound) noexcept;

    /// \~english What happened to datagrams.  \~spanish Lo que les paso a los datagramas.  \~
    const DatagramCounts &datagrams() const noexcept { return dgram_counts_; }

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *out, size_t cap, int timeout_ms) noexcept override;
    /// \~english The name it is chosen by; the only place it is written.
    /// \~spanish El nombre por el que se elige; el unico sitio donde esta escrito.  \~
    static constexpr const char *kName = "iocp";

    const char *name() const noexcept override { return kName; }

    /**
     * @brief
     * \~english What the system said last time something failed.
     * \~spanish Lo que dijo el sistema la ultima vez que algo fallo.
     * \~
     *
     * \~english
     * Because a backend that returns false and says nothing is a backend whose
     * failures are all the same failure.  Whoever is looking needs the number
     * the system gave, not the fact that there was one.
     *
     * \~spanish
     * Porque un backend que devuelve false y no dice nada es un backend cuyos
     * fallos son todos el mismo fallo.  Quien mire necesita el numero que dio el
     * sistema, no que hubiera uno.
     * \~
     */
    int32_t last_error() const noexcept { return last_error_; }

    /// \~english How many operations the kernel is holding.
    /// \~spanish Cuantas operaciones tiene el nucleo.  \~
    size_t in_flight() const noexcept { return in_flight_; }

    /**
     * @brief
     * \~english How many operations @c release had to leave with the kernel.
     * \~spanish Cuantas operaciones tuvo que dejarle @c release al nucleo.
     * \~
     *
     * \~english
     * Zero unless the kernel did not give back, in time, operations that were
     * cancelled.  Their records are then deliberately NOT freed -- the kernel
     * may still write into them -- and this says how many were left, across
     * every @c release: a number that is not zero is memory kept on purpose
     * and a sign that something did not answer a cancellation.
     * \~spanish
     * Cero salvo que el nucleo no devolviera a tiempo operaciones canceladas.
     * Sus registros NO se liberan entonces, a proposito -- el nucleo todavia
     * puede escribir en ellos --, y esto dice cuantas se quedaron, sumando todos
     * los @c release: un numero que no es cero es memoria guardada a proposito y
     * la senal de que algo no contesto a una cancelacion.
     * \~
     */
    uint64_t stranded() const noexcept { return stranded_; }

    /**
     * @brief
     * \~english Posts a packet with no operation behind it; any thread (HVX-5, 6.4).
     * \~spanish Pone un paquete sin operacion detras; cualquier hilo (HVX-5, 6.4).
     * \~
     *
     * \~english
     * What the system offers for this: it ends a wait in
     * `GetQueuedCompletionStatusEx`, needs no handle to the waiting thread and
     * runs nothing in the middle of the wait, as an APC would.  The packet
     * carries no record, so @c wait passes over it.
     * \~spanish
     * Lo que el sistema ofrece para esto: acaba una espera en
     * `GetQueuedCompletionStatusEx`, no necesita el handle del hilo que espera y
     * no ejecuta nada en mitad de la espera, como lo haria una APC.  El paquete
     * no lleva registro, asi que @c wait lo salta.
     * \~
     */
    bool wake() noexcept override;

    /// \~english What the system said when a wake failed.  \~spanish Lo que dijo el sistema cuando fallo un despertar.  \~
    int32_t wake_error() const noexcept { return wake_error_.load(std::memory_order_relaxed); }

    /**
     * @brief
     * \~english Gives everything back and stops listening.
     * \~spanish Devuelve todo y deja de escuchar.
     * \~
     *
     * \~english
     * Everything the kernel holds is cancelled and WAITED for before a record
     * is freed, including reads and writes on sockets that belong to the
     * caller: until its completion is taken, an operation still names its
     * record and its buffer, and the kernel writes into both whenever it
     * finishes.  The caller's sockets stay open.
     * \~spanish
     * Todo lo que tiene el nucleo se cancela y se ESPERA antes de liberar un
     * registro, incluidas las lecturas y escrituras en sockets que son de quien
     * llama: hasta que se recoge su finalizacion, una operacion sigue nombrando
     * su registro y su buffer, y el nucleo escribe en los dos cuando acaba.  Los
     * sockets de quien llama siguen abiertos.
     * \~
     */
    void release() noexcept;

  private:
    /// \~english Cancels every operation the kernel holds on a caller's socket.
    /// \~spanish Cancela toda operacion que tenga el nucleo en un socket de quien llama.  \~
    void cancel_pending() noexcept;

    /**
     * @brief
     * \~english Takes back from the port every operation still held.
     * \~spanish Recoge del puerto toda operacion que siga pendiente.
     * \~
     *
     * @return \~english false, with @c last_error set, if the kernel stopped answering first
     *         \~spanish false, con @c last_error puesto, si el nucleo dejo de contestar antes  \~
     */
    bool drain() noexcept;

    /// \~english Operations left with the kernel by @c release.
    /// \~spanish Operaciones que @c release le dejo al nucleo.  \~
    uint64_t stranded_ = 0;

    std::atomic<int32_t> wake_error_{0};

    /**
     * \~english
     * One operation the kernel is holding.  Defined in the translation unit,
     * because what it really contains is an `OVERLAPPED` and a socket, and
     * naming either of those here would be the Windows headers coming back.
     * \~spanish
     * Una operacion que tiene el nucleo.  Definido en la unidad de traduccion,
     * porque lo que tiene de verdad dentro es un `OVERLAPPED` y un socket, y
     * nombrar cualquiera de los dos aqui serian las cabeceras de Windows
     * volviendo.
     * \~
     */
    struct Context;

    Context *take() noexcept;
    void give(Context *c) noexcept;

    /**
     * @brief
     * \~english Remembers a completion for an operation that never started.
     * \~spanish Recuerda una finalizacion de una operacion que no llego a empezar.
     * \~
     *
     * \~english
     * An operation the system refuses ON THE SPOT produces no completion
     * packet, and it still has to produce a completion: whoever asked is
     * holding a buffer and waiting to be told what became of it.  Returning
     * false instead would say "there was no room to ask", which is a different
     * thing that the caller answers by trying again -- so a read that failed
     * would be asked for for ever.
     *
     * \~spanish
     * Una operacion que el sistema rechaza EN EL ACTO no produce ningun paquete
     * de finalizacion, y tiene que producir una finalizacion igual: quien la
     * pidio tiene un buffer en la mano esperando que le digan en que quedo.
     * Devolver false en su lugar diria "no habia sitio para pedirlo", que es otra
     * cosa y que quien llama contesta volviendo a intentarlo -- asi que una
     * lectura que fallo se pediria para siempre.
     * \~
     */
    bool remember_failure(const Op &op, int32_t error) noexcept;

    bool start_accept(const Op &op, Context *c) noexcept;
    bool start_ready(const Op &op, Context *c) noexcept;
    bool start_recv(const Op &op, Context *c) noexcept;
    bool start_send(const Op &op, Context *c) noexcept;
    bool start_close(const Op &op) noexcept;

    /**
     * @brief
     * \~english Ends the read outstanding on @p op's socket, and nothing else of it (OpKind::Cancel).
     * \~spanish Acaba la lectura pendiente en el socket de @p op, y nada mas suyo (OpKind::Cancel).
     * \~
     *
     * \~english
     * `CancelIoEx` on the READ's own OVERLAPPED: cancelling everything on
     * the socket would also end a write still going out, and closing with
     * courtesy is letting that write finish.
     * \~spanish
     * `CancelIoEx` sobre el OVERLAPPED de la LECTURA: cancelar todo lo del socket
     * acabaria tambien una escritura que todavia sale, y cerrar con cortesia es
     * dejar que acabe.
     * \~
     */
    bool start_cancel(const Op &op) noexcept;

    /// \~english Remembers @p c as the read outstanding on its socket.  \~spanish Recuerda @p c como la lectura pendiente en su socket.  \~
    void note_read(const Context *c) noexcept;

    /// \~english Forgets @p c as the read of its socket, if it was.  \~spanish Olvida @p c como la lectura de su socket, si lo era.  \~
    void forget_read(const Context *c) noexcept;

    /// \~english Posts a receive of one datagram.
    /// \~spanish Pone la recepcion de un datagrama.  \~
    bool start_recv_from(const Op &op, Context *c) noexcept;

    /// \~english Starts sending one datagram.
    /// \~spanish Empieza a mandar un datagrama.  \~
    bool start_send_to(const Op &op, Context *c) noexcept;

    /**
     * @brief
     * \~english What a datagram operation came to, from what Windows said.
     * \~spanish En que quedo una operacion de datagramas, por lo que dijo Windows.
     * \~
     *
     * @return \~english the completion's result  \~spanish el resultado de la finalizacion  \~
     */
    int32_t finish_datagram(Context *c, bool fine, uint32_t moved,
                            uint32_t flags) noexcept;

    /// \~english Closes every datagram socket.
    /// \~spanish Cierra todos los sockets de datagramas.  \~
    void close_datagrams() noexcept;

    /// \~english The datagram sockets opened.
    /// \~spanish Los sockets de datagramas abiertos.  \~
    DatagramSockets dgram_;

    /// \~english `WSARecvMsg`, looked up at run time like `AcceptEx`.
    /// \~spanish `WSARecvMsg`, buscado en ejecucion como `AcceptEx`.  \~
    void *recvmsg_fn_ = nullptr;

    DatagramCounts dgram_counts_;

    /// \~english The completion port.  \~spanish El puerto de finalizacion.  \~
    void *iocp_ = nullptr;

    /// \~english The listening socket.  \~spanish El socket de escucha.  \~
    uintptr_t listener_ = static_cast<uintptr_t>(-1);

    /// \~english The listener's address family, which every accepted socket must share.
    /// \~spanish La familia de direcciones del socket de escucha, que tienen que compartir los aceptados.  \~
    int32_t listener_family_ = 0;

    /// \~english `AcceptEx`, looked up at run time as Windows requires.
    /// \~spanish `AcceptEx`, buscado en ejecucion como exige Windows.  \~
    void *accept_fn_ = nullptr;

    Context *contexts_ = nullptr;
    uint32_t context_count_ = 0;

    /**
     * \~english
     * The read outstanding on each socket, by socket: what a cancel looks up.
     * A hash and not an array because sockets on Windows are handles, not
     * small dense numbers; sized by the contexts, since a read is one.
     * \~spanish
     * La lectura pendiente en cada socket, por socket: lo que busca una
     * cancelacion.  Un hash y no un array porque en Windows los sockets son
     * handles, no numeros pequenos y densos; del tamano de los contextos, porque
     * una lectura es uno.
     * \~
     */
    IdIndex reads_;
    uint32_t free_head_ = 0xFFFFFFFF;
    size_t in_flight_ = 0;

    BufferPool *pool_ = nullptr;

    /**
     * \~english
     * The completions of operations that failed before they began.  Fixed,
     * like everything else here: what fills it is this end's own refusals, and
     * a queue that grew would be one more thing a busy moment could make
     * unbounded.
     * \~spanish
     * Las finalizaciones de operaciones que fallaron antes de empezar.  Fija,
     * como todo lo demas de aqui: lo que la llena son los rechazos de este mismo
     * extremo, y una cola que creciera seria una cosa mas que un momento de mucho
     * trabajo puede volver ilimitada.
     * \~
     */
    Completion failed_[64];
    size_t failed_count_ = 0;

    uint16_t port_ = 0;
    int32_t last_error_ = 0;
    bool started_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_IOCP_BACKEND_H
