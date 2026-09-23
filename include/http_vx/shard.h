/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/shard.h
 * @brief
 * \~english The loop: who holds what, and for exactly how long.
 * \~spanish El bucle: quien tiene que, y exactamente cuanto tiempo.
 * \~
 *
 * \~english
 * Everything the other files made, driven.  A shard owns its connections, its
 * buffers, its deadlines and its backend, and it owns them ALONE -- R4 says a
 * connection never changes shard, so nothing here is shared with another
 * thread and nothing here is atomic.  That is not an optimisation; it is what
 * lets every structure underneath be a plain array.
 *
 * **What the loop is actually for is deciding who holds a buffer.**  The
 * parsing was decided elsewhere, the framing was decided elsewhere; what is
 * left, and what nothing else can do, is:
 *
 *  - a connection gets a buffer when there is a reason to read and gives it
 *    back the moment there is not.  R1 is not a property of the buffer class,
 *    it is a property of this loop, and it is where it is either true or
 *    quietly false;
 *  - a buffer is the operating system's while an operation on it is
 *    outstanding, so giving it back has to wait for the completion -- not for
 *    the decision that it is no longer wanted;
 *  - and a deadline is pushed forward by activity and only fires on its
 *    absence, which means arming it is the most frequent thing the loop does.
 *
 * Those three are the whole file, and each of them fails silently when it is
 * wrong.
 *
 * \~spanish
 * Todo lo que hicieron los otros ficheros, movido.  Un fragmento posee sus
 * conexiones, sus buffers, sus plazos y su backend, y los posee EL SOLO -- la
 * R4 dice que una conexion no cambia de fragmento, asi que aqui no se comparte
 * nada con otro hilo y aqui no hay nada atomico.  Eso no es una optimizacion;
 * es lo que permite que todas las estructuras de debajo sean arrays pelados.
 *
 * **Para lo que sirve el bucle de verdad es para decidir quien tiene un
 * buffer.**  El analisis se decidio en otro sitio, el entramado se decidio en
 * otro sitio; lo que queda, y lo que no puede hacer nada mas, es:
 *
 *  - una conexion recibe un buffer cuando hay razon para leer y lo devuelve en
 *    cuanto no la hay.  La R1 no es una propiedad de la clase buffer, es una
 *    propiedad de este bucle, y aqui es donde es cierta o falsa por lo bajo;
 *  - un buffer es del sistema operativo mientras tenga una operacion
 *    pendiente, asi que devolverlo tiene que esperar a la finalizacion -- no a
 *    la decision de que ya no hace falta;
 *  - y un plazo lo empuja la actividad y solo vence con su ausencia, lo que
 *    quiere decir que armarlo es lo que mas veces hace el bucle.
 *
 * Esas tres son el fichero entero, y las tres fallan en silencio cuando estan
 * mal.
 *
 * \~
 */
#ifndef HTTP_VX_SHARD_H
#define HTTP_VX_SHARD_H

#include "http_vx/buffer_pool.h"
#include "http_vx/conn_table.h"
#include "http_vx/reactor_ops.h"
#include "http_vx/timer_wheel.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What a connection is doing.
 * \~spanish Que esta haciendo una conexion.
 * \~
 *
 * \~english
 * Four states, and they are about OPERATIONS rather than about HTTP: the loop
 * does not know what a request is and does not need to.  What it needs to know
 * is whether the operating system is holding this connection's buffer, because
 * that is the question that decides whether the buffer may be given back.
 *
 * \~spanish
 * Cuatro estados, y hablan de OPERACIONES y no de HTTP: el bucle no sabe lo que
 * es una peticion y no le hace falta.  Lo que le hace falta saber es si el
 * sistema operativo tiene el buffer de esta conexion, porque esa es la pregunta
 * que decide si se puede devolver.
 *
 * \~
 */
enum class ConnState : uint16_t {
    /// \~english Nothing is outstanding and nothing is owed.
    /// \~spanish No hay nada pendiente y no se debe nada.  \~
    Idle,

    /// \~english A read is with the operating system.
    /// \~spanish Hay una lectura en el sistema operativo.  \~
    Reading,

    /// \~english A write is with the operating system.
    /// \~spanish Hay una escritura en el sistema operativo.  \~
    Writing,

    /**
     * \~english
     * It is over, and the loop is waiting for what the operating system still
     * holds.  A connection does not leave until its outstanding operations
     * come back, because until then its buffer is not this shard's to give
     * away.
     * \~spanish
     * Se acabo, y el bucle espera lo que todavia tiene el sistema operativo.
     * Una conexion no se va hasta que vuelvan sus operaciones pendientes,
     * porque hasta entonces su buffer no es de este fragmento para darlo.
     * \~
     */
    Closing,
};

/**
 * @brief
 * \~english What the shard does with the bytes.
 * \~spanish Lo que hace el fragmento con los bytes.
 * \~
 *
 * \~english
 * The loop's one hole, and it is this shape on purpose: bytes in, bytes out,
 * and no mention of HTTP anywhere.  A shard that knew what a request was would
 * be a shard that had to be changed to serve HTTP/3, and the whole point of
 * everything under `proto/` is that it does not.
 *
 * \~spanish
 * El unico hueco del bucle, y tiene esta forma a proposito: bytes que entran,
 * bytes que salen, y ninguna mencion a HTTP en ningun sitio.  Un fragmento que
 * supiera lo que es una peticion seria un fragmento al que habria que cambiar
 * para servir HTTP/3, y toda la gracia de lo que hay bajo `proto/` es que no.
 *
 * \~
 */
class Service {
  public:
    virtual ~Service();

    Service() noexcept = default;
    Service(const Service &) = delete;
    Service &operator=(const Service &) = delete;

    /**
     * @brief
     * \~english Bytes arrived on @p c; write any answer into @p out.
     * \~spanish Llegaron bytes por @p c; escribe la respuesta en @p out.
     * \~
     *
     * \~english
     * @p in points into the connection's read buffer and stops being valid
     * when this returns -- R13: the body is not copied, so what is handed over
     * is a view and the service either uses it or keeps its own copy.
     *
     * \~spanish
     * @p in apunta al buffer de lectura de la conexion y deja de valer cuando
     * esto vuelve -- R13: el cuerpo no se copia, asi que lo que se entrega es
     * una vista y el servicio la usa o se guarda su propia copia.
     *
     * \~
     * @param c   \~english which connection  \~spanish que conexion  \~
     * @param in  \~english the bytes  \~spanish los bytes  \~
     * @param n   \~english how many  \~spanish cuantos  \~
     * @param out \~english where an answer goes  \~spanish donde va una respuesta  \~
     * @return    \~english false to end the connection
     *            \~spanish false para acabar la conexion  \~
     */
    virtual bool on_bytes(ConnHandle c, const uint8_t *in, size_t n,
                          Buffer &out) noexcept = 0;

    /// \~english A connection arrived.  \~spanish Llego una conexion.  \~
    virtual void on_open(ConnHandle c) noexcept { (void)c; }

    /// \~english And went.  \~spanish Y se fue.  \~
    virtual void on_close(ConnHandle c) noexcept { (void)c; }
};

/**
 * @brief
 * \~english What a shard is built with.
 * \~spanish Con que se hace un fragmento.
 * \~
 */
struct ShardConfig {
    /// \~english How many connections at once.
    /// \~spanish Cuantas conexiones a la vez.  \~
    uint32_t connections = 1024;

    /**
     * \~english
     * How many buffers.  Deliberately fewer than the connections, which is R1
     * as a number: a connection that is not mid-message does not have one, and
     * on any real connection that is almost all of the time.
     * \~spanish
     * Cuantos buffers.  A proposito menos que las conexiones, que es la R1 como
     * numero: una conexion que no esta a mitad de mensaje no tiene, y en
     * cualquier conexion real eso es casi todo el tiempo.
     * \~
     */
    uint32_t buffers = 128;

    /// \~english The most a buffer may keep between tenants.
    /// \~spanish Lo mas que puede guardar un buffer entre inquilinos.  \~
    size_t buffer_ceiling = 1 << 20;

    /// \~english How long a connection may say nothing, in ticks.
    /// \~spanish Cuanto puede callarse una conexion, en tics.  \~
    uint32_t idle_ticks = 60;

    /// \~english How many ticks the deadline wheel covers.
    /// \~spanish Cuantos tics abarca la rueda de plazos.  \~
    uint32_t wheel_slots = 4096;

    /// \~english How much to ask for in one read.
    /// \~spanish Cuanto pedir en una lectura.  \~
    uint32_t read_size = 16384;

    /// \~english How many completions to take at once.
    /// \~spanish Cuantas finalizaciones coger de una vez.  \~
    size_t batch = 64;
};

/**
 * @brief
 * \~english One thread's worth of server.
 * \~spanish Lo que le toca de servidor a un hilo.
 * \~
 */
class Shard {
  public:
    Shard() noexcept = default;

    Shard(const Shard &) = delete;
    Shard &operator=(const Shard &) = delete;

    /**
     * @brief
     * \~english Makes it ready.
     * \~spanish Lo deja listo.
     * \~
     *
     * @param cfg     \~english the sizes  \~spanish los tamanos  \~
     * @param io      \~english where operations go
     *                \~spanish donde van las operaciones  \~
     * @param service \~english what to do with the bytes
     *                \~spanish que hacer con los bytes  \~
     * @param now     \~english what tick it is  \~spanish en que tic se esta  \~
     * @return        \~english false if the memory could not be had
     *                \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(const ShardConfig &cfg, Backend &io, Service &service,
               uint64_t now) noexcept;

    /**
     * @brief
     * \~english Takes a connection that has arrived.
     * \~spanish Coge una conexion que ha llegado.
     * \~
     *
     * \~english
     * The socket comes from outside because accepting is the backend's, and
     * which shard a connection lands on is decided above both (R5).  What
     * happens here is everything else: a slot, a deadline, and the first read
     * asked for.
     *
     * \~spanish
     * El socket viene de fuera porque aceptar es del backend, y en que fragmento
     * cae una conexion se decide por encima de los dos (R5).  Lo que pasa aqui
     * es todo lo demas: una casilla, un plazo, y la primera lectura pedida.
     *
     * \~
     * @param fd  \~english the socket  \~spanish el socket  \~
     * @param now \~english what tick it is  \~spanish en que tic se esta  \~
     * @return    \~english the handle, or an invalid one when full
     *            \~spanish la referencia, o una invalida cuando esta lleno  \~
     */
    ConnHandle adopt(int32_t fd, uint64_t now) noexcept;

    /**
     * @brief
     * \~english Takes whatever the operating system has finished.
     * \~spanish Coge lo que haya acabado el sistema operativo.
     * \~
     *
     * @param now        \~english what tick it is  \~spanish en que tic se esta  \~
     * @param timeout_ms \~english how long to wait; negative is forever
     *                   \~spanish cuanto esperar; negativo es para siempre  \~
     * @return           \~english how many completions were dealt with
     *                   \~spanish cuantas finalizaciones se atendieron  \~
     */
    size_t poll(uint64_t now, int timeout_ms) noexcept;

    /**
     * @brief
     * \~english Closes whatever has said nothing for too long.
     * \~spanish Cierra lo que lleve demasiado tiempo callado.
     * \~
     *
     * @param now \~english what tick it is  \~spanish en que tic se esta  \~
     * @return    \~english how many were closed
     *            \~spanish cuantas se cerraron  \~
     */
    size_t expire(uint64_t now) noexcept;

    /**
     * @brief
     * \~english Ends @p c.
     * \~spanish Acaba @p c.
     * \~
     *
     * \~english
     * It does not necessarily go now.  A connection with an operation still in
     * the operating system waits for it to come back, because until then its
     * buffer is not this shard's to give away -- so this may leave it
     * @c Closing and finish later.
     *
     * \~spanish
     * No se va necesariamente ahora.  Una conexion con una operacion todavia en
     * el sistema operativo espera a que vuelva, porque hasta entonces su buffer
     * no es de este fragmento para darlo -- asi que esto puede dejarla
     * @c Closing y acabar despues.
     *
     * \~
     * @param c \~english which connection  \~spanish que conexion  \~
     */
    void close(ConnHandle c) noexcept;

    /// \~english The connections.  \~spanish Las conexiones.  \~
    ConnTable &conns() noexcept { return conns_; }

    /// \~english The buffers.  \~spanish Los buffers.  \~
    BufferPool &buffers() noexcept { return pool_; }

    /// \~english The deadlines.  \~spanish Los plazos.  \~
    TimerWheel &deadlines() noexcept { return wheel_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /// \~english Gets a buffer and asks for a read.
    /// \~spanish Consigue un buffer y pide una lectura.  \~
    bool start_read(ConnHandle c, uint64_t now) noexcept;

    /// \~english Lets go of whatever @p h is holding.
    /// \~spanish Suelta lo que sea que tenga @p h.  \~
    void let_go(ConnHandle c, ConnHot &h) noexcept;

    void on_read(const Completion &done, uint64_t now) noexcept;
    void on_write(const Completion &done, uint64_t now) noexcept;

    ConnTable conns_;
    BufferPool pool_;
    TimerWheel wheel_;

    Backend *io_ = nullptr;
    Service *service_ = nullptr;
    ShardConfig cfg_;
};

} // namespace http_vx

#endif // HTTP_VX_SHARD_H
