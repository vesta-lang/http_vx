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
#include "http_vx/datagram_service.h"
#include "http_vx/kick_queue.h"
#include "http_vx/open_port.h"
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
enum ConnFlag : uint16_t {
    /**
     * \~english
     * A read is with the operating system.  At most ONE, and that is not a
     * limitation: two reads outstanding on the same stream socket complete in
     * whatever order the kernel finishes them, so the bytes would arrive in
     * two buffers with no way to say which came first.  A stream that can be
     * reordered is not a stream.
     * \~spanish
     * Hay una lectura en el sistema operativo.  Como mucho UNA, y eso no es una
     * limitacion: dos lecturas pendientes sobre el mismo socket de flujo acaban
     * en el orden en que las termine el nucleo, asi que los bytes llegarian en
     * dos buffers sin forma de decir cual iba antes.  Un flujo que se puede
     * desordenar no es un flujo.
     * \~
     */
    kReadPending = 1,

    /**
     * \~english
     * A write is with the operating system.  Also at most one, for the same
     * reason read the other way round: two writes would interleave on the
     * wire.  What there may be more of is answers WAITING, and those go in the
     * queue.
     * \~spanish
     * Hay una escritura en el sistema operativo.  Tambien como mucho una, por lo
     * mismo leido al reves: dos escrituras se entrelazarian en el cable.  De lo
     * que si puede haber mas es de respuestas ESPERANDO, y esas van en la cola.
     * \~
     */
    kWritePending = 2,

    /**
     * \~english
     * It is over, and the loop is waiting for what the operating system still
     * holds.  A connection does not leave until its outstanding operations
     * come back, because until then their buffers are not this shard's to give
     * away.
     * \~spanish
     * Se acabo, y el bucle espera lo que todavia tiene el sistema operativo.
     * Una conexion no se va hasta que vuelvan sus operaciones pendientes,
     * porque hasta entonces sus buffers no son de este fragmento para darlos.
     * \~
     */
    kClosing = 4,

    /**
     * \~english
     * Its bytes are not handed to the service and nothing more is read: an
     * HTTP/1.1 response is open and the requests behind it wait (HVX-5, 7.1).
     * \~spanish
     * Sus bytes no se le dan al servicio y no se lee mas: hay una respuesta de
     * HTTP/1.1 abierta y las peticiones de detras esperan (HVX-5, 7.1).
     * \~
     */
    kHeld = 8,

    /**
     * \~english
     * The service asked for @c Service::on_writable, which comes once nothing
     * of this connection is going out.
     * \~spanish
     * El servicio pidio @c Service::on_writable, que llega en cuanto no sale
     * nada de esta conexion.
     * \~
     */
    kWantWritable = 16,

    /**
     * \~english
     * It stopped being held while the service was being called, so what it
     * left is handed over once that call returns.
     * \~spanish
     * Dejo de estar retenida mientras se llamaba al servicio, asi que lo que
     * dejo se entrega en cuanto vuelva esa llamada.
     * \~
     */
    kResume = 32,

    /// \~english Closed because its deadline passed.  \~spanish Cerrada porque vencio su plazo.  \~
    kExpired = 64,
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
     * \~english Bytes arrived on @p c; consume what you used, answer into @p out.
     * \~spanish Llegaron bytes por @p c; consume lo que uses, contesta en @p out.
     * \~
     *
     * \~english
     * **The service consumes, and what it leaves stays.**  A request arrives
     * in as many reads as the network feels like -- a head split across two
     * packets is the ordinary case, not a corner -- so a service that was
     * handed a view that died on return would have to copy the leftover
     * somewhere of its own, and then every protocol would carry its own
     * buffer beside the one it was just given.
     *
     * So what comes in is the BUFFER.  The service takes what makes a whole
     * message, @c Buffer::consume says so, and whatever is left is still
     * there when the next read lands after it.  The shard keeps the buffer for
     * exactly as long as something is left in it, which is also what R1 means:
     * a connection mid-message legitimately holds one, and a connection
     * between messages does not.
     *
     * \~spanish
     * **El servicio consume, y lo que deja se queda.**  Una peticion llega en
     * tantas lecturas como le apetezca a la red -- una cabeza partida entre dos
     * paquetes es el caso corriente, no una esquina -- asi que un servicio al
     * que se le diera una vista que muere al volver tendria que copiar el resto
     * a un sitio suyo, y entonces cada protocolo llevaria su propio buffer al
     * lado del que le acaban de dar.
     *
     * Asi que lo que entra es el BUFFER.  El servicio coge lo que forme un
     * mensaje entero, lo dice con @c Buffer::consume, y lo que quede sigue ahi
     * cuando caiga detras la lectura siguiente.  El fragmento se queda el buffer
     * exactamente mientras quede algo dentro, que es ademas lo que quiere decir
     * la R1: una conexion a mitad de mensaje tiene uno con todo derecho, y una
     * entre mensajes no.
     *
     * \~
     * @param c   \~english which connection  \~spanish que conexion  \~
     * @param in  \~english what has arrived and not been used yet
     *            \~spanish lo que ha llegado y no se ha usado todavia  \~
     * @param out \~english where an answer goes  \~spanish donde va una respuesta  \~
     * @return    \~english false to end the connection
     *            \~spanish false para acabar la conexion  \~
     */
    virtual bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept = 0;

    /// \~english A connection arrived.  \~spanish Llego una conexion.  \~
    virtual void on_open(ConnHandle c) noexcept { (void)c; }

    /// \~english And went.  \~spanish Y se fue.  \~
    virtual void on_close(ConnHandle c) noexcept { (void)c; }

    /**
     * @brief
     * \~english Gives the service its shard's side of open responses (HVX-5); once, at @c Shard::reset.
     * \~spanish Le da al servicio el lado de su fragmento de las respuestas abiertas (HVX-5); una vez, en @c Shard::reset.
     * \~
     *
     * \~english
     * A service that wraps another passes it on.  One that never opens a
     * response ignores it.
     * \~spanish
     * Un servicio que envuelve a otro se lo pasa.  Uno que nunca abre una
     * respuesta lo ignora.
     * \~
     */
    virtual void attach(StreamPort *port) noexcept { (void)port; }

    /**
     * @brief
     * \~english Room on @p c, asked for with @c StreamPort::want_writable: fill what is open into @p out.
     * \~spanish Hay sitio en @p c, pedido con @c StreamPort::want_writable: rellena en @p out lo que este abierto.
     * \~
     *
     * \~english
     * At most @p budget bytes are appended to @p out in one call, framing
     * included.  TLS asks for one record's worth, so what the service writes
     * is sealed where it lies, and asks again while the service writes; what
     * did not fit waits for the next call.
     * \~spanish
     * En una llamada se anaden a @p out como mucho @p budget bytes, enmarcado
     * incluido.  TLS pide lo que cabe en un registro, para que lo que escriba el
     * servicio se selle donde esta, y vuelve a pedir mientras el servicio
     * escriba; lo que no cupo espera a la llamada siguiente.
     * \~
     *
     * @param budget \~english the most bytes this call may append  \~spanish lo mas que puede anadir esta llamada  \~
     * @return \~english false to end the connection once @p out has gone
     *         \~spanish false para acabar la conexion cuando haya salido @p out  \~
     */
    virtual bool on_writable(ConnHandle c, Buffer &out, size_t budget) noexcept {
        (void)c;
        (void)out;
        (void)budget;
        return true;
    }
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

    /**
     * \~english
     * How many answers may wait behind the one going out before the loop
     * stops reading from that connection.
     *
     * It is flow control and not a limit on the protocol: a peer that keeps
     * sending requests without reading the answers is a peer making this
     * server hold its output, and the answer is to stop taking more in.  The
     * bytes wait in the kernel's receive queue, which is where they belong,
     * and reading starts again as soon as an answer goes out.
     *
     * \~spanish
     * Cuantas respuestas pueden esperar detras de la que esta saliendo antes de
     * que el bucle deje de leer de esa conexion.
     *
     * Es control de flujo y no un limite del protocolo: un extremo que siga
     * mandando peticiones sin leer las respuestas es un extremo haciendo que
     * este servidor le guarde su salida, y la respuesta es dejar de aceptar mas.
     * Los bytes esperan en la cola de recepcion del nucleo, que es donde les
     * toca, y se vuelve a leer en cuanto salga una respuesta.
     * \~
     */
    uint16_t max_queued = 8;

    /// \~english How many completions to take at once.
    /// \~spanish Cuantas finalizaciones coger de una vez.  \~
    size_t batch = 64;

    /**
     * \~english
     * How many accepts this shard keeps outstanding, and zero means it does
     * not accept at all.
     *
     * More than one because accepting is a completion like any other: with a
     * single one posted, every connection that arrives while the previous
     * accept is being dealt with waits in the kernel's backlog for a round of
     * the loop.  Several posted means several arrive at once, which is what
     * happens when a server is under load and is the only time it matters.
     *
     * **Zero is the default and it is not a disabled feature.**  R5 says
     * accepting is spread across shards, and how it is spread is the platform's
     * answer rather than this one's: one listening socket per shard where the
     * system distributes them, or one shard accepting and handing sockets to
     * the others where it does not.  A shard that accepted by default would
     * make the first arrangement the only one anybody ever wrote.
     *
     * \~spanish
     * Cuantas aceptaciones mantiene pendientes este fragmento, y cero quiere
     * decir que no acepta nada.
     *
     * Mas de una porque aceptar es una finalizacion como cualquier otra: con una
     * sola puesta, cada conexion que llegue mientras se atiende la anterior
     * espera una vuelta del bucle en la cola del nucleo.  Varias puestas quiere
     * decir que llegan varias a la vez, que es lo que pasa cuando un servidor
     * tiene trabajo y es la unica vez que importa.
     *
     * **Cero es el valor por defecto y no es una funcion apagada.**  La R5 dice
     * que aceptar se reparte entre fragmentos, y COMO se reparte es la respuesta
     * de la plataforma y no de esto: un socket de escucha por fragmento donde el
     * sistema los reparte, o un fragmento aceptando y pasandoles los sockets a
     * los demas donde no.  Un fragmento que aceptara por defecto haria que el
     * primer arreglo fuera el unico que escribiera nadie.
     * \~
     */
    uint32_t accepts = 0;

    /**
     * \~english
     * How many responses may be open at once on this shard, and on one
     * connection (HVX-5, 8).  A request that would go over is answered 503.
     * \~spanish
     * Cuantas respuestas pueden estar abiertas a la vez en este fragmento, y en
     * una conexion (HVX-5, 8).  Una peticion que se pasaria se contesta 503.
     * \~
     */
    uint32_t max_open = 1024;
    uint16_t max_open_per_conn = 16;

    /// \~english The most one @c Service::on_writable call may write.  \~spanish Lo mas que puede escribir una llamada a @c Service::on_writable.  \~
    uint32_t write_size = 65536;
};

/**
 * @brief
 * \~english What a shard refused or could not serve, each counted apart.
 * \~spanish Lo que un fragmento rechazo o no pudo servir, cada cosa contada aparte.
 * \~
 */
struct ShardCounts {
    /**
     * \~english
     * Stream completions -- a read, a write, a notice, an accept -- that
     * reached a shard with no stream side.  Each gave its buffer back and an
     * accepted socket was closed; a number that moves means something is
     * submitting stream operations to a shard that cannot serve them.
     * \~spanish
     * Finalizaciones de flujo -- una lectura, una escritura, un aviso, una
     * aceptacion -- que llegaron a un fragmento sin lado de flujos.  Cada una
     * devolvio su buffer y se cerro el socket aceptado; un numero que se mueve
     * quiere decir que algo esta entregando operaciones de flujo a un fragmento
     * que no puede servirlas.
     * \~
     */
    uint64_t unserved = 0;

    /// \~english Sockets @c adopt refused because there is no stream side.
    /// \~spanish Sockets que @c adopt rechazo porque no hay lado de flujos.  \~
    uint64_t refused_adoptions = 0;

    /**
     * \~english
     * Closes whose outstanding read could not be cancelled: the backend's
     * queue was full.  Such a connection leaves when its peer next speaks
     * or goes, not before.
     * \~spanish
     * Cierres cuya lectura pendiente no se pudo cancelar: la cola del backend
     * estaba llena.  Una conexion asi se va cuando su otro extremo vuelva a
     * hablar o se vaya, no antes.
     * \~
     */
    uint64_t uncancelled = 0;
};

/**
 * @brief
 * \~english One thread's worth of server.
 * \~spanish Lo que le toca de servidor a un hilo.
 * \~
 */
class Shard final : public StreamPort {
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
     * \~english Makes it ready with no stream side: a shard for datagrams only.
     * \~spanish Lo deja listo sin lado de flujos: un fragmento solo de datagramas.
     * \~
     *
     * \~english
     * What a UDP-only server needs, followed by @c attach_datagrams.  Such a
     * shard adopts no connection (@c adopt returns an invalid handle, counted
     * in @c ShardCounts::refused_adoptions) and a configuration that asks it
     * to accept is refused here, where it is a sentence.  A stream completion
     * that reaches it anyway -- from an operation somebody else submitted --
     * is NOT dropped: its buffer goes back, an accepted socket is closed, and
     * it is counted in @c ShardCounts::unserved.
     *
     * The connection table and the deadline wheel are still made, sized by
     * @p cfg as always; a datagram-only caller keeps @c connections small.
     * \~spanish
     * Lo que necesita un servidor solo UDP, seguido de @c attach_datagrams.  Un
     * fragmento asi no adopta ninguna conexion (@c adopt devuelve una referencia
     * invalida, contada en @c ShardCounts::refused_adoptions) y una
     * configuracion que le pida aceptar se rechaza aqui, donde es una frase.
     * Una finalizacion de flujo que le llegue igualmente -- de una operacion
     * que entrego otro -- NO se tira: su buffer vuelve, un socket aceptado se
     * cierra, y se cuenta en @c ShardCounts::unserved.
     *
     * La tabla de conexiones y la rueda de plazos se hacen igual, del tamano
     * que diga @p cfg; quien solo quiera datagramas pone @c connections pequeno.
     * \~
     *
     * @param cfg \~english the sizes  \~spanish los tamanos  \~
     * @param io  \~english where operations go  \~spanish donde van las operaciones  \~
     * @param now \~english what tick it is  \~spanish en que tic se esta  \~
     * @return    \~english false if the memory could not be had, or @p cfg asks to accept
     *            \~spanish false si no se pudo conseguir la memoria, o @p cfg pide aceptar  \~
     */
    bool reset(const ShardConfig &cfg, Backend &io, uint64_t now) noexcept;

    /// \~english Whether it has a stream side.  \~spanish Si tiene lado de flujos.  \~
    bool serves_streams() const noexcept { return service_ != nullptr; }

    /// \~english What it refused or could not serve.  \~spanish Lo que rechazo o no pudo servir.  \~
    const ShardCounts &counts() const noexcept { return counts_; }

    /**
     * @brief
     * \~english Where the open responses of this shard's connections are kicked (HVX-5).
     * \~spanish Donde se avisa a las respuestas abiertas de las conexiones de este fragmento (HVX-5).
     * \~
     *
     * \~english
     * A service opens a source here; any thread kicks it; every poll drains
     * the kicks after the completions and before the datagram side flushes.
     * \~spanish
     * Un servicio abre aqui una fuente; cualquier hilo la avisa; cada poll vacia
     * los avisos despues de las finalizaciones y antes de que el lado de
     * datagramas vacie lo suyo.
     * \~
     */
    KickQueue &kicks() noexcept { return kicks_; }
    const KickQueue &kicks() const noexcept { return kicks_; }

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

    /**
     * @brief
     * \~english Gives the shard a datagram side, driven by @p service.
     * \~spanish Le da al fragmento un lado de datagramas, movido por @p service.
     * \~
     *
     * \~english
     * After @c reset, which is where the backend and the pool come from.  From
     * here on @c poll also runs the service's timer, keeps receives posted on
     * every socket added, and pulls what the service has to send -- and the
     * @c now it is given is handed to the service as it is.
     * \~spanish
     * Despues de @c reset, que es de donde salen el backend y el pozo.  A partir
     * de aqui @c poll tambien ejecuta el temporizador del servicio, mantiene
     * puestas las recepciones de cada socket anadido, y saca lo que el servicio
     * tenga que mandar -- y el @c now que recibe se le pasa al servicio tal cual.
     * \~
     *
     * @return \~english false before @c reset or for a configuration that cannot work
     *         \~spanish false antes de @c reset o para una configuracion que no puede funcionar  \~
     */
    bool attach_datagrams(DatagramService &service,
                          const DatagramConfig &cfg) noexcept;

    /**
     * @brief
     * \~english Starts receiving datagrams on @p fd, which the backend opened.
     * \~spanish Empieza a recibir datagramas por @p fd, que abrio el backend.
     * \~
     *
     * @param fd    \~english the socket  \~spanish el socket  \~
     * @param bound \~english the address the backend bound it to
     *              \~spanish la direccion a la que lo ato el backend  \~
     */
    bool add_datagram_socket(int32_t fd, const NetAddress &bound) noexcept;

    /// \~english The datagram side.  \~spanish El lado de datagramas.  \~
    ShardDatagrams &datagrams() noexcept { return datagrams_; }

    /**
     * @brief
     * \~english Gives the memory back.
     * \~spanish Devuelve la memoria.
     * \~
     *
     * \~english
     * Every connection still here is told it went, with the reason
     * @c GoneReason::Shutdown for what it had open, and every source is told
     * its @c gone before this returns.  The service must still be alive.
     * \~spanish
     * A cada conexion que siga aqui se le dice que se fue, con el motivo
     * @c GoneReason::Shutdown para lo que tuviera abierto, y cada fuente recibe su
     * @c gone antes de que esto vuelva.  El servicio tiene que seguir vivo.
     * \~
     */
    void release() noexcept;

    /// \~english What was done with open responses.  \~spanish Lo que se hizo con las respuestas abiertas.  \~
    OpenCounts open_counts() const noexcept;

    OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s,
                      KickTarget &target) noexcept override;
    size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override;
    void end(BodySource &s, GoneReason why) noexcept override;
    void want_writable(ConnHandle c) noexcept override;
    void hold_reads(ConnHandle c, bool hold) noexcept override;
    GoneReason closing_reason(ConnHandle c) const noexcept override;

  private:
    /**
     * @brief
     * \~english Hands what is in buffer @p buf to the service, sends its answer, and reads on.
     * \~spanish Le da al servicio lo que hay en el buffer @p buf, manda su respuesta, y sigue leyendo.
     * \~
     */
    void serve(ConnHandle c, ConnHot &h, uint32_t buf) noexcept;

    /**
     * @brief
     * \~english Calls @c Service::on_writable into a fresh buffer and sends what it wrote.
     * \~spanish Llama a @c Service::on_writable sobre un buffer nuevo y manda lo que escribio.
     * \~
     */
    void run_writable(ConnHandle c, ConnHot &h) noexcept;

    /**
     * @brief
     * \~english Does what the service asked for during the turn: room to write, reads to resume.
     * \~spanish Hace lo que pidio el servicio durante la vuelta: sitio para escribir, lecturas que reanudar.
     * \~
     *
     * \~english
     * Asking never calls the service back from inside itself: the connection
     * is put on a list, and the list is served here, at the end of every
     * poll, where the shard is calling nobody.
     * \~spanish
     * Pedir nunca vuelve a llamar al servicio desde dentro de si mismo: la
     * conexion se pone en una lista, y la lista se atiende aqui, al final de
     * cada poll, donde el fragmento no esta llamando a nadie.
     * \~
     */
    void run_asked() noexcept;

    /// \~english Puts @p c on the list @c run_asked serves, once.  \~spanish Pone @p c en la lista que atiende @c run_asked, una vez.  \~
    void ask(ConnHandle c) noexcept;

    /// \~english Tells the service every connection went, and delivers every @c gone.
    /// \~spanish Le dice al servicio que se fueron todas las conexiones, y entrega todos los @c gone.  \~
    void shut_down() noexcept;
    /**
     * @brief
     * \~english Asks for the next thing this connection has to say.
     * \~spanish Pide lo siguiente que tenga que decir esta conexion.
     * \~
     *
     * \~english
     * Which of the two halves it asks for depends on whether there is half a
     * message in hand: one that has none asks to be TOLD when there is
     * something, which costs no buffer, and one that has some reads straight
     * into the buffer it already holds.
     * \~spanish
     * Cual de las dos mitades pide depende de si tiene medio mensaje en la mano:
     * una que no tiene ninguno pide que le AVISEN cuando haya algo, que no cuesta
     * buffer, y una que tiene algo lee directamente al buffer que ya tiene.
     * \~
     */
    void want_read(ConnHandle c, ConnHot &h) noexcept;

    /// \~english Gets a buffer and reads, now that there is something to read.
    /// \~spanish Consigue un buffer y lee, ahora que hay algo que leer.  \~
    void read_into_buffer(ConnHandle c, ConnHot &h) noexcept;

    /// \~english Sends @p buffer, or queues it behind what is already going.
    /// \~spanish Manda @p buffer, o lo encola detras de lo que ya va.  \~
    bool want_write(ConnHandle c, ConnHot &h, uint32_t buf) noexcept;

    /// \~english Sends the next queued answer, if there is one.
    /// \~spanish Manda la respuesta encolada siguiente, si hay.  \~
    void send_next(ConnHandle c, ConnHot &h) noexcept;

    /// \~english Gives back every answer that was still waiting.
    /// \~spanish Devuelve todas las respuestas que seguian esperando.  \~
    void drop_queue(ConnHot &h) noexcept;

    /// \~english Lets go of everything @p h has.
    /// \~spanish Suelta todo lo que tiene @p h.  \~
    void let_go(ConnHandle c, ConnHot &h) noexcept;

    /// \~english Finishes leaving, if nothing is outstanding any more.
    /// \~spanish Acaba de irse, si ya no queda nada pendiente.  \~
    bool leave_if_done(ConnHandle c, ConnHot &h) noexcept;

    void on_read(const Completion &done) noexcept;
    void on_write(const Completion &done) noexcept;

    /// \~english The socket says it has something: now get a buffer and read.
    /// \~spanish El socket dice que tiene algo: ahora si, buffer y lectura.  \~
    void on_ready(const Completion &done) noexcept;

    /**
     * @brief
     * \~english Takes a connection the operating system handed over.
     * \~spanish Coge una conexion que entrego el sistema operativo.
     * \~
     *
     * \~english
     * And asks for another accept, always -- whether this one worked, whether
     * the table had room, whether the socket had to be closed again.  An accept
     * that is not replaced is a listening socket that has quietly stopped
     * listening, and the server goes on looking perfectly healthy: the
     * connections it already had carry on being served while nothing new ever
     * arrives.
     *
     * \~spanish
     * Y pide otra aceptacion, siempre -- funcionara o no, hubiera sitio en la
     * tabla o no, hubiera que volver a cerrar el socket o no --.  Una aceptacion
     * que no se repone es un socket de escucha que ha dejado de escuchar por lo
     * bajo, y el servidor sigue pareciendo perfectamente sano: las conexiones que
     * ya tenia se siguen sirviendo mientras no llega ninguna nueva.
     * \~
     *
     * @param done \~english what came back  \~spanish lo que volvio  \~
     * @param now  \~english what tick it is  \~spanish en que tic se esta  \~
     */
    void on_accept(const Completion &done, uint64_t now) noexcept;

    /// \~english Asks for one more connection.
    /// \~spanish Pide una conexion mas.  \~
    void want_accept() noexcept;

    /// \~english What both @c reset forms do; @p service is null for no stream side.
    /// \~spanish Lo que hacen las dos formas de @c reset; @p service es nulo sin lado de flujos.  \~
    bool start(const ShardConfig &cfg, Backend &io, Service *service,
               uint64_t now) noexcept;

    /// \~english A stream completion on a shard with no stream side: given back, counted.
    /// \~spanish Una finalizacion de flujo en un fragmento sin lado de flujos: devuelta, contada.  \~
    void unserved(const Completion &done) noexcept;

    ConnTable conns_;
    BufferPool pool_;
    TimerWheel wheel_;
    ShardDatagrams datagrams_;

    /**
     * \~english
     * The queued answers, threaded through an array indexed by buffer.  One
     * entry per buffer in the pool and not one per connection, because a
     * buffer is in exactly one connection's queue or in none -- so the whole
     * of every queue on the shard fits in the same four bytes per buffer,
     * with nothing allocated when an answer is queued.
     * \~spanish
     * Las respuestas encoladas, enhebradas en un array indexado por buffer.  Una
     * entrada por buffer del pozo y no una por conexion, porque un buffer esta
     * en la cola de exactamente una conexion o en ninguna -- asi que todas las
     * colas del fragmento caben en los mismos cuatro bytes por buffer, y no se
     * reserva nada al encolar una respuesta.
     * \~
     */
    uint32_t *queue_next_ = nullptr;

    Backend *io_ = nullptr;

    /// \~english The stream side, or null for a shard of datagrams only.
    /// \~spanish El lado de flujos, o nulo para un fragmento solo de datagramas.  \~
    Service *service_ = nullptr;
    ShardConfig cfg_;
    ShardCounts counts_;
    KickQueue kicks_;

    OpenCounts open_counts_;

    /**
     * @brief
     * \~english The port the datagram side's service is given: the shard's limit, kicks and counts, and no connection table.
     * \~spanish La puerta que recibe el servicio del lado de datagramas: el tope, los avisos y las cuentas del fragmento, y ninguna tabla de conexiones.
     * \~
     *
     * \~english
     * Its connection handles are the service's own, so nothing here looks
     * them up in @c conns_: a QUIC handle with the slot and life of a live
     * TCP connection would count against the wrong one.
     * \~spanish
     * Sus referencias de conexion son del propio servicio, asi que aqui nada las
     * busca en @c conns_: una referencia QUIC con la casilla y la vida de una
     * conexion TCP viva contaria contra la que no es.
     * \~
     */
    class DatagramPort final : public OpenPort {
      public:
        explicit DatagramPort(Shard &shard) noexcept : shard_(&shard) {}

        OpenResponse open(ConnHandle c, uint64_t stream, BodySource &s,
                          KickTarget &target) noexcept override;
        size_t fill(BodySource &s, uint8_t *dst, size_t room, bool &done) noexcept override;
        void end(BodySource &s, GoneReason why) noexcept override;

      private:
        Shard *shard_;
    };

    DatagramPort datagram_port_{*this};

    /// \~english Handed to the service on a resume with nothing held here; never given memory.
    /// \~spanish Lo que se le da al servicio en una reanudacion sin nada guardado aqui; nunca recibe memoria.  \~
    Buffer nothing_;

    /// \~english The datagram side's service, or null.  \~spanish El servicio del lado de datagramas, o nulo.  \~
    DatagramService *datagram_service_ = nullptr;

    /**
     * \~english
     * The connections that asked for something this turn, threaded through an
     * array indexed by slot like the answer queue: one entry per connection,
     * nothing allocated to ask.  @c kNotAsked marks a slot not on the list.
     * \~spanish
     * Las conexiones que pidieron algo en esta vuelta, enhebradas en un array
     * indexado por casilla como la cola de respuestas: una entrada por conexion,
     * nada reservado al pedir.  @c kNotAsked marca una casilla que no esta en la
     * lista.
     * \~
     */
    static constexpr uint32_t kNotAsked = 0xFFFFFFFE;
    uint32_t *asked_next_ = nullptr;
    uint32_t asked_head_ = kNoSlot;
    uint32_t asked_tail_ = kNoSlot;

    /// \~english Letting go of everything: what is still open goes with @c GoneReason::Shutdown.
    /// \~spanish Soltandolo todo: lo que siga abierto se va con @c GoneReason::Shutdown.  \~
    bool shutting_down_ = false;
};

} // namespace http_vx

#endif // HTTP_VX_SHARD_H
