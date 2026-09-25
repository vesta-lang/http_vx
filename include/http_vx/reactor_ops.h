/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/reactor_ops.h
 * @brief
 * \~english Asking the operating system for something, and being told later.
 * \~spanish Pedirle algo al sistema operativo, y que te lo digan despues.
 * \~
 *
 * \~english
 * R7: the interface is by COMPLETION.  "Read this into that and tell me when
 * it is done", not "tell me when reading would not block".  Windows only
 * offers completion and Linux offers both, so choosing completion here makes
 * IOCP and io_uring thin translations and leaves only epoll needing
 * adaptation.  The other way round would mean emulating IOCP on an interface
 * that is not one, and that emulation is where the bugs that do not reproduce
 * live.
 *
 * **And it changes who owns a buffer, which is the whole difficulty.**  With
 * readiness, a buffer is yours: the kernel tells you a socket is ready, and
 * YOU read, at a moment you chose, into memory you were holding the whole
 * time.  With completion you hand the kernel a pointer and it writes there
 * when it gets round to it -- so from the moment an operation is submitted
 * until its completion arrives, that memory belongs to the kernel and nobody
 * else may touch it, move it, or give it back to a pool.
 *
 * A buffer returned while an operation on it is outstanding is a
 * use-after-free that the KERNEL performs, into memory that by then belongs to
 * another connection.  It does not crash and it is not visible in a debugger:
 * one client's bytes appear in the middle of another client's request.
 *
 * That is why an operation names its buffer and a completion names it back.
 * Nothing here can enforce the rule on its own -- the enforcing is the loop's
 * -- but making the buffer travel with the operation means the loop always has
 * the number it needs to enforce it, instead of having to remember.
 *
 * \~spanish
 * R7: la interfaz es por FINALIZACION.  "Lee esto en aquello y avisame cuando
 * este", no "avisame cuando leer no vaya a bloquear".  Windows solo ofrece
 * finalizacion y Linux ofrece las dos, asi que elegir finalizacion aqui hace de
 * IOCP e io_uring traducciones finas y deja que solo epoll necesite adaptacion.
 * Al reves habria que emular IOCP sobre una interfaz que no lo es, y esa
 * emulacion es donde viven los errores que no se reproducen.
 *
 * **Y cambia de quien es un buffer, que es toda la dificultad.**  Con
 * disponibilidad, un buffer es tuyo: el nucleo te dice que un socket esta
 * listo, y lees TU, en un momento que elegiste, en una memoria que tenias todo
 * el rato.  Con finalizacion le das al nucleo un puntero y escribe ahi cuando
 * le viene bien -- asi que desde que se entrega una operacion hasta que llega
 * su finalizacion, esa memoria es del nucleo y no la puede tocar, mover ni
 * devolver a un pozo nadie mas.
 *
 * Un buffer devuelto con una operacion suya pendiente es un uso despues de
 * liberar QUE HACE EL NUCLEO, sobre una memoria que para entonces es de otra
 * conexion.  No revienta y no se ve en un depurador: los bytes de un cliente
 * aparecen en mitad de la peticion de otro.
 *
 * Por eso una operacion nombra su buffer y una finalizacion lo devuelve.  Nada
 * de aqui puede hacer cumplir la regla por su cuenta -- hacerla cumplir es cosa
 * del bucle -- pero que el buffer viaje con la operacion quiere decir que el
 * bucle siempre tiene el numero que necesita para hacerlo, en vez de tener que
 * acordarse.
 *
 * \~
 */
#ifndef HTTP_VX_REACTOR_OPS_H
#define HTTP_VX_REACTOR_OPS_H

#include "http_vx/conn_table.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What was asked for.
 * \~spanish Que se pidio.
 * \~
 */
enum class OpKind : uint8_t {
    /// \~english Take the next connection that arrives.
    /// \~spanish Coger la conexion siguiente que llegue.  \~
    Accept,

    /**
     * \~english
     * Say when there is something to read, and take no buffer to do it.
     *
     * **This is what R1 is made of, and without it the requirement is not
     * met.**  A completion-based read has to be given somewhere to write before
     * there is anything to write, so a connection waiting for its next request
     * holds a buffer for as long as it waits -- and a connection waiting for
     * its next request is what a keep-alive connection IS, almost all of the
     * time.  Sixteen kilobytes times a million is sixteen gigabytes held to
     * receive nothing.
     *
     * So the question is asked in two halves.  This half costs no memory at
     * all: it is the socket saying it has something, and the buffer is taken
     * only then -- which is the sentence R1 is written in.
     *
     * **It is deliberately not a @c Recv with no buffer**, because a @c Recv
     * that completes with zero means the peer closed its end, and this
     * completing with zero means the opposite: go and read.  Two meanings on
     * one number is how a server comes to hang up on the clients that were
     * about to say something.
     *
     * Every platform has it and each calls it something else -- a zero-length
     * receive on Windows, a provided buffer on io_uring, and on epoll it is not
     * a trick at all but the only thing epoll ever did.
     *
     * \~spanish
     * Decir cuando hay algo que leer, y no coger ningun buffer para ello.
     *
     * **De esto esta hecha la R1, y sin ello el requisito no se cumple.**  A una
     * lectura por finalizacion hay que darle donde escribir antes de que haya
     * nada que escribir, asi que una conexion que espera su peticion siguiente
     * tiene un buffer todo el rato que espere -- y una conexion que espera su
     * peticion siguiente es lo que ES una conexion mantenida viva, casi todo el
     * tiempo.  Dieciseis kilobytes por un millon son dieciseis gigabytes
     * guardados para no recibir nada.
     *
     * Asi que la pregunta se hace en dos mitades.  Esta no cuesta memoria
     * ninguna: es el socket diciendo que tiene algo, y el buffer se coge solo
     * entonces -- que es la frase en la que esta escrita la R1.
     *
     * **A proposito no es un @c Recv sin buffer**, porque un @c Recv que acaba
     * con cero quiere decir que el otro extremo cerro su lado, y este acabando
     * con cero quiere decir lo contrario: ve y lee.  Dos significados en un
     * numero es como un servidor acaba colgandole a los clientes que iban a
     * decir algo.
     *
     * Lo tienen todas las plataformas y cada una lo llama de otra forma -- una
     * recepcion de longitud cero en Windows, un buffer provisto en io_uring, y en
     * epoll no es ningun truco sino lo unico que ha hecho epoll nunca.
     * \~
     */
    Ready,

    /// \~english Read into the buffer.  \~spanish Leer al buffer.  \~
    Recv,

    /// \~english Write from the buffer.  \~spanish Escribir desde el buffer.  \~
    Send,

    /**
     * \~english
     * Read datagrams, more than one at a time.  R26: QUIC runs on UDP and one
     * system call per datagram is the ceiling long before the encryption or
     * the parsing is, so the batched operations of each platform are not an
     * optimisation to add later -- they decide the shape of this enum now.
     * \~spanish
     * Leer datagramas, mas de uno a la vez.  R26: QUIC va sobre UDP y una
     * llamada al sistema por datagrama es el techo mucho antes que el cifrado o
     * el analisis, asi que las operaciones agrupadas de cada plataforma no son
     * una optimizacion para mas tarde -- deciden la forma de este enum ahora.
     * \~
     */
    RecvFrom,

    /// \~english Write datagrams, more than one at a time.
    /// \~spanish Escribir datagramas, mas de uno a la vez.  \~
    SendTo,

    /**
     * \~english
     * Shut the socket.  It is an operation and not a call because on a
     * completion interface it has to be ordered with the others: closing a
     * socket that still has a read outstanding is asking the kernel about
     * memory it is about to write to.
     * \~spanish
     * Cerrar el socket.  Es una operacion y no una llamada porque en una
     * interfaz por finalizacion tiene que ordenarse con las demas: cerrar un
     * socket que todavia tiene una lectura pendiente es preguntarle al nucleo
     * por una memoria en la que esta a punto de escribir.
     * \~
     */
    Close,
};

/**
 * @brief
 * \~english Something asked of the operating system.
 * \~spanish Algo que se le pide al sistema operativo.
 * \~
 */
struct Op {
    /**
     * \~english
     * Who it is for, INCLUDING which of that slot's lives.  A completion can
     * arrive after the connection it was for has gone -- that is the ordinary
     * case, not a corner: the peer disappeared, the read was already
     * submitted, and the kernel finishes it either way.  Carrying the life
     * means the loop can tell that apart from a completion for whoever is in
     * the slot now, which is the difference between dropping a result and
     * handing one client's bytes to another.
     * \~spanish
     * Para quien es, INCLUYENDO cual de las vidas de esa casilla.  Una
     * finalizacion puede llegar despues de que la conexion se haya ido -- que es
     * el caso corriente y no una esquina: el otro extremo desaparecio, la
     * lectura ya estaba entregada, y el nucleo la acaba igual --.  Llevar la
     * vida quiere decir que el bucle puede distinguir eso de una finalizacion
     * para quien este ahora en la casilla, que es la diferencia entre tirar un
     * resultado y darle los bytes de un cliente a otro.
     * \~
     */
    ConnHandle conn;

    OpKind kind = OpKind::Recv;

    /// \~english Which pooled buffer, or @c kNoBuffer when there is none.
    /// \~spanish Que buffer del pozo, o @c kNoBuffer cuando no hay.  \~
    /// \~spanish Que buffer del pozo, o @c kNoBuffer cuando no hay.  \~
    uint32_t buffer = kNoBuffer;

    /**
     * \~english
     * Where in the buffer, and how much.  Both are needed because a send does
     * not start at the beginning: a partial write leaves the rest to go, and
     * the operation that carries it on must name the part that is left rather
     * than the whole thing.
     * \~spanish
     * Donde dentro del buffer, y cuanto.  Hacen falta los dos porque un envio no
     * empieza al principio: una escritura parcial deja el resto por mandar, y la
     * operacion que lo continua tiene que nombrar el trozo que queda y no la
     * cosa entera.
     * \~
     */
    uint32_t offset = 0;
    uint32_t length = 0;

    /**
     * \~english
     * Which socket.
     *
     * The operation names it, rather than the backend working it out from
     * @c conn, and that is what keeps a backend from needing a connection
     * table.  A backend that had one would be a second place where a slot's
     * life is tracked, and the two would disagree exactly once -- on the
     * completion that arrives after its connection has gone, which is the case
     * the whole handle design exists for.
     *
     * Two operations have no connection to be worked out from anyway, which is
     * the same answer arriving from the other side:
     *
     *  - an @c Accept has no connection yet -- producing one is the point of it
     *    -- so this is where the socket it produced comes back;
     *  - a @c Close of a socket that was never adopted.  A shard that accepts
     *    while its table is full has a socket in its hand and nowhere to put
     *    it, and the only wrong answer is to drop it: an unclosed socket is a
     *    descriptor leaked on every accept a busy server refuses, which ends
     *    with a server that cannot accept anything and no memory missing.
     *
     * \~spanish
     * Que socket.
     *
     * Lo nombra la operacion, en vez de que el backend lo saque de @c conn, y eso
     * es lo que evita que un backend necesite una tabla de conexiones.  Uno que
     * la tuviera seria un segundo sitio donde se lleva la vida de una casilla, y
     * los dos discreparian exactamente una vez -- en la finalizacion que llega
     * despues de que su conexion se haya ido, que es el caso para el que existe
     * todo el diseno de las referencias.
     *
     * Dos operaciones no tienen ademas ninguna conexion de la que sacarlo, que es
     * la misma respuesta llegando por el otro lado:
     *
     *  - un @c Accept no tiene conexion todavia -- producir una es para lo que
     *    esta -- asi que aqui es donde vuelve el socket que produjo;
     *  - un @c Close de un socket que no llego a adoptarse.  Un fragmento que
     *    acepta con la tabla llena tiene un socket en la mano y ningun sitio
     *    donde ponerlo, y la unica respuesta equivocada es soltarlo: un socket
     *    sin cerrar es un descriptor perdido en cada aceptacion que rechaza un
     *    servidor con trabajo, y eso acaba en un servidor que no puede aceptar
     *    nada sin que falte memoria.
     * \~
     */
    int32_t fd = -1;
};

/**
 * @brief
 * \~english What came of it.
 * \~spanish En que quedo.
 * \~
 */
struct Completion {
    ConnHandle conn;
    OpKind kind = OpKind::Recv;

    /**
     * \~english
     * The buffer the operation was on, handed straight back.  It is here so
     * that the loop can give it to the pool without looking anything up -- and
     * so that it cannot give back a DIFFERENT one, which is what happens when
     * the number is carried along on the side and the two get out of step.
     * \~spanish
     * El buffer sobre el que iba la operacion, devuelto tal cual.  Esta aqui
     * para que el bucle pueda devolverlo al pozo sin consultar nada -- y para
     * que no pueda devolver OTRO, que es lo que pasa cuando el numero se lleva
     * por separado y los dos se desacompasan.
     * \~
     */
    uint32_t buffer = kNoBuffer;

    /**
     * \~english
     * How many bytes moved, or a NEGATIVE number when it failed.  One field
     * and not two, because every caller has to look at both anyway and a pair
     * lets somebody read the count of a call that did not happen.
     *
     * Zero on a @c Recv is not an error and not a short read: it is the peer
     * closing its end, and a loop that treated it as either would either spin
     * forever or report a failure that nobody caused.
     *
     * \~spanish
     * Cuantos bytes se movieron, o un numero NEGATIVO cuando fallo.  Un campo y
     * no dos, porque todo el que llama tiene que mirar los dos de todas formas y
     * un par deja que alguien lea la cuenta de una llamada que no ocurrio.
     *
     * Un cero en un @c Recv no es un error ni una lectura corta: es el otro
     * extremo cerrando su lado, y un bucle que lo tomara por cualquiera de las
     * dos cosas o daria vueltas para siempre o informaria de un fallo que no
     * causo nadie.
     * \~
     */
    int32_t result = 0;

    /**
     * \~english
     * The socket an @c Accept produced, and @c -1 on anything else.
     *
     * A separate field from @c result rather than the socket returned as the
     * "count", because they are different things and a reader cannot tell them
     * apart afterwards: a count is a number of bytes and a socket is a name,
     * and code that treated one as the other would work perfectly until the
     * day a descriptor came back as zero.
     *
     * \~spanish
     * El socket que produjo un @c Accept, y @c -1 en cualquier otra cosa.
     *
     * Un campo aparte de @c result y no el socket devuelto como si fuera la
     * "cuenta", porque son cosas distintas y despues no se distinguen: una
     * cuenta es un numero de bytes y un socket es un nombre, y un codigo que
     * tratara uno por el otro funcionaria perfectamente hasta el dia en que
     * volviera un descriptor que fuera cero.
     * \~
     */
    int32_t fd = -1;

    /// \~english Whether it worked.  \~spanish Si funciono.  \~
    bool ok() const noexcept { return result >= 0; }

    /// \~english Whether the peer closed its end.
    /// \~spanish Si el otro extremo cerro su lado.  \~
    bool eof() const noexcept {
        return result == 0 && (kind == OpKind::Recv || kind == OpKind::RecvFrom);
    }
};

/**
 * @brief
 * \~english What a shard needs from an operating system.
 * \~spanish Lo que necesita un fragmento de un sistema operativo.
 * \~
 *
 * \~english
 * The whole boundary, and it is deliberately this small: everything above it
 * -- the parsers, the streams, the windows, the tables, the deadlines -- has
 * been written and tested without any of it.
 *
 * The calls are virtual, which is a cost worth naming: R8 says the backend is
 * chosen in configuration, so it has to be chosen at run time, and a call
 * through a pointer is what that costs.  What makes it not matter is WHERE the
 * calls are: @c wait returns a batch and @c submit is one operation, so the
 * indirection is paid per batch and per socket operation -- never per
 * connection and never per byte.  A backend interface with a virtual call per
 * event would be a different proposition, and is not this.
 *
 * \~spanish
 * Toda la frontera, y es asi de pequena a proposito: todo lo que hay por encima
 * -- los analizadores, los flujos, las ventanas, las tablas, los plazos -- se ha
 * escrito y probado sin nada de esto.
 *
 * Las llamadas son virtuales, y es un coste que merece nombrarse: la R8 dice que
 * el backend se elige en configuracion, asi que hay que elegirlo en ejecucion, y
 * una llamada por puntero es lo que eso cuesta.  Lo que hace que no importe es
 * DONDE estan las llamadas: @c wait devuelve un lote y @c submit es una
 * operacion, asi que la indireccion se paga por lote y por operacion de socket
 * -- nunca por conexion y nunca por byte --.  Una interfaz de backend con una
 * llamada virtual por suceso seria otra cosa, y no es esta.
 *
 * \~
 */
class Backend {
  public:
    virtual ~Backend();

    Backend() noexcept = default;
    Backend(const Backend &) = delete;
    Backend &operator=(const Backend &) = delete;

    /**
     * @brief
     * \~english Asks for @p op.
     * \~spanish Pide @p op.
     * \~
     *
     * \~english
     * From the moment this returns true, the buffer named by @p op belongs to
     * the operating system until its completion comes back.  Touching it,
     * moving it or returning it to the pool before then is a use-after-free
     * the kernel performs.
     *
     * A false return is the submission queue being full, which is a shard at
     * its limit rather than a shard in trouble: the caller waits for
     * completions, which is what will make room, and tries again.
     *
     * \~spanish
     * Desde que esto devuelve true, el buffer que nombra @p op es del sistema
     * operativo hasta que vuelva su finalizacion.  Tocarlo, moverlo o
     * devolverlo al pozo antes es un uso despues de liberar que hace el nucleo.
     *
     * Un false es la cola de entrega llena, que es un fragmento en su limite y
     * no un fragmento con un problema: quien llama espera finalizaciones, que es
     * lo que va a hacer sitio, y lo vuelve a intentar.
     *
     * \~
     * @param op \~english what is wanted  \~spanish lo que se quiere  \~
     * @return   \~english false if there was no room to ask
     *           \~spanish false si no habia sitio para pedirlo  \~
     */
    virtual bool submit(const Op &op) noexcept = 0;

    /**
     * @brief
     * \~english Waits for completions, up to @p cap of them.
     * \~spanish Espera finalizaciones, hasta @p cap de ellas.
     * \~
     *
     * \~english
     * A batch and not one at a time, because that is what every one of these
     * interfaces gives and taking them one by one would throw away the reason
     * they exist.  R18 says the same thing about the writing side.
     *
     * @p timeout_ms of zero returns whatever is already there without waiting,
     * which is what a shard with work to do wants; a negative one waits until
     * something happens, which is what an idle shard wants so that it costs no
     * CPU at all.
     *
     * \~spanish
     * Un lote y no de una en una, porque es lo que da cada una de estas
     * interfaces y cogerlas de una en una tiraria la razon por la que existen.
     * La R18 dice lo mismo del lado de escribir.
     *
     * Un @p timeout_ms de cero devuelve lo que ya haya sin esperar, que es lo
     * que quiere un fragmento con trabajo; uno negativo espera hasta que pase
     * algo, que es lo que quiere un fragmento parado para no costar nada de CPU.
     *
     * \~
     * @param out        \~english where the completions go
     *                   \~spanish donde van las finalizaciones  \~
     * @param cap        \~english how many fit  \~spanish cuantas caben  \~
     * @param timeout_ms \~english how long to wait; negative is forever
     *                   \~spanish cuanto esperar; negativo es para siempre  \~
     * @return           \~english how many came back
     *                   \~spanish cuantas volvieron  \~
     */
    virtual size_t wait(Completion *out, size_t cap,
                        int timeout_ms) noexcept = 0;

    /**
     * @brief
     * \~english What this backend is called.
     * \~spanish Como se llama este backend.
     * \~
     *
     * \~english
     * So that a server can say which one it is using.  R8 is about epoll not
     * being a path nobody tests, and the first thing that needs is for anybody
     * to be able to tell which path they are on -- a server that silently fell
     * back would be exactly the failure that requirement describes.
     *
     * \~spanish
     * Para que un servidor pueda decir cual esta usando.  La R8 va de que epoll
     * no sea un camino que no prueba nadie, y lo primero que hace falta para eso
     * es que cualquiera pueda saber en que camino esta -- un servidor que se
     * cayera a otro en silencio seria justo el fallo que describe ese requisito.
     *
     * \~
     */
    virtual const char *name() const noexcept = 0;
};

} // namespace http_vx

#endif // HTTP_VX_REACTOR_OPS_H
