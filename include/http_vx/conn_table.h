/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/conn_table.h
 * @brief
 * \~english A connection is a slot, and the number that says which one it is now.
 * \~spanish Una conexion es una casilla, y el numero que dice cual es ahora.
 * \~
 *
 * \~english
 * A million connections is a million of whatever a connection is, so what a
 * connection IS decides whether the server exists.  An object per connection
 * means a million allocations, a million pointers to chase, and a heap whose
 * shape depends on the order people connected in.  R2 says the other thing: a
 * fixed-size record in a dense array, and a connection is an INDEX.
 *
 * **Which buys everything and costs one thing, and the one thing is the whole
 * of this file.**  Indices get reused.  A slot closes and opens again as
 * somebody else, and anything still holding the old number -- a deadline that
 * was about to fire, a completion the kernel queued before the close, a
 * handler that kept a reference -- now points at a live connection belonging
 * to someone else.
 *
 * That is a use-after-free that does not crash.  It serves one client's
 * request on another client's socket, quietly, on a server that looks
 * perfectly healthy.  It is the same failure as an HTTP/2 stream identifier
 * being reused, and it has the same answer in spirit and a different one in
 * practice: a stream never reuses a number because there are four thousand
 * million of them and a connection does not last that long, while a slot MUST
 * be reused because there are only as many as fit in memory.
 *
 * So the number is not enough, and a reference is two numbers: **which slot,
 * and which of that slot's lives**.  The second one goes up every time the
 * slot is reused, so a reference from a previous life does not match and is
 * refused.  It costs four bytes per connection and one comparison per lookup,
 * and it converts the worst bug this design can have into a null return.
 *
 * \~spanish
 * Un millon de conexiones son un millon de lo que sea una conexion, asi que lo
 * que una conexion ES decide si el servidor existe.  Un objeto por conexion son
 * un millon de reservas, un millon de punteros que perseguir, y un monticulo
 * cuya forma depende del orden en que se conecto la gente.  La R2 dice la otra
 * cosa: un registro de tamano fijo en un array denso, y una conexion es un
 * INDICE.
 *
 * **Lo que compra todo y cuesta una cosa, y esa cosa es todo este fichero.**
 * Los indices se reutilizan.  Una casilla se cierra y se vuelve a abrir siendo
 * otro, y cualquiera que siga guardando el numero viejo -- un plazo que estaba a
 * punto de vencer, una finalizacion que el nucleo encolo antes del cierre, un
 * manejador que se guardo una referencia -- apunta ahora a una conexion viva de
 * otra persona.
 *
 * Eso es un uso despues de liberar que no revienta.  Sirve la peticion de un
 * cliente por el socket de otro, en silencio, en un servidor que se ve
 * perfectamente sano.  Es el mismo fallo que reutilizar un identificador de
 * flujo de HTTP/2, y tiene la misma respuesta en el fondo y otra distinta en la
 * practica: un flujo no reutiliza un numero porque hay cuatro mil millones y una
 * conexion no dura tanto, mientras que una casilla TIENE que reutilizarse porque
 * solo hay las que caben en memoria.
 *
 * Asi que el numero no basta, y una referencia son dos numeros: **que casilla, y
 * cual de las vidas de esa casilla**.  El segundo sube cada vez que la casilla
 * se reutiliza, asi que una referencia de una vida anterior no casa y se
 * rechaza.  Cuesta cuatro bytes por conexion y una comparacion por consulta, y
 * convierte el peor fallo que puede tener este diseno en un retorno nulo.
 *
 * \~
 */
#ifndef HTTP_VX_CONN_TABLE_H
#define HTTP_VX_CONN_TABLE_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english The index that is not one.
 * \~spanish El indice que no lo es.
 * \~
 */
constexpr uint32_t kNoSlot = 0xFFFFFFFF;

/**
 * @brief
 * \~english What a connection is holding of the buffer pool, when it holds any.
 * \~spanish Lo que tiene una conexion del pozo de buffers, cuando tiene algo.
 * \~
 *
 * \~english
 * R1: a connection with nothing in flight has no buffer.  An idle one is a
 * record in an array and a socket, and the sixteen kilobytes it would have
 * been given are back in the pool serving somebody who is actually talking.
 * At a million connections that is the difference between sixteen gigabytes
 * and however many are busy at once.
 *
 * \~spanish
 * R1: una conexion sin nada en vuelo no tiene buffer.  Una parada es un registro
 * de un array y un socket, y los dieciseis kilobytes que se le habrian dado
 * estan de vuelta en el pozo sirviendo a alguien que si esta hablando.  Al
 * millon de conexiones esa es la diferencia entre dieciseis gigabytes y los que
 * haya ocupados a la vez.
 *
 * \~
 */
constexpr uint32_t kNoBuffer = 0xFFFFFFFF;

/**
 * @brief
 * \~english Which slot, and which of its lives.
 * \~spanish Que casilla, y cual de sus vidas.
 * \~
 *
 * \~english
 * Eight bytes, so it is passed and returned in registers and there is never a
 * reason to hold a pointer into the table instead.  That matters more than the
 * size: a pointer would go stale the same way the index does AND would survive
 * the check, because a stale pointer into a dense array still points at a
 * perfectly valid record.
 *
 * \~spanish
 * Ocho bytes, asi que se pasa y se devuelve en registros y no hay nunca razon
 * para guardar en su lugar un puntero a la tabla.  Eso importa mas que el
 * tamano: un puntero se quedaria rancio igual que el indice Y ademas se saltaria
 * la comprobacion, porque un puntero rancio a un array denso sigue apuntando a
 * un registro perfectamente valido.
 *
 * \~
 */
struct ConnHandle {
    uint32_t slot = kNoSlot;
    uint32_t life = 0;

    /// \~english Whether it names a slot at all.
    /// \~spanish Si nombra siquiera una casilla.  \~
    bool valid() const noexcept { return slot != kNoSlot; }
};

/**
 * @brief
 * \~english What the event loop touches every time round.
 * \~spanish Lo que toca el bucle de sucesos cada vuelta.
 * \~
 *
 * \~english
 * Sixteen bytes, four to a cache line, and what is in it was decided by asking
 * one question: does the loop read this on a connection that has nothing to
 * do?  R17 says the answer sorts the fields into two arrays, and the reason is
 * not tidiness -- at a million connections, one field that belongs in the cold
 * array and sits here instead makes every sweep read twice the memory for the
 * same work.
 *
 * \~spanish
 * Dieciseis bytes, cuatro por linea de cache, y lo que hay dentro se decidio
 * haciendo una pregunta: lee el bucle esto en una conexion que no tiene nada que
 * hacer?  La R17 dice que la respuesta reparte los campos en dos arrays, y la
 * razon no es el orden -- al millon de conexiones, un campo que pertenece al
 * array frio y esta aqui hace que cada barrido lea el doble de memoria para el
 * mismo trabajo.
 *
 * \~
 */
struct ConnHot {
    /**
     * \~english
     * The socket, or -1 when the slot is free.  Signed because that is what
     * the operating system hands out and converting it here would mean
     * converting it back at every call.
     * \~spanish
     * El socket, o -1 cuando la casilla esta libre.  Con signo porque es lo que
     * da el sistema operativo y convertirlo aqui obligaria a convertirlo de
     * vuelta en cada llamada.
     * \~
     */
    int32_t fd;

    /**
     * \~english
     * Which life this slot is on.  It is here rather than in the cold array
     * although nothing reads it in a sweep, because it is read on EVERY
     * lookup -- and a lookup that had to touch the cold array to check whether
     * the hot one may be read would have made the split pointless.
     * \~spanish
     * En que vida va esta casilla.  Esta aqui y no en el array frio aunque no lo
     * lea nadie en un barrido, porque se lee en TODAS las consultas -- y una
     * consulta que tuviera que tocar el array frio para saber si puede leer el
     * caliente habria hecho inutil el reparto.
     * \~
     */
    uint32_t life;

    /**
     * \~english
     * The first answer waiting to go out, or @c kNoBuffer.  A connection may
     * have a write with the operating system AND more answers ready behind it,
     * because reading and writing are independent directions and the loop does
     * both at once -- so there has to be somewhere for the second answer to
     * wait that is not "hold up the read that produced it".
     *
     * The rest of the queue is threaded through an array beside the buffers,
     * so a queue of any depth is still this one field.
     *
     * \~spanish
     * La primera respuesta que espera para salir, o @c kNoBuffer.  Una conexion
     * puede tener una escritura en el sistema operativo Y mas respuestas listas
     * detras, porque leer y escribir son sentidos independientes y el bucle hace
     * los dos a la vez -- asi que la segunda respuesta tiene que tener donde
     * esperar que no sea "retener la lectura que la produjo".
     *
     * El resto de la cola va enhebrado en un array al lado de los buffers, asi
     * que una cola de cualquier profundidad sigue siendo este unico campo.
     * \~
     */
    uint32_t queue;

    /**
     * \~english
     * The buffer holding half a message, or @c kNoBuffer.
     *
     * A request arrives in as many reads as the network feels like, so what a
     * read leaves behind has to be there when the rest lands after it.  The
     * next read goes into this same buffer rather than a fresh one, which is
     * what makes a head split across two packets a thing that simply works.
     *
     * It is the field that took the record past sixteen bytes, and it was
     * worth it: without it the only ways to keep half a message are to copy it
     * somewhere else -- which is the copy R13 exists to avoid -- or to refuse
     * requests that arrive in pieces, which is most of the large ones.
     *
     * \~spanish
     * El buffer que tiene medio mensaje, o @c kNoBuffer.
     *
     * Una peticion llega en tantas lecturas como le apetezca a la red, asi que
     * lo que deje una lectura tiene que estar ahi cuando caiga detras el resto.
     * La lectura siguiente va a este mismo buffer y no a uno nuevo, que es lo
     * que hace que una cabeza partida entre dos paquetes sea algo que
     * sencillamente funciona.
     *
     * Es el campo que saco el registro de los dieciseis bytes, y valio la pena:
     * sin el, las unicas formas de guardar medio mensaje son copiarlo a otro
     * sitio -- que es la copia que la R13 existe para evitar -- o rechazar las
     * peticiones que lleguen a trozos, que son casi todas las grandes.
     * \~
     */
    uint32_t reading;

    /// \~english What is outstanding and whether it is ending; see @c ConnFlag.
    /// \~spanish Que hay pendiente y si se esta acabando; ver @c ConnFlag.  \~
    uint16_t flags;

    /// \~english How many answers are waiting behind the one going out.
    /// \~spanish Cuantas respuestas esperan detras de la que esta saliendo.  \~
    uint16_t queued;

    uint32_t _pad;
};

/**
 * \~english
 * Twenty-four bytes, not the sixteen it started at.  The record is not swept
 * -- nothing walks the table, because the deadlines are a wheel and the work
 * arrives as completions carrying the slot -- so what the size costs is memory
 * and not cache lines read for nothing: at a million connections, eight
 * megabytes more, for the field that lets a request arrive in pieces.
 *
 * \~spanish
 * Veinticuatro bytes, no los dieciseis con los que empezo.  El registro no se
 * BARRE -- nadie recorre la tabla, porque los plazos son una rueda y el trabajo
 * llega como finalizaciones que traen la casilla -- asi que lo que cuesta el
 * tamano es memoria y no lineas de cache leidas para nada: al millon de
 * conexiones, ocho megabytes mas, por el campo que permite que una peticion
 * llegue a trozos.
 * \~
 */
static_assert(sizeof(ConnHot) == 24,
              "the hot record is meant to be twenty-four bytes");

/**
 * @brief
 * \~english What only somebody diagnosing ever reads.
 * \~spanish Lo que solo lee quien esta diagnosticando.
 * \~
 *
 * \~english
 * Kept for every connection and read for almost none.  It is the half that
 * would ruin the other one if they shared an array, and it is also the half
 * that a server without it cannot answer any question about itself -- so it is
 * not dropped, it is moved.
 *
 * \~spanish
 * Se guarda de todas las conexiones y se lee de casi ninguna.  Es la mitad que
 * estropearia a la otra si compartieran array, y es tambien la mitad sin la
 * cual un servidor no puede contestar ninguna pregunta sobre si mismo -- asi que
 * no se quita, se mueve.
 *
 * \~
 */
struct ConnCold {
    /// \~english When it arrived, in the shard's ticks.
    /// \~spanish Cuando llego, en tics del fragmento.  \~
    uint64_t opened;

    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t requests;

    /// \~english The peer, big enough for either kind of address.
    /// \~spanish El otro extremo, con sitio para las dos clases de direccion.  \~
    uint8_t peer[16];
    uint16_t port;

    /// \~english How many of its responses are open (HVX-5, 8).  \~spanish Cuantas de sus respuestas estan abiertas (HVX-5, 8).  \~
    uint16_t open;

    uint16_t _pad[2];
};

/**
 * @brief
 * \~english The connections of one shard.
 * \~spanish Las conexiones de un fragmento.
 * \~
 */
class ConnTable {
  public:
    ConnTable() noexcept = default;
    ~ConnTable();

    ConnTable(const ConnTable &) = delete;
    ConnTable &operator=(const ConnTable &) = delete;

    /**
     * @brief
     * \~english Makes room for @p capacity connections.
     * \~spanish Hace sitio para @p capacity conexiones.
     * \~
     *
     * \~english
     * All of it, once, and it never grows.  A table that grew would move the
     * records -- and every index handed out, every deadline armed, every
     * completion the kernel has not delivered yet, is a number that means a
     * position in that array.  Growing is not expensive here, it is wrong.
     *
     * The memory is spent up front on purpose.  A server that can hold a
     * million connections should find that out when it starts rather than at
     * the nine hundred thousandth, which is a moment chosen by whoever is
     * attacking it.
     *
     * \~spanish
     * Todo de una vez, y no crece nunca.  Una tabla que creciera moveria los
     * registros -- y cada indice entregado, cada plazo armado, cada finalizacion
     * que el nucleo todavia no ha entregado, es un numero que significa una
     * posicion de ese array.  Crecer aqui no es caro, es incorrecto.
     *
     * La memoria se gasta por delante a proposito.  Un servidor que puede tener
     * un millon de conexiones deberia enterarse al arrancar y no en la
     * novecientas mil, que es un momento que elige quien lo este atacando.
     *
     * \~
     * @param capacity \~english how many at once
     *                 \~spanish cuantas a la vez  \~
     * @return         \~english false if the memory could not be had
     *                 \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t capacity) noexcept;

    /**
     * @brief
     * \~english Takes a slot for @p fd, or gives back an invalid handle.
     * \~spanish Coge una casilla para @p fd, o devuelve una referencia invalida.
     * \~
     *
     * \~english
     * An invalid handle is the accept loop being told to stop, and it is the
     * right way to say it: the table is the number this server can hold, so a
     * full table is a server at its limit rather than a server in trouble.
     * What the caller does with the socket then -- close it, or leave it in the
     * backlog for another shard -- is not this class's business.
     *
     * \~spanish
     * Una referencia invalida es decirle al bucle de aceptacion que pare, y es la
     * forma correcta de decirlo: la tabla es el numero que puede tener este
     * servidor, asi que una tabla llena es un servidor en su limite y no un
     * servidor con un problema.  Lo que haga quien llama con el socket entonces
     * -- cerrarlo, o dejarlo en la cola para otro fragmento -- no es cosa de esta
     * clase.
     *
     * \~
     * @param fd     \~english the socket  \~spanish el socket  \~
     * @param opened \~english what tick it is now
     *               \~spanish en que tic se esta ahora  \~
     * @return       \~english the handle, or an invalid one when it is full
     *               \~spanish la referencia, o una invalida cuando esta llena  \~
     */
    ConnHandle open(int32_t fd, uint64_t opened) noexcept;

    /**
     * @brief
     * \~english Gives the slot back, and ends that life.
     * \~spanish Devuelve la casilla, y acaba esa vida.
     * \~
     *
     * \~english
     * Closing with a handle from a previous life does NOTHING, which is the
     * point: a deadline that fired for a connection that has already gone
     * would otherwise close whoever is in the slot now.  That is the bug this
     * whole file exists for, and this is where it would happen if it were
     * going to.
     *
     * \~spanish
     * Cerrar con una referencia de una vida anterior no hace NADA, que es de lo
     * que se trata: un plazo que vencio por una conexion que ya se fue cerraria
     * si no a quien este ahora en la casilla.  Ese es el fallo para el que existe
     * todo este fichero, y aqui es donde pasaria si fuera a pasar.
     *
     * \~
     * @param h \~english which connection  \~spanish que conexion  \~
     * @return  \~english whether it was the one that was there
     *          \~spanish si era la que estaba  \~
     */
    bool close(ConnHandle h) noexcept;

    /**
     * @brief
     * \~english The hot record of @p h, or null if that life is over.
     * \~spanish El registro caliente de @p h, o nulo si esa vida se acabo.
     * \~
     *
     * @param h \~english which connection  \~spanish que conexion  \~
     * @return  \~english the record, or null  \~spanish el registro, o nulo  \~
     */
    ConnHot *hot(ConnHandle h) noexcept;

    /// \~english The same, to read.  \~spanish Lo mismo, para leer.  \~
    const ConnHot *hot(ConnHandle h) const noexcept;

    /// \~english The same for the half nobody reads in a sweep.
    /// \~spanish Lo mismo para la mitad que no lee nadie en un barrido.  \~
    ConnCold *cold(ConnHandle h) noexcept;

    /**
     * @brief
     * \~english Whether @p h is still the connection it was.
     * \~spanish Si @p h sigue siendo la conexion que era.
     * \~
     *
     * @param h \~english which connection  \~spanish que conexion  \~
     * @return  \~english whether that life is still running
     *          \~spanish si esa vida sigue corriendo  \~
     */
    bool alive(ConnHandle h) const noexcept;

    /**
     * @brief
     * \~english The handle for the connection in slot @p i right now.
     * \~spanish La referencia de la conexion que hay ahora en la casilla @p i.
     * \~
     *
     * \~english
     * For whatever hands back a bare index -- an event queue, a completion,
     * a lookup by socket.  It is the one legitimate way to turn a number back
     * into a handle, and it goes through here rather than being assembled by
     * the caller so that the life is read from the table and never guessed.
     *
     * \~spanish
     * Para lo que devuelva un indice desnudo -- una cola de sucesos, una
     * finalizacion, una busqueda por socket --.  Es la unica forma legitima de
     * convertir un numero otra vez en una referencia, y pasa por aqui en vez de
     * montarla quien llama para que la vida se lea de la tabla y no se adivine
     * nunca.
     *
     * \~
     * @param i \~english which slot  \~spanish que casilla  \~
     * @return  \~english the handle, or an invalid one if the slot is free
     *          \~spanish la referencia, o una invalida si la casilla esta libre  \~
     */
    ConnHandle at(uint32_t i) const noexcept;

    /// \~english How many are open.  \~spanish Cuantas hay abiertas.  \~
    size_t count() const noexcept { return count_; }

    /// \~english How many there is room for.  \~spanish Para cuantas hay sitio.  \~
    uint32_t capacity() const noexcept { return capacity_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    ConnHot *hot_ = nullptr;
    ConnCold *cold_ = nullptr;

    /**
     * \~english
     * The free slots, as a queue threaded through an array of their own.  A
     * queue and not a stack, and the reason is the bug at the top of this
     * file: a stack hands back the slot that was just freed, so the window in
     * which a stale reference could be caught is nothing at all.  A queue
     * hands back the slot that has been free the LONGEST, which makes that
     * window as wide as the table.
     *
     * It costs cache.  A stack would reuse a record that is still warm; this
     * walks the whole table before coming round.  That is the trade and it is
     * made on purpose: the miss is a few nanoseconds on an operation that
     * happens once per connection, and the thing it buys is that the worst bug
     * this design can have has the longest possible chance of being a null
     * return instead.
     *
     * \~spanish
     * Las casillas libres, como una cola enhebrada en un array propio.  Una cola
     * y no una pila, y la razon es el fallo del principio de este fichero: una
     * pila devuelve la casilla que se acaba de liberar, asi que la ventana en la
     * que se podria pillar una referencia rancia no es nada.  Una cola devuelve
     * la casilla que lleva libre MAS TIEMPO, que hace esa ventana tan ancha como
     * la tabla.
     *
     * Cuesta cache.  Una pila reutilizaria un registro que sigue caliente; esto
     * recorre la tabla entera antes de dar la vuelta.  Ese es el trato y esta
     * hecho a proposito: el fallo de cache son unos nanosegundos en una operacion
     * que pasa una vez por conexion, y lo que compra es que el peor fallo que
     * puede tener este diseno tenga la oportunidad mas larga posible de ser un
     * retorno nulo.
     * \~
     */
    uint32_t *next_free_ = nullptr;
    uint32_t free_head_ = kNoSlot;
    uint32_t free_tail_ = kNoSlot;

    uint32_t capacity_ = 0;
    size_t count_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_CONN_TABLE_H
