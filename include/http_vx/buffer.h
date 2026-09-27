/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/buffer.h
 * @brief
 * \~english The bytes of a connection, with offsets that survive.
 * \~spanish Los bytes de una conexion, con desplazamientos que sobreviven.
 * \~
 *
 * \~english
 * Everything that gets parsed points into here, and nothing that gets parsed
 * holds a pointer.  That is the whole design, and it comes from three
 * requirements that pull in the same direction.
 *
 * Completion-based I/O (R7) hands the kernel somewhere to write **before** the
 * data exists, so the buffer must be able to offer writable room on demand.  A
 * header may be split across two reads, and the parser must not go back over
 * what it already looked at (R12), so what it recorded from the first read has
 * to still be valid after the second.  And the body is never copied (R13): the
 * handler gets a view.
 *
 * Both of the things that move memory here -- growing, and sliding the
 * leftovers to the front -- move `data()` with it.  So:
 *
 *  - **An offset from `data()` stays valid across a grow and across a
 *    compaction.**
 *  - **A pointer does not.**
 *  - **Only `consume()` invalidates offsets**, and that is exactly the
 *    boundary where the message they belonged to ended.
 *
 * That invariant is what lets the field collection store offsets, the parser
 * keep its position, and the handler hold a view -- without any of the three
 * knowing when the buffer last moved.
 *
 * \~spanish
 * Todo lo que se analiza apunta aqui dentro, y nada de lo que se analiza
 * guarda un puntero.  Ese es todo el diseno, y sale de tres exigencias que
 * tiran en la misma direccion.
 *
 * La entrada y salida por finalizacion (R7) le da al sistema donde escribir
 * **antes** de que los datos existan, asi que el buffer tiene que poder ofrecer
 * sitio escribible cuando se le pida.  Una cabecera puede llegar partida entre
 * dos lecturas, y el analizador no puede volver sobre lo que ya miro (R12), asi
 * que lo que anoto de la primera lectura tiene que seguir valiendo tras la
 * segunda.  Y el cuerpo no se copia nunca (R13): al manejador se le da una
 * vista.
 *
 * Las dos cosas que mueven memoria aqui -- crecer, y deslizar lo que sobra
 * hacia delante -- mueven `data()` con ella.  Asi que:
 *
 *  - **Un desplazamiento desde `data()` sigue valiendo tras crecer y tras
 *    compactar.**
 *  - **Un puntero no.**
 *  - **Solo `consume()` invalida desplazamientos**, y esa es justo la frontera
 *    donde termino el mensaje al que pertenecian.
 *
 * Ese invariante es lo que permite que la coleccion de cabeceras guarde
 * desplazamientos, que el analizador conserve su posicion y que el manejador
 * tenga una vista -- sin que ninguno de los tres sepa cuando se movio el buffer
 * por ultima vez.
 *
 * \~
 */
#ifndef HTTP_VX_BUFFER_H
#define HTTP_VX_BUFFER_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english The bytes that are here, and where they are in the stream.
 * \~spanish Los bytes que hay, y donde estan dentro del flujo.
 * \~
 *
 * \~english
 * Three numbers instead of two, and the third is the one that closes a hole.
 *
 * An offset from @c data survives growing and sliding, because both move
 * @c data with them.  What it does not survive is DROPPING what is in front of
 * it: after bytes are consumed, the same offset names a byte further along.
 * That is fine while a message is read from start to finish and thrown away
 * whole, and it is not fine for a body of a gigabyte -- which cannot be
 * dropped as it is processed, so it stays in memory until the message ends.
 *
 * So a reader counts from the START OF THE CONNECTION instead, and @c origin
 * says how many bytes have already been dropped.  A position measured that way
 * survives all three, and there is nothing to adjust when bytes go -- which is
 * the point: an adjustment that has to be remembered is an adjustment that is
 * forgotten, and forgetting it is silent.
 *
 * | | grows | slides | drops |
 * | :-- | :-- | :-- | :-- |
 * | a pointer | dies | dies | dies |
 * | an offset from @c data | lives | lives | **dies** |
 * | a position in the stream | lives | lives | lives |
 *
 * The spans inside a message -- a field's name, a request's target -- stay
 * offsets from @c data, because they are small, there are many of them, and
 * they die with the message anyway.  What that costs is one rule: **the bytes
 * of a message may not be dropped while anything still points into them.**
 *
 * \~spanish
 * Tres numeros en vez de dos, y el tercero es el que cierra un hueco.
 *
 * Un desplazamiento desde @c data sobrevive a crecer y a deslizar, porque las
 * dos cosas mueven @c data con ellas.  A lo que no sobrevive es a DESCARTAR lo
 * que tiene delante: despues de consumir bytes, el mismo desplazamiento nombra
 * un byte mas adelante.  Eso vale mientras un mensaje se lea de principio a fin
 * y se tire entero, y no vale para un cuerpo de un gigabyte -- que no se puede
 * ir descartando segun se procesa, asi que se queda en memoria hasta que
 * termine el mensaje.
 *
 * Asi que un lector cuenta desde el PRINCIPIO DE LA CONEXION, y @c origin dice
 * cuantos bytes se descartaron ya.  Una posicion medida asi sobrevive a las
 * tres, y no hay nada que ajustar cuando se van bytes -- que es de lo que se
 * trata: un ajuste que hay que acordarse de hacer es un ajuste que se olvida, y
 * olvidarlo es mudo.
 *
 * | | crece | desliza | descarta |
 * | :-- | :-- | :-- | :-- |
 * | un puntero | muere | muere | muere |
 * | un desplazamiento desde @c data | vive | vive | **muere** |
 * | una posicion del flujo | vive | vive | vive |
 *
 * Los trozos de dentro de un mensaje -- el nombre de una cabecera, el destino
 * de una peticion -- siguen siendo desplazamientos desde @c data, porque son
 * pequenos, hay muchos y mueren con el mensaje de todas formas.  Lo que eso
 * cuesta es una regla: **los bytes de un mensaje no se pueden descartar
 * mientras algo siga apuntando dentro de ellos.**
 *
 * \~
 */
struct View {
    /// \~english The first byte that is still here.
    /// \~spanish El primer byte que sigue aqui.  \~
    const uint8_t *data;
    /// \~english How many there are.  \~spanish Cuantos hay.  \~
    size_t size;
    /**
     * \~english
     * Which byte of the connection @c data is.  Zero on a fresh one, and it
     * only ever goes up.
     * \~spanish
     * Que byte de la conexion es @c data.  Cero en una recien hecha, y solo
     * sube.
     * \~
     */
    uint64_t origin;

    /// \~english The stream position one past the last byte here.
    /// \~spanish La posicion del flujo una detras del ultimo byte de aqui.  \~
    uint64_t end() const noexcept { return origin + size; }

    /**
     * @brief
     * \~english Whether @p len bytes from stream position @p at are here.
     * \~spanish Si los @p len bytes desde la posicion @p at del flujo estan aqui.
     * \~
     *
     * \~english
     * Asked before resolving, always.  A position before @c origin names a
     * byte that has already been dropped, and resolving it would produce a
     * pointer BEFORE the buffer -- which is not a read of the wrong bytes, it
     * is a read of somebody else's memory.
     *
     * \~spanish
     * Se pregunta antes de resolver, siempre.  Una posicion anterior a
     * @c origin nombra un byte que ya se descarto, y resolverla produciria un
     * puntero ANTERIOR al buffer -- que no es una lectura de los bytes
     * equivocados, es una lectura de la memoria de otro.
     *
     * \~
     */
    bool has(uint64_t at, uint64_t len) const noexcept {
        return at >= origin && len <= end() - at;
    }

    /**
     * @brief
     * \~english Where stream position @p at is right now.
     * \~spanish Donde esta ahora mismo la posicion @p at del flujo.
     * \~
     * @param at \~english the position  \~spanish la posicion  \~
     * @return   \~english the pointer; only meaningful if @c has said so
     *           \~spanish el puntero; solo significa algo si @c has lo dijo  \~
     */
    const uint8_t *at(uint64_t pos) const noexcept {
        return data + (pos - origin);
    }
};

/**
 * @brief
 * \~english What the first allocation asks for.
 * \~spanish Lo que pide la primera reserva.
 * \~
 *
 * \~english
 * A page.  The ordinary request's header section fits in it with room to
 * spare, which is what makes one read enough (R15); asking for less would buy
 * a second allocation on almost every connection to save bytes on a buffer
 * that only exists while there is traffic on it.
 *
 * \~spanish
 * Una pagina.  La seccion de cabeceras de una peticion corriente cabe en ella
 * con holgura, que es lo que hace que baste una lectura (R15); pedir menos
 * compraria una segunda reserva en casi todas las conexiones por ahorrar bytes
 * en un buffer que solo existe mientras hay trafico en el.
 *
 * \~
 */
constexpr size_t kBufferInitialCapacity = 4096;

/**
 * @brief
 * \~english The ceiling no buffer passes.  A backstop, not a policy.
 * \~spanish El techo que ningun buffer pasa.  Un tope de seguridad, no una politica.
 * \~
 *
 * \~english
 * The real limits are the codec's and they are far lower: how many bytes a
 * header section may take, how long a request line may be.  Those belong with
 * the codec because they differ between the versions and because refusing at
 * that level produces a status code instead of a dead connection.
 *
 * This is underneath them, and it is here for what they do not cover: a bug.
 * A limit that only exists in the layer that is supposed to enforce it is a
 * limit that a mistake in that layer removes, and the consequence of removing
 * this one is the machine rather than the connection.
 *
 * \~spanish
 * Los limites de verdad son los del codec y estan mucho mas abajo: cuantos
 * bytes puede ocupar una seccion de cabeceras, cuanto puede medir una linea de
 * peticion.  Esos van con el codec porque difieren entre las versiones y porque
 * rechazar a ese nivel produce un codigo de estado en vez de una conexion
 * muerta.
 *
 * Este esta por debajo de ellos, y esta aqui para lo que ellos no cubren: un
 * error.  Un limite que solo existe en la capa que tiene que imponerlo es un
 * limite que una equivocacion en esa capa quita, y la consecuencia de quitar
 * este es la maquina y no la conexion.
 *
 * \~
 */
constexpr size_t kBufferMaxCapacity = 64u * 1024u * 1024u;

/**
 * @brief
 * \~english A growing byte buffer that a connection reads into.
 * \~spanish Un buffer de bytes creciente en el que lee una conexion.
 * \~
 */
class Buffer {
  public:
    Buffer() noexcept = default;
    ~Buffer();

    /* \~english
     * Not copyable.  A buffer is the memory of one connection and copying it
     * would be copying a connection, which is not a thing.  It moves, because
     * a connection may change hands between structures.
     * \~spanish
     * No se copia.  Un buffer es la memoria de una conexion y copiarlo seria
     * copiar una conexion, que no es nada.  Se mueve, porque una conexion puede
     * cambiar de manos entre estructuras.
     * \~ */
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
    Buffer(Buffer &&other) noexcept;
    Buffer &operator=(Buffer &&other) noexcept;

    /// \~english The live bytes.  \~spanish Los bytes vivos.  \~
    const uint8_t *data() const noexcept { return base_ + head_; }

    /**
     * @brief
     * \~english The same bytes, to be written over.
     * \~spanish Los mismos bytes, para escribir encima.
     * \~
     *
     * \~english
     * For un-framing in place: a chunked body arrives with its own size lines
     * interleaved through it, so the bytes that MEAN something are not next to
     * each other until somebody moves them.  Moving them where they already
     * are is the cheapest place, and it is the owner of the buffer rewriting
     * its own pending bytes rather than anybody reaching in.
     *
     * It is a separate call from @c data and not a loosening of it, so that
     * writing into the live region is something a caller asks for by name.
     * The one rule is the obvious one: only where the caller has already read.
     * A reader that is still going to look at a byte must not have it changed
     * underneath it.
     *
     * \~spanish
     * Para desentramar en el sitio: un cuerpo por trozos llega con sus propias
     * lineas de tamano intercaladas, asi que los bytes que SIGNIFICAN algo no
     * estan seguidos hasta que alguien los mueve.  Moverlos donde ya estan es el
     * sitio mas barato, y es el dueno del buffer reescribiendo sus propios bytes
     * pendientes y no alguien metiendo mano.
     *
     * Es una llamada aparte de @c data y no un aflojamiento de ella, para que
     * escribir en la region viva sea algo que quien llama pide por su nombre.
     * La unica regla es la evidente: solo donde ya ha leido.  A un lector que
     * todavia va a mirar un byte no se le puede cambiar por debajo.
     *
     * \~
     */
    uint8_t *writable() noexcept { return base_ + head_; }
    /// \~english How many there are.  \~spanish Cuantos hay.  \~
    size_t size() const noexcept { return tail_ - head_; }
    /// \~english Whether there is none.  \~spanish Si no hay ninguno.  \~
    bool empty() const noexcept { return head_ == tail_; }
    /// \~english How much memory it holds.  \~spanish Cuanta memoria tiene.  \~
    size_t capacity() const noexcept { return cap_; }

    /**
     * @brief
     * \~english Which byte of the connection @c data is.
     * \~spanish Que byte de la conexion es @c data.
     * \~
     *
     * \~english
     * It counts what has been dropped, so it only goes up, and it is what
     * makes a position survive the dropping.  It is sixty-four bits because a
     * connection that stays open carries more than four thousand million bytes
     * without anything unusual happening -- and a counter that wrapped would
     * put a reader's position behind the buffer.
     *
     * \~spanish
     * Cuenta lo que se ha descartado, asi que solo sube, y es lo que hace que
     * una posicion sobreviva al descarte.  Son sesenta y cuatro bits porque una
     * conexion que se quede abierta lleva mas de cuatro mil millones de bytes
     * sin que pase nada raro -- y un contador que diera la vuelta pondria la
     * posicion de un lector por detras del buffer.
     *
     * \~
     */
    uint64_t origin() const noexcept { return origin_; }

    /**
     * @brief
     * \~english The bytes that are here, and where they are in the stream.
     * \~spanish Los bytes que hay, y donde estan dentro del flujo.
     * \~
     *
     * \~english
     * The three things a reader needs, taken from one object so they cannot
     * disagree.  Handing them over separately would let a caller pass the
     * pointer of one buffer and the origin of another, which is a mistake that
     * compiles.
     *
     * \~spanish
     * Las tres cosas que necesita un lector, sacadas de un objeto para que no
     * puedan discrepar.  Entregarlas por separado dejaria pasar el puntero de
     * un buffer y el origen de otro, que es una equivocacion que compila.
     *
     * \~
     */
    View view() const noexcept { return View{data(), size(), origin_}; }

    /**
     * @brief
     * \~english Makes sure there is room for @p n more bytes, and says where.
     * \~spanish Se asegura de que hay sitio para @p n bytes mas, y dice donde.
     * \~
     *
     * \~english
     * This is what completion-based I/O needs: the address is handed to the
     * kernel and the bytes appear there later, so it has to exist before there
     * is anything to put in it.
     *
     * It may grow the buffer and it may slide the leftovers to the front, so
     * **`data()` may move**.  Offsets survive that; pointers taken before the
     * call do not.
     *
     * It does not extend `size()`.  The bytes are not there yet -- that is the
     * point -- and it is `commit` that says how many arrived.
     *
     * \~spanish
     * Esto es lo que necesita la entrada y salida por finalizacion: la
     * direccion se le da al sistema y los bytes aparecen ahi despues, asi que
     * tiene que existir antes de que haya nada que poner en ella.
     *
     * Puede hacer crecer el buffer y puede deslizar lo que sobra hacia delante,
     * asi que **`data()` puede moverse**.  Los desplazamientos sobreviven a
     * eso; los punteros tomados antes de la llamada no.
     *
     * No alarga `size()`.  Los bytes todavia no estan -- de eso se trata -- y
     * es `commit` quien dice cuantos llegaron.
     *
     * \~
     * @param n \~english how many writable bytes are wanted
     *          \~spanish cuantos bytes escribibles se quieren  \~
     * @return  \~english where to write, or null if the memory could not be
     *          had; the buffer is left untouched in that case
     *          \~spanish donde escribir, o nulo si no se pudo conseguir la
     *          memoria; en ese caso el buffer se queda como estaba  \~
     */
    uint8_t *reserve(size_t n) noexcept;

    /// \~english Where the writable room starts.  \~spanish Donde empieza el sitio escribible.  \~
    uint8_t *tail() noexcept { return base_ + tail_; }
    /// \~english How much of it there is.  \~spanish Cuanto hay de el.  \~
    size_t tail_room() const noexcept { return cap_ - tail_; }

    /**
     * @brief
     * \~english Says that @p n bytes arrived in the reserved room.
     * \~spanish Dice que llegaron @p n bytes al sitio reservado.
     * \~
     *
     * \~english
     * More than was reserved is a mistake in the caller, not in the peer, and
     * it is clamped rather than trusted: the number comes back from an I/O
     * completion and believing one that is too large would hand the parser
     * bytes nobody wrote.
     *
     * \~spanish
     * Mas de lo que se reservo es una equivocacion de quien llama y no del otro
     * extremo, y se recorta en vez de creerse: el numero vuelve de una
     * finalizacion de entrada y salida, y creerse uno demasiado grande le daria
     * al analizador bytes que no escribio nadie.
     *
     * \~
     * @param n \~english how many bytes arrived  \~spanish cuantos bytes llegaron  \~
     */
    void commit(size_t n) noexcept;

    /**
     * @brief
     * \~english Takes back the last @p n committed bytes, clamped to what is live.
     * \~spanish Retira los ultimos @p n bytes confirmados, recortado a lo que esta vivo.
     * \~
     *
     * \~english
     * For room kept in front of what somebody else may or may not write -- a
     * record header -- that turns out not to be needed.
     * \~spanish
     * Para un sitio guardado delante de lo que otro puede escribir o no -- la
     * cabecera de un registro -- que resulta no hacer falta.
     * \~
     * @param n \~english how many bytes  \~spanish cuantos bytes  \~
     */
    void uncommit(size_t n) noexcept {
        const size_t live = tail_ - head_;
        tail_ -= n < live ? n : live;
    }

    /**
     * @brief
     * \~english Drops the first @p n live bytes: a message is done with.
     * \~spanish Descarta los primeros @p n bytes vivos: un mensaje ya esta.
     * \~
     *
     * \~english
     * **This is the one call that invalidates offsets**, and it is meant to
     * be: what it drops is the message they described.  Anything left over
     * belongs to the next message, which nobody has parsed yet, so there are no
     * offsets into it to break -- and it stays in the buffer so it can be
     * parsed without going back to the socket (R16).
     *
     * Nothing is moved here.  The leftovers slide to the front the next time
     * room is needed, which is the only time it is worth paying for.
     *
     * \~spanish
     * **Esta es la unica llamada que invalida desplazamientos**, y esta pensada
     * para serlo: lo que descarta es el mensaje que describian.  Lo que sobre
     * pertenece al mensaje siguiente, que no ha analizado nadie todavia, asi
     * que no hay desplazamientos que romper -- y se queda en el buffer para
     * poder analizarlo sin volver al socket (R16).
     *
     * Aqui no se mueve nada.  Lo que sobra se desliza hacia delante la proxima
     * vez que haga falta sitio, que es la unica vez en que compensa pagarlo.
     *
     * \~
     * @param n \~english how many bytes to drop  \~spanish cuantos bytes descartar  \~
     */
    void consume(size_t n) noexcept;

    /**
     * @brief
     * \~english Empties it, keeping the memory.
     * \~spanish Lo vacia, conservando la memoria.
     * \~
     */
    void clear() noexcept {
        head_ = 0;
        tail_ = 0;
    }

    /**
     * @brief
     * \~english Empties it for a DIFFERENT connection, keeping the memory.
     * \~spanish Lo vacia para OTRA conexion, conservando la memoria.
     * \~
     *
     * \~english
     * The third thing, and neither of the other two will do.  @c clear empties
     * the buffer for the next message of the same connection, so the stream
     * carries on counting; @c release starts the stream over but gives the
     * memory back.  Handing a buffer from one connection to another needs both
     * halves: the memory stays, and the stream starts at zero.
     *
     * Using @c clear here is the mistake this exists to prevent, and it is a
     * silent one.  The new connection's readers count from the start of the
     * connection, which is zero, while the buffer would still be reporting the
     * PREVIOUS tenant's origin -- so every offset they asked about would be
     * measured from a point that connection never had.  Nothing would report
     * an error; the reads would simply land somewhere else.
     *
     * The bytes are NOT wiped, and that is safe rather than overlooked: the
     * live region is what lies between @c head_ and @c tail_, both of which
     * are now zero, and nothing in this project reads past @c size().  Wiping
     * would be sixteen kilobytes written for every connection that ever
     * spoke, to hide bytes that cannot be reached.
     *
     * \~spanish
     * La tercera cosa, y no vale ninguna de las otras dos.  @c clear vacia el
     * buffer para el mensaje siguiente de la misma conexion, asi que el flujo
     * sigue contando; @c release empieza el flujo de nuevo pero devuelve la
     * memoria.  Pasarle un buffer de una conexion a otra necesita las dos
     * mitades: la memoria se queda, y el flujo empieza en cero.
     *
     * Usar @c clear aqui es la equivocacion para la que existe esto, y es
     * silenciosa.  Los lectores de la conexion nueva cuentan desde el principio
     * de la conexion, que es cero, mientras que el buffer seguiria diciendo el
     * origen del inquilino ANTERIOR -- asi que todos los desplazamientos por los
     * que preguntaran se medirian desde un punto que esa conexion no tuvo nunca.
     * Nadie daria ningun error; las lecturas caerian simplemente en otro sitio.
     *
     * Los bytes NO se borran, y eso es seguro y no un descuido: la region viva
     * es lo que hay entre @c head_ y @c tail_, que ahora son los dos cero, y
     * nada de este proyecto lee mas alla de @c size().  Borrarlos serian
     * dieciseis kilobytes escritos por cada conexion que haya hablado, para
     * esconder unos bytes a los que no se puede llegar.
     *
     * \~
     */
    void recycle() noexcept {
        head_ = 0;
        tail_ = 0;
        origin_ = 0;
    }

    /**
     * @brief
     * \~english Says this empty buffer carries on from byte @p at of a connection.
     * \~spanish Dice que este buffer vacio sigue desde el byte @p at de una conexion.
     * \~
     *
     * \~english
     * The fourth thing, and it exists because R1 and the stream position pull
     * against each other.  A connection that has nothing in flight gives its
     * buffer back, and the next one it is lent has been recycled -- so it
     * starts the stream at zero, while the connection is four thousand bytes
     * in.  Every position a reader remembered is then measured from a point
     * that connection passed long ago.
     *
     * Nothing reports that.  A reader asking for a position it kept gets told
     * the bytes are not here -- @c View::has is doing exactly its job -- and
     * what the caller sees is a connection that stops making progress with
     * every frame of it perfectly legal.  It is the failure shape this whole
     * file was written to avoid, arriving through the one door left open: the
     * stream is a property of the CONNECTION and the count was living in the
     * buffer.
     *
     * Only on an empty one, because on any other it would move bytes that are
     * already here without moving what points at them.
     *
     * \~spanish
     * La cuarta cosa, y existe porque la R1 y la posicion del flujo tiran en
     * sentidos contrarios.  Una conexion sin nada en vuelo devuelve su buffer, y
     * el siguiente que le prestan viene reciclado -- asi que empieza el flujo en
     * cero, mientras la conexion lleva cuatro mil bytes --.  Todas las posiciones
     * que recordara un lector quedan entonces medidas desde un punto por el que
     * esa conexion paso hace rato.
     *
     * Eso no lo dice nadie.  Un lector que pregunte por una posicion que guardo
     * recibe que esos bytes no estan -- @c View::has haciendo justo su trabajo --
     * y lo que se ve desde fuera es una conexion que deja de avanzar con todas
     * sus tramas perfectamente legales.  Es el modo de fallar que este fichero
     * entero se escribio para evitar, llegando por la unica puerta que quedaba
     * abierta: el flujo es una propiedad de la CONEXION y la cuenta vivia en el
     * buffer.
     *
     * Solo sobre uno vacio, porque sobre cualquier otro moveria unos bytes que
     * ya estan aqui sin mover lo que les apunta.
     *
     * \~
     * @param at \~english which byte of the connection the next one will be
     *           \~spanish que byte de la conexion sera el siguiente  \~
     */
    void rebase(uint64_t at) noexcept {
        if (head_ != tail_) return;
        head_ = 0;
        tail_ = 0;
        origin_ = at;
    }

    /**
     * @brief
     * \~english Gives the memory back.
     * \~spanish Devuelve la memoria.
     * \~
     *
     * \~english
     * This is what R1 is made of: a connection with nothing in flight has no
     * buffer.  It is not an optimisation with a name -- at a million
     * connections, a four-kilobyte buffer that outlives its traffic is four
     * gigabytes of memory holding nothing.
     *
     * \~spanish
     * De esto esta hecho R1: una conexion sin nada en vuelo no tiene buffer.
     * No es una optimizacion con nombre -- a un millon de conexiones, un buffer
     * de cuatro kilobytes que sobreviva a su trafico son cuatro gigabytes de
     * memoria sin nada dentro.
     *
     * \~
     */
    void release() noexcept;

  private:
    /**
     * \~english
     * Slides the live bytes to the front.  Called only from @c reserve, and
     * only when it buys the room that was asked for.
     *
     * Cold, like @c grow below and for the same reason: what runs on every
     * read is @c reserve finding the room already there, and these two are
     * what it does when it does not.  Keeping them out of that path is a
     * matter of what shares a cache line with the loop that reads the bytes.
     *
     * \~spanish
     * Desliza los bytes vivos hacia delante.  Se llama solo desde @c reserve, y
     * solo cuando compra el sitio que se pidio.
     *
     * En frio, como @c grow de abajo y por lo mismo: lo que corre en cada
     * lectura es @c reserve encontrando el sitio ya puesto, y estas dos son lo
     * que hace cuando no.  Mantenerlas fuera de ese camino es cuestion de que
     * comparte linea de cache con el bucle que lee los bytes.
     * \~
     */
    [[gnu::noinline, gnu::cold]] void compact() noexcept;

    /**
     * \~english
     * Asks for a bigger block and moves the live bytes into it.
     * \~spanish
     * Pide un bloque mayor y traslada a el los bytes vivos.
     * \~
     */
    [[gnu::noinline, gnu::cold]] bool grow(size_t want) noexcept;

    uint8_t *base_ = nullptr;
    size_t cap_ = 0;
    size_t head_ = 0;
    size_t tail_ = 0;

    /**
     * \~english
     * How many bytes of the connection have been dropped.  It is not reset by
     * @c clear, which empties the buffer for the NEXT message of the same
     * connection: the stream carries on, and a position from before would be
     * as valid as it ever was.  @c release does reset it, because that is a
     * connection ending.
     * \~spanish
     * Cuantos bytes de la conexion se han descartado.  No lo reinicia
     * @c clear, que vacia el buffer para el mensaje SIGUIENTE de la misma
     * conexion: el flujo sigue, y una posicion de antes vale lo mismo que
     * valia.  @c release si lo reinicia, porque eso es una conexion que acaba.
     * \~
     */
    uint64_t origin_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_BUFFER_H
