/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/buffer_pool.h
 * @brief
 * \~english The buffers, lent to whoever is talking right now.
 * \~spanish Los buffers, prestados a quien este hablando ahora mismo.
 * \~
 *
 * \~english
 * R1 says an idle connection has no buffer, and this is the sentence made of
 * code.  It is the difference between a server that holds a million buffers
 * and one that holds as many as there are people mid-sentence -- which, on any
 * real connection, is a small fraction of the time.  A browser opens six
 * connections and keeps them for minutes; it is talking on them for
 * milliseconds.
 *
 * **So the pool is deliberately smaller than the connection table, and that is
 * the whole design rather than a setting.**  Its size is chosen from how many
 * connections are mid-message at once, not from how many exist.  Sixteen
 * kilobytes times a million is sixteen gigabytes; sixteen kilobytes times ten
 * thousand is a hundred and sixty megabytes, and it serves the same million
 * connections.
 *
 * **And an empty pool is not an error.**  It is the server saying it is at its
 * limit, and the answer is that a connection which cannot get a buffer does
 * not read this time round.  The bytes stay in the kernel's receive queue,
 * which is a place designed to hold them, and TCP slows the peer down by
 * itself.  Failing here instead would be turning a busy moment into dropped
 * connections.
 *
 * \~spanish
 * La R1 dice que una conexion parada no tiene buffer, y esto es esa frase hecha
 * codigo.  Es la diferencia entre un servidor que tiene un millon de buffers y
 * uno que tiene tantos como gente haya a media frase -- que, en cualquier
 * conexion real, es una fraccion pequena del tiempo.  Un navegador abre seis
 * conexiones y las tiene minutos; esta hablando por ellas milisegundos.
 *
 * **Asi que el pozo es a proposito mas pequeno que la tabla de conexiones, y eso
 * es todo el diseno y no un ajuste.**  Su tamano sale de cuantas conexiones
 * estan a mitad de mensaje a la vez, no de cuantas existen.  Dieciseis
 * kilobytes por un millon son dieciseis gigabytes; dieciseis kilobytes por diez
 * mil son ciento sesenta megabytes, y sirven al mismo millon de conexiones.
 *
 * **Y un pozo vacio no es un error.**  Es el servidor diciendo que esta en su
 * limite, y la respuesta es que una conexion que no consigue buffer no lee esta
 * vuelta.  Los bytes se quedan en la cola de recepcion del nucleo, que es un
 * sitio hecho para guardarlos, y TCP frena al otro extremo el solo.  Fallar aqui
 * en vez de eso seria convertir un momento de mucho trabajo en conexiones
 * caidas.
 *
 * \~
 */
#ifndef HTTP_VX_BUFFER_POOL_H
#define HTTP_VX_BUFFER_POOL_H

#include "http_vx/buffer.h"
#include "http_vx/conn_table.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english The buffers of one shard.
 * \~spanish Los buffers de un fragmento.
 * \~
 */
class BufferPool {
  public:
    BufferPool() noexcept = default;
    ~BufferPool();

    BufferPool(const BufferPool &) = delete;
    BufferPool &operator=(const BufferPool &) = delete;

    /**
     * @brief
     * \~english Makes @p count buffers, each allowed to grow to @p ceiling.
     * \~spanish Hace @p count buffers, cada uno con permiso para crecer hasta @p ceiling.
     * \~
     *
     * \~english
     * No memory for the buffers themselves is taken here.  A @c Buffer does
     * not allocate until something is written into it, so a pool that has been
     * made and not used costs the array of them and nothing else -- which
     * matters because a shard is made when the server starts and may not see
     * traffic for a while.
     *
     * @p ceiling is what a buffer may grow to before it is thrown away rather
     * than lent again; see @c release.
     *
     * \~spanish
     * Aqui no se coge memoria para los buffers.  Un @c Buffer no reserva hasta
     * que le escriben algo, asi que un pozo hecho y sin usar cuesta el array de
     * ellos y nada mas -- que importa porque un fragmento se hace al arrancar el
     * servidor y puede tardar en ver trafico.
     *
     * @p ceiling es lo que puede crecer un buffer antes de tirarlo en vez de
     * volver a prestarlo; ver @c release.
     *
     * \~
     * @param count   \~english how many buffers  \~spanish cuantos buffers  \~
     * @param ceiling \~english the most one may keep between tenants
     *                \~spanish lo mas que puede guardar uno entre inquilinos  \~
     * @return        \~english false if the memory could not be had
     *                \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t count, size_t ceiling) noexcept;

    /**
     * @brief
     * \~english Lends one out, or says there are none.
     * \~spanish Presta uno, o dice que no hay.
     * \~
     *
     * \~english
     * The buffer comes back EMPTY and with its stream starting at zero, which
     * is @c Buffer::recycle and not @c Buffer::clear.  The difference is the
     * previous tenant's origin, and getting it wrong is silent: the new
     * connection's readers count from the start of the connection, and every
     * offset they asked about would be measured from a point that connection
     * never had.
     *
     * \~spanish
     * El buffer vuelve VACIO y con su flujo empezando en cero, que es
     * @c Buffer::recycle y no @c Buffer::clear.  La diferencia es el origen del
     * inquilino anterior, y equivocarse es silencioso: los lectores de la
     * conexion nueva cuentan desde el principio de la conexion, y todos los
     * desplazamientos por los que preguntaran se medirian desde un punto que esa
     * conexion no tuvo nunca.
     *
     * \~
     * @return \~english which buffer, or @c kNoBuffer when the pool is empty
     *         \~spanish que buffer, o @c kNoBuffer cuando el pozo esta vacio  \~
     */
    uint32_t acquire() noexcept;

    /**
     * @brief
     * \~english Takes @p i back.
     * \~spanish Recoge @p i.
     * \~
     *
     * \~english
     * **A buffer that grew past the ceiling gives its memory back instead of
     * being kept.**  One huge upload makes a buffer huge, and a pool that
     * simply kept it would let every slot creep up to the largest thing that
     * ever went through it -- so the pool's memory would converge on the peak
     * times the count, on a server that never looked like it was leaking.
     *
     * The ordinary buffer keeps its memory, which is the point of a pool: what
     * is being reused is the allocation, not the object.
     *
     * \~spanish
     * **Un buffer que crecio por encima del techo devuelve su memoria en vez de
     * quedarse.**  Una subida enorme hace enorme un buffer, y un pozo que se lo
     * quedara sin mas dejaria que todas las plazas fueran subiendo hasta lo mas
     * grande que haya pasado por ellas -- asi que la memoria del pozo tenderia
     * al pico por el numero, en un servidor que no pareceria tener ninguna fuga.
     *
     * El buffer corriente conserva su memoria, que es de lo que va un pozo: lo
     * que se reutiliza es la reserva, no el objeto.
     *
     * \~
     * @param i \~english which buffer  \~spanish que buffer  \~
     */
    void release(uint32_t i) noexcept;

    /**
     * @brief
     * \~english The buffer @p i, or null if that is not one.
     * \~spanish El buffer @p i, o nulo si no es uno.
     * \~
     *
     * \~english
     * There is no check that @p i is lent out rather than sitting in the pool,
     * and there cannot usefully be one: a buffer's index is held by exactly
     * one connection, handed back the moment it is done, and never given to a
     * timer or a kernel completion -- so there is no previous life for a
     * reference to come from.  That is the difference from @c ConnTable, where
     * the whole design is about references outliving what they name.
     *
     * \~spanish
     * No se comprueba que @p i este prestado y no descansando en el pozo, y no
     * podria comprobarse de forma util: el indice de un buffer lo tiene
     * exactamente una conexion, se devuelve en cuanto acaba, y no se le da nunca
     * a un plazo ni a una finalizacion del nucleo -- asi que no hay ninguna vida
     * anterior de la que pueda venir una referencia.  Esa es la diferencia con
     * @c ConnTable, cuyo diseno entero va de referencias que sobreviven a lo que
     * nombran.
     *
     * \~
     * @param i \~english which buffer  \~spanish que buffer  \~
     * @return  \~english the buffer, or null  \~spanish el buffer, o nulo  \~
     */
    Buffer *at(uint32_t i) noexcept;

    /// \~english How many are lent out.  \~spanish Cuantos hay prestados.  \~
    size_t lent() const noexcept { return lent_; }

    /// \~english How many there are.  \~spanish Cuantos hay.  \~
    uint32_t count() const noexcept { return count_; }

    /**
     * @brief
     * \~english How many bytes the buffers are holding between them.
     * \~spanish Cuantos bytes tienen los buffers entre todos.
     * \~
     *
     * \~english
     * What R1 is worth, as a number somebody can read.  A claim about memory
     * that nothing can report is a claim that stops being true without anybody
     * finding out.
     *
     * \~spanish
     * Lo que vale R1, como un numero que alguien puede leer.  Una afirmacion
     * sobre memoria que no puede decir nadie es una afirmacion que deja de ser
     * cierta sin que se entere nadie.
     *
     * \~
     */
    size_t bytes_held() const noexcept;

    /// \~english Gives all the memory back.  \~spanish Devuelve toda la memoria.  \~
    void release_all() noexcept;

  private:
    Buffer *buffers_ = nullptr;

    /**
     * \~english
     * The free ones, as a stack.  A stack and NOT the queue the connection
     * table uses, and the contrast is the point: the queue is there because a
     * connection's index outlives the connection in timers and kernel
     * completions, so the longest possible wait before reuse is worth a cache
     * miss.  A buffer's index does not outlive anything -- one connection
     * holds it and hands it straight back -- so there is nothing to protect
     * against and the warm one is simply better.
     *
     * \~spanish
     * Los libres, como una pila.  Una pila y NO la cola que usa la tabla de
     * conexiones, y el contraste es lo que importa: la cola esta ahi porque el
     * indice de una conexion le sobrevive en plazos y finalizaciones del nucleo,
     * asi que la espera mas larga posible antes de reutilizar vale un fallo de
     * cache.  El indice de un buffer no le sobrevive a nada -- lo tiene una
     * conexion y lo devuelve enseguida -- asi que no hay de que protegerse y el
     * caliente es sencillamente mejor.
     * \~
     */
    uint32_t *next_free_ = nullptr;
    uint32_t free_head_ = kNoBuffer;

    uint32_t count_ = 0;
    size_t ceiling_ = 0;
    size_t lent_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_BUFFER_POOL_H
