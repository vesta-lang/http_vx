/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_table.h
 * @brief
 * \~english The fields a connection remembers, and how long it keeps them.
 * \~spanish Las cabeceras que recuerda una conexion, y cuanto las guarda.
 * \~
 *
 * \~english
 * This is the half of HPACK that has state, and everything difficult about
 * HPACK is here.
 *
 * What it does is simple: a field that has been sent once is remembered, and
 * from then on it is an index.  What makes it difficult is that the memory
 * belongs to the CONNECTION and not to the message -- so both ends must agree
 * on it byte for byte, forever, or every index after the disagreement names a
 * different field.  There is no way to notice: the block still decodes.
 *
 * Three things follow from that, and they shape this file:
 *
 *  - **the size is counted the specification's way, not the machine's.**  An
 *    entry costs its name plus its value plus thirty-two, and the thirty-two
 *    is not an estimate of anything here -- it is a number both ends add so
 *    that they evict at the same moment.  Counting what the entry really
 *    takes would be right about this machine and wrong about the protocol.
 *  - **eviction is from the oldest, always**, which is what lets the bytes
 *    live in a ring: they leave in the order they arrived.
 *  - **and the table is not made until it is used.**  Four kilobytes on a
 *    million connections is four gigabytes, and a connection whose fields all
 *    come from the static table -- which is most of a `GET` -- never needs
 *    one.
 *
 * \~spanish
 * Esta es la mitad de HPACK que tiene estado, y todo lo dificil de HPACK esta
 * aqui.
 *
 * Lo que hace es sencillo: una cabecera que se ha mandado una vez se recuerda,
 * y a partir de ahi es un indice.  Lo que lo hace dificil es que la memoria es
 * de la CONEXION y no del mensaje -- asi que los dos extremos tienen que estar
 * de acuerdo sobre ella byte a byte, para siempre, o todos los indices
 * posteriores a la discrepancia nombran otra cabecera.  Y no hay forma de
 * notarlo: el bloque se sigue descodificando.
 *
 * De ahi salen tres cosas, y dan forma a este fichero:
 *
 *  - **el tamano se cuenta como dice la especificacion, no como lo cuenta la
 *    maquina.**  Una entrada cuesta su nombre mas su valor mas treinta y dos,
 *    y los treinta y dos no son una estimacion de nada de aqui -- son un
 *    numero que suman los dos extremos para desalojar en el mismo momento.
 *    Contar lo que la entrada ocupa de verdad seria acertar sobre esta maquina
 *    y errar sobre el protocolo.
 *  - **se desaloja siempre por la mas vieja**, que es lo que permite que los
 *    bytes vivan en un anillo: se van en el orden en que llegaron.
 *  - **y la tabla no se hace hasta que se usa.**  Cuatro kilobytes en un millon
 *    de conexiones son cuatro gigabytes, y una conexion cuyas cabeceras salgan
 *    todas de la tabla estatica -- que es casi todo un `GET` -- no necesita
 *    una nunca.
 *
 * \~
 */
#ifndef HTTP_VX_H2_TABLE_H
#define HTTP_VX_H2_TABLE_H

#include "http_vx/field.h"
#include "http_vx/h2_hpack.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {
namespace hpack {

/**
 * @brief
 * \~english What the specification adds to every entry.
 * \~spanish Lo que la especificacion suma a cada entrada.
 * \~
 *
 * \~english
 * RFC 7541 section 4.1 picks thirty-two and says it stands for whatever an
 * implementation spends on an entry besides the bytes.  What matters is not
 * whether it is a good estimate -- it is not one for this implementation or
 * for any other -- but that BOTH ENDS USE IT.  An encoder that counted its own
 * real cost would evict at a different moment from the decoder, and from then
 * on the two would disagree about what every index means.
 *
 * \~spanish
 * El RFC 7541 seccion 4.1 elige treinta y dos y dice que representa lo que una
 * implementacion gaste en una entrada aparte de los bytes.  Lo que importa no
 * es si es una buena estimacion -- no lo es para esta implementacion ni para
 * ninguna -- sino que LO USAN LOS DOS EXTREMOS.  Un codificador que contara su
 * coste real desalojaria en un momento distinto que el descodificador, y a
 * partir de ahi los dos discreparian sobre lo que significa cada indice.
 *
 * \~
 */
constexpr uint32_t kEntryOverhead = 32;

/**
 * @brief
 * \~english One remembered field.
 * \~spanish Una cabecera recordada.
 * \~
 *
 * \~english
 * The bytes are not here: they are in the table's own storage, and they may be
 * in two pieces because that storage is a ring.  Which is why they are read
 * with @c DynamicTable::copy_name rather than pointed at -- a pointer would be
 * a promise the ring cannot keep.
 *
 * \~spanish
 * Los bytes no estan aqui: estan en el almacen de la tabla, y pueden estar en
 * dos pedazos porque ese almacen es un anillo.  Que es la razon de que se lean
 * con @c DynamicTable::copy_name y no se apunten -- un puntero seria una
 * promesa que el anillo no puede cumplir.
 *
 * \~
 */
struct TableEntry {
    /**
     * \~english
     * Where its bytes start in the ring.  Written once and never touched
     * again: evicting moves the ring's HEAD, and an entry that survives an
     * eviction is still exactly where it was put.
     *
     * So this is not a second thing to keep in step with the ring -- which is
     * what it looked like at first, and what made the first version of this
     * walk the entries in front of it to work the position out.  That walk was
     * work for nothing, on every indexed field.
     *
     * \~spanish
     * Donde empiezan sus bytes en el anillo.  Se escribe una vez y no se toca
     * mas: desalojar mueve la CABEZA del anillo, y una entrada que sobrevive a
     * un desalojo sigue exactamente donde se puso.
     *
     * Asi que esto no es una segunda cosa que mantener de acuerdo con el anillo
     * -- que es lo que parecia al principio, y lo que hizo que la primera
     * version de esto recorriera las entradas de delante para averiguar la
     * posicion.  Ese recorrido era trabajo para nada, en cada cabecera
     * indexada.
     * \~
     */
    uint32_t byte_off;
    uint16_t name_len;
    uint16_t value_len;
    /// \~english What the name is, when this project knows it.
    /// \~spanish Que es el nombre, cuando este proyecto lo conoce.  \~
    FieldId id;
    /// \~english Which piece of a request it is, when it is one.
    /// \~spanish Que pieza de una peticion es, cuando lo es.  \~
    Pseudo pseudo;

    /// \~english What it costs against the limit.
    /// \~spanish Lo que cuesta contra el limite.  \~
    uint32_t cost() const noexcept {
        return static_cast<uint32_t>(name_len) + value_len + kEntryOverhead;
    }
};

/**
 * @brief
 * \~english The fields one connection remembers.
 * \~spanish Las cabeceras que recuerda una conexion.
 * \~
 */
class DynamicTable {
  public:
    DynamicTable() noexcept = default;
    ~DynamicTable();

    DynamicTable(const DynamicTable &) = delete;
    DynamicTable &operator=(const DynamicTable &) = delete;

    /**
     * @brief
     * \~english Says the most this table may ever hold, and empties it.
     * \~spanish Dice lo mas que puede tener esta tabla, y la vacia.
     * \~
     *
     * \~english
     * @p announced is what this server told the peer it would accept.  It is
     * the CEILING and not the current limit: the peer may ask for less at any
     * time, and may never ask for more.  Nothing is allocated here -- the
     * number is remembered and the memory waits until a field is actually
     * remembered.
     *
     * \~spanish
     * @p announced es lo que este servidor le dijo al otro extremo que
     * aceptaria.  Es el TECHO y no el limite actual: el otro extremo puede
     * pedir menos cuando quiera, y no puede pedir mas nunca.  Aqui no se
     * reserva nada -- el numero se recuerda y la memoria espera a que se
     * recuerde una cabecera de verdad.
     *
     * \~
     * @param announced \~english what was announced to the peer
     *                  \~spanish lo que se le anuncio al otro extremo  \~
     */
    void reset(uint32_t announced) noexcept;

    /**
     * @brief
     * \~english Takes the peer's request to make the table smaller, or bigger.
     * \~spanish Acepta que el otro extremo haga la tabla menor, o mayor.
     * \~
     *
     * \~english
     * A peer may change the limit within what was announced, and it evicts
     * immediately if the new one is smaller.  Asking for more than was
     * announced is refused: the announcement is what this end reserved its
     * arithmetic for, and a peer that ignores it is the peer a limit exists
     * for.
     *
     * \~spanish
     * Un extremo puede cambiar el limite dentro de lo que se anuncio, y
     * desaloja en el acto si el nuevo es menor.  Pedir mas de lo anunciado se
     * rechaza: el anuncio es aquello para lo que este extremo reservo su
     * aritmetica, y un extremo que lo ignore es el extremo para el que existe
     * un limite.
     *
     * \~
     * @param n \~english the new limit  \~spanish el limite nuevo  \~
     * @return  \~english false if it is more than was announced
     *          \~spanish false si es mas de lo anunciado  \~
     */
    bool set_max_size(uint32_t n) noexcept;

    /**
     * @brief
     * \~english Remembers a field, evicting whatever has to go.
     * \~spanish Recuerda una cabecera, desalojando lo que tenga que irse.
     * \~
     *
     * \~english
     * The bytes are COPIED, which is the one place in this project that copies
     * a header and the one place where copying is right: the entry outlives
     * the message it came in, and a span into that message would name bytes
     * that the connection dropped several requests ago.
     *
     * An entry larger than the whole table empties the table and is not added.
     * That is not an error and it must not be treated as one -- the
     * specification says so in as many words, and both ends do it, so a
     * decoder that refused would be refusing a message an encoder is allowed
     * to send.
     *
     * \~spanish
     * Los bytes se COPIAN, que es el unico sitio de este proyecto donde se
     * copia una cabecera y el unico donde copiar esta bien: la entrada
     * sobrevive al mensaje en el que vino, y un trozo de ese mensaje nombraria
     * bytes que la conexion descarto hace varias peticiones.
     *
     * Una entrada mayor que la tabla entera vacia la tabla y no se anade.  Eso
     * no es un error y no se puede tratar como tal -- la especificacion lo dice
     * con todas las letras, y los dos extremos lo hacen, asi que un
     * descodificador que rechazara estaria rechazando un mensaje que un
     * codificador puede mandar.
     *
     * \~
     * @param name   \~english the name's bytes  \~spanish los bytes del nombre  \~
     * @param nlen   \~english how many  \~spanish cuantos  \~
     * @param value  \~english the value's bytes  \~spanish los bytes del valor  \~
     * @param vlen   \~english how many  \~spanish cuantos  \~
     * @param id     \~english what the name is, if known
     *               \~spanish que es el nombre, si se conoce  \~
     * @param pseudo \~english which piece of a request it is, if it is one
     *               \~spanish que pieza de una peticion es, si lo es  \~
     * @return       \~english false only if the memory could not be had
     *               \~spanish false solo si no se pudo conseguir la memoria  \~
     */
    bool add(const uint8_t *name, size_t nlen, const uint8_t *value,
             size_t vlen, FieldId id, Pseudo pseudo) noexcept;

    /**
     * @brief
     * \~english The entry at @p i, counting from the most recent.
     * \~spanish La entrada en @p i, contando desde la mas reciente.
     * \~
     *
     * \~english
     * Zero is the one just added.  That is the specification's order and it is
     * the opposite of the order the bytes are in, which is why the index is
     * turned around here and not by every caller: the one place that knows
     * about the ring is the one place that should do the arithmetic.
     *
     * \~spanish
     * El cero es la que se acaba de anadir.  Ese es el orden de la
     * especificacion y es el contrario del orden en que estan los bytes, que es
     * la razon de que el indice se de la vuelta aqui y no en cada llamante: el
     * unico sitio que sabe del anillo es el unico que deberia hacer la
     * aritmetica.
     *
     * \~
     * @param i \~english how far back  \~spanish cuanto hacia atras  \~
     * @return  \~english the entry, or null  \~spanish la entrada, o nulo  \~
     */
    const TableEntry *at(size_t i) const noexcept;

    /**
     * @brief
     * \~english Copies the name of entry @p i into @p out.
     * \~spanish Copia el nombre de la entrada @p i en @p out.
     * \~
     *
     * \~english
     * Copied rather than pointed at because the bytes live in a ring and may
     * be in two pieces.  The caller has somewhere to put them anyway: what it
     * is building is the decompressed header list, which is a different place
     * from both the message and this table.
     *
     * \~spanish
     * Copiado y no apuntado porque los bytes viven en un anillo y pueden estar
     * en dos pedazos.  Quien llama tiene donde ponerlos de todas formas: lo que
     * esta construyendo es la lista de cabeceras descomprimida, que es un sitio
     * distinto del mensaje y de esta tabla.
     *
     * \~
     * @param i   \~english how far back  \~spanish cuanto hacia atras  \~
     * @param out \~english where to put them  \~spanish donde ponerlos  \~
     * @param cap \~english how much room there is  \~spanish cuanto sitio hay  \~
     * @return    \~english how many bytes, or zero if there was no room or no
     *            entry
     *            \~spanish cuantos bytes, o cero si no habia sitio ni entrada  \~
     */
    size_t copy_name(size_t i, uint8_t *out, size_t cap) const noexcept;

    /// \~english The same for the value.  \~spanish Lo mismo para el valor.  \~
    size_t copy_value(size_t i, uint8_t *out, size_t cap) const noexcept;

    /// \~english How many entries there are.  \~spanish Cuantas entradas hay.  \~
    size_t count() const noexcept { return count_; }

    /// \~english What they cost between them.  \~spanish Lo que cuestan entre todas.  \~
    uint32_t size() const noexcept { return size_; }

    /// \~english The limit right now.  \~spanish El limite ahora mismo.  \~
    uint32_t max_size() const noexcept { return max_; }

    /// \~english The most it may ever be.  \~spanish Lo mas que puede llegar a ser.  \~
    uint32_t announced() const noexcept { return announced_; }

    /**
     * @brief
     * \~english Gives the memory back.
     * \~spanish Devuelve la memoria.
     * \~
     *
     * \~english
     * What a connection does when it goes quiet.  The limit is remembered, so
     * the table can be used again without being told about it twice.
     *
     * \~spanish
     * Lo que hace una conexion cuando se queda callada.  El limite se recuerda,
     * asi que la tabla se puede volver a usar sin que se lo digan dos veces.
     *
     * \~
     */
    void release() noexcept;

  private:
    /// \~english Throws out the oldest.  \~spanish Tira la mas vieja.  \~
    void evict_oldest() noexcept;

    /// \~english Makes the storage, the first time it is needed.
    /// \~spanish Hace el almacen, la primera vez que hace falta.  \~
    [[gnu::noinline, gnu::cold]] bool make_room() noexcept;

    size_t copy_piece(size_t at, size_t len, uint8_t *out,
                      size_t cap) const noexcept;

    /**
     * \~english
     * The bytes, as a ring.  A ring works because entries leave in the order
     * they arrived, which is the one thing the specification fixes about
     * eviction.
     * \~spanish
     * Los bytes, como un anillo.  Un anillo vale porque las entradas se van en
     * el orden en que llegaron, que es lo unico que fija la especificacion
     * sobre el desalojo.
     * \~
     */
    uint8_t *bytes_ = nullptr;
    size_t bytes_cap_ = 0;
    size_t bytes_head_ = 0;
    size_t bytes_len_ = 0;

    /// \~english The entries, also a ring.  \~spanish Las entradas, tambien un anillo.  \~
    TableEntry *entries_ = nullptr;
    size_t entries_cap_ = 0;
    size_t oldest_ = 0;
    size_t count_ = 0;

    uint32_t size_ = 0;
    uint32_t max_ = 0;
    uint32_t announced_ = 0;
};

} // namespace hpack
} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_TABLE_H
