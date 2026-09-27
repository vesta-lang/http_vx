/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/id_index.h
 * @brief
 * \~english Where a 64-bit identifier lives in a table of fixed slots, in constant time.
 * \~spanish Donde vive un identificador de 64 bits en una tabla de casillas fijas, en tiempo constante.
 * \~
 *
 * \~english
 * Every table in this project that holds things by an identifier the peer
 * chooses -- QUIC streams, HTTP/3 requests -- needs the same answer: which
 * slot has this identifier.  A walk over the slots answers it in time
 * proportional to the table, on every frame; this answers it in one probe or
 * a few.
 *
 * Open addressing with linear probing, and BACKWARD-SHIFT deletion: when an
 * entry goes, the ones after it that had probed past its place move back.
 * No tombstones, so a table that sees millions of identifiers come and go
 * never slows down with dead entries.  The table is sized once, at least
 * twice the entries it will ever hold, so a probe sequence stays short and
 * inserting never has to grow anything.
 *
 * The identifiers are not a secret-keyed hash's input: the ones this holds
 * are bounded and sequential (a peer can open a stream only within the limit
 * it was given), so a peer cannot pick them to collide.
 *
 * \~spanish
 * Toda tabla de este proyecto que guarda cosas por un identificador que elige
 * el otro extremo -- flujos QUIC, peticiones HTTP/3 -- necesita la misma
 * respuesta: que casilla tiene este identificador.  Recorrer las casillas lo
 * contesta en un tiempo proporcional a la tabla, en cada trama; esto lo
 * contesta en una prueba o en unas pocas.
 *
 * Direccionamiento abierto con sondeo lineal, y borrado DESPLAZANDO HACIA
 * ATRAS: cuando una entrada se va, las de detras que pasaron por su sitio al
 * buscar hueco vuelven a el.  Sin lapidas, asi que una tabla que ve ir y venir
 * millones de identificadores no se ralentiza con entradas muertas.  La tabla
 * se dimensiona una vez, al menos el doble de las entradas que tendra nunca,
 * asi que una secuencia de sondeo se queda corta e insertar no tiene que hacer
 * crecer nada.
 *
 * Los identificadores no son la entrada de un hash con clave secreta: los que
 * guarda esto estan acotados y son secuenciales (un extremo solo puede abrir
 * un flujo dentro del limite que se le dio), asi que el otro no puede elegirlos
 * para que choquen.
 * \~
 */
#ifndef HTTP_VX_ID_INDEX_H
#define HTTP_VX_ID_INDEX_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english A map from 64-bit identifiers to 32-bit slots, of fixed room.
 * \~spanish Un mapa de identificadores de 64 bits a casillas de 32 bits, de sitio fijo.
 * \~
 */
class IdIndex {
public:
    /// \~english What @c find answers for an identifier that is not there.
    /// \~spanish Lo que contesta @c find para un identificador que no esta.  \~
    static constexpr uint32_t kAbsent = 0xFFFFFFFFu;

    /// \~english The one identifier that cannot be held: it marks an empty place.
    /// \~spanish El unico identificador que no se puede guardar: marca un sitio vacio.  \~
    static constexpr uint64_t kNoId = ~uint64_t{0};

    IdIndex() noexcept = default;
    ~IdIndex();
    IdIndex(const IdIndex &) = delete;
    IdIndex &operator=(const IdIndex &) = delete;

    /**
     * @brief
     * \~english Makes room for @p most identifiers at once, forgetting any held.
     * \~spanish Hace sitio para @p most identificadores a la vez, olvidando los que haya.
     * \~
     *
     * @return \~english false if the memory could not be had or @p most is zero
     *         \~spanish false si no se pudo conseguir la memoria o @p most es cero  \~
     */
    bool reset(size_t most) noexcept;

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

    /**
     * @brief
     * \~english Remembers that @p id lives in @p slot; @p id must not be held already.
     * \~spanish Recuerda que @p id vive en @p slot; @p id no debe estar ya.
     * \~
     *
     * @return \~english false if @p id is @c kNoId or @p most are held already
     *         \~spanish false si @p id es @c kNoId o ya hay @p most  \~
     */
    bool insert(uint64_t id, uint32_t slot) noexcept;

    /// \~english The slot of @p id, or @c kAbsent.  \~spanish La casilla de @p id, o @c kAbsent.  \~
    uint32_t find(uint64_t id) const noexcept;

    /// \~english Forgets @p id; false if it was not held.  \~spanish Olvida @p id; false si no estaba.  \~
    bool erase(uint64_t id) noexcept;

    /// \~english How many are held.  \~spanish Cuantos hay.  \~
    size_t size() const noexcept { return count_; }

private:
    struct Entry {
        uint64_t id;
        uint32_t slot;
    };

    /// \~english The place @p id is looked for first.  \~spanish El sitio donde se busca @p id primero.  \~
    size_t home(uint64_t id) const noexcept;

    /// \~english The place holding @p id, or the table's size if none.  \~spanish El sitio que tiene @p id, o el tamano de la tabla si ninguno.  \~
    size_t place(uint64_t id) const noexcept;

    Entry *table_ = nullptr;
    size_t mask_ = 0;
    size_t most_ = 0;
    size_t count_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_ID_INDEX_H
