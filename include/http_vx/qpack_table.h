/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/qpack_table.h
 * @brief
 * \~english QPACK's dynamic table: a FIFO whose entries keep one absolute index for life (RFC 9204, 3.2).
 * \~spanish La tabla dinamica de QPACK: una cola cuyas entradas conservan un indice absoluto toda su vida (RFC 9204, 3.2).
 * \~
 *
 * \~english
 * Not HPACK's table, though it looks like one.  Three rules differ and each
 * would be a silent disagreement with the peer if shared:
 *
 * - An entry is named by its **absolute index**, the count of inserts
 *   before it (3.2.4), because field sections are read out of order with
 *   the inserts; HPACK only ever counts from the newest.
 * - An entry larger than the capacity is an **error** (3.2.2); in HPACK it
 *   empties the table.
 * - Eviction is **limited** on the encoder's side: an entry still
 *   referenced, or not yet acknowledged, may not go (2.1.1).  This table
 *   evicts as it is told; whether it may be told is the encoder's to know.
 *
 * Both ends keep one: the decoder's follows the encoder stream, the
 * encoder's is what it has sent.
 *
 * \~spanish
 * No es la tabla de HPACK, aunque se le parezca.  Tres reglas cambian y cada una
 * seria un desacuerdo silencioso con el otro si se compartiera:
 *
 * - Una entrada se nombra por su **indice absoluto**, la cuenta de inserciones
 *   anteriores (3.2.4), porque las secciones de campos se leen desordenadas
 *   respecto a las inserciones; HPACK solo cuenta desde la mas nueva.
 * - Una entrada mayor que la capacidad es un **error** (3.2.2); en HPACK vacia
 *   la tabla.
 * - Desalojar esta **limitado** en el lado del codificador: una entrada aun
 *   referenciada, o aun no confirmada, no puede irse (2.1.1).  Esta tabla
 *   desaloja cuando se le dice; si se le puede decir lo sabe el codificador.
 *
 * Los dos extremos tienen una: la del descodificador sigue al flujo del
 * codificador, la del codificador es lo que ha mandado.
 * \~
 */
#ifndef HTTP_VX_QPACK_TABLE_H
#define HTTP_VX_QPACK_TABLE_H

#include "http_vx/buffer.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace qpack {

/**
 * @brief
 * \~english The dynamic table.  \~spanish La tabla dinamica.
 * \~
 */
class Table {
public:
    /// \~english The largest maximum capacity a table is made for: 1 GiB.  \~spanish La mayor capacidad maxima para la que se hace una tabla: 1 GiB.  \~
    static constexpr uint64_t kLargestMax = uint64_t{1} << 30;

    Table() noexcept = default;
    ~Table();
    Table(const Table &) = delete;
    Table &operator=(const Table &) = delete;

    /**
     * @brief
     * \~english Empties it, with @p max as the most its capacity may ever be (3.2.3); false past kLargestMax.
     * \~spanish La vacia, con @p max como lo mas que podra ser su capacidad (3.2.3); falso pasado kLargestMax.
     * \~
     *
     * \~english The capacity starts at zero (3.2.2).  Memory comes on the first insert.
     * \~spanish La capacidad empieza en cero (3.2.2).  La memoria llega con la primera insercion.  \~
     */
    bool reset(uint64_t max) noexcept;

    /**
     * @brief
     * \~english Sets the capacity, evicting the oldest until the table fits; false past the maximum.
     * \~spanish Fija la capacidad, desalojando las mas viejas hasta que la tabla quepa; falso pasado el maximo.
     * \~
     */
    bool set_capacity(uint64_t c) noexcept;

    /// \~english How an insert went.  \~spanish Como fue una insercion.  \~
    enum class Insert : uint8_t { Ok, TooLarge, NoMemory };

    /**
     * @brief
     * \~english Adds an entry, evicting the oldest until it fits; TooLarge if it is larger than the capacity.
     * \~spanish Anade una entrada, desalojando las mas viejas hasta que quepa; TooLarge si es mayor que la capacidad.
     * \~
     *
     * \~english
     * The bytes must not be the table's own: an entry named by reference may
     * be the one the insert evicts (3.2.2), so its name is copied out first.
     * \~spanish
     * Los bytes no deben ser de la propia tabla: una entrada nombrada por
     * referencia puede ser la que desaloja la insercion (3.2.2), asi que su
     * nombre se copia fuera antes.
     * \~
     */
    Insert insert(const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) noexcept;

    /// \~english The Insert Count: entries ever added (1.1).  \~spanish El Insert Count: entradas anadidas en total (1.1).  \~
    uint64_t inserted() const noexcept { return inserted_; }
    /// \~english Entries ever evicted: the oldest live one has this absolute index.
    /// \~spanish Entradas desalojadas en total: la mas vieja viva tiene este indice absoluto.  \~
    uint64_t dropped() const noexcept { return inserted_ - count_; }
    uint64_t count() const noexcept { return count_; }
    /// \~english What the entries cost between them (3.2.1).  \~spanish Lo que cuestan las entradas entre todas (3.2.1).  \~
    uint64_t size() const noexcept { return size_; }
    uint64_t capacity() const noexcept { return capacity_; }
    uint64_t max_capacity() const noexcept { return max_; }
    /// \~english floor(max / 32): the most entries there can be (4.5.1.1).  \~spanish floor(max / 32): las entradas que puede haber como mucho (4.5.1.1).  \~
    uint64_t max_entries() const noexcept { return max_ / 32; }

    /// \~english Whether absolute index @p abs is in the table now.  \~spanish Si el indice absoluto @p abs esta ahora en la tabla.  \~
    bool has(uint64_t abs) const noexcept { return abs < inserted_ && abs >= dropped(); }

    /// \~english What entry @p abs costs; 0 if it is not there.  \~spanish Lo que cuesta la entrada @p abs; 0 si no esta.  \~
    uint64_t cost(uint64_t abs) const noexcept;

    /**
     * @brief
     * \~english Appends the name (or the value) of entry @p abs to @p out; false if it is not there or memory fails.
     * \~spanish Anade a @p out el nombre (o el valor) de la entrada @p abs; falso si no esta o falla la memoria.
     * \~
     */
    bool copy_name(uint64_t abs, Buffer &out, Span &where) const noexcept;
    bool copy_value(uint64_t abs, Buffer &out, Span &where) const noexcept;

    /// \~english Whether entry @p abs has this name (and, with @p value, this value).
    /// \~spanish Si la entrada @p abs tiene este nombre (y, con @p value, este valor).  \~
    bool has_name(uint64_t abs, const uint8_t *name, size_t nlen) const noexcept;
    bool is(uint64_t abs, const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) const noexcept;

    /// \~english Gives the memory back, keeping nothing.  \~spanish Devuelve la memoria, sin guardar nada.  \~
    void release() noexcept;

private:
    struct Entry {
        uint32_t at;
        uint32_t name_len;
        uint32_t value_len;
    };

    const Entry *find(uint64_t abs) const noexcept;
    void evict_oldest() noexcept;
    bool make_room() noexcept;
    bool copy_piece(size_t at, size_t len, Buffer &out, Span &where) const noexcept;
    bool piece_is(size_t at, size_t len, const uint8_t *p) const noexcept;

    /* \~english Two rings: the bytes, and the entries, oldest first.
     * \~spanish Dos anillos: los bytes, y las entradas, la mas vieja primero.  \~ */
    uint8_t *bytes_ = nullptr;
    size_t bytes_cap_ = 0;
    size_t bytes_head_ = 0;
    size_t bytes_len_ = 0;
    Entry *entries_ = nullptr;
    size_t entries_cap_ = 0;
    size_t oldest_ = 0;
    uint64_t count_ = 0;

    uint64_t inserted_ = 0;
    uint64_t size_ = 0;
    uint64_t capacity_ = 0;
    uint64_t max_ = 0;
};

} // namespace qpack
} // namespace http_vx

#endif // HTTP_VX_QPACK_TABLE_H
