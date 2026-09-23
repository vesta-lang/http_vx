/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/table.cpp
 * @brief
 * \~english Remembering fields, and forgetting them in the right order.
 * \~spanish Recordar cabeceras, y olvidarlas en el orden correcto.
 * \~
 */

#include "http_vx/h2_table.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h2 {
namespace hpack {
namespace {

/**
 * @brief
 * \~english How a connection's memory of its fields declares itself.
 * \~spanish Como se declara la memoria de cabeceras de una conexion.
 * \~
 *
 * \~english
 * `Long`, because this outlives every message on the connection and that is
 * the whole point of it; `Fixed`, because it is asked for once at the size the
 * limit allows and never grows; and `Sparse`, because a table is mostly empty
 * -- a connection that remembers four headers has touched two hundred bytes of
 * its four thousand, and that fraction is what decides how a block is handed
 * back.
 *
 * \~spanish
 * `Long`, porque esto sobrevive a todos los mensajes de la conexion y de eso se
 * trata; `Fixed`, porque se pide una vez del tamano que permite el limite y no
 * crece; y `Sparse`, porque una tabla esta casi siempre vacia -- una conexion
 * que recuerde cuatro cabeceras ha tocado doscientos bytes de sus cuatro mil, y
 * esa fraccion es la que decide como se entrega un bloque.
 *
 * \~
 */
inline util::AllocScope open_scope() noexcept {
    return util::AllocScope(util::AllocUse::Long, util::AllocShape::Fixed,
                            util::AllocFill::Sparse);
}

} // namespace

DynamicTable::~DynamicTable() { release(); }

void DynamicTable::release() noexcept {
    if (bytes_ != nullptr) util::host_free(bytes_);
    if (entries_ != nullptr) util::host_free(entries_);
    bytes_ = nullptr;
    entries_ = nullptr;
    bytes_cap_ = 0;
    entries_cap_ = 0;
    bytes_head_ = 0;
    bytes_len_ = 0;
    oldest_ = 0;
    count_ = 0;
    size_ = 0;
}

void DynamicTable::reset(uint32_t announced) noexcept {
    release();
    announced_ = announced;
    max_ = announced;
}

bool DynamicTable::set_max_size(uint32_t n) noexcept {
    /* \~english
     * More than was announced is refused.  The announcement is what this end
     * sized its arithmetic for, and a peer that asks past it is asking this
     * server to remember more than it said it would -- which is the shape of
     * every limit in this codec, and the reason they are announced at all.
     *
     * \~spanish
     * Mas de lo anunciado se rechaza.  El anuncio es para lo que este extremo
     * dimensiono su aritmetica, y un extremo que pida por encima esta pidiendo
     * a este servidor que recuerde mas de lo que dijo -- que es la forma de
     * todos los limites de este codec, y la razon de anunciarlos.
     * \~ */
    if (n > announced_) return false;

    max_ = n;

    /* \~english
     * And smaller takes effect now, not when the next field arrives.  Both
     * ends evict at the same moment or they stop agreeing about what an index
     * means, and "when it is convenient" is not the same moment.
     *
     * \~spanish
     * Y mas pequeno surte efecto ahora, no cuando llegue la cabecera siguiente.
     * Los dos extremos desalojan en el mismo momento o dejan de estar de
     * acuerdo sobre lo que significa un indice, y "cuando venga bien" no es el
     * mismo momento.
     * \~ */
    while (count_ != 0 && size_ > max_) evict_oldest();

    return true;
}

bool DynamicTable::make_room() noexcept {
    if (announced_ == 0) return false;

    const util::AllocScope scope = open_scope();

    /* \~english
     * The bytes never take more than the limit, because an entry costs its
     * bytes PLUS thirty-two and the sum of the costs is what the limit bounds.
     * So the announced size is enough for the strings whatever they are.
     *
     * \~spanish
     * Los bytes no ocupan nunca mas que el limite, porque una entrada cuesta
     * sus bytes MAS treinta y dos y lo que acota el limite es la suma de los
     * costes.  Asi que el tamano anunciado basta para las cadenas sean las que
     * sean.
     * \~ */
    bytes_cap_ = announced_;

    /* \~english
     * And there can never be more entries than the limit divided by what an
     * entry costs at its very cheapest, which is the thirty-two alone.
     * \~spanish
     * Y no puede haber nunca mas entradas que el limite dividido entre lo que
     * cuesta una entrada en el mejor de los casos, que son los treinta y dos
     * solos.
     * \~ */
    entries_cap_ = announced_ / kEntryOverhead + 1;

    bytes_ = static_cast<uint8_t *>(util::host_alloc(bytes_cap_));
    if (bytes_ == nullptr) {
        bytes_cap_ = 0;
        entries_cap_ = 0;
        return false;
    }

    entries_ = static_cast<TableEntry *>(
        util::host_alloc(entries_cap_ * sizeof(TableEntry)));
    if (entries_ == nullptr) {
        util::host_free(bytes_);
        bytes_ = nullptr;
        bytes_cap_ = 0;
        entries_cap_ = 0;
        return false;
    }

    return true;
}

void DynamicTable::evict_oldest() noexcept {
    const TableEntry &e = entries_[oldest_];
    const size_t bytes = static_cast<size_t>(e.name_len) + e.value_len;

    size_ -= e.cost();
    bytes_head_ = (bytes_head_ + bytes) % bytes_cap_;
    bytes_len_ -= bytes;
    oldest_ = (oldest_ + 1) % entries_cap_;
    --count_;
}

bool DynamicTable::add(const uint8_t *name, size_t nlen, const uint8_t *value,
                       size_t vlen, FieldId id, Pseudo pseudo) noexcept {
    const uint64_t cost = static_cast<uint64_t>(nlen) + vlen + kEntryOverhead;

    /* \~english
     * An entry bigger than the whole table empties it and is not added.  That
     * is a rule and not a refusal: RFC 7541 section 4.4 says so, both ends do
     * it, and a decoder that answered with an error here would be refusing a
     * message an encoder is entitled to send.
     *
     * Emptying is the part that matters.  The encoder does it too, so after
     * this both ends have the same empty table -- which is what keeps the next
     * index meaning the same thing on both sides.
     *
     * \~spanish
     * Una entrada mayor que la tabla entera la vacia y no se anade.  Es una
     * regla y no un rechazo: el RFC 7541 seccion 4.4 lo dice, los dos extremos
     * lo hacen, y un descodificador que contestara con un error aqui estaria
     * rechazando un mensaje que un codificador puede mandar.
     *
     * Vaciarla es la parte que importa.  El codificador lo hace tambien, asi
     * que despues de esto los dos extremos tienen la misma tabla vacia -- que
     * es lo que hace que el indice siguiente signifique lo mismo en los dos
     * lados.
     * \~ */
    if (cost > max_) {
        while (count_ != 0) evict_oldest();
        return true;
    }

    if (bytes_ == nullptr && !make_room()) return false;

    while (count_ != 0 && static_cast<uint64_t>(size_) + cost > max_)
        evict_oldest();

    /* \~english
     * The bytes go in at the tail of the ring, and a name or a value may
     * straddle the end of it.  Writing it in two pieces is what a ring costs,
     * and the ring is what a FIFO buys: nothing is ever moved.
     *
     * \~spanish
     * Los bytes entran por la cola del anillo, y un nombre o un valor pueden
     * quedar a caballo del final.  Escribirlo en dos pedazos es lo que cuesta
     * un anillo, y el anillo es lo que compra una cola: no se mueve nunca nada.
     * \~ */
    const size_t total = nlen + vlen;
    const size_t start = (bytes_head_ + bytes_len_) % bytes_cap_;
    size_t at = start;

    const uint8_t *src[2] = {name, value};
    const size_t lens[2] = {nlen, vlen};

    for (int part = 0; part < 2; ++part) {
        size_t left = lens[part];
        const uint8_t *from = src[part];
        while (left != 0) {
            const size_t room = bytes_cap_ - at;
            const size_t n = left < room ? left : room;
            util::vesta_memcpy(bytes_ + at, from, n);
            from += n;
            left -= n;
            at = (at + n) % bytes_cap_;
        }
    }

    bytes_len_ += total;

    const size_t slot = (oldest_ + count_) % entries_cap_;
    entries_[slot].byte_off = static_cast<uint32_t>(start);
    entries_[slot].name_len = static_cast<uint16_t>(nlen);
    entries_[slot].value_len = static_cast<uint16_t>(vlen);
    entries_[slot].id = id;
    entries_[slot].pseudo = pseudo;

    ++count_;
    size_ += static_cast<uint32_t>(cost);
    return true;
}

const TableEntry *DynamicTable::at(size_t i) const noexcept {
    if (i >= count_) return nullptr;

    /* \~english
     * The specification counts from the newest and the ring holds them oldest
     * first, so the index is turned around here.  Doing it in one place is the
     * point: an index turned around twice, or not at all, still names an entry
     * -- just not the one the peer meant.
     *
     * \~spanish
     * La especificacion cuenta desde la mas nueva y el anillo las tiene con la
     * mas vieja delante, asi que el indice se da la vuelta aqui.  Hacerlo en un
     * solo sitio es lo que importa: un indice dado la vuelta dos veces, o
     * ninguna, sigue nombrando una entrada -- solo que no la que queria decir
     * el otro extremo.
     * \~ */
    const size_t slot = (oldest_ + count_ - 1 - i) % entries_cap_;
    return &entries_[slot];
}

size_t DynamicTable::copy_piece(size_t at, size_t len, uint8_t *out,
                                size_t cap) const noexcept {
    if (len > cap) return 0;

    size_t left = len;
    size_t written = 0;
    size_t from = at;

    while (left != 0) {
        const size_t room = bytes_cap_ - from;
        const size_t n = left < room ? left : room;
        util::vesta_memcpy(out + written, bytes_ + from, n);
        written += n;
        left -= n;
        from = (from + n) % bytes_cap_;
    }

    return written;
}

/**
 * @brief
 * \~english Whether @p len bytes from @p at in the ring are @p p.
 * \~spanish Si los @p len bytes desde @p at del anillo son @p p.
 * \~
 */
bool DynamicTable::piece_is(size_t at, size_t len, const uint8_t *p,
                            size_t plen) const noexcept {
    if (len != plen) return false;

    size_t left = len;
    size_t from = at;
    size_t done = 0;

    while (left != 0) {
        const size_t room = bytes_cap_ - from;
        const size_t n = left < room ? left : room;
        for (size_t i = 0; i < n; ++i)
            if (bytes_[from + i] != p[done + i]) return false;
        done += n;
        left -= n;
        from = (from + n) % bytes_cap_;
    }

    return true;
}

size_t DynamicTable::find(const uint8_t *name, size_t nlen,
                          const uint8_t *value, size_t vlen,
                          bool &exact) const noexcept {
    exact = false;
    size_t by_name = count_;

    for (size_t i = 0; i < count_; ++i) {
        const TableEntry *e = at(i);
        if (!piece_is(e->byte_off, e->name_len, name, nlen)) continue;

        /* \~english
         * A name match is worth remembering and not worth stopping for: a
         * field further back may match the value as well, and that one costs
         * one byte where this one costs the whole value.
         * \~spanish
         * Una coincidencia de nombre merece recordarse y no merece pararse: mas
         * atras puede haber una que ademas coincida en el valor, y esa cuesta
         * un byte donde esta cuesta el valor entero.
         * \~ */
        if (by_name == count_) by_name = i;

        if (piece_is((e->byte_off + e->name_len) % bytes_cap_, e->value_len,
                     value, vlen)) {
            exact = true;
            return i;
        }
    }

    return by_name;
}

size_t DynamicTable::copy_name(size_t i, uint8_t *out, size_t cap) const noexcept {
    const TableEntry *e = at(i);
    if (e == nullptr) return 0;
    return copy_piece(e->byte_off, e->name_len, out, cap);
}

size_t DynamicTable::copy_value(size_t i, uint8_t *out, size_t cap) const noexcept {
    const TableEntry *e = at(i);
    if (e == nullptr) return 0;
    return copy_piece((e->byte_off + e->name_len) % bytes_cap_, e->value_len, out,
                      cap);
}

} // namespace hpack
} // namespace h2
} // namespace http_vx
