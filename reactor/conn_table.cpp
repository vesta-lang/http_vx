/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/conn_table.cpp
 * @brief
 * \~english Taking a slot, giving it back, and refusing the previous tenant.
 * \~spanish Coger una casilla, devolverla, y rechazar al inquilino anterior.
 * \~
 */

#include "http_vx/conn_table.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {

ConnTable::~ConnTable() { release(); }

void ConnTable::release() noexcept {
    if (hot_ != nullptr) {
        util::host_free(hot_);
        hot_ = nullptr;
    }
    if (cold_ != nullptr) {
        util::host_free(cold_);
        cold_ = nullptr;
    }
    if (next_free_ != nullptr) {
        util::host_free(next_free_);
        next_free_ = nullptr;
    }

    capacity_ = 0;
    count_ = 0;
    free_head_ = kNoSlot;
    free_tail_ = kNoSlot;
}

bool ConnTable::reset(uint32_t capacity) noexcept {
    release();

    if (capacity == 0 || capacity >= kNoSlot) return false;

    /* \~english
     * Three arrays and not one of structures, which is what "dense" means
     * here: a sweep of the loop reads the hot one and nothing else, and a
     * record that carried its cold half with it would make every cache line
     * read half useful.
     *
     * The scope says what all three are: as long-lived as the shard, never
     * resized, and touched at scattered indices rather than walked end to end.
     *
     * \~spanish
     * Tres arrays y no uno de estructuras, que es lo que quiere decir "denso"
     * aqui: un barrido del bucle lee el caliente y nada mas, y un registro que
     * llevara su mitad fria encima haria que cada linea de cache fuera util a
     * medias.
     *
     * El alcance dice lo que son los tres: de vida tan larga como el fragmento,
     * sin cambiar de tamano nunca, y tocados en indices sueltos en vez de
     * recorridos de punta a punta.
     * \~ */
    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    hot_ = static_cast<ConnHot *>(
        util::host_alloc(static_cast<size_t>(capacity) * sizeof(ConnHot)));
    cold_ = static_cast<ConnCold *>(
        util::host_alloc(static_cast<size_t>(capacity) * sizeof(ConnCold)));
    next_free_ = static_cast<uint32_t *>(
        util::host_alloc(static_cast<size_t>(capacity) * sizeof(uint32_t)));

    if (hot_ == nullptr || cold_ == nullptr || next_free_ == nullptr) {
        release();
        return false;
    }

    capacity_ = capacity;
    count_ = 0;

    /* \~english
     * Every slot starts free, on its first life, and threaded onto the queue
     * in order.  Life ONE and not zero: a handle left at its default names
     * slot @c kNoSlot with life zero, and starting the count at one means a
     * default-made handle cannot match a real slot even if somebody managed to
     * put a real index in it.
     *
     * \~spanish
     * Todas las casillas empiezan libres, en su primera vida, y enhebradas en la
     * cola en orden.  Vida UNO y no cero: una referencia dejada como viene
     * nombra la casilla @c kNoSlot con vida cero, y empezar la cuenta en uno
     * hace que una referencia recien hecha no pueda casar con una casilla de
     * verdad ni aunque alguien consiguiera meterle un indice bueno.
     * \~ */
    for (uint32_t i = 0; i < capacity_; ++i) {
        hot_[i].fd = -1;
        hot_[i].life = 1;
        hot_[i].queue = kNoBuffer;
        hot_[i].reading = kNoBuffer;
        hot_[i].flags = 0;
        hot_[i].queued = 0;
        hot_[i]._pad = 0;

        next_free_[i] = i + 1 == capacity_ ? kNoSlot : i + 1;
    }

    free_head_ = 0;
    free_tail_ = capacity_ - 1;
    return true;
}

ConnHandle ConnTable::open(int32_t fd, uint64_t opened) noexcept {
    if (hot_ == nullptr || free_head_ == kNoSlot) return ConnHandle{};

    const uint32_t slot = free_head_;
    free_head_ = next_free_[slot];
    if (free_head_ == kNoSlot) free_tail_ = kNoSlot;

    ConnHot &h = hot_[slot];
    h.fd = fd;
    h.queue = kNoBuffer;
    h.reading = kNoBuffer;
    h.flags = 0;
    h.queued = 0;

    /* \~english
     * The cold half is cleared here, where it costs one write of sixty-four
     * bytes on a connection that has just arrived, rather than being left with
     * the previous tenant's counters.  A server whose statistics carried over
     * between connections would not be wrong in any way that failed -- it would
     * just answer questions about itself with numbers that were somebody
     * else's.
     *
     * \~spanish
     * La mitad fria se limpia aqui, donde cuesta una escritura de sesenta y
     * cuatro bytes en una conexion que acaba de llegar, en vez de dejarla con
     * los contadores del inquilino anterior.  Un servidor cuyas estadisticas se
     * arrastraran de una conexion a otra no estaria mal de ninguna forma que
     * fallara -- solo contestaria preguntas sobre si mismo con numeros que eran
     * de otro.
     * \~ */
    ConnCold &c = cold_[slot];
    util::vesta_memset(&c, 0, sizeof c);
    c.opened = opened;

    ++count_;
    return ConnHandle{slot, h.life};
}

bool ConnTable::close(ConnHandle h) noexcept {
    if (!alive(h)) return false;

    ConnHot &slot = hot_[h.slot];
    slot.fd = -1;
    slot.queue = kNoBuffer;
    slot.reading = kNoBuffer;
    slot.flags = 0;
    slot.queued = 0;

    /* \~english
     * The life goes up HERE, which is the single line the whole file is about.
     * From this instruction on, every reference anybody still holds to this
     * connection -- the deadline that was armed, the completion the kernel has
     * not delivered, the handler that kept a copy -- stops matching, and every
     * one of them gets a refusal instead of somebody else's socket.
     *
     * Wrapping round is not guarded against and could not usefully be: after
     * four thousand million lives of one slot a reference from the first one
     * would match again.  What makes that unreachable is not a check, it is
     * the queue: slots are handed out in order, so reaching that count on one
     * slot means the server has opened four thousand million times the
     * capacity of the table, and a reference would have to have survived all
     * of it.
     *
     * \~spanish
     * La vida sube AQUI, que es la unica linea de la que va todo el fichero.  A
     * partir de esta instruccion, toda referencia que alguien siga guardando a
     * esta conexion -- el plazo que estaba armado, la finalizacion que el nucleo
     * no ha entregado, el manejador que se quedo una copia -- deja de casar, y
     * cada una de ellas recibe un rechazo en vez del socket de otro.
     *
     * Que de la vuelta no se vigila y no se podria vigilar de forma util:
     * despues de cuatro mil millones de vidas de una casilla, una referencia de
     * la primera volveria a casar.  Lo que hace eso inalcanzable no es una
     * comprobacion, es la cola: las casillas se reparten en orden, asi que
     * llegar a esa cuenta en una sola quiere decir que el servidor ha abierto
     * cuatro mil millones de veces la capacidad de la tabla, y una referencia
     * habria tenido que sobrevivir a todo ello.
     * \~ */
    ++slot.life;

    /* \~english
     * And onto the BACK of the queue, so this slot is the last to be handed
     * out again.  Pushing it on the front would be a stack, and a stack gives
     * a stale reference no time at all to be caught.
     * \~spanish
     * Y al FINAL de la cola, para que esta casilla sea la ultima en volver a
     * repartirse.  Meterla por delante seria una pila, y una pila no le da a una
     * referencia rancia ningun tiempo para que la pillen.
     * \~ */
    next_free_[h.slot] = kNoSlot;
    if (free_tail_ != kNoSlot)
        next_free_[free_tail_] = h.slot;
    else
        free_head_ = h.slot;
    free_tail_ = h.slot;

    --count_;
    return true;
}

bool ConnTable::alive(ConnHandle h) const noexcept {
    if (hot_ == nullptr || h.slot >= capacity_) return false;

    const ConnHot &slot = hot_[h.slot];

    /* \~english
     * Both, and the socket is checked as well as the life.  The life alone
     * would say yes to a slot that is free and has not been reused yet, which
     * is exactly where a deadline fires from: the connection was closed a
     * moment ago and nobody has taken the slot.
     * \~spanish
     * Las dos, y se comprueba el socket ademas de la vida.  La vida sola diria
     * que si a una casilla libre que todavia no se ha reutilizado, que es justo
     * desde donde vence un plazo: la conexion se cerro hace un momento y nadie
     * ha cogido la casilla.
     * \~ */
    return slot.fd >= 0 && slot.life == h.life;
}

ConnHot *ConnTable::hot(ConnHandle h) noexcept {
    if (!alive(h)) return nullptr;
    return &hot_[h.slot];
}

const ConnHot *ConnTable::hot(ConnHandle h) const noexcept {
    if (!alive(h)) return nullptr;
    return &hot_[h.slot];
}

ConnCold *ConnTable::cold(ConnHandle h) noexcept {
    if (!alive(h)) return nullptr;
    return &cold_[h.slot];
}

ConnHandle ConnTable::at(uint32_t i) const noexcept {
    if (hot_ == nullptr || i >= capacity_) return ConnHandle{};
    if (hot_[i].fd < 0) return ConnHandle{};
    return ConnHandle{i, hot_[i].life};
}

} // namespace http_vx
