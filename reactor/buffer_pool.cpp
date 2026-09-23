/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/buffer_pool.cpp
 * @brief
 * \~english Lending a buffer, taking it back, and throwing away the one that grew.
 * \~spanish Prestar un buffer, recogerlo, y tirar el que crecio.
 * \~
 */

#include "http_vx/buffer_pool.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {

BufferPool::~BufferPool() { release_all(); }

void BufferPool::release_all() noexcept {
    if (buffers_ != nullptr) {
        /* \~english
         * Each one gives its own memory back before the array holding them
         * does.  They were made with placement new because the array is raw
         * memory from the allocator, so nothing would call the destructors if
         * this did not.
         * \~spanish
         * Cada uno devuelve su memoria antes de que lo haga el array que los
         * guarda.  Se hicieron con un new posicionado porque el array es memoria
         * cruda del asignador, asi que nadie llamaria a los destructores si esto
         * no lo hiciera.
         * \~ */
        for (uint32_t i = 0; i < count_; ++i) buffers_[i].~Buffer();

        util::host_free(buffers_);
        buffers_ = nullptr;
    }

    if (next_free_ != nullptr) {
        util::host_free(next_free_);
        next_free_ = nullptr;
    }

    count_ = 0;
    lent_ = 0;
    free_head_ = kNoBuffer;
}

bool BufferPool::reset(uint32_t count, size_t ceiling) noexcept {
    release_all();

    if (count == 0 || count >= kNoBuffer) return false;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    buffers_ = static_cast<Buffer *>(
        util::host_alloc(static_cast<size_t>(count) * sizeof(Buffer)));
    next_free_ = static_cast<uint32_t *>(
        util::host_alloc(static_cast<size_t>(count) * sizeof(uint32_t)));

    if (buffers_ == nullptr || next_free_ == nullptr) {
        /* \~english
         * Nothing has been constructed yet, so the count is zeroed before
         * giving up -- otherwise the cleanup would run destructors over
         * memory that never held an object.
         * \~spanish
         * Todavia no se ha construido nada, asi que la cuenta se pone a cero
         * antes de rendirse -- si no, la limpieza correria destructores sobre
         * memoria que no tuvo nunca un objeto.
         * \~ */
        count_ = 0;
        release_all();
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        new (&buffers_[i]) Buffer();

        /* \~english
         * The stack is threaded so that slot zero is on top, which is where a
         * server that has just started and is serving one connection will keep
         * landing.  It costs nothing to arrange and means the first traffic
         * touches the same memory every time.
         * \~spanish
         * La pila se enhebra para que la plaza cero quede arriba, que es donde
         * va a caer una y otra vez un servidor recien arrancado que sirve una
         * conexion.  No cuesta nada dejarlo asi y hace que el primer trafico
         * toque siempre la misma memoria.
         * \~ */
        next_free_[i] = i + 1 == count ? kNoBuffer : i + 1;
    }

    count_ = count;
    ceiling_ = ceiling;
    free_head_ = 0;
    lent_ = 0;
    return true;
}

uint32_t BufferPool::acquire() noexcept {
    if (buffers_ == nullptr || free_head_ == kNoBuffer) return kNoBuffer;

    const uint32_t i = free_head_;
    free_head_ = next_free_[i];

    /* \~english
     * Recycled and not cleared, which is the difference between a buffer for
     * the next message and a buffer for somebody else.  See
     * @c Buffer::recycle: clearing would leave the previous tenant's origin
     * in place, and every offset the new connection asked about would be
     * measured from a point it never had.
     * \~spanish
     * Reciclado y no vaciado, que es la diferencia entre un buffer para el
     * mensaje siguiente y un buffer para otra persona.  Ver @c Buffer::recycle:
     * vaciarlo dejaria en su sitio el origen del inquilino anterior, y todos los
     * desplazamientos por los que preguntara la conexion nueva se medirian desde
     * un punto que no tuvo nunca.
     * \~ */
    buffers_[i].recycle();

    ++lent_;
    return i;
}

void BufferPool::release(uint32_t i) noexcept {
    if (buffers_ == nullptr || i >= count_) return;

    /* \~english
     * The one that grew too big goes back to the allocator rather than back
     * into the pool with its memory.  Keeping it would let every slot creep up
     * to the largest thing that ever passed through it, and the pool would
     * settle at the peak times the count on a server that never looked like it
     * was leaking anything.
     *
     * The buffer itself stays -- it is a slot in an array and it is not going
     * anywhere.  What is given back is what it was holding.
     *
     * \~spanish
     * El que crecio demasiado vuelve al asignador y no al pozo con su memoria.
     * Quedarselo dejaria que todas las plazas fueran subiendo hasta lo mas
     * grande que haya pasado por ellas, y el pozo se asentaria en el pico por el
     * numero en un servidor que no pareceria tener ninguna fuga.
     *
     * El buffer en si se queda -- es una plaza de un array y no se va a ningun
     * sitio --.  Lo que se devuelve es lo que tenia.
     * \~ */
    if (ceiling_ != 0 && buffers_[i].capacity() > ceiling_) buffers_[i].release();

    /* \~english
     * And that is all: the buffer is NOT emptied here.  Getting it ready for
     * somebody else happens in @c acquire, at the moment there is a somebody
     * else to get it ready for, and it happens in exactly one place so that
     * one place can be wrong and be caught.
     *
     * Doing it in both would look safer and would be worse: whichever of the
     * two was wrong, the other would cover for it, and no test could tell
     * which one the correctness depended on.
     *
     * \~spanish
     * Y ya esta: el buffer NO se vacia aqui.  Dejarlo listo para otro pasa en
     * @c acquire, en el momento en que hay otro para quien dejarlo listo, y pasa
     * en un solo sitio para que ese sitio pueda estar mal y se pille.
     *
     * Hacerlo en los dos pareceria mas seguro y seria peor: estuviera mal el que
     * estuviera, el otro lo taparia, y ninguna prueba podria decir de cual de
     * los dos dependia la correccion.
     * \~ */

    next_free_[i] = free_head_;
    free_head_ = i;

    if (lent_ != 0) --lent_;
}

Buffer *BufferPool::at(uint32_t i) noexcept {
    if (buffers_ == nullptr || i >= count_) return nullptr;
    return &buffers_[i];
}

size_t BufferPool::bytes_held() const noexcept {
    size_t total = 0;
    for (uint32_t i = 0; i < count_; ++i) total += buffers_[i].capacity();
    return total;
}

} // namespace http_vx
