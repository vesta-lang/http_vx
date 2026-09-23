/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file core/buffer.cpp
 * @brief
 * \~english Growing, sliding and letting go of a connection's bytes.
 * \~spanish Crecer, deslizar y soltar los bytes de una conexion.
 * \~
 *
 * \~english
 * The allocator's headers declare their interface without pulling in any of
 * the system's, so using them here does not cost R6: `core/` still builds with
 * nothing from the operating system in sight, and its tests still run without
 * opening a socket.
 *
 * \~spanish
 * Las cabeceras del asignador declaran su interfaz sin arrastrar ninguna del
 * sistema, asi que usarlas aqui no cuesta R6: `core/` sigue construyendo sin
 * nada del sistema operativo a la vista, y sus pruebas siguen corriendo sin
 * abrir un socket.
 *
 * \~
 */

#include "http_vx/buffer.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english How a connection's buffer declares itself to the allocator.
 * \~spanish Como se declara a si mismo el buffer de una conexion.
 * \~
 *
 * \~english
 * Three axes, and each one is a fact the allocator cannot work out on its own:
 *
 *  - it lives as long as a message does, which is a phase and not a program
 *    (`Medium`);
 *  - it is a container that will grow and abandon this block (`Growing`), so
 *    the block it holds now is not the one it will end with;
 *  - and a good part of it gets touched (`Dense`) -- which is the axis that
 *    decides how a large block is handed back, and the only one where a
 *    default that looks like knowledge would be a lie rather than a gap.
 *
 * \~spanish
 * Tres ejes, y cada uno es un hecho que el asignador no puede averiguar solo:
 *
 *  - vive lo que un mensaje, que es una fase y no un programa (`Medium`);
 *  - es un contenedor que crecera y abandonara este bloque (`Growing`), asi que
 *    el que tiene ahora no es con el que va a acabar;
 *  - y se toca buena parte de el (`Dense`) -- que es el eje que decide como se
 *    entrega un bloque grande, y el unico donde un valor por defecto que parece
 *    saber seria una mentira y no un hueco.
 *
 * \~
 */
inline util::AllocScope open_scope() noexcept {
    return util::AllocScope(util::AllocUse::Medium, util::AllocShape::Growing,
                            util::AllocFill::Dense);
}

/**
 * @brief
 * \~english The capacity to ask for when @p want bytes are needed.
 * \~spanish La capacidad que pedir cuando hacen falta @p want bytes.
 * \~
 *
 * \~english
 * Doubling, because the alternative -- growing by what is needed -- turns a
 * body arriving in small reads into a copy of everything received so far on
 * every read, which is quadratic in the size of the message.  That is not
 * merely slow: the size of the message is chosen by the peer.
 *
 * \~spanish
 * Doblando, porque la alternativa -- crecer lo que haga falta -- convierte un
 * cuerpo que llega en lecturas pequenas en una copia de todo lo recibido hasta
 * el momento en cada lectura, que es cuadratico en el tamano del mensaje.  Eso
 * no es solo lento: el tamano del mensaje lo elige el otro extremo.
 *
 * \~
 */
size_t grown_capacity(size_t cap, size_t want) noexcept {
    size_t n = cap != 0 ? cap : kBufferInitialCapacity;
    while (n < want) {
        /* \~english
         * The doubling itself has to be able to stop.  A want near the top of
         * the address space would double past it and come back small, which is
         * an allocation that succeeds and a buffer that reports room it does
         * not have.
         * \~spanish
         * El propio doblado tiene que poder pararse.  Un `want` cerca del techo
         * del espacio de direcciones lo doblaria por encima y volveria pequeno,
         * que es una reserva que triunfa y un buffer que dice tener sitio que no
         * tiene.
         * \~ */
        if (n > kBufferMaxCapacity) break;
        n *= 2;
    }

    /* \~english
     * And what doubling overshot is asked for exactly.  Otherwise a buffer
     * just under the ceiling would be refused a size that is under it too,
     * only because the next power of two is not -- a refusal that would be
     * about the growth policy and not about the limit.
     *
     * \~spanish
     * Y lo que el doblado se pasara se pide exacto.  Si no, a un buffer justo
     * por debajo del techo se le negaria un tamano que tambien esta por debajo,
     * solo porque la potencia de dos siguiente no lo esta -- una negativa que
     * seria sobre la politica de crecimiento y no sobre el limite.
     * \~ */
    return n <= kBufferMaxCapacity ? n : want;
}

} // namespace

Buffer::~Buffer() { release(); }

Buffer::Buffer(Buffer &&other) noexcept
    : base_(other.base_), cap_(other.cap_), head_(other.head_),
      tail_(other.tail_) {
    other.base_ = nullptr;
    other.cap_ = 0;
    other.head_ = 0;
    other.tail_ = 0;
}

Buffer &Buffer::operator=(Buffer &&other) noexcept {
    if (this == &other) return *this;
    release();
    base_ = other.base_;
    cap_ = other.cap_;
    head_ = other.head_;
    tail_ = other.tail_;
    other.base_ = nullptr;
    other.cap_ = 0;
    other.head_ = 0;
    other.tail_ = 0;
    return *this;
}

void Buffer::release() noexcept {
    if (base_ == nullptr) return;
    util::host_free(base_);
    base_ = nullptr;
    cap_ = 0;
    head_ = 0;
    tail_ = 0;
}

void Buffer::compact() noexcept {
    if (head_ == 0) return;
    const size_t live = tail_ - head_;
    if (live != 0) {
        /* \~english
         * A move and not a copy: what is being dropped is in front of what is
         * being kept, so the two regions overlap whenever more than half the
         * buffer is live.  A copy would be right most of the time, which is
         * the worst way for it to be wrong.
         * \~spanish
         * Un traslado y no una copia: lo que se descarta esta delante de lo que
         * se conserva, asi que las dos regiones se solapan siempre que este
         * vivo mas de medio buffer.  Una copia acertaria casi siempre, que es
         * la peor forma de equivocarse.
         * \~ */
        util::vesta_memmove(base_, base_ + head_, live);
    }
    head_ = 0;
    tail_ = live;
}

bool Buffer::grow(size_t want) noexcept {
    const size_t cap = grown_capacity(cap_, want);
    if (cap > kBufferMaxCapacity) return false;

    const util::AllocScope scope = open_scope();
    uint8_t *fresh = static_cast<uint8_t *>(util::host_alloc(cap));
    if (fresh == nullptr) return false;

    /* \~english
     * Only the live bytes travel, so growing also drops whatever `consume` had
     * finished with.  That is why this does not use the allocator's `realloc`:
     * it would faithfully copy the part that is already rubbish.
     *
     * \~spanish
     * Solo viajan los bytes vivos, asi que crecer descarta tambien lo que
     * `consume` hubiera dado por terminado.  Por eso esto no usa el `realloc`
     * del asignador: copiaria fielmente la parte que ya es basura.
     * \~ */
    const size_t live = tail_ - head_;
    if (live != 0) util::vesta_memcpy(fresh, base_ + head_, live);
    if (base_ != nullptr) util::host_free(base_);

    base_ = fresh;
    cap_ = cap;
    head_ = 0;
    tail_ = live;
    return true;
}

uint8_t *Buffer::reserve(size_t n) noexcept {
    if (n == 0) return base_ != nullptr ? base_ + tail_ : nullptr;

    /* \~english
     * Already there.  This is the case on every read after the first on a
     * connection whose messages fit, so it is the one that has to cost a
     * comparison.
     * \~spanish
     * Ya esta.  Es el caso de todas las lecturas menos la primera en una
     * conexion cuyos mensajes caben, asi que es el que tiene que costar una
     * comparacion.
     * \~ */
    if (cap_ - tail_ >= n) return base_ + tail_;

    /* \~english
     * Sliding first, and only if it is enough on its own.  It costs a move of
     * what is live, which is little just after a message ended, and it saves
     * an allocation and a free.  If it does not reach, there is no point doing
     * it: growing moves the live bytes anyway and leaves the front free.
     *
     * \~spanish
     * Deslizar primero, y solo si basta por si solo.  Cuesta un traslado de lo
     * que esta vivo, que es poco justo despues de terminar un mensaje, y ahorra
     * una reserva y una liberacion.  Si no llega, no tiene sentido hacerlo:
     * crecer mueve los bytes vivos de todas formas y deja el principio libre.
     * \~ */
    const size_t live = tail_ - head_;
    if (head_ != 0 && cap_ - live >= n) {
        compact();
        return base_ + tail_;
    }

    /* \~english
     * The addition is checked before it is made.  `live + n` with an `n` the
     * caller got wrong would wrap and ask for a small block, and the reserve
     * would succeed while returning room that is not there -- which the kernel
     * would then write past.
     * \~spanish
     * La suma se comprueba antes de hacerla.  `live + n` con una `n` que quien
     * llama calculo mal daria la vuelta y pediria un bloque pequeno, y la
     * reserva triunfaria devolviendo un sitio que no esta -- por detras del
     * cual escribiria el sistema.
     * \~ */
    if (n > kBufferMaxCapacity - live) return nullptr;
    if (!grow(live + n)) return nullptr;
    return base_ + tail_;
}

void Buffer::commit(size_t n) noexcept {
    const size_t room = cap_ - tail_;
    tail_ += n < room ? n : room;
}

void Buffer::consume(size_t n) noexcept {
    const size_t live = tail_ - head_;
    head_ += n < live ? n : live;

    /* \~english
     * Everything consumed is the common case -- one message per read -- and
     * resetting both marks there keeps the next read starting at the front
     * without a slide.
     * \~spanish
     * Consumirlo todo es el caso corriente -- un mensaje por lectura -- y poner
     * las dos marcas a cero ahi hace que la lectura siguiente empiece al
     * principio sin deslizar nada.
     * \~ */
    if (head_ == tail_) {
        head_ = 0;
        tail_ = 0;
    }
}

} // namespace http_vx
