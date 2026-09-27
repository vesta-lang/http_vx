/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/uring_ring.h
 * @brief
 * \~english Where the kernel and an io_uring backend meet, and how its indices are read and published (private to linux/).
 * \~spanish Donde se encuentran el nucleo y un backend de io_uring, y como se leen y publican sus indices (privado de linux/).
 * \~
 *
 * \~english
 * Its own header because two files write entries into the ring: the
 * operations in `uring_backend.cpp` and the wake read in `uring_wake.cpp`.
 * \~spanish
 * Cabecera propia porque dos ficheros escriben entradas en el anillo: las
 * operaciones en `uring_backend.cpp` y la lectura de despertar en
 * `uring_wake.cpp`.
 * \~
 */
#ifndef HTTP_VX_LINUX_URING_RING_H
#define HTTP_VX_LINUX_URING_RING_H

#include "http_vx/uring_backend.h"

#include <linux/io_uring.h>

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Reads a ring index the kernel may be writing.
 * \~spanish Lee un indice del anillo que puede estar escribiendo el nucleo.
 * \~
 *
 * \~english
 * ACQUIRE, and that is not decoration.  The tail of the completion ring is
 * written by the kernel and the entries it points at are written BEFORE it; a
 * plain read may be moved after the reads of those entries by either the
 * compiler or the processor, and then this end reads a completion that has not
 * been filled in yet.
 *
 * It does not fail loudly.  What it produces is a completion naming an
 * operation that was never asked for, once in a while, on a machine under
 * load.
 *
 * \~spanish
 * ACQUIRE, y no es un adorno.  La cola del anillo de finalizaciones la escribe
 * el nucleo y las entradas a las que apunta se escriben ANTES; una lectura
 * normal la pueden mover detras de las lecturas de esas entradas el compilador o
 * el procesador, y entonces este extremo lee una finalizacion que todavia no se
 * ha rellenado.
 *
 * Y no falla en voz alta.  Lo que produce es una finalizacion que nombra una
 * operacion que no pidio nadie, de vez en cuando, en una maquina con trabajo.
 * \~
 */
inline uint32_t ring_load_acquire(const uint32_t *p) noexcept {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

/// \~english Publishes a ring index the kernel will read.
/// \~spanish Publica un indice del anillo que leera el nucleo.  \~
inline void ring_store_release(uint32_t *p, uint32_t v) noexcept {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

/**
 * @brief
 * \~english Where the kernel and this end meet.
 * \~spanish Donde se encuentran el nucleo y este extremo.
 * \~
 */
struct UringBackend::Ring {
    /// \~english The mapping, and how much of it there is.
    /// \~spanish El mapeo, y cuanto hay de el.  \~
    void *rings = nullptr;
    size_t rings_size = 0;

    io_uring_sqe *sqes = nullptr;
    size_t sqes_size = 0;

    /* \~english
     * Pointers INTO the mapping rather than copies of what is there.  Every
     * one of these is a place the kernel and this end both write, so a copy
     * would be a second answer that stops agreeing with the first.
     * \~spanish
     * Punteros DENTRO del mapeo y no copias de lo que hay.  Todos estos son un
     * sitio en el que escriben el nucleo y este extremo, asi que una copia seria
     * una segunda respuesta que deja de estar de acuerdo con la primera.
     * \~ */
    uint32_t *sq_head = nullptr;
    uint32_t *sq_tail = nullptr;
    uint32_t *sq_array = nullptr;
    uint32_t sq_mask = 0;
    uint32_t sq_entries = 0;

    uint32_t *cq_head = nullptr;
    uint32_t *cq_tail = nullptr;
    io_uring_cqe *cqes = nullptr;
    uint32_t cq_mask = 0;

    /// \~english Whether the kernel accepts a deadline on the wait.
    /// \~spanish Si el nucleo acepta un plazo en la espera.  \~
    bool ext_arg = false;
};

/**
 * @brief
 * \~english What an operation was for, kept until its number comes back.
 * \~spanish De que era una operacion, guardado hasta que vuelva su numero.
 * \~
 *
 * \~english
 * Here and not in `uring_backend.cpp` because the cancel (`uring_cancel.cpp`)
 * has to name the number of the read it ends.
 * \~spanish
 * Aqui y no en `uring_backend.cpp` porque la cancelacion (`uring_cancel.cpp`)
 * tiene que nombrar el numero de la lectura que acaba.
 * \~
 */
struct UringBackend::Slot {
    Op op;
    uint32_t next;

    /**
     * \~english
     * Which of this slot's lives the operation in it is, bumped every time
     * the slot is taken, and carried in the high half of the number the ring
     * gives back.  It is what lets a cancel name ONE operation: a cancel that
     * reached the kernel after the read it meant had completed, and after its
     * slot had been taken by somebody else's write, would otherwise end that
     * write -- the number alone would match.
     * \~spanish
     * Cual de las vidas de esta casilla es la operacion que tiene, subida cada
     * vez que se coge la casilla, y llevada en la mitad alta del numero que
     * devuelve el anillo.  Es lo que deja que una cancelacion nombre UNA
     * operacion: una cancelacion que llegara al nucleo despues de acabar la
     * lectura que queria decir, y despues de que otro cogiera su casilla para
     * una escritura, acabaria esa escritura -- el numero solo coincidiria.
     * \~
     */
    uint32_t life;

    bool busy;

    /// \~english Whether a cancel of it is already with the kernel.
    /// \~spanish Si ya tiene el nucleo una cancelacion suya.  \~
    bool cancelling;
};

/**
 * @brief
 * \~english The number the ring carries for the operation in slot @p index, life @p life.
 * \~spanish El numero que lleva el anillo para la operacion de la casilla @p index, vida @p life.
 * \~
 *
 * @param index \~english the slot  \~spanish la casilla  \~
 * @param life  \~english its life  \~spanish su vida  \~
 * @return      \~english the ring's @c user_data  \~spanish el @c user_data del anillo  \~
 */
inline uint64_t slot_user_data(uint32_t index, uint32_t life) noexcept {
    return (static_cast<uint64_t>(life) << 32) | index;
}

/// \~english The slot a ring number names.  \~spanish La casilla que nombra un numero del anillo.  \~
inline uint32_t slot_index_of(uint64_t user_data) noexcept {
    return static_cast<uint32_t>(user_data);
}

/// \~english The life a ring number names.  \~spanish La vida que nombra un numero del anillo.  \~
inline uint32_t slot_life_of(uint64_t user_data) noexcept {
    return static_cast<uint32_t>(user_data >> 32);
}

} // namespace http_vx

#endif // HTTP_VX_LINUX_URING_RING_H
