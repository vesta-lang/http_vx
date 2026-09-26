/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/deadline_heap.h
 * @brief
 * \~english Which of many things is due first, each with one exact deadline that moves.
 * \~spanish Cual de muchas cosas vence primero, cada una con un plazo exacto que se mueve.
 * \~
 *
 * \~english
 * A binary min-heap over identifiers 0 to capacity-1, with each one's place
 * in the heap kept, so moving a deadline is O(log n) and not a search.  For
 * what has its own exact time and moves it often -- a QUIC connection's
 * timer, which a single acknowledgement can move -- where the timer wheel
 * (timer_wheel.h) would round it to a tick.
 *
 * \~spanish
 * Un monticulo binario de minimos sobre los identificadores 0 a capacity-1,
 * guardando el sitio de cada uno en el monticulo, asi que mover un plazo es
 * O(log n) y no una busqueda.  Para lo que tiene su propia hora exacta y la
 * mueve a menudo -- el temporizador de una conexion QUIC, que una sola
 * confirmacion puede mover --, donde la rueda de temporizadores
 * (timer_wheel.h) lo redondearia a un tic.
 * \~
 */
#ifndef HTTP_VX_DEADLINE_HEAP_H
#define HTTP_VX_DEADLINE_HEAP_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Deadlines by identifier, the earliest first.
 * \~spanish Plazos por identificador, el primero delante.
 * \~
 */
class DeadlineHeap {
  public:
    /// \~english No deadline: set() with it removes.  \~spanish Ningun plazo: set() con el quita.  \~
    static constexpr uint64_t kNever = ~uint64_t{0};

    DeadlineHeap() noexcept = default;
    ~DeadlineHeap() { release(); }
    DeadlineHeap(const DeadlineHeap &) = delete;
    DeadlineHeap &operator=(const DeadlineHeap &) = delete;

    /// \~english Room for identifiers 0 to @p capacity - 1; false if the memory could not be had.
    /// \~spanish Sitio para los identificadores 0 a @p capacity - 1; falso si no se pudo conseguir la memoria.  \~
    bool reset(uint32_t capacity) noexcept;

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

    /// \~english @p id is due at @p when; kNever takes it out.  \~spanish @p id vence a @p when; kNever lo saca.  \~
    void set(uint32_t id, uint64_t when) noexcept;

    /// \~english @p id has no deadline.  \~spanish @p id no tiene plazo.  \~
    void remove(uint32_t id) noexcept;

    bool empty() const noexcept { return count_ == 0; }
    size_t size() const noexcept { return count_; }
    /// \~english The one due first; only when not empty.  \~spanish El que vence primero; solo si no esta vacio.  \~
    uint32_t top() const noexcept { return heap_[0]; }
    /// \~english When the first is due, or kNever.  \~spanish Cuando vence el primero, o kNever.  \~
    uint64_t next() const noexcept { return count_ == 0 ? kNever : when_[heap_[0]]; }
    /// \~english When @p id is due, or kNever.  \~spanish Cuando vence @p id, o kNever.  \~
    uint64_t when(uint32_t id) const noexcept { return pos_[id] == kOut ? kNever : when_[id]; }

  private:
    static constexpr uint32_t kOut = 0xFFFFFFFF;

    void up(uint32_t at) noexcept;
    void down(uint32_t at) noexcept;
    void place(uint32_t at, uint32_t id) noexcept {
        heap_[at] = id;
        pos_[id] = at;
    }

    uint32_t *heap_ = nullptr;
    uint32_t *pos_ = nullptr;
    uint64_t *when_ = nullptr;
    uint32_t capacity_ = 0;
    uint32_t count_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_DEADLINE_HEAP_H
