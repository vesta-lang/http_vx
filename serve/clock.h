/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/clock.h
 * @brief
 * \~english The steady clock every shard of the runnable server counts time with.
 * \~spanish El reloj estable con el que cuentan el tiempo todos los fragmentos del servidor ejecutable.
 * \~
 *
 * \~english
 * It is a STEADY clock and not the wall one.  The wall clock jumps -- it is
 * corrected, it changes for the summer -- and a deadline measured against
 * something that can go backwards is a connection that either never times out
 * or times out at once, twice a year, on a server that worked all the other
 * days.  It is also the ONE clock: shards count from the same start, so a tick
 * means the same thing on all of them.
 * \~spanish
 * Es un reloj ESTABLE y no el de pared.  El de pared da saltos -- se corrige,
 * cambia en verano -- y un plazo medido contra algo que puede ir hacia atras es
 * una conexion que o no vence nunca o vence en el acto, dos veces al ano, en un
 * servidor que funciono todos los demas dias.  Y es EL reloj: los fragmentos
 * cuentan desde el mismo comienzo, asi que un tic significa lo mismo en todos.
 * \~
 */
#ifndef HTTP_VX_SERVE_CLOCK_H
#define HTTP_VX_SERVE_CLOCK_H

#include <chrono>
#include <cstdint>

namespace serve {

/**
 * @brief
 * \~english What tick it is, counted in seconds since the first call.
 * \~spanish En que tic se esta, contado en segundos desde la primera llamada.
 * \~
 *
 * \~english
 * A second, because that is the unit deadlines are talked about in.  The first
 * call fixes the start, so the server calls it once before it makes any shard.
 * \~spanish
 * Un segundo, porque es la unidad en la que se habla de los plazos.  La primera
 * llamada fija el comienzo, asi que el servidor la llama una vez antes de hacer
 * ningun fragmento.
 * \~
 */
inline uint64_t now_ticks() {
    using Clock = std::chrono::steady_clock;
    static const Clock::time_point start = Clock::now();

    const auto since = Clock::now() - start;
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(since).count());
}

/// \~english The same steady clock in microseconds: ticket ages are measured in milliseconds.
/// \~spanish El mismo reloj estable en microsegundos: las edades de los tickets se miden en milisegundos.  \~
inline uint64_t now_us() {
    using Clock = std::chrono::steady_clock;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count());
}

} // namespace serve

#endif // HTTP_VX_SERVE_CLOCK_H
