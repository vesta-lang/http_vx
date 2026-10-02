/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/cpu_affinity.h
 * @brief
 * \~english Which CPUs this process may use, and pinning a thread to one of them.
 * \~spanish Que CPU puede usar este proceso, y fijar un hilo a una de ellas.
 * \~
 *
 * \~english
 * HVX-6, 3 and R44.  A shard is a thread pinned to a CPU, and it builds its
 * memory AFTER it is pinned so the pages land on that CPU's node.  The CPUs
 * are the ones the process is ALLOWED (its affinity mask, which a container or
 * `taskset` narrows), not the ones the machine has: the i-th shard goes to the
 * i-th allowed CPU.  On Windows only the first processor group (64 CPUs) is
 * seen.
 * \~spanish
 * HVX-6, 3 y R44.  Un fragmento es un hilo fijado a una CPU, y construye su
 * memoria DESPUES de fijarse para que las paginas caigan en el nodo de esa CPU.
 * Las CPU son las que el proceso TIENE PERMITIDAS (su mascara de afinidad, que
 * un contenedor o `taskset` estrechan), no las que tiene la maquina: el
 * fragmento i-esimo va a la CPU permitida i-esima.  En Windows solo se ve el
 * primer grupo de procesadores (64 CPU).
 * \~
 */
#ifndef HTTP_VX_SERVE_CPU_AFFINITY_H
#define HTTP_VX_SERVE_CPU_AFFINITY_H

#include <cstdint>

namespace serve {

/// \~english How many CPUs this process may run on; at least 1.  \~spanish En cuantas CPU puede correr este proceso; al menos 1.  \~
uint32_t usable_cpus() noexcept;

/**
 * @brief
 * \~english Pins the calling thread to the @p index-th allowed CPU (modulo how many there are).
 * \~spanish Fija el hilo que llama a la CPU permitida @p index-esima (modulo cuantas hay).
 * \~
 *
 * @param index \~english which shard  \~spanish que fragmento  \~
 * @param cpu   \~english the CPU number it was pinned to, when it worked  \~spanish el numero de la CPU a la que se fijo, cuando funciono  \~
 * @return      \~english false if the system refused  \~spanish false si el sistema se nego  \~
 */
bool pin_current_thread(uint32_t index, uint32_t &cpu) noexcept;

} // namespace serve

#endif // HTTP_VX_SERVE_CPU_AFFINITY_H
