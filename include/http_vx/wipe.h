/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/wipe.h
 * @brief
 * \~english Clearing secret bytes where the compiler cannot drop the store: one definition for every layer.
 * \~spanish Borrar bytes secretos donde el compilador no puede quitar la escritura: una definicion para todas las capas.
 * \~
 *
 * \~english
 * Header-only on purpose: the packet protection, the TLS key schedule and
 * sessions, and the providers all clear keys, and they sit in libraries
 * that cannot depend on one another.  There were six copies of this
 * function, one per file, which is how one of them ends up without its
 * barrier one day and a key stays in memory.
 * \~spanish
 * Solo cabecera a proposito: la proteccion de paquetes, el calendario de
 * claves y las sesiones de TLS, y los proveedores borran claves, y viven en
 * bibliotecas que no pueden depender unas de otras.  Habia seis copias de esta
 * funcion, una por fichero, que es como una de ellas acaba un dia sin su
 * barrera y una clave se queda en memoria.
 * \~
 */
#ifndef HTTP_VX_WIPE_H
#define HTTP_VX_WIPE_H

#include "util/mem/vesta_memset.h"

#include <cstddef>

namespace http_vx {

/**
 * @brief
 * \~english Clears @p n secret bytes at @p p where the compiler cannot drop the store.
 * \~spanish Borra @p n bytes secretos en @p p donde el compilador no puede quitar la escritura.
 * \~
 *
 * \~english
 * A store to memory that is about to be freed or to go out of scope is dead
 * to the optimiser, and a secret "wiped" that way is still in memory.  The
 * memset is the out-of-line one, and the empty asm that takes the pointer
 * and clobbers memory tells the compiler the bytes are read afterwards.
 * \~spanish
 * Una escritura a memoria que se va a liberar o a salir de ambito esta muerta
 * para el optimizador, y un secreto "borrado" asi sigue en memoria.  El memset
 * es el que no se pone en linea, y el asm vacio que toma el puntero y ensucia
 * la memoria le dice al compilador que los bytes se leen despues.
 * \~
 * @param p \~english where  \~spanish donde  \~
 * @param n \~english how many bytes  \~spanish cuantos bytes  \~
 */
inline void wipe_secret(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

} // namespace http_vx

#endif // HTTP_VX_WIPE_H
