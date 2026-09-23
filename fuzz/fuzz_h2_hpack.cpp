/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/fuzz_h2_hpack.cpp
 * @brief
 * \~english The entry point for the header block decoder.
 * \~spanish El punto de entrada del descodificador de bloques de cabeceras.
 * \~
 *
 * \~english
 * The most worthwhile of the four targets, because this is the layer with the
 * most ways to be wrong in one place: variable-length numbers, a bit-aligned
 * code, a table whose indices come from the peer, and an output buffer filled
 * from three different sources.  Every one of those is arithmetic on a length
 * somebody else chose.
 *
 * @code
 * ./build-fuzz/fuzz_h2_hpack corpus-hpack/
 * @endcode
 *
 * \~spanish
 * El mas util de los cuatro objetivos, porque esta es la capa con mas formas de
 * estar mal en un solo sitio: numeros de longitud variable, un codigo alineado
 * a bits, una tabla cuyos indices vienen del otro extremo, y un buffer de
 * salida que se llena desde tres sitios distintos.  Todo eso es aritmetica con
 * una longitud que eligio otro.
 *
 * @code
 * ./build-fuzz/fuzz_h2_hpack corpus-hpack/
 * @endcode
 *
 * \~
 */

#include "codec_invariants.h"

#include <cstdio>
#include <cstdlib>

/**
 * @brief
 * \~english Hands one input to the decoder's invariant check.
 * \~spanish Entrega una entrada a la comprobacion de invariantes del descodificador.
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english zero, as libFuzzer requires
 *             \~spanish cero, como exige libFuzzer  \~
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const http_vx::fuzz::Breach b = http_vx::fuzz::check_hpack(data, size);
    if (b != http_vx::fuzz::Breach::None) {
        std::fprintf(stderr, "http_vx: %s\n", http_vx::fuzz::breach_name(b));
        std::abort();
    }
    return 0;
}
