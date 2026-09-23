/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/fuzz_h1_chunked.cpp
 * @brief
 * \~english The entry point for the body reader.
 * \~spanish El punto de entrada del lector de cuerpo.
 * \~
 *
 * \~english
 * Its own target and not a flag inside the head's, because a fuzzer learns the
 * shape of what it is given: bytes that are a request head are not bytes that
 * are a chunked body, and mixing them spends the run on inputs one of the two
 * refuses at the first byte.
 *
 * @code
 * ./build-fuzz/fuzz_h1_chunked corpus-chunked/
 * @endcode
 *
 * \~spanish
 * Objetivo propio y no una bandera dentro del de la cabeza, porque un fuzzer
 * aprende la forma de lo que se le da: unos bytes que son una cabeza de
 * peticion no son unos bytes que sean un cuerpo troceado, y mezclarlos gasta la
 * corrida en entradas que uno de los dos rechaza al primer byte.
 *
 * @code
 * ./build-fuzz/fuzz_h1_chunked corpus-chunked/
 * @endcode
 *
 * \~
 */

#include "codec_invariants.h"

#include <cstdio>
#include <cstdlib>

/**
 * @brief
 * \~english Hands one input to the body reader's invariant check.
 * \~spanish Entrega una entrada a la comprobacion de invariantes del lector.
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english zero, as libFuzzer requires
 *             \~spanish cero, como exige libFuzzer  \~
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const http_vx::fuzz::Breach b = http_vx::fuzz::check_chunked(data, size);
    if (b != http_vx::fuzz::Breach::None) {
        std::fprintf(stderr, "http_vx: %s\n", http_vx::fuzz::breach_name(b));
        std::abort();
    }
    return 0;
}
