/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/fuzz_h2_frame.cpp
 * @brief
 * \~english The entry point for the frame reader.
 * \~spanish El punto de entrada del lector de tramas.
 * \~
 *
 * \~english
 * A fuzzer is worth more against a binary format than against a text one, and
 * the reason is the same one that makes a binary format worth having.  Text is
 * read by looking for delimiters, and a mistake there is usually visible in a
 * case somebody thought of; frames are read by doing arithmetic on lengths
 * that came from the peer, and arithmetic fails at edges nobody thinks of.
 *
 * @code
 * ./build-fuzz/fuzz_h2_frame corpus-h2/
 * @endcode
 *
 * \~spanish
 * Un fuzzer vale mas contra un formato binario que contra uno de texto, y la
 * razon es la misma que hace que merezca la pena un formato binario.  El texto
 * se lee buscando delimitadores, y una equivocacion ahi suele verse en un caso
 * que se le ocurrio a alguien; las tramas se leen haciendo aritmetica con
 * longitudes que vinieron del otro extremo, y la aritmetica falla en extremos
 * que no se le ocurren a nadie.
 *
 * @code
 * ./build-fuzz/fuzz_h2_frame corpus-h2/
 * @endcode
 *
 * \~
 */

#include "codec_invariants.h"

#include <cstdio>
#include <cstdlib>

/**
 * @brief
 * \~english Hands one input to the frame reader's invariant check.
 * \~spanish Entrega una entrada a la comprobacion de invariantes del lector.
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english zero, as libFuzzer requires
 *             \~spanish cero, como exige libFuzzer  \~
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const http_vx::fuzz::Breach b = http_vx::fuzz::check_frames(data, size);
    if (b != http_vx::fuzz::Breach::None) {
        std::fprintf(stderr, "http_vx: %s\n", http_vx::fuzz::breach_name(b));
        std::abort();
    }
    return 0;
}
