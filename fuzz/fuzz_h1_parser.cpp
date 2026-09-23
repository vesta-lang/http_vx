/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/fuzz_h1_parser.cpp
 * @brief
 * \~english The entry point a real fuzzer drives.
 * \~spanish El punto de entrada que gobierna un fuzzer de verdad.
 * \~
 *
 * \~english
 * Four lines, and that is the point: what is worth checking is in
 * @c h1_invariants, where an ordinary test checks the same things without
 * needing a toolchain that has a fuzzer.  This file only hands the bytes over.
 *
 * It is also all that R6 buys, made concrete.  The parser includes nothing
 * from the operating system, so a fuzzer drives it as it would any function --
 * no socket, no port, no privileges, and a crash reproduces from a file.
 *
 * Build it with a compiler that has libFuzzer:
 *
 * @code
 * cmake -S . -B build-fuzz -DHTTP_VX_BUILD_FUZZ=ON \
 *       -DCMAKE_CXX_COMPILER=clang++ \
 *       -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined"
 * ./build-fuzz/fuzz_h1_parser corpus/
 * @endcode
 *
 * \~spanish
 * Cuatro lineas, y de eso se trata: lo que merece comprobarse esta en
 * @c h1_invariants, donde una prueba corriente comprueba lo mismo sin necesitar
 * un entorno que tenga fuzzer.  Este fichero solo entrega los bytes.
 *
 * Es ademas todo lo que compra R6, hecho concreto.  El analizador no incluye
 * nada del sistema operativo, asi que un fuzzer lo gobierna como a cualquier
 * funcion -- sin socket, sin puerto, sin permisos, y una caida se reproduce
 * desde un fichero.
 *
 * Se construye con un compilador que tenga libFuzzer:
 *
 * @code
 * cmake -S . -B build-fuzz -DHTTP_VX_BUILD_FUZZ=ON \
 *       -DCMAKE_CXX_COMPILER=clang++ \
 *       -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined"
 * ./build-fuzz/fuzz_h1_parser corpus/
 * @endcode
 *
 * \~
 */

#include "h1_invariants.h"

#include <cstdio>
#include <cstdlib>

/**
 * @brief
 * \~english Hands one input to the invariant check.
 * \~spanish Entrega una entrada a la comprobacion de invariantes.
 * \~
 *
 * \~english
 * A broken property aborts rather than returning, because a fuzzer only
 * records what crashes.  Returning quietly would leave the finding in a log
 * nobody reads while the run carries on reporting success.
 *
 * \~spanish
 * Una propiedad rota aborta en vez de volver, porque un fuzzer solo anota lo
 * que cae.  Volver calladamente dejaria el hallazgo en un registro que no lee
 * nadie mientras la corrida sigue informando de exito.
 *
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english zero, as libFuzzer requires
 *             \~spanish cero, como exige libFuzzer  \~
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const http_vx::fuzz::Breach b = http_vx::fuzz::check_parse(data, size);
    if (b != http_vx::fuzz::Breach::None) {
        std::fprintf(stderr, "http_vx: %s\n", http_vx::fuzz::breach_name(b));
        std::abort();
    }
    return 0;
}

/*
 * \~english
 * The body has a target of its own rather than a flag inside this one.  A
 * fuzzer learns the shape of what it is given, and bytes that are a request
 * head are not bytes that are a chunked body: mixing them would spend the run
 * on inputs that one of the two readers refuses at the first byte, and would
 * make a corpus that means one thing for half its entries.
 *
 * \~spanish
 * El cuerpo tiene objetivo propio en vez de una bandera dentro de este.  Un
 * fuzzer aprende la forma de lo que se le da, y unos bytes que son una cabeza
 * de peticion no son unos bytes que sean un cuerpo troceado: mezclarlos
 * gastaria la corrida en entradas que uno de los dos lectores rechaza al primer
 * byte, y haria un corpus que significa una cosa para la mitad de sus entradas.
 * \~
 */
