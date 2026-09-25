# =============================================================================
#  http_vx -- servidor HTTP (1.1, 2 y 3) por finalizacion
# =============================================================================
#
# Se construye de dos maneras, igual que `vesta_alloc` y `vesta_prof`:
#
#   - COMO PARTE de otro proyecto (`add_subdirectory`): el que lo incruste
#     enlaza contra sus objetivos y las pruebas propias se apagan, para no
#     duplicar binarios ni tiempo de construccion.
#   - SOLO, como cualquier proyecto:
#
#         cmake -S . -B build && cmake --build build && ctest --test-dir build
#
# LOS BACKENDS NO SE PROMETEN TODOS.  io_uring necesita cabeceras que no estan
# en todas las maquinas, y hay distribuciones que lo desactivan por politica.
# Se detecta, y si falta se omite DICIENDOLO: epoll no es un respaldo sino un
# backend de primera (ver doc/architecture.md, R8), asi que construir sin
# io_uring no es construir a medias.  Lo que no puede pasar es creerse que se
# construyo uno que no esta.
#
# Ver README.md para la disposicion y doc/architecture.md para el porque.
cmake_minimum_required(VERSION 3.16)

project(http_vx
        VERSION 0.1.0
        DESCRIPTION "Servidor HTTP 1.1/2/3 por finalizacion"
        LANGUAGES CXX)

# Suelto o incrustado?  Mismo criterio que el asignador y el perfilador.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(HTTP_VX_STANDALONE ON)
else ()
    set(HTTP_VX_STANDALONE OFF)
endif ()

option(HTTP_VX_BUILD_TESTS "Construir las pruebas" ${HTTP_VX_STANDALONE})
option(HTTP_VX_BUILD_BENCH "Construir las medidas" ${HTTP_VX_STANDALONE})
option(HTTP_VX_BUILD_FUZZ  "Construir el fuzzing del analizador" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# vesta_alloc: de donde sale la memoria, y tambien el memcpy y el memset.
#
# Es la UNICA dependencia, y no es de comodidad: la arena de fase es lo que
# hace que atender una peticion no sea una coleccion de reservas sueltas (ver
# doc/architecture.md, R10), y las listas libres por hilo son lo que permite
# que un fragmento no sincronice con nadie (R9).
#
# Se busca donde suele estar y se puede senalar con -DHTTP_VX_VESTA_ALLOC_DIR.
# Si no aparece se PARA diciendo donde se miro: construir sin ella significaria
# caer al asignador del sistema sin que nadie lo notase, y entonces las medidas
# de `bench/` dirian otra cosa que el binario que se publica.
# ---------------------------------------------------------------------------
set(HTTP_VX_VESTA_ALLOC_DIR "" CACHE PATH
        "Donde esta vesta_alloc (el directorio que contiene include/util/alloc)")

if (HTTP_VX_VESTA_ALLOC_DIR)
    set(_hvx_alloc_candidates "${HTTP_VX_VESTA_ALLOC_DIR}")
else ()
    set(_hvx_alloc_candidates
            "${CMAKE_CURRENT_SOURCE_DIR}/../libs/SourceCode/vesta_alloc"
            "${CMAKE_CURRENT_SOURCE_DIR}/../vesta_alloc"
            "${CMAKE_CURRENT_SOURCE_DIR}/libs/vesta_alloc")
endif ()

set(HTTP_VX_ALLOC_ROOT "")
foreach (_dir IN LISTS _hvx_alloc_candidates)
    if (EXISTS "${_dir}/include/util/alloc/scratch_arena.h")
        get_filename_component(HTTP_VX_ALLOC_ROOT "${_dir}" ABSOLUTE)
        break()
    endif ()
endforeach ()

if (NOT HTTP_VX_ALLOC_ROOT)
    message(FATAL_ERROR
            "no encuentro vesta_alloc.  Se miro en:\n"
            "  ${_hvx_alloc_candidates}\n"
            "Senalalo con -DHTTP_VX_VESTA_ALLOC_DIR=<ruta>.")
endif ()
set(HTTP_VX_ALLOC_INCLUDE "${HTTP_VX_ALLOC_ROOT}/include")
message(STATUS "http_vx: vesta_alloc en ${HTTP_VX_ALLOC_ROOT}")

# Y se ENLAZA, no solo se incluye.  `SmallVector` y `AllocScope` parecen
# cabeceras y no lo son del todo: acaban llamando al asignador, asi que sin su
# objetivo el enlace se cae -- que es el modo correcto de fallar, porque la
# alternativa seria caer al del sistema sin enterarse.
#
# Se anade solo si no lo ha anadido ya quien nos incrusta: en el arbol del
# compilador, `vesta_alloc` ya esta puesto y volver a anadirlo seria declarar
# sus objetivos dos veces.
if (NOT TARGET vesta_alloc)
    add_subdirectory("${HTTP_VX_ALLOC_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/vesta_alloc")
endif ()

# ---------------------------------------------------------------------------
# El arbol se puebla por escalones; el orden y el porque estan en
# doc/architecture.md, seccion 14.  Lo que hay hoy es la semantica -- lo que una
# peticion SIGNIFICA --, que es lo unico comun a las tres versiones y lo unico
# que no necesita ni plataforma ni bucle de eventos para probarse.
# ---------------------------------------------------------------------------

# `reactor/timer_wheel.cpp` vive aqui y no en un objetivo `http_vx_reactor`
# porque no toca el sistema operativo: son tres arrays y una mascara.  El
# objetivo del reactor sera el que SI lo toque -- epoll, IOCP, io_uring -- y lo
# que se pueda probar sin abrir un puerto no tiene por que depender de el.
add_library(http_vx_core STATIC
        core/buffer.cpp
        reactor/buffer_pool.cpp
        reactor/conn_table.cpp
        reactor/memory_backend.cpp
        reactor/shard.cpp
        reactor/stdio_backend.cpp
        reactor/timer_wheel.cpp
)
target_include_directories(http_vx_core
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
target_compile_options(http_vx_core PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_core PUBLIC vesta_alloc)

add_library(http_vx_proto STATIC
        proto/semantics/chars.cpp
        proto/semantics/content_length.cpp
        proto/semantics/field.cpp
        proto/semantics/fields.cpp
        proto/semantics/message.cpp
        proto/semantics/method.cpp
        proto/semantics/response.cpp
        proto/semantics/status.cpp

        proto/h1/chunked.cpp
        proto/h1/framing.cpp
        proto/h1/parser.cpp
        proto/h1/service.cpp
        proto/h1/writer.cpp

        proto/h2/connection.cpp
        proto/h2/decoder.cpp
        proto/h2/encoder.cpp
        proto/h2/frame.cpp
        proto/h2/hpack.cpp
        proto/h2/huffman.cpp
        proto/h2/table.cpp
        proto/h2/reader.cpp
        proto/h2/service.cpp
        proto/h2/settings.cpp
        proto/h2/stream.cpp
        proto/h2/writer.cpp
)
target_include_directories(http_vx_proto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
target_compile_options(http_vx_proto PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_proto PUBLIC vesta_alloc)

# ---------------------------------------------------------------------------
# QUIC.  Va en su propia libreria y AL LADO de `reactor/`, no debajo de
# `proto/` (R27): es un transporte, no una sintaxis de HTTP, y lo usa HTTP/3
# como HTTP/1.1 y HTTP/2 usan TCP.
#
# Y sin ninguna cabecera del sistema, por lo mismo que `core/` y `proto/`
# (R6): lo que lee QUIC es lo que manda un desconocido, y tiene que poder
# darsele bytes torcidos desde una prueba corriente sin abrir ningun puerto.
# ---------------------------------------------------------------------------
add_library(http_vx_quic STATIC
        quic/ack.cpp
        quic/frame.cpp
        quic/packet.cpp
        quic/protection.cpp
        quic/recovery.cpp
        quic/stream_recv.cpp
        quic/stream_send.cpp
        quic/varint.cpp
)
target_include_directories(http_vx_quic
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
target_compile_options(http_vx_quic PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_quic PUBLIC vesta_alloc)

# ---------------------------------------------------------------------------
# Un proveedor criptografico para QUIC, sobre la libcrypto de OpenSSL.
#
# APARTE y OPCIONAL, por la R22: `http_vx_quic` no enlaza ninguna biblioteca de
# criptografia -- define la interfaz (`quic_crypto.h`) y la logica del RFC 9001
# encima --, y el proveedor lo elige quien construye el servidor.  Este es UNO
# de ellos, no el proveedor.
#
# Si no se encuentra OpenSSL no se construye, y se DICE: sin proveedor, la
# prueba contra los paquetes enteros de los RFC no se puede ejecutar, y eso no
# puede pasar por una suite en verde sin mas.  La logica de QUIC se sigue
# comprobando igual, con `test_quic_protection`, que no necesita proveedor.
#
# Con un OpenSSL estatico: -DOPENSSL_ROOT_DIR=<prefijo> -DOPENSSL_USE_STATIC_LIBS=ON
# ---------------------------------------------------------------------------
option(HTTP_VX_OPENSSL_PROVIDER "Construir el proveedor QUIC sobre OpenSSL" ON)

if (HTTP_VX_OPENSSL_PROVIDER)
    find_package(OpenSSL 3.0 COMPONENTS Crypto)
endif ()

if (HTTP_VX_OPENSSL_PROVIDER AND OpenSSL_FOUND)
    add_library(http_vx_crypto_openssl STATIC
            providers/openssl/openssl_crypto.cpp
    )
    target_include_directories(http_vx_crypto_openssl
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/providers/openssl)
    target_compile_options(http_vx_crypto_openssl PRIVATE -Wall -Wextra -pedantic-errors)
    target_link_libraries(http_vx_crypto_openssl
            PUBLIC http_vx_quic
            PRIVATE OpenSSL::Crypto)

    # Una libcrypto ESTATICA en Windows trae lo suyo: sockets, el almacen de
    # certificados y el generador de numeros aleatorios del sistema.
    if (WIN32)
        target_link_libraries(http_vx_crypto_openssl PRIVATE ws2_32 crypt32 bcrypt)
    endif ()
    message(STATUS "[http_vx] QUIC provider: openssl ${OPENSSL_VERSION}")
elseif (HTTP_VX_OPENSSL_PROVIDER)
    message(WARNING "[http_vx] OpenSSL 3 was not found: the openssl QUIC provider is "
                    "not built, and the RFC packet vectors are NOT checked against it. "
                    "Point -DOPENSSL_ROOT_DIR at one to check them.")
endif ()

# ---------------------------------------------------------------------------
# Y el proveedor del propio SISTEMA en Windows: la CNG (bcrypt.dll).  Es el que
# la R22 nombra como natural ahi -- nada que distribuir ni que parchear, lo
# parchea Windows Update -- y por eso se construye siempre que se construye en
# Windows: no depende de nada que pueda faltar.  Enlazarlo sigue siendo decision
# de quien construye el servidor.
#
# AES sale del sistema; ChaCha20-Poly1305, de `http_vx_chacha`, porque la CNG
# de Windows 10 no tiene ni el AEAD ni el flujo en bruto que pide su proteccion
# de cabecera.
# ---------------------------------------------------------------------------
# ChaCha20 y Poly1305 (RFC 8439), escritos aqui: la CNG de Windows 10 no tiene
# ninguno de los dos.  Sin ninguna cabecera del sistema, asi que se construye y
# se prueba en TODAS las plataformas, lo use ahi un proveedor o no.  Escribir un
# algoritmo basico no va contra la R22: lo que deja fuera es una BIBLIOTECA con
# una licencia que no encaja con la de este proyecto.
add_library(http_vx_chacha STATIC
        providers/common/chacha20_poly1305.cpp
)
target_include_directories(http_vx_chacha
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/providers/common
        PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
target_compile_options(http_vx_chacha PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_chacha PUBLIC vesta_alloc)

if (WIN32)
    add_library(http_vx_crypto_cng STATIC
            providers/windows/cng_crypto.cpp
    )
    target_include_directories(http_vx_crypto_cng
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/providers/windows)
    target_compile_options(http_vx_crypto_cng PRIVATE -Wall -Wextra -pedantic-errors)
    target_link_libraries(http_vx_crypto_cng
            PUBLIC http_vx_quic
            PRIVATE http_vx_chacha bcrypt)
    message(STATUS "[http_vx] QUIC provider: cng (the system's own)")
endif ()

# ---------------------------------------------------------------------------
# Un servidor que se EJECUTA, y sin red por ningun sitio: lee una peticion de su
# entrada estandar y escribe la respuesta en su salida.  Eso es un transporte de
# verdad y no un sustituto -- HTTP por una tuberia es como se le habla al demonio
# de Docker --, y ademas es lo que dice que las piezas son un servidor y no una
# coleccion de piezas que pasan sus pruebas.
#
# Se construye SIEMPRE, tambien cuando las pruebas estan apagadas: si lo que se
# publica no compila, eso hay que saberlo al construir y no al publicar.
# ---------------------------------------------------------------------------
add_executable(http_vx_serve serve/main.cpp)
target_include_directories(http_vx_serve PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(http_vx_serve PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_serve PRIVATE http_vx_proto http_vx_core)

# El que escucha en un PUERTO va mas abajo, despues de las librerias de
# plataforma: es lo unico de aqui que enlaza una.

# ---------------------------------------------------------------------------
# El primer backend con un sistema operativo dentro.  Va en su propia libreria
# y no en `http_vx_core` por la R6: lo que hay en `core/` y en `proto/` no
# incluye ni una cabecera del sistema, y eso es lo que permite darles bytes
# torcidos desde una prueba corriente sin abrir ningun puerto.  Este SI abre
# uno, asi que vive aparte y lo enlaza quien lo quiera.
#
# Y va por plataforma, no por opcion: un objetivo de IOCP en Linux no es una
# caracteristica apagada, es un fichero que no compila.  Cuando llegue io_uring
# entrara aqui al lado con la condicion contraria.
# ---------------------------------------------------------------------------
if (WIN32)
    add_library(http_vx_windows STATIC windows/iocp_backend.cpp)
    target_include_directories(http_vx_windows
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
            PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
    target_compile_options(http_vx_windows PRIVATE -Wall -Wextra -pedantic-errors)

    # `ws2_32` es Winsock y `mswsock` es donde vive de verdad `AcceptEx`.  Se
    # enlazan PUBLIC porque quien use este backend acaba llamando a los dos sin
    # nombrarlos.
    target_link_libraries(http_vx_windows
            PUBLIC http_vx_core vesta_alloc ws2_32 mswsock)
endif ()

# Los DOS de Linux, que es lo que pide la R8: io_uring y epoll como backends de
# primera.  No porque dos sean mejor que uno -- porque el que solo esta para los
# nucleos viejos es el que no corre nadie, y un camino que no corre nadie es un
# camino que esta roto y no lo sabe.
if (UNIX)
    add_library(http_vx_linux STATIC
            linux/epoll_backend.cpp
            linux/uring_backend.cpp)
    target_include_directories(http_vx_linux
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
            PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
    target_compile_options(http_vx_linux PRIVATE -Wall -Wextra -pedantic-errors)
    target_link_libraries(http_vx_linux PUBLIC http_vx_core vesta_alloc)
endif ()

# ---------------------------------------------------------------------------
# Y el mismo servidor, en un PUERTO.  Hasta que existio no habia en el proyecto
# ningun programa que abriera uno: los backends estaban escritos y los movian
# las pruebas, y una prueba es un buen sitio para averiguar si un socket
# funciona y uno malo para averiguar lo que cuesta un servidor -- sirve cinco
# peticiones y termina.
#
# Va aqui y no al lado de `http_vx_serve` porque es lo unico del proyecto que
# enlaza una libreria de plataforma, y esas se definen justo arriba.
# ---------------------------------------------------------------------------
add_executable(http_vx_listen serve/listen.cpp)
target_include_directories(http_vx_listen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(http_vx_listen PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_listen PRIVATE http_vx_proto http_vx_core)

if (WIN32)
    target_link_libraries(http_vx_listen PRIVATE http_vx_windows)
else ()
    target_link_libraries(http_vx_listen PRIVATE http_vx_linux)
endif ()

# ---------------------------------------------------------------------------
# Las medidas.  El README dice que no son opcionales y tiene razon por dos
# lados: un servidor que promete un millon de conexiones tiene que poder ensenar
# cuanto ocupa cada una, y uno que promete velocidad tiene que poder ensenar
# cuanta.  Ademas una de las cuatro medidas es de SEGURIDAD -- que partir la
# entrada no encarezca el analisis (R12) --, y esa no se puede comprobar
# leyendo el codigo.
#
# Se construyen con OPTIMIZACION aunque el build sea de depuracion: una medida
# tomada sin optimizar no dice nada de lo que se publica, y publicar una asi
# seria peor que no medir.
# ---------------------------------------------------------------------------
if (HTTP_VX_BUILD_BENCH)
    add_executable(http_vx_bench bench/main.cpp)
    target_compile_options(http_vx_bench PRIVATE -Wall -Wextra -pedantic-errors -O2)
    target_link_libraries(http_vx_bench PRIVATE http_vx_proto http_vx_core)
endif ()

if (HTTP_VX_BUILD_TESTS)
    enable_testing()
    include(cmake/http_vx_tests.cmake)
    # Cada prueba es SU fichero y nada mas: lo que necesite sale de las dos
    # librerias, que es lo que las hace.  Antes cada una listaba los fuentes que
    # usaba, y siete de ellas repetian las mismas siete lineas de `semantics/`:
    # siete listas que mantener de acuerdo entre si y con el fichero de al lado,
    # y cuyo modo de fallo es que anadir un fuente rompe el enlace de las que se
    # olvidaron -- o, peor, que quitarlo no rompa nada porque ya no lo usaba
    # ninguna.
    http_vx_add_test(test_buffer tests/test_buffer.cpp)
    http_vx_add_test(test_buffer_pool tests/test_buffer_pool.cpp)
    http_vx_add_test(test_chars tests/test_chars.cpp)
    http_vx_add_test(test_content_length tests/test_content_length.cpp)
    http_vx_add_test(test_drain tests/test_drain.cpp)
    http_vx_add_test(test_field tests/test_field.cpp)
    http_vx_add_test(test_fields tests/test_fields.cpp)
    http_vx_add_test(test_h1_chunked tests/test_h1_chunked.cpp)
    http_vx_add_test(test_h1_framing tests/test_h1_framing.cpp)
    http_vx_add_test(test_codec_fuzz tests/test_codec_fuzz.cpp fuzz/codec_invariants.cpp)
    http_vx_add_test(test_conn_table tests/test_conn_table.cpp)
    http_vx_add_test(test_h1_parser tests/test_h1_parser.cpp)
    http_vx_add_test(test_http1_service tests/test_http1_service.cpp)
    http_vx_add_test(test_h1_writer tests/test_h1_writer.cpp)
    http_vx_add_test(test_h2_connection tests/test_h2_connection.cpp)
    http_vx_add_test(test_h2_decoder tests/test_h2_decoder.cpp)
    http_vx_add_test(test_h2_encoder tests/test_h2_encoder.cpp)
    http_vx_add_test(test_h2_frame tests/test_h2_frame.cpp)
    http_vx_add_test(test_h2_hpack tests/test_h2_hpack.cpp)
    http_vx_add_test(test_h2_huffman tests/test_h2_huffman.cpp)
    http_vx_add_test(test_h2_settings tests/test_h2_settings.cpp)
    http_vx_add_test(test_h2_stream tests/test_h2_stream.cpp)
    http_vx_add_test(test_h2_writer tests/test_h2_writer.cpp)
    http_vx_add_test(test_http2_service tests/test_http2_service.cpp)
    http_vx_add_test(test_quic_ack tests/test_quic_ack.cpp)
    http_vx_add_test(test_quic_frame tests/test_quic_frame.cpp)
    http_vx_add_test(test_quic_packet tests/test_quic_packet.cpp)
    http_vx_add_test(test_quic_protection tests/test_quic_protection.cpp)
    http_vx_add_test(test_quic_recovery tests/test_quic_recovery.cpp)
    http_vx_add_test(test_quic_stream_recv tests/test_quic_stream_recv.cpp)
    http_vx_add_test(test_quic_stream_send tests/test_quic_stream_send.cpp)
    http_vx_add_test(test_quic_varint tests/test_quic_varint.cpp)
    http_vx_add_test(test_chacha20_poly1305 tests/test_chacha20_poly1305.cpp)
    target_link_libraries(test_chacha20_poly1305 PRIVATE http_vx_chacha)

    # Contra los paquetes enteros de los RFC: solo si hay un proveedor con el
    # que sellarlos.  Si no lo hay ya se dijo arriba, al buscarlo.  Con varios,
    # es UNA prueba que corre los mismos casos contra cada uno (la R8 aplicada
    # a los proveedores, como `test_socket_backend` a los backends).
    if (TARGET http_vx_crypto_openssl OR TARGET http_vx_crypto_cng)
        http_vx_add_test(test_quic_vectors tests/test_quic_vectors.cpp)
        if (TARGET http_vx_crypto_openssl)
            target_link_libraries(test_quic_vectors PRIVATE http_vx_crypto_openssl)
            target_compile_definitions(test_quic_vectors PRIVATE HTTP_VX_HAVE_OPENSSL=1)
        endif ()
        if (TARGET http_vx_crypto_cng)
            target_link_libraries(test_quic_vectors PRIVATE http_vx_crypto_cng)
            target_compile_definitions(test_quic_vectors PRIVATE HTTP_VX_HAVE_CNG=1)
        endif ()
    endif ()
    http_vx_add_test(test_h2_table tests/test_h2_table.cpp)
    http_vx_add_test(test_message tests/test_message.cpp)
    http_vx_add_test(test_method tests/test_method.cpp)
    http_vx_add_test(test_reactor_ops tests/test_reactor_ops.cpp)
    http_vx_add_test(test_response tests/test_response.cpp)
    http_vx_add_test(test_shard tests/test_shard.cpp)
    http_vx_add_test(test_status tests/test_status.cpp)
    http_vx_add_test(test_stdio_backend tests/test_stdio_backend.cpp)
    http_vx_add_test(test_timer_wheel tests/test_timer_wheel.cpp)

    # La unica prueba que abre un puerto, y por eso enlaza lo que las demas no.
    # Lo que comprueba son las cosas en las que un backend sin sistema operativo
    # dentro NO PUEDE equivocarse -- perder un socket, no atarse, devolver un
    # descriptor de otro --, asi que no sustituye a ninguna: se anade a ellas.
    #
    # Es UN fichero para los dos sistemas, y eso es la R8: que epoll no sea un
    # camino que no prueba nadie no se consigue escribiendole una segunda
    # prueba, se consigue haciendo que los MISMOS casos corran contra el backend
    # que haya.  Dos ficheros serian dos juegos de casos, y el que se quedara
    # atras seria el de la maquina en la que no construye nadie.
    http_vx_add_test(test_socket_backend tests/test_socket_backend.cpp)
    if (WIN32)
        target_link_libraries(test_socket_backend PRIVATE http_vx_windows)
    else ()
        target_link_libraries(test_socket_backend PRIVATE http_vx_linux)
    endif ()
endif ()

# ---------------------------------------------------------------------------
# El objetivo de fuzzing.  Apagado por defecto porque necesita un compilador con
# libFuzzer, que no esta en todas partes; lo que SI corre en todas partes es
# `test_codec_fuzz`, que comprueba las mismas propiedades contra entrada que genera
# el.  Ver fuzz/codec_invariants.h: una comprobacion que solo vive dentro de un
# objetivo de fuzzing es una que corre cuando alguien se acuerda.
# ---------------------------------------------------------------------------
if (HTTP_VX_BUILD_FUZZ)
    # Uno por lector, no uno con una bandera dentro: un fuzzer aprende la forma
    # de lo que se le da, y unos bytes que son una cabeza de peticion no son
    # unos bytes que sean un cuerpo troceado.
    foreach (_target h1_parser h1_chunked h2_frame h2_hpack)
        add_executable(fuzz_${_target}
                fuzz/fuzz_${_target}.cpp fuzz/codec_invariants.cpp)
        target_include_directories(fuzz_${_target}
                PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
        target_compile_options(fuzz_${_target}
                PRIVATE -Wall -Wextra -pedantic-errors)
        target_link_libraries(fuzz_${_target} PRIVATE http_vx_proto http_vx_core)
    endforeach ()
endif ()
