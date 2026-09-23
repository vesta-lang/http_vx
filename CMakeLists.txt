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

add_library(http_vx_core STATIC
        core/buffer.cpp
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
        proto/semantics/status.cpp

        proto/h1/chunked.cpp
        proto/h1/framing.cpp
        proto/h1/parser.cpp
        proto/h1/writer.cpp

        proto/h2/frame.cpp
        proto/h2/reader.cpp
)
target_include_directories(http_vx_proto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PUBLIC ${HTTP_VX_ALLOC_INCLUDE})
target_compile_options(http_vx_proto PRIVATE -Wall -Wextra -pedantic-errors)
target_link_libraries(http_vx_proto PUBLIC vesta_alloc)

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
    http_vx_add_test(test_chars tests/test_chars.cpp)
    http_vx_add_test(test_content_length tests/test_content_length.cpp)
    http_vx_add_test(test_field tests/test_field.cpp)
    http_vx_add_test(test_fields tests/test_fields.cpp)
    http_vx_add_test(test_h1_chunked tests/test_h1_chunked.cpp)
    http_vx_add_test(test_h1_framing tests/test_h1_framing.cpp)
    http_vx_add_test(test_codec_fuzz tests/test_codec_fuzz.cpp fuzz/codec_invariants.cpp)
    http_vx_add_test(test_h1_parser tests/test_h1_parser.cpp)
    http_vx_add_test(test_h1_writer tests/test_h1_writer.cpp)
    http_vx_add_test(test_h2_frame tests/test_h2_frame.cpp)
    http_vx_add_test(test_message tests/test_message.cpp)
    http_vx_add_test(test_method tests/test_method.cpp)
    http_vx_add_test(test_status tests/test_status.cpp)
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
    foreach (_target h1_parser h1_chunked h2_frame)
        add_executable(fuzz_${_target}
                fuzz/fuzz_${_target}.cpp fuzz/codec_invariants.cpp)
        target_include_directories(fuzz_${_target}
                PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
        target_compile_options(fuzz_${_target}
                PRIVATE -Wall -Wextra -pedantic-errors)
        target_link_libraries(fuzz_${_target} PRIVATE http_vx_proto http_vx_core)
    endforeach ()
endif ()
