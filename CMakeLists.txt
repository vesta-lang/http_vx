# =============================================================================
#  http_vx -- servidor HTTP/1.1 por finalizacion
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
        DESCRIPTION "Servidor HTTP/1.1 por finalizacion"
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
# Aun no hay fuentes: este arbol es el esqueleto acordado en doc/architecture.md
# y se va poblando por escalones.  El orden esta en ese documento; el primero es
# `proto/`, que es donde vive la correctitud y no necesita ni plataforma ni
# bucle de eventos para probarse.
# ---------------------------------------------------------------------------

if (HTTP_VX_BUILD_TESTS)
    enable_testing()
endif ()
