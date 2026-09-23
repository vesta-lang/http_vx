# =============================================================================
#  Las pruebas de http_vx
# =============================================================================
#
# Cada fichero de `tests/` produce un ejecutable propio y se registra en ctest.
# No hay marco de pruebas: un test es un `main` que devuelve 0 o no, y eso basta
# para lo que se prueba aqui -- bytes que entran y estructuras que salen --.
#
# Lo que SI importa es que no enlacen nada del sistema: si una prueba de
# `core/` o `proto/` necesitara un socket, el corte del proyecto estaria mal
# (ver doc/architecture.md, R6).
#
# Una prueba lista SU fichero y nada mas.  Lo que use sale de `http_vx_core` y
# `http_vx_proto`, que son estaticas: el enlazador se lleva los objetos que
# hagan falta y deja los demas, asi que enlazar las dos no engorda un binario
# que solo mire una tabla de cabeceras.
# =============================================================================

function(http_vx_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name}
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz
            PRIVATE ${HTTP_VX_ALLOC_INCLUDE})
    target_compile_options(${name} PRIVATE -Wall -Wextra -pedantic-errors)
    target_link_libraries(${name} PRIVATE http_vx_proto http_vx_core vesta_alloc)
    add_test(NAME ${name} COMMAND ${name})
endfunction()
