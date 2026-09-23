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
# =============================================================================

function(http_vx_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name}
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
            PRIVATE ${HTTP_VX_ALLOC_INCLUDE})
    target_compile_options(${name} PRIVATE -Wall -Wextra -pedantic-errors)
    target_link_libraries(${name} PRIVATE vesta_alloc)
    add_test(NAME ${name} COMMAND ${name})
endfunction()
