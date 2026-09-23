/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_fields.cpp
 * @brief
 * \~english The field collection, and the two ways it could lie.
 * \~spanish La coleccion de cabeceras, y las dos formas en que podria mentir.
 * \~
 *
 * \~english
 * The presence mask is an optimisation, and an optimisation that answers wrong
 * is worse than not having it.  There are exactly two ways it can drift from
 * the array -- a field added without setting its bit, and a reuse that empties
 * the array without emptying the mask -- and neither breaks anything visibly:
 * the collection keeps answering, and answers something plausible.
 *
 * \~spanish
 * La mascara de presencia es una optimizacion, y una optimizacion que contesta
 * mal es peor que no tenerla.  Hay exactamente dos formas de que se separe del
 * array -- una cabecera anadida sin poner su bit, y una reutilizacion que
 * vacia el array sin vaciar la mascara -- y ninguna rompe nada de forma
 * visible: la coleccion sigue contestando, y contesta algo plausible.
 *
 * \~
 */

#include "http_vx/fields.h"

#include <cstdio>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

http_vx::Field make(http_vx::FieldId id, uint32_t name_off = 0,
                    uint32_t value_off = 0) {
    http_vx::Field f{};
    f.id = id;
    f.name_off = name_off;
    f.value_off = value_off;
    f.name_len = 4;
    f.value_len = 8;
    return f;
}

/**
 * @brief
 * \~english What was recorded can be found, and what was not cannot.
 * \~spanish Lo anotado se encuentra, y lo no anotado no.
 * \~
 */
void test_add_and_find() {
    using http_vx::FieldId;
    http_vx::Fields f;

    check(f.empty(), "a fresh collection is not empty");
    check(!f.has(FieldId::Host), "an empty collection claims to have a field");
    check(f.find(FieldId::Host) == nullptr,
          "an empty collection found something");

    f.add(make(FieldId::Host, 10));
    f.add(make(FieldId::ContentLength, 20));

    check(f.size() == 2, "the size does not match what was added");
    check(f.has(FieldId::Host), "a recorded field is not reported present");
    check(f.has(FieldId::ContentLength), "the second one is not present");
    check(!f.has(FieldId::Accept), "a field nobody added is reported present");

    const http_vx::Field *host = f.find(FieldId::Host);
    check(host != nullptr, "the recorded field was not found");
    check(host != nullptr && host->name_off == 10,
          "the field found is not the one recorded");
    check(f.find(FieldId::Accept) == nullptr,
          "something absent was found");
}

/**
 * @brief
 * \~english Repetition is kept: `set-cookie` arrives several times by design.
 * \~spanish La repeticion se conserva: `set-cookie` llega varias veces.
 * \~
 */
void test_repeated() {
    using http_vx::FieldId;
    http_vx::Fields f;
    f.add(make(FieldId::SetCookie, 1));
    f.add(make(FieldId::Host, 2));
    f.add(make(FieldId::SetCookie, 3));
    f.add(make(FieldId::SetCookie, 4));

    const http_vx::Field *p = f.find(FieldId::SetCookie);
    check(p != nullptr && p->name_off == 1, "the first repetition is not the first");
    p = f.find_next(p);
    check(p != nullptr && p->name_off == 3, "the second repetition is missing");
    p = f.find_next(p);
    check(p != nullptr && p->name_off == 4, "the third repetition is missing");
    check(f.find_next(p) == nullptr, "there is a fourth repetition that was never added");

    /* \~english
     * And the one that appears once has no next: the walk must stop at the end
     * of the array and not read past it.
     * \~spanish
     * Y la que aparece una vez no tiene siguiente: el recorrido tiene que
     * pararse al final del array y no leer mas alla.
     * \~ */
    const http_vx::Field *host = f.find(FieldId::Host);
    check(host != nullptr && f.find_next(host) == nullptr,
          "a field that appears once has a next one");
}

/**
 * @brief
 * \~english A field from elsewhere is refused instead of walking foreign memory.
 * \~spanish Una cabecera ajena se rechaza en vez de recorrer memoria de otro.
 * \~
 */
void test_foreign_field() {
    using http_vx::FieldId;
    http_vx::Fields a;
    http_vx::Fields b;
    a.add(make(FieldId::Host, 1));
    b.add(make(FieldId::Host, 2));

    const http_vx::Field *from_b = b.find(FieldId::Host);
    check(a.find_next(from_b) == nullptr,
          "a field from another collection was accepted");
    check(a.find_next(nullptr) == nullptr, "a null field was accepted");
}

/**
 * @brief
 * \~english Reuse empties the mask too.
 * \~spanish La reutilizacion vacia tambien la mascara.
 * \~
 *
 * \~english
 * This is the one that matters.  A connection serves message after message on
 * the same collection, so a mask that survives the clear would report the
 * previous message's fields on the next one -- and `find` would return null
 * for something it just said was there, which is a contradiction nobody is
 * looking for.
 *
 * \~spanish
 * Esta es la que importa.  Una conexion sirve mensaje tras mensaje sobre la
 * misma coleccion, asi que una mascara que sobreviviera al vaciado informaria
 * de las cabeceras del mensaje anterior en el siguiente -- y `find` devolveria
 * nulo para algo que acaba de decir que estaba, que es una contradiccion que
 * nadie va buscando.
 *
 * \~
 */
void test_clear_resets_the_mask() {
    using http_vx::FieldId;
    http_vx::Fields f;
    f.add(make(FieldId::Host, 1));
    f.add(make(FieldId::Authorization, 2));
    check(f.has(FieldId::Authorization), "it was not recorded");

    f.clear();

    check(f.empty(), "clearing left fields behind");
    check(!f.has(FieldId::Host), "the mask survived the clear");
    check(!f.has(FieldId::Authorization),
          "the mask survived the clear for the second one");
    check(f.find(FieldId::Host) == nullptr, "find answers after a clear");

    /* \~english
     * And it serves again afterwards: clearing is for reusing, not for
     * retiring the collection.
     * \~spanish
     * Y vuelve a servir despues: vaciar es para reutilizar, no para retirar la
     * coleccion.
     * \~ */
    f.add(make(FieldId::Accept, 9));
    check(f.has(FieldId::Accept) && f.size() == 1,
          "the collection does not serve again after a clear");
    check(!f.has(FieldId::Host), "the previous message leaked into this one");
}

/**
 * @brief
 * \~english Past the inline room it keeps working, and keeps its answers.
 * \~spanish Pasado el sitio de dentro sigue funcionando, y sigue acertando.
 * \~
 *
 * \~english
 * Growing moves the array, so anything that had kept a pointer into it would
 * now be reading elsewhere.  What is checked is that the collection's own
 * answers survive the move: a field recorded before growing is still found
 * after it.
 *
 * \~spanish
 * Crecer mueve el array, asi que lo que hubiera guardado un puntero dentro
 * estaria leyendo en otro sitio.  Lo que se comprueba es que las respuestas de
 * la propia coleccion sobreviven al movimiento: una cabecera anotada antes de
 * crecer se sigue encontrando despues.
 *
 * \~
 */
void test_overflow() {
    using http_vx::FieldId;
    http_vx::Fields f;
    f.add(make(FieldId::Host, 7));

    const size_t many = http_vx::kInlineFields * 3;
    for (size_t i = 0; i < many; ++i)
        f.add(make(FieldId::Unknown, static_cast<uint32_t>(100 + i)));

    check(f.size() == many + 1, "fields were lost while growing");
    const http_vx::Field *host = f.find(FieldId::Host);
    check(host != nullptr && host->name_off == 7,
          "the field recorded before growing did not survive");

    /* \~english
     * `Unknown` takes no bit, so a collection full of unrecognised names must
     * not claim to hold a known one.
     * \~spanish
     * `Unknown` no ocupa bit, asi que una coleccion llena de nombres sin
     * reconocer no debe decir que tiene uno conocido.
     * \~ */
    check(!f.has(FieldId::Accept), "unknown fields lit a known bit");
}

} // namespace

int main() {
    test_add_and_find();
    test_repeated();
    test_foreign_field();
    test_clear_resets_the_mask();
    test_overflow();

    if (failures != 0) {
        std::fprintf(stderr, "test_fields: %d failures\n", failures);
        return 1;
    }
    std::printf("test_fields: ok\n");
    return 0;
}
