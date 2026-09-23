/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/fields.cpp
 * @brief
 * \~english The field collection: recording, asking and reusing.
 * \~spanish La coleccion de cabeceras: anotar, preguntar y reutilizar.
 * \~
 */

#include "http_vx/fields.h"

#include "util/alloc/alloc_tag.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english The bit that stands for @p id in the mask.
 * \~spanish El bit que representa a @p id en la mascara.
 * \~
 *
 * \~english
 * @c Unknown gets no bit, and that is the point: it is not one name but every
 * name nobody had to recognise, so "is there an unknown field" is not a
 * question anyone asks -- and answering it with a bit would suggest otherwise.
 *
 * \~spanish
 * @c Unknown no tiene bit, y eso es lo que se quiere decir: no es un nombre
 * sino todos los que nadie tuvo que reconocer, asi que "hay alguna cabecera
 * desconocida" no es una pregunta que nadie haga -- y contestarla con un bit
 * sugeriria lo contrario.
 *
 * \~
 */
constexpr uint64_t bit_of(FieldId id) noexcept {
    return id == FieldId::Unknown
               ? uint64_t{0}
               : uint64_t{1} << static_cast<unsigned>(id);
}

} // namespace

void Fields::add(const Field &f) {
    /* \~english
     * What overflows the inline room lives as long as the message -- one
     * phase -- and grows as headers keep arriving.  Saying so is what lets the
     * allocator serve it from the path meant for that instead of the general
     * one, and it costs a declaration.
     *
     * \~spanish
     * Lo que desborde el sitio de dentro vive lo que el mensaje -- una fase --
     * y crece segun siguen llegando cabeceras.  Decirlo es lo que permite al
     * asignador servirlo por el camino pensado para eso en vez de por el
     * general, y cuesta una declaracion.
     * \~ */
    const util::AllocScope scope(util::AllocUse::Medium,
                                 util::AllocShape::Growing);
    v_.push_back(f);
    known_ |= bit_of(f.id);
}

bool Fields::has(FieldId id) const noexcept {
    return (known_ & bit_of(id)) != 0;
}

const Field *Fields::find(FieldId id) const noexcept {
    /* \~english
     * The mask first.  Asking for something absent -- which is most of the
     * asking -- ends here without reading the array.
     *
     * \~spanish
     * La mascara primero.  Preguntar por algo que no esta -- que es la mayoria
     * de las preguntas -- termina aqui sin leer el array.
     * \~ */
    if (!has(id)) return nullptr;
    for (const Field &f : v_)
        if (f.id == id) return &f;
    return nullptr;
}

const Field *Fields::find_next(const Field *from) const noexcept {
    if (from == nullptr) return nullptr;
    const Field *const last = end();
    /* \~english
     * A field from another collection would walk memory that is not this one's
     * and answer something plausible.  It is cheap to notice and silent if not
     * noticed, which is the combination that earns a check.
     *
     * \~spanish
     * Una cabecera de otra coleccion recorreria memoria que no es de esta y
     * contestaria algo plausible.  Es barato de notar y mudo si no se nota,
     * que es la combinacion que se gana una comprobacion.
     * \~ */
    if (from < begin() || from >= last) return nullptr;

    for (const Field *p = from + 1; p != last; ++p)
        if (p->id == from->id) return p;
    return nullptr;
}

void Fields::clear() noexcept {
    v_.clear();
    known_ = 0;
}

} // namespace http_vx
