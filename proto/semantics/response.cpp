/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/response.cpp
 * @brief
 * \~english Collecting an answer, in no version of the protocol.
 * \~spanish Recoger una respuesta, en ninguna version del protocolo.
 * \~
 */

#include "http_vx/response.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

bool ResponseBuilder::put(const void *p, size_t n, Span &where) noexcept {
    const size_t at = store_->size();

    if (n != 0) {
        uint8_t *room = store_->reserve(n);
        if (room == nullptr) {
            failed_ = true;
            return false;
        }
        util::vesta_memcpy(room, p, n);
        store_->commit(n);
    }

    where = Span{static_cast<uint32_t>(at), static_cast<uint32_t>(n)};
    return true;
}

bool ResponseBuilder::field(FieldId id, const char *v, size_t n) noexcept {
    /* \~english
     * A field after the body has started is refused rather than put somewhere.
     * The body is one run of bytes at the end of the store, so a field added
     * now would either land inside it or have to move it -- and a response
     * whose head is written after its body is not a response.
     * \~spanish
     * Una cabecera despues de empezar el cuerpo se rechaza en vez de ponerla en
     * algun sitio.  El cuerpo es una tirada de bytes al final del almacen, asi
     * que una cabecera anadida ahora caeria dentro de el o habria que moverlo --
     * y una respuesta cuya cabeza se escribe despues de su cuerpo no es una
     * respuesta.
     * \~ */
    if (started_body_) {
        failed_ = true;
        return false;
    }

    Span value;
    if (!put(v, n, value)) return false;

    Field f;
    f.name_off = 0;
    f.name_len = 0;
    f.value_off = value.off;
    f.value_len = static_cast<uint16_t>(value.len);
    f.id = id;
    f.reserved = 0;

    fields_.add(f);
    return true;
}

bool ResponseBuilder::field(const char *name, size_t nlen, const char *v,
                            size_t vlen) noexcept {
    if (started_body_) {
        failed_ = true;
        return false;
    }

    Span n;
    if (!put(name, nlen, n)) return false;

    Span value;
    if (!put(v, vlen, value)) return false;

    /* \~english
     * A name this project knows is stored as what it IS and not as the letters
     * that were typed.  It is the same reason the parsers do it on the way in:
     * every decision downstream -- which fields may not travel, which are
     * already in a compression table, which frame a message -- asks what a
     * field is, and a caller that spelled it out should not get a different
     * answer from one that named it.
     *
     * \~spanish
     * Un nombre que este proyecto conoce se guarda como lo que ES y no como las
     * letras que se escribieron.  Es la misma razon por la que lo hacen los
     * analizadores a la entrada: todas las decisiones de despues -- que
     * cabeceras no pueden viajar, cuales estan ya en una tabla de compresion,
     * cuales trocean un mensaje -- preguntan que ES una cabecera, y quien la
     * deletree no deberia recibir otra respuesta que quien la nombre.
     * \~ */
    const FieldId id = field_id_of(name, nlen);

    Field f;
    f.name_off = n.off;
    f.name_len = static_cast<uint16_t>(n.len);
    f.value_off = value.off;
    f.value_len = static_cast<uint16_t>(value.len);
    f.id = id;
    f.reserved = 0;

    fields_.add(f);
    return true;
}

bool ResponseBuilder::body(const void *p, size_t n) noexcept {
    if (n == 0) return true;

    const size_t at = store_->size();

    uint8_t *room = store_->reserve(n);
    if (room == nullptr) {
        failed_ = true;
        return false;
    }
    util::vesta_memcpy(room, p, n);
    store_->commit(n);

    /* \~english
     * The pieces join, so a body written in parts is one span.  The first
     * piece decides where it starts and every one after it only makes it
     * longer -- which works because nothing else may be added once it has
     * begun, so the bytes cannot be interrupted by anything.
     * \~spanish
     * Los pedazos se juntan, asi que un cuerpo escrito a trozos es un solo
     * trozo.  El primer pedazo decide donde empieza y todos los de detras solo
     * lo alargan -- que funciona porque una vez empezado no se puede anadir nada
     * mas, asi que los bytes no los puede interrumpir nada.
     * \~ */
    if (!started_body_) {
        started_body_ = true;
        body_ = Span{static_cast<uint32_t>(at), static_cast<uint32_t>(n)};
    } else {
        body_.len += static_cast<uint32_t>(n);
    }

    return true;
}

OpenResponse ResponseBuilder::open(BodySource &s) noexcept {
    /* \~english
     * Once.  A second source would be a second body for one response, and the
     * first is already the port's -- so the second is refused and never used.
     * \~spanish
     * Una vez.  Una segunda fuente seria un segundo cuerpo para una respuesta, y
     * la primera ya es de la puerta -- asi que la segunda se rechaza y no se usa.
     * \~ */
    if (port_ == nullptr || source_ != nullptr || open_refused_) return OpenResponse();

    const OpenResponse r = port_->open(conn_, stream_, s, *target_);
    if (!r.valid()) {
        open_refused_ = true;
        return r;
    }

    source_ = &s;
    opened_ = r;
    return r;
}

} // namespace http_vx
