/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/message.cpp
 * @brief
 * \~english Emptying a message for the next one, and naming a version.
 * \~spanish Vaciar un mensaje para el siguiente, y nombrar una version.
 * \~
 */

#include "http_vx/message.h"

namespace http_vx {
namespace {

constexpr Span kNowhere = {0, 0};

/**
 * @brief
 * \~english The wire spelling of each version, indexed by the enum.
 * \~spanish La grafia en el cable de cada version, indexada por la enumeracion.
 * \~
 *
 * \~english
 * The two that are not written have an empty row rather than being left out.
 * An entry for every value is what makes the lookup an index instead of a
 * search, and it makes adding a version a compiler error here rather than a
 * silent gap.
 *
 * \~spanish
 * Las dos que no se escriben tienen fila vacia en vez de quedarse fuera.  Una
 * entrada por valor es lo que hace que la busqueda sea un indice y no un
 * recorrido, y hace que anadir una version sea un error del compilador aqui y
 * no un hueco mudo.
 *
 * \~
 */
constexpr const char *kVersionText[] = {
    "",         // Unknown
    "HTTP/1.0", // Http10
    "HTTP/1.1", // Http11
    "",         // Http2, announced by the connection and not by the message
    "",         // Http3, likewise
};

constexpr size_t kVersionCount = sizeof(kVersionText) / sizeof(kVersionText[0]);

static_assert(kVersionCount == static_cast<size_t>(Version::Http3) + 1,
              "the version table needs one row per Version, in the same order");

} // namespace

void Request::clear() noexcept {
    method = MethodId::Unknown;
    method_text = kNowhere;
    target = kNowhere;
    authority = kNowhere;
    scheme = kNowhere;
    version = Version::Unknown;
    fields.clear();
}

void Response::clear() noexcept {
    status = 0;
    version = Version::Unknown;
    fields.clear();
}

const char *version_text(Version v) noexcept {
    const size_t i = static_cast<size_t>(v);
    if (i >= kVersionCount) return "";
    return kVersionText[i];
}

} // namespace http_vx
