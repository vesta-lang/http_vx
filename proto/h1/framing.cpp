/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/framing.cpp
 * @brief
 * \~english Reading the transfer codings, and deciding where the body ends.
 * \~spanish Leer las codificaciones de transferencia, y decidir donde acaba el cuerpo.
 * \~
 */

#include "http_vx/h1_framing.h"

#include "http_vx/chars.h"
#include "http_vx/content_length.h"

namespace http_vx {
namespace h1 {
namespace {

/**
 * @brief
 * \~english Whether the coding named in @p p is `chunked`.
 * \~spanish Si la codificacion nombrada en @p p es `chunked`.
 * \~
 *
 * \~english
 * There is one name worth recognising and this is it.  `chunked` is the only
 * coding that changes where the body ends; every other one -- `gzip`,
 * something nobody registered, a typo -- ends the same way, as a request this
 * server cannot apply, answered 501.  A table of the compressing codings would
 * let this file distinguish names it then treats identically.
 *
 * Case does not matter, unlike in a method: RFC 9110 section 10.1.4 compares
 * transfer codings without regard to it, so `Chunked` is the same coding.
 * Missing that would read a perfectly valid request as one using a coding
 * nobody implements.
 *
 * \~spanish
 * Hay un nombre que merece reconocerse y es este.  `chunked` es la unica
 * codificacion que cambia donde acaba el cuerpo; cualquier otra -- `gzip`, algo
 * que nadie registro, una errata -- acaba igual, como una peticion que este
 * servidor no puede aplicar, contestada con 501.  Una tabla de las
 * codificaciones que comprimen dejaria que este fichero distinguiera nombres
 * que luego trata igual.
 *
 * Las mayusculas dan igual, al reves que en un metodo: el RFC 9110 seccion
 * 10.1.4 compara las codificaciones de transferencia sin atender a ellas, asi
 * que `Chunked` es la misma.  No verlo leeria una peticion perfectamente valida
 * como una que usa una codificacion que nadie implementa.
 *
 * \~
 */
bool is_chunked(const uint8_t *p, size_t len) noexcept { return token_equals(p, len, "chunked"); }

/**
 * @brief
 * \~english What walking the transfer encodings found.
 * \~spanish Que se encontro al recorrer las codificaciones de transferencia.
 * \~
 */
struct Codings {
    bool present;
    bool malformed;
    uint32_t count;
    uint32_t chunked_count;
    bool last_is_chunked;
};

/**
 * @brief
 * \~english Walks every transfer coding of the message, in order.
 * \~spanish Recorre todas las codificaciones de transferencia del mensaje, en orden.
 * \~
 *
 * \~english
 * In order and all of them, because the rule is about the LAST one and about
 * how many times `chunked` appears.  Reading only the first field, or only the
 * last coding of it, would answer both questions from a part of the list --
 * and a list is exactly where a sender puts the part it wants each recipient
 * to read.
 *
 * \~spanish
 * En orden y todas, porque la regla habla de la ULTIMA y de cuantas veces
 * aparece `chunked`.  Leer solo la primera cabecera, o solo la ultima
 * codificacion de ella, contestaria las dos preguntas desde un trozo de la
 * lista -- y una lista es justo donde quien envia pone el trozo que quiere que
 * lea cada receptor.
 *
 * \~
 */
Codings walk_codings(const Fields &fields, const uint8_t *base) noexcept {
    Codings out{};
    const Field *f = fields.find(FieldId::TransferEncoding);
    if (f == nullptr) return out;
    out.present = true;

    for (; f != nullptr; f = fields.find_next(f)) {
        ListReader list(base + f->value_off, f->value_len);
        ListItem item;
        while (list.next(item)) {
            const uint8_t *p = item.p;
            const size_t len = item.len;

            /* \~english
             * A coding may carry parameters after a semicolon.  They do not
             * change which coding it is, so the name ends there.
             * \~spanish
             * Una codificacion puede llevar parametros tras un punto y coma.
             * No cambian cual es, asi que el nombre acaba ahi.
             * \~ */
            size_t name_len = 0;
            while (name_len < len && p[name_len] != ';') ++name_len;
            while (name_len != 0 && is_ows(p[name_len - 1])) --name_len;

            if (name_len == 0) {
                /* \~english
                 * An empty element.  RFC 9110 tolerates one in a general list,
                 * and here it is refused: this list decides where the body
                 * ends, and a hole in it is what a value looks like after
                 * somebody removed a coding the next recipient will still see.
                 * \~spanish
                 * Un elemento vacio.  El RFC 9110 tolera uno en una lista
                 * general, y aqui se rechaza: esta lista decide donde acaba el
                 * cuerpo, y un hueco es lo que parece un valor despues de que
                 * alguien quitara una codificacion que el receptor siguiente si
                 * va a ver.
                 * \~ */
                out.malformed = true;
            } else if (!token_is_valid(reinterpret_cast<const char *>(p),
                                       name_len)) {
                out.malformed = true;
            } else {
                const bool chunked = is_chunked(p, name_len);
                ++out.count;
                out.last_is_chunked = chunked;
                if (chunked) ++out.chunked_count;
            }
        }
    }
    return out;
}

} // namespace

bool connection_persists(const Request &req, const uint8_t *base) noexcept {
    bool close = false;
    bool keep_alive = false;
    for (const Field *f = req.fields.find(FieldId::Connection); f != nullptr; f = req.fields.find_next(f)) {
        ListReader list(base + f->value_off, f->value_len);
        ListItem item;
        while (list.next(item)) {
            if (token_equals(item.p, item.len, "close")) close = true;
            if (token_equals(item.p, item.len, "keep-alive")) keep_alive = true;
        }
    }
    if (close) return false;
    if (req.version == Version::Http10) return keep_alive;
    return true;
}

StatusCode framing_status(FramingError e) noexcept {
    switch (e) {
    case FramingError::None:
        return 0;
    case FramingError::LengthTooLarge:
        return status::kContentTooLarge;
    case FramingError::UnsupportedCoding:
        return status::kNotImplemented;
    default:
        return status::kBadRequest;
    }
}

Framing frame_request_body(const Request &req, const uint8_t *base) noexcept {
    const Codings codings = walk_codings(req.fields, base);
    const ContentLength cl = parse_content_length(req.fields, base);

    /* \~english
     * Both at once, first and before anything else is judged.  It comes first
     * because it is the only failure here that is not about the message being
     * malformed: each half is fine on its own, and what is wrong is having
     * both -- which is why a specification that said "the encoding wins" left
     * a decade of software agreeing to disagree.
     *
     * \~spanish
     * Las dos a la vez, lo primero y antes de juzgar nada mas.  Va primero
     * porque es el unico fallo de aqui que no es que el mensaje este mal
     * formado: cada mitad esta bien por su cuenta, y lo que esta mal es tener
     * las dos -- que es la razon de que una especificacion que decia "gana la
     * codificacion" dejara una decada de programas de acuerdo en discrepar.
     * \~ */
    if (codings.present && cl.status != ContentLengthStatus::Absent)
        return Framing{BodyKind::None, 0, FramingError::LengthAndEncoding};

    if (codings.present) {
        /* \~english
         * Chunked did not exist in HTTP/1.0, so a client announcing that
         * version and using it is saying one thing and doing another.  The
         * pair is a known way of getting an old intermediary and a new one to
         * read the same bytes as different messages.
         * \~spanish
         * El troceado no existia en HTTP/1.0, asi que un cliente que anuncie
         * esa version y lo use esta diciendo una cosa y haciendo otra.  El par
         * es una forma conocida de hacer que un intermediario viejo y uno nuevo
         * lean los mismos bytes como mensajes distintos.
         * \~ */
        if (req.version == Version::Http10)
            return Framing{BodyKind::None, 0, FramingError::EncodingInHttp10};

        if (codings.malformed || codings.count == 0)
            return Framing{BodyKind::None, 0, FramingError::ChunkedNotLast};

        if (codings.chunked_count > 1)
            return Framing{BodyKind::None, 0, FramingError::ChunkedTwice};

        /* \~english
         * `chunked` last is what makes the end findable, so it is checked
         * before complaining about a coding that cannot be applied: a request
         * that is unframeable is unframeable whether or not this server could
         * have decompressed it.
         * \~spanish
         * Que `chunked` sea la ultima es lo que hace que el final se pueda
         * encontrar, asi que se comprueba antes de quejarse de una codificacion
         * que no se puede aplicar: una peticion sin frontera no la tiene
         * pudiera o no este servidor descomprimirla.
         * \~ */
        if (!codings.last_is_chunked)
            return Framing{BodyKind::None, 0, FramingError::ChunkedNotLast};

        /* \~english
         * And anything applied under it is something this server would have to
         * undo -- decompress, most likely -- and does not.  It is 501 and not
         * 400: the message is well formed and the one that cannot is here.
         * \~spanish
         * Y cualquier cosa aplicada por debajo es algo que este servidor
         * tendria que deshacer -- descomprimir, lo mas probable -- y no hace.
         * Es 501 y no 400: el mensaje esta bien formado y el que no puede esta
         * aqui.
         * \~ */
        if (codings.count != codings.chunked_count)
            return Framing{BodyKind::None, 0, FramingError::UnsupportedCoding};

        return Framing{BodyKind::Chunked, 0, FramingError::None};
    }

    switch (cl.status) {
    case ContentLengthStatus::Present:
        return Framing{BodyKind::Exact, cl.value, FramingError::None};
    case ContentLengthStatus::Conflicting:
        return Framing{BodyKind::None, 0, FramingError::ConflictingLength};
    case ContentLengthStatus::Malformed:
        return Framing{BodyKind::None, 0, FramingError::MalformedLength};
    case ContentLengthStatus::TooLarge:
        return Framing{BodyKind::None, 0, FramingError::LengthTooLarge};
    case ContentLengthStatus::Absent:
        break;
    }

    /* \~english
     * Neither.  A request with no framing has no body -- not a body that runs
     * until the connection closes, which is what a RESPONSE without framing
     * means.  Getting the two the same way round is not a detail: a server
     * that waited for a close on a `POST` with no length would hang on a
     * message that was already complete, and one that did not wait on a
     * response would truncate one that was not.
     *
     * \~spanish
     * Ninguna.  Una peticion sin troceado no tiene cuerpo -- no un cuerpo que
     * corre hasta que se cierre la conexion, que es lo que quiere decir una
     * RESPUESTA sin troceado --.  Que los dos vayan en sentidos distintos no es
     * un detalle: un servidor que esperara un cierre en un `POST` sin longitud
     * se colgaria en un mensaje que ya estaba completo, y uno que no esperara
     * en una respuesta truncaria una que no lo estaba.
     * \~ */
    return Framing{BodyKind::None, 0, FramingError::None};
}

} // namespace h1
} // namespace http_vx
