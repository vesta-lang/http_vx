/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/hpack.cpp
 * @brief
 * \~english Reading and writing HPACK's numbers, and the static table.
 * \~spanish Leer y escribir los numeros de HPACK, y la tabla estatica.
 * \~
 */

#include "http_vx/h2_hpack.h"

namespace http_vx {
namespace h2 {
namespace hpack {
namespace {

/**
 * @brief
 * \~english Builds an entry, measuring both literals at compile time.
 * \~spanish Construye una entrada, midiendo los dos literales al compilar.
 * \~
 */
template <size_t N, size_t M>
constexpr StaticEntry row(const char (&name)[N], const char (&value)[M],
                          FieldId id, Pseudo pseudo = Pseudo::None) {
    return StaticEntry{name,
                       value,
                       static_cast<uint16_t>(N - 1),
                       static_cast<uint16_t>(M - 1),
                       id,
                       pseudo};
}

/**
 * @brief
 * \~english The static table, RFC 7541 appendix A, in its own order.
 * \~spanish La tabla estatica, RFC 7541 apendice A, en su propio orden.
 * \~
 *
 * \~english
 * The order is the specification's and is not ours to improve.  Both ends
 * count indices from it, and an entry moved is every index after it pointing
 * at the wrong field -- silently, because the block still decodes.
 *
 * The identifier in each row is written out rather than looked up, and a test
 * checks every one of them against @c field_id_of.  That is the second opinion
 * the table needs: written by hand it can be wrong, and derived from the other
 * table it could not be checked against it.
 *
 * \~spanish
 * El orden es el de la especificacion y no es nuestro para mejorarlo.  Los dos
 * extremos cuentan indices a partir de ella, y una entrada movida son todos los
 * indices posteriores apuntando a la cabecera equivocada -- en silencio, porque
 * el bloque se sigue descodificando.
 *
 * El identificador de cada fila se escribe y no se busca, y una prueba comprueba
 * todos contra @c field_id_of.  Esa es la segunda opinion que necesita la
 * tabla: escrita a mano puede estar mal, y derivada de la otra tabla no se
 * podria comprobar contra ella.
 *
 * \~
 */
constexpr StaticEntry kStatic[] = {
    // 1-7: lo que HTTP/1.1 escribia en la linea de peticion.
    row(":authority", "", FieldId::Unknown, Pseudo::Authority),
    row(":method", "GET", FieldId::Unknown, Pseudo::Method),
    row(":method", "POST", FieldId::Unknown, Pseudo::Method),
    row(":path", "/", FieldId::Unknown, Pseudo::Path),
    row(":path", "/index.html", FieldId::Unknown, Pseudo::Path),
    row(":scheme", "http", FieldId::Unknown, Pseudo::Scheme),
    row(":scheme", "https", FieldId::Unknown, Pseudo::Scheme),

    // 8-14: y lo que escribia en la linea de estado.
    row(":status", "200", FieldId::Unknown, Pseudo::Status),
    row(":status", "204", FieldId::Unknown, Pseudo::Status),
    row(":status", "206", FieldId::Unknown, Pseudo::Status),
    row(":status", "304", FieldId::Unknown, Pseudo::Status),
    row(":status", "400", FieldId::Unknown, Pseudo::Status),
    row(":status", "404", FieldId::Unknown, Pseudo::Status),
    row(":status", "500", FieldId::Unknown, Pseudo::Status),

    // 15-61: cabeceras corrientes, casi todas sin valor.
    row("accept-charset", "", FieldId::Unknown),
    row("accept-encoding", "gzip, deflate", FieldId::AcceptEncoding),
    row("accept-language", "", FieldId::AcceptLanguage),
    row("accept-ranges", "", FieldId::AcceptRanges),
    row("accept", "", FieldId::Accept),
    row("access-control-allow-origin", "", FieldId::Unknown),
    row("age", "", FieldId::Age),
    row("allow", "", FieldId::Allow),
    row("authorization", "", FieldId::Authorization),
    row("cache-control", "", FieldId::CacheControl),
    row("content-disposition", "", FieldId::ContentDisposition),
    row("content-encoding", "", FieldId::ContentEncoding),
    row("content-language", "", FieldId::ContentLanguage),
    row("content-length", "", FieldId::ContentLength),
    row("content-location", "", FieldId::Unknown),
    row("content-range", "", FieldId::ContentRange),
    row("content-type", "", FieldId::ContentType),
    row("cookie", "", FieldId::Cookie),
    row("date", "", FieldId::Date),
    row("etag", "", FieldId::ETag),
    row("expect", "", FieldId::Expect),
    row("expires", "", FieldId::Expires),
    row("from", "", FieldId::Unknown),
    row("host", "", FieldId::Host),
    row("if-match", "", FieldId::IfMatch),
    row("if-modified-since", "", FieldId::IfModifiedSince),
    row("if-none-match", "", FieldId::IfNoneMatch),
    row("if-range", "", FieldId::IfRange),
    row("if-unmodified-since", "", FieldId::IfUnmodifiedSince),
    row("last-modified", "", FieldId::LastModified),
    row("link", "", FieldId::Unknown),
    row("location", "", FieldId::Location),
    row("max-forwards", "", FieldId::Unknown),
    row("proxy-authenticate", "", FieldId::Unknown),
    row("proxy-authorization", "", FieldId::ProxyAuthorization),
    row("range", "", FieldId::Range),
    row("referer", "", FieldId::Referer),
    row("refresh", "", FieldId::Unknown),
    row("retry-after", "", FieldId::RetryAfter),
    row("server", "", FieldId::Server),
    row("set-cookie", "", FieldId::SetCookie),
    row("strict-transport-security", "", FieldId::Unknown),
    row("transfer-encoding", "", FieldId::TransferEncoding),
    row("user-agent", "", FieldId::UserAgent),
    row("vary", "", FieldId::Vary),
    row("via", "", FieldId::Unknown),
    row("www-authenticate", "", FieldId::WWWAuthenticate),
};

static_assert(sizeof(kStatic) / sizeof(kStatic[0]) == kStaticEntries,
              "the static table must have exactly the sixty-one entries the "
              "specification fixes: both ends count dynamic indices from it");

} // namespace

const StaticEntry *static_entry(uint64_t index) noexcept {
    /* \~english
     * Zero is refused rather than read as the first entry.  It is the one
     * index a block may not use, and an implementation that let it through by
     * indexing an array from zero would resolve every index in that block one
     * place out -- decoding a message that is not the one that was sent.
     *
     * \~spanish
     * El cero se rechaza en vez de leerlo como la primera entrada.  Es el unico
     * indice que un bloque no puede usar, y una implementacion que lo dejara
     * pasar indexando un array desde cero resolveria todos los indices de ese
     * bloque con un sitio de diferencia -- descodificando un mensaje que no es
     * el que se mando.
     * \~ */
    if (index == 0 || index > kStaticEntries) return nullptr;
    return &kStatic[index - 1];
}

IntResult decode_int(const uint8_t *p, size_t n, uint8_t prefix_bits) noexcept {
    /* \~english
     * A prefix outside one to eight is not a header block this could be about,
     * it is a mistake in the code above.  It is refused rather than worked
     * around, because the useful thing to do with an impossible argument is to
     * make the call that passed it fail.
     *
     * \~spanish
     * Un prefijo fuera de uno a ocho no es un bloque de cabeceras del que esto
     * pueda hablar, es una equivocacion del codigo de arriba.  Se rechaza en
     * vez de arreglarlo, porque lo util que hacer con un argumento imposible es
     * que falle la llamada que lo paso.
     * \~ */
    if (prefix_bits == 0 || prefix_bits > 8)
        return IntResult{Status::Malformed, 0, 0};

    if (p == nullptr || n == 0) return IntResult{Status::Truncated, 0, 0};

    const uint64_t mask = (uint64_t{1} << prefix_bits) - 1;
    uint64_t value = p[0] & mask;

    /* \~english
     * Under the mask it is the whole number, and there is nothing behind it.
     * This is the common case by a long way: an index into the static table,
     * a string of fewer than a hundred and twenty-seven bytes.
     *
     * \~spanish
     * Por debajo de la mascara es el numero entero y no hay nada detras.  Es el
     * caso corriente con mucho: un indice de la tabla estatica, una cadena de
     * menos de ciento veintisiete bytes.
     * \~ */
    if (value < mask) return IntResult{Status::Ok, value, 1};

    size_t used = 1;
    unsigned shift = 0;

    for (;;) {
        if (used == n) return IntResult{Status::Truncated, 0, 0};

        /* \~english
         * The byte cap is checked before the byte is read, not after the value
         * grows.  A sender writing `0x80` over and over adds nothing to the
         * value each time, so a check on the value alone would never fire --
         * it would just keep reading.
         *
         * \~spanish
         * El tope de bytes se comprueba antes de leer el byte, no despues de
         * que crezca el valor.  Quien escriba `0x80` una y otra vez no anade
         * nada al valor cada vez, asi que una comprobacion solo sobre el valor
         * no saltaria nunca -- seguiria leyendo.
         * \~ */
        if (used > kMaxIntBytes) return IntResult{Status::TooLarge, 0, 0};

        const uint8_t b = p[used];
        ++used;

        const uint64_t add = static_cast<uint64_t>(b & 0x7F) << shift;

        /* \~english
         * And the value, before it is added rather than after.  Adding first
         * and noticing afterwards is noticing an overflow that already
         * happened, and what it leaves behind is a number the sender chose.
         *
         * \~spanish
         * Y el valor, antes de sumar y no despues.  Sumar primero y darse
         * cuenta luego es darse cuenta de un desbordamiento que ya ocurrio, y
         * lo que deja detras es un numero que eligio quien envia.
         * \~ */
        if (shift >= 32 || add > kMaxInt - value)
            return IntResult{Status::TooLarge, 0, 0};

        value += add;
        shift += 7;

        if ((b & 0x80) == 0) break;
    }

    if (value > kMaxInt) return IntResult{Status::TooLarge, 0, 0};
    return IntResult{Status::Ok, value, used};
}

size_t encode_int(uint8_t *out, uint64_t value, uint8_t prefix_bits,
                  uint8_t keep) noexcept {
    const uint64_t mask = (uint64_t{1} << prefix_bits) - 1;

    if (value < mask) {
        out[0] = static_cast<uint8_t>(keep | value);
        return 1;
    }

    out[0] = static_cast<uint8_t>(keep | mask);
    value -= mask;

    size_t used = 1;
    while (value >= 0x80) {
        out[used++] = static_cast<uint8_t>((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out[used++] = static_cast<uint8_t>(value);
    return used;
}

} // namespace hpack
} // namespace h2
} // namespace http_vx
