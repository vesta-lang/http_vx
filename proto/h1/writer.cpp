/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/writer.cpp
 * @brief
 * \~english Building a response head, byte by byte and checked as it goes.
 * \~spanish Construir la cabeza de una respuesta, byte a byte y comprobada.
 * \~
 */

#include "http_vx/h1_writer.h"

#include "http_vx/chars.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h1 {

const uint8_t kChunkEnd[2] = {'\r', '\n'};
const uint8_t kLastChunk[5] = {'0', '\r', '\n', '\r', '\n'};

namespace {

constexpr char kColonSpace[] = ": ";
constexpr char kCrLf[] = "\r\n";

/**
 * @brief
 * \~english Whether the application may write @p id itself.
 * \~spanish Si la aplicacion puede escribir @p id por su cuenta.
 * \~
 *
 * \~english
 * Two fields, and the reason is the same one that runs through the whole
 * codec: a message must say each thing once.  Where the response ends is
 * settled at @c finish, from what the body is declared to be, and a second
 * answer written by hand is a second answer -- which is what the reader spends
 * its time refusing on the way in.
 *
 * \~spanish
 * Dos cabeceras, y la razon es la misma que recorre el codec entero: un mensaje
 * tiene que decir cada cosa una vez.  Donde acaba la respuesta se resuelve en
 * @c finish, de lo que se declare que es el cuerpo, y una segunda respuesta
 * escrita a mano es una segunda respuesta -- que es lo que el lector se pasa la
 * vida rechazando a la entrada.
 *
 * \~
 */
inline bool is_framing_field(FieldId id) noexcept {
    return id == FieldId::ContentLength || id == FieldId::TransferEncoding;
}

/**
 * @brief
 * \~english Writes @p v as decimal into @p out, backwards then reversed.
 * \~spanish Escribe @p v en decimal en @p out, al reves y luego dado la vuelta.
 * \~
 *
 * \~english
 * Written out rather than handed to the C library.  `snprintf` would look at
 * the locale, and a locale that groups digits would put a separator inside a
 * content length -- which is a number the peer parses, not text a person
 * reads.  It has happened, and it is the kind of bug that only appears on the
 * machines configured a certain way.
 *
 * \~spanish
 * Escrito a mano y no entregado a la biblioteca de C.  `snprintf` miraria la
 * configuracion regional, y una que agrupe digitos pondria un separador dentro
 * de una longitud de contenido -- que es un numero que analiza el otro extremo,
 * no texto que lea una persona --.  Ha pasado, y es de los errores que solo
 * aparecen en las maquinas configuradas de cierta forma.
 *
 * \~
 */
size_t decimal(uint8_t *out, uint64_t v) noexcept {
    uint8_t tmp[20];
    size_t n = 0;
    do {
        tmp[n++] = static_cast<uint8_t>('0' + (v % 10));
        v /= 10;
    } while (v != 0);

    for (size_t i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    return n;
}

} // namespace

size_t write_chunk_header(uint8_t *out, uint64_t size) noexcept {
    static const char kHex[] = "0123456789abcdef";

    uint8_t tmp[16];
    size_t n = 0;
    do {
        tmp[n++] = static_cast<uint8_t>(kHex[size & 0xF]);
        size >>= 4;
    } while (size != 0);

    for (size_t i = 0; i < n; ++i) out[i] = tmp[n - 1 - i];
    out[n] = '\r';
    out[n + 1] = '\n';
    return n + 2;
}

WriteError ResponseWriter::fail(WriteError e) noexcept {
    state_ = State::Failed;
    return e;
}

bool ResponseWriter::put(const void *p, size_t n) noexcept {
    if (n == 0) return true;
    uint8_t *room = out_.reserve(n);
    if (room == nullptr) return false;
    util::vesta_memcpy(room, p, n);
    out_.commit(n);
    return true;
}

bool ResponseWriter::put_u64(uint64_t v) noexcept {
    uint8_t digits[20];
    const size_t n = decimal(digits, v);
    return put(digits, n);
}

bool ResponseWriter::put_name(FieldId id) noexcept {
    /* \~english
     * The writer's own fields are spelled from the same table as the
     * application's, and not from a literal here.  A literal would be the
     * second spelling this file has just refused to have -- and it would show
     * up as a response where the framing fields are capitalised and the rest
     * are not, which is the sort of difference that gets noticed by whoever is
     * debugging something else.
     *
     * \~spanish
     * Las cabeceras propias del escritor se escriben de la misma tabla que las
     * de la aplicacion, y no de un literal aqui.  Un literal seria la segunda
     * grafia que este fichero acaba de negarse a tener -- y apareceria como una
     * respuesta en la que las cabeceras de troceado van capitalizadas y las
     * demas no, que es de las diferencias que descubre quien esta depurando
     * otra cosa.
     * \~ */
    return put(field_name(id), field_name_len(id)) && put(kColonSpace, 2);
}

bool ResponseWriter::put_own_field(FieldId id, const char *value,
                                   size_t len) noexcept {
    return put_name(id) && put(value, len) && put(kCrLf, 2);
}

void ResponseWriter::release() noexcept {
    out_.release();
    state_ = State::Fresh;
}

WriteError ResponseWriter::begin(Version version, StatusCode status,
                                 MethodId method, bool keep_alive) noexcept {
    out_.clear();
    state_ = State::Fresh;
    version_ = version;
    status_ = status;
    method_ = method;
    keep_alive_ = keep_alive;
    closes_ = !keep_alive;
    body_follows_ = false;
    chunked_ = false;
    wrote_connection_ = false;

    if (!status_is_valid(status)) return fail(WriteError::BadStatus);

    /* \~english
     * Only the text versions are written out.  Asking this writer for HTTP/2
     * is asking the wrong codec, and answering with something plausible --
     * `HTTP/1.1`, say -- would produce a response that works and is not what
     * was asked for.
     *
     * \~spanish
     * Solo se escriben las versiones de texto.  Pedirle HTTP/2 a este escritor
     * es pedirselo al codec equivocado, y contestar con algo plausible --
     * `HTTP/1.1`, por ejemplo -- produciria una respuesta que funciona y no es
     * la que se pidio.
     * \~ */
    if (!version_is_text(version)) return fail(WriteError::BadStatus);

    const char *v = version_text(version);
    const char *reason = status_reason(status);

    if (!put(v, 8)) return fail(WriteError::OutOfMemory);
    if (!put(" ", 1)) return fail(WriteError::OutOfMemory);
    if (!put_u64(status)) return fail(WriteError::OutOfMemory);
    if (!put(" ", 1)) return fail(WriteError::OutOfMemory);

    /* \~english
     * A code nobody registered has no phrase, and an empty one is legal:
     * RFC 9112 section 4 makes the phrase optional, so there is nothing to
     * make up.  Making one up would be writing this server's opinion of a
     * status the application chose.
     *
     * \~spanish
     * Un codigo que nadie registro no tiene frase, y una vacia es legal: el RFC
     * 9112 seccion 4 hace la frase opcional, asi que no hay nada que inventar.
     * Inventarla seria escribir la opinion de este servidor sobre un estado que
     * eligio la aplicacion.
     * \~ */
    if (!put(reason, status_reason_len(status)))
        return fail(WriteError::OutOfMemory);
    if (!put(kCrLf, 2)) return fail(WriteError::OutOfMemory);

    state_ = State::Fields;
    return WriteError::None;
}

WriteError ResponseWriter::field(FieldId id, const char *value,
                                 size_t len) noexcept {
    if (state_ == State::Failed) return WriteError::OutOfOrder;
    if (state_ != State::Fields) return fail(WriteError::OutOfOrder);
    if (is_framing_field(id)) return fail(WriteError::FramingIsNotYours);

    /* \~english
     * The name goes out in LOWER CASE, which is what the table holds, and that
     * is a decision rather than an oversight.
     *
     * HTTP/1.1 compares field names without regard to case, so it is legal;
     * HTTP/2 and HTTP/3 REQUIRE lower case, so it is the only spelling that
     * serves all three.  Writing `Content-Type` here would mean a second
     * spelling of every name -- one for this codec and one for the other two --
     * and a second spelling is a second thing to keep in step, which is what
     * @c field.cpp exists to avoid.
     *
     * There is no algorithm that recovers the conventional capitalisation
     * either: it gives `Content-Type` correctly and `Etag` and
     * `Www-Authenticate` wrongly, which is worse than plainly lower case --
     * plausible and not canonical is harder to notice than obviously uniform.
     *
     * \~spanish
     * El nombre sale en MINUSCULAS, que es lo que tiene la tabla, y eso es una
     * decision y no un descuido.
     *
     * HTTP/1.1 compara los nombres de cabecera sin atender a las mayusculas,
     * asi que es legal; HTTP/2 y HTTP/3 las EXIGEN en minusculas, asi que es la
     * unica grafia que sirve a las tres.  Escribir `Content-Type` aqui
     * significaria una segunda grafia de cada nombre -- una para este codec y
     * otra para los otros dos -- y una segunda grafia es una segunda cosa que
     * mantener de acuerdo, que es de lo que existe para librar @c field.cpp.
     *
     * Y tampoco hay un algoritmo que recupere la capitalizacion habitual: da
     * `Content-Type` bien y `Etag` y `Www-Authenticate` mal, que es peor que
     * minusculas a secas -- plausible y no canonico se nota menos que
     * uniformemente distinto.
     * \~ */
    /* \~english
     * A length of zero means the identifier names nothing -- @c Unknown, or a
     * value from outside the enumeration.  There is no name to write.
     * \~spanish
     * Longitud cero quiere decir que el identificador no nombra nada --
     * @c Unknown, o un valor de fuera de la enumeracion --.  No hay nombre que
     * escribir.
     * \~ */
    if (field_name_len(id) == 0) return fail(WriteError::BadFieldName);

    if (!field_value_is_valid(value, len))
        return fail(WriteError::BadFieldValue);

    if (id == FieldId::Connection) wrote_connection_ = true;

    if (!put_own_field(id, value, len)) return fail(WriteError::OutOfMemory);
    return WriteError::None;
}

WriteError ResponseWriter::field(const char *name, size_t nlen,
                                 const char *value, size_t vlen) noexcept {
    if (state_ == State::Failed) return WriteError::OutOfOrder;
    if (state_ != State::Fields) return fail(WriteError::OutOfOrder);

    if (!token_is_valid(name, nlen)) return fail(WriteError::BadFieldName);
    if (!field_value_is_valid(value, vlen))
        return fail(WriteError::BadFieldValue);

    /* \~english
     * The name is resolved so the framing rule catches a field written as
     * text.  A rule that only stopped the identifier would be a rule with a
     * spelling that gets around it, and `content-length` spelled out is
     * exactly how it would be written by code that did not know better.
     *
     * \~spanish
     * El nombre se resuelve para que la regla del troceado pille una cabecera
     * escrita como texto.  Una regla que solo parara el identificador seria una
     * regla con una grafia que la rodea, y `content-length` escrito entero es
     * justo como lo escribiria un codigo que no supiera que no debe.
     * \~ */
    const FieldId id = field_id_of(name, nlen);
    if (is_framing_field(id)) return fail(WriteError::FramingIsNotYours);
    if (id == FieldId::Connection) wrote_connection_ = true;

    /* \~english
     * A name given as text goes out AS GIVEN, even when it was recognised.
     * The canonical spelling is what this project calls the field; what the
     * caller wrote is what the caller meant, and rewriting it would be
     * changing a name the application chose for a reason this file does not
     * know.
     *
     * \~spanish
     * Un nombre dado como texto sale TAL COMO SE DIO, incluso cuando se
     * reconocio.  La grafia canonica es como llama este proyecto a la cabecera;
     * lo que escribio quien llama es lo que queria decir, y reescribirlo seria
     * cambiar un nombre que la aplicacion eligio por una razon que este fichero
     * no conoce.
     * \~ */
    if (!put(name, nlen)) return fail(WriteError::OutOfMemory);
    if (!put(kColonSpace, 2)) return fail(WriteError::OutOfMemory);
    if (!put(value, vlen)) return fail(WriteError::OutOfMemory);
    if (!put(kCrLf, 2)) return fail(WriteError::OutOfMemory);
    return WriteError::None;
}

WriteError ResponseWriter::finish(ResponseBody body, uint64_t length) noexcept {
    if (state_ == State::Failed) return WriteError::OutOfOrder;
    if (state_ != State::Fields) return fail(WriteError::OutOfOrder);

    const bool allowed = response_can_have_body(method_, status_);

    /* \~english
     * A body where none may go.  The two halves of that rule -- the status and
     * the method -- are asked together, because asking only the status is the
     * almost-right answer that gets `HEAD` wrong.
     *
     * \~spanish
     * Un cuerpo donde no puede ir ninguno.  Las dos mitades de esa regla -- el
     * estado y el metodo -- se preguntan juntas, porque preguntar solo al
     * estado es la respuesta casi buena que yerra en `HEAD`.
     * \~ */
    if (!allowed && body != ResponseBody::None) {
        /* \~english
         * Except a length for HEAD, which is the whole point of HEAD: the
         * fields come out exactly as the GET's, `Content-Length` included, and
         * then nothing follows.  Refusing it would make a HEAD answer a
         * different question than the GET.
         * \~spanish
         * Salvo una longitud para HEAD, que es de lo que va HEAD: las cabeceras
         * salen exactamente como las del GET, `Content-Length` incluida, y
         * despues no va nada.  Rechazarla haria que un HEAD contestara una
         * pregunta distinta que el GET.
         * \~ */
        const bool head_length =
            method_ == MethodId::Head && body == ResponseBody::Length &&
            status_class(status_) != StatusClass::Informational &&
            status_ != status::kNoContent && status_ != status::kNotModified;
        if (!head_length) return fail(WriteError::BodyNotAllowed);
    }

    if (body == ResponseBody::Chunked && version_ != Version::Http11)
        return fail(WriteError::ChunkedNotAvailable);

    switch (body) {
    case ResponseBody::Length:
        if (!put_name(FieldId::ContentLength)) return fail(WriteError::OutOfMemory);
        if (!put_u64(length)) return fail(WriteError::OutOfMemory);
        if (!put(kCrLf, 2)) return fail(WriteError::OutOfMemory);
        body_follows_ = allowed && length != 0;
        break;

    case ResponseBody::Chunked:
        if (!put_own_field(FieldId::TransferEncoding, "chunked", 7))
            return fail(WriteError::OutOfMemory);
        chunked_ = true;
        body_follows_ = allowed;
        break;

    case ResponseBody::UntilClose:
        /* \~english
         * No framing field at all, and the connection cannot survive: the end
         * of the body IS the end of the connection, so promising to reuse it
         * would be promising a boundary that does not exist.
         * \~spanish
         * Ninguna cabecera de troceado, y la conexion no sobrevive: el final
         * del cuerpo ES el final de la conexion, asi que prometer reutilizarla
         * seria prometer una frontera que no existe.
         * \~ */
        closes_ = true;
        body_follows_ = allowed;
        break;

    case ResponseBody::None:
        body_follows_ = false;
        break;
    }

    /* \~english
     * And what the connection does next, which the two versions disagree about
     * by default: HTTP/1.1 keeps it unless told to close, HTTP/1.0 closes it
     * unless told to keep.  So each one is written only when it differs from
     * what the peer already assumes, and saying nothing means the default --
     * which is the one case where silence is not a guess.
     *
     * \~spanish
     * Y que hace despues la conexion, en lo que las dos versiones discrepan por
     * defecto: HTTP/1.1 la conserva salvo que se diga que cierre, y HTTP/1.0 la
     * cierra salvo que se diga que la conserve.  Asi que cada una se escribe
     * solo cuando difiere de lo que el otro extremo ya supone, y no decir nada
     * quiere decir el valor por defecto -- que es el unico caso donde callarse
     * no es una conjetura.
     * \~ */
    if (!wrote_connection_) {
        if (closes_) {
            if (!put_own_field(FieldId::Connection, "close", 5))
                return fail(WriteError::OutOfMemory);
        } else if (version_ == Version::Http10) {
            if (!put_own_field(FieldId::Connection, "keep-alive", 10))
                return fail(WriteError::OutOfMemory);
        }
    }

    if (!put(kCrLf, 2)) return fail(WriteError::OutOfMemory);
    state_ = State::Finished;
    return WriteError::None;
}

} // namespace h1
} // namespace http_vx
