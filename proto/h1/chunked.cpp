/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/chunked.cpp
 * @brief
 * \~english The state machine that reads a chunked body.
 * \~spanish La maquina de estados que lee un cuerpo troceado.
 * \~
 *
 * \~english
 * Same shape as the head's: every state scans forward over what belongs to it,
 * checks it as it goes, and stops on the byte that ends it.  Running out of
 * input is not a failure; the next call carries on from the same byte.
 *
 * The one difference is that this one also HANDS BACK pieces, so it returns
 * mid-body and is called again.  That is what keeps a body of any size from
 * ever being held whole (R13).
 *
 * \~spanish
 * La misma forma que la de la cabeza: cada estado recorre hacia delante lo que
 * le pertenece, lo comprueba por el camino, y se para en el byte que lo
 * termina.  Quedarse sin entrada no es un fallo; la llamada siguiente sigue por
 * el mismo byte.
 *
 * La unica diferencia es que esta ademas ENTREGA pedazos, asi que vuelve a
 * mitad de cuerpo y se la vuelve a llamar.  Eso es lo que impide que un cuerpo
 * de cualquier tamano se tenga nunca entero (R13).
 *
 * \~
 */

#include "http_vx/h1_chunked.h"

#include "http_vx/chars.h"

namespace http_vx {
namespace h1 {
namespace {

constexpr uint8_t kCr = '\r';
constexpr uint8_t kLf = '\n';

/**
 * @brief
 * \~english The value of a hexadecimal digit, or sixteen if it is not one.
 * \~spanish El valor de un digito hexadecimal, o dieciseis si no lo es.
 * \~
 *
 * \~english
 * Sixteen and not a separate "is it one" because the caller needs the value
 * anyway: asking twice is reading the byte twice, and the answer is out of
 * range exactly when the question was wrong.
 *
 * \~spanish
 * Dieciseis y no un "lo es?" aparte porque quien llama necesita el valor de
 * todas formas: preguntar dos veces es leer el byte dos veces, y la respuesta
 * se sale del rango justo cuando la pregunta estaba mal.
 *
 * \~
 */
inline uint8_t hex_value(uint8_t c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 16;
}

/**
 * @brief
 * \~english The fields that may not arrive as trailers, as one bit each.
 * \~spanish Las cabeceras que no pueden llegar como remolque, un bit cada una.
 * \~
 *
 * \~english
 * A mask and not a list, for the same reason the presence of a field is a
 * mask: the question is asked of every trailer and the answer is a bit test.
 * It rests on the same invariant -- that there are at most sixty-four known
 * identifiers -- which @c fields.h already asserts.
 *
 * What is in it is RFC 9110 section 6.5.1, and the grouping is the
 * specification's reasoning rather than an alphabetical list: a trailer
 * arrives AFTER the decisions these fields drive have been taken, so accepting
 * one is accepting an answer to a question that was already answered.
 *
 * \~spanish
 * Una mascara y no una lista, por la misma razon por la que la presencia de una
 * cabecera es una mascara: la pregunta se le hace a todos los remolques y la
 * respuesta es probar un bit.  Se apoya en el mismo invariante -- que hay como
 * mucho sesenta y cuatro identificadores conocidos -- que ya comprueba
 * @c fields.h.
 *
 * Lo que hay dentro es el RFC 9110 seccion 6.5.1, y la agrupacion es el
 * razonamiento de la especificacion y no una lista alfabetica: un remolque
 * llega DESPUES de que se tomaran las decisiones que gobiernan estas
 * cabeceras, asi que aceptar uno es aceptar una respuesta a una pregunta que ya
 * estaba contestada.
 *
 * \~
 */
constexpr uint64_t bit(FieldId id) noexcept {
    return uint64_t{1} << static_cast<unsigned>(id);
}

constexpr uint64_t kForbiddenInTrailers =
    // Framing: how long the body was.  It has just been read.
    // Troceado: cuanto media el cuerpo.  Se acaba de leer.
    bit(FieldId::ContentLength) | bit(FieldId::TransferEncoding) |
    // Connection control: it governs a connection the message is leaving.
    // Control de conexion: gobierna una conexion que el mensaje esta dejando.
    bit(FieldId::Connection) | bit(FieldId::KeepAlive) | bit(FieldId::Upgrade) |
    bit(FieldId::TE) | bit(FieldId::Trailer) | bit(FieldId::Expect) |
    // Routing: which host was being addressed.  It was routed already.
    // Encaminamiento: a que anfitrion iba.  Ya se encamino.
    bit(FieldId::Host) |
    // Authentication: it decides whether to serve, and serving is under way.
    // Autenticacion: decide si servir, y servir ya esta en marcha.
    bit(FieldId::Authorization) | bit(FieldId::ProxyAuthorization) |
    bit(FieldId::SetCookie) | bit(FieldId::Cookie) |
    // What the content is: it was needed to read it.
    // Que es el contenido: hizo falta para leerlo.
    bit(FieldId::ContentType) | bit(FieldId::ContentEncoding) |
    bit(FieldId::ContentRange) |
    // Caching: it decides what to keep of a response already sent.
    // Cache: decide que guardar de una respuesta ya enviada.
    bit(FieldId::CacheControl);

} // namespace

bool field_forbidden_in_trailers(FieldId id) noexcept {
    if (id == FieldId::Unknown) return false;
    if (static_cast<unsigned>(id) >= static_cast<unsigned>(FieldId::Count))
        return false;
    return (kForbiddenInTrailers & bit(id)) != 0;
}

StatusCode chunk_status(ChunkError e) noexcept {
    switch (e) {
    case ChunkError::None:
        return 0;
    case ChunkError::BodyTooLarge:
        return status::kContentTooLarge;
    case ChunkError::TrailersTooLarge:
        return status::kHeaderFieldsTooLarge;
    default:
        return status::kBadRequest;
    }
}

void ChunkedReader::reset(size_t body_start) noexcept {
    state_ = State::Size;
    error_ = ChunkError::None;
    pos_ = body_start;
    mark_ = body_start;
    trailers_start_ = body_start;
    chunk_ = Span{0, 0};
    chunk_left_ = 0;
    body_bytes_ = 0;
    size_digits_ = 0;
    name_off_ = 0;
    name_len_ = 0;
    trailer_count_ = 0;
    name_id_ = FieldId::Unknown;
}

ChunkResult ChunkedReader::fail(ChunkError e) noexcept {
    state_ = State::Failed;
    error_ = e;
    return ChunkResult::Error;
}

ChunkResult ChunkedReader::read(const uint8_t *data, size_t size,
                                Fields &trailers) noexcept {
    if (state_ == State::Done) return ChunkResult::Done;
    if (state_ == State::Failed) return ChunkResult::Error;

    for (;;) {
        switch (state_) {

        case State::Size: {
            while (pos_ < size) {
                const uint8_t v = hex_value(data[pos_]);
                if (v == 16) break;

                ++size_digits_;
                if (size_digits_ > limits_.max_chunk_size_digits)
                    return fail(ChunkError::ChunkSizeTooLong);

                /* \~english
                 * The overflow is checked even though the digit limit above
                 * already rules it out at sixteen: the limit is a setting, and
                 * a correctness guarantee that holds only while a setting is
                 * left alone is not a guarantee.
                 * \~spanish
                 * El desbordamiento se comprueba aunque el limite de digitos de
                 * arriba ya lo descarte en dieciseis: el limite es un ajuste, y
                 * una garantia de correccion que solo vale mientras nadie toque
                 * un ajuste no es una garantia.
                 * \~ */
                if (chunk_left_ > (~uint64_t{0} - v) / 16)
                    return fail(ChunkError::ChunkSizeTooLong);

                chunk_left_ = chunk_left_ * 16 + v;
                ++pos_;
            }
            if (pos_ == size) return ChunkResult::NeedMore;

            /* \~english
             * A size with no digits is not a size of zero.  It is what the
             * start of a chunk looks like when the previous one ended
             * somewhere other than where this reader thinks it did.
             * \~spanish
             * Un tamano sin digitos no es un tamano de cero.  Es lo que parece
             * el principio de un trozo cuando el anterior acabo en un sitio
             * distinto del que cree este lector.
             * \~ */
            if (size_digits_ == 0) return fail(ChunkError::BadChunkSize);

            const uint8_t c = data[pos_];
            if (c == ';') {
                mark_ = pos_;
                ++pos_;
                state_ = State::Extension;
                break;
            }
            if (c == kCr) {
                ++pos_;
                state_ = State::SizeLf;
                break;
            }
            if (c == kLf) return fail(ChunkError::BareLineFeed);
            return fail(ChunkError::BadChunkSize);
        }

        case State::Extension: {
            while (pos_ < size) {
                const uint8_t c = data[pos_];
                if (c == kCr) break;
                if (c == kLf) return fail(ChunkError::BareLineFeed);
                /* \~english
                 * Extensions are ignored, which is not the same as unread.  A
                 * byte the grammar does not allow here is refused rather than
                 * skipped over: what an extension may carry is what separates
                 * a chunk header this reader ends where the next server does.
                 * \~spanish
                 * Las extensiones se ignoran, que no es lo mismo que no
                 * leerlas.  Un byte que la gramatica no permite aqui se rechaza
                 * en vez de saltarse: lo que puede llevar una extension es lo
                 * que separa una cabecera de trozo que este lector termina
                 * donde la termina el servidor siguiente.
                 * \~ */
                if (!is_field_vchar(c) && !is_ows(c))
                    return fail(ChunkError::BadChunkExtension);
                ++pos_;
            }
            if (pos_ - mark_ > limits_.max_chunk_extension)
                return fail(ChunkError::BadChunkExtension);
            if (pos_ == size) return ChunkResult::NeedMore;
            ++pos_;
            state_ = State::SizeLf;
            break;
        }

        case State::SizeLf: {
            if (pos_ == size) return ChunkResult::NeedMore;
            if (data[pos_] != kLf) return fail(ChunkError::BareCarriageReturn);
            ++pos_;

            if (chunk_left_ == 0) {
                trailers_start_ = pos_;
                state_ = State::TrailerStart;
                break;
            }

            /* \~english
             * The limit is checked against what the chunk ANNOUNCES, before a
             * byte of it is taken.  Waiting until the bytes arrive would mean
             * accepting a gigabyte one read at a time and refusing it at the
             * end, having already spent the memory it was about to be refused
             * for.
             * \~spanish
             * El limite se comprueba contra lo que el trozo ANUNCIA, antes de
             * coger un byte de el.  Esperar a que lleguen los bytes seria
             * aceptar un gigabyte de lectura en lectura y rechazarlo al final,
             * habiendo gastado ya la memoria por la que se iba a rechazar.
             * \~ */
            if (chunk_left_ > limits_.max_body_bytes - body_bytes_)
                return fail(ChunkError::BodyTooLarge);

            state_ = State::Data;
            break;
        }

        case State::Data: {
            const size_t avail = size - pos_;
            if (avail == 0) return ChunkResult::NeedMore;

            const uint64_t want = chunk_left_;
            const size_t take = want < avail ? static_cast<size_t>(want) : avail;

            chunk_ = Span{static_cast<uint32_t>(pos_),
                          static_cast<uint32_t>(take)};
            pos_ += take;
            chunk_left_ -= take;
            body_bytes_ += take;

            if (chunk_left_ == 0) state_ = State::DataCr;
            return ChunkResult::Data;
        }

        case State::DataCr: {
            if (pos_ == size) return ChunkResult::NeedMore;
            const uint8_t c = data[pos_];
            if (c == kLf) return fail(ChunkError::BareLineFeed);
            if (c != kCr) return fail(ChunkError::BadChunkTerminator);
            ++pos_;
            state_ = State::DataLf;
            break;
        }

        case State::DataLf: {
            if (pos_ == size) return ChunkResult::NeedMore;
            if (data[pos_] != kLf) return fail(ChunkError::BareCarriageReturn);
            ++pos_;
            size_digits_ = 0;
            chunk_left_ = 0;
            state_ = State::Size;
            break;
        }

        case State::TrailerStart: {
            if (pos_ == size) return ChunkResult::NeedMore;
            if (pos_ - trailers_start_ > limits_.max_trailer_bytes)
                return fail(ChunkError::TrailersTooLarge);

            const uint8_t c = data[pos_];
            if (c == kCr) {
                ++pos_;
                state_ = State::EndLf;
                break;
            }
            if (c == kLf) return fail(ChunkError::BareLineFeed);
            if (is_ows(c)) return fail(ChunkError::ObsoleteLineFolding);
            if (trailer_count_ >= limits_.max_trailers)
                return fail(ChunkError::TrailersTooLarge);

            mark_ = pos_;
            state_ = State::TrailerName;
            break;
        }

        case State::TrailerName: {
            while (pos_ < size && is_tchar(data[pos_])) ++pos_;
            if (pos_ - trailers_start_ > limits_.max_trailer_bytes)
                return fail(ChunkError::TrailersTooLarge);
            if (pos_ == size) return ChunkResult::NeedMore;

            if (data[pos_] != ':') return fail(ChunkError::BadTrailerName);
            if (pos_ == mark_) return fail(ChunkError::BadTrailerName);

            const size_t len = pos_ - mark_;
            if (len > 0xFFFF) return fail(ChunkError::TrailersTooLarge);

            name_off_ = static_cast<uint32_t>(mark_);
            name_len_ = static_cast<uint16_t>(len);
            name_id_ =
                field_id_of(reinterpret_cast<const char *>(data + mark_), len);

            if (field_forbidden_in_trailers(name_id_))
                return fail(ChunkError::ForbiddenTrailer);

            ++pos_;
            state_ = State::TrailerValueStart;
            break;
        }

        case State::TrailerValueStart: {
            while (pos_ < size && is_ows(data[pos_])) ++pos_;
            if (pos_ - trailers_start_ > limits_.max_trailer_bytes)
                return fail(ChunkError::TrailersTooLarge);
            if (pos_ == size) return ChunkResult::NeedMore;
            mark_ = pos_;
            state_ = State::TrailerValue;
            break;
        }

        case State::TrailerValue: {
            while (pos_ < size) {
                const uint8_t c = data[pos_];
                if (c == kCr) break;
                if (c == kLf) return fail(ChunkError::BareLineFeed);
                if (!is_field_vchar(c) && !is_ows(c))
                    return fail(ChunkError::BadTrailerValue);
                ++pos_;
            }
            if (pos_ - trailers_start_ > limits_.max_trailer_bytes)
                return fail(ChunkError::TrailersTooLarge);
            if (pos_ == size) return ChunkResult::NeedMore;

            size_t end = pos_;
            while (end > mark_ && is_ows(data[end - 1])) --end;

            const size_t len = end - mark_;
            if (len > 0xFFFF) return fail(ChunkError::TrailersTooLarge);

            Field f{};
            f.name_off = name_off_;
            f.name_len = name_len_;
            f.value_off = static_cast<uint32_t>(mark_);
            f.value_len = static_cast<uint16_t>(len);
            f.id = name_id_;
            trailers.add(f);
            ++trailer_count_;

            ++pos_;
            state_ = State::TrailerLf;
            break;
        }

        case State::TrailerLf: {
            if (pos_ == size) return ChunkResult::NeedMore;
            if (data[pos_] != kLf) return fail(ChunkError::BareCarriageReturn);
            ++pos_;
            state_ = State::TrailerStart;
            break;
        }

        case State::EndLf: {
            if (pos_ == size) return ChunkResult::NeedMore;
            if (data[pos_] != kLf) return fail(ChunkError::BareCarriageReturn);
            ++pos_;
            state_ = State::Done;
            return ChunkResult::Done;
        }

        case State::Done:
            return ChunkResult::Done;

        case State::Failed:
            return ChunkResult::Error;
        }
    }
}

} // namespace h1
} // namespace http_vx
