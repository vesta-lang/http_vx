/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h1/parser.cpp
 * @brief
 * \~english The state machine that reads a request head.
 * \~spanish La maquina de estados que lee la cabeza de una peticion.
 * \~
 *
 * \~english
 * Every state does the same three things: it scans forward over the bytes that
 * belong to it, it checks them as it scans, and it stops on the one byte that
 * ends it.  Running out of input inside a state is not a failure -- it returns
 * and the next call carries on from the same byte, with the state and the mark
 * where they were.
 *
 * Nothing here looks backwards.  The only thing that is read twice is the
 * version, and it is copied into the parser as it arrives rather than found
 * again in the buffer.
 *
 * \~spanish
 * Todos los estados hacen las mismas tres cosas: recorren hacia delante los
 * bytes que les pertenecen, los comprueban por el camino, y se paran en el
 * unico byte que los termina.  Quedarse sin entrada dentro de un estado no es
 * un fallo -- se vuelve, y la llamada siguiente sigue por el mismo byte, con el
 * estado y la marca donde estaban.
 *
 * Aqui nada mira hacia atras.  Lo unico que se lee dos veces es la version, y
 * se copia al analizador segun llega en vez de buscarla otra vez en el buffer.
 *
 * \~
 */

#include "http_vx/h1_parser.h"

#include "http_vx/chars.h"

namespace http_vx {
namespace h1 {
namespace {

constexpr uint8_t kCr = '\r';
constexpr uint8_t kLf = '\n';
constexpr uint8_t kSp = ' ';

/**
 * @brief
 * \~english Whether @p c may appear in a request target.
 * \~spanish Si @p c puede aparecer en el destino de una peticion.
 * \~
 *
 * \~english
 * Visible ASCII, and nothing else.  Not @c is_field_vchar, which allows the
 * bytes from 0x80 up: those are legal in a field value for historical reasons
 * and are not legal in a URI, and letting them through is letting a target
 * through that the next server in the chain will percent-decode differently.
 *
 * \~spanish
 * ASCII visible, y nada mas.  No @c is_field_vchar, que permite los bytes de
 * 0x80 en adelante: esos son legales en un valor de cabecera por razones
 * historicas y no lo son en una URI, y dejarlos pasar es dejar pasar un destino
 * que el servidor siguiente de la cadena descodificara de otra forma.
 *
 * \~
 */
inline bool is_target_char(uint8_t c) noexcept { return c > 0x20 && c < 0x7F; }

/**
 * @brief
 * \~english Reads the version that was collected, or says it is not one.
 * \~spanish Lee la version recogida, o dice que no lo es.
 * \~
 *
 * \~english
 * The shape is checked before the numbers, so `HTTP/9.9` comes back as a
 * version this codec does not speak while `HTTPS/1.1` comes back as not a
 * version at all.  They answer differently -- 505 against 400 -- and the
 * difference is worth keeping: one of them is a peer that wanted something
 * else, and the other is a peer that is not speaking HTTP.
 *
 * \~spanish
 * La forma se comprueba antes que los numeros, asi que `HTTP/9.9` vuelve como
 * una version que este codec no habla mientras que `HTTPS/1.1` vuelve como que
 * no es una version.  Contestan distinto -- 505 frente a 400 -- y la diferencia
 * merece conservarse: uno es un extremo que queria otra cosa, y el otro es un
 * extremo que no esta hablando HTTP.
 *
 * \~
 */
Version read_version(const char *text, uint8_t len, bool &well_formed) noexcept {
    well_formed = false;
    if (len != 8) return Version::Unknown;
    if (text[0] != 'H' || text[1] != 'T' || text[2] != 'T' || text[3] != 'P' ||
        text[4] != '/' || text[6] != '.')
        return Version::Unknown;

    const char major = text[5];
    const char minor = text[7];
    if (major < '0' || major > '9' || minor < '0' || minor > '9')
        return Version::Unknown;

    well_formed = true;
    if (major == '1' && minor == '1') return Version::Http11;
    if (major == '1' && minor == '0') return Version::Http10;
    return Version::Unknown;
}

} // namespace

void RequestParser::reset() noexcept {
    state_ = State::Start;
    error_ = ParseError::None;
    pos_ = 0;
    mark_ = 0;
    line_start_ = 0;
    fields_start_ = 0;
    name_off_ = 0;
    name_len_ = 0;
    name_id_ = FieldId::Unknown;
    field_count_ = 0;
    version_len_ = 0;
}

ParseResult RequestParser::fail(ParseError e) noexcept {
    state_ = State::Failed;
    error_ = e;
    return ParseResult::Error;
}

ParseResult RequestParser::finish(Request &out) noexcept {
    /* \~english
     * A `Host` is required of HTTP/1.1 and its absence is a refusal, not a
     * default: the field is what says which of the sites answering on this
     * address was meant, and picking one would be answering a question the
     * peer did not ask.
     *
     * \~spanish
     * HTTP/1.1 exige un `Host` y su ausencia es un rechazo, no un valor por
     * defecto: la cabecera es lo que dice cual de los sitios que contestan en
     * esta direccion se pedia, y elegir uno seria contestar una pregunta que el
     * otro extremo no hizo.
     * \~ */
    const Field *host = out.fields.find(FieldId::Host);
    if (host == nullptr) {
        if (out.version == Version::Http11) return fail(ParseError::MissingHost);
    } else {
        if (out.fields.find_next(host) != nullptr)
            return fail(ParseError::MultipleHosts);

        /* \~english
         * And this is where R30 is paid: the handler reads `authority`, and
         * never learns that in this version it came from a field while in the
         * other two it came from a pseudo-header.
         * \~spanish
         * Y aqui es donde se paga R30: el manejador lee `authority`, y no se
         * entera de que en esta version vino de una cabecera mientras que en
         * las otras dos vino de una pseudo-cabecera.
         * \~ */
        out.authority = Span{host->value_off, host->value_len};
    }

    state_ = State::Done;
    return ParseResult::Done;
}

ParseResult RequestParser::parse(const uint8_t *data, size_t size,
                                 Request &out) noexcept {
    if (state_ == State::Done) return ParseResult::Done;
    if (state_ == State::Failed) return ParseResult::Error;

    for (;;) {
        switch (state_) {

        case State::Start: {
            if (pos_ == size) return ParseResult::NeedMore;
            const uint8_t c = data[pos_];

            /* \~english
             * An empty line before the request line.  It is refused unless it
             * was asked for, and the reason is in `Limits`: those bytes follow
             * a body, so taking them is taking bytes that could not be
             * attributed to the message that carried them.
             * \~spanish
             * Una linea vacia antes de la linea de peticion.  Se rechaza salvo
             * que se haya pedido, y la razon esta en `Limits`: esos bytes van
             * detras de un cuerpo, asi que cogerlos es coger bytes que no se
             * pudieron atribuir al mensaje que los llevaba.
             * \~ */
            if (c == kCr && limits_.allow_leading_crlf) {
                ++pos_;
                state_ = State::StartLf;
                break;
            }
            if (c == kLf) return fail(ParseError::BareLineFeed);

            mark_ = pos_;
            line_start_ = pos_;
            state_ = State::Method;
            break;
        }

        case State::StartLf: {
            if (pos_ == size) return ParseResult::NeedMore;
            if (data[pos_] != kLf) return fail(ParseError::BareCarriageReturn);
            ++pos_;
            /* \~english
             * One, and only one.  A stream of them is not a client writing a
             * spare line ending, it is somebody keeping a connection alive
             * without sending a request.
             * \~spanish
             * Una, y solo una.  Un chorro de ellas no es un cliente escribiendo
             * un fin de linea de mas, es alguien manteniendo viva una conexion
             * sin mandar una peticion.
             * \~ */
            mark_ = pos_;
            line_start_ = pos_;
            state_ = State::Method;
            break;
        }

        case State::Method: {
            while (pos_ < size && is_tchar(data[pos_])) ++pos_;
            /* \~english
             * The limit is checked after the scan and not only when the input
             * runs out.  A line that arrives whole in one read never runs out,
             * so a check placed there would be a limit that only applies to
             * requests that came in pieces -- which is the opposite of the
             * ones worth limiting.
             * \~spanish
             * El limite se comprueba tras el recorrido y no solo al acabarse la
             * entrada.  Una linea que llegue entera en una lectura no se acaba
             * nunca, asi que una comprobacion puesta ahi seria un limite que
             * solo se aplica a las peticiones que llegaron a trozos -- que es
             * lo contrario de las que merecen limitarse.
             * \~ */
            if (pos_ - line_start_ > limits_.max_request_line)
                return fail(ParseError::RequestLineTooLong);
            if (pos_ == size) return ParseResult::NeedMore;
            if (data[pos_] != kSp) return fail(ParseError::BadMethod);
            if (pos_ == mark_) return fail(ParseError::BadMethod);

            const size_t len = pos_ - mark_;
            out.method_text = Span{static_cast<uint32_t>(mark_),
                                   static_cast<uint32_t>(len)};
            out.method = method_id_of(
                reinterpret_cast<const char *>(data + mark_), len);

            ++pos_;
            mark_ = pos_;
            state_ = State::Target;
            break;
        }

        case State::Target: {
            while (pos_ < size && is_target_char(data[pos_])) ++pos_;
            if (pos_ - line_start_ > limits_.max_request_line)
                return fail(ParseError::RequestLineTooLong);
            if (pos_ == size) return ParseResult::NeedMore;
            /* \~english
             * Exactly one space ends it.  A second one does not extend the
             * target: it starts the version, and a target that could contain a
             * space is a target that the next server in the chain splits in
             * another place.
             * \~spanish
             * Lo termina exactamente un espacio.  Un segundo no alarga el
             * destino: empieza la version, y un destino que pudiera llevar un
             * espacio es un destino que el servidor siguiente de la cadena
             * parte en otro sitio.
             * \~ */
            if (data[pos_] != kSp) return fail(ParseError::BadTarget);
            if (pos_ == mark_) return fail(ParseError::BadTarget);

            out.target = Span{static_cast<uint32_t>(mark_),
                              static_cast<uint32_t>(pos_ - mark_)};
            ++pos_;
            version_len_ = 0;
            state_ = State::VersionText;
            break;
        }

        case State::VersionText: {
            while (pos_ < size && data[pos_] != kCr) {
                const uint8_t c = data[pos_];
                if (c == kLf) return fail(ParseError::BareLineFeed);
                if (version_len_ >= sizeof(version_))
                    return fail(ParseError::BadVersion);
                version_[version_len_++] = static_cast<char>(c);
                ++pos_;
            }
            /* \~english
             * No length check here: the collector refuses a ninth byte, so
             * this state cannot run away however long the garbage after the
             * target is.
             * \~spanish
             * Aqui no hay comprobacion de longitud: el recogedor rechaza un
             * noveno byte, asi que este estado no se puede desbocar por larga
             * que sea la basura tras el destino.
             * \~ */
            if (pos_ == size) return ParseResult::NeedMore;

            bool well_formed = false;
            const Version v = read_version(version_, version_len_, well_formed);
            if (!well_formed) return fail(ParseError::BadVersion);
            if (v == Version::Unknown)
                return fail(ParseError::UnsupportedVersion);
            out.version = v;

            ++pos_;
            state_ = State::RequestLineLf;
            break;
        }

        case State::RequestLineLf: {
            if (pos_ == size) return ParseResult::NeedMore;
            if (data[pos_] != kLf) return fail(ParseError::BareCarriageReturn);
            ++pos_;
            fields_start_ = pos_;
            state_ = State::FieldStart;
            break;
        }

        case State::FieldStart: {
            if (pos_ == size) return ParseResult::NeedMore;
            if (pos_ - fields_start_ > limits_.max_header_bytes)
                return fail(ParseError::HeadersTooLarge);

            const uint8_t c = data[pos_];
            if (c == kCr) {
                ++pos_;
                state_ = State::SectionLf;
                break;
            }
            if (c == kLf) return fail(ParseError::BareLineFeed);

            /* \~english
             * A line that begins with whitespace is the deprecated way of
             * continuing the one before.  It is refused and not joined: two
             * ways of writing one value are two values as soon as two
             * recipients disagree about which way it was.
             * \~spanish
             * Una linea que empieza con espacio es la forma retirada de
             * continuar la anterior.  Se rechaza y no se une: dos formas de
             * escribir un valor son dos valores en cuanto dos receptores
             * discrepan sobre cual era.
             * \~ */
            if (is_ows(c)) return fail(ParseError::ObsoleteLineFolding);

            if (field_count_ >= limits_.max_fields)
                return fail(ParseError::TooManyFields);

            mark_ = pos_;
            state_ = State::FieldName;
            break;
        }

        case State::FieldName: {
            while (pos_ < size && is_tchar(data[pos_])) ++pos_;
            if (pos_ - fields_start_ > limits_.max_header_bytes)
                return fail(ParseError::HeadersTooLarge);
            if (pos_ == size) return ParseResult::NeedMore;

            const uint8_t c = data[pos_];
            if (is_ows(c)) return fail(ParseError::SpaceBeforeColon);
            if (c != ':') return fail(ParseError::BadFieldName);
            if (pos_ == mark_) return fail(ParseError::BadFieldName);

            const size_t len = pos_ - mark_;
            /* \~english
             * A name longer than a field can record is not a name this can
             * carry, and truncating it would produce a field that means
             * something else.
             * \~spanish
             * Un nombre mas largo de lo que una cabecera puede anotar no es un
             * nombre que esto pueda llevar, y recortarlo produciria una
             * cabecera que significa otra cosa.
             * \~ */
            if (len > 0xFFFF) return fail(ParseError::HeadersTooLarge);

            name_off_ = static_cast<uint32_t>(mark_);
            name_len_ = static_cast<uint16_t>(len);
            name_id_ =
                field_id_of(reinterpret_cast<const char *>(data + mark_), len);

            ++pos_;
            state_ = State::FieldValueStart;
            break;
        }

        case State::FieldValueStart: {
            /* \~english
             * The spacing after the colon is not part of the value, so it is
             * skipped here rather than trimmed later.  Skipping it as it
             * arrives is what keeps the value's offset right the first time.
             * \~spanish
             * El espaciado tras los dos puntos no es parte del valor, asi que
             * se salta aqui y no se recorta despues.  Saltarlo segun llega es
             * lo que deja bien el desplazamiento del valor a la primera.
             * \~ */
            while (pos_ < size && is_ows(data[pos_])) ++pos_;
            if (pos_ - fields_start_ > limits_.max_header_bytes)
                return fail(ParseError::HeadersTooLarge);
            if (pos_ == size) return ParseResult::NeedMore;
            mark_ = pos_;
            state_ = State::FieldValue;
            break;
        }

        case State::FieldValue: {
            while (pos_ < size) {
                const uint8_t c = data[pos_];
                if (c == kCr) break;
                if (c == kLf) return fail(ParseError::BareLineFeed);
                if (!is_field_vchar(c) && !is_ows(c))
                    return fail(ParseError::BadFieldValue);
                ++pos_;
            }
            if (pos_ - fields_start_ > limits_.max_header_bytes)
                return fail(ParseError::HeadersTooLarge);
            if (pos_ == size) return ParseResult::NeedMore;

            /* \~english
             * The trailing spacing comes off here, walking back over bytes
             * already read rather than reading any again.
             * \~spanish
             * El espaciado del final se quita aqui, retrocediendo sobre bytes
             * ya leidos y sin volver a leer ninguno.
             * \~ */
            size_t end = pos_;
            while (end > mark_ && is_ows(data[end - 1])) --end;

            const size_t len = end - mark_;
            if (len > 0xFFFF) return fail(ParseError::HeadersTooLarge);

            Field f{};
            f.name_off = name_off_;
            f.name_len = name_len_;
            f.value_off = static_cast<uint32_t>(mark_);
            f.value_len = static_cast<uint16_t>(len);
            f.id = name_id_;
            out.fields.add(f);
            ++field_count_;

            ++pos_;
            state_ = State::FieldLf;
            break;
        }

        case State::FieldLf: {
            if (pos_ == size) return ParseResult::NeedMore;
            if (data[pos_] != kLf) return fail(ParseError::BareCarriageReturn);
            ++pos_;
            state_ = State::FieldStart;
            break;
        }

        case State::SectionLf: {
            if (pos_ == size) return ParseResult::NeedMore;
            if (data[pos_] != kLf) return fail(ParseError::BareCarriageReturn);
            ++pos_;
            return finish(out);
        }

        case State::Done:
            return ParseResult::Done;

        case State::Failed:
            return ParseResult::Error;
        }
    }
}

} // namespace h1
} // namespace http_vx
