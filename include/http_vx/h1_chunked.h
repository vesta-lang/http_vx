/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h1_chunked.h
 * @brief
 * \~english Reading a body that announces its own pieces.
 * \~spanish Leer un cuerpo que anuncia sus propios trozos.
 * \~
 *
 * \~english
 * The chunked encoding exists so that a sender can start writing before it
 * knows how much it will write: each piece announces its size, and a piece of
 * size zero says there are no more.  That makes it the framing used by
 * everything generated on the fly, which today is most things.
 *
 * It is also the second place in HTTP/1.1 where where-the-body-ends is written
 * down, which makes it the second place a chain of servers can disagree.  The
 * first is in @c h1_framing.h and the rule there is that a message may not use
 * both.  Here the rule is narrower and there are more of them, because a chunk
 * header is a tiny grammar of its own and every piece of it has been read
 * differently by somebody:
 *
 *  - a size is hexadecimal, so a reader that accepts `0x10` reads sixteen
 *    where a stricter one reads a malformed chunk and stops;
 *  - a size may carry extensions after a semicolon, so a reader that stops at
 *    the semicolon and one that does not are reading different sizes if the
 *    extension contains digits;
 *  - the data is followed by a carriage return and a line feed, so a reader
 *    that accepts the line feed alone finds the next chunk one byte from where
 *    a stricter one finds it;
 *  - and the trailers come after, which is a second chance to send fields --
 *    including, if nobody checks, the ones that say how long the body was.
 *
 * Every one of those is refused here, and the last is refused by name: a
 * trailer is not a place to put framing.
 *
 * \~spanish
 * La codificacion por trozos existe para que quien envia pueda empezar a
 * escribir antes de saber cuanto va a escribir: cada trozo anuncia su tamano, y
 * uno de tamano cero dice que no hay mas.  Eso la convierte en el troceado de
 * todo lo que se genera sobre la marcha, que hoy es casi todo.
 *
 * Es ademas el segundo sitio de HTTP/1.1 donde se escribe donde-acaba-el-
 * cuerpo, lo que la convierte en el segundo sitio donde una cadena de
 * servidores puede discrepar.  El primero esta en @c h1_framing.h y alli la
 * regla es que un mensaje no puede usar los dos.  Aqui la regla es mas
 * estrecha y hay mas, porque la cabecera de un trozo es una gramatica diminuta
 * y cada pieza de ella la ha leido alguien de otra forma:
 *
 *  - un tamano es hexadecimal, asi que un lector que acepte `0x10` lee
 *    dieciseis donde uno mas estricto lee un trozo mal formado y se para;
 *  - un tamano puede llevar extensiones tras un punto y coma, asi que un lector
 *    que se pare en el punto y coma y uno que no estan leyendo tamanos
 *    distintos si la extension lleva digitos;
 *  - tras los datos van un retorno de carro y un salto de linea, asi que un
 *    lector que acepte el salto solo encuentra el trozo siguiente a un byte de
 *    donde lo encuentra uno mas estricto;
 *  - y detras vienen los remolques, que son una segunda oportunidad de mandar
 *    cabeceras -- incluidas, si no mira nadie, las que dicen cuanto media el
 *    cuerpo.
 *
 * Todas se rechazan aqui, y la ultima se rechaza por nombre: un remolque no es
 * sitio para poner troceado.
 *
 * \~
 */
#ifndef HTTP_VX_H1_CHUNKED_H
#define HTTP_VX_H1_CHUNKED_H

#include "http_vx/buffer.h"
#include "http_vx/fields.h"
#include "http_vx/h1_limits.h"
#include "http_vx/span.h"
#include "http_vx/status.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h1 {

/**
 * @brief
 * \~english Why the body could not be read.
 * \~spanish Por que no se pudo leer el cuerpo.
 * \~
 */
enum class ChunkError : uint8_t {
    /// \~english Nothing is wrong.  \~spanish No pasa nada.  \~
    None = 0,

    /// \~english A chunk size that is not hexadecimal digits, or is empty.
    /// \~spanish Un tamano de trozo que no son digitos hexadecimales, o esta vacio.  \~
    BadChunkSize,

    /// \~english More size digits than a size can need.
    /// \~spanish Mas digitos de tamano de los que puede necesitar un tamano.  \~
    ChunkSizeTooLong,

    /// \~english An extension carrying a byte it may not, or longer than allowed.
    /// \~spanish Una extension con un byte que no puede llevar, o mas larga de lo permitido.  \~
    BadChunkExtension,

    /**
     * \~english
     * A chunk's data not followed by a carriage return and a line feed.  It is
     * refused rather than resynchronised: a reader that hunts for the next
     * plausible chunk header is a reader that finds one wherever the sender
     * put it.
     * \~spanish
     * Los datos de un trozo sin un retorno de carro y un salto de linea
     * detras.  Se rechaza en vez de resincronizar: un lector que busque la
     * siguiente cabecera de trozo plausible es un lector que encuentra una
     * donde quien envia la haya puesto.
     * \~
     */
    BadChunkTerminator,

    /// \~english A line ending without its carriage return.
    /// \~spanish Un fin de linea sin su retorno de carro.  \~
    BareLineFeed,

    /// \~english A carriage return with something other than a line feed after it.
    /// \~spanish Un retorno de carro con algo que no es un salto de linea detras.  \~
    BareCarriageReturn,

    /// \~english A trailer continued on the next line, which the head refuses too.
    /// \~spanish Un remolque continuado en la linea siguiente, que la cabeza tambien rechaza.  \~
    ObsoleteLineFolding,

    /// \~english A trailer name that is not a token.
    /// \~spanish Un nombre de remolque que no es un token.  \~
    BadTrailerName,

    /// \~english A trailer value carrying a byte it may not.
    /// \~spanish Un valor de remolque con un byte que no puede llevar.  \~
    BadTrailerValue,

    /**
     * \~english
     * A trailer naming a field that may not be one.  The specification lists
     * them and the list is not arbitrary: they are the fields that decide
     * framing, routing, authentication and caching, and a trailer arrives
     * AFTER those decisions were taken.  A recipient that accepted a
     * `Transfer-Encoding` trailer would be accepting framing from a message it
     * has already finished framing, and one that accepted a `Content-Length`
     * trailer would have two answers for how long the body it just read was.
     * \~spanish
     * Un remolque que nombra una cabecera que no puede serlo.  La
     * especificacion las lista y la lista no es arbitraria: son las que deciden
     * el troceado, el encaminamiento, la autenticacion y la cache, y un
     * remolque llega DESPUES de que esas decisiones se tomaran.  Quien aceptara
     * un remolque `Transfer-Encoding` estaria aceptando troceado de un mensaje
     * que ya termino de trocear, y quien aceptara uno `Content-Length` tendria
     * dos respuestas sobre cuanto media el cuerpo que acaba de leer.
     * \~
     */
    ForbiddenTrailer,

    /// \~english More trailer bytes or trailer fields than allowed.
    /// \~spanish Mas bytes o mas cabeceras de remolque de las permitidas.  \~
    TrailersTooLarge,

    /// \~english The body is longer than allowed.  Answers 413.
    /// \~spanish El cuerpo es mas largo de lo permitido.  Contesta 413.  \~
    BodyTooLarge,
};

/**
 * @brief
 * \~english How far reading the body got.
 * \~spanish Hasta donde llego la lectura del cuerpo.
 * \~
 */
enum class ChunkResult : uint8_t {
    /// \~english Nothing more can be read from what is here.  Read more.
    /// \~spanish De lo que hay no se puede leer mas.  Leer mas.  \~
    NeedMore,
    /// \~english A piece of the body is ready.  See @c ChunkedReader::chunk.
    /// \~spanish Hay un trozo del cuerpo listo.  Ver @c ChunkedReader::chunk.  \~
    Data,
    /// \~english The body and its trailers are complete.
    /// \~spanish El cuerpo y sus remolques estan completos.  \~
    Done,
    /// \~english It is not a body this can read.  \~spanish No es un cuerpo que esto pueda leer.  \~
    Error,
};

/**
 * @brief
 * \~english Reads one chunked body.
 * \~spanish Lee un cuerpo troceado.
 * \~
 *
 * \~english
 * Fed the same way as @c RequestParser: the whole live region of the buffer
 * every time, not only what is new, and it carries on from where it stopped.
 * Every offset it deals in -- where it started, where a piece is, what it
 * consumed -- is measured from the same first byte, so a piece of the body and
 * a piece of the head are named on the same scale.
 *
 * \~spanish
 * Se alimenta igual que @c RequestParser: la region viva entera del buffer cada
 * vez, no solo lo nuevo, y sigue por donde se paro.  Todos los desplazamientos
 * que maneja -- por donde empezo, donde esta un trozo, cuanto consumio -- se
 * miden desde el mismo primer byte, asi que un pedazo del cuerpo y un pedazo de
 * la cabeza se nombran en la misma escala.
 *
 * \~
 */
class ChunkedReader {
  public:
    ChunkedReader() noexcept = default;
    explicit ChunkedReader(const Limits &limits) noexcept : limits_(limits) {}

    /**
     * @brief
     * \~english Says where the body starts and makes it ready to read one.
     * \~spanish Dice donde empieza el cuerpo y lo deja listo para leer uno.
     * \~
     *
     * @param body_start
     *   \~english the stream position the body starts at, which is the
     *   buffer's origin plus @c RequestParser::head_size
     *   \~spanish la posicion del flujo donde empieza el cuerpo, que es el
     *   origen del buffer mas @c RequestParser::head_size  \~
     */
    void reset(uint64_t body_start) noexcept;

    /**
     * @brief
     * \~english Reads as far as it can, and says what it found.
     * \~spanish Lee hasta donde puede, y dice que encontro.
     * \~
     *
     * \~english
     * It returns at most ONE piece of body per call, so it is called in a loop
     * until it answers @c NeedMore, @c Done or @c Error.  Returning one at a
     * time is what lets the caller do something with each piece -- write it to
     * a file, hash it, forward it -- instead of being handed an array of them
     * that had to be held somewhere first.
     *
     * A chunk split across two reads comes back as two pieces, and that is not
     * a degraded case: it is the ordinary one for a body of any size, and the
     * reason nothing here ever needs the whole body at once.
     *
     * \~spanish
     * Devuelve como mucho UN pedazo de cuerpo por llamada, asi que se le llama
     * en bucle hasta que conteste @c NeedMore, @c Done o @c Error.  Devolver de
     * uno en uno es lo que permite a quien llama hacer algo con cada pedazo --
     * escribirlo a un fichero, resumirlo, reenviarlo -- en vez de recibir un
     * array de ellos que hubo que guardar antes en algun sitio.
     *
     * Un trozo partido entre dos lecturas vuelve como dos pedazos, y eso no es
     * un caso degradado: es el corriente para un cuerpo de cualquier tamano, y
     * la razon de que aqui nada necesite nunca el cuerpo entero de una vez.
     *
     * \~
     * @param v        \~english the bytes that are here and where they are
     *                 \~spanish los bytes que hay y donde estan  \~
     * @param trailers \~english where the trailer fields go
     *                 \~spanish donde van las cabeceras de remolque  \~
     * @return         \~english what it found  \~spanish que encontro  \~
     */
    ChunkResult read(const View &v, Fields &trailers) noexcept;

    /**
     * @brief
     * \~english The piece of body the last @c Data refers to.
     * \~spanish El pedazo de cuerpo al que se refiere el ultimo @c Data.
     * \~
     *
     * \~english
     * A view, never a copy (R13).  It stays valid as long as the buffer's
     * offsets do, which is until the message is consumed.
     *
     * \~spanish
     * Una vista, nunca una copia (R13).  Vale mientras valgan los
     * desplazamientos del buffer, que es hasta que se consuma el mensaje.
     *
     * \~
     */
    Span chunk() const noexcept { return chunk_; }

    /// \~english Why it was refused, when it was.  \~spanish Por que se rechazo, cuando se rechazo.  \~
    ChunkError error() const noexcept { return error_; }

    /**
     * @brief
     * \~english How many bytes of the message have been read.
     * \~spanish Cuantos bytes del mensaje se han leido.
     * \~
     *
     * \~english
     * After @c Done this is where the NEXT message starts, framing and
     * trailers included.
     *
     * **It is a point with nothing behind it**, which is what makes it safe to
     * drop up to while the body is still arriving -- and dropping as it
     * arrives is the whole reason this reader counts from the connection.
     *
     * While the trailers are being read it stops at where they began, and does
     * not follow the reading.  A trailer's name is recorded when its colon
     * arrives and used when its value ends, so between those two moments the
     * reader is holding a position behind where it is looking; following the
     * reading would invite dropping the name of the field about to be built.
     * Trailers are small and they are the last thing in a message, so nothing
     * is lost by waiting.
     *
     * The same care is the caller's afterwards: once the message is done, the
     * trailers are spans into these bytes, and they may not be dropped while
     * anything is still reading them.
     *
     * \~spanish
     * Tras @c Done, aqui es donde empieza el mensaje SIGUIENTE, con troceado y
     * remolques incluidos.
     *
     * **Es un punto sin nada detras**, que es lo que hace seguro descartar
     * hasta el mientras el cuerpo sigue llegando -- y descartar segun llega es
     * toda la razon de que este lector cuente desde la conexion.
     *
     * Mientras se leen los remolques se queda donde empezaron, y no sigue a la
     * lectura.  El nombre de un remolque se anota cuando llegan sus dos puntos
     * y se usa cuando acaba su valor, asi que entre esos dos momentos el lector
     * tiene una posicion por detras de donde mira; seguir a la lectura
     * invitaria a descartar el nombre de la cabecera que se esta construyendo.
     * Los remolques son pequenos y son lo ultimo de un mensaje, asi que no se
     * pierde nada esperando.
     *
     * El mismo cuidado es de quien llama despues: una vez terminado el mensaje,
     * los remolques son trozos dentro de estos bytes, y no se pueden descartar
     * mientras algo los siga leyendo.
     *
     * \~
     */
    uint64_t consumed() const noexcept {
        return in_trailers_ ? trailers_start_ : pos_;
    }

    /**
     * @brief
     * \~english How far it has looked, which is not where it has finished.
     * \~spanish Hasta donde ha mirado, que no es donde ha terminado.
     * \~
     *
     * \~english
     * The two are the same number for most of a body and differ once the
     * trailers begin, and telling them apart is what @c consumed is about.
     * This one is the reading: it moves with every byte, so it is what says
     * whether a connection is getting anywhere -- which is the question a
     * timeout asks, and the one that @c consumed would answer wrongly for a
     * peer that is dribbling out a trailer.
     *
     * \~spanish
     * Los dos son el mismo numero durante casi todo un cuerpo y difieren en
     * cuanto empiezan los remolques, y distinguirlos es de lo que va
     * @c consumed.  Este es la lectura: se mueve con cada byte, asi que es lo
     * que dice si una conexion esta llegando a alguna parte -- que es la
     * pregunta que hace un plazo, y la que @c consumed contestaria mal para un
     * extremo que este soltando un remolque gota a gota.
     *
     * \~
     */
    uint64_t position() const noexcept { return pos_; }

    /// \~english How many bytes of body there were.
    /// \~spanish Cuantos bytes de cuerpo habia.  \~
    uint64_t body_bytes() const noexcept { return body_bytes_; }

  private:
    enum class State : uint8_t {
        Size,
        Extension,
        SizeLf,
        Data,
        DataCr,
        DataLf,
        TrailerStart,
        TrailerName,
        TrailerValueStart,
        TrailerValue,
        TrailerLf,
        EndLf,
        Done,
        Failed,
    };

    [[gnu::noinline, gnu::cold]] ChunkResult fail(ChunkError e) noexcept;

    Limits limits_;
    State state_ = State::Size;
    ChunkError error_ = ChunkError::None;

    uint64_t pos_ = 0;
    uint64_t mark_ = 0;
    uint64_t trailers_start_ = 0;

    Span chunk_ = {0, 0};
    uint64_t chunk_left_ = 0;
    uint64_t body_bytes_ = 0;
    uint32_t size_digits_ = 0;
    uint32_t name_off_ = 0;
    uint16_t name_len_ = 0;
    uint16_t trailer_count_ = 0;

    /**
     * \~english
     * Whether the trailers have begun.  It freezes what @c consumed reports,
     * because from here on the reader keeps a position behind where it is
     * looking.
     * \~spanish
     * Si empezaron los remolques.  Congela lo que informa @c consumed, porque
     * de aqui en adelante el lector guarda una posicion por detras de donde
     * mira.
     * \~
     */
    bool in_trailers_ = false;
    FieldId name_id_ = FieldId::Unknown;
};

/**
 * @brief
 * \~english The status code that @p e should be answered with.
 * \~spanish El codigo de estado con el que contestar a @p e.
 * \~
 *
 * \~english
 * As in @c h1_framing.h, the mapping is part of the rule rather than the
 * caller's to invent.  And as there, none of these leaves the connection
 * usable: once a chunk header has been read wrong, where the next message
 * starts is a guess.
 *
 * \~spanish
 * Como en @c h1_framing.h, la correspondencia es parte de la regla y no algo
 * que invente quien llama.  Y como alli, ninguno de estos deja la conexion
 * utilizable: una vez leida mal una cabecera de trozo, donde empieza el mensaje
 * siguiente es una conjetura.
 *
 * \~
 * @param e \~english the reason  \~spanish el motivo  \~
 * @return  \~english the status code, or 0 if there is nothing to answer
 *          \~spanish el codigo de estado, o 0 si no hay nada que contestar  \~
 */
[[gnu::cold]] StatusCode chunk_status(ChunkError e) noexcept;

/**
 * @brief
 * \~english Whether @p id may not appear as a trailer.
 * \~spanish Si @p id no puede aparecer como remolque.
 * \~
 *
 * \~english
 * Exposed because a codec for another version needs the same answer: HTTP/2
 * and HTTP/3 carry trailers too, and the reason a field is forbidden in one is
 * the reason it is forbidden in all three.  Having it here rather than inside
 * the reader is what keeps the three from each deciding for themselves.
 *
 * \~spanish
 * Expuesto porque un codec de otra version necesita la misma respuesta: HTTP/2
 * y HTTP/3 tambien llevan remolques, y la razon de que una cabecera este
 * prohibida en uno es la razon de que lo este en los tres.  Tenerlo aqui y no
 * dentro del lector es lo que impide que los tres lo decidan cada uno por su
 * cuenta.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true if it may not be a trailer
 *           \~spanish true si no puede ser un remolque  \~
 */
bool field_forbidden_in_trailers(FieldId id) noexcept;

} // namespace h1
} // namespace http_vx

#endif // HTTP_VX_H1_CHUNKED_H
