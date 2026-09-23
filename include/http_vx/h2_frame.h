/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_frame.h
 * @brief
 * \~english The frames of HTTP/2: nine bytes of header and what follows.
 * \~spanish Las tramas de HTTP/2: nueve bytes de cabecera y lo que va detras.
 * \~
 *
 * \~english
 * HTTP/2 replaces the text of HTTP/1.1 with frames, and the reason is not
 * terseness.  A text message occupies its connection from its first byte to
 * its last, so a slow response blocks every request behind it; frames belong
 * to streams, and streams are interleaved, so one slow response is one slow
 * stream.  Everything else about this version follows from that.
 *
 * What it costs is a new set of ways to be wrong, and they are not the text
 * ones.  There is no ambiguity about where a frame ends -- the length is a
 * number in the header, and this is the whole gain of a binary format.  What
 * replaces it is arithmetic: a padding length longer than the frame that
 * contains it, a fixed-size frame that is not that size, a header block split
 * across so many frames that the recipient never gets to finish it.
 *
 * Each of those is checked here, and each one is checked BEFORE the number it
 * produces is used for anything, which for a length is the difference between
 * a refusal and a read past the end of a buffer.
 *
 * \~spanish
 * HTTP/2 sustituye el texto de HTTP/1.1 por tramas, y la razon no es la
 * brevedad.  Un mensaje de texto ocupa su conexion desde su primer byte hasta
 * el ultimo, asi que una respuesta lenta bloquea todas las peticiones que vayan
 * detras; las tramas son de flujos, y los flujos se entrelazan, asi que una
 * respuesta lenta es un flujo lento.  Todo lo demas de esta version sale de
 * ahi.
 *
 * Lo que cuesta es un juego nuevo de formas de estar mal, y no son las del
 * texto.  No hay ambiguedad sobre donde acaba una trama -- la longitud es un
 * numero de la cabecera, y esa es toda la ganancia de un formato binario --.
 * Lo que la sustituye es aritmetica: un relleno mas largo que la trama que lo
 * lleva, una trama de tamano fijo que no mide eso, un bloque de cabeceras
 * partido en tantas tramas que quien recibe no llega nunca a terminarlo.
 *
 * Todas se comprueban aqui, y todas se comprueban ANTES de usar para nada el
 * numero que producen, que en una longitud es la diferencia entre un rechazo y
 * una lectura pasado el final de un buffer.
 *
 * \~
 */
#ifndef HTTP_VX_H2_FRAME_H
#define HTTP_VX_H2_FRAME_H

#include "http_vx/h2_limits.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/// \~english The nine bytes every frame starts with.
/// \~spanish Los nueve bytes con los que empieza toda trama.  \~
constexpr size_t kFrameHeaderSize = 9;

/**
 * @brief
 * \~english How this protocol's numbers are read and written.
 * \~spanish Como se leen y se escriben los numeros de este protocolo.
 * \~
 *
 * \~english
 * Byte by byte, not by reading a word and turning it round.  Every one of
 * these fields is three or four bytes at an offset that is aligned to nothing,
 * so a word read would be unaligned AND would still need turning round; this
 * way there is nothing to get wrong on a machine of either byte order.
 *
 * They are here rather than beside the first thing that needed them because
 * everything in this protocol uses them -- frame headers, settings, window
 * updates, stream identifiers -- and byte order is exactly the kind of thing
 * that must be stated once.  A second copy does not fail when it is written;
 * it fails on the one field somebody read with the other one.
 *
 * \~spanish
 * Byte a byte, no leyendo una palabra y dandole la vuelta.  Todos estos campos
 * miden tres o cuatro bytes en un desplazamiento que no esta alineado a nada,
 * asi que una lectura de palabra estaria desalineada Y seguiria haciendo falta
 * darle la vuelta; asi no hay nada que errar en una maquina de cualquiera de
 * los dos ordenes de byte.
 *
 * Estan aqui y no al lado de lo primero que los necesito porque los usa todo
 * este protocolo -- cabeceras de trama, ajustes, actualizaciones de ventana,
 * identificadores de flujo -- y el orden de byte es justo de lo que hay que
 * decir una sola vez.  Una segunda copia no falla cuando se escribe; falla en
 * el unico campo que alguien leyo con la otra.
 *
 * \~
 */
inline uint16_t be16(const uint8_t *p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

/// \~english The same for three bytes.  \~spanish Lo mismo para tres bytes.  \~
inline uint32_t be24(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
}

/// \~english And for four.  \~spanish Y para cuatro.  \~
inline uint32_t be32(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

/// \~english Writes two bytes.  \~spanish Escribe dos bytes.  \~
inline void put_be16(uint8_t *p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

/// \~english Writes three.  \~spanish Escribe tres.  \~
inline void put_be24(uint8_t *p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 16);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v);
}

/// \~english Writes four.  \~spanish Escribe cuatro.  \~
inline void put_be32(uint8_t *p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

/**
 * @brief
 * \~english The bytes a client sends before its first frame.
 * \~spanish Los bytes que manda un cliente antes de su primera trama.
 * \~
 *
 * \~english
 * It is a valid-looking HTTP/1.1 request line that no HTTP/1.1 server will
 * act on, and that is the whole idea: a server or proxy that does not speak
 * HTTP/2 sees a method it does not know and refuses, rather than trying to
 * interpret the frames that follow as text.
 *
 * \~spanish
 * Es una linea de peticion con aspecto de HTTP/1.1 que ningun servidor de
 * HTTP/1.1 va a atender, y de eso se trata: un servidor o intermediario que no
 * hable HTTP/2 ve un metodo que no conoce y rechaza, en vez de intentar
 * interpretar como texto las tramas que van detras.
 *
 * \~
 */
extern const uint8_t kClientPreface[24];

/**
 * @brief
 * \~english What a frame is for.
 * \~spanish Para que sirve una trama.
 * \~
 *
 * \~english
 * The numbers are the wire values, unlike @c FieldId and @c MethodId: a frame
 * type is a byte the peer sends, so naming it does not make the name the
 * identity.
 *
 * Types past the last one here are not an error.  The specification requires a
 * recipient to ignore and discard a frame whose type it does not know, which
 * is the one place in this codec where being strict would be wrong: that rule
 * is how the protocol gets extended without breaking everything already
 * deployed, and a server that refused would be refusing the future.
 *
 * \~spanish
 * Los numeros son los valores del cable, al reves que @c FieldId y
 * @c MethodId: un tipo de trama es un byte que manda el otro extremo, asi que
 * ponerle nombre no hace que el nombre sea la identidad.
 *
 * Los tipos pasado el ultimo de aqui no son un error.  La especificacion exige
 * que quien recibe ignore y descarte una trama de un tipo que no conoce, que es
 * el unico sitio de este codec donde ser estricto estaria mal: esa regla es
 * como se extiende el protocolo sin romper todo lo que ya esta desplegado, y un
 * servidor que rechazara estaria rechazando el futuro.
 *
 * \~
 */
enum class FrameType : uint8_t {
    Data = 0x00,
    Headers = 0x01,
    Priority = 0x02,
    RstStream = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Ping = 0x06,
    Goaway = 0x07,
    WindowUpdate = 0x08,
    Continuation = 0x09,
};

/**
 * @brief
 * \~english The flags a frame may carry.
 * \~spanish Las banderas que puede llevar una trama.
 * \~
 *
 * \~english
 * The same bit means different things in different frames, which is why they
 * are named for what they mean and not for their position: bit zero is
 * @c EndStream on a DATA and @c Ack on a SETTINGS, and reading one as the
 * other turns an acknowledgement into the end of a request.
 *
 * \~spanish
 * El mismo bit significa cosas distintas en tramas distintas, que es la razon
 * de que se nombren por lo que quieren decir y no por su posicion: el bit cero
 * es @c EndStream en una DATA y @c Ack en una SETTINGS, y leer uno como el otro
 * convierte un acuse de recibo en el final de una peticion.
 *
 * \~
 */
enum FrameFlag : uint8_t {
    /// \~english DATA, HEADERS: nothing more comes on this stream.
    /// \~spanish DATA, HEADERS: no viene nada mas por este flujo.  \~
    kEndStream = 0x01,
    /// \~english SETTINGS, PING: this is the answer, not the question.
    /// \~spanish SETTINGS, PING: esto es la respuesta, no la pregunta.  \~
    kAck = 0x01,
    /// \~english HEADERS, PUSH_PROMISE, CONTINUATION: the block ends here.
    /// \~spanish HEADERS, PUSH_PROMISE, CONTINUATION: el bloque acaba aqui.  \~
    kEndHeaders = 0x04,
    /// \~english DATA, HEADERS, PUSH_PROMISE: there is padding at the end.
    /// \~spanish DATA, HEADERS, PUSH_PROMISE: hay relleno al final.  \~
    kPadded = 0x08,
    /// \~english HEADERS: five bytes of priority come first.
    /// \~spanish HEADERS: van cinco bytes de prioridad delante.  \~
    kPriority = 0x20,
};

/**
 * @brief
 * \~english Why a connection or a stream is being ended.
 * \~spanish Por que se esta terminando una conexion o un flujo.
 * \~
 *
 * \~english
 * The values are the wire ones.  Unlike HTTP/1.1, where a server explains
 * itself with a status code and a body, HTTP/2 has a place for saying what
 * went wrong at the protocol level -- which is why the errors in this codec
 * carry one of these rather than being told apart afterwards.
 *
 * \~spanish
 * Los valores son los del cable.  A diferencia de HTTP/1.1, donde un servidor
 * se explica con un codigo de estado y un cuerpo, HTTP/2 tiene un sitio donde
 * decir que fue mal al nivel del protocolo -- que es la razon de que los
 * errores de este codec lleven uno de estos y no se distingan despues.
 *
 * \~
 */
enum class ErrorCode : uint32_t {
    NoError = 0x00,
    ProtocolError = 0x01,
    InternalError = 0x02,
    FlowControlError = 0x03,
    SettingsTimeout = 0x04,
    StreamClosed = 0x05,
    FrameSizeError = 0x06,
    RefusedStream = 0x07,
    Cancel = 0x08,
    CompressionError = 0x09,
    ConnectError = 0x0A,
    /// \~english Slow down: the peer is asking for too much.
    /// \~spanish Mas despacio: el otro extremo pide demasiado.  \~
    EnhanceYourCalm = 0x0B,
    InadequateSecurity = 0x0C,
    Http11Required = 0x0D,
};

/**
 * @brief
 * \~english The nine bytes at the front of a frame, read out.
 * \~spanish Los nueve bytes de delante de una trama, leidos.
 * \~
 */
struct FrameHeader {
    /// \~english How many bytes of payload follow.  Twenty-four bits.
    /// \~spanish Cuantos bytes de carga van detras.  Veinticuatro bits.  \~
    uint32_t length;
    /// \~english Which stream it belongs to.  Thirty-one bits; zero is the connection.
    /// \~spanish De que flujo es.  Treinta y un bits; el cero es la conexion.  \~
    uint32_t stream_id;
    /// \~english What it is for.  \~spanish Para que es.  \~
    uint8_t type;
    /// \~english What it carries.  \~spanish Que lleva.  \~
    uint8_t flags;

    /// \~english Whether @p f is set.  \~spanish Si @p f esta puesta.  \~
    bool has(FrameFlag f) const noexcept { return (flags & f) != 0; }

    /// \~english Whether it is of a type this codec knows.
    /// \~spanish Si es de un tipo que este codec conoce.  \~
    bool known() const noexcept {
        return type <= static_cast<uint8_t>(FrameType::Continuation);
    }
};

static_assert(sizeof(FrameHeader) == 12,
              "a frame header must stay small: a connection reads one per "
              "frame and a busy one reads thousands a second");

/**
 * @brief
 * \~english Reads the nine bytes at @p p into @p out.
 * \~spanish Lee los nueve bytes de @p p en @p out.
 * \~
 *
 * \~english
 * There must be nine bytes there; the caller checks that.  It cannot fail on
 * the content: any nine bytes are a syntactically valid frame header, and
 * whether the header makes sense is @c validate_frame's question.  Splitting
 * the two is what lets a refusal say which rule was broken.
 *
 * The reserved bit at the top of the stream identifier is dropped rather than
 * refused.  The specification says to ignore it on receipt, and it is worth
 * saying why that is not leniency: the bit is reserved for a use nobody has
 * defined yet, so a recipient that refused would be refusing a message that a
 * later version makes legal.
 *
 * \~spanish
 * Tiene que haber nueve bytes ahi; eso lo comprueba quien llama.  No puede
 * fallar por el contenido: cualesquiera nueve bytes son una cabecera de trama
 * sintacticamente valida, y si la cabecera tiene sentido es la pregunta de
 * @c validate_frame.  Partir las dos cosas es lo que permite que un rechazo
 * diga que regla se rompio.
 *
 * El bit reservado de arriba del identificador de flujo se descarta en vez de
 * rechazarse.  La especificacion dice que se ignore al recibir, y merece decir
 * por que eso no es permisividad: el bit esta reservado para un uso que nadie
 * ha definido, asi que quien recibe y rechazara estaria rechazando un mensaje
 * que una version posterior hace legal.
 *
 * \~
 * @param p   \~english at least nine bytes  \~spanish al menos nueve bytes  \~
 * @param out \~english where the header goes  \~spanish donde va la cabecera  \~
 */
void decode_frame_header(const uint8_t *p, FrameHeader &out) noexcept;

/**
 * @brief
 * \~english Writes @p h as nine bytes into @p p.
 * \~spanish Escribe @p h como nueve bytes en @p p.
 * \~
 * @param p \~english at least nine bytes of room
 *          \~spanish al menos nueve bytes de sitio  \~
 * @param h \~english the header  \~spanish la cabecera  \~
 */
void encode_frame_header(uint8_t *p, const FrameHeader &h) noexcept;

/**
 * @brief
 * \~english Whether @p h is a frame that could exist, and why not.
 * \~spanish Si @p h es una trama que podria existir, y por que no.
 * \~
 *
 * \~english
 * Three rules, from RFC 9113 section 6, and they are checked before a byte of
 * payload is looked at:
 *
 *  - **the length**, against what this server said it would accept.  A frame
 *    larger than that is refused without reading it, which is the point: the
 *    alternative is buffering it first to find out it was too big.
 *  - **the stream**.  Some frames are about the connection and must be on
 *    stream zero; others are about a stream and must not be.  A SETTINGS on a
 *    stream is not a settings frame that got misfiled -- it is a peer whose
 *    idea of the connection differs from this one's.
 *  - **the size, for the frames that have one**.  A RST_STREAM is four bytes
 *    because it is an error code, and one that is three is a frame whose error
 *    code would have to be read from somewhere it is not.
 *
 * An unknown type passes all three.  It has to: the rule that a recipient
 * ignores what it does not know is how the protocol gets extended, and the
 * length and stream rules of a frame nobody has defined are not knowable.
 *
 * \~spanish
 * Tres reglas, del RFC 9113 seccion 6, y se comprueban antes de mirar un byte
 * de carga:
 *
 *  - **la longitud**, contra lo que este servidor dijo que aceptaria.  Una
 *    trama mayor se rechaza sin leerla, que es de lo que se trata: la
 *    alternativa es guardarla entera para averiguar que era demasiado grande.
 *  - **el flujo**.  Algunas tramas son de la conexion y tienen que ir en el
 *    flujo cero; otras son de un flujo y no pueden ir ahi.  Una SETTINGS en un
 *    flujo no es una trama de ajustes mal archivada -- es un extremo cuya idea
 *    de la conexion difiere de la de este.
 *  - **el tamano, en las tramas que tienen uno**.  Una RST_STREAM mide cuatro
 *    bytes porque es un codigo de error, y una que mida tres es una trama cuyo
 *    codigo de error habria que leer de donde no esta.
 *
 * Un tipo desconocido pasa las tres.  Tiene que hacerlo: la regla de que quien
 * recibe ignora lo que no conoce es como se extiende el protocolo, y la
 * longitud y el flujo de una trama que nadie ha definido no se pueden saber.
 *
 * \~
 * @param h      \~english the header  \~spanish la cabecera  \~
 * @param limits \~english what this connection accepts
 *               \~spanish lo que acepta esta conexion  \~
 * @return       \~english @c NoError, or why not
 *               \~spanish @c NoError, o por que no  \~
 */
ErrorCode validate_frame(const FrameHeader &h, const Limits &limits) noexcept;

/**
 * @brief
 * \~english The name of @p type, for a message a human reads.
 * \~spanish El nombre de @p type, para un mensaje que lee una persona.
 * \~
 * @param type \~english the type byte  \~spanish el byte del tipo  \~
 * @return     \~english its name, or "UNKNOWN"  \~spanish su nombre, o "UNKNOWN"  \~
 */
const char *frame_type_name(uint8_t type) noexcept;

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_FRAME_H
