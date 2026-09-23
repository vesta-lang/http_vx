/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/frame.cpp
 * @brief
 * \~english The frame header, and the rules a frame obeys on its own.
 * \~spanish La cabecera de trama, y las reglas que cumple una trama por su cuenta.
 * \~
 */

#include "http_vx/h2_frame.h"

namespace http_vx {
namespace h2 {

const uint8_t kClientPreface[24] = {'P',  'R',  'I',  ' ',  '*',  ' ',
                                    'H',  'T',  'T',  'P',  '/',  '2',
                                    '.',  '0',  '\r', '\n', '\r', '\n',
                                    'S',  'M',  '\r', '\n', '\r', '\n'};

namespace {

/**
 * @brief
 * \~english Where a frame of this type may live.
 * \~spanish Donde puede vivir una trama de este tipo.
 * \~
 *
 * \~english
 * Stream zero is the connection itself and not a stream with a small number.
 * That is why this is a rule and not a range check: a frame about the
 * connection carried on a stream, or one about a stream carried on the
 * connection, is not a frame in the wrong place -- it is a peer describing a
 * different connection than the one it is on.
 *
 * \~spanish
 * El flujo cero es la conexion misma y no un flujo con un numero pequeno.  Por
 * eso esto es una regla y no una comprobacion de rango: una trama de la
 * conexion llevada por un flujo, o una de un flujo llevada por la conexion, no
 * es una trama en el sitio equivocado -- es un extremo describiendo una
 * conexion distinta de aquella en la que esta.
 *
 * \~
 */
enum class Where : uint8_t {
    /// \~english On the connection, and only there.
    /// \~spanish En la conexion, y solo ahi.  \~
    Connection,
    /// \~english On a stream, and only there.
    /// \~spanish En un flujo, y solo ahi.  \~
    Stream,
};

/**
 * @brief
 * \~english One row: what a frame of this type must look like.
 * \~spanish Una fila: que aspecto tiene que tener una trama de este tipo.
 * \~
 */
struct TypeRow {
    const char *name;
    Where where;
    /// \~english Exactly this many bytes, or zero for "it varies".
    /// \~spanish Exactamente estos bytes, o cero para "varia".  \~
    uint32_t exact;
    /// \~english A whole number of these, or zero for "it varies".
    /// \~spanish Un numero entero de estos, o cero para "varia".  \~
    uint32_t multiple;
};

/**
 * @brief
 * \~english The table, indexed by the type byte.
 * \~spanish La tabla, indexada por el byte del tipo.
 * \~
 *
 * \~english
 * The order MUST match the wire values, because the type IS the index -- which
 * it can be here, unlike in the field and method tables, because these numbers
 * are the protocol's rather than this project's.
 *
 * \~spanish
 * El orden DEBE coincidir con los valores del cable, porque el tipo ES el
 * indice -- cosa que aqui puede ser, al reves que en las tablas de cabeceras y
 * metodos, porque estos numeros son del protocolo y no de este proyecto.
 *
 * \~
 */
constexpr TypeRow kTypes[] = {
    // DATA: the body of a message.  Any size, on a stream.
    // DATA: el cuerpo de un mensaje.  Cualquier tamano, en un flujo.
    {"DATA", Where::Stream, 0, 0},

    // HEADERS: the fields, compressed.  Any size, on a stream.
    // HEADERS: las cabeceras, comprimidas.  Cualquier tamano, en un flujo.
    {"HEADERS", Where::Stream, 0, 0},

    /* \~english
     * PRIORITY: five bytes, and RFC 9113 deprecated what they mean.  The frame
     * is still read and still validated, because a peer may still send it and
     * a recipient that choked on it would be refusing a legal message; what is
     * not done is acting on it.
     * \~spanish
     * PRIORITY: cinco bytes, y el RFC 9113 retiro lo que significan.  La trama
     * se sigue leyendo y se sigue validando, porque un extremo todavia puede
     * mandarla y quien se atragantara con ella estaria rechazando un mensaje
     * legal; lo que no se hace es actuar sobre ella.
     * \~ */
    {"PRIORITY", Where::Stream, 5, 0},

    // RST_STREAM: four bytes, which are an error code.
    // RST_STREAM: cuatro bytes, que son un codigo de error.
    {"RST_STREAM", Where::Stream, 4, 0},

    // SETTINGS: pairs of an identifier and a value, six bytes each.
    // SETTINGS: parejas de identificador y valor, seis bytes cada una.
    {"SETTINGS", Where::Connection, 0, 6},

    // PUSH_PROMISE: a stream identifier and a header block.
    // PUSH_PROMISE: un identificador de flujo y un bloque de cabeceras.
    {"PUSH_PROMISE", Where::Stream, 0, 0},

    // PING: eight bytes that come back unchanged.
    // PING: ocho bytes que vuelven sin cambiar.
    {"PING", Where::Connection, 8, 0},

    // GOAWAY: the last stream, an error code, and anything it wants to say.
    // GOAWAY: el ultimo flujo, un codigo de error, y lo que quiera decir.
    {"GOAWAY", Where::Connection, 0, 0},

    /* \~english
     * WINDOW_UPDATE: four bytes.  It is the one frame that is legal in both
     * places and means something different in each -- on the connection it is
     * about the connection's window, on a stream about that stream's -- so it
     * is the reason @c Where has no third value: giving it one would make the
     * table say "anywhere" for the only frame where the place is the meaning.
     * \~spanish
     * WINDOW_UPDATE: cuatro bytes.  Es la unica trama legal en los dos sitios y
     * que significa algo distinto en cada uno -- en la conexion habla de la
     * ventana de la conexion, en un flujo de la de ese flujo -- asi que es la
     * razon de que @c Where no tenga un tercer valor: darselo haria que la
     * tabla dijera "en cualquier sitio" para la unica trama en la que el sitio
     * ES el significado.
     * \~ */
    {"WINDOW_UPDATE", Where::Connection, 4, 0},

    // CONTINUATION: more of a header block.  Any size, on a stream.
    // CONTINUATION: mas de un bloque de cabeceras.  Cualquier tamano, en un flujo.
    {"CONTINUATION", Where::Stream, 0, 0},
};

constexpr size_t kTypeCount = sizeof(kTypes) / sizeof(kTypes[0]);

static_assert(kTypeCount == static_cast<size_t>(FrameType::Continuation) + 1,
              "the frame table and FrameType disagree: every type needs "
              "exactly one row, at its own wire value");

/**
 * @brief
 * \~english Reads a big-endian number of @p n bytes.
 * \~spanish Lee un numero big-endian de @p n bytes.
 * \~
 *
 * \~english
 * Byte by byte rather than by reading a word and swapping it.  The header is
 * nine bytes and its fields are three and four long and not aligned to
 * anything, so a word read would be unaligned and a swap would still be
 * needed; this way there is nothing to get wrong on a machine of either
 * byte order.
 *
 * \~spanish
 * Byte a byte y no leyendo una palabra y dandole la vuelta.  La cabecera mide
 * nueve bytes y sus campos miden tres y cuatro y no estan alineados a nada, asi
 * que una lectura de palabra estaria desalineada y seguiria haciendo falta
 * darle la vuelta; asi no hay nada que errar en una maquina de cualquiera de
 * los dos ordenes de byte.
 *
 * \~
 */
inline uint32_t be24(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
}

inline uint32_t be32(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

} // namespace

void decode_frame_header(const uint8_t *p, FrameHeader &out) noexcept {
    out.length = be24(p);
    out.type = p[3];
    out.flags = p[4];

    /* \~english
     * The top bit of the identifier is reserved, and the specification says to
     * ignore it on receipt.  Masking it off rather than refusing is not
     * leniency: the bit is reserved for a use nobody has defined, so refusing
     * would be refusing a message a later version makes legal -- and a stream
     * identifier with it left in is a number two thousand million larger than
     * the one the peer meant.
     *
     * \~spanish
     * El bit de arriba del identificador esta reservado, y la especificacion
     * dice que se ignore al recibir.  Quitarlo con una mascara en vez de
     * rechazar no es permisividad: el bit esta reservado para un uso que nadie
     * ha definido, asi que rechazar seria rechazar un mensaje que una version
     * posterior hace legal -- y un identificador de flujo con el puesto es un
     * numero dos mil millones mayor que el que queria decir el otro extremo.
     * \~ */
    out.stream_id = be32(p + 5) & 0x7FFFFFFFu;
}

void encode_frame_header(uint8_t *p, const FrameHeader &h) noexcept {
    p[0] = static_cast<uint8_t>((h.length >> 16) & 0xFF);
    p[1] = static_cast<uint8_t>((h.length >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>(h.length & 0xFF);
    p[3] = h.type;
    p[4] = h.flags;

    /* \~english
     * And the reserved bit goes out clear, whatever was in the identifier.
     * Writing it set would be claiming a meaning nobody has defined.
     * \~spanish
     * Y el bit reservado sale a cero, hubiera lo que hubiera en el
     * identificador.  Escribirlo puesto seria reclamar un significado que nadie
     * ha definido.
     * \~ */
    const uint32_t id = h.stream_id & 0x7FFFFFFFu;
    p[5] = static_cast<uint8_t>((id >> 24) & 0xFF);
    p[6] = static_cast<uint8_t>((id >> 16) & 0xFF);
    p[7] = static_cast<uint8_t>((id >> 8) & 0xFF);
    p[8] = static_cast<uint8_t>(id & 0xFF);
}

const char *frame_type_name(uint8_t type) noexcept {
    if (type >= kTypeCount) return "UNKNOWN";
    return kTypes[type].name;
}

ErrorCode validate_frame(const FrameHeader &h, const Limits &limits) noexcept {
    /* \~english
     * The length first, and against what this server announced rather than
     * against what the format allows.  A frame larger than that is refused
     * from its header, without reading the payload -- which is the whole
     * reason the length is in the header and not at the end.
     *
     * \~spanish
     * La longitud primero, y contra lo que anuncio este servidor y no contra lo
     * que permite el formato.  Una trama mayor se rechaza desde su cabecera,
     * sin leer la carga -- que es toda la razon de que la longitud vaya en la
     * cabecera y no al final.
     * \~ */
    if (h.length > limits.max_frame_size) return ErrorCode::FrameSizeError;

    /* \~english
     * A type nobody has defined passes everything else.  The rule that a
     * recipient ignores what it does not know is how this protocol gets
     * extended, and the length and stream rules of a frame that does not exist
     * yet are not knowable -- so checking them would be inventing them.
     *
     * \~spanish
     * Un tipo que nadie ha definido pasa todo lo demas.  La regla de que quien
     * recibe ignora lo que no conoce es como se extiende este protocolo, y la
     * longitud y el flujo de una trama que todavia no existe no se pueden
     * saber -- asi que comprobarlos seria inventarlos.
     * \~ */
    if (!h.known()) return ErrorCode::NoError;

    const TypeRow &row = kTypes[h.type];

    /* \~english
     * WINDOW_UPDATE is the one frame that belongs in both places, so it is the
     * one exception to the table's rule -- and it is written here rather than
     * as a third value in @c Where, because the place is what the frame MEANS
     * and a table that said "anywhere" would be hiding that.
     *
     * \~spanish
     * WINDOW_UPDATE es la unica trama que va en los dos sitios, asi que es la
     * unica excepcion a la regla de la tabla -- y se escribe aqui y no como un
     * tercer valor de @c Where, porque el sitio es lo que la trama SIGNIFICA y
     * una tabla que dijera "en cualquier sitio" lo estaria escondiendo.
     * \~ */
    if (h.type != static_cast<uint8_t>(FrameType::WindowUpdate)) {
        const bool on_connection = h.stream_id == 0;
        const bool wants_connection = row.where == Where::Connection;
        if (on_connection != wants_connection) return ErrorCode::ProtocolError;
    }

    if (row.exact != 0 && h.length != row.exact)
        return ErrorCode::FrameSizeError;

    if (row.multiple != 0 && h.length % row.multiple != 0)
        return ErrorCode::FrameSizeError;

    /* \~english
     * An acknowledgement carries nothing, and one that carries something is
     * not an acknowledgement with extra bytes -- it is a peer answering a
     * question this connection did not ask, with a payload that would be read
     * as settings if the flag were missed.
     *
     * \~spanish
     * Un acuse de recibo no lleva nada, y uno que lleva algo no es un acuse con
     * bytes de mas -- es un extremo contestando una pregunta que esta conexion
     * no hizo, con una carga que se leeria como ajustes si se pasara por alto
     * la bandera.
     * \~ */
    if (h.type == static_cast<uint8_t>(FrameType::Settings) &&
        (h.flags & kAck) != 0 && h.length != 0)
        return ErrorCode::FrameSizeError;

    return ErrorCode::NoError;
}

} // namespace h2
} // namespace http_vx
