/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h1_parser.h
 * @brief
 * \~english Reading the head of an HTTP/1.1 message, one byte at a time, once.
 * \~spanish Leer la cabeza de un mensaje HTTP/1.1, byte a byte, una vez.
 * \~
 *
 * \~english
 * Two properties shape this parser, and neither is about speed for its own
 * sake.
 *
 * **It reads each byte once and never goes back** (R12).  A message arrives
 * across several reads, so a parser that started over each time would do work
 * proportional to the square of the message -- and the message's size is
 * chosen by whoever is sending it, which turns slowness into a way of taking
 * the server down.  So it is a state machine that remembers where it stopped,
 * and resuming means carrying on from that byte.  The buffer's offsets survive
 * growing and sliding, which is what makes that possible.
 *
 * **It refuses everything the grammar does not allow.**  Not out of rigour:
 * HTTP/1.1 is a text protocol read by chains of servers, and a request that
 * two of them read differently is a request one of them serves and the other
 * never saw.  Every leniency below was somebody's compatibility fix and later
 * somebody else's vulnerability -- the line folded across two lines, the space
 * before the colon, the line ending without its carriage return.  The ones
 * that can still be wanted are here as options, off by default; the ones whose
 * only use is to disagree with a neighbour are not here at all.
 *
 * \~spanish
 * Dos propiedades dan forma a este analizador, y ninguna es velocidad por la
 * velocidad.
 *
 * **Lee cada byte una vez y no vuelve atras** (R12).  Un mensaje llega en
 * varias lecturas, asi que un analizador que empezara de cero cada vez haria
 * trabajo proporcional al cuadrado del mensaje -- y el tamano del mensaje lo
 * elige quien lo manda, lo que convierte la lentitud en una forma de tirar el
 * servidor.  Asi que es una maquina de estados que recuerda donde se paro, y
 * reanudar es seguir por ese byte.  Los desplazamientos del buffer sobreviven a
 * crecer y a deslizar, que es lo que lo hace posible.
 *
 * **Rechaza todo lo que la gramatica no permite.**  No por rigor: HTTP/1.1 es
 * un protocolo de texto que leen cadenas de servidores, y una peticion que dos
 * de ellos lean distinto es una peticion que uno sirve y el otro no vio nunca.
 * Cada permisividad de abajo fue el arreglo de compatibilidad de alguien y
 * despues la vulnerabilidad de algun otro -- la cabecera partida en dos lineas,
 * el espacio antes de los dos puntos, el fin de linea sin su retorno de carro.
 * Las que todavia se pueden querer estan como opciones, apagadas por defecto;
 * las que solo sirven para discrepar del vecino no estan.
 *
 * \~
 */
#ifndef HTTP_VX_H1_PARSER_H
#define HTTP_VX_H1_PARSER_H

#include "http_vx/h1_limits.h"
#include "http_vx/message.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h1 {

/**
 * @brief
 * \~english Why the head was refused.
 * \~spanish Por que se rechazo la cabeza.
 * \~
 *
 * \~english
 * The reasons are told apart because they are not degrees of one failure: they
 * answer different codes, and three of them mean the connection cannot be
 * reused whatever is answered.  A parser that returned one flag would force
 * every caller to guess which, and the guesses would not agree.
 *
 * \~spanish
 * Los motivos se distinguen porque no son grados de un mismo fallo: contestan
 * codigos distintos, y tres de ellos quieren decir que la conexion no se puede
 * reutilizar se conteste lo que se conteste.  Un analizador que devolviera una
 * bandera obligaria a cada llamante a adivinar cual, y las conjeturas no
 * coincidirian.
 *
 * \~
 */
enum class ParseError : uint8_t {
    /// \~english Nothing is wrong.  \~spanish No pasa nada.  \~
    None = 0,

    /**
     * \~english
     * The request line is not three parts separated by one space each.  More
     * than one space is refused on purpose: a target that may contain a space
     * is a target that the next server in the chain reads as a different
     * request line.
     * \~spanish
     * La linea de peticion no son tres partes separadas por un espacio cada
     * una.  Mas de un espacio se rechaza a proposito: un destino que pueda
     * llevar un espacio es un destino que el servidor siguiente de la cadena
     * lee como otra linea de peticion.
     * \~
     */
    BadRequestLine,

    /// \~english The method is not a token, or is empty.
    /// \~spanish El metodo no es un token, o esta vacio.  \~
    BadMethod,

    /// \~english The target is empty or carries a byte it may not.
    /// \~spanish El destino esta vacio o lleva un byte que no puede.  \~
    BadTarget,

    /// \~english What follows the target is not an HTTP version.
    /// \~spanish Lo que sigue al destino no es una version de HTTP.  \~
    BadVersion,

    /**
     * \~english
     * It IS a version, and not one this codec speaks.  Told apart from
     * @c BadVersion because it answers 505 and not 400: the message is well
     * formed and the disagreement is about which protocol, which is worth
     * saying rather than calling the request broken.
     * \~spanish
     * SI es una version, y no una que hable este codec.  Se distingue de
     * @c BadVersion porque contesta 505 y no 400: el mensaje esta bien formado
     * y la discrepancia es sobre que protocolo, que merece decirse en vez de
     * llamar rota a la peticion.
     * \~
     */
    UnsupportedVersion,

    /// \~english A field name is not a token.
    /// \~spanish Un nombre de cabecera no es un token.  \~
    BadFieldName,

    /// \~english A field value carries a byte it may not.
    /// \~spanish Un valor de cabecera lleva un byte que no puede.  \~
    BadFieldValue,

    /**
     * \~english
     * Whitespace between a field name and its colon.  It must be refused, not
     * trimmed: a recipient that trims reads `Content-Length : 5` as a length
     * and one that does not reads it as a field nobody knows, and between the
     * two of them the body ends in two places.
     * \~spanish
     * Espacio entre un nombre de cabecera y sus dos puntos.  Hay que
     * rechazarlo, no recortarlo: quien recorta lee `Content-Length : 5` como
     * una longitud y quien no lo hace lo lee como una cabecera que nadie
     * conoce, y entre los dos el cuerpo acaba en dos sitios.
     * \~
     */
    SpaceBeforeColon,

    /**
     * \~english
     * A field line continued on the next one by starting it with whitespace.
     * The specification deprecated it and requires a server to refuse it, for
     * the same reason: it is a second way of writing a value, and two ways of
     * writing a value is two values.
     * \~spanish
     * Una cabecera continuada en la linea siguiente empezandola con espacio.
     * La especificacion lo retiro y obliga a un servidor a rechazarlo, por la
     * misma razon: es una segunda forma de escribir un valor, y dos formas de
     * escribir un valor son dos valores.
     * \~
     */
    ObsoleteLineFolding,

    /**
     * \~english
     * A line ended with a line feed and no carriage return before it.  Some
     * servers accept it, which is exactly the problem: a message written with
     * both kinds of ending is read as one message by them and as two by
     * anything stricter.
     * \~spanish
     * Una linea acabo en salto de linea sin retorno de carro delante.  Algunos
     * servidores lo aceptan, que es justo el problema: un mensaje escrito con
     * las dos clases de final lo leen ellos como un mensaje y cualquier cosa
     * mas estricta como dos.
     * \~
     */
    BareLineFeed,

    /// \~english A carriage return with something other than a line feed after it.
    /// \~spanish Un retorno de carro con algo que no es un salto de linea detras.  \~
    BareCarriageReturn,

    /// \~english The request line is longer than allowed.  Answers 414.
    /// \~spanish La linea de peticion es mas larga de lo permitido.  Contesta 414.  \~
    RequestLineTooLong,

    /// \~english The field section is larger than allowed.  Answers 431.
    /// \~spanish La seccion de cabeceras es mayor de lo permitido.  Contesta 431.  \~
    HeadersTooLarge,

    /// \~english There are more fields than allowed.  Answers 431.
    /// \~spanish Hay mas cabeceras de las permitidas.  Contesta 431.  \~
    TooManyFields,

    /**
     * \~english
     * An HTTP/1.1 request without a `Host`.  The specification requires one
     * and requires a server to refuse a request that lacks it, because without
     * it there is no saying which of the sites on this address was meant.
     * \~spanish
     * Una peticion HTTP/1.1 sin `Host`.  La especificacion exige una y exige
     * que un servidor rechace la peticion que no la lleve, porque sin ella no
     * hay forma de decir cual de los sitios de esta direccion se pedia.
     * \~
     */
    MissingHost,

    /// \~english More than one `Host`, which names two sites.
    /// \~spanish Mas de un `Host`, que nombra dos sitios.  \~
    MultipleHosts,
};

/**
 * @brief
 * \~english How far the parser got.
 * \~spanish Hasta donde llego el analizador.
 * \~
 */
enum class ParseResult : uint8_t {
    /// \~english The head is not all here yet.  Read more and call again.
    /// \~spanish La cabeza todavia no esta entera.  Leer mas y volver a llamar.  \~
    NeedMore,
    /// \~english The head is complete.  \~spanish La cabeza esta completa.  \~
    Done,
    /// \~english It is not a message this can read.  \~spanish No es un mensaje que esto pueda leer.  \~
    Error,
};

/**
 * @brief
 * \~english Reads the head of one request.
 * \~spanish Lee la cabeza de una peticion.
 * \~
 *
 * \~english
 * One parser serves one message.  A connection that serves several calls
 * @c reset between them, which costs nothing and is what keeps the position
 * from the previous message out of the next one.
 *
 * \~spanish
 * Un analizador sirve un mensaje.  Una conexion que sirva varios llama a
 * @c reset entre ellos, que no cuesta nada y es lo que mantiene la posicion del
 * mensaje anterior fuera del siguiente.
 *
 * \~
 */
class RequestParser {
  public:
    RequestParser() noexcept = default;
    explicit RequestParser(const Limits &limits) noexcept : limits_(limits) {}

    /**
     * @brief
     * \~english Reads what is there, and says whether that was enough.
     * \~spanish Lee lo que hay, y dice si eso bastaba.
     * \~
     *
     * \~english
     * It is called again with MORE of the same message each time -- the whole
     * live region of the buffer, not only what is new -- and it carries on
     * from where it stopped.  Handing it only the new bytes would be handing
     * it a message that starts in the middle.
     *
     * And it must be the same @p out every time.  Each piece is written into
     * it as it completes, so a different one would be a request with its
     * earlier pieces missing.
     *
     * The scheme is not filled in.  HTTP/1.1 does not write it, and the only
     * thing that knows whether this connection is `http` or `https` is the
     * connection -- so it sets it, and doing it here would be guessing.
     *
     * \~spanish
     * Se le vuelve a llamar con MAS del mismo mensaje cada vez -- la region
     * viva entera del buffer, no solo lo nuevo -- y sigue por donde se paro.
     * Darle solo los bytes nuevos seria darle un mensaje que empieza por la
     * mitad.
     *
     * Y tiene que ser el mismo @p out todas las veces.  Cada pieza se escribe
     * en el segun se completa, asi que otro seria una peticion a la que le
     * faltan las piezas de antes.
     *
     * El esquema no se rellena.  HTTP/1.1 no lo escribe, y lo unico que sabe si
     * esta conexion es `http` o `https` es la conexion -- asi que lo pone ella,
     * y hacerlo aqui seria adivinar.
     *
     * \~
     * @param data \~english the message's first byte, which is
     *             @c Buffer::data()
     *             \~spanish el primer byte del mensaje, que es
     *             @c Buffer::data()  \~
     * @param size \~english how many bytes are there  \~spanish cuantos bytes hay  \~
     * @param out  \~english where the pieces go  \~spanish donde van las piezas  \~
     * @return     \~english how far it got  \~spanish hasta donde llego  \~
     */
    ParseResult parse(const uint8_t *data, size_t size, Request &out) noexcept;

    /// \~english Why it was refused, when it was.  \~spanish Por que se rechazo, cuando se rechazo.  \~
    ParseError error() const noexcept { return error_; }

    /**
     * @brief
     * \~english How many bytes the head took.
     * \~spanish Cuantos bytes ocupo la cabeza.
     * \~
     *
     * \~english
     * An offset from the bytes this was given, not a position in the
     * connection, and it is named for what it is so that it cannot be
     * mistaken for the other.  The readers that consume as they go count
     * from the start of the CONNECTION, because what they produce dies
     * immediately and the bytes behind it can be dropped; this one counts
     * from the message, because what it produces -- the request -- stays
     * alive while the handler uses it, and those bytes cannot be dropped
     * until it is done.
     *
     * So it is where the body starts, measured from where the head did.
     *
     * \~spanish
     * Un desplazamiento desde los bytes que se le dieron, no una posicion en
     * la conexion, y se llama por lo que es para que no se pueda confundir
     * con la otra.  Los lectores que consumen segun avanzan cuentan desde el
     * principio de la CONEXION, porque lo que producen muere en el acto y
     * los bytes de detras se pueden descartar; este cuenta desde el mensaje,
     * porque lo que produce -- la peticion -- sigue vivo mientras el
     * manejador la usa, y esos bytes no se pueden descartar hasta que
     * termine.
     *
     * Asi que es donde empieza el cuerpo, medido desde donde empezo la
     * cabeza.
     *
     * \~
     */
    size_t head_size() const noexcept { return pos_; }

    /// \~english Makes it ready for the next message.
    /// \~spanish Lo deja listo para el mensaje siguiente.  \~
    void reset() noexcept;

  private:
    /**
     * \~english
     * Where in the head the reading is.  Each one scans forward over the bytes
     * that belong to it and validates them as it goes, so no byte is looked at
     * twice.
     * \~spanish
     * Por donde va la lectura de la cabeza.  Cada uno recorre hacia delante los
     * bytes que le pertenecen y los valida por el camino, asi que ningun byte
     * se mira dos veces.
     * \~
     */
    enum class State : uint8_t {
        Start,
        StartLf,
        Method,
        Target,
        VersionText,
        RequestLineLf,
        FieldStart,
        FieldName,
        FieldValueStart,
        FieldValue,
        FieldLf,
        SectionLf,
        Done,
        Failed,
    };

    /**
     * \~english
     * Refusing, which is called from a dozen places inside the state machine
     * and taken by none of them in an ordinary request.  Out of line and cold
     * so that those dozen call sites stay a call each instead of a copy each:
     * the switch is the only hot loop in the whole parse, and what it costs is
     * measured in how much of it fits in the instruction cache.
     *
     * \~spanish
     * Rechazar, que se llama desde una docena de sitios de la maquina de
     * estados y no lo coge ninguno en una peticion corriente.  Fuera de linea y
     * en frio para que esa docena de sitios sean una llamada cada uno y no una
     * copia cada uno: el switch es el unico bucle caliente de todo el analisis,
     * y lo que cuesta se mide en cuanto de el cabe en la cache de
     * instrucciones.
     * \~
     */
    [[gnu::noinline, gnu::cold]] ParseResult fail(ParseError e) noexcept;

    ParseResult finish(Request &out) noexcept;

    Limits limits_;
    State state_ = State::Start;
    ParseError error_ = ParseError::None;

    /// \~english How far it has read.  \~spanish Hasta donde ha leido.  \~
    size_t pos_ = 0;
    /// \~english Where the piece being read started.
    /// \~spanish Donde empezo la pieza que se esta leyendo.  \~
    size_t mark_ = 0;
    /**
     * \~english
     * Where the request line started, which is not always zero: an empty line
     * before it is allowed to be skipped, and the length limit has to be
     * measured from the line and not from whatever came before it.
     * \~spanish
     * Donde empezo la linea de peticion, que no siempre es cero: se puede
     * permitir saltarse una linea vacia antes, y el limite de longitud hay que
     * medirlo desde la linea y no desde lo que viniera antes.
     * \~
     */
    size_t line_start_ = 0;
    /// \~english Where the field section started.
    /// \~spanish Donde empezo la seccion de cabeceras.  \~
    size_t fields_start_ = 0;

    uint32_t name_off_ = 0;
    uint16_t name_len_ = 0;
    FieldId name_id_ = FieldId::Unknown;
    uint16_t field_count_ = 0;

    /**
     * \~english
     * The version is eight bytes at most, so it is collected here as it
     * arrives rather than looked at again once the line ends.  Copying a byte
     * is not re-reading the buffer, which is what R12 is about.
     * \~spanish
     * La version mide ocho bytes como mucho, asi que se recoge aqui segun llega
     * en vez de mirarla otra vez al acabar la linea.  Copiar un byte no es
     * volver a leer el buffer, que es de lo que habla R12.
     * \~
     */
    char version_[8] = {};
    uint8_t version_len_ = 0;
};

} // namespace h1
} // namespace http_vx

#endif // HTTP_VX_H1_PARSER_H
