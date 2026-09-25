/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_packet.h
 * @brief
 * \~english The part of a QUIC packet that can be read before it is decrypted.
 * \~spanish La parte de un paquete QUIC que se puede leer antes de descifrarlo.
 * \~
 *
 * \~english
 * RFC 8999 (what never changes between versions) and RFC 9000, section 17 (what
 * version 1 adds on top).  This is the first thing QUIC does with a datagram,
 * and it stops at a precise place: **where the packet number starts.**
 *
 * Everything after that point is under header protection -- the low bits of
 * the first byte and the packet number itself are masked with bytes derived
 * from the encrypted payload -- so they cannot be read until the keys are
 * known.  A parser that went further would be reading ciphertext as if it were
 * a length.  What this produces instead is exactly what the next step needs:
 * which keys to try, where the protected part begins, and where this packet
 * ENDS -- because a datagram may carry several.
 *
 * **Coalescing is the reason a size matters.**  A client's first datagram
 * commonly carries an Initial and a Handshake packet back to back, and the
 * only thing that says where one stops is the Length field.  A parser that
 * assumed one packet per datagram would decrypt the second packet's header as
 * the first packet's payload, fail authentication, and drop both -- silently,
 * because a packet that fails authentication is supposed to be dropped
 * silently.
 *
 * **And three limits are enforced here rather than later, all three for the
 * same reason: past this point the bytes are decrypted, and decryption is the
 * expensive part.**  A packet that claims more bytes than the datagram has, a
 * connection ID longer than version 1 allows, or a payload too short to take
 * the header-protection sample from, is dropped before any key is touched.
 * The last one is not a nicety: the sample is read at a fixed distance past
 * the packet number, and a packet shorter than that would have it read past
 * the end of the packet.
 *
 * \~spanish
 * RFC 8999 (lo que no cambia nunca entre versiones) y RFC 9000, seccion 17 (lo
 * que anade encima la version 1).  Es lo primero que hace QUIC con un datagrama,
 * y se para en un sitio exacto: **donde empieza el numero de paquete.**
 *
 * Todo lo que va detras esta bajo la proteccion de cabecera -- los bits bajos
 * del primer byte y el propio numero de paquete se enmascaran con bytes sacados
 * de la carga cifrada -- asi que no se pueden leer hasta tener las claves.  Un
 * analizador que siguiera leeria texto cifrado como si fuera una longitud.  Lo
 * que produce en su lugar es justo lo que necesita el paso siguiente: que
 * claves probar, donde empieza la parte protegida, y donde ACABA este paquete
 * -- porque un datagrama puede llevar varios.
 *
 * **Por eso importa el tamano: los paquetes van pegados.**  El primer datagrama
 * de un cliente lleva muchas veces un Initial y un Handshake seguidos, y lo
 * unico que dice donde acaba uno es el campo Length.  Un analizador que diera
 * por hecho un paquete por datagrama descifraria la cabecera del segundo como
 * carga del primero, fallaria la autenticacion y tiraria los dos -- en
 * silencio, porque un paquete que falla la autenticacion se tira en silencio.
 *
 * **Y aqui se hacen cumplir tres limites en vez de mas tarde, los tres por lo
 * mismo: pasado este punto los bytes se descifran, y descifrar es lo caro.**
 * Un paquete que dice tener mas bytes que el datagrama, un identificador de
 * conexion mas largo de lo que permite la version 1, o una carga demasiado
 * corta para sacar de ella la muestra de la proteccion de cabecera, se tiran
 * antes de tocar ninguna clave.  Lo ultimo no es un detalle: la muestra se lee a
 * una distancia fija detras del numero de paquete, y un paquete mas corto que
 * eso la haria leer mas alla del final del paquete.
 *
 * \~
 */
#ifndef HTTP_VX_QUIC_PACKET_H
#define HTTP_VX_QUIC_PACKET_H

#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english QUIC version 1 (RFC 9000).  \~spanish QUIC version 1 (RFC 9000).  \~
constexpr uint32_t kVersion1 = 0x00000001;

/**
 * \~english
 * QUIC version 2 (RFC 9369).  The same protocol with the long-header packet
 * types renumbered and different key-derivation constants, which exists so
 * that middleboxes cannot ossify around version 1's exact bytes.  Understood
 * here because the renumbering is in the header, and a server that took a
 * version 2 Handshake for a version 1 Retry would be wrong about every packet.
 * \~spanish
 * QUIC version 2 (RFC 9369).  El mismo protocolo con los tipos de paquete de
 * cabecera larga renumerados y otras constantes de derivacion de claves, que
 * existe para que los equipos intermedios no se oxiden alrededor de los bytes
 * exactos de la version 1.  Se entiende aqui porque la renumeracion esta en la
 * cabecera, y un servidor que tomara un Handshake de version 2 por un Retry de
 * version 1 se equivocaria en todos los paquetes.
 * \~
 */
constexpr uint32_t kVersion2 = 0x6b3343cf;

/// \~english The longest connection ID versions 1 and 2 allow.
/// \~spanish El identificador de conexion mas largo que permiten las versiones 1 y 2.  \~
constexpr size_t kMaxConnectionId = 20;

/**
 * \~english
 * The smallest datagram that may carry a client's Initial packet (RFC 9000,
 * section 14.1).  It is enforced where the DATAGRAM is known, not here, because
 * this parser is handed one packet at a time and a coalesced packet does not
 * know how large the datagram around it was.
 *
 * What it is for is amplification: a server may send at most three times what
 * it received before the client's address is validated, so a client that could
 * send a tiny Initial would make the server an amplifier.
 * \~spanish
 * El datagrama mas pequeno que puede llevar el Initial de un cliente (RFC 9000,
 * seccion 14.1).  Se hace cumplir donde se conoce el DATAGRAMA, no aqui, porque a
 * este analizador se le da un paquete cada vez y un paquete pegado a otros no
 * sabe cuanto media el datagrama que lo rodea.
 *
 * Para lo que esta es la amplificacion: un servidor puede mandar como mucho tres
 * veces lo que recibio antes de validar la direccion del cliente, asi que un
 * cliente que pudiera mandar un Initial diminuto convertiria al servidor en un
 * amplificador.
 * \~
 */
constexpr size_t kMinInitialDatagram = 1200;

/**
 * \~english
 * Where the header-protection sample starts, counted from the packet number,
 * and how long it is (RFC 9001, section 5.4.2).  The sample is taken as if the
 * packet number were four bytes long, whatever its real length, because its
 * real length is one of the things the protection hides.
 * \~spanish
 * Donde empieza la muestra de la proteccion de cabecera, contando desde el
 * numero de paquete, y cuanto mide (RFC 9001, seccion 5.4.2).  La muestra se
 * toma como si el numero de paquete midiera cuatro bytes, mida lo que mida,
 * porque su longitud real es una de las cosas que oculta la proteccion.
 * \~
 */
constexpr size_t kSampleOffset = 4;
constexpr size_t kSampleSize = 16;

/// \~english The integrity tag at the end of a Retry packet.
/// \~spanish La marca de integridad al final de un paquete Retry.  \~
constexpr size_t kRetryTagSize = 16;

/**
 * @brief
 * \~english What kind of packet it is.
 * \~spanish Que clase de paquete es.
 * \~
 */
enum class PacketType : uint8_t {
    /// \~english The first flight; its keys come from the connection ID.
    /// \~spanish El primer vuelo; sus claves salen del identificador de conexion.  \~
    Initial,
    /// \~english Early data a client sends before the handshake finishes.
    /// \~spanish Datos tempranos que manda un cliente antes de acabar el saludo.  \~
    ZeroRtt,
    Handshake,
    /// \~english A server asking the client to prove its address.
    /// \~spanish Un servidor pidiendo al cliente que demuestre su direccion.  \~
    Retry,
    /// \~english A short-header packet: everything after the handshake.
    /// \~spanish Un paquete de cabecera corta: todo lo que va tras el saludo.  \~
    OneRtt,
    /// \~english The version field is zero and what follows is a list.
    /// \~spanish El campo de version es cero y lo que sigue es una lista.  \~
    VersionNegotiation,

    /**
     * \~english
     * A long header of a version this server does not speak.  It is NOT an
     * error: it is how a new version meets an old server, and the right answer
     * is a Version Negotiation packet listing what this end does speak.  The
     * connection IDs are parsed for exactly that reason -- the answer has to
     * echo them.
     * \~spanish
     * Una cabecera larga de una version que este servidor no habla.  NO es un
     * error: es como se encuentra una version nueva con un servidor viejo, y la
     * respuesta correcta es un paquete Version Negotiation con lo que si habla
     * este extremo.  Los identificadores de conexion se analizan justamente por
     * eso -- la respuesta tiene que devolverlos.
     * \~
     */
    UnsupportedVersion,
};

/**
 * @brief
 * \~english Why a packet was dropped.
 * \~spanish Por que se tiro un paquete.
 * \~
 *
 * \~english
 * None of these are answered: a malformed packet is dropped without a word
 * (RFC 9000, section 12.2), because answering it would let anybody who can
 * forge a source address make this server talk to a victim.  They are named so
 * that the server can COUNT them -- a flood of one kind is information, and a
 * drop that nobody could see would be a server losing traffic invisibly.
 * \~spanish
 * Ninguno se contesta: un paquete mal formado se tira sin decir nada (RFC 9000,
 * seccion 12.2), porque contestarlo dejaria que cualquiera que pueda falsificar
 * una direccion de origen haga que este servidor le hable a una victima.  Tienen
 * nombre para que el servidor los pueda CONTAR -- una avalancha de una clase es
 * informacion, y un descarte que no pudiera ver nadie seria un servidor
 * perdiendo trafico sin que se note.
 * \~
 */
enum class HeaderError : uint8_t {
    None,
    /// \~english The datagram ends inside the header.
    /// \~spanish El datagrama acaba dentro de la cabecera.  \~
    Truncated,
    /// \~english The bit that must be one is zero, and nobody agreed otherwise.
    /// \~spanish El bit que tiene que ser uno es cero, y nadie acordo otra cosa.  \~
    FixedBitClear,
    /// \~english Longer than twenty bytes in a version that allows twenty.
    /// \~spanish Mas de veinte bytes en una version que permite veinte.  \~
    ConnectionIdTooLong,
    /// \~english The packet claims more bytes than the datagram has left.
    /// \~spanish El paquete dice tener mas bytes de los que quedan en el datagrama.  \~
    LengthTooLong,
    /// \~english Too short to take the header-protection sample from.
    /// \~spanish Demasiado corto para sacarle la muestra de la proteccion de cabecera.  \~
    TooShortToProtect,
    /// \~english A version list that is empty or not a whole number of versions.
    /// \~spanish Una lista de versiones vacia o que no es un numero entero de ellas.  \~
    BadVersionList,
    /// \~english Larger than any UDP datagram can be.
    /// \~spanish Mayor de lo que puede ser cualquier datagrama UDP.  \~
    DatagramTooLarge,
};

/**
 * @brief
 * \~english What the parser needs to know that the packet does not say.
 * \~spanish Lo que necesita saber el analizador que el paquete no dice.
 * \~
 */
struct HeaderContext {
    /**
     * \~english
     * How long this server's connection IDs are.  A short header does not say
     * how long its connection ID is -- saving that byte on every packet is
     * the point of a short header -- so the receiver has to know, and it can,
     * because it chose them.
     * \~spanish
     * Cuanto miden los identificadores de conexion de este servidor.  Una
     * cabecera corta no dice cuanto mide su identificador -- ahorrarse ese byte
     * en cada paquete es para lo que existe la cabecera corta -- asi que lo
     * tiene que saber quien recibe, y puede, porque los eligio el.
     * \~
     */
    size_t short_dcid_len = 8;

    /**
     * \~english
     * Whether the peer agreed that the fixed bit may be zero (RFC 9287).  Off
     * by default: until it is agreed, a zero there means the datagram is not
     * QUIC -- which is the whole reason the bit is there.
     * \~spanish
     * Si el otro extremo acordo que el bit fijo puede ser cero (RFC 9287).
     * Apagado por defecto: hasta que se acuerde, un cero ahi quiere decir que el
     * datagrama no es QUIC -- que es toda la razon de que exista el bit.
     * \~
     */
    bool fixed_bit_may_be_clear = false;
};

/**
 * @brief
 * \~english One packet's header, as far as it can be read without keys.
 * \~spanish La cabecera de un paquete, hasta donde se puede leer sin claves.
 * \~
 *
 * \~english
 * Every span is an offset from the first byte of the PACKET, which is where
 * the parser was pointed -- for a coalesced packet, not the datagram.
 * \~spanish
 * Todos los trozos son desplazamientos desde el primer byte del PAQUETE, que es
 * a donde se apunto al analizador -- en un paquete pegado a otros, no el
 * datagrama.
 * \~
 */
struct PacketHeader {
    PacketType type = PacketType::Initial;

    /**
     * \~english
     * The first byte as it arrived.  Its low bits -- the packet number length
     * and, for short headers, the key phase -- are still protected, so they
     * mean nothing yet.
     * \~spanish
     * El primer byte tal como llego.  Sus bits bajos -- la longitud del numero
     * de paquete y, en la cabecera corta, la fase de clave -- siguen protegidos,
     * asi que todavia no significan nada.
     * \~
     */
    uint8_t first = 0;

    /// \~english Zero for a short header.  \~spanish Cero en una cabecera corta.  \~
    uint32_t version = 0;

    Span dcid = {0, 0};
    Span scid = {0, 0};

    /// \~english An Initial's token or a Retry's.
    /// \~spanish El testigo de un Initial o el de un Retry.  \~
    Span token = {0, 0};

    /// \~english A Retry's integrity tag.  \~spanish La marca de integridad de un Retry.  \~
    Span tag = {0, 0};

    /// \~english A Version Negotiation packet's list.
    /// \~spanish La lista de un paquete Version Negotiation.  \~
    Span versions = {0, 0};

    /**
     * \~english
     * Where the protected packet number starts, or zero for the packet types
     * that have none (Retry, Version Negotiation, an unknown version).
     * \~spanish
     * Donde empieza el numero de paquete protegido, o cero en los tipos que no
     * tienen (Retry, Version Negotiation, una version desconocida).
     * \~
     */
    uint32_t pn_offset = 0;

    /**
     * \~english
     * How many bytes this packet takes.  The next coalesced packet, if any,
     * starts here.
     * \~spanish
     * Cuantos bytes ocupa este paquete.  El paquete pegado siguiente, si lo hay,
     * empieza aqui.
     * \~
     */
    uint32_t size = 0;
};

/**
 * @brief
 * \~english Reads the header of the packet at @p p.
 * \~spanish Lee la cabecera del paquete de @p p.
 * \~
 *
 * @param p   \~english where the packet starts  \~spanish donde empieza el paquete  \~
 * @param n   \~english how many bytes are left in the datagram
 *            \~spanish cuantos bytes quedan en el datagrama  \~
 * @param ctx \~english what the packet does not say  \~spanish lo que el paquete no dice  \~
 * @param out \~english the header  \~spanish la cabecera  \~
 * @return    \~english why it was dropped, or @c None
 *            \~spanish por que se tiro, o @c None  \~
 */
HeaderError parse_packet(const uint8_t *p, size_t n, const HeaderContext &ctx,
                         PacketHeader &out) noexcept;

/// \~english A short name for @p e, for counting and for logs.
/// \~spanish Un nombre corto para @p e, para contar y para los registros.  \~
const char *header_error_name(HeaderError e) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_PACKET_H
