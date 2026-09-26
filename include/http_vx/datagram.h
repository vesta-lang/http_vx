/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/datagram.h
 * @brief
 * \~english What travels with a datagram, and where it travels in a buffer.
 * \~spanish Lo que viaja con un datagrama, y por donde viaja en un buffer.
 * \~
 *
 * \~english
 * R26: the reactor carries datagrams as well as streams.  A stream only needs
 * its bytes; a datagram also needs WHO it came from and, to answer on the same
 * path, to which of this end's addresses it was sent.  QUIC is built on that
 * pair (RFC 9000, 9: a path is the 2-tuple at each end), so losing either half
 * is not a detail -- a reply sent from the wrong address is a reply the peer
 * does not recognise.
 *
 * **Why the addresses go INSIDE the buffer and not inside the operation.**  An
 * @c Op is copied into every table of pending operations: epoll keeps two per
 * descriptor, for every descriptor it may ever see.  Fifty-eight bytes of
 * addresses in each would multiply that table for the sake of the few sockets
 * that are datagram sockets.  And the addresses have the same owner as the
 * bytes: the kernel writes the peer's address while it writes the payload, so
 * they must live exactly as long -- which is what the buffer already does.
 * So a datagram buffer is a fixed header (@c DatagramHeader, in the first
 * @c kDatagramHeaderRoom bytes) followed by the payload, and an operation that
 * names the buffer names both.
 *
 * R27: nothing here knows QUIC.  @c NetAddress is laid out like
 * `quic::Address` -- 28 opaque bytes and a length -- and @c EcnMark counts in
 * the same order as `quic::Ecn`, so whoever joins the two converts with a copy
 * and a cast, without this header knowing the other exists.
 *
 * \~spanish
 * R26: el reactor lleva datagramas ademas de flujos.  A un flujo le bastan sus
 * bytes; un datagrama necesita ademas DE QUIEN vino y, para contestar por el
 * mismo camino, a cual de las direcciones de este extremo se mando.  QUIC esta
 * hecho sobre ese par (RFC 9000, 9: un camino es la tupla de cada extremo), asi
 * que perder cualquiera de las dos mitades no es un detalle -- una respuesta
 * mandada desde la direccion equivocada es una respuesta que el otro extremo no
 * reconoce.
 *
 * **Por que las direcciones van DENTRO del buffer y no dentro de la
 * operacion.**  Un @c Op se copia en todas las tablas de operaciones
 * pendientes: epoll guarda dos por descriptor, para todos los descriptores que
 * pueda ver.  Cincuenta y ocho bytes de direcciones en cada una multiplicarian
 * esa tabla por culpa de los pocos sockets que son de datagramas.  Y las
 * direcciones tienen el mismo dueno que los bytes: el nucleo escribe la
 * direccion del otro extremo mientras escribe la carga, asi que tienen que vivir
 * exactamente lo mismo -- que es lo que ya hace el buffer.  Asi que un buffer de
 * datagrama es una cabecera fija (@c DatagramHeader, en los primeros
 * @c kDatagramHeaderRoom bytes) seguida de la carga, y una operacion que nombra
 * el buffer nombra las dos cosas.
 *
 * R27: aqui nada sabe de QUIC.  @c NetAddress tiene la forma de `quic::Address`
 * -- 28 bytes opacos y una longitud -- y @c EcnMark cuenta en el mismo orden que
 * `quic::Ecn`, asi que quien junte los dos convierte con una copia y un cast,
 * sin que esta cabecera sepa que existe la otra.
 * \~
 */
#ifndef HTTP_VX_DATAGRAM_H
#define HTTP_VX_DATAGRAM_H

#include "http_vx/buffer.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * \~english
 * Room for the largest socket address the reactor produces: a `sockaddr_in6`,
 * which is 28 bytes on Linux and on Windows alike.  A `sockaddr_in` is 16.
 * \~spanish
 * Sitio para la direccion de socket mas grande que produce el reactor: un
 * `sockaddr_in6`, que son 28 bytes igual en Linux que en Windows.  Un
 * `sockaddr_in` son 16.
 * \~
 */
constexpr size_t kMaxNetAddress = 28;

/**
 * @brief
 * \~english One endpoint's address, as opaque bytes.
 * \~spanish La direccion de un extremo, como bytes opacos.
 * \~
 *
 * \~english
 * Opaque to everything above the backend, which is the only piece that reads
 * it: it is the platform's socket address, in a CANONICAL form -- every byte
 * that does not identify the endpoint is zero (the padding of a v4 address,
 * the flow label of a v6 one) -- so that two addresses of the same endpoint
 * are equal byte for byte.  A comparison that had to know the family would
 * have to know the platform.
 *
 * An empty address (@c len zero) means "not known", never "any".
 *
 * \~spanish
 * Opaca para todo lo que hay por encima del backend, que es la unica pieza que
 * la lee: es la direccion de socket de la plataforma, en forma CANONICA -- todo
 * byte que no identifica al extremo es cero (el relleno de una v4, la etiqueta
 * de flujo de una v6) -- para que dos direcciones del mismo extremo sean iguales
 * byte a byte.  Una comparacion que tuviera que saber la familia tendria que
 * saber la plataforma.
 *
 * Una direccion vacia (@c len cero) quiere decir "no se sabe", nunca
 * "cualquiera".
 * \~
 */
struct NetAddress {
    uint8_t bytes[kMaxNetAddress] = {};
    uint8_t len = 0;
};

/**
 * @brief
 * \~english This end's address and the peer's, as one datagram saw them.
 * \~spanish La direccion de este extremo y la del otro, tal como las vio un datagrama.
 * \~
 */
struct DatagramPath {
    NetAddress local;
    NetAddress peer;
};

/**
 * @brief
 * \~english The ECN codepoint of a datagram (RFC 3168, 5), in QUIC's order.
 * \~spanish El codigo ECN de un datagrama (RFC 3168, 5), en el orden de QUIC.
 * \~
 *
 * \~english
 * Named, not the two raw bits, because the bits are in the other order:
 * ECT(1) is 01 and ECT(0) is 10.  Handing the bits upwards would put the
 * swap in every consumer, and one of them would forget.
 * \~spanish
 * Con nombre, y no los dos bits en crudo, porque los bits van en el otro
 * orden: ECT(1) es 01 y ECT(0) es 10.  Pasar los bits hacia arriba pondria el
 * cambio en cada consumidor, y alguno se lo olvidaria.
 * \~
 */
enum class EcnMark : uint8_t { NotEct, Ect0, Ect1, Ce };

/**
 * @brief
 * \~english What a backend managed to learn about a received datagram.
 * \~spanish Lo que un backend consiguio saber de un datagrama recibido.
 * \~
 *
 * \~english
 * Separate bits because "not known" and "zero" are different answers.  A
 * platform that cannot report the ECN bits must not report Not-ECT as if it
 * had read them, and one that cannot say where a datagram was sent must not
 * leave an empty local address to be mistaken for a real one.
 * \~spanish
 * Bits aparte porque "no se sabe" y "cero" son respuestas distintas.  Una
 * plataforma que no puede dar los bits ECN no puede dar Not-ECT como si los
 * hubiera leido, y una que no puede decir a donde se mando un datagrama no puede
 * dejar una direccion local vacia que se tome por una de verdad.
 * \~
 */
enum DatagramFlag : uint8_t {
    /// \~english @c path.local is the address the datagram was sent to.
    /// \~spanish @c path.local es la direccion a la que se mando el datagrama.  \~
    kDatagramLocalKnown = 1,

    /// \~english @c ecn was read from the IP header.
    /// \~spanish @c ecn se leyo de la cabecera IP.  \~
    kDatagramEcnKnown = 2,
};

/**
 * @brief
 * \~english The fixed part in front of a datagram's bytes inside its buffer.
 * \~spanish La parte fija delante de los bytes de un datagrama dentro de su buffer.
 * \~
 *
 * \~english
 * Received: the backend writes it when the datagram arrives.  Sent: the loop
 * writes it before asking, and @c path.peer is where the datagram goes; a
 * known @c path.local asks for it to leave FROM that address.  It is copied in
 * and out with a memcpy, never read in place, so the buffer needs no alignment.
 * \~spanish
 * Recibido: lo escribe el backend cuando llega el datagrama.  Enviado: lo
 * escribe el bucle antes de pedirlo, y @c path.peer es adonde va el datagrama;
 * un @c path.local conocido pide que salga DESDE esa direccion.  Se copia de y
 * hacia el buffer con un memcpy, nunca se lee en su sitio, asi que el buffer no
 * necesita alineacion.
 * \~
 */
struct DatagramHeader {
    DatagramPath path;
    EcnMark ecn = EcnMark::NotEct;

    /// \~english @c DatagramFlag bits.  \~spanish Bits de @c DatagramFlag.  \~
    uint8_t flags = 0;
};

/**
 * \~english
 * Where the payload starts in a datagram buffer.  Rounded up from the header's
 * size so that the payload starts on a cache-friendly boundary.
 * \~spanish
 * Donde empieza la carga en un buffer de datagrama.  Redondeado por encima del
 * tamano de la cabecera para que la carga empiece en un limite amable con la
 * cache.
 * \~
 */
constexpr size_t kDatagramHeaderRoom = 64;

static_assert(sizeof(DatagramHeader) <= kDatagramHeaderRoom,
              "the datagram header no longer fits in front of the payload");

/**
 * @brief
 * \~english Whether two addresses are the same endpoint.
 * \~spanish Si dos direcciones son el mismo extremo.
 * \~
 */
bool same_net_address(const NetAddress &a, const NetAddress &b) noexcept;

/**
 * @brief
 * \~english The codepoint in the two low bits of a TOS or traffic class byte.
 * \~spanish El codigo en los dos bits bajos de un byte TOS o de clase de trafico.
 * \~
 *
 * @param tos \~english the byte from the IP header  \~spanish el byte de la cabecera IP  \~
 * @return    \~english the codepoint  \~spanish el codigo  \~
 */
EcnMark ecn_from_tos(uint8_t tos) noexcept;

/**
 * @brief
 * \~english Makes room for a datagram of up to @p room bytes, header included.
 * \~spanish Hace sitio para un datagrama de hasta @p room bytes, con su cabecera.
 * \~
 *
 * \~english
 * For a receive: the backend hands the kernel the returned pointer, which is
 * where the PAYLOAD goes; the header in front of it is written at completion,
 * by @c datagram_commit.  The buffer must be empty -- one buffer, one datagram.
 * \~spanish
 * Para una recepcion: el backend le da al nucleo el puntero devuelto, que es
 * donde va la CARGA; la cabecera de delante se escribe al acabar, con
 * @c datagram_commit.  El buffer tiene que estar vacio -- un buffer, un
 * datagrama.
 * \~
 *
 * @param b    \~english the buffer  \~spanish el buffer  \~
 * @param room \~english the most payload  \~spanish la mayor carga  \~
 * @return     \~english where the payload goes, or null
 *             \~spanish donde va la carga, o nulo  \~
 */
uint8_t *datagram_reserve(Buffer &b, size_t room) noexcept;

/**
 * @brief
 * \~english Writes @p h in front of @p n payload bytes already in place, and keeps both.
 * \~spanish Escribe @p h delante de @p n bytes de carga ya en su sitio, y se queda los dos.
 * \~
 *
 * @param b \~english the buffer @c datagram_reserve was called on
 *          \~spanish el buffer sobre el que se llamo a @c datagram_reserve  \~
 * @param h \~english what came with the datagram  \~spanish lo que vino con el datagrama  \~
 * @param n \~english how many payload bytes  \~spanish cuantos bytes de carga  \~
 */
void datagram_commit(Buffer &b, const DatagramHeader &h, size_t n) noexcept;

/**
 * @brief
 * \~english Reads the header of the datagram in @p b.
 * \~spanish Lee la cabecera del datagrama que hay en @p b.
 * \~
 *
 * @param b \~english the buffer  \~spanish el buffer  \~
 * @param h \~english where it goes  \~spanish donde va  \~
 * @return  \~english false if @p b does not hold a datagram
 *          \~spanish false si @p b no tiene un datagrama  \~
 */
bool datagram_header(const Buffer &b, DatagramHeader &h) noexcept;

/// \~english The payload of the datagram in @p b.
/// \~spanish La carga del datagrama que hay en @p b.  \~
inline const uint8_t *datagram_payload(const Buffer &b) noexcept {
    return b.data() + kDatagramHeaderRoom;
}

/// \~english How many payload bytes @p b holds; zero if it holds no datagram.
/// \~spanish Cuantos bytes de carga tiene @p b; cero si no tiene datagrama.  \~
inline size_t datagram_size(const Buffer &b) noexcept {
    return b.size() < kDatagramHeaderRoom ? 0 : b.size() - kDatagramHeaderRoom;
}

/**
 * \~english
 * How many datagram sockets a backend opens and a shard drives.  A handful:
 * one per family and address served, not one per peer -- that is the whole
 * point of datagrams.
 * \~spanish
 * Cuantos sockets de datagramas abre un backend y mueve un fragmento.  Unos
 * pocos: uno por familia y direccion servida, no uno por otro extremo -- que es
 * toda la gracia de los datagramas.
 * \~
 */
constexpr size_t kMaxDatagramSockets = 8;

/**
 * @brief
 * \~english The datagram sockets a backend opened, and what each is bound to.
 * \~spanish Los sockets de datagramas que abrio un backend, y a que esta atado cada uno.
 * \~
 *
 * \~english
 * A backend needs it for two things: to refuse a datagram operation on a
 * socket that is not one of these -- a @c RecvFrom on a stream socket would
 * otherwise "work" and deliver a stream's bytes as a datagram from nobody --
 * and to know the port a received datagram was sent to, which the packet
 * information gives without.
 * \~spanish
 * Un backend lo necesita para dos cosas: rechazar una operacion de datagramas
 * sobre un socket que no sea uno de estos -- un @c RecvFrom sobre un socket de
 * flujo "funcionaria" y entregaria los bytes de un flujo como un datagrama de
 * nadie -- y saber el puerto al que se mando un datagrama recibido, que la
 * informacion del paquete da sin el.
 * \~
 */
class DatagramSockets {
  public:
    /// \~english Remembers @p fd; false when full.
    /// \~spanish Recuerda @p fd; false cuando esta lleno.  \~
    bool add(int32_t fd, const NetAddress &bound) noexcept;

    /**
     * \~english
     * Forgets @p fd, which is being closed.  Kept would be a note about a
     * number the system hands straight out again, to a socket that is not one
     * of these.
     * \~spanish
     * Olvida @p fd, que se esta cerrando.  Guardarlo seria una nota sobre un
     * numero que el sistema vuelve a dar enseguida, a un socket que no es uno de
     * estos.
     * \~
     */
    void remove(int32_t fd) noexcept;

    /// \~english Which entry is @p fd, or -1.
    /// \~spanish Que entrada es @p fd, o -1.  \~
    int32_t find(int32_t fd) const noexcept;

    /// \~english What entry @p i is bound to.  \~spanish A que esta atada la entrada @p i.  \~
    const NetAddress &bound(size_t i) const noexcept { return bound_[i]; }

    /// \~english The socket of entry @p i.  \~spanish El socket de la entrada @p i.  \~
    int32_t fd(size_t i) const noexcept { return fd_[i]; }

    /// \~english How many.  \~spanish Cuantos.  \~
    size_t count() const noexcept { return count_; }

    /// \~english Forgets them all, closing none.  \~spanish Los olvida todos, sin cerrar ninguno.  \~
    void clear() noexcept { count_ = 0; }

  private:
    int32_t fd_[kMaxDatagramSockets] = {};
    NetAddress bound_[kMaxDatagramSockets];
    size_t count_ = 0;
};

/**
 * @brief
 * \~english What a backend has done with datagrams, counted.
 * \~spanish Lo que un backend ha hecho con datagramas, contado.
 * \~
 *
 * \~english
 * Counted by every backend that does datagrams, so that nothing about them is
 * silent: a truncated datagram, a send the system refused and a control
 * message cut short are each a number that grows, next to the calls that were
 * made -- which is also how the batching is SEEN rather than believed.
 * \~spanish
 * Lo cuenta cada backend que hace datagramas, para que nada de ellos sea
 * callado: un datagrama truncado, un envio que rechazo el sistema y un mensaje
 * de control cortado son cada uno un numero que crece, al lado de las llamadas
 * que se hicieron -- que es tambien como se VE que se agrupa en vez de
 * creerselo.
 * \~
 */
struct DatagramCounts {
    /// \~english Datagrams delivered whole.  \~spanish Datagramas entregados enteros.  \~
    uint64_t received = 0;

    /// \~english Datagrams the system took to send.
    /// \~spanish Datagramas que el sistema acepto enviar.  \~
    uint64_t sent = 0;

    /**
     * \~english
     * Datagrams larger than the room given, which the system cut.  They are
     * NOT delivered: their operation completes with @c kTruncated.
     * \~spanish
     * Datagramas mayores que el sitio dado, que el sistema corto.  NO se
     * entregan: su operacion acaba con @c kTruncated.
     * \~
     */
    uint64_t truncated = 0;

    /// \~english Control data cut short: local address or ECN may be missing.
    /// \~spanish Datos de control cortados: puede faltar la direccion local o el ECN.  \~
    uint64_t control_truncated = 0;

    /// \~english Receives that failed.  \~spanish Recepciones que fallaron.  \~
    uint64_t receive_errors = 0;

    /// \~english Sends that failed.  \~spanish Envios que fallaron.  \~
    uint64_t send_errors = 0;

    /// \~english System calls that received.  \~spanish Llamadas al sistema que recibieron.  \~
    uint64_t receive_calls = 0;

    /// \~english System calls that sent.  \~spanish Llamadas al sistema que enviaron.  \~
    uint64_t send_calls = 0;
};

} // namespace http_vx

#endif // HTTP_VX_DATAGRAM_H
