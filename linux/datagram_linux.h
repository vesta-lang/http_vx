/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/datagram_linux.h
 * @brief
 * \~english What epoll and io_uring share about UDP: the socket and the message (private to linux/).
 * \~spanish Lo que comparten epoll e io_uring de UDP: el socket y el mensaje (privado de linux/).
 * \~
 *
 * \~english
 * The two Linux backends ask the kernel differently -- one `recvmmsg` over
 * every waiting receive, or one ring entry each -- but the message they hand
 * it is the same `msghdr`, and what comes back is read the same way.  Written
 * once, here, so that the two cannot disagree about which control message
 * carries the local address.
 *
 * Relied on: the Linux man pages recvmsg(2), recvmmsg(2), sendmmsg(2), ip(7),
 * ipv6(7) and cmsg(3) as installed; `IPV6_RECVTCLASS` and `IPV6_TCLASS` are not
 * described in ipv6(7) and come from RFC 3542, 6.5, as declared by the
 * system's headers.
 * \~spanish
 * Los dos backends de Linux le preguntan al nucleo de forma distinta -- un
 * `recvmmsg` sobre todas las recepciones que esperan, o una entrada del anillo
 * cada una -- pero el mensaje que le dan es el mismo `msghdr`, y lo que vuelve
 * se lee igual.  Escrito una vez, aqui, para que los dos no puedan discrepar
 * sobre que mensaje de control lleva la direccion local.
 *
 * En que se apoya: las paginas de manual de Linux recvmsg(2), recvmmsg(2),
 * sendmmsg(2), ip(7), ipv6(7) y cmsg(3) instaladas; `IPV6_RECVTCLASS` e
 * `IPV6_TCLASS` no estan descritas en ipv6(7) y salen del RFC 3542, 6.5, tal
 * como las declaran las cabeceras del sistema.
 * \~
 */
#ifndef HTTP_VX_LINUX_DATAGRAM_LINUX_H
#define HTTP_VX_LINUX_DATAGRAM_LINUX_H

#include "http_vx/buffer.h"
#include "http_vx/datagram.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace udp {

/**
 * \~english
 * Room for one datagram's control data: packet information and the traffic
 * class of either family, with room to spare.  Too little is a
 * @c MSG_CTRUNC, counted, and a datagram whose local address is not known.
 * \~spanish
 * Sitio para los datos de control de un datagrama: informacion del paquete y
 * clase de trafico de cualquier familia, con holgura.  Poco es un
 * @c MSG_CTRUNC, contado, y un datagrama del que no se sabe la direccion local.
 * \~
 */
constexpr size_t kControlRoom = 128;

/**
 * @brief
 * \~english What a message points at, besides the payload.
 * \~spanish A lo que apunta un mensaje, ademas de la carga.
 * \~
 *
 * \~english
 * On epoll it lives on the stack for the one call; on io_uring it has to live
 * until the completion, because the kernel writes the address and the control
 * data when the datagram arrives.
 * \~spanish
 * En epoll vive en la pila lo que dura la llamada; en io_uring tiene que vivir
 * hasta la finalizacion, porque el nucleo escribe la direccion y los datos de
 * control cuando llega el datagrama.
 * \~
 */
struct MsgRoom {
    sockaddr_in6 name;
    iovec iov;
    /// \~english Aligned as a `cmsghdr`, whose length field is a `size_t` (cmsg(3)).
    /// \~spanish Alineado como un `cmsghdr`, cuyo campo de longitud es un `size_t` (cmsg(3)).  \~
    struct {
        alignas(size_t) uint8_t bytes[kControlRoom];
    } control;
};

/**
 * @brief
 * \~english Opens a UDP socket on @p host : @p port, with packet information and ECN on.
 * \~spanish Abre un socket UDP en @p host : @p port, con la informacion del paquete y el ECN encendidos.
 * \~
 *
 * @param nonblock \~english whether it must not block (epoll) or may (io_uring)
 *                 \~spanish si no debe bloquear (epoll) o puede (io_uring)  \~
 * @param bound    \~english the address it got  \~spanish la direccion que le toco  \~
 * @param error    \~english the system's error when it fails
 *                 \~spanish el error del sistema cuando falla  \~
 * @return         \~english the socket, or -1  \~spanish el socket, o -1  \~
 */
int open_socket(const char *host, uint16_t port, bool nonblock,
                NetAddress &bound, int32_t &error) noexcept;

/**
 * @brief
 * \~english Aims @p m at @p n bytes of room for one datagram and its addresses.
 * \~spanish Apunta @p m a @p n bytes de sitio para un datagrama y sus direcciones.
 * \~
 */
void aim_receive(msghdr &m, MsgRoom &r, uint8_t *room, size_t n) noexcept;

/**
 * @brief
 * \~english Aims @p m at the datagram in @p b, to its peer, from its local address if known.
 * \~spanish Apunta @p m al datagrama de @p b, a su otro extremo, desde su direccion local si se sabe.
 * \~
 *
 * @param family_len \~english the length of an address of the socket's family
 *                   \~spanish la longitud de una direccion de la familia del socket  \~
 * @return \~english false if @p b holds no datagram of @p len bytes for that family
 *         \~spanish false si @p b no tiene un datagrama de @p len bytes para esa familia  \~
 */
bool aim_send(msghdr &m, MsgRoom &r, Buffer &b, uint32_t len,
              uint8_t family_len) noexcept;

/**
 * @brief
 * \~english Reads what came back with a received datagram and keeps it, or says it was cut.
 * \~spanish Lee lo que volvio con un datagrama recibido y se lo queda, o dice que se corto.
 * \~
 *
 * @param m     \~english the message as the kernel left it  \~spanish el mensaje como lo dejo el nucleo  \~
 * @param got   \~english the datagram's real length  \~spanish la longitud real del datagrama  \~
 * @param room  \~english the room it was given  \~spanish el sitio que se le dio  \~
 * @param bound \~english the socket's own address  \~spanish la direccion del propio socket  \~
 * @param b     \~english the buffer it landed in  \~spanish el buffer donde cayo  \~
 * @param c     \~english what to count on  \~spanish donde contar  \~
 * @return      \~english the payload size, or @c kTruncated
 *              \~spanish el tamano de la carga, o @c kTruncated  \~
 */
int32_t finish_receive(const msghdr &m, size_t got, size_t room,
                       const NetAddress &bound, Buffer &b,
                       DatagramCounts &c) noexcept;

} // namespace udp
} // namespace http_vx

#endif // HTTP_VX_LINUX_DATAGRAM_LINUX_H
