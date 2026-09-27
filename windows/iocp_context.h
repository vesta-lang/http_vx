/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_context.h
 * @brief
 * \~english The record an operation keeps while Windows holds it (private to windows/).
 * \~spanish El registro que guarda una operacion mientras la tiene Windows (privado de windows/).
 * \~
 *
 * \~english
 * Its own header because two files fill it: the stream operations in
 * `iocp_backend.cpp` and the datagram ones in `iocp_datagram.cpp`.  It has to
 * be included FIRST, before anything else, for the reason written at the top
 * of `iocp_backend.cpp`: the Windows headers settle which version they
 * describe the first time any of them is seen.
 * \~spanish
 * Cabecera propia porque lo rellenan dos ficheros: las operaciones de flujo en
 * `iocp_backend.cpp` y las de datagramas en `iocp_datagram.cpp`.  Hay que
 * incluirla LA PRIMERA, antes que nada, por lo que esta escrito al principio de
 * `iocp_backend.cpp`: las cabeceras de Windows deciden que version describen la
 * primera vez que se ve cualquiera de ellas.
 * \~
 */
#ifndef HTTP_VX_WINDOWS_IOCP_CONTEXT_H
#define HTTP_VX_WINDOWS_IOCP_CONTEXT_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <winsock2.h>

#include <mswsock.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "http_vx/iocp_backend.h"

namespace http_vx {

/**
 * @brief
 * \~english How much room `AcceptEx` needs for the two addresses.
 * \~spanish Cuanto sitio necesita `AcceptEx` para las dos direcciones.
 * \~
 *
 * \~english
 * Sixteen bytes more than the address on each side, and the sixteen are not
 * slack: `AcceptEx` is documented to require them and writing exactly the size
 * of a `sockaddr` fails with a message about a parameter rather than about a
 * buffer.  The address is the v6 one because it is the larger, so the same room
 * serves both families.
 *
 * \~spanish
 * Dieciseis bytes mas que la direccion en cada lado, y los dieciseis no son
 * holgura: `AcceptEx` los exige por documentacion, y darle exactamente el tamano
 * de un `sockaddr` falla con un mensaje sobre un parametro y no sobre un buffer.
 * La direccion es la de v6 por ser la mayor, asi que el mismo sitio sirve para
 * las dos familias.
 *
 * \~
 */
constexpr size_t kAddressRoom = sizeof(sockaddr_in6) + 16;

/**
 * \~english
 * Room for the control data of one datagram: the packet information of
 * either family, with its header, and slack for one more message the stack
 * may add.  Too little is not a crash but a @c MSG_CTRUNC, counted, and a
 * datagram whose local address is then not known.
 * \~spanish
 * Sitio para los datos de control de un datagrama: la informacion del paquete
 * de cualquiera de las dos familias, con su cabecera, y holgura para un mensaje
 * mas que pueda anadir la pila.  Poco no es un fallo grave sino un
 * @c MSG_CTRUNC, contado, y un datagrama del que entonces no se sabe la
 * direccion local.
 * \~
 */
constexpr size_t kControlRoom = 128;

/// \~english What a socket handle is when there is none.
/// \~spanish Lo que es un socket cuando no hay ninguno.  \~
constexpr uintptr_t kNoSocket = static_cast<uintptr_t>(INVALID_SOCKET);

/**
 * @brief
 * \~english The socket address a host and a port name, in room for either family.
 * \~spanish La direccion de socket que nombran un anfitrion y un puerto, en sitio para cualquier familia.
 * \~
 */
struct WinAddress {
    union {
        sockaddr_in v4;
        sockaddr_in6 v6;
    } raw;
    int len = 0;
    int family = AF_INET;
};

/**
 * @brief
 * \~english Reads @p host as an IPv4 or IPv6 literal; the one reader for TCP and UDP.
 * \~spanish Lee @p host como un literal IPv4 o IPv6; el unico lector para TCP y UDP.
 * \~
 *
 * @return \~english false if it is neither  \~spanish false si no es ninguno  \~
 */
bool win_address(const char *host, uint16_t port, WinAddress &out) noexcept;

/// \~english Turns a socket into the number the rest of the project uses.
/// \~spanish Convierte un socket en el numero que usa el resto del proyecto.  \~
inline int32_t as_fd(SOCKET s) noexcept { return static_cast<int32_t>(s); }

/// \~english And back.  \~spanish Y al reves.  \~
inline SOCKET as_socket(int32_t fd) noexcept { return static_cast<SOCKET>(fd); }

/**
 * @brief
 * \~english One operation the kernel is holding, and everything it must keep alive.
 * \~spanish Una operacion que tiene el nucleo, y todo lo que tiene que mantener vivo.
 * \~
 *
 * \~english
 * The `OVERLAPPED` goes FIRST, and that is not style: what a completion hands
 * back is a pointer to it, and this is turned back into the record around it by
 * a cast.  A field moved in front of it would turn every completion into a read
 * of the wrong object, and it would keep working for as long as the compiler
 * happened to lay things out kindly.
 *
 * \~spanish
 * El `OVERLAPPED` va PRIMERO, y no es estilo: lo que devuelve una finalizacion es
 * un puntero a el, y esto se vuelve a convertir en el registro que lo rodea con
 * un cast.  Un campo puesto delante convertiria cada finalizacion en la lectura
 * del objeto equivocado, y seguiria funcionando mientras el compilador colocara
 * las cosas por casualidad de forma amable.
 *
 * \~
 */
struct IocpBackend::Context {
    OVERLAPPED ov;

    /// \~english What was asked for.  \~spanish Lo que se pidio.  \~
    Op op;

    /**
     * \~english
     * The socket an @c Accept is accepting INTO.  Windows wants it made before
     * the accept is asked for, which is the opposite of every other platform
     * and is the reason accepting needs a record at all.
     * \~spanish
     * El socket EN EL QUE acepta un @c Accept.  Windows lo quiere hecho antes de
     * pedir la aceptacion, que es al reves que en cualquier otra plataforma y es
     * la razon de que aceptar necesite un registro siquiera.
     * \~
     */
    SOCKET sock;

    /// \~english The next free record.  \~spanish El registro libre siguiente.  \~
    uint32_t next;

    /**
     * \~english
     * Whether the kernel holds it.  What @c release asks to know which
     * operations to cancel: the free list says which records are free, not
     * which are taken.
     * \~spanish
     * Si lo tiene el nucleo.  Lo que pregunta @c release para saber que
     * operaciones cancelar: la lista libre dice que registros estan libres, no
     * cuales estan cogidos.
     * \~
     */
    bool busy;

    /**
     * \~english
     * Where `AcceptEx` writes the two addresses.  Nobody here reads them --
     * this server does not care who connected, and a connection that has to say
     * will say it in a field -- but the call will not run without somewhere to
     * put them.
     * \~spanish
     * Donde escribe `AcceptEx` las dos direcciones.  Aqui no las lee nadie --
     * a este servidor no le importa quien se conecto, y una conexion que tenga
     * que decirlo lo dira en una cabecera -- pero la llamada no corre sin un
     * sitio donde ponerlas.
     * \~
     */
    uint8_t addrs[2 * kAddressRoom];

    /**
     * \~english
     * A datagram's message: its description, the peer's address and the
     * control data.  All of it here and not on the stack, because Windows
     * writes the address and the control data when the datagram ARRIVES --
     * long after the call that posted the receive has returned.
     * \~spanish
     * El mensaje de un datagrama: su descripcion, la direccion del otro extremo
     * y los datos de control.  Todo aqui y no en la pila, porque Windows escribe
     * la direccion y los datos de control cuando LLEGA el datagrama -- mucho
     * despues de que haya vuelto la llamada que puso la recepcion.
     * \~
     */
    WSAMSG msg;
    WSABUF payload;
    sockaddr_in6 name;
    union {
        WSACMSGHDR align;
        uint8_t bytes[kControlRoom];
    } control;
};

} // namespace http_vx

#endif // HTTP_VX_WINDOWS_IOCP_CONTEXT_H
