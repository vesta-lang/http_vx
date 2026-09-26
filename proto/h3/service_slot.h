/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service_slot.h
 * @brief
 * \~english One connection of the HTTP/3 service: what the two halves of the service share.
 * \~spanish Una conexion del servicio HTTP/3: lo que comparten las dos mitades del servicio.
 * \~
 *
 * \~english
 * Private to `proto/h3/`: service.cpp drives connections and requests,
 * service_route.cpp keeps the route table, the send queue and the timer heap,
 * and both need to see a slot.
 * \~spanish
 * Privado de `proto/h3/`: service.cpp lleva conexiones y peticiones,
 * service_route.cpp guarda la tabla de rutas, la cola de envio y el monticulo
 * de temporizadores, y los dos necesitan ver una casilla.
 * \~
 */
#ifndef HTTP_VX_PROTO_H3_SERVICE_SLOT_H
#define HTTP_VX_PROTO_H3_SERVICE_SLOT_H

#include "http_vx/http3_service.h"

namespace http_vx {

/**
 * @brief
 * \~english A place for one connection, used or free.
 * \~spanish Un sitio para una conexion, usado o libre.
 * \~
 *
 * \~english
 * The three layers are built in place, in that order, and torn down in the
 * other: the handshake and HTTP/3 hold a reference to the transport.
 * \~spanish
 * Las tres capas se construyen en su sitio, en ese orden, y se derriban en el
 * contrario: el saludo y HTTP/3 guardan una referencia al transporte.
 * \~
 */
struct Http3Service::Slot {
    quic::Connection *quic = nullptr;
    tls::QuicHandshake *tls = nullptr;
    h3::Connection *h3 = nullptr;

    /// \~english One piece of work per place HTTP/3 keeps a request in (h3::Event::slot).
    /// \~spanish Un trabajo por cada sitio donde HTTP/3 guarda una peticion (h3::Event::slot).  \~
    Work *works = nullptr;

    /// \~english The IDs that lead here, as registered in the route table.
    /// \~spanish Los identificadores que llevan aqui, tal como estan en la tabla de rutas.  \~
    Cid routes[kRoutes];
    size_t route_count = 0;

    /**
     * \~english
     * The client's first destination ID.  It routes here for as long as the
     * connection lives, and not only until the handshake: a duplicated or
     * delayed Initial arriving later would otherwise reach the acceptor as a
     * new client and hold a slot until it timed out.  Here, the connection
     * drops it and counts it.
     * \~spanish
     * El primer identificador de destino del cliente.  Lleva aqui mientras viva
     * la conexion, y no solo hasta el saludo: un Initial duplicado o retrasado
     * que llegara despues le llegaria si no al acceptor como un cliente nuevo y
     * ocuparia una casilla hasta caducar.  Aqui, la conexion lo tira y lo
     * cuenta.
     * \~
     */
    Cid first;

    /// \~english Whether it is in the send queue: once at most.
    /// \~spanish Si esta en la cola de envio: una vez como mucho.  \~
    bool queued = false;

    /// \~english HTTP/3 failed and was counted.  \~spanish HTTP/3 fallo y se conto.  \~
    bool failure_counted = false;

    /// \~english The next free slot, while free.  \~spanish La casilla libre siguiente, mientras esta libre.  \~
    uint32_t next_free = kNone;
};

} // namespace http_vx

#endif // HTTP_VX_PROTO_H3_SERVICE_SLOT_H
