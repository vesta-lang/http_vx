/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/http3_datagrams.h
 * @brief
 * \~english The HTTP/3 service as the datagram side of a shard: what puts it on a real UDP socket.
 * \~spanish El servicio HTTP/3 como lado de datagramas de un shard: lo que lo pone sobre un socket UDP de verdad.
 * \~
 *
 * \~english
 * Http3Service knows QUIC and nothing of sockets; the shard knows sockets and
 * nothing of QUIC (R27).  This is the one place that knows both, and all it
 * does is translate: addresses and ECN marks, which have the same layout on
 * both sides, and time, which does not.
 *
 * **Time is the part that needs care.**  The shard runs on coarse ticks --
 * whole seconds in the runnable server, which is right for idle connections
 * -- and hands those to its datagram side.  QUIC's timers are microseconds:
 * a probe due in 30 ms that waited for the next tick would be a second late
 * on every loss.  So this keeps its own clock, given at construction, and
 * answers the shard's question -- "is your timer due by now?" -- in the
 * shard's terms: due, or not yet.  How long the loop may sleep comes from
 * wait_ms(), which the loop asks directly.
 *
 * \~spanish
 * Http3Service sabe de QUIC y nada de sockets; el shard sabe de sockets y nada
 * de QUIC (R27).  Este es el unico sitio que sabe de los dos, y lo unico que
 * hace es traducir: direcciones y marcas ECN, que tienen la misma forma a los
 * dos lados, y el tiempo, que no.
 *
 * **El tiempo es la parte delicada.**  El shard corre en tics gruesos --
 * segundos enteros en el servidor ejecutable, que es lo correcto para las
 * conexiones ociosas -- y se los pasa a su lado de datagramas.  Los
 * temporizadores de QUIC son microsegundos: una sonda que vence en 30 ms y
 * esperara al tic siguiente llegaria un segundo tarde en cada perdida.  Asi que
 * esto lleva su propio reloj, dado al construirlo, y contesta la pregunta del
 * shard -- "ha vencido tu temporizador?" -- en los terminos del shard: vencido,
 * o aun no.  Cuanto puede dormir el bucle sale de wait_ms(), que el bucle
 * pregunta directamente.
 * \~
 */
#ifndef HTTP_VX_HTTP3_DATAGRAMS_H
#define HTTP_VX_HTTP3_DATAGRAMS_H

#include "http_vx/datagram_service.h"
#include "http_vx/http3_service.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english Http3Service behind the shard's DatagramService.
 * \~spanish Http3Service detras del DatagramService del shard.
 * \~
 */
class Http3Datagrams final : public DatagramService {
  public:
    /// \~english A clock in microseconds.  \~spanish Un reloj en microsegundos.  \~
    using Clock = uint64_t (*)();

    Http3Datagrams(Http3Service &service, Clock now_us) noexcept : service_(service), now_us_(now_us) {}

    void on_datagram(const DatagramPath &path, uint8_t *data, size_t n, EcnMark ecn,
                     uint64_t now) noexcept override;
    size_t next_datagram(DatagramPath &path, uint8_t *out, size_t room, uint64_t now) noexcept override;

    /**
     * @brief
     * \~english Zero when the service's timer is due by this clock; otherwise a time no tick reaches.
     * \~spanish Cero si el temporizador del servicio vencio segun este reloj; si no, un tiempo al que no llega ningun tic.
     * \~
     */
    uint64_t timer() const noexcept override;

    void on_timer(uint64_t now) noexcept override;

    /// \~english Hands the shard's port to the service: it opens, fills and ends responses through it.
    /// \~spanish Le pasa la puerta del fragmento al servicio: abre, rellena y acaba respuestas por ella.  \~
    void attach(OpenPort *port) noexcept override { service_.attach(port); }

    /// \~english The shard lets go: the service ends everything open with GoneReason::Shutdown.
    /// \~spanish El fragmento lo suelta todo: el servicio acaba todo lo abierto con GoneReason::Shutdown.  \~
    void on_shutdown() noexcept override { service_.on_shutdown(); }

    /// \~english How long the loop may sleep before the service's next timer, at most @p cap_ms.
    /// \~spanish Cuanto puede dormir el bucle antes del siguiente temporizador del servicio, como mucho @p cap_ms.  \~
    int wait_ms(int cap_ms) const noexcept;

  private:
    Http3Service &service_;
    Clock now_us_;
};

} // namespace http_vx

#endif // HTTP_VX_HTTP3_DATAGRAMS_H
