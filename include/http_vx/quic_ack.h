/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_ack.h
 * @brief
 * \~english What a QUIC endpoint received, and when to say so (RFC 9000, section 13.2).
 * \~spanish Lo que recibio un extremo QUIC, y cuando decirlo (RFC 9000, seccion 13.2).
 * \~
 *
 * \~english
 * One tracker per packet number space -- Initial, Handshake and application
 * data each number their packets from zero, and each is acknowledged only in
 * its own space.  It answers three questions: is this packet new, which
 * ranges go in the next ACK, and must that ACK go out now or can it wait.
 *
 * **Its memory is fixed.**  A peer that sends every other packet number makes
 * one range per packet, and a tracker that kept them all would give that
 * peer a way to grow this server's memory without bound.  So it keeps a
 * fixed number of ranges, and when it has to drop one it drops the lowest
 * and raises a FLOOR: everything below it counts as already seen.  That is
 * what RFC 9000, 13.2.3 allows -- a range may be forgotten only if packets in
 * it will not be accepted again -- and the cost is that a very late packet is
 * dropped as if it were a duplicate.  Every frame is idempotent, so the peer
 * sends its content again; no data is lost, only a retransmission is spent.
 *
 * Time is passed in, in microseconds, and never read here: the same rule as
 * the timer wheel, so that a test can say "2 ms later" without waiting 2 ms.
 *
 * \~spanish
 * Un seguidor por espacio de numeros de paquete -- Initial, Handshake y datos
 * de aplicacion numeran cada uno sus paquetes desde cero, y cada uno se
 * confirma solo en su propio espacio.  Contesta tres preguntas: si este paquete
 * es nuevo, que rangos van en el proximo ACK, y si ese ACK tiene que salir ya o
 * puede esperar.
 *
 * **Su memoria es fija.**  Un extremo que manda un numero de paquete si y otro
 * no crea un rango por paquete, y un seguidor que los guardara todos le daria a
 * ese extremo una forma de hacer crecer sin limite la memoria de este servidor.
 * Asi que guarda un numero fijo de rangos, y cuando tiene que soltar uno suelta
 * el mas bajo y sube un SUELO: todo lo de debajo cuenta como ya visto.  Es lo
 * que permite el RFC 9000, 13.2.3 -- un rango solo se puede olvidar si no se van
 * a aceptar otra vez paquetes de el --, y el precio es que un paquete muy tardio
 * se tira como si fuera un duplicado.  Todas las tramas son idempotentes, asi
 * que el otro extremo vuelve a mandar su contenido; no se pierde ningun dato,
 * solo se gasta una retransmision.
 *
 * El tiempo se pasa desde fuera, en microsegundos, y aqui no se lee nunca: la
 * misma regla que la rueda de plazos, para que una prueba pueda decir "2 ms
 * despues" sin esperar 2 ms.
 * \~
 */
#ifndef HTTP_VX_QUIC_ACK_H
#define HTTP_VX_QUIC_ACK_H

#include "http_vx/quic_frame.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english How many ranges one tracker remembers.  \~spanish Cuantos rangos recuerda un seguidor.  \~
constexpr size_t kAckRanges = 16;

/// \~english No deadline.  \~spanish Sin plazo.  \~
constexpr uint64_t kNever = UINT64_MAX;

/**
 * @brief
 * \~english The ECN codepoint a packet arrived with, from its IP header.
 * \~spanish El codigo ECN con el que llego un paquete, de su cabecera IP.
 * \~
 */
enum class Ecn : uint8_t { NotEct, Ect0, Ect1, Ce };

/**
 * @brief
 * \~english What receiving a packet number turned out to be.
 * \~spanish Lo que resulto ser recibir un numero de paquete.
 * \~
 */
enum class Receipt : uint8_t {
    New,
    /// \~english Seen before: drop it without processing.  \~spanish Ya visto: se tira sin procesarlo.  \~
    Duplicate,
    /**
     * \~english
     * Below the floor: it may or may not have been seen, and it is treated as
     * seen, because the range that would say was forgotten.
     * \~spanish
     * Por debajo del suelo: puede que se viera o no, y se trata como visto,
     * porque el rango que lo diria se olvido.
     * \~
     */
    TooOld,
};

/**
 * @brief
 * \~english How a tracker behaves: set once per packet number space.
 * \~spanish Como se porta un seguidor: se fija una vez por espacio de numeros de paquete.
 * \~
 */
struct AckPolicy {
    /**
     * \~english
     * Acknowledge every ack-eliciting packet at once: required for the
     * Initial and Handshake spaces (13.2.1), where every round trip is part
     * of the handshake.
     * \~spanish
     * Confirmar al momento cada paquete que pide confirmacion: obligatorio en
     * los espacios Initial y Handshake (13.2.1), donde cada viaje de ida y vuelta
     * es parte del saludo.
     * \~
     */
    bool immediate = false;

    /// \~english The max_ack_delay this end announced, in microseconds.
    /// \~spanish El max_ack_delay que anuncio este extremo, en microsegundos.  \~
    uint64_t max_ack_delay_us = 25000;

    /// \~english After this many ack-eliciting packets, an ACK goes out now (13.2.2).
    /// \~spanish Tras estos paquetes que piden confirmacion, un ACK sale ya (13.2.2).  \~
    uint32_t eliciting_threshold = 2;

    /// \~english The ack_delay_exponent this end announced.  \~spanish El ack_delay_exponent que anuncio este extremo.  \~
    uint8_t ack_delay_exponent = 3;
};

/**
 * @brief
 * \~english The received side of one packet number space.
 * \~spanish El lado de recepcion de un espacio de numeros de paquete.
 * \~
 */
class AckTracker {
public:
    explicit AckTracker(const AckPolicy &policy = AckPolicy{}) noexcept : policy_(policy) {}

    /**
     * @brief
     * \~english Whether @p pn would be new, without recording anything.
     * \~spanish Si @p pn seria nuevo, sin anotar nada.
     * \~
     *
     * \~english
     * Asked before processing -- a duplicate must not be processed twice --
     * and `on_received` records it after, once the packet was opened and its
     * frames accepted: a packet that fails authentication is not received.
     * \~spanish
     * Se pregunta antes de procesar -- un duplicado no se tiene que procesar dos
     * veces -- y `on_received` lo anota despues, una vez abierto el paquete y
     * aceptadas sus tramas: un paquete que no se autentica no se ha recibido.
     * \~
     */
    Receipt classify(uint64_t pn) const noexcept;

    /// \~english Records @p pn as received and processed at @p now_us.
    /// \~spanish Anota @p pn como recibido y procesado en @p now_us.  \~
    Receipt on_received(uint64_t pn, bool ack_eliciting, Ecn ecn,
                        uint64_t now_us) noexcept;

    /// \~english Whether any packet was ever received here.  \~spanish Si alguna vez se recibio aqui un paquete.  \~
    bool any() const noexcept { return any_; }

    /// \~english The largest packet number received; kept even when its range is dropped.
    /// \~spanish El mayor numero de paquete recibido; se guarda aunque se suelte su rango.  \~
    uint64_t largest() const noexcept { return largest_; }

    /// \~english What `decode_packet_number` expects: one past the largest, or zero.
    /// \~spanish Lo que espera `decode_packet_number`: uno mas que el mayor, o cero.  \~
    uint64_t expected_pn() const noexcept { return any_ ? largest_ + 1 : 0; }

    /// \~english Whether an ACK must go out without waiting.  \~spanish Si un ACK tiene que salir sin esperar.  \~
    bool ack_now() const noexcept { return ack_now_; }

    /// \~english When an ACK must have gone out; kNever if none is owed.
    /// \~spanish Cuando tiene que haber salido un ACK; kNever si no se debe ninguno.  \~
    uint64_t ack_deadline() const noexcept;

    /**
     * @brief
     * \~english Writes the ACK frame for what was received, as much as fits.
     * \~spanish Escribe la trama ACK de lo recibido, todo lo que quepa.
     * \~
     *
     * \~english
     * The most recent ranges go first and the oldest are left out if the
     * frame does not fit (13.2.3); the range with the largest packet number
     * is never left out -- if even that does not fit, nothing is written.
     * \~spanish
     * Los rangos mas recientes van primero y los mas viejos se quedan fuera si
     * la trama no cabe (13.2.3); el rango con el mayor numero de paquete no se
     * queda fuera nunca -- si ni ese cabe, no se escribe nada.
     * \~
     *
     * @return \~english bytes written, zero if nothing to acknowledge or no room
     *         \~spanish bytes escritos, cero si no hay nada que confirmar o no hay sitio  \~
     */
    size_t write_ack(uint8_t *p, size_t room, uint64_t now_us) const noexcept;

    /// \~english The ACK just written went out: nothing is owed until more arrives.
    /// \~spanish El ACK recien escrito salio: no se debe nada hasta que llegue mas.  \~
    void on_ack_sent() noexcept;

    /**
     * @brief
     * \~english The peer acknowledged a packet that carried an ACK up to @p largest (13.2.4).
     * \~spanish El otro extremo confirmo un paquete que llevaba un ACK hasta @p largest (13.2.4).
     * \~
     *
     * \~english
     * The peer has seen everything up to there acknowledged, so it need not be
     * acknowledged again: those ranges are dropped and the floor rises.
     * \~spanish
     * El otro extremo ya vio confirmado todo hasta ahi, asi que no hace falta
     * volver a confirmarlo: esos rangos se sueltan y el suelo sube.
     * \~
     */
    void on_ack_acknowledged(uint64_t largest) noexcept;

    /// \~english How many ranges are held now.  \~spanish Cuantos rangos hay ahora.  \~
    size_t ranges() const noexcept { return count_; }

    /// \~english The i-th range, largest first.  \~spanish El rango i-esimo, del mayor al menor.  \~
    const AckRange &range(size_t i) const noexcept { return r_[i]; }

    /// \~english Everything below this counts as seen.  \~spanish Todo lo de debajo de esto cuenta como visto.  \~
    uint64_t floor() const noexcept { return floor_; }

    /// \~english How many ranges were dropped for lack of room -- observable, not silent.
    /// \~spanish Cuantos rangos se soltaron por falta de sitio -- observable, no en silencio.  \~
    uint64_t ranges_evicted() const noexcept { return evicted_; }

private:
    void insert(uint64_t pn) noexcept;
    void drop_lowest() noexcept;

    AckPolicy policy_;
    AckRange r_[kAckRanges];
    size_t count_ = 0;
    uint64_t floor_ = 0;
    uint64_t largest_ = 0;
    uint64_t largest_time_ = 0;
    uint64_t largest_eliciting_ = 0;
    bool any_ = false;
    bool any_eliciting_ = false;

    bool ack_now_ = false;
    uint32_t eliciting_unacked_ = 0;
    uint64_t first_unacked_time_ = 0;

    uint64_t ecn_[3] = {0, 0, 0};
    uint64_t evicted_ = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_ACK_H
