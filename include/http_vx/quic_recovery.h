/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_recovery.h
 * @brief
 * \~english Loss detection and congestion control for QUIC (RFC 9002).
 * \~spanish Deteccion de perdidas y control de congestion de QUIC (RFC 9002).
 * \~
 *
 * \~english
 * The sending side of a connection: which packets are in flight, which of
 * them the peer acknowledged, which are lost, how long a round trip takes,
 * and how much may be sent now.  One object per connection, covering the
 * three packet number spaces, because RTT and the congestion window belong to
 * the path, not to a space.
 *
 * **Its memory is fixed, and a full table stops the sender.**  Sent packets
 * live in a ring per space, allocated once.  When a ring is full no packet
 * can be recorded, and `can_record` says so before anything is sent -- a
 * sender stalled by its own bookkeeping, visibly, rather than one whose
 * memory grows with a peer that never acknowledges.
 *
 * Acknowledged and lost packets stay in the ring as TOMBSTONES until they
 * leave from the front.  That is not waste: persistent congestion (7.6.2) is
 * declared only if no packet sent BETWEEN two lost ones was acknowledged, and
 * the tombstones are exactly what can say so.
 *
 * What the packets carried is not known here.  Each carries a tag the caller
 * chose, and acknowledgement and loss come back through a listener with that
 * tag: the stream layer decides what to retransmit.  Time is passed in, in
 * microseconds, as everywhere else.
 *
 * \~spanish
 * El lado emisor de una conexion: que paquetes estan en vuelo, cuales confirmo
 * el otro extremo, cuales se perdieron, cuanto tarda un viaje de ida y vuelta, y
 * cuanto se puede mandar ahora.  Un objeto por conexion, que cubre los tres
 * espacios de numeros de paquete, porque el RTT y la ventana de congestion son
 * del camino, no de un espacio.
 *
 * **Su memoria es fija, y una tabla llena para al emisor.**  Los paquetes
 * enviados viven en un anillo por espacio, reservado una vez.  Cuando un anillo
 * esta lleno no se puede anotar ningun paquete, y `can_record` lo dice antes de
 * mandar nada -- un emisor parado por su propia contabilidad, a la vista, en vez
 * de uno cuya memoria crece con un extremo que no confirma nunca.
 *
 * Los paquetes confirmados y perdidos se quedan en el anillo como LAPIDAS hasta
 * que salen por delante.  No es desperdicio: la congestion persistente (7.6.2)
 * solo se declara si ningun paquete enviado ENTRE dos perdidos fue confirmado, y
 * las lapidas son justo lo que puede decirlo.
 *
 * Lo que llevaban los paquetes no se sabe aqui.  Cada uno lleva una etiqueta que
 * eligio quien llama, y la confirmacion y la perdida vuelven por un oyente con
 * esa etiqueta: la capa de flujos decide que retransmitir.  El tiempo se pasa
 * desde fuera, en microsegundos, como en todo lo demas.
 * \~
 */
#ifndef HTTP_VX_QUIC_RECOVERY_H
#define HTTP_VX_QUIC_RECOVERY_H

#include "http_vx/quic_ack.h"
#include "http_vx/quic_frame.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english The three packet number spaces.  \~spanish Los tres espacios de numeros de paquete.  \~
enum class Space : uint8_t { Initial = 0, Handshake = 1, Application = 2 };

constexpr size_t kSpaces = 3;

/* \~english
 * RFC 9002, appendix A.2 and B.1, in microseconds and bytes.
 * \~spanish
 * RFC 9002, apendices A.2 y B.1, en microsegundos y bytes.
 * \~ */
constexpr uint64_t kPacketThreshold = 3;
constexpr uint64_t kGranularityUs = 1000;
constexpr uint64_t kInitialRttUs = 333000;
constexpr uint64_t kPersistentCongestionThreshold = 3;

/**
 * @brief
 * \~english One sent packet, as the recovery remembers it.
 * \~spanish Un paquete enviado, tal como lo recuerda la recuperacion.
 * \~
 */
struct SentPacket {
    uint64_t pn;
    uint64_t time_sent;
    /// \~english The caller's: what the packet carried.  \~spanish De quien llama: lo que llevaba el paquete.  \~
    uint64_t tag;
    /**
     * \~english
     * The Largest Acknowledged of the ACK frame this packet carried, or
     * kNever: when this packet is acknowledged, the peer has seen that ACK,
     * and `AckTracker::on_ack_acknowledged` can drop what it covered.
     * \~spanish
     * El Largest Acknowledged de la trama ACK que llevaba este paquete, o
     * kNever: cuando este paquete se confirma, el otro extremo vio ese ACK, y
     * `AckTracker::on_ack_acknowledged` puede soltar lo que cubria.
     * \~
     */
    uint64_t ack_largest;
    uint32_t bytes;
    bool ack_eliciting;
    /// \~english Counts toward bytes in flight: anything but ACK-only.
    /// \~spanish Cuenta en los bytes en vuelo: todo lo que no sea solo ACK.  \~
    bool in_flight;
    /// \~english Outstanding, acknowledged or lost; internal.  \~spanish Pendiente, confirmado o perdido; interno.  \~
    uint8_t state;
};

/**
 * @brief
 * \~english Who hears about acknowledged and lost packets.
 * \~spanish Quien se entera de los paquetes confirmados y perdidos.
 * \~
 */
class RecoveryListener {
public:
    virtual ~RecoveryListener() = default;
    virtual void on_acked(Space space, const SentPacket &p) noexcept = 0;
    virtual void on_lost(Space space, const SentPacket &p) noexcept = 0;
};

/**
 * @brief
 * \~english The values a connection starts with.
 * \~spanish Los valores con los que empieza una conexion.
 * \~
 */
struct RecoveryConfig {
    bool is_server = true;
    /// \~english The path's maximum datagram, 1200 until PMTU says more.
    /// \~spanish El datagrama maximo del camino, 1200 hasta que la PMTU diga mas.  \~
    uint32_t max_datagram_size = 1200;
    /// \~english The PEER's max_ack_delay, in microseconds.  \~spanish El max_ack_delay del OTRO extremo, en microsegundos.  \~
    uint64_t max_ack_delay_us = 25000;
    /// \~english The PEER's ack_delay_exponent.  \~spanish El ack_delay_exponent del OTRO extremo.  \~
    uint8_t peer_ack_delay_exponent = 3;
    /// \~english How many sent packets each space can remember.
    /// \~spanish Cuantos paquetes enviados puede recordar cada espacio.  \~
    uint32_t capacity[kSpaces] = {64, 64, 1024};
};

/**
 * @brief
 * \~english What processing an ACK frame found.
 * \~spanish Lo que encontro procesar una trama ACK.
 * \~
 */
enum class AckResult : uint8_t {
    Ok,
    /**
     * \~english
     * It acknowledges a packet number this end never sent: a
     * PROTOCOL_VIOLATION (RFC 9000, 13.1).  A peer that acknowledges what it
     * did not receive is trying to open the congestion window faster than
     * the path allows.
     * \~spanish
     * Confirma un numero de paquete que este extremo no mando nunca: un
     * PROTOCOL_VIOLATION (RFC 9000, 13.1).  Un extremo que confirma lo que no
     * recibio intenta abrir la ventana de congestion mas deprisa de lo que
     * permite el camino.
     * \~
     */
    AcknowledgedUnsent,
};

/**
 * @brief
 * \~english What a timer expiry asks of the sender.
 * \~spanish Lo que pide al emisor que venza el temporizador.
 * \~
 */
struct TimeoutAction {
    enum Kind : uint8_t {
        /// \~english The timer had not expired.  \~spanish El temporizador no habia vencido.  \~
        None,
        /// \~english Packets were declared lost by time; the listener heard which.
        /// \~spanish Se declararon paquetes perdidos por tiempo; el oyente oyo cuales.  \~
        Loss,
        /**
         * \~english
         * A probe timeout: send one or two ack-eliciting packets in `space`,
         * new data if there is any, else old data, else a PING (6.2.4).  They
         * go out whatever the congestion window says.
         * \~spanish
         * Un plazo de sondeo: mandar uno o dos paquetes que pidan confirmacion
         * en `space`, datos nuevos si los hay, si no viejos, si no un PING
         * (6.2.4).  Salen diga lo que diga la ventana de congestion.
         * \~
         */
        Probe,
    };
    Kind kind = None;
    Space space = Space::Initial;
};

/**
 * @brief
 * \~english The sending side of one connection.
 * \~spanish El lado emisor de una conexion.
 * \~
 */
class Recovery {
public:
    explicit Recovery(const RecoveryConfig &config = RecoveryConfig{}) noexcept;
    ~Recovery();

    Recovery(const Recovery &) = delete;
    Recovery &operator=(const Recovery &) = delete;

    /// \~english Whether the rings could be allocated.  \~spanish Si se pudieron reservar los anillos.  \~
    bool ready() const noexcept;

    /// \~english Whether one more packet fits in @p s's ring.
    /// \~spanish Si cabe un paquete mas en el anillo de @p s.  \~
    bool can_record(Space s) const noexcept;

    /**
     * @brief
     * \~english Whether the congestion window lets @p bytes more go out now.
     * \~spanish Si la ventana de congestion deja salir ahora @p bytes mas.
     * \~
     *
     * \~english True regardless of the window while probes are owed after a PTO.
     * \~spanish Verdadero sea cual sea la ventana mientras se deban sondeos tras un PTO.  \~
     */
    bool window_allows(uint64_t bytes) const noexcept;

    /**
     * @brief
     * \~english Records a packet just sent.
     * \~spanish Anota un paquete recien enviado.
     * \~
     *
     * @return \~english false if the ring is full or @p pn does not increase -- both the caller's bug
     *         \~spanish falso si el anillo esta lleno o @p pn no crece -- los dos, fallo de quien llama  \~
     */
    bool on_packet_sent(Space s, uint64_t pn, uint32_t bytes, bool ack_eliciting,
                        bool in_flight, uint64_t tag, uint64_t ack_largest,
                        uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Processes an ACK frame read from @p payload for space @p s.
     * \~spanish Procesa una trama ACK leida de @p payload para el espacio @p s.
     * \~
     */
    AckResult on_ack_received(Space s, const Frame &ack, const uint8_t *payload,
                              uint64_t now_us, RecoveryListener &l) noexcept;

    /// \~english When the loss detection timer fires; kNever if it is not armed.
    /// \~spanish Cuando vence el temporizador de perdidas; kNever si no esta armado.  \~
    uint64_t timer() const noexcept { return timer_; }

    /// \~english Handles the timer if it has expired at @p now_us.
    /// \~spanish Atiende el temporizador si vencio en @p now_us.  \~
    TimeoutAction on_timeout(uint64_t now_us, RecoveryListener &l) noexcept;

    /**
     * @brief
     * \~english Forgets a space whose keys were discarded (Initial or Handshake).
     * \~spanish Olvida un espacio cuyas claves se tiraron (Initial o Handshake).
     * \~
     */
    void discard_space(Space s, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english A client accepted a Retry: congestion control and loss recovery start over (6.3).
     * \~spanish Un cliente acepto un Retry: el control de congestion y la recuperacion empiezan de nuevo (6.3).
     * \~
     *
     * \~english
     * The Initial packets in flight were answered with a Retry, not received:
     * each is handed to @p l as lost, so its CRYPTO goes out again, but none
     * counts as a loss -- the path lost nothing.  Window, threshold, probe
     * count and timers go back to their starting values.  Packet numbers do
     * NOT: they keep growing (RFC 9000, 17.2.5.3).
     * \~spanish
     * Los paquetes Initial en vuelo recibieron un Retry por respuesta, no se
     * recibieron: cada uno se le pasa a @p l como perdido, para que su CRYPTO
     * salga otra vez, pero ninguno cuenta como perdida -- el camino no perdio
     * nada.  Ventana, umbral, cuenta de sondeos y temporizadores vuelven a sus
     * valores de partida.  Los numeros de paquete NO: siguen creciendo
     * (RFC 9000, 17.2.5.3).
     * \~
     */
    void on_retry(uint64_t now_us, RecoveryListener &l) noexcept;

    /* \~english
     * What the connection tells recovery as the handshake advances.  Each
     * re-arms the timer, because each changes which timer applies.
     * \~spanish
     * Lo que la conexion le dice a la recuperacion segun avanza el saludo.  Cada
     * una rearma el temporizador, porque cada una cambia que temporizador aplica.
     * \~ */
    void set_handshake_confirmed(uint64_t now_us) noexcept;
    void set_peer_address_validated(uint64_t now_us) noexcept;
    void set_has_handshake_keys(uint64_t now_us) noexcept;
    /// \~english A server at its anti-amplification limit sets no timer (A.8).
    /// \~spanish Un servidor en su limite antiamplificacion no pone temporizador (A.8).  \~
    void set_amplification_blocked(bool blocked, uint64_t now_us) noexcept;
    /// \~english Nothing to send: the window must not grow on acknowledgements (B.5).
    /// \~spanish Nada que mandar: la ventana no debe crecer con las confirmaciones (B.5).  \~
    void set_app_limited(bool limited) noexcept { app_limited_ = limited; }
    bool app_limited() const noexcept { return app_limited_; }

    /**
     * @brief
     * \~english The peer's max_ack_delay and ack_delay_exponent, once its transport parameters are known.
     * \~spanish El max_ack_delay y el ack_delay_exponent del otro, cuando se conocen sus parametros de transporte.
     * \~
     *
     * \~english
     * They are the peer's (RFC 9002, A.3; RFC 9000, 18.2) and arrive with the
     * handshake, after the connection exists; until then the defaults, 25 ms
     * and 3, are what the RFC says to assume.
     * \~spanish
     * Son los del otro (RFC 9002, A.3; RFC 9000, 18.2) y llegan con el saludo,
     * despues de que exista la conexion; hasta entonces, los valores por
     * defecto, 25 ms y 3, son lo que el RFC dice que se suponga.
     * \~
     */
    void set_peer_ack_params(uint64_t max_ack_delay_us, uint8_t ack_delay_exponent,
                             uint64_t now_us) noexcept;

    uint64_t latest_rtt() const noexcept { return latest_rtt_; }
    uint64_t smoothed_rtt() const noexcept { return smoothed_rtt_; }
    uint64_t rttvar() const noexcept { return rttvar_; }
    uint64_t min_rtt() const noexcept { return min_rtt_; }
    uint64_t congestion_window() const noexcept { return cwnd_; }
    uint64_t ssthresh() const noexcept { return ssthresh_; }
    uint64_t bytes_in_flight() const noexcept { return bytes_in_flight_; }
    uint32_t pto_count() const noexcept { return pto_count_; }
    uint32_t probes_owed() const noexcept { return probes_; }
    uint64_t largest_acked(Space s) const noexcept { return largest_acked_[idx(s)]; }

    /// \~english Counters: what happened, for whoever watches.
    /// \~spanish Contadores: lo que paso, para quien mire.  \~
    uint64_t packets_lost() const noexcept { return lost_; }
    uint64_t congestion_events() const noexcept { return congestion_events_; }
    uint64_t persistent_congestion_events() const noexcept { return persistent_; }
    uint64_t pto_events() const noexcept { return pto_events_; }

    /// \~english The minimum and initial windows for this path.
    /// \~spanish Las ventanas minima e inicial de este camino.  \~
    uint64_t minimum_window() const noexcept { return 2ull * cfg_.max_datagram_size; }
    uint64_t initial_window() const noexcept;

private:
    struct Ring {
        SentPacket *buf = nullptr;
        uint32_t cap = 0;
        uint32_t head = 0;
        uint32_t size = 0;
        SentPacket &at(uint32_t i) const noexcept { return buf[(head + i) % cap]; }
    };

    static size_t idx(Space s) noexcept { return static_cast<size_t>(s); }

    void update_rtt(uint64_t ack_delay_us, uint64_t now_us) noexcept;
    void detect_lost(Space s, uint64_t now_us, RecoveryListener &l) noexcept;
    void congestion_event(uint64_t sent_time, uint64_t now_us) noexcept;
    void on_acked_cc(const SentPacket &p) noexcept;
    bool in_recovery(uint64_t sent_time) const noexcept;
    bool peer_validated() const noexcept;
    bool any_eliciting_in_flight() const noexcept;
    uint64_t pto_base() const noexcept;
    uint64_t pto_time(Space &space, uint64_t now_us) const noexcept;
    uint64_t loss_time(Space &space) const noexcept;
    void pop_front(Ring &r) noexcept;
    void set_timer(uint64_t now_us) noexcept;

    RecoveryConfig cfg_;
    Ring ring_[kSpaces];
    bool ready_ = false;

    uint64_t largest_sent_[kSpaces] = {0, 0, 0};
    bool any_sent_[kSpaces] = {false, false, false};
    uint64_t largest_acked_[kSpaces] = {kNever, kNever, kNever};
    uint64_t last_eliciting_time_[kSpaces] = {0, 0, 0};
    uint64_t loss_time_[kSpaces] = {0, 0, 0};
    uint32_t eliciting_in_flight_[kSpaces] = {0, 0, 0};
    uint64_t ecn_ce_[kSpaces] = {0, 0, 0};

    uint64_t latest_rtt_ = 0;
    uint64_t smoothed_rtt_ = kInitialRttUs;
    uint64_t rttvar_ = kInitialRttUs / 2;
    uint64_t min_rtt_ = 0;
    uint64_t first_rtt_sample_ = 0;
    bool has_rtt_sample_ = false;

    uint64_t cwnd_;
    uint64_t ssthresh_ = kNever;
    uint64_t bytes_in_flight_ = 0;
    uint64_t bytes_acked_ca_ = 0;
    uint64_t recovery_start_ = 0;
    bool in_recovery_period_ = false;
    bool app_limited_ = false;

    uint32_t pto_count_ = 0;
    uint32_t probes_ = 0;
    uint64_t timer_ = kNever;

    bool handshake_confirmed_ = false;
    bool peer_address_validated_ = false;
    bool has_handshake_keys_ = false;
    bool amplification_blocked_ = false;

    uint64_t lost_ = 0;
    uint64_t congestion_events_ = 0;
    uint64_t persistent_ = 0;
    uint64_t pto_events_ = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_RECOVERY_H
