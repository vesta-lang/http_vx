/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_service.h
 * @brief
 * \~english HTTP/1.1 and HTTP/2 over TLS 1.3: a stream service that decrypts for another one and encrypts what it answers.
 * \~spanish HTTP/1.1 y HTTP/2 sobre TLS 1.3: un servicio de flujo que descifra para otro y cifra lo que contesta.
 * \~
 *
 * \~english
 * The shard knows bytes and services, and this is one more service: what
 * comes in is records, what goes to the inner service is the plaintext, what
 * the inner service writes goes out in records.  The inner services do not
 * know TLS is there -- Http1Service and Http2Service run unchanged -- and the
 * shard does not know it is serving HTTPS.
 *
 * **ALPN (RFC 7301) chooses the inner service.**  The server offers "h2" when
 * it has an Http2Service and "http/1.1" when it has an Http1Service, in that
 * order of preference; the client's list decides between them (3.2).  A
 * client that offers neither gets no_application_protocol; one that offers no
 * ALPN at all gets HTTP/1.1, or -- with only HTTP/2 here, which MUST be
 * negotiated (RFC 9113, 3.2) -- no_application_protocol too.
 *
 * **Memory per connection.**  Fixed, in a contiguous array indexed by slot
 * (R2): one Slot -- a Channel (two RecordKeys, the ALPN answer, flags and
 * counters) plus the plaintext buffer's index and stream position; its size
 * is `slot_size()`, printed by the test.  Besides that, the provider's two
 * prepared AEAD states, which are the provider's own memory.  During the
 * handshake only, the Session (`sizeof(tls::Session)`) and its transcript,
 * a few kilobytes, given back once the handshake completes.  A plaintext
 * buffer is lent from this service's own pool while a message is half
 * decrypted-and-unread and returned the moment it is not (R1): an idle TLS
 * connection holds no buffer.  The inner service's answer is written into ONE
 * scratch buffer shared by every connection -- the shard runs one call at a
 * time -- and sealed from there into the shard's output.
 *
 * **Not done over TCP: 0-RTT.**  Tickets issued here never allow early data,
 * and early data offered anyway is turned down and skipped (tls_channel.h).
 * Replayable requests are the price of 0-RTT, and over TCP it buys one round
 * trip that HTTP/3 already offers without TCP's.
 *
 * \~spanish
 * El fragmento sabe de bytes y servicios, y esto es un servicio mas: lo que
 * entra son registros, lo que va al servicio de dentro es el texto en claro, lo
 * que escribe el servicio de dentro sale en registros.  Los servicios de dentro
 * no saben que TLS esta ahi -- Http1Service y Http2Service corren sin cambios --
 * y el fragmento no sabe que sirve HTTPS.
 *
 * **ALPN (RFC 7301) elige el servicio de dentro.**  El servidor ofrece "h2"
 * cuando tiene un Http2Service y "http/1.1" cuando tiene un Http1Service, en
 * ese orden de preferencia; la lista del cliente decide entre ellos (3.2).  Un
 * cliente que no ofrece ninguno recibe no_application_protocol; uno que no
 * ofrece ALPN recibe HTTP/1.1, o -- con solo HTTP/2 aqui, que DEBE negociarse
 * (RFC 9113, 3.2) -- tambien no_application_protocol.
 *
 * **Memoria por conexion.**  Fija, en un array contiguo indexado por casilla
 * (R2): una Slot -- un Channel (dos RecordKeys, la respuesta de ALPN, marcas y
 * contadores) mas el indice y la posicion en el flujo del buffer en claro; su
 * tamano es `slot_size()`, que imprime la prueba.  Aparte, los dos estados AEAD
 * preparados del proveedor, que son memoria del proveedor.  Solo durante el
 * saludo, la Session (`sizeof(tls::Session)`) y su transcripcion, unos pocos
 * kilobytes, devueltos cuando el saludo se completa.  Un buffer en claro se
 * presta del pozo propio de este servicio mientras un mensaje esta descifrado a
 * medias y sin leer, y se devuelve en cuanto no (R1): una conexion TLS ociosa no
 * tiene buffer.  La respuesta del servicio de dentro se escribe en UN buffer de
 * trabajo compartido por todas las conexiones -- el fragmento hace una llamada
 * cada vez -- y se sella desde ahi a la salida del fragmento.
 *
 * **Lo que no se hace sobre TCP: 0-RTT.**  Los tickets que se emiten aqui nunca
 * permiten datos tempranos, y los datos tempranos ofrecidos de todos modos se
 * rechazan y se saltan (tls_channel.h).  Las peticiones repetibles son el precio
 * del 0-RTT, y sobre TCP compra una ida y vuelta que HTTP/3 ya ofrece sin la de
 * TCP.
 * \~
 */
#ifndef HTTP_VX_TLS_SERVICE_H
#define HTTP_VX_TLS_SERVICE_H

#include "http_vx/buffer_pool.h"
#include "http_vx/shard.h"
#include "http_vx/tls_channel.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What a TLS service is built with.  Every pointer is the caller's and outlives the service.
 * \~spanish Con que se hace un servicio TLS.  Cada puntero es de quien llama y vive mas que el servicio.
 * \~
 */
struct TlsServiceConfig {
    /// \~english The provider (R22); without one there is no TLS, and reset() says so (R24).
    /// \~spanish El proveedor (R22); sin uno no hay TLS, y reset() lo dice (R24).  \~
    quic::Crypto *crypto = nullptr;
    /// \~english The inner services; at least one.  \~spanish Los servicios de dentro; al menos uno.  \~
    Service *http1 = nullptr;
    Service *http2 = nullptr;

    /// \~english The chain, end-entity first (DER), and the provider's signing key for it.
    /// \~spanish La cadena, el certificado final primero (DER), y la clave de firma del proveedor para el.  \~
    const uint8_t *const *certificates = nullptr;
    const size_t *certificate_lens = nullptr;
    size_t certificate_count = 0;
    void *signing_key = nullptr;
    quic::Scheme scheme = quic::Scheme::EcdsaSecp256r1Sha256;

    /// \~english Resumption: tickets are issued and taken back when set (tls_ticket.h).
    /// \~spanish Reanudacion: con esto se emiten tickets y se aceptan de vuelta (tls_ticket.h).  \~
    const tls::TicketSealer *tickets = nullptr;

    /// \~english Plaintext buffers: fewer than connections, as with the shard's (R1).
    /// \~spanish Buffers en claro: menos que conexiones, como los del fragmento (R1).  \~
    uint32_t buffers = 128;
    /// \~english The most a buffer keeps between tenants.  \~spanish Lo mas que guarda un buffer entre inquilinos.  \~
    size_t buffer_ceiling = 1 << 20;
};

/**
 * @brief
 * \~english Serves TLS 1.3 over a stream, routing each connection by ALPN to an inner service.
 * \~spanish Sirve TLS 1.3 sobre un flujo, llevando cada conexion segun ALPN a un servicio de dentro.
 * \~
 */
class TlsService final : public Service {
public:
    TlsService() noexcept = default;
    ~TlsService() override;

    /**
     * @brief
     * \~english Makes room for @p connections; false, with why(), when it cannot serve TLS.
     * \~spanish Hace sitio para @p connections; falso, con why(), cuando no puede servir TLS.
     * \~
     *
     * \~english
     * No provider, no certificate, no key or no inner service are refused
     * here, at start, rather than on every connection (R24).  The inner
     * services must have been reset for the same connections: they index
     * their state by the same slots.
     * \~spanish
     * Sin proveedor, sin certificado, sin clave o sin servicio de dentro se
     * rechaza aqui, al arrancar, y no en cada conexion (R24).  Los servicios de
     * dentro tienen que estar preparados para las mismas conexiones: indexan su
     * estado por las mismas casillas.
     * \~
     */
    bool reset(uint32_t connections, const TlsServiceConfig &cfg) noexcept;

    bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override;
    void on_open(ConnHandle c) noexcept override;
    void on_close(ConnHandle c) noexcept override;

    /// \~english The clock for tickets, in microseconds; the loop sets it.  \~spanish El reloj de los tickets, en microsegundos; lo pone el bucle.  \~
    void set_clock(uint64_t now_us) noexcept { clock_us_ = now_us; }

    /// \~english Why reset() refused.  \~spanish Por que rechazo reset().  \~
    const char *why() const noexcept { return why_; }
    /// \~english Handshakes completed, and connections an alert ended.  \~spanish Saludos completados, y conexiones que acabo una alerta.  \~
    size_t handshakes() const noexcept { return handshakes_; }
    size_t failures() const noexcept { return failures_; }
    /// \~english Connections closed for want of a plaintext buffer.  \~spanish Conexiones cerradas por falta de un buffer en claro.  \~
    size_t starved() const noexcept { return starved_; }
    /// \~english The last failure: its alert, whether the peer sent it, and why.
    /// \~spanish El ultimo fallo: su alerta, si la mando el otro, y por que.  \~
    tls::Alert last_alert() const noexcept { return last_alert_; }
    bool last_alert_received() const noexcept { return last_received_; }
    const char *last_failure() const noexcept { return last_why_; }
    /// \~english The plaintext buffers lent now.  \~spanish Los buffers en claro prestados ahora.  \~
    size_t buffers_lent() const noexcept { return plain_.lent(); }
    /// \~english The fixed memory one connection takes here.  \~spanish La memoria fija que ocupa aqui una conexion.  \~
    static size_t slot_size() noexcept;
    /// \~english The channel of @p c, for what a test or a log wants to see.  \~spanish El canal de @p c, para lo que quiera ver una prueba o un registro.  \~
    const tls::Channel *channel(ConnHandle c) const noexcept;

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

private:
    struct Slot;

    bool route(ConnHandle c, Slot &s) noexcept;
    bool finish(ConnHandle c, Slot &s, Buffer &out, bool keep) noexcept;
    void give_back(Slot &s) noexcept;

    Slot *slots_ = nullptr;
    uint32_t capacity_ = 0;
    BufferPool plain_;
    Buffer scratch_;
    TlsServiceConfig cfg_;
    tls::SessionConfig session_;
    const char *alpn_[2] = {nullptr, nullptr};
    uint64_t clock_us_ = 0;
    const char *why_ = nullptr;
    size_t handshakes_ = 0;
    size_t failures_ = 0;
    size_t starved_ = 0;
    tls::Alert last_alert_ = tls::Alert::None;
    bool last_received_ = false;
    const char *last_why_ = nullptr;
};

} // namespace http_vx

#endif // HTTP_VX_TLS_SERVICE_H
