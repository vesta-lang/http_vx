/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_acceptor.h
 * @brief
 * \~english What a QUIC server does with a datagram no connection owns (RFC 9000, 5.2.2, 6, 8.1).
 * \~spanish Lo que hace un servidor QUIC con un datagrama que no es de ninguna conexion (RFC 9000, 5.2.2, 6, 8.1).
 * \~
 *
 * \~english
 * Before a connection exists there is no state to lean on, and there must
 * not be: this is the part of the server a stranger reaches with a single
 * forged datagram, so anything it did that cost memory would be a way to
 * exhaust it.  The acceptor keeps nothing between datagrams.  For each one
 * it answers with one of three things:
 *
 *   - drop it (counted by reason);
 *   - reply statelessly -- Version Negotiation for a version this server
 *     does not speak, Retry to make the client prove its address, or an
 *     immediate CONNECTION_CLOSE with INVALID_TOKEN for a Retry token that
 *     does not hold;
 *   - accept it: a connection may now be created for it.
 *
 * **The Retry token carries the state instead.**  It is sealed with a key
 * only this server holds, bound to the client's address as associated data,
 * and holds the original destination ID, the Retry's own ID and the time it
 * was issued.  When the client returns it, the server learns all it needs
 * without having remembered anything -- and a token copied to another
 * address, or kept past its lifetime, does not open.
 *
 * \~spanish
 * Antes de que exista una conexion no hay estado en el que apoyarse, y no debe
 * haberlo: esta es la parte del servidor a la que llega un desconocido con un
 * solo datagrama falsificado, asi que cualquier cosa que hiciera que costara
 * memoria seria una forma de agotarla.  El acceptor no guarda nada entre
 * datagramas.  Para cada uno contesta una de tres cosas:
 *
 *   - tirarlo (contado por motivo);
 *   - responder sin estado -- Version Negotiation para una version que este
 *     servidor no habla, Retry para que el cliente pruebe su direccion, o un
 *     CONNECTION_CLOSE inmediato con INVALID_TOKEN para un testigo de Retry que
 *     no se sostiene;
 *   - aceptarlo: ya se puede crear una conexion para el.
 *
 * **El testigo de Retry lleva el estado en su lugar.**  Va sellado con una
 * clave que solo tiene este servidor, atado a la direccion del cliente como
 * datos asociados, y lleva el identificador de destino original, el del propio
 * Retry y la hora en que se emitio.  Cuando el cliente lo devuelve, el servidor
 * sabe todo lo que necesita sin haber recordado nada -- y un testigo copiado a
 * otra direccion, o guardado pasado su plazo, no abre.
 * \~
 */
#ifndef HTTP_VX_QUIC_ACCEPTOR_H
#define HTTP_VX_QUIC_ACCEPTOR_H

#include "http_vx/quic_crypto.h"
#include "http_vx/quic_packet.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english How the acceptor behaves.
 * \~spanish Como se porta el acceptor.
 * \~
 */
struct AcceptorConfig {
    /// \~english The versions this server speaks, preferred first.
    /// \~spanish Las versiones que habla este servidor, la preferida primero.  \~
    uint32_t versions[4] = {kVersion1, kVersion2, 0, 0};
    size_t version_count = 2;

    /// \~english Make every new client prove its address with a Retry first (8.1.2).
    /// \~spanish Hacer que cada cliente nuevo pruebe primero su direccion con un Retry (8.1.2).  \~
    bool require_retry = false;

    /// \~english The key Retry tokens are sealed with: secret, and this server's only.
    /// \~spanish La clave con la que se sellan los testigos de Retry: secreta, y solo de este servidor.  \~
    uint8_t token_key[16] = {};

    /// \~english How long a Retry token is good for.  \~spanish Cuanto vale un testigo de Retry.  \~
    uint64_t token_lifetime_us = 10000000;

    /// \~english The length of the connection IDs this server hands out.
    /// \~spanish La longitud de los identificadores de conexion que reparte este servidor.  \~
    size_t cid_len = 8;
};

/**
 * @brief
 * \~english What became of a datagram.
 * \~spanish Que fue de un datagrama.
 * \~
 */
enum class Admit : uint8_t {
    /// \~english Dropped; see the reason.  \~spanish Tirado; ver el motivo.  \~
    Drop,
    /// \~english Answered with the bytes in the reply buffer.  \~spanish Contestado con los bytes del buffer de respuesta.  \~
    Reply,
    /// \~english A connection may be created for it.  \~spanish Se puede crear una conexion para el.  \~
    Accept,
};

/**
 * @brief
 * \~english Why, in detail: every outcome has a name, and a counter.
 * \~spanish Por que, en detalle: cada resultado tiene nombre, y un contador.
 * \~
 */
enum class AdmitReason : uint8_t {
    Accepted,
    AcceptedWithToken,
    SentVersionNegotiation,
    SentRetry,
    SentInvalidToken,
    /// \~english Not parseable as QUIC.  \~spanish No se puede leer como QUIC.  \~
    BadHeader,
    /// \~english A short header for no known connection (stateless reset, later).
    /// \~spanish Una cabecera corta de ninguna conexion conocida (reinicio sin estado, mas adelante).  \~
    UnknownConnection,
    /// \~english A known version, but not an Initial: nothing to start from (5.2.2).
    /// \~spanish Una version conocida, pero no un Initial: nada desde lo que empezar (5.2.2).  \~
    NotInitial,
    /// \~english Under 1200 bytes: could make the server an amplifier (14.1).
    /// \~spanish Menos de 1200 bytes: podria hacer del servidor un amplificador (14.1).  \~
    TooSmall,
    /// \~english A first destination ID under 8 bytes (7.2).  \~spanish Un primer identificador de destino de menos de 8 bytes (7.2).  \~
    ShortDestination,
    /// \~english A Version Negotiation packet: never answered with another (6.1).
    /// \~spanish Un paquete Version Negotiation: nunca se contesta con otro (6.1).  \~
    VersionNegotiationReceived,
    /// \~english The provider failed: said, not guessed around.  \~spanish Fallo el proveedor: dicho, no rodeado.  \~
    ProviderFailed,
    /// \~english Used although `ready()` said no.  \~spanish Usado aunque `ready()` dijo que no.  \~
    NotReady,
    kCount,
};

/// \~english A short name for @p r.  \~spanish Un nombre corto para @p r.  \~
const char *admit_reason_name(AdmitReason r) noexcept;

/**
 * @brief
 * \~english The verdict on one datagram, and what a new connection needs to start.
 * \~spanish El veredicto sobre un datagrama, y lo que necesita una conexion nueva para empezar.
 * \~
 */
struct Admission {
    Admit verdict = Admit::Drop;
    AdmitReason reason = AdmitReason::BadHeader;
    /// \~english Bytes to send back, on `Reply`.  \~spanish Bytes que devolver, en `Reply`.  \~
    size_t reply_len = 0;

    /// \~english On `Accept`: the version the client chose.  \~spanish En `Accept`: la version que eligio el cliente.  \~
    uint32_t version = 0;
    /// \~english The client's very first destination ID: original_destination_connection_id.
    /// \~spanish El primer identificador de destino del cliente: original_destination_connection_id.  \~
    uint8_t odcid[kMaxConnectionId] = {};
    size_t odcid_len = 0;
    /// \~english This packet's destination ID: the Initial keys come from it.
    /// \~spanish El identificador de destino de este paquete: de el salen las claves Initial.  \~
    uint8_t dcid[kMaxConnectionId] = {};
    size_t dcid_len = 0;
    /// \~english The client's source ID: where the server's packets go.
    /// \~spanish El identificador de origen del cliente: adonde van los paquetes del servidor.  \~
    uint8_t scid[kMaxConnectionId] = {};
    size_t scid_len = 0;
    /// \~english A Retry token proved the address: no amplification limit (8.1).
    /// \~spanish Un testigo de Retry probo la direccion: sin limite de amplificacion (8.1).  \~
    bool address_validated = false;
};

/**
 * @brief
 * \~english The stateless front door of a QUIC server.
 * \~spanish La puerta de entrada sin estado de un servidor QUIC.
 * \~
 */
class Acceptor {
public:
    Acceptor(Crypto &crypto, const AcceptorConfig &config) noexcept;
    ~Acceptor();

    Acceptor(const Acceptor &) = delete;
    Acceptor &operator=(const Acceptor &) = delete;

    /**
     * @brief
     * \~english Whether the configuration holds and the token key could be prepared.
     * \~spanish Si la configuracion se sostiene y se pudo preparar la clave de los testigos.
     * \~
     *
     * \~english
     * An ID longer than twenty bytes, or more versions than fit, is refused
     * here rather than written past the end of a buffer later.  A server that
     * is not ready must not start (R24).
     * \~spanish
     * Un identificador de mas de veinte bytes, o mas versiones de las que caben,
     * se rechaza aqui en vez de escribirse despues mas alla del final de un
     * buffer.  Un servidor que no esta listo no debe arrancar (R24).
     * \~
     */
    bool ready() const noexcept { return token_state_ != nullptr; }

    /**
     * @brief
     * \~english Decides on a datagram for which no connection exists.
     * \~spanish Decide sobre un datagrama para el que no existe conexion.
     * \~
     *
     * @param address \~english the client's address, as bytes: what a token is bound to
     *                \~spanish la direccion del cliente, como bytes: a lo que se ata un testigo  \~
     * @param reply   \~english where a reply is written; at least 1200 bytes
     *                \~spanish donde se escribe una respuesta; al menos 1200 bytes  \~
     */
    Admission on_datagram(const uint8_t *data, size_t n, const uint8_t *address,
                          size_t address_len, uint64_t now_us, uint8_t *reply,
                          size_t reply_room) noexcept;

    /// \~english How many datagrams ended each way.  \~spanish Cuantos datagramas acabaron de cada forma.  \~
    uint64_t count(AdmitReason r) const noexcept { return counts_[static_cast<size_t>(r)]; }

private:
    bool speaks(uint32_t version) const noexcept;
    size_t write_version_negotiation(const uint8_t *data, const PacketHeader &h, uint8_t *out,
                                     size_t room) noexcept;
    size_t write_retry(const uint8_t *data, const PacketHeader &h, const uint8_t *address,
                       size_t address_len, uint64_t now_us, uint8_t *out, size_t room) noexcept;
    size_t write_invalid_token(const uint8_t *data, const PacketHeader &h, uint8_t *out,
                               size_t room) noexcept;
    bool open_token(const uint8_t *token, size_t len, const uint8_t *address, size_t address_len,
                    uint64_t now_us, const uint8_t *dcid, size_t dcid_len,
                    Admission &out) noexcept;
    Admission finish(Admission a) noexcept;

    Crypto &crypto_;
    AcceptorConfig cfg_;
    void *token_state_ = nullptr;
    uint64_t counts_[static_cast<size_t>(AdmitReason::kCount)] = {};
};

/// \~english The first byte of every Retry token this server issues.
/// \~spanish El primer byte de todo testigo de Retry que emite este servidor.  \~
constexpr uint8_t kRetryTokenMark = 0x52;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_ACCEPTOR_H
