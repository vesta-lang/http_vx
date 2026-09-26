/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_schedule.h
 * @brief
 * \~english TLS 1.3's key schedule: the transcript, and every secret that comes from it (RFC 8446, 7.1).
 * \~spanish El calendario de claves de TLS 1.3: la transcripcion, y cada secreto que sale de ella (RFC 8446, 7.1).
 * \~
 *
 * \~english
 * The first piece of this project's own TLS 1.3.  R22 keeps TLS libraries
 * out and draws the line at the primitives: the provider hashes, runs HKDF
 * and HMAC; which labels, which transcript and in which order is TLS, and
 * lives here, checked once against RFC 8448's traces for every provider.
 *
 * **The transcript is kept, not hashed as it goes.**  A handshake needs its
 * hash at a handful of points (4.4.1), and keeping the few kilobytes of
 * messages means no provider has to copy a running hash state -- and the
 * hash can be chosen after the messages arrive, which is how it is: the
 * ClientHello is written before the ServerHello says which suite, and so
 * which hash.
 *
 * \~spanish
 * La primera pieza del TLS 1.3 propio de este proyecto.  La R22 deja fuera las
 * bibliotecas de TLS y pone la linea en las primitivas: el proveedor resume,
 * ejecuta HKDF y HMAC; que etiquetas, que transcripcion y en que orden es TLS, y
 * vive aqui, comprobado una vez contra las trazas del RFC 8448 para todos los
 * proveedores.
 *
 * **La transcripcion se guarda, no se resume segun llega.**  Un saludo necesita
 * su resumen en un punado de puntos (4.4.1), y guardar los pocos kilobytes de
 * mensajes hace que ningun proveedor tenga que copiar un estado de resumen a
 * medias -- y que el resumen se pueda elegir despues de que lleguen los
 * mensajes, que es como pasa: el ClientHello se escribe antes de que el
 * ServerHello diga que algoritmo, y por tanto que resumen.
 * \~
 */
#ifndef HTTP_VX_TLS_SCHEDULE_H
#define HTTP_VX_TLS_SCHEDULE_H

#include "http_vx/quic_crypto.h"
#include "http_vx/wipe.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

using quic::Crypto;
using quic::Hash;
using quic::hash_size;

/// \~english The longest hash output: SHA-384.  \~spanish La salida de resumen mas larga: SHA-384.  \~
constexpr size_t kMaxHash = quic::kMaxSecret;


/**
 * @brief
 * \~english Writes HkdfLabel for "tls13 " + @p label and @p context (7.1); its size, or 0 if it cannot be.
 * \~spanish Escribe el HkdfLabel de "tls13 " + @p label y @p context (7.1); su tamano, o 0 si no puede ser.
 * \~
 */
size_t hkdf_label(uint8_t *out, size_t room, size_t length, const char *label,
                  const uint8_t *context, size_t context_len) noexcept;

/**
 * @brief
 * \~english HKDF-Expand-Label (7.1), from a secret of the hash's own length.
 * \~spanish HKDF-Expand-Label (7.1), a partir de un secreto de la longitud del propio resumen.
 * \~
 */
bool expand_label(Crypto &c, Hash h, const uint8_t *secret, const char *label,
                  const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len) noexcept;

/**
 * @brief
 * \~english HMAC with the handshake's hash: `hash_size(h)` bytes to @p out.
 * \~spanish HMAC con el resumen del saludo: `hash_size(h)` bytes en @p out.
 * \~
 *
 * \~english
 * Through HKDF-Extract, which RFC 5869 defines as exactly this -- HMAC keyed
 * with the salt over the input -- so no provider needs a separate call.
 * \~spanish
 * A traves de HKDF-Extract, que el RFC 5869 define exactamente como esto --
 * HMAC con la sal como clave sobre la entrada --, asi que ningun proveedor
 * necesita una llamada aparte.
 * \~
 */
bool hmac(Crypto &c, Hash h, const uint8_t *key, size_t key_len, const uint8_t *msg, size_t n,
          uint8_t *out) noexcept;

/**
 * @brief
 * \~english The verify_data of a Finished message (4.4.4).
 * \~spanish El verify_data de un mensaje Finished (4.4.4).
 * \~
 *
 * @param base_key \~english the sender's handshake traffic secret
 *                 \~spanish el secreto de trafico del saludo de quien lo manda  \~
 * @param transcript_hash \~english the transcript up to, not including, this Finished
 *                        \~spanish la transcripcion hasta este Finished, sin incluirlo  \~
 */
bool finished_data(Crypto &c, Hash h, const uint8_t *base_key, const uint8_t *transcript_hash,
                   uint8_t *out) noexcept;

/**
 * @brief
 * \~english The PSK a NewSessionTicket makes from the resumption secret (4.6.1).
 * \~spanish La PSK que hace un NewSessionTicket a partir del secreto de reanudacion (4.6.1).
 * \~
 */
bool ticket_psk(Crypto &c, Hash h, const uint8_t *resumption_master, const uint8_t *nonce,
                size_t nonce_len, uint8_t *out) noexcept;

/**
 * @brief
 * \~english The handshake messages so far, kept to be hashed at the points that need it (4.4.1).
 * \~spanish Los mensajes del saludo hasta ahora, guardados para resumirlos en los puntos que lo necesitan (4.4.1).
 * \~
 */
class Transcript {
public:
    /// \~english More than this is refused: a handshake has no reason to be larger.
    /// \~spanish Mas que esto se rechaza: un saludo no tiene por que ser mas grande.  \~
    static constexpr size_t kMaxSize = 64u << 10;

    Transcript() noexcept = default;
    ~Transcript();
    Transcript(const Transcript &) = delete;
    Transcript &operator=(const Transcript &) = delete;

    /// \~english Appends a whole handshake message, header included; false past kMaxSize or out of memory.
    /// \~spanish Anade un mensaje del saludo entero, cabecera incluida; falso pasado kMaxSize o sin memoria.  \~
    bool add(const uint8_t *msg, size_t n) noexcept;

    /// \~english The hash of everything added so far.  \~spanish El resumen de todo lo anadido hasta ahora.  \~
    bool hash(Crypto &c, Hash h, uint8_t *out) const noexcept;

    /**
     * @brief
     * \~english After a HelloRetryRequest: ClientHello1 becomes a message_hash of it (4.4.1).
     * \~spanish Tras un HelloRetryRequest: ClientHello1 pasa a ser un message_hash de el (4.4.1).
     * \~
     *
     * \~english Only when ClientHello1 is all there is.  \~spanish Solo cuando ClientHello1 es todo lo que hay.  \~
     */
    bool replace_with_message_hash(Crypto &c, Hash h) noexcept;

    size_t size() const noexcept { return len_; }
    const uint8_t *bytes() const noexcept { return buf_; }

private:
    uint8_t *buf_ = nullptr;
    size_t len_ = 0;
    size_t cap_ = 0;
};

/**
 * @brief
 * \~english The secrets of RFC 8446, 7.1, derived in order; the intermediate ones stay inside and are wiped.
 * \~spanish Los secretos del RFC 8446, 7.1, derivados en orden; los intermedios se quedan dentro y se borran.
 * \~
 *
 * \~english
 * Each step takes the transcript hash it is defined over; it is the caller,
 * which knows the messages, that knows which hash that is.  Out of order is
 * refused.  Every output is `hash_size(h)` bytes.
 * \~spanish
 * Cada paso toma el resumen de la transcripcion sobre el que esta definido; es
 * quien llama, que conoce los mensajes, quien sabe cual es.  Fuera de orden se
 * rechaza.  Cada salida mide `hash_size(h)` bytes.
 * \~
 */
class KeySchedule {
public:
    KeySchedule(Crypto &c, Hash h) noexcept : c_(c), h_(h) {}
    ~KeySchedule();
    KeySchedule(const KeySchedule &) = delete;
    KeySchedule &operator=(const KeySchedule &) = delete;

    /// \~english The Early Secret, from a PSK or, with none, from zeros.
    /// \~spanish El Early Secret, de una PSK o, sin ninguna, de ceros.  \~
    bool start(const uint8_t *psk, size_t psk_len) noexcept;

    /// \~english The binder key: "res binder" for a resumption PSK, "ext binder" for an external one.
    /// \~spanish La clave del binder: "res binder" para una PSK de reanudacion, "ext binder" para una externa.  \~
    bool binder_key(bool resumption, uint8_t *out) const noexcept;

    /// \~english client_early_traffic_secret, over the ClientHello.  \~spanish client_early_traffic_secret, sobre el ClientHello.  \~
    bool early_traffic(const uint8_t *client_hello_hash, uint8_t *out) const noexcept;

    /// \~english The Handshake Secret from the (EC)DHE secret, and both handshake traffic secrets.
    /// \~spanish El Handshake Secret a partir del secreto (EC)DHE, y los dos secretos de trafico del saludo.  \~
    bool handshake(const uint8_t *shared, size_t shared_len, const uint8_t *hello_hash,
                   uint8_t *client_out, uint8_t *server_out) noexcept;

    /// \~english The Master Secret, both application traffic secrets and the exporter master secret.
    /// \~spanish El Master Secret, los dos secretos de trafico de aplicacion y el secreto maestro de exportacion.  \~
    bool application(const uint8_t *server_finished_hash, uint8_t *client_out, uint8_t *server_out,
                     uint8_t *exporter_out) noexcept;

    /// \~english The resumption master secret, over the transcript to the client's Finished.
    /// \~spanish El secreto maestro de reanudacion, sobre la transcripcion hasta el Finished del cliente.  \~
    bool resumption(const uint8_t *client_finished_hash, uint8_t *out) noexcept;

    Hash hash() const noexcept { return h_; }

private:
    enum class Stage : uint8_t { None, Early, Handshake, Master, Done };
    bool derive(const char *label, const uint8_t *transcript_hash, uint8_t *out) const noexcept;
    bool advance(const uint8_t *ikm, size_t ikm_len) noexcept;

    Crypto &c_;
    Hash h_;
    Stage stage_ = Stage::None;
    uint8_t secret_[kMaxHash] = {};
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_SCHEDULE_H
