/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_record.h
 * @brief
 * \~english TLS 1.3's record layer: framing, protection, padding and the per-record nonce (RFC 8446, 5).
 * \~spanish La capa de registros de TLS 1.3: entramado, proteccion, relleno y el nonce por registro (RFC 8446, 5).
 * \~
 *
 * \~english
 * What QUIC does not use of TLS, and what TLS over TCP is made of.  One
 * record is a five-byte header -- type, legacy version, length -- and a
 * fragment; once keys exist the fragment is an AEAD over the content, its
 * real type and any zeros of padding, with the header as associated data
 * (5.2) and a nonce made from a sequence number (5.3).
 *
 * The line R22 draws holds here as in QUIC: the provider seals and opens
 * with a prepared key, and that is all it knows.  Which labels make the key
 * and the IV (7.3), how a secret moves to its next generation (7.2), how
 * the nonce is made and what the associated data is live here, checked
 * once against RFC 8448's records for every provider.
 *
 * **One direction per RecordKeys.**  The two directions of a connection have
 * independent secrets and independent sequence numbers (5.3), and they
 * change at different moments: a server writes with its application keys
 * while it still reads with the client's handshake ones.
 *
 * **What a record means is not decided here.**  Which types are allowed
 * when, whether a change_cipher_spec is dropped or refused, what an alert
 * does -- that is the channel's (tls_channel.h), which knows where the
 * handshake is.  This file frames, seals, opens and says why an opening
 * failed, each failure its own value so the channel can send the alert RFC
 * 8446 names for it.
 *
 * \~spanish
 * Lo que QUIC no usa de TLS, y de lo que esta hecho TLS sobre TCP.  Un registro
 * es una cabecera de cinco bytes -- tipo, version heredada, longitud -- y un
 * fragmento; cuando hay claves el fragmento es un AEAD sobre el contenido, su
 * tipo de verdad y los ceros de relleno que haya, con la cabecera como datos
 * asociados (5.2) y un nonce hecho de un numero de secuencia (5.3).
 *
 * La linea que traza la R22 se mantiene aqui como en QUIC: el proveedor sella y
 * abre con una clave preparada, y es todo lo que sabe.  Que etiquetas hacen la
 * clave y el IV (7.3), como pasa un secreto a su generacion siguiente (7.2),
 * como se hace el nonce y cuales son los datos asociados vive aqui, comprobado
 * una vez contra los registros del RFC 8448 para todos los proveedores.
 *
 * **Una direccion por RecordKeys.**  Las dos direcciones de una conexion tienen
 * secretos independientes y numeros de secuencia independientes (5.3), y
 * cambian en momentos distintos: un servidor escribe con sus claves de
 * aplicacion mientras todavia lee con las del saludo del cliente.
 *
 * **Lo que significa un registro no se decide aqui.**  Que tipos se admiten y
 * cuando, si un change_cipher_spec se tira o se rechaza, que hace una alerta --
 * eso es del canal (tls_channel.h), que sabe por donde va el saludo.  Este
 * fichero entrama, sella, abre y dice por que fallo una apertura, cada fallo
 * con su propio valor para que el canal mande la alerta que nombra el RFC 8446.
 * \~
 */
#ifndef HTTP_VX_TLS_RECORD_H
#define HTTP_VX_TLS_RECORD_H

#include "http_vx/quic_crypto.h"
#include "http_vx/tls_schedule.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

using quic::Aead;

/// \~english The record content types (5.1).  \~spanish Los tipos de contenido de un registro (5.1).  \~
enum class ContentType : uint8_t {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
};

/// \~english type(1), legacy_record_version(2), length(2) (5.1).  \~spanish type(1), legacy_record_version(2), length(2) (5.1).  \~
constexpr size_t kRecordHeader = 5;
/// \~english The largest TLSPlaintext.fragment: 2^14 (5.1).  \~spanish El TLSPlaintext.fragment mas grande: 2^14 (5.1).  \~
constexpr size_t kMaxFragment = size_t{1} << 14;
/// \~english The largest encoded TLSInnerPlaintext, padding and type included: 2^14 + 1 (5.4).
/// \~spanish El TLSInnerPlaintext codificado mas grande, relleno y tipo incluidos: 2^14 + 1 (5.4).  \~
constexpr size_t kMaxInnerPlaintext = kMaxFragment + 1;
/// \~english The largest TLSCiphertext.length: 2^14 + 256 (5.2).  \~spanish El TLSCiphertext.length mas grande: 2^14 + 256 (5.2).  \~
constexpr size_t kMaxCiphertext = kMaxFragment + 256;
/// \~english What a protected record adds to its content without padding: header, type, tag.
/// \~spanish Lo que un registro protegido anade a su contenido sin relleno: cabecera, tipo, marca.  \~
constexpr size_t kRecordOverhead = kRecordHeader + 1 + quic::kTagSize;
/// \~english legacy_record_version everywhere but a first ClientHello (5.1).  \~spanish legacy_record_version en todas partes salvo un primer ClientHello (5.1).  \~
constexpr uint16_t kRecordVersion = 0x0303;
/// \~english A first ClientHello's record: 0x0301 SHOULD, for old middleboxes (5.1).
/// \~spanish El registro de un primer ClientHello: 0x0301 DEBERIA, por las cajas intermedias viejas (5.1).  \~
constexpr uint16_t kFirstHelloVersion = 0x0301;

/// \~english A record header, as read.  \~spanish Una cabecera de registro, tal como se leyo.  \~
struct RecordHeader {
    uint8_t type = 0;
    /// \~english Read and ignored: it "MUST be ignored for all purposes" (5.1).  \~spanish Se lee y se ignora: "DEBE ignorarse a todos los efectos" (5.1).  \~
    uint16_t version = 0;
    uint16_t length = 0;
};

/// \~english The header at @p p, which holds at least kRecordHeader bytes.  \~spanish La cabecera en @p p, que tiene al menos kRecordHeader bytes.  \~
inline RecordHeader read_record_header(const uint8_t *p) noexcept {
    RecordHeader h;
    h.type = p[0];
    h.version = static_cast<uint16_t>(p[1] << 8 | p[2]);
    h.length = static_cast<uint16_t>(p[3] << 8 | p[4]);
    return h;
}

/**
 * @brief
 * \~english Writes an unprotected record: header, then @p n bytes of @p content; its size, or 0 if it cannot be.
 * \~spanish Escribe un registro sin proteger: cabecera, y luego @p n bytes de @p content; su tamano, o 0 si no puede ser.
 * \~
 *
 * \~english
 * Zero-length and over-2^14 fragments are refused: the first is forbidden
 * for handshake records and pointless for the others (5.1), the second is
 * what record_overflow is for (5.1).
 * \~spanish
 * Los fragmentos vacios o de mas de 2^14 se rechazan: el primero esta prohibido
 * en registros del saludo y no sirve de nada en los demas (5.1), el segundo es
 * para lo que existe record_overflow (5.1).
 * \~
 */
size_t write_plaintext_record(ContentType type, uint16_t version, const uint8_t *content, size_t n,
                              uint8_t *out, size_t room) noexcept;

/**
 * @brief
 * \~english What opening a protected record found.
 * \~spanish Lo que encontro abrir un registro protegido.
 * \~
 */
struct Opened {
    enum class Status : uint8_t {
        /// \~english @c type and @c len say what it holds.  \~spanish @c type y @c len dicen lo que tiene.  \~
        Ok,
        /// \~english It does not authenticate: bad_record_mac (5.2).  \~spanish No se autentica: bad_record_mac (5.2).  \~
        Forged,
        /// \~english The provider could not run: this end's failure, not the peer's.  \~spanish El proveedor no pudo ejecutar: fallo de este extremo, no del otro.  \~
        Failed,
        /// \~english All zeros, no content type: unexpected_message (5.4).  \~spanish Todo ceros, sin tipo de contenido: unexpected_message (5.4).  \~
        NoType,
        /// \~english Longer than 2^14 + 1 once opened, or than 2^14 + 256 before: record_overflow (5.2, 5.4).
        /// \~spanish Mas largo que 2^14 + 1 abierto, o que 2^14 + 256 antes: record_overflow (5.2, 5.4).  \~
        Overflow,
        /// \~english The sequence number would wrap: no record may be read with these keys (5.3).
        /// \~spanish El numero de secuencia daria la vuelta: con estas claves no se puede leer ningun registro (5.3).  \~
        Exhausted,
    };
    Status status = Status::Failed;
    ContentType type = ContentType::Invalid;
    /// \~english The content, without type and padding, from the first byte written.
    /// \~spanish El contenido, sin tipo ni relleno, desde el primer byte escrito.  \~
    size_t len = 0;
};

/**
 * @brief
 * \~english One direction's record protection: the AEAD key, the IV, the sequence number and the secret they came from.
 * \~spanish La proteccion de registros de una direccion: la clave AEAD, el IV, el numero de secuencia y el secreto del que salieron.
 * \~
 *
 * \~english
 * Uninstalled, it protects nothing: records in that direction go
 * unprotected, which is how every connection starts (5.1).  The secret is
 * kept only to make the next generation from (7.2), and is wiped with the
 * key when the keys change or go.
 * \~spanish
 * Sin instalar, no protege nada: los registros en esa direccion van sin
 * proteger, que es como empieza toda conexion (5.1).  El secreto se guarda solo
 * para hacer la generacion siguiente (7.2), y se borra con la clave cuando las
 * claves cambian o se van.
 * \~
 */
class RecordKeys {
public:
    RecordKeys() noexcept = default;
    ~RecordKeys();
    RecordKeys(const RecordKeys &) = delete;
    RecordKeys &operator=(const RecordKeys &) = delete;

    /**
     * @brief
     * \~english Keys from a traffic secret (`hash_size(hash_of(a))` bytes): key and IV by 7.3, sequence at zero (5.3).
     * \~spanish Claves a partir de un secreto de trafico (`hash_size(hash_of(a))` bytes): clave e IV por 7.3, secuencia a cero (5.3).
     * \~
     * @return \~english false if the provider could not; nothing is left installed then
     *         \~spanish falso si el proveedor no pudo; entonces no queda nada instalado  \~
     */
    bool install(Crypto &c, Aead a, const uint8_t *secret) noexcept;

    /**
     * @brief
     * \~english The next generation: application_traffic_secret_N+1 = HKDF-Expand-Label(N, "traffic upd", "", Hash.length) (7.2).
     * \~spanish La generacion siguiente: application_traffic_secret_N+1 = HKDF-Expand-Label(N, "traffic upd", "", Hash.length) (7.2).
     * \~
     */
    bool update() noexcept;

    /// \~english Forgets the keys and the secret: back to unprotected.  \~spanish Olvida las claves y el secreto: de vuelta a sin proteger.  \~
    void clear() noexcept;

    bool installed() const noexcept { return state_ != nullptr; }
    Aead aead() const noexcept { return aead_; }

    /// \~english The sequence number the next record uses.  \~spanish El numero de secuencia que usa el registro siguiente.  \~
    uint64_t sequence() const noexcept { return seq_; }
    /**
     * @brief
     * \~english Sets the sequence number: for the limits, which no test can reach by counting.
     * \~spanish Pone el numero de secuencia: para los limites, a los que ninguna prueba llega contando.
     * \~
     */
    void set_sequence(uint64_t s) noexcept { seq_ = s; }
    /**
     * @brief
     * \~english No record may use these keys any more: the next number would wrap (5.3).
     * \~spanish Ningun registro puede usar ya estas claves: el numero siguiente daria la vuelta (5.3).
     * \~
     *
     * \~english
     * The last number, 2^64 - 1, is given up rather than used: after it the
     * counter could only wrap, and a record sealed with it would leave a
     * connection that cannot send even the alert that closes it.
     * \~spanish
     * El ultimo numero, 2^64 - 1, se deja sin usar: despues de el el contador
     * solo podria dar la vuelta, y un registro sellado con el dejaria una
     * conexion que no puede mandar ni la alerta que la cierra.
     * \~
     */
    bool exhausted() const noexcept { return seq_ == ~uint64_t{0}; }

    /// \~english The per-record nonce: the IV XORed with the sequence number, left-padded (5.3).
    /// \~spanish El nonce por registro: el IV con XOR del numero de secuencia, rellenado por la izquierda (5.3).  \~
    void nonce(uint8_t *out) const noexcept;

    /**
     * @brief
     * \~english Seals one record of @p type: header, @p n bytes of content, the type, @p padding zeros, the tag (5.2, 5.4).
     * \~spanish Sella un registro de @p type: cabecera, @p n bytes de contenido, el tipo, @p padding ceros, la marca (5.2, 5.4).
     * \~
     *
     * \~english
     * @p content may not overlap @p out.  Refused -- 0 -- past 2^14 of
     * content or 2^14 + 1 of inner plaintext, without room, uninstalled,
     * exhausted, or if the provider could not.
     * \~spanish
     * @p content no puede solaparse con @p out.  Se rechaza -- 0 -- pasados 2^14
     * de contenido o 2^14 + 1 de texto interior, sin sitio, sin instalar,
     * agotadas, o si el proveedor no pudo.
     * \~
     * @return \~english the record's size  \~spanish el tamano del registro  \~
     */
    size_t seal(ContentType type, const uint8_t *content, size_t n, size_t padding, uint8_t *out,
                size_t room) noexcept;

    /**
     * @brief
     * \~english The same, with the @p n bytes of content already where they go: at @p out + kRecordHeader.
     * \~spanish Lo mismo, con los @p n bytes de contenido ya donde van: en @p out + kRecordHeader.
     * \~
     *
     * \~english
     * What lets a body written by the service be sealed with no copy: the
     * header is written in front of it, the type, padding and tag behind, and
     * the provider seals the inner plaintext where it lies.
     * \~spanish
     * Lo que permite sellar sin copia un cuerpo escrito por el servicio: la
     * cabecera se escribe delante, el tipo, el relleno y la marca detras, y el
     * proveedor sella el texto interior donde esta.
     * \~
     * @return \~english the record's size, or 0 as @c seal refuses  \~spanish el tamano del registro, o 0 como rechaza @c seal  \~
     */
    size_t seal_in_place(ContentType type, size_t n, size_t padding, uint8_t *out, size_t room) noexcept;

    /**
     * @brief
     * \~english Opens the whole record at @p record (header included, @p total bytes) into @p out.
     * \~spanish Abre el registro entero de @p record (cabecera incluida, @p total bytes) en @p out.
     * \~
     *
     * \~english
     * @p out has room for the fragment and must not overlap it.  The content
     * type is the last non-zero byte of what opened, the scan never leaving
     * it (5.4).  The sequence number moves on only for a record that opened.
     * \~spanish
     * @p out tiene sitio para el fragmento y no puede solaparse con el.  El tipo
     * de contenido es el ultimo byte no nulo de lo que se abrio, sin que la
     * busqueda salga de ahi (5.4).  El numero de secuencia avanza solo con un
     * registro que se abrio.
     * \~
     */
    Opened open(const uint8_t *record, size_t total, uint8_t *out) noexcept;

private:
    Crypto *c_ = nullptr;
    void *state_ = nullptr;
    uint64_t seq_ = 0;
    uint8_t iv_[quic::kNonceSize] = {};
    uint8_t secret_[kMaxHash] = {};
    Aead aead_ = Aead::Aes128Gcm;
};

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_RECORD_H
