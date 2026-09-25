/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_protection.h
 * @brief
 * \~english QUIC packet protection (RFC 9001, section 5), on top of a provider's primitives.
 * \~spanish La proteccion de paquetes de QUIC (RFC 9001, seccion 5), sobre las primitivas de un proveedor.
 * \~
 *
 * \~english
 * Two layers protect a QUIC packet, and they are removed in the opposite order
 * to the one they were put on.  The payload is sealed with an AEAD whose
 * associated data is the header; then a mask, computed from sixteen bytes of
 * that sealed payload, hides the packet number and the low bits of the first
 * byte.  So a receiver removes the mask first -- it needs the packet number to
 * build the nonce -- and only then opens the payload.
 *
 * The packet number is hidden because it would otherwise let anybody on the
 * path link a connection across a change of address, and because its length
 * is one of the things a middlebox would ossify around.  What stays readable
 * is exactly what `parse_packet` reads.
 *
 * **Everything here works in place.**  A packet is unmasked where it lies and
 * opened into the bytes it came in; sealing likewise.  A second buffer per
 * packet would be a copy of every byte QUIC carries, which R14's reasoning
 * forbids for the same reason it forbids one on the TCP path.
 *
 * \~spanish
 * Dos capas protegen un paquete QUIC, y se quitan en el orden contrario al que
 * se pusieron.  La carga se sella con un AEAD cuyos datos asociados son la
 * cabecera; despues una mascara, calculada con dieciseis bytes de esa carga
 * sellada, oculta el numero de paquete y los bits bajos del primer byte.  Asi
 * que quien recibe quita primero la mascara -- necesita el numero de paquete
 * para construir el nonce -- y solo despues abre la carga.
 *
 * El numero de paquete se oculta porque si no dejaria a cualquiera en el camino
 * enlazar una conexion a traves de un cambio de direccion, y porque su longitud
 * es una de las cosas alrededor de las que se oxidaria un equipo intermedio.  Lo
 * que queda legible es justo lo que lee `parse_packet`.
 *
 * **Todo aqui trabaja en su sitio.**  Un paquete se desenmascara donde esta y se
 * abre sobre los mismos bytes en que llego; sellar, igual.  Un segundo buffer
 * por paquete seria una copia de cada byte que lleva QUIC, que el razonamiento
 * de la R14 prohibe por lo mismo que la prohibe en el camino de TCP.
 * \~
 */
#ifndef HTTP_VX_QUIC_PROTECTION_H
#define HTTP_VX_QUIC_PROTECTION_H

#include "http_vx/quic_crypto.h"
#include "http_vx/quic_packet.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/// \~english Whether this end knows @p version's key-derivation constants.
/// \~spanish Si este extremo conoce las constantes de derivacion de @p version.  \~
bool knows_version(uint32_t version) noexcept;

/**
 * @brief
 * \~english Builds TLS 1.3's HkdfLabel for "tls13 " + @p label, with an empty context.
 * \~spanish Construye el HkdfLabel de TLS 1.3 para "tls13 " + @p label, con contexto vacio.
 * \~
 *
 * \~english
 * `uint16 length || uint8 len || "tls13 " label || uint8 0` (RFC 8446, section
 * 7.1).  Public because it is the part of the derivation the RFC prints byte
 * by byte, so it can be checked on its own without any provider.
 * \~spanish
 * `uint16 length || uint8 len || "tls13 " label || uint8 0` (RFC 8446, seccion
 * 7.1).  Publico porque es la parte de la derivacion que el RFC imprime byte a
 * byte, asi que se puede comprobar por su cuenta sin ningun proveedor.
 * \~
 *
 * @return \~english its size, or zero if @p room is short  \~spanish su tamano, o cero si falta sitio  \~
 */
size_t hkdf_label(uint8_t *out, size_t room, const char *label,
                  size_t out_len) noexcept;

/// \~english HKDF-Expand-Label with an empty context.
/// \~spanish HKDF-Expand-Label con contexto vacio.  \~
bool expand_label(Crypto &c, Hash h, const uint8_t *secret, size_t secret_len,
                  const char *label, uint8_t *out, size_t out_len) noexcept;

/**
 * @brief
 * \~english The Initial secrets both ends derive from the client's first DCID.
 * \~spanish Los secretos Initial que sacan los dos extremos del primer DCID del cliente.
 * \~
 *
 * \~english
 * Initial packets are protected, but not secret: anybody who sees the first
 * packet can derive these.  What the protection buys at this stage is that a
 * packet cannot be altered on the path unseen, and that only an end that saw
 * the connection ID can speak.  @p client and @p server get 32 bytes each.
 * \~spanish
 * Los paquetes Initial van protegidos pero no son secretos: cualquiera que vea el
 * primer paquete puede sacar estos.  Lo que compra la proteccion en esta etapa
 * es que un paquete no se pueda alterar en el camino sin que se note, y que solo
 * pueda hablar un extremo que vio el identificador.  @p client y @p server
 * reciben 32 bytes cada uno.
 * \~
 */
bool initial_secrets(Crypto &c, uint32_t version, const uint8_t *dcid,
                     size_t dcid_len, uint8_t *client,
                     uint8_t *server) noexcept;

/**
 * @brief
 * \~english The bytes of one direction's keys, before a provider prepares them.
 * \~spanish Los bytes de las claves de un sentido, antes de que un proveedor las prepare.
 * \~
 */
struct KeyMaterial {
    Aead aead = Aead::Aes128Gcm;
    uint8_t key[kMaxKey] = {};
    uint8_t iv[kNonceSize] = {};
    uint8_t hp[kMaxKey] = {};
};

/// \~english Derives key, IV and header-protection key from @p secret.
/// \~spanish Saca la clave, el IV y la clave de proteccion de cabecera de @p secret.  \~
bool derive_key_material(Crypto &c, uint32_t version, Aead a,
                         const uint8_t *secret, size_t secret_len,
                         KeyMaterial &out) noexcept;

/**
 * @brief
 * \~english The secret after a key update ("quic ku"), `hash_size` bytes.
 * \~spanish El secreto tras una actualizacion de claves ("quic ku"), `hash_size` bytes.
 * \~
 *
 * \~english
 * Only the AEAD key and IV change on an update; the header-protection key
 * does not, which is what lets a receiver unmask a packet before it knows
 * which generation of keys sealed it.
 * \~spanish
 * En una actualizacion solo cambian la clave y el IV del AEAD; la de proteccion
 * de cabecera no, que es lo que deja a quien recibe desenmascarar un paquete
 * antes de saber que generacion de claves lo sello.
 * \~
 */
bool next_secret(Crypto &c, uint32_t version, Aead a, const uint8_t *secret,
                 size_t secret_len, uint8_t *out) noexcept;

/**
 * @brief
 * \~english One direction's keys, prepared.
 * \~spanish Las claves de un sentido, preparadas.
 * \~
 */
struct PacketKeys {
    Aead aead = Aead::Aes128Gcm;
    void *aead_state = nullptr;
    void *hp_state = nullptr;
    uint8_t iv[kNonceSize] = {};
};

/**
 * @brief
 * \~english Hands @p m to the provider and wipes the key bytes from it.
 * \~spanish Le da @p m al proveedor y borra de ella los bytes de las claves.
 * \~
 *
 * \~english
 * On failure nothing is left half-prepared: whatever was prepared is released.
 * \~spanish
 * Si falla no queda nada a medio preparar: lo que se preparo se suelta.
 * \~
 */
bool prepare_keys(Crypto &c, KeyMaterial &m, PacketKeys &out) noexcept;

/// \~english Releases @p k's states and wipes it.
/// \~spanish Suelta los estados de @p k y lo borra.  \~
void forget_keys(Crypto &c, PacketKeys &k) noexcept;

/**
 * @brief
 * \~english The Initial keys for one end: what it reads with and what it writes with.
 * \~spanish Las claves Initial de un extremo: con las que lee y con las que escribe.
 * \~
 */
bool make_initial_keys(Crypto &c, uint32_t version, const uint8_t *dcid,
                       size_t dcid_len, bool is_server, PacketKeys &read,
                       PacketKeys &write) noexcept;

/// \~english The per-packet nonce: @p iv with @p pn XORed into its low bytes.
/// \~spanish El nonce de cada paquete: @p iv con @p pn en OR exclusivo en sus bytes bajos.  \~
void make_nonce(const uint8_t *iv, uint64_t pn, uint8_t *out) noexcept;

/**
 * @brief
 * \~english Recovers a full packet number from its truncated form (RFC 9000, A.3).
 * \~spanish Recupera un numero de paquete entero de su forma truncada (RFC 9000, A.3).
 * \~
 *
 * @param expected  \~english one more than the largest received, zero if none
 *                  \~spanish uno mas que el mayor recibido, cero si ninguno  \~
 * @param truncated \~english what the packet carried  \~spanish lo que llevaba el paquete  \~
 * @param len       \~english how many bytes it took, one to four
 *                  \~spanish cuantos bytes ocupo, de uno a cuatro  \~
 */
uint64_t decode_packet_number(uint64_t expected, uint64_t truncated,
                              size_t len) noexcept;

/**
 * @brief
 * \~english How many bytes to send @p pn in (RFC 9000, A.2).
 * \~spanish En cuantos bytes mandar @p pn (RFC 9000, A.2).
 * \~
 *
 * \~english
 * Enough that the receiver, whose largest seen may be as old as the largest
 * acknowledged, still lands on @p pn.  Zero means no length can: more than
 * 2^31 packets are in flight, which is a sender that stopped reading
 * acknowledgements, and saying so beats sending a number that decodes to
 * another packet.
 * \~spanish
 * Los suficientes para que quien recibe, cuyo mayor visto puede ser tan viejo
 * como el mayor confirmado, siga cayendo en @p pn.  Cero quiere decir que no
 * vale ninguna longitud: hay mas de 2^31 paquetes en vuelo, que es un emisor que
 * dejo de leer confirmaciones, y decirlo es mejor que mandar un numero que se
 * descodifica como otro paquete.
 * \~
 */
size_t packet_number_length(uint64_t pn, uint64_t largest_acked,
                            bool any_acked) noexcept;

/**
 * @brief
 * \~english How removing a packet's protection ended.
 * \~spanish Como acabo quitarle la proteccion a un paquete.
 * \~
 */
enum class Unprotect : uint8_t {
    Ok,
    /// \~english A packet type that carries no protection (Retry, VN).
    /// \~spanish Un tipo de paquete que no lleva proteccion (Retry, VN).  \~
    NotProtected,
    /// \~english It did not authenticate: drop it and count it.
    /// \~spanish No se autentico: se tira y se cuenta.  \~
    Forged,
    /**
     * \~english
     * It authenticated and its reserved bits are not zero.  Unlike a forgery
     * this is the PEER misbehaving -- only the key holder could have sealed it
     * -- so it is a PROTOCOL_VIOLATION on the connection, not a silent drop
     * (RFC 9000, section 17.2).  It can only be checked after opening, because
     * before that the bits are masked and a forger could set them at will.
     * \~spanish
     * Se autentico y sus bits reservados no son cero.  A diferencia de una
     * falsificacion esto es el OTRO EXTREMO portandose mal -- solo quien tiene
     * la clave pudo sellarlo --, asi que es un PROTOCOL_VIOLATION en la
     * conexion, no un descarte en silencio (RFC 9000, seccion 17.2).  Solo se
     * puede comprobar tras abrir, porque antes los bits van enmascarados y un
     * falsificador los podria poner como quisiera.
     * \~
     */
    ReservedBitsSet,
    /// \~english The provider could not do it.  \~spanish El proveedor no pudo hacerlo.  \~
    Failed,
};

/// \~english A short name for @p u, for counting and for logs.
/// \~spanish Un nombre corto para @p u, para contar y para los registros.  \~
const char *unprotect_name(Unprotect u) noexcept;

/**
 * @brief
 * \~english What removing the protection revealed.
 * \~spanish Lo que desvelo quitar la proteccion.
 * \~
 */
struct Unprotected {
    /// \~english The first byte, unmasked.  \~spanish El primer byte, desenmascarado.  \~
    uint8_t first = 0;
    /// \~english One to four.  \~spanish De uno a cuatro.  \~
    uint8_t pn_len = 0;
    uint64_t pn = 0;
    /// \~english The plaintext, from the first byte of the packet; tag excluded.
    /// \~spanish El texto claro, desde el primer byte del paquete; sin la marca.  \~
    Span payload = {0, 0};
};

/**
 * @brief
 * \~english Removes the header protection of @p packet, in place.
 * \~spanish Quita la proteccion de cabecera de @p packet, en su sitio.
 * \~
 *
 * \~english
 * Split from opening for key updates: the header-protection key never
 * changes, so a short-header packet is unmasked once, and then the key phase
 * bit says which AEAD key to try.  Fills everything in @p out but nothing is
 * authenticated yet; until `open_payload` says `Ok`, the packet number is a
 * number a forger may have chosen.
 * \~spanish
 * Separado de abrir por las actualizaciones de clave: la clave de proteccion de
 * cabecera no cambia nunca, asi que un paquete de cabecera corta se desenmascara
 * una vez, y despues el bit de fase de clave dice que clave de AEAD probar.
 * Rellena todo @p out pero todavia no hay nada autenticado; hasta que
 * `open_payload` diga `Ok`, el numero de paquete es uno que puede haber elegido
 * un falsificador.
 * \~
 */
Unprotect unmask_header(Crypto &c, void *hp_state, uint8_t *packet,
                        const PacketHeader &h, uint64_t expected_pn,
                        Unprotected &out) noexcept;

/**
 * @brief
 * \~english Opens the payload of a packet whose header was unmasked.
 * \~spanish Abre la carga de un paquete cuya cabecera se desenmascaro.
 * \~
 *
 * @param into \~english where the plaintext goes; `packet + u.payload.off` opens in place
 *             \~spanish donde va el texto claro; `packet + u.payload.off` abre en su sitio  \~
 */
Unprotect open_payload(Crypto &c, const PacketKeys &k, const uint8_t *packet,
                       const PacketHeader &h, const Unprotected &u,
                       uint8_t *into) noexcept;

/**
 * @brief
 * \~english Both steps, in place: what a receiver does with a packet in the common case.
 * \~spanish Los dos pasos, en su sitio: lo que hace quien recibe con un paquete en el caso comun.
 * \~
 */
Unprotect unprotect_packet(Crypto &c, const PacketKeys &k, uint8_t *packet,
                           const PacketHeader &h, uint64_t expected_pn,
                           Unprotected &out) noexcept;

/**
 * @brief
 * \~english How protecting a packet ended.
 * \~spanish Como acabo proteger un paquete.
 * \~
 */
enum class Protect : uint8_t {
    Ok,
    /**
     * \~english
     * Packet number plus payload is shorter than four bytes: after sealing
     * there would be no sixteen bytes to sample from four past the start of
     * the packet number.  The sender has to pad (RFC 9001, section 5.4.2); it
     * is refused here rather than sampled past the end.
     * \~spanish
     * Numero de paquete mas carga miden menos de cuatro bytes: tras sellar no
     * habria dieciseis bytes que muestrear a cuatro del principio del numero de
     * paquete.  El emisor tiene que rellenar (RFC 9001, seccion 5.4.2); aqui se
     * rechaza en vez de muestrear pasado el final.
     * \~
     */
    TooShortToSample,
    /// \~english @p pn_len is not one to four.  \~spanish @p pn_len no es de uno a cuatro.  \~
    BadPacketNumberLength,
    /// \~english The provider could not do it.  \~spanish El proveedor no pudo hacerlo.  \~
    Failed,
};

/**
 * @brief
 * \~english Protects a packet laid out in @p packet, in place.
 * \~spanish Protege un paquete dispuesto en @p packet, en su sitio.
 * \~
 *
 * \~english
 * On entry: the header up to @p pn_offset is written -- including, in a long
 * header, a Length that already counts `pn_len + payload_len + kTagSize` --
 * and the plaintext payload sits at `pn_offset + pn_len`, with `kTagSize`
 * bytes of room after it.  This writes the packet number, the length bits of
 * the first byte, seals, and masks.  The packet then takes
 * `pn_offset + pn_len + payload_len + kTagSize` bytes.
 * \~spanish
 * Al entrar: la cabecera esta escrita hasta @p pn_offset -- incluido, en una
 * cabecera larga, un Length que ya cuenta `pn_len + payload_len + kTagSize` -- y
 * la carga en claro esta en `pn_offset + pn_len`, con `kTagSize` bytes de sitio
 * detras.  Esto escribe el numero de paquete, los bits de longitud del primer
 * byte, sella y enmascara.  El paquete ocupa entonces
 * `pn_offset + pn_len + payload_len + kTagSize` bytes.
 * \~
 */
Protect protect_packet(Crypto &c, const PacketKeys &k, uint8_t *packet,
                       size_t pn_offset, size_t pn_len, uint64_t pn,
                       size_t payload_len) noexcept;

/**
 * @brief
 * \~english The integrity tag of a Retry packet (RFC 9001, section 5.8).
 * \~spanish La marca de integridad de un paquete Retry (RFC 9001, seccion 5.8).
 * \~
 *
 * \~english
 * An AEAD over nothing, with the original DCID and the Retry packet (without
 * its tag) as associated data, under a key the RFC publishes.  It is not
 * secrecy -- the key is public -- but it proves the Retry was made by an end
 * that saw the client's Initial, which a blind attacker did not.
 *
 * The associated data is the two pieces glued together, so they are glued in
 * @p scratch, which must hold `1 + odcid_len + n` bytes.
 * \~spanish
 * Un AEAD sobre nada, con el DCID original y el paquete Retry (sin su marca)
 * como datos asociados, bajo una clave que publica el RFC.  No es secreto -- la
 * clave es publica --, pero demuestra que el Retry lo hizo un extremo que vio el
 * Initial del cliente, cosa que un atacante a ciegas no vio.
 *
 * Los datos asociados son los dos trozos pegados, asi que se pegan en @p scratch,
 * que tiene que tener sitio para `1 + odcid_len + n` bytes.
 * \~
 */
bool retry_tag(Crypto &c, uint32_t version, const uint8_t *odcid,
               size_t odcid_len, const uint8_t *retry, size_t n,
               uint8_t *scratch, size_t scratch_room, uint8_t *tag) noexcept;

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_PROTECTION_H
