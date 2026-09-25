/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_crypto.h
 * @brief
 * \~english The cryptographic primitives QUIC needs, as a service somebody provides.
 * \~spanish Las primitivas criptograficas que necesita QUIC, como un servicio que provee alguien.
 * \~
 *
 * \~english
 * R22 says http_vx links no TLS library -- the reference one's license does
 * not fit this project's.  This is where that rule meets QUIC, and the cut is
 * drawn at the
 * PRIMITIVES: a provider knows how to run HKDF, an AEAD and a block cipher, and
 * nothing about QUIC.  Everything QUIC-specific -- the labels, the initial
 * salts, how the nonce is made from the packet number, which bits of the first
 * byte are masked, the order in which a packet is unprotected -- lives in
 * `quic_protection.h`, on this side of the line.
 *
 * Drawing the line lower than that would tie the core to one way of getting
 * the primitives, leaving whoever builds no choice.  Drawing it higher -- a
 * provider that "protects a QUIC packet" -- would mean every provider
 * re-implementing the same RFC 9001 logic, each with its own chance of getting
 * the mask bits wrong, and the RFC's test vectors would be testing the
 * provider instead of this project.  With the line here, one implementation of
 * the QUIC logic is checked against the RFC once, for every provider.
 *
 * **Keys are PREPARED once, not handed over per packet.**  Setting an AES key
 * expands it into a schedule, and doing that for every packet would cost more
 * than the packet itself.  So a provider turns key bytes into an opaque state
 * once, and that state is what the per-packet calls take.  What the state is,
 * and where its memory comes from, is the provider's business.
 *
 * \~spanish
 * La R22 dice que http_vx no enlaza ninguna biblioteca de TLS -- la de
 * referencia tiene una licencia que no encaja con la de este proyecto --.  Aqui
 * es donde esa regla se encuentra con QUIC, y el corte va en las PRIMITIVAS: un proveedor sabe hacer HKDF, un AEAD y un cifrado
 * de bloque, y nada de QUIC.  Todo lo que es de QUIC -- las etiquetas, las sales
 * iniciales, como sale el nonce del numero de paquete, que bits del primer byte
 * se enmascaran, en que orden se desprotege un paquete -- vive en
 * `quic_protection.h`, a este lado de la linea.
 *
 * Poner la linea mas abajo ataria el nucleo a una sola forma de obtener las
 * primitivas, sin que quien construye pudiera elegir.  Ponerla mas arriba -- un proveedor que
 * "protege un paquete QUIC" -- seria que cada proveedor reimplementara la misma
 * logica del RFC 9001, cada uno con su propia ocasion de equivocarse en los bits
 * de la mascara, y los vectores del RFC probarian al proveedor en vez de a este
 * proyecto.  Con la linea aqui, una sola implementacion de la logica de QUIC se
 * comprueba contra el RFC una vez, para todos los proveedores.
 *
 * **Las claves se PREPARAN una vez, no se entregan en cada paquete.**  Poner una
 * clave AES la expande en una agenda, y hacerlo en cada paquete costaria mas que
 * el paquete.  Asi que el proveedor convierte los bytes de la clave en un estado
 * opaco una vez, y ese estado es lo que toman las llamadas por paquete.  Que es
 * el estado, y de donde sale su memoria, es cosa del proveedor.
 * \~
 */
#ifndef HTTP_VX_QUIC_CRYPTO_H
#define HTTP_VX_QUIC_CRYPTO_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english The AEADs TLS 1.3 defines for QUIC (RFC 9001, section 5.3).
 * \~spanish Los AEAD que define TLS 1.3 para QUIC (RFC 9001, seccion 5.3).
 * \~
 *
 * \~english
 * AES-128-CCM exists too, and is left out on purpose: nobody deploys it for
 * QUIC, and a suite that is offered and never exercised is a suite whose bugs
 * are found by an attacker.
 * \~spanish
 * Existe tambien AES-128-CCM, y se deja fuera a proposito: nadie lo despliega
 * para QUIC, y un algoritmo que se ofrece y no se usa nunca es uno cuyos fallos
 * los encuentra un atacante.
 * \~
 */
enum class Aead : uint8_t {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
};

/// \~english The hashes behind HKDF.  \~spanish Los resumenes que hay detras de HKDF.  \~
enum class Hash : uint8_t {
    Sha256,
    Sha384,
};

/// \~english Every AEAD here uses a twelve-byte nonce.
/// \~spanish Todos los AEAD de aqui usan un nonce de doce bytes.  \~
constexpr size_t kNonceSize = 12;

/// \~english Every AEAD here adds a sixteen-byte tag.
/// \~spanish Todos los AEAD de aqui anaden una marca de dieciseis bytes.  \~
constexpr size_t kTagSize = 16;

/// \~english The header-protection mask is five bytes; the rest is not used.
/// \~spanish La mascara de la proteccion de cabecera son cinco bytes; el resto no se usa.  \~
constexpr size_t kMaskSize = 5;

/// \~english The longest secret: a SHA-384 output.
/// \~spanish El secreto mas largo: una salida de SHA-384.  \~
constexpr size_t kMaxSecret = 48;

/// \~english The longest AEAD or header-protection key.
/// \~spanish La clave de AEAD o de proteccion de cabecera mas larga.  \~
constexpr size_t kMaxKey = 32;

/// \~english The hash a TLS 1.3 suite pairs with @p a.
/// \~spanish El resumen con el que TLS 1.3 empareja a @p a.  \~
inline Hash hash_of(Aead a) noexcept {
    return a == Aead::Aes256Gcm ? Hash::Sha384 : Hash::Sha256;
}

/// \~english How many bytes @p h produces.  \~spanish Cuantos bytes produce @p h.  \~
inline size_t hash_size(Hash h) noexcept {
    return h == Hash::Sha384 ? 48 : 32;
}

/// \~english How long @p a's key is -- and its header-protection key.
/// \~spanish Cuanto mide la clave de @p a -- y la de su proteccion de cabecera.  \~
inline size_t key_size(Aead a) noexcept {
    return a == Aead::Aes128Gcm ? 16 : 32;
}

/**
 * @brief
 * \~english How opening a packet ended.
 * \~spanish Como acabo abrir un paquete.
 * \~
 *
 * \~english
 * Two failures and not one, because they mean opposite things.  A packet that
 * does not authenticate is traffic -- forged, damaged, or sealed with keys
 * this end has already thrown away -- and is dropped and counted.  A provider
 * that could not run the primitive at all is this server broken, and R24 says
 * that is said out loud rather than taken for a bad packet: a server whose
 * provider fails every call would otherwise look like a server under a flood
 * of forgeries, and drop every connection quietly.
 * \~spanish
 * Dos fallos y no uno, porque quieren decir cosas opuestas.  Un paquete que no
 * se autentica es trafico -- falsificado, estropeado, o sellado con claves que
 * este extremo ya tiro -- y se tira y se cuenta.  Un proveedor que no pudo
 * ejecutar la primitiva es este servidor roto, y la R24 dice que eso se dice en
 * voz alta en vez de tomarse por un paquete malo: un servidor cuyo proveedor
 * fallara en cada llamada pareceria si no un servidor bajo una avalancha de
 * falsificaciones, y tiraria todas las conexiones en silencio.
 * \~
 */
enum class OpenResult : uint8_t {
    Ok,
    /// \~english The tag does not match.  \~spanish La marca no coincide.  \~
    Forged,
    /// \~english The provider could not do it.  \~spanish El proveedor no pudo hacerlo.  \~
    Failed,
};

/**
 * @brief
 * \~english What a cryptographic provider has to supply.
 * \~spanish Lo que tiene que poner un proveedor criptografico.
 * \~
 *
 * \~english
 * Every call is `noexcept` and says whether it worked; none may keep a pointer
 * to the bytes it was given past the call.  Buffers may overlap exactly --
 * `out == in` -- where noted, which is how a packet is sealed and opened in
 * place, without a second copy of it.
 * \~spanish
 * Todas las llamadas son `noexcept` y dicen si funcionaron; ninguna puede
 * quedarse con un puntero a los bytes que recibio mas alla de la llamada.  Los
 * buffers pueden coincidir exactamente -- `out == in` -- donde se indica, que es
 * como se sella y se abre un paquete en su sitio, sin una segunda copia de el.
 * \~
 */
class Crypto {
public:
    virtual ~Crypto() = default;

    /// \~english A short name, for logs.  \~spanish Un nombre corto, para los registros.  \~
    virtual const char *name() const noexcept = 0;

    /**
     * @brief
     * \~english Whether this provider can run @p a -- its AEAD and its header protection.
     * \~spanish Si este proveedor sabe ejecutar @p a -- su AEAD y su proteccion de cabecera.
     * \~
     *
     * \~english
     * Not every provider has to have every suite -- a system library may lack
     * one, as Windows 10's CNG lacks ChaCha20.  R23 says the server ASKS
     * rather than assumes, and this is where: the handshake offers only what
     * this answers yes to, so a peer can never pick a suite that would fail on
     * the first packet.
     * \~spanish
     * No todos los proveedores tienen por que tener todos los algoritmos -- a una
     * biblioteca del sistema le puede faltar uno, como a la CNG de Windows 10 le
     * falta ChaCha20.  La R23 dice que el servidor PREGUNTA en vez de suponer, y es
     * aqui: el handshake ofrece solo aquello a lo que esto dice que si, asi que
     * el otro extremo nunca puede elegir un algoritmo que fallaria en el primer
     * paquete.
     * \~
     */
    virtual bool supports(Aead a) const noexcept = 0;

    /**
     * @brief
     * \~english Fills @p out with @p n unpredictable bytes: connection IDs, token nonces.
     * \~spanish Llena @p out con @p n bytes impredecibles: identificadores de conexion, nonces de testigos.
     * \~
     *
     * \~english
     * From the provider, like every other primitive: a connection ID an
     * attacker can predict lets it route or reset connections it never saw,
     * so "random enough" is a cryptographic property, not a convenience.
     * \~spanish
     * Del proveedor, como cualquier otra primitiva: un identificador de conexion
     * que un atacante puede predecir le deja encaminar o reiniciar conexiones
     * que nunca vio, asi que "suficientemente aleatorio" es una propiedad
     * criptografica, no una comodidad.
     * \~
     */
    virtual bool random(uint8_t *out, size_t n) noexcept = 0;

    /**
     * @brief
     * \~english The hash of @p n bytes: writes `hash_size(h)` bytes to @p out.
     * \~spanish El resumen de @p n bytes: escribe `hash_size(h)` bytes en @p out.
     * \~
     *
     * \~english
     * What TLS 1.3 hashes its transcript with (RFC 8446, 4.4.1).  One call over
     * the whole input: the handshake keeps its messages and hashes them at the
     * few points it needs to, so no provider has to copy a running state.
     * \~spanish
     * Con lo que TLS 1.3 resume su transcripcion (RFC 8446, 4.4.1).  Una llamada
     * sobre toda la entrada: el saludo guarda sus mensajes y los resume en los
     * pocos puntos en que lo necesita, asi que ningun proveedor tiene que copiar
     * un estado a medias.
     * \~
     */
    virtual bool digest(Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept = 0;

    /**
     * @brief
     * \~english HKDF-Extract (RFC 5869): writes `hash_size(h)` bytes to @p prk.
     * \~spanish HKDF-Extract (RFC 5869): escribe `hash_size(h)` bytes en @p prk.
     * \~
     */
    virtual bool extract(Hash h, const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t *prk) noexcept = 0;

    /**
     * @brief
     * \~english HKDF-Expand (RFC 5869): writes @p out_len bytes to @p out.
     * \~spanish HKDF-Expand (RFC 5869): escribe @p out_len bytes en @p out.
     * \~
     */
    virtual bool expand(Hash h, const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) noexcept = 0;

    /**
     * @brief
     * \~english Prepares @p key (`key_size(a)` bytes) for sealing and opening.
     * \~spanish Prepara @p key (`key_size(a)` bytes) para sellar y abrir.
     * \~
     * @return \~english the state, or null if it could not  \~spanish el estado, o nulo si no pudo  \~
     */
    virtual void *prepare_aead(Aead a, const uint8_t *key) noexcept = 0;

    /**
     * @brief
     * \~english Prepares a header-protection key (`key_size(a)` bytes).
     * \~spanish Prepara una clave de proteccion de cabecera (`key_size(a)` bytes).
     * \~
     *
     * \~english
     * For the AES suites that is AES in ECB mode on one block; for ChaCha20,
     * the ChaCha20 stream with the sample as counter and nonce (RFC 9001,
     * section 5.4).
     * \~spanish
     * En los algoritmos AES es AES en modo ECB sobre un bloque; en ChaCha20, el
     * flujo ChaCha20 con la muestra como contador y nonce (RFC 9001, seccion
     * 5.4).
     * \~
     */
    virtual void *prepare_hp(Aead a, const uint8_t *key) noexcept = 0;

    /// \~english Releases a prepared state; null is allowed.
    /// \~spanish Suelta un estado preparado; se admite nulo.  \~
    virtual void forget(void *state) noexcept = 0;

    /**
     * @brief
     * \~english Seals @p n bytes: writes `n + kTagSize` to @p out (may be @p in).
     * \~spanish Sella @p n bytes: escribe `n + kTagSize` en @p out (puede ser @p in).
     * \~
     */
    virtual bool seal(void *aead, const uint8_t *nonce,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *in, size_t n,
                      uint8_t *out) noexcept = 0;

    /**
     * @brief
     * \~english Opens @p n bytes, tag included: writes `n - kTagSize` to @p out.
     * \~spanish Abre @p n bytes, marca incluida: escribe `n - kTagSize` en @p out.
     * \~
     *
     * \~english
     * @p out may be @p in.  On anything but `Ok` what it holds is undefined --
     * a provider may have decrypted before it checked the tag -- so a caller
     * that needs to try other keys must open into another buffer.
     * \~spanish
     * @p out puede ser @p in.  En cualquier cosa que no sea `Ok` lo que contenga
     * no esta definido -- un proveedor puede haber descifrado antes de comprobar
     * la marca --, asi que quien necesite probar otras claves tiene que abrir en
     * otro buffer.
     * \~
     */
    virtual OpenResult open(void *aead, const uint8_t *nonce,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *in, size_t n,
                            uint8_t *out) noexcept = 0;

    /**
     * @brief
     * \~english The header-protection mask for a sixteen-byte @p sample.
     * \~spanish La mascara de la proteccion de cabecera para una @p sample de dieciseis bytes.
     * \~
     */
    virtual bool mask(void *hp, const uint8_t *sample,
                      uint8_t *out) noexcept = 0;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_CRYPTO_H
