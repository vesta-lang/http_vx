/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/common/chacha20_poly1305.h
 * @brief
 * \~english ChaCha20 and Poly1305 (RFC 8439), for providers whose system lacks them.
 * \~spanish ChaCha20 y Poly1305 (RFC 8439), para los proveedores cuyo sistema no los tiene.
 * \~
 *
 * \~english
 * Windows 10's CNG has neither the ChaCha20-Poly1305 AEAD nor the raw
 * ChaCha20 stream that QUIC's header protection needs, so a Windows server
 * using the system's provider could not offer the one suite that is fast on
 * machines without AES instructions.  Both algorithms are small, specified to
 * the last bit, and come with test vectors for every edge their arithmetic
 * has, so they are written here, under this project's own license.
 *
 * That does not go against R22: what R22 keeps out is a LIBRARY whose license
 * does not fit this project's, not the writing of a basic algorithm.
 *
 * It lives in `providers/`, not in the core: a provider USES it, `http_vx_quic`
 * never sees it.  And it has no operating-system header, so it is checked on
 * every platform against RFC 8439, whether or not any provider there needs it.
 *
 * Written for constant time: no branch and no table index depends on a key,
 * a nonce or a message byte, and a tag is compared without stopping at the
 * first difference.  A tag comparison that stopped early would tell an
 * attacker, by timing, how many bytes of a forged tag were right.
 *
 * \~spanish
 * La CNG de Windows 10 no tiene ni el AEAD ChaCha20-Poly1305 ni el flujo
 * ChaCha20 en bruto que necesita la proteccion de cabecera de QUIC, asi que un
 * servidor de Windows con el proveedor del sistema no podria ofrecer el unico
 * algoritmo que es rapido en maquinas sin instrucciones AES.  Los dos algoritmos
 * son pequenos, estan especificados hasta el ultimo bit y traen vectores de
 * prueba para cada borde de su aritmetica, asi que se escriben aqui, bajo la
 * licencia de este proyecto.
 *
 * Eso no va contra la R22: lo que la R22 deja fuera es una BIBLIOTECA cuya
 * licencia no encaja con la de este proyecto, no escribir un algoritmo basico.
 *
 * Vive en `providers/`, no en el nucleo: lo USA un proveedor, `http_vx_quic` no
 * lo ve nunca.  Y no tiene ninguna cabecera del sistema, asi que se comprueba en
 * todas las plataformas contra el RFC 8439, lo necesite ahi un proveedor o no.
 *
 * Escrito en tiempo constante: ninguna rama ni ningun indice de tabla depende de
 * una clave, un nonce o un byte del mensaje, y una marca se compara sin pararse
 * en la primera diferencia.  Una comparacion que se parara antes le diria a un
 * atacante, por el tiempo, cuantos bytes de una marca falsificada acerto.
 * \~
 */
#ifndef HTTP_VX_PROVIDERS_CHACHA20_POLY1305_H
#define HTTP_VX_PROVIDERS_CHACHA20_POLY1305_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace chacha {

constexpr size_t kKeySize = 32;
constexpr size_t kNonceSize = 12;
constexpr size_t kBlockSize = 64;
constexpr size_t kTagSize = 16;

/**
 * @brief
 * \~english One ChaCha20 block (RFC 8439, 2.3): 64 bytes of keystream.
 * \~spanish Un bloque de ChaCha20 (RFC 8439, 2.3): 64 bytes de flujo de clave.
 * \~
 */
void block(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
           uint8_t *out) noexcept;

/**
 * @brief
 * \~english ChaCha20 encryption (RFC 8439, 2.4): @p in XOR the keystream from @p counter.
 * \~spanish Cifrado ChaCha20 (RFC 8439, 2.4): @p in XOR el flujo desde @p counter.
 * \~
 *
 * \~english @p out may be @p in.  \~spanish @p out puede ser @p in.  \~
 */
void xor_stream(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                const uint8_t *in, uint8_t *out, size_t n) noexcept;

/**
 * @brief
 * \~english A Poly1305 computation in progress (RFC 8439, 2.5).
 * \~spanish Un calculo de Poly1305 en curso (RFC 8439, 2.5).
 * \~
 *
 * \~english
 * The accumulator and r are kept in five 26-bit limbs, so that every product
 * of two limbs, summed five times and multiplied by five, still fits in 64
 * bits: that is what lets the arithmetic modulo 2^130 - 5 run without any
 * big-number code and without branches.
 * \~spanish
 * El acumulador y r se guardan en cinco miembros de 26 bits, para que cualquier
 * producto de dos, sumado cinco veces y multiplicado por cinco, quepa aun en 64
 * bits: eso es lo que deja que la aritmetica modulo 2^130 - 5 corra sin codigo de
 * numeros grandes y sin ramas.
 * \~
 */
struct Poly1305 {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t pending[16];
    size_t used;
};

/// \~english Starts with a one-time key: r (clamped here) then s.
/// \~spanish Empieza con una clave de un solo uso: r (aqui se recorta) y despues s.  \~
void poly1305_init(Poly1305 &p, const uint8_t *key) noexcept;

/// \~english Feeds @p n bytes; any split gives the same tag.
/// \~spanish Anade @p n bytes; cualquier troceado da la misma marca.  \~
void poly1305_update(Poly1305 &p, const uint8_t *m, size_t n) noexcept;

/// \~english Writes the 16-byte tag and wipes @p p.
/// \~spanish Escribe la marca de 16 bytes y borra @p p.  \~
void poly1305_finish(Poly1305 &p, uint8_t *tag) noexcept;

/**
 * @brief
 * \~english AEAD_CHACHA20_POLY1305 sealing (RFC 8439, 2.8): writes `n + kTagSize` to @p out.
 * \~spanish Sellado AEAD_CHACHA20_POLY1305 (RFC 8439, 2.8): escribe `n + kTagSize` en @p out.
 * \~
 *
 * \~english @p out may be @p in.  \~spanish @p out puede ser @p in.  \~
 */
void seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
          size_t ad_len, const uint8_t *in, size_t n, uint8_t *out) noexcept;

/**
 * @brief
 * \~english AEAD_CHACHA20_POLY1305 opening: @p n counts the tag; writes `n - kTagSize`.
 * \~spanish Apertura AEAD_CHACHA20_POLY1305: @p n cuenta la marca; escribe `n - kTagSize`.
 * \~
 *
 * \~english
 * The tag is checked BEFORE anything is decrypted, so a forged packet leaves
 * @p out untouched -- which, unlike the interface's general promise, a
 * caller may rely on here.  @p out may be @p in.
 * \~spanish
 * La marca se comprueba ANTES de descifrar nada, asi que un paquete falsificado
 * deja @p out sin tocar -- de lo que, a diferencia de la promesa general de la
 * interfaz, quien llama si puede depender aqui.  @p out puede ser @p in.
 * \~
 *
 * @return \~english false if the tag does not match  \~spanish falso si la marca no coincide  \~
 */
bool open(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
          size_t ad_len, const uint8_t *in, size_t n, uint8_t *out) noexcept;

} // namespace chacha
} // namespace http_vx

#endif // HTTP_VX_PROVIDERS_CHACHA20_POLY1305_H
