/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/protection.cpp
 * @brief
 * \~english QUIC packet protection: the RFC 9001 logic, with the primitives left to a provider.
 * \~spanish La proteccion de paquetes de QUIC: la logica del RFC 9001, con las primitivas a cargo de un proveedor.
 * \~
 */

#include "http_vx/quic_protection.h"

#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace quic {

namespace {

/**
 * @brief
 * \~english What changes with the version: the salt, the labels and the Retry key.
 * \~spanish Lo que cambia con la version: la sal, las etiquetas y la clave del Retry.
 * \~
 */
struct VersionConstants {
    uint32_t version;
    uint8_t salt[20];
    const char *key;
    const char *iv;
    const char *hp;
    const char *ku;
    uint8_t retry_key[16];
    uint8_t retry_nonce[kNonceSize];
};

/* \~english
 * RFC 9001, sections 5.2 and 5.8, and RFC 9369, section 3.3.  Version 2 exists
 * to change exactly these bytes -- so that a middlebox that learned version 1's
 * constants by heart cannot read version 2 -- and a table is the honest shape
 * for "the same algorithm with other constants".
 * \~spanish
 * RFC 9001, secciones 5.2 y 5.8, y RFC 9369, seccion 3.3.  La version 2 existe
 * para cambiar justo estos bytes -- que un equipo intermedio que se aprendio de
 * memoria las constantes de la version 1 no pueda leer la 2 --, y una tabla es
 * la forma honrada de "el mismo algoritmo con otras constantes".
 * \~ */
constexpr VersionConstants kVersions[] = {
    {kVersion1,
     {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
     "quic key", "quic iv", "quic hp", "quic ku",
     {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
      0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e},
     {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}},
    {kVersion2,
     {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
      0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
     "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku",
     {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
      0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92},
     {0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a}},
};

/// \~english The constants of @p version, or null.
/// \~spanish Las constantes de @p version, o nulo.  \~
const VersionConstants *constants_of(uint32_t version) noexcept {
    for (const VersionConstants &v : kVersions)
        if (v.version == version) return &v;
    return nullptr;
}

/**
 * @brief
 * \~english Overwrites @p n bytes of key material so that no later read finds them.
 * \~spanish Sobrescribe @p n bytes de material de clave para que ninguna lectura posterior los encuentre.
 * \~
 *
 * \~english
 * A plain zeroing of memory that is about to die is a dead store, and an
 * optimizer is entitled to delete it -- which is how keys survive in freed
 * memory.  The out-of-line call and the empty asm that claims to read the
 * bytes are what keep the zeroing in the binary.
 * \~spanish
 * Poner a cero memoria que esta a punto de morir es un almacen muerto, y el
 * optimizador tiene derecho a borrarlo -- que es como sobreviven las claves en
 * memoria liberada.  La llamada fuera de linea y el asm vacio que dice leer los
 * bytes son lo que mantiene el borrado en el binario.
 * \~
 */
void wipe(void *p, size_t n) noexcept {
    util::vesta_memset_noinline(p, 0, n);
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/// \~english The bits of the first byte header protection covers.
/// \~spanish Los bits del primer byte que cubre la proteccion de cabecera.  \~
uint8_t masked_bits(uint8_t first) noexcept {
    /* \~english
     * A long header masks four bits (two reserved, two of packet-number
     * length); a short one five, because it also hides the key phase.
     * \~spanish
     * Una cabecera larga enmascara cuatro bits (dos reservados y dos de
     * longitud del numero de paquete); una corta cinco, porque tambien oculta la
     * fase de clave.
     * \~ */
    return (first & 0x80) ? 0x0f : 0x1f;
}

/// \~english The reserved bits, which must be zero once unmasked.
/// \~spanish Los bits reservados, que tienen que ser cero una vez desenmascarados.  \~
uint8_t reserved_bits(uint8_t first) noexcept {
    return (first & 0x80) ? 0x0c : 0x18;
}

/// \~english Whether this packet type carries a packet number at all.
/// \~spanish Si este tipo de paquete lleva numero de paquete.  \~
bool is_protected(const PacketHeader &h) noexcept {
    switch (h.type) {
    case PacketType::Initial:
    case PacketType::ZeroRtt:
    case PacketType::Handshake:
    case PacketType::OneRtt:
        return h.pn_offset != 0;
    default:
        return false;
    }
}

} // namespace

bool knows_version(uint32_t version) noexcept {
    return constants_of(version) != nullptr;
}

size_t hkdf_label(uint8_t *out, size_t room, const char *label,
                  size_t out_len) noexcept {
    static const char kPrefix[] = "tls13 ";
    constexpr size_t kPrefixLen = sizeof kPrefix - 1;

    size_t label_len = 0;
    while (label[label_len] != '\0') ++label_len;

    /* \~english
     * The label is length-prefixed with one byte, so "tls13 " plus the label
     * cannot pass 255; and the output length is a uint16.
     * \~spanish
     * La etiqueta lleva delante su longitud en un byte, asi que "tls13 " mas la
     * etiqueta no puede pasar de 255; y la longitud de salida es un uint16.
     * \~ */
    const size_t full = kPrefixLen + label_len;
    if (full > 255 || out_len > 0xFFFF) return 0;

    const size_t size = 2 + 1 + full + 1;
    if (size > room) return 0;

    out[0] = static_cast<uint8_t>(out_len >> 8);
    out[1] = static_cast<uint8_t>(out_len);
    out[2] = static_cast<uint8_t>(full);
    util::vesta_memcpy(out + 3, kPrefix, kPrefixLen);
    util::vesta_memcpy(out + 3 + kPrefixLen, label, label_len);

    // \~english The context, empty.  \~spanish El contexto, vacio.  \~
    out[3 + full] = 0;
    return size;
}

bool expand_label(Crypto &c, Hash h, const uint8_t *secret, size_t secret_len,
                  const char *label, uint8_t *out, size_t out_len) noexcept {
    uint8_t info[2 + 1 + 255 + 1];
    const size_t n = hkdf_label(info, sizeof info, label, out_len);
    if (n == 0) return false;
    return c.expand(h, secret, secret_len, info, n, out, out_len);
}

bool initial_secrets(Crypto &c, uint32_t version, const uint8_t *dcid,
                     size_t dcid_len, uint8_t *client,
                     uint8_t *server) noexcept {
    const VersionConstants *v = constants_of(version);
    if (v == nullptr) return false;

    // \~english Initial keys are always SHA-256 and AES-128-GCM (RFC 9001, 5.2).
    // \~spanish Las claves Initial son siempre SHA-256 y AES-128-GCM (RFC 9001, 5.2).  \~
    uint8_t prk[32];
    bool ok = c.extract(Hash::Sha256, v->salt, sizeof v->salt, dcid, dcid_len,
                        prk) &&
              expand_label(c, Hash::Sha256, prk, sizeof prk, "client in",
                           client, 32) &&
              expand_label(c, Hash::Sha256, prk, sizeof prk, "server in",
                           server, 32);
    wipe(prk, sizeof prk);
    return ok;
}

bool derive_key_material(Crypto &c, uint32_t version, Aead a,
                         const uint8_t *secret, size_t secret_len,
                         KeyMaterial &out) noexcept {
    const VersionConstants *v = constants_of(version);
    if (v == nullptr) return false;

    const Hash h = hash_of(a);

    /* \~english
     * A secret of the wrong length is a secret from the wrong suite, and
     * expanding it anyway would give keys that seal packets nobody can open --
     * a failure that shows up as "every packet forged", far from its cause.
     * \~spanish
     * Un secreto de la longitud equivocada es un secreto de otro algoritmo, y
     * expandirlo igualmente daria claves que sellan paquetes que nadie puede
     * abrir -- un fallo que aparece como "todos los paquetes falsificados",
     * lejos de su causa.
     * \~ */
    if (secret_len != hash_size(h)) return false;

    out.aead = a;
    const size_t ks = key_size(a);
    return expand_label(c, h, secret, secret_len, v->key, out.key, ks) &&
           expand_label(c, h, secret, secret_len, v->iv, out.iv, kNonceSize) &&
           expand_label(c, h, secret, secret_len, v->hp, out.hp, ks);
}

bool next_secret(Crypto &c, uint32_t version, Aead a, const uint8_t *secret,
                 size_t secret_len, uint8_t *out) noexcept {
    const VersionConstants *v = constants_of(version);
    if (v == nullptr) return false;

    const Hash h = hash_of(a);
    if (secret_len != hash_size(h)) return false;
    return expand_label(c, h, secret, secret_len, v->ku, out, secret_len);
}

bool prepare_keys(Crypto &c, KeyMaterial &m, PacketKeys &out) noexcept {
    out.aead = m.aead;
    out.aead_state = c.prepare_aead(m.aead, m.key);
    out.hp_state = c.prepare_hp(m.aead, m.hp);
    util::vesta_memcpy(out.iv, m.iv, kNonceSize);

    // \~english The provider has its copy; this one is no longer needed.
    // \~spanish El proveedor tiene su copia; esta ya no hace falta.  \~
    wipe(&m, sizeof m);

    if (out.aead_state == nullptr || out.hp_state == nullptr) {
        forget_keys(c, out);
        return false;
    }
    return true;
}

void forget_keys(Crypto &c, PacketKeys &k) noexcept {
    c.forget(k.aead_state);
    c.forget(k.hp_state);
    k.aead_state = nullptr;
    k.hp_state = nullptr;
    wipe(k.iv, sizeof k.iv);
}

bool make_initial_keys(Crypto &c, uint32_t version, const uint8_t *dcid,
                       size_t dcid_len, bool is_server, PacketKeys &read,
                       PacketKeys &write) noexcept {
    uint8_t client[32];
    uint8_t server[32];
    KeyMaterial m;

    bool ok = initial_secrets(c, version, dcid, dcid_len, client, server);

    // \~english A server reads what the client seals, and the other way round.
    // \~spanish Un servidor lee lo que sella el cliente, y al reves.  \~
    const uint8_t *rs = is_server ? client : server;
    const uint8_t *ws = is_server ? server : client;

    ok = ok && derive_key_material(c, version, Aead::Aes128Gcm, rs, 32, m) &&
         prepare_keys(c, m, read);
    if (ok) {
        ok = derive_key_material(c, version, Aead::Aes128Gcm, ws, 32, m) &&
             prepare_keys(c, m, write);
        if (!ok) forget_keys(c, read);
    }

    wipe(client, sizeof client);
    wipe(server, sizeof server);
    wipe(&m, sizeof m);
    return ok;
}

void make_nonce(const uint8_t *iv, uint64_t pn, uint8_t *out) noexcept {
    util::vesta_memcpy(out, iv, kNonceSize);

    // \~english The packet number, big-endian, XORed into the IV's last eight bytes.
    // \~spanish El numero de paquete, en orden de red, en OR exclusivo con los ocho ultimos bytes del IV.  \~
    for (size_t i = 0; i < 8; ++i)
        out[kNonceSize - 1 - i] ^= static_cast<uint8_t>(pn >> (8 * i));
}

uint64_t decode_packet_number(uint64_t expected, uint64_t truncated,
                              size_t len) noexcept {
    const uint64_t win = uint64_t{1} << (8 * len);
    const uint64_t hwin = win / 2;
    const uint64_t mask = win - 1;

    /* \~english
     * The closest number to the one expected whose low bits are the ones that
     * came.  The comparisons are written as sums, not as `expected - hwin`,
     * because early in a connection `expected` is smaller than half a window
     * and the subtraction would wrap to a huge number that every candidate is
     * below.
     * \~spanish
     * El numero mas cercano al esperado cuyos bits bajos son los que llegaron.
     * Las comparaciones van escritas como sumas y no como `expected - hwin`,
     * porque al principio de una conexion `expected` es menor que media ventana
     * y la resta daria la vuelta a un numero enorme por debajo del cual estan
     * todos los candidatos.
     * \~ */
    const uint64_t candidate = (expected & ~mask) | (truncated & mask);

    if (candidate + hwin <= expected && candidate < (uint64_t{1} << 62) - win)
        return candidate + win;
    if (candidate > expected + hwin && candidate >= win)
        return candidate - win;
    return candidate;
}

size_t packet_number_length(uint64_t pn, uint64_t largest_acked,
                            bool any_acked) noexcept {
    if (any_acked && pn <= largest_acked) return 0;

    const uint64_t unacked = any_acked ? pn - largest_acked : pn + 1;

    /* \~english
     * RFC 9000, A.2: log2(unacked) + 1 bits, rounded up to bytes -- that is,
     * the smallest length whose half window reaches `unacked`.
     * \~spanish
     * RFC 9000, A.2: log2(unacked) + 1 bits, redondeado a bytes -- es decir, la
     * longitud mas pequena cuya media ventana llega a `unacked`.
     * \~ */
    for (size_t len = 1; len <= 4; ++len)
        if (unacked <= (uint64_t{1} << (8 * len - 1))) return len;
    return 0;
}

const char *unprotect_name(Unprotect u) noexcept {
    switch (u) {
    case Unprotect::Ok:              return "ok";
    case Unprotect::NotProtected:    return "not-protected";
    case Unprotect::Forged:          return "forged";
    case Unprotect::ReservedBitsSet: return "reserved-bits-set";
    case Unprotect::Failed:          return "provider-failed";
    }
    return "unknown";
}

Unprotect unmask_header(Crypto &c, void *hp_state, uint8_t *packet,
                        const PacketHeader &h, uint64_t expected_pn,
                        Unprotected &out) noexcept {
    if (!is_protected(h)) return Unprotect::NotProtected;

    /* \~english
     * `parse_packet` already refused anything shorter than the packet number
     * plus twenty bytes, so the sample -- sixteen bytes, four past the start
     * of the packet number -- is inside the packet.  That is why the check is
     * there and not here: it had to happen before any key was touched.
     * \~spanish
     * `parse_packet` ya rechazo todo lo que mida menos que el numero de paquete
     * mas veinte bytes, asi que la muestra -- dieciseis bytes, a cuatro del
     * principio del numero de paquete -- esta dentro del paquete.  Por eso la
     * comprobacion esta alli y no aqui: tenia que hacerse antes de tocar
     * ninguna clave.
     * \~ */
    uint8_t m[kMaskSize];
    if (!c.mask(hp_state, packet + h.pn_offset + kSampleOffset, m))
        return Unprotect::Failed;

    packet[0] = static_cast<uint8_t>(packet[0] ^ (m[0] & masked_bits(packet[0])));

    const size_t pn_len = static_cast<size_t>(packet[0] & 0x03) + 1;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; ++i) {
        packet[h.pn_offset + i] =
            static_cast<uint8_t>(packet[h.pn_offset + i] ^ m[1 + i]);
        truncated = (truncated << 8) | packet[h.pn_offset + i];
    }

    const size_t payload_off = h.pn_offset + pn_len;

    out.first = packet[0];
    out.pn_len = static_cast<uint8_t>(pn_len);
    out.pn = decode_packet_number(expected_pn, truncated, pn_len);
    out.payload = {static_cast<uint32_t>(payload_off),
                   static_cast<uint32_t>(h.size - payload_off - kTagSize)};
    return Unprotect::Ok;
}

Unprotect open_payload(Crypto &c, const PacketKeys &k, const uint8_t *packet,
                       const PacketHeader &h, const Unprotected &u,
                       uint8_t *into) noexcept {
    (void)h;

    uint8_t nonce[kNonceSize];
    make_nonce(k.iv, u.pn, nonce);

    // \~english The associated data is the whole header, unmasked.
    // \~spanish Los datos asociados son la cabecera entera, desenmascarada.  \~
    const OpenResult r = c.open(k.aead_state, nonce, packet, u.payload.off,
                                packet + u.payload.off,
                                u.payload.len + kTagSize, into);
    if (r == OpenResult::Failed) return Unprotect::Failed;
    if (r == OpenResult::Forged) return Unprotect::Forged;

    if ((u.first & reserved_bits(u.first)) != 0)
        return Unprotect::ReservedBitsSet;
    return Unprotect::Ok;
}

Unprotect unprotect_packet(Crypto &c, const PacketKeys &k, uint8_t *packet,
                           const PacketHeader &h, uint64_t expected_pn,
                           Unprotected &out) noexcept {
    const Unprotect r = unmask_header(c, k.hp_state, packet, h, expected_pn, out);
    if (r != Unprotect::Ok) return r;
    return open_payload(c, k, packet, h, out, packet + out.payload.off);
}

Protect protect_packet(Crypto &c, const PacketKeys &k, uint8_t *packet,
                       size_t pn_offset, size_t pn_len, uint64_t pn,
                       size_t payload_len) noexcept {
    if (pn_len < 1 || pn_len > 4) return Protect::BadPacketNumberLength;
    if (pn_len + payload_len < kSampleOffset) return Protect::TooShortToSample;

    packet[0] = static_cast<uint8_t>((packet[0] & ~0x03) | (pn_len - 1));
    for (size_t i = 0; i < pn_len; ++i)
        packet[pn_offset + i] =
            static_cast<uint8_t>(pn >> (8 * (pn_len - 1 - i)));

    const size_t payload_off = pn_offset + pn_len;

    uint8_t nonce[kNonceSize];
    make_nonce(k.iv, pn, nonce);
    if (!c.seal(k.aead_state, nonce, packet, payload_off, packet + payload_off,
                payload_len, packet + payload_off))
        return Protect::Failed;

    // \~english The mask comes from what was just sealed, so it goes on last.
    // \~spanish La mascara sale de lo que se acaba de sellar, asi que va la ultima.  \~
    uint8_t m[kMaskSize];
    if (!c.mask(k.hp_state, packet + pn_offset + kSampleOffset, m))
        return Protect::Failed;

    packet[0] = static_cast<uint8_t>(packet[0] ^ (m[0] & masked_bits(packet[0])));
    for (size_t i = 0; i < pn_len; ++i)
        packet[pn_offset + i] = static_cast<uint8_t>(packet[pn_offset + i] ^ m[1 + i]);
    return Protect::Ok;
}

bool retry_tag(Crypto &c, uint32_t version, const uint8_t *odcid,
               size_t odcid_len, const uint8_t *retry, size_t n,
               uint8_t *scratch, size_t scratch_room, uint8_t *tag) noexcept {
    const VersionConstants *v = constants_of(version);
    if (v == nullptr || odcid_len > kMaxConnectionId) return false;
    if (scratch_room < 1 + odcid_len + n) return false;

    // \~english The Retry pseudo-packet (RFC 9001, section 5.8).
    // \~spanish El pseudo-paquete del Retry (RFC 9001, seccion 5.8).  \~
    scratch[0] = static_cast<uint8_t>(odcid_len);
    util::vesta_memcpy(scratch + 1, odcid, odcid_len);
    util::vesta_memcpy(scratch + 1 + odcid_len, retry, n);

    void *aead = c.prepare_aead(Aead::Aes128Gcm, v->retry_key);
    if (aead == nullptr) return false;

    // \~english Sealing nothing leaves only the tag.
    // \~spanish Sellar nada deja solo la marca.  \~
    const bool ok = c.seal(aead, v->retry_nonce, scratch, 1 + odcid_len + n,
                           tag, 0, tag);
    c.forget(aead);
    return ok;
}

} // namespace quic
} // namespace http_vx
