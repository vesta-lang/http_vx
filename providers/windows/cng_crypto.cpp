/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/windows/cng_crypto.cpp
 * @brief
 * \~english The QUIC primitives, run by Windows CNG.
 * \~spanish Las primitivas de QUIC, ejecutadas por la CNG de Windows.
 * \~
 */

/* \~english
 * Windows 10, and before ANY include, for the same reason as in the IOCP
 * backend: the headers settle what exists the first time one of them is
 * pulled in.  Ten because that is where CNG's HKDF arrives.
 * \~spanish
 * Windows 10, y antes de CUALQUIER include, por lo mismo que en el backend de
 * IOCP: las cabeceras deciden que existe la primera vez que se incluye una.
 * Diez porque es donde llega el HKDF de CNG.
 * \~ */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>

#include <bcrypt.h>
#include <wincrypt.h>

#include "cng_crypto.h"

#include "chacha20_poly1305.h"
#include "http_vx/wipe.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

#include <climits>

namespace http_vx {

namespace {

/* \~english
 * CNG's HKDF names, which the Windows SDK declares and MinGW's `bcrypt.h` does
 * not yet.  They are the strings the system looks for, so spelling them here
 * is not a guess: a wrong one would make `ready()` false at start-up.
 * \~spanish
 * Los nombres del HKDF de CNG, que declara el SDK de Windows y el `bcrypt.h` de
 * MinGW todavia no.  Son las cadenas que busca el sistema, asi que escribirlas
 * aqui no es adivinar: una equivocada haria que `ready()` diera falso al
 * arrancar.
 * \~ */
const wchar_t kHkdfAlgorithm[] = L"HKDF";
const wchar_t kHkdfHashAlgorithm[] = L"HkdfHashAlgorithm";
const wchar_t kHkdfPrkAndFinalize[] = L"HkdfPrkAndFinalize";
constexpr ULONG kKdfHkdfInfo = 0x14;

/* \~english
 * Names and magic numbers the Windows SDK's bcrypt.h declares (checked
 * against 10.0.28000.0) and MinGW's does not.
 * \~spanish
 * Nombres y numeros magicos que declara el bcrypt.h del SDK de Windows
 * (comprobados contra el 10.0.28000.0) y el de MinGW no.
 * \~ */
const wchar_t kEcdhAlgorithm[] = L"ECDH";
const wchar_t kEccCurveName[] = L"ECCCurveName";
const wchar_t kCurve25519[] = L"curve25519";
const wchar_t kKdfRawSecret[] = L"TRUNCATE";
constexpr ULONG kEcdhPublicGenericMagic = 0x504B4345;
constexpr ULONG kEcdhPrivateGenericMagic = 0x564B4345;

/// \~english The status CNG gives when a signature does not verify.
/// \~spanish El estado que da CNG cuando una firma no se verifica.  \~
constexpr LONG kInvalidSignature = static_cast<LONG>(0xC000A000UL);

/// \~english The status CNG gives when a tag does not match.
/// \~spanish El estado que da CNG cuando una marca no coincide.  \~
constexpr LONG kAuthTagMismatch = static_cast<LONG>(0xC000A002UL);

/// \~english Whether an NTSTATUS says it worked.  \~spanish Si un NTSTATUS dice que funciono.  \~
bool ok(NTSTATUS s) noexcept {
    return s >= 0;
}

/**
 * @brief
 * \~english What a prepared key is, and what it is for.
 * \~spanish Lo que es una clave preparada, y para que es.
 * \~
 *
 * \~english
 * For AES, the system's key handle.  For ChaCha20, the key bytes themselves:
 * ChaCha20 has no key schedule to precompute -- the key goes into the state
 * word for word on every block -- so keeping the bytes IS preparing it.
 * \~spanish
 * Para AES, el manejador de clave del sistema.  Para ChaCha20, los propios
 * bytes de la clave: ChaCha20 no tiene agenda que precalcular -- la clave entra
 * en el estado palabra a palabra en cada bloque --, asi que guardar los bytes ES
 * prepararla.
 * \~
 */
struct State {
    enum Kind : uint8_t { Aead, HpAes, AeadChaCha, HpChaCha };

    Kind kind;
    BCRYPT_KEY_HANDLE key;
    uint8_t chacha_key[chacha::kKeySize];
};

/// \~english A State from our allocator, with no key yet.
/// \~spanish Un State de nuestro asignador, todavia sin clave.  \~
State *alloc_state(State::Kind kind) noexcept {
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    State *s = static_cast<State *>(util::host_alloc(sizeof(State)));
    if (s == nullptr) return nullptr;
    s->kind = kind;
    s->key = nullptr;
    return s;
}

/// \~english A key for @p alg from @p key, wrapped in a State.
/// \~spanish Una clave para @p alg a partir de @p key, envuelta en un State.  \~
State *new_state(State::Kind kind, void *alg, const uint8_t *key,
                 size_t key_len) noexcept {
    BCRYPT_KEY_HANDLE k = nullptr;

    // \~english The system allocates the key object itself when given none.
    // \~spanish El sistema reserva el objeto de la clave el mismo cuando no se le da.  \~
    if (!ok(BCryptGenerateSymmetricKey(static_cast<BCRYPT_ALG_HANDLE>(alg), &k,
                                       nullptr, 0, const_cast<PUCHAR>(key),
                                       static_cast<ULONG>(key_len), 0)))
        return nullptr;

    State *s = alloc_state(kind);
    if (s == nullptr) {
        BCryptDestroyKey(k);
        return nullptr;
    }
    s->key = k;
    return s;
}

/// \~english A ChaCha20 State holding a copy of @p key.
/// \~spanish Un State de ChaCha20 con una copia de @p key.  \~
State *new_chacha_state(State::Kind kind, const uint8_t *key) noexcept {
    State *s = alloc_state(kind);
    if (s == nullptr) return nullptr;
    util::vesta_memcpy(s->chacha_key, key, chacha::kKeySize);
    return s;
}

/// \~english Opens @p id, optionally with a chaining mode; null if the system refuses.
/// \~spanish Abre @p id, con un modo de encadenado si se da; nulo si el sistema se niega.  \~
void *open_alg(const wchar_t *id, ULONG flags, const wchar_t *mode,
               size_t mode_size) noexcept {
    BCRYPT_ALG_HANDLE h = nullptr;
    if (!ok(BCryptOpenAlgorithmProvider(&h, id, nullptr, flags))) return nullptr;
    if (mode != nullptr &&
        !ok(BCryptSetProperty(h, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(mode)),
                              static_cast<ULONG>(mode_size), 0))) {
        BCryptCloseAlgorithmProvider(h, 0);
        return nullptr;
    }
    return h;
}

/// \~english Closes @p h if it was opened.  \~spanish Cierra @p h si se abrio.  \~
void close_alg(void *h) noexcept {
    if (h != nullptr) BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(h), 0);
}

} // namespace

CngCrypto::CngCrypto() noexcept {
    gcm_ = open_alg(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_GCM,
                    sizeof BCRYPT_CHAIN_MODE_GCM);
    ecb_ = open_alg(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_ECB,
                    sizeof BCRYPT_CHAIN_MODE_ECB);
    hmac256_ = open_alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG,
                        nullptr, 0);
    hmac384_ = open_alg(BCRYPT_SHA384_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG,
                        nullptr, 0);
    sha256_ = open_alg(BCRYPT_SHA256_ALGORITHM, 0, nullptr, 0);
    sha384_ = open_alg(BCRYPT_SHA384_ALGORITHM, 0, nullptr, 0);
    hkdf_ = open_alg(kHkdfAlgorithm, 0, nullptr, 0);

    // \~english The key exchange and signature algorithms: asked about through supports(Group), not ready().
    // \~spanish Los algoritmos de intercambio de claves y de firma: se pregunta por ellos con supports(Group), no con ready().  \~
    x25519_ = open_alg(kEcdhAlgorithm, 0, nullptr, 0);
    if (x25519_ != nullptr &&
        !ok(BCryptSetProperty(static_cast<BCRYPT_ALG_HANDLE>(x25519_), kEccCurveName,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(kCurve25519)), sizeof kCurve25519, 0))) {
        close_alg(x25519_);
        x25519_ = nullptr;
    }
    ecdh256_ = open_alg(BCRYPT_ECDH_P256_ALGORITHM, 0, nullptr, 0);
    ecdsa256_ = open_alg(BCRYPT_ECDSA_P256_ALGORITHM, 0, nullptr, 0);
    rsa_ = open_alg(BCRYPT_RSA_ALGORITHM, 0, nullptr, 0);

    // \~english The first one missing is named, so that the refusal says why.
    // \~spanish Se nombra el primero que falte, para que la negativa diga por que.  \~
    if (gcm_ == nullptr) missing_ = "AES-GCM";
    else if (ecb_ == nullptr) missing_ = "AES-ECB";
    else if (hmac256_ == nullptr) missing_ = "HMAC-SHA256";
    else if (hmac384_ == nullptr) missing_ = "HMAC-SHA384";
    else if (sha256_ == nullptr) missing_ = "SHA256";
    else if (sha384_ == nullptr) missing_ = "SHA384";
    else if (hkdf_ == nullptr) missing_ = "HKDF";
}

CngCrypto::~CngCrypto() {
    close_alg(gcm_);
    close_alg(ecb_);
    close_alg(hmac256_);
    close_alg(hmac384_);
    close_alg(sha256_);
    close_alg(sha384_);
    close_alg(hkdf_);
    close_alg(x25519_);
    close_alg(ecdh256_);
    close_alg(ecdsa256_);
    close_alg(rsa_);
}

bool CngCrypto::digest(quic::Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept {
    void *alg = h == quic::Hash::Sha384 ? sha384_ : sha256_;
    if (alg == nullptr || n > ULONG_MAX) return false;
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (!ok(BCryptCreateHash(static_cast<BCRYPT_ALG_HANDLE>(alg), &hh, nullptr, 0, nullptr, 0, 0)))
        return false;
    bool done = true;
    if (n != 0) done = ok(BCryptHashData(hh, const_cast<PUCHAR>(in), static_cast<ULONG>(n), 0));
    done = done && ok(BCryptFinishHash(hh, out, static_cast<ULONG>(quic::hash_size(h)), 0));
    BCryptDestroyHash(hh);
    return done;
}

bool CngCrypto::ready() const noexcept {
    return missing_ == nullptr;
}

bool CngCrypto::random(uint8_t *out, size_t n) noexcept {
    // \~english The system's preferred generator: no algorithm handle to keep.
    // \~spanish El generador preferido del sistema: sin manejador de algoritmo que guardar.  \~
    while (n != 0) {
        const ULONG take = n > (1u << 20) ? (1u << 20) : static_cast<ULONG>(n);
        if (!ok(BCryptGenRandom(nullptr, out, take, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return false;
        out += take;
        n -= take;
    }
    return true;
}

bool CngCrypto::supports(quic::Aead a) const noexcept {
    // \~english ChaCha20 comes from `providers/common`, not from the system.
    // \~spanish ChaCha20 sale de `providers/common`, no del sistema.  \~
    (void)a;
    return ready();
}

bool CngCrypto::extract(quic::Hash h, const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t *prk) noexcept {
    void *alg = h == quic::Hash::Sha384 ? hmac384_ : hmac256_;
    if (alg == nullptr) return false;
    if (salt_len > ULONG_MAX || ikm_len > ULONG_MAX) return false;

    /* \~english
     * HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM): the salt is the HMAC key
     * and the input keying material the message.  This is the definition in
     * RFC 5869, not a construction of this project's.
     * \~spanish
     * HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM): la sal es la clave del
     * HMAC y el material de entrada el mensaje.  Es la definicion del RFC 5869,
     * no una construccion de este proyecto.
     * \~ */
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (!ok(BCryptCreateHash(static_cast<BCRYPT_ALG_HANDLE>(alg), &hh, nullptr, 0,
                             const_cast<PUCHAR>(salt),
                             static_cast<ULONG>(salt_len), 0)))
        return false;

    bool done = true;
    if (ikm_len != 0)
        done = ok(BCryptHashData(hh, const_cast<PUCHAR>(ikm),
                                 static_cast<ULONG>(ikm_len), 0));
    done = done && ok(BCryptFinishHash(hh, prk,
                                       static_cast<ULONG>(quic::hash_size(h)), 0));
    BCryptDestroyHash(hh);
    return done;
}

bool CngCrypto::expand(quic::Hash h, const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len, uint8_t *out,
                       size_t out_len) noexcept {
    if (hkdf_ == nullptr) return false;
    if (prk_len > ULONG_MAX || info_len > ULONG_MAX || out_len > ULONG_MAX)
        return false;

    BCRYPT_KEY_HANDLE k = nullptr;
    if (!ok(BCryptGenerateSymmetricKey(static_cast<BCRYPT_ALG_HANDLE>(hkdf_), &k,
                                       nullptr, 0, const_cast<PUCHAR>(prk),
                                       static_cast<ULONG>(prk_len), 0)))
        return false;

    const wchar_t *hash = h == quic::Hash::Sha384 ? BCRYPT_SHA384_ALGORITHM
                                                  : BCRYPT_SHA256_ALGORITHM;
    ULONG hash_bytes = 0;
    while (hash[hash_bytes] != 0) ++hash_bytes;
    hash_bytes = (hash_bytes + 1) * sizeof(wchar_t);

    // \~english The secret given IS the pseudorandom key: skip the extract half.
    // \~spanish El secreto dado ES la clave pseudoaleatoria: se salta la mitad extract.  \~
    static uint8_t kEmpty = 0;
    BCryptBuffer param;
    param.cbBuffer = static_cast<ULONG>(info_len);
    param.BufferType = kKdfHkdfInfo;
    param.pvBuffer = info_len ? const_cast<uint8_t *>(info) : &kEmpty;
    BCryptBufferDesc desc;
    desc.ulVersion = BCRYPTBUFFER_VERSION;
    desc.cBuffers = 1;
    desc.pBuffers = &param;

    ULONG got = 0;
    const bool done =
        ok(BCryptSetProperty(k, kHkdfHashAlgorithm,
                             reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(hash)),
                             hash_bytes, 0)) &&
        ok(BCryptSetProperty(k, kHkdfPrkAndFinalize, nullptr, 0, 0)) &&
        ok(BCryptKeyDerivation(k, &desc, out, static_cast<ULONG>(out_len), &got, 0)) &&
        got == out_len;
    BCryptDestroyKey(k);
    return done;
}

void *CngCrypto::prepare_aead(quic::Aead a, const uint8_t *key) noexcept {
    if (!supports(a)) return nullptr;
    if (a == quic::Aead::ChaCha20Poly1305) return new_chacha_state(State::AeadChaCha, key);
    return new_state(State::Aead, gcm_, key, quic::key_size(a));
}

void *CngCrypto::prepare_hp(quic::Aead a, const uint8_t *key) noexcept {
    if (!supports(a)) return nullptr;
    if (a == quic::Aead::ChaCha20Poly1305) return new_chacha_state(State::HpChaCha, key);
    return new_state(State::HpAes, ecb_, key, quic::key_size(a));
}

void CngCrypto::forget(void *state) noexcept {
    State *s = static_cast<State *>(state);
    if (s == nullptr) return;
    // \~english Destroying a system key also wipes it; our own bytes we wipe.
    // \~spanish Destruir una clave del sistema tambien la borra; los bytes propios los borramos.  \~
    if (s->key != nullptr) BCryptDestroyKey(s->key);
    wipe_secret(s->chacha_key, sizeof s->chacha_key);
    util::host_free(s);
}

bool CngCrypto::seal(void *aead, const uint8_t *nonce, const uint8_t *ad,
                     size_t ad_len, const uint8_t *in, size_t n,
                     uint8_t *out) noexcept {
    State *s = static_cast<State *>(aead);
    if (s == nullptr) return false;
    if (s->kind == State::AeadChaCha) {
        chacha::seal(s->chacha_key, nonce, ad, ad_len, in, n, out);
        return true;
    }
    if (s->kind != State::Aead) return false;
    if (n > ULONG_MAX || ad_len > ULONG_MAX) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(quic::kNonceSize);
    info.pbAuthData = const_cast<PUCHAR>(ad);
    info.cbAuthData = static_cast<ULONG>(ad_len);
    info.pbTag = out + n;
    info.cbTag = static_cast<ULONG>(quic::kTagSize);

    // \~english CNG encrypts in place when input and output are the same buffer.
    // \~spanish CNG cifra en su sitio cuando entrada y salida son el mismo buffer.  \~
    ULONG done = 0;
    if (!ok(BCryptEncrypt(s->key, const_cast<PUCHAR>(in), static_cast<ULONG>(n),
                          &info, nullptr, 0, out, static_cast<ULONG>(n), &done, 0)))
        return false;
    return done == n;
}

quic::OpenResult CngCrypto::open(void *aead, const uint8_t *nonce,
                                 const uint8_t *ad, size_t ad_len,
                                 const uint8_t *in, size_t n,
                                 uint8_t *out) noexcept {
    State *s = static_cast<State *>(aead);
    if (s == nullptr) return quic::OpenResult::Failed;
    if (s->kind == State::AeadChaCha)
        return chacha::open(s->chacha_key, nonce, ad, ad_len, in, n, out)
                   ? quic::OpenResult::Ok
                   : quic::OpenResult::Forged;
    if (s->kind != State::Aead) return quic::OpenResult::Failed;
    if (n > ULONG_MAX || ad_len > ULONG_MAX) return quic::OpenResult::Failed;
    if (n < quic::kTagSize) return quic::OpenResult::Forged;

    const size_t body = n - quic::kTagSize;

    // \~english The tag is held apart, as in the OpenSSL provider, before decrypting in place.
    // \~spanish La marca se guarda aparte, como en el proveedor de OpenSSL, antes de descifrar en su sitio.  \~
    uint8_t tag[quic::kTagSize];
    util::vesta_memcpy(tag, in + body, quic::kTagSize);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(quic::kNonceSize);
    info.pbAuthData = const_cast<PUCHAR>(ad);
    info.cbAuthData = static_cast<ULONG>(ad_len);
    info.pbTag = tag;
    info.cbTag = static_cast<ULONG>(quic::kTagSize);

    ULONG done = 0;
    const NTSTATUS st =
        BCryptDecrypt(s->key, const_cast<PUCHAR>(in), static_cast<ULONG>(body),
                      &info, nullptr, 0, out, static_cast<ULONG>(body), &done, 0);

    // \~english Only a tag mismatch is the packet's fault; anything else is ours.
    // \~spanish Solo una marca que no coincide es culpa del paquete; cualquier otra cosa es nuestra.  \~
    if (st == kAuthTagMismatch) return quic::OpenResult::Forged;
    if (!ok(st) || done != body) return quic::OpenResult::Failed;
    return quic::OpenResult::Ok;
}

bool CngCrypto::mask(void *hp, const uint8_t *sample, uint8_t *out) noexcept {
    State *s = static_cast<State *>(hp);
    if (s == nullptr) return false;

    if (s->kind == State::HpChaCha) {
        /* \~english
         * RFC 9001, 5.4.4: counter = the sample's first four bytes read
         * little-endian, nonce = its other twelve; the mask is the first five
         * bytes of that block's keystream.
         * \~spanish
         * RFC 9001, 5.4.4: contador = los cuatro primeros bytes de la muestra
         * leidos en orden inverso, nonce = los otros doce; la mascara son los
         * cinco primeros bytes del flujo de ese bloque.
         * \~ */
        const uint32_t counter = static_cast<uint32_t>(sample[0]) |
                                 (static_cast<uint32_t>(sample[1]) << 8) |
                                 (static_cast<uint32_t>(sample[2]) << 16) |
                                 (static_cast<uint32_t>(sample[3]) << 24);
        uint8_t ks[chacha::kBlockSize];
        chacha::block(s->chacha_key, counter, sample + 4, ks);
        util::vesta_memcpy(out, ks, quic::kMaskSize);
        wipe_secret(ks, sizeof ks);
        return true;
    }
    if (s->kind != State::HpAes) return false;

    // \~english One AES block, ECB, no padding: the first five bytes are the mask.
    // \~spanish Un bloque AES, ECB, sin relleno: los cinco primeros bytes son la mascara.  \~
    uint8_t block[16];
    ULONG done = 0;
    if (!ok(BCryptEncrypt(s->key, const_cast<PUCHAR>(sample), 16, nullptr,
                          nullptr, 0, block, sizeof block, &done, 0)) ||
        done != sizeof block)
        return false;
    util::vesta_memcpy(out, block, quic::kMaskSize);
    return true;
}

namespace {

/// \~english A key-exchange or signing key, and what it is for.  \~spanish Una clave de intercambio o de firma, y para que es.  \~
struct CngKey {
    BCRYPT_KEY_HANDLE key;
    bool signing;
    quic::Group group;
    quic::Scheme scheme;
};

CngKey *wrap_key(BCRYPT_KEY_HANDLE k, bool signing, quic::Group g, quic::Scheme s) noexcept {
    if (k == nullptr) return nullptr;
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed, util::AllocFill::All);
    CngKey *w = static_cast<CngKey *>(util::host_alloc(sizeof(CngKey)));
    if (w == nullptr) {
        BCryptDestroyKey(k);
        return nullptr;
    }
    w->key = k;
    w->signing = signing;
    w->group = g;
    w->scheme = s;
    return w;
}

/// \~english The DER of the P-256 curve's OID, as the key parameters carry it.
/// \~spanish El DER del OID de la curva P-256, como lo llevan los parametros de la clave.  \~
const uint8_t kP256Oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

bool is_p256_params(const CRYPT_OBJID_BLOB &p) noexcept {
    if (p.cbData != sizeof kP256Oid) return false;
    for (size_t i = 0; i < sizeof kP256Oid; ++i)
        if (p.pbData[i] != kP256Oid[i]) return false;
    return true;
}

/// \~english Whether two C strings are equal.  \~spanish Si dos cadenas de C son iguales.  \~
bool same(const char *a, const char *b) noexcept {
    if (a == nullptr || b == nullptr) return false;
    while (*a != '\0' && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

/**
 * @brief
 * \~english CNG's raw ECDSA signature (r then s, 32 bytes each) as the DER ECDSA-Sig-Value TLS carries (RFC 8446, 4.2.3).
 * \~spanish La firma ECDSA en crudo de CNG (r y luego s, 32 bytes cada uno) como el ECDSA-Sig-Value en DER que lleva TLS (RFC 8446, 4.2.3).
 * \~
 */
size_t der_from_raw(const uint8_t *raw, uint8_t *out) noexcept {
    uint8_t body[2 * (2 + 33)];
    size_t b = 0;
    for (int half = 0; half < 2; ++half) {
        const uint8_t *v = raw + 32 * half;
        size_t skip = 0;
        while (skip < 31 && v[skip] == 0) ++skip;
        // \~english A leading 0x00 keeps an integer with its top bit set positive (X.690).
        // \~spanish Un 0x00 delante mantiene positivo un entero con el bit alto puesto (X.690).  \~
        const bool pad = (v[skip] & 0x80) != 0;
        body[b++] = 0x02;
        body[b++] = static_cast<uint8_t>(32 - skip + (pad ? 1 : 0));
        if (pad) body[b++] = 0;
        util::vesta_memcpy(body + b, v + skip, 32 - skip);
        b += 32 - skip;
    }
    out[0] = 0x30;
    out[1] = static_cast<uint8_t>(b);
    util::vesta_memcpy(out + 2, body, b);
    return b + 2;
}

/**
 * @brief
 * \~english A DER ECDSA-Sig-Value as CNG's raw 64 bytes; false unless it is strict DER with both integers in range.
 * \~spanish Un ECDSA-Sig-Value en DER como los 64 bytes en crudo de CNG; falso salvo que sea DER estricto con los dos enteros en rango.
 * \~
 *
 * \~english
 * Strict on purpose: a signature that only verifies because this reader is
 * lenient -- a sign bit set, a redundant leading zero, a byte after the
 * sequence -- would verify here and not with the other provider.
 * \~spanish
 * Estricto a proposito: una firma que solo se verifica porque este lector es
 * permisivo -- un bit de signo puesto, un cero de sobra delante, un byte tras la
 * secuencia -- se verificaria aqui y no con el otro proveedor.
 * \~
 */
bool raw_from_der(const uint8_t *der, size_t n, uint8_t *raw) noexcept {
    if (n < 8 || der[0] != 0x30 || der[1] != n - 2 || der[1] >= 0x80) return false;
    size_t at = 2;
    for (int half = 0; half < 2; ++half) {
        if (at + 2 > n || der[at] != 0x02) return false;
        const size_t len = der[at + 1];
        at += 2;
        if (len == 0 || len > 33 || at + len > n) return false;
        const uint8_t *v = der + at;
        if ((v[0] & 0x80) != 0) return false;                        // \~english negative  \~spanish negativo  \~
        if (len > 1 && v[0] == 0 && (v[1] & 0x80) == 0) return false; // \~english not minimal  \~spanish no minimo  \~
        const size_t skip = v[0] == 0 && len > 1 ? 1 : 0;
        if (len - skip > 32) return false;
        util::vesta_memset(raw + 32 * half, 0, 32);
        util::vesta_memcpy(raw + 32 * half + 32 - (len - skip), v + skip, len - skip);
        at += len;
    }
    return at == n;
}

/// \~english The public half of @p k, as TLS carries it.  \~spanish La mitad publica de @p k, como la lleva TLS.  \~
bool export_public(BCRYPT_KEY_HANDLE k, quic::Group g, uint8_t *pub) noexcept {
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    ULONG got = 0;
    if (!ok(BCryptExportKey(k, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &got, 0)) ||
        got != sizeof blob)
        return false;
    const uint8_t *x = blob + sizeof(BCRYPT_ECCKEY_BLOB);
    if (g == quic::Group::X25519) {
        util::vesta_memcpy(pub, x, 32);
        return true;
    }
    pub[0] = 4;
    util::vesta_memcpy(pub + 1, x, 64);
    return true;
}

/**
 * @brief
 * \~english An ECC key blob: header, X, Y and, for a private one, d.
 * \~spanish Un blob de clave ECC: cabecera, X, Y y, para una privada, d.
 * \~
 *
 * \~english X25519 has only the u coordinate, which goes as X; Y is zero.
 * \~spanish X25519 solo tiene la coordenada u, que va como X; Y es cero.  \~
 */
size_t ecc_blob(quic::Group g, bool with_private, const uint8_t *pub, const uint8_t *priv, uint8_t *blob) noexcept {
    BCRYPT_ECCKEY_BLOB h;
    h.dwMagic = g == quic::Group::X25519 ? (with_private ? kEcdhPrivateGenericMagic : kEcdhPublicGenericMagic)
                                         : (with_private ? BCRYPT_ECDH_PRIVATE_P256_MAGIC : BCRYPT_ECDH_PUBLIC_P256_MAGIC);
    h.cbKey = 32;
    util::vesta_memcpy(blob, &h, sizeof h);
    uint8_t *x = blob + sizeof h;
    if (g == quic::Group::X25519) {
        util::vesta_memcpy(x, pub, 32);
        util::vesta_memset(x + 32, 0, 32);
    } else {
        util::vesta_memcpy(x, pub + 1, 64);
    }
    if (with_private) {
        uint8_t *d = x + 64;
        util::vesta_memcpy(d, priv, 32);
        /* \~english
         * CNG only takes an X25519 scalar already clamped; clamping it here
         * changes nothing, since X25519 clamps it anyway (RFC 7748, 5:
         * decodeScalar25519).
         * \~spanish
         * CNG solo acepta un escalar de X25519 ya recortado; recortarlo aqui no
         * cambia nada, porque X25519 lo recorta igualmente (RFC 7748, 5:
         * decodeScalar25519).
         * \~ */
        if (g == quic::Group::X25519) {
            d[0] = static_cast<uint8_t>(d[0] & 248);
            d[31] = static_cast<uint8_t>((d[31] & 127) | 64);
        }
    }
    return sizeof h + (with_private ? 96 : 64);
}

} // namespace

bool CngCrypto::supports(quic::Group g) const noexcept {
    return (g == quic::Group::X25519 ? x25519_ : ecdh256_) != nullptr;
}

void *CngCrypto::generate_key(quic::Group g, uint8_t *pub) noexcept {
    void *alg = g == quic::Group::X25519 ? x25519_ : ecdh256_;
    if (alg == nullptr) return nullptr;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!ok(BCryptGenerateKeyPair(static_cast<BCRYPT_ALG_HANDLE>(alg), &k, g == quic::Group::X25519 ? 255 : 256,
                                  0)))
        return nullptr;
    if (!ok(BCryptFinalizeKeyPair(k, 0)) || !export_public(k, g, pub)) {
        BCryptDestroyKey(k);
        return nullptr;
    }
    return wrap_key(k, false, g, quic::Scheme::EcdsaSecp256r1Sha256);
}

void *CngCrypto::import_key(quic::Group g, const uint8_t *priv, size_t priv_len, const uint8_t *pub) noexcept {
    void *alg = g == quic::Group::X25519 ? x25519_ : ecdh256_;
    if (alg == nullptr || priv_len != 32) return nullptr;
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 96];
    const size_t n = ecc_blob(g, true, pub, priv, blob);
    BCRYPT_KEY_HANDLE k = nullptr;
    const bool imported = ok(BCryptImportKeyPair(static_cast<BCRYPT_ALG_HANDLE>(alg), nullptr, BCRYPT_ECCPRIVATE_BLOB,
                                                 &k, blob, static_cast<ULONG>(n), 0));
    wipe_secret(blob, sizeof blob);
    if (!imported) return nullptr;
    CngKey *w = wrap_key(k, false, g, quic::Scheme::EcdsaSecp256r1Sha256);
    if (w == nullptr) return nullptr;
    /* \~english
     * The system keeps the public half as given, even another key's, and
     * gives it back unchanged, so comparing it proves nothing.  What does is
     * a trial agreement with a fresh key: DH(d, E) equals DH(e, pub) only if
     * pub is d's.  Only known-answer tests import keys, so the cost is theirs.
     * \~spanish
     * El sistema guarda la mitad publica como se le da, aunque sea de otra
     * clave, y la devuelve igual, asi que compararla no prueba nada.  Lo que si
     * lo prueba es un acuerdo de prueba con una clave nueva: DH(d, E) es igual a
     * DH(e, pub) solo si pub es la de d.  Solo las pruebas de respuesta conocida
     * importan claves, asi que el coste es suyo.
     * \~ */
    uint8_t e_pub[quic::kMaxPublicKey];
    uint8_t s1[quic::kMaxShared];
    uint8_t s2[quic::kMaxShared];
    void *e = generate_key(g, e_pub);
    const size_t len = quic::public_key_size(g);
    bool pair = e != nullptr && agree(w, e_pub, len, s1) == quic::Agreed::Ok &&
                agree(e, pub, len, s2) == quic::Agreed::Ok;
    for (size_t i = 0; pair && i < quic::kMaxShared; ++i)
        if (s1[i] != s2[i]) pair = false;
    forget_key(e);
    wipe_secret(s1, sizeof s1);
    wipe_secret(s2, sizeof s2);
    if (!pair) {
        forget_key(w);
        return nullptr;
    }
    return w;
}

quic::Agreed CngCrypto::agree(void *key, const uint8_t *peer, size_t peer_len, uint8_t *shared) noexcept {
    CngKey *k = static_cast<CngKey *>(key);
    if (k == nullptr || k->signing) return quic::Agreed::Failed;
    if (peer_len != quic::public_key_size(k->group)) return quic::Agreed::BadPeerKey;
    if (k->group == quic::Group::Secp256r1 && peer[0] != 4) return quic::Agreed::BadPeerKey;
    void *alg = k->group == quic::Group::X25519 ? x25519_ : ecdh256_;

    // \~english The system checks the point is on the curve when it imports it (4.2.8.2).
    // \~spanish El sistema comprueba que el punto esta en la curva al importarlo (4.2.8.2).  \~
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    const size_t n = ecc_blob(k->group, false, peer, nullptr, blob);
    BCRYPT_KEY_HANDLE other = nullptr;
    if (!ok(BCryptImportKeyPair(static_cast<BCRYPT_ALG_HANDLE>(alg), nullptr, BCRYPT_ECCPUBLIC_BLOB, &other, blob,
                                static_cast<ULONG>(n), 0)))
        return quic::Agreed::BadPeerKey;

    quic::Agreed result = quic::Agreed::Failed;
    BCRYPT_SECRET_HANDLE secret = nullptr;
    ULONG got = 0;
    if (ok(BCryptSecretAgreement(k->key, other, &secret, 0)) &&
        ok(BCryptDeriveKey(secret, kKdfRawSecret, nullptr, shared, 32, &got, 0)) && got == 32) {
        /* \~english
         * The raw secret comes out in the reverse of the order TLS wants, for
         * both groups -- measured against RFC 5903 and RFC 7748, not assumed:
         * P-256's is the X coordinate big-endian (RFC 8446, 7.4.2), X25519's
         * the byte string of RFC 7748.
         * \~spanish
         * El secreto en crudo sale en el orden inverso al que quiere TLS, en los
         * dos grupos -- medido contra el RFC 5903 y el RFC 7748, no supuesto: el de
         * P-256 es la coordenada X en big-endian (RFC 8446, 7.4.2), el de X25519
         * la cadena de bytes del RFC 7748.
         * \~ */
        for (size_t i = 0; i < 16; ++i) {
            const uint8_t t = shared[i];
            shared[i] = shared[31 - i];
            shared[31 - i] = t;
        }
        uint8_t any = 0;
        for (size_t i = 0; i < 32; ++i) any = static_cast<uint8_t>(any | shared[i]);
        // \~english An all-zero X25519 result MUST abort (7.4.2).  \~spanish Un resultado de X25519 a ceros DEBE abortar (7.4.2).  \~
        result = any != 0 ? quic::Agreed::Ok : quic::Agreed::BadPeerKey;
    } else if (k->group == quic::Group::X25519) {
        result = quic::Agreed::BadPeerKey;
    }
    if (secret != nullptr) BCryptDestroySecret(secret);
    BCryptDestroyKey(other);
    return result;
}

void *CngCrypto::signing_key(quic::Scheme s, const uint8_t *pkcs8, size_t len) noexcept {
    // \~english PKCS#8 is decoded by the system (crypt32): no ASN.1 reader of this project's own.
    // \~spanish PKCS#8 lo decodifica el sistema (crypt32): ningun lector ASN.1 propio de este proyecto.  \~
    CRYPT_PRIVATE_KEY_INFO *info = nullptr;
    DWORD info_len = 0;
    if (len > ULONG_MAX ||
        !CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, pkcs8,
                             static_cast<DWORD>(len), CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &info_len))
        return nullptr;

    BCRYPT_KEY_HANDLE k = nullptr;
    if (s == quic::Scheme::EcdsaSecp256r1Sha256 && ecdsa256_ != nullptr &&
        same(info->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) && is_p256_params(info->Algorithm.Parameters)) {
        CRYPT_ECC_PRIVATE_KEY_INFO *ec = nullptr;
        DWORD ec_len = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_PRIVATE_KEY, info->PrivateKey.pbData,
                                info->PrivateKey.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &ec, &ec_len)) {
            // \~english The public point has to be there: CNG imports both halves.
            // \~spanish El punto publico tiene que estar: CNG importa las dos mitades.  \~
            if (ec->PrivateKey.cbData <= 32 && ec->PublicKey.cbData == 65 && ec->PublicKey.pbData[0] == 4) {
                uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 96] = {};
                BCRYPT_ECCKEY_BLOB h;
                h.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                h.cbKey = 32;
                util::vesta_memcpy(blob, &h, sizeof h);
                util::vesta_memcpy(blob + sizeof h, ec->PublicKey.pbData + 1, 64);
                util::vesta_memcpy(blob + sizeof h + 64 + 32 - ec->PrivateKey.cbData, ec->PrivateKey.pbData,
                                   ec->PrivateKey.cbData);
                if (!ok(BCryptImportKeyPair(static_cast<BCRYPT_ALG_HANDLE>(ecdsa256_), nullptr,
                                            BCRYPT_ECCPRIVATE_BLOB, &k, blob, sizeof blob, 0)))
                    k = nullptr;
                wipe_secret(blob, sizeof blob);
            }
            wipe_secret(ec, ec_len);
            LocalFree(ec);
        }
    } else if (s == quic::Scheme::RsaPssRsaeSha256 && rsa_ != nullptr &&
               same(info->Algorithm.pszObjId, szOID_RSA_RSA)) {
        // \~english The system's own RSA key blob, which CNG imports as it is.
        // \~spanish El blob de clave RSA del propio sistema, que CNG importa tal cual.  \~
        uint8_t *legacy = nullptr;
        DWORD legacy_len = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, info->PrivateKey.pbData,
                                info->PrivateKey.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &legacy, &legacy_len)) {
            if (!ok(BCryptImportKeyPair(static_cast<BCRYPT_ALG_HANDLE>(rsa_), nullptr, LEGACY_RSAPRIVATE_BLOB, &k,
                                        legacy, legacy_len, 0)))
                k = nullptr;
            wipe_secret(legacy, legacy_len);
            LocalFree(legacy);
        }
    }
    wipe_secret(info, info_len);
    LocalFree(info);
    return wrap_key(k, true, quic::Group::X25519, s);
}

bool CngCrypto::sign(void *key, const uint8_t *msg, size_t n, uint8_t *sig, size_t room,
                     size_t &sig_len) noexcept {
    CngKey *k = static_cast<CngKey *>(key);
    uint8_t hash[32];
    if (k == nullptr || !k->signing || !digest(quic::Hash::Sha256, msg, n, hash)) return false;
    ULONG got = 0;
    if (k->scheme == quic::Scheme::EcdsaSecp256r1Sha256) {
        uint8_t raw[64];
        if (room < 72 || !ok(BCryptSignHash(k->key, nullptr, hash, sizeof hash, raw, sizeof raw, &got, 0)) ||
            got != sizeof raw)
            return false;
        sig_len = der_from_raw(raw, sig);
        return true;
    }
    // \~english RSA-PSS with MGF1 and a salt the length of the hash (RFC 8446, 4.2.3).
    // \~spanish RSA-PSS con MGF1 y una sal de la longitud del resumen (RFC 8446, 4.2.3).  \~
    BCRYPT_PSS_PADDING_INFO pad{BCRYPT_SHA256_ALGORITHM, sizeof hash};
    if (room > ULONG_MAX ||
        !ok(BCryptSignHash(k->key, &pad, hash, sizeof hash, sig, static_cast<ULONG>(room), &got, BCRYPT_PAD_PSS)))
        return false;
    sig_len = got;
    return true;
}

quic::Verified CngCrypto::verify(quic::Scheme s, const uint8_t *cert, size_t cert_len, const uint8_t *msg, size_t n,
                                 const uint8_t *sig, size_t sig_len) noexcept {
    if (cert_len > ULONG_MAX || sig_len > ULONG_MAX) return quic::Verified::WrongKey;
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, cert, static_cast<DWORD>(cert_len));
    if (c == nullptr) return quic::Verified::WrongKey;
    CERT_PUBLIC_KEY_INFO &spki = c->pCertInfo->SubjectPublicKeyInfo;
    // \~english rsa_pss_rsae wants an rsaEncryption key (RFC 8446, 4.2.3); ECDSA here, a P-256 one.
    // \~spanish rsa_pss_rsae quiere una clave rsaEncryption (RFC 8446, 4.2.3); ECDSA aqui, una P-256.  \~
    const bool fits = s == quic::Scheme::EcdsaSecp256r1Sha256
                          ? same(spki.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) && is_p256_params(spki.Algorithm.Parameters)
                          : same(spki.Algorithm.pszObjId, szOID_RSA_RSA);
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!fits || !CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &spki, 0, nullptr, &k)) {
        CertFreeCertificateContext(c);
        return quic::Verified::WrongKey;
    }
    quic::Verified result = quic::Verified::Failed;
    uint8_t hash[32];
    if (digest(quic::Hash::Sha256, msg, n, hash)) {
        NTSTATUS st;
        if (s == quic::Scheme::EcdsaSecp256r1Sha256) {
            uint8_t raw[64];
            st = raw_from_der(sig, sig_len, raw) ? BCryptVerifySignature(k, nullptr, hash, sizeof hash, raw, sizeof raw, 0)
                                                 : kInvalidSignature;
        } else {
            BCRYPT_PSS_PADDING_INFO pad{BCRYPT_SHA256_ALGORITHM, sizeof hash};
            st = BCryptVerifySignature(k, &pad, hash, sizeof hash, const_cast<PUCHAR>(sig), static_cast<ULONG>(sig_len),
                                       BCRYPT_PAD_PSS);
        }
        // \~english Anything but success is a signature that does not verify.
        // \~spanish Cualquier cosa que no sea exito es una firma que no se verifica.  \~
        result = ok(st) ? quic::Verified::Ok : quic::Verified::Bad;
    }
    BCryptDestroyKey(k);
    CertFreeCertificateContext(c);
    return result;
}

void CngCrypto::forget_key(void *key) noexcept {
    CngKey *k = static_cast<CngKey *>(key);
    if (k == nullptr) return;
    BCryptDestroyKey(k->key);
    util::host_free(k);
}

} // namespace http_vx
