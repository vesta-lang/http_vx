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

#include "cng_crypto.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

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

/// \~english The status CNG gives when a tag does not match.
/// \~spanish El estado que da CNG cuando una marca no coincide.  \~
constexpr LONG kAuthTagMismatch = static_cast<LONG>(0xC000A002UL);

/// \~english Whether an NTSTATUS says it worked.  \~spanish Si un NTSTATUS dice que funciono.  \~
bool ok(NTSTATUS s) noexcept {
    return s >= 0;
}

/**
 * @brief
 * \~english What a prepared key is: the system's key handle and what it is for.
 * \~spanish Lo que es una clave preparada: el manejador de clave del sistema y para que es.
 * \~
 */
struct State {
    enum Kind : uint8_t { Aead, HpAes };

    Kind kind;
    BCRYPT_KEY_HANDLE key;
};

/// \~english A key for @p alg from @p key, wrapped in a State from our allocator.
/// \~spanish Una clave para @p alg a partir de @p key, envuelta en un State de nuestro asignador.  \~
State *new_state(State::Kind kind, void *alg, const uint8_t *key,
                 size_t key_len) noexcept {
    BCRYPT_KEY_HANDLE k = nullptr;

    // \~english The system allocates the key object itself when given none.
    // \~spanish El sistema reserva el objeto de la clave el mismo cuando no se le da.  \~
    if (!ok(BCryptGenerateSymmetricKey(static_cast<BCRYPT_ALG_HANDLE>(alg), &k,
                                       nullptr, 0, const_cast<PUCHAR>(key),
                                       static_cast<ULONG>(key_len), 0)))
        return nullptr;

    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    State *s = static_cast<State *>(util::host_alloc(sizeof(State)));
    if (s == nullptr) {
        BCryptDestroyKey(k);
        return nullptr;
    }
    s->kind = kind;
    s->key = k;
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
    hkdf_ = open_alg(kHkdfAlgorithm, 0, nullptr, 0);

    // \~english The first one missing is named, so that the refusal says why.
    // \~spanish Se nombra el primero que falte, para que la negativa diga por que.  \~
    if (gcm_ == nullptr) missing_ = "AES-GCM";
    else if (ecb_ == nullptr) missing_ = "AES-ECB";
    else if (hmac256_ == nullptr) missing_ = "HMAC-SHA256";
    else if (hmac384_ == nullptr) missing_ = "HMAC-SHA384";
    else if (hkdf_ == nullptr) missing_ = "HKDF";
}

CngCrypto::~CngCrypto() {
    close_alg(gcm_);
    close_alg(ecb_);
    close_alg(hmac256_);
    close_alg(hmac384_);
    close_alg(hkdf_);
}

bool CngCrypto::ready() const noexcept {
    return missing_ == nullptr;
}

const char *CngCrypto::name() const noexcept {
    return "cng";
}

bool CngCrypto::supports(quic::Aead a) const noexcept {
    return ready() && a != quic::Aead::ChaCha20Poly1305;
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
    return new_state(State::Aead, gcm_, key, quic::key_size(a));
}

void *CngCrypto::prepare_hp(quic::Aead a, const uint8_t *key) noexcept {
    if (!supports(a)) return nullptr;
    return new_state(State::HpAes, ecb_, key, quic::key_size(a));
}

void CngCrypto::forget(void *state) noexcept {
    State *s = static_cast<State *>(state);
    if (s == nullptr) return;
    // \~english Destroying the key also wipes it.  \~spanish Destruir la clave tambien la borra.  \~
    BCryptDestroyKey(s->key);
    util::host_free(s);
}

bool CngCrypto::seal(void *aead, const uint8_t *nonce, const uint8_t *ad,
                     size_t ad_len, const uint8_t *in, size_t n,
                     uint8_t *out) noexcept {
    State *s = static_cast<State *>(aead);
    if (s == nullptr || s->kind != State::Aead) return false;
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
    if (s == nullptr || s->kind != State::Aead) return quic::OpenResult::Failed;
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
    if (s == nullptr || s->kind != State::HpAes) return false;

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

} // namespace http_vx
