/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file providers/openssl/openssl_crypto.cpp
 * @brief
 * \~english The QUIC primitives, run by OpenSSL 3's libcrypto.
 * \~spanish Las primitivas de QUIC, ejecutadas por la libcrypto de OpenSSL 3.
 * \~
 */

#include "openssl_crypto.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <climits>

namespace http_vx {

namespace {

/**
 * @brief
 * \~english What a prepared key is, whichever primitive it is for.
 * \~spanish Lo que es una clave preparada, sea para la primitiva que sea.
 * \~
 *
 * \~english
 * One shape for both kinds because `forget` takes either and has to know what
 * it holds.  An AEAD key keeps two contexts, one per direction: OpenSSL can
 * switch one context between sealing and opening, but a context that is
 * always in the same direction is one less thing to reason about, and the
 * memory is per connection, not per packet.
 * \~spanish
 * Una forma para las dos clases porque `forget` recibe cualquiera y tiene que
 * saber que contiene.  Una clave de AEAD guarda dos contextos, uno por sentido:
 * OpenSSL puede cambiar un contexto entre sellar y abrir, pero un contexto que
 * siempre va en el mismo sentido es una cosa menos en la que pensar, y la
 * memoria es por conexion, no por paquete.
 * \~
 */
struct State {
    enum Kind : uint8_t { Aead, HpAes, HpChaCha };

    Kind kind;
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
};

/// \~english The digest name OpenSSL knows @p h by.
/// \~spanish El nombre con el que OpenSSL conoce a @p h.  \~
const char *digest_name(quic::Hash h) noexcept {
    return h == quic::Hash::Sha384 ? "SHA384" : "SHA256";
}

/// \~english The AEAD cipher for @p a.  \~spanish El cifrado AEAD de @p a.  \~
const EVP_CIPHER *aead_cipher(quic::Aead a) noexcept {
    switch (a) {
    case quic::Aead::Aes128Gcm:        return EVP_aes_128_gcm();
    case quic::Aead::Aes256Gcm:        return EVP_aes_256_gcm();
    case quic::Aead::ChaCha20Poly1305: return EVP_chacha20_poly1305();
    }
    return nullptr;
}

/// \~english A context with @p cipher and @p key set, for one direction.
/// \~spanish Un contexto con @p cipher y @p key puestos, para un sentido.  \~
EVP_CIPHER_CTX *keyed(const EVP_CIPHER *cipher, const uint8_t *key,
                      int enc) noexcept {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return nullptr;
    if (EVP_CipherInit_ex(ctx, cipher, nullptr, key, nullptr, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

/// \~english A new State, from our allocator.  \~spanish Un State nuevo, de nuestro asignador.  \~
State *new_state(State::Kind kind) noexcept {
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                 util::AllocFill::All);
    State *s = static_cast<State *>(util::host_alloc(sizeof(State)));
    if (s == nullptr) return nullptr;
    s->kind = kind;
    s->enc = nullptr;
    s->dec = nullptr;
    return s;
}

/// \~english Frees @p s and what it holds.  \~spanish Libera @p s y lo que contiene.  \~
void free_state(State *s) noexcept {
    if (s == nullptr) return;
    // \~english Freeing a context also wipes its key schedule.
    // \~spanish Liberar un contexto tambien borra su agenda de claves.  \~
    EVP_CIPHER_CTX_free(s->enc);
    EVP_CIPHER_CTX_free(s->dec);
    util::host_free(s);
}

/**
 * @brief
 * \~english Runs OpenSSL's HKDF in one of its two halves.
 * \~spanish Ejecuta el HKDF de OpenSSL en una de sus dos mitades.
 * \~
 */
bool run_hkdf(EVP_KDF *kdf, int mode, quic::Hash h, const uint8_t *key,
              size_t key_len, const uint8_t *salt_or_info, size_t sl,
              uint8_t *out, size_t out_len) noexcept {
    /* \~english
     * OpenSSL wants a non-null pointer even for an empty octet string, and a
     * zero-length connection ID is legal.
     * \~spanish
     * OpenSSL quiere un puntero no nulo incluso para una cadena de bytes vacia,
     * y un identificador de conexion de longitud cero es legal.
     * \~ */
    static uint8_t kEmpty = 0;

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, const_cast<char *>(digest_name(h)), 0);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, key_len ? const_cast<uint8_t *>(key) : &kEmpty,
        key_len);
    params[3] = OSSL_PARAM_construct_octet_string(
        mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY ? OSSL_KDF_PARAM_SALT
                                               : OSSL_KDF_PARAM_INFO,
        sl ? const_cast<uint8_t *>(salt_or_info) : &kEmpty, sl);
    params[4] = OSSL_PARAM_construct_end();

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == nullptr) return false;
    const bool ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

} // namespace

OpensslCrypto::OpensslCrypto() noexcept
    : kdf_(EVP_KDF_fetch(nullptr, "HKDF", nullptr)) {}

OpensslCrypto::~OpensslCrypto() {
    EVP_KDF_free(static_cast<EVP_KDF *>(kdf_));
}

const char *OpensslCrypto::name() const noexcept {
    return "openssl";
}

bool OpensslCrypto::extract(quic::Hash h, const uint8_t *salt,
                            size_t salt_len, const uint8_t *ikm,
                            size_t ikm_len, uint8_t *prk) noexcept {
    if (kdf_ == nullptr) return false;
    return run_hkdf(static_cast<EVP_KDF *>(kdf_),
                    EVP_KDF_HKDF_MODE_EXTRACT_ONLY, h, ikm, ikm_len, salt,
                    salt_len, prk, quic::hash_size(h));
}

bool OpensslCrypto::expand(quic::Hash h, const uint8_t *prk, size_t prk_len,
                           const uint8_t *info, size_t info_len, uint8_t *out,
                           size_t out_len) noexcept {
    if (kdf_ == nullptr) return false;
    return run_hkdf(static_cast<EVP_KDF *>(kdf_), EVP_KDF_HKDF_MODE_EXPAND_ONLY,
                    h, prk, prk_len, info, info_len, out, out_len);
}

void *OpensslCrypto::prepare_aead(quic::Aead a, const uint8_t *key) noexcept {
    const EVP_CIPHER *cipher = aead_cipher(a);
    if (cipher == nullptr) return nullptr;

    State *s = new_state(State::Aead);
    if (s == nullptr) return nullptr;
    s->enc = keyed(cipher, key, 1);
    s->dec = keyed(cipher, key, 0);
    if (s->enc == nullptr || s->dec == nullptr) {
        free_state(s);
        return nullptr;
    }
    return s;
}

void *OpensslCrypto::prepare_hp(quic::Aead a, const uint8_t *key) noexcept {
    const bool chacha = a == quic::Aead::ChaCha20Poly1305;
    const EVP_CIPHER *cipher = chacha ? EVP_chacha20()
                             : a == quic::Aead::Aes256Gcm ? EVP_aes_256_ecb()
                                                          : EVP_aes_128_ecb();

    State *s = new_state(chacha ? State::HpChaCha : State::HpAes);
    if (s == nullptr) return nullptr;
    s->enc = keyed(cipher, key, 1);
    if (s->enc == nullptr) {
        free_state(s);
        return nullptr;
    }

    // \~english One block in, one block out: ECB with no padding.
    // \~spanish Un bloque entra, un bloque sale: ECB sin relleno.  \~
    if (!chacha) EVP_CIPHER_CTX_set_padding(s->enc, 0);
    return s;
}

void OpensslCrypto::forget(void *state) noexcept {
    free_state(static_cast<State *>(state));
}

bool OpensslCrypto::seal(void *aead, const uint8_t *nonce, const uint8_t *ad,
                         size_t ad_len, const uint8_t *in, size_t n,
                         uint8_t *out) noexcept {
    State *s = static_cast<State *>(aead);
    if (s == nullptr || s->kind != State::Aead) return false;
    if (n > INT_MAX || ad_len > INT_MAX) return false;

    EVP_CIPHER_CTX *x = s->enc;
    int l = 0;

    // \~english A new nonce on the key already set: no key schedule is redone.
    // \~spanish Un nonce nuevo sobre la clave ya puesta: no se rehace la agenda.  \~
    if (EVP_EncryptInit_ex(x, nullptr, nullptr, nullptr, nonce) != 1) return false;
    if (ad_len != 0 &&
        EVP_EncryptUpdate(x, nullptr, &l, ad, static_cast<int>(ad_len)) != 1)
        return false;

    int done = 0;
    if (n != 0) {
        if (EVP_EncryptUpdate(x, out, &done, in, static_cast<int>(n)) != 1)
            return false;
    }
    int tail = 0;
    if (EVP_EncryptFinal_ex(x, out + done, &tail) != 1) return false;
    if (static_cast<size_t>(done + tail) != n) return false;

    return EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG,
                               static_cast<int>(quic::kTagSize), out + n) == 1;
}

quic::OpenResult OpensslCrypto::open(void *aead, const uint8_t *nonce,
                                     const uint8_t *ad, size_t ad_len,
                                     const uint8_t *in, size_t n,
                                     uint8_t *out) noexcept {
    State *s = static_cast<State *>(aead);
    if (s == nullptr || s->kind != State::Aead) return quic::OpenResult::Failed;
    if (n > INT_MAX || ad_len > INT_MAX) return quic::OpenResult::Failed;

    // \~english Shorter than a tag: nothing to authenticate, so not genuine.
    // \~spanish Mas corto que una marca: nada que autenticar, asi que no es autentico.  \~
    if (n < quic::kTagSize) return quic::OpenResult::Forged;

    const size_t body = n - quic::kTagSize;

    /* \~english
     * The tag is copied out before decrypting.  Opening in place writes the
     * plaintext over the ciphertext, and although it stops short of the tag,
     * holding it separately means that is not something to rely on.
     * \~spanish
     * La marca se copia fuera antes de descifrar.  Abrir en su sitio escribe el
     * texto claro sobre el cifrado, y aunque se para antes de la marca, tenerla
     * aparte hace que eso no sea algo de lo que depender.
     * \~ */
    uint8_t tag[quic::kTagSize];
    util::vesta_memcpy(tag, in + body, quic::kTagSize);

    EVP_CIPHER_CTX *x = s->dec;
    int l = 0;
    if (EVP_DecryptInit_ex(x, nullptr, nullptr, nullptr, nonce) != 1)
        return quic::OpenResult::Failed;
    if (ad_len != 0 &&
        EVP_DecryptUpdate(x, nullptr, &l, ad, static_cast<int>(ad_len)) != 1)
        return quic::OpenResult::Failed;

    int done = 0;
    if (body != 0 &&
        EVP_DecryptUpdate(x, out, &done, in, static_cast<int>(body)) != 1)
        return quic::OpenResult::Failed;
    if (EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(quic::kTagSize), tag) != 1)
        return quic::OpenResult::Failed;

    // \~english Final is where the tag is checked; its failure is the packet's.
    // \~spanish Final es donde se comprueba la marca; su fallo es del paquete.  \~
    int tail = 0;
    if (EVP_DecryptFinal_ex(x, out + done, &tail) != 1)
        return quic::OpenResult::Forged;
    return quic::OpenResult::Ok;
}

bool OpensslCrypto::mask(void *hp, const uint8_t *sample,
                         uint8_t *out) noexcept {
    State *s = static_cast<State *>(hp);
    if (s == nullptr) return false;

    int l = 0;
    if (s->kind == State::HpAes) {
        uint8_t block[16];
        if (EVP_EncryptUpdate(s->enc, block, &l, sample, 16) != 1 || l != 16)
            return false;
        util::vesta_memcpy(out, block, quic::kMaskSize);
        return true;
    }

    if (s->kind == State::HpChaCha) {
        /* \~english
         * RFC 9001, 5.4.4: the counter is the sample's first four bytes,
         * little-endian, and the nonce its other twelve -- which is exactly
         * the sixteen-byte IV OpenSSL's ChaCha20 takes, so the sample goes in
         * as it is.  The mask is the keystream: five zeros, encrypted.
         * \~spanish
         * RFC 9001, 5.4.4: el contador son los cuatro primeros bytes de la
         * muestra, en orden inverso, y el nonce los otros doce -- que es
         * exactamente el IV de dieciseis bytes que toma el ChaCha20 de OpenSSL,
         * asi que la muestra entra tal cual.  La mascara es el flujo de clave:
         * cinco ceros, cifrados.
         * \~ */
        static const uint8_t kZeros[quic::kMaskSize] = {};
        if (EVP_EncryptInit_ex(s->enc, nullptr, nullptr, nullptr, sample) != 1)
            return false;
        return EVP_EncryptUpdate(s->enc, out, &l, kZeros,
                                 static_cast<int>(quic::kMaskSize)) == 1 &&
               l == static_cast<int>(quic::kMaskSize);
    }
    return false;
}

} // namespace http_vx
