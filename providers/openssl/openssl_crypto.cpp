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
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <climits>
#include <cstring>

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

bool OpensslCrypto::random(uint8_t *out, size_t n) noexcept {
    // \~english RAND_bytes takes an int; ask in pieces that fit.
    // \~spanish RAND_bytes toma un int; se pide en trozos que quepan.  \~
    while (n != 0) {
        const int take = n > 1u << 20 ? 1 << 20 : static_cast<int>(n);
        if (RAND_bytes(out, take) != 1) return false;
        out += take;
        n -= static_cast<size_t>(take);
    }
    return true;
}

bool OpensslCrypto::supports(quic::Aead a) const noexcept {
    // \~english libcrypto has all three, AEADs and header protection alike.
    // \~spanish libcrypto tiene los tres, AEAD y proteccion de cabecera por igual.  \~
    return aead_cipher(a) != nullptr;
}

bool OpensslCrypto::digest(quic::Hash h, const uint8_t *in, size_t n, uint8_t *out) noexcept {
    const EVP_MD *md = h == quic::Hash::Sha384 ? EVP_sha384() : EVP_sha256();
    // \~english EVP_Digest wants a non-null pointer even for nothing to hash.
    // \~spanish EVP_Digest quiere un puntero no nulo aunque no haya nada que resumir.  \~
    static const uint8_t kEmpty = 0;
    unsigned int len = 0;
    return EVP_Digest(n != 0 ? in : &kEmpty, n, out, &len, md, nullptr) == 1 &&
           len == quic::hash_size(h);
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

namespace {

/**
 * @brief
 * \~english A key-exchange or signing key: the EVP key, and what it is for.
 * \~spanish Una clave de intercambio o de firma: la clave EVP, y para que es.
 * \~
 */
struct Key {
    EVP_PKEY *pkey;
    bool signing;
    quic::Group group;
    quic::Scheme scheme;
};

Key *new_key(EVP_PKEY *pkey) noexcept {
    if (pkey == nullptr) return nullptr;
    const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed, util::AllocFill::All);
    Key *k = static_cast<Key *>(util::host_alloc(sizeof(Key)));
    if (k == nullptr) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    k->pkey = pkey;
    k->signing = false;
    k->group = quic::Group::X25519;
    k->scheme = quic::Scheme::EcdsaSecp256r1Sha256;
    return k;
}

/// \~english An EC P-256 key from its parts: the public point, and the private scalar if given.
/// \~spanish Una clave EC P-256 a partir de sus partes: el punto publico, y el escalar privado si se da.  \~
EVP_PKEY *p256_from(const uint8_t *priv, size_t priv_len, const uint8_t *pub) noexcept {
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    if (b == nullptr) return nullptr;
    BIGNUM *d = priv != nullptr ? BN_bin2bn(priv, static_cast<int>(priv_len), nullptr) : nullptr;
    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM *params = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    const bool built =
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, 65) == 1 &&
        (priv == nullptr || (d != nullptr && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d) == 1));
    if (built) params = OSSL_PARAM_BLD_to_param(b);
    if (params != nullptr) ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx != nullptr && EVP_PKEY_fromdata_init(ctx) == 1)
        EVP_PKEY_fromdata(ctx, &pkey, priv != nullptr ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_clear_free(d);
    OSSL_PARAM_BLD_free(b);
    return pkey;
}

/// \~english Whether @p pkey is an EC key on P-256.  \~spanish Si @p pkey es una clave EC sobre P-256.  \~
bool is_p256(EVP_PKEY *pkey) noexcept {
    char name[32] = {};
    size_t len = 0;
    return EVP_PKEY_is_a(pkey, "EC") == 1 &&
           EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof name, &len) == 1 &&
           std::strcmp(name, "prime256v1") == 0;
}

/**
 * @brief
 * \~english Whether @p pkey can make or check signatures of @p s.
 * \~spanish Si @p pkey puede hacer o comprobar firmas de @p s.
 * \~
 *
 * \~english
 * rsa_pss_rsae wants an rsaEncryption key -- "RSA", not "RSA-PSS" (RFC 8446,
 * 4.2.3).
 * \~spanish
 * rsa_pss_rsae quiere una clave rsaEncryption -- "RSA", no "RSA-PSS" (RFC
 * 8446, 4.2.3).
 * \~
 */
bool fits(EVP_PKEY *pkey, quic::Scheme s) noexcept {
    switch (s) {
    case quic::Scheme::EcdsaSecp256r1Sha256: return is_p256(pkey);
    case quic::Scheme::RsaPssRsaeSha256:     return EVP_PKEY_is_a(pkey, "RSA") == 1;
    }
    return false;
}

/**
 * @brief
 * \~english Sets up @p ctx for @p s: SHA-256, and for PSS the salt the length of the hash (RFC 8446, 4.2.3).
 * \~spanish Prepara @p ctx para @p s: SHA-256, y para PSS la sal de la longitud del resumen (RFC 8446, 4.2.3).
 * \~
 */
bool pss_if_needed(EVP_PKEY_CTX *pctx, quic::Scheme s) noexcept {
    if (s != quic::Scheme::RsaPssRsaeSha256) return true;
    return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
           EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1 &&
           EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) == 1;
}

} // namespace

bool OpensslCrypto::supports(quic::Group g) const noexcept {
    (void)g;
    return true;
}

void *OpensslCrypto::generate_key(quic::Group g, uint8_t *pub) noexcept {
    EVP_PKEY *pkey = g == quic::Group::X25519 ? EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519")
                                              : EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (pkey == nullptr) return nullptr;
    size_t len = quic::public_key_size(g);
    const bool ok = g == quic::Group::X25519
                        ? EVP_PKEY_get_raw_public_key(pkey, pub, &len) == 1 && len == 32
                        : EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, 65,
                                                          &len) == 1 &&
                              len == 65 && pub[0] == 4;
    if (!ok) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    Key *k = new_key(pkey);
    if (k != nullptr) k->group = g;
    return k;
}

void *OpensslCrypto::import_key(quic::Group g, const uint8_t *priv, size_t priv_len,
                                const uint8_t *pub) noexcept {
    EVP_PKEY *pkey = nullptr;
    if (g == quic::Group::X25519) {
        if (priv_len != 32) return nullptr;
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
        // \~english The public key given has to be the private key's: a mismatch is refused.
        // \~spanish La clave publica dada tiene que ser la de la privada: si no coincide, se rechaza.  \~
        uint8_t mine[32];
        size_t len = sizeof mine;
        if (pkey != nullptr &&
            (EVP_PKEY_get_raw_public_key(pkey, mine, &len) != 1 || std::memcmp(mine, pub, 32) != 0)) {
            EVP_PKEY_free(pkey);
            return nullptr;
        }
    } else {
        pkey = p256_from(priv, priv_len, pub);
        // \~english Built from parts, the pair is not checked: the public point has to be the scalar's.
        // \~spanish Construido a partir de partes, el par no se comprueba: el punto publico tiene que ser el del escalar.  \~
        EVP_PKEY_CTX *check = pkey != nullptr ? EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr) : nullptr;
        if (pkey != nullptr && (check == nullptr || EVP_PKEY_pairwise_check(check) != 1)) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
        EVP_PKEY_CTX_free(check);
    }
    Key *k = new_key(pkey);
    if (k != nullptr) k->group = g;
    return k;
}

quic::Agreed OpensslCrypto::agree(void *key, const uint8_t *peer, size_t peer_len, uint8_t *shared) noexcept {
    Key *k = static_cast<Key *>(key);
    if (k == nullptr || k->signing) return quic::Agreed::Failed;
    // \~english The size is the group's; P-256 comes uncompressed only (RFC 8446, 4.2.8.2).
    // \~spanish El tamano es el del grupo; P-256 llega solo sin comprimir (RFC 8446, 4.2.8.2).  \~
    if (peer_len != quic::public_key_size(k->group)) return quic::Agreed::BadPeerKey;
    if (k->group == quic::Group::Secp256r1 && peer[0] != 4) return quic::Agreed::BadPeerKey;

    EVP_PKEY *other = k->group == quic::Group::X25519
                          ? EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer, 32)
                          : p256_from(nullptr, 0, peer);
    if (other == nullptr) return quic::Agreed::BadPeerKey;

    quic::Agreed result = quic::Agreed::Failed;
    EVP_PKEY_CTX *check = EVP_PKEY_CTX_new_from_pkey(nullptr, other, nullptr);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, k->pkey, nullptr);
    size_t len = 32;
    uint8_t zero = 0;
    // \~english The point MUST be on the curve (4.2.8.2): checked, not assumed.
    // \~spanish El punto DEBE estar en la curva (4.2.8.2): se comprueba, no se supone.  \~
    if (k->group == quic::Group::Secp256r1 && (check == nullptr || EVP_PKEY_public_check(check) != 1)) {
        result = quic::Agreed::BadPeerKey;
    } else if (ctx != nullptr && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, other) == 1) {
        if (EVP_PKEY_derive(ctx, shared, &len) == 1 && len == 32) {
            // \~english An all-zero X25519 result MUST abort (7.4.2): OR-ed, no early exit.
            // \~spanish Un resultado de X25519 a ceros DEBE abortar (7.4.2): con OR, sin salida temprana.  \~
            for (size_t i = 0; i < 32; ++i) zero = static_cast<uint8_t>(zero | shared[i]);
            result = zero != 0 ? quic::Agreed::Ok : quic::Agreed::BadPeerKey;
        } else if (k->group == quic::Group::X25519) {
            // \~english Any 32 bytes are an X25519 input: a failure here is the all-zero result refused.
            // \~spanish Cualesquiera 32 bytes son una entrada de X25519: fallar aqui es el resultado a ceros rechazado.  \~
            result = quic::Agreed::BadPeerKey;
        }
    }
    EVP_PKEY_CTX_free(check);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(other);
    return result;
}

void *OpensslCrypto::signing_key(quic::Scheme s, const uint8_t *pkcs8, size_t len) noexcept {
    const unsigned char *p = pkcs8;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(len));
    if (pkey == nullptr) return nullptr;
    if (!fits(pkey, s)) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    Key *k = new_key(pkey);
    if (k != nullptr) {
        k->signing = true;
        k->scheme = s;
    }
    return k;
}

bool OpensslCrypto::sign(void *key, const uint8_t *msg, size_t n, uint8_t *sig, size_t room,
                         size_t &sig_len) noexcept {
    Key *k = static_cast<Key *>(key);
    if (k == nullptr || !k->signing) return false;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    size_t len = room;
    const bool ok = md != nullptr && EVP_DigestSignInit(md, &pctx, EVP_sha256(), nullptr, k->pkey) == 1 &&
                    pss_if_needed(pctx, k->scheme) && EVP_DigestSign(md, sig, &len, msg, n) == 1;
    EVP_MD_CTX_free(md);
    if (ok) sig_len = len;
    return ok;
}

quic::Verified OpensslCrypto::verify(quic::Scheme s, const uint8_t *cert, size_t cert_len, const uint8_t *msg,
                                     size_t n, const uint8_t *sig, size_t sig_len) noexcept {
    const unsigned char *p = cert;
    X509 *x = d2i_X509(nullptr, &p, static_cast<long>(cert_len));
    if (x == nullptr) return quic::Verified::WrongKey;
    EVP_PKEY *pkey = X509_get0_pubkey(x);
    quic::Verified result = quic::Verified::WrongKey;
    if (pkey != nullptr && fits(pkey, s)) {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pctx = nullptr;
        if (md == nullptr || EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), nullptr, pkey) != 1 ||
            !pss_if_needed(pctx, s)) {
            result = quic::Verified::Failed;
        } else {
            // \~english 1 verifies; anything else -- a wrong signature, a malformed one -- does not.
            // \~spanish 1 verifica; cualquier otra cosa -- una firma equivocada, una mal formada -- no.  \~
            result = EVP_DigestVerify(md, sig, sig_len, msg, n) == 1 ? quic::Verified::Ok : quic::Verified::Bad;
        }
        EVP_MD_CTX_free(md);
    }
    X509_free(x);
    return result;
}

void OpensslCrypto::forget_key(void *key) noexcept {
    Key *k = static_cast<Key *>(key);
    if (k == nullptr) return;
    // \~english Freeing an EVP key clears its private material.  \~spanish Liberar una clave EVP borra su material privado.  \~
    EVP_PKEY_free(k->pkey);
    util::host_free(k);
}

} // namespace http_vx
