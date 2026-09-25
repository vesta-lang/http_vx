/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_vectors.cpp
 * @brief
 * \~english QUIC packet protection against the RFCs' own packets, with a real provider.
 * \~spanish La proteccion de paquetes de QUIC contra los paquetes de los propios RFC, con un proveedor de verdad.
 * \~
 *
 * \~english
 * Appendix A of RFC 9001 (version 1) and of RFC 9369 (version 2) print every
 * step of protecting four packets: the secrets, the keys, the sample, the mask
 * and the final bytes.  They are what every QUIC implementation was checked
 * against, so a packet that comes out one byte different from them is a
 * packet no other implementation can open.
 *
 * Each packet is checked in both directions.  Sealed here, it has to come out
 * as the RFC prints it -- every byte of the 1200, not only the header -- and
 * the RFC's bytes, opened here, have to give back the plaintext.  A server
 * spends its life on the second direction, which is why it is not left to be
 * inferred from the first.
 *
 * This test needs a provider, and is only built when one is: `test_quic_protection`
 * is what checks the QUIC logic on a machine without one.
 *
 * \~spanish
 * El apendice A del RFC 9001 (version 1) y del RFC 9369 (version 2) imprimen
 * cada paso de proteger cuatro paquetes: los secretos, las claves, la muestra,
 * la mascara y los bytes finales.  Son contra lo que se comprobaron todas las
 * implementaciones de QUIC, asi que un paquete que sale un byte distinto de
 * ellos es un paquete que ninguna otra implementacion puede abrir.
 *
 * Cada paquete se comprueba en los dos sentidos.  Sellado aqui, tiene que salir
 * como lo imprime el RFC -- cada byte de los 1200, no solo la cabecera --, y los
 * bytes del RFC, abiertos aqui, tienen que devolver el texto claro.  Un servidor
 * se pasa la vida en el segundo sentido, y por eso no se deja deducir del
 * primero.
 *
 * Esta prueba necesita un proveedor, y solo se construye cuando lo hay:
 * `test_quic_protection` es lo que comprueba la logica de QUIC en una maquina
 * sin el.
 * \~
 */

#include "http_vx/quic_packet.h"
#include "http_vx/quic_protection.h"

#include "openssl_crypto.h"

#include <cstdio>
#include <cstring>

namespace {

using namespace http_vx::quic;

int failures = 0;

/// \~english Which version is being checked, for the messages.
/// \~spanish Que version se esta comprobando, para los mensajes.  \~
const char *current = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

/// \~english Turns hex text into bytes.  \~spanish Convierte texto hexadecimal en bytes.  \~
size_t from_hex(const char *hex, uint8_t *out, size_t room) {
    size_t n = 0;
    while (hex[0] != '\0' && hex[1] != '\0' && n < room) {
        unsigned v = 0;
        std::sscanf(hex, "%2x", &v);
        out[n++] = static_cast<uint8_t>(v);
        hex += 2;
    }
    return n;
}

/// \~english Whether the @p n bytes at @p p are exactly @p hex.
/// \~spanish Si los @p n bytes de @p p son exactamente @p hex.  \~
bool same_as(const uint8_t *p, size_t n, const char *hex) {
    uint8_t want[1300];
    return from_hex(hex, want, sizeof want) == n && std::memcmp(p, want, n) == 0;
}

/// \~english The client's first DCID, the same in every example.
/// \~spanish El primer DCID del cliente, el mismo en todos los ejemplos.  \~
const uint8_t kDcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

/// \~english The CRYPTO frame the client's Initial carries (both versions).
/// \~spanish La trama CRYPTO que lleva el Initial del cliente (las dos versiones).  \~
const char kClientFrame[] =
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c000004130113"
    "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a"
    "0008000600" "1d00170018001000070005"
    "04616c706e0005000501000000000033" "00260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce1" "5d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408" "050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff050480" "00ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806" "048000ffff";

/// \~english The server's Initial payload: an ACK and a CRYPTO frame (both versions).
/// \~spanish La carga del Initial del servidor: un ACK y una trama CRYPTO (las dos versiones).  \~
const char kServerPayload[] =
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304";

/// \~english The ChaCha20 example's secret (both versions).
/// \~spanish El secreto del ejemplo de ChaCha20 (las dos versiones).  \~
const char kChaChaSecret[] =
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";

/**
 * @brief
 * \~english Everything one version's appendix prints.
 * \~spanish Todo lo que imprime el apendice de una version.
 * \~
 */
struct Vectors {
    const char *name;
    uint32_t version;
    const char *client_secret;
    const char *server_secret;
    const char *client_key;
    const char *client_iv;
    const char *client_hp;
    const char *server_key;
    const char *server_iv;
    const char *server_hp;
    const char *client_header;
    const char *client_packet;
    const char *server_header;
    const char *server_packet;
    const char *retry;
    const char *chacha_key;
    const char *chacha_iv;
    const char *chacha_hp;
    const char *chacha_ku;
    const char *chacha_packet;
};

const Vectors kVersion1Vectors = {
    "v1",
    kVersion1,
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    "1f369613dd76d5467730efcbe3b1a22d",
    "fa044b2f42a3fd3b46fb255c",
    "9f50449e04a0e810283a1e9933adedd2",
    "cf3a5331653c364c88f0f379b6067e37",
    "0ac1493ca1905853b0bba03e",
    "c206b8d9b9f0f37644430b490eeaa314",
    "c300000001088394c8f03e5157080000449e00000002",
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934",
    "c1000000010008f067a5502a4262b50040750001",
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee",
    "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f"
    "0f2496ba",
    "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
    "e0459b3474bdd0e44a41c144",
    "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
    "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
    "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
};

const Vectors kVersion2Vectors = {
    "v2",
    kVersion2,
    "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b",
    "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1",
    "8b1a0bc121284290a29e0971b5cd045d",
    "91f73e2351d8fa91660e909f",
    "45b95e15235d6f45a6b19cbcb0294ba9",
    "82db637861d55e1d011f19ea71d5d2a7",
    "dd13c276499c0249d3310652",
    "edf6d05c83121201b436e16877593c3a",
    "d36b3343cf088394c8f03e5157080000449e00000002",
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485"
    "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04"
    "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d"
    "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a"
    "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500"
    "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68"
    "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33"
    "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3"
    "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd"
    "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520"
    "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045"
    "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f"
    "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12"
    "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5"
    "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
    "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b"
    "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7"
    "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9"
    "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91"
    "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd"
    "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db"
    "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18"
    "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15"
    "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc"
    "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61"
    "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710"
    "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b"
    "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e"
    "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce"
    "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
    "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1"
    "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd"
    "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3"
    "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89"
    "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53"
    "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19"
    "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b"
    "a18b2faa745b6fe189cf772a9f84cbfc",
    "d16b3343cf0008f067a5502a4262b50040750001",
    "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698"
    "baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17"
    "f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2"
    "c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8"
    "4bed8521e2e140",
    "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d9555436"
    "65dcc7b6",
    "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2",
    "a6b5bc6ab7dafce30ffff5dd",
    "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2",
    "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88",
    "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba",
};

/// \~english The secrets and keys: section A.1 of each appendix.
/// \~spanish Los secretos y las claves: la seccion A.1 de cada apendice.  \~
void test_keys(Crypto &c, const Vectors &v) {
    uint8_t client[32];
    uint8_t server[32];
    check(initial_secrets(c, v.version, kDcid, sizeof kDcid, client, server),
          "the initial secrets could not be derived");
    check(same_as(client, 32, v.client_secret), "the client initial secret is not the RFC's");
    check(same_as(server, 32, v.server_secret), "the server initial secret is not the RFC's");

    KeyMaterial m;
    check(derive_key_material(c, v.version, Aead::Aes128Gcm, client, 32, m),
          "the client keys could not be derived");
    check(same_as(m.key, 16, v.client_key), "the client key is not the RFC's");
    check(same_as(m.iv, 12, v.client_iv), "the client iv is not the RFC's");
    check(same_as(m.hp, 16, v.client_hp), "the client hp key is not the RFC's");

    check(derive_key_material(c, v.version, Aead::Aes128Gcm, server, 32, m),
          "the server keys could not be derived");
    check(same_as(m.key, 16, v.server_key), "the server key is not the RFC's");
    check(same_as(m.iv, 12, v.server_iv), "the server iv is not the RFC's");
    check(same_as(m.hp, 16, v.server_hp), "the server hp key is not the RFC's");

    check(!derive_key_material(c, v.version, Aead::Aes256Gcm, client, 32, m),
          "a SHA-256 secret was expanded as if it were a SHA-384 one");
}

/**
 * @brief
 * \~english Sealed here, a packet has to be the RFC's; the RFC's, opened here, the plaintext.
 * \~spanish Sellado aqui, un paquete tiene que ser el del RFC; el del RFC, abierto aqui, el texto claro.
 * \~
 *
 * @param from_server \~english who seals it  \~spanish quien lo sella  \~
 */
void check_packet(Crypto &c, const Vectors &v, bool from_server,
                  const char *header_hex, const char *payload_hex,
                  size_t payload_len, const char *packet_hex, uint64_t pn,
                  const char *what) {
    char msg[160];
    uint8_t plain[1300] = {};
    const size_t head = from_hex(header_hex, plain, sizeof plain);
    from_hex(payload_hex, plain + head, sizeof plain - head);
    const size_t pn_len = static_cast<size_t>(plain[0] & 0x03) + 1;
    const size_t pn_off = head - pn_len;
    const size_t total = head + payload_len + kTagSize;

    PacketKeys cr, cw, sr, sw;
    check(make_initial_keys(c, v.version, kDcid, sizeof kDcid, false, cr, cw) &&
              make_initial_keys(c, v.version, kDcid, sizeof kDcid, true, sr, sw),
          "the initial keys could not be made");
    PacketKeys &seal = from_server ? sw : cw;
    PacketKeys &open = from_server ? cr : sr;

    uint8_t p[1300];
    std::memcpy(p, plain, sizeof p);
    const Protect pr = protect_packet(c, seal, p, pn_off, pn_len, pn, payload_len);
    std::snprintf(msg, sizeof msg, "the %s could not be protected", what);
    check(pr == Protect::Ok, msg);
    std::snprintf(msg, sizeof msg, "the %s sealed here is not the RFC's, byte for byte", what);
    check(same_as(p, total, packet_hex), msg);

    uint8_t q[1300];
    from_hex(packet_hex, q, sizeof q);
    PacketHeader h;
    std::snprintf(msg, sizeof msg, "the RFC's %s does not parse", what);
    check(parse_packet(q, total, HeaderContext{}, h) == HeaderError::None && h.size == total, msg);

    // \~english The receiver's own copy, kept to try tampering on.
    // \~spanish La copia de quien recibe, guardada para probar a manipularla.  \~
    uint8_t original[1300];
    std::memcpy(original, q, sizeof q);

    Unprotected u;
    const Unprotect ur = unprotect_packet(c, open, q, h, 0, u);
    std::snprintf(msg, sizeof msg, "the RFC's %s does not open: %s", what, unprotect_name(ur));
    check(ur == Unprotect::Ok, msg);
    std::snprintf(msg, sizeof msg, "the RFC's %s opened to another packet number", what);
    check(u.pn == pn && u.pn_len == pn_len, msg);
    std::snprintf(msg, sizeof msg, "the RFC's %s opened to another plaintext", what);
    check(u.payload.off == head && u.payload.len == payload_len &&
              std::memcmp(q + u.payload.off, plain + head, payload_len) == 0,
          msg);

    /* \~english
     * One bit flipped in the ciphertext, and one in the header, which nothing
     * masks: both have to be caught, the second one only by the associated
     * data.
     * \~spanish
     * Un bit cambiado en el texto cifrado, y uno en la cabecera, que no
     * enmascara nada: los dos tienen que cogerse, el segundo solo por los datos
     * asociados.
     * \~ */
    std::memcpy(q, original, sizeof q);
    q[total - 40] ^= 0x01;
    std::snprintf(msg, sizeof msg, "a bit flipped in the %s's payload went unnoticed", what);
    check(unprotect_packet(c, open, q, h, 0, u) == Unprotect::Forged, msg);

    std::memcpy(q, original, sizeof q);
    q[7] ^= 0x01;
    std::snprintf(msg, sizeof msg, "a bit flipped in the %s's header went unnoticed", what);
    check(unprotect_packet(c, open, q, h, 0, u) == Unprotect::Forged, msg);

    forget_keys(c, cr);
    forget_keys(c, cw);
    forget_keys(c, sr);
    forget_keys(c, sw);
}

/// \~english A.4: the Retry's integrity tag.  \~spanish A.4: la marca de integridad del Retry.  \~
void test_retry(Crypto &c, const Vectors &v) {
    uint8_t r[64];
    const size_t n = from_hex(v.retry, r, sizeof r);
    uint8_t scratch[128];
    uint8_t tag[kTagSize];
    check(retry_tag(c, v.version, kDcid, sizeof kDcid, r, n - kTagSize, scratch,
                    sizeof scratch, tag),
          "the Retry tag could not be computed");
    check(std::memcmp(tag, r + n - kTagSize, kTagSize) == 0, "the Retry tag is not the RFC's");

    check(!retry_tag(c, v.version, kDcid, sizeof kDcid, r, n - kTagSize, scratch, 20, tag),
          "a Retry tag was computed into a scratch too small for it");
}

/// \~english A.5: ChaCha20-Poly1305 and a short header.
/// \~spanish A.5: ChaCha20-Poly1305 y una cabecera corta.  \~
void test_chacha(Crypto &c, const Vectors &v) {
    uint8_t secret[32];
    from_hex(kChaChaSecret, secret, sizeof secret);

    KeyMaterial m;
    check(derive_key_material(c, v.version, Aead::ChaCha20Poly1305, secret, 32, m),
          "the ChaCha20 keys could not be derived");
    check(same_as(m.key, 32, v.chacha_key), "the ChaCha20 key is not the RFC's");
    check(same_as(m.iv, 12, v.chacha_iv), "the ChaCha20 iv is not the RFC's");
    check(same_as(m.hp, 32, v.chacha_hp), "the ChaCha20 hp key is not the RFC's");

    uint8_t ku[32];
    check(next_secret(c, v.version, Aead::ChaCha20Poly1305, secret, 32, ku) &&
              same_as(ku, 32, v.chacha_ku),
          "the secret after a key update is not the RFC's");

    PacketKeys k;
    check(prepare_keys(c, m, k), "the ChaCha20 keys could not be prepared");

    uint8_t p[21] = {0x42, 0, 0, 0, 0x01};
    check(protect_packet(c, k, p, 1, 3, 654360564, 1) == Protect::Ok,
          "the short packet could not be protected");
    check(same_as(p, sizeof p, v.chacha_packet), "the short packet is not the RFC's");

    HeaderContext ctx;
    ctx.short_dcid_len = 0;
    PacketHeader h;
    Unprotected u;
    from_hex(v.chacha_packet, p, sizeof p);
    check(parse_packet(p, sizeof p, ctx, h) == HeaderError::None &&
              unprotect_packet(c, k, p, h, 654360000, u) == Unprotect::Ok &&
              u.pn == 654360564 && u.payload.len == 1 && p[u.payload.off] == 0x01,
          "the RFC's short packet does not open to a PING");
    forget_keys(c, k);
}

void run(Crypto &c, const Vectors &v) {
    current = v.name;
    test_keys(c, v);
    check_packet(c, v, false, v.client_header, kClientFrame, 1162, v.client_packet, 2,
                 "client Initial");
    check_packet(c, v, true, v.server_header, kServerPayload, 99, v.server_packet, 1,
                 "server Initial");
    test_retry(c, v);
    test_chacha(c, v);
}

} // namespace

int main() {
    http_vx::OpensslCrypto c;
    if (!c.ready()) {
        std::fprintf(stderr, "FAIL: the openssl provider is not ready: no HKDF\n");
        return 1;
    }

    run(c, kVersion1Vectors);
    run(c, kVersion2Vectors);

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic vectors (%s): OK\n", c.name());
    return 0;
}
