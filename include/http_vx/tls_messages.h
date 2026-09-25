/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_messages.h
 * @brief
 * \~english TLS 1.3 handshake messages: reading them from bytes and writing them (RFC 8446, 4).
 * \~spanish Los mensajes del saludo de TLS 1.3: leerlos de bytes y escribirlos (RFC 8446, 4).
 * \~
 *
 * \~english
 * **Reading checks everything one message can show on its own**: the length
 * of every vector (decode_error), an extension in a message the table of 4.2
 * does not allow it in (illegal_parameter), two of the same type, a
 * pre_shared_key that is not last, a legacy compression other than null.  An
 * unknown extension is ignored where the RFC says so -- ClientHello,
 * NewSessionTicket -- and is unsupported_extension in the server's other
 * messages, since a client never asks for what it does not know.  What needs
 * two messages to judge -- the version chosen against the ones offered, a
 * suite that was never offered -- is the state machine's.
 *
 * **Nothing is copied**: a parsed message holds spans into the bytes it was
 * read from, which the caller keeps alive while it looks at them.
 *
 * **Writing** is a small writer that patches vector lengths when the vector
 * closes, and one helper per extension.  Composing a message from them is
 * how the tests rebuild RFC 8448's messages byte for byte, the extensions
 * this project does not send included.
 *
 * Where the RFC requires refusing but names no alert -- a duplicated
 * extension (4.2), two server names of one type (RFC 6066, 3), a server ALPN
 * with more than one name (RFC 7301, 3.1) -- the alert is illegal_parameter:
 * "a field in the handshake was incorrect or inconsistent with other fields"
 * (6.2).  That is this project's choice, not the RFC's.
 *
 * \~spanish
 * **Leer comprueba todo lo que un mensaje puede ensenar por si solo**: la
 * longitud de cada vector (decode_error), una extension en un mensaje en el que
 * la tabla de 4.2 no la permite (illegal_parameter), dos del mismo tipo, un
 * pre_shared_key que no va el ultimo, una compresion heredada que no es la nula.
 * Una extension desconocida se ignora donde el RFC lo dice -- ClientHello,
 * NewSessionTicket -- y es unsupported_extension en los demas mensajes del
 * servidor, porque un cliente nunca pide lo que no conoce.  Lo que necesita dos
 * mensajes para juzgarse -- la version elegida frente a las ofrecidas, un
 * algoritmo que nunca se ofrecio -- es de la maquina de estados.
 *
 * **No se copia nada**: un mensaje leido guarda tramos dentro de los bytes de los
 * que se leyo, que quien llama mantiene vivos mientras los mira.
 *
 * **Escribir** es un escritor pequeno que parchea las longitudes de los vectores
 * al cerrarlos, y un ayudante por extension.  Componer un mensaje con ellos es
 * como las pruebas reconstruyen byte a byte los mensajes del RFC 8448, incluidas
 * las extensiones que este proyecto no manda.
 *
 * Donde el RFC exige rechazar pero no nombra la alerta -- una extension
 * duplicada (4.2), dos nombres de servidor del mismo tipo (RFC 6066, 3), un ALPN
 * del servidor con mas de un nombre (RFC 7301, 3.1) -- la alerta es
 * illegal_parameter: "un campo del saludo era incorrecto o incoherente con otros"
 * (6.2).  Esa es una decision de este proyecto, no del RFC.
 * \~
 */
#ifndef HTTP_VX_TLS_MESSAGES_H
#define HTTP_VX_TLS_MESSAGES_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

/// \~english Handshake message types (4, B.3).  \~spanish Tipos de mensaje del saludo (4, B.3).  \~
enum class Handshake : uint8_t {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
};

/// \~english The alerts this code can end a handshake with (6.2).  \~spanish Las alertas con las que este codigo puede acabar un saludo (6.2).  \~
enum class Alert : uint8_t {
    None = 0,
    UnexpectedMessage = 10,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InternalError = 80,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
};

/// \~english A short name for @p a.  \~spanish Un nombre corto para @p a.  \~
const char *alert_name(Alert a) noexcept;

/// \~english Extension types this code knows (4.2; RFC 9001, 8.2).  \~spanish Tipos de extension que conoce este codigo (4.2; RFC 9001, 8.2).  \~
namespace ext {
constexpr uint16_t ServerName = 0;
constexpr uint16_t SupportedGroups = 10;
constexpr uint16_t SignatureAlgorithms = 13;
constexpr uint16_t Alpn = 16;
constexpr uint16_t PreSharedKey = 41;
constexpr uint16_t EarlyData = 42;
constexpr uint16_t SupportedVersions = 43;
constexpr uint16_t Cookie = 44;
constexpr uint16_t PskKeyExchangeModes = 45;
constexpr uint16_t CertificateAuthorities = 47;
constexpr uint16_t PostHandshakeAuth = 49;
constexpr uint16_t SignatureAlgorithmsCert = 50;
constexpr uint16_t KeyShare = 51;
constexpr uint16_t QuicTransportParameters = 0x39;
} // namespace ext

/// \~english TLS 1.3 itself (4.2.1).  \~spanish El propio TLS 1.3 (4.2.1).  \~
constexpr uint16_t kTls13 = 0x0304;
constexpr uint16_t kLegacyVersion = 0x0303;

/// \~english Cipher suites (B.4).  \~spanish Algoritmos de cifrado (B.4).  \~
namespace suite {
constexpr uint16_t Aes128GcmSha256 = 0x1301;
constexpr uint16_t Aes256GcmSha384 = 0x1302;
constexpr uint16_t ChaCha20Poly1305Sha256 = 0x1303;
} // namespace suite

/// \~english Named groups (4.2.7).  \~spanish Grupos con nombre (4.2.7).  \~
namespace group {
constexpr uint16_t Secp256r1 = 0x0017;
constexpr uint16_t Secp384r1 = 0x0018;
constexpr uint16_t X25519 = 0x001d;
} // namespace group

/// \~english Signature schemes (4.2.3).  \~spanish Esquemas de firma (4.2.3).  \~
namespace scheme {
constexpr uint16_t EcdsaSecp256r1Sha256 = 0x0403;
constexpr uint16_t EcdsaSecp384r1Sha384 = 0x0503;
constexpr uint16_t RsaPssRsaeSha256 = 0x0804;
constexpr uint16_t Ed25519 = 0x0807;
} // namespace scheme

/// \~english The ServerHello.random that makes it a HelloRetryRequest (4.1.3).
/// \~spanish El ServerHello.random que lo convierte en un HelloRetryRequest (4.1.3).  \~
extern const uint8_t kHelloRetryRandom[32];

/// \~english A stretch of the message's bytes.  \~spanish Un tramo de los bytes del mensaje.  \~
struct Span {
    uint32_t off = 0;
    uint32_t len = 0;
};

/**
 * @brief
 * \~english One handshake message found at the front of @p data: its type and body.
 * \~spanish Un mensaje del saludo encontrado al principio de @p data: su tipo y su cuerpo.
 * \~
 *
 * @return \~english the whole message's size (header included), or 0 if it is not all there yet
 *         \~spanish el tamano del mensaje entero (cabecera incluida), o 0 si aun no esta todo  \~
 */
size_t frame_message(const uint8_t *data, size_t n, Handshake &type, Span &body) noexcept;

/// \~english What a parse found: nothing wrong, or the alert to end the handshake with.
/// \~spanish Lo que encontro una lectura: nada mal, o la alerta con la que acabar el saludo.  \~
struct Parsed {
    Alert alert = Alert::None;
    bool ok() const noexcept { return alert == Alert::None; }
};

/**
 * \~english
 * The extensions a message carried, as spans of their data: present or
 * not.  Unknown ones are not kept; the ones that the table of 4.2 or the
 * rules above refuse never get here.
 * \~spanish
 * Las extensiones que llevaba un mensaje, como tramos de sus datos: presentes o
 * no.  Las desconocidas no se guardan; las que rechazan la tabla de 4.2 o las
 * reglas de arriba no llegan aqui.
 * \~
 */
struct Extensions {
    bool has_server_name = false;
    Span server_name;          ///< \~english the host name (CH), or nothing (EE)  \~spanish el nombre (CH), o nada (EE)  \~
    bool has_supported_groups = false;
    Span supported_groups;     ///< \~english the uint16 list  \~spanish la lista de uint16  \~
    bool has_signature_algorithms = false;
    Span signature_algorithms; ///< \~english the uint16 list  \~spanish la lista de uint16  \~
    bool has_alpn = false;
    Span alpn;                 ///< \~english the ProtocolName list, each with its length byte  \~spanish la lista de ProtocolName, cada uno con su byte de longitud  \~
    bool has_pre_shared_key = false;
    Span psk_identities;       ///< \~english CH: the identities  \~spanish CH: las identidades  \~
    Span psk_binders;          ///< \~english CH: the binders  \~spanish CH: los binders  \~
    uint32_t psk_binders_at = 0; ///< \~english CH: where the binders list starts, from the message's first byte  \~spanish CH: donde empieza la lista de binders, desde el primer byte del mensaje  \~
    uint16_t psk_selected = 0; ///< \~english SH: the identity chosen  \~spanish SH: la identidad elegida  \~
    bool has_early_data = false;
    uint32_t max_early_data = 0; ///< \~english NST only  \~spanish solo NST  \~
    bool has_supported_versions = false;
    Span versions;             ///< \~english CH: the uint16 list  \~spanish CH: la lista de uint16  \~
    uint16_t selected_version = 0; ///< \~english SH, HRR  \~spanish SH, HRR  \~
    bool has_cookie = false;
    Span cookie;
    bool has_psk_modes = false;
    Span psk_modes;
    bool has_key_share = false;
    Span key_shares;           ///< \~english CH: the KeyShareEntry list  \~spanish CH: la lista de KeyShareEntry  \~
    uint16_t share_group = 0;  ///< \~english SH, HRR  \~spanish SH, HRR  \~
    Span share_key;            ///< \~english SH  \~spanish SH  \~
    bool has_transport_parameters = false;
    Span transport_parameters;
};

struct ClientHello {
    Span random;
    Span session_id;
    Span cipher_suites;
    Extensions ext;
};

struct ServerHello {
    Span random;
    Span session_id;
    uint16_t cipher_suite = 0;
    /// \~english Its random is the special value: a HelloRetryRequest (4.1.3).
    /// \~spanish Su random es el valor especial: un HelloRetryRequest (4.1.3).  \~
    bool retry = false;
    Extensions ext;
};

struct EncryptedExtensions {
    Extensions ext;
};

struct CertificateMessage {
    Span context;
    Span entries; ///< \~english walked with next_certificate  \~spanish se recorre con next_certificate  \~
};

struct CertificateRequest {
    Span context;
    Extensions ext;
};

struct CertificateVerify {
    uint16_t scheme = 0;
    Span signature;
};

struct NewSessionTicket {
    uint32_t lifetime = 0;
    uint32_t age_add = 0;
    Span nonce;
    Span ticket;
    Extensions ext;
};

/* \~english
 * Each parser takes the message's BODY -- after the four-byte header -- and
 * reports spans from @p m, the start of the whole message, so that a span
 * can also be hashed as part of the transcript.  @p m + 4 is the body.
 * \~spanish
 * Cada lector toma el CUERPO del mensaje -- tras la cabecera de cuatro bytes -- y
 * da tramos desde @p m, el principio del mensaje entero, para que un tramo se
 * pueda resumir tambien como parte de la transcripcion.  @p m + 4 es el cuerpo.
 * \~ */
Parsed parse_client_hello(const uint8_t *m, size_t n, ClientHello &out) noexcept;
Parsed parse_server_hello(const uint8_t *m, size_t n, ServerHello &out) noexcept;
Parsed parse_encrypted_extensions(const uint8_t *m, size_t n, EncryptedExtensions &out) noexcept;
Parsed parse_certificate(const uint8_t *m, size_t n, CertificateMessage &out) noexcept;
Parsed parse_certificate_request(const uint8_t *m, size_t n, CertificateRequest &out) noexcept;
Parsed parse_certificate_verify(const uint8_t *m, size_t n, CertificateVerify &out) noexcept;
Parsed parse_new_session_ticket(const uint8_t *m, size_t n, NewSessionTicket &out) noexcept;

/**
 * @brief
 * \~english The next certificate of a parsed Certificate message; false when there are no more.
 * \~spanish El siguiente certificado de un mensaje Certificate leido; falso cuando no hay mas.
 * \~
 *
 * @param at \~english where to go on from; 0 the first time  \~spanish desde donde seguir; 0 la primera vez  \~
 */
bool next_certificate(const uint8_t *m, const CertificateMessage &c, uint32_t &at, Span &cert) noexcept;

/// \~english A big-endian uint16 at @p p.  \~spanish Un uint16 big-endian en @p p.  \~
inline uint16_t read16(const uint8_t *p) noexcept {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

/**
 * @brief
 * \~english Writes handshake messages into a buffer, patching each vector's length when it closes.
 * \~spanish Escribe mensajes del saludo en un buffer, parcheando la longitud de cada vector al cerrarlo.
 * \~
 *
 * \~english
 * Running out of room, or a vector longer than its length field can say,
 * makes the writer `failed()`: every later call does nothing, and the caller
 * checks once at the end instead of after every field.
 * \~spanish
 * Quedarse sin sitio, o un vector mas largo de lo que su campo de longitud puede
 * decir, deja al escritor en `failed()`: cada llamada posterior no hace nada, y
 * quien llama lo comprueba una vez al final en vez de tras cada campo.
 * \~
 */
class Writer {
public:
    Writer(uint8_t *buf, size_t room) noexcept : buf_(buf), room_(room) {}

    void u8(uint8_t v) noexcept;
    void u16(uint16_t v) noexcept;
    void u24(uint32_t v) noexcept;
    void u32(uint32_t v) noexcept;
    void bytes(const void *p, size_t n) noexcept;

    /// \~english Opens a vector whose length takes @p width bytes; returns its mark.
    /// \~spanish Abre un vector cuya longitud ocupa @p width bytes; devuelve su marca.  \~
    size_t open(size_t width) noexcept;
    /// \~english Closes the vector opened at @p mark, writing its length.
    /// \~spanish Cierra el vector abierto en @p mark, escribiendo su longitud.  \~
    void close(size_t mark, size_t width) noexcept;

    /// \~english A message: its type, and a mark for end_message.  \~spanish Un mensaje: su tipo, y una marca para end_message.  \~
    size_t begin_message(Handshake t) noexcept;
    void end_message(size_t mark) noexcept { close(mark, 3); }

    /// \~english An extension header: its type, and a mark for close(mark, 2).
    /// \~spanish La cabecera de una extension: su tipo, y una marca para close(mark, 2).  \~
    size_t begin_extension(uint16_t type) noexcept;

    size_t size() const noexcept { return len_; }
    bool failed() const noexcept { return failed_; }
    uint8_t *data() noexcept { return buf_; }

private:
    uint8_t *buf_;
    size_t room_;
    size_t len_ = 0;
    bool failed_ = false;
};

/* \~english
 * One helper per extension; each writes the whole extension, header
 * included, with the data as the RFC lays it out for that message.
 * \~spanish
 * Un ayudante por extension; cada uno escribe la extension entera, cabecera
 * incluida, con los datos como los dispone el RFC para ese mensaje.
 * \~ */
void write_server_name(Writer &w, const char *host, size_t len) noexcept;
void write_empty_extension(Writer &w, uint16_t type) noexcept;
void write_u16_list(Writer &w, uint16_t type, const uint16_t *v, size_t count) noexcept;
void write_supported_versions_client(Writer &w, const uint16_t *v, size_t count) noexcept;
void write_supported_versions_server(Writer &w, uint16_t version) noexcept;
void write_alpn(Writer &w, const char *const *names, size_t count) noexcept;
void write_psk_modes(Writer &w, const uint8_t *modes, size_t count) noexcept;
/// \~english Client key_share: parallel arrays of groups and public keys.
/// \~spanish key_share del cliente: arrays paralelos de grupos y claves publicas.  \~
void write_key_share_client(Writer &w, const uint16_t *groups, const uint8_t *const *keys,
                            const size_t *key_lens, size_t count) noexcept;
void write_key_share_server(Writer &w, uint16_t group, const uint8_t *key, size_t key_len) noexcept;
void write_key_share_retry(Writer &w, uint16_t group) noexcept;
void write_cookie(Writer &w, const uint8_t *cookie, size_t len) noexcept;
void write_transport_parameters(Writer &w, const uint8_t *tp, size_t len) noexcept;
void write_early_data_ticket(Writer &w, uint32_t max_early_data) noexcept;
void write_psk_server(Writer &w, uint16_t selected) noexcept;
/// \~english Any extension, its data as given: for what this code does not write itself.
/// \~spanish Cualquier extension, con sus datos tal cual: para lo que este codigo no escribe el mismo.  \~
void write_raw_extension(Writer &w, uint16_t type, const uint8_t *data, size_t len) noexcept;

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_MESSAGES_H
