/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/qpack_decoder.h
 * @brief
 * \~english QPACK's decoder: the encoder stream in, field sections out, the decoder stream back (RFC 9204, 2.2).
 * \~spanish El descodificador de QPACK: entra el flujo del codificador, salen secciones de campos, vuelve el flujo del descodificador (RFC 9204, 2.2).
 * \~
 *
 * \~english
 * **Field lines, not a message.**  What comes out is name, value and the
 * never-indexed bit, in order (2.2), handed to a sink; which pseudo-header
 * goes where, what a request may carry, is HTTP/3's and happens above.  That
 * is the one thing HPACK's decoder here does differently, and on purpose:
 * the message rules are shared by both protocols, the compression is not.
 *
 * **The encoder stream is a stream.**  Its bytes come in any pieces; an
 * instruction cut short waits, and one whose length is known is not read
 * again until all of it is here -- so a large insert arriving a byte at a
 * time costs its length, not its length squared.
 *
 * **A section may have to wait** (2.2.1): one that needs inserts not yet in
 * is Blocked, counted against the blocked streams this end announced, and
 * read again when the caller hands it back.  More blocked streams than
 * announced is QPACK_DECOMPRESSION_FAILED (2.1.2).
 *
 * **What goes back** -- Section Acknowledgment, Stream Cancellation, Insert
 * Count Increment (4.4) -- waits in output() for the decoder stream.
 *
 * **Every refusal says which rule.**  A connection error leaves its code
 * and a sentence in failure(); a section that fails alone says why in
 * section_why().
 *
 * \~spanish
 * **Lineas de campo, no un mensaje.**  Lo que sale es nombre, valor y la marca
 * de nunca indexar, en orden (2.2), entregado a un sumidero; que pseudo-cabecera
 * va donde, que puede llevar una peticion, es de HTTP/3 y pasa arriba.  Es lo
 * unico que el descodificador de HPACK de aqui hace distinto, y a proposito: las
 * reglas del mensaje las comparten los dos protocolos, la compresion no.
 *
 * **El flujo del codificador es un flujo.**  Sus bytes llegan en cualquier
 * pedazo; una instruccion cortada espera, y una cuya longitud ya se sabe no se
 * vuelve a leer hasta que este entera aqui -- asi una insercion grande que llega
 * byte a byte cuesta su longitud, no su longitud al cuadrado.
 *
 * **Una seccion puede tener que esperar** (2.2.1): una que necesita inserciones
 * que no han llegado queda Blocked, cuenta contra los flujos bloqueados que
 * anuncio este extremo, y se lee otra vez cuando quien llama la devuelve.  Mas
 * flujos bloqueados de los anunciados es QPACK_DECOMPRESSION_FAILED (2.1.2).
 *
 * **Lo que vuelve** -- Section Acknowledgment, Stream Cancellation, Insert Count
 * Increment (4.4) -- espera en output() al flujo del descodificador.
 *
 * **Cada rechazo dice que regla.**  Un error de conexion deja su codigo y una
 * frase en failure(); una seccion que falla sola dice por que en section_why().
 * \~
 */
#ifndef HTTP_VX_QPACK_DECODER_H
#define HTTP_VX_QPACK_DECODER_H

#include "http_vx/buffer.h"
#include "http_vx/qpack.h"
#include "http_vx/qpack_table.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace qpack {

/// \~english HTTP/3's own code for a failure of this end, not of the peer (RFC 9114, 8.1).
/// \~spanish El codigo de HTTP/3 para un fallo de este extremo, no del otro (RFC 9114, 8.1).  \~
constexpr uint64_t kInternalError = 0x0102;

/**
 * @brief
 * \~english Why the connection cannot go on: an HTTP/3 error code and the rule, in words.
 * \~spanish Por que la conexion no puede seguir: un codigo de error de HTTP/3 y la regla, en palabras.
 * \~
 */
struct Failure {
    uint64_t code = 0;
    const char *why = nullptr;
};

/**
 * @brief
 * \~english One field line as it came out; the spans point into the caller's buffer.
 * \~spanish Una linea de campo tal como salio; los tramos apuntan al buffer de quien llama.
 * \~
 */
struct FieldLine {
    Span name{0, 0};
    Span value{0, 0};
    /// \~english The 'N' bit: re-encoded, it stays a literal (4.5.4, 7.1.3).  \~spanish La marca 'N': recodificada, sigue siendo literal (4.5.4, 7.1.3).  \~
    bool never_indexed = false;
};

/**
 * @brief
 * \~english Where decoded field lines go, one at a time and in order.
 * \~spanish Adonde van las lineas de campo descodificadas, una a una y en orden.
 * \~
 */
class FieldSink {
public:
    virtual ~FieldSink() = default;
    /// \~english Takes a line; false refuses the section, and decoding stops.  \~spanish Toma una linea; falso rechaza la seccion, y se deja de descodificar.  \~
    virtual bool field(const Buffer &out, const FieldLine &line) noexcept = 0;
};

/**
 * @brief
 * \~english What this end announced, and the limits it keeps.  \~spanish Lo que anuncio este extremo, y los limites que guarda.
 * \~
 */
struct DecoderConfig {
    /// \~english SETTINGS_QPACK_MAX_TABLE_CAPACITY sent (3.2.3).  \~spanish SETTINGS_QPACK_MAX_TABLE_CAPACITY enviado (3.2.3).  \~
    uint64_t max_table_capacity = 0;
    /// \~english SETTINGS_QPACK_BLOCKED_STREAMS sent (2.1.2).  \~spanish SETTINGS_QPACK_BLOCKED_STREAMS enviado (2.1.2).  \~
    uint64_t blocked_streams = 0;
    /// \~english The longest name or value this end reads (7.4).  \~spanish El nombre o valor mas largo que lee este extremo (7.4).  \~
    size_t max_string = 64 * 1024;
    /// \~english The largest field section kept, counted as RFC 9114, 4.2.2 counts it.
    /// \~spanish La mayor seccion de campos que se guarda, contada como la cuenta el RFC 9114, 4.2.2.  \~
    uint64_t max_section = 64 * 1024;
};

/**
 * @brief
 * \~english How reading one field section went.  \~spanish Como fue leer una seccion de campos.
 * \~
 */
enum class Outcome : uint8_t {
    /// \~english Every line went to the sink.  \~spanish Todas las lineas fueron al sumidero.  \~
    Done,
    /// \~english It needs inserts not in yet: hand it back later (2.2.1).  \~spanish Necesita inserciones que no han llegado: devolverla despues (2.2.1).  \~
    Blocked,
    /**
     * \~english
     * Larger than max_section.  It was read to the end, lines past the limit
     * thrown away, and acknowledged: the answer can be a 431 on the same
     * stream (RFC 9114, 4.2.2), and the encoder's references are released.
     * \~spanish
     * Mayor que max_section.  Se leyo hasta el final, tirando las lineas pasado
     * el limite, y se confirmo: la respuesta puede ser un 431 en el mismo flujo
     * (RFC 9114, 4.2.2), y las referencias del codificador quedan liberadas.
     * \~
     */
    TooLarge,
    /// \~english A string or integer past what this end reads: a stream error (7.4); cancel the stream.
    /// \~spanish Una cadena o un entero mas alla de lo que lee este extremo: error de flujo (7.4); cancelar el flujo.  \~
    StreamFailed,
    /// \~english The sink refused a line; cancel the stream.  \~spanish El sumidero rechazo una linea; cancelar el flujo.  \~
    Rejected,
    /// \~english The connection cannot go on: failure() says why.  \~spanish La conexion no puede seguir: failure() dice por que.  \~
    Failed,
};

/**
 * @brief
 * \~english One connection's QPACK decoder.  \~spanish El descodificador de QPACK de una conexion.
 * \~
 */
class Decoder {
public:
    Decoder() noexcept = default;
    ~Decoder();
    Decoder(const Decoder &) = delete;
    Decoder &operator=(const Decoder &) = delete;

    /// \~english Ready for a connection, forgetting everything; false if the limits cannot be kept.
    /// \~spanish Listo para una conexion, olvidandolo todo; falso si los limites no se pueden guardar.  \~
    bool reset(const DecoderConfig &cfg) noexcept;

    /**
     * @brief
     * \~english Takes encoder stream bytes, in order; false once the connection has failed.
     * \~spanish Toma bytes del flujo del codificador, en orden; falso cuando la conexion ha fallado.
     * \~
     */
    bool on_encoder_stream(const uint8_t *p, size_t n) noexcept;

    /**
     * @brief
     * \~english Reads one whole encoded field section from stream @p stream; the strings land in @p out.
     * \~spanish Lee una seccion de campos codificada entera del flujo @p stream; las cadenas quedan en @p out.
     * \~
     */
    Outcome decode(uint64_t stream, const uint8_t *block, size_t n, Buffer &out, FieldSink &sink) noexcept;

    /**
     * @brief
     * \~english Tells the encoder about inserts no acknowledgment covered yet: one Insert Count Increment (4.4.3).
     * \~spanish Cuenta al codificador las inserciones que aun no cubrio ninguna confirmacion: un Insert Count Increment (4.4.3).
     * \~
     *
     * \~english
     * When is the decoder's choice (2.2.2.3).  Called once everything that
     * arrived has been handed over -- inserts and the sections they
     * unblocked --, a Section Acknowledgment often covers them and nothing
     * more is sent.  Called too seldom, the encoder waits to use what it
     * inserted.
     * \~spanish
     * Cuando es cosa del descodificador (2.2.2.3).  Llamado una vez entregado
     * todo lo que llego -- inserciones y las secciones que desbloquearon --, a
     * menudo un Section Acknowledgment ya las cubre y no se manda nada mas.
     * Llamado demasiado poco, el codificador espera para usar lo que inserto.
     * \~
     */
    bool flush() noexcept;

    /// \~english Streams no longer blocked, into @p ids; how many.  \~spanish Flujos que ya no estan bloqueados, en @p ids; cuantos.  \~
    size_t take_unblocked(uint64_t *ids, size_t cap) noexcept;

    /**
     * @brief
     * \~english Stream @p stream was reset or abandoned: its references are released (2.2.2.2).
     * \~spanish El flujo @p stream se reinicio o se abandono: sus referencias quedan liberadas (2.2.2.2).
     * \~
     */
    void cancel_stream(uint64_t stream) noexcept;

    /// \~english Decoder stream bytes waiting to go out.  \~spanish Bytes del flujo del descodificador que esperan salir.  \~
    const uint8_t *output(size_t &n) const noexcept;
    void sent(size_t n) noexcept;

    bool failed() const noexcept { return failure_.code != 0; }
    const Failure &failure() const noexcept { return failure_; }
    /// \~english Why the last section failed on its own; null otherwise.  \~spanish Por que fallo sola la ultima seccion; nulo si no.  \~
    const char *section_why() const noexcept { return section_why_; }
    const Table &table() const noexcept { return table_; }
    /// \~english The Known Received Count this end has told the encoder about (2.1.4).
    /// \~spanish El Known Received Count que este extremo ha contado al codificador (2.1.4).  \~
    uint64_t known_received() const noexcept { return known_; }
    size_t blocked() const noexcept { return blocked_count_; }
    /// \~english Times an encoder instruction was read, whole or cut short: what the stream cost.
    /// \~spanish Veces que se leyo una instruccion del codificador, entera o cortada: lo que costo el flujo.  \~
    uint64_t instruction_reads() const noexcept { return reads_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

private:
    struct Blocked {
        uint64_t stream;
        uint64_t required;
    };

    bool fail(uint64_t code, const char *why) noexcept;
    Outcome section_fail(Outcome o, const char *why) noexcept;
    /// \~english One encoder instruction at the front: its bytes, 0 if cut short, or ~0 on failure.
    /// \~spanish Una instruccion del codificador al principio: sus bytes, 0 si esta cortada, o ~0 si fallo.  \~
    size_t instruction(const uint8_t *p, size_t n) noexcept;
    bool dynamic_name(uint64_t relative, Span &name) noexcept;
    bool emit(uint64_t value, unsigned prefix, uint8_t high) noexcept;
    bool remember_blocked(uint64_t stream, uint64_t required) noexcept;
    void forget_blocked(uint64_t stream) noexcept;

    DecoderConfig cfg_;
    Table table_;
    Failure failure_;
    const char *section_why_ = nullptr;

    /* \~english Encoder stream bytes not read yet, and how many must be here before trying again.
     * \~spanish Bytes del flujo del codificador aun sin leer, y cuantos deben estar antes de volver a intentarlo.  \~ */
    Buffer pending_;
    size_t need_ = 0;
    uint64_t reads_ = 0;
    /// \~english Where an instruction's strings go while it is read.  \~spanish Adonde van las cadenas de una instruccion mientras se lee.  \~
    Buffer scratch_;
    /// \~english Lines past max_section, read and thrown away.  \~spanish Lineas pasado max_section, leidas y tiradas.  \~
    Buffer discard_;
    Buffer out_;

    uint64_t known_ = 0;
    Blocked *blocked_ = nullptr;
    size_t blocked_count_ = 0;
};

} // namespace qpack
} // namespace http_vx

#endif // HTTP_VX_QPACK_DECODER_H
