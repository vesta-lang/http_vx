/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/qpack_encoder.h
 * @brief
 * \~english QPACK's encoder: field lines in, field sections and encoder instructions out, the decoder stream back (RFC 9204, 2.1).
 * \~spanish El codificador de QPACK: entran lineas de campo, salen secciones de campos e instrucciones del codificador, vuelve el flujo del descodificador (RFC 9204, 2.1).
 * \~
 *
 * \~english
 * QPACK puts "the burden of optional state tracking on the encoder" (2.1),
 * and this is where it is carried.  What the encoder must know, it tracks:
 *
 * - **Which entries each unacknowledged section references**, so none of
 *   them is evicted while the decoder may still need it (2.1.1).  An entry
 *   is evictable once its insert is acknowledged and no unacknowledged
 *   section references it; an insert that would need evicting one that is
 *   not is simply not made.
 * - **Which streams could be blocked** (2.1.2): an unacknowledged entry is
 *   referenced only by a stream that already could be, or while there is
 *   room under the peer's SETTINGS_QPACK_BLOCKED_STREAMS.
 * - **The Known Received Count** (2.1.4), from Section Acknowledgments and
 *   Insert Count Increments -- and every decoder instruction that could not
 *   have come from a conformant decoder is QPACK_DECODER_STREAM_ERROR (4.4).
 *
 * The memory this takes is bounded here and not by the peer (7.3): a
 * section keeps at most kRefsPerSection references and at most
 * kPendingSections sections wait for acknowledgment; past either, the
 * encoder writes literals.  That costs compression and never correctness.
 *
 * **What to insert is the caller's call**, line by line: insert when it
 * fits, never insert, or never index -- the last one also marks the line so
 * no intermediary indexes it either (7.1.3).  **When** it may write on the
 * encoder stream is also the caller's: each call says how many bytes the
 * stream's flow control has room for, and no instruction is written that
 * does not fit (2.1.3).
 *
 * \~spanish
 * QPACK pone "la carga del seguimiento de estado opcional en el codificador"
 * (2.1), y aqui es donde se lleva.  Lo que el codificador debe saber, lo sigue:
 *
 * - **Que entradas referencia cada seccion sin confirmar**, para que ninguna se
 *   desaloje mientras el descodificador pueda necesitarla aun (2.1.1).  Una
 *   entrada se puede desalojar cuando su insercion esta confirmada y ninguna
 *   seccion sin confirmar la referencia; una insercion que obligaria a desalojar
 *   una que no se puede simplemente no se hace.
 * - **Que flujos podrian quedar bloqueados** (2.1.2): una entrada sin confirmar
 *   solo la referencia un flujo que ya podia estarlo, o mientras quede sitio
 *   bajo el SETTINGS_QPACK_BLOCKED_STREAMS del otro.
 * - **El Known Received Count** (2.1.4), por los Section Acknowledgment y los
 *   Insert Count Increment -- y toda instruccion del descodificador que no pudo
 *   venir de un descodificador conforme es QPACK_DECODER_STREAM_ERROR (4.4).
 *
 * La memoria que esto ocupa la acota este extremo y no el otro (7.3): una
 * seccion guarda como mucho kRefsPerSection referencias y como mucho esperan
 * confirmacion kPendingSections secciones; pasado cualquiera de los dos, el
 * codificador escribe literales.  Eso cuesta compresion y nunca correccion.
 *
 * **Que insertar lo decide quien llama**, linea a linea: insertar si cabe, no
 * insertar nunca, o no indexar nunca -- esto ultimo ademas marca la linea para
 * que tampoco la indexe ningun intermediario (7.1.3).  **Cuando** se puede
 * escribir en el flujo del codificador tambien es de quien llama: cada llamada
 * dice cuantos bytes admite el control de flujo del flujo, y no se escribe
 * ninguna instruccion que no quepa (2.1.3).
 * \~
 */
#ifndef HTTP_VX_QPACK_ENCODER_H
#define HTTP_VX_QPACK_ENCODER_H

#include "http_vx/buffer.h"
#include "http_vx/qpack.h"
#include "http_vx/qpack_decoder.h"
#include "http_vx/qpack_table.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace qpack {

/**
 * @brief
 * \~english What may be done with a line.  \~spanish Lo que se puede hacer con una linea.
 * \~
 */
enum class Indexing : uint8_t {
    /// \~english Referenced if it is in a table, inserted if it fits.  \~spanish Referenciada si esta en una tabla, insertada si cabe.  \~
    Insert,
    /// \~english Referenced if it is in a table, never inserted.  \~spanish Referenciada si esta en una tabla, nunca insertada.  \~
    NoInsert,
    /// \~english A literal with the 'N' bit: never indexed here or on any later hop (7.1.3).
    /// \~spanish Un literal con la marca 'N': nunca indexada aqui ni en ningun salto posterior (7.1.3).  \~
    Never,
};

/**
 * @brief
 * \~english One field line to encode.  \~spanish Una linea de campo a codificar.
 * \~
 */
struct Line {
    const uint8_t *name = nullptr;
    size_t name_len = 0;
    const uint8_t *value = nullptr;
    size_t value_len = 0;
    Indexing indexing = Indexing::Insert;
};

/**
 * @brief
 * \~english This end's own limits.  \~spanish Los limites propios de este extremo.
 * \~
 */
struct EncoderConfig {
    /// \~english The most table this encoder uses, whatever the peer allows (3.2.3, 7.3).
    /// \~spanish La mayor tabla que usa este codificador, permita lo que permita el otro (3.2.3, 7.3).  \~
    uint64_t max_capacity = 4096;
};

/**
 * @brief
 * \~english One connection's QPACK encoder.  \~spanish El codificador de QPACK de una conexion.
 * \~
 */
class Encoder {
public:
    /// \~english References one section keeps; past it, literals.  \~spanish Referencias que guarda una seccion; pasado eso, literales.  \~
    static constexpr size_t kRefsPerSection = 16;
    /// \~english Sections waiting for acknowledgment; past it, literals.  \~spanish Secciones esperando confirmacion; pasado eso, literales.  \~
    static constexpr size_t kPendingSections = 128;

    Encoder() noexcept = default;
    ~Encoder();
    Encoder(const Encoder &) = delete;
    Encoder &operator=(const Encoder &) = delete;

    /// \~english Ready for a connection: no table until the peer's settings say so (3.2.3).
    /// \~spanish Listo para una conexion: sin tabla hasta que los parametros del otro lo digan (3.2.3).  \~
    bool reset(const EncoderConfig &cfg) noexcept;

    /**
     * @brief
     * \~english A client sending 0-RTT: the settings remembered from the connection the ticket came from (3.2.3).
     * \~spanish Un cliente que manda 0-RTT: los parametros recordados de la conexion de la que salio el ticket (3.2.3).
     * \~
     *
     * \~english
     * Used until the server's SETTINGS arrive, which must then repeat a
     * non-zero remembered capacity exactly.
     * \~spanish
     * Se usan hasta que lleguen los SETTINGS del servidor, que entonces deben
     * repetir exactamente una capacidad recordada distinta de cero.
     * \~
     */
    bool remember_peer_settings(uint64_t max_table_capacity, uint64_t blocked_streams) noexcept;

    /**
     * @brief
     * \~english The peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS (5); once.
     * \~spanish SETTINGS_QPACK_MAX_TABLE_CAPACITY y SETTINGS_QPACK_BLOCKED_STREAMS del otro (5); una vez.
     * \~
     *
     * \~english
     * A non-zero capacity starts the table: a Set Dynamic Table Capacity
     * goes into output().
     * \~spanish
     * Una capacidad distinta de cero arranca la tabla: un Set Dynamic Table
     * Capacity va a output().
     * \~
     */
    bool on_peer_settings(uint64_t max_table_capacity, uint64_t blocked_streams) noexcept;

    /**
     * @brief
     * \~english Encodes @p count lines for stream @p stream into @p out; encoder instructions, at most @p room bytes, into output().
     * \~spanish Codifica @p count lineas para el flujo @p stream en @p out; instrucciones del codificador, como mucho @p room bytes, en output().
     * \~
     *
     * @return \~english false only once the connection has failed  \~spanish falso solo cuando la conexion ha fallado  \~
     */
    bool encode(uint64_t stream, const Line *lines, size_t count, Buffer &out, size_t room) noexcept;

    /// \~english Takes decoder stream bytes, in order; false once the connection has failed.
    /// \~spanish Toma bytes del flujo del descodificador, en orden; falso cuando la conexion ha fallado.  \~
    bool on_decoder_stream(const uint8_t *p, size_t n) noexcept;

    /// \~english Encoder stream bytes waiting to go out.  \~spanish Bytes del flujo del codificador que esperan salir.  \~
    const uint8_t *output(size_t &n) const noexcept;
    void sent(size_t n) noexcept;

    bool failed() const noexcept { return failure_.code != 0; }
    const Failure &failure() const noexcept { return failure_; }
    const Table &table() const noexcept { return table_; }
    uint64_t known_received() const noexcept { return known_; }
    /// \~english Sections waiting for acknowledgment.  \~spanish Secciones esperando confirmacion.  \~
    size_t pending() const noexcept { return pending_count_; }
    /// \~english Streams that could be blocked now (2.1.2).  \~spanish Flujos que podrian estar bloqueados ahora (2.1.2).  \~
    size_t blocking_streams() const noexcept;

    void release() noexcept;

private:
    struct Section {
        uint64_t stream;
        uint64_t required;
        uint32_t ref_count;
        uint64_t refs[kRefsPerSection];
    };

    bool fail(uint64_t code, const char *why) noexcept;
    bool start_table() noexcept;
    bool is_blocking(uint64_t stream) const noexcept;
    bool evictable(uint64_t abs) const noexcept;
    bool can_insert(uint64_t cost) const noexcept;
    uint64_t find_exact(const Line &l) const noexcept;
    uint64_t find_name(const Line &l) const noexcept;
    bool insert(const Line &l, const StaticMatch &st, size_t &room) noexcept;
    bool reference(Section &s, uint64_t abs) noexcept;
    void drop_section(size_t i) noexcept;
    bool instruction(uint64_t value, unsigned prefix, uint8_t high) noexcept;
    size_t decoder_instruction(const uint8_t *p, size_t n) noexcept;

    EncoderConfig cfg_;
    Table table_;
    Failure failure_;
    Buffer out_;
    Buffer pending_in_;
    /// ~english A section's lines, before its prefix is known.  ~spanish Las lineas de una seccion, antes de saber su prefijo.  ~
    Buffer body_;
    /// \~english The peer's settings, and whether they came or are remembered.  \~spanish Los parametros del otro, y si llegaron o son recordados.  \~
    uint64_t peer_capacity_ = 0;
    uint64_t peer_blocked_ = 0;
    bool settings_ = false;
    bool remembered_ = false;

    uint64_t known_ = 0;
    /// \~english Unacknowledged references per entry, by absolute index modulo the ring.
    /// \~spanish Referencias sin confirmar por entrada, por indice absoluto modulo el anillo.  \~
    uint32_t *refcount_ = nullptr;
    size_t refcount_cap_ = 0;
    /// \~english Sections waiting for acknowledgment, oldest first.  \~spanish Secciones esperando confirmacion, la mas vieja primero.  \~
    Section *sections_ = nullptr;
    size_t pending_count_ = 0;
};

} // namespace qpack
} // namespace http_vx

#endif // HTTP_VX_QPACK_ENCODER_H
