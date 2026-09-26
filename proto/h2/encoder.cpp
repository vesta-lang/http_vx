/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/encoder.cpp
 * @brief
 * \~english Writing header blocks.
 * \~spanish Escribir bloques de cabeceras.
 * \~
 */

#include "http_vx/h2_encoder.h"

#include "http_vx/h2_huffman.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h2 {
namespace hpack {

namespace {

/**
 * @brief
 * \~english The top bits that say what a representation is.
 * \~spanish Los bits de arriba que dicen que es una representacion.
 * \~
 *
 * \~english
 * HPACK tells the four representations apart by the top bits of the first byte,
 * and how many bits are left over for the number that follows is DIFFERENT for
 * each one.  So the two travel together here: a pattern written next to the
 * wrong prefix width produces a block that decodes into other fields, and there
 * is nothing about it that looks wrong at the call site.
 *
 * \~spanish
 * HPACK distingue las cuatro representaciones por los bits de arriba del primer
 * byte, y cuantos bits sobran para el numero que sigue es DISTINTO en cada una.
 * Asi que aqui los dos van juntos: un patron escrito al lado de la anchura de
 * prefijo equivocada produce un bloque que se descodifica en otras cabeceras, y
 * nada en el sitio de llamada tiene aspecto de estar mal.
 *
 * \~
 */
struct Form {
    uint8_t keep;
    uint8_t prefix_bits;
};

/// \~english `1xxxxxxx`: it is entirely in a table.
/// \~spanish `1xxxxxxx`: esta entera en una tabla.  \~
constexpr Form kIndexed{0x80, 7};

/// \~english `01xxxxxx`: spelled out, and remember it.
/// \~spanish `01xxxxxx`: escrita, y recuerdala.  \~
constexpr Form kIncremental{0x40, 6};

/// \~english `0000xxxx`: spelled out, do not remember it.
/// \~spanish `0000xxxx`: escrita, no la recuerdes.  \~
constexpr Form kWithoutIndexing{0x00, 4};

/**
 * \~english
 * `0001xxxx`: spelled out, and nobody remembers it -- not this end, not the
 * peer, and not any intermediary that re-encodes the message on the way.  The
 * last of those is what makes this different from the one above, and it is the
 * whole reason the representation exists.
 * \~spanish
 * `0001xxxx`: escrita, y no la recuerda nadie -- ni este extremo, ni el otro,
 * ni ningun intermediario que recodifique el mensaje por el camino.  Lo ultimo
 * es lo que hace que esta sea distinta de la de arriba, y es toda la razon de
 * que la representacion exista.
 * \~
 */
constexpr Form kNever{0x10, 4};

/**
 * \~english
 * `001xxxxx`: the table has changed size.  It is not a field at all -- it
 * carries no name and no value -- which is why it can only appear where a
 * field would start and must be the first thing in a block.
 * \~spanish
 * `001xxxxx`: la tabla ha cambiado de tamano.  No es una cabecera -- no lleva
 * nombre ni valor -- que es la razon de que solo pueda aparecer donde empezaria
 * una y tenga que ser lo primero de un bloque.
 * \~
 */
constexpr Form kSizeUpdate{0x20, 5};

/**
 * @brief
 * \~english The most a name or a value may be.
 * \~spanish Lo mas que puede medir un nombre o un valor.
 * \~
 *
 * \~english
 * The same ceiling the reading side puts on an integer, and the same one for
 * the same reason: a length this side cannot write is a length the other side
 * would refuse to read.  Checked here rather than trusted to the caller because
 * a caller that got it wrong would produce a block that is not a header block,
 * and the place that finds that out is the peer.
 *
 * \~spanish
 * El mismo techo que le pone a un entero el lado que lee, y el mismo por la
 * misma razon: una longitud que este lado no puede escribir es una longitud que
 * el otro se negaria a leer.  Se comprueba aqui y no se fia de quien llama
 * porque quien se equivocara produciria un bloque que no es un bloque de
 * cabeceras, y el sitio donde eso se averigua es el otro extremo.
 *
 * \~
 */
constexpr size_t kMaxPiece = static_cast<size_t>(kMaxInt);

/**
 * @brief
 * \~english Puts @p n bytes of @p p at the end of @p out.
 * \~spanish Pone los @p n bytes de @p p al final de @p out.
 * \~
 */
bool put_bytes(Buffer &out, const void *p, size_t n) noexcept {
    if (n == 0) return true;
    uint8_t *room = out.reserve(n);
    if (room == nullptr) return false;
    util::vesta_memcpy(room, p, n);
    out.commit(n);
    return true;
}

} // namespace

void Encoder::reset(uint32_t peer_table_size) noexcept {
    table_.reset(peer_table_size);
    pending_size_ = kNoSizeUpdate;
}

void Encoder::set_table_size(uint32_t n) noexcept {
    /* \~english
     * Never above what this end announced it would spend.  The peer's number
     * is a permission and not an instruction: it says what the peer will hold,
     * and holding it is this end's own memory to decide about.
     * \~spanish
     * Nunca por encima de lo que anuncio este extremo que gastaria.  El numero
     * del otro es un permiso y no una orden: dice lo que va a guardar el otro, y
     * guardarlo es memoria propia de este sobre la que decide el.
     * \~ */
    const uint32_t want = n < table_.announced() ? n : table_.announced();
    if (want == table_.max_size()) return;

    table_.set_max_size(want);
    pending_size_ = want;
}

WriteStatus Encoder::flush_size_update(Buffer &out) noexcept {
    if (pending_size_ == kNoSizeUpdate) return WriteStatus::Ok;

    const uint32_t n = pending_size_;

    /* \~english
     * Cleared BEFORE the write rather than after.  A write that fails is a
     * connection that is ending -- the block is half made and cannot be
     * unmade -- so leaving the flag set would only mean the next block, if
     * there somehow were one, announced a size that had already been
     * announced.
     * \~spanish
     * Se borra ANTES de escribir y no despues.  Una escritura que falla es una
     * conexion que se acaba -- el bloque esta a medio hacer y no se puede
     * deshacer -- asi que dejar la marca puesta solo querria decir que el bloque
     * siguiente, si de algun modo lo hubiera, anunciaria un tamano ya
     * anunciado.
     * \~ */
    pending_size_ = kNoSizeUpdate;
    return put_int(out, n, kSizeUpdate.prefix_bits, kSizeUpdate.keep);
}

WriteStatus Encoder::put_int(Buffer &out, uint64_t value, uint8_t prefix_bits,
                             uint8_t keep) noexcept {
    uint8_t tmp[kMaxIntBytes + 1];
    const size_t n = encode_int(tmp, value, prefix_bits, keep);
    return put_bytes(out, tmp, n) ? WriteStatus::Ok : WriteStatus::OutOfMemory;
}

WriteStatus Encoder::put_string(Buffer &out, const uint8_t *p,
                                size_t n) noexcept {
    if (n > kMaxPiece) return WriteStatus::TooLong;

    /* \~english
     * Coded only when coding it is shorter, which HPACK leaves up to the
     * sender.  It is asked and not assumed: a value the code was not measured
     * on -- a token, a hash, a base64 blob, which is most of what is long
     * enough to matter -- comes out LONGER coded, and sending it that way would
     * be paying to make the message bigger and paying again to have it decoded.
     *
     * \~spanish
     * Codificado solo cuando codificarlo es mas corto, cosa que HPACK deja en
     * manos de quien envia.  Se pregunta y no se supone: un valor sobre el que
     * no se midio el codigo -- un testigo, un resumen, un base64, que es casi
     * todo lo bastante largo como para importar -- sale MAS LARGO codificado, y
     * mandarlo asi seria pagar por agrandar el mensaje y pagar otra vez por que
     * lo descodifiquen.
     * \~ */
    const size_t coded = n == 0 ? 0 : huffman_encoded_length(p, n);
    const bool huffman = n != 0 && coded < n;

    const WriteStatus s = put_int(out, huffman ? coded : n, 7,
                                  huffman ? 0x80 : 0x00);
    if (s != WriteStatus::Ok) return s;

    if (!huffman) {
        return put_bytes(out, p, n) ? WriteStatus::Ok
                                    : WriteStatus::OutOfMemory;
    }

    uint8_t *room = out.reserve(coded);
    if (room == nullptr) return WriteStatus::OutOfMemory;

    const size_t wrote = huffman_encode(room, coded, p, n);
    if (wrote != coded) return WriteStatus::OutOfMemory;
    out.commit(wrote);
    return WriteStatus::Ok;
}

WriteStatus Encoder::write_status(Buffer &out, StatusCode status) noexcept {
    /* \~english
     * Three digits, always.  A status is written as text here even though it is
     * a number everywhere else in this project, because on the wire it IS text
     * -- and the seven that a server sends most of are in the static table, so
     * the common ones never reach the spelling below.
     *
     * \~spanish
     * Tres cifras, siempre.  Un estado se escribe aqui como texto aunque sea un
     * numero en todo el resto del proyecto, porque en el cable ES texto -- y los
     * siete que manda un servidor la mayoria de las veces estan en la tabla
     * estatica, asi que los corrientes no llegan a la escritura de abajo.
     * \~ */
    if (status < 100 || status > 999) return WriteStatus::TooLong;

    const WriteStatus su = flush_size_update(out);
    if (su != WriteStatus::Ok) return su;

    uint8_t text[3];
    text[0] = static_cast<uint8_t>('0' + status / 100);
    text[1] = static_cast<uint8_t>('0' + status / 10 % 10);
    text[2] = static_cast<uint8_t>('0' + status % 10);

    const uint64_t whole = static_index_of(Pseudo::Status, text, sizeof text);
    if (whole != 0)
        return put_int(out, whole, kIndexed.prefix_bits, kIndexed.keep);

    /* \~english
     * Not one of the seven, so the name comes from the table and the value is
     * spelled out.  It is NOT remembered: a status is three bytes, and the
     * entry that would hold it costs thirty-five.
     *
     * \~spanish
     * No es de los siete, asi que el nombre sale de la tabla y el valor se
     * escribe.  NO se recuerda: un estado son tres bytes, y la entrada que lo
     * guardaria cuesta treinta y cinco.
     * \~ */
    const uint64_t by_name = static_index_of(Pseudo::Status, nullptr, 0);
    const WriteStatus s = put_int(out, by_name, kWithoutIndexing.prefix_bits,
                                  kWithoutIndexing.keep);
    if (s != WriteStatus::Ok) return s;

    return put_string(out, text, sizeof text);
}

WriteStatus Encoder::write_field(Buffer &out, FieldId id, const uint8_t *value,
                                 size_t vlen, Indexing how) noexcept {
    if (id == FieldId::Unknown) return WriteStatus::TooLong;

    const char *name = field_name(id);
    const size_t nlen = field_name_len(id);
    if (name == nullptr || nlen == 0) return WriteStatus::TooLong;

    return write_pair(out, id, reinterpret_cast<const uint8_t *>(name), nlen,
                      value, vlen, how);
}

WriteStatus Encoder::write_field(Buffer &out, const uint8_t *name, size_t nlen,
                                 const uint8_t *value, size_t vlen,
                                 Indexing how) noexcept {
    if (nlen == 0) return WriteStatus::TooLong;

    /* \~english
     * The name is resolved here and not inside, so that a caller who spells
     * `cookie` out gets the same refusal as one who passes @c FieldId::Cookie.
     * A rule about which fields are secret that only applied to one of the two
     * ways of naming them would be a rule with a way round it, and the way
     * round is the one a caller takes when the identifier does not exist.
     *
     * \~spanish
     * El nombre se resuelve aqui y no dentro, para que quien escriba `cookie`
     * con letras reciba el mismo rechazo que quien pase @c FieldId::Cookie.  Una
     * regla sobre que cabeceras son secretas que solo valiera para una de las
     * dos formas de nombrarlas seria una regla con una puerta de atras, y la
     * puerta de atras es la que coge quien llama cuando el identificador no
     * existe.
     * \~ */
    return write_pair(out, field_id_of(reinterpret_cast<const char *>(name),
                                       nlen),
                      name, nlen, value, vlen, how);
}

WriteStatus Encoder::write_pair(Buffer &out, FieldId id, const uint8_t *name,
                                size_t nlen, const uint8_t *value, size_t vlen,
                                Indexing how) noexcept {
    if (nlen > kMaxPiece || vlen > kMaxPiece) return WriteStatus::TooLong;

    /* \~english
     * Refused, and not quietly turned into the safe thing.  Doing the safe
     * thing in silence would leave the call site saying `Incremental` about a
     * credential, and the next person to read it would believe it -- and would
     * copy it to a header where nothing stops it.
     *
     * \~spanish
     * Rechazado, y no convertido por lo bajo en lo seguro.  Hacer lo seguro en
     * silencio dejaria el sitio de llamada diciendo `Incremental` de una
     * credencial, y quien lo leyera despues se lo creeria -- y lo copiaria a una
     * cabecera donde no lo para nada.
     * \~ */
    if (how == Indexing::Incremental && field_is_secret(id))
        return WriteStatus::MustNotBeIndexed;

    /* \~english
     * After the refusals and before anything is written.  A size update is the
     * first thing in a block, and a field that is going to be refused has not
     * begun one.
     * \~spanish
     * Despues de los rechazos y antes de escribir nada.  Una actualizacion de
     * tamano es lo primero de un bloque, y una cabecera que va a ser rechazada
     * no ha empezado ninguno.
     * \~ */
    const WriteStatus su = flush_size_update(out);
    if (su != WriteStatus::Ok) return su;

    uint64_t index = 0;
    bool exact = false;

    /* \~english
     * A field the peer must never remember is not looked for in the table
     * either, and that is not the same check twice.  Finding it there would
     * mean it had been remembered before -- and writing the index would send
     * the secret as a number, which is exactly what a message-length oracle
     * reads.  The lookup is skipped rather than its result discarded, because a
     * lookup whose answer must be thrown away is a lookup somebody will
     * eventually use.
     *
     * \~spanish
     * Una cabecera que el otro extremo no puede recordar nunca tampoco se busca
     * en la tabla, y no es la misma comprobacion dos veces.  Encontrarla ahi
     * querria decir que se recordo antes -- y escribir el indice mandaria el
     * secreto como un numero, que es justo lo que lee un oraculo de longitud de
     * mensaje.  Se salta la busqueda en vez de tirar su resultado, porque una
     * busqueda cuya respuesta hay que tirar es una busqueda que alguien acabara
     * usando.
     * \~ */
    if (how != Indexing::Never) {
        /* \~english
         * The whole field in one byte, when a table already has it.  The static
         * one is asked first because its answer never changes: an index into it
         * means the same thing on a connection that started a moment ago and on
         * one that has been running for a day.
         * \~spanish
         * La cabecera entera en un byte, cuando ya la tiene una tabla.  Se le
         * pregunta antes a la estatica porque su respuesta no cambia nunca: un
         * indice suyo significa lo mismo en una conexion que empezo hace un
         * momento y en una que lleva un dia corriendo.
         * \~ */
        if (id != FieldId::Unknown) {
            const uint64_t whole = static_index_of(id, value, vlen);
            if (whole != 0)
                return put_int(out, whole, kIndexed.prefix_bits, kIndexed.keep);
            index = static_index_of(id);
        }

        const size_t back = table_.find(name, nlen, value, vlen, exact);
        if (back != table_.count()) {
            /* \~english
             * A dynamic index counts from after the static table, and it is
             * turned around here: zero from `find` is the most recent entry,
             * and on the wire the most recent is `kStaticEntries + 1`.
             * \~spanish
             * Un indice dinamico cuenta a partir del final de la tabla
             * estatica, y aqui se le da la vuelta: el cero de `find` es la
             * entrada mas reciente, y en el cable la mas reciente es
             * `kStaticEntries + 1`.
             * \~ */
            const uint64_t dyn = kStaticEntries + 1 + back;
            if (exact)
                return put_int(out, dyn, kIndexed.prefix_bits, kIndexed.keep);

            /* \~english
             * A name found in the dynamic table is used only if the static
             * table did not have one.  A static index says the same thing and
             * never stops being true, while a dynamic one is only as good as
             * the two ends' agreement about the table.
             * \~spanish
             * Un nombre encontrado en la tabla dinamica solo se usa si la
             * estatica no tenia ninguno.  Un indice estatico dice lo mismo y no
             * deja de ser cierto nunca, mientras que uno dinamico vale solo lo
             * que valga el acuerdo de los dos extremos sobre la tabla.
             * \~ */
            if (index == 0) index = dyn;
        }
    }

    /* \~english
     * Remembered BEFORE the bytes go out, although the number written above
     * talks about the table as it was before.  Those two are not in conflict:
     * what the number means is fixed by the order the PEER does things in --
     * it resolves the index and then adds -- and nothing about when this end
     * adds is visible on the wire.
     *
     * What is visible is the failure.  Written first and remembered after, a
     * table that could not grow would leave the peer remembering a field this
     * end does not, and from then on every index would name something else, on
     * a connection that keeps working.  This way round the memory is asked for
     * while nothing has been sent, so a refusal is still a refusal and the
     * caller can send the field without asking for it to be remembered.
     *
     * \~spanish
     * Se recuerda ANTES de que salgan los bytes, aunque el numero escrito arriba
     * hable de la tabla como estaba antes.  Las dos cosas no se contradicen: lo
     * que significa el numero lo fija el orden en que hace las cosas el OTRO
     * extremo -- resuelve el indice y luego anade -- y cuando anada este no se
     * ve en el cable.
     *
     * Lo que si se ve es el fallo.  Escrito primero y recordado despues, una
     * tabla que no pudiera crecer dejaria al otro extremo recordando una
     * cabecera que este no recuerda, y a partir de ahi todos los indices
     * nombrarian otra cosa, en una conexion que sigue funcionando.  De esta
     * forma la memoria se pide cuando todavia no se ha mandado nada, asi que un
     * rechazo sigue siendo un rechazo y quien llama puede mandar la cabecera sin
     * pedir que se recuerde.
     * \~ */
    if (how == Indexing::Incremental &&
        !table_.add(name, nlen, value, vlen, id, Pseudo::None))
        return WriteStatus::OutOfMemory;

    const Form form = how == Indexing::Incremental      ? kIncremental
                      : how == Indexing::Never          ? kNever
                                                        : kWithoutIndexing;

    /* \~english
     * The name is either an index or a string, and which it is is said by the
     * number itself: zero in the prefix means a string follows.  That is why
     * the number is written even when there is no index.
     * \~spanish
     * El nombre es un indice o una cadena, y cual de las dos lo dice el propio
     * numero: un cero en el prefijo quiere decir que detras va una cadena.  Por
     * eso el numero se escribe aunque no haya indice.
     * \~ */
    WriteStatus s = put_int(out, index, form.prefix_bits, form.keep);
    if (s != WriteStatus::Ok) return s;

    if (index == 0) {
        s = put_string(out, name, nlen);
        if (s != WriteStatus::Ok) return s;
    }

    return put_string(out, value, vlen);
}

} // namespace hpack
} // namespace h2
} // namespace http_vx
