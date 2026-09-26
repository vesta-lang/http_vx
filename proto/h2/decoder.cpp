/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/decoder.cpp
 * @brief
 * \~english Reading a header block, and refusing the ones that lie.
 * \~spanish Leer un bloque de cabeceras, y rechazar los que mienten.
 * \~
 */

#include "http_vx/h2_decoder.h"

#include "http_vx/chars.h"
#include "http_vx/h2_huffman.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {
namespace h2 {
namespace hpack {
namespace {

/**
 * @brief
 * \~english The five names that are not field names.
 * \~spanish Los cinco nombres que no son nombres de cabecera.
 * \~
 *
 * \~english
 * One table, and the colon is part of it.  A name that begins with a colon and
 * is not one of these is refused rather than passed along as an ordinary
 * field: the colon is reserved for the protocol, so a name nobody has defined
 * with one is a name from a version this end does not speak -- and treating it
 * as an ordinary field would be inventing a meaning for it.
 *
 * \~spanish
 * Una tabla, y los dos puntos son parte de ella.  Un nombre que empiece por dos
 * puntos y no sea uno de estos se rechaza en vez de pasarlo como cabecera
 * corriente: los dos puntos estan reservados para el protocolo, asi que un
 * nombre con ellos que nadie ha definido es un nombre de una version que este
 * extremo no habla -- y tratarlo como cabecera corriente seria inventarle un
 * significado.
 *
 * \~
 */
struct PseudoRow {
    const char *name;
    uint8_t len;
    Pseudo which;
};

template <size_t N>
constexpr PseudoRow prow(const char (&text)[N], Pseudo which) {
    return PseudoRow{text, static_cast<uint8_t>(N - 1), which};
}

constexpr PseudoRow kPseudo[] = {
    prow(":authority", Pseudo::Authority), prow(":method", Pseudo::Method),
    prow(":path", Pseudo::Path),           prow(":scheme", Pseudo::Scheme),
    prow(":status", Pseudo::Status),
};

constexpr size_t kPseudoCount = sizeof(kPseudo) / sizeof(kPseudo[0]);

Pseudo pseudo_of(const uint8_t *name, size_t len) noexcept {
    for (size_t i = 0; i < kPseudoCount; ++i) {
        if (kPseudo[i].len != len) continue;
        size_t j = 0;
        for (; j < len; ++j)
            if (name[j] != static_cast<uint8_t>(kPseudo[i].name[j])) break;
        if (j == len) return kPseudo[i].which;
    }
    return Pseudo::None;
}

/**
 * @brief
 * \~english Puts @p n bytes into @p out and says where they landed.
 * \~spanish Pone @p n bytes en @p out y dice donde cayeron.
 * \~
 *
 * \~english
 * The span is an offset from @c out.data, which growing does not move.  That
 * is the buffer's invariant and it is what lets a field decoded early still
 * name its bytes after a later one made the buffer bigger.
 *
 * \~spanish
 * El trozo es un desplazamiento desde @c out.data, que crecer no mueve.  Ese es
 * el invariante del buffer y es lo que permite que una cabecera descodificada
 * pronto siga nombrando sus bytes despues de que otra posterior haya hecho
 * crecer el buffer.
 *
 * \~
 */
bool put(Buffer &out, const void *p, size_t n, Span &span) noexcept {
    const size_t at = out.size();
    if (n != 0) {
        uint8_t *room = out.reserve(n);
        if (room == nullptr) return false;
        util::vesta_memcpy(room, p, n);
        out.commit(n);
    }
    span = Span{static_cast<uint32_t>(at), static_cast<uint32_t>(n)};
    return true;
}

} // namespace

void Decoder::reset(const Limits &limits) noexcept {
    limits_ = limits;
    table_.reset(limits.header_table_size);
    list_size_ = 0;
    why_ = nullptr;
}

ErrorCode Decoder::take_string(const uint8_t *p, size_t n, size_t &at,
                               Buffer &out, Span &span) noexcept {
    if (at >= n) return ErrorCode::CompressionError;

    const bool coded = (p[at] & 0x80) != 0;
    const IntResult len = decode_int(p + at, n - at, 7);
    if (len.status != Status::Ok) return ErrorCode::CompressionError;

    at += len.used;
    if (len.value > n - at) return ErrorCode::CompressionError;

    const size_t take = static_cast<size_t>(len.value);

    if (!coded) {
        if (!put(out, p + at, take, span)) return ErrorCode::InternalError;
        at += take;
        return ErrorCode::NoError;
    }

    /* \~english
     * Room for the most it can come to, asked for BEFORE it is decoded.  The
     * bound is small -- eight fifths -- and knowing it is what keeps this from
     * being a place where a sender decides how much memory is asked for.
     *
     * \~spanish
     * Sitio para lo mas que puede llegar a ser, pedido ANTES de descodificarlo.
     * La cota es pequena -- ocho quintos -- y conocerla es lo que impide que
     * esto sea un sitio donde quien envia decide cuanta memoria se pide.
     * \~ */
    const size_t most = huffman_max_decoded(take);
    const size_t start = out.size();

    uint8_t *room = out.reserve(most);
    if (room == nullptr) return ErrorCode::InternalError;

    const HuffmanResult r = huffman_decode(room, most, p + at, take);
    if (r.status != Status::Ok) return ErrorCode::CompressionError;

    out.commit(r.len);
    span = Span{static_cast<uint32_t>(start), static_cast<uint32_t>(r.len)};
    at += take;
    return ErrorCode::NoError;
}

ErrorCode Decoder::take_indexed_name(uint64_t index, Buffer &out,
                                     Reading &f) noexcept {
    if (index == 0) return ErrorCode::CompressionError;

    if (index <= kStaticEntries) {
        const StaticEntry *e = static_entry(index);
        if (!put(out, e->name, e->name_len, f.name))
            return ErrorCode::InternalError;
        f.id = e->id;
        f.pseudo = e->pseudo;
        return ErrorCode::NoError;
    }

    const size_t back = static_cast<size_t>(index - kStaticEntries - 1);
    const TableEntry *e = table_.at(back);

    /* \~english
     * An index past what is remembered.  It is a connection error and not a
     * bad request: the peer and this end disagree about what the table holds,
     * so every index after this one is a guess -- and the peer has no way of
     * being told which one went wrong.
     *
     * \~spanish
     * Un indice mas alla de lo recordado.  Es un error de conexion y no una
     * peticion mala: el otro extremo y este discrepan sobre lo que hay en la
     * tabla, asi que todos los indices de aqui en adelante son conjeturas -- y
     * al otro extremo no hay forma de decirle cual fue el que fallo.
     * \~ */
    if (e == nullptr) return ErrorCode::CompressionError;

    const size_t start = out.size();
    uint8_t *room = out.reserve(e->name_len);
    if (room == nullptr) return ErrorCode::InternalError;

    const size_t got = table_.copy_name(back, room, e->name_len);
    out.commit(got);
    f.name = Span{static_cast<uint32_t>(start), static_cast<uint32_t>(got)};
    f.id = e->id;
    f.pseudo = e->pseudo;
    return ErrorCode::NoError;
}

bool Decoder::names_something(uint64_t index) const noexcept {
    if (index == 0) return false;
    if (index <= kStaticEntries) return true;
    return table_.at(static_cast<size_t>(index - kStaticEntries - 1)) != nullptr;
}

ErrorCode Decoder::keep(const Buffer &out, const Reading &f,
                        Request &req) noexcept {
    (void)req;
    /* \~english
     * What it costs once it is written out, counted the specification's way.
     * This is the limit the bomb runs into: a thousand mentions of a remembered
     * field are a thousand bytes on the wire and a thousand times the field
     * here.
     *
     * \~spanish
     * Lo que cuesta una vez escrita, contado como dice la especificacion.  Este
     * es el limite con el que choca la bomba: mil menciones de una cabecera
     * recordada son mil bytes en el cable y mil veces la cabecera aqui.
     * \~ */
    list_size_ += static_cast<uint64_t>(f.name.len) + f.value.len + 32;
    if (list_size_ > limits_.max_header_list_size) {
        why_ = "a header list larger than SETTINGS_MAX_HEADER_LIST_SIZE (RFC "
               "9113, 6.5.2, 10.5.1)";
        return ErrorCode::EnhanceYourCalm;
    }

    /* \~english
     * What the line means for the message is judged where HTTP/3's is judged
     * too (request_builder.h): the rules are the same, and two copies of them
     * would sooner or later disagree.  A line that breaks one makes the
     * message malformed: a stream error, PROTOCOL_ERROR (RFC 9113, 8.1.1).
     * \~spanish
     * Lo que significa la linea para el mensaje se juzga donde se juzga tambien
     * la de HTTP/3 (request_builder.h): las reglas son las mismas, y dos copias
     * de ellas acabarian discrepando.  Una linea que rompe una deja el mensaje
     * mal formado: error de flujo, PROTOCOL_ERROR (RFC 9113, 8.1.1).
     * \~ */
    const char *bad = builder_.add(out.data(), f.name, f.value, f.id);
    if (bad != nullptr) {
        why_ = bad;
        return ErrorCode::ProtocolError;
    }
    return ErrorCode::NoError;
}

ErrorCode Decoder::decode(const uint8_t *block, size_t n, Buffer &out,
                          Request &req) noexcept {
    builder_.start(req, RequestBuilder::Options::http2());
    const ErrorCode e = read_block(block, n, out, req);
    if (e == ErrorCode::NoError) req.version = Version::Http2;
    return e;
}

ErrorCode Decoder::decode_trailers(const uint8_t *block, size_t n, Buffer &out,
                                   Request &req) noexcept {
    /* \~english
     * The same reading and the same table, since a trailer section is a field
     * block like any other (RFC 9113, 8.1) -- only the builder is told that
     * what comes is added to @p req and may not name a pseudo-header field.
     * \~spanish
     * La misma lectura y la misma tabla, porque una seccion de remolques es un
     * bloque de campos como cualquier otro (RFC 9113, 8.1) -- solo que al
     * constructor se le dice que lo que venga se anade a @p req y no puede
     * nombrar una pseudo-cabecera.
     * \~ */
    builder_.start_trailers(req);
    return read_block(block, n, out, req);
}

ErrorCode Decoder::read_block(const uint8_t *block, size_t n, Buffer &out,
                              Request &req) noexcept {
    why_ = nullptr;
    list_size_ = 0;

    const ErrorCode e = read_fields(block, n, out, req);

    /* \~english
     * The two answers that end the connection say why too, over whatever
     * reason an earlier field had left: once the table is lost, which field
     * broke a message rule no longer matters to anyone.
     * \~spanish
     * Las dos respuestas que acaban la conexion dicen por que tambien, por
     * encima del motivo que hubiera dejado una cabecera anterior: perdida la
     * tabla, que cabecera rompio una regla del mensaje ya no le importa a nadie.
     * \~ */
    if (e == ErrorCode::CompressionError)
        why_ = "a field block HPACK cannot decode (RFC 7541; RFC 9113, 4.3)";
    else if (e == ErrorCode::InternalError)
        why_ = "no memory to decode a field block, so the table is lost (RFC "
               "9113, 4.3)";
    return e;
}

ErrorCode Decoder::read_fields(const uint8_t *block, size_t n, Buffer &out,
                               Request &req) noexcept {
    /* \~english
     * The first message rule broken, if one has been.  From then on the
     * block is still read to its end -- every field, every insertion into the
     * table -- because the peer's encoder made those insertions in ITS table
     * and a decoder that stopped here would be a field short from now on
     * (RFC 9113, 4.3: "A receiver MUST terminate the connection ... if it does
     * not decompress a field block"; 10.5.1: "The field block MUST be
     * processed to ensure a consistent connection state").  What changes is
     * where the fields go: nowhere.  They are decoded into @c scratch_, which
     * is emptied field by field, so a refused block costs one field of memory
     * however long it is -- and an indexed field, which changes nothing in the
     * table, is only checked and not copied at all.
     *
     * \~spanish
     * La primera regla del mensaje rota, si se ha roto alguna.  Desde ahi el
     * bloque se sigue leyendo hasta el final -- cada cabecera, cada insercion
     * en la tabla -- porque el codificador del otro extremo hizo esas
     * inserciones en SU tabla y un descodificador que parara aqui iria una
     * cabecera por detras desde ahora (RFC 9113, 4.3: "A receiver MUST
     * terminate the connection ... if it does not decompress a field block";
     * 10.5.1: "The field block MUST be processed to ensure a consistent
     * connection state").  Lo que cambia es adonde van las cabeceras: a
     * ninguna parte.  Se descodifican en @c scratch_, que se vacia cabecera a
     * cabecera, asi que un bloque rechazado cuesta la memoria de una cabecera
     * por largo que sea -- y una cabecera indexada, que no cambia nada de la
     * tabla, solo se comprueba y no se copia.
     * \~ */
    ErrorCode refused = ErrorCode::NoError;

    /* \~english
     * A size update may only come at the front of a block.  Once a field has
     * been read, the table has changed underneath, and a limit arriving then
     * would evict things the encoder still believes are there.
     *
     * \~spanish
     * Un cambio de tamano solo puede ir al principio de un bloque.  Una vez
     * leida una cabecera la tabla ha cambiado por debajo, y un limite que
     * llegara entonces desalojaria cosas que el codificador todavia cree que
     * estan.
     * \~ */
    bool updates_still_allowed = true;

    size_t at = 0;
    while (at < n) {
        const bool discarding = refused != ErrorCode::NoError;
        Buffer &sink = discarding ? scratch_ : out;
        if (discarding) scratch_.clear();

        const uint8_t lead = block[at];

        if ((lead & 0x80) != 0) {
            // Indexada: nombre y valor, los dos de una tabla.
            const IntResult idx = decode_int(block + at, n - at, 7);
            if (idx.status != Status::Ok) return ErrorCode::CompressionError;
            at += idx.used;
            updates_still_allowed = false;

            /* \~english
             * Discarded, an indexed field changes nothing: it only has to name
             * something.  Copying it would let a refused block of one-byte
             * references cost a copy of the table per byte.
             * \~spanish
             * Descartada, una cabecera indexada no cambia nada: solo tiene que
             * nombrar algo.  Copiarla dejaria que un bloque rechazado de
             * referencias de un byte costara una copia de la tabla por byte.
             * \~ */
            if (discarding) {
                if (!names_something(idx.value))
                    return ErrorCode::CompressionError;
                continue;
            }

            Reading f{};
            const ErrorCode e = take_indexed_name(idx.value, out, f);
            if (e != ErrorCode::NoError) return e;

            if (idx.value <= kStaticEntries) {
                const StaticEntry *se = static_entry(idx.value);
                if (!put(out, se->value, se->value_len, f.value))
                    return ErrorCode::InternalError;
            } else {
                const size_t back =
                    static_cast<size_t>(idx.value - kStaticEntries - 1);
                const TableEntry *te = table_.at(back);
                if (te == nullptr) return ErrorCode::CompressionError;

                const size_t start = out.size();
                uint8_t *room = out.reserve(te->value_len);
                if (room == nullptr) return ErrorCode::InternalError;
                const size_t got = table_.copy_value(back, room, te->value_len);
                out.commit(got);
                f.value = Span{static_cast<uint32_t>(start),
                               static_cast<uint32_t>(got)};
            }

            refused = keep(out, f, req);
            continue;
        }

        if ((lead & 0x20) != 0 && (lead & 0x40) == 0) {
            // Cambio de tamano de la tabla.
            if (!updates_still_allowed) return ErrorCode::CompressionError;

            const IntResult size = decode_int(block + at, n - at, 5);
            if (size.status != Status::Ok) return ErrorCode::CompressionError;
            at += size.used;

            if (!table_.set_max_size(static_cast<uint32_t>(size.value)))
                return ErrorCode::CompressionError;
            continue;
        }

        /* \~english
         * Everything left is a literal, and the three kinds differ in two
         * things: how many bits of the first byte are the index, and whether
         * the field is remembered afterwards.
         *
         * \~spanish
         * Lo que queda son literales, y las tres clases se diferencian en dos
         * cosas: cuantos bits del primer byte son el indice, y si la cabecera
         * se recuerda despues.
         * \~ */
        const bool remember = (lead & 0x40) != 0;
        const uint8_t prefix = remember ? 6 : 4;

        const IntResult idx = decode_int(block + at, n - at, prefix);
        if (idx.status != Status::Ok) return ErrorCode::CompressionError;
        at += idx.used;
        updates_still_allowed = false;

        Reading f{};
        f.id = FieldId::Unknown;
        f.pseudo = Pseudo::None;

        if (idx.value != 0) {
            /* \~english
             * A name the table will not be given back is only checked, for
             * the same reason as an indexed field; one that is remembered has
             * to be copied, since adding it may evict the entry it came from.
             * \~spanish
             * Un nombre que no se le va a devolver a la tabla solo se
             * comprueba, por lo mismo que una cabecera indexada; uno que se
             * recuerda hay que copiarlo, porque anadirlo puede desalojar la
             * entrada de la que salio.
             * \~ */
            if (discarding && !remember) {
                if (!names_something(idx.value))
                    return ErrorCode::CompressionError;
            } else {
                const ErrorCode e = take_indexed_name(idx.value, sink, f);
                if (e != ErrorCode::NoError) return e;
            }
        } else {
            const ErrorCode e = take_string(block, n, at, sink, f.name);
            if (e != ErrorCode::NoError) return e;

            const uint8_t *nm = sink.data() + f.name.off;
            f.id = field_id_of(reinterpret_cast<const char *>(nm), f.name.len);
            f.pseudo = f.name.len != 0 && nm[0] == ':'
                           ? pseudo_of(nm, f.name.len)
                           : Pseudo::None;
        }

        const ErrorCode e = take_string(block, n, at, sink, f.value);
        if (e != ErrorCode::NoError) return e;

        if (remember) {
            const uint8_t *base = sink.data();
            if (!table_.add(base + f.name.off, f.name.len, base + f.value.off,
                            f.value.len, f.id, f.pseudo))
                return ErrorCode::InternalError;
        }

        if (!discarding) refused = keep(out, f, req);
    }

    if (refused != ErrorCode::NoError) return refused;

    // \~english The block is whole: what the request must carry, and CONNECT's form (RFC 9113, 8.3.1, 8.5).
    // \~spanish El bloque esta entero: lo que debe llevar la peticion, y la forma de CONNECT (RFC 9113, 8.3.1, 8.5).  \~
    const char *bad = builder_.finish(out.data());
    if (bad != nullptr) {
        why_ = bad;
        return ErrorCode::ProtocolError;
    }
    return ErrorCode::NoError;
}

} // namespace hpack
} // namespace h2
} // namespace http_vx
