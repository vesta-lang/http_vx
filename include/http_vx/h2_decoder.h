/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_decoder.h
 * @brief
 * \~english Turning a header block into a request.
 * \~spanish Convertir un bloque de cabeceras en una peticion.
 * \~
 *
 * \~english
 * This is where the four pieces of HPACK meet, and where the claim this
 * project has been making since `proto/semantics/` either holds or does not:
 * what comes out of here is a @c Request, and it is the same @c Request the
 * HTTP/1.1 parser produces from text.  Nothing above this has to know which.
 *
 * **What comes out points at a different buffer from what went in, and that is
 * the whole design.**  A field's name may have arrived as an index into a
 * table, as Huffman-coded bits, or as plain bytes -- three places, and only
 * one of them is the message.  So the decoder writes every name and value into
 * a buffer of its own and the spans point there.  It is a decompressor: it
 * produces the header list, it does not reference the compressed form.
 *
 * That buffer is the message's, in the sense R10 means: it lives for the
 * request and dies with it.  The table is the connection's and outlives them
 * all -- which is why the table copies and this does not.
 *
 * **And this is where the bomb is stopped.**  A block of three hundred bytes
 * can name a remembered field a thousand times; each naming costs one byte on
 * the wire and the whole field once it is written out.  The frame layer's
 * limit never fires -- the block really is three hundred bytes -- so the
 * limit that matters is counted here, on what comes out.
 *
 * \~spanish
 * Aqui se juntan las cuatro piezas de HPACK, y aqui la afirmacion que viene
 * haciendo este proyecto desde `proto/semantics/` se cumple o no se cumple: lo
 * que sale de aqui es un @c Request, y es el mismo @c Request que produce de
 * texto el analizador de HTTP/1.1.  Nada de mas arriba tiene que saber cual.
 *
 * **Lo que sale apunta a un buffer distinto del que entro, y ese es todo el
 * diseno.**  El nombre de una cabecera puede haber llegado como indice de una
 * tabla, como bits Huffman, o como bytes tal cual -- tres sitios, y solo uno es
 * el mensaje.  Asi que el descodificador escribe todos los nombres y valores en
 * un buffer propio y los trozos apuntan ahi.  Es un descompresor: produce la
 * lista de cabeceras, no referencia la forma comprimida.
 *
 * Ese buffer es del mensaje, en el sentido de R10: vive lo que la peticion y
 * muere con ella.  La tabla es de la conexion y les sobrevive a todas -- que es
 * la razon de que la tabla copie y esto no.
 *
 * **Y aqui es donde se para la bomba.**  Un bloque de trescientos bytes puede
 * nombrar mil veces una cabecera recordada; cada mencion cuesta un byte en el
 * cable y la cabecera entera una vez escrita.  El limite de la capa de tramas
 * no salta -- el bloque mide trescientos bytes de verdad -- asi que el limite
 * que importa se cuenta aqui, sobre lo que sale.
 *
 * \~
 */
#ifndef HTTP_VX_H2_DECODER_H
#define HTTP_VX_H2_DECODER_H

#include "http_vx/buffer.h"
#include "http_vx/h2_frame.h"
#include "http_vx/h2_limits.h"
#include "http_vx/h2_table.h"
#include "http_vx/message.h"
#include "http_vx/request_builder.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {
namespace hpack {

/**
 * @brief
 * \~english Reads header blocks for one connection.
 * \~spanish Lee bloques de cabeceras de una conexion.
 * \~
 *
 * \~english
 * One decoder per connection and not per message, because the table is the
 * connection's: a decoder made fresh for each request would forget everything
 * the encoder still remembers, and from the first index they would be talking
 * about different fields.
 *
 * \~spanish
 * Un descodificador por conexion y no por mensaje, porque la tabla es de la
 * conexion: uno nuevo por peticion olvidaria todo lo que el codificador sigue
 * recordando, y desde el primer indice estarian hablando de cabeceras
 * distintas.
 *
 * \~
 */
class Decoder {
  public:
    Decoder() noexcept = default;

    /**
     * @brief
     * \~english Makes it ready for a connection, and forgets everything.
     * \~spanish Lo deja listo para una conexion, y lo olvida todo.
     * \~
     *
     * @param limits \~english what this connection accepts, and announced
     *               \~spanish lo que acepta esta conexion, y anuncio  \~
     */
    void reset(const Limits &limits) noexcept;

    /**
     * @brief
     * \~english Reads one whole header block into @p req.
     * \~spanish Lee un bloque de cabeceras entero en @p req.
     * \~
     *
     * \~english
     * **The block must be all of it.**  Unlike everything else in this
     * project, there is no "read more and call again": a block that is half
     * here cannot be read at all, because the table changes as it is read and
     * stopping in the middle would leave the table in a state the encoder does
     * not share.  The frame layer above already waits for the last
     * CONTINUATION before handing one over, and that is why.
     *
     * If a block is split across frames, the caller joins the pieces first.
     * That is a copy, and it is the one this design accepts: the alternative
     * is a decoder that can be interrupted, which means a table that can be
     * left half-updated, which means a connection that has silently stopped
     * agreeing with its peer.
     *
     * \~spanish
     * **El bloque tiene que estar entero.**  A diferencia de todo lo demas de
     * este proyecto, aqui no hay "lee mas y vuelve a llamar": un bloque que
     * esta a medias no se puede leer, porque la tabla cambia segun se lee y
     * parar en medio la dejaria en un estado que el codificador no comparte.
     * La capa de tramas de arriba ya espera a la ultima CONTINUATION antes de
     * entregar uno, y es por esto.
     *
     * Si un bloque viene partido entre tramas, quien llama junta los pedazos
     * primero.  Eso es una copia, y es la que este diseno acepta: la
     * alternativa es un descodificador que se puede interrumpir, que es una
     * tabla que se puede quedar a medio actualizar, que es una conexion que ha
     * dejado de estar de acuerdo con su extremo en silencio.
     *
     * \~
     * @param block \~english the whole block  \~spanish el bloque entero  \~
     * @param n     \~english how many bytes  \~spanish cuantos bytes  \~
     * @param out   \~english where the decompressed names and values go; the
     *              spans in @p req point into its @c data
     *              \~spanish donde van los nombres y valores descomprimidos;
     *              los trozos de @p req apuntan a su @c data  \~
     * @param req   \~english where the request goes; it is emptied first
     *              \~spanish donde va la peticion; se vacia antes  \~
     * \~english
     * **And the block is read to its end whatever the message turns out to
     * be.**  A field that breaks a rule of the message -- malformed, or one
     * too many for `SETTINGS_MAX_HEADER_LIST_SIZE` -- refuses the MESSAGE,
     * and the fields after it still go through the table and are thrown
     * away, because the peer's encoder put them in its table too (RFC 9113,
     * 4.3 and 10.5.1).  The first rule broken is the one reported.  Only the
     * two errors that already end the connection stop the reading early.
     *
     * \~spanish
     * **Y el bloque se lee hasta el final resulte lo que resulte el mensaje.**
     * Una cabecera que rompe una regla del mensaje -- mal formada, o una de
     * mas para `SETTINGS_MAX_HEADER_LIST_SIZE` -- rechaza el MENSAJE, y las
     * cabeceras de detras pasan igual por la tabla y se tiran, porque el
     * codificador del otro extremo tambien las metio en la suya (RFC 9113, 4.3
     * y 10.5.1).  La primera regla rota es la que se cuenta.  Solo los dos
     * errores que ya acaban la conexion paran antes la lectura.
     *
     * \~
     * @return      \~english @c NoError, or why not.  @c CompressionError and
     *              @c InternalError mean the CONNECTION cannot go on, because
     *              the table is now in a state the peer does not share --
     *              the block could not be decoded, or there was no memory to
     *              decode the rest of it; anything else is about this message
     *              only, and the table is intact
     *              \~spanish @c NoError, o por que no.  @c CompressionError e
     *              @c InternalError quieren decir que la CONEXION no puede
     *              seguir, porque la tabla esta en un estado que el otro
     *              extremo no comparte -- el bloque no se pudo descodificar, o
     *              no hubo memoria para descodificar el resto; cualquier otro
     *              es solo de este mensaje, y la tabla esta intacta  \~
     */
    ErrorCode decode(const uint8_t *block, size_t n, Buffer &out,
                     Request &req) noexcept;

    /**
     * @brief
     * \~english Reads one whole trailer section, adding its fields to @p req.
     * \~spanish Lee una seccion de remolques entera, anadiendo sus campos a @p req.
     * \~
     *
     * \~english
     * The same block and the same table as @c decode -- a trailer section is
     * an HPACK block like any other, and skipping it would leave the table out
     * of step with the peer's.  What differs is where it goes: @p req is NOT
     * emptied, its fields gain the trailers, and a pseudo-header field makes
     * the message malformed (RFC 9113, 8.1).  For the new spans and the old
     * ones to share a base, @p out is the buffer the head was decoded into,
     * and it is only appended to.
     *
     * \~spanish
     * El mismo bloque y la misma tabla que @c decode -- una seccion de remolques
     * es un bloque HPACK como cualquier otro, y saltarselo dejaria la tabla
     * desacompasada de la del otro extremo.  Lo que cambia es adonde va: @p req
     * NO se vacia, sus campos ganan los remolques, y una pseudo-cabecera deja el
     * mensaje mal formado (RFC 9113, 8.1).  Para que los trozos nuevos y los
     * viejos compartan base, @p out es el buffer en que se descodifico la
     * cabecera, y solo se le anade.
     *
     * \~
     * @param block \~english the whole block  \~spanish el bloque entero  \~
     * @param n     \~english how many bytes  \~spanish cuantos bytes  \~
     * @param out   \~english where the names and values go, after what it holds
     *              \~spanish donde van los nombres y valores, detras de lo que tiene  \~
     * @param req   \~english the request the trailers belong to
     *              \~spanish la peticion de la que son los remolques  \~
     * @return      \~english as @c decode  \~spanish como @c decode  \~
     */
    ErrorCode decode_trailers(const uint8_t *block, size_t n, Buffer &out,
                              Request &req) noexcept;

    /// \~english What the connection remembers.  \~spanish Lo que recuerda la conexion.  \~
    DynamicTable &table() noexcept { return table_; }

    /// \~english Why the last block was refused, for the message or for the connection; null otherwise.
    /// \~spanish Por que se rechazo el ultimo bloque, por el mensaje o por la conexion; nulo si no.  \~
    const char *why() const noexcept { return why_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept {
        table_.release();
        scratch_.release();
    }

  private:
    /**
     * \~english
     * What one field came to while it was being read.  It is a struct rather
     * than four out-parameters because the four move together: a name and a
     * value, and what this project knows each of them to be.
     * \~spanish
     * A que llego una cabecera mientras se leia.  Es una estructura y no cuatro
     * parametros de salida porque las cuatro cosas van juntas: un nombre y un
     * valor, y lo que este proyecto sepa de cada uno.
     * \~
     */
    struct Reading {
        Span name;
        Span value;
        FieldId id;
        Pseudo pseudo;
    };

    ErrorCode take_string(const uint8_t *p, size_t n, size_t &at, Buffer &out,
                          Span &span) noexcept;
    ErrorCode take_indexed_name(uint64_t index, Buffer &out,
                                Reading &f) noexcept;
    ErrorCode keep(const Buffer &out, const Reading &f, Request &req) noexcept;

    /// \~english Whether @p index names an entry of either table.
    /// \~spanish Si @p index nombra una entrada de alguna de las dos tablas.  \~
    bool names_something(uint64_t index) const noexcept;

    /// \~english The block itself, once the builder knows whether it is a head or trailers; says why the connection ends, if it does.
    /// \~spanish El bloque en si, una vez el constructor sabe si es cabecera o remolques; dice por que acaba la conexion, si acaba.  \~
    ErrorCode read_block(const uint8_t *block, size_t n, Buffer &out,
                         Request &req) noexcept;

    /// \~english Every field of the block, the ones after a refusal included.
    /// \~spanish Todas las cabeceras del bloque, tambien las de detras de un rechazo.  \~
    ErrorCode read_fields(const uint8_t *block, size_t n, Buffer &out,
                          Request &req) noexcept;

    DynamicTable table_;

    /**
     * \~english
     * Where the fields of a refused block are decoded, one at a time, so
     * they can reach the table without reaching the caller's buffer.  Empty
     * until a block is refused, and emptied before each field, so it never
     * holds more than the largest single field.
     * \~spanish
     * Donde se descodifican, de una en una, las cabeceras de un bloque
     * rechazado, para que lleguen a la tabla sin llegar al buffer de quien
     * llama.  Vacio hasta que se rechaza un bloque, y vaciado antes de cada
     * cabecera, asi que nunca guarda mas que la cabecera suelta mas grande.
     * \~
     */
    Buffer scratch_;
    Limits limits_;

    /// \~english How much the fields of this block are worth so far.
    /// \~spanish Cuanto valen hasta ahora las cabeceras de este bloque.  \~
    uint64_t list_size_ = 0;
    /// \~english The rules of the message, shared with HTTP/3.  \~spanish Las reglas del mensaje, compartidas con HTTP/3.  \~
    RequestBuilder builder_;
    const char *why_ = nullptr;
};

} // namespace hpack
} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_DECODER_H
