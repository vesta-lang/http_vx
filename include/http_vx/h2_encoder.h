/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_encoder.h
 * @brief
 * \~english Writing a header block, and the field that must not be compressed.
 * \~spanish Escribir un bloque de cabeceras, y la cabecera que no se comprime.
 * \~
 *
 * \~english
 * The decoder's danger was a small block that means a great deal.  The
 * encoder's is the opposite and it is not about size at all:
 *
 * **Compression leaks what it compressed.**  A field is shorter when it
 * repeats something already sent, so how long a message came out says
 * something about what was in it.  Give an attacker a way to put bytes into a
 * message that also carries a secret -- a query parameter reflected into a
 * header, a cookie sent beside it -- and they can guess the secret one byte at
 * a time: the guess that makes the message shorter was right.  That is CRIME
 * and BREACH, and HPACK does not repeal them.
 *
 * So the writing of every field says what may be done with it, and the
 * sensitive ones are written in the form that exists for exactly this: LITERAL
 * NEVER INDEXED, which asks not only this end but every intermediary along the
 * way not to remember it.  There is no other reason for that representation to
 * exist.
 *
 * **And this table is not the other one.**  A connection has two, one per
 * direction: what the peer told this end to remember, and what this end told
 * the peer. They are updated by different messages and they are never the
 * same.  Confusing them is not a bug that shows up as a crash -- it is a
 * header the peer reads as a different one.
 *
 * \~spanish
 * El peligro del descodificador era un bloque pequeno que significa muchisimo.
 * El del codificador es el contrario y no va de tamano:
 *
 * **Comprimir filtra lo comprimido.**  Una cabecera es mas corta cuando repite
 * algo ya mandado, asi que cuanto mide un mensaje dice algo de lo que llevaba
 * dentro.  Dale a un atacante una forma de meter bytes en un mensaje que ademas
 * lleva un secreto -- un parametro de consulta reflejado en una cabecera, una
 * cookie que va al lado -- y puede adivinar el secreto byte a byte: el intento
 * que acorta el mensaje era el bueno.  Eso son CRIME y BREACH, y HPACK no los
 * deroga.
 *
 * Asi que al escribir cada cabecera se dice que se puede hacer con ella, y las
 * sensibles se escriben en la forma que existe justo para esto: LITERAL QUE NO
 * SE INDEXA NUNCA, que le pide no solo a este extremo sino a todos los
 * intermediarios del camino que no la recuerden.  No hay otra razon para que
 * esa representacion exista.
 *
 * **Y esta tabla no es la otra.**  Una conexion tiene dos, una por sentido: lo
 * que el otro extremo le dijo a este que recordara, y lo que este le dijo al
 * otro.  Las actualizan mensajes distintos y no son nunca la misma.
 * Confundirlas no es un fallo que salga como una caida -- es una cabecera que
 * el otro extremo lee como otra.
 *
 * \~
 */
#ifndef HTTP_VX_H2_ENCODER_H
#define HTTP_VX_H2_ENCODER_H

#include "http_vx/buffer.h"
#include "http_vx/h2_table.h"
#include "http_vx/status.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {
namespace hpack {

/**
 * @brief
 * \~english What may be done with a field once it has been sent.
 * \~spanish Que se puede hacer con una cabecera una vez mandada.
 * \~
 *
 * \~english
 * The caller decides, and it has to be the caller: whether a value is safe to
 * remember depends on where it came from, and this layer only sees bytes.  A
 * `content-type` this server chose and a `content-type` echoed back from the
 * request look identical here and are not the same thing at all.
 *
 * \~spanish
 * Lo decide quien llama, y tiene que ser quien llama: si un valor se puede
 * recordar sin peligro depende de donde vino, y esta capa solo ve bytes.  Un
 * `content-type` que eligio este servidor y uno devuelto de la peticion son
 * identicos aqui y no son en absoluto lo mismo.
 *
 * \~
 */
enum class Indexing : uint8_t {
    /**
     * \~english
     * Sent as it is and forgotten.  The default, because it is the answer that
     * is never wrong: it gives up the compression a repeated field would buy
     * and gives up nothing else.
     * \~spanish
     * Se manda tal cual y se olvida.  El valor por defecto, porque es la
     * respuesta que nunca esta mal: renuncia a la compresion que compraria una
     * cabecera repetida y no renuncia a nada mas.
     * \~
     */
    WithoutIndexing,

    /**
     * \~english
     * Remembered, so that the next message that carries it costs one byte.
     * For a field whose value this server chose -- a `server` name, a
     * `content-type` from a fixed set -- and for no other.
     * \~spanish
     * Se recuerda, para que el mensaje siguiente que la lleve cueste un byte.
     * Para una cabecera cuyo valor eligio este servidor -- un nombre de
     * `server`, un `content-type` de un juego fijo -- y para ninguna otra.
     * \~
     */
    Incremental,

    /**
     * \~english
     * Never remembered, by anybody.  This one says something the other two do
     * not: it is a request to every intermediary on the way as well, and it is
     * what stands between a secret and a compression oracle.
     * \~spanish
     * No se recuerda nunca, ni aqui ni en ningun sitio.  Esta dice algo que las
     * otras dos no: es una peticion tambien a todos los intermediarios del
     * camino, y es lo que hay entre un secreto y un oraculo de compresion.
     * \~
     */
    Never,
};

/**
 * @brief
 * \~english Why a field could not be written.
 * \~spanish Por que no se pudo escribir una cabecera.
 * \~
 *
 * \~english
 * **Two of these are answers and one is the end of the connection.**
 * @c MustNotBeIndexed and @c TooLong are decided before a single byte goes
 * out, so the block is exactly as it was and the caller may write the field
 * another way.  @c OutOfMemory can happen with half a field written, and half
 * a field cannot be taken back: a header block is not a sequence of
 * independent pieces, it is a conversation about a table, and a peer that
 * received part of one has a table this end can no longer predict.  A caller
 * that sees it must close the connection rather than carry on with the block
 * it has.
 *
 * Which is why a field that is to be remembered is put in the table BEFORE its
 * bytes are written -- see @c write_pair.  Done the other way round, a table
 * that could not grow would leave the peer remembering a field this end does
 * not, and every index after it would name something else.  Done this way, the
 * failure happens while nothing has been sent.
 *
 * \~spanish
 * **Dos de estos son respuestas y uno es el fin de la conexion.**
 * @c MustNotBeIndexed y @c TooLong se deciden antes de que salga un solo byte,
 * asi que el bloque esta exactamente como estaba y quien llama puede escribir
 * la cabecera de otra forma.  @c OutOfMemory puede pasar con media cabecera
 * escrita, y media cabecera no se puede retirar: un bloque de cabeceras no es
 * una sucesion de pedazos independientes, es una conversacion sobre una tabla,
 * y un extremo que ha recibido parte de uno tiene una tabla que este extremo ya
 * no puede predecir.  Quien lo vea tiene que cerrar la conexion en vez de
 * seguir con el bloque que tenga.
 *
 * Por eso una cabecera que se va a recordar se mete en la tabla ANTES de
 * escribir sus bytes -- ver @c write_pair.  Al reves, una tabla que no pudiera
 * crecer dejaria al otro extremo recordando una cabecera que este no recuerda,
 * y todos los indices posteriores nombrarian otra cosa.  Asi, el fallo ocurre
 * cuando todavia no se ha mandado nada.
 *
 * \~
 */
enum class WriteStatus : uint8_t {
    /// \~english It was written.  \~spanish Se escribio.  \~
    Ok,

    /**
     * \~english
     * The caller asked for a field to be remembered that must never be.  It is
     * refused rather than quietly downgraded: quietly doing the safe thing
     * would leave the call site saying something untrue about the field, and
     * the next person to read it would believe it.
     * \~spanish
     * Quien llama pidio que se recordara una cabecera que no se puede recordar
     * nunca.  Se rechaza en vez de rebajarlo por lo bajo: hacer lo seguro en
     * silencio dejaria el sitio de llamada diciendo algo falso sobre la
     * cabecera, y quien lo leyera despues se lo creeria.
     * \~
     */
    MustNotBeIndexed,

    /// \~english The name or value is longer than a field can be.
    /// \~spanish El nombre o el valor son mas largos de lo que puede ser una cabecera.  \~
    TooLong,

    /// \~english The memory could not be had.
    /// \~spanish No se pudo conseguir la memoria.  \~
    OutOfMemory,
};

/**
 * @brief
 * \~english Whether @p id is one that must never be remembered.
 * \~spanish Si @p id es una de las que no se pueden recordar nunca.
 * \~
 *
 * \~english
 * The fields that carry what somebody is, rather than what they asked for.  A
 * remembered credential is a credential whose length can be measured by
 * somebody who can make the server send it again -- which is the whole of
 * CRIME in one sentence.
 *
 * Exposed because it is a question with one answer, and a caller that worked
 * it out for itself would be a second list of what is a secret.
 *
 * \~spanish
 * Las cabeceras que llevan quien es alguien, en vez de que ha pedido.  Una
 * credencial recordada es una credencial cuya longitud puede medir alguien que
 * consiga que el servidor la mande otra vez -- que es todo CRIME en una frase.
 *
 * Expuesto porque es una pregunta con una sola respuesta, y quien la resolviera
 * por su cuenta seria una segunda lista de lo que es un secreto.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true if it must never be remembered
 *           \~spanish true si no se puede recordar nunca  \~
 */
bool must_never_be_indexed(FieldId id) noexcept;

/**
 * @brief
 * \~english Writes header blocks for one connection.
 * \~spanish Escribe bloques de cabeceras de una conexion.
 * \~
 */
class Encoder {
  public:
    Encoder() noexcept = default;

    /**
     * @brief
     * \~english Makes it ready, for a peer that will accept @p peer_table_size.
     * \~spanish Lo deja listo, para un extremo que aceptara @p peer_table_size.
     * \~
     *
     * \~english
     * The number is the PEER'S `SETTINGS_HEADER_TABLE_SIZE`, not this end's.
     * They are different connections' worth of memory in opposite directions,
     * and using one for the other is how an encoder comes to believe the peer
     * remembers something it evicted.
     *
     * \~spanish
     * El numero es el `SETTINGS_HEADER_TABLE_SIZE` DEL OTRO EXTREMO, no el de
     * este.  Son memorias de conexion distintas en sentidos opuestos, y usar
     * una por la otra es como un codificador acaba creyendo que el otro extremo
     * recuerda algo que desalojo.
     *
     * \~
     * @param peer_table_size \~english what the peer said it would remember
     *                        \~spanish lo que el otro extremo dijo que recordaria  \~
     */
    void reset(uint32_t peer_table_size) noexcept;

    /**
     * @brief
     * \~english Writes the status of a response.
     * \~spanish Escribe el estado de una respuesta.
     * \~
     *
     * \~english
     * It goes first, because a pseudo-header comes before the fields.  Seven
     * of the common statuses are in the static table, so an ordinary `200`
     * costs one byte.
     *
     * \~spanish
     * Va primero, porque una pseudo-cabecera va antes que las cabeceras.  Siete
     * de los estados corrientes estan en la tabla estatica, asi que un `200`
     * normal cuesta un byte.
     *
     * \~
     * @param out    \~english where the block goes  \~spanish donde va el bloque  \~
     * @param status \~english the status code  \~spanish el codigo de estado  \~
     * @return       \~english what went wrong, or @c Ok
     *               \~spanish que fue mal, o @c Ok  \~
     */
    WriteStatus write_status(Buffer &out, StatusCode status) noexcept;

    /**
     * @brief
     * \~english Writes a field whose name this project knows.
     * \~spanish Escribe una cabecera cuyo nombre conoce este proyecto.
     * \~
     *
     * @param out   \~english where the block goes  \~spanish donde va el bloque  \~
     * @param id    \~english the identifier  \~spanish el identificador  \~
     * @param value \~english its value  \~spanish su valor  \~
     * @param vlen  \~english how many bytes  \~spanish cuantos bytes  \~
     * @param how   \~english what may be done with it once it is sent
     *              \~spanish que se puede hacer con ella una vez mandada  \~
     * @return      \~english what went wrong, or @c Ok
     *              \~spanish que fue mal, o @c Ok  \~
     */
    WriteStatus write_field(Buffer &out, FieldId id, const uint8_t *value,
                            size_t vlen,
                            Indexing how = Indexing::WithoutIndexing) noexcept;

    /**
     * @brief
     * \~english Writes a field by name.
     * \~spanish Escribe una cabecera por su nombre.
     * \~
     *
     * \~english
     * The name is written as it is given and is NOT lowered.  HTTP/2 requires
     * lower case on the wire, so a capital here is a message the peer must
     * refuse -- and lowering it quietly would make this server send something
     * the caller did not write, which is the same mistake as trimming a value.
     *
     * \~spanish
     * El nombre se escribe tal como se da y NO se baja a minusculas.  HTTP/2
     * exige minusculas en el cable, asi que una mayuscula aqui es un mensaje
     * que el otro extremo tiene que rechazar -- y bajarla por lo bajo haria que
     * este servidor mandara algo que quien llama no escribio, que es la misma
     * equivocacion que recortar un valor.
     *
     * \~
     * @param out   \~english where the block goes  \~spanish donde va el bloque  \~
     * @param name  \~english the name  \~spanish el nombre  \~
     * @param nlen  \~english how many bytes  \~spanish cuantos bytes  \~
     * @param value \~english its value  \~spanish su valor  \~
     * @param vlen  \~english how many bytes  \~spanish cuantos bytes  \~
     * @param how   \~english what may be done with it once it is sent
     *              \~spanish que se puede hacer con ella una vez mandada  \~
     * @return      \~english what went wrong, or @c Ok
     *              \~spanish que fue mal, o @c Ok  \~
     */
    WriteStatus write_field(Buffer &out, const uint8_t *name, size_t nlen,
                            const uint8_t *value, size_t vlen,
                            Indexing how = Indexing::WithoutIndexing) noexcept;

    /// \~english What this end told the peer to remember.
    /// \~spanish Lo que este extremo le dijo al otro que recordara.  \~
    DynamicTable &table() noexcept { return table_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept { table_.release(); }

  private:
    WriteStatus write_pair(Buffer &out, FieldId id, const uint8_t *name,
                           size_t nlen, const uint8_t *value, size_t vlen,
                           Indexing how) noexcept;
    WriteStatus put_string(Buffer &out, const uint8_t *p, size_t n) noexcept;
    WriteStatus put_int(Buffer &out, uint64_t value, uint8_t prefix_bits,
                        uint8_t keep) noexcept;

    DynamicTable table_;
};

} // namespace hpack
} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_ENCODER_H
