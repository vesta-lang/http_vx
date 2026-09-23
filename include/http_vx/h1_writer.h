/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h1_writer.h
 * @brief
 * \~english Writing a response, and refusing to write one that lies.
 * \~spanish Escribir una respuesta, y negarse a escribir una que miente.
 * \~
 *
 * \~english
 * Reading is where a server is attacked and writing is where it attacks
 * itself.  The parser's danger is a message built to be read two ways; the
 * writer's is a message built from something the application was given and did
 * not look at.
 *
 * It is the same failure, pointed the other way.  A field value carrying a
 * carriage return ends the field and starts another, so `Location:` built from
 * a query parameter lets whoever wrote that parameter add fields to the
 * response, and enough of them to add a second response.  The client believes
 * all of it, because all of it arrived on a connection to this server.
 *
 * So **every value is checked before it is written**, and a value the grammar
 * does not allow is refused rather than cleaned up.  Cleaning it up is worse
 * than refusing: it changes what the application meant, silently, and leaves
 * the bug that produced it in place.
 *
 * Two more things are refused, both for the same reason -- that a message must
 * say each thing once:
 *
 *  - the application may not write the framing fields.  How long the body is
 *    is decided at @c finish, from what the application says the body IS, and
 *    a second answer written by hand is a second answer.
 *  - a body may not be written where the status or the method forbids one.
 *    That rule is @c response_can_have_body, and getting it wrong costs the
 *    connection rather than the response.
 *
 * **What it does not do is find out the time.**  A response should carry a
 * `Date`, and reading the clock needs the operating system, which `proto/` may
 * not touch (R6).  So the date arrives as bytes from whoever has a clock --
 * which is also the one that can keep one string per second instead of
 * formatting one per response.
 *
 * \~spanish
 * Leer es por donde atacan a un servidor y escribir es por donde se ataca el
 * solo.  El peligro del analizador es un mensaje hecho para leerse de dos
 * formas; el del escritor es un mensaje hecho con algo que le dieron a la
 * aplicacion y que no miro.
 *
 * Es el mismo fallo, apuntando al otro lado.  Un valor de cabecera con un
 * retorno de carro termina la cabecera y empieza otra, asi que un `Location:`
 * construido con un parametro de la consulta deja que quien escribiera ese
 * parametro anada cabeceras a la respuesta, y las suficientes para anadir una
 * segunda respuesta.  El cliente se lo cree todo, porque todo llego por una
 * conexion a este servidor.
 *
 * Asi que **todos los valores se comprueban antes de escribirse**, y un valor
 * que la gramatica no permite se rechaza en vez de limpiarse.  Limpiarlo es
 * peor que rechazarlo: cambia en silencio lo que la aplicacion queria decir, y
 * deja donde estaba el error que lo produjo.
 *
 * Se rechazan dos cosas mas, las dos porque un mensaje tiene que decir cada
 * cosa una vez:
 *
 *  - la aplicacion no puede escribir las cabeceras de troceado.  Cuanto mide el
 *    cuerpo se decide en @c finish, de lo que la aplicacion diga que el cuerpo
 *    ES, y una segunda respuesta escrita a mano es una segunda respuesta.
 *  - no se puede escribir cuerpo donde el estado o el metodo lo prohiben.  Esa
 *    regla es @c response_can_have_body, y errarla cuesta la conexion y no la
 *    respuesta.
 *
 * **Lo que no hace es averiguar la hora.**  Una respuesta deberia llevar
 * `Date`, y leer el reloj necesita el sistema operativo, que `proto/` no puede
 * tocar (R6).  Asi que la fecha llega como bytes de quien tenga reloj -- que
 * es ademas el que puede guardar una cadena por segundo en vez de formatear una
 * por respuesta.
 *
 * \~
 */
#ifndef HTTP_VX_H1_WRITER_H
#define HTTP_VX_H1_WRITER_H

#include "http_vx/buffer.h"
#include "http_vx/io_slice.h"
#include "http_vx/message.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h1 {

/**
 * @brief
 * \~english Why a response could not be written.
 * \~spanish Por que no se pudo escribir una respuesta.
 * \~
 *
 * \~english
 * These are all the writer's own side: a request that cannot be read is
 * somebody else's mistake, and a response that cannot be written is this
 * program's.  They are told apart anyway, because the answer to each is a
 * different line of code to go and change.
 *
 * \~spanish
 * Todos son del propio lado del escritor: una peticion que no se puede leer es
 * un error de otro, y una respuesta que no se puede escribir es de este
 * programa.  Se distinguen igual, porque la respuesta a cada uno es una linea
 * de codigo distinta que hay que ir a cambiar.
 *
 * \~
 */
enum class WriteError : uint8_t {
    /// \~english Nothing is wrong.  \~spanish No pasa nada.  \~
    None = 0,

    /// \~english The status code is not three digits between 100 and 599.
    /// \~spanish El codigo de estado no son tres cifras entre 100 y 599.  \~
    BadStatus,

    /// \~english A field name that is not a token.
    /// \~spanish Un nombre de cabecera que no es un token.  \~
    BadFieldName,

    /**
     * \~english
     * A field value carrying a byte it may not, which is very nearly always a
     * carriage return or a line feed that arrived from outside.  This is
     * response splitting, and it is the reason every value is checked.
     * \~spanish
     * Un valor de cabecera con un byte que no puede llevar, que casi siempre es
     * un retorno de carro o un salto de linea que vino de fuera.  Esto es la
     * particion de respuestas, y es la razon de que se compruebe cada valor.
     * \~
     */
    BadFieldValue,

    /**
     * \~english
     * The application tried to write a framing field.  How long the body is is
     * settled at @c finish, from what the body is said to be; writing it by
     * hand as well is writing it twice, and two answers to where a response
     * ends is the same disagreement the parser spends its time refusing.
     * \~spanish
     * La aplicacion intento escribir una cabecera de troceado.  Cuanto mide el
     * cuerpo se resuelve en @c finish, de lo que se diga que es el cuerpo;
     * escribirla ademas a mano es escribirla dos veces, y dos respuestas a
     * donde acaba una respuesta es la misma discrepancia que el analizador se
     * pasa la vida rechazando.
     * \~
     */
    FramingIsNotYours,

    /**
     * \~english
     * A body was declared where the status or the method forbids one.  See
     * @c response_can_have_body: writing it would put bytes where the peer
     * reads the start of the next response.
     * \~spanish
     * Se declaro un cuerpo donde el estado o el metodo lo prohiben.  Ver
     * @c response_can_have_body: escribirlo pondria bytes donde el otro extremo
     * lee el principio de la respuesta siguiente.
     * \~
     */
    BodyNotAllowed,

    /**
     * \~english
     * Chunks asked of HTTP/1.0, which had none.  A client that announced that
     * version will read the chunk headers as body.
     * \~spanish
     * Se pidieron trozos a HTTP/1.0, que no los tenia.  Un cliente que anuncio
     * esa version leera las cabeceras de los trozos como cuerpo.
     * \~
     */
    ChunkedNotAvailable,

    /// \~english Something was written out of order: a field after @c finish.
    /// \~spanish Se escribio algo fuera de orden: una cabecera tras @c finish.  \~
    OutOfOrder,

    /// \~english The memory for the head could not be had.
    /// \~spanish No se pudo conseguir la memoria de la cabeza.  \~
    OutOfMemory,
};

/**
 * @brief
 * \~english How the body of a response is delimited.
 * \~spanish Como se delimita el cuerpo de una respuesta.
 * \~
 */
enum class ResponseBody : uint8_t {
    /**
     * \~english
     * None at all, and no framing field either.  It is what `1xx`, `204` and
     * `304` take, and the only thing they take.
     * \~spanish
     * Ninguno, y tampoco cabecera de troceado.  Es lo que llevan `1xx`, `204` y
     * `304`, y lo unico que llevan.
     * \~
     */
    None,

    /**
     * \~english
     * A known number of bytes.  This is also what a response to `HEAD` uses:
     * the length is written as if the body were coming and then it is not,
     * which is what makes a `HEAD` answer the same question as the `GET`.
     * \~spanish
     * Un numero conocido de bytes.  Es tambien lo que usa una respuesta a
     * `HEAD`: la longitud se escribe como si el cuerpo fuera a ir y luego no
     * va, que es lo que hace que un `HEAD` conteste la misma pregunta que el
     * `GET`.
     * \~
     */
    Length,

    /**
     * \~english
     * Pieces that announce their own sizes, for when the length is not known
     * when the head is written.  HTTP/1.1 only.
     * \~spanish
     * Pedazos que anuncian su propio tamano, para cuando la longitud no se sabe
     * al escribir la cabeza.  Solo HTTP/1.1.
     * \~
     */
    Chunked,

    /**
     * \~english
     * Until the connection closes.  It is the last resort and it costs the
     * connection, so it is worth saying when it is right: an HTTP/1.0 client
     * asking for something of unknown length has no other framing, because
     * chunks did not exist yet.
     * \~spanish
     * Hasta que se cierre la conexion.  Es el ultimo recurso y cuesta la
     * conexion, asi que merece decirse cuando es lo correcto: un cliente
     * HTTP/1.0 que pide algo de longitud desconocida no tiene otro troceado,
     * porque los trozos todavia no existian.
     * \~
     */
    UntilClose,
};

/**
 * @brief
 * \~english Builds the head of one response.
 * \~spanish Construye la cabeza de una respuesta.
 * \~
 *
 * \~english
 * The head is built into a buffer of its own because it does not exist
 * anywhere else -- it is being made up.  The BODY is not, and never comes
 * through here: it is added to an @c IoList beside the head and the two go out
 * in one write (R14).
 *
 * \~spanish
 * La cabeza se construye en un buffer propio porque no existe en ningun otro
 * sitio -- se esta inventando --.  El CUERPO no, y no pasa nunca por aqui: se
 * anade a una @c IoList al lado de la cabeza y los dos salen en una escritura
 * (R14).
 *
 * \~
 */
class ResponseWriter {
  public:
    /**
     * @brief
     * \~english Starts a response.
     * \~spanish Empieza una respuesta.
     * \~
     *
     * \~english
     * The request's method is needed, not out of tidiness: a response to
     * `HEAD` carries the fields of the `GET` and none of its body, and that is
     * decided here rather than remembered later.
     *
     * \~spanish
     * Hace falta el metodo de la peticion, y no por orden: una respuesta a
     * `HEAD` lleva las cabeceras del `GET` y nada de su cuerpo, y eso se decide
     * aqui y no se recuerda despues.
     *
     * \~
     * @param version    \~english which version to write  \~spanish en que version escribir  \~
     * @param status     \~english the status code  \~spanish el codigo de estado  \~
     * @param method     \~english the method of the request being answered
     *                   \~spanish el metodo de la peticion que se contesta  \~
     * @param keep_alive \~english whether the connection is to be reused
     *                   \~spanish si la conexion se va a reutilizar  \~
     * @return           \~english what went wrong, or @c None
     *                   \~spanish que fue mal, o @c None  \~
     */
    WriteError begin(Version version, StatusCode status, MethodId method,
                     bool keep_alive) noexcept;

    /**
     * @brief
     * \~english Writes a field whose name this project knows.
     * \~spanish Escribe una cabecera cuyo nombre conoce este proyecto.
     * \~
     *
     * @param id    \~english the identifier  \~spanish el identificador  \~
     * @param value \~english its value  \~spanish su valor  \~
     * @param len   \~english how many bytes  \~spanish cuantos bytes  \~
     * @return      \~english what went wrong, or @c None
     *              \~spanish que fue mal, o @c None  \~
     */
    WriteError field(FieldId id, const char *value, size_t len) noexcept;

    /**
     * @brief
     * \~english Writes a field by name.
     * \~spanish Escribe una cabecera por su nombre.
     * \~
     *
     * \~english
     * The name is checked too, and not only the value.  A name is a token by
     * the grammar, so one that is not a token carries whatever separated it
     * from being one -- a colon, a space, a line ending -- into the place
     * where the parser on the other side looks for the next field.
     *
     * \~spanish
     * El nombre se comprueba tambien, y no solo el valor.  Un nombre es un
     * token por la gramatica, asi que uno que no lo sea lleva lo que fuera que
     * le impedia serlo -- dos puntos, un espacio, un fin de linea -- justo
     * donde el analizador del otro lado busca la cabecera siguiente.
     *
     * \~
     * @param name  \~english the name  \~spanish el nombre  \~
     * @param nlen  \~english its length  \~spanish su longitud  \~
     * @param value \~english its value  \~spanish su valor  \~
     * @param vlen  \~english its length  \~spanish su longitud  \~
     * @return      \~english what went wrong, or @c None
     *              \~spanish que fue mal, o @c None  \~
     */
    WriteError field(const char *name, size_t nlen, const char *value,
                     size_t vlen) noexcept;

    /**
     * @brief
     * \~english Finishes the head, declaring what the body is.
     * \~spanish Termina la cabeza, declarando que es el cuerpo.
     * \~
     *
     * \~english
     * The framing is a parameter and not a separate call that could be left
     * out.  A writer that defaulted to something when nobody said would be
     * choosing the one thing that decides where the response ends, and the
     * convenient default -- until the connection closes -- is the one that
     * silently costs connection reuse on every response that forgot.
     *
     * \~spanish
     * El troceado es un parametro y no una llamada aparte que se pudiera dejar
     * sin hacer.  Un escritor que pusiera algo por defecto cuando no lo dijera
     * nadie estaria eligiendo lo unico que decide donde acaba la respuesta, y
     * el valor comodo -- hasta que se cierre la conexion -- es el que cuesta en
     * silencio la reutilizacion de la conexion en cada respuesta que se olvido.
     *
     * \~
     * @param body   \~english how the body is delimited
     *               \~spanish como se delimita el cuerpo  \~
     * @param length \~english how many bytes, when @p body is @c Length
     *               \~spanish cuantos bytes, cuando @p body es @c Length  \~
     * @return       \~english what went wrong, or @c None
     *               \~spanish que fue mal, o @c None  \~
     */
    WriteError finish(ResponseBody body, uint64_t length = 0) noexcept;

    /**
     * @brief
     * \~english Whether body bytes are to be written after the head.
     * \~spanish Si tras la cabeza hay que escribir bytes de cuerpo.
     * \~
     *
     * \~english
     * This is where `HEAD` differs from everything else and the only place it
     * does: the head was written with a length, and no bytes follow it.  A
     * caller that asked the status instead of asking here would send the body
     * of a `HEAD`, which the peer reads as the beginning of the next response.
     *
     * \~spanish
     * Aqui es donde `HEAD` se diferencia de todo lo demas y el unico sitio
     * donde lo hace: la cabeza se escribio con una longitud, y detras no va
     * ningun byte.  Quien preguntara al estado en vez de preguntar aqui
     * mandaria el cuerpo de un `HEAD`, que el otro extremo lee como el
     * principio de la respuesta siguiente.
     *
     * \~
     */
    bool body_follows() const noexcept { return body_follows_; }

    /// \~english Whether the body is written as chunks.
    /// \~spanish Si el cuerpo se escribe como trozos.  \~
    bool body_is_chunked() const noexcept { return chunked_; }

    /// \~english Whether the connection ends with this response.
    /// \~spanish Si la conexion termina con esta respuesta.  \~
    bool closes() const noexcept { return closes_; }

    /// \~english The bytes of the head.  \~spanish Los bytes de la cabeza.  \~
    const uint8_t *head() const noexcept { return out_.data(); }
    /// \~english How many there are.  \~spanish Cuantos hay.  \~
    size_t head_size() const noexcept { return out_.size(); }

    /**
     * @brief
     * \~english Puts the head into @p out, for the write that sends it.
     * \~spanish Pone la cabeza en @p out, para la escritura que la manda.
     * \~
     *
     * @param out \~english the list to add to  \~spanish la lista a la que anadir  \~
     * @return    \~english false if there was no room
     *            \~spanish false si no habia sitio  \~
     */
    bool gather(IoList &out) const noexcept {
        return out.push(out_.data(), out_.size());
    }

    /**
     * @brief
     * \~english Gives the memory back and makes it ready for another response.
     * \~spanish Devuelve la memoria y lo deja listo para otra respuesta.
     * \~
     */
    void release() noexcept;

  private:
    enum class State : uint8_t { Fresh, Fields, Finished, Failed };

    [[gnu::noinline, gnu::cold]] WriteError fail(WriteError e) noexcept;
    bool put(const void *p, size_t n) noexcept;
    bool put_u64(uint64_t v) noexcept;
    bool put_name(FieldId id) noexcept;
    bool put_own_field(FieldId id, const char *value, size_t len) noexcept;

    Buffer out_;
    State state_ = State::Fresh;
    Version version_ = Version::Unknown;
    StatusCode status_ = 0;
    MethodId method_ = MethodId::Unknown;
    bool keep_alive_ = true;
    bool closes_ = false;
    bool body_follows_ = false;
    bool chunked_ = false;
    bool wrote_connection_ = false;
};

/**
 * @brief
 * \~english Writes the header of one chunk into @p out.
 * \~spanish Escribe la cabecera de un trozo en @p out.
 * \~
 *
 * \~english
 * A chunk on the wire is a size, the bytes, and an ending, and only the first
 * and the last are made up here -- the bytes in the middle are the caller's
 * and are never copied.  So this writes the size into a small buffer the
 * caller owns and says how long it came out, and the caller gathers three
 * runs: this, its own bytes, and @c kChunkEnd.
 *
 * \~spanish
 * Un trozo en el cable son un tamano, los bytes, y un final, y aqui solo se
 * inventan el primero y el ultimo -- los bytes de en medio son de quien llama y
 * no se copian nunca --.  Asi que esto escribe el tamano en un buffer pequeno
 * de quien llama y dice cuanto salio, y quien llama junta tres tiradas: esta,
 * sus propios bytes, y @c kChunkEnd.
 *
 * \~
 * @param out  \~english where to write; at least @c kChunkHeaderMax bytes
 *             \~spanish donde escribir; al menos @c kChunkHeaderMax bytes  \~
 * @param size \~english how many bytes the chunk has
 *             \~spanish cuantos bytes tiene el trozo  \~
 * @return     \~english how many bytes were written
 *             \~spanish cuantos bytes se escribieron  \~
 */
size_t write_chunk_header(uint8_t *out, uint64_t size) noexcept;

/// \~english The most a chunk header takes: sixteen digits and a CRLF.
/// \~spanish Lo mas que ocupa una cabecera de trozo: dieciseis digitos y un CRLF.  \~
constexpr size_t kChunkHeaderMax = 18;

/// \~english What goes after a chunk's bytes.
/// \~spanish Lo que va tras los bytes de un trozo.  \~
extern const uint8_t kChunkEnd[2];

/// \~english The last chunk, with no trailers.
/// \~spanish El ultimo trozo, sin remolques.  \~
extern const uint8_t kLastChunk[5];

} // namespace h1
} // namespace http_vx

#endif // HTTP_VX_H1_WRITER_H
