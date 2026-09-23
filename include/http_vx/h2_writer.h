/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_writer.h
 * @brief
 * \~english Putting a response on the wire, in pieces somebody else chose the size of.
 * \~spanish Poner una respuesta en el cable, en pedazos cuyo tamano eligio otro.
 * \~
 *
 * \~english
 * HTTP/1.1 wrote a response by writing it: the head, then the body, and the
 * only question was how many bytes there were.  Here there are three answers
 * that are not this end's to give, and every one of them cuts the response
 * into pieces:
 *
 *  - the peer said how big a frame may be, so a header block longer than that
 *    goes out as a HEADERS and then CONTINUATIONs;
 *  - the peer said how much it will hold for this stream, and how much for the
 *    whole connection, so the body goes out in as much as the SMALLER of the
 *    two allows and then waits;
 *  - and other streams are being written at the same time down the same
 *    socket.
 *
 * **Which is why a header block, once begun, cannot be interrupted.**  Not by
 * another stream's frames, not by a PING, not by anything: the peer's
 * decompressor is a single running state and a frame in the middle would be
 * read as part of the block.  It is the one place in HTTP/2 where the whole
 * connection waits on one stream, and it is not an implementation limit -- it
 * is what the protocol requires.  This writer produces all the pieces of a
 * block at once so that a caller cannot write half of one and go away.
 *
 * **And two flags that look alike go in different places.**  `END_HEADERS`
 * says the block is finished, so it goes on the LAST piece.  `END_STREAM` says
 * the REQUEST-RESPONSE is finished, which is a fact about the stream and not
 * about the block, so it goes on the FIRST -- on the HEADERS frame, even when
 * six CONTINUATIONs follow it.  Putting them in the same place is a mistake
 * that works for every response short enough to fit in one frame, which is
 * almost all of them.
 *
 * \~spanish
 * HTTP/1.1 escribia una respuesta escribiendola: la cabecera, luego el cuerpo,
 * y la unica pregunta era cuantos bytes habia.  Aqui hay tres respuestas que no
 * le toca dar a este extremo, y todas ellas parten la respuesta en pedazos:
 *
 *  - el otro extremo dijo cuanto puede medir una trama, asi que un bloque de
 *    cabeceras mas largo que eso sale como un HEADERS y luego CONTINUATIONs;
 *  - el otro extremo dijo cuanto le cabe de este flujo, y cuanto de la conexion
 *    entera, asi que el cuerpo sale en lo que deje la MENOR de las dos y luego
 *    espera;
 *  - y a la vez se estan escribiendo otros flujos por el mismo socket.
 *
 * **Por eso un bloque de cabeceras, una vez empezado, no se puede
 * interrumpir.**  Ni por las tramas de otro flujo, ni por un PING, ni por nada:
 * el descompresor del otro extremo es un solo estado en marcha y una trama en
 * medio se leeria como parte del bloque.  Es el unico sitio de HTTP/2 donde la
 * conexion entera espera a un flujo, y no es una limitacion de la
 * implementacion -- es lo que exige el protocolo --.  Este escritor produce
 * todos los pedazos de un bloque de una vez, para que quien llama no pueda
 * escribir medio e irse.
 *
 * **Y dos banderas que se parecen van en sitios distintos.**  `END_HEADERS`
 * dice que el bloque se ha acabado, asi que va en el ULTIMO pedazo.
 * `END_STREAM` dice que se ha acabado la PETICION-RESPUESTA, que es un hecho
 * del flujo y no del bloque, asi que va en el PRIMERO -- en la trama HEADERS,
 * aunque detras vayan seis CONTINUATIONs --.  Ponerlas en el mismo sitio es una
 * equivocacion que funciona en todas las respuestas lo bastante cortas como
 * para caber en una trama, que son casi todas.
 *
 * \~
 */
#ifndef HTTP_VX_H2_WRITER_H
#define HTTP_VX_H2_WRITER_H

#include "http_vx/h2_flow.h"
#include "http_vx/h2_frame.h"
#include "http_vx/io_slice.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english The most frame headers one response may need at once.
 * \~spanish Las cabeceras de trama mas que puede necesitar de golpe una respuesta.
 * \~
 *
 * \~english
 * Eight, which is @c kMaxIoSlices halved: every piece written costs two
 * entries in the scatter list -- its nine-byte header and its payload -- so a
 * list of sixteen holds eight pieces and no more.  The number is derived here
 * rather than picked so that the two cannot drift: a writer that produced nine
 * pieces would fill the list and lose the last one, and losing the last piece
 * of a header block is a peer waiting for a CONTINUATION that never comes.
 *
 * \~spanish
 * Ocho, que es @c kMaxIoSlices entre dos: cada pedazo escrito cuesta dos
 * entradas de la lista dispersa -- sus nueve bytes de cabecera y su carga --
 * asi que una lista de dieciseis guarda ocho pedazos y ninguno mas.  El numero
 * se deriva aqui en vez de elegirse para que los dos no se separen: un escritor
 * que produjera nueve pedazos llenaria la lista y perderia el ultimo, y perder
 * el ultimo pedazo de un bloque de cabeceras es un extremo esperando una
 * CONTINUATION que no llega nunca.
 *
 * \~
 */
constexpr size_t kMaxPieces = kMaxIoSlices / 2;

/**
 * @brief
 * \~english Why a response could not be put on the wire.
 * \~spanish Por que no se pudo poner una respuesta en el cable.
 * \~
 */
enum class FrameError : uint8_t {
    /// \~english It could.  \~spanish Si se pudo.  \~
    Ok,

    /**
     * \~english
     * The header block needs more pieces than one scatter list holds.  It is
     * not an error in the response -- it is a response whose headers are so
     * large that at the peer's frame size they do not fit in one write, and
     * the caller has to write what it got and ask for the rest.
     *
     * Reported rather than silently truncated, because a truncated header
     * block is not a shorter response: it is a stream the peer will wait on
     * forever.
     *
     * \~spanish
     * El bloque de cabeceras necesita mas pedazos de los que guarda una lista
     * dispersa.  No es un error de la respuesta -- es una respuesta cuyas
     * cabeceras son tan grandes que al tamano de trama del otro extremo no
     * caben en una escritura, y quien llama tiene que escribir lo que le dieron
     * y pedir el resto.
     *
     * Se dice en vez de recortarlo por lo bajo, porque un bloque de cabeceras
     * recortado no es una respuesta mas corta: es un flujo en el que el otro
     * extremo se va a quedar esperando para siempre.
     * \~
     */
    TooManyPieces,

    /**
     * \~english
     * Nothing may be sent right now because one of the two windows is closed.
     * Not an error: it is the peer saying "wait", which is the entire purpose
     * of flow control.
     * \~spanish
     * Ahora mismo no se puede mandar nada porque una de las dos ventanas esta
     * cerrada.  No es un error: es el otro extremo diciendo "espera", que es
     * para lo que existe el control de flujo.
     * \~
     */
    WouldBlock,

    /// \~english The frame size the peer announced is not one.
    /// \~spanish El tamano de trama que anuncio el otro extremo no lo es.  \~
    BadFrameSize,
};

/**
 * @brief
 * \~english Cuts a header block into frames and lists them for one write.
 * \~spanish Parte un bloque de cabeceras en tramas y las lista para una escritura.
 * \~
 *
 * \~english
 * The block's bytes are NOT copied.  What goes in the list is the frame
 * headers -- which this holds, because they are nine bytes each and there is
 * nowhere else for them -- and slices that point straight at the block the
 * encoder built.  R14: a response is one scatter write, and the way to get
 * there is to never put two things in the same buffer just because they go out
 * together.
 *
 * \~spanish
 * Los bytes del bloque NO se copian.  Lo que va a la lista son las cabeceras de
 * trama -- que esto si guarda, porque son nueve bytes cada una y no hay otro
 * sitio para ellas -- y trozos que apuntan directamente al bloque que construyo
 * el codificador.  R14: una respuesta es una escritura dispersa, y la forma de
 * llegar ahi es no meter nunca dos cosas en el mismo buffer solo porque salgan
 * juntas.
 *
 * \~
 */
class HeaderFramer {
  public:
    HeaderFramer() noexcept = default;

    /**
     * @brief
     * \~english Frames @p n bytes of @p block for stream @p id.
     * \~spanish Entrama @p n bytes de @p block para el flujo @p id.
     * \~
     *
     * \~english
     * All the pieces at once, because a block that is begun and not finished
     * stops the whole connection -- see the note at the top of this file.  A
     * caller that gets @c TooManyPieces has written nothing and may ask again
     * with a smaller block; one that gets @c Ok has every frame it needs.
     *
     * \~spanish
     * Todos los pedazos de una vez, porque un bloque empezado y no acabado para
     * la conexion entera -- ver la nota del principio de este fichero --.  Quien
     * reciba @c TooManyPieces no ha escrito nada y puede volver a pedir con un
     * bloque menor; quien reciba @c Ok tiene todas las tramas que necesita.
     *
     * \~
     * @param out        \~english where the frames are listed
     *                   \~spanish donde se listan las tramas  \~
     * @param id         \~english which stream  \~spanish que flujo  \~
     * @param block      \~english the header block  \~spanish el bloque de cabeceras  \~
     * @param n          \~english how many bytes  \~spanish cuantos bytes  \~
     * @param max_frame  \~english what the peer said a frame may be
     *                   \~spanish lo que dijo el otro extremo que puede medir una trama  \~
     * @param end_stream \~english whether the response ends here
     *                   \~spanish si la respuesta se acaba aqui  \~
     * @return           \~english what went wrong, or @c Ok
     *                   \~spanish que fue mal, o @c Ok  \~
     */
    FrameError frame(IoList &out, uint32_t id, const uint8_t *block, size_t n,
                     uint32_t max_frame, bool end_stream) noexcept;

    /**
     * @brief
     * \~english How many frames the last call made.
     * \~spanish Cuantas tramas hizo la ultima llamada.
     * \~
     */
    size_t pieces() const noexcept { return pieces_; }

  private:
    /**
     * \~english
     * The frame headers, nine bytes each.  They live here and not in the
     * caller's buffer because they are the only bytes of a response this layer
     * invents, and putting them next to the block would mean copying the block
     * to make room.
     * \~spanish
     * Las cabeceras de trama, nueve bytes cada una.  Viven aqui y no en el
     * buffer de quien llama porque son los unicos bytes de una respuesta que se
     * inventa esta capa, y ponerlas al lado del bloque obligaria a copiar el
     * bloque para hacerles sitio.
     * \~
     */
    uint8_t heads_[kMaxPieces * kFrameHeaderSize] = {};
    size_t pieces_ = 0;
};

/**
 * @brief
 * \~english How much body may go out right now, and frames it.
 * \~spanish Cuanto cuerpo puede salir ahora mismo, y lo entrama.
 * \~
 *
 * \~english
 * Both windows are spent, and they are spent TOGETHER or not at all.  Taking
 * from one and then failing on the other would leave the connection believing
 * it had sent bytes that never left -- and nothing would ever give that
 * allowance back, because a WINDOW_UPDATE returns what was received and the
 * peer received nothing.  A window leak is silent until the connection stops.
 *
 * So the amount is worked out FIRST, from the smallest of the three bounds,
 * and only then is anything spent.
 *
 * \~spanish
 * Se gastan las dos ventanas, y se gastan JUNTAS o no se gasta ninguna.  Coger
 * de una y luego fallar en la otra dejaria a la conexion creyendo que mando
 * bytes que no salieron -- y nadie devolveria nunca ese credito, porque un
 * WINDOW_UPDATE devuelve lo RECIBIDO y el otro extremo no recibio nada.  Una
 * fuga de ventana es silenciosa hasta que la conexion se para.
 *
 * Asi que la cantidad se calcula PRIMERO, con la menor de las tres cotas, y solo
 * entonces se gasta algo.
 *
 * \~
 * @param out        \~english where the frame is listed
 *                   \~spanish donde se lista la trama  \~
 * @param head       \~english nine bytes this call writes the frame header into
 *                   \~spanish nueve bytes donde esta llamada escribe la cabecera  \~
 * @param id         \~english which stream  \~spanish que flujo  \~
 * @param body       \~english the bytes to send  \~spanish los bytes que mandar  \~
 * @param n          \~english how many are left  \~spanish cuantos quedan  \~
 * @param max_frame  \~english what the peer said a frame may be
 *                   \~spanish lo que dijo el otro extremo que puede medir una trama  \~
 * @param stream     \~english what this stream may still send
 *                   \~spanish lo que puede mandar todavia este flujo  \~
 * @param connection \~english what the connection may still send
 *                   \~spanish lo que puede mandar todavia la conexion  \~
 * @param sent       \~english how many bytes went out
 *                   \~spanish cuantos bytes salieron  \~
 * @return           \~english what went wrong, or @c Ok
 *                   \~spanish que fue mal, o @c Ok  \~
 */
FrameError frame_body(IoList &out, uint8_t *head, uint32_t id,
                      const uint8_t *body, size_t n, uint32_t max_frame,
                      Window &stream, Window &connection,
                      size_t &sent) noexcept;

/**
 * @brief
 * \~english Writes an empty DATA frame that just says the response is over.
 * \~spanish Escribe un DATA vacio que solo dice que la respuesta se acabo.
 * \~
 *
 * \~english
 * A zero-length frame, which costs no window -- which is why it is a separate
 * call rather than @c frame_body with nothing left.  That one would have to
 * decide whether an empty body means "send nothing" or "send the end", and
 * those are different answers that look identical from inside.
 *
 * \~spanish
 * Una trama de longitud cero, que no cuesta ventana -- que es la razon de que
 * sea una llamada aparte y no @c frame_body sin nada que mandar --.  Aquella
 * tendria que decidir si un cuerpo vacio quiere decir "no mandes nada" o "manda
 * el final", y son dos respuestas distintas que desde dentro se ven iguales.
 *
 * \~
 * @param out  \~english where the frame is listed  \~spanish donde se lista la trama  \~
 * @param head \~english nine bytes for the frame header
 *             \~spanish nueve bytes para la cabecera de trama  \~
 * @param id   \~english which stream  \~spanish que flujo  \~
 * @return     \~english whether it fitted in the list
 *             \~spanish si cupo en la lista  \~
 */
bool frame_end_of_body(IoList &out, uint8_t *head, uint32_t id) noexcept;

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_WRITER_H
