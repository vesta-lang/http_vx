/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_connection.h
 * @brief
 * \~english One connection: the frames, the streams, and what must be answered.
 * \~spanish Una conexion: las tramas, los flujos, y lo que hay que contestar.
 * \~
 *
 * \~english
 * The piece the other five were written for.  Bytes go in and requests come
 * out, and what happens in between is the frame reader, the header decoder,
 * the stream table and the two windows all being driven by the same bytes.
 *
 * **Most of HTTP/2 is answering things**, and that turns out to be the part
 * with the security in it.  A SETTINGS must be acknowledged.  A PING must be
 * echoed.  Data received must be given back as window or the connection stops.
 * Each answer is cheap, and a peer can ask for thousands of them in one read
 * of a socket -- so the only question that matters is what this end does when
 * the answers pile up faster than they go out.
 *
 * The answer here is a FIXED buffer and backpressure: when there is no room
 * for the next answer, reading stops and the caller is told to flush.  Nothing
 * grows.  A peer that floods PINGs gets its pings answered at exactly the rate
 * its own socket drains them, and the memory this end spends on it does not
 * depend on how many it sent.  A server that answered into a growing buffer
 * would be one where a peer chooses how much memory the server uses, which is
 * the whole of that attack.
 *
 * **And answering is a source of work that is not a request**, which is why
 * the frames that ask for nothing else -- PRIORITY, an unknown type -- are
 * read and dropped rather than refused.  Refusing them would close
 * connections with peers speaking a later version; acting on them would be
 * inventing a meaning.
 *
 * \~spanish
 * La pieza para la que se escribieron las otras cinco.  Entran bytes y salen
 * peticiones, y lo que pasa en medio es el lector de tramas, el descodificador
 * de cabeceras, la tabla de flujos y las dos ventanas movidos todos por los
 * mismos bytes.
 *
 * **Casi todo HTTP/2 es contestar cosas**, y resulta que esa es la parte donde
 * esta la seguridad.  Un SETTINGS hay que confirmarlo.  Un PING hay que
 * devolverlo.  Los datos recibidos hay que devolverlos como ventana o la
 * conexion se para.  Cada respuesta es barata, y un extremo puede pedir miles
 * en una sola lectura del socket -- asi que la unica pregunta que importa es que
 * hace este extremo cuando las respuestas se acumulan mas deprisa de lo que
 * salen.
 *
 * La respuesta de aqui es un buffer FIJO y contrapresion: cuando no hay sitio
 * para la respuesta siguiente, se deja de leer y se le dice a quien llama que
 * vacie.  No crece nada.  A un extremo que inunde de PINGs se le contestan sus
 * pings exactamente al ritmo al que los vacia su propio socket, y la memoria que
 * gasta este extremo en ello no depende de cuantos mando.  Un servidor que
 * contestara a un buffer que crece seria uno donde el otro extremo elige cuanta
 * memoria usa el servidor, que es todo ese ataque.
 *
 * **Y contestar es una fuente de trabajo que no es una peticion**, que es la
 * razon de que las tramas que no piden nada mas -- PRIORITY, un tipo
 * desconocido -- se lean y se tiren en vez de rechazarse.  Rechazarlas cerraria
 * conexiones con extremos que hablan una version posterior; atenderlas seria
 * inventarles un significado.
 *
 * \~
 */
#ifndef HTTP_VX_H2_CONNECTION_H
#define HTTP_VX_H2_CONNECTION_H

#include "http_vx/buffer.h"
#include "http_vx/h2_decoder.h"
#include "http_vx/h2_encoder.h"
#include "http_vx/h2_flow.h"
#include "http_vx/h2_reader.h"
#include "http_vx/h2_settings.h"
#include "http_vx/h2_stream.h"
#include "http_vx/message.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english How much room the answers get.
 * \~spanish Cuanto sitio tienen las respuestas.
 * \~
 *
 * \~english
 * A kilobyte, which is about sixty of the largest control frame.  It is not
 * tuned and it does not need to be: what makes it safe is that it is FIXED, so
 * the cost of a peer that asks for a million answers is the same as one that
 * asks for sixty.  Making it larger would buy fewer flushes and change nothing
 * about the worst case.
 *
 * \~spanish
 * Un kilobyte, que son unas sesenta de la trama de control mas grande.  No esta
 * afinado y no hace falta: lo que lo hace seguro es que es FIJO, asi que un
 * extremo que pida un millon de respuestas cuesta lo mismo que uno que pida
 * sesenta.  Hacerlo mayor compraria menos vaciados y no cambiaria nada del peor
 * caso.
 *
 * \~
 */
constexpr size_t kControlRoom = 1024;

/**
 * @brief
 * \~english What came out of reading.
 * \~spanish Que salio de leer.
 * \~
 */
enum class EventKind : uint8_t {
    /**
     * \~english
     * Nothing yet: read more from the socket and call again.  It is also what
     * comes back when the answers need flushing first, which the caller tells
     * apart by looking at @c pending -- and has to, because writing more into
     * a full buffer is the one thing that would make this grow.
     * \~spanish
     * Todavia nada: leer mas del socket y volver a llamar.  Es tambien lo que
     * vuelve cuando hay que vaciar antes las respuestas, que quien llama
     * distingue mirando @c pending -- y tiene que hacerlo, porque escribir mas
     * en un buffer lleno es lo unico que haria crecer esto.
     * \~
     */
    None,

    /**
     * \~english
     * A whole request head.  The @c Request is filled and its spans point into
     * the header buffer that was passed in.
     * \~spanish
     * Una cabecera de peticion entera.  El @c Request esta relleno y sus trozos
     * apuntan al buffer de cabeceras que se paso.
     * \~
     */
    Request,

    /// \~english Body bytes for a stream.  \~spanish Bytes de cuerpo de un flujo.  \~
    Body,

    /**
     * \~english
     * One stream is over and the connection carries on.  Whatever was being
     * done for it should stop.
     * \~spanish
     * Un flujo se acabo y la conexion sigue.  Lo que se estuviera haciendo por
     * el deberia parar.
     * \~
     */
    StreamEnded,

    /**
     * \~english
     * The connection is over.  @c error says why, and a GOAWAY has already
     * been written into @c pending -- so the caller flushes and closes rather
     * than closing at once, because a peer that is told why can log it and a
     * peer whose socket simply dies cannot.
     * \~spanish
     * La conexion se acabo.  @c error dice por que, y ya se ha escrito un GOAWAY
     * en @c pending -- asi que quien llama vacia y cierra en vez de cerrar de
     * golpe, porque a un extremo al que se le dice por que puede anotarlo y uno
     * cuyo socket se muere sin mas no puede.
     * \~
     */
    Closed,
};

/**
 * @brief
 * \~english One thing that happened.
 * \~spanish Una cosa que paso.
 * \~
 */
struct Event {
    EventKind kind = EventKind::None;
    uint32_t stream_id = 0;
    ErrorCode error = ErrorCode::NoError;

    /**
     * \~english
     * Whether the peer has now said everything it is going to say on this
     * stream.  It is a field on the event rather than an event of its own
     * because it is a fact the frame already carries: a `GET` is one HEADERS
     * with the flag on it, and turning that into two events would mean
     * remembering, between calls, that a second one is owed -- state kept
     * solely to report something that was already in hand.
     *
     * \~spanish
     * Si el otro extremo ya ha dicho todo lo que iba a decir por este flujo.  Es
     * un campo del suceso y no un suceso propio porque es un hecho que ya lleva
     * la trama: un `GET` es un HEADERS con la bandera puesta, y convertir eso en
     * dos sucesos obligaria a recordar, entre llamada y llamada, que se debe un
     * segundo -- estado guardado solo para contar algo que ya se tenia.
     * \~
     */
    bool ends = false;

    /**
     * \~english
     * For @c Body, where the bytes are.  They point into the caller's own
     * buffer and they stop being valid the moment it is drained -- R13: the
     * body is not copied, so what is handed over is a view and the handler
     * either uses it or keeps its own copy.
     * \~spanish
     * Para @c Body, donde estan los bytes.  Apuntan al buffer de quien llama y
     * dejan de valer en cuanto se vacie -- R13: el cuerpo no se copia, asi que
     * lo que se entrega es una vista y el manejador la usa o se guarda su propia
     * copia.
     * \~
     */
    const uint8_t *data = nullptr;
    size_t size = 0;
};

/**
 * @brief
 * \~english One HTTP/2 connection.
 * \~spanish Una conexion HTTP/2.
 * \~
 */
class Connection {
  public:
    Connection() noexcept = default;

    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    /**
     * @brief
     * \~english Makes it ready, and writes this server's opening SETTINGS.
     * \~spanish La deja lista, y escribe el SETTINGS de apertura de este servidor.
     * \~
     *
     * \~english
     * The SETTINGS goes out BEFORE a byte has been read, which is what the
     * specification requires and is also the only order that makes sense: the
     * peer is allowed to start sending requests the moment it has sent its
     * preface, and every one of them is read under limits it has not been told
     * about yet unless this end spoke first.
     *
     * \~spanish
     * El SETTINGS sale ANTES de haber leido un byte, que es lo que exige la
     * especificacion y es ademas el unico orden que tiene sentido: el otro
     * extremo puede empezar a mandar peticiones en cuanto ha mandado su
     * preambulo, y todas ellas se leen con unos limites de los que todavia no le
     * han hablado si este extremo no habla primero.
     *
     * \~
     * @param limits \~english what this server enforces
     *               \~spanish lo que hace cumplir este servidor  \~
     */
    void reset(const Limits &limits) noexcept;

    /**
     * @brief
     * \~english Reads what there is, and says what happened.
     * \~spanish Lee lo que hay, y dice que paso.
     * \~
     *
     * \~english
     * Called in a loop until it says @c None.  One event per call, because a
     * caller that got a list would have to be given somewhere to put it, and
     * because the body views handed out point into @p v -- which the caller
     * may want to drain between events.
     *
     * \~spanish
     * Se llama en bucle hasta que diga @c None.  Un suceso por llamada, porque
     * a quien recibiera una lista habria que darle donde ponerla, y porque las
     * vistas de cuerpo que se entregan apuntan a @p v -- que quien llama puede
     * querer vaciar entre suceso y suceso.
     *
     * \~
     * @param v       \~english the whole live region of the connection buffer
     *                \~spanish la region viva entera del buffer de la conexion  \~
     * @param headers \~english where decompressed names and values go; the
     *                spans of a @c Request point into it
     *                \~spanish donde van los nombres y valores descomprimidos;
     *                los trozos de un @c Request apuntan ahi  \~
     * @param req     \~english filled when the event is a @c Request
     *                \~spanish se rellena cuando el suceso es un @c Request  \~
     * @return        \~english what happened  \~spanish que paso  \~
     */
    Event read(const View &v, Buffer &headers, http_vx::Request &req) noexcept;

    /**
     * @brief
     * \~english How far into the connection everything has been dealt with.
     * \~spanish Hasta donde de la conexion se ha atendido todo.
     * \~
     *
     * \~english
     * What to hand @c Buffer::consume.  It is the frame reader's number and
     * not this class's, because the frame reader is the one that knows where a
     * frame ENDED as opposed to where it has looked.
     *
     * \~spanish
     * Lo que hay que darle a @c Buffer::consume.  Es el numero del lector de
     * tramas y no de esta clase, porque el lector de tramas es el que sabe
     * donde ACABO una trama en vez de hasta donde ha mirado.
     *
     * \~
     */
    uint64_t consumed() const noexcept { return reader_.consumed(); }

    /**
     * @brief
     * \~english The answers waiting to go out.
     * \~spanish Las respuestas que esperan para salir.
     * \~
     *
     * \~english
     * Written to the socket by the caller, which then says how much left with
     * @c flushed.  Not written from in here, because this layer has no socket
     * -- which is the same reason the parsers take a view instead of reading
     * one, and is what lets the whole of this be tested without opening a
     * port.
     *
     * \~spanish
     * Quien llama las escribe en el socket y luego dice cuantas salieron con
     * @c flushed.  No se escriben desde aqui, porque esta capa no tiene socket
     * -- que es la misma razon por la que los analizadores reciben una vista en
     * vez de leer de uno, y es lo que permite probar todo esto sin abrir un
     * puerto.
     *
     * \~
     */
    const uint8_t *pending() const noexcept { return control_; }

    /// \~english How many bytes are waiting.
    /// \~spanish Cuantos bytes estan esperando.  \~
    size_t pending_size() const noexcept { return control_len_; }

    /**
     * @brief
     * \~english Says @p n bytes of the answers went out.
     * \~spanish Dice que salieron @p n bytes de las respuestas.
     * \~
     *
     * @param n \~english how many  \~spanish cuantos  \~
     */
    void flushed(size_t n) noexcept;

    /**
     * @brief
     * \~english Gives back the window for @p n bytes of body the caller is done with.
     * \~spanish Devuelve la ventana de @p n bytes de cuerpo con los que quien llama acabo.
     * \~
     *
     * \~english
     * Called by whoever consumed the body, and NOT when the body arrived.
     * That difference is the whole of flow control: giving the window back on
     * arrival would say "keep sending" to a peer whose data is piling up
     * unread, which is the same as having no flow control while paying for it.
     *
     * Two WINDOW_UPDATEs go out, one for the stream and one for the
     * connection, because the peer keeps two counts and giving back only one
     * of them stops the connection just as surely -- only later, and for no
     * reason anybody can see.
     *
     * \~spanish
     * Lo llama quien consumio el cuerpo, y NO cuando el cuerpo llego.  Esa
     * diferencia es todo el control de flujo: devolver la ventana al llegar
     * seria decirle "sigue mandando" a un extremo cuyos datos se estan
     * amontonando sin leer, que es lo mismo que no tener control de flujo pero
     * pagandolo.
     *
     * Salen dos WINDOW_UPDATE, uno del flujo y otro de la conexion, porque el
     * otro extremo lleva dos cuentas y devolverle solo una detiene la conexion
     * igual de seguro -- solo que mas tarde, y sin que nadie pueda ver por que.
     *
     * \~
     * @param id \~english which stream  \~spanish que flujo  \~
     * @param n  \~english how many bytes  \~spanish cuantos bytes  \~
     * @return   \~english false if there was no room to say so yet
     *           \~spanish false si todavia no habia sitio para decirlo  \~
     */
    bool release_window(uint32_t id, uint32_t n) noexcept;

    /**
     * @brief
     * \~english Ends stream @p id with @p code.
     * \~spanish Acaba el flujo @p id con @p code.
     * \~
     *
     * @param id   \~english which stream  \~spanish que flujo  \~
     * @param code \~english why  \~spanish por que  \~
     * @return     \~english false if there was no room to say so yet
     *             \~spanish false si todavia no habia sitio para decirlo  \~
     */
    bool reset_stream(uint32_t id, ErrorCode code) noexcept;

    /// \~english What the peer said it would accept.
    /// \~spanish Lo que dijo el otro extremo que aceptaria.  \~
    const Settings &peer() const noexcept { return peer_; }

    /// \~english The streams in flight.  \~spanish Los flujos en vuelo.  \~
    StreamSet &streams() noexcept { return streams_; }

    /// \~english What this end may still send on the connection.
    /// \~spanish Lo que puede mandar todavia este extremo por la conexion.  \~
    Window &send_window() noexcept { return send_; }

    /// \~english The header writer for this connection.
    /// \~spanish El escritor de cabeceras de esta conexion.  \~
    hpack::Encoder &encoder() noexcept { return encoder_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /// \~english Whether @p n more bytes of answer fit.
    /// \~spanish Si caben @p n bytes mas de respuesta.  \~
    bool control_room(size_t n) const noexcept {
        return kControlRoom - control_len_ >= n;
    }

    bool put_frame(FrameType type, uint8_t flags, uint32_t id,
                   const uint8_t *payload, size_t n) noexcept;

    /**
     * @brief
     * \~english Gives the CONNECTION back @p n bytes nobody will ever be handed.
     * \~spanish Devuelve a la CONEXION @p n bytes que no se le van a dar a nadie.
     * \~
     *
     * \~english
     * The other half of flow control, and the half that is easy to leave out
     * because nothing complains about it.  @c release_window is for bytes the
     * caller RECEIVED and finished with; this is for bytes that were charged to
     * the connection and then never reached anybody:
     *
     *  - the padding of a DATA frame, which the reader strips and the peer
     *    counted;
     *  - the whole payload of a frame for a stream that is already over, which
     *    is @c Verdict::Discard -- a frame the peer sent before it could have
     *    known.
     *
     * Neither has a stream to credit: one has no reader and the other has no
     * stream.  So only the connection's window moves, and it moves here rather
     * than being left for a caller that has not been told the bytes existed.
     *
     * A server that skipped this would lose a little allowance on every padded
     * or discarded frame and stop for good after enough of them, with neither
     * end able to say why -- which is the exact failure the stream table's own
     * notes describe and then do not prevent.
     *
     * \~spanish
     * La otra mitad del control de flujo, y la que es facil dejarse porque no se
     * queja nadie.  @c release_window es para bytes que quien llama RECIBIO y con
     * los que acabo; esto es para bytes que se le cobraron a la conexion y no
     * llegaron nunca a nadie:
     *
     *  - el relleno de una trama DATA, que el lector quita y el otro extremo
     *    conto;
     *  - la carga entera de una trama de un flujo ya terminado, que es
     *    @c Verdict::Discard -- una trama que el otro mando antes de poder
     *    saberlo.
     *
     * Ninguno de los dos tiene flujo al que abonar: uno no tiene lector y el otro
     * no tiene flujo.  Asi que solo se mueve la ventana de la conexion, y se
     * mueve aqui y no se le deja a quien llama, que no se ha enterado de que esos
     * bytes existieran.
     *
     * Un servidor que se saltara esto perderia un poco de credito en cada trama
     * rellenada o descartada y se pararia para siempre despues de bastantes, sin
     * que ninguno de los dos extremos supiera decir por que -- que es justo el
     * fallo que describen las notas de la tabla de flujos y luego no evitan.
     *
     * \~
     * @param n \~english how many bytes  \~spanish cuantos bytes  \~
     * @return  \~english false if there was no room to say so yet
     *          \~spanish false si todavia no habia sitio para decirlo  \~
     */
    bool credit_connection(uint32_t n) noexcept;

    Event fail(ErrorCode code) noexcept;
    Event on_settings(const View &v) noexcept;
    Event on_ping(const View &v) noexcept;
    Event on_window_update(const View &v) noexcept;
    Event on_headers(const View &v, Buffer &headers,
                     http_vx::Request &req) noexcept;

    FrameReader reader_;
    hpack::Decoder decoder_;
    hpack::Encoder encoder_;
    StreamSet streams_;

    Limits limits_;
    Settings peer_;

    /// \~english What this end may still send, and what the peer may.
    /// \~spanish Lo que puede mandar todavia este extremo, y lo que el otro.  \~
    Window send_;
    Window recv_;

    /**
     * \~english
     * Where a header block that the peer SPLIT gets joined back together.
     *
     * The ordinary case never touches it: a block that arrives as one HEADERS
     * is decoded straight out of the connection buffer, because it is already
     * contiguous.  It is only when the peer sends CONTINUATIONs that the
     * pieces have to be put next to each other, and that is the peer's choice
     * rather than this end's -- so the copy is paid by the connection that
     * asked for it, and the lazy allocation means the ones that never do never
     * pay for the room either.
     *
     * \~spanish
     * Donde se vuelve a juntar un bloque de cabeceras que el otro extremo
     * PARTIO.
     *
     * El caso corriente no lo toca: un bloque que llega como un solo HEADERS se
     * descodifica directamente del buffer de la conexion, porque ya esta
     * seguido.  Solo cuando el otro extremo manda CONTINUATIONs hay que poner
     * los pedazos uno al lado del otro, y eso lo eligio el otro y no este -- asi
     * que la copia la paga la conexion que la pidio, y como se reserva tarde las
     * que no lo hacen nunca tampoco pagan el sitio.
     * \~
     */
    Buffer block_;

    /**
     * \~english
     * What the HEADERS that began the open block said.  They are kept here
     * because a block may end on a CONTINUATION, and a CONTINUATION says
     * neither of them: `END_STREAM` has no place on one, and the stream is
     * only implied.  Reading them off whatever frame happens to be in hand
     * when the block ends would answer for the wrong frame.
     * \~spanish
     * Lo que dijo el HEADERS que empezo el bloque abierto.  Se guardan aqui
     * porque un bloque puede acabar en una CONTINUATION, y una CONTINUATION no
     * dice ninguna de las dos cosas: `END_STREAM` no tiene sitio en ella, y el
     * flujo solo esta implicito.  Leerlas de la trama que toque tener cuando
     * acaba el bloque seria contestar por la trama equivocada.
     * \~
     */
    uint32_t block_stream_ = 0;
    bool block_ends_ = false;

    /// \~english Why the stream was refused, if it was.
    /// \~spanish Por que se rechazo el flujo, si se rechazo.  \~
    ErrorCode block_refused_ = ErrorCode::NoError;

    uint8_t control_[kControlRoom] = {};
    size_t control_len_ = 0;

    bool closed_ = false;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_CONNECTION_H
