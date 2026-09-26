/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_stream.h
 * @brief
 * \~english The requests in flight on one connection, and what may still happen.
 * \~spanish Las peticiones en vuelo de una conexion, y que puede pasar todavia.
 * \~
 *
 * \~english
 * This is where a header block stops being a thing on its own and becomes a
 * request inside a connection that is carrying hundreds of others.
 *
 * **The rule that holds it all up is that identifiers only go up.**  A client
 * numbers its requests 1, 3, 5, and never reuses or goes back.  It reads like
 * bookkeeping and it is the single thing that makes this cheap AND safe:
 *
 *  - CHEAP, because a connection that has served a million requests remembers
 *    ONE number.  A stream that has finished is forgotten entirely, and a
 *    frame that names an identifier below the highest seen but is not in the
 *    table is a frame for a stream that finished -- which is a different
 *    answer from "a stream that never existed", and it can be told apart
 *    without keeping a list of every identifier ever used;
 *  - SAFE, because reuse is what lets two requests be confused for each other.
 *    It is the same failure HTTP/1.1 has when a body length is ambiguous --
 *    two ends disagreeing about where one request ends and the next begins --
 *    and here the defence is that the number never comes round again.
 *
 * **And a stream that is over still costs something.**  When this end refuses
 * a stream, frames the peer already sent are still on their way, and they will
 * arrive after the refusal.  They must not be acted on -- and they MUST still
 * be counted against the connection's flow-control window, because the peer
 * counted them when it sent them.  A server that quietly dropped them would
 * lose a little window on every reset stream, and after enough of them the
 * connection would stop for good with neither end able to say why.  That is
 * what @c Verdict::Discard is for, and it is the reason a verdict is not just
 * "yes or no".
 *
 * Which finished streams get that treatment depends on who ended them, and
 * that is the one thing the highest identifier cannot say: frames on a
 * stream THIS end reset are late, frames on one that closed any other way
 * were sent by a peer that knew (RFC 9113, 5.1).  @c RecentStreams keeps that
 * much for the last few hundred identifiers, in a fixed ring.
 *
 * \~spanish
 * Aqui es donde un bloque de cabeceras deja de ser una cosa suelta y pasa a ser
 * una peticion dentro de una conexion que lleva otras cientos.
 *
 * **La regla que sujeta todo esto es que los identificadores solo suben.**  Un
 * cliente numera sus peticiones 1, 3, 5, y no reutiliza ni vuelve atras.  Se
 * lee como contabilidad y es lo unico que hace esto barato Y seguro:
 *
 *  - BARATO, porque una conexion que ha servido un millon de peticiones
 *    recuerda UN numero.  Un flujo terminado se olvida del todo, y una trama
 *    que nombra un identificador por debajo del mayor visto y no esta en la
 *    tabla es una trama de un flujo que termino -- que es una respuesta
 *    distinta de "un flujo que no existio nunca", y se distingue sin guardar
 *    una lista de todos los identificadores usados;
 *  - SEGURO, porque reutilizar es lo que permite confundir dos peticiones.  Es
 *    el mismo fallo que tiene HTTP/1.1 cuando la longitud de un cuerpo es
 *    ambigua -- dos extremos discrepando sobre donde acaba una peticion y
 *    empieza la siguiente -- y aqui la defensa es que el numero no vuelve a
 *    salir nunca.
 *
 * **Y un flujo terminado sigue costando algo.**  Cuando este extremo rechaza un
 * flujo, las tramas que el otro ya mando siguen de camino, y llegaran despues
 * del rechazo.  No se pueden atender -- y SI hay que contarlas contra la
 * ventana de control de flujo de la conexion, porque el otro extremo las conto
 * al mandarlas.  Un servidor que las tirara por lo bajo perderia un poco de
 * ventana en cada flujo abortado, y despues de bastantes la conexion se pararia
 * para siempre sin que ninguno de los dos supiera decir por que.  Para eso esta
 * @c Verdict::Discard, y es la razon de que un veredicto no sea solo "si o no".
 *
 * Que flujos terminados reciben ese trato depende de quien los acabo, y eso es
 * lo unico que no puede decir el identificador mayor: las tramas de un flujo
 * que reinicio ESTE extremo llegan tarde, las de uno que se cerro de otra forma
 * las mando un extremo que lo sabia (RFC 9113, 5.1).  @c RecentStreams guarda
 * eso de los ultimos cientos de identificadores, en un anillo fijo.
 *
 * \~
 */
#ifndef HTTP_VX_H2_STREAM_H
#define HTTP_VX_H2_STREAM_H

#include "http_vx/h2_flow.h"
#include "http_vx/h2_limits.h"
#include "http_vx/h2_recent.h"
#include "http_vx/h2_settings.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english Where a stream is in its life.
 * \~spanish En que punto de su vida esta un flujo.
 * \~
 *
 * \~english
 * RFC 9113 draws seven states and two of them cannot happen here.  Both
 * reserved states exist for a pushed response, and this server does not push
 * and announces that it does not -- so a connection that reached one of them
 * would be a connection where a PUSH_PROMISE got past the frame layer, which
 * is a different bug from anything this enum could describe.
 *
 * They are left out rather than added and never reached.  A state nothing can
 * put a stream into is a branch nothing can test, and a branch nothing can
 * test is where the next mistake goes to hide.
 *
 * \~spanish
 * El RFC 9113 dibuja siete estados y dos de ellos aqui no pueden darse.  Los
 * dos estados reservados existen para una respuesta empujada, y este servidor
 * no empuja y ademas lo anuncia -- asi que una conexion que llegara a uno de
 * ellos seria una donde un PUSH_PROMISE se colo por la capa de tramas, que es
 * un fallo distinto de cualquier cosa que pudiera describir este enum.
 *
 * Se dejan fuera en vez de ponerlos y no llegar nunca.  Un estado al que nada
 * puede llevar un flujo es una rama que nada puede probar, y una rama que nada
 * puede probar es donde se esconde la equivocacion siguiente.
 *
 * \~
 */
enum class StreamState : uint8_t {
    /// \~english Both ends are still talking.  \~spanish Los dos extremos siguen hablando.  \~
    Open,

    /**
     * \~english
     * The peer has said everything it is going to say, and this end has not
     * finished answering.  The ordinary state of a `GET` being served.
     * \~spanish
     * El otro extremo ya ha dicho todo lo que iba a decir, y este todavia no ha
     * acabado de contestar.  El estado corriente de un `GET` que se esta
     * sirviendo.
     * \~
     */
    HalfClosedRemote,

    /**
     * \~english
     * This end has finished answering and the peer has not finished asking --
     * a response sent before the whole request body arrived, which is legal
     * and is how a server refuses a large upload without reading it.
     * \~spanish
     * Este extremo ha acabado de contestar y el otro no ha acabado de preguntar
     * -- una respuesta mandada antes de que llegara el cuerpo entero, que es
     * legal y es como un servidor rechaza una subida grande sin leerla.
     * \~
     */
    HalfClosedLocal,

    /**
     * \~english
     * Over.  A stream in this state is not kept: it is forgotten, and what
     * remembers it is the highest identifier seen -- and, for the recent
     * ones, how it ended (@c RecentStreams).
     * \~spanish
     * Terminado.  Un flujo en este estado no se guarda: se olvida, y lo que se
     * acuerda de el es el identificador mayor visto -- y, de los recientes,
     * como acabo (@c RecentStreams).
     * \~
     */
    Closed,
};

/**
 * @brief
 * \~english What is to be done with a frame that arrived.
 * \~spanish Que hay que hacer con una trama que ha llegado.
 * \~
 */
enum class Verdict : uint8_t {
    /// \~english Act on it.  \~spanish Atenderla.  \~
    Accept,

    /**
     * \~english
     * Do not act on it, and do not treat it as an error either: it is a frame
     * the peer sent before it could have known, and it must still be counted
     * against the connection window.  Dropping it without counting is how a
     * connection quietly runs out of allowance and stops.
     * \~spanish
     * No atenderla, y tampoco tratarla como un error: es una trama que el otro
     * extremo mando antes de poder saberlo, y hay que contarla igual contra la
     * ventana de la conexion.  Tirarla sin contarla es como una conexion se
     * queda sin credito por lo bajo y se para.
     * \~
     */
    Discard,

    /**
     * \~english
     * This stream is finished with an error and the connection carries on.
     * The distinction from the one below is the whole difference between one
     * request failing and every request on the connection failing.
     * \~spanish
     * Este flujo se acaba con un error y la conexion sigue.  La distincion con
     * el de abajo es toda la diferencia entre que falle una peticion y que
     * fallen todas las de la conexion.
     * \~
     */
    StreamError,

    /// \~english The connection cannot go on.
    /// \~spanish La conexion no puede seguir.  \~
    ConnectionError,
};

/**
 * @brief
 * \~english What a frame turned out to mean.
 * \~spanish En que quedo una trama.
 * \~
 */
struct Outcome {
    Verdict verdict = Verdict::Accept;
    ErrorCode error = ErrorCode::NoError;

    /// \~english Which rule a @c StreamError or @c ConnectionError broke; null for @c Accept and @c Discard.
    /// \~spanish Que regla rompio un @c StreamError o un @c ConnectionError; nulo para @c Accept y @c Discard.  \~
    const char *why = nullptr;
};

/**
 * @brief
 * \~english One request in flight.
 * \~spanish Una peticion en vuelo.
 * \~
 *
 * \~english
 * Twenty-four bytes, and it is worth saying why the shape matters: there is one
 * of these per concurrent request, and the reactor walks them.  R17 says the
 * state the loop touches every time round goes in a dense array; this is that
 * array's element, so what belongs here is what the loop needs and nothing it
 * only wants when something has gone wrong.
 *
 * It was sixteen until the content length came in, and the eight bytes it
 * costs are loop state and not error state: every DATA frame of a request
 * that declared a length is counted against it, as it arrives (RFC 9113,
 * 8.1.1).
 *
 * \~spanish
 * Veinticuatro bytes, y merece decirse por que importa la forma: hay uno de
 * estos por peticion concurrente, y el reactor los recorre.  La R17 dice que el
 * estado que toca el bucle cada vuelta va en un array denso; esto es el
 * elemento de ese array, asi que aqui va lo que necesita el bucle y nada de lo
 * que solo quiere cuando algo ha ido mal.
 *
 * Eran dieciseis hasta que entro la longitud de contenido, y los ocho bytes que
 * cuesta son estado del bucle y no de error: cada trama DATA de una peticion
 * que declaro una longitud se cuenta contra ella, segun llega (RFC 9113,
 * 8.1.1).
 *
 * \~
 */
struct Stream {
    uint32_t id;

    /// \~english What this end may still send on it.
    /// \~spanish Lo que este extremo puede mandar todavia por el.  \~
    Window send;

    /// \~english What the peer may still send on it.
    /// \~spanish Lo que el otro extremo puede mandar todavia por el.  \~
    Window recv;

    StreamState state;

    /// \~english Whether the request declared a content length.
    /// \~spanish Si la peticion declaro una longitud de contenido.  \~
    bool counted;

    uint8_t _pad[2];

    /// \~english How much content is still owed, when @c counted.
    /// \~spanish Cuanto contenido se debe todavia, cuando @c counted.  \~
    uint64_t content_left;
};

static_assert(sizeof(Stream) == 24, "a stream is meant to be twenty-four bytes");

/**
 * @brief
 * \~english The streams of one connection.
 * \~spanish Los flujos de una conexion.
 * \~
 */
class StreamSet {
  public:
    StreamSet() noexcept = default;
    ~StreamSet();

    StreamSet(const StreamSet &) = delete;
    StreamSet &operator=(const StreamSet &) = delete;

    /**
     * @brief
     * \~english Makes it ready for a connection with these @p limits.
     * \~spanish Lo deja listo para una conexion con estos @p limits.
     * \~
     *
     * \~english
     * Nothing is allocated here.  A connection that never gets a request --
     * which is most of them, most of the time, at the scale this is built for
     * -- never needs the table, and R1 says an idle connection has no buffer.
     * The same decision the header table makes, for the same reason.
     *
     * \~spanish
     * Aqui no se reserva nada.  Una conexion que no recibe ninguna peticion --
     * que son la mayoria, la mayor parte del tiempo, a la escala para la que
     * esta hecho esto -- no necesita la tabla nunca, y la R1 dice que una
     * conexion parada no tiene buffer.  La misma decision que toma la tabla de
     * cabeceras, por la misma razon.
     *
     * \~
     * @param limits \~english what this server enforces
     *               \~spanish lo que hace cumplir este servidor  \~
     */
    void reset(const Limits &limits) noexcept;

    /**
     * @brief
     * \~english Says what the peer will accept, for the streams opened from now on.
     * \~spanish Dice lo que aceptara el otro extremo, para los flujos que se abran.
     * \~
     *
     * \~english
     * Only the ones opened LATER.  Changing what the existing ones may send is
     * @c adjust_send_windows, and they are separate because they are separate
     * events: this one is what a new stream starts at, and that one moves
     * streams that are already running.  A peer's SETTINGS does both, and an
     * implementation that did only one of them would be out of step with its
     * peer in a way that shows up as a stall much later.
     *
     * \~spanish
     * Solo los que se abran DESPUES.  Cambiar lo que pueden mandar los que ya
     * existen es @c adjust_send_windows, y estan aparte porque son sucesos
     * aparte: este es en cuanto empieza un flujo nuevo, y aquel mueve flujos que
     * ya estan corriendo.  El SETTINGS de un extremo hace las dos cosas, y una
     * implementacion que hiciera solo una se quedaria desacompasada con su
     * extremo de una forma que sale como un atasco mucho despues.
     *
     * \~
     * @param n \~english the peer's initial window
     *          \~spanish la ventana inicial del otro extremo  \~
     */
    void set_peer_initial_window(uint32_t n) noexcept { peer_initial_ = n; }

    /**
     * @brief
     * \~english Moves what every open stream may send, by @p delta.
     * \~spanish Mueve lo que puede mandar cada flujo abierto, @p delta.
     * \~
     *
     * \~english
     * The retroactive half of a changed initial window, and the one that can
     * leave a stream in debt -- see @c Window::adjust.  It touches the send
     * side only: the peer's setting says what the PEER will accept, and what
     * this end will accept is this end's setting and not the peer's to change.
     *
     * \~spanish
     * La mitad retroactiva de una ventana inicial cambiada, y la que puede
     * dejar un flujo en deuda -- ver @c Window::adjust.  Toca solo el lado de
     * mandar: el ajuste del otro extremo dice lo que acepta EL OTRO, y lo que
     * acepta este es el ajuste de este y no le toca cambiarlo al otro.
     *
     * \~
     * @param delta \~english how far, either way
     *              \~spanish cuanto, en cualquier sentido  \~
     * @return      \~english @c NoError, or the first stream that could not take it
     *              \~spanish @c NoError, o el primer flujo que no pudo con ello  \~
     */
    ErrorCode adjust_send_windows(int64_t delta) noexcept;

    /**
     * @brief
     * \~english What a HEADERS on @p id means.
     * \~spanish Que significa un HEADERS sobre @p id.
     * \~
     *
     * \~english
     * Three refusals, and each says something different about the peer:
     *
     *  - an EVEN identifier, or zero, is a client numbering its requests the
     *    server's way.  Connection error: the two ends disagree about who
     *    opens what, and nothing after it can be trusted to mean what it says;
     *  - an identifier at or below the highest already seen is either a reused
     *    number or one out of order, and both are the shape of a request being
     *    confused for another.  Connection error for the same reason;
     *  - one TOO MANY is not an error at all in the same sense -- the peer did
     *    nothing wrong, it just asked for more at once than this server holds.
     *    It is a STREAM error with @c RefusedStream, which is the one code that
     *    tells a client the request may simply be sent again.  Answering it
     *    with a connection error would turn a busy moment into a dropped
     *    connection.
     *
     * The second one has three exceptions, because an identifier at or below
     * the highest that is not in the table belongs to a stream that is over,
     * and how it ended decides (RFC 9113, 5.1): one THIS end reset is
     * @c Discard -- the peer sent the HEADERS before it read the reset, and
     * the block is still decoded by the caller; one that closed any other way
     * is a connection error, @c StreamClosed; one never opened at all is the
     * reuse above, @c ProtocolError (5.1.1).
     *
     * \~spanish
     * Tres rechazos, y cada uno dice algo distinto del otro extremo:
     *
     *  - un identificador PAR, o el cero, es un cliente numerando sus peticiones
     *    como las numera el servidor.  Error de CONEXION: los dos extremos
     *    discrepan sobre quien abre que, y nada de lo que venga detras se puede
     *    dar por lo que dice;
     *  - un identificador igual o menor que el mayor ya visto es un numero
     *    reutilizado o uno fuera de orden, y los dos tienen la forma de una
     *    peticion que se confunde con otra.  Error de conexion por lo mismo;
     *  - uno DE MAS no es un error en ese mismo sentido -- el otro extremo no ha
     *    hecho nada mal, solo ha pedido mas a la vez de lo que guarda este
     *    servidor.  Es un error de FLUJO con @c RefusedStream, que es el unico
     *    codigo que le dice a un cliente que puede volver a mandar la peticion
     *    tal cual.  Contestarlo con un error de conexion convertiria un momento
     *    de mucho trabajo en una conexion caida.
     *
     * El segundo tiene tres excepciones, porque un identificador igual o por
     * debajo del mayor que no esta en la tabla es de un flujo que se acabo, y
     * decide como acabo (RFC 9113, 5.1): uno que reinicio ESTE extremo es
     * @c Discard -- el otro mando el HEADERS antes de leer el reinicio, y quien
     * llama descodifica el bloque igual --; uno que se cerro de otra forma es
     * un error de conexion, @c StreamClosed; uno que no se abrio nunca es la
     * reutilizacion de arriba, @c ProtocolError (5.1.1).
     *
     * \~
     * @param id         \~english the identifier  \~spanish el identificador  \~
     * @param end_stream \~english whether the peer said it was done
     *                   \~spanish si el otro extremo dijo que habia acabado  \~
     * @return           \~english what to do  \~spanish que hacer  \~
     */
    Outcome open(uint32_t id, bool end_stream) noexcept;

    /**
     * @brief
     * \~english What a DATA of @p len on @p id means.
     * \~spanish Que significa un DATA de @p len sobre @p id.
     * \~
     *
     * \~english
     * The length is the WHOLE payload, padding included.  Padding is not free:
     * the peer spent window on it, so this end must spend the same or the two
     * stop agreeing -- and a sender that padded heavily would otherwise be
     * given back more allowance than it used.
     *
     * The connection window is NOT touched here.  It belongs to the
     * connection and not to this set, and a frame that this refuses still owes
     * it -- which is the point of @c Verdict::Discard and would be lost if the
     * two were spent in the same place.
     *
     * A DATA on a stream that is over is @c Discard only when THIS end reset
     * the stream (or it is too old to know): the peer sent it before it could
     * have known.  On a stream that closed any other way the peer DID know,
     * and it is a connection error, @c StreamClosed (RFC 9113, 5.1).
     *
     * \~spanish
     * La longitud es la carga ENTERA, relleno incluido.  El relleno no es
     * gratis: el otro extremo gasto ventana en el, asi que este tiene que gastar
     * lo mismo o los dos dejan de estar de acuerdo -- y a quien rellenara mucho
     * se le estaria devolviendo si no mas credito del que uso.
     *
     * La ventana de la CONEXION no se toca aqui.  Es de la conexion y no de este
     * conjunto, y una trama que esto rechace se la debe igual -- que es de lo
     * que va @c Verdict::Discard y se perderia si las dos se gastaran en el
     * mismo sitio.
     *
     * Un DATA de un flujo terminado es @c Discard solo cuando el flujo lo
     * reinicio ESTE extremo (o es demasiado viejo para saberlo): el otro lo
     * mando antes de poder saberlo.  En un flujo que se cerro de otra forma el
     * otro SI lo sabia, y es un error de conexion, @c StreamClosed (RFC 9113,
     * 5.1).
     *
     * \~english
     * The CONTENT is a different number, and it is the one a declared
     * content length is compared with: the sum of what the frames carry,
     * padding NOT included, has to come to exactly what the request said
     * (RFC 9113, 8.1.1).  Too much is refused on the frame that crosses the
     * line, not at the end; too little is refused on the frame that ends the
     * stream.  Either one is a malformed request: a stream error,
     * @c ProtocolError.
     *
     * \~spanish
     * El CONTENIDO es otro numero, y es con el que se compara una longitud de
     * contenido declarada: la suma de lo que llevan las tramas, relleno NO
     * incluido, tiene que llegar exactamente a lo que dijo la peticion (RFC
     * 9113, 8.1.1).  Lo que sobra se rechaza en la trama que pasa de la raya, no
     * al final; lo que falta se rechaza en la trama que acaba el flujo.
     * Cualquiera de los dos es una peticion mal formada: error de flujo,
     * @c ProtocolError.
     *
     * \~
     * @param id         \~english the identifier  \~spanish el identificador  \~
     * @param len        \~english the whole payload's length
     *                   \~spanish la longitud de la carga entera  \~
     * @param content    \~english how much of it is content, padding taken off
     *                   \~spanish cuanto de ella es contenido, quitado el relleno  \~
     * @param end_stream \~english whether it is the last
     *                   \~spanish si es la ultima  \~
     * @return           \~english what to do  \~spanish que hacer  \~
     */
    Outcome on_data(uint32_t id, uint32_t len, uint32_t content,
                    bool end_stream) noexcept;

    /**
     * @brief
     * \~english Records the content length the request on @p id declared.
     * \~spanish Apunta la longitud de contenido que declaro la peticion de @p id.
     * \~
     *
     * \~english
     * Called once the header block that opened the stream has been read,
     * because that is the first moment the length is known.  A request whose
     * HEADERS already ended the stream has no content at all, so a length
     * other than zero is refused here and not left for a DATA frame that is
     * never coming (RFC 9113, 8.1.1).
     *
     * \~spanish
     * Se llama una vez leido el bloque de cabeceras que abrio el flujo, porque
     * ese es el primer momento en que se conoce la longitud.  Una peticion cuyo
     * HEADERS ya acabo el flujo no tiene contenido ninguno, asi que una longitud
     * distinta de cero se rechaza aqui y no se deja para una trama DATA que no
     * va a llegar (RFC 9113, 8.1.1).
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @param n  \~english the length declared  \~spanish la longitud declarada  \~
     * @return   \~english what to do  \~spanish que hacer  \~
     */
    Outcome expect_content(uint32_t id, uint64_t n) noexcept;

    /**
     * @brief
     * \~english What a second HEADERS on @p id, the trailer section, means.
     * \~spanish Que significa un segundo HEADERS sobre @p id, la seccion de remolques.
     * \~
     *
     * \~english
     * Asked only for a stream still in the table; one that is not is a
     * question for @c open.  Three refusals, all stream errors:
     *
     *  - the peer had already ended the stream: @c StreamClosed (RFC 9113,
     *    5.1, half-closed (remote));
     *  - the HEADERS does not carry END_STREAM: the trailer section is the
     *    last thing on a request, so one that does not end it is malformed,
     *    @c ProtocolError (RFC 9113, 8.1);
     *  - the content that arrived is less than the length declared: the
     *    trailers end the stream, and with it the content, @c ProtocolError
     *    (RFC 9113, 8.1.1).
     *
     * An accepted one ends the stream the way a DATA with END_STREAM would.
     *
     * \~spanish
     * Solo se pregunta por un flujo que sigue en la tabla; uno que no esta es
     * una pregunta para @c open.  Tres rechazos, todos errores de flujo:
     *
     *  - el otro extremo ya habia acabado el flujo: @c StreamClosed (RFC 9113,
     *    5.1, half-closed (remote));
     *  - el HEADERS no lleva END_STREAM: la seccion de remolques es lo ultimo de
     *    una peticion, asi que una que no la acaba esta mal formada,
     *    @c ProtocolError (RFC 9113, 8.1);
     *  - el contenido que llego es menos que la longitud declarada: los
     *    remolques acaban el flujo, y con el el contenido, @c ProtocolError
     *    (RFC 9113, 8.1.1).
     *
     * Uno aceptado acaba el flujo como lo acabaria un DATA con END_STREAM.
     *
     * \~
     * @param id         \~english the identifier  \~spanish el identificador  \~
     * @param end_stream \~english whether the HEADERS carries END_STREAM
     *                   \~spanish si el HEADERS lleva END_STREAM  \~
     * @return           \~english what to do  \~spanish que hacer  \~
     */
    Outcome on_trailers(uint32_t id, bool end_stream) noexcept;

    /**
     * @brief
     * \~english What a RST_STREAM on @p id means.
     * \~spanish Que significa un RST_STREAM sobre @p id.
     * \~
     *
     * \~english
     * The stream ends and the connection does not care why.  A reset for a
     * stream that has already finished is not an error: it is the other end's
     * reset crossing this end's, which happens on any connection where both
     * sides may give up at once.
     *
     * \~spanish
     * El flujo se acaba y a la conexion le da igual por que.  Un reinicio de un
     * flujo ya terminado no es un error: es el reinicio del otro extremo
     * cruzandose con el de este, que pasa en cualquier conexion donde los dos
     * lados pueden rendirse a la vez.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @return   \~english what to do  \~spanish que hacer  \~
     */
    Outcome on_reset(uint32_t id) noexcept;

    /**
     * @brief
     * \~english Says THIS end sent RST_STREAM on @p id.
     * \~spanish Dice que ESTE extremo mando RST_STREAM por @p id.
     * \~
     *
     * \~english
     * Not the same as @c on_reset, and the difference is the whole of RFC
     * 9113, 5.1 on closed streams: after the peer's reset, it knows the stream
     * is over; after this end's, it may still send anything, and whatever it
     * sends is late rather than wrong.  So the stream is forgotten here as
     * there, and the fact that this end ended it is kept.
     *
     * \~spanish
     * No es lo mismo que @c on_reset, y la diferencia es todo el RFC 9113, 5.1
     * sobre flujos cerrados: despues del reinicio del otro, el otro sabe que el
     * flujo se acabo; despues del de este, puede seguir mandando cualquier
     * cosa, y lo que mande llega tarde y no mal.  Asi que el flujo se olvida
     * aqui igual que alli, y se guarda que lo acabo este extremo.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     */
    void on_reset_sent(uint32_t id) noexcept;

    /**
     * @brief
     * \~english Whether @p id names a stream the peer never opened: above the highest, or even.
     * \~spanish Si @p id nombra un flujo que el otro no abrio nunca: por encima del mayor, o par.
     * \~
     *
     * \~english
     * An even identifier is the server's to open, and this server opens none,
     * so it is idle whatever the highest is (RFC 9113, 5.1.1).
     * \~spanish
     * Un identificador par lo abre el servidor, y este no abre ninguno, asi que
     * esta inactivo sea cual sea el mayor (RFC 9113, 5.1.1).
     * \~
     * @param id \~english a nonzero identifier  \~spanish un identificador distinto de cero  \~
     * @return   \~english whether it is idle  \~spanish si esta inactivo  \~
     */
    bool never_opened(uint32_t id) const noexcept {
        return id > highest_ || (id & 1) == 0;
    }

    /**
     * @brief
     * \~english Says this end has finished answering on @p id.
     * \~spanish Dice que este extremo ha acabado de contestar por @p id.
     * \~
     *
     * \~english
     * Called when the response's last frame goes out.  It is what finally
     * forgets the stream when the peer had already finished, and forgetting is
     * what keeps a long-lived connection's memory flat.
     *
     * \~spanish
     * Se llama cuando sale la ultima trama de la respuesta.  Es lo que olvida al
     * fin el flujo cuando el otro extremo ya habia acabado, y olvidar es lo que
     * mantiene plana la memoria de una conexion larga.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     */
    void finish(uint32_t id) noexcept;

    /**
     * @brief
     * \~english The stream with @p id, or null if it is not open.
     * \~spanish El flujo con @p id, o nulo si no esta abierto.
     * \~
     *
     * \~english
     * Found by walking.  At a hundred and twenty-eight sixteen-byte entries
     * the whole table is two kilobytes and a walk is thirty-two cache lines
     * read in order, which a prefetcher does for free; a hash over the same
     * numbers would be a lookup that jumps.  The project's rule about
     * contiguous arrays over node-based containers is not about elegance, it
     * is this.
     *
     * \~spanish
     * Se encuentra recorriendo.  A ciento veintiocho entradas de dieciseis bytes
     * la tabla entera son dos kilobytes y un recorrido son treinta y dos lineas
     * de cache leidas en orden, que el precargador hace gratis; un hash sobre
     * los mismos numeros seria una busqueda que salta.  La regla del proyecto
     * sobre arrays contiguos frente a contenedores de nodos no va de elegancia,
     * va de esto.
     *
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @return   \~english the stream, or null  \~spanish el flujo, o nulo  \~
     */
    Stream *find(uint32_t id) noexcept;

    /// \~english How many are open.  \~spanish Cuantos hay abiertos.  \~
    size_t count() const noexcept { return count_; }

    /// \~english The largest identifier the peer has used.
    /// \~spanish El identificador mayor que ha usado el otro extremo.  \~
    uint32_t highest_seen() const noexcept { return highest_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /// \~english Makes the table, the first time it is needed.
    /// \~spanish Hace la tabla, la primera vez que hace falta.  \~
    [[gnu::noinline, gnu::cold]] bool make_room() noexcept;

    /// \~english Forgets the one at @p i.  \~spanish Olvida el de @p i.  \~
    void drop(size_t i) noexcept;

    /// \~english The peer has finished on @p s: half-closed, or forgotten if this end had too.
    /// \~spanish El otro extremo acabo en @p s: medio cerrado, u olvidado si este tambien.  \~
    void end_remote(Stream *s) noexcept;

    /// \~english What a HEADERS on @p id, at or below the highest and not in the table, means.
    /// \~spanish Que significa un HEADERS sobre @p id, igual o por debajo del mayor y fuera de la tabla.  \~
    Outcome headers_on_closed(uint32_t id) noexcept;

    Stream *streams_ = nullptr;
    size_t cap_ = 0;
    size_t count_ = 0;

    uint32_t highest_ = 0;
    uint32_t max_streams_ = 128;
    uint32_t own_initial_ = 65535;
    uint32_t peer_initial_ = 65535;

    /// \~english How the recent streams ended.  \~spanish Como acabaron los flujos recientes.  \~
    RecentStreams recent_;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_STREAM_H
