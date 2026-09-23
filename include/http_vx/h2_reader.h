/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_reader.h
 * @brief
 * \~english Reading frames off a connection, one at a time and whole.
 * \~spanish Leer tramas de una conexion, de una en una y enteras.
 * \~
 *
 * \~english
 * **A frame is delivered whole, and that is the opposite of what the HTTP/1.1
 * body reader does.**  The difference is worth stating because it looks like
 * an inconsistency and is not.
 *
 * In HTTP/1.1 a body has no bound the recipient agreed to: the sender says how
 * long it is, or does not, and either way the number is the sender's.  So a
 * body is handed over in pieces as it arrives, because holding one whole means
 * holding whatever the sender chose.
 *
 * In HTTP/2 a frame cannot be larger than `SETTINGS_MAX_FRAME_SIZE`, which is
 * a number THIS SERVER announced -- sixteen kilobytes unless it said
 * otherwise.  A frame too big is refused from its header, before its payload
 * is read.  So waiting for a whole frame costs a bound this server chose, and
 * in exchange everything downstream gets a complete unit rather than a
 * fragment it has to reassemble.
 *
 * The streaming has not gone anywhere: a body is a SEQUENCE of DATA frames,
 * and they are delivered one at a time.  What moved is where the boundary is
 * -- from "however much arrived in this read" to "one frame" -- and a boundary
 * both ends agree on is worth more than a boundary that is whatever the
 * network did.
 *
 * \~spanish
 * **Una trama se entrega entera, y eso es lo contrario de lo que hace el lector
 * de cuerpo de HTTP/1.1.**  La diferencia merece decirse porque parece una
 * incoherencia y no lo es.
 *
 * En HTTP/1.1 un cuerpo no tiene ninguna cota que quien recibe haya aceptado:
 * quien envia dice cuanto mide, o no lo dice, y en cualquier caso el numero es
 * suyo.  Asi que un cuerpo se entrega a pedazos segun llega, porque tener uno
 * entero es tener lo que eligiera quien envia.
 *
 * En HTTP/2 una trama no puede ser mayor que `SETTINGS_MAX_FRAME_SIZE`, que es
 * un numero que anuncio ESTE SERVIDOR -- dieciseis kilobytes salvo que dijera
 * otra cosa --.  Una trama demasiado grande se rechaza desde su cabecera, antes
 * de leer su carga.  Asi que esperar a una trama entera cuesta una cota que
 * eligio este servidor, y a cambio todo lo de mas abajo recibe una unidad
 * completa y no un fragmento que tenga que recomponer.
 *
 * El flujo no se ha ido a ninguna parte: un cuerpo es una SUCESION de tramas
 * DATA, y se entregan de una en una.  Lo que se ha movido es donde esta la
 * frontera -- de "lo que llegara en esta lectura" a "una trama" -- y una
 * frontera en la que los dos extremos estan de acuerdo vale mas que una que sea
 * lo que hiciera la red.
 *
 * \~
 */
#ifndef HTTP_VX_H2_READER_H
#define HTTP_VX_H2_READER_H

#include "http_vx/h2_frame.h"
#include "http_vx/h2_limits.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english How far reading got.
 * \~spanish Hasta donde llego la lectura.
 * \~
 */
enum class ReadResult : uint8_t {
    /// \~english Not a whole frame yet.  Read more and call again.
    /// \~spanish Todavia no hay una trama entera.  Leer mas y volver a llamar.  \~
    NeedMore,
    /// \~english There is one.  See @c header and @c payload.
    /// \~spanish Hay una.  Ver @c header y @c payload.  \~
    Frame,
    /// \~english It is not a connection this can read.
    /// \~spanish No es una conexion que esto pueda leer.  \~
    Error,
};

/**
 * @brief
 * \~english Reads the frames of one connection.
 * \~spanish Lee las tramas de una conexion.
 * \~
 *
 * \~english
 * Fed the same way as everything else here: the whole live region of the
 * buffer every time, carrying on from where it stopped, with every offset
 * measured from the same first byte.
 *
 * \~spanish
 * Se alimenta igual que todo lo demas de aqui: la region viva entera del buffer
 * cada vez, siguiendo por donde se paro, con todos los desplazamientos medidos
 * desde el mismo primer byte.
 *
 * \~
 */
class FrameReader {
  public:
    FrameReader() noexcept = default;
    explicit FrameReader(const Limits &limits) noexcept : limits_(limits) {}

    /**
     * @brief
     * \~english Makes it ready to read a connection from @p start.
     * \~spanish Lo deja listo para leer una conexion desde @p start.
     * \~
     *
     * @param start   \~english where the connection's bytes begin
     *                \~spanish donde empiezan los bytes de la conexion  \~
     * @param preface \~english whether the client's preface comes first, which
     *                it does on a connection a client opened
     *                \~spanish si va delante el preambulo del cliente, que es
     *                lo que pasa en una conexion que abrio un cliente  \~
     */
    void reset(size_t start, bool preface) noexcept;

    /**
     * @brief
     * \~english Reads as far as it can, and says what it found.
     * \~spanish Lee hasta donde puede, y dice que encontro.
     * \~
     *
     * \~english
     * It returns at most one frame per call and is called in a loop until it
     * answers @c NeedMore or @c Error.
     *
     * \~spanish
     * Devuelve como mucho una trama por llamada y se le llama en bucle hasta
     * que conteste @c NeedMore o @c Error.
     *
     * \~
     * @param data \~english the connection's first byte
     *             \~spanish el primer byte de la conexion  \~
     * @param size \~english how many bytes are there  \~spanish cuantos bytes hay  \~
     * @return     \~english what it found  \~spanish que encontro  \~
     */
    ReadResult read(const uint8_t *data, size_t size) noexcept;

    /// \~english The header of the frame the last @c Frame refers to.
    /// \~spanish La cabecera de la trama a la que se refiere el ultimo @c Frame.  \~
    const FrameHeader &header() const noexcept { return header_; }

    /**
     * @brief
     * \~english The part of the payload that means something.
     * \~spanish La parte de la carga que significa algo.
     * \~
     *
     * \~english
     * Padding and the deprecated priority bytes are already off, because the
     * arithmetic that takes them off is where a frame gets read past its end:
     * a padding length larger than the frame that carries it produces a
     * remainder that is negative, and a negative length that is treated as
     * unsigned is an enormous one.  Doing it once here means there is one
     * place to get it right rather than one per frame type downstream.
     *
     * \~spanish
     * El relleno y los bytes de prioridad retirados ya estan fuera, porque la
     * aritmetica que los quita es por donde se lee una trama pasado su final:
     * una longitud de relleno mayor que la trama que la lleva produce un resto
     * negativo, y una longitud negativa tratada como sin signo es enorme.
     * Hacerlo una vez aqui deja un sitio donde acertar en vez de uno por cada
     * tipo de trama de mas abajo.
     *
     * \~
     */
    Span payload() const noexcept { return payload_; }

    /// \~english Why it was refused, when it was.
    /// \~spanish Por que se rechazo, cuando se rechazo.  \~
    ErrorCode error() const noexcept { return error_; }

    /**
     * @brief
     * \~english Where the last whole frame ended.
     * \~spanish Donde acabo la ultima trama entera.
     * \~
     *
     * \~english
     * **Always a frame boundary**, which is the property that makes it safe to
     * hand to @c Buffer::consume.  While a frame is half here it does not
     * move, even though the reader has already read that frame's header and
     * will not read it again: the header has been understood but it has not
     * been finished with, and a caller that discarded up to where the reader
     * had LOOKED would discard a header whose payload has not arrived -- and
     * then read that payload as the header of a frame that does not exist.
     *
     * The difference from the HTTP/1.1 readers is real and comes from the same
     * place as everything else here: they hand over what they have as they go,
     * so what they looked at and what they finished are the same thing.  This
     * one delivers whole frames, so they are not.
     *
     * \~spanish
     * **Siempre una frontera de trama**, que es la propiedad que hace seguro
     * pasarselo a @c Buffer::consume.  Mientras hay media trama no se mueve,
     * aunque el lector ya haya leido la cabecera de esa trama y no vaya a
     * leerla otra vez: la cabecera esta entendida pero no esta terminada, y
     * quien descartara hasta donde el lector ha MIRADO descartaria una cabecera
     * cuya carga no ha llegado -- y despues leeria esa carga como la cabecera
     * de una trama que no existe.
     *
     * La diferencia con los lectores de HTTP/1.1 es real y sale del mismo sitio
     * que todo lo demas de aqui: ellos entregan lo que tienen segun avanzan,
     * asi que lo que miraron y lo que terminaron es lo mismo.  Este entrega
     * tramas enteras, asi que no lo es.
     *
     * \~
     */
    size_t consumed() const noexcept { return boundary_; }

    /**
     * @brief
     * \~english Whether a header block is still waiting to be finished.
     * \~spanish Si queda un bloque de cabeceras por terminar.
     * \~
     *
     * \~english
     * While this is true the connection is holding an unfinished message, and
     * nothing but a CONTINUATION on the same stream may arrive.  It is worth
     * asking from outside because a connection that goes quiet in this state
     * is one holding state it may never get to use -- which is the shape of
     * the flood @c Limits::max_continuation_frames is about.
     *
     * \~spanish
     * Mientras esto sea cierto la conexion tiene un mensaje sin terminar, y no
     * puede llegar nada que no sea una CONTINUATION del mismo flujo.  Merece
     * poder preguntarse desde fuera porque una conexion que se quede callada en
     * este estado tiene estado guardado que quiza no llegue a usar -- que es la
     * forma de la riada de la que habla @c Limits::max_continuation_frames.
     *
     * \~
     */
    bool awaiting_continuation() const noexcept { return continuing_; }

  private:
    enum class State : uint8_t { Preface, Header, Payload, Failed };

    [[gnu::noinline, gnu::cold]] ReadResult fail(ErrorCode e) noexcept;

    /**
     * \~english
     * Takes the padding and the priority bytes off, or says the frame lies
     * about how long they are.
     * \~spanish
     * Quita el relleno y los bytes de prioridad, o dice que la trama miente
     * sobre cuanto miden.
     * \~
     */
    bool strip(const uint8_t *data, size_t &off, size_t &len) noexcept;

    /**
     * \~english
     * Keeps the rule that a header block is finished before anything else
     * happens, and that it does not go on forever.
     * \~spanish
     * Mantiene la regla de que un bloque de cabeceras se termina antes de que
     * pase otra cosa, y de que no sigue para siempre.
     * \~
     */
    ErrorCode check_continuation() noexcept;

    Limits limits_;
    State state_ = State::Preface;
    ErrorCode error_ = ErrorCode::NoError;

    /// \~english How far it has looked.  \~spanish Hasta donde ha mirado.  \~
    size_t pos_ = 0;
    /**
     * \~english
     * How far it has finished, which is not the same and is what
     * @c consumed reports.  Two numbers because a frame header is understood
     * before its payload arrives, and the difference between them is a header
     * that must not be thrown away yet.
     * \~spanish
     * Hasta donde ha terminado, que no es lo mismo y es lo que informa
     * @c consumed.  Dos numeros porque una cabecera de trama se entiende antes
     * de que llegue su carga, y la diferencia entre los dos es una cabecera que
     * todavia no se puede tirar.
     * \~
     */
    size_t boundary_ = 0;
    FrameHeader header_ = {};
    Span payload_ = {0, 0};

    /// \~english Whether a header block is open, and on which stream.
    /// \~spanish Si hay un bloque de cabeceras abierto, y en que flujo.  \~
    bool continuing_ = false;
    uint32_t continuing_stream_ = 0;
    uint32_t continuation_frames_ = 0;
    uint64_t header_block_bytes_ = 0;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_READER_H
