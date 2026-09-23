/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_settings.h
 * @brief
 * \~english What the two ends told each other, and when it starts being true.
 * \~spanish Lo que se dijeron los dos extremos, y cuando empieza a ser cierto.
 * \~
 *
 * \~english
 * HTTP/1.1 had nothing like this: a connection meant the same thing at both
 * ends because there was nothing to agree about.  HTTP/2 has six numbers that
 * each end announces, and every one of them changes how the other end reads
 * the bytes that follow.
 *
 * Which is why the interesting thing here is not the parsing -- six identifiers
 * and six values, and the list is short -- but **the moment a setting starts
 * applying**:
 *
 *  - a setting one end SENDS is a promise about what it will accept, and it is
 *    in force for the other end from the moment that end reads it;
 *  - a setting one end RECEIVES is not in force until it has acknowledged it,
 *    because the peer is still sending frames that were written under the old
 *    value and they were legal when they were written;
 *  - and an unknown identifier is IGNORED, not refused.  That is not
 *    permissiveness, it is how the protocol is extended: an implementation
 *    that refused what it did not recognise would break every connection with
 *    a newer peer, which is the failure mode that froze HTTP/1.1 in place for
 *    fifteen years.
 *
 * The one that is not just a number is `SETTINGS_INITIAL_WINDOW_SIZE`, and it
 * is the reason this file and @c h2_flow.h are written together: changing it
 * does not set the windows, it MOVES them -- by the difference, on every
 * stream that already exists, and a window can come out negative.  See
 * @c Window::adjust.
 *
 * \~spanish
 * HTTP/1.1 no tenia nada parecido: una conexion significaba lo mismo en los dos
 * extremos porque no habia nada sobre lo que ponerse de acuerdo.  HTTP/2 tiene
 * seis numeros que anuncia cada extremo, y todos ellos cambian como lee el otro
 * los bytes que vienen detras.
 *
 * Por eso lo interesante aqui no es el analisis -- seis identificadores y seis
 * valores, y la lista es corta -- sino **el momento en que un ajuste empieza a
 * aplicarse**:
 *
 *  - un ajuste que un extremo MANDA es una promesa sobre lo que va a aceptar, y
 *    rige para el otro extremo desde que ese otro lo lee;
 *  - un ajuste que un extremo RECIBE no rige hasta que lo ha confirmado, porque
 *    el otro sigue mandando tramas escritas con el valor viejo y eran legales
 *    cuando se escribieron;
 *  - y un identificador desconocido se IGNORA, no se rechaza.  Eso no es ser
 *    permisivo, es como se extiende el protocolo: una implementacion que
 *    rechazara lo que no reconoce romperia todas las conexiones con un extremo
 *    mas nuevo, que es la forma de fallar que dejo congelado HTTP/1.1 durante
 *    quince anos.
 *
 * El que no es solo un numero es `SETTINGS_INITIAL_WINDOW_SIZE`, y es la razon
 * de que este fichero y @c h2_flow.h se escribieran juntos: cambiarlo no pone
 * las ventanas, las MUEVE -- por la diferencia, en todos los flujos que ya
 * existen, y una ventana puede quedar negativa.  Ver @c Window::adjust.
 *
 * \~
 */
#ifndef HTTP_VX_H2_SETTINGS_H
#define HTTP_VX_H2_SETTINGS_H

#include "http_vx/h2_frame.h"
#include "http_vx/h2_limits.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english How many bytes one setting takes.
 * \~spanish Cuantos bytes ocupa un ajuste.
 * \~
 *
 * \~english
 * Six: two of identifier and four of value.  A SETTINGS payload that is not a
 * multiple of six is a connection error and not a short read -- the frame
 * layer already said how long the payload is, so a remainder is a sender that
 * disagrees with its own frame header.
 *
 * \~spanish
 * Seis: dos de identificador y cuatro de valor.  Una carga de SETTINGS que no
 * sea multiplo de seis es un error de CONEXION y no una lectura corta -- la
 * capa de tramas ya dijo cuanto mide la carga, asi que un resto es quien envia
 * discrepando de su propia cabecera de trama.
 *
 * \~
 */
constexpr size_t kSettingSize = 6;

/**
 * @brief
 * \~english The identifiers RFC 9113 gives numbers to.
 * \~spanish Los identificadores a los que el RFC 9113 les pone numero.
 * \~
 */
enum class SettingId : uint16_t {
    HeaderTableSize = 0x01,
    EnablePush = 0x02,
    MaxConcurrentStreams = 0x03,
    InitialWindowSize = 0x04,
    MaxFrameSize = 0x05,
    MaxHeaderListSize = 0x06,
};

/**
 * @brief
 * \~english The largest a flow-control window may be.
 * \~spanish Lo mas que puede medir una ventana de control de flujo.
 * \~
 *
 * \~english
 * Two to the thirty-first minus one.  It is a SIGNED limit on an unsigned
 * field, which is not an accident: a window is allowed to be negative, so the
 * arithmetic has to happen in a type that can hold one, and the protocol
 * reserves the sign bit to make room for it.
 *
 * \~spanish
 * Dos elevado a treinta y uno menos uno.  Es un limite CON SIGNO sobre un campo
 * sin signo, y no es un accidente: una ventana puede ser negativa, asi que la
 * aritmetica tiene que hacerse en un tipo que lo admita, y el protocolo reserva
 * el bit de signo para dejarle sitio.
 *
 * \~
 */
constexpr int64_t kMaxWindow = 0x7FFFFFFF;

/**
 * @brief
 * \~english The smallest and largest a peer may set the frame size to.
 * \~spanish Lo menor y lo mayor a que puede poner el tamano de trama un extremo.
 * \~
 *
 * \~english
 * Sixteen kilobytes is not a default that may be lowered -- it is the FLOOR,
 * and a peer that asks for less is refused.  Every implementation may assume
 * it, so a connection where it did not hold would be one where a frame legal
 * everywhere else is illegal.
 *
 * \~spanish
 * Dieciseis kilobytes no es un valor por defecto que se pueda bajar -- es el
 * SUELO, y a un extremo que pida menos se le rechaza.  Cualquier
 * implementacion puede darlo por hecho, asi que una conexion donde no se
 * cumpliera seria una donde una trama legal en todas partes es ilegal.
 *
 * \~
 */
constexpr uint32_t kMinFrameSize = 16384;

/// \~english And the ceiling: sixteen megabytes minus one.
/// \~spanish Y el techo: dieciseis megabytes menos uno.  \~
constexpr uint32_t kMaxFrameSize = 16777215;

/**
 * @brief
 * \~english The six numbers, as one end believes them.
 * \~spanish Los seis numeros, tal como se los cree un extremo.
 * \~
 *
 * \~english
 * The values here are the ones RFC 9113 section 6.5.2 gives for a connection
 * that has said nothing, so a fresh one is already correct without anybody
 * sending a frame.  That matters more than it looks: the first SETTINGS is not
 * instantaneous, and a connection that treated "not told yet" as zero would
 * spend the first round trip believing the peer accepts nothing.
 *
 * \~spanish
 * Los valores de aqui son los que da el RFC 9113 seccion 6.5.2 para una conexion
 * que no ha dicho nada, asi que una recien hecha ya es correcta sin que nadie
 * haya mandado una trama.  Importa mas de lo que parece: el primer SETTINGS no
 * es instantaneo, y una conexion que tomara "todavia no me lo han dicho" por
 * cero se pasaria la primera ida y vuelta creyendo que el otro extremo no
 * acepta nada.
 *
 * \~
 */
struct Settings {
    uint32_t header_table_size = 4096;
    uint32_t max_concurrent_streams = 0xFFFFFFFF;
    uint32_t initial_window_size = 65535;
    uint32_t max_frame_size = kMinFrameSize;
    uint32_t max_header_list_size = 0xFFFFFFFF;

    /**
     * \~english
     * A server never pushes, so this is here to be REFUSED when a peer sets it
     * to something other than zero or one -- and it is a field rather than a
     * check in passing because the value is also what says whether the peer
     * would accept a push, and something later will want to ask.
     * \~spanish
     * Un servidor no empuja nunca, asi que esto esta aqui para RECHAZARLO
     * cuando un extremo lo ponga a algo que no sea cero ni uno -- y es un campo
     * y no una comprobacion al paso porque el valor es ademas lo que dice si el
     * otro extremo aceptaria un empuje, y algo de mas adelante querra
     * preguntarlo.
     * \~
     */
    bool enable_push = true;
};

/**
 * @brief
 * \~english What a setting did to the connection.
 * \~spanish Que le hizo un ajuste a la conexion.
 * \~
 */
struct SettingsChange {
    /// \~english @c NoError, or why the connection cannot go on.
    /// \~spanish @c NoError, o por que no puede seguir la conexion.  \~
    ErrorCode error = ErrorCode::NoError;

    /**
     * \~english
     * How far `SETTINGS_INITIAL_WINDOW_SIZE` moved, and the reason this is a
     * result rather than something applied inside: the streams are not here.
     * A caller adds this to every open stream's window -- see
     * @c Window::adjust -- and adds it to none of the connection's, because the
     * connection window is not a setting and never moves.
     *
     * \~spanish
     * Cuanto se movio `SETTINGS_INITIAL_WINDOW_SIZE`, y la razon de que esto sea
     * un resultado y no algo que se aplique dentro: los flujos no estan aqui.
     * Quien llama se lo suma a la ventana de cada flujo abierto -- ver
     * @c Window::adjust -- y a ninguna de la conexion, porque la ventana de la
     * conexion no es un ajuste y no se mueve nunca.
     * \~
     */
    int64_t window_delta = 0;
};

/**
 * @brief
 * \~english Reads a SETTINGS payload into @p s.
 * \~spanish Lee una carga de SETTINGS sobre @p s.
 * \~
 *
 * \~english
 * The settings are applied AS THEY ARE READ and in order, which is the
 * specification's wording and not an implementation convenience: a payload may
 * name the same identifier twice, and what the connection ends up with is the
 * last one.  A reader that collected them and applied them afterwards would
 * get the same answer for that case and a different one for the window delta,
 * which is the difference between the FIRST value seen and the last.
 *
 * On an error nothing is rolled back.  There is nothing to roll back to: a
 * SETTINGS this end could not read is a connection this end is about to close,
 * and the state of a structure nobody will read again is not worth the code to
 * restore it.  What matters is that the error says which one it is, because
 * `FrameSizeError` and `FlowControlError` and `ProtocolError` send different
 * GOAWAY codes and the peer's logs are the only place anybody will see them.
 *
 * \~spanish
 * Los ajustes se aplican SEGUN SE LEEN y en orden, que es como lo dice la
 * especificacion y no una comodidad de implementacion: una carga puede nombrar
 * dos veces el mismo identificador, y con lo que se queda la conexion es con el
 * ultimo.  Un lector que los recogiera y los aplicara despues llegaria a lo
 * mismo en ese caso y a otra cosa en la diferencia de ventana, que es entre el
 * PRIMER valor visto y el ultimo.
 *
 * Ante un error no se deshace nada.  No hay a donde deshacer: un SETTINGS que
 * este extremo no pudo leer es una conexion que este extremo va a cerrar, y el
 * estado de una estructura que nadie va a volver a leer no vale el codigo de
 * restaurarla.  Lo que importa es que el error diga cual es, porque
 * `FrameSizeError`, `FlowControlError` y `ProtocolError` mandan codigos de
 * GOAWAY distintos y los registros del otro extremo son el unico sitio donde
 * alguien los va a ver.
 *
 * \~
 * @param p \~english the payload  \~spanish la carga  \~
 * @param n \~english how many bytes  \~spanish cuantos bytes  \~
 * @param s \~english what to change  \~spanish lo que hay que cambiar  \~
 * @return  \~english what it did, or why not
 *          \~spanish lo que hizo, o por que no  \~
 */
SettingsChange apply_settings(const uint8_t *p, size_t n,
                              Settings &s) noexcept;

/**
 * @brief
 * \~english Writes this server's own SETTINGS payload from @p limits.
 * \~spanish Escribe la carga de SETTINGS propia de este servidor desde @p limits.
 * \~
 *
 * \~english
 * Only what differs from the defaults is written, which is not an optimisation
 * worth six bytes -- it is that a setting written is a setting the peer must
 * acknowledge and then honour, and announcing a value that is already the
 * default asks it to do work to arrive where it was.
 *
 * The values come from @c Limits and not from arguments, because they are the
 * SAME numbers the reading side enforces.  Announcing one number and enforcing
 * another is a connection that refuses what it asked for, and it is a mistake
 * that only shows up against a peer that believed the announcement.
 *
 * \~spanish
 * Solo se escribe lo que difiere de los valores por defecto, que no es una
 * optimizacion de seis bytes -- es que un ajuste escrito es un ajuste que el
 * otro extremo tiene que confirmar y luego cumplir, y anunciar un valor que ya
 * es el de por defecto es pedirle trabajo para llegar a donde estaba.
 *
 * Los valores salen de @c Limits y no de argumentos, porque son los MISMOS
 * numeros que hace cumplir el lado que lee.  Anunciar un numero y hacer cumplir
 * otro es una conexion que rechaza lo que pidio, y es una equivocacion que solo
 * sale con un extremo que se creyo el anuncio.
 *
 * \~
 * @param out    \~english where to write; at least @c kSettingSize * 6
 *               \~spanish donde escribir; al menos @c kSettingSize * 6  \~
 * @param cap    \~english how much room there is  \~spanish cuanto sitio hay  \~
 * @param limits \~english what this server enforces
 *               \~spanish lo que hace cumplir este servidor  \~
 * @return       \~english how many bytes, or zero if there was no room
 *               \~spanish cuantos bytes, o cero si no habia sitio  \~
 */
size_t write_settings(uint8_t *out, size_t cap, const Limits &limits) noexcept;

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_SETTINGS_H
