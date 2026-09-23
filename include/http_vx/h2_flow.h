/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_flow.h
 * @brief
 * \~english How much may still be sent, and why it can be less than nothing.
 * \~spanish Cuanto queda por mandar, y por que puede ser menos que nada.
 * \~
 *
 * \~english
 * HTTP/1.1 had one way to say "stop sending": stop reading, and let TCP do it.
 * That works because a connection carries one message.  HTTP/2 carries
 * hundreds at once down the same socket, so stopping the socket stops all of
 * them -- and a slow handler on one request would hold up every other request
 * on the connection.
 *
 * So each stream gets its own allowance, and the connection gets one more on
 * top.  A DATA frame spends BOTH, which is what stops any single stream from
 * eating the connection.
 *
 * **A window is signed, and that is the whole difficulty.**  It looks like a
 * counter that cannot go below zero -- you may not send more than you are
 * allowed -- and it goes below zero anyway, by a route that has nothing to do
 * with sending: the peer may lower `SETTINGS_INITIAL_WINDOW_SIZE`, and that
 * change applies to streams that ALREADY EXIST, retroactively.  A stream with
 * thirty kilobytes of allowance left, on a connection whose initial window
 * drops by forty, is now forty thousand bytes in debt -- and it has done
 * nothing wrong.  What it must do is send nothing until a WINDOW_UPDATE pays
 * the debt off.
 *
 * An implementation that held windows in an unsigned type does not fail there
 * with an error.  It wraps, and the stream is suddenly allowed four gigabytes.
 *
 * \~spanish
 * HTTP/1.1 tenia una forma de decir "deja de mandar": dejar de leer, y que lo
 * haga TCP.  Eso vale porque una conexion lleva un mensaje.  HTTP/2 lleva
 * cientos a la vez por el mismo socket, asi que parar el socket los para todos
 * -- y un manejador lento de una peticion retendria a todas las demas
 * peticiones de la conexion.
 *
 * Asi que cada flujo tiene su propio credito, y la conexion tiene otro por
 * encima.  Una trama DATA gasta LOS DOS, que es lo que impide que un solo flujo
 * se coma la conexion.
 *
 * **Una ventana tiene signo, y en eso esta toda la dificultad.**  Parece un
 * contador que no puede bajar de cero -- no puedes mandar mas de lo que te
 * dejan -- y baja de cero igualmente, por un camino que no tiene nada que ver
 * con mandar: el otro extremo puede bajar
 * `SETTINGS_INITIAL_WINDOW_SIZE`, y ese cambio se aplica a los flujos que YA
 * EXISTEN, con efecto retroactivo.  Un flujo al que le quedaban treinta
 * kilobytes de credito, en una conexion cuya ventana inicial baja cuarenta,
 * debe ahora cuarenta mil bytes -- y no ha hecho nada mal.  Lo que tiene que
 * hacer es no mandar nada hasta que un WINDOW_UPDATE pague la deuda.
 *
 * Una implementacion que guardara las ventanas en un tipo sin signo no falla
 * ahi con un error.  Da la vuelta, y de pronto el flujo puede mandar cuatro
 * gigabytes.
 *
 * \~
 */
#ifndef HTTP_VX_H2_FLOW_H
#define HTTP_VX_H2_FLOW_H

#include "http_vx/h2_frame.h"
#include "http_vx/h2_settings.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english How much may still travel one way.
 * \~spanish Cuanto puede viajar todavia en un sentido.
 * \~
 *
 * \~english
 * One of these per direction per stream, plus one per direction for the
 * connection.  It is four bytes of state and no behaviour beyond arithmetic,
 * which is deliberate: with a thousand streams on a connection this is the
 * thing there are the most of, and R2 says the per-connection state is a fixed
 * size in a dense array rather than an object somebody allocated.
 *
 * \~spanish
 * Una de estas por sentido y por flujo, mas una por sentido para la conexion.
 * Son cuatro bytes de estado y ningun comportamiento mas alla de la aritmetica,
 * y es a proposito: con mil flujos en una conexion esto es de lo que mas hay, y
 * la R2 dice que el estado por conexion es de tamano fijo en un array denso y
 * no un objeto que alguien reservo.
 *
 * \~
 */
class Window {
  public:
    Window() noexcept = default;

    /// \~english Starts it at @p initial.  \~spanish La empieza en @p initial.  \~
    explicit Window(uint32_t initial) noexcept
        : left_(static_cast<int32_t>(initial)) {}

    /// \~english How much is left; may be negative.
    /// \~spanish Cuanto queda; puede ser negativo.  \~
    int32_t left() const noexcept { return left_; }

    /**
     * @brief
     * \~english Whether @p n bytes may be sent right now.
     * \~spanish Si se pueden mandar @p n bytes ahora mismo.
     * \~
     *
     * \~english
     * Asked rather than found out by trying, because the two are different
     * questions and only this one can be asked about a window that is in debt.
     * `left() >= n` on a negative window is false for every @p n INCLUDING
     * zero, and a zero-length DATA frame is legal -- it is how a sender says
     * `END_STREAM` with nothing left to say.
     *
     * \~spanish
     * Se pregunta en vez de averiguarlo intentandolo, porque son dos preguntas
     * distintas y solo esta se puede hacer sobre una ventana en deuda.
     * `left() >= n` en una ventana negativa es falso para todo @p n INCLUIDO el
     * cero, y una trama DATA de longitud cero es legal -- es como dice quien
     * envia `END_STREAM` sin nada mas que decir.
     *
     * \~
     * @param n \~english how many  \~spanish cuantos  \~
     * @return  \~english whether they fit  \~spanish si caben  \~
     */
    bool allows(uint32_t n) const noexcept {
        return n == 0 || (left_ > 0 && static_cast<int64_t>(n) <= left_);
    }

    /**
     * @brief
     * \~english Spends @p n of it.
     * \~spanish Gasta @p n de ella.
     * \~
     *
     * \~english
     * Refuses rather than clamping.  A window that went past its own bottom
     * would be a receiver that accepted more than it said it could hold, and
     * the memory it holds that data in is sized by what it said.
     *
     * \~spanish
     * Rechaza en vez de recortar.  Una ventana que se pasara de su propio suelo
     * seria un receptor aceptando mas de lo que dijo que le cabia, y la memoria
     * donde guarda esos datos esta dimensionada por lo que dijo.
     *
     * \~
     * @param n \~english how many bytes  \~spanish cuantos bytes  \~
     * @return  \~english false if there was not that much
     *          \~spanish false si no habia tanto  \~
     */
    bool take(uint32_t n) noexcept {
        if (!allows(n)) return false;
        left_ -= static_cast<int32_t>(n);
        return true;
    }

    /**
     * @brief
     * \~english Gives @p n back, as a WINDOW_UPDATE does.
     * \~spanish Devuelve @p n, como hace un WINDOW_UPDATE.
     * \~
     *
     * \~english
     * Two refusals, and they are different errors on the wire.  An increment of
     * ZERO is a protocol error: it is a frame that says nothing, and a peer
     * that sends a stream of them is spending this end's time without spending
     * its own window -- the same shape as a flood of empty CONTINUATION frames.
     * Going PAST the ceiling is a flow-control error: it is a peer offering an
     * allowance the field cannot hold, which means one of the two ends has lost
     * count.
     *
     * The addition is done in sixty-four bits and compared afterwards.  Done in
     * thirty-two it would overflow -- and signed overflow is not a large number
     * in C++, it is a program the compiler may assume never happens, which is
     * how a bounds check disappears entirely.
     *
     * \~spanish
     * Dos rechazos, y son errores distintos en el cable.  Un incremento de CERO
     * es un error de protocolo: es una trama que no dice nada, y un extremo que
     * mande una riada de ellas esta gastando el tiempo de este sin gastar su
     * propia ventana -- la misma forma que una riada de CONTINUATION vacias.
     * Pasarse del TECHO es un error de control de flujo: es un extremo
     * ofreciendo un credito que no cabe en el campo, lo que quiere decir que uno
     * de los dos ha perdido la cuenta.
     *
     * La suma se hace en sesenta y cuatro bits y se compara despues.  Hecha en
     * treinta y dos desbordaria -- y el desbordamiento con signo no es un numero
     * grande en C++, es un programa que el compilador puede dar por imposible,
     * que es como desaparece del todo una comprobacion de limites.
     *
     * \~
     * @param n \~english the increment  \~spanish el incremento  \~
     * @return  \~english @c NoError, or which error it is
     *          \~spanish @c NoError, o cual de los dos errores es  \~
     */
    ErrorCode give(uint32_t n) noexcept {
        if (n == 0) return ErrorCode::ProtocolError;

        const int64_t after = static_cast<int64_t>(left_) + n;
        if (after > kMaxWindow) return ErrorCode::FlowControlError;

        left_ = static_cast<int32_t>(after);
        return ErrorCode::NoError;
    }

    /**
     * @brief
     * \~english Moves it by @p delta, as a changed initial window does.
     * \~spanish La mueve @p delta, como hace una ventana inicial cambiada.
     * \~
     *
     * \~english
     * The one that can leave it negative, and the reason the whole class is
     * signed.  It is separate from @c give because the two mean opposite
     * things: @c give is the peer saying "you may send more", and it is
     * refused when it does not make sense.  This is the peer saying "what I
     * told you the allowance was has changed", which is not a request and
     * cannot be refused -- the peer already sent it and both ends have to end
     * up at the same number.
     *
     * Only going PAST the ceiling upwards is an error, because that one means
     * the two ends disagree about what the allowance was.  Going below zero is
     * not an error at all; it is a stream that must wait.
     *
     * \~spanish
     * La que puede dejarla negativa, y la razon de que toda la clase tenga
     * signo.  Esta aparte de @c give porque las dos significan cosas contrarias:
     * @c give es el otro extremo diciendo "puedes mandar mas", y se rechaza
     * cuando no tiene sentido.  Esta es el otro extremo diciendo "lo que te dije
     * que era el credito ha cambiado", que no es una peticion y no se puede
     * rechazar -- el otro ya lo mando y los dos extremos tienen que acabar en el
     * mismo numero.
     *
     * Solo pasarse del techo hacia arriba es un error, porque ese si quiere
     * decir que los dos extremos discrepan sobre cual era el credito.  Bajar de
     * cero no es ningun error; es un flujo que tiene que esperar.
     *
     * \~
     * @param delta \~english how far it moves, either way
     *              \~spanish cuanto se mueve, en cualquier sentido  \~
     * @return      \~english @c NoError, or @c FlowControlError
     *              \~spanish @c NoError, o @c FlowControlError  \~
     */
    ErrorCode adjust(int64_t delta) noexcept {
        const int64_t after = static_cast<int64_t>(left_) + delta;
        if (after > kMaxWindow) return ErrorCode::FlowControlError;

        /* \~english
         * And the floor, which is not zero: a window may be in debt but the
         * debt is bounded by the same field.  Beyond it the two ends have lost
         * count of each other just as surely as above the ceiling.
         * \~spanish
         * Y el suelo, que no es cero: una ventana puede estar en deuda pero la
         * deuda la acota el mismo campo.  Mas alla, los dos extremos han
         * perdido la cuenta el uno del otro igual de seguro que por arriba.
         * \~ */
        if (after < -kMaxWindow - 1) return ErrorCode::FlowControlError;

        left_ = static_cast<int32_t>(after);
        return ErrorCode::NoError;
    }

  private:
    int32_t left_ = 65535;
};

/**
 * @brief
 * \~english Reads the increment out of a WINDOW_UPDATE payload.
 * \~spanish Lee el incremento de una carga de WINDOW_UPDATE.
 * \~
 *
 * \~english
 * Four bytes with the top one reserved, and the reserved bit is MASKED rather
 * than checked.  That is the specification's instruction and it is the same
 * rule as the reserved bit in a stream identifier: a bit nobody has defined
 * yet may carry meaning in a version this end does not speak, and refusing it
 * would be refusing a connection with a newer peer.
 *
 * \~spanish
 * Cuatro bytes con el de arriba reservado, y el bit reservado se ENMASCARA en
 * vez de comprobarse.  Es lo que manda la especificacion y es la misma regla
 * que el bit reservado de un identificador de flujo: un bit que nadie ha
 * definido todavia puede llevar significado en una version que este extremo no
 * habla, y rechazarlo seria rechazar una conexion con un extremo mas nuevo.
 *
 * \~
 * @param p \~english the payload, which must be four bytes
 *          \~spanish la carga, que tiene que ser de cuatro bytes  \~
 * @return  \~english the increment  \~spanish el incremento  \~
 */
inline uint32_t window_increment(const uint8_t *p) noexcept {
    return be32(p) & 0x7FFFFFFFu;
}

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_FLOW_H
