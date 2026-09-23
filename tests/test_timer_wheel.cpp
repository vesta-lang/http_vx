/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_timer_wheel.cpp
 * @brief
 * \~english Deadlines: arming, cancelling, and the one that would fire early.
 * \~spanish Plazos: armar, cancelar, y el que venceria antes de tiempo.
 * \~
 *
 * \~english
 * The cases here are picked by what would go wrong SILENTLY.
 *
 * A wheel that dropped a timer, or fired one late, would be caught by anything
 * -- a connection would hang and somebody would notice.  The dangerous ones
 * are the other way round: a deadline that lands in the slot being emptied and
 * fires a whole turn early, or one past the horizon that wraps and fires at a
 * tick nobody asked for.  Neither reports an error.  A few connections just
 * die young on a server that looks perfectly healthy.
 *
 * And one case is not about correctness at all but about cost: re-arming.  It
 * is what every read of every connection does, so it is by far the most
 * frequent operation, and it is the one a priority queue has no good answer
 * for.  The test does it a million times to say that the answer here does not
 * depend on how many timers there are.
 *
 * \~spanish
 * Los casos de aqui estan elegidos por lo que se estropearia EN SILENCIO.
 *
 * Una rueda que perdiera un plazo, o que venciera uno tarde, la pillaria
 * cualquiera -- una conexion se colgaria y alguien lo notaria --.  Los
 * peligrosos son los del otro lado: un plazo que cae en la casilla que se esta
 * vaciando y vence una vuelta entera antes, o uno pasado del horizonte que da la
 * vuelta y vence en un tic que no pidio nadie.  Ninguno de los dos da error.
 * Solo se mueren jovenes unas cuantas conexiones en un servidor que se ve
 * perfectamente sano.
 *
 * Y un caso no va de correccion sino de coste: rearmar.  Es lo que hace cada
 * lectura de cada conexion, asi que es con diferencia la operacion mas
 * frecuente, y es para la que una cola de prioridad no tiene buena respuesta.
 * La prueba lo hace un millon de veces para decir que la respuesta de aqui no
 * depende de cuantos plazos haya.
 *
 * \~
 */

#include "http_vx/timer_wheel.h"

#include <cstdio>

namespace {

using http_vx::kNoTimer;
using http_vx::TimerWheel;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english How many come due at @p now.
 * \~spanish Cuantos vencen en @p now.
 * \~
 */
size_t drain(TimerWheel &w, uint64_t now) {
    size_t n = 0;
    while (w.take_due(now) != kNoTimer) ++n;
    return n;
}

/**
 * @brief
 * \~english Whether @p id comes due at @p now and nothing else does.
 * \~spanish Si @p id vence en @p now y no vence nada mas.
 * \~
 */
bool only(TimerWheel &w, uint64_t now, uint32_t id) {
    if (w.take_due(now) != id) return false;
    return w.take_due(now) == kNoTimer;
}

/**
 * @brief
 * \~english A deadline comes due at its tick and not before.
 * \~spanish Un plazo vence en su tic y no antes.
 * \~
 */
void test_a_deadline_comes_due_when_it_should() {
    TimerWheel w;
    check(w.reset(64, 16, 1000), "the wheel would not be made");

    check(w.arm(7, 3), "a deadline within the horizon was refused");
    check(w.armed(7), "an armed deadline does not say it is armed");
    check(w.armed_count() == 1, "the wheel did not count the deadline");

    check(drain(w, 1000) == 0, "a deadline came due on the tick it was set");
    check(drain(w, 1001) == 0, "a deadline came due a tick early");
    check(drain(w, 1002) == 0, "a deadline came due two ticks early");

    check(only(w, 1003, 7), "the deadline did not come due on its tick");
    check(!w.armed(7), "an expired deadline is still armed");
    check(w.armed_count() == 0, "the wheel still counts an expired deadline");
}

/**
 * @brief
 * \~english A deadline that is late still comes due, once.
 * \~spanish Un plazo que llega tarde vence igual, una vez.
 * \~
 *
 * \~english
 * A shard does not get to run exactly on the tick.  It was busy, or the
 * machine was, and it comes back several ticks later -- so everything that
 * fell in the meantime has to come out, in one sweep, and none of it twice.
 *
 * \~spanish
 * Un fragmento no corre exactamente en el tic.  Tenia trabajo, o lo tenia la
 * maquina, y vuelve varios tics despues -- asi que todo lo que cayo mientras
 * tanto tiene que salir, en un barrido, y nada de ello dos veces.
 *
 * \~
 */
void test_a_late_sweep_catches_everything_once() {
    TimerWheel w;
    check(w.reset(64, 16, 0), "the wheel would not be made");

    check(w.arm(1, 1), "a deadline was refused");
    check(w.arm(2, 3), "a deadline was refused");
    check(w.arm(3, 5), "a deadline was refused");

    /* \~english
     * Nobody swept for five ticks.  All three come out now.
     * \~spanish
     * Nadie barrio en cinco tics.  Los tres salen ahora.
     * \~ */
    check(drain(w, 5) == 3, "a late sweep did not catch everything");
    check(w.armed_count() == 0, "something was left armed after a late sweep");
    check(drain(w, 5) == 0, "a second sweep found the same deadlines again");
    check(drain(w, 6) == 0, "a later sweep found them again");
}

/**
 * @brief
 * \~english Re-arming replaces the deadline rather than adding one.
 * \~spanish Rearmar sustituye el plazo en vez de anadir otro.
 * \~
 *
 * \~english
 * The common case, by a long way: every read of a connection pushes its idle
 * timeout further out.  If arming twice left two deadlines, a busy connection
 * would be closed by the first one it ever set -- and the wheel would fill up
 * with deadlines nothing can cancel, because a caller only knows about the
 * last one.
 *
 * \~spanish
 * El caso corriente, con diferencia: cada lectura de una conexion empuja su
 * plazo de inactividad mas lejos.  Si armar dos veces dejara dos plazos, una
 * conexion con trabajo la cerraria el primero que puso nunca -- y la rueda se
 * llenaria de plazos que no puede cancelar nadie, porque quien llama solo sabe
 * del ultimo.
 *
 * \~
 */
void test_re_arming_replaces_the_old_deadline() {
    TimerWheel w;
    check(w.reset(64, 16, 0), "the wheel would not be made");

    check(w.arm(4, 2), "a deadline was refused");
    check(w.arm(4, 6), "re-arming was refused");
    check(w.armed_count() == 1, "re-arming left two deadlines");

    check(drain(w, 5) == 0, "the replaced deadline came due anyway");
    check(only(w, 6, 4), "the new deadline did not come due on its tick");
}

/**
 * @brief
 * \~english Cancelling takes it away, and cancelling twice is not an error.
 * \~spanish Cancelar lo quita, y cancelar dos veces no es un error.
 * \~
 *
 * \~english
 * A connection is closed from more than one place -- the peer went away, a
 * request failed, the deadline itself came due -- and making each of them
 * remember whether the timer was still there would be making each of them keep
 * a copy of the wheel's state.
 *
 * \~spanish
 * Una conexion se cierra desde mas de un sitio -- el otro extremo se fue, una
 * peticion fallo, el plazo mismo vencio -- y hacer que cada uno se acuerde de si
 * el plazo seguia ahi seria hacer que cada uno guarde una copia del estado de la
 * rueda.
 *
 * \~
 */
void test_cancelling_is_safe_to_repeat() {
    TimerWheel w;
    check(w.reset(64, 16, 0), "the wheel would not be made");

    check(w.arm(9, 4), "a deadline was refused");
    w.cancel(9);
    check(!w.armed(9), "a cancelled deadline is still armed");
    check(w.armed_count() == 0, "a cancelled deadline is still counted");

    w.cancel(9);
    w.cancel(9);
    check(w.armed_count() == 0, "cancelling again broke the count");

    check(drain(w, 10) == 0, "a cancelled deadline came due");

    /* \~english
     * And one that was never armed.
     * \~spanish
     * Y uno que no se armo nunca.
     * \~ */
    w.cancel(11);
    check(w.armed_count() == 0, "cancelling an unarmed deadline broke the count");
}

/**
 * @brief
 * \~english Cancelling from the middle of a slot does not disturb the rest.
 * \~spanish Cancelar en medio de una casilla no molesta al resto.
 * \~
 *
 * \~english
 * Every connection with the same deadline shares a slot, and on an idle
 * server that is ALL of them.  So the list a cancel unlinks from is the long
 * one, and getting the unlink wrong would show up only when the middle is
 * taken out -- which the obvious test, of one timer in one slot, never does.
 *
 * \~spanish
 * Todas las conexiones con el mismo plazo comparten casilla, y en un servidor
 * parado son TODAS.  Asi que la lista de la que desenlaza un cancelar es la
 * larga, y equivocarse en el desenlace saldria solo al sacar el de en medio --
 * que es lo que la prueba evidente, de un plazo en una casilla, no hace nunca.
 *
 * \~
 */
void test_a_cancel_from_the_middle_keeps_the_rest() {
    TimerWheel w;
    check(w.reset(64, 16, 0), "the wheel would not be made");

    for (uint32_t i = 0; i < 10; ++i)
        check(w.arm(i, 5), "a deadline was refused");

    /* \~english
     * The head, the tail and one in the middle, which between them are every
     * shape the unlink has.
     * \~spanish
     * La cabeza, la cola y uno de en medio, que entre los tres son todas las
     * formas que tiene el desenlace.
     * \~ */
    w.cancel(9);
    w.cancel(0);
    w.cancel(5);
    check(w.armed_count() == 7, "cancelling three left the wrong count");

    check(drain(w, 5) == 7, "the rest of the slot was lost with the cancels");
}

/**
 * @brief
 * \~english A deadline past the horizon is refused, not wrapped round.
 * \~spanish Un plazo pasado del horizonte se rechaza, no se da la vuelta.
 * \~
 *
 * \~english
 * The silent one.  A wheel of sixteen slots asked for a deadline sixteen ticks
 * away has a slot for it -- the one being emptied -- and putting it there
 * would fire it NOW instead of sixteen ticks from now.  Seventeen would fire
 * at one.  Nothing reports an error, and the only symptom is connections
 * closing early on a server that looks fine.
 *
 * Zero is refused for the same reason from the other side: a deadline that has
 * already passed is not a deadline, and the caller asking for one meant
 * something it should say out loud.
 *
 * \~spanish
 * El silencioso.  Una rueda de dieciseis casillas a la que le pidan un plazo de
 * dieciseis tics tiene casilla para el -- la que se esta vaciando -- y ponerlo
 * ahi lo haria vencer AHORA en vez de dentro de dieciseis tics.  Diecisiete
 * venceria en uno.  Nadie da ningun error, y el unico sintoma son conexiones
 * cerrandose antes de tiempo en un servidor que se ve bien.
 *
 * El cero se rechaza por lo mismo desde el otro lado: un plazo que ya paso no es
 * un plazo, y quien pida uno queria decir algo que deberia decir en voz alta.
 *
 * \~
 */
void test_a_deadline_past_the_horizon_is_refused() {
    TimerWheel w;
    check(w.reset(64, 16, 0), "the wheel would not be made");

    check(w.horizon() == 15, "the horizon is not one less than the slots");

    check(w.arm(1, 15), "a deadline exactly at the horizon was refused");
    check(!w.arm(2, 16), "a deadline one past the horizon was accepted");
    check(!w.arm(3, 17), "a deadline past the horizon was accepted");
    check(!w.arm(4, 0), "a deadline of zero ticks was accepted");

    check(w.armed_count() == 1, "a refused deadline was armed anyway");

    /* \~english
     * And the one at the horizon really does wait the whole way, which is what
     * says the refusal above is about the horizon and not about an off-by-one
     * that also happens to reject the valid case.
     * \~spanish
     * Y el del horizonte espera de verdad todo el camino, que es lo que dice que
     * el rechazo de arriba va del horizonte y no de un desfase de uno que
     * ademas rechaza el caso bueno.
     * \~ */
    check(drain(w, 14) == 0, "the deadline at the horizon came due early");
    check(only(w, 15, 1), "the deadline at the horizon did not come due");
}

/**
 * @brief
 * \~english The number of slots is rounded up, and out-of-range is refused.
 * \~spanish El numero de casillas se redondea, y lo que se sale se rechaza.
 * \~
 */
void test_the_edges_of_the_wheel() {
    TimerWheel w;

    check(w.reset(64, 10, 0), "a wheel of ten slots would not be made");
    check(w.horizon() == 15, "ten slots were not rounded up to sixteen");

    check(!w.arm(64, 1), "an identifier past the capacity was armed");
    check(!w.arm(kNoTimer, 1), "the none identifier was armed");
    check(!w.armed(64), "an identifier past the capacity says it is armed");

    /* \~english
     * A clock that went backwards is a clock, not a reason to fire every
     * deadline at once.
     * \~spanish
     * Un reloj que fue hacia atras es un reloj, no una razon para vencer todos
     * los plazos de golpe.
     * \~ */
    check(w.reset(64, 16, 1000), "the wheel would not be made");
    check(w.arm(1, 5), "a deadline was refused");
    check(drain(w, 900) == 0, "a clock going backwards fired a deadline");
    check(w.armed_count() == 1, "a clock going backwards lost a deadline");
    check(only(w, 1005, 1), "the deadline was lost after the clock went back");
}

/**
 * @brief
 * \~english A million re-arms, because that is what a busy shard does.
 * \~spanish Un millon de rearmes, porque es lo que hace un fragmento con trabajo.
 * \~
 *
 * \~english
 * Not a measurement -- there is no timing here and the build is not tuned for
 * it.  It is a statement about SHAPE: a wheel full of a hundred thousand
 * deadlines is re-armed a million times and the test finishes, which it could
 * not do if arming looked at anything but the entry it was handed.  The same
 * loop against a structure that searched for the old deadline would be
 * quadratic and would still be running.
 *
 * \~spanish
 * No es una medida -- aqui no se cronometra nada y la construccion no esta
 * afinada para eso --.  Es una afirmacion sobre la FORMA: una rueda con cien mil
 * plazos dentro se rearma un millon de veces y la prueba acaba, cosa que no
 * podria hacer si armar mirara algo que no fuera la entrada que le dieron.  El
 * mismo bucle contra una estructura que buscara el plazo viejo seria cuadratico
 * y seguiria corriendo.
 *
 * \~
 */
void test_a_million_re_arms() {
    const uint32_t kConnections = 100000;

    TimerWheel w;
    check(w.reset(kConnections, 4096, 0), "a big wheel would not be made");

    for (uint32_t i = 0; i < kConnections; ++i)
        check(w.arm(i, 1 + i % 4000) || i == 0, "a deadline was refused");

    check(w.armed_count() == kConnections, "the big wheel lost deadlines");

    /* \~english
     * Ten passes over every connection, each pushing its deadline further out
     * -- which is what ten reads on every connection would do.
     * \~spanish
     * Diez pasadas por todas las conexiones, cada una empujando su plazo mas
     * lejos -- que es lo que harian diez lecturas en cada conexion.
     * \~ */
    for (int pass = 0; pass < 10; ++pass)
        for (uint32_t i = 0; i < kConnections; ++i) w.arm(i, 1 + (i + pass) % 4000);

    check(w.armed_count() == kConnections,
          "a million re-arms changed how many deadlines there are");

    /* \~english
     * And everything still comes out.  A wheel that lost a link somewhere in a
     * million operations would be short here, and nothing else would say so.
     * \~spanish
     * Y todo sigue saliendo.  Una rueda que hubiera perdido un enlace en algun
     * punto de un millon de operaciones se quedaria corta aqui, y no lo diria
     * nada mas.
     * \~ */
    size_t out = 0;
    for (uint64_t t = 0; t <= 4000; ++t) out += drain(w, t);

    check(out == kConnections, "the big wheel did not give everything back");
    check(w.armed_count() == 0, "the big wheel kept something armed");
}

} // namespace

int main() {
    test_a_deadline_comes_due_when_it_should();
    test_a_late_sweep_catches_everything_once();
    test_re_arming_replaces_the_old_deadline();
    test_cancelling_is_safe_to_repeat();
    test_a_cancel_from_the_middle_keeps_the_rest();
    test_a_deadline_past_the_horizon_is_refused();
    test_the_edges_of_the_wheel();
    test_a_million_re_arms();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
