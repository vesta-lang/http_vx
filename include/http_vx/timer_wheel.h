/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/timer_wheel.h
 * @brief
 * \~english When a connection has waited too long, and why that is not a queue.
 * \~spanish Cuando una conexion ha esperado demasiado, y por que eso no es una cola.
 * \~
 *
 * \~english
 * Every connection has a deadline.  With a million of them that is a million
 * timers, and the shape of the thing that holds them decides whether the
 * server works.
 *
 * **The instinct is a priority queue, and it is wrong -- not because of the
 * logarithm, but because of what actually happens to a timer.**  Almost no
 * timer ever fires.  A connection reads something, and its old deadline is
 * replaced by a new one; it reads again, and again.  A busy connection cancels
 * and re-arms its timeout on every single read.  So the operation that has to
 * be cheap is not "find the earliest", it is **cancel this one**, and a heap
 * has no answer to that at all: it can pop the smallest, but removing a
 * known element from the middle means finding it first.
 *
 * A wheel answers it in a way that needs no search.  A timer is a link in a
 * list, the list is one of a fixed number of slots, and the slot is worked out
 * from the deadline by taking a remainder.  Arming is pushing onto a list.
 * Cancelling is unlinking a node whose neighbours it already knows.  Expiring
 * a tick is taking a whole list at once.  None of the three looks at anything
 * it was not handed.
 *
 * **And the price is precision, which is the one thing nobody needs here.**  A
 * slot covers a whole tick, so a deadline lands at the end of the tick it fell
 * in -- an idle timeout of thirty seconds might fire at thirty point nine.  For
 * deciding that a connection has gone away, that is not an error, it is
 * rounding.  What would be an error is spending a comparison per connection
 * per second to avoid it.
 *
 * \~spanish
 * Toda conexion tiene un plazo.  Con un millon de ellas eso es un millon de
 * plazos, y la forma de lo que los guarda decide si el servidor funciona.
 *
 * **El instinto es una cola de prioridad, y esta mal -- no por el logaritmo,
 * sino por lo que de verdad le pasa a un plazo.**  Casi ningun plazo llega a
 * cumplirse.  Una conexion lee algo, y su plazo viejo lo sustituye uno nuevo;
 * lee otra vez, y otra.  Una conexion con trabajo cancela y rearma su plazo en
 * cada lectura.  Asi que la operacion que tiene que ser barata no es "encuentra
 * el primero", es **cancela este**, y un monticulo no tiene ninguna respuesta
 * para eso: sabe sacar el menor, pero quitar un elemento conocido de en medio
 * obliga a encontrarlo antes.
 *
 * Una rueda lo contesta sin buscar nada.  Un plazo es un eslabon de una lista,
 * la lista es una de un numero fijo de casillas, y la casilla sale del plazo
 * con un resto.  Armar es meter en una lista.  Cancelar es desenlazar un nodo
 * que ya conoce a sus vecinos.  Vencer un tic es coger una lista entera de
 * golpe.  Ninguna de las tres mira nada que no le hayan dado.
 *
 * **Y el precio es precision, que es justo lo que aqui no necesita nadie.**  Una
 * casilla cubre un tic entero, asi que un plazo cae al final del tic en que
 * cayo -- un plazo de inactividad de treinta segundos puede vencer a los treinta
 * con nueve.  Para decidir que una conexion se ha ido, eso no es un error, es
 * redondeo.  Lo que si seria un error es gastar una comparacion por conexion y
 * por segundo para evitarlo.
 *
 * \~
 */
#ifndef HTTP_VX_TIMER_WHEEL_H
#define HTTP_VX_TIMER_WHEEL_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english What is returned when there is no timer.
 * \~spanish Lo que se devuelve cuando no hay ningun plazo.
 * \~
 *
 * \~english
 * The largest identifier there is, used as "none".  It is not a valid
 * connection: a server holding four thousand million connections at once has
 * problems this class cannot help with.
 *
 * \~spanish
 * El identificador mas grande que hay, usado como "ninguno".  No es una conexion
 * valida: un servidor con cuatro mil millones de conexiones a la vez tiene
 * problemas con los que esta clase no puede ayudar.
 *
 * \~
 */
constexpr uint32_t kNoTimer = 0xFFFFFFFF;

/**
 * @brief
 * \~english The deadlines of one shard.
 * \~spanish Los plazos de un fragmento.
 * \~
 *
 * \~english
 * One per shard and never shared, which is what makes every operation here a
 * few writes with no atomics and no lock: R4 says a connection never changes
 * shard, so its deadline never crosses a thread either.
 *
 * \~spanish
 * Una por fragmento y nunca compartida, que es lo que hace que aqui toda
 * operacion sean unas cuantas escrituras sin atomicos y sin cerrojo: la R4 dice
 * que una conexion no cambia de fragmento, asi que su plazo tampoco cruza un
 * hilo.
 *
 * \~
 */
class TimerWheel {
  public:
    TimerWheel() noexcept = default;
    ~TimerWheel();

    TimerWheel(const TimerWheel &) = delete;
    TimerWheel &operator=(const TimerWheel &) = delete;

    /**
     * @brief
     * \~english Makes room for @p capacity identifiers over @p slots ticks.
     * \~spanish Hace sitio para @p capacity identificadores sobre @p slots tics.
     * \~
     *
     * \~english
     * Both are fixed for the life of the shard, and neither grows.  The
     * identifiers are indices into this wheel's own arrays -- which is the
     * whole reason cancelling needs no search -- so a wheel that grew would
     * have to move them, and the thing that makes them useful is that they do
     * not move.
     *
     * @p slots is rounded UP to a power of two, because the slot of a deadline
     * is a remainder and a remainder by a power of two is a mask.  It is
     * rounded rather than refused because the number a caller has in mind is
     * "about four minutes", not a bit pattern.
     *
     * \~spanish
     * Los dos son fijos para toda la vida del fragmento, y ninguno crece.  Los
     * identificadores son indices de los propios arrays de esta rueda -- que es
     * toda la razon de que cancelar no busque nada -- asi que una rueda que
     * creciera tendria que moverlos, y lo que los hace utiles es que no se
     * mueven.
     *
     * @p slots se redondea HACIA ARRIBA a potencia de dos, porque la casilla de
     * un plazo es un resto y un resto entre una potencia de dos es una mascara.
     * Se redondea en vez de rechazarse porque el numero que tiene en la cabeza
     * quien llama es "unos cuatro minutos", no un patron de bits.
     *
     * \~
     * **@p now is when the wheel starts**, and it is given here rather than
     * worked out at the first sweep for a reason that cost a bug: a deadline
     * armed before the first sweep has to land in a slot measured from
     * somewhere, and a wheel that decided where it was only once somebody
     * asked it to expire something would put those deadlines in slots
     * measured from zero and then look for them in slots measured from the
     * clock.  They would not fire until the wheel had turned all the way
     * round.  A shard whose clock is the machine's uptime would never see them
     * at all.
     *
     * \~spanish
     * **@p now es cuando empieza la rueda**, y se da aqui en vez de averiguarlo
     * en el primer barrido por una razon que costo un fallo: un plazo armado
     * antes del primer barrido tiene que caer en una casilla medida desde algun
     * sitio, y una rueda que decidiera donde estaba solo cuando alguien le
     * pidiera vencer algo pondria esos plazos en casillas medidas desde cero y
     * luego los buscaria en casillas medidas desde el reloj.  No venceran hasta
     * que la rueda haya dado la vuelta entera.  Un fragmento cuyo reloj sea el
     * tiempo encendido de la maquina no los veria nunca.
     *
     * \~
     * @param capacity \~english the most identifiers at once
     *                 \~spanish los identificadores mas a la vez  \~
     * @param slots    \~english how many ticks the wheel covers
     *                 \~spanish cuantos tics abarca la rueda  \~
     * @param now      \~english what tick it is when the wheel starts
     *                 \~spanish en que tic se esta cuando empieza la rueda  \~
     * @return         \~english false if the memory could not be had
     *                 \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t capacity, uint32_t slots, uint64_t now) noexcept;

    /**
     * @brief
     * \~english Sets @p id to come due @p ticks from now.
     * \~spanish Pone a @p id a vencer dentro de @p ticks tics.
     * \~
     *
     * \~english
     * Arming an identifier that is already armed REPLACES its deadline, and
     * that is the common case rather than a corner: every read of a connection
     * pushes its idle timeout further out, so this is called far more often
     * than anything ever expires.  It is one unlink and one push, and it looks
     * at nothing it was not handed.
     *
     * **A deadline further away than the wheel reaches is refused**, loudly,
     * instead of being folded round.  A wheel of a thousand slots asked for a
     * deadline a thousand and one ticks away has a slot for it -- the same one
     * as a deadline of one tick -- and putting it there would make a
     * connection time out a thousand ticks early.  Nothing would report an
     * error; a few connections would just die young, on a server that looked
     * fine.
     *
     * \~spanish
     * Armar un identificador que ya esta armado SUSTITUYE su plazo, y ese es el
     * caso corriente y no una esquina: cada lectura de una conexion empuja su
     * plazo de inactividad mas lejos, asi que esto se llama muchisimas mas veces
     * de las que vence nada.  Es un desenlace y un meter en una lista, y no mira
     * nada que no le hayan dado.
     *
     * **Un plazo mas lejos de lo que alcanza la rueda se rechaza**, en voz alta,
     * en vez de darle la vuelta.  Una rueda de mil casillas a la que le pidan un
     * plazo de mil un tics tiene casilla para el -- la misma que la de un plazo
     * de un tic -- y ponerlo ahi haria vencer una conexion mil tics antes de
     * tiempo.  Nadie daria ningun error; solo se moririan jovenes unas cuantas
     * conexiones, en un servidor que se veria bien.
     *
     * \~
     * @param id    \~english which one  \~spanish cual  \~
     * @param ticks \~english how far away, from one to @c horizon
     *              \~spanish cuanto mas alla, de uno a @c horizon  \~
     * @return      \~english false if @p id or @p ticks is out of range
     *              \~spanish false si @p id o @p ticks se salen  \~
     */
    bool arm(uint32_t id, uint32_t ticks) noexcept;

    /**
     * @brief
     * \~english Takes @p id's deadline away.
     * \~spanish Le quita el plazo a @p id.
     * \~
     *
     * \~english
     * Cancelling one that is not armed does nothing and is not an error.  A
     * connection is closed from more than one place -- the peer went away, a
     * request failed, the deadline itself came due -- and making each of them
     * remember whether the timer was still there would be making each of them
     * keep a copy of this class's state.
     *
     * \~spanish
     * Cancelar uno que no esta armado no hace nada y no es un error.  Una
     * conexion se cierra desde mas de un sitio -- el otro extremo se fue, una
     * peticion fallo, el plazo mismo vencio -- y hacer que cada uno de ellos se
     * acuerde de si el plazo seguia ahi seria hacer que cada uno guarde una
     * copia del estado de esta clase.
     *
     * \~
     * @param id \~english which one  \~spanish cual  \~
     */
    void cancel(uint32_t id) noexcept;

    /**
     * @brief
     * \~english Whether @p id has a deadline.
     * \~spanish Si @p id tiene plazo.
     * \~
     *
     * @param id \~english which one  \~spanish cual  \~
     * @return   \~english whether it is armed  \~spanish si esta armado  \~
     */
    bool armed(uint32_t id) const noexcept;

    /**
     * @brief
     * \~english Hands back one identifier that has come due, or @c kNoTimer.
     * \~spanish Devuelve un identificador que ha vencido, o @c kNoTimer.
     * \~
     *
     * \~english
     * Called in a loop until it says there are no more.  One at a time rather
     * than a list, because a list would have to go somewhere -- and whatever
     * the caller does with an expired connection is allowed to arm or cancel
     * other timers, which a caller walking a snapshot could not be allowed to
     * do.
     *
     * An expired identifier is UNARMED before it is handed over, so the caller
     * may do anything with it, including arming it again -- which is what
     * happens when a deadline means "ask, and wait some more" rather than
     * "close".
     *
     * \~spanish
     * Se llama en bucle hasta que diga que no hay mas.  De uno en uno y no una
     * lista, porque una lista tendria que ir a alguna parte -- y lo que haga
     * quien llama con una conexion vencida puede armar o cancelar otros plazos,
     * cosa que no se le podria permitir a quien estuviera recorriendo una foto
     * fija.
     *
     * Un identificador vencido se DESARMA antes de entregarlo, asi que quien
     * llama puede hacer con el lo que quiera, incluido volver a armarlo -- que
     * es lo que pasa cuando un plazo quiere decir "pregunta, y espera otro
     * poco" en vez de "cierra".
     *
     * \~
     * @param now \~english what tick it is now
     *            \~spanish en que tic se esta ahora  \~
     * @return    \~english an identifier, or @c kNoTimer when there are none left
     *            \~spanish un identificador, o @c kNoTimer cuando no queda ninguno  \~
     */
    uint32_t take_due(uint64_t now) noexcept;

    /**
     * @brief
     * \~english The furthest ahead a deadline may be set.
     * \~spanish Lo mas lejos que se puede poner un plazo.
     * \~
     *
     * \~english
     * One less than the number of slots.  The last slot is the one being
     * emptied, and a deadline landing in it would come due immediately rather
     * than a whole turn later -- so it is not offered, instead of being offered
     * and meaning something else.
     *
     * \~spanish
     * Una menos que el numero de casillas.  La ultima casilla es la que se esta
     * vaciando, y un plazo que cayera en ella venceria en el acto en vez de una
     * vuelta despues -- asi que no se ofrece, en lugar de ofrecerse y significar
     * otra cosa.
     *
     * \~
     */
    uint32_t horizon() const noexcept { return slots_ == 0 ? 0 : slots_ - 1; }

    /// \~english How many are armed.  \~spanish Cuantos hay armados.  \~
    size_t armed_count() const noexcept { return armed_; }

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

  private:
    /// \~english Takes @p id out of whatever list it is in.
    /// \~spanish Saca a @p id de la lista en la que este.  \~
    void unlink(uint32_t id) noexcept;

    /**
     * \~english
     * One entry per identifier, indexed by it.  Two links and the slot it is
     * in: twelve bytes, and the reason a cancel is three writes.  A connection
     * that is not armed has @c kNoTimer in @c slot, which is the one field
     * that has to be true for the other two to be read.
     *
     * \~spanish
     * Una entrada por identificador, indexada por el.  Dos enlaces y la casilla
     * en que esta: doce bytes, y la razon de que cancelar sean tres escrituras.
     * Una conexion que no esta armada tiene @c kNoTimer en @c slot, que es el
     * unico campo que tiene que ser cierto para leer los otros dos.
     * \~
     */
    struct Entry {
        uint32_t prev;
        uint32_t next;
        uint32_t slot;
    };

    Entry *entries_ = nullptr;
    uint32_t *heads_ = nullptr;

    uint32_t capacity_ = 0;
    uint32_t slots_ = 0;
    uint32_t mask_ = 0;
    size_t armed_ = 0;

    /**
     * \~english
     * The tick this wheel has emptied up to.  It only ever goes forward:
     * @c take_due with a @p now behind it does nothing, because a clock that
     * went backwards is a clock, not a reason to fire every timer at once.
     * \~spanish
     * El tic hasta el que esta vaciada esta rueda.  Solo va hacia delante:
     * @c take_due con un @p now anterior no hace nada, porque un reloj que fue
     * hacia atras es un reloj, no una razon para vencer todos los plazos de
     * golpe.
     * \~
     */
    uint64_t swept_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_TIMER_WHEEL_H
