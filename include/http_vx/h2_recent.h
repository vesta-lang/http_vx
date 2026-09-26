/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_recent.h
 * @brief
 * \~english How the recent streams ended: the memory that tells a late frame from a wrong one.
 * \~spanish Como acabaron los flujos recientes: la memoria que distingue una trama tardia de una mala.
 * \~
 *
 * \~english
 * A stream that is over is forgotten by the stream table, and for most
 * frames that is enough: the highest identifier seen says it existed.  It is
 * not enough to answer the one question RFC 9113, 5.1 makes depend on HOW a
 * stream closed.  When THIS end sent the RST_STREAM, the peer may have sent
 * or queued any kind of frame before it read the reset, and every one of them
 * "MUST [be] minimally process[ed] and then discard[ed]" -- a HEADERS still
 * goes through HPACK, a DATA still counts against the connection window.
 * When the stream closed any other way, the peer knew it was over when it
 * sent the frame, and the section lets that be a connection error of type
 * STREAM_CLOSED.  Killing a connection over the first kind is the bug this
 * exists to prevent; waving the second kind through would hide a peer that
 * has lost track of its own streams.
 *
 * **What is kept is two bits per identifier, for the last @c kRecentStreams
 * client identifiers.**  One says the stream was opened (so a lower
 * identifier that was never opened, which RFC 9113, 5.1.1 calls closed but
 * refuses as a reused number, can be told apart); the other says this end
 * reset it.  Client identifiers are odd, so identifier @c id lives in slot
 * `id / 2`, and the slots form a ring that slides forward as higher
 * identifiers are opened.  Asking is a shift and a mask; opening is the same
 * plus clearing the slots skipped over, which is at most both rings --
 * sixteen words -- however far the peer jumps.  Nothing grows: the memory is
 * the same for a connection that served one request and one that served a
 * billion, and a peer cannot make it larger.
 *
 * **And what falls off the end is treated as reset here.**  An identifier
 * older than the ring has no answer, and the RFC says which guess is safe:
 * "An endpoint can perform this minimal processing for all streams that are
 * in the 'closed' state" (RFC 9113, 5.1).  Ignoring a frame of an old stream
 * that closed normally loses a MAY; treating a frame of an old stream this
 * end reset as an error breaks a MUST and drops a connection that did nothing
 * wrong.  So the forgotten ones are ignored.  The window is wide enough that
 * this only happens to a peer that opened hundreds of streams after the one
 * whose frame is arriving -- by then the frame is either very late or wrong,
 * and costing it a decode and a window credit is what both answers cost.
 *
 * The ring lives inside the stream table rather than being allocated: at
 * sixteen words it is smaller than the pointer bookkeeping an allocation
 * would need to be worth it, and an allocation would put a failure path in
 * the middle of opening a stream.
 *
 * \~spanish
 * Un flujo terminado lo olvida la tabla de flujos, y para casi todas las
 * tramas basta: el identificador mayor visto dice que existio.  No basta para
 * contestar la unica pregunta que el RFC 9113, 5.1 hace depender de COMO se
 * cerro un flujo.  Cuando el RST_STREAM lo mando ESTE extremo, el otro puede
 * haber mandado o encolado cualquier tipo de trama antes de leer el reinicio,
 * y todas ellas "MUST [be] minimally process[ed] and then discard[ed]" -- un
 * HEADERS pasa igual por HPACK, un DATA cuenta igual contra la ventana de la
 * conexion.  Cuando el flujo se cerro de otra forma, el otro sabia que se
 * habia acabado cuando mando la trama, y la seccion deja que eso sea un error
 * de conexion de tipo STREAM_CLOSED.  Matar una conexion por lo primero es el
 * fallo que esto existe para evitar; dejar pasar lo segundo esconderia a un
 * extremo que ha perdido la cuenta de sus propios flujos.
 *
 * **Lo que se guarda son dos bits por identificador, de los ultimos
 * @c kRecentStreams identificadores del cliente.**  Uno dice que el flujo se
 * abrio (para distinguir un identificador menor que no se abrio nunca, que el
 * RFC 9113, 5.1.1 llama cerrado pero rechaza como numero reutilizado); el otro
 * dice que este extremo lo reinicio.  Los identificadores del cliente son
 * impares, asi que el identificador @c id vive en la plaza `id / 2`, y las
 * plazas forman un anillo que avanza segun se abren identificadores mayores.
 * Preguntar es un desplazamiento y una mascara; abrir es lo mismo mas limpiar
 * las plazas saltadas, que como mucho son los dos anillos -- dieciseis
 * palabras -- salte lo que salte el otro extremo.  No crece nada: la memoria es la misma
 * para una conexion que sirvio una peticion y para una que sirvio mil
 * millones, y el otro extremo no puede hacerla mayor.
 *
 * **Y lo que se cae por el final se trata como reiniciado aqui.**  Un
 * identificador mas viejo que el anillo no tiene respuesta, y el RFC dice que
 * suposicion es segura: "An endpoint can perform this minimal processing for
 * all streams that are in the 'closed' state" (RFC 9113, 5.1).  Ignorar una
 * trama de un flujo viejo que se cerro normalmente pierde un MAY; tratar como
 * error una trama de un flujo viejo que reinicio este extremo rompe un MUST y
 * tira una conexion que no hizo nada mal.  Asi que los olvidados se ignoran.
 * La ventana es lo bastante ancha para que esto solo le pase a un extremo que
 * abrio cientos de flujos despues de aquel cuya trama llega -- para entonces la
 * trama es o muy tardia o mala, y lo que le cuesta es un descodificado y un
 * abono de ventana, que es lo que cuestan las dos respuestas.
 *
 * El anillo vive dentro de la tabla de flujos en vez de reservarse: con
 * dieciseis palabras es mas pequeno que la contabilidad que haria falta para
 * que una reserva compensara, y una reserva pondria un camino de fallo en
 * medio de abrir un flujo.
 *
 * \~
 */
#ifndef HTTP_VX_H2_RECENT_H
#define HTTP_VX_H2_RECENT_H

#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english How many client identifiers are remembered: the width of the ring.
 * \~spanish Cuantos identificadores del cliente se recuerdan: el ancho del anillo.
 * \~
 *
 * \~english
 * Five hundred and twelve, four times the default of
 * `SETTINGS_MAX_CONCURRENT_STREAMS`.  A frame that this end has to ignore is
 * one the peer sent before it read a reset, so it trails the reset by one
 * round trip; for it to fall off the ring the peer would have to open five
 * hundred streams inside that round trip.  And falling off is safe anyway --
 * see the file notes -- so the number buys strictness, not correctness.
 * \~spanish
 * Quinientos doce, cuatro veces el valor por defecto de
 * `SETTINGS_MAX_CONCURRENT_STREAMS`.  Una trama que este extremo tiene que
 * ignorar es una que el otro mando antes de leer un reinicio, asi que va una
 * ida y vuelta por detras del reinicio; para que se cayera del anillo el otro
 * tendria que abrir quinientos flujos dentro de esa ida y vuelta.  Y caerse es
 * seguro de todas formas -- ver las notas del fichero --, asi que el numero
 * compra rigor, no correccion.
 * \~
 */
constexpr uint32_t kRecentStreams = 512;

/**
 * @brief
 * \~english What is known about a stream that is not in the table any more.
 * \~spanish Lo que se sabe de un flujo que ya no esta en la tabla.
 * \~
 */
enum class Past : uint8_t {
    /**
     * \~english
     * Older than the ring: nothing is known, and it is treated as @c ResetHere
     * (RFC 9113, 5.1 allows the minimal processing for every closed stream).
     * \~spanish
     * Mas viejo que el anillo: no se sabe nada, y se trata como @c ResetHere
     * (el RFC 9113, 5.1 permite el procesado minimo para todo flujo cerrado).
     * \~
     */
    Forgotten,

    /**
     * \~english
     * Never opened: an identifier the peer skipped, which closed when a
     * higher one was opened (RFC 9113, 5.1.1).
     * \~spanish
     * No se abrio nunca: un identificador que el otro extremo se salto, y que
     * se cerro cuando se abrio uno mayor (RFC 9113, 5.1.1).
     * \~
     */
    Skipped,

    /**
     * \~english
     * Opened, and ended without this end resetting it: both sides finished,
     * or the PEER reset it.  Either way the peer knew.
     * \~spanish
     * Abierto, y acabado sin que este extremo lo reiniciara: acabaron los dos
     * lados, o lo reinicio el OTRO.  En los dos casos el otro lo sabia.
     * \~
     */
    Closed,

    /**
     * \~english
     * This end sent RST_STREAM on it.  Frames still arriving were sent before
     * the peer could know, and are processed minimally and dropped.
     * \~spanish
     * Este extremo mando RST_STREAM por el.  Las tramas que sigan llegando se
     * mandaron antes de que el otro pudiera saberlo, y se procesan lo minimo y
     * se tiran.
     * \~
     */
    ResetHere,
};

/**
 * @brief
 * \~english Two bits for each of the last @c kRecentStreams client identifiers.
 * \~spanish Dos bits por cada uno de los ultimos @c kRecentStreams identificadores del cliente.
 * \~
 */
class RecentStreams {
  public:
    /**
     * @brief
     * \~english Forgets everything, for a new connection.
     * \~spanish Lo olvida todo, para una conexion nueva.
     * \~
     *
     * \~english
     * The bits are not cleared, and need not be: with nothing opened no slot
     * is asked about, and @c opened clears every slot it moves over before
     * any of them can be.
     * \~spanish
     * Los bits no se limpian, ni hace falta: sin nada abierto no se pregunta
     * por ninguna plaza, y @c opened limpia cada plaza que pasa antes de que se
     * pueda preguntar por ella.
     * \~
     */
    void reset() noexcept { next_ = 0; }

    /**
     * @brief
     * \~english Says the peer opened @p id, the highest so far.
     * \~spanish Dice que el otro extremo abrio @p id, el mayor hasta ahora.
     * \~
     *
     * \~english
     * The ring slides up to it, and every slot it slides over is cleared: the
     * identifiers skipped on the way were never opened, and whatever those
     * slots said was about identifiers a whole ring older.  An @p id that is
     * not above the last one opened is not an opening and changes nothing.
     * \~spanish
     * El anillo avanza hasta el, y cada plaza que salta se limpia: los
     * identificadores saltados por el camino no se abrieron nunca, y lo que
     * dijeran esas plazas era de identificadores un anillo entero mas viejos.
     * Un @p id que no esta por encima del ultimo abierto no es una apertura y no
     * cambia nada.
     * \~
     * @param id \~english an odd identifier  \~spanish un identificador impar  \~
     */
    void opened(uint32_t id) noexcept {
        const uint32_t slot = id >> 1;
        if (slot < next_) return;

        clear_slots(next_, slot + 1 - next_);
        next_ = slot + 1;
        set(opened_, slot);
    }

    /**
     * @brief
     * \~english Says this end sent RST_STREAM on @p id.
     * \~spanish Dice que este extremo mando RST_STREAM por @p id.
     * \~
     *
     * @param id \~english an identifier already opened
     *           \~spanish un identificador ya abierto  \~
     */
    void reset_here(uint32_t id) noexcept {
        const uint32_t slot = id >> 1;
        if (!remembers(slot)) return;
        set(reset_, slot);
    }

    /**
     * @brief
     * \~english How @p id ended.
     * \~spanish Como acabo @p id.
     * \~
     *
     * \~english
     * Asked only about an odd identifier at or below the highest opened and
     * not in the stream table; anything above has not happened yet and is
     * answered @c Skipped, which is what it will be if it is never opened.
     * \~spanish
     * Solo se pregunta por un identificador impar igual o por debajo del mayor
     * abierto y que no esta en la tabla de flujos; uno por encima todavia no ha
     * pasado y se contesta @c Skipped, que es lo que sera si no se abre nunca.
     * \~
     * @param id \~english the identifier  \~spanish el identificador  \~
     * @return   \~english what is known  \~spanish lo que se sabe  \~
     */
    Past past(uint32_t id) const noexcept {
        const uint32_t slot = id >> 1;
        if (slot >= next_) return Past::Skipped;
        if (!remembers(slot)) return Past::Forgotten;
        if (get(reset_, slot)) return Past::ResetHere;
        if (get(opened_, slot)) return Past::Closed;
        return Past::Skipped;
    }

  private:
    static constexpr uint32_t kWords = kRecentStreams / 64;

    static_assert(kRecentStreams % 64 == 0,
                  "the ring is a whole number of words");

    /// \~english Whether @p slot is still inside the ring.
    /// \~spanish Si @p slot sigue dentro del anillo.  \~
    bool remembers(uint32_t slot) const noexcept {
        return slot < next_ && next_ - slot <= kRecentStreams;
    }

    static void set(uint64_t *bits, uint32_t slot) noexcept {
        const uint32_t at = slot % kRecentStreams;
        bits[at / 64] |= uint64_t{1} << (at % 64);
    }

    static bool get(const uint64_t *bits, uint32_t slot) noexcept {
        const uint32_t at = slot % kRecentStreams;
        return (bits[at / 64] >> (at % 64) & 1) != 0;
    }

    /**
     * @brief
     * \~english Clears @p count slots from @p from, in both rings, a word at a time.
     * \~spanish Limpia @p count plazas desde @p from, en los dos anillos, de palabra en palabra.
     * \~
     *
     * \~english
     * A word at a time so that a peer that jumps its identifiers by the width
     * of the ring on every HEADERS costs sixteen word writes and not a
     * thousand bit writes.
     * \~spanish
     * De palabra en palabra para que un extremo que salte sus identificadores
     * el ancho del anillo en cada HEADERS cueste dieciseis escrituras de palabra
     * y no mil de bit.
     * \~
     * @param from  \~english the first slot  \~spanish la primera plaza  \~
     * @param count \~english how many  \~spanish cuantas  \~
     */
    void clear_slots(uint32_t from, uint32_t count) noexcept {
        if (count >= kRecentStreams) {
            for (uint32_t i = 0; i < kWords; ++i) {
                opened_[i] = 0;
                reset_[i] = 0;
            }
            return;
        }

        uint32_t at = from % kRecentStreams;
        while (count != 0) {
            const uint32_t bit = at % 64;
            const uint32_t room = 64 - bit;
            const uint32_t n = count < room ? count : room;
            const uint64_t mask =
                n == 64 ? ~uint64_t{0} : ((uint64_t{1} << n) - 1) << bit;

            opened_[at / 64] &= ~mask;
            reset_[at / 64] &= ~mask;

            count -= n;
            at = (at + n) % kRecentStreams;
        }
    }

    uint64_t opened_[kWords] = {};
    uint64_t reset_[kWords] = {};

    /// \~english One past the slot of the highest identifier opened; 0 before any.
    /// \~spanish Una mas que la plaza del identificador mayor abierto; 0 antes de ninguno.  \~
    uint32_t next_ = 0;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_RECENT_H
