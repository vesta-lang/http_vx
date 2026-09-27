/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/kick_queue.h
 * @brief
 * \~english A shard's kicks: a lock-free stack whose nodes are the sources, and a coalesced wake.
 * \~spanish Los avisos de un fragmento: una pila sin cerrojos cuyos nodos son las fuentes, y un despertar agrupado.
 * \~
 *
 * \~english
 * HVX-5, 6.  Kicking a source is an exchange on its own mark -- a source is
 * in the stack at most once, however often it is kicked -- and, the first
 * time, a compare-and-swap on the head.  The shard takes the whole stack with
 * one exchange.  Nothing is allocated and nothing is locked; nodes are never
 * removed from the middle, so there is no ABA to guard against.
 *
 * Waking follows Dekker: the shard publishes "sleeping" and THEN looks at the
 * stack again; a kicker pushes and THEN looks at "sleeping".  With sequential
 * order on both sides one of them always sees the other, and a race costs at
 * most one wake too many -- never one too few.
 * \~spanish
 * HVX-5, 6.  Avisar a una fuente es un intercambio sobre su propia marca --
 * una fuente esta en la pila como mucho una vez, por muchas veces que la
 * avisen -- y, la primera vez, un compare-and-swap sobre la cabeza.  El
 * fragmento se lleva la pila entera con un intercambio.  No se reserva nada ni
 * se bloquea nada; los nodos nunca se quitan del medio, asi que no hay ABA del
 * que protegerse.
 *
 * Despertar sigue a Dekker: el fragmento publica "durmiendo" y DESPUES vuelve
 * a mirar la pila; quien avisa mete y DESPUES mira "durmiendo".  Con orden
 * secuencial en los dos lados uno de los dos ve siempre al otro, y una carrera
 * cuesta como mucho un despertar de mas -- nunca uno de menos.
 * \~
 */
#ifndef HTTP_VX_KICK_QUEUE_H
#define HTTP_VX_KICK_QUEUE_H

#include "http_vx/open_response.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace http_vx {

class Backend;

/**
 * @brief
 * \~english What a shard's kick queue has counted.
 * \~spanish Lo que ha contado la cola de avisos de un fragmento.
 * \~
 */
struct KickCounts {
    /// \~english Sources taken from the stack.  \~spanish Fuentes sacadas de la pila.  \~
    uint64_t taken = 0;
    /// \~english Kicks that found their source already queued.  \~spanish Avisos que encontraron su fuente ya en la cola.  \~
    uint64_t coalesced = 0;
    /// \~english Times a sleeping shard was woken.  \~spanish Veces que se desperto a un fragmento dormido.  \~
    uint64_t wakes = 0;
    /// \~english Wakes the backend could not deliver.  \~spanish Despertares que el backend no pudo entregar.  \~
    uint64_t failed_wakes = 0;
    /// \~english Sources ended, by reason (indexed by @c GoneReason).  \~spanish Fuentes acabadas, por motivo (indice @c GoneReason).  \~
    uint64_t gone[5] = {};
};

/**
 * @brief
 * \~english One shard's kicks.
 * \~spanish Los avisos de un fragmento.
 * \~
 */
class KickQueue {
public:
    KickQueue() noexcept = default;
    KickQueue(const KickQueue &) = delete;
    KickQueue &operator=(const KickQueue &) = delete;

    /// \~english The backend a sleeping shard is woken through.  \~spanish El backend por el que se despierta a un fragmento dormido.  \~
    void reset(Backend *io) noexcept;

    /**
     * @brief
     * \~english Opens @p s for @p r: from now on it can be kicked, and @p target is told.
     * \~spanish Abre @p s para @p r: desde ahora se la puede avisar, y se le dice a @p target.
     * \~
     */
    void open(BodySource &s, KickTarget &target, OpenResponse r) noexcept;

    /**
     * @brief
     * \~english Ends @p s; its @c gone comes when it is out of the stack.
     * \~spanish Acaba @p s; su @c gone llega cuando esta fuera de la pila.
     * \~
     *
     * \~english
     * The mark is set for good with an exchange.  Was it clear?  Then no
     * thread holds the source and @c gone is delivered now.  Was it set?  Then
     * the source is in the stack, or a kicker is pushing it this instant, and
     * @c gone is delivered when the shard takes it (HVX-5, 4.4).
     * \~spanish
     * La marca se pone para siempre con un intercambio.  Estaba a cero?
     * Entonces ningun hilo tiene la fuente y @c gone se entrega ya.  Estaba
     * puesta?  Entonces la fuente esta en la pila, o alguien la esta metiendo en
     * este instante, y @c gone se entrega cuando el fragmento la saque (HVX-5,
     * 4.4).
     * \~
     *
     * @return \~english false if @p s was ended already: nothing was done
     *         \~spanish false si @p s ya estaba acabada: no se hizo nada  \~
     */
    bool close(BodySource &s, GoneReason why) noexcept;

    /// \~english Pushes @p s, and wakes the shard if it sleeps; any thread.  \~spanish Mete @p s, y despierta al fragmento si duerme; cualquier hilo.  \~
    bool kick(BodySource &s) noexcept;

    /**
     * @brief
     * \~english The shard is about to wait: publishes "sleeping", then looks again.
     * \~spanish El fragmento va a esperar: publica "durmiendo", y vuelve a mirar.
     * \~
     *
     * @return \~english false if a kick is already there: do not sleep
     *         \~spanish false si ya hay un aviso: no dormir  \~
     */
    bool about_to_sleep() noexcept;

    /// \~english The shard is back from its wait.  \~spanish El fragmento vuelve de su espera.  \~
    void awake() noexcept;

    /**
     * @brief
     * \~english Takes every kicked source and hands each to its target, or delivers its @c gone.
     * \~spanish Se lleva cada fuente avisada y se la da a su destino, o le entrega su @c gone.
     * \~
     *
     * \~english
     * A live source's mark is cleared BEFORE its target is told, so a kick
     * that arrives while it fills queues it again instead of being lost.
     * \~spanish
     * La marca de una fuente viva se limpia ANTES de decirselo a su destino,
     * asi que un aviso que llega mientras rellena la vuelve a meter en vez de
     * perderse.
     * \~
     *
     * @return \~english how many sources were taken  \~spanish cuantas fuentes se sacaron  \~
     */
    size_t drain() noexcept;

    /// \~english Whether any kick is waiting.  \~spanish Si hay algun aviso esperando.  \~
    bool pending() const noexcept { return head_.load(std::memory_order_acquire) != nullptr; }

    /// \~english What has been counted.  \~spanish Lo que se ha contado.  \~
    KickCounts counts() const noexcept;

private:
    /// \~english Hands @p s its @c gone and counts it.  \~spanish Le entrega a @p s su @c gone y lo cuenta.  \~
    void deliver_gone(BodySource &s) noexcept;

    std::atomic<BodySource *> head_{nullptr};
    std::atomic<uint32_t> sleeping_{0};
    Backend *io_ = nullptr;

    /// \~english Counted by kickers, which may be any thread.  \~spanish Contados por quien avisa, que puede ser cualquier hilo.  \~
    std::atomic<uint64_t> wakes_{0};
    std::atomic<uint64_t> failed_wakes_{0};

    /// \~english Counted by the shard alone.  \~spanish Contados solo por el fragmento.  \~
    uint64_t taken_ = 0;
    uint64_t coalesced_ = 0;
    uint64_t gone_[5] = {};
};

} // namespace http_vx

#endif // HTTP_VX_KICK_QUEUE_H
