/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/shard_wake.h
 * @brief
 * \~english A shard's "sleeping" mark and its coalesced wake: one owner for every stack that can wake it.
 * \~spanish La marca "durmiendo" de un fragmento y su despertar agrupado: un solo dueno para cada pila que pueda despertarlo.
 * \~
 *
 * \~english
 * HVX-5, 6.3 and HVX-6, 6.  A shard has several lock-free stacks other threads
 * push into -- the kicks of open responses and the mailbox -- and ONE way to be
 * woken.  If each stack kept its own flag, a shard would have to publish
 * several of them before sleeping and a producer could wake it through a flag
 * the shard had already cleared; with one flag the protocol is the same as it
 * was for a single stack:
 *
 *  - the shard publishes "sleeping" ONCE, THEN looks at every stack again;
 *  - a producer pushes, THEN exchanges "sleeping" with 0 and wakes if it was 1.
 *
 * Sequential order on both sides: one of them always sees the other, and a
 * race costs at most one wake too many -- never one too few.
 * \~spanish
 * HVX-5, 6.3 y HVX-6, 6.  Un fragmento tiene varias pilas sin cerrojos en las
 * que meten otros hilos -- los avisos de las respuestas abiertas y el buzon --
 * y UNA sola forma de despertarlo.  Si cada pila tuviera su propia marca, el
 * fragmento tendria que publicar varias antes de dormir y un productor podria
 * despertarlo por una marca que el ya habia limpiado; con una sola marca el
 * protocolo es el mismo que con una pila:
 *
 *  - el fragmento publica "durmiendo" UNA vez, DESPUES vuelve a mirar cada pila;
 *  - un productor mete, DESPUES intercambia "durmiendo" con 0 y despierta si era 1.
 *
 * Orden secuencial en los dos lados: uno de los dos ve siempre al otro, y una
 * carrera cuesta como mucho un despertar de mas -- nunca uno de menos.
 * \~
 */
#ifndef HTTP_VX_SHARD_WAKE_H
#define HTTP_VX_SHARD_WAKE_H

#include <atomic>
#include <cstdint>

namespace http_vx {

class Backend;

/**
 * @brief
 * \~english What a shard's wake has counted.
 * \~spanish Lo que ha contado el despertar de un fragmento.
 * \~
 */
struct WakeCounts {
    /// \~english Times a sleeping shard was woken.  \~spanish Veces que se desperto a un fragmento dormido.  \~
    uint64_t wakes = 0;
    /// \~english Wakes the backend could not deliver.  \~spanish Despertares que el backend no pudo entregar.  \~
    uint64_t failed_wakes = 0;
};

/**
 * @brief
 * \~english One shard's "sleeping" mark and the backend wake behind it.
 * \~spanish La marca "durmiendo" de un fragmento y el despertar del backend que hay detras.
 * \~
 */
class ShardWake {
public:
    ShardWake() noexcept = default;
    ShardWake(const ShardWake &) = delete;
    ShardWake &operator=(const ShardWake &) = delete;

    /// \~english The backend a sleeping shard is woken through; counts start again.  \~spanish El backend por el que se despierta a un fragmento dormido; las cuentas empiezan otra vez.  \~
    void reset(Backend *io) noexcept;

    /**
     * @brief
     * \~english The shard is about to wait: publishes "sleeping".  The caller MUST then look at every stack again.
     * \~spanish El fragmento va a esperar: publica "durmiendo".  Quien llama DEBE despues volver a mirar cada pila.
     * \~
     */
    void publish_sleeping() noexcept { sleeping_.store(1, std::memory_order_seq_cst); }

    /// \~english A stack was not empty after all: the shard will not sleep.  \~spanish Una pila no estaba vacia: el fragmento no va a dormir.  \~
    void cancel_sleeping() noexcept { sleeping_.store(0, std::memory_order_relaxed); }

    /// \~english The shard is back from its wait.  \~spanish El fragmento vuelve de su espera.  \~
    void awake() noexcept { sleeping_.store(0, std::memory_order_relaxed); }

    /**
     * @brief
     * \~english A producer has pushed: wakes the shard if it sleeps; any thread.
     * \~spanish Un productor ha metido: despierta al fragmento si duerme; cualquier hilo.
     * \~
     *
     * \~english
     * Only the first push since the shard went to sleep finds 1 and pays the
     * system call; every other one is this exchange and nothing more.
     * \~spanish
     * Solo el primer push desde que el fragmento se durmio encuentra un 1 y
     * paga la llamada al sistema; cualquier otro es este intercambio y nada mas.
     * \~
     *
     * @return \~english false if the wake could not be delivered (counted)  \~spanish false si el despertar no se pudo entregar (contado)  \~
     */
    bool notify() noexcept;

    /// \~english What has been counted.  \~spanish Lo que se ha contado.  \~
    WakeCounts counts() const noexcept;

private:
    std::atomic<uint32_t> sleeping_{0};
    Backend *io_ = nullptr;

    /// \~english Counted by producers, which may be any thread.  \~spanish Contados por los productores, que pueden ser cualquier hilo.  \~
    std::atomic<uint64_t> wakes_{0};
    std::atomic<uint64_t> failed_wakes_{0};
};

} // namespace http_vx

#endif // HTTP_VX_SHARD_WAKE_H
