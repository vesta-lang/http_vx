/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file include/http_vx/mailbox.h
 * @brief
 * \~english What one shard says to another: a lock-free mailbox, and the sender's own fixed pool of messages.
 * \~spanish Lo que un fragmento le dice a otro: un buzon sin cerrojos, y el pozo fijo de mensajes propio del remitente.
 * \~
 *
 * \~english
 * HVX-6, 6.  Traffic between shards is rare -- sockets an acceptor hands over,
 * a stop -- and what dominates its cost is the wake, not the atomic
 * operation, so the mailbox is the same mechanism as the kick queue: a
 * Treiber stack with many producers and one consumer, taken whole with one
 * exchange and turned round so the oldest message is served first.
 *
 * Where the messages come from is the part that matters.  A message is a
 * fixed-size node taken from a pool the SENDER owns, built on the sender's own
 * thread; when the receiver has dealt with it, it pushes the node onto the
 * sender's "returned" stack -- another lock-free stack, consumed by the sender
 * alone -- and the sender moves what came back into its free list the next
 * time it needs a node.  So nothing is allocated to send and nothing is ever
 * freed into another shard's pool (the same rule as Seastar's cross-core
 * frees); a pool with no node left REFUSES the send and counts it.
 *
 * Both stacks only ever push one node and are emptied whole, so no node is
 * removed from the middle and there is no ABA to guard against.
 *
 * The enum has no datagram kind yet: a kind nobody handles would be a case a
 * receiver had to refuse, and it is added with the code that handles it.
 * \~spanish
 * HVX-6, 6.  El trafico entre fragmentos es raro -- sockets que reparte un
 * aceptador, una orden de parar -- y lo que manda en su coste es el despertar,
 * no la operacion atomica, asi que el buzon es el mismo mecanismo que la cola
 * de avisos: una pila de Treiber de varios productores y un consumidor, que se
 * lleva entera con un intercambio y se da la vuelta para atender primero el
 * mensaje mas antiguo.
 *
 * Lo que importa es de donde salen los mensajes.  Un mensaje es un nodo de
 * tamano fijo sacado de un pozo del que es dueno el REMITENTE, construido en su
 * propio hilo; cuando el receptor lo ha atendido, lo mete en la pila de
 * "devueltos" del remitente -- otra pila sin cerrojos, que consume solo el
 * remitente --, y este pasa lo que volvio a su lista libre la proxima vez que
 * necesita un nodo.  Asi no se reserva nada al mandar y nunca se libera nada en
 * el pozo de otro fragmento (la misma regla que las liberaciones entre nucleos
 * de Seastar); un pozo sin ningun nodo RECHAZA el envio y lo cuenta.
 *
 * Las dos pilas solo meten un nodo y se vacian enteras, asi que nunca se quita
 * un nodo del medio y no hay ABA del que protegerse.
 *
 * El enum todavia no tiene un tipo de datagrama: un tipo que nadie atiende
 * seria un caso que el receptor tendria que rechazar, y se anade con el codigo
 * que lo atiende.
 * \~
 */
#ifndef HTTP_VX_MAILBOX_H
#define HTTP_VX_MAILBOX_H

#include "http_vx/shard_wake.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace http_vx {

class MailPool;

/**
 * @brief
 * \~english What a message asks the receiving shard to do.
 * \~spanish Lo que un mensaje le pide hacer al fragmento receptor.
 * \~
 */
enum class MailKind : uint8_t {
    /// \~english Take the accepted socket in @c fd as one of your connections.  \~spanish Coge el socket aceptado de @c fd como una de tus conexiones.  \~
    AdoptSocket = 0,
    /// \~english Finish: the loop ends after this turn.  \~spanish Acaba: el bucle termina tras esta vuelta.  \~
    Stop = 1,
};

/// \~english How many kinds there are; sizes the per-kind counters.  \~spanish Cuantos tipos hay; dimensiona las cuentas por tipo.  \~
constexpr size_t kMailKinds = 2;

/**
 * @brief
 * \~english One message: its link, the pool it goes back to, and what it says.
 * \~spanish Un mensaje: su enlace, el pozo al que vuelve, y lo que dice.
 * \~
 */
struct MailNode {
    /// \~english The stack or free list it is in; never read by a thread that does not hold the node.  \~spanish La pila o lista libre en la que esta; no la lee ningun hilo que no tenga el nodo.  \~
    MailNode *next = nullptr;
    /// \~english Whose pool it is: where it returns when handled.  \~spanish De quien es el pozo: adonde vuelve al atenderse.  \~
    MailPool *home = nullptr;
    /// \~english Which message.  \~spanish Que mensaje.  \~
    MailKind kind = MailKind::Stop;
    /// \~english The socket of an @c AdoptSocket, as a connection's descriptor is held everywhere (@c Completion::fd).  \~spanish El socket de un @c AdoptSocket, como se guarda en todas partes el descriptor de una conexion (@c Completion::fd).  \~
    int32_t fd = -1;
};

/**
 * @brief
 * \~english Adds one to a counter only its owner thread writes, and that others may read.
 * \~spanish Suma uno a una cuenta que solo escribe su hilo dueno, y que otros pueden leer.
 * \~
 *
 * \~english
 * A load and a store, not a locked add: with a single writer nothing can be
 * lost, and the atomic is only there so a reader on another thread does not
 * race.
 * \~spanish
 * Una lectura y una escritura, no una suma con bloqueo: con un unico escritor
 * no se puede perder nada, y el atomico esta solo para que un lector de otro
 * hilo no corra una carrera.
 * \~
 */
inline void bump(std::atomic<uint64_t> &counter) noexcept {
    counter.store(counter.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
}

/**
 * @brief
 * \~english What a mailbox has taken.
 * \~spanish Lo que ha cogido un buzon.
 * \~
 */
struct MailboxCounts {
    /// \~english Messages taken out, in total.  \~spanish Mensajes sacados, en total.  \~
    uint64_t received = 0;
    /// \~english Messages taken out, by kind (indexed by @c MailKind).  \~spanish Mensajes sacados, por tipo (indice @c MailKind).  \~
    uint64_t by_kind[kMailKinds] = {};
};

/**
 * @brief
 * \~english One shard's inbox.
 * \~spanish El buzon de entrada de un fragmento.
 * \~
 */
class Mailbox {
public:
    Mailbox() noexcept = default;
    Mailbox(const Mailbox &) = delete;
    Mailbox &operator=(const Mailbox &) = delete;

    /// \~english The shard's wake, shared with its kick queue; counts start again.  \~spanish El despertar del fragmento, compartido con su cola de avisos; las cuentas empiezan otra vez.  \~
    void reset(ShardWake &wake) noexcept;

    /**
     * @brief
     * \~english Pushes @p n and wakes the shard if it sleeps; any thread.
     * \~spanish Mete @p n y despierta al fragmento si duerme; cualquier hilo.
     * \~
     *
     * \~english
     * The node is in the stack when this returns even if the wake failed (and
     * was counted): the shard takes it on its next turn regardless.
     * \~spanish
     * El nodo esta en la pila al volver aunque el despertar fallara (y se
     * contara): el fragmento lo coge en su proxima vuelta de todas formas.
     * \~
     *
     * @return \~english false if the wake could not be delivered  \~spanish false si el despertar no se pudo entregar  \~
     */
    bool push(MailNode &n) noexcept;

    /**
     * @brief
     * \~english Takes every message, oldest first; only the shard.
     * \~spanish Se lleva todos los mensajes, el mas antiguo primero; solo el fragmento.
     * \~
     *
     * @return \~english the first of a list linked by @c next, or null  \~spanish el primero de una lista enlazada por @c next, o nulo  \~
     */
    MailNode *take_all() noexcept;

    /// \~english Whether any message is waiting.  \~spanish Si hay algun mensaje esperando.  \~
    bool pending() const noexcept { return head_.load(std::memory_order_seq_cst) != nullptr; }

    /// \~english What has been counted.  \~spanish Lo que se ha contado.  \~
    MailboxCounts counts() const noexcept;

private:
    std::atomic<MailNode *> head_{nullptr};
    ShardWake *wake_ = nullptr;

    std::atomic<uint64_t> received_{0};
    std::atomic<uint64_t> by_kind_[kMailKinds] = {};
};

/**
 * @brief
 * \~english What a sender's pool has counted.
 * \~spanish Lo que ha contado el pozo de un remitente.
 * \~
 */
struct MailPoolCounts {
    /// \~english Messages sent.  \~spanish Mensajes mandados.  \~
    uint64_t sent = 0;
    /// \~english Sends refused because no node was free.  \~spanish Envios rechazados porque no habia ningun nodo libre.  \~
    uint64_t refused = 0;
    /// \~english Nodes that came back from their receivers.  \~spanish Nodos que volvieron de sus receptores.  \~
    uint64_t returned = 0;
};

/**
 * @brief
 * \~english A sender's fixed pool of messages: it sends from it and takes them back.
 * \~spanish El pozo fijo de mensajes de un remitente: manda desde el y los recupera.
 * \~
 *
 * \~english
 * Everything except @c give_back belongs to ONE thread, the sender's: the
 * free list is a plain list.  Build it (@c reset) on that thread so the
 * memory lands on its node (HVX-6, R44).
 * \~spanish
 * Todo salvo @c give_back es de UN solo hilo, el del remitente: la lista libre
 * es una lista corriente.  Se construye (@c reset) en ese hilo para que la
 * memoria caiga en su nodo (HVX-6, R44).
 * \~
 */
class MailPool {
public:
    MailPool() noexcept = default;
    ~MailPool();
    MailPool(const MailPool &) = delete;
    MailPool &operator=(const MailPool &) = delete;

    /**
     * @brief
     * \~english Makes @p nodes messages; any the pool already had are given up first.
     * \~spanish Hace @p nodes mensajes; los que ya tuviera el pozo se sueltan antes.
     * \~
     *
     * @return \~english false if the memory could not be had  \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t nodes) noexcept;

    /**
     * @brief
     * \~english Gives the memory back, if every node is home.
     * \~spanish Devuelve la memoria, si todos los nodos estan en casa.
     * \~
     *
     * \~english
     * A node still away is in some receiver's mailbox or in its hands, and
     * freeing the block under it would be a write into freed memory; so the
     * block is kept (leaked, on purpose) and the number is returned for the
     * caller to say.
     * \~spanish
     * Un nodo que sigue fuera esta en el buzon de algun receptor o en sus
     * manos, y liberar el bloque debajo seria escribir en memoria liberada; asi
     * que el bloque se conserva (se pierde, a proposito) y se devuelve el numero
     * para que quien llama lo diga.
     * \~
     *
     * @return \~english how many nodes were not home; zero when the memory was freed  \~spanish cuantos nodos no estaban en casa; cero cuando se libero la memoria  \~
     */
    size_t release() noexcept;

    /**
     * @brief
     * \~english Sends a message to @p to; refused, and counted, when no node is free.
     * \~spanish Manda un mensaje a @p to; se rechaza, y se cuenta, cuando no queda ningun nodo libre.
     * \~
     *
     * @param to   \~english the receiving shard's mailbox  \~spanish el buzon del fragmento receptor  \~
     * @param kind \~english what it asks  \~spanish lo que pide  \~
     * @param fd   \~english the socket of an @c AdoptSocket, else -1  \~spanish el socket de un @c AdoptSocket, si no -1  \~
     * @return     \~english false if refused: the caller still owns @p fd  \~spanish false si se rechazo: quien llama sigue siendo dueno de @p fd  \~
     */
    bool send(Mailbox &to, MailKind kind, int32_t fd) noexcept;

    /**
     * @brief
     * \~english A receiver is done with @p n: it goes back to its sender's returned stack; any thread.
     * \~spanish Un receptor ha acabado con @p n: vuelve a la pila de devueltos de su remitente; cualquier hilo.
     * \~
     */
    static void give_back(MailNode &n) noexcept;

    /// \~english Moves what came back into the free list; only the sender.  \~spanish Pasa lo que volvio a la lista libre; solo el remitente.  \~
    size_t reclaim() noexcept;

    /// \~english Nodes in the pool, home or away.  \~spanish Nodos del pozo, en casa o fuera.  \~
    uint32_t capacity() const noexcept { return capacity_; }

    /// \~english Nodes in the free list; only the sender (the returned ones are not counted until reclaimed).  \~spanish Nodos de la lista libre; solo el remitente (los devueltos no cuentan hasta recuperarse).  \~
    uint32_t free_count() const noexcept { return free_; }

    /// \~english What has been counted.  \~spanish Lo que se ha contado.  \~
    MailPoolCounts counts() const noexcept;

private:
    MailNode *nodes_ = nullptr;
    uint32_t capacity_ = 0;

    /// \~english The sender's own list of nodes at home.  \~spanish La lista propia del remitente de nodos en casa.  \~
    MailNode *free_head_ = nullptr;
    uint32_t free_ = 0;

    /// \~english Nodes handed back by receivers, which may be any thread.  \~spanish Nodos devueltos por los receptores, que pueden ser cualquier hilo.  \~
    std::atomic<MailNode *> returned_{nullptr};

    std::atomic<uint64_t> sent_{0};
    std::atomic<uint64_t> refused_{0};
    std::atomic<uint64_t> returned_count_{0};
};

} // namespace http_vx

#endif // HTTP_VX_MAILBOX_H
