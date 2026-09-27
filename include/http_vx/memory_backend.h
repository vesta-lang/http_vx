/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/memory_backend.h
 * @brief
 * \~english A backend with no operating system in it.
 * \~spanish Un backend sin ningun sistema operativo dentro.
 * \~
 *
 * \~english
 * It is a real backend and not a stand-in for one.  What a backend does is
 * take operations, finish them later, and hand back completions; where the
 * bytes came from is not part of that.  This one gets them from memory the
 * caller put there, and every other part of the server -- the loop, the
 * parsers, the streams, the deadlines -- runs against it byte for byte as it
 * would against a socket.
 *
 * **Which is what makes the loop testable at all.**  A bug in a reactor driven
 * by a real network is a bug that happens once every few thousand runs, in an
 * order nobody chose, on a machine that was busy; the same bug here happens on
 * the run that asks for it.  The completion that arrives after its connection
 * has gone -- the case the whole handle design exists for -- is a thing that
 * takes a race to see and one line to arrange.
 *
 * It is also what a loopback transport would be, which is not a coincidence:
 * a backend that moves bytes between two endpoints in the same process is
 * exactly what an HTTP server spoken to over a pipe needs.
 *
 * \~spanish
 * Es un backend de verdad y no un sustituto de uno.  Lo que hace un backend es
 * coger operaciones, acabarlas despues y devolver finalizaciones; de donde
 * salieron los bytes no forma parte de eso.  Este los saca de una memoria que
 * puso quien llama, y todas las demas partes del servidor -- el bucle, los
 * analizadores, los flujos, los plazos -- corren contra el byte a byte igual que
 * lo harian contra un socket.
 *
 * **Y es lo que hace que el bucle se pueda probar siquiera.**  Un fallo en un
 * reactor movido por una red de verdad es un fallo que ocurre una vez cada
 * varios miles de corridas, en un orden que no eligio nadie, en una maquina que
 * tenia trabajo; el mismo fallo aqui ocurre en la corrida que lo pide.  La
 * finalizacion que llega despues de que su conexion se haya ido -- el caso para
 * el que existe todo el diseno de las referencias -- es algo que cuesta una
 * carrera ver y una linea preparar.
 *
 * Es ademas lo que seria un transporte de bucle local, y no es casualidad: un
 * backend que mueve bytes entre dos extremos del mismo proceso es exactamente lo
 * que necesita un servidor HTTP al que se le habla por una tuberia.
 *
 * \~
 */
#ifndef HTTP_VX_MEMORY_BACKEND_H
#define HTTP_VX_MEMORY_BACKEND_H

#include "http_vx/buffer_pool.h"
#include "http_vx/datagram.h"
#include "http_vx/reactor_ops.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english How many operations may be outstanding at once.
 * \~spanish Cuantas operaciones pueden estar pendientes a la vez.
 * \~
 *
 * \~english
 * Fixed, like everything else a peer can ask for more of.  A submission queue
 * that grew would be a queue whose size somebody else chooses.
 *
 * \~spanish
 * Fija, como todo lo demas de lo que un extremo puede pedir mas.  Una cola de
 * entrega que creciera seria una cola cuyo tamano elige otro.
 *
 * \~
 */
constexpr size_t kMaxPending = 256;

/// \~english How many datagrams wait to be received, and how many sent ones are kept.
/// \~spanish Cuantos datagramas esperan a recibirse, y cuantos mandados se guardan.  \~
constexpr size_t kMemoryDatagrams = 16;

/// \~english The largest datagram the memory backend carries.
/// \~spanish El datagrama mas grande que lleva el backend de memoria.  \~
constexpr size_t kMemoryDatagramRoom = 2048;

/**
 * @brief
 * \~english One datagram in the memory backend, either way.
 * \~spanish Un datagrama en el backend de memoria, en cualquier sentido.
 * \~
 */
struct MemoryDatagram {
    DatagramHeader header;

    /// \~english The socket it was sent on; -1 for one received.
    /// \~spanish El socket por el que se mando; -1 para uno recibido.  \~
    int32_t fd = -1;

    size_t size = 0;
    uint8_t bytes[kMemoryDatagramRoom];
};

/**
 * @brief
 * \~english A backend that finishes operations out of memory.
 * \~spanish Un backend que acaba operaciones sacando de memoria.
 * \~
 */
class MemoryBackend final : public Backend {
  public:
    /**
     * @brief
     * \~english Makes one that reads and writes through @p pool.
     * \~spanish Hace uno que lee y escribe a traves de @p pool.
     * \~
     *
     * \~english
     * The pool is where the buffers named by operations live, and this needs
     * it for the same reason a kernel needs the address: a @c Recv writes into
     * the buffer, so it has to be able to reach it.
     *
     * \~spanish
     * El pozo es donde viven los buffers que nombran las operaciones, y esto lo
     * necesita por lo mismo que un nucleo necesita la direccion: un @c Recv
     * escribe en el buffer, asi que tiene que poder llegar a el.
     *
     * \~
     * @param pool \~english where the buffers are  \~spanish donde estan los buffers  \~
     */
    explicit MemoryBackend(BufferPool &pool) noexcept : pool_(&pool) {}

    /**
     * @brief
     * \~english Puts @p n bytes where the next read will find them.
     * \~spanish Pone @p n bytes donde los encontrara la lectura siguiente.
     * \~
     *
     * \~english
     * What the peer sent, in other words.  It is kept separately from the
     * operations because in a real backend it arrives on its own schedule, and
     * a test that could only supply bytes at submission time would be unable
     * to arrange the case where a read is outstanding and nothing has come.
     *
     * \~spanish
     * Lo que mando el otro extremo, dicho de otra forma.  Se guarda aparte de
     * las operaciones porque en un backend de verdad llega a su propio ritmo, y
     * una prueba que solo pudiera dar bytes al entregar la operacion no podria
     * preparar el caso en que hay una lectura pendiente y no ha llegado nada.
     *
     * \~
     * @param p \~english the bytes  \~spanish los bytes  \~
     * @param n \~english how many  \~spanish cuantos  \~
     * @return  \~english false if there was no room
     *          \~spanish false si no habia sitio  \~
     */
    bool feed(const uint8_t *p, size_t n) noexcept;

    /**
     * @brief
     * \~english Says a connection has arrived, and that it is @p fd.
     * \~spanish Dice que ha llegado una conexion, y que es @p fd.
     * \~
     *
     * \~english
     * What a listening socket does, in other words.  Until one arrives an
     * accept stays outstanding, which is the state a listening server is in
     * almost all of the time and the one a test would otherwise have no way to
     * be in: an accept that completed the moment it was asked for would make
     * every loop spin, and make the case that matters -- nobody is connecting
     * -- the case nothing ever runs.
     *
     * The number is the test's to choose, because a socket is a name and this
     * backend does not have an operating system to get one from.
     *
     * \~spanish
     * Lo que hace un socket de escucha, dicho de otra forma.  Hasta que llega una,
     * una aceptacion sigue pendiente, que es el estado en el que esta un servidor
     * a la escucha casi todo el tiempo y en el que una prueba no podria ponerse de
     * otra forma: una aceptacion que acabara en cuanto se pide haria dar vueltas a
     * cualquier bucle, y haria que el caso que importa -- que no se conecte nadie
     * -- fuera el caso que no corre nunca.
     *
     * El numero lo elige la prueba, porque un socket es un nombre y este backend
     * no tiene ningun sistema operativo del que sacar uno.
     *
     * \~
     * @param fd \~english the socket  \~spanish el socket  \~
     * @return   \~english false if there was no room to remember it
     *           \~spanish false si no habia sitio para recordarla  \~
     */
    bool arrive(int32_t fd) noexcept;

    /// \~english How many sockets this backend was told to close.
    /// \~spanish Cuantos sockets se le dijo a este backend que cerrara.  \~
    size_t closed() const noexcept { return closed_; }

    /// \~english How many outstanding reads were cancelled.  \~spanish Cuantas lecturas pendientes se cancelaron.  \~
    size_t cancelled() const noexcept { return cancelled_; }

    /**
     * @brief
     * \~english Says the peer has closed its end.
     * \~spanish Dice que el otro extremo ha cerrado su lado.
     * \~
     *
     * \~english
     * After what has been fed is read, the next read finishes with zero rather
     * than waiting.  It is a state and not a byte because that is what it is
     * on a socket, and a backend that faked it with a sentinel would be one
     * where a connection could send the sentinel.
     *
     * \~spanish
     * Cuando se haya leido lo que se le dio, la lectura siguiente acaba con cero
     * en vez de esperar.  Es un estado y no un byte porque eso es lo que es en
     * un socket, y un backend que lo fingiera con un centinela seria uno en el
     * que una conexion puede mandar el centinela.
     *
     * \~
     */
    void end_of_stream() noexcept { ended_ = true; }

    /// \~english What has been written out, in order.
    /// \~spanish Lo que se ha escrito, en orden.  \~
    const uint8_t *written() const noexcept { return out_; }

    /// \~english How much.  \~spanish Cuanto.  \~
    size_t written_size() const noexcept { return out_len_; }

    /**
     * @brief
     * \~english Makes the next @p n operations fail with @p error.
     * \~spanish Hace que las @p n operaciones siguientes fallen con @p error.
     * \~
     *
     * \~english
     * Because a loop's behaviour when the operating system says no is not
     * something to find out in production.  A test that could only make things
     * work would leave every error path unrun -- and the error paths are the
     * ones nobody reads twice.
     *
     * \~spanish
     * Porque lo que hace un bucle cuando el sistema operativo dice que no no es
     * algo que averiguar en produccion.  Una prueba que solo pudiera hacer que
     * las cosas funcionaran dejaria sin correr todos los caminos de error -- y
     * los caminos de error son los que no lee nadie dos veces.
     *
     * \~
     * @param n     \~english how many operations  \~spanish cuantas operaciones  \~
     * @param error \~english the negative result they get
     *              \~spanish el resultado negativo que reciben  \~
     */
    void fail_next(uint32_t n, int32_t error) noexcept {
        failures_ = n;
        failure_ = error;
    }

    /**
     * @brief
     * \~english The most bytes one operation will move.
     * \~spanish Los bytes mas que movera una operacion.
     * \~
     *
     * \~english
     * Zero means as much as fits.  Setting it is how a test arranges the
     * partial read and the partial write, which on a real socket are the
     * ordinary case and in a test are the case somebody forgets: a loop that
     * assumed a send moved everything would work perfectly until the first
     * response that did not fit in the kernel's send buffer.
     *
     * \~spanish
     * Cero quiere decir todo lo que quepa.  Ponerlo es como prepara una prueba
     * la lectura parcial y la escritura parcial, que en un socket de verdad son
     * el caso corriente y en una prueba son el caso que se olvida: un bucle que
     * diera por hecho que un envio movio todo funcionaria perfectamente hasta la
     * primera respuesta que no cupiera en el buffer de envio del nucleo.
     *
     * \~
     * @param n \~english the most, or zero for no limit
     *          \~spanish lo mas, o cero para no limitar  \~
     */
    void chunk(uint32_t n) noexcept { chunk_ = n; }

    bool submit(const Op &op) noexcept override;
    size_t wait(Completion *out, size_t cap, int timeout_ms) noexcept override;
    const char *name() const noexcept override { return "memory"; }

    /**
     * @brief
     * \~english Counts the wake; any thread.  This backend never sleeps, so there is nothing else to do.
     * \~spanish Cuenta el despertar; cualquier hilo.  Este backend no duerme nunca, asi que no hay nada mas que hacer.
     * \~
     */
    bool wake() noexcept override {
        wakes_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    /// \~english How many wakes arrived.  \~spanish Cuantos despertares llegaron.  \~
    uint64_t wakes() const noexcept { return wakes_.load(std::memory_order_relaxed); }

    /// \~english How many are waiting to finish.
    /// \~spanish Cuantas esperan para acabar.  \~
    size_t pending() const noexcept { return pending_count_; }

    /**
     * @brief
     * \~english The peer sends a datagram on @p path.
     * \~spanish El otro extremo manda un datagrama por @p path.
     * \~
     *
     * \~english
     * It waits in order until a @c RecvFrom takes it, as it would in a socket's
     * receive queue.  A @p flags without @c kDatagramLocalKnown stands in for a
     * platform that could not say where it was sent.
     * \~spanish
     * Espera en orden hasta que lo coja un @c RecvFrom, como en la cola de
     * recepcion de un socket.  Unos @p flags sin @c kDatagramLocalKnown hacen de
     * una plataforma que no supo decir a donde se mando.
     * \~
     *
     * @return \~english false if it does not fit  \~spanish false si no cabe  \~
     */
    bool feed_datagram(const DatagramPath &path, const uint8_t *p, size_t n,
                       EcnMark ecn = EcnMark::NotEct,
                       uint8_t flags = kDatagramLocalKnown |
                                       kDatagramEcnKnown) noexcept;

    /// \~english How many datagrams have been sent, in order.
    /// \~spanish Cuantos datagramas se han mandado, en orden.  \~
    size_t datagrams_out() const noexcept { return dgram_out_count_; }

    /// \~english The @p i -th datagram sent, or null.
    /// \~spanish El datagrama mandado numero @p i, o nulo.  \~
    const MemoryDatagram *datagram_out(size_t i) const noexcept {
        return i < dgram_out_count_ ? &dgram_out_[i] : nullptr;
    }

    /// \~english What happened to datagrams.  \~spanish Lo que les paso a los datagramas.  \~
    const DatagramCounts &datagrams() const noexcept { return dgram_counts_; }

  private:
    Completion finish(const Op &op) noexcept;

    /// \~english Finishes a @c RecvFrom or a @c SendTo.
    /// \~spanish Acaba un @c RecvFrom o un @c SendTo.  \~
    Completion finish_datagram(const Op &op) noexcept;

    /// \~english Whether @p op has to keep waiting.
    /// \~spanish Si @p op tiene que seguir esperando.  \~
    bool waiting(const Op &op) const noexcept;

    BufferPool *pool_ = nullptr;

    Op pending_[kMaxPending];
    size_t pending_head_ = 0;
    size_t pending_count_ = 0;

    /**
     * \~english
     * What the peer has sent and what has been sent to it.  Fixed and modest:
     * this is for arranging cases, not for carrying traffic, and a test that
     * needed more than this is a test that had stopped being about one thing.
     * \~spanish
     * Lo que ha mandado el otro extremo y lo que se le ha mandado.  Fijos y
     * modestos: esto es para preparar casos, no para llevar trafico, y una
     * prueba que necesitara mas que esto es una prueba que habia dejado de ir de
     * una sola cosa.
     * \~
     */
    uint8_t in_[65536];
    size_t in_len_ = 0;
    size_t in_read_ = 0;

    uint8_t out_[65536];
    size_t out_len_ = 0;

    /**
     * \~english
     * The connections waiting to be accepted.  A handful, because this is for
     * arranging cases: what it has to be able to hold is several arriving
     * before the loop looks, which is what tells a shard with more than one
     * accept posted apart from one with a single one.
     * \~spanish
     * Las conexiones esperando a que las acepten.  Unas pocas, porque esto es
     * para preparar casos: lo que tiene que poder guardar son varias llegando
     * antes de que mire el bucle, que es lo que distingue un fragmento con varias
     * aceptaciones puestas de uno con una sola.
     * \~
     */
    int32_t arrivals_[16] = {};
    size_t arrivals_head_ = 0;
    size_t arrivals_count_ = 0;

    size_t closed_ = 0;
    size_t cancelled_ = 0;

    /// \~english The socket a cancelled read is left with: it completes as a failure.
    /// \~spanish El socket con el que se queda una lectura cancelada: acaba como fallo.  \~
    static constexpr int32_t kCancelledFd = -0x7FFFFFFF - 1;

    /// \~english The datagrams waiting to be received, as a ring.
    /// \~spanish Los datagramas esperando a recibirse, en anillo.  \~
    MemoryDatagram dgram_in_[kMemoryDatagrams];
    size_t dgram_in_head_ = 0;
    size_t dgram_in_count_ = 0;

    /// \~english Every datagram sent, in order.
    /// \~spanish Todos los datagramas mandados, en orden.  \~
    MemoryDatagram dgram_out_[kMemoryDatagrams];
    size_t dgram_out_count_ = 0;

    DatagramCounts dgram_counts_;

    uint32_t failures_ = 0;
    int32_t failure_ = -1;
    uint32_t chunk_ = 0;
    bool ended_ = false;
    std::atomic<uint64_t> wakes_{0};
};

} // namespace http_vx

#endif // HTTP_VX_MEMORY_BACKEND_H
