/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/epoll_backend.cpp
 * @brief
 * \~english Readiness turned into completion, one syscall at a time.
 * \~spanish Disponibilidad convertida en finalizacion, una llamada al sistema cada vez.
 * \~
 */

#include "epoll_waiting.h"
#include "socket_open.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memset.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <new>

namespace http_vx {

namespace {

/// \~english Whether @p kind is one that reads.
/// \~spanish Si @p kind es de los que leen.  \~
bool reads(OpKind kind) noexcept {
    return kind == OpKind::Recv || kind == OpKind::Accept ||
           kind == OpKind::Ready;
}

/**
 * @brief
 * \~english Whether the system is saying "not now" rather than "no".
 * \~spanish Si el sistema esta diciendo "ahora no" en vez de "no".
 * \~
 *
 * \~english
 * The two answers look identical to a caller that only checks for -1, and they
 * are opposite: one means wait and try again, the other means the connection is
 * over.  `EWOULDBLOCK` is the same number as `EAGAIN` on Linux and a different
 * one elsewhere, so both are named -- and a compiler that sees one comparison
 * twice will say so rather than the code being wrong on a platform nobody tried.
 *
 * \~spanish
 * Las dos respuestas se ven identicas para quien solo mire si hay un -1, y son
 * contrarias: una quiere decir espera y vuelve a intentarlo, la otra que la
 * conexion se acabo.  `EWOULDBLOCK` es el mismo numero que `EAGAIN` en Linux y
 * otro en otros sitios, asi que se nombran los dos -- y un compilador que vea la
 * misma comparacion dos veces lo dira, en vez de que el codigo este mal en una
 * plataforma que no ha probado nadie.
 * \~
 */
bool not_now(int e) noexcept {
#if EAGAIN == EWOULDBLOCK
    return e == EAGAIN;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

/// \~english Writes into @p c that @p op failed.
/// \~spanish Escribe en @p c que @p op fallo.  \~
void answer_failed(Completion &c, const Op &op) noexcept {
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = -1;
    c.fd = -1;
}

} // namespace

EpollBackend::~EpollBackend() { release(); }

void EpollBackend::release() noexcept {
    if (listener_ >= 0) {
        ::close(listener_);
        listener_ = -1;
    }

    dgram_release();

    if (queue_ >= 0) {
        ::close(queue_);
        queue_ = -1;
    }

    if (waiting_ != nullptr) {
        for (uint32_t i = 0; i < max_fds_; ++i) waiting_[i].~Waiting();
        util::host_free(waiting_);
        waiting_ = nullptr;
    }

    drop_ready();

    max_fds_ = 0;
    in_flight_ = 0;
    port_ = 0;
}

bool EpollBackend::reset(BufferPool &pool, uint32_t max_fds) noexcept {
    release();

    if (max_fds == 0) return false;

    pool_ = &pool;

    queue_ = epoll_create1(EPOLL_CLOEXEC);
    if (queue_ < 0) {
        last_error_ = errno;
        return false;
    }

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    waiting_ = static_cast<Waiting *>(
        util::host_alloc(static_cast<size_t>(max_fds) * sizeof(Waiting)));
    if (waiting_ == nullptr) {
        release();
        return false;
    }

    max_fds_ = max_fds;
    for (uint32_t i = 0; i < max_fds; ++i) {
        new (&waiting_[i]) Waiting();
        waiting_[i].has_read = false;
        waiting_[i].has_write = false;
        waiting_[i].armed = 0;
        waiting_[i].known = false;
        waiting_[i].dgram = -1;
    }

    if (!dgram_reset() || !make_room()) {
        release();
        return false;
    }

    return true;
}

bool EpollBackend::listen(const char *host, uint16_t port, int backlog) noexcept {
    if (queue_ < 0) return false;

    const int s = open_listener(host, port, backlog, true, port_, last_error_);
    if (s < 0) return false;

    if (static_cast<uint32_t>(s) >= max_fds_) {
        last_error_ = EMFILE;
        ::close(s);
        return false;
    }

    listener_ = s;
    return true;
}

bool EpollBackend::arm(int32_t fd) noexcept {
    Waiting &w = waiting_[fd];

    uint32_t want = 0;
    if (w.has_read) want |= EPOLLIN;
    if (w.has_write) want |= EPOLLOUT;
    if (w.dgram >= 0) want = dgram_events(w.dgram);

    if (w.known && w.armed == want) return true;

    /* \~english
     * Nothing waited on means the socket is left DISARMED, and with
     * `EPOLLONESHOT` that has already happened: the kernel takes a descriptor
     * out of the ready set the moment it reports it, and puts it back only
     * when it is told to.  So there is nothing to say here, and saying it
     * would be a system call bought to repeat something already true.
     *
     * Without oneshot this had to be an `EPOLL_CTL_DEL`, because epoll is
     * level-triggered: a socket left registered for reading with nobody
     * waiting stays ready for ever, and every wait would hand it back with
     * nothing to do.  So a keep-alive connection paid a DEL when its read was
     * taken and an ADD when the next one was asked for -- two of the five
     * system calls a request costs, spent saying twice a turn what the kernel
     * would have done by itself.
     *
     * \~spanish
     * Que no se espere nada quiere decir que el socket se queda DESARMADO, y con
     * `EPOLLONESHOT` eso ya ha pasado: el nucleo saca un descriptor del conjunto
     * de listos en cuanto lo informa, y lo vuelve a meter solo cuando se lo
     * dicen.  Asi que aqui no hay nada que decir, y decirlo seria una llamada al
     * sistema comprada para repetir algo que ya es cierto.
     *
     * Sin oneshot esto tenia que ser un `EPOLL_CTL_DEL`, porque epoll es por
     * nivel: un socket que se quede registrado para leer sin que nadie espere
     * sigue listo para siempre, y todas las esperas lo devolverian sin nada que
     * hacer.  Asi que una conexion mantenida viva pagaba un DEL cuando se
     * llevaban su lectura y un ADD cuando se pedia la siguiente -- dos de las
     * cinco llamadas al sistema que cuesta una peticion, gastadas en decir dos
     * veces por vuelta lo que el nucleo iba a hacer solo.
     * \~ */
    if (want == 0) {
        w.armed = 0;
        return true;
    }

    epoll_event ev;
    util::vesta_memset(&ev, 0, sizeof ev);

    /* \~english
     * `EPOLLONESHOT` on every registration.  It means "tell me once", and the
     * re-arming that costs is a call this loop was making anyway: a connection
     * whose read has just been taken asks for the next one, and that ask is
     * the `EPOLL_CTL_MOD` that puts it back.
     * \~spanish
     * `EPOLLONESHOT` en cada registro.  Quiere decir "avisame una vez", y el
     * rearme que cuesta es una llamada que este bucle hacia igual: una conexion a
     * la que le acaban de coger su lectura pide la siguiente, y esa peticion es
     * el `EPOLL_CTL_MOD` que la vuelve a poner.
     * \~ */
    ev.events = want | EPOLLONESHOT;
    ev.data.fd = fd;

    const int how = w.known ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(queue_, how, fd, &ev) < 0) {
        last_error_ = errno;
        return false;
    }

    w.known = true;
    w.armed = want;
    return true;
}

void EpollBackend::forget(int32_t fd) noexcept {
    if (fd < 0 || static_cast<uint32_t>(fd) >= max_fds_) return;

    Waiting &w = waiting_[fd];

    if (w.has_read) --in_flight_;
    if (w.has_write) --in_flight_;

    w.has_read = false;
    w.has_write = false;
    w.armed = 0;
    w.known = false;
}

bool EpollBackend::park(const Op &op) noexcept {
    Waiting &w = waiting_[op.fd];

    /* \~english
     * One per direction, and a second one in the same direction is refused
     * rather than replacing it.  Two reads on one socket would be the bytes of
     * a stream arriving in an order nobody chose, which is why the loop above
     * never asks for one -- and a backend that quietly allowed it would make
     * that rule the loop's private habit instead of something the interface
     * holds to.
     * \~spanish
     * Una por sentido, y una segunda en el mismo sentido se rechaza en vez de
     * sustituirla.  Dos lecturas sobre un socket serian los bytes de un flujo
     * llegando en un orden que no eligio nadie, que es la razon de que el bucle
     * de encima no pida nunca una -- y un backend que lo permitiera por lo bajo
     * convertiria esa regla en una costumbre privada del bucle en vez de en algo
     * que sostiene la interfaz.
     * \~ */
    if (reads(op.kind)) {
        if (w.has_read) return false;
        w.read = op;
        w.has_read = true;
    } else {
        if (w.has_write) return false;
        w.write = op;
        w.has_write = true;
    }

    ++in_flight_;

    if (!arm(op.fd)) {
        /* \~english
         * This one is refused -- the caller still holds it and hears "no" --
         * and whatever ALREADY waited on the socket is failed, into the ready
         * list, where it has room.  It used to be forgotten along with this
         * one: an accepted operation that simply stopped existing, its buffer
         * with it.
         * \~spanish
         * Esta se rechaza -- quien llama la sigue teniendo y oye "no" -- y lo
         * que YA esperaba en el socket se hace fallar, a la lista de listas,
         * donde tiene sitio.  Antes se olvidaba junto con esta: una operacion
         * aceptada que dejaba de existir sin mas, y su buffer con ella.
         * \~ */
        if (reads(op.kind))
            w.has_read = false;
        else
            w.has_write = false;
        --in_flight_;
        fail_waiting(op.fd);
        return false;
    }

    return true;
}

int EpollBackend::try_now(const Op &op) noexcept {
    switch (op.kind) {
    case OpKind::Accept: {
        const int taken = accept4(op.fd, nullptr, nullptr,
                                  SOCK_NONBLOCK | SOCK_CLOEXEC);
        return taken;
    }

    case OpKind::Ready:
        /* \~english
         * It is ready, and NOTHING was asked to find that out.  This is only
         * ever reached from @c wait, where the queue has just said the
         * descriptor has something -- so the answer was already in hand, and a
         * system call here would be buying it a second time.
         *
         * It bought it twice for a while: a one-byte `MSG_PEEK`, once when the
         * notice was asked for and again when it was reported.  The first one
         * almost always came back with "not yet", because a @c Ready is only
         * asked for when this end has nothing -- which is exactly when the
         * socket is most likely to have nothing either.
         *
         * \~spanish
         * Esta listo, y no se pregunto NADA para averiguarlo.  Aqui solo se llega
         * desde @c wait, donde la cola acaba de decir que el descriptor tiene algo
         * -- asi que la respuesta ya estaba en la mano, y una llamada al sistema
         * aqui seria comprarla por segunda vez.
         *
         * La compro dos veces durante un tiempo: un `MSG_PEEK` de un byte, una al
         * pedir el aviso y otra al informarlo.  La primera volvia casi siempre con
         * "todavia no", porque un @c Ready solo se pide cuando este extremo no
         * tiene nada -- que es justo cuando es mas probable que el socket tampoco
         * tenga.
         * \~ */
        return 0;

    /* \~english
     * Never here: datagram operations go to their socket's queues in
     * @c submit, and a stream call on them would read a datagram as a stream.
     * \~spanish
     * Nunca aqui: las operaciones de datagramas van a las colas de su socket en
     * @c submit, y una llamada de flujo sobre ellas leeria un datagrama como un
     * flujo.
     * \~ */
    case OpKind::RecvFrom:
    case OpKind::SendTo:
        errno = EINVAL;
        return -1;

    case OpKind::Recv: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr) return -1;

        uint8_t *room = b->reserve(op.length);
        if (room == nullptr) return -1;

        const ssize_t n = ::recv(op.fd, room, op.length, 0);

        /* \~english
         * And the bytes become part of the buffer only when it is known how
         * many arrived, exactly as on a completion port.  The two backends
         * differ in when the room is reserved -- here it could have waited --
         * and not in this, because this is what the buffer's own rules say.
         * \~spanish
         * Y los bytes pasan a ser parte del buffer solo cuando se sabe cuantos
         * llegaron, exactamente igual que en un puerto de finalizacion.  Los dos
         * backends difieren en cuando se reserva el sitio -- aqui podria haber
         * esperado -- y no en esto, porque esto es lo que dicen las reglas del
         * propio buffer.
         * \~ */
        if (n > 0) b->commit(static_cast<size_t>(n));
        return static_cast<int>(n);
    }

    case OpKind::Send: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr) return -1;
        if (op.offset + op.length > b->size()) return -1;

        /* \~english
         * `MSG_NOSIGNAL`, because writing to a connection the peer has already
         * closed raises `SIGPIPE`, and the default for that signal is to end
         * the process.  A server that died because one client hung up early
         * would be a server killed by its most ordinary event.
         * \~spanish
         * `MSG_NOSIGNAL`, porque escribir en una conexion que el otro extremo ya
         * cerro levanta `SIGPIPE`, y lo que hace esa senal por defecto es terminar
         * el proceso.  Un servidor que se muriera porque un cliente colgo antes de
         * tiempo seria un servidor matado por su suceso mas corriente.
         * \~ */
        const ssize_t n =
            ::send(op.fd, b->data() + op.offset, op.length, MSG_NOSIGNAL);
        return static_cast<int>(n);
    }

    case OpKind::Close:
        return 0;
    }

    return -1;
}

bool EpollBackend::submit(const Op &want) noexcept {
    if (queue_ < 0) return false;

    Op op = want;

    /* \~english
     * An @c Accept does not name a socket, because the caller has no name for
     * the one it means: the listening socket belongs to the backend, which is
     * the only piece that ever bound it.  So it is filled in here, and from
     * there on an accept is an operation on a descriptor like any other --
     * parked on the same note, armed on the same queue, retried by the same
     * code.
     *
     * Leaving it empty was worth a whole run of the suite: every accept was
     * refused for naming no socket, the shard replaced it, and the server
     * listened on a port it never looked at.
     *
     * \~spanish
     * Un @c Accept no nombra ningun socket, porque quien llama no tiene nombre
     * para el que quiere decir: el socket de escucha es del backend, que es la
     * unica pieza que llego a atarlo.  Asi que se rellena aqui, y a partir de ahi
     * una aceptacion es una operacion sobre un descriptor como cualquier otra --
     * guardada en la misma nota, armada en la misma cola, reintentada por el
     * mismo codigo.
     *
     * Dejarlo vacio costo una corrida entera de la suite: todas las aceptaciones
     * se rechazaban por no nombrar ningun socket, el fragmento las reponia, y el
     * servidor escuchaba en un puerto al que no miraba nunca.
     * \~ */
    if (op.kind == OpKind::Accept) op.fd = listener_;

    /* \~english
     * Room for this operation's completion is made FIRST, before anything is
     * done: after this line every path below either completes it or keeps it
     * waiting, and both have somewhere to report to.  The one refusal left is
     * here, with nothing touched -- a @c Close that had already closed its
     * socket and then said "no room" would be retried on a number the system
     * may by then have given to somebody else.
     * \~spanish
     * El sitio para la finalizacion de esta operacion se hace PRIMERO, antes de
     * hacer nada: a partir de esta linea todos los caminos de abajo o la acaban o
     * la dejan esperando, y los dos tienen donde informar.  El unico rechazo que
     * queda esta aqui, sin haber tocado nada -- un @c Close que ya hubiera
     * cerrado su socket y despues dijera "no hay sitio" se reintentaria sobre un
     * numero que el sistema puede haberle dado ya a otro.
     * \~ */
    if (!make_room()) return false;

    if (op.kind == OpKind::Close) {
        /* \~english
         * Everything this socket was waiting for is forgotten BEFORE it is
         * closed, and the order is the whole of it: a descriptor that closes
         * leaves the queue by itself, and the number is handed straight out
         * again to the next connection.  A note left behind would be a note
         * about somebody else.
         * \~spanish
         * Todo lo que esperara este socket se olvida ANTES de cerrarlo, y el orden
         * es todo: un descriptor que se cierra sale de la cola el solo, y el
         * numero se vuelve a dar enseguida a la conexion siguiente.  Una nota
         * olvidada ahi seria una nota sobre otro.
         * \~ */
        if (op.fd >= 0) {
            if (static_cast<uint32_t>(op.fd) < max_fds_ &&
                waiting_[op.fd].dgram >= 0)
                dgram_close(waiting_[op.fd].dgram);
            forget(op.fd);
            ::close(op.fd);
        }
        remember(op, 0, -1);
        return true;
    }

    if (op.fd < 0 || static_cast<uint32_t>(op.fd) >= max_fds_) {
        last_error_ = EBADF;
        remember(op, -1, -1);
        return true;
    }

    /* \~english
     * A datagram operation goes to its socket's queues -- and only on a
     * socket opened for datagrams.  Anywhere else it is refused, counted: a
     * stream read answering it would deliver a stream's bytes as a datagram
     * from nobody.
     * \~spanish
     * Una operacion de datagramas va a las colas de su socket -- y solo sobre un
     * socket abierto para datagramas.  En cualquier otro se rechaza, contada: una
     * lectura de flujo que la contestara entregaria los bytes de un flujo como un
     * datagrama de nadie.
     * \~ */
    if (op.kind == OpKind::RecvFrom || op.kind == OpKind::SendTo) {
        const int8_t at = waiting_[op.fd].dgram;
        if (at >= 0) return dgram_submit(op, at);

        last_error_ = ENOTSOCK;
        if (op.kind == OpKind::RecvFrom)
            ++dgram_counts_.receive_errors;
        else
            ++dgram_counts_.send_errors;
        remember(op, -1, -1);
        return true;
    }

    if (waiting_[op.fd].dgram >= 0) {
        last_error_ = EINVAL;
        remember(op, -1, -1);
        return true;
    }

    /* \~english
     * **A notice is never tried.**  What it asks is "tell me when there is
     * something", and that is the queue's question: trying it here would be a
     * system call spent asking a socket what the queue is already watching it
     * to find out -- and spent, overwhelmingly, to be told "not yet", because a
     * notice is only ever asked for when this end has nothing left.
     *
     * So it goes straight to waiting.  What that costs, when the socket DID
     * already have something, is one turn of the loop; what it saves is a
     * system call on every request that ever waits, which is most of them.
     *
     * \~spanish
     * **Un aviso no se intenta nunca.**  Lo que pregunta es "avisame cuando haya
     * algo", y esa es la pregunta de la cola: intentarlo aqui seria una llamada
     * al sistema gastada en preguntarle a un socket lo que la cola ya esta
     * vigilando para averiguar -- y gastada, en la inmensa mayoria de los casos,
     * para que le digan "todavia no", porque un aviso solo se pide cuando a este
     * extremo no le queda nada.
     *
     * Asi que va directo a esperar.  Lo que eso cuesta, cuando el socket SI tenia
     * algo, es una vuelta del bucle; lo que ahorra es una llamada al sistema en
     * cada peticion que espere, que son casi todas.
     * \~ */
    if (op.kind == OpKind::Ready) return park(op);

    /* \~english
     * Tried at once, even with completions piling up: the room for this one
     * was made above, so doing it now can never leave bytes that moved with
     * nowhere to say so.
     * \~spanish
     * Se intenta en el acto, aunque se amontonen finalizaciones: el sitio para
     * esta se hizo arriba, asi que hacerla ahora no puede dejar nunca unos bytes
     * que se movieron sin donde decirlo.
     * \~ */
    const int n = try_now(op);

    if (n >= 0) {
        if (op.kind == OpKind::Accept) {
            if (static_cast<uint32_t>(n) >= max_fds_) {
                ::close(n);
                last_error_ = EMFILE;
                remember(op, -1, -1);
                return true;
            }
            remember(op, 0, n);
            return true;
        }
        remember(op, n, -1);
        return true;
    }

    if (not_now(errno)) return park(op);

    last_error_ = errno;
    remember(op, -1, -1);
    return true;
}

size_t EpollBackend::wait(Completion *out, size_t cap, int timeout_ms) noexcept {
    /* \~english
     * The datagrams waiting to go out go FIRST, all of each socket in one
     * `sendmmsg`: this is the moment a loop that asked for several sends
     * hands over, so it is the moment they can leave together.
     * \~spanish
     * Los datagramas que esperan a salir van PRIMERO, todos los de cada socket
     * en un `sendmmsg`: este es el momento en que un bucle que pidio varios
     * envios los entrega, asi que es el momento en que pueden salir juntos.
     * \~ */
    if (dgram_ != nullptr)
        for (int32_t i = 0; i < static_cast<int32_t>(kMaxDatagramSockets); ++i)
            dgram_flush(i);

    size_t made = take_ready(out, cap, 0);

    if (queue_ < 0 || made == cap) return made;

    epoll_event events[64];
    int room = static_cast<int>(cap - made);
    if (room > 64) room = 64;

    /* \~english
     * The queue is asked even when completions were already in hand, and with
     * no waiting when they were.  Skipping it would mean a server whose sockets
     * always answer at once never looks at the one that has been ready for a
     * while -- and the one that has been ready for a while is usually the
     * listening socket, so the server would stop accepting exactly when it was
     * busy.
     *
     * \~spanish
     * A la cola se le pregunta aunque ya hubiera finalizaciones en la mano, y sin
     * esperar cuando las habia.  Saltarsela seria que un servidor cuyos sockets
     * contestan siempre en el acto no mira nunca al que lleva un rato listo -- y
     * el que lleva un rato listo suele ser el socket de escucha, asi que el
     * servidor dejaria de aceptar justo cuando tiene trabajo.
     * \~ */
    const int ms = made != 0 ? 0 : timeout_ms;
    const int got = epoll_wait(queue_, events, room, ms);
    if (got <= 0) return made;

    /* \~english
     * EVERY event is visited, even once @p out is full.  With `EPOLLONESHOT`
     * the kernel disarmed each descriptor it reported, so one skipped here
     * would stay disarmed while this end believed it armed -- its operations
     * parked for ever.  One with no room left does nothing but get re-armed,
     * and reports again on the next wait.
     * \~spanish
     * Se visitan TODOS los sucesos, aunque @p out ya este lleno.  Con
     * `EPOLLONESHOT` el nucleo desarmo cada descriptor que informo, asi que uno
     * saltado aqui se quedaria desarmado mientras este extremo lo cree armado --
     * con sus operaciones guardadas para siempre.  Uno sin sitio no hace nada
     * mas que rearmarse, y vuelve a informar en la espera siguiente.
     * \~ */
    for (int i = 0; i < got; ++i) {
        const int32_t fd = events[i].data.fd;
        if (fd < 0 || static_cast<uint32_t>(fd) >= max_fds_) continue;

        Waiting &w = waiting_[fd];

        /* \~english
         * The kernel disarmed it when it reported it, so what this end
         * remembers about the registration is now stale.  Saying so here is
         * what makes the re-arming below a `MOD` that actually happens: an
         * @c arm that still believed the old mask was in force would decide
         * nothing had changed and say nothing, and the descriptor would never
         * be reported again.
         * \~spanish
         * El nucleo lo desarmo al informarlo, asi que lo que este extremo recuerda
         * del registro ya no vale.  Decirlo aqui es lo que hace que el rearme de
         * abajo sea un `MOD` que ocurre de verdad: un @c arm que siguiera creyendo
         * que la mascara vieja esta puesta decidiria que no ha cambiado nada y no
         * diria nada, y el descriptor no se volveria a informar nunca.
         * \~ */
        w.armed = 0;

        /* \~english
         * A socket in trouble -- an error, or the peer gone -- is reported to
         * whatever was waiting on it in EITHER direction.  epoll says so with
         * flags that are not `EPOLLIN` or `EPOLLOUT`, and a backend that only
         * looked at those two would leave a write waiting on a socket that is
         * never going to take anything again.
         * \~spanish
         * Un socket con problemas -- un error, o el otro extremo ido -- se le
         * comunica a lo que estuviera esperando en CUALQUIERA de los dos sentidos.
         * epoll lo dice con banderas que no son `EPOLLIN` ni `EPOLLOUT`, y un
         * backend que solo mirara esas dos dejaria una escritura esperando en un
         * socket que no va a aceptar nada nunca mas.
         * \~ */
        const bool broken = (events[i].events & (EPOLLERR | EPOLLHUP)) != 0;
        const bool readable = broken || (events[i].events & EPOLLIN) != 0;
        const bool writable = broken || (events[i].events & EPOLLOUT) != 0;

        if (w.dgram >= 0) {
            made += dgram_ready(w.dgram, readable, writable, out + made,
                                cap - made);
            if (!arm(fd)) fail_waiting(fd);
            continue;
        }

        if (readable && w.has_read && made < cap) {
            const Op op = w.read;
            w.has_read = false;
            --in_flight_;

            const int n = try_now(op);

            if (n < 0 && not_now(errno)) {
                /* \~english
                 * Ready and then not: another completion in this same batch
                 * took the bytes, or the kernel changed its mind.  It goes back
                 * to waiting, which is the only answer that does not invent a
                 * result.
                 * \~spanish
                 * Listo y luego no: otra finalizacion de este mismo lote se llevo
                 * los bytes, o el nucleo cambio de idea.  Vuelve a esperar, que es
                 * la unica respuesta que no se inventa un resultado.
                 *
                 * \~english
                 * And if the queue will not watch it again, it is answered
                 * here as a failure rather than dropped: it was accepted, and
                 * its slot in @p out is still free.
                 * \~spanish
                 * Y si la cola no lo quiere volver a vigilar, se contesta aqui
                 * como fallo en vez de tirarla: se acepto, y su sitio en @p out
                 * sigue libre.
                 * \~ */
                if (!park(op)) answer_failed(out[made++], op);
            } else if (op.kind == OpKind::Accept) {
                if (n >= 0 && static_cast<uint32_t>(n) >= max_fds_) {
                    ::close(n);
                    out[made].conn = op.conn;
                    out[made].kind = op.kind;
                    out[made].buffer = op.buffer;
                    out[made].result = -1;
                    out[made].fd = -1;
                } else {
                    out[made].conn = op.conn;
                    out[made].kind = op.kind;
                    out[made].buffer = op.buffer;
                    out[made].result = n < 0 ? -1 : 0;
                    out[made].fd = n < 0 ? -1 : n;
                }
                ++made;
            } else {
                out[made].conn = op.conn;
                out[made].kind = op.kind;
                out[made].buffer = op.buffer;
                out[made].result = n;
                out[made].fd = -1;
                ++made;
            }
        }

        if (writable && w.has_write && made < cap) {
            const Op op = w.write;
            w.has_write = false;
            --in_flight_;

            const int n = try_now(op);

            if (n < 0 && not_now(errno)) {
                if (!park(op)) answer_failed(out[made++], op);
            } else {
                out[made].conn = op.conn;
                out[made].kind = op.kind;
                out[made].buffer = op.buffer;
                out[made].result = n;
                out[made].fd = -1;
                ++made;
            }
        }

        /* \~english
         * Re-armed for what is still waiting; a queue that refuses fails it
         * instead, because nothing else would ever report on it again.
         * \~spanish
         * Rearmado para lo que sigue esperando; una cola que se niega lo hace
         * fallar en su lugar, porque nada mas volveria a informar de ello.
         * \~ */
        if (!arm(fd)) fail_waiting(fd);
    }

    /* \~english
     * And what a socket that became writable just sent is reported now, not
     * one wait later.
     * \~spanish
     * Y lo que acaba de mandar un socket que se pudo escribir se informa ahora,
     * no una espera despues.
     * \~ */
    return take_ready(out, cap, made);
}

} // namespace http_vx
