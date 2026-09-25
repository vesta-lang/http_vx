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

#include "http_vx/epoll_backend.h"

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

/**
 * @brief
 * \~english What one socket is waiting for, in each direction.
 * \~spanish Lo que espera un socket, en cada sentido.
 * \~
 */
struct EpollBackend::Waiting {
    Op read;
    Op write;

    bool has_read;
    bool has_write;

    /**
     * \~english
     * What the queue was last told about this socket, so that it is only told
     * again when it changed.  An `epoll_ctl` per operation would be a syscall
     * bought for nothing on every read of a connection that was already being
     * read from.
     * \~spanish
     * Lo ultimo que se le dijo a la cola sobre este socket, para decirselo solo
     * cuando cambie.  Un `epoll_ctl` por operacion seria una llamada al sistema
     * comprada para nada en cada lectura de una conexion de la que ya se estaba
     * leyendo.
     * \~
     */
    uint32_t armed;

    bool known;
};

namespace {

/// \~english Whether @p kind is one that reads.
/// \~spanish Si @p kind es de los que leen.  \~
bool reads(OpKind kind) noexcept {
    return kind == OpKind::Recv || kind == OpKind::RecvFrom ||
           kind == OpKind::Accept || kind == OpKind::Ready;
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

} // namespace

EpollBackend::~EpollBackend() { release(); }

void EpollBackend::release() noexcept {
    if (listener_ >= 0) {
        ::close(listener_);
        listener_ = -1;
    }

    if (queue_ >= 0) {
        ::close(queue_);
        queue_ = -1;
    }

    if (waiting_ != nullptr) {
        for (uint32_t i = 0; i < max_fds_; ++i) waiting_[i].~Waiting();
        util::host_free(waiting_);
        waiting_ = nullptr;
    }

    max_fds_ = 0;
    in_flight_ = 0;
    ready_count_ = 0;
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
    }

    return true;
}

bool EpollBackend::listen(const char *host, uint16_t port, int backlog) noexcept {
    if (queue_ < 0) return false;

    const int s = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                           IPPROTO_TCP);
    if (s < 0) {
        last_error_ = errno;
        return false;
    }

    /* \~english
     * `SO_REUSEADDR`, which on Linux means what a server wants it to mean: a
     * port whose last connection is still in `TIME_WAIT` can be bound again.
     * Without it, a server that restarts fails to start for a minute or two
     * after having worked perfectly -- which reads as a broken build.
     * \~spanish
     * `SO_REUSEADDR`, que en Linux quiere decir lo que un servidor quiere que
     * quiera decir: un puerto cuya ultima conexion siga en `TIME_WAIT` se puede
     * volver a atar.  Sin el, un servidor que se reinicia no arranca durante un
     * minuto o dos despues de haber funcionado perfectamente -- que se lee como
     * una construccion rota.
     * \~ */
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    sockaddr_in addr;
    util::vesta_memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        last_error_ = errno;
        ::close(s);
        return false;
    }

    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0) {
        last_error_ = errno;
        ::close(s);
        return false;
    }

    if (::listen(s, backlog) < 0) {
        last_error_ = errno;
        ::close(s);
        return false;
    }

    socklen_t len = sizeof addr;
    if (getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
        port_ = ntohs(addr.sin_port);

    if (static_cast<uint32_t>(s) >= max_fds_) {
        last_error_ = EMFILE;
        ::close(s);
        return false;
    }

    listener_ = s;
    return true;
}

bool EpollBackend::remember(const Op &op, int32_t result, int32_t fd) noexcept {
    if (ready_count_ == 256) return false;

    Completion &c = ready_[ready_count_];
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = result;
    c.fd = fd;
    ++ready_count_;
    return true;
}

bool EpollBackend::arm(int32_t fd) noexcept {
    Waiting &w = waiting_[fd];

    uint32_t want = 0;
    if (w.has_read) want |= EPOLLIN;
    if (w.has_write) want |= EPOLLOUT;

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
        forget(op.fd);
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

    case OpKind::Ready: {
        /* \~english
         * One byte looked at and left where it was.  `MSG_PEEK` is the whole
         * answer here: there is no buffer to read into -- not having one is the
         * point -- and what is being asked is only whether a read would find
         * anything.
         *
         * A zero would have been simpler and is wrong: a receive of zero bytes
         * returns zero on Linux whatever the socket is doing, so it would say
         * "ready" about every socket in the server, for ever.
         *
         * Zero from a real peek IS the answer though -- it is the peer having
         * closed -- and it is reported as ready on purpose: the read that
         * follows finds the end of the stream, which is a thing the loop above
         * needs to be told about the ordinary way.
         *
         * \~spanish
         * Un byte mirado y dejado donde estaba.  `MSG_PEEK` es toda la respuesta
         * aqui: no hay buffer en el que leer -- no tenerlo es de lo que se trata
         * -- y lo unico que se pregunta es si una lectura encontraria algo.
         *
         * Un cero habria sido mas simple y esta mal: una recepcion de cero bytes
         * devuelve cero en Linux haga lo que haga el socket, asi que diria "listo"
         * de todos los sockets del servidor, para siempre.
         *
         * Un cero de un vistazo de verdad SI es la respuesta -- es el otro extremo
         * habiendo cerrado -- y se dice que esta listo a proposito: la lectura que
         * viene detras encuentra el fin del flujo, que es algo de lo que hay que
         * avisar al bucle de encima por la via corriente.
         * \~ */
        uint8_t peek = 0;
        const ssize_t n = ::recv(op.fd, &peek, 1, MSG_PEEK);
        return n < 0 ? -1 : 0;
    }

    case OpKind::Recv:
    case OpKind::RecvFrom: {
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

    case OpKind::Send:
    case OpKind::SendTo: {
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
            forget(op.fd);
            ::close(op.fd);
        }
        return remember(op, 0, -1);
    }

    if (op.fd < 0 || static_cast<uint32_t>(op.fd) >= max_fds_) {
        last_error_ = EBADF;
        return remember(op, -1, -1);
    }

    /* \~english
     * With no room to report a completion, the operation is PARKED rather than
     * tried.  Doing it and having nowhere to say so would lose bytes that had
     * already left a socket, and nothing would ever ask for them again; waiting
     * costs a turn of the loop and cannot be wrong.
     * \~spanish
     * Sin sitio para dar una finalizacion, la operacion se GUARDA en vez de
     * intentarse.  Hacerla y no tener donde decirlo perderia unos bytes que ya
     * habian salido de un socket, y no volveria a pedirlos nadie; esperar cuesta
     * una vuelta del bucle y no puede estar mal.
     * \~ */
    if (ready_count_ == 256) return park(op);

    const int n = try_now(op);

    if (n >= 0) {
        if (op.kind == OpKind::Accept) {
            if (static_cast<uint32_t>(n) >= max_fds_) {
                ::close(n);
                last_error_ = EMFILE;
                return remember(op, -1, -1);
            }
            return remember(op, 0, n);
        }
        return remember(op, n, -1);
    }

    if (not_now(errno)) return park(op);

    last_error_ = errno;
    return remember(op, -1, -1);
}

size_t EpollBackend::wait(Completion *out, size_t cap, int timeout_ms) noexcept {
    size_t made = 0;

    while (made < cap && made < ready_count_) {
        out[made] = ready_[made];
        ++made;
    }

    if (made != 0) {
        for (size_t i = made; i < ready_count_; ++i)
            ready_[i - made] = ready_[i];
        ready_count_ -= made;
    }

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

    for (int i = 0; i < got && made < cap; ++i) {
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
                 * \~ */
                park(op);
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
                park(op);
            } else {
                out[made].conn = op.conn;
                out[made].kind = op.kind;
                out[made].buffer = op.buffer;
                out[made].result = n;
                out[made].fd = -1;
                ++made;
            }
        }

        arm(fd);
    }

    return made;
}

} // namespace http_vx
