/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_backend_cancel.cpp
 * @brief
 * \~english Ending a read a socket is waiting on, against both Linux backends.
 * \~spanish Acabar una lectura que espera en un socket, contra los dos backends de Linux.
 * \~
 *
 * \~english
 * @c OpKind::Cancel is what lets a shard close a connection whose peer went
 * silent: the connection's read is with the system, only the peer would
 * complete it, and the connection cannot leave while it is out.  What is
 * checked is the contract, straight on the backend and with no shard: the
 * read comes back once, as a failure, with its buffer; a write on the same
 * socket is not touched; the cancel itself is never a completion; with no
 * read out it does nothing; and a read that already finished comes back as
 * it finished.  The same cases run against epoll and io_uring -- R8 -- over a
 * socket pair, so nothing here needs a port.
 *
 * \~spanish
 * @c OpKind::Cancel es lo que deja a un fragmento cerrar una conexion cuyo otro
 * extremo se callo: la lectura de la conexion esta con el sistema, solo la
 * completaria el otro extremo, y la conexion no se puede ir mientras este
 * fuera.  Lo que se comprueba es el contrato, directamente sobre el backend y
 * sin fragmento: la lectura vuelve una vez, como fallo, con su buffer; una
 * escritura en el mismo socket no se toca; la cancelacion en si no es nunca una
 * finalizacion; sin lectura fuera no hace nada; y una lectura que ya acabo
 * vuelve como acabo.  Los mismos casos corren contra epoll y contra io_uring
 * -- la R8 -- sobre un par de sockets, asi que nada de aqui necesita un puerto.
 * \~
 */

#include "http_vx/epoll_backend.h"
#include "http_vx/uring_backend.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Backend;
using http_vx::Buffer;
using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::kNoBuffer;
using http_vx::Op;
using http_vx::OpKind;

enum class Which { Epoll, Uring };

int failures = 0;
const char *against = "?";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", against, what);
    ++failures;
}

/**
 * @brief
 * \~english One backend, its pool, and what the cases need to ask of it beyond the interface.
 * \~spanish Un backend, su pozo, y lo que los casos necesitan preguntarle mas alla de la interfaz.
 * \~
 */
struct Rig {
    BufferPool pool;
    http_vx::EpollBackend epoll;
    http_vx::UringBackend uring;
    Backend *io = nullptr;
    Which which = Which::Epoll;

    /// \~english Starts @p w with a ring of @p entries (io_uring only).
    /// \~spanish Arranca @p w con un anillo de @p entries (solo io_uring).  \~
    bool start(Which w, uint32_t entries = 64) {
        which = w;
        if (!pool.reset(8, 8192)) return false;
        if (w == Which::Epoll) {
            if (!epoll.reset(pool, 1024)) return false;
            io = &epoll;
        } else {
            if (!uring.reset(pool, entries)) return false;
            io = &uring;
        }
        return true;
    }

    size_t in_flight() const {
        return which == Which::Epoll ? epoll.in_flight() : uring.in_flight();
    }

    int32_t last_error() const {
        return which == Which::Epoll ? epoll.last_error() : uring.last_error();
    }

    /**
     * @brief
     * \~english A connected pair; [0] is the backend's, [1] the test's.
     * \~spanish Un par conectado; [0] es del backend, [1] de la prueba.
     * \~
     *
     * \~english
     * Non-blocking for epoll, which assumes it (it tries first, and a socket
     * that blocked would stop the loop); blocking for io_uring, whose own
     * sockets are -- the ring waits for them itself.
     * \~spanish
     * Que no bloquea para epoll, que lo supone (intenta primero, y un socket que
     * bloqueara pararia el bucle); que bloquea para io_uring, cuyos sockets
     * propios lo son -- el anillo espera por ellos el solo.
     * \~
     */
    bool pair(int sv[2]) const {
        const int flags = which == Which::Epoll ? SOCK_NONBLOCK : 0;
        return socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | flags, 0, sv) == 0;
    }
};

/**
 * @brief
 * \~english What came back over some turns of @c wait, counted by kind.
 * \~spanish Lo que volvio en unas vueltas de @c wait, contado por clase.
 * \~
 */
struct Seen {
    static constexpr size_t kKinds = static_cast<size_t>(OpKind::Cancel) + 1;

    Completion last[kKinds];
    size_t count[kKinds] = {};
    size_t total = 0;

    size_t of(OpKind k) const { return count[static_cast<size_t>(k)]; }

    /// \~english The last one of @p k that came back.  \~spanish La ultima de @p k que volvio.  \~
    const Completion &latest(OpKind k) const { return last[static_cast<size_t>(k)]; }
};

/// \~english Waits @p rounds times without blocking, adding what came back to @p s.
/// \~spanish Espera @p rounds veces sin bloquear, sumando a @p s lo que volvio.  \~
void collect(Rig &r, Seen &s, int rounds) {
    Completion done[16];
    for (int i = 0; i < rounds; ++i) {
        const size_t got = r.io->wait(done, 16, 0);
        for (size_t j = 0; j < got; ++j) {
            ++s.count[static_cast<size_t>(done[j].kind)];
            s.last[static_cast<size_t>(done[j].kind)] = done[j];
            ++s.total;
        }
        usleep(500);
    }
}

/// \~english An operation of @p kind on @p fd.  \~spanish Una operacion de @p kind sobre @p fd.  \~
Op op_on(OpKind kind, int fd, uint32_t buffer = kNoBuffer, uint32_t length = 0) {
    Op op;
    op.kind = kind;
    op.fd = fd;
    op.buffer = buffer;
    op.length = length;
    op.conn.slot = static_cast<uint32_t>(fd);
    op.conn.life = 7;
    return op;
}

/**
 * @brief
 * \~english Closes the backend's end of a pair THROUGH the backend, and takes the close's completion.
 * \~spanish Cierra el extremo del backend de un par A TRAVES del backend, y recoge la finalizacion del cierre.
 * \~
 *
 * \~english
 * Closing it behind the backend's back would leave the backend's notes about
 * that number in place, and the next socket given the same number would
 * inherit them -- a test failing for a reason of its own making.
 * \~spanish
 * Cerrarlo a espaldas del backend dejaria en su sitio las notas del backend
 * sobre ese numero, y el siguiente socket que recibiera el mismo numero las
 * heredaria -- una prueba fallando por un motivo que se fabrico ella.
 * \~
 */
void shut(Rig &r, int fd) {
    check(r.io->submit(op_on(OpKind::Close, fd)), "a close was refused");
    Seen s;
    for (int i = 0; i < 40 && s.of(OpKind::Close) == 0; ++i) collect(r, s, 1);
    check(s.of(OpKind::Close) == 1 && s.total == 1, "a close did not come back alone");
}

/**
 * @brief
 * \~english A waiting notice is ended once, as a failure; a second cancel adds nothing.
 * \~spanish Un aviso que espera se acaba una vez, como fallo; una segunda cancelacion no anade nada.
 * \~
 */
void test_a_waiting_notice_is_ended(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    check(r.io->submit(op_on(OpKind::Ready, sv[0])), "the notice was refused");
    Seen before;
    collect(r, before, 5);
    check(before.total == 0, "a notice completed on a silent socket");

    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");
    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "a second cancel was refused");

    Seen after;
    collect(r, after, 20);
    check(after.of(OpKind::Ready) == 1, "the notice did not come back exactly once");
    check(after.total == after.of(OpKind::Ready), "the cancel itself came back as a completion");
    const Completion &c = after.latest(OpKind::Ready);
    check(!c.ok(), "a cancelled notice came back as a success");
    check(c.conn.slot == static_cast<uint32_t>(sv[0]) && c.conn.life == 7,
          "the notice came back for somebody else");
    check(c.buffer == kNoBuffer, "a notice came back with a buffer");
    check(r.in_flight() == 0, "the cancelled notice is still counted as in flight");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english A waiting receive is ended once, as a failure, with its buffer and nothing in it.
 * \~spanish Una recepcion que espera se acaba una vez, como fallo, con su buffer y nada dentro.
 * \~
 */
void test_a_waiting_receive_is_ended_with_its_buffer(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    const uint32_t b = r.pool.acquire();
    check(r.io->submit(op_on(OpKind::Recv, sv[0], b, 512)), "the receive was refused");
    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");

    Seen s;
    collect(r, s, 20);
    check(s.of(OpKind::Recv) == 1, "the receive did not come back exactly once");
    check(s.total == 1, "something besides the receive came back");
    const Completion &c = s.latest(OpKind::Recv);
    check(!c.ok() && !c.eof(), "a cancelled receive came back as data or as the end");
    check(c.buffer == b, "the receive came back without its buffer");
    check(r.pool.at(b) != nullptr && r.pool.at(b)->size() == 0,
          "a cancelled receive left bytes in its buffer");
    check(r.in_flight() == 0, "the cancelled receive is still counted as in flight");

    r.pool.release(b);
    check(r.pool.lent() == 0, "a buffer is still lent");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english A write waiting on the same socket is not touched, and still completes whole.
 * \~spanish Una escritura que espera en el mismo socket no se toca, y sigue acabando entera.
 * \~
 */
void test_a_write_on_the_same_socket_is_left_alone(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    // \~english The socket is filled first, so the write has to wait.
    // \~spanish El socket se llena primero, para que la escritura tenga que esperar.  \~
    char chunk[4096];
    std::memset(chunk, 'f', sizeof chunk);
    size_t filled = 0;
    for (int i = 0; i < 100000; ++i) {
        const ssize_t n = send(sv[0], chunk, sizeof chunk, MSG_DONTWAIT);
        if (n <= 0) break;
        filled += static_cast<size_t>(n);
    }

    const uint32_t b = r.pool.acquire();
    Buffer *out = r.pool.at(b);
    uint8_t *room = out == nullptr ? nullptr : out->reserve(4096);
    check(room != nullptr, "no room in the write's buffer");
    if (room == nullptr) return;
    std::memset(room, 'w', 4096);
    out->commit(4096);

    check(r.io->submit(op_on(OpKind::Send, sv[0], b, 4096)), "the write was refused");
    check(r.io->submit(op_on(OpKind::Ready, sv[0])), "the notice was refused");

    Seen before;
    collect(r, before, 5);
    check(before.total == 0, "the write did not have to wait");

    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");

    Seen after;
    collect(r, after, 20);
    check(after.of(OpKind::Ready) == 1, "the notice did not come back exactly once");
    check(!after.latest(OpKind::Ready).ok(),
          "a cancelled notice came back as a success");
    check(after.of(OpKind::Send) == 0, "the cancel ended the write too");

    // \~english The peer reads, and the write goes.
    // \~spanish El otro extremo lee, y la escritura sale.  \~
    size_t drained = 0;
    Seen sent;
    for (int i = 0; i < 4000 && sent.of(OpKind::Send) == 0; ++i) {
        char sink[65536];
        const ssize_t n = recv(sv[1], sink, sizeof sink, MSG_DONTWAIT);
        if (n > 0) drained += static_cast<size_t>(n);
        collect(r, sent, 1);
    }
    check(sent.of(OpKind::Send) == 1, "the write never completed");
    const Completion &c = sent.latest(OpKind::Send);
    check(c.ok() && c.result == 4096, "the write did not complete whole");
    check(c.buffer == b, "the write came back without its buffer");
    check(sent.of(OpKind::Ready) == 0, "the cancelled notice came back twice");
    check(drained <= filled + 4096, "the peer read more than was ever sent");
    check(r.in_flight() == 0, "something is still counted as in flight");

    r.pool.release(b);
    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english A cancel with no read out does nothing, and is not a completion.
 * \~spanish Una cancelacion sin lectura fuera no hace nada, y no es una finalizacion.
 * \~
 */
void test_a_cancel_with_nothing_waiting_does_nothing(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "a cancel of nothing was refused");
    check(r.io->submit(op_on(OpKind::Cancel, -1)), "a cancel of no socket was refused");

    Seen s;
    collect(r, s, 10);
    check(s.total == 0, "a cancel of nothing produced a completion");
    check(r.in_flight() == 0, "a cancel of nothing is counted as in flight");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english A read that finished before the cancel comes back once, as it finished.
 * \~spanish Una lectura que acabo antes de la cancelacion vuelve una vez, como acabo.
 * \~
 *
 * \~english
 * Finished, not yet handed out: a write on another socket is asked for first
 * and a wait of ONE takes only it, so the read's completion is still waiting
 * to be taken -- in the ready list on epoll, in the completion ring on
 * io_uring -- when the cancel arrives.
 * \~spanish
 * Acabada, sin entregar todavia: antes se pide una escritura en otro socket y
 * una espera de UNA se lleva solo esa, asi que la finalizacion de la lectura
 * sigue esperando a que la recojan -- en la lista de listas en epoll, en el
 * anillo de finalizaciones en io_uring -- cuando llega la cancelacion.
 * \~
 */
void test_a_cancel_after_the_read_finished_changes_nothing(Rig &r) {
    int sv[2];
    int other[2];
    check(r.pair(sv) && r.pair(other), "no socket pairs");
    check(send(sv[1], "hello", 5, 0) == 5, "the peer could not speak");

    const uint32_t wb = r.pool.acquire();
    Buffer *w = r.pool.at(wb);
    uint8_t *room = w == nullptr ? nullptr : w->reserve(2);
    if (room != nullptr) {
        room[0] = 'o';
        room[1] = 'k';
        w->commit(2);
    }
    check(r.io->submit(op_on(OpKind::Send, other[0], wb, 2)), "the write was refused");

    const uint32_t rb = r.pool.acquire();
    check(r.io->submit(op_on(OpKind::Recv, sv[0], rb, 512)), "the receive was refused");

    Completion first[1];
    size_t got = 0;
    for (int i = 0; i < 100 && got == 0; ++i) got = r.io->wait(first, 1, 0);
    check(got == 1 && first[0].kind == OpKind::Send,
          "the setup did not leave the read's completion untaken");

    const int32_t error_before = r.last_error();
    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");

    Seen s;
    collect(r, s, 20);
    check(s.of(OpKind::Recv) == 1, "the finished read did not come back exactly once");
    const Completion &c = s.latest(OpKind::Recv);
    check(c.ok() && c.result == 5, "the finished read was turned into a failure");
    check(c.buffer == rb && r.pool.at(rb) != nullptr &&
              std::memcmp(r.pool.at(rb)->data(), "hello", 5) == 0,
          "the finished read lost its bytes");
    check(s.total == s.of(OpKind::Recv), "the cancel came back as a completion");
    check(r.last_error() == error_before, "a cancel that lost the race was reported as an error");
    check(r.in_flight() == 0, "something is still counted as in flight");

    r.pool.release(wb);
    r.pool.release(rb);
    shut(r, sv[0]);
    ::close(sv[1]);
    shut(r, other[0]);
    ::close(other[1]);
}

/**
 * @brief
 * \~english After a cancel the socket takes a new read, and it completes normally.
 * \~spanish Tras una cancelacion el socket acepta una lectura nueva, y acaba normalmente.
 * \~
 */
void test_the_socket_reads_again_after_a_cancel(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    check(r.io->submit(op_on(OpKind::Ready, sv[0])), "the notice was refused");
    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");
    Seen cancelled;
    collect(r, cancelled, 20);
    check(cancelled.of(OpKind::Ready) == 1, "the notice did not come back");

    check(r.io->submit(op_on(OpKind::Ready, sv[0])), "the next notice was refused");
    check(send(sv[1], "x", 1, 0) == 1, "the peer could not speak");

    Seen again;
    collect(r, again, 40);
    check(again.of(OpKind::Ready) == 1, "the next notice did not come back");
    check(again.latest(OpKind::Ready).ok(),
          "the next notice came back as a failure");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english Many cancels, one after another, never use up the backend.
 * \~spanish Muchas cancelaciones, una tras otra, no agotan nunca el backend.
 * \~
 *
 * \~english
 * Against a small ring on io_uring, so that a cancel whose own answer was
 * never counted back would run it out of places within a few turns.
 * \~spanish
 * Contra un anillo pequeno en io_uring, para que una cancelacion cuya
 * respuesta propia no se descontara nunca lo dejara sin sitios en pocas
 * vueltas.
 * \~
 */
void test_many_cancels_use_nothing_up(Which which) {
    Rig r;
    check(r.start(which, 4), "the small backend would not start");
    if (r.io == nullptr) return;

    int sv[2];
    check(r.pair(sv), "no socket pair");

    size_t back = 0;
    for (int i = 0; i < 40; ++i) {
        if (!r.io->submit(op_on(OpKind::Ready, sv[0]))) {
            check(false, "a notice was refused after some cancels");
            break;
        }
        check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "a cancel was refused");
        Seen s;
        for (int t = 0; t < 40 && s.of(OpKind::Ready) == 0; ++t) collect(r, s, 1);
        back += s.of(OpKind::Ready);
    }
    check(back == 40, "not every cancelled notice came back");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english A socket closed with its read out does not stand in the way of the next socket given its number.
 * \~spanish Un socket cerrado con su lectura fuera no estorba al siguiente socket que reciba su numero.
 * \~
 */
void test_a_closed_socket_frees_its_number(Rig &r) {
    int old[2];
    check(r.pair(old), "no socket pair");

    check(r.io->submit(op_on(OpKind::Ready, old[0])), "the notice was refused");
    check(r.io->submit(op_on(OpKind::Close, old[0])), "the close was refused");
    Seen closed;
    collect(r, closed, 20);
    check(closed.of(OpKind::Close) == 1, "the close did not come back");

    int sv[2];
    check(r.pair(sv), "no socket pair");
    if (sv[0] != old[0]) {
        std::printf("     (the system did not reuse the number; case not exercised)\n");
    }

    check(r.io->submit(op_on(OpKind::Ready, sv[0])), "the new socket's notice was refused");
    Seen quiet;
    collect(r, quiet, 5);
    check(quiet.of(OpKind::Ready) == 0, "the new socket's notice failed at once");

    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");
    Seen s;
    collect(r, s, 20);
    check(s.of(OpKind::Ready) == 1 && !s.latest(OpKind::Ready).ok(),
          "the new socket's notice could not be cancelled");

    shut(r, sv[0]);
    ::close(sv[1]);

    /* \~english
     * On io_uring the old read is still with the kernel -- a close does not
     * end it, which is why a shard cancels first -- and the peer going now
     * completes it.  It is taken here so it does not land in the next case.
     * \~spanish
     * En io_uring la lectura vieja sigue con el nucleo -- un cierre no la acaba,
     * que es por lo que un fragmento cancela primero -- y que se vaya el otro
     * extremo ahora la completa.  Se recoge aqui para que no caiga en el caso
     * siguiente.
     * \~ */
    ::close(old[1]);
    Seen orphan;
    collect(r, orphan, 10);
}

/**
 * @brief
 * \~english A second read on a socket that has one out is never left where no cancel reaches it.
 * \~spanish Una segunda lectura en un socket que ya tiene una fuera no se queda nunca donde no llega ninguna cancelacion.
 * \~
 *
 * \~english
 * epoll refuses it outright and io_uring fails it at once; either way,
 * everything that was accepted comes back after one cancel, and nothing is
 * left in flight.
 * \~spanish
 * epoll la rechaza sin mas e io_uring la hace fallar en el acto; de las dos
 * formas, todo lo que se acepto vuelve tras una cancelacion, y no queda nada
 * en vuelo.
 * \~
 */
void test_a_second_read_is_never_out_of_reach(Rig &r) {
    int sv[2];
    check(r.pair(sv), "no socket pair");

    size_t accepted = 0;
    if (r.io->submit(op_on(OpKind::Ready, sv[0]))) ++accepted;
    if (r.io->submit(op_on(OpKind::Ready, sv[0]))) ++accepted;
    check(accepted >= 1, "the first notice was refused");

    check(r.io->submit(op_on(OpKind::Cancel, sv[0])), "the cancel was refused");
    Seen s;
    collect(r, s, 20);
    check(s.of(OpKind::Ready) == accepted, "an accepted notice never came back");
    check(r.in_flight() == 0, "a notice is still out, where no cancel reaches it");

    shut(r, sv[0]);
    ::close(sv[1]);
}

/**
 * @brief
 * \~english Submits @p op, waiting for room when the queue is full; false if room never came.
 * \~spanish Entrega @p op, esperando sitio cuando la cola esta llena; false si el sitio no llego.
 * \~
 */
bool submit_patiently(Rig &r, const Op &op, Seen &s) {
    for (int i = 0; i < 100; ++i) {
        if (r.io->submit(op)) return true;
        collect(r, s, 1);
    }
    return false;
}

/**
 * @brief
 * \~english Cancels are taken even when every slot holds a read.
 * \~spanish Las cancelaciones se aceptan aunque todas las casillas tengan una lectura.
 * \~
 *
 * \~english
 * Which is exactly when a shard needs them: every read out is an idle
 * connection whose deadline passed, and nothing else can move until they
 * end.  A cancel refused for want of a slot would be refused for ever, since
 * only the cancels would free one.  Against a ring of four on io_uring --
 * eight slots, all of them reads.
 * \~spanish
 * Que es justo cuando un fragmento las necesita: cada lectura fuera es una
 * conexion callada con el plazo vencido, y nada mas se puede mover hasta que
 * acaben.  Una cancelacion rechazada por falta de casilla se rechazaria para
 * siempre, porque solo las cancelaciones liberarian una.  Contra un anillo de
 * cuatro en io_uring -- ocho casillas, todas lecturas.
 * \~
 */
void test_cancels_are_taken_with_every_slot_busy(Which which) {
    Rig r;
    check(r.start(which, 4), "the small backend would not start");
    if (r.io == nullptr) return;

    constexpr int kReads = 8;
    int sv[kReads][2];
    Seen s;
    int out = 0;
    for (int i = 0; i < kReads; ++i) {
        check(r.pair(sv[i]), "no socket pair");
        if (submit_patiently(r, op_on(OpKind::Ready, sv[i][0]), s)) ++out;
    }
    check(out == kReads, "the notices did not all go out");
    check(s.total == 0, "a notice completed on a silent socket");

    for (int i = 0; i < kReads; ++i)
        check(submit_patiently(r, op_on(OpKind::Cancel, sv[i][0]), s),
              "a cancel was refused for good with every slot busy");

    for (int t = 0; t < 100 && s.of(OpKind::Ready) < static_cast<size_t>(out); ++t)
        collect(r, s, 1);
    check(s.of(OpKind::Ready) == static_cast<size_t>(out), "not every notice was ended");
    check(s.total == s.of(OpKind::Ready), "a cancel came back as a completion");
    check(r.in_flight() == 0, "something is still counted as in flight");

    for (int i = 0; i < kReads; ++i) {
        shut(r, sv[i][0]);
        ::close(sv[i][1]);
    }
}

/**
 * @brief
 * \~english A cancel on the listening socket does not end its @c Accept: only reads are cancelled.
 * \~spanish Una cancelacion en el socket de escucha no acaba su @c Accept: solo se cancelan lecturas.
 * \~
 */
void test_an_accept_is_not_a_read(Rig &r) {
    /* \~english
     * The listening socket's number is the backend's own; it is the lowest
     * free one when it is opened, which a probe finds just before.
     * \~spanish
     * El numero del socket de escucha es del propio backend; es el menor libre
     * cuando se abre, que una sonda encuentra justo antes.
     * \~ */
    const int probe = socket(AF_INET, SOCK_STREAM, 0);
    ::close(probe);

    const bool listening = r.which == Which::Epoll ? r.epoll.listen("127.0.0.1", 0)
                                                   : r.uring.listen("127.0.0.1", 0);
    check(listening, "the backend would not listen");
    if (!listening) return;
    const uint16_t port = r.which == Which::Epoll ? r.epoll.port() : r.uring.port();

    check(r.io->submit(op_on(OpKind::Accept, -1)), "the accept was refused");
    Seen quiet;
    collect(r, quiet, 5);
    check(quiet.of(OpKind::Accept) == 0, "an accept completed with nobody connecting");

    check(r.io->submit(op_on(OpKind::Cancel, probe)), "the cancel was refused");
    Seen none;
    collect(r, none, 5);
    check(none.of(OpKind::Accept) == 0, "a cancel on the listening socket ended its accept");

    const int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    sockaddr_in to;
    std::memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(client, reinterpret_cast<sockaddr *>(&to), sizeof to);

    Seen s;
    for (int t = 0; t < 200 && s.of(OpKind::Accept) == 0; ++t) collect(r, s, 1);
    check(s.of(OpKind::Accept) == 1 && s.latest(OpKind::Accept).ok(),
          "the accept did not survive a cancel on its socket");

    if (s.latest(OpKind::Accept).fd >= 0) shut(r, s.latest(OpKind::Accept).fd);
    ::close(client);
}

/// \~english Runs every case against @p which.  \~spanish Corre todos los casos contra @p which.  \~
void run_every_case(Which which) {
    against = which == Which::Epoll ? http_vx::EpollBackend::kName : http_vx::UringBackend::kName;
    std::printf("  -- %s --\n", against);

    {
        Rig r;
        check(r.start(which), "the backend would not start");
        if (r.io == nullptr) return;
        test_a_waiting_notice_is_ended(r);
        test_a_waiting_receive_is_ended_with_its_buffer(r);
        test_a_write_on_the_same_socket_is_left_alone(r);
        test_a_cancel_with_nothing_waiting_does_nothing(r);
        test_a_cancel_after_the_read_finished_changes_nothing(r);
        test_the_socket_reads_again_after_a_cancel(r);
        test_a_second_read_is_never_out_of_reach(r);
        test_a_closed_socket_frees_its_number(r);
        test_an_accept_is_not_a_read(r);
    }

    test_many_cancels_use_nothing_up(which);
    test_cancels_are_taken_with_every_slot_busy(which);
}

} // namespace

int main() {
    run_every_case(Which::Epoll);

    /* \~english
     * io_uring only if this kernel gives a ring, and a skip SAYS so: a silent
     * skip would be a green run where half the backends never ran.
     * \~spanish
     * io_uring solo si este nucleo da un anillo, y un salto lo DICE: uno
     * callado seria una corrida verde donde la mitad de los backends no corrio.
     * \~ */
    if (http_vx::uring_available())
        run_every_case(Which::Uring);
    else
        std::printf("  -- io_uring: SKIPPED, this kernel gives no ring --\n");

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
