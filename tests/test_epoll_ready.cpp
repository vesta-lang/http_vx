/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_epoll_ready.cpp
 * @brief
 * \~english epoll never loses a completion it owes: not to a full list, not to a queue that refuses.
 * \~spanish epoll no pierde nunca una finalizacion que debe: ni por una lista llena, ni por una cola que se niega.
 * \~
 *
 * \~english
 * Every operation epoll accepts holds a buffer until its completion comes
 * back, so a completion lost is a buffer the pool never sees again.  Two ways
 * it used to happen, both silent:
 *
 *  - the list of completions already true had 256 places, and closing a
 *    datagram socket answered every operation queued on it -- up to 128 --
 *    into it without looking for room;
 *  - when the queue refused to watch a socket (`epoll_ctl` failing), the
 *    operation being asked for was refused and the one ALREADY waiting on
 *    the socket, in the other direction, was forgotten with it.
 *
 * Linux only: this is the adaptation R7 says only epoll needs.
 *
 * \~spanish
 * Toda operacion que acepta epoll tiene un buffer hasta que vuelve su
 * finalizacion, asi que una finalizacion perdida es un buffer que el pozo no
 * vuelve a ver.  Dos formas en que pasaba, las dos en silencio:
 *
 *  - la lista de finalizaciones ya ciertas tenia 256 sitios, y cerrar un socket
 *    de datagramas contestaba ahi todas las operaciones que tuviera en cola --
 *    hasta 128 -- sin mirar si habia sitio;
 *  - cuando la cola se negaba a vigilar un socket (fallaba `epoll_ctl`), la
 *    operacion que se pedia se rechazaba y la que YA esperaba en el socket, en
 *    el otro sentido, se olvidaba con ella.
 *
 * Solo Linux: esta es la adaptacion que la R7 dice que solo necesita epoll.
 * \~
 */

#include "http_vx/epoll_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace {

using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::EpollBackend;
using http_vx::kNoBuffer;
using http_vx::NetAddress;
using http_vx::Op;
using http_vx::OpKind;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english A @c Close of no socket: completes at once, holds nothing.
/// \~spanish Un @c Close de ningun socket: acaba en el acto, no tiene nada.  \~
Op nothing_to_close(uint32_t tag) {
    Op op;
    op.kind = OpKind::Close;
    op.buffer = kNoBuffer;
    op.fd = -1;
    op.conn.slot = tag;
    return op;
}

/// \~english Takes every completion there is, releasing buffers; how many of @p kind.
/// \~spanish Recoge todas las finalizaciones que haya, soltando buffers; cuantas de @p kind.  \~
size_t drain(EpollBackend &io, BufferPool &pool, OpKind kind, size_t &failed) {
    size_t seen = 0;
    Completion done[64];
    for (int round = 0; round < 200; ++round) {
        const size_t got = io.wait(done, 64, 0);
        for (size_t i = 0; i < got; ++i) {
            if (done[i].buffer != kNoBuffer) pool.release(done[i].buffer);
            if (done[i].kind != kind) continue;
            ++seen;
            if (!done[i].ok()) ++failed;
        }
        if (got == 0 && round > 2) break;
    }
    return seen;
}

/**
 * @brief
 * \~english A datagram socket closed with full queues, behind a full ready list, gives every buffer back.
 * \~spanish Un socket de datagramas cerrado con las colas llenas, detras de una lista llena, devuelve todos los buffers.
 * \~
 */
void test_closing_a_full_datagram_socket_loses_nothing() {
    BufferPool pool;
    check(pool.reset(256, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 1024), "epoll would not start");

    NetAddress bound;
    const int32_t fd = io.open_datagram("127.0.0.1", 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    /* \~english
     * Sixty-four receives and sixty-four sends, the most either queue holds.
     * The sends are not flushed: that only happens when the backend waits.
     * \~spanish
     * Sesenta y cuatro recepciones y sesenta y cuatro envios, lo mas que cabe
     * en cada cola.  Los envios no salen: eso solo pasa cuando espera el
     * backend.
     * \~ */
    size_t receives = 0;
    size_t sends = 0;
    for (int i = 0; i < 64; ++i) {
        Op op;
        op.kind = OpKind::RecvFrom;
        op.buffer = pool.acquire();
        op.length = 512;
        op.fd = fd;
        if (io.submit(op)) ++receives;

        op.kind = OpKind::SendTo;
        op.buffer = pool.acquire();
        op.length = 0;
        if (io.submit(op)) ++sends;
    }
    check(receives == 64 && sends == 64, "the queues did not take what they hold");
    check(io.in_flight() == 128, "the queued operations were not counted");

    /* \~english
     * The ready list filled to where the old one had room for six more.
     * \~spanish
     * La lista de listas llena hasta donde a la vieja le quedaba sitio para
     * seis mas.
     * \~ */
    size_t closes = 0;
    for (uint32_t i = 0; i < 250; ++i)
        if (io.submit(nothing_to_close(i))) ++closes;
    check(closes == 250, "an immediate completion was refused");

    Op shut;
    shut.kind = OpKind::Close;
    shut.buffer = kNoBuffer;
    shut.fd = fd;
    check(io.submit(shut), "closing the datagram socket was refused");
    check(io.in_flight() == 0, "an operation still waits on a closed socket");

    size_t failed = 0;
    const size_t back_r = drain(io, pool, OpKind::RecvFrom, failed);
    check(back_r == 64, "a receive on the closed socket was never answered");
    check(failed == 64, "a receive on a closed socket was reported as received");
    check(pool.lent() == 0, "a buffer never came back to the pool");
    check(io.refused() == 0, "a submission was refused for lack of memory");
}

/**
 * @brief
 * \~english Everything a closed datagram socket held comes back as a failure, sends included.
 * \~spanish Todo lo que tenia un socket de datagramas cerrado vuelve como fallo, envios incluidos.
 * \~
 */
void test_closing_answers_every_operation_as_failed() {
    BufferPool pool;
    check(pool.reset(256, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 1024), "epoll would not start");

    NetAddress bound;
    const int32_t fd = io.open_datagram("127.0.0.1", 0, bound);
    if (fd < 0) {
        check(false, "a datagram socket could not be opened");
        return;
    }

    for (int i = 0; i < 64; ++i) {
        Op op;
        op.kind = OpKind::SendTo;
        op.buffer = pool.acquire();
        op.fd = fd;
        io.submit(op);
    }
    for (uint32_t i = 0; i < 250; ++i) io.submit(nothing_to_close(i));

    Op shut;
    shut.kind = OpKind::Close;
    shut.buffer = kNoBuffer;
    shut.fd = fd;
    io.submit(shut);

    size_t failed = 0;
    check(drain(io, pool, OpKind::SendTo, failed) == 64,
          "a send queued on the closed socket was never answered");
    check(failed == 64, "a send on a closed socket was reported as sent");
    check(pool.lent() == 0, "a send's buffer never came back");
}

/**
 * @brief
 * \~english Completions already true are never refused for number, and come out in order.
 * \~spanish Las finalizaciones ya ciertas no se rechazan por numero, y salen en orden.
 * \~
 *
 * \~english
 * Some are taken first so that the ring has wrapped when it has to grow:
 * the order out is the order in, across the wrap and across the growing.
 * \~spanish
 * Se cogen algunas primero para que el anillo haya dado la vuelta cuando tenga
 * que crecer: el orden de salida es el de entrada, a traves de la vuelta y del
 * crecimiento.
 * \~
 */
void test_the_ready_list_grows_in_order() {
    BufferPool pool;
    check(pool.reset(4, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 64), "epoll would not start");

    uint32_t next_in = 0;
    uint32_t next_out = 0;
    bool in_order = true;
    Completion done[64];

    for (int i = 0; i < 200; ++i) check(io.submit(nothing_to_close(next_in++)), "a close was refused");

    size_t got = io.wait(done, 64, 0);
    for (size_t i = 0; i < got; ++i)
        if (done[i].conn.slot != next_out++) in_order = false;
    check(got == 64, "the first batch did not come out whole");

    for (int i = 0; i < 700; ++i) check(io.submit(nothing_to_close(next_in++)), "a close was refused once many were waiting");

    for (int round = 0; round < 100 && next_out < next_in; ++round) {
        got = io.wait(done, 64, 0);
        for (size_t i = 0; i < got; ++i)
            if (done[i].conn.slot != next_out++) in_order = false;
    }

    check(next_out == next_in, "completions were lost when the list grew");
    check(in_order, "completions came out in another order than they went in");
    check(io.refused() == 0, "a submission was refused for lack of memory");
}

/**
 * @brief
 * \~english The ring turns over without growing, many times, and still hands out in order.
 * \~spanish El anillo da la vuelta sin crecer, muchas veces, y sigue entregando en orden.
 * \~
 */
void test_the_ready_ring_turns_over() {
    BufferPool pool;
    check(pool.reset(4, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 64), "epoll would not start");

    uint32_t next_in = 0;
    uint32_t next_out = 0;
    bool in_order = true;
    Completion done[64];

    for (int round = 0; round < 5; ++round) {
        for (int i = 0; i < 100; ++i) check(io.submit(nothing_to_close(next_in++)), "a close was refused");
        while (next_out < next_in) {
            const size_t got = io.wait(done, 64, 0);
            if (got == 0) break;
            for (size_t i = 0; i < got; ++i)
                if (done[i].conn.slot != next_out++) in_order = false;
        }
    }

    check(next_out == next_in, "completions were lost as the ring turned over");
    check(in_order, "the ring handed out in another order once it turned over");
}

/**
 * @brief
 * \~english Closes @p fd behind the backend and gives its number to a new socket pair.
 * \~spanish Cierra @p fd por detras del backend y le da su numero a un par de sockets nuevo.
 * \~
 *
 * \~english
 * The registration the backend believes in is then gone, so its next change
 * to the queue for that number fails with `ENOENT` -- the way `epoll_ctl`
 * otherwise fails only under memory pressure.
 * \~spanish
 * El registro en el que cree el backend deja de existir, asi que su siguiente
 * cambio en la cola para ese numero falla con `ENOENT` -- como falla
 * `epoll_ctl` si no, solo con presion de memoria.
 * \~
 *
 * @return \~english false, said, if the system did not reuse the number
 *         \~spanish false, dicho, si el sistema no reutilizo el numero  \~
 */
bool swap_behind(int fd, int again[2]) {
    ::close(fd);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, again) != 0) {
        check(false, "a replacement socket pair could not be made");
        return false;
    }
    if (again[0] == fd) return true;

    check(false, "the system did not reuse the number, so the case was not reached");
    ::close(again[0]);
    ::close(again[1]);
    return false;
}

/**
 * @brief
 * \~english The mirror case: a read waits, a send is refused, and the read comes back failed.
 * \~spanish El caso espejo: espera una lectura, se rechaza un envio, y la lectura vuelve fallada.
 * \~
 */
void test_a_refused_socket_fails_the_read_that_waited() {
    BufferPool pool;
    check(pool.reset(4, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 1024), "epoll would not start");

    int ends[2];
    check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, ends) == 0,
          "a socket pair could not be made");

    const uint32_t b = pool.acquire();
    Op read;
    read.kind = OpKind::Recv;
    read.buffer = b;
    read.length = 512;
    read.fd = ends[0];
    check(io.submit(read), "the read was not taken");
    check(io.in_flight() == 1, "the read is not waiting");

    int again[2];
    if (!swap_behind(ends[0], again)) {
        ::close(ends[1]);
        return;
    }

    Op send;
    send.kind = OpKind::Send;
    send.buffer = kNoBuffer;
    send.fd = again[0];
    check(!io.submit(send), "a socket the queue refused was taken");
    check(io.in_flight() == 0, "the read still waits on a socket nobody watches");

    Completion done[4];
    const size_t got = io.wait(done, 4, 0);
    check(got == 1 && done[0].kind == OpKind::Recv && !done[0].ok() &&
              done[0].buffer == b,
          "the read that was waiting was forgotten instead of failed");
    if (got == 1) pool.release(done[0].buffer);
    check(pool.lent() == 0, "the read's buffer never came back");

    ::close(again[0]);
    ::close(again[1]);
    ::close(ends[1]);
}

/**
 * @brief
 * \~english A datagram receive the queue refuses is refused whole: not queued, not counted, never answered.
 * \~spanish Una recepcion de datagramas que la cola rechaza se rechaza entera: ni en cola, ni contada, ni contestada.
 * \~
 *
 * \~english
 * The queue is only told something when the interest changes, and with a
 * receive already queued it does not: so the refusal is reached with the
 * receive queue empty.  What could still be waiting then is a blocked send,
 * which loopback UDP never produces.
 * \~spanish
 * A la cola solo se le dice algo cuando cambia el interes, y con una recepcion
 * ya en cola no cambia: asi que al rechazo se llega con la cola de recepciones
 * vacia.  Lo que podria estar esperando entonces es un envio bloqueado, que UDP
 * por el bucle local no produce nunca.
 * \~
 */
void test_a_refused_datagram_receive_is_refused_whole() {
    BufferPool pool;
    check(pool.reset(4, 4096), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 1024), "epoll would not start");

    NetAddress bound;
    const int32_t fd = io.open_datagram("127.0.0.1", 0, bound);
    check(fd >= 0, "a datagram socket could not be opened");
    if (fd < 0) return;

    /* \~english
     * One receive completed for real first, so that the socket is registered
     * with the queue: a socket never registered would be ADDed afresh, and an
     * ADD of the new socket behind the number succeeds.
     * \~spanish
     * Primero una recepcion completada de verdad, para que el socket este
     * registrado en la cola: uno que no lo estuviera se anadiria de nuevo, y
     * anadir el socket nuevo que hay detras del numero funciona.
     * \~ */
    Op first;
    first.kind = OpKind::RecvFrom;
    first.buffer = pool.acquire();
    first.length = 512;
    first.fd = fd;
    check(io.submit(first), "the first receive was not taken");

    const int peer = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in to;
    std::memcpy(&to, bound.bytes, sizeof to);
    check(sendto(peer, "d", 1, 0, reinterpret_cast<sockaddr *>(&to), sizeof to) == 1,
          "the datagram could not be sent");
    ::close(peer);

    Completion done[4];
    size_t got = 0;
    for (int round = 0; round < 100 && got == 0; ++round) got = io.wait(done, 4, 10);
    check(got == 1 && done[0].ok(), "the first receive did not complete");
    if (got == 1) pool.release(done[0].buffer);

    int again[2];
    if (!swap_behind(fd, again)) return;

    Op receive;
    receive.kind = OpKind::RecvFrom;
    receive.buffer = pool.acquire();
    receive.length = 512;
    receive.fd = fd;
    check(!io.submit(receive), "a receive the queue refused was taken");
    check(io.in_flight() == 0, "a refused receive is counted as waiting");
    check(io.wait(done, 4, 0) == 0, "a refused receive was answered as well");
    pool.release(receive.buffer);
    check(pool.lent() == 0, "a receive's buffer never came back");

    /* \~english The number is still the backend's datagram socket: it closes it itself.
     * \~spanish El numero sigue siendo el socket de datagramas del backend: lo cierra el.  \~ */
    ::close(again[1]);
}

/**
 * @brief
 * \~english A queue that refuses a socket fails what already waited on it, instead of forgetting it.
 * \~spanish Una cola que rechaza un socket hace fallar lo que ya esperaba en el, en vez de olvidarlo.
 * \~
 *
 * \~english
 * `epoll_ctl` is made to fail the way it fails for real only under memory
 * pressure: the socket a send is parked on is closed BEHIND the backend and
 * its number handed to a new one, so the registration the backend believes
 * in is gone and the next change to it is `ENOENT`.  The @c Ready asked for
 * on the new socket is refused; the @c Send that was waiting has to come
 * back, failed, with its buffer.
 * \~spanish
 * Se hace fallar `epoll_ctl` como falla de verdad solo con presion de memoria:
 * el socket en el que espera un envio se cierra POR DETRAS del backend y su
 * numero se le da a otro, asi que el registro en el que cree el backend ya no
 * esta y el siguiente cambio sobre el es `ENOENT`.  El @c Ready que se pide
 * sobre el socket nuevo se rechaza; el @c Send que esperaba tiene que volver,
 * fallado, con su buffer.
 * \~
 */
void test_a_refused_socket_fails_what_waited() {
    BufferPool pool;
    check(pool.reset(4, 1 << 20), "the pool would not start");

    EpollBackend io;
    check(io.reset(pool, 1024), "epoll would not start");

    int ends[2];
    check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, ends) == 0,
          "a socket pair could not be made");

    /* \~english The send queue filled, so the next send has to wait.
     * \~spanish La cola de envio llena, para que el envio siguiente tenga que esperar.  \~ */
    char junk[4096];
    std::memset(junk, 'x', sizeof junk);
    while (::send(ends[0], junk, sizeof junk, MSG_DONTWAIT) > 0) {
    }

    const uint32_t b = pool.acquire();
    uint8_t *room = pool.at(b)->reserve(1024);
    std::memset(room, 'y', 1024);
    pool.at(b)->commit(1024);

    Op send;
    send.kind = OpKind::Send;
    send.buffer = b;
    send.length = 1024;
    send.fd = ends[0];
    check(io.submit(send), "the send was not taken");
    check(io.in_flight() == 1, "the send is not waiting");

    int again[2];
    if (!swap_behind(ends[0], again)) {
        ::close(ends[1]);
        return;
    }

    Op ready;
    ready.kind = OpKind::Ready;
    ready.buffer = kNoBuffer;
    ready.fd = again[0];
    check(!io.submit(ready), "a socket the queue refused was taken");
    check(io.last_error() == ENOENT, "the refusal did not say why");
    check(io.in_flight() == 0, "something still waits on a socket nobody watches");

    Completion done[4];
    const size_t got = io.wait(done, 4, 0);
    check(got == 1 && done[0].kind == OpKind::Send && !done[0].ok() &&
              done[0].buffer == b,
          "the send that was waiting was forgotten instead of failed");
    if (got == 1) pool.release(done[0].buffer);
    check(pool.lent() == 0, "the send's buffer never came back");

    ::close(again[0]);
    ::close(again[1]);
    ::close(ends[1]);
}

} // namespace

int main() {
    test_closing_a_full_datagram_socket_loses_nothing();
    test_closing_answers_every_operation_as_failed();
    test_the_ready_list_grows_in_order();
    test_the_ready_ring_turns_over();
    test_a_refused_socket_fails_what_waited();
    test_a_refused_socket_fails_the_read_that_waited();
    test_a_refused_datagram_receive_is_refused_whole();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("epoll ready: OK\n");
    return 0;
}
