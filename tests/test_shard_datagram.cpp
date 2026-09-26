/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard_datagram.cpp
 * @brief
 * \~english The shard's datagram side, driven through memory: what goes to the service and what comes out.
 * \~spanish El lado de datagramas del fragmento, movido por memoria: lo que va al servicio y lo que sale.
 * \~
 *
 * \~english
 * The loop's half of R26, without a network, so that every rule can be put
 * in a state a real socket would only reach by chance: a datagram that is
 * cut, a service asking for a family nobody serves, a pool with nothing left,
 * a timer due.  Each of these either reaches the service whole, or is counted
 * where somebody will see it -- never neither.
 *
 * Before this file there was no datagram side at all: a @c RecvFrom that
 * completed was read as a connection's stream, by the slot number its
 * operation happened to carry.
 *
 * \~spanish
 * La mitad del bucle de la R26, sin red, para poder poner cada regla en un
 * estado al que un socket de verdad solo llegaria por casualidad: un datagrama
 * que se corta, un servicio que pide una familia que no sirve nadie, un pozo sin
 * nada, un temporizador vencido.  Cada uno llega entero al servicio o se cuenta
 * donde alguien lo va a ver -- nunca ninguna de las dos.
 *
 * Antes de este fichero no habia lado de datagramas: un @c RecvFrom que
 * acababa se leia como el flujo de una conexion, por el numero de casilla que
 * llevara su operacion.
 * \~
 */

#include "http_vx/datagram_service.h"
#include "http_vx/memory_backend.h"
#include "http_vx/shard.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::DatagramPath;
using http_vx::EcnMark;
using http_vx::MemoryBackend;
using http_vx::NetAddress;
using http_vx::Shard;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

NetAddress made_up(uint8_t fill, uint8_t len) {
    NetAddress a;
    std::memset(a.bytes, fill, len);
    a.len = len;
    return a;
}

/**
 * @brief
 * \~english Remembers what it is handed and answers each datagram once, on its own path.
 * \~spanish Recuerda lo que le dan y contesta cada datagrama una vez, por su propio camino.
 * \~
 */
class Reply final : public http_vx::DatagramService {
  public:
    void on_datagram(const DatagramPath &path, uint8_t *data, size_t n,
                     EcnMark ecn, uint64_t now) noexcept override {
        if (count == 8) return;
        paths[count] = path;
        sizes[count] = n;
        marks[count] = ecn;
        clocks[count] = now;
        if (n != 0) std::memcpy(bytes[count], data, n < 64 ? n : 64);
        ++count;
    }

    size_t next_datagram(DatagramPath &path, uint8_t *out, size_t room,
                         uint64_t now) noexcept override {
        (void)now;
        ++asked;
        if (overstate) {
            overstate = false;
            path.peer = made_up(0xA1, 16);
            return room + 1;
        }
        if (extra.len != 0) {
            path.peer = extra;
            path.local = NetAddress();
            extra = NetAddress();
            out[0] = 'x';
            return 1;
        }
        if (answered == count || room < sizes[answered]) return 0;
        path = paths[answered];
        std::memcpy(out, bytes[answered], sizes[answered]);
        return sizes[answered++];
    }

    uint64_t timer() const noexcept override { return due; }

    void on_timer(uint64_t now) noexcept override {
        ++fired;
        fired_at = now;
        due = http_vx::kNoDatagramTimer;
        extra = on_fire;
    }

    /// \~english Where a datagram goes when the timer fires, if anywhere.
    /// \~spanish Adonde va un datagrama cuando vence el temporizador, si a algun sitio.  \~
    NetAddress on_fire;

    DatagramPath paths[8];
    size_t sizes[8] = {};
    EcnMark marks[8] = {};
    uint64_t clocks[8] = {};
    uint8_t bytes[8][64] = {};
    size_t count = 0;
    size_t answered = 0;
    int asked = 0;

    /// \~english Once, claim a datagram larger than the room -- a service bug.
    /// \~spanish Una vez, decir que un datagrama es mayor que el sitio -- un fallo del servicio.  \~
    bool overstate = false;

    /// \~english One datagram to a peer of this family, sent before the answers.
    /// \~spanish Un datagrama a un extremo de esta familia, antes de las respuestas.  \~
    NetAddress extra;

    uint64_t due = http_vx::kNoDatagramTimer;
    int fired = 0;
    uint64_t fired_at = 0;
};

/// \~english The shard takes a stream service to be made; none is used here.
/// \~spanish El fragmento necesita un servicio de flujos para hacerse; aqui no se usa.  \~
class NoStreams final : public http_vx::Service {
  public:
    bool on_bytes(http_vx::ConnHandle c, http_vx::Buffer &in,
                  http_vx::Buffer &out) noexcept override {
        (void)c;
        (void)in;
        (void)out;
        return false;
    }
};

struct Rig {
    NoStreams streams;
    Reply service;
    Shard shard;
    MemoryBackend io;

    Rig() : io(shard.buffers()) {}

    bool start(uint32_t buffers, uint32_t receives, uint32_t room = 1500) {
        http_vx::ShardConfig cfg;
        cfg.connections = 4;
        cfg.buffers = buffers;
        cfg.idle_ticks = 10;
        cfg.wheel_slots = 64;
        if (!shard.reset(cfg, io, streams, 0)) return false;

        http_vx::DatagramConfig dc;
        dc.receives = receives;
        dc.room = room;
        return shard.attach_datagrams(service, dc);
    }
};

/**
 * @brief
 * \~english Datagrams reach the service whole, with their path, and the answers go out on it.
 * \~spanish Los datagramas llegan enteros al servicio, con su camino, y las respuestas salen por el.
 * \~
 */
void test_datagrams_in_and_answers_out() {
    Rig r;
    check(r.start(16, 4), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");

    check(r.shard.datagrams().posted(0) == 4, "the receives were not posted");
    check(r.shard.buffers().lent() == 4, "the receives do not hold their buffers");

    DatagramPath a;
    a.peer = made_up(0xA1, 16);
    a.local = made_up(0x10, 16);
    DatagramPath b;
    b.peer = made_up(0xB2, 16);
    b.local = made_up(0x11, 16);

    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>("one"), 3, EcnMark::Ect0);
    r.io.feed_datagram(b, reinterpret_cast<const uint8_t *>("two!"), 4, EcnMark::Ce);
    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>(""), 0);

    /* \~english
     * One turn: the three arrive, and the two answers they call for are
     * handed to the backend in the SAME turn, so that the next wait sends
     * them together.
     * \~spanish
     * Una vuelta: llegan los tres, y las dos respuestas que piden se le dan al
     * backend en la MISMA vuelta, para que la espera siguiente las mande juntas.
     * \~ */
    r.shard.poll(77, 0);
    check(r.shard.datagrams().sending() == 2,
          "the answers were not handed over in the turn that made them");

    for (int i = 0; i < 3; ++i) r.shard.poll(77, 0);

    check(r.service.count == 3, "the service was not handed all three");
    check(r.service.sizes[0] == 3 && std::memcmp(r.service.bytes[0], "one", 3) == 0,
          "the first datagram changed");
    check(http_vx::same_net_address(r.service.paths[1].peer, b.peer) &&
              http_vx::same_net_address(r.service.paths[1].local, b.local),
          "the second datagram lost its path");
    check(r.service.marks[0] == EcnMark::Ect0 && r.service.marks[1] == EcnMark::Ce,
          "the ECN marks were not handed on");
    check(r.service.sizes[2] == 0, "an empty datagram was not handed on as empty");
    check(r.service.clocks[0] == 77, "the service was not given the caller's clock");

    /* \~english
     * Two answers, not three: the empty datagram's answer is empty, and zero
     * from @c next_datagram means "nothing to send" -- an empty datagram
     * cannot be sent through this interface, which is also what QUIC needs.
     * \~spanish
     * Dos respuestas, no tres: la del datagrama vacio es vacia, y cero en
     * @c next_datagram quiere decir "nada que mandar" -- un datagrama vacio no se
     * puede mandar por esta interfaz, que es ademas lo que necesita QUIC.
     * \~ */
    check(r.io.datagrams_out() == 2, "the two answers did not both go out");
    const http_vx::MemoryDatagram *second = r.io.datagram_out(1);
    check(second != nullptr &&
              http_vx::same_net_address(second->header.path.peer, b.peer) &&
              http_vx::same_net_address(second->header.path.local, b.local) &&
              (second->header.flags & http_vx::kDatagramLocalKnown) != 0,
          "an answer did not go back on its path");
    check(second != nullptr && second->size == 4 &&
              std::memcmp(second->bytes, "two!", 4) == 0,
          "an answer changed on the way out");

    const http_vx::ShardDatagramCounts &c = r.shard.datagrams().counts();
    check(c.delivered == 3 && c.sent == 2, "the shard did not count what it moved");
    check(r.shard.datagrams().posted(0) == 4, "the receives were not replaced");
    check(r.shard.datagrams().sending() == 0, "a send never came back");

    /* \~english
     * R1 as the datagram side keeps it: the posted receives and nothing else.
     * \~spanish
     * La R1 como la mantiene el lado de datagramas: las recepciones puestas y
     * nada mas.
     * \~ */
    check(r.shard.buffers().lent() == 4,
          "buffers are held beyond the posted receives");
}

/**
 * @brief
 * \~english A cut datagram is counted and dropped, and the socket carries on.
 * \~spanish Un datagrama cortado se cuenta y se tira, y el socket sigue.
 * \~
 */
void test_a_cut_datagram_is_counted() {
    Rig r;
    check(r.start(8, 2, 8), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");

    DatagramPath a;
    a.peer = made_up(0xA1, 16);

    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>("far too long"), 12);
    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>("short"), 5);

    for (int i = 0; i < 4; ++i) r.shard.poll(1, 0);

    check(r.service.count == 1, "a cut datagram was handed to the service");
    check(r.service.sizes[0] == 5, "the datagram after the cut one was lost");
    check(r.shard.datagrams().counts().truncated == 1, "the cut was not counted");
    check(r.shard.datagrams().posted(0) == 2, "the cut receive was not replaced");
}

/**
 * @brief
 * \~english A datagram no socket can carry is dropped, counted, and the rest still go.
 * \~spanish Un datagrama que no puede llevar ningun socket se tira, contado, y los demas salen.
 * \~
 */
void test_a_datagram_nobody_can_carry_is_counted() {
    Rig r;
    check(r.start(8, 1), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");

    r.service.extra = made_up(0xC3, 28);

    DatagramPath a;
    a.peer = made_up(0xA1, 16);
    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>("hi"), 2);

    for (int i = 0; i < 4; ++i) r.shard.poll(1, 0);

    check(r.shard.datagrams().counts().dropped == 1,
          "a datagram to a family nobody serves was not counted");
    check(r.io.datagrams_out() == 1, "the answer behind it did not go");
    check(r.shard.buffers().lent() == 1, "the dropped datagram kept its buffer");

    /* \~english
     * A service that claims more than the room it was given wrote past it or
     * lies; either way what it produced is not sent.
     * \~spanish
     * Un servicio que dice mas que el sitio que se le dio escribio fuera o
     * miente; de cualquier forma lo que produjo no se manda.
     * \~ */
    r.service.overstate = true;
    r.shard.poll(2, 0);
    r.shard.poll(3, 0);
    check(r.shard.datagrams().counts().dropped == 2,
          "a datagram larger than its room was not dropped");
    check(r.io.datagrams_out() == 1, "a datagram larger than its room went out");
}

/**
 * @brief
 * \~english Among several sockets, a datagram leaves by the one bound to its local address.
 * \~spanish Entre varios sockets, un datagrama sale por el atado a su direccion local.
 * \~
 */
void test_the_socket_of_the_local_address_is_used() {
    Rig r;
    check(r.start(16, 1), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)), "first socket");
    check(r.shard.add_datagram_socket(21, made_up(0x60, 28)), "second socket");
    check(r.shard.add_datagram_socket(22, made_up(0x11, 16)), "third socket");

    DatagramPath b;
    b.peer = made_up(0xB2, 16);
    b.local = made_up(0x11, 16);
    r.io.feed_datagram(b, reinterpret_cast<const uint8_t *>("x"), 1);

    for (int i = 0; i < 4; ++i) r.shard.poll(1, 0);

    check(r.io.datagrams_out() == 1, "the answer did not go");
    check(r.io.datagram_out(0) != nullptr && r.io.datagram_out(0)->fd == 22,
          "the answer left by the wrong socket");
}

/**
 * @brief
 * \~english With no buffer the service is not asked, and nothing is lost.
 * \~spanish Sin buffer no se le pregunta al servicio, y no se pierde nada.
 * \~
 */
void test_no_buffer_means_not_asked() {
    Rig r;
    check(r.start(2, 2), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");

    r.service.extra = made_up(0xA1, 16);
    r.shard.poll(1, 0);

    check(r.service.asked == 0, "the service was asked with nowhere to write");
    check(r.shard.datagrams().counts().starved != 0, "the starving was not counted");
    check(r.shard.datagrams().counts().dropped == 0, "something was dropped");
}

/**
 * @brief
 * \~english The service's timer runs when due, and not before.
 * \~spanish El temporizador del servicio corre cuando vence, y no antes.
 * \~
 */
void test_the_timer_runs_when_due() {
    Rig r;
    check(r.start(8, 1), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");
    r.service.due = 50;
    r.service.on_fire = made_up(0xA1, 16);

    check(r.shard.datagrams().timer() == 50, "the timer is not the service's");

    r.shard.poll(49, 0);
    check(r.service.fired == 0, "the timer ran early");

    /* \~english
     * And what the timer wanted to say goes out in the SAME turn: the timer
     * runs before the wait, and so does handing over what it produced.
     * \~spanish
     * Y lo que queria decir el temporizador sale en la MISMA vuelta: el
     * temporizador corre antes de esperar, y lo que produjo se entrega tambien
     * antes.
     * \~ */
    r.shard.poll(50, 0);
    check(r.service.fired == 1 && r.service.fired_at == 50,
          "the timer did not run when due");
    check(r.io.datagrams_out() == 1,
          "what the timer produced did not go out in the turn it fired");
}

/**
 * @brief
 * \~english A failed receive or send is counted and never handed on as a datagram.
 * \~spanish Una recepcion o un envio fallidos se cuentan y nunca se entregan como datagrama.
 * \~
 */
void test_failures_are_counted() {
    Rig r;
    check(r.start(8, 1), "the shard would not start");
    check(r.shard.add_datagram_socket(20, made_up(0x10, 16)),
          "the socket was not taken");

    DatagramPath a;
    a.peer = made_up(0xA1, 16);
    r.io.feed_datagram(a, reinterpret_cast<const uint8_t *>("ok"), 2);
    r.shard.poll(1, 0);
    check(r.service.count == 1, "the datagram was not delivered");

    /* \~english
     * Waiting now: the replaced receive, then the answer's send.  Both fail.
     * \~spanish
     * Esperan ahora: la recepcion repuesta, y despues el envio de la respuesta.
     * Fallan las dos.
     * \~ */
    r.io.fail_next(2, -1);
    r.shard.poll(2, 0);

    const http_vx::ShardDatagramCounts &c = r.shard.datagrams().counts();
    check(c.receive_failures == 1, "the failed receive was not counted");
    check(c.send_failures == 1, "the failed send was not counted");
    check(c.sent == 0, "a failed send was counted as sent");
    check(r.service.count == 1, "a failed receive was handed on");
    check(r.shard.datagrams().posted(0) == 1, "the failed receive was not replaced");
    check(r.shard.buffers().lent() == 1, "a failure kept its buffer");
}

/**
 * @brief
 * \~english Without a datagram side, a datagram completion still gives its buffer back.
 * \~spanish Sin lado de datagramas, una finalizacion de datagrama devuelve igual su buffer.
 * \~
 */
void test_a_stray_datagram_completion_keeps_the_pool_whole() {
    NoStreams streams;
    Shard shard;
    MemoryBackend io(shard.buffers());

    http_vx::ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 4;
    cfg.idle_ticks = 10;
    cfg.wheel_slots = 64;
    check(shard.reset(cfg, io, streams, 0), "the shard would not start");

    const uint32_t b = shard.buffers().acquire();
    DatagramPath a;
    a.peer = made_up(1, 16);
    io.feed_datagram(a, reinterpret_cast<const uint8_t *>("z"), 1);

    http_vx::Op op;
    op.kind = http_vx::OpKind::RecvFrom;
    op.buffer = b;
    op.length = 64;
    io.submit(op);

    shard.poll(1, 0);
    check(shard.buffers().lent() == 0, "a stray datagram completion leaked its buffer");
    check(shard.conns().count() == 0, "a datagram was taken for a connection");
}

/**
 * @brief
 * \~english A datagram side that could not work is refused when it is made.
 * \~spanish Un lado de datagramas que no podria funcionar se rechaza al hacerlo.
 * \~
 */
void test_a_side_that_cannot_work_is_refused() {
    Rig r;
    http_vx::DatagramConfig dc;

    check(!r.shard.attach_datagrams(r.service, dc),
          "a datagram side was attached before the shard was made");

    check(r.start(4, 1), "the shard would not start");

    dc.receives = 0;
    check(!r.shard.attach_datagrams(r.service, dc), "no receives was accepted");
    dc.receives = 1;
    dc.room = 0;
    check(!r.shard.attach_datagrams(r.service, dc), "no room was accepted");
    dc.room = 1500;
    dc.sends_per_turn = 0;
    check(!r.shard.attach_datagrams(r.service, dc), "no sends per turn was accepted");

    check(!r.shard.add_datagram_socket(20, made_up(1, 16)),
          "a socket was taken by a side that was never made");

    /* \~english
     * And a shard let go of lets go of its datagram side too: a service kept
     * after the shard's memory is gone would be driven into freed buffers.
     * \~spanish
     * Y un fragmento que se suelta suelta tambien su lado de datagramas: un
     * servicio guardado cuando ya no esta la memoria del fragmento se moveria
     * sobre buffers liberados.
     * \~ */
    dc.sends_per_turn = 8;
    check(r.shard.attach_datagrams(r.service, dc), "a good side was refused");
    check(r.shard.add_datagram_socket(20, made_up(1, 16)), "the socket was refused");
    r.shard.release();
    check(!r.shard.datagrams().attached() && r.shard.datagrams().sockets() == 0,
          "the datagram side outlived its shard");
}

} // namespace

int main() {
    test_a_side_that_cannot_work_is_refused();
    test_datagrams_in_and_answers_out();
    test_a_cut_datagram_is_counted();
    test_a_datagram_nobody_can_carry_is_counted();
    test_the_socket_of_the_local_address_is_used();
    test_no_buffer_means_not_asked();
    test_the_timer_runs_when_due();
    test_failures_are_counted();
    test_a_stray_datagram_completion_keeps_the_pool_whole();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
