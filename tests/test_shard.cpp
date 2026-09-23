/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard.cpp
 * @brief
 * \~english Who holds a buffer, and for exactly how long.
 * \~spanish Quien tiene un buffer, y exactamente cuanto tiempo.
 * \~
 *
 * \~english
 * R1 says an idle connection has no buffer.  It is a claim about this loop and
 * about nothing else -- no buffer class can make it true -- so this is where
 * it is checked, by counting.
 *
 * The other two are about time rather than memory.  A buffer is the operating
 * system's while an operation on it is outstanding, so a connection that is
 * closed mid-read does not hand it back until the completion arrives; and a
 * deadline is pushed forward by activity, so a connection that keeps talking
 * never times out while one that stops does.
 *
 * All three fail silently.  Holding a buffer too long is a server that runs
 * out of them under a load nothing explains; handing one back too early is the
 * kernel writing into somebody else's memory; and a deadline that is not
 * pushed forward closes connections that were doing fine.
 *
 * \~spanish
 * La R1 dice que una conexion parada no tiene buffer.  Es una afirmacion sobre
 * este bucle y sobre nada mas -- ninguna clase de buffer puede hacerla cierta --
 * asi que aqui es donde se comprueba, contando.
 *
 * Las otras dos van de tiempo y no de memoria.  Un buffer es del sistema
 * operativo mientras tenga una operacion pendiente, asi que una conexion que se
 * cierra a media lectura no lo devuelve hasta que llega la finalizacion; y un
 * plazo lo empuja la actividad, asi que una conexion que sigue hablando no vence
 * nunca y una que se calla si.
 *
 * Las tres fallan en silencio.  Guardar un buffer de mas es un servidor que se
 * queda sin ellos con una carga que no lo explica; devolverlo de menos es el
 * nucleo escribiendo en la memoria de otro; y un plazo que no se empuja cierra
 * conexiones que iban bien.
 *
 * \~
 */

#include "http_vx/memory_backend.h"
#include "http_vx/shard.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Buffer;
using http_vx::ConnHandle;
using http_vx::ConnState;
using http_vx::MemoryBackend;
using http_vx::Service;
using http_vx::Shard;
using http_vx::ShardConfig;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english A service that answers every read with a fixed line.
 * \~spanish Un servicio que contesta cada lectura con una linea fija.
 * \~
 *
 * \~english
 * It does not parse anything, and that is the point: what is being tested is
 * the loop, and a loop that needed a real protocol to be exercised would be a
 * loop that knew about one.
 *
 * \~spanish
 * No analiza nada, y de eso se trata: lo que se prueba es el bucle, y un bucle
 * que necesitara un protocolo de verdad para ejercitarse seria un bucle que
 * supiera de alguno.
 *
 * \~
 */
class Echo final : public Service {
  public:
    bool on_bytes(ConnHandle c, const uint8_t *in, size_t n,
                  Buffer &out) noexcept override {
        (void)c;
        ++calls;
        seen += n;

        if (silent) return true;
        if (refuse) return false;

        uint8_t *room = out.reserve(n);
        if (room == nullptr) return false;
        std::memcpy(room, in, n);
        out.commit(n);
        return true;
    }

    void on_open(ConnHandle c) noexcept override {
        (void)c;
        ++opened;
    }

    void on_close(ConnHandle c) noexcept override {
        (void)c;
        ++closed;
    }

    int calls = 0;
    int opened = 0;
    int closed = 0;
    size_t seen = 0;

    /// \~english Answer nothing, which is legal and must not leak a buffer.
    /// \~spanish No contestar nada, que es legal y no puede perder un buffer.  \~
    bool silent = false;

    /// \~english End the connection.  \~spanish Acabar la conexion.  \~
    bool refuse = false;
};

/**
 * @brief
 * \~english A shard with its backend and service, made together.
 * \~spanish Un fragmento con su backend y su servicio, hechos juntos.
 * \~
 */
struct Rig {
    Echo service;
    Shard shard;
    MemoryBackend io;

    Rig() : io(shard.buffers()) {}

    bool start(uint32_t buffers, uint32_t idle) {
        ShardConfig cfg;
        cfg.connections = 8;
        cfg.buffers = buffers;
        cfg.idle_ticks = idle;
        cfg.wheel_slots = 64;
        return shard.reset(cfg, io, service, 0);
    }
};

/**
 * @brief
 * \~english An idle connection holds no buffer.
 * \~spanish Una conexion parada no tiene buffer.
 * \~
 *
 * \~english
 * R1, counted.  A connection that has arrived and said nothing has a record in
 * an array and a socket; the buffer it would have been given is in the pool
 * serving somebody who is actually talking.
 *
 * The check is on the POOL and not on the connection, because that is where
 * the claim matters: what R1 is worth is the number of buffers a server holds,
 * and a connection that thought it had none while the pool said otherwise
 * would be the same server with a tidier field.
 *
 * \~spanish
 * La R1, contada.  Una conexion que ha llegado y no ha dicho nada tiene un
 * registro de un array y un socket; el buffer que se le habria dado esta en el
 * pozo sirviendo a alguien que si habla.
 *
 * La comprobacion es sobre el POZO y no sobre la conexion, porque ahi es donde
 * importa la afirmacion: lo que vale la R1 es el numero de buffers que tiene un
 * servidor, y una conexion que creyera no tener ninguno mientras el pozo dijera
 * otra cosa seria el mismo servidor con un campo mas ordenado.
 *
 * \~
 */
void test_an_idle_connection_holds_no_buffer() {
    Rig r;
    check(r.start(4, 10), "the shard would not start");

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");
    check(r.service.opened == 1, "the service was not told");

    /* \~english
     * A read is outstanding, so exactly one buffer is out -- the one the
     * operating system is writing into.
     * \~spanish
     * Hay una lectura pendiente, asi que hay exactamente un buffer fuera -- ese
     * en el que esta escribiendo el sistema operativo.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "a connection with a read outstanding is not holding one buffer");

    const char *msg = "hello";
    check(r.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    check(r.shard.poll(1, 0) == 1, "the read did not come back");
    check(r.service.calls == 1, "the service did not see the bytes");
    check(r.service.seen == std::strlen(msg),
          "the service saw the wrong number of bytes");

    /* \~english
     * Now it is answering, so it holds the write buffer -- and the read one
     * went back the moment the service was done with it.
     * \~spanish
     * Ahora esta contestando, asi que tiene el buffer de escritura -- y el de
     * lectura volvio en cuanto el servicio acabo con el.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "a connection answering is not holding exactly one buffer");

    check(r.shard.poll(2, 0) == 1, "the write did not come back");
    check(r.io.written_size() == std::strlen(msg), "the answer did not go out");

    /* \~english
     * And it is reading again, which is keep-alive: one buffer, for the read.
     * \~spanish
     * Y esta leyendo otra vez, que es mantener viva la conexion: un buffer, el
     * de la lectura.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "a connection reading again is not holding one buffer");

    r.shard.close(c);
    check(r.service.closed == 0,
          "a connection with a read outstanding left straight away");

    /* \~english
     * The buffer is the operating system's until the completion arrives, so
     * closing does NOT hand it back now.  Handing it back here is a
     * use-after-free the kernel performs, into memory that by then belongs to
     * somebody else.
     * \~spanish
     * El buffer es del sistema operativo hasta que llegue la finalizacion, asi
     * que cerrar NO lo devuelve ahora.  Devolverlo aqui es un uso despues de
     * liberar que hace el nucleo, sobre una memoria que para entonces es de
     * otro.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "closing handed back a buffer the operating system still had");

    r.io.end_of_stream();
    r.shard.poll(3, 0);

    check(r.service.closed == 1, "the connection did not finish leaving");
    check(r.shard.buffers().lent() == 0,
          "a connection that has gone is still holding a buffer");
}

/**
 * @brief
 * \~english A connection that keeps talking never times out.
 * \~spanish Una conexion que sigue hablando no vence nunca.
 * \~
 */
void test_activity_pushes_the_deadline() {
    Rig r;
    check(r.start(4, 5), "the shard would not start");

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");
    check(r.shard.deadlines().armed(c.slot),
          "a new connection has no deadline");

    uint64_t now = 0;
    for (int i = 0; i < 20; ++i) {
        const char *msg = "x";
        r.io.feed(reinterpret_cast<const uint8_t *>(msg), 1);

        now += 3;
        check(r.shard.expire(now) == 0,
              "a connection that was talking was closed for being quiet");

        r.shard.poll(now, 0);
        r.shard.poll(now, 0);
    }

    check(r.shard.conns().alive(c), "the connection did not survive talking");

    /* \~english
     * And then it stops.  Five ticks later it goes, which is the deadline
     * doing the one thing it is for.
     * \~spanish
     * Y entonces se calla.  Cinco tics despues se va, que es el plazo haciendo
     * lo unico para lo que esta.
     * \~ */
    check(r.shard.expire(now + 4) == 0, "the connection was closed too early");
    check(r.shard.expire(now + 6) == 1,
          "the connection was not closed for being quiet");

    /* \~english
     * And it leaves in TWO steps, because it had a read outstanding.  The
     * deadline decides it is over; the buffer is still the operating system's,
     * so the connection waits for the completion before it actually goes.
     *
     * The first version of this test asserted the service had been told
     * already, which is the natural thing to assume and is the whole bug the
     * closing rule exists to prevent: a shard that told the service and handed
     * the buffer back here would be handing back memory the kernel is about to
     * write into.
     *
     * \~spanish
     * Y se va en DOS pasos, porque tenia una lectura pendiente.  El plazo decide
     * que se acabo; el buffer sigue siendo del sistema operativo, asi que la
     * conexion espera a la finalizacion antes de irse de verdad.
     *
     * La primera version de esta prueba afirmaba que ya se le habia dicho al
     * servicio, que es lo natural de suponer y es justo el fallo para el que
     * existe la regla de cierre: un fragmento que se lo dijera al servicio y
     * devolviera el buffer aqui estaria devolviendo una memoria en la que el
     * nucleo esta a punto de escribir.
     * \~ */
    check(r.service.closed == 0,
          "a connection with a read outstanding left straight away");
    check(r.shard.buffers().lent() == 1,
          "a deadline handed back a buffer the operating system still had");

    r.io.end_of_stream();
    r.shard.poll(now + 6, 0);

    check(r.service.closed == 1, "the service was not told it had gone");
    check(r.shard.buffers().lent() == 0,
          "the connection left without giving its buffer back");
}

/**
 * @brief
 * \~english With no buffers, a connection waits rather than failing.
 * \~spanish Sin buffers, una conexion espera en vez de fallar.
 * \~
 *
 * \~english
 * The pool is deliberately smaller than the table, so running out is the
 * ordinary case and not an emergency.  A connection that cannot get one does
 * not read this time round; the bytes wait in the kernel's receive queue,
 * which is a place designed to hold them.
 *
 * Its deadline is still armed, which is the part worth checking: a connection
 * that never gets a turn has to go away like any other, or a shard that ran
 * out of buffers once would fill up with connections that can never be served
 * and never expire.
 *
 * \~spanish
 * El pozo es a proposito mas pequeno que la tabla, asi que quedarse sin es el
 * caso corriente y no una emergencia.  Una conexion que no consigue uno no lee
 * esta vuelta; los bytes esperan en la cola de recepcion del nucleo, que es un
 * sitio hecho para guardarlos.
 *
 * Su plazo sigue armado, que es la parte que merece comprobarse: una conexion a
 * la que no le toque nunca tiene que irse como cualquier otra, o un fragmento
 * que se quedara sin buffers una vez se llenaria de conexiones a las que no se
 * puede servir y que no vencen nunca.
 *
 * \~
 */
void test_a_connection_without_a_buffer_still_expires() {
    Rig r;
    check(r.start(1, 5), "the shard would not start");

    const ConnHandle first = r.shard.adopt(7, 0);
    check(first.valid(), "the first connection was not adopted");
    check(r.shard.buffers().lent() == 1, "the first read took no buffer");

    const ConnHandle second = r.shard.adopt(8, 0);
    check(second.valid(), "the second connection was not adopted");
    check(r.shard.conns().count() == 2, "the second connection was refused");

    /* \~english
     * There was no buffer for it, so it is not reading -- and that is not an
     * error anywhere.
     * \~spanish
     * No habia buffer para ella, asi que no esta leyendo -- y eso no es un error
     * en ningun sitio.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "the second connection got a buffer that did not exist");

    const http_vx::ConnHot *h = r.shard.conns().hot(second);
    check(h != nullptr &&
              h->state == static_cast<uint16_t>(ConnState::Idle),
          "a connection with no buffer is not idle");
    check(h != nullptr && h->buffer == http_vx::kNoBuffer,
          "a connection with no buffer says it has one");

    /* \~english
     * And it still goes away when its time is up.
     * \~spanish
     * Y se va igual cuando se le acaba el tiempo.
     * \~ */
    check(r.shard.deadlines().armed(second.slot),
          "a connection with no buffer has no deadline");
    check(r.shard.expire(6) == 2, "the quiet connections were not closed");
}

/**
 * @brief
 * \~english A service that answers nothing does not lose the buffer it was given.
 * \~spanish Un servicio que no contesta nada no pierde el buffer que le dieron.
 * \~
 *
 * \~english
 * Half a request is a legitimate read, and the answer to it is nothing.  It is
 * also the shape a leak takes: the write buffer was acquired before the
 * service was asked, so a loop that only released it on the way out through
 * the write would leak one buffer per partial read -- and a peer that sent its
 * requests one byte at a time would empty the pool.
 *
 * \~spanish
 * Media peticion es una lectura legitima, y la respuesta a ella es nada.  Es
 * ademas la forma que tiene una fuga: el buffer de escritura se cogio antes de
 * preguntarle al servicio, asi que un bucle que solo lo soltara de salida por la
 * escritura perderia un buffer por cada lectura parcial -- y un extremo que
 * mandara sus peticiones byte a byte vaciaria el pozo.
 *
 * \~
 */
void test_answering_nothing_keeps_the_pool_whole() {
    Rig r;
    check(r.start(4, 10), "the shard would not start");
    r.service.silent = true;

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    for (int i = 0; i < 50; ++i) {
        const char *msg = "x";
        r.io.feed(reinterpret_cast<const uint8_t *>(msg), 1);
        check(r.shard.poll(1, 0) == 1, "the read did not come back");

        /* \~english
         * One buffer, for the read that was started again.  Never two, never
         * creeping.
         * \~spanish
         * Un buffer, el de la lectura que se volvio a empezar.  Nunca dos, y
         * nunca subiendo.
         * \~ */
        check(r.shard.buffers().lent() == 1,
              "answering nothing left a buffer behind");
    }

    check(r.service.calls == 50, "the service was not asked every time");
    check(r.io.written_size() == 0, "a silent service wrote something");
}

/**
 * @brief
 * \~english A service that gives up ends the connection and keeps nothing.
 * \~spanish Un servicio que se rinde acaba la conexion y no se queda nada.
 * \~
 */
void test_a_service_can_end_it() {
    Rig r;
    check(r.start(4, 10), "the shard would not start");
    r.service.refuse = true;

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    const char *msg = "bad";
    r.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg));
    r.shard.poll(1, 0);

    check(r.service.closed == 1, "the connection was not closed");
    check(!r.shard.conns().alive(c), "the connection is still alive");
    check(r.shard.buffers().lent() == 0,
          "a refused connection kept a buffer");
    check(!r.shard.deadlines().armed(c.slot),
          "a closed connection kept its deadline");
}

} // namespace

int main() {
    test_an_idle_connection_holds_no_buffer();
    test_activity_pushes_the_deadline();
    test_a_connection_without_a_buffer_still_expires();
    test_answering_nothing_keeps_the_pool_whole();
    test_a_service_can_end_it();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
