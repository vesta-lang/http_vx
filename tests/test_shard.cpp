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
using http_vx::kReadPending;
using http_vx::kWritePending;
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
    bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override {
        (void)c;
        ++calls;

        const size_t n = in.size();
        seen += n;

        if (refuse) return false;

        /* \~english
         * A silent service takes the bytes and says nothing, which is what a
         * protocol does with half a message.  It still consumes them here,
         * because what it is standing in for is a service that HAS used them
         * -- leaving them would be testing the other case.
         * \~spanish
         * Un servicio callado coge los bytes y no dice nada, que es lo que hace
         * un protocolo con medio mensaje.  Los consume igual, porque lo que
         * esta representando es un servicio que SI los ha usado -- dejarlos
         * seria probar el otro caso.
         * \~ */
        if (silent) {
            in.consume(n);
            return true;
        }

        uint8_t *room = out.reserve(n);
        if (room == nullptr) return false;
        std::memcpy(room, in.data(), n);
        out.commit(n);
        in.consume(n);
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

    bool start(uint32_t buffers, uint32_t idle, uint32_t accepts = 0,
               uint32_t connections = 8) {
        ShardConfig cfg;
        cfg.connections = connections;
        cfg.buffers = buffers;
        cfg.idle_ticks = idle;
        cfg.wheel_slots = 64;
        cfg.accepts = accepts;
        return shard.reset(cfg, io, service, 0);
    }
};

/**
 * @brief
 * \~english A connection that arrives is taken and served.
 * \~spanish Una conexion que llega se coge y se sirve.
 * \~
 *
 * \~english
 * Accepting is a completion like any other, which is the whole point: the loop
 * does not call `accept` and wait, it asks for the next connection and is told
 * when there is one.  What this checks is that the socket the operating system
 * handed over ends up in the table with nobody outside having been asked.
 *
 * \~spanish
 * Aceptar es una finalizacion como cualquier otra, que es de lo que se trata: el
 * bucle no llama a `accept` y espera, pide la conexion siguiente y le avisan
 * cuando hay una.  Lo que se comprueba aqui es que el socket que entrego el
 * sistema operativo acaba en la tabla sin haberle preguntado a nadie de fuera.
 * \~
 */
void test_a_connection_that_arrives_is_taken() {
    Rig r;
    check(r.start(4, 10, 1), "the shard would not start");

    check(r.shard.conns().count() == 0, "there was a connection before any came");

    check(r.io.arrive(11), "the arrival would not fit");
    r.shard.poll(1, 0);

    check(r.shard.conns().count() == 1, "the connection that arrived was not taken");

    /* \~english
     * And it is a connection like any other from here on: bytes for it are
     * read and answered without anybody adopting anything by hand.
     * \~spanish
     * Y a partir de aqui es una conexion como cualquier otra: sus bytes se leen y
     * se contestan sin que nadie adopte nada a mano.
     * \~ */
    r.io.feed(reinterpret_cast<const uint8_t *>("hello"), 5);
    for (int i = 0; i < 8; ++i) r.shard.poll(2, 0);

    check(r.service.seen == 5, "the connection that arrived was never read");
    check(r.io.written_size() == 5, "it was never answered");
}

/**
 * @brief
 * \~english Taking one connection asks for the next.
 * \~spanish Coger una conexion pide la siguiente.
 * \~
 *
 * \~english
 * An accept that is not replaced is a listening socket that has quietly
 * stopped listening, and it is the worst shape of failure there is: the
 * connections the server already had go on being served perfectly, so
 * everything looks healthy, while nothing new ever arrives again.
 *
 * \~spanish
 * Una aceptacion que no se repone es un socket de escucha que ha dejado de
 * escuchar por lo bajo, y es el peor modo de fallo que hay: las conexiones que
 * el servidor ya tenia se siguen sirviendo perfectamente, asi que todo parece
 * sano, mientras no vuelve a llegar ninguna nueva.
 * \~
 */
void test_accepting_asks_for_another() {
    Rig r;
    check(r.start(4, 10, 1), "the shard would not start");

    for (int32_t fd = 11; fd < 16; ++fd) {
        check(r.io.arrive(fd), "the arrival would not fit");
        r.shard.poll(1, 0);
    }

    check(r.shard.conns().count() == 5,
          "the shard stopped accepting after the first");
}

/**
 * @brief
 * \~english A connection that does not fit is closed, not dropped.
 * \~spanish Una conexion que no cabe se cierra, no se suelta.
 * \~
 *
 * \~english
 * A shard at its limit is a state a server is meant to survive -- the pools are
 * sized for it on purpose -- but a socket accepted and then forgotten is a
 * descriptor leaked on every refused connection.  Under load the server runs
 * out of descriptors and stops accepting for good, with no memory missing and
 * nothing to point at.
 *
 * \~spanish
 * Un fragmento en su limite es un estado al que un servidor tiene que sobrevivir
 * -- los pozos estan dimensionados para eso a proposito -- pero un socket
 * aceptado y luego olvidado es un descriptor perdido en cada conexion rechazada.
 * Con trabajo, el servidor se queda sin descriptores y deja de aceptar para
 * siempre, sin que falte memoria y sin nada a lo que senalar.
 * \~
 */
void test_a_connection_that_does_not_fit_is_closed() {
    Rig r;
    check(r.start(4, 10, 1, 2), "the shard would not start");

    for (int32_t fd = 11; fd < 15; ++fd) {
        check(r.io.arrive(fd), "the arrival would not fit");
        r.shard.poll(1, 0);
    }

    /* \~english
     * One more turn, because closing is an operation and not a call: the shard
     * ASKS for the socket to be shut and is told later, exactly like a read.
     * The last refusal's close is still on its way when the arrivals stop.
     * \~spanish
     * Una vuelta mas, porque cerrar es una operacion y no una llamada: el
     * fragmento PIDE que se cierre el socket y se lo dicen despues, igual que una
     * lectura.  El cierre del ultimo rechazo sigue de camino cuando se acaban las
     * llegadas.
     * \~ */
    r.shard.poll(1, 0);

    check(r.shard.conns().count() == 2, "the table took more than it holds");
    check(r.io.closed() == 2,
          "the sockets that did not fit were dropped instead of closed");
}

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
     * **Nothing is out.**  The connection is waiting to be told that there is
     * something, which costs no memory at all -- and this line is R1: a
     * connection that has arrived and said nothing has a record in an array and
     * a socket, and that is all.
     *
     * The first version of this test asserted the opposite, in a body under a
     * name that promised this one: it checked that a connection with a read
     * outstanding held ONE buffer, and explained why that was fine.  It was not
     * fine -- sixteen kilobytes times a million is sixteen gigabytes held to
     * receive nothing -- and the test had been written to agree with the code
     * rather than with the requirement.
     *
     * \~spanish
     * **No hay nada fuera.**  La conexion espera a que le avisen de que hay algo,
     * que no cuesta memoria ninguna -- y esta linea es la R1: una conexion que ha
     * llegado y no ha dicho nada tiene un registro de un array y un socket, y se
     * acabo.
     *
     * La primera version de esta prueba afirmaba lo contrario, en un cuerpo bajo
     * un nombre que prometia esto: comprobaba que una conexion con una lectura
     * pendiente tenia UN buffer, y explicaba por que estaba bien.  No estaba bien
     * -- dieciseis kilobytes por un millon son dieciseis gigabytes guardados para
     * no recibir nada -- y la prueba se habia escrito para darle la razon al
     * codigo en vez de al requisito.
     * \~ */
    check(r.shard.buffers().lent() == 0,
          "a connection that has said nothing is holding a buffer");

    const char *msg = "hello";
    check(r.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    /* \~english
     * Two turns, because the question was asked in two halves: one says there
     * is something, and the one after it goes and gets it.
     * \~spanish
     * Dos vueltas, porque la pregunta se hizo en dos mitades: una dice que hay
     * algo, y la de despues va a por ello.
     * \~ */
    check(r.shard.poll(1, 0) == 1, "nobody was told there was something");
    check(r.shard.poll(1, 0) == 1, "the read did not come back");
    check(r.service.calls == 1, "the service did not see the bytes");
    check(r.service.seen == std::strlen(msg),
          "the service saw the wrong number of bytes");

    /* \~english
     * Now it is answering and waiting to be told, so it holds ONE: the buffer
     * the answer is going out of.  That is the high-water mark of the pool and
     * the number to size it by -- not how many connections talk at once, and
     * not even how many are mid-exchange, but how many ANSWERS are in flight.
     * \~spanish
     * Ahora esta contestando y esperando a que le avisen, asi que tiene UNO: el
     * buffer del que sale la respuesta.  Ese es el pico del pozo y el numero por
     * el que dimensionarlo -- no cuantas conexiones hablan a la vez, y ni siquiera
     * cuantas estan a mitad de intercambio, sino cuantas RESPUESTAS hay en vuelo.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "a connection answering is not holding exactly one buffer");

    check(r.shard.poll(2, 0) == 1, "the write did not come back");
    check(r.io.written_size() == std::strlen(msg), "the answer did not go out");

    /* \~english
     * And it is back to waiting to be told, which is keep-alive: NOTHING.  The
     * high-water mark of the pool is how many connections are mid-exchange, and
     * a kept-alive one between requests is not one of them.
     * \~spanish
     * Y vuelve a esperar a que le avisen, que es mantener viva la conexion:
     * NADA.  El pico del pozo es cuantas conexiones estan a mitad de intercambio,
     * y una mantenida viva entre peticiones no es una de ellas.
     * \~ */
    check(r.shard.buffers().lent() == 0,
          "a connection between requests is holding a buffer");

    r.shard.close(c);

    /* \~english
     * It still does not leave, and the reason is unchanged: something of this
     * connection's is in the operating system's hands -- here the question of
     * whether there is anything to read -- and a connection cannot be let go of
     * while an operation naming it is outstanding.  What changed is that the
     * thing being held is no longer memory.
     * \~spanish
     * Sigue sin irse, y la razon no ha cambiado: algo de esta conexion esta en
     * manos del sistema operativo -- aqui la pregunta de si hay algo que leer --
     * y una conexion no se puede soltar con una operacion que la nombra
     * pendiente.  Lo que ha cambiado es que lo que se tiene ya no es memoria.
     * \~ */
    check(r.service.closed == 0,
          "a connection with something outstanding left straight away");

    r.io.end_of_stream();
    r.shard.poll(3, 0);
    r.shard.poll(4, 0);

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

    const ConnHandle second = r.shard.adopt(8, 0);
    check(second.valid(), "the second connection was not adopted");
    check(r.shard.conns().count() == 2, "the second connection was refused");

    /* \~english
     * Two connections and no buffers at all, because waiting to be told costs
     * none.  The pool being empty is now something that can only happen when
     * there are bytes -- which is what makes a pool smaller than the connection
     * table the design rather than a gamble.
     * \~spanish
     * Dos conexiones y ningun buffer, porque esperar a que te avisen no cuesta
     * ninguno.  Que el pozo este vacio es ahora algo que solo puede pasar cuando
     * hay bytes -- que es lo que hace que un pozo menor que la tabla de conexiones
     * sea el diseno y no una apuesta.
     * \~ */
    check(r.shard.buffers().lent() == 0,
          "connections that have said nothing are holding buffers");

    /* \~english
     * Now there is something, and there is one buffer for two connections.  The
     * first takes it; the second is told there are bytes, finds no buffer, and
     * does not read -- which is not an error anywhere.
     * \~spanish
     * Ahora hay algo, y hay un buffer para dos conexiones.  La primera se lo
     * lleva; a la segunda le avisan de que hay bytes, no encuentra buffer, y no
     * lee -- que no es un error en ningun sitio.
     * \~ */
    const char *msg = "hello";
    check(r.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    r.shard.poll(1, 0);

    check(r.shard.buffers().lent() == 1,
          "the second connection got a buffer that did not exist");

    const http_vx::ConnHot *h = r.shard.conns().hot(second);
    check(h != nullptr && (h->flags & kReadPending) == 0,
          "a connection with no buffer says it is reading");
    check(h != nullptr && h->queue == http_vx::kNoBuffer,
          "a connection with no buffer has an answer queued");

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
 * \~english An expired connection leaves although its peer never says anything again: its read is cancelled.
 * \~spanish Una conexion vencida se va aunque su otro extremo no vuelva a decir nada: su lectura se cancela.
 * \~
 *
 * \~english
 * The read outstanding on a quiet connection is one only the peer would
 * complete.  Closing it has to END that read (OpKind::Cancel) and not wait
 * for it, or a peer gone for good keeps its connection for ever.  Nothing
 * here ends the stream by hand, which is what hid this.
 * \~spanish
 * La lectura pendiente en una conexion callada es una que solo completaria el
 * otro extremo.  Cerrarla tiene que ACABAR esa lectura (OpKind::Cancel) y no
 * esperarla, o un extremo que se fue para siempre conserva su conexion para
 * siempre.  Aqui nada acaba el flujo a mano, que es lo que tapaba esto.
 * \~
 */
void test_an_expired_connection_leaves_without_its_peer() {
    Rig r;
    check(r.start(4, 5), "the shard would not start");

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");
    r.shard.poll(1, 0);

    const http_vx::ConnHot *h = r.shard.conns().hot(c);
    check(h != nullptr && (h->flags & kReadPending) != 0, "a quiet connection is not waiting to be told");

    check(r.shard.expire(6) == 1, "the quiet connection was not closed");
    for (int i = 0; i < 4; ++i) r.shard.poll(7, 0);

    check(r.io.cancelled() == 1, "its outstanding read was not cancelled");
    check(r.shard.conns().count() == 0, "the connection is still in the table");
    check(r.io.closed() == 1, "its socket was not shut");
    check(r.shard.buffers().lent() == 0, "a buffer was kept");
    check(r.shard.counts().uncancelled == 0, "a cancel was refused");
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

        check(r.shard.poll(1, 0) == 1, "nobody was told there was something");
        check(r.shard.poll(1, 0) == 1, "the read did not come back");

        /* \~english
         * And none held afterwards, fifty times over.  What this is looking for
         * is a pool that creeps: one buffer not given back per exchange is a
         * server that works perfectly for an hour.
         * \~spanish
         * Y ninguno guardado despues, cincuenta veces seguidas.  Lo que se busca
         * aqui es un pozo que suba: un buffer sin devolver por intercambio es un
         * servidor que funciona perfectamente durante una hora.
         * \~ */
        check(r.shard.buffers().lent() == 0,
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
    r.shard.poll(1, 0);

    check(r.service.closed == 1, "the connection was not closed");
    check(!r.shard.conns().alive(c), "the connection is still alive");
    check(r.shard.buffers().lent() == 0,
          "a refused connection kept a buffer");
    check(!r.shard.deadlines().armed(c.slot),
          "a closed connection kept its deadline");
}

/**
 * @brief
 * \~english Reading carries on while an answer is still going out.
 * \~spanish Se sigue leyendo mientras una respuesta todavia esta saliendo.
 * \~
 *
 * \~english
 * The two directions of a socket are independent, so a peer that sends its
 * next request while this one is being answered must not be made to wait for
 * an answer it has not asked for yet.  A loop that read only between writes
 * would turn every connection into strict ping-pong -- correct, and slower
 * than the protocol allows for no reason the protocol gives.
 *
 * What there may NOT be two of is reads, or writes: two reads outstanding on
 * a stream socket complete in whatever order the kernel finishes them, so the
 * bytes would arrive with no way to say which came first, and two writes would
 * interleave on the wire.  A stream that can be reordered is not a stream.
 *
 * \~spanish
 * Los dos sentidos de un socket son independientes, asi que a un extremo que
 * manda su peticion siguiente mientras se contesta esta no se le puede hacer
 * esperar por una respuesta que todavia no ha pedido.  Un bucle que solo leyera
 * entre escrituras convertiria cada conexion en un ping-pong estricto --
 * correcto, y mas lento de lo que permite el protocolo sin ninguna razon que de
 * el protocolo.
 *
 * De lo que NO puede haber dos es de lecturas, ni de escrituras: dos lecturas
 * pendientes sobre un socket de flujo acaban en el orden en que las termine el
 * nucleo, asi que los bytes llegarian sin forma de decir cual iba antes, y dos
 * escrituras se entrelazarian en el cable.  Un flujo que se puede desordenar no
 * es un flujo.
 *
 * \~
 */
void test_both_directions_at_once() {
    Rig r;
    check(r.start(8, 10), "the shard would not start");

    /* \~english
     * The kernel takes the answer two bytes at a time, so a write stays
     * outstanding across several completions -- which is what makes room for
     * a read to happen while it is going.
     * \~spanish
     * El nucleo coge la respuesta de dos en dos bytes, asi que una escritura
     * sigue pendiente durante varias finalizaciones -- que es lo que hace sitio
     * para que ocurra una lectura mientras va.
     * \~ */
    r.io.chunk(2);

    const ConnHandle c = r.shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    const char *first = "aaaaaaaa";
    r.io.feed(reinterpret_cast<const uint8_t *>(first), std::strlen(first));
    check(r.shard.poll(1, 0) == 1, "nobody was told there was something");
    check(r.shard.poll(1, 0) == 1, "the first read did not come back");

    const http_vx::ConnHot *h = r.shard.conns().hot(c);
    check(h != nullptr, "the connection is not there");

    /* \~english
     * A write is going AND a read is outstanding, at the same time, on the
     * same connection.  That is the whole point.
     * \~spanish
     * Va una escritura Y hay una lectura pendiente, a la vez, en la misma
     * conexion.  De eso se trata.
     * \~ */
    check(h != nullptr && (h->flags & kWritePending) != 0,
          "the answer is not going out");
    check(h != nullptr && (h->flags & kReadPending) != 0,
          "reading stopped while the answer was going out");

    /* \~english
     * And ONE buffer, not two: the answer is going out of one, and the read
     * that is outstanding is the half that costs nothing -- the connection is
     * waiting to be told there is something, and will take a buffer when there
     * is.  So the pool's high-water mark is one per answer IN FLIGHT rather
     * than two per connection mid-exchange.
     * \~spanish
     * Y UN buffer, no dos: la respuesta sale de uno, y la lectura pendiente es la
     * mitad que no cuesta nada -- la conexion espera a que le avisen de que hay
     * algo, y cogera buffer cuando lo haya --.  Asi que el pico del pozo es uno
     * por respuesta EN VUELO y no dos por conexion a mitad de intercambio.
     * \~ */
    check(r.shard.buffers().lent() == 1,
          "a connection answering and waiting is not holding one buffer");

    /* \~english
     * The peer sends again while the first answer is still going out.  The
     * second answer cannot be sent yet -- two writes would interleave -- so it
     * waits in the queue instead of holding up the read that made it.
     * \~spanish
     * El otro extremo manda otra vez mientras la primera respuesta sigue
     * saliendo.  La segunda no se puede mandar todavia -- dos escrituras se
     * entrelazarian -- asi que espera en la cola en vez de retener la lectura
     * que la hizo.
     * \~ */
    const char *second = "bb";
    r.io.feed(reinterpret_cast<const uint8_t *>(second), std::strlen(second));

    for (int i = 0; i < 3; ++i) r.shard.poll(2, 0);

    check(r.service.calls >= 2, "the second request was not read");

    /* \~english
     * And it all comes out, in order: the first answer whole, then the second.
     * A response that overtook the one before it would be the answer to the
     * wrong request.
     * \~spanish
     * Y sale todo, en orden: la primera respuesta entera y luego la segunda.
     * Una respuesta que adelantara a la anterior seria la respuesta a la
     * peticion equivocada.
     * \~ */
    for (int i = 0; i < 40; ++i) r.shard.poll(3, 0);

    const size_t total = std::strlen(first) + std::strlen(second);
    check(r.io.written_size() == total, "not everything went out");
    check(std::memcmp(r.io.written(), first, std::strlen(first)) == 0,
          "the first answer is not what went out first");
    check(std::memcmp(r.io.written() + std::strlen(first), second,
                      std::strlen(second)) == 0,
          "the second answer did not follow the first");
}

/**
 * @brief
 * \~english What a read leaves behind is there when the rest lands.
 * \~spanish Lo que deja una lectura esta ahi cuando cae el resto.
 * \~
 *
 * \~english
 * A request arrives in as many reads as the network feels like, and a head
 * split across two packets is the ordinary case rather than a corner.  So a
 * service that has only half of one consumes nothing, and what it left has to
 * be waiting in the same buffer when the rest arrives after it.
 *
 * A loop that released the buffer here would make every request that came in
 * pieces unparseable -- which is most of the large ones, and none of the ones
 * a test sends in a single write.
 *
 * \~spanish
 * Una peticion llega en tantas lecturas como le apetezca a la red, y una cabeza
 * partida entre dos paquetes es el caso corriente y no una esquina.  Asi que un
 * servicio que solo tiene la mitad no consume nada, y lo que dejo tiene que
 * estar esperando en el mismo buffer cuando llegue el resto detras.
 *
 * Un bucle que soltara el buffer aqui haria ilegible toda peticion que llegara
 * a trozos -- que son casi todas las grandes, y ninguna de las que manda una
 * prueba en una sola escritura.
 *
 * \~
 */
void test_half_a_message_waits_for_the_rest() {
    /**
     * \~english
     * A service that answers only once it has seen a full stop, and consumes
     * nothing until then.  That is what a protocol does: it cannot act on half
     * a head, and it must not throw the half away.
     * \~spanish
     * Un servicio que solo contesta cuando ha visto un punto, y hasta entonces
     * no consume nada.  Eso es lo que hace un protocolo: no puede actuar sobre
     * media cabeza, y no puede tirar la mitad.
     * \~
     */
    class UntilStop final : public Service {
      public:
        bool on_bytes(ConnHandle c, Buffer &in, Buffer &out) noexcept override {
            (void)c;
            ++calls;

            size_t end = 0;
            while (end < in.size() && in.data()[end] != '.') ++end;

            if (end == in.size()) return true;

            ++messages;
            const size_t whole = end + 1;

            uint8_t *room = out.reserve(whole);
            if (room == nullptr) return false;
            std::memcpy(room, in.data(), whole);
            out.commit(whole);
            in.consume(whole);
            return true;
        }

        int calls = 0;
        int messages = 0;
    };

    UntilStop service;
    Shard shard;
    MemoryBackend io(shard.buffers());

    ShardConfig cfg;
    cfg.connections = 4;
    cfg.buffers = 4;
    cfg.idle_ticks = 10;
    cfg.wheel_slots = 64;
    check(shard.reset(cfg, io, service, 0), "the shard would not start");

    const ConnHandle c = shard.adopt(7, 0);
    check(c.valid(), "the connection was not adopted");

    /* \~english
     * The first half.  Nothing is consumed and nothing is answered, and the
     * buffer stays with the connection.
     * \~spanish
     * La primera mitad.  No se consume nada ni se contesta nada, y el buffer se
     * queda con la conexion.
     * \~ */
    const char *first = "GET /some";
    io.feed(reinterpret_cast<const uint8_t *>(first), std::strlen(first));
    check(shard.poll(1, 0) == 1, "nobody was told there was something");
    check(shard.poll(1, 0) == 1, "the first read did not come back");

    check(service.calls == 1, "the service was not asked");
    check(service.messages == 0, "half a message was answered");
    check(io.written_size() == 0, "half a message produced an answer");

    /* \~english
     * One buffer, still.  It is the same one -- the next read was submitted
     * into it rather than into a fresh one -- and that cannot be read off a
     * field afterwards, because submitting the read hands it back to the
     * operating system.  What says it is the count: a shard that had thrown
     * the half away and taken a new buffer would show one here too, and would
     * then fail to put the message back together below.
     * \~spanish
     * Un buffer, todavia.  Es el mismo -- la lectura siguiente se entrego sobre
     * el y no sobre uno nuevo -- y eso no se puede leer de un campo despues,
     * porque entregar la lectura se lo devuelve al sistema operativo.  Lo que lo
     * dice es la cuenta: un fragmento que hubiera tirado la mitad y cogido un
     * buffer nuevo tambien ensenaria uno aqui, y luego no sabria recomponer el
     * mensaje mas abajo.
     * \~ */
    check(shard.buffers().lent() == 1,
          "a connection holding half a message is not holding one buffer");

    /* \~english
     * The rest.  It has to land AFTER what was already there, in the same
     * buffer, or the service sees a message that never arrived.
     * \~spanish
     * El resto.  Tiene que caer DETRAS de lo que ya habia, en el mismo buffer, o
     * el servicio ve un mensaje que no llego nunca.
     * \~ */
    const char *rest = "thing.";
    io.feed(reinterpret_cast<const uint8_t *>(rest), std::strlen(rest));
    check(shard.poll(2, 0) == 1, "the second read did not come back");

    check(service.messages == 1, "the whole message was not put back together");

    for (int i = 0; i < 4; ++i) shard.poll(3, 0);

    const char *whole = "GET /something.";
    check(io.written_size() == std::strlen(whole),
          "the answer is not the whole message");
    check(std::memcmp(io.written(), whole, std::strlen(whole)) == 0,
          "the message was not put back together in order");

    /* \~english
     * And with nothing left over there is NOTHING out: the connection is back
     * to waiting to be told, which is where a kept-alive connection spends
     * almost all of its life and where it costs nothing.
     * \~spanish
     * Y sin nada que sobre no hay NADA fuera: la conexion vuelve a esperar a que
     * le avisen, que es donde pasa casi toda su vida una conexion mantenida viva
     * y donde no cuesta nada.
     * \~ */
    check(shard.buffers().lent() == 0,
          "a connection between messages is holding a buffer");
}

} // namespace

int main() {
    test_a_connection_that_arrives_is_taken();
    test_accepting_asks_for_another();
    test_a_connection_that_does_not_fit_is_closed();
    test_half_a_message_waits_for_the_rest();
    test_both_directions_at_once();
    test_an_idle_connection_holds_no_buffer();
    test_activity_pushes_the_deadline();
    test_a_connection_without_a_buffer_still_expires();
    test_an_expired_connection_leaves_without_its_peer();
    test_answering_nothing_keeps_the_pool_whole();
    test_a_service_can_end_it();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
