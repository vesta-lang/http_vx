/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard.cpp
 * @brief
 * \~english Driving one thread's connections, in both directions at once.
 * \~spanish Mover las conexiones de un hilo, en los dos sentidos a la vez.
 * \~
 */

#include "http_vx/shard.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {

Service::~Service() = default;

namespace {

/// \~english Whether the operating system is holding anything of @p h.
/// \~spanish Si el sistema operativo tiene algo de @p h.  \~
bool busy(const ConnHot &h) noexcept {
    return (h.flags & (kReadPending | kWritePending)) != 0;
}

bool closing(const ConnHot &h) noexcept { return (h.flags & kClosing) != 0; }

} // namespace

bool Shard::reset(const ShardConfig &cfg, Backend &io, Service &service,
                  uint64_t now) noexcept {
    release();

    cfg_ = cfg;
    io_ = &io;
    service_ = &service;

    if (!conns_.reset(cfg.connections)) return false;
    if (!pool_.reset(cfg.buffers, cfg.buffer_ceiling)) return false;
    if (!wheel_.reset(cfg.connections, cfg.wheel_slots, now)) return false;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    queue_next_ = static_cast<uint32_t *>(
        util::host_alloc(static_cast<size_t>(cfg.buffers) * sizeof(uint32_t)));
    if (queue_next_ == nullptr) return false;

    for (uint32_t i = 0; i < cfg.buffers; ++i) queue_next_[i] = kNoBuffer;

    /* \~english
     * A deadline that does not fit the wheel is refused when it is armed, so
     * it is checked here instead -- where it is a configuration that cannot
     * work rather than a connection that quietly never times out.
     * \~spanish
     * Un plazo que no cabe en la rueda se rechaza al armarlo, asi que se
     * comprueba aqui -- donde es una configuracion que no puede funcionar y no
     * una conexion que por lo bajo no vence nunca.
     * \~ */
    if (cfg.idle_ticks == 0 || cfg.idle_ticks > wheel_.horizon()) return false;

    /* \~english
     * And the accepts are posted, which is what makes a shard start listening.
     * They go LAST, after everything a connection will need exists: an accept
     * posted before the connection table is made could be completed by the
     * operating system before this function returns, and the answer to a
     * connection arriving is not allowed to be "in a moment".
     * \~spanish
     * Y se ponen las aceptaciones, que es lo que hace que un fragmento empiece a
     * escuchar.  Van AL FINAL, cuando ya existe todo lo que va a necesitar una
     * conexion: una aceptacion puesta antes de hacer la tabla de conexiones
     * podria acabarla el sistema operativo antes de que volviera esta funcion, y
     * la respuesta a una conexion que llega no puede ser "un momento".
     * \~ */
    for (uint32_t i = 0; i < cfg_.accepts; ++i) want_accept();

    return true;
}

void Shard::want_accept() noexcept {
    if (io_ == nullptr) return;

    Op op;
    op.kind = OpKind::Accept;
    op.buffer = kNoBuffer;

    /* \~english
     * A submission that is refused is the queue being full, and the accept is
     * NOT retried here.  It will be posted again by the next accept that
     * completes, and if there is no such accept then this shard never accepted
     * anything -- which is a configuration that could not work and shows up as
     * a port nobody answers on, rather than as a loop spinning on a full queue.
     * \~spanish
     * Una entrega rechazada es la cola llena, y la aceptacion NO se reintenta
     * aqui.  La volvera a poner la aceptacion siguiente que acabe, y si no hay
     * ninguna es que este fragmento no acepto nada nunca -- que es una
     * configuracion que no podia funcionar y se ve como un puerto en el que no
     * contesta nadie, en vez de como un bucle dando vueltas sobre una cola llena.
     * \~ */
    io_->submit(op);
}

void Shard::on_accept(const Completion &done, uint64_t now) noexcept {
    want_accept();

    if (!done.ok() || done.fd < 0) return;

    /* \~english
     * A socket that does not fit is closed, and closing it is the whole point
     * of doing this here.  The shard is full -- which is what R1 and the pools
     * are sized for, and is a state a server is meant to survive -- but a
     * socket that was accepted and then dropped is a descriptor leaked on every
     * refused connection.  A server under load would run out of descriptors and
     * stop accepting for good, with no memory missing and nothing to point at.
     *
     * \~spanish
     * Un socket que no cabe se cierra, y cerrarlo es para lo que esta esto aqui.
     * El fragmento esta lleno -- que es para lo que estan dimensionados la R1 y
     * los pozos, y es un estado al que un servidor tiene que sobrevivir -- pero
     * un socket aceptado y luego soltado es un descriptor perdido en cada
     * conexion rechazada.  Un servidor con trabajo se quedaria sin descriptores y
     * dejaria de aceptar para siempre, sin que falte memoria y sin nada a lo que
     * senalar.
     * \~ */
    const ConnHandle c = adopt(done.fd, now);
    if (c.valid()) return;

    Op shut;
    shut.kind = OpKind::Close;
    shut.buffer = kNoBuffer;
    shut.fd = done.fd;
    io_->submit(shut);
}

void Shard::release() noexcept {
    if (queue_next_ != nullptr) {
        util::host_free(queue_next_);
        queue_next_ = nullptr;
    }

    conns_.release();
    pool_.release_all();
    wheel_.release();
    io_ = nullptr;
    service_ = nullptr;
}

void Shard::drop_queue(ConnHot &h) noexcept {
    /* \~english
     * Half a message goes back too.  It is this shard's buffer -- the read
     * that filled it came back -- and a connection that is ending will never
     * see the rest of what it was holding.
     * \~spanish
     * Medio mensaje vuelve tambien.  Es un buffer de este fragmento -- la
     * lectura que lo lleno ya volvio -- y una conexion que se esta acabando no
     * va a ver nunca el resto de lo que guardaba.
     * \~ */
    if (h.reading != kNoBuffer) {
        pool_.release(h.reading);
        h.reading = kNoBuffer;
    }

    while (h.queue != kNoBuffer) {
        const uint32_t next = queue_next_[h.queue];
        queue_next_[h.queue] = kNoBuffer;
        pool_.release(h.queue);
        h.queue = next;
    }
    h.queued = 0;
}

void Shard::let_go(ConnHandle c, ConnHot &h) noexcept {
    drop_queue(h);
    wheel_.cancel(c.slot);
    service_->on_close(c);

    /* \~english
     * And the socket is shut.  It is asked for as an operation and not done
     * here, because on a completion interface closing has to be ORDERED with
     * the rest: a socket closed while a read is still in the kernel is asking
     * about memory the kernel is about to write to.  What makes it safe at this
     * point is that @c leave_if_done let it get here, and that check is
     * precisely "nothing outstanding".
     *
     * It goes before the slot is given back, because the slot is where the
     * socket's number lives -- and a table that had already forgotten it would
     * leave nothing to close.  That is how this was missing: with a backend
     * that has no operating system in it there is no socket to leak, so a shard
     * that never closed one passed every test there was.
     *
     * \~spanish
     * Y el socket se cierra.  Se pide como operacion y no se hace aqui porque en
     * una interfaz por finalizacion cerrar tiene que ORDENARSE con lo demas: un
     * socket cerrado con una lectura todavia en el nucleo es preguntar por una
     * memoria en la que el nucleo esta a punto de escribir.  Lo que lo hace seguro
     * en este punto es que @c leave_if_done dejo llegar hasta aqui, y esa
     * comprobacion es justamente "no queda nada pendiente".
     *
     * Va antes de devolver la casilla, porque la casilla es donde vive el numero
     * del socket -- y una tabla que ya lo hubiera olvidado no dejaria nada que
     * cerrar --.  Asi es como faltaba esto: con un backend sin ningun sistema
     * operativo dentro no hay ningun socket que perder, asi que un fragmento que
     * no cerrara ninguno pasaba todas las pruebas que habia.
     * \~ */
    if (io_ != nullptr && h.fd >= 0) {
        Op shut;
        shut.conn = c;
        shut.kind = OpKind::Close;
        shut.buffer = kNoBuffer;
        shut.fd = h.fd;
        io_->submit(shut);
    }

    conns_.close(c);
}

bool Shard::leave_if_done(ConnHandle c, ConnHot &h) noexcept {
    /* \~english
     * Nothing outstanding AND nothing left to say.  The second half is what
     * makes closing graceful: a connection that has been told to end still
     * owes whatever answers were already written, and going before they are
     * out is the same as not having written them.
     * \~spanish
     * Nada pendiente Y nada que decir.  La segunda mitad es lo que hace que
     * cerrar sea con cortesia: una conexion a la que se le ha dicho que se acabe
     * sigue debiendo las respuestas que ya estaban escritas, e irse antes de que
     * salgan es lo mismo que no haberlas escrito.
     * \~ */
    if (!closing(h) || busy(h) || h.queue != kNoBuffer) return false;
    let_go(c, h);
    return true;
}

void Shard::want_read(ConnHandle c, ConnHot &h) noexcept {
    if ((h.flags & kReadPending) != 0 || closing(h)) return;

    /* \~english
     * A connection with answers piling up is not read from.  That is flow
     * control and not a limit: a peer sending faster than it reads is making
     * this server hold its output, and the answer is to stop taking more in.
     * The bytes wait in the kernel's receive queue, which is where they
     * belong.
     * \~spanish
     * De una conexion con respuestas amontonandose no se lee.  Eso es control de
     * flujo y no un limite: un extremo que manda mas deprisa de lo que lee esta
     * haciendo que este servidor le guarde su salida, y la respuesta es dejar de
     * aceptar mas.  Los bytes esperan en la cola de recepcion del nucleo, que es
     * donde les toca.
     * \~ */
    if (h.queued >= cfg_.max_queued) return;

    /* \~english
     * Half a message from the last read goes back into the SAME buffer, so
     * the rest lands right after it.  Only a connection between messages takes
     * a fresh one -- which is also when it had none, because a connection that
     * finished a message gave its buffer back.
     * \~spanish
     * Medio mensaje de la lectura anterior vuelve al MISMO buffer, para que el
     * resto caiga justo detras.  Solo una conexion entre mensajes coge uno
     * nuevo -- que es ademas cuando no tenia ninguno, porque una conexion que
     * acabo un mensaje devolvio su buffer.
     * \~ */
    uint32_t b = h.reading;

    /* \~english
     * The buffer is taken HERE, when there is a reason to read, and not when
     * the connection arrived.  That is R1.  Not getting one is not a failure
     * either: the connection does not read this time round, its deadline is
     * still armed, and TCP slows the peer down by itself.
     * \~spanish
     * El buffer se coge AQUI, cuando hay razon para leer, y no cuando llego la
     * conexion.  Eso es la R1.  Y que no haya tampoco es un fallo: la conexion
     * no lee esta vuelta, su plazo sigue armado, y TCP frena al otro extremo el
     * solo.
     * \~ */
    if (b == kNoBuffer) {
        b = pool_.acquire();
        if (b == kNoBuffer) return;

        /* \~english
         * And it is told where in the connection it is starting.  A buffer
         * comes out of the pool having forgotten everything, which is right for
         * a new connection and wrong for this one: the connection may be
         * thousands of bytes in, and a reader that kept a position measured
         * from the start of it would find that position sitting before a buffer
         * that thinks it begins at zero.
         *
         * Nothing would report that.  The reader would simply be told its bytes
         * are not here, for ever, and what anybody could see is a connection
         * that stops moving with nothing wrong in any frame -- the one failure
         * that R1 buys and that has to be paid for right here, because this is
         * the only place that knows both that a buffer is fresh and how far the
         * connection has come.
         *
         * \~spanish
         * Y se le dice por donde de la conexion empieza.  Un buffer sale del pozo
         * habiendolo olvidado todo, que esta bien para una conexion nueva y mal
         * para esta: la conexion puede llevar miles de bytes, y un lector que
         * guardara una posicion medida desde su principio se encontraria esa
         * posicion por detras de un buffer que cree empezar en cero.
         *
         * Eso no lo diria nadie.  Al lector se le contestaria simplemente que sus
         * bytes no estan, para siempre, y lo que se veria desde fuera es una
         * conexion que deja de avanzar sin que haya nada mal en ninguna trama --
         * el unico fallo que compra la R1, y que hay que pagar justo aqui, porque
         * este es el unico sitio que sabe a la vez que un buffer viene limpio y
         * cuanto lleva andado la conexion.
         * \~ */
        Buffer *fresh = pool_.at(b);
        const ConnCold *cold = conns_.cold(c);
        if (fresh != nullptr && cold != nullptr) fresh->rebase(cold->bytes_in);
    }

    Op op;
    op.conn = c;
    op.kind = OpKind::Recv;
    op.buffer = b;
    op.offset = 0;
    op.length = cfg_.read_size;
    op.fd = h.fd;

    if (!io_->submit(op)) {
        /* \~english
         * Only a buffer taken just now is given back.  One that was already
         * holding half a message is kept, because giving it back would throw
         * away a message that had started arriving -- and the connection would
         * then read the REST of it as the beginning of another.
         * \~spanish
         * Solo se devuelve un buffer cogido ahora mismo.  Uno que ya tenia medio
         * mensaje se queda, porque devolverlo tiraria un mensaje que habia
         * empezado a llegar -- y la conexion leeria despues el RESTO como el
         * principio de otro.
         * \~ */
        if (h.reading == kNoBuffer) pool_.release(b);
        return;
    }

    h.reading = kNoBuffer;
    h.flags |= kReadPending;
}

bool Shard::want_write(ConnHandle c, ConnHot &h, uint32_t buf) noexcept {
    /* \~english
     * Straight out when nothing is going and nothing is waiting.  Otherwise
     * it goes to the BACK of the queue -- answers leave in the order they were
     * made, which is not a nicety: a response that overtook the one before it
     * would be a response to the wrong request.
     * \~spanish
     * Sale directa cuando no va nada ni espera nada.  Si no, va al FINAL de la
     * cola -- las respuestas salen en el orden en que se hicieron, y eso no es
     * un detalle: una respuesta que adelantara a la anterior seria la respuesta
     * a la peticion equivocada.
     * \~ */
    if ((h.flags & kWritePending) == 0 && h.queue == kNoBuffer) {
        Buffer *out = pool_.at(buf);
        if (out == nullptr) return false;

        Op op;
        op.conn = c;
        op.kind = OpKind::Send;
        op.buffer = buf;
        op.offset = 0;
        op.length = static_cast<uint32_t>(out->size());
        op.fd = h.fd;

        if (!io_->submit(op)) return false;

        h.flags |= kWritePending;
        return true;
    }

    queue_next_[buf] = kNoBuffer;

    if (h.queue == kNoBuffer) {
        h.queue = buf;
    } else {
        uint32_t at = h.queue;
        while (queue_next_[at] != kNoBuffer) at = queue_next_[at];
        queue_next_[at] = buf;
    }

    ++h.queued;
    return true;
}

void Shard::send_next(ConnHandle c, ConnHot &h) noexcept {
    if ((h.flags & kWritePending) != 0 || h.queue == kNoBuffer) return;

    const uint32_t buf = h.queue;
    h.queue = queue_next_[buf];
    queue_next_[buf] = kNoBuffer;
    if (h.queued != 0) --h.queued;

    Buffer *out = pool_.at(buf);
    if (out == nullptr) {
        pool_.release(buf);
        return;
    }

    Op op;
    op.conn = c;
    op.kind = OpKind::Send;
    op.buffer = buf;
    op.offset = 0;
    op.length = static_cast<uint32_t>(out->size());
    op.fd = h.fd;

    if (!io_->submit(op)) {
        pool_.release(buf);
        return;
    }

    h.flags |= kWritePending;
}

ConnHandle Shard::adopt(int32_t fd, uint64_t now) noexcept {
    (void)now;

    const ConnHandle c = conns_.open(fd, now);
    if (!c.valid()) return c;

    ConnHot *h = conns_.hot(c);
    h->queue = kNoBuffer;
    h->queued = 0;
    h->flags = 0;

    /* \~english
     * The deadline is armed by the SLOT and not by the handle, and that is
     * safe because arming a slot that is already armed replaces what was
     * there.  Where the two must not be confused is when a deadline FIRES, and
     * there the index is turned back into a handle by asking the table.
     * \~spanish
     * El plazo se arma por la CASILLA y no por la referencia, y es seguro porque
     * armar una casilla ya armada sustituye lo que hubiera.  Donde no se pueden
     * confundir es cuando un plazo VENCE, y ahi el indice se convierte otra vez
     * en referencia preguntandole a la tabla.
     * \~ */
    wheel_.arm(c.slot, cfg_.idle_ticks);

    service_->on_open(c);
    want_read(c, *h);
    return c;
}

void Shard::close(ConnHandle c) noexcept {
    ConnHot *h = conns_.hot(c);
    if (h == nullptr) return;

    h->flags |= kClosing;

    /* \~english
     * **What is already written still goes out.**  Closing is not the same as
     * throwing away, and the difference is the whole of how a client finds out
     * what happened: a refusal that is decided and then dropped leaves a
     * client whose socket simply died, and a client that cannot tell a bad
     * request from a fallen-over server retries -- so a request refused every
     * time becomes a request sent every time.
     *
     * So this stops the reading and lets the writing finish.  The connection
     * goes when there is nothing left of it in either place, which
     * @c leave_if_done decides.
     *
     * \~spanish
     * **Lo que ya esta escrito sale igual.**  Cerrar no es lo mismo que tirar,
     * y la diferencia es todo lo que le permite a un cliente enterarse de lo que
     * paso: un rechazo que se decide y luego se tira deja a un cliente cuyo
     * socket se murio sin mas, y un cliente que no puede distinguir una peticion
     * mala de un servidor caido reintenta -- asi que una peticion rechazada
     * siempre se convierte en una peticion mandada siempre.
     *
     * Asi que esto para la lectura y deja que acabe la escritura.  La conexion
     * se va cuando no quede nada de ella en ninguno de los dos sitios, que es lo
     * que decide @c leave_if_done.
     * \~ */
    if (h->reading != kNoBuffer) {
        pool_.release(h->reading);
        h->reading = kNoBuffer;
    }

    send_next(c, *h);
    leave_if_done(c, *h);
}

void Shard::on_read(const Completion &done) noexcept {
    ConnHot *h = conns_.hot(done.conn);

    /* \~english
     * A completion for a connection that is no longer this one.  With the
     * closing rule it should not happen, so reaching here means something
     * released a slot it did not own -- and the buffer is given back anyway,
     * because a pool that leaked one per occurrence would end up empty and the
     * server would stop reading, which is a symptom nobody could trace back to
     * here.
     * \~spanish
     * Una finalizacion de una conexion que ya no es esta.  Con la regla de
     * cierre no deberia pasar, asi que llegar aqui quiere decir que algo solto
     * una casilla que no era suya -- y el buffer se devuelve igual, porque un
     * pozo que perdiera uno por vez acabaria vacio y el servidor dejaria de
     * leer, que es un sintoma que nadie podria rastrear hasta aqui.
     * \~ */
    if (h == nullptr) {
        if (done.buffer != kNoBuffer) pool_.release(done.buffer);
        return;
    }

    h->flags &= static_cast<uint16_t>(~kReadPending);

    if (closing(*h)) {
        pool_.release(done.buffer);
        leave_if_done(done.conn, *h);
        return;
    }

    /* \~english
     * A failure or the peer closing its end.  Neither is an error worth
     * telling anybody about -- one is the network and the other is a client
     * that has finished -- and what they have in common is that there is
     * nothing more to read.  What is already queued still goes out, which is
     * why this closes rather than letting go: a client that sent its last
     * request and shut its sending half is owed the answer.
     * \~spanish
     * Un fallo o el otro extremo cerrando su lado.  Ninguno es un error del que
     * contarle nada a nadie -- uno es la red y el otro un cliente que ha acabado
     * -- y lo que tienen en comun es que ya no hay nada mas que leer.  Lo que ya
     * este encolado sale igual, que es la razon de que esto cierre en vez de
     * soltar: a un cliente que mando su ultima peticion y cerro su mitad de
     * enviar se le debe la respuesta.
     * \~ */
    if (!done.ok() || done.eof()) {
        pool_.release(done.buffer);
        close(done.conn);
        return;
    }

    Buffer *in = pool_.at(done.buffer);
    if (in == nullptr) {
        close(done.conn);
        return;
    }

    /* \~english
     * Activity pushes the deadline out, and this is the most frequent thing
     * the loop does -- which is why the wheel was built so that doing it is an
     * unlink and a push rather than a search.
     * \~spanish
     * La actividad empuja el plazo mas lejos, y es lo que mas veces hace el
     * bucle -- que es la razon de que la rueda se hiciera para que hacerlo sea
     * un desenlace y un meter en una lista, y no una busqueda.
     * \~ */
    wheel_.arm(done.conn.slot, cfg_.idle_ticks);

    ConnCold *cold = conns_.cold(done.conn);
    if (cold != nullptr) cold->bytes_in += static_cast<uint64_t>(done.result);

    /* \~english
     * A second buffer for the answer, so a connection mid-exchange holds two.
     * Not getting one closes the connection rather than holding the request:
     * keeping it would mean a request that is never answered and a peer that
     * waits until its own timeout, which is a worse way to be told the same
     * thing.
     * \~spanish
     * Un segundo buffer para la respuesta, asi que una conexion a mitad de
     * intercambio tiene dos.  No conseguirlo cierra la conexion en vez de
     * retener la peticion: quedarsela seria una peticion que no se contesta
     * nunca y un extremo que espera hasta su propio plazo, que es una forma peor
     * de que le digan lo mismo.
     * \~ */
    const uint32_t wb = pool_.acquire();
    if (wb == kNoBuffer) {
        pool_.release(done.buffer);
        close(done.conn);
        return;
    }

    Buffer *out = pool_.at(wb);
    const bool keep = service_->on_bytes(done.conn, *in, *out);

    /* \~english
     * **The read buffer goes back only if the service emptied it.**  What is
     * left is half a message, and it has to be there when the rest lands after
     * it -- so the buffer stays with the connection and the next read appends
     * to the same one.
     *
     * That is not a hole in R1, it is what R1 says: a connection mid-message
     * holds a buffer with every right, and a connection between messages does
     * not.  A shard that released it here would make every request that
     * arrived in two packets unparseable, which is most of the large ones.
     *
     * \~spanish
     * **El buffer de lectura vuelve solo si el servicio lo vacio.**  Lo que
     * queda es medio mensaje, y tiene que estar ahi cuando caiga detras el resto
     * -- asi que el buffer se queda con la conexion y la lectura siguiente anade
     * al mismo.
     *
     * Eso no es un agujero en la R1, es lo que dice la R1: una conexion a mitad
     * de mensaje tiene un buffer con todo el derecho, y una entre mensajes no.
     * Un fragmento que lo soltara aqui haria ilegible toda peticion que llegara
     * en dos paquetes, que son casi todas las grandes.
     * \~ */
    const bool empty = out->empty();
    h->reading = in->empty() ? kNoBuffer : done.buffer;

    if (h->reading == kNoBuffer) pool_.release(done.buffer);

    /* \~english
     * The answer goes out BEFORE the connection is ended, whether or not the
     * service wants to carry on.  A service that refuses a request has usually
     * written the refusal, and throwing it away here is the difference between
     * a client that is told why and a client whose socket simply died.
     * \~spanish
     * La respuesta sale ANTES de acabar la conexion, quiera seguir el servicio o
     * no.  Un servicio que rechaza una peticion normalmente ha escrito el
     * rechazo, y tirarlo aqui es la diferencia entre un cliente al que se le
     * dice por que y uno cuyo socket se murio sin mas.
     * \~ */
    if (empty) {
        pool_.release(wb);
    } else if (!want_write(done.conn, *h, wb)) {
        pool_.release(wb);
        close(done.conn);
        return;
    }

    if (!keep) {
        close(done.conn);
        return;
    }

    /* \~english
     * And straight back to reading, WITHOUT waiting for the answer to go out.
     * That is the whole of what having two directions buys: a peer sending its
     * next request while this one is being answered is not made to wait for
     * the answer it has not asked for yet.
     * \~spanish
     * Y de vuelta a leer, SIN esperar a que salga la respuesta.  Eso es todo lo
     * que compra tener dos sentidos: a un extremo que manda su peticion
     * siguiente mientras se contesta esta no se le hace esperar por una respuesta
     * que todavia no ha pedido.
     * \~ */
    want_read(done.conn, *h);
}

void Shard::on_write(const Completion &done) noexcept {
    ConnHot *h = conns_.hot(done.conn);
    if (h == nullptr) {
        if (done.buffer != kNoBuffer) pool_.release(done.buffer);
        return;
    }

    h->flags &= static_cast<uint16_t>(~kWritePending);

    Buffer *out = pool_.at(done.buffer);

    /* \~english
     * A write that failed means nothing more can go out, so the rest is
     * dropped rather than tried.  It is the one place the queue is thrown
     * away, and it is the honest one: the socket is gone, and pretending
     * otherwise would be a connection that keeps submitting writes nobody can
     * receive.
     * \~spanish
     * Una escritura que fallo quiere decir que ya no puede salir nada, asi que
     * el resto se tira en vez de intentarlo.  Es el unico sitio donde se tira la
     * cola, y es el honesto: el socket se fue, y fingir otra cosa seria una
     * conexion entregando escrituras que no puede recibir nadie.
     * \~ */
    if (!done.ok() || out == nullptr) {
        pool_.release(done.buffer);
        drop_queue(*h);
        close(done.conn);
        return;
    }

    ConnCold *cold = conns_.cold(done.conn);
    if (cold != nullptr) cold->bytes_out += static_cast<uint64_t>(done.result);

    /* \~english
     * What went out is consumed, so what is left is simply what is still in
     * the buffer.  Remembering how far a response had got would be a number
     * beside the buffer that says what the buffer already knows, and two of
     * those disagree.
     *
     * Consuming here is safe because the operation has COME BACK: the buffer
     * stopped being the kernel's the moment this completion arrived.
     *
     * \~spanish
     * Lo que salio se consume, asi que lo que queda es lo que sigue en el
     * buffer.  Acordarse de por donde iba una respuesta seria un numero al lado
     * del buffer que dice lo que el buffer ya sabe, y dos de esos discrepan.
     *
     * Consumir aqui es seguro porque la operacion ha VUELTO: el buffer dejo de
     * ser del nucleo en el momento en que llego esta finalizacion.
     * \~ */
    out->consume(static_cast<size_t>(done.result));

    /* \~english
     * A write that moved NOTHING while there is still something to move is not
     * progress, and submitting the rest would ask again for exactly what was
     * just refused -- for ever.  A backend should report that as a failure and
     * this one is the loop not taking a backend's word for it: backends are
     * pluggable, and a loop that spins on a badly behaved one is a server that
     * stops answering while using a whole core.
     *
     * \~spanish
     * Una escritura que no movio NADA cuando todavia queda algo que mover no es
     * avance, y entregar el resto seria pedir otra vez exactamente lo que
     * acaban de rechazar -- para siempre.  Un backend deberia decir que eso es
     * un fallo, y esto es el bucle no fiandose de su palabra: los backends son
     * enchufables, y un bucle que da vueltas con uno que se porta mal es un
     * servidor que deja de contestar gastando un nucleo entero.
     * \~ */
    if (done.result == 0 && !out->empty()) {
        pool_.release(done.buffer);
        drop_queue(*h);
        close(done.conn);
        return;
    }

    if (!out->empty()) {
        Op op;
        op.conn = done.conn;
        op.kind = OpKind::Send;
        op.buffer = done.buffer;
        op.offset = 0;
        op.length = static_cast<uint32_t>(out->size());
        op.fd = h->fd;

        if (!io_->submit(op)) {
            pool_.release(done.buffer);
            close(done.conn);
            return;
        }

        h->flags |= kWritePending;
        return;
    }

    pool_.release(done.buffer);

    /* \~english
     * The next answer goes out, and reading starts again -- room in the queue
     * has just appeared, so a connection that was being held back for sending
     * faster than it reads is let go of here.  Both refuse by themselves on a
     * connection that is ending, which is what lets one path serve the
     * ordinary case and the graceful close.
     * \~spanish
     * Sale la respuesta siguiente, y se vuelve a leer -- acaba de aparecer sitio
     * en la cola, asi que una conexion a la que se estaba frenando por mandar
     * mas deprisa de lo que lee se suelta aqui.  Las dos se niegan solas en una
     * conexion que se esta acabando, que es lo que permite que un mismo camino
     * sirva al caso corriente y al cierre con cortesia.
     * \~ */
    send_next(done.conn, *h);

    if (closing(*h)) {
        leave_if_done(done.conn, *h);
        return;
    }

    wheel_.arm(done.conn.slot, cfg_.idle_ticks);
    want_read(done.conn, *h);
}

size_t Shard::poll(uint64_t now, int timeout_ms) noexcept {
    if (io_ == nullptr) return 0;

    Completion done[64];
    size_t cap = cfg_.batch;
    if (cap > 64) cap = 64;

    const size_t made = io_->wait(done, cap, timeout_ms);

    for (size_t i = 0; i < made; ++i) {
        switch (done[i].kind) {
        case OpKind::Recv:
        case OpKind::RecvFrom:
            on_read(done[i]);
            break;

        case OpKind::Send:
        case OpKind::SendTo:
            on_write(done[i]);
            break;

        case OpKind::Accept:
            on_accept(done[i], now);
            break;

        case OpKind::Close:
            break;
        }
    }

    return made;
}

size_t Shard::expire(uint64_t now) noexcept {
    size_t closed = 0;

    for (;;) {
        const uint32_t slot = wheel_.take_due(now);
        if (slot == kNoTimer) break;

        /* \~english
         * The index becomes a handle by asking the table, so the life is read
         * and never guessed.  A deadline armed for a connection that has since
         * gone names a slot somebody else may be in -- and closing that one
         * would be disconnecting a client for another client's silence.
         * \~spanish
         * El indice se convierte en referencia preguntandole a la tabla, asi que
         * la vida se lee y no se adivina.  Un plazo armado por una conexion que
         * ya se fue nombra una casilla en la que puede estar otro -- y cerrar a
         * ese seria desconectar a un cliente por el silencio de otro.
         * \~ */
        const ConnHandle c = conns_.at(slot);
        if (!c.valid()) continue;

        close(c);
        ++closed;
    }

    return closed;
}

} // namespace http_vx
