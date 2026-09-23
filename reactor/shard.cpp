/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard.cpp
 * @brief
 * \~english Driving one thread's connections.
 * \~spanish Mover las conexiones de un hilo.
 * \~
 */

#include "http_vx/shard.h"

namespace http_vx {

Service::~Service() = default;

namespace {

/**
 * @brief
 * \~english Whether the operating system is holding something of @p h.
 * \~spanish Si el sistema operativo tiene algo de @p h.
 * \~
 *
 * \~english
 * The question the buffer rules turn on, and it is answerable from one field
 * because this loop keeps AT MOST ONE operation per connection outstanding.
 *
 * That is a real limitation and it is worth naming: a connection cannot be
 * reading and writing at the same time here, so a peer that sends while a
 * response is going out waits for the kernel's receive queue to hold it.  For
 * request-and-response that is exactly right.  For HTTP/2, where a peer may
 * be sending one request while another is being answered, it costs
 * concurrency that the protocol allows -- and lifting it means a count and a
 * per-operation record rather than a state, which is a bigger change than it
 * looks and is not worth making before something measures the cost.
 *
 * \~spanish
 * La pregunta sobre la que giran las reglas del buffer, y se puede contestar
 * con un solo campo porque este bucle mantiene COMO MUCHO UNA operacion
 * pendiente por conexion.
 *
 * Es una limitacion de verdad y merece nombrarse: aqui una conexion no puede
 * estar leyendo y escribiendo a la vez, asi que un extremo que mande mientras
 * sale una respuesta espera a que se lo guarde la cola de recepcion del nucleo.
 * Para peticion-y-respuesta eso es exactamente lo correcto.  Para HTTP/2, donde
 * un extremo puede estar mandando una peticion mientras se contesta otra, cuesta
 * una concurrencia que el protocolo permite -- y levantarlo es una cuenta y un
 * registro por operacion en vez de un estado, que es un cambio mayor de lo que
 * parece y no vale la pena hacerlo antes de que algo mida lo que cuesta.
 *
 * \~
 */
bool busy(const ConnHot &h) noexcept {
    return h.state == static_cast<uint16_t>(ConnState::Reading) ||
           h.state == static_cast<uint16_t>(ConnState::Writing);
}

void set_state(ConnHot &h, ConnState s) noexcept {
    h.state = static_cast<uint16_t>(s);
}

bool is_state(const ConnHot &h, ConnState s) noexcept {
    return h.state == static_cast<uint16_t>(s);
}

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

    return true;
}

void Shard::release() noexcept {
    conns_.release();
    pool_.release_all();
    wheel_.release();
    io_ = nullptr;
    service_ = nullptr;
}

void Shard::let_go(ConnHandle c, ConnHot &h) noexcept {
    if (h.buffer != kNoBuffer) {
        pool_.release(h.buffer);
        h.buffer = kNoBuffer;
    }

    wheel_.cancel(c.slot);
    set_state(h, ConnState::Idle);

    service_->on_close(c);
    conns_.close(c);
}

bool Shard::start_read(ConnHandle c, uint64_t now) noexcept {
    (void)now;

    ConnHot *h = conns_.hot(c);
    if (h == nullptr) return false;

    /* \~english
     * The buffer is taken HERE, when there is a reason to read, and not when
     * the connection arrived.  That is R1: an idle connection is a record in
     * an array and a socket, and the buffer it would have been given is
     * serving somebody who is actually talking.
     * \~spanish
     * El buffer se coge AQUI, cuando hay razon para leer, y no cuando llego la
     * conexion.  Eso es la R1: una conexion parada es un registro de un array y
     * un socket, y el buffer que se le habria dado esta sirviendo a alguien que
     * si esta hablando.
     * \~ */
    if (h->buffer == kNoBuffer) {
        h->buffer = pool_.acquire();

        /* \~english
         * No buffer is not a failure.  The connection stays idle and does not
         * read this time round; the bytes wait in the kernel's receive queue,
         * which is a place designed to hold them, and TCP slows the peer down
         * by itself.  Its deadline is still armed, so a connection that never
         * gets a turn still goes away rather than sitting there forever.
         * \~spanish
         * Que no haya buffer no es un fallo.  La conexion se queda parada y no
         * lee esta vuelta; los bytes esperan en la cola de recepcion del nucleo,
         * que es un sitio hecho para guardarlos, y TCP frena al otro extremo el
         * solo.  Su plazo sigue armado, asi que una conexion a la que no le
         * toque nunca se va igual en vez de quedarse ahi para siempre.
         * \~ */
        if (h->buffer == kNoBuffer) return false;
    }

    Op op;
    op.conn = c;
    op.kind = OpKind::Recv;
    op.buffer = h->buffer;
    op.offset = 0;
    op.length = cfg_.read_size;

    if (!io_->submit(op)) {
        pool_.release(h->buffer);
        h->buffer = kNoBuffer;
        return false;
    }

    set_state(*h, ConnState::Reading);
    return true;
}

ConnHandle Shard::adopt(int32_t fd, uint64_t now) noexcept {
    const ConnHandle c = conns_.open(fd, now);
    if (!c.valid()) return c;

    ConnHot *h = conns_.hot(c);
    h->buffer = kNoBuffer;
    set_state(*h, ConnState::Idle);

    /* \~english
     * The deadline is armed by the SLOT and not by the handle, and that is
     * safe for one reason: arming a slot that is already armed replaces what
     * was there.  So a slot handed to a new connection cannot still be
     * carrying the previous one's deadline -- the arming here is what
     * overwrites it.  Where the two must not be confused is when a deadline
     * FIRES, and there the index is turned back into a handle by asking the
     * table, so the life is read rather than assumed.
     * \~spanish
     * El plazo se arma por la CASILLA y no por la referencia, y eso es seguro
     * por una razon: armar una casilla que ya esta armada sustituye lo que
     * hubiera.  Asi que una casilla entregada a una conexion nueva no puede
     * seguir llevando el plazo de la anterior -- armarla aqui es lo que lo pisa.
     * Donde no se pueden confundir las dos cosas es cuando un plazo VENCE, y
     * ahi el indice se convierte otra vez en referencia preguntandole a la
     * tabla, asi que la vida se lee en vez de suponerse.
     * \~ */
    wheel_.arm(c.slot, cfg_.idle_ticks);

    service_->on_open(c);
    start_read(c, now);
    return c;
}

void Shard::close(ConnHandle c) noexcept {
    ConnHot *h = conns_.hot(c);
    if (h == nullptr) return;

    /* \~english
     * A connection with an operation still in the operating system does not
     * leave now.  Its buffer is the kernel's until the completion comes back,
     * and giving it to the pool before then is a use-after-free the kernel
     * performs -- into memory that by then belongs to somebody else.  So the
     * connection is marked and the completion finishes the job.
     * \~spanish
     * Una conexion con una operacion todavia en el sistema operativo no se va
     * ahora.  Su buffer es del nucleo hasta que vuelva la finalizacion, y darlo
     * al pozo antes es un uso despues de liberar que hace el nucleo -- sobre una
     * memoria que para entonces es de otro --.  Asi que la conexion se marca y
     * la finalizacion acaba el trabajo.
     * \~ */
    if (busy(*h)) {
        set_state(*h, ConnState::Closing);
        return;
    }

    let_go(c, *h);
}

void Shard::on_read(const Completion &done, uint64_t now) noexcept {
    ConnHot *h = conns_.hot(done.conn);

    /* \~english
     * A completion for a connection that is no longer this one.  With the
     * closing rule above it should not happen -- a connection with an
     * operation outstanding keeps its slot -- so reaching here means something
     * released a slot it did not own.  The buffer is given back anyway,
     * because a pool that leaked one buffer per occurrence would end up empty
     * and the server would stop reading, which is a symptom nobody could trace
     * back to here.
     * \~spanish
     * Una finalizacion de una conexion que ya no es esta.  Con la regla de
     * cierre de arriba no deberia pasar -- una conexion con una operacion
     * pendiente se queda su casilla -- asi que llegar aqui quiere decir que algo
     * solto una casilla que no era suya.  El buffer se devuelve igual, porque un
     * pozo que perdiera un buffer por vez acabaria vacio y el servidor dejaria
     * de leer, que es un sintoma que nadie podria rastrear hasta aqui.
     * \~ */
    if (h == nullptr) {
        if (done.buffer != kNoBuffer) pool_.release(done.buffer);
        return;
    }

    if (is_state(*h, ConnState::Closing)) {
        let_go(done.conn, *h);
        return;
    }

    set_state(*h, ConnState::Idle);

    /* \~english
     * A failure or the peer closing its end, and neither is an error worth
     * telling anybody about: one is the network and the other is a client that
     * has finished.  What they have in common is that there is nothing more to
     * read.
     * \~spanish
     * Un fallo o el otro extremo cerrando su lado, y ninguno es un error del que
     * contarle nada a nadie: uno es la red y el otro es un cliente que ha
     * acabado.  Lo que tienen en comun es que ya no hay nada mas que leer.
     * \~ */
    if (!done.ok() || done.eof()) {
        close(done.conn);
        return;
    }

    Buffer *in = pool_.at(h->buffer);
    if (in == nullptr) {
        close(done.conn);
        return;
    }

    /* \~english
     * Activity pushes the deadline out, and this is the most frequent thing
     * the loop does -- which is why the wheel was built so that doing it is an
     * unlink and a push rather than a search.
     * \~spanish
     * La actividad empuja el plazo mas lejos, y esto es lo que mas veces hace el
     * bucle -- que es la razon de que la rueda se hiciera para que hacerlo sea
     * un desenlace y un meter en una lista, y no una busqueda.
     * \~ */
    wheel_.arm(done.conn.slot, cfg_.idle_ticks);

    ConnCold *cold = conns_.cold(done.conn);
    if (cold != nullptr) cold->bytes_in += static_cast<uint64_t>(done.result);

    /* \~english
     * A second buffer for the answer, so a connection that is answering holds
     * TWO of them.  It is the pool's real high-water mark and it is worth
     * knowing: the number to size the pool by is not how many connections talk
     * at once, it is how many are mid-exchange.
     *
     * Not getting one closes the connection rather than holding the request.
     * That is the shard at its limit saying so: keeping it would mean a
     * request that is never answered and a peer that waits for a response
     * until its own timeout, which is a worse way to be told the same thing.
     *
     * \~spanish
     * Un segundo buffer para la respuesta, asi que una conexion que esta
     * contestando tiene DOS.  Es el pico de verdad del pozo y merece saberse: el
     * numero por el que dimensionarlo no es cuantas conexiones hablan a la vez,
     * es cuantas estan a mitad de intercambio.
     *
     * No conseguirlo cierra la conexion en vez de retener la peticion.  Es el
     * fragmento en su limite diciendolo: quedarsela seria una peticion que no se
     * contesta nunca y un extremo que espera una respuesta hasta su propio
     * plazo, que es una forma peor de que le digan lo mismo.
     * \~ */
    const uint32_t wb = pool_.acquire();
    if (wb == kNoBuffer) {
        close(done.conn);
        return;
    }

    Buffer *out = pool_.at(wb);
    const bool keep =
        service_->on_bytes(done.conn, in->data(), in->size(), *out);

    /* \~english
     * The read buffer goes back now, whatever happens next.  What the service
     * wanted from it, it has taken -- and holding it through the write would
     * be holding a buffer for a connection that is not reading, which is the
     * thing R1 is about.
     * \~spanish
     * El buffer de lectura vuelve ahora, pase lo que pase despues.  Lo que
     * quisiera el servicio de el ya lo ha cogido -- y guardarlo durante la
     * escritura seria tener un buffer para una conexion que no esta leyendo, que
     * es de lo que va la R1.
     * \~ */
    pool_.release(h->buffer);
    h->buffer = kNoBuffer;

    if (!keep || out->empty()) {
        pool_.release(wb);
        if (!keep) {
            close(done.conn);
            return;
        }
        start_read(done.conn, now);
        return;
    }

    Op op;
    op.conn = done.conn;
    op.kind = OpKind::Send;
    op.buffer = wb;
    op.offset = 0;
    op.length = static_cast<uint32_t>(out->size());

    if (!io_->submit(op)) {
        pool_.release(wb);
        close(done.conn);
        return;
    }

    h->buffer = wb;
    set_state(*h, ConnState::Writing);
}

void Shard::on_write(const Completion &done, uint64_t now) noexcept {
    ConnHot *h = conns_.hot(done.conn);
    if (h == nullptr) {
        if (done.buffer != kNoBuffer) pool_.release(done.buffer);
        return;
    }

    if (is_state(*h, ConnState::Closing)) {
        let_go(done.conn, *h);
        return;
    }

    set_state(*h, ConnState::Idle);

    if (!done.ok()) {
        close(done.conn);
        return;
    }

    Buffer *out = pool_.at(done.buffer);
    if (out == nullptr) {
        close(done.conn);
        return;
    }

    ConnCold *cold = conns_.cold(done.conn);
    if (cold != nullptr) cold->bytes_out += static_cast<uint64_t>(done.result);

    /* \~english
     * What went out is consumed, so what is left is simply what is still in
     * the buffer.  The alternative -- remembering how far a response had got
     * -- would be a number kept beside the buffer that says the same thing the
     * buffer already knows, and two of those disagree.
     *
     * Consuming here is safe because the operation has COME BACK: the buffer
     * stopped being the kernel's the moment this completion arrived.  Doing it
     * while the write was outstanding would be moving memory the kernel is
     * reading from.
     *
     * \~spanish
     * Lo que salio se consume, asi que lo que queda es sencillamente lo que
     * sigue en el buffer.  La alternativa -- acordarse de por donde iba una
     * respuesta -- seria un numero guardado al lado del buffer que dice lo mismo
     * que el buffer ya sabe, y dos de esos discrepan.
     *
     * Consumir aqui es seguro porque la operacion ha VUELTO: el buffer dejo de
     * ser del nucleo en el momento en que llego esta finalizacion.  Hacerlo
     * mientras la escritura estaba pendiente seria mover una memoria de la que
     * el nucleo esta leyendo.
     * \~ */
    out->consume(static_cast<size_t>(done.result));

    if (!out->empty()) {
        Op op;
        op.conn = done.conn;
        op.kind = OpKind::Send;
        op.buffer = done.buffer;
        op.offset = 0;
        op.length = static_cast<uint32_t>(out->size());

        if (!io_->submit(op)) {
            close(done.conn);
            return;
        }

        set_state(*h, ConnState::Writing);
        return;
    }

    pool_.release(done.buffer);
    h->buffer = kNoBuffer;

    wheel_.arm(done.conn.slot, cfg_.idle_ticks);
    start_read(done.conn, now);
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
            on_read(done[i], now);
            break;

        case OpKind::Send:
        case OpKind::SendTo:
            on_write(done[i], now);
            break;

        case OpKind::Accept:
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
         *
         * It cannot happen here, because closing a connection cancels its
         * deadline and arming replaces what was there.  Going through the
         * table anyway costs one comparison and means the property does not
         * depend on both of those staying true.
         *
         * \~spanish
         * El indice se convierte en referencia preguntandole a la tabla, asi que
         * la vida se lee y no se adivina nunca.  Un plazo armado por una conexion
         * que ya se fue nombra una casilla en la que puede estar otro -- y
         * cerrar a ese seria desconectar a un cliente por el silencio de otro.
         *
         * Aqui no puede pasar, porque cerrar una conexion cancela su plazo y
         * armar sustituye lo que hubiera.  Pasar por la tabla igualmente cuesta
         * una comparacion y quiere decir que la propiedad no depende de que esas
         * dos cosas sigan siendo ciertas.
         * \~ */
        const ConnHandle c = conns_.at(slot);
        if (!c.valid()) continue;

        close(c);
        ++closed;
    }

    return closed;
}

} // namespace http_vx
