/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/service.cpp
 * @brief
 * \~english The HTTP/2 service's memory: connections, pieces of work and their buffers.
 * \~spanish La memoria del servicio HTTP/2: conexiones, trabajos y sus buffers.
 * \~
 *
 * \~english
 * The rest of the service is split by what it does: reading a connection's
 * frames into requests (service_read.cpp), answering them (service_answer.cpp)
 * and putting the frames on the way out (service_write.cpp).
 * \~spanish
 * El resto del servicio va repartido por lo que hace: leer las tramas de una
 * conexion como peticiones (service_read.cpp), contestarlas
 * (service_answer.cpp) y poner las tramas de salida (service_write.cpp).
 * \~
 */

#include "http_vx/http2_service.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

#include <new>

namespace http_vx {

Http2Service::~Http2Service() { release(); }

void Http2Service::release() noexcept {
    if (state_ != nullptr) {
        for (uint32_t i = 0; i < capacity_; ++i) state_[i].~State();
        util::host_free(state_);
        state_ = nullptr;
    }
    capacity_ = 0;

    if (works_ != nullptr) {
        for (uint32_t i = 0; i < work_count_; ++i) works_[i].~Work();
        util::host_free(works_);
        works_ = nullptr;
    }
    work_count_ = 0;
    free_work_ = kNoWork;
    in_hand_ = 0;

    bodies_.release_all();
    opens_.release();
    said_.release();
    block_.release();
    names_.release();
}

bool Http2Service::reset(uint32_t connections, uint32_t requests,
                         size_t max_body, Handler &handler,
                         const h2::Limits &limits, uint32_t opens) noexcept {
    release();

    if (connections == 0 || requests == 0) return false;

    handler_ = &handler;
    limits_ = limits;
    max_body_ = max_body;
    served_ = 0;
    bad_answers_ = 0;
    last_bad_answer_ = nullptr;
    open_full_ = 0;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    state_ = static_cast<State *>(
        util::host_alloc(static_cast<size_t>(connections) * sizeof(State)));
    if (state_ == nullptr) return false;

    capacity_ = connections;
    for (uint32_t i = 0; i < capacity_; ++i) {
        new (&state_[i]) State();
        state_[i].works = kNoWork;
    }

    works_ = static_cast<Work *>(
        util::host_alloc(static_cast<size_t>(requests) * sizeof(Work)));
    if (works_ == nullptr) {
        release();
        return false;
    }

    work_count_ = requests;
    for (uint32_t i = 0; i < work_count_; ++i) {
        new (&works_[i]) Work();
        works_[i].buffer = kNoBuffer;
        works_[i].next = i + 1 == work_count_ ? kNoWork : i + 1;
    }
    free_work_ = 0;

    /* \~english
     * One buffer per piece of work and no more, because a piece of work holds
     * exactly one for exactly as long as it exists.  Two pools of the same size
     * rather than one structure holding both, so that the buffer's own rule --
     * a buffer that grew past the ceiling gives its memory back instead of
     * being kept -- goes on applying without being written a second time.
     *
     * \~spanish
     * Un buffer por trabajo y ninguno mas, porque un trabajo tiene exactamente
     * uno exactamente mientras existe.  Dos pozos del mismo tamano en vez de una
     * estructura con las dos cosas, para que la regla propia del buffer -- uno
     * que crecio por encima del techo devuelve su memoria en vez de quedarse --
     * siga valiendo sin escribirla otra vez.
     *
     * \~english
     * The ceiling is the ordinary buffer size and not the body limit on
     * purpose: one large upload makes one buffer large, and a pool that kept it
     * would let every slot creep up to the biggest thing that ever went through
     * it -- so the memory would converge on the peak times the count, on a
     * server that never looked like it was leaking.
     *
     * \~spanish
     * El techo es el tamano corriente de un buffer y no el limite de cuerpo a
     * proposito: una subida grande hace grande un buffer, y un pozo que se lo
     * quedara dejaria que todas las plazas subieran hasta lo mas grande que haya
     * pasado por ellas -- asi que la memoria tenderia al pico por el numero, en un
     * servidor que no pareceria tener ninguna fuga.
     * \~ */
    if (!bodies_.reset(requests, kBufferInitialCapacity)) {
        release();
        return false;
    }

    // \~english The open responses have a table of their own, so a long one never holds a request's entry (HVX-5, 7.2).
    // \~spanish Las respuestas abiertas tienen su propia tabla, para que una larga no ocupe nunca la entrada de una peticion (HVX-5, 7.2).  \~
    if (!opens_.reset(opens)) {
        release();
        return false;
    }

    return true;
}

void Http2Service::on_open(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    State &s = state_[c.slot];

    /* \~english
     * The connection's opening SETTINGS is written here and goes out on the
     * first flush, which is the first time there are bytes to answer.  Nothing
     * is lost by that: a client sends its preface the moment it connects, so
     * the first read always comes before the first byte of a request -- and
     * this layer has no socket of its own to write to anyway.
     * \~spanish
     * El SETTINGS de apertura de la conexion se escribe aqui y sale en el primer
     * vaciado, que es la primera vez que hay bytes que contestar.  Con eso no se
     * pierde nada: un cliente manda su preambulo en cuanto se conecta, asi que la
     * primera lectura llega siempre antes del primer byte de una peticion -- y
     * esta capa no tiene ningun socket propio en el que escribir.
     * \~ */
    s.conn.reset(limits_);
    s.headers.recycle();
    s.req.clear();
    s.works = kNoWork;
    s.handle = c;
    s.opens = h2::OpenList();
}

void Http2Service::on_close(ConnHandle c) noexcept {
    if (c.slot >= capacity_) return;

    State &s = state_[c.slot];

    /* \~english
     * Everything this connection was in the middle of goes back to the pools.
     * A request whose answer never finished is not an error to report here --
     * the connection is gone and there is nobody to report it to -- but its
     * buffer is one that another connection is waiting for.
     * \~spanish
     * Todo lo que esta conexion tuviera a medias vuelve a los pozos.  Una
     * peticion cuya respuesta no acabo no es un error del que informar aqui -- la
     * conexion se fue y no hay a quien -- pero su buffer es uno que esta
     * esperando otra conexion.
     * \~ */
    while (s.works != kNoWork) drop_work(s, &works_[s.works]);

    // \~english The open responses go with their connection, and each source is told why.
    // \~spanish Las respuestas abiertas se van con su conexion, y a cada fuente se le dice por que.  \~
    if (s.opens.count != 0 && port_ != nullptr) {
        const GoneReason why = port_->closing_reason(c);
        for (uint32_t i = opens_.pop(s.opens); i != h2::kNoOpen; i = opens_.pop(s.opens))
            drop_open(i, why);
    }

    s.conn.release();
    s.headers.release();
    s.req.clear();
}

Http2Service::Work *Http2Service::take_work(State &s,
                                            uint32_t stream) noexcept {
    if (free_work_ == kNoWork) return nullptr;

    const uint32_t buffer = bodies_.acquire();
    if (buffer == kNoBuffer) return nullptr;

    const uint32_t i = free_work_;
    Work *w = &works_[i];
    free_work_ = w->next;

    w->req.clear();
    w->buffer = buffer;
    w->stream = stream;
    w->head_size = 0;
    w->sent = 0;
    w->answering = false;

    w->next = s.works;
    s.works = i;
    ++in_hand_;

    return w;
}

void Http2Service::drop_work(State &s, Work *w) noexcept {
    const uint32_t i = static_cast<uint32_t>(w - works_);

    /* \~english
     * Unlinked by walking, because a connection's list is short -- one entry in
     * the ordinary case and never more than the pool -- and a doubly linked one
     * would be two more fields kept in step for a walk of two.
     * \~spanish
     * Se desenlaza recorriendo, porque la lista de una conexion es corta -- una
     * entrada en el caso corriente y nunca mas que el pozo -- y una doblemente
     * enlazada serian dos campos mas que mantener de acuerdo para un recorrido de
     * dos.
     * \~ */
    if (s.works == i) {
        s.works = w->next;
    } else {
        uint32_t at = s.works;
        while (at != kNoWork && works_[at].next != i) at = works_[at].next;
        if (at != kNoWork) works_[at].next = w->next;
    }

    if (w->buffer != kNoBuffer) bodies_.release(w->buffer);
    w->buffer = kNoBuffer;
    w->stream = 0;
    w->answering = false;
    w->req.clear();

    w->next = free_work_;
    free_work_ = i;
    --in_hand_;
}

Http2Service::Work *Http2Service::find_work(State &s,
                                            uint32_t stream) noexcept {
    for (uint32_t i = s.works; i != kNoWork; i = works_[i].next)
        if (works_[i].stream == stream) return &works_[i];
    return nullptr;
}

} // namespace http_vx
