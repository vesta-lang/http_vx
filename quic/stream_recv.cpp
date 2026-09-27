/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/stream_recv.cpp
 * @brief
 * \~english Reassembling a stream's bytes, and receive-side flow control.
 * \~spanish Reensamblar los bytes de un flujo, y el control de flujo del lado receptor.
 * \~
 */

#include "http_vx/quic_stream_recv.h"

#include "bitmap.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memcpy.h"
#include "util/mem/vesta_memset.h"

namespace http_vx {
namespace quic {

/// \~english Which bytes of one chunk of the window arrived: all an abandoned stream keeps (RFC 9000, 3.5).
/// \~spanish Que bytes de un trozo de la ventana llegaron: todo lo que guarda un flujo abandonado (RFC 9000, 3.5).  \~
struct RecvStream::Marks {
    uint64_t bits[kRecvChunk / 64];
};

/// \~english One chunk of the window: which bytes arrived, and the bytes.
/// \~spanish Un trozo de la ventana: que bytes llegaron, y los bytes.  \~
struct RecvStream::Chunk : RecvStream::Marks {
    uint8_t data[kRecvChunk];
};

namespace {

inline uint64_t min64(uint64_t a, uint64_t b) noexcept { return a < b ? a : b; }

} // namespace

const char *stream_error_name(StreamError e) noexcept {
    switch (e) {
    case StreamError::None:        return "none";
    case StreamError::FlowControl: return "flow-control";
    case StreamError::FinalSize:   return "final-size";
    case StreamError::OutOfMemory: return "out-of-memory";
    }
    return "unknown";
}

TransportError transport_error_of(StreamError e) noexcept {
    switch (e) {
    case StreamError::None:        return TransportError::NoError;
    case StreamError::FlowControl: return TransportError::FlowControlError;
    case StreamError::FinalSize:   return TransportError::FinalSizeError;
    case StreamError::OutOfMemory: return TransportError::InternalError;
    }
    return TransportError::InternalError;
}

RecvStream::RecvStream(uint64_t window) noexcept {
    // \~english A whole number of chunks, and at least one.
    // \~spanish Un numero entero de trozos, y al menos uno.  \~
    const uint64_t chunks = window == 0 ? 1 : (window + kRecvChunk - 1) / kRecvChunk;
    window_ = chunks * kRecvChunk;
    /* \~english
     * The first limit is EXACTLY the window asked for: it is what the
     * transport parameter announces, and data past it MUST be a
     * FLOW_CONTROL_ERROR (4.1, 19.10).  Rounding it up to whole chunks, as the
     * memory is, would let a peer past a limit it was told.  Later limits are
     * the ones MAX_STREAM_DATA sends, whatever they are.
     * \~spanish
     * El primer limite es EXACTAMENTE la ventana pedida: es lo que anuncia el
     * parametro de transporte, y los datos por encima DEBEN ser un
     * FLOW_CONTROL_ERROR (4.1, 19.10).  Redondearlo a trozos enteros, como la
     * memoria, dejaria al otro pasar de un limite que se le dijo.  Los limites
     * siguientes son los que manda MAX_STREAM_DATA, sean cuales sean.
     * \~ */
    limit_ = window;

    /* \~english
     * One slot more than the window holds whole chunks: a window that starts
     * in the middle of a chunk ends in the middle of another, and touches
     * one chunk more than its size divided by the chunk.
     * \~spanish
     * Una ranura mas de los trozos enteros que caben en la ventana: una ventana
     * que empieza en mitad de un trozo acaba en mitad de otro, y toca un trozo
     * mas que su tamano dividido por el del trozo.
     * \~ */
    nslots_ = static_cast<size_t>(chunks) + 1;
}

RecvStream::~RecvStream() {
    release_all();
    if (slots_ != nullptr) util::host_free(slots_);
}

RecvStream::Marks *RecvStream::chunk_for(uint64_t index, bool create) noexcept {
    if (slots_ == nullptr) {
        if (!create) return nullptr;

        // \~english The slot table too is only paid for once data arrives.
        // \~spanish La tabla de ranuras tambien se paga solo cuando llegan datos.  \~
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                     util::AllocFill::All);
        slots_ = static_cast<Marks **>(util::host_alloc(nslots_ * sizeof(Marks *)));
        if (slots_ == nullptr) return nullptr;
        util::vesta_memset(slots_, 0, nslots_ * sizeof(Marks *));
    }

    Marks *&slot = slots_[index % nslots_];
    if (slot == nullptr && create) {
        const util::AllocScope scope(util::AllocUse::Medium, util::AllocShape::Fixed,
                                     util::AllocFill::Dense);
        /* \~english
         * An abandoned stream keeps no byte, only which ones arrived: a chunk
         * made after the stop is its marks alone, an eighth of its size.
         * \~spanish
         * Un flujo abandonado no guarda ningun byte, solo cuales llegaron: un
         * trozo hecho despues de la parada son solo sus marcas, un octavo de su
         * tamano.
         * \~ */
        slot = static_cast<Marks *>(util::host_alloc(abandoned_ ? sizeof(Marks) : sizeof(Chunk)));
        if (slot == nullptr) return nullptr;
        util::vesta_memset(slot->bits, 0, sizeof slot->bits);
        ++held_;
    }
    return slot;
}

void RecvStream::release_below(uint64_t offset) noexcept {
    if (slots_ == nullptr) return;

    // \~english Every chunk that lies wholly below @p offset has been read.
    // \~spanish Cada trozo que queda entero por debajo de @p offset ya se leyo.  \~
    const uint64_t first = read_ / kRecvChunk;
    const uint64_t last = offset / kRecvChunk;
    for (uint64_t i = first; i < last; ++i) {
        Marks *&slot = slots_[i % nslots_];
        if (slot != nullptr) {
            util::host_free(slot);
            slot = nullptr;
            --held_;
        }
    }
}

void RecvStream::release_all() noexcept {
    if (slots_ == nullptr) return;
    for (size_t i = 0; i < nslots_; ++i) {
        if (slots_[i] != nullptr) {
            util::host_free(slots_[i]);
            slots_[i] = nullptr;
        }
    }
    held_ = 0;
}

bool RecvStream::all_received() const noexcept {
    return size_known_ && read_ + buffered_ == final_;
}

StreamError RecvStream::on_data(uint64_t offset, const uint8_t *p, size_t len, bool fin,
                                uint64_t &new_bytes, uint64_t &released) noexcept {
    new_bytes = 0;
    released = 0;
    const uint64_t end = offset + len;

    /* \~english
     * The final size rules hold even after a reset or once everything was
     * read (4.5): data past it, or a FIN elsewhere, is the peer lying about
     * how much it sent -- and so about how much of the connection's window
     * it used.
     * \~spanish
     * Las reglas del tamano final siguen valiendo tras un reinicio o cuando ya
     * se leyo todo (4.5): datos mas alla, o un FIN en otro sitio, es el otro
     * extremo mintiendo sobre cuanto mando -- y por tanto sobre cuanta ventana
     * de la conexion gasto.
     * \~ */
    if (size_known_) {
        if (end > final_ || (fin && end != final_)) return StreamError::FinalSize;
    } else if (fin && end < highest_) {
        return StreamError::FinalSize;
    }
    if (end > limit_) return StreamError::FlowControl;

    if (state_ == RecvState::ResetRecvd || state_ == RecvState::ResetRead) return StreamError::None;

    if (fin && !size_known_) {
        size_known_ = true;
        final_ = end;
        if (state_ == RecvState::Recv) state_ = RecvState::SizeKnown;
    }
    if (end > highest_) {
        new_bytes = end - highest_;
        highest_ = end;
    }
    if (state_ == RecvState::DataRecvd || state_ == RecvState::DataRead) return StreamError::None;

    /* \~english
     * An abandoned stream gives back at once what a frame costs (3.5): the
     * bytes are counted, never kept.  Which ones arrived is still marked --
     * the holes are what tell when every byte up to the final size came
     * (3.2), and a retransmission of marked bytes costs nothing.
     * \~spanish
     * Un flujo abandonado devuelve en el acto lo que cuesta una trama (3.5):
     * los bytes se cuentan, nunca se guardan.  Cuales llegaron se sigue
     * marcando -- los huecos son lo que dice cuando llego cada byte hasta el
     * tamano final (3.2), y una retransmision de bytes marcados no cuesta nada.
     * \~ */
    if (abandoned_) released = new_bytes;

    // \~english What was already read is dropped; the rest is copied chunk by chunk.
    // \~spanish Lo ya leido se tira; el resto se copia trozo a trozo.  \~
    uint64_t pos = offset > read_ ? offset : read_;
    while (pos < end) {
        Marks *m = chunk_for(pos / kRecvChunk, true);
        if (m == nullptr) return StreamError::OutOfMemory;

        const size_t in = static_cast<size_t>(pos % kRecvChunk);
        const size_t n = static_cast<size_t>(min64(end - pos, kRecvChunk - in));

        /* \~english
         * Copied over whatever was there: a retransmission carries the same
         * bytes (2.2), so rewriting them is cheaper than skipping them.
         * \~spanish
         * Copiado encima de lo que hubiera: una retransmision lleva los mismos
         * bytes (2.2), asi que reescribirlos es mas barato que saltarselos.
         * \~ */
        if (!abandoned_) util::vesta_memcpy(static_cast<Chunk *>(m)->data + in, p + (pos - offset), n);
        buffered_ += bits::set(m->bits, in, n);
        pos += n;
    }
    if (abandoned_) skip_marked();

    if (all_received()) {
        /* \~english
         * Abandoned: nobody is left to read the end, so "Data Recvd" is
         * "Data Read" at once, and the stream can go (3.2, 3.5).
         * \~spanish
         * Abandonado: no queda nadie que lea el final, asi que "Data Recvd" es
         * "Data Read" en el acto, y el flujo se puede ir (3.2, 3.5).
         * \~ */
        state_ = abandoned_ ? RecvState::DataRead : RecvState::DataRecvd;

        /* \~english
         * A FIN that arrives after everything was read leaves no byte to
         * read, but it is still an end the application has not heard: the
         * stream stays in "Data Recvd" until `read_end` (3.2).  Going to "Data
         * Read" here let the stream be collected with the end untold.  Only
         * the memory goes now.
         * \~spanish
         * Un FIN que llega cuando ya se leyo todo no deja ningun byte que leer,
         * pero sigue siendo un final que la aplicacion no ha oido: el flujo
         * sigue en "Data Recvd" hasta `read_end` (3.2).  Pasar aqui a "Data
         * Read" dejaba recoger el flujo con el final sin decir.  Solo la
         * memoria se va ya.
         * \~ */
        if (read_ == final_) release_all();
    }
    return StreamError::None;
}

StreamError RecvStream::on_reset(uint64_t final_size, uint64_t error_code,
                                 uint64_t &new_bytes, uint64_t &released) noexcept {
    new_bytes = 0;
    released = 0;

    if (size_known_ && final_size != final_) return StreamError::FinalSize;
    if (final_size < highest_) return StreamError::FinalSize;
    if (final_size > limit_) return StreamError::FlowControl;

    /* \~english
     * Everything already received, or already reset: the reset changes
     * nothing -- the RFC makes that transition optional, and delivering data
     * that fully arrived beats throwing it away.
     * \~spanish
     * Todo ya recibido, o ya reiniciado: el reinicio no cambia nada -- el RFC
     * hace opcional esa transicion, y entregar datos que llegaron enteros es
     * mejor que tirarlos.
     * \~ */
    if (state_ != RecvState::Recv && state_ != RecvState::SizeKnown) return StreamError::None;

    /* \~english
     * What the connection already has back: what was read, or, on an
     * abandoned stream, everything counted, which went back as it came.
     * \~spanish
     * Lo que la conexion ya tiene de vuelta: lo leido, o, en un flujo
     * abandonado, todo lo contado, que volvio segun llegaba.
     * \~ */
    const uint64_t given_back = abandoned_ ? highest_ : read_;
    new_bytes = final_size - highest_;
    highest_ = final_size;
    final_ = final_size;
    size_known_ = true;

    // \~english Counted as received, never to be read: the connection gets it back.
    // \~spanish Contado como recibido, sin leerse nunca: la conexion lo recupera.  \~
    released = final_size - given_back;
    reset_code_ = error_code;
    /* \~english
     * The application that asked for this reset with STOP_SENDING already gave
     * the stream up (3.5): nobody is left to be told, so it is read as it
     * arrives.  Any other reset waits in "Reset Recvd" for `read_end`.
     * \~spanish
     * La aplicacion que pidio este reinicio con STOP_SENDING ya abandono el
     * flujo (3.5): no queda nadie a quien decirselo, asi que se lee al llegar.
     * Cualquier otro reinicio espera en "Reset Recvd" a `read_end`.
     * \~ */
    state_ = abandoned_ ? RecvState::ResetRead : RecvState::ResetRecvd;
    buffered_ = 0;
    release_all();
    return StreamError::None;
}

size_t RecvStream::peek(const uint8_t *&p) const noexcept {
    if (state_ == RecvState::ResetRecvd || state_ == RecvState::ResetRead ||
        state_ == RecvState::DataRead || abandoned_ || slots_ == nullptr)
        return 0;

    const Marks *m = slots_[(read_ / kRecvChunk) % nslots_];
    if (m == nullptr) return 0;

    const size_t in = static_cast<size_t>(read_ % kRecvChunk);
    const size_t n = bits::run(m->bits, in, kRecvChunk, true);
    // \~english Never abandoned here: every chunk holds its bytes.  \~spanish Nunca abandonado aqui: cada trozo tiene sus bytes.  \~
    p = static_cast<const Chunk *>(m)->data + in;
    return n;
}

void RecvStream::advance(uint64_t n) noexcept {
    const uint64_t to = read_ + n;
    release_below(to);
    read_ = to;
    buffered_ -= n;
}

void RecvStream::skip_marked() noexcept {
    /* \~english
     * Past every byte that arrived with no hole before it, one run per
     * chunk: each byte is passed once, so the cost follows the data, and
     * the marks of chunks left behind are freed.
     * \~spanish
     * Mas alla de cada byte que llego sin hueco delante, una racha por trozo:
     * cada byte se pasa una vez, asi que el coste sigue a los datos, y las
     * marcas de los trozos que quedan atras se liberan.
     * \~ */
    while (slots_ != nullptr) {
        const Marks *m = slots_[(read_ / kRecvChunk) % nslots_];
        if (m == nullptr) return;
        const size_t n = bits::run(m->bits, static_cast<size_t>(read_ % kRecvChunk), kRecvChunk, true);
        if (n == 0) return;
        advance(n);
    }
}

bool RecvStream::stop(uint64_t code, uint64_t &released) noexcept {
    released = 0;
    if (abandoned_) return false;
    abandoned_ = true;
    switch (state_) {
    case RecvState::ResetRecvd:
        // \~english The reset's bytes were given back when it came; only its reader is gone.
        // \~spanish Los bytes del reinicio se devolvieron al llegar; solo falta su lector.  \~
        state_ = RecvState::ResetRead;
        return false;
    case RecvState::ResetRead:
    case RecvState::DataRead:
        return false;
    case RecvState::DataRecvd:
        /* \~english
         * Everything is here: nothing to ask the peer (3.3, 3.5), only the
         * unread bytes to give back, and the stream ends.
         * \~spanish
         * Todo esta aqui: nada que pedir al otro (3.3, 3.5), solo devolver los
         * bytes sin leer, y el flujo acaba.
         * \~ */
        released = final_ - read_;
        advance(released);
        release_all();
        state_ = RecvState::DataRead;
        return false;
    case RecvState::Recv:
    case RecvState::SizeKnown:
        break;
    }
    /* \~english
     * "Recv" or "Size Known": every byte counted and not read goes back to
     * the connection now, holes included -- their bytes will cost nothing
     * when they come.  The marks stay, to see the stream through to its end
     * or its reset, and a STOP_SENDING is owed, again if it is lost, until
     * then (3.5, 13.3).
     * \~spanish
     * "Recv" o "Size Known": cada byte contado y no leido vuelve ya a la
     * conexion, huecos incluidos -- sus bytes no costaran nada cuando lleguen.
     * Las marcas se quedan, para llevar el flujo hasta su final o su reinicio,
     * y se debe un STOP_SENDING, otra vez si se pierde, hasta entonces (3.5,
     * 13.3).
     * \~ */
    released = highest_ - read_;
    skip_marked();
    stopped_ = true;
    stop_pending_ = true;
    stop_code_ = code;
    return true;
}

size_t RecvStream::consume(size_t n) noexcept {
    if (abandoned_) return 0;
    advance(n);

    // \~english The last byte read: the memory goes, the end waits for `read_end` (3.2).
    // \~spanish Leido el ultimo byte: la memoria se va, el final espera a `read_end` (3.2).  \~
    if (state_ == RecvState::DataRecvd && read_ == final_) release_all();
    return n;
}

bool RecvStream::read_end() noexcept {
    if (state_ == RecvState::DataRecvd && read_ == final_) {
        state_ = RecvState::DataRead;
        return true;
    }
    if (state_ == RecvState::ResetRecvd) {
        state_ = RecvState::ResetRead;
        return true;
    }
    return false;
}

bool RecvStream::wants_update() const noexcept {
    // \~english With the size known there is nothing more to allow (3.2).
    // \~spanish Con el tamano conocido no hay nada mas que permitir (3.2).  \~
    if (!takes_credit()) return false;
    return limit_ - read_ < window_ / 2;
}

uint64_t RecvStream::next_limit() const noexcept {
    const uint64_t next = read_ + window_;
    return next > limit_ ? next : limit_;
}

uint64_t RecvStream::advertise() noexcept {
    const uint64_t next = read_ + window_;
    if (next > limit_) limit_ = next;
    return limit_;
}

bool RecvFlow::on_received(uint64_t new_bytes) noexcept {
    received_ += new_bytes;
    return received_ <= limit_;
}

uint64_t RecvFlow::advertise() noexcept {
    const uint64_t next = consumed_ + window_;
    if (next > limit_) limit_ = next;
    return limit_;
}

} // namespace quic
} // namespace http_vx
