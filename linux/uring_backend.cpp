/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/uring_backend.cpp
 * @brief
 * \~english Two rings shared with the kernel, and the barriers that make them safe.
 * \~spanish Dos anillos compartidos con el nucleo, y las barreras que los hacen seguros.
 * \~
 */

#include "http_vx/uring_backend.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memset.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <new>

namespace http_vx {

namespace {

/**
 * @brief
 * \~english The three system calls a ring is made of.
 * \~spanish Las tres llamadas al sistema de las que esta hecho un anillo.
 * \~
 *
 * \~english
 * Written out rather than taken from `liburing`, because a wrapper is what
 * this would be depending on: the calls are two, their arguments are fixed,
 * and the project has its own assembler and linker -- adding a library to be
 * spared this would make the build depend on what a machine happens to have.
 *
 * \~spanish
 * Escritas a mano en vez de cogidas de `liburing`, porque una envoltura es de lo
 * que se estaria dependiendo: las llamadas son dos, sus argumentos son fijos, y
 * el proyecto tiene ensamblador y enlazador propios -- anadir una biblioteca
 * para ahorrarse esto haria que la construccion dependiera de lo que tenga una
 * maquina.
 * \~
 */
int ring_setup(uint32_t entries, io_uring_params *p) noexcept {
    return static_cast<int>(syscall(__NR_io_uring_setup, entries, p));
}

int ring_enter(int fd, uint32_t to_submit, uint32_t min_complete,
               uint32_t flags, const void *arg, size_t arg_size) noexcept {
    return static_cast<int>(syscall(__NR_io_uring_enter, fd, to_submit,
                                    min_complete, flags, arg, arg_size));
}

/**
 * @brief
 * \~english Reads a ring index the kernel may be writing.
 * \~spanish Lee un indice del anillo que puede estar escribiendo el nucleo.
 * \~
 *
 * \~english
 * ACQUIRE, and that is not decoration.  The tail of the completion ring is
 * written by the kernel and the entries it points at are written BEFORE it; a
 * plain read may be moved after the reads of those entries by either the
 * compiler or the processor, and then this end reads a completion that has not
 * been filled in yet.
 *
 * It does not fail loudly.  What it produces is a completion naming an
 * operation that was never asked for, once in a while, on a machine under
 * load.
 *
 * \~spanish
 * ACQUIRE, y no es un adorno.  La cola del anillo de finalizaciones la escribe
 * el nucleo y las entradas a las que apunta se escriben ANTES; una lectura
 * normal la pueden mover detras de las lecturas de esas entradas el compilador o
 * el procesador, y entonces este extremo lee una finalizacion que todavia no se
 * ha rellenado.
 *
 * Y no falla en voz alta.  Lo que produce es una finalizacion que nombra una
 * operacion que no pidio nadie, de vez en cuando, en una maquina con trabajo.
 * \~
 */
uint32_t load_acquire(const uint32_t *p) noexcept {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

/// \~english Publishes a ring index the kernel will read.
/// \~spanish Publica un indice del anillo que leera el nucleo.  \~
void store_release(uint32_t *p, uint32_t v) noexcept {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

} // namespace

/**
 * @brief
 * \~english Where the kernel and this end meet.
 * \~spanish Donde se encuentran el nucleo y este extremo.
 * \~
 */
struct UringBackend::Ring {
    /// \~english The mapping, and how much of it there is.
    /// \~spanish El mapeo, y cuanto hay de el.  \~
    void *rings = nullptr;
    size_t rings_size = 0;

    io_uring_sqe *sqes = nullptr;
    size_t sqes_size = 0;

    /* \~english
     * Pointers INTO the mapping rather than copies of what is there.  Every
     * one of these is a place the kernel and this end both write, so a copy
     * would be a second answer that stops agreeing with the first.
     * \~spanish
     * Punteros DENTRO del mapeo y no copias de lo que hay.  Todos estos son un
     * sitio en el que escriben el nucleo y este extremo, asi que una copia seria
     * una segunda respuesta que deja de estar de acuerdo con la primera.
     * \~ */
    uint32_t *sq_head = nullptr;
    uint32_t *sq_tail = nullptr;
    uint32_t *sq_array = nullptr;
    uint32_t sq_mask = 0;
    uint32_t sq_entries = 0;

    uint32_t *cq_head = nullptr;
    uint32_t *cq_tail = nullptr;
    io_uring_cqe *cqes = nullptr;
    uint32_t cq_mask = 0;

    /// \~english Whether the kernel accepts a deadline on the wait.
    /// \~spanish Si el nucleo acepta un plazo en la espera.  \~
    bool ext_arg = false;
};

/**
 * @brief
 * \~english What an operation was for, kept until its number comes back.
 * \~spanish De que era una operacion, guardado hasta que vuelva su numero.
 * \~
 */
struct UringBackend::Slot {
    Op op;
    uint32_t next;
    bool busy;
};

bool uring_available() noexcept {
    io_uring_params p;
    util::vesta_memset(&p, 0, sizeof p);

    const int fd = ring_setup(4, &p);
    if (fd < 0) return false;

    close(fd);
    return true;
}

UringBackend::~UringBackend() { release(); }

void UringBackend::release() noexcept {
    if (listener_ >= 0) {
        close(listener_);
        listener_ = -1;
    }

    if (ring_ != nullptr) {
        if (ring_->sqes != nullptr) munmap(ring_->sqes, ring_->sqes_size);
        if (ring_->rings != nullptr) munmap(ring_->rings, ring_->rings_size);
        ring_->~Ring();
        util::host_free(ring_);
        ring_ = nullptr;
    }

    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }

    if (slots_ != nullptr) {
        for (uint32_t i = 0; i < slot_count_; ++i) slots_[i].~Slot();
        util::host_free(slots_);
        slots_ = nullptr;
    }

    slot_count_ = 0;
    free_head_ = 0xFFFFFFFF;
    in_flight_ = 0;
    waiting_ = 0;
    failed_count_ = 0;
    port_ = 0;
}

bool UringBackend::reset(BufferPool &pool, uint32_t entries) noexcept {
    release();

    if (entries == 0) return false;

    pool_ = &pool;

    io_uring_params p;
    util::vesta_memset(&p, 0, sizeof p);

    fd_ = ring_setup(entries, &p);
    if (fd_ < 0) {
        last_error_ = errno;
        return false;
    }

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    ring_ = static_cast<Ring *>(util::host_alloc(sizeof(Ring)));
    if (ring_ == nullptr) {
        release();
        return false;
    }
    new (ring_) Ring();

    /* \~english
     * One mapping for both rings where the kernel says it can, and two where
     * it cannot.  `IORING_FEAT_SINGLE_MMAP` is not an optimisation to take on
     * trust: a kernel without it puts the completion ring somewhere else, and
     * reading it out of the submission mapping would be reading whatever
     * happens to be at that offset.
     *
     * \~spanish
     * Un mapeo para los dos anillos donde el nucleo dice que se puede, y dos
     * donde no.  `IORING_FEAT_SINGLE_MMAP` no es una optimizacion que creerse: un
     * nucleo sin ella pone el anillo de finalizaciones en otro sitio, y leerlo del
     * mapeo de entregas seria leer lo que haya en ese desplazamiento.
     * \~ */
    size_t sq_size = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_size = p.cq_off.cqes + p.cq_entries * sizeof(io_uring_cqe);

    const bool single = (p.features & IORING_FEAT_SINGLE_MMAP) != 0;
    if (single) {
        if (cq_size > sq_size) sq_size = cq_size;
        cq_size = sq_size;
    }

    void *sq = mmap(nullptr, sq_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) {
        last_error_ = errno;
        release();
        return false;
    }

    void *cq = sq;
    if (!single) {
        cq = mmap(nullptr, cq_size, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_CQ_RING);
        if (cq == MAP_FAILED) {
            last_error_ = errno;
            munmap(sq, sq_size);
            release();
            return false;
        }
    }

    ring_->rings = sq;
    ring_->rings_size = sq_size;

    ring_->sqes_size = p.sq_entries * sizeof(io_uring_sqe);
    ring_->sqes = static_cast<io_uring_sqe *>(
        mmap(nullptr, ring_->sqes_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_POPULATE, fd_, IORING_OFF_SQES));
    if (ring_->sqes == MAP_FAILED) {
        last_error_ = errno;
        ring_->sqes = nullptr;
        release();
        return false;
    }

    uint8_t *s = static_cast<uint8_t *>(sq);
    uint8_t *c = static_cast<uint8_t *>(cq);

    ring_->sq_head = reinterpret_cast<uint32_t *>(s + p.sq_off.head);
    ring_->sq_tail = reinterpret_cast<uint32_t *>(s + p.sq_off.tail);
    ring_->sq_array = reinterpret_cast<uint32_t *>(s + p.sq_off.array);
    ring_->sq_mask = *reinterpret_cast<uint32_t *>(s + p.sq_off.ring_mask);
    ring_->sq_entries = p.sq_entries;

    ring_->cq_head = reinterpret_cast<uint32_t *>(c + p.cq_off.head);
    ring_->cq_tail = reinterpret_cast<uint32_t *>(c + p.cq_off.tail);
    ring_->cqes = reinterpret_cast<io_uring_cqe *>(c + p.cq_off.cqes);
    ring_->cq_mask = *reinterpret_cast<uint32_t *>(c + p.cq_off.ring_mask);

    ring_->ext_arg = (p.features & IORING_FEAT_EXT_ARG) != 0;

    /* \~english
     * The indirection array is filled ONCE with the identity, and never
     * touched again.  It exists so that a submission entry can be anywhere in
     * the array of them, which matters to a program that keeps long-lived
     * entries around; this one writes an entry and hands it over immediately,
     * so the only mapping it needs is "the same place".
     *
     * \~spanish
     * El array de indireccion se rellena UNA vez con la identidad, y no se vuelve
     * a tocar.  Existe para que una entrada de entrega pueda estar en cualquier
     * sitio del array de ellas, que le importa a un programa que guarde entradas
     * mucho tiempo; este escribe una entrada y la entrega enseguida, asi que la
     * unica correspondencia que necesita es "el mismo sitio".
     * \~ */
    for (uint32_t i = 0; i < p.sq_entries; ++i) ring_->sq_array[i] = i;

    /* \~english
     * More places to remember an operation than the ring holds, because the
     * ring bounds what is waiting to be HANDED OVER and these bound what is in
     * flight -- and the kernel makes the completion ring twice the size for
     * exactly that reason.
     * \~spanish
     * Mas sitios donde recordar una operacion que los que tiene el anillo, porque
     * el anillo acota lo que espera a ENTREGARSE y estos acotan lo que esta en
     * vuelo -- y el nucleo hace el anillo de finalizaciones del doble justo por
     * eso.
     * \~ */
    slot_count_ = p.cq_entries;
    slots_ = static_cast<Slot *>(
        util::host_alloc(static_cast<size_t>(slot_count_) * sizeof(Slot)));
    if (slots_ == nullptr) {
        release();
        return false;
    }

    for (uint32_t i = 0; i < slot_count_; ++i) {
        new (&slots_[i]) Slot();
        slots_[i].busy = false;
        slots_[i].next = i + 1 == slot_count_ ? 0xFFFFFFFF : i + 1;
    }
    free_head_ = 0;

    return true;
}

bool UringBackend::listen(const char *host, uint16_t port, int backlog) noexcept {
    if (fd_ < 0) return false;

    const int s = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (s < 0) {
        last_error_ = errno;
        return false;
    }

    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    sockaddr_in addr;
    util::vesta_memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        last_error_ = errno;
        close(s);
        return false;
    }

    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0) {
        last_error_ = errno;
        close(s);
        return false;
    }

    if (::listen(s, backlog) < 0) {
        last_error_ = errno;
        close(s);
        return false;
    }

    socklen_t len = sizeof addr;
    if (getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
        port_ = ntohs(addr.sin_port);

    listener_ = s;
    return true;
}

UringBackend::Slot *UringBackend::take() noexcept {
    if (free_head_ == 0xFFFFFFFF) return nullptr;

    Slot *s = &slots_[free_head_];
    free_head_ = s->next;
    s->busy = true;
    ++in_flight_;
    return s;
}

void UringBackend::give(Slot *s) noexcept {
    s->busy = false;
    s->next = free_head_;
    free_head_ = static_cast<uint32_t>(s - slots_);
    --in_flight_;
}

bool UringBackend::remember(const Op &op, int32_t result, int32_t fd) noexcept {
    if (failed_count_ == 64) return false;

    Completion &c = failed_[failed_count_];
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = result;
    c.fd = fd;
    ++failed_count_;
    return true;
}

bool UringBackend::submit(const Op &op) noexcept {
    if (ring_ == nullptr) return false;

    /* \~english
     * Room in the ring is checked against what the KERNEL has read, not
     * against what this end has written.  The two differ by exactly the
     * entries that are waiting to be handed over, and using the wrong one
     * would overwrite an entry the kernel has not seen -- which is an
     * operation that silently becomes another operation.
     * \~spanish
     * El sitio del anillo se comprueba contra lo que ha leido el NUCLEO, no
     * contra lo que ha escrito este extremo.  Los dos se diferencian justo en las
     * entradas que esperan a entregarse, y usar el que no es pisaria una entrada
     * que el nucleo no ha visto -- que es una operacion que se convierte por lo
     * bajo en otra.
     * \~ */
    const uint32_t tail = *ring_->sq_tail;
    const uint32_t head = load_acquire(ring_->sq_head);

    if (tail - head >= ring_->sq_entries) return false;

    Slot *slot = take();
    if (slot == nullptr) return false;

    slot->op = op;

    io_uring_sqe *sqe = &ring_->sqes[tail & ring_->sq_mask];
    util::vesta_memset(sqe, 0, sizeof *sqe);

    sqe->user_data = static_cast<uint64_t>(slot - slots_);

    bool made = true;

    switch (op.kind) {
    case OpKind::Accept:
        /* \~english
         * The listening socket is named here and not by the caller, for the
         * same reason it is on epoll: whoever asks for a connection has no
         * name for the socket that produces one.
         * \~spanish
         * El socket de escucha se nombra aqui y no lo nombra quien llama, por lo
         * mismo que en epoll: quien pide una conexion no tiene nombre para el
         * socket que la produce.
         * \~ */
        if (listener_ < 0) {
            made = false;
            break;
        }
        sqe->opcode = IORING_OP_ACCEPT;
        sqe->fd = listener_;
        sqe->addr = 0;
        sqe->off = 0;
        sqe->accept_flags = SOCK_CLOEXEC;
        break;

    case OpKind::Ready:
        /* \~english
         * A poll, which costs a ring entry and no system call at all.  This is
         * what makes R1 free here: asking to be told when there is something
         * is one more thing in the batch that was going to be handed over
         * anyway, so the buffer a connection does not hold costs nothing to
         * not hold.
         * \~spanish
         * Un sondeo, que cuesta una entrada del anillo y ninguna llamada al
         * sistema.  Esto es lo que hace gratis la R1 aqui: pedir que te avisen
         * cuando haya algo es una cosa mas del lote que se iba a entregar de todas
         * formas, asi que el buffer que una conexion no tiene no cuesta nada no
         * tenerlo.
         * \~ */
        if (op.fd < 0) {
            made = false;
            break;
        }
        sqe->opcode = IORING_OP_POLL_ADD;
        sqe->fd = op.fd;
        sqe->poll32_events = POLLIN;
        break;

    case OpKind::Recv:
    case OpKind::RecvFrom: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr || op.fd < 0) {
            made = false;
            break;
        }

        /* \~english
         * The room is reserved now, because the address is what is being
         * handed over -- exactly as on a completion port, and for exactly the
         * same reason.  From here until the completion, the buffer is the
         * kernel's.
         * \~spanish
         * El sitio se reserva ahora, porque lo que se entrega es la direccion --
         * exactamente igual que en un puerto de finalizacion y por lo mismo.
         * Desde aqui hasta la finalizacion, el buffer es del nucleo.
         * \~ */
        uint8_t *room = b->reserve(op.length);
        if (room == nullptr) {
            made = false;
            break;
        }

        sqe->opcode = IORING_OP_RECV;
        sqe->fd = op.fd;
        sqe->addr = reinterpret_cast<uint64_t>(room);
        sqe->len = op.length;
        break;
    }

    case OpKind::Send:
    case OpKind::SendTo: {
        Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
        if (b == nullptr || op.fd < 0 || op.offset + op.length > b->size()) {
            made = false;
            break;
        }

        sqe->opcode = IORING_OP_SEND;
        sqe->fd = op.fd;
        sqe->addr = reinterpret_cast<uint64_t>(b->data() + op.offset);
        sqe->len = op.length;
        sqe->msg_flags = MSG_NOSIGNAL;
        break;
    }

    case OpKind::Close:
        if (op.fd < 0) {
            made = false;
            break;
        }
        sqe->opcode = IORING_OP_CLOSE;
        sqe->fd = op.fd;
        break;
    }

    if (!made) {
        give(slot);
        return remember(op, -1, -1);
    }

    /* \~english
     * And the tail is published, which is the whole of handing an operation
     * over: the kernel is not called, it is TOLD -- and it is told by a store
     * that cannot be moved before the entry it points at.
     * \~spanish
     * Y se publica la cola, que es todo lo que es entregar una operacion: al
     * nucleo no se le llama, se le DICE -- y se le dice con una escritura que no
     * se puede mover por delante de la entrada a la que apunta.
     * \~ */
    store_release(ring_->sq_tail, tail + 1);
    ++waiting_;
    return true;
}

int UringBackend::enter(uint32_t want, int timeout_ms) noexcept {
    uint32_t flags = 0;
    if (want != 0) flags |= IORING_ENTER_GETEVENTS;

    const uint32_t submit = waiting_;
    waiting_ = 0;

    if (submit == 0 && want == 0) return 0;

    ++enters_;

    /* \~english
     * A bounded wait needs the extended argument, which carries a deadline.
     * Without it the only two waits a ring offers are "do not wait" and "wait
     * for ever", and a loop that has deadlines of its own needs a third.
     * \~spanish
     * Una espera acotada necesita el argumento extendido, que lleva un plazo.  Sin
     * el, las dos unicas esperas que ofrece un anillo son "no esperes" y "espera
     * para siempre", y un bucle que tiene plazos propios necesita una tercera.
     * \~ */
    if (want != 0 && timeout_ms >= 0 && ring_->ext_arg) {
        __kernel_timespec ts;
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = static_cast<long long>(timeout_ms % 1000) * 1000000LL;

        io_uring_getevents_arg arg;
        util::vesta_memset(&arg, 0, sizeof arg);
        arg.ts = reinterpret_cast<uint64_t>(&ts);

        flags |= IORING_ENTER_EXT_ARG;
        return ring_enter(fd_, submit, want, flags, &arg, sizeof arg);
    }

    return ring_enter(fd_, submit, want, flags, nullptr, 0);
}

size_t UringBackend::wait(Completion *out, size_t cap, int timeout_ms) noexcept {
    size_t made = 0;

    while (made < cap && made < failed_count_) {
        out[made] = failed_[made];
        ++made;
    }

    if (made != 0) {
        for (size_t i = made; i < failed_count_; ++i)
            failed_[i - made] = failed_[i];
        failed_count_ -= made;
    }

    if (ring_ == nullptr || made == cap) return made;

    /* \~english
     * What is already in the completion ring is taken FIRST, and only then is
     * the kernel entered.  Entering when there is already work to report would
     * be a system call spent asking for what is in hand -- which is the one
     * thing this backend exists to avoid.
     * \~spanish
     * Lo que ya esta en el anillo de finalizaciones se coge PRIMERO, y solo
     * despues se entra al nucleo.  Entrar cuando ya hay trabajo del que informar
     * seria una llamada al sistema gastada en pedir lo que se tiene en la mano --
     * que es justo lo que este backend existe para evitar.
     * \~ */
    uint32_t head = *ring_->cq_head;
    uint32_t tail = load_acquire(ring_->cq_tail);

    if (head == tail) {
        /* \~english
         * Nothing to report, so this is the moment to hand over everything
         * waiting AND ask to be woken -- in one call, which is the shape of
         * the whole backend.
         * \~spanish
         * Nada de lo que informar, asi que este es el momento de entregar todo lo
         * que espera Y pedir que te despierten -- en una llamada, que es la forma
         * de todo el backend.
         * \~ */
        const int r = enter(1, timeout_ms);
        if (r < 0 && errno != EINTR && errno != ETIME) last_error_ = errno;

        head = *ring_->cq_head;
        tail = load_acquire(ring_->cq_tail);
    } else if (waiting_ != 0) {
        /* \~english
         * There IS something to report, so nothing is waited for -- but what
         * is written and not handed over goes now anyway.  Leaving it would be
         * operations sitting in a ring the kernel has not been told about,
         * which is how a busy server comes to a stop with a full queue.
         * \~spanish
         * SI hay de lo que informar, asi que no se espera nada -- pero lo escrito
         * y sin entregar se va igual.  Dejarlo seria tener operaciones en un
         * anillo del que no se le ha hablado al nucleo, que es como un servidor
         * con trabajo se para con la cola llena.
         * \~ */
        enter(0, 0);
    }

    while (made < cap && head != tail) {
        const io_uring_cqe &cqe = ring_->cqes[head & ring_->cq_mask];

        const uint64_t which = cqe.user_data;
        const int32_t res = cqe.res;

        ++head;

        if (which >= slot_count_) continue;

        Slot *slot = &slots_[which];
        if (!slot->busy) continue;

        const Op op = slot->op;
        give(slot);

        Completion done;
        done.conn = op.conn;
        done.kind = op.kind;
        done.buffer = op.buffer;
        done.fd = -1;

        if (op.kind == OpKind::Accept) {
            done.result = res < 0 ? -1 : 0;
            done.fd = res < 0 ? -1 : res;
        } else if (op.kind == OpKind::Ready) {
            /* \~english
             * A poll comes back with the events that happened, which is a
             * positive number and not a count of bytes.  It is turned into the
             * plain "go ahead" this interface uses, because a caller that read
             * it as a length would believe a connection had said something
             * before anything was read.
             * \~spanish
             * Un sondeo vuelve con los sucesos que ocurrieron, que es un numero
             * positivo y no una cuenta de bytes.  Se convierte en el "adelante"
             * pelado que usa esta interfaz, porque quien lo leyera como una
             * longitud creeria que una conexion dijo algo antes de haber leido
             * nada.
             * \~ */
            done.result = res < 0 ? -1 : 0;
        } else {
            done.result = res;

            if (res > 0 && (op.kind == OpKind::Recv ||
                            op.kind == OpKind::RecvFrom)) {
                Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
                if (b != nullptr) b->commit(static_cast<size_t>(res));
            }
        }

        out[made] = done;
        ++made;
    }

    /* \~english
     * And the head is published, which is what gives those entries back to the
     * kernel.  Not doing it fills the ring with completions nobody claimed,
     * and the kernel stops being able to report anything.
     * \~spanish
     * Y se publica la cabeza, que es lo que le devuelve esas entradas al nucleo.
     * No hacerlo llena el anillo de finalizaciones que no reclamo nadie, y el
     * nucleo deja de poder informar de nada.
     * \~ */
    store_release(ring_->cq_head, head);

    return made;
}

} // namespace http_vx
