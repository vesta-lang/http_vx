/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_backend.cpp
 * @brief
 * \~english Operations handed to Windows, and results taken back in batches.
 * \~spanish Operaciones entregadas a Windows, y resultados recogidos en lotes.
 * \~
 */

/* \~english
 * Which Windows this is written against, and it has to be said BEFORE anything
 * else is included -- not before the Windows headers, before ANYTHING.  The
 * headers decide what exists by reading these two the first time any of them is
 * pulled in, and something as innocent as the allocator's header may pull one
 * in first: then the version is already settled, the batched dequeue and
 * `InetPton` are simply not declared, and the error says the name does not
 * exist rather than that it was ruled out.
 *
 * Vista, because that is where `GetQueuedCompletionStatusEx` arrives, and
 * taking completions one at a time is the thing R18 exists to avoid.
 *
 * \~spanish
 * Contra que Windows esta escrito esto, y hay que decirlo ANTES de incluir nada
 * -- no antes de las cabeceras de Windows, antes de NADA --.  Las cabeceras
 * deciden que existe leyendo estas dos la primera vez que se incluye cualquiera
 * de ellas, y algo tan inocente como la cabecera del asignador puede arrastrar
 * una primero: entonces la version ya esta decidida, la recogida en lote y
 * `InetPton` sencillamente no estan declaradas, y el error dice que el nombre no
 * existe en vez de que se descarto.
 *
 * Vista, porque es donde aparece `GetQueuedCompletionStatusEx`, y coger las
 * finalizaciones de una en una es justo lo que la R18 existe para evitar.
 * \~ */
#include "iocp_context.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"
#include "util/mem/vesta_memset.h"

#include <new>

namespace http_vx {

namespace {

/// \~english What a socket handle is when there is none.
/// \~spanish Lo que es un socket cuando no hay ninguno.  \~
constexpr uintptr_t kNoSocket = static_cast<uintptr_t>(INVALID_SOCKET);

} // namespace

IocpBackend::~IocpBackend() { release(); }

void IocpBackend::release() noexcept {
    if (listener_ != kNoSocket) {
        closesocket(static_cast<SOCKET>(listener_));
        listener_ = kNoSocket;
    }

    close_datagrams();

    /* \~english
     * The port is closed before the records are given back, and the order
     * matters: closing it releases every operation the kernel was still
     * holding, and a record freed while an operation named it would be the
     * kernel writing into memory that has gone.
     * \~spanish
     * El puerto se cierra antes de devolver los registros, y el orden importa:
     * cerrarlo suelta todas las operaciones que tuviera el nucleo, y un registro
     * liberado mientras lo nombrara una operacion seria el nucleo escribiendo en
     * una memoria que ya no esta.
     * \~ */
    if (iocp_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(iocp_));
        iocp_ = nullptr;
    }

    if (contexts_ != nullptr) {
        for (uint32_t i = 0; i < context_count_; ++i) {
            if (contexts_[i].sock != INVALID_SOCKET)
                closesocket(contexts_[i].sock);
            contexts_[i].~Context();
        }
        util::host_free(contexts_);
        contexts_ = nullptr;
    }

    context_count_ = 0;
    free_head_ = 0xFFFFFFFF;
    in_flight_ = 0;
    failed_count_ = 0;
    accept_fn_ = nullptr;
    port_ = 0;

    if (started_) {
        WSACleanup();
        started_ = false;
    }
}

bool IocpBackend::reset(BufferPool &pool, uint32_t pending) noexcept {
    release();

    if (pending == 0) return false;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        last_error_ = static_cast<int32_t>(GetLastError());
        return false;
    }
    started_ = true;

    pool_ = &pool;

    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (iocp_ == nullptr) {
        last_error_ = static_cast<int32_t>(GetLastError());
        release();
        return false;
    }

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    contexts_ = static_cast<Context *>(
        util::host_alloc(static_cast<size_t>(pending) * sizeof(Context)));
    if (contexts_ == nullptr) {
        release();
        return false;
    }

    context_count_ = pending;
    for (uint32_t i = 0; i < pending; ++i) {
        new (&contexts_[i]) Context();
        contexts_[i].sock = INVALID_SOCKET;
        contexts_[i].next = i + 1 == pending ? 0xFFFFFFFF : i + 1;
    }
    free_head_ = 0;

    return true;
}

bool IocpBackend::listen(const char *host, uint16_t port, int backlog) noexcept {
    if (iocp_ == nullptr) return false;

    const SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        return false;
    }

    sockaddr_in addr;
    util::vesta_memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (InetPtonA(AF_INET, host, &addr.sin_addr) != 1) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return false;
    }

    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr) ==
        SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return false;
    }

    if (::listen(s, backlog) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return false;
    }

    /* \~english
     * Which port it really got, asked of the socket rather than assumed.  A
     * caller that said zero meant "any", and the only place the answer exists
     * is here.
     * \~spanish
     * Que puerto le toco de verdad, preguntandoselo al socket en vez de darlo por
     * hecho.  Quien dijo cero queria decir "cualquiera", y el unico sitio donde
     * existe la respuesta es este.
     * \~ */
    int len = sizeof addr;
    if (getsockname(s, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
        port_ = ntohs(addr.sin_port);

    /* \~english
     * `AcceptEx` is not in any library: it is asked of the socket at run time,
     * because it belongs to the provider underneath and a different provider
     * may implement it elsewhere.  Windows has done it this way since Winsock
     * 2 and linking against a name would work on this machine and fail on
     * somebody else's.
     * \~spanish
     * `AcceptEx` no esta en ninguna biblioteca: se le pide al socket en ejecucion,
     * porque es del proveedor de debajo y otro proveedor puede tenerlo en otro
     * sitio.  Windows lo hace asi desde Winsock 2, y enlazar contra un nombre
     * funcionaria en esta maquina y fallaria en la de otro.
     * \~ */
    GUID id = WSAID_ACCEPTEX;
    LPFN_ACCEPTEX fn = nullptr;
    DWORD got = 0;

    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id, &fn,
                 sizeof fn, &got, nullptr, nullptr) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        closesocket(s);
        return false;
    }

    if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(s),
                               static_cast<HANDLE>(iocp_), 0, 0) == nullptr) {
        last_error_ = static_cast<int32_t>(GetLastError());
        closesocket(s);
        return false;
    }

    accept_fn_ = reinterpret_cast<void *>(fn);
    listener_ = static_cast<uintptr_t>(s);
    return true;
}

IocpBackend::Context *IocpBackend::take() noexcept {
    if (free_head_ == 0xFFFFFFFF) return nullptr;

    Context *c = &contexts_[free_head_];
    free_head_ = c->next;

    util::vesta_memset(&c->ov, 0, sizeof c->ov);
    c->sock = INVALID_SOCKET;
    ++in_flight_;
    return c;
}

void IocpBackend::give(Context *c) noexcept {
    c->sock = INVALID_SOCKET;
    c->next = free_head_;
    free_head_ = static_cast<uint32_t>(c - contexts_);
    --in_flight_;
}

bool IocpBackend::remember_failure(const Op &op, int32_t error) noexcept {
    if (failed_count_ == 64) return false;

    Completion &c = failed_[failed_count_];
    c.conn = op.conn;
    c.kind = op.kind;
    c.buffer = op.buffer;
    c.result = error;
    c.fd = -1;
    ++failed_count_;
    return true;
}

bool IocpBackend::start_accept(const Op &op, Context *c) noexcept {
    (void)op;

    if (listener_ == kNoSocket || accept_fn_ == nullptr) return false;

    c->sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                         WSA_FLAG_OVERLAPPED);
    if (c->sock == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        return false;
    }

    LPFN_ACCEPTEX fn = reinterpret_cast<LPFN_ACCEPTEX>(accept_fn_);
    DWORD got = 0;

    /* \~english
     * With a receive length of ZERO, which is the whole of the difference
     * between an accept and a security hole.  `AcceptEx` will happily wait for
     * the first bytes as part of accepting, and that is a connection that can
     * be opened and left silent to hold a socket, a record here and a buffer,
     * for as long as the peer likes -- with no deadline on it, because the
     * deadline belongs to a connection this end has not been told about yet.
     *
     * \~spanish
     * Con longitud de recepcion CERO, que es toda la diferencia entre una
     * aceptacion y un agujero de seguridad.  `AcceptEx` espera tan contento los
     * primeros bytes como parte de aceptar, y eso es una conexion que se puede
     * abrir y dejar callada para retener un socket, un registro de aqui y un
     * buffer, todo el tiempo que quiera el otro extremo -- y sin ningun plazo
     * encima, porque el plazo es de una conexion de la que a este extremo
     * todavia no le han hablado.
     * \~ */
    if (fn(static_cast<SOCKET>(listener_), c->sock, c->addrs, 0,
           static_cast<DWORD>(kAddressRoom), static_cast<DWORD>(kAddressRoom),
           &got, &c->ov) == FALSE) {
        const int e = WSAGetLastError();
        if (e != ERROR_IO_PENDING) {
            last_error_ = e;
            closesocket(c->sock);
            c->sock = INVALID_SOCKET;
            return false;
        }
    }

    return true;
}

bool IocpBackend::start_ready(const Op &op, Context *c) noexcept {
    if (op.fd < 0) return false;

    /* \~english
     * A receive of ZERO bytes into nothing.  Windows finishes it when the
     * socket has something to give -- or when the peer closes, which is also
     * something to find out -- and it is the whole of R1 on this platform: the
     * question "is there anything" asked without the sixteen kilobytes that
     * asking "what is it" would cost.
     *
     * The buffer is a real address with a length of zero rather than null,
     * because the provider is entitled to look at the array even when it is
     * told there is nothing in it, and one of them does.
     *
     * \~spanish
     * Una recepcion de CERO bytes en nada.  Windows la acaba cuando el socket
     * tiene algo que dar -- o cuando el otro extremo cierra, que tambien es algo
     * que hay que saber -- y es toda la R1 en esta plataforma: la pregunta "hay
     * algo" hecha sin los dieciseis kilobytes que costaria preguntar "que es".
     *
     * El buffer es una direccion de verdad con longitud cero y no un nulo, porque
     * el proveedor tiene derecho a mirar el array aunque le digan que no lleva
     * nada, y alguno lo hace.
     * \~ */
    WSABUF wsa;
    wsa.len = 0;
    wsa.buf = reinterpret_cast<CHAR *>(c->addrs);

    DWORD flags = 0;
    DWORD moved = 0;

    if (WSARecv(as_socket(op.fd), &wsa, 1, &moved, &flags, &c->ov, nullptr) ==
        SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            last_error_ = e;
            return false;
        }
    }

    return true;
}

bool IocpBackend::start_recv(const Op &op, Context *c) noexcept {
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
    if (b == nullptr || op.fd < 0) return false;

    /* \~english
     * The room is reserved NOW, before there is anything to put in it, because
     * the address is what is being handed over.  That is the whole shape of a
     * completion interface -- and it is also why the buffer may not be touched
     * again until the completion arrives: from here on the kernel is holding
     * this pointer.
     * \~spanish
     * El sitio se reserva AHORA, antes de que haya nada que poner en el, porque
     * lo que se esta entregando es la direccion.  Esa es toda la forma de una
     * interfaz por finalizacion -- y es tambien la razon de que no se pueda
     * volver a tocar el buffer hasta que llegue la finalizacion: a partir de aqui
     * el nucleo tiene este puntero.
     * \~ */
    uint8_t *room = b->reserve(op.length);
    if (room == nullptr) return false;

    WSABUF wsa;
    wsa.len = op.length;
    wsa.buf = reinterpret_cast<CHAR *>(room);

    DWORD flags = 0;
    DWORD moved = 0;

    if (WSARecv(as_socket(op.fd), &wsa, 1, &moved, &flags, &c->ov, nullptr) ==
        SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            last_error_ = e;
            return false;
        }
    }

    return true;
}

bool IocpBackend::start_send(const Op &op, Context *c) noexcept {
    Buffer *b = pool_ == nullptr ? nullptr : pool_->at(op.buffer);
    if (b == nullptr || op.fd < 0) return false;
    if (op.offset + op.length > b->size()) return false;

    WSABUF wsa;
    wsa.len = op.length;
    wsa.buf = reinterpret_cast<CHAR *>(
        const_cast<uint8_t *>(b->data() + op.offset));

    DWORD moved = 0;

    if (WSASend(as_socket(op.fd), &wsa, 1, &moved, 0, &c->ov, nullptr) ==
        SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            last_error_ = e;
            return false;
        }
    }

    return true;
}

bool IocpBackend::start_close(const Op &op) noexcept {
    if (op.fd >= 0) {
        dgram_.remove(op.fd);
        closesocket(as_socket(op.fd));
    }

    /* \~english
     * Closing is the one operation that finishes where it is asked for: there
     * is no packet to wait for, because there is nothing left to wait on.  The
     * completion is still produced, because whoever asked is entitled to be
     * told what became of what they asked -- and a backend that answered some
     * operations and not others would make the loop remember which.
     * \~spanish
     * Cerrar es la unica operacion que acaba donde se pide: no hay ningun paquete
     * que esperar, porque no queda nada a lo que esperar.  La finalizacion se
     * produce igual, porque quien la pidio tiene derecho a que le digan en que
     * quedo lo que pidio -- y un backend que contestara unas operaciones y otras
     * no obligaria al bucle a acordarse de cuales.
     * \~ */
    return remember_failure(op, 0);
}

bool IocpBackend::submit(const Op &op) noexcept {
    if (iocp_ == nullptr) return false;

    if (op.kind == OpKind::Close) return start_close(op);

    Context *c = take();
    if (c == nullptr) return false;

    c->op = op;

    bool started = false;

    switch (op.kind) {
    case OpKind::Accept:
        started = start_accept(op, c);
        break;

    case OpKind::Ready:
        started = start_ready(op, c);
        break;

    case OpKind::Recv:
        started = start_recv(op, c);
        break;

    case OpKind::Send:
        started = start_send(op, c);
        break;

    case OpKind::RecvFrom:
        started = start_recv_from(op, c);
        break;

    case OpKind::SendTo:
        started = start_send_to(op, c);
        break;

    case OpKind::Close:
        break;
    }

    if (started) return true;

    /* \~english
     * It never began, so there will be no packet and the caller has to be told
     * here.  @c submit returning false would say something else -- "no room to
     * ask" -- which the caller answers by asking again, and an operation that
     * cannot start would then be asked for for ever.
     * \~spanish
     * No llego a empezar, asi que no va a haber ningun paquete y hay que decirlo
     * aqui.  Que @c submit devolviera false diria otra cosa -- "no hay sitio para
     * pedirlo" -- que quien llama contesta volviendo a pedirlo, y una operacion
     * que no puede empezar se pediria entonces para siempre.
     * \~ */
    give(c);
    return remember_failure(op, -1);
}

size_t IocpBackend::wait(Completion *out, size_t cap, int timeout_ms) noexcept {
    size_t made = 0;

    /* \~english
     * What failed before it began goes first, and it goes even when the port
     * has nothing: those completions are owed to a caller that is holding a
     * buffer, and making them wait for an unrelated packet would be making a
     * failure depend on somebody else's traffic.
     * \~spanish
     * Lo que fallo antes de empezar va primero, y va aunque el puerto no tenga
     * nada: esas finalizaciones se le deben a quien tiene un buffer en la mano, y
     * hacerlas esperar a un paquete que no tiene nada que ver seria hacer que un
     * fallo dependa del trafico de otro.
     * \~ */
    while (made < cap && made < failed_count_) {
        out[made] = failed_[made];
        ++made;
    }

    if (made != 0) {
        for (size_t i = made; i < failed_count_; ++i)
            failed_[i - made] = failed_[i];
        failed_count_ -= made;
    }

    if (iocp_ == nullptr || made == cap) return made;

    OVERLAPPED_ENTRY entries[64];
    ULONG room = static_cast<ULONG>(cap - made);
    if (room > 64) room = 64;

    ULONG got = 0;
    const DWORD ms = timeout_ms < 0 ? INFINITE
                                    : static_cast<DWORD>(timeout_ms);

    /* \~english
     * A batch, which is what R18 is about on this side.  Taking completions
     * one at a time is a system call each, and at the rate a loaded server
     * finishes operations that is the ceiling before anything this project
     * does becomes visible.
     * \~spanish
     * Un lote, que es de lo que va la R18 por este lado.  Coger las
     * finalizaciones de una en una es una llamada al sistema cada una, y al ritmo
     * al que acaba operaciones un servidor con trabajo eso es el techo antes de
     * que se vea nada de lo que hace este proyecto.
     * \~ */
    if (GetQueuedCompletionStatusEx(static_cast<HANDLE>(iocp_), entries, room,
                                    &got, ms, FALSE) == FALSE)
        return made;

    for (ULONG i = 0; i < got; ++i) {
        Context *c = reinterpret_cast<Context *>(entries[i].lpOverlapped);
        if (c == nullptr) continue;

        Completion done;
        done.conn = c->op.conn;
        done.kind = c->op.kind;
        done.buffer = c->op.buffer;
        done.fd = -1;

        const SOCKET on = c->op.kind == OpKind::Accept ? c->sock
                                                       : as_socket(c->op.fd);

        DWORD moved = 0;
        DWORD flags = 0;

        /* \~english
         * Whether it worked is ASKED, not deduced from the byte count.  Zero
         * bytes on a read is the peer closing its end -- an ordinary, correct
         * outcome -- and zero bytes on a failure looks exactly the same from
         * here.  A loop told the second was the first would carry on serving a
         * connection that had died.
         * \~spanish
         * Si funciono se PREGUNTA, no se deduce de la cuenta de bytes.  Cero bytes
         * en una lectura es el otro extremo cerrando su lado -- un resultado
         * corriente y correcto -- y cero bytes en un fallo se ve exactamente
         * igual desde aqui.  Un bucle al que le dijeran que lo segundo es lo
         * primero seguiria sirviendo una conexion que se habia muerto.
         * \~ */
        const BOOL fine =
            WSAGetOverlappedResult(on, &c->ov, &moved, FALSE, &flags);

        if (c->op.kind == OpKind::RecvFrom || c->op.kind == OpKind::SendTo) {
            done.result = finish_datagram(c, fine != FALSE, moved, flags);
        } else if (fine == FALSE) {
            done.result = -1;

            if (c->op.kind == OpKind::Accept && c->sock != INVALID_SOCKET)
                closesocket(c->sock);
        } else if (c->op.kind == OpKind::Accept) {
            /* \~english
             * An accepted socket knows nothing about the listener it came from
             * until it is told, and until then `getpeername` and half the
             * options on it do not work.  Then it is put on the port, because
             * a socket answers to one and only one.
             * \~spanish
             * Un socket aceptado no sabe nada del socket de escucha del que salio
             * hasta que se le dice, y hasta entonces `getpeername` y la mitad de
             * las opciones no funcionan sobre el.  Luego se pone en el puerto,
             * porque un socket responde a uno y solo uno.
             * \~ */
            const SOCKET from = static_cast<SOCKET>(listener_);
            setsockopt(c->sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                       reinterpret_cast<const char *>(&from), sizeof from);

            if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(c->sock),
                                       static_cast<HANDLE>(iocp_), 0,
                                       0) == nullptr) {
                closesocket(c->sock);
                done.result = -1;
            } else {
                done.fd = as_fd(c->sock);
                done.result = 0;
            }

            c->sock = INVALID_SOCKET;
        } else {
            done.result = static_cast<int32_t>(moved);

            /* \~english
             * And the bytes are made part of the buffer HERE, when it is known
             * how many arrived.  The room was reserved when the read was asked
             * for; what did not arrive is not part of anything.
             * \~spanish
             * Y los bytes se hacen parte del buffer AQUI, cuando se sabe cuantos
             * llegaron.  El sitio se reservo al pedir la lectura; lo que no llego
             * no es parte de nada.
             * \~ */
            if (moved != 0 && c->op.kind == OpKind::Recv) {
                Buffer *b = pool_ == nullptr ? nullptr : pool_->at(c->op.buffer);
                if (b != nullptr) b->commit(moved);
            }
        }

        give(c);

        out[made] = done;
        ++made;
    }

    return made;
}

} // namespace http_vx
