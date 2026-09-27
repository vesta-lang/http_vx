/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/stdio_wake.cpp
 * @brief
 * \~english A stdio backend that another thread can wake: the pipe read by a helper, as IOCP would, and events to wait on.
 * \~spanish Un backend de stdio que otro hilo puede despertar: la tuberia la lee un auxiliar, como lo haria IOCP, y sucesos por los que esperar.
 * \~
 *
 * \~english
 * HVX-5, 6.4.  An anonymous pipe cannot be read asynchronously -- and it
 * cannot be reopened for it either: `ReOpenFile` refuses it
 * (`ERROR_PIPE_BUSY`).  Worse, every operation on a synchronous handle holds
 * its file object's lock: while one thread is inside `ReadFile` on the pipe,
 * ANY other call on it -- `PeekNamedPipe` included -- waits for that read.
 * Both were measured here.
 *
 * So one thread, and only one, touches the input pipe: a helper that is to
 * this backend what the kernel is to IOCP.  The shard hands it a read -- the
 * room already reserved in the operation's buffer, which from then on is the
 * helper's, exactly as a buffer handed to IOCP is the kernel's -- and waits
 * on two events: "read done" and a wake, with the deadline it was given.  A
 * wake is `SetEvent`: any thread, no spinning, nothing cancelled.  A read cut
 * short by a wake stays in flight and is waited for again on the next wait.
 *
 * Cancelling the shard's own blocking read from the waking thread -- libuv's
 * `CancelSynchronousIo` protocol applied to the shard -- was tried and is
 * wrong: between seeing "blocking" and cancelling, the shard may have moved
 * on to a synchronous WRITE on the output pipe, and the cancel aborts it.
 * The helper does nothing but read, so the one cancel left -- on shutdown,
 * of the helper -- cannot hit anything else.
 *
 * One helper per stdio backend, and a stdio backend serves one conversation
 * per process.
 *
 * \~spanish
 * HVX-5, 6.4.  Una tuberia anonima no se puede leer de forma asincrona -- ni
 * reabrir para ello: `ReOpenFile` la rechaza (`ERROR_PIPE_BUSY`).  Peor: toda
 * operacion sobre un handle sincrono coge el cerrojo de su objeto de fichero:
 * mientras un hilo esta dentro de `ReadFile` sobre la tuberia, CUALQUIER otra
 * llamada sobre ella -- `PeekNamedPipe` incluida -- espera a esa lectura.  Las
 * dos cosas se midieron aqui.
 *
 * Asi que un hilo, y solo uno, toca la tuberia de entrada: un auxiliar que es
 * para este backend lo que el nucleo es para IOCP.  El fragmento le da una
 * lectura -- el sitio ya reservado en el buffer de la operacion, que desde ese
 * momento es del auxiliar, exactamente como un buffer entregado a IOCP es del
 * nucleo -- y espera por dos sucesos: "lectura hecha" y un despertar, con el
 * plazo que le dieron.  Un despertar es `SetEvent`: cualquier hilo, sin vueltas,
 * sin cancelar nada.  Una lectura cortada por un despertar sigue en vuelo y se
 * vuelve a esperar en la espera siguiente.
 *
 * Cancelar la lectura bloqueada del propio fragmento desde el hilo que
 * despierta -- el protocolo de `CancelSynchronousIo` de libuv aplicado al
 * fragmento -- se probo y esta mal: entre ver "bloqueado" y cancelar, el
 * fragmento puede haber pasado a una ESCRITURA sincrona en la tuberia de
 * salida, y la cancelacion la aborta.  El auxiliar no hace nada mas que leer,
 * asi que la unica cancelacion que queda -- al cerrar, del auxiliar -- no puede
 * dar con nada mas.
 *
 * Un auxiliar por backend de stdio, y un backend de stdio sirve una
 * conversacion por proceso.
 * \~
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif

#include <windows.h>

#include <io.h>

#include "http_vx/stdio_backend.h"

#include "util/alloc/host_allocator.h"

namespace http_vx {

namespace {

/**
 * @brief
 * \~english What the helper shares with the shard: the pipe, the read handed over, and its events.
 * \~spanish Lo que el auxiliar comparte con el fragmento: la tuberia, la lectura entregada, y sus sucesos.
 * \~
 *
 * \~english
 * The request and the result travel through the two auto-reset events: the
 * shard writes the request BEFORE setting "read this", the helper writes the
 * result BEFORE setting "read done" -- `SetEvent` and a satisfied wait order
 * memory, so plain fields are enough.
 * \~spanish
 * La peticion y el resultado viajan por los dos sucesos de reinicio automatico:
 * el fragmento escribe la peticion ANTES de poner "lee esto", el auxiliar
 * escribe el resultado ANTES de poner "lectura hecha" -- `SetEvent` y una
 * espera satisfecha ordenan la memoria, asi que bastan campos corrientes.
 * \~
 */
struct Helper {
    HANDLE pipe;
    HANDLE request;
    HANDLE done;
    uint8_t **room;
    uint32_t *len;
    long *result;
    std::atomic<bool> *stopping;
};

/**
 * @brief
 * \~english The helper: wait to be handed a read, read, say it is done.
 * \~spanish El auxiliar: esperar a que le den una lectura, leer, decir que esta hecha.
 * \~
 */
DWORD WINAPI read_pipe(void *arg) {
    Helper *h = static_cast<Helper *>(arg);
    for (;;) {
        WaitForSingleObject(h->request, INFINITE);
        if (h->stopping->load(std::memory_order_acquire)) break;
        DWORD got = 0;
        const BOOL ok = ReadFile(h->pipe, *h->room, *h->len, &got, nullptr);
        if (ok != FALSE) {
            *h->result = static_cast<long>(got);
        } else {
            const DWORD e = GetLastError();
            // \~english The peer closed its end: the end of the stream, as a read of zero says.
            // \~spanish El otro extremo cerro su lado: el final del flujo, como dice una lectura de cero.  \~
            *h->result = (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF) ? 0 : -1;
        }
        if (h->stopping->load(std::memory_order_acquire)) break;
        SetEvent(h->done);
    }
    util::host_free(h);
    return 0;
}

} // namespace

StdioBackend::StdioBackend(BufferPool &pool, int in, int out) noexcept
    : pool_(&pool), in_(in), out_(out) {
    wake_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    request_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    done_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    const HANDLE pipe = reinterpret_cast<HANDLE>(_get_osfhandle(in_));
    if (wake_event_ == nullptr || request_event_ == nullptr || done_event_ == nullptr ||
        pipe == INVALID_HANDLE_VALUE) {
        wake_error_.store(static_cast<int32_t>(GetLastError()), std::memory_order_relaxed);
        return;
    }
    Helper *h = static_cast<Helper *>(util::host_alloc(sizeof(Helper)));
    if (h == nullptr) return;
    h->pipe = pipe;
    h->request = static_cast<HANDLE>(request_event_);
    h->done = static_cast<HANDLE>(done_event_);
    h->room = &read_room_;
    h->len = &read_len_;
    h->result = &read_result_;
    h->stopping = &stopping_;
    helper_ = CreateThread(nullptr, 64 * 1024, read_pipe, h, 0, nullptr);
    if (helper_ == nullptr) {
        wake_error_.store(static_cast<int32_t>(GetLastError()), std::memory_order_relaxed);
        util::host_free(h);
    }
}

StdioBackend::~StdioBackend() {
    if (helper_ != nullptr) {
        const HANDLE t = static_cast<HANDLE>(helper_);
        stopping_.store(true, std::memory_order_release);
        SetEvent(static_cast<HANDLE>(request_event_));
        // \~english The helper does nothing but read, so cancelling it cannot hit anything else.
        // \~spanish El auxiliar no hace nada mas que leer, asi que cancelarlo no puede dar con nada mas.  \~
        while (WaitForSingleObject(t, 10) == WAIT_TIMEOUT) CancelSynchronousIo(t);
        CloseHandle(t);
    }
    if (wake_event_ != nullptr) CloseHandle(static_cast<HANDLE>(wake_event_));
    if (request_event_ != nullptr) CloseHandle(static_cast<HANDLE>(request_event_));
    if (done_event_ != nullptr) CloseHandle(static_cast<HANDLE>(done_event_));
}

bool StdioBackend::ready() const noexcept { return helper_ != nullptr; }

bool StdioBackend::wake() noexcept {
    if (wake_event_ == nullptr) return false;
    if (SetEvent(static_cast<HANDLE>(wake_event_)) != FALSE) return true;
    wake_error_.store(static_cast<int32_t>(GetLastError()), std::memory_order_relaxed);
    return false;
}

long StdioBackend::read_or_wake(uint8_t *room, uint32_t n, int timeout_ms, bool &woken) noexcept {
    woken = false;
    if (helper_ == nullptr) return -1;

    /* \~english
     * A read already in flight -- cut short by a wake before -- keeps its
     * room: the helper is writing into it.  The room offered now is the same
     * reservation, since nothing was committed in between.
     * \~spanish
     * Una lectura ya en vuelo -- cortada antes por un despertar -- conserva su
     * sitio: el auxiliar esta escribiendo en el.  El sitio que se ofrece ahora
     * es la misma reserva, porque no se confirmo nada entre medias.
     * \~ */
    if (!read_in_flight_) {
        read_room_ = room;
        read_len_ = n;
        read_in_flight_ = true;
        SetEvent(static_cast<HANDLE>(request_event_));
    }

    // \~english The wake first: with both set, the lower index is returned and only it is reset.
    // \~spanish El despertar primero: con los dos puestos, se devuelve el indice menor y solo el se reinicia.  \~
    const HANDLE events[2] = {static_cast<HANDLE>(wake_event_), static_cast<HANDLE>(done_event_)};
    const DWORD r = WaitForMultipleObjects(2, events, FALSE,
                                           timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms));
    if (r == WAIT_OBJECT_0 + 1) {
        read_in_flight_ = false;
        return read_result_;
    }
    if (r == WAIT_OBJECT_0 || r == WAIT_TIMEOUT) {
        woken = true;
        return 0;
    }
    wake_error_.store(static_cast<int32_t>(GetLastError()), std::memory_order_relaxed);
    return -1;
}

} // namespace http_vx
