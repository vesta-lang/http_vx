/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_wake.cpp
 * @brief
 * \~english Waking an IOCP backend from another thread: a packet with no operation behind it.
 * \~spanish Despertar un backend de IOCP desde otro hilo: un paquete sin operacion detras.
 * \~
 *
 * \~english
 * HVX-5, 6.4.  The packet names no record (a null `OVERLAPPED`), which is
 * how @c wait and the drain in @c release already tell a packet that is not
 * an operation.  How many can be pending is bounded by the kick queue, not
 * here: a shard is woken at most once per time it went to sleep.
 * \~spanish
 * HVX-5, 6.4.  El paquete no nombra ningun registro (un `OVERLAPPED` nulo), que
 * es como @c wait y el vaciado de @c release ya distinguen un paquete que no es
 * una operacion.  Cuantos puede haber pendientes lo acota la cola de avisos, no
 * esto: a un fragmento se le despierta como mucho una vez por cada vez que se
 * durmio.
 * \~
 */
#include "iocp_context.h"

namespace http_vx {

bool IocpBackend::wake() noexcept {
    void *port = iocp_;
    if (port == nullptr) return false;
    if (PostQueuedCompletionStatus(static_cast<HANDLE>(port), 0, 0, nullptr) != FALSE) return true;
    wake_error_.store(static_cast<int32_t>(GetLastError()), std::memory_order_relaxed);
    return false;
}

} // namespace http_vx
