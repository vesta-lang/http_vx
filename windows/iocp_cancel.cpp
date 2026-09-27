/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file windows/iocp_cancel.cpp
 * @brief
 * \~english Ending a read the peer would never complete, and only the read.
 * \~spanish Acabar una lectura que el otro extremo no completaria nunca, y solo la lectura.
 * \~
 *
 * \~english
 * OpKind::Cancel.  The read is found by its socket in @c reads_ and
 * `CancelIoEx` is given ITS overlapped: the packet then comes back as an
 * aborted operation through the ordinary completion path, with its buffer,
 * and the shard sees a failed read.  A read that finished meanwhile is not in
 * the index any more -- or `CancelIoEx` answers ERROR_NOT_FOUND -- and its
 * own completion arrives as it would have.
 *
 * \~spanish
 * OpKind::Cancel.  La lectura se encuentra por su socket en @c reads_ y a
 * `CancelIoEx` se le da SU overlapped: el paquete vuelve entonces como operacion
 * abortada por el camino corriente de finalizaciones, con su buffer, y el
 * fragmento ve una lectura fallida.  Una lectura que acabo entre medias ya no
 * esta en el indice -- o `CancelIoEx` contesta ERROR_NOT_FOUND -- y su propia
 * finalizacion llega como habria llegado.
 * \~
 */

#include "iocp_context.h"

namespace http_vx {

void IocpBackend::note_read(const Context *c) noexcept {
    reads_.insert(static_cast<uint32_t>(c->op.fd), static_cast<uint32_t>(c - contexts_));
}

void IocpBackend::forget_read(const Context *c) noexcept {
    const uint64_t id = static_cast<uint32_t>(c->op.fd);
    if (reads_.find(id) == static_cast<uint32_t>(c - contexts_)) reads_.erase(id);
}

bool IocpBackend::start_cancel(const Op &op) noexcept {
    if (op.fd < 0) return true;
    const uint32_t at = reads_.find(static_cast<uint32_t>(op.fd));
    if (at == IdIndex::kAbsent) return true;

    Context &c = contexts_[at];
    if (CancelIoEx(reinterpret_cast<HANDLE>(as_socket(op.fd)), &c.ov) == FALSE) {
        // \~english Not found is a read that already finished: its completion is on its way.
        // \~spanish No encontrada es una lectura que ya acabo: su finalizacion va de camino.  \~
        const DWORD e = GetLastError();
        if (e != ERROR_NOT_FOUND) last_error_ = static_cast<int32_t>(e);
    }
    return true;
}

} // namespace http_vx
