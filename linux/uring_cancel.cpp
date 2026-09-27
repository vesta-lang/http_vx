/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file linux/uring_cancel.cpp
 * @brief
 * \~english Ending the read a socket has with the kernel: one cancel entry, naming it exactly.
 * \~spanish Acabar la lectura que tiene un socket con el nucleo: una entrada de cancelacion, que la nombra exactamente.
 * \~
 *
 * \~english
 * A quiet connection has a read with the kernel -- a poll, or a receive --
 * that only its peer would complete, and a connection does not leave while
 * an operation of it is outstanding.  So closing it has to END that read.
 * Here the read is memory the kernel holds, and only the kernel can let it
 * go: an `IORING_OP_ASYNC_CANCEL` whose address is the read's number.  The
 * read then completes through its own slot with `-ECANCELED`, and its buffer
 * comes back with it -- which is the one thing the cancel may not take a
 * shortcut on, because until that completion the kernel may still write
 * there.
 *
 * \~spanish
 * Una conexion callada tiene una lectura con el nucleo -- un sondeo, o una
 * recepcion -- que solo completaria su otro extremo, y una conexion no se va
 * mientras tenga una operacion pendiente.  Asi que cerrarla tiene que ACABAR
 * esa lectura.  Aqui la lectura es memoria que tiene el nucleo, y solo el
 * nucleo puede soltarla: un `IORING_OP_ASYNC_CANCEL` cuya direccion es el
 * numero de la lectura.  La lectura acaba entonces por su propia casilla con
 * `-ECANCELED`, y su buffer vuelve con ella -- que es lo unico en lo que la
 * cancelacion no puede tomar un atajo, porque hasta esa finalizacion el nucleo
 * todavia puede escribir ahi.
 * \~
 */
#include "uring_ring.h"

#include "util/mem/vesta_memset.h"

namespace http_vx {

bool UringBackend::submit_cancel(const Op &op) noexcept {
    if (ring_ == nullptr) return false;

    /* \~english
     * No read on the socket -- it completed and its answer is on its way, or
     * there never was one -- is nothing to do, and costs no ring entry.
     * \~spanish
     * Sin lectura en el socket -- acabo y su respuesta va de camino, o no la
     * hubo nunca -- no hay nada que hacer, y no cuesta ninguna entrada del
     * anillo.
     * \~ */
    if (op.fd < 0) return true;
    const uint32_t index = reads_.find(static_cast<uint64_t>(op.fd));
    if (index == IdIndex::kAbsent) return true;

    Slot &read = slots_[index];

    /* \~english
     * Already being ended: a second cancel could only answer "not found",
     * and would be one more answer in a completion ring nobody counts it in.
     * \~spanish
     * Ya se esta acabando: una segunda cancelacion solo podria contestar "no
     * esta", y seria una respuesta mas en un anillo de finalizaciones donde no
     * la cuenta nadie.
     * \~ */
    if (read.cancelling) return true;

    /* \~english
     * Room in the submission ring, measured against what the kernel has read
     * (as in @c submit); none is a full queue, said as one: false, with
     * nothing done.
     *
     * And NOT a slot, nor a place counted against them, on purpose.  The
     * moment a shard most needs a cancel is when every slot is a read of an
     * idle connection whose deadline has passed -- refusing it then, for want
     * of a slot, is the hang this operation exists to end, back again at
     * scale.  The cancel's own answer can therefore find the completion ring
     * full, and the kernel keeps it rather than dropping it: that is
     * `IORING_FEAT_NODROP`, which came with 5.5, and this backend already
     * needs 5.6 for `IORING_OP_SEND` and `IORING_OP_RECV`.  How far over it
     * can go is bounded too: one cancel per read at a time (@c cancelling),
     * so never more answers than twice the slots, plus the wake read.
     *
     * \~spanish
     * Sitio en el anillo de entregas, medido contra lo que ha leido el nucleo
     * (como en @c submit); que no haya es una cola llena, dicho como tal: false,
     * sin hacer nada.
     *
     * Y NO una casilla, ni un sitio contado contra ellas, a proposito.  El
     * momento en que un fragmento mas necesita una cancelacion es cuando todas
     * las casillas son lecturas de conexiones calladas con el plazo vencido --
     * rechazarla entonces, por falta de casilla, es el cuelgue que esta
     * operacion existe para acabar, otra vez y a escala.  Asi que la respuesta
     * propia de la cancelacion puede encontrarse lleno el anillo de
     * finalizaciones, y el nucleo la guarda en vez de tirarla: eso es
     * `IORING_FEAT_NODROP`, que llego con la 5.5, y este backend ya necesita la
     * 5.6 para `IORING_OP_SEND` e `IORING_OP_RECV`.  Cuanto se puede pasar
     * tambien esta acotado: una cancelacion por lectura a la vez
     * (@c cancelling), asi que nunca mas respuestas que el doble de casillas,
     * mas la lectura de despertar.
     * \~ */
    const uint32_t tail = *ring_->sq_tail;
    const uint32_t head = ring_load_acquire(ring_->sq_head);
    if (tail - head >= ring_->sq_entries) return false;

    io_uring_sqe *sqe = &ring_->sqes[tail & ring_->sq_mask];
    util::vesta_memset(sqe, 0, sizeof *sqe);

    /* \~english
     * The address is the read's whole number, life included, and the kernel
     * matches all of it: a cancel that got there late cannot end whatever
     * took the slot afterwards.
     * \~spanish
     * La direccion es el numero entero de la lectura, vida incluida, y el
     * nucleo lo compara entero: una cancelacion que llegara tarde no puede
     * acabar lo que cogiera la casilla despues.
     * \~ */
    sqe->opcode = IORING_OP_ASYNC_CANCEL;
    sqe->fd = -1;
    sqe->addr = slot_user_data(index, read.life);
    sqe->user_data = kCancelData;

    ring_store_release(ring_->sq_tail, tail + 1);
    ++waiting_;
    read.cancelling = true;
    return true;
}

} // namespace http_vx
