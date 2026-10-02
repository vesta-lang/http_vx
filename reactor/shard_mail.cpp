/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard_mail.cpp
 * @brief
 * \~english The shard's side of its mailbox: when it may sleep, what it does with each message, and how a socket is let go.
 * \~spanish El lado del buzon que le toca al fragmento: cuando puede dormir, que hace con cada mensaje, y como se suelta un socket.
 * \~
 */
#include "http_vx/shard.h"

namespace http_vx {

int Shard::wait_budget(int timeout_ms) noexcept {
    if (timeout_ms == 0) return 0;

    /* \~english
     * Dekker's first half, for BOTH stacks: publish "sleeping" ONCE, THEN look
     * at each of them.  A producer of either pushed before this store -- and
     * the look below sees it -- or after it, and its exchange sees the 1 and
     * wakes.  Looking at only one stack would leave a shard asleep with the
     * other's message waiting.
     * \~spanish
     * La primera mitad de Dekker, para las DOS pilas: publicar "durmiendo" UNA
     * vez, DESPUES mirar cada una.  Un productor de cualquiera metio antes de
     * esta escritura -- y la mirada de abajo lo ve -- o despues, y su
     * intercambio ve el 1 y despierta.  Mirar solo una pila dejaria al
     * fragmento dormido con el mensaje de la otra esperando.
     * \~ */
    wake_.publish_sleeping();
    if (kicks_.pending() || mail_.pending()) {
        wake_.cancel_sleeping();
        return 0;
    }
    return timeout_ms;
}

void Shard::close_socket(int32_t fd) noexcept {
    if (io_ == nullptr) return;

    Op shut;
    shut.kind = OpKind::Close;
    shut.buffer = kNoBuffer;
    shut.fd = fd;

    // \~english A refused close is a descriptor kept open: said, not dropped.
    // \~spanish Un cierre rechazado es un descriptor que sigue abierto: se dice, no se tira.  \~
    if (!io_->submit(shut)) ++counts_.unclosed;
}

void Shard::run_mail(uint64_t now) noexcept {
    MailNode *n = mail_.take_all();

    while (n != nullptr) {
        // \~english Read before the node goes back: from then on it is its sender's again.
        // \~spanish Se lee antes de devolver el nodo: desde entonces vuelve a ser de su remitente.  \~
        MailNode *next = n->next;
        const MailKind kind = n->kind;
        const int32_t fd = n->fd;
        MailPool::give_back(*n);
        n = next;

        switch (kind) {
        case MailKind::AdoptSocket: {
            /* \~english
             * A socket that does not fit is closed: the sender gave it up when
             * it sent it, and a socket dropped here is a descriptor leaked.
             * \~spanish
             * Un socket que no cabe se cierra: el remitente lo dio al mandarlo,
             * y un socket soltado aqui es un descriptor perdido.
             * \~ */
            const ConnHandle c = adopt(fd, now);
            if (c.valid()) {
                ++counts_.mail_adopted;
            } else {
                ++counts_.mail_adopt_refused;
                close_socket(fd);
            }
            break;
        }

        case MailKind::Stop:
            stop_requested_ = true;
            break;
        }
    }
}

void Shard::release_mail() noexcept {
    MailNode *n = mail_.take_all();
    while (n != nullptr) {
        MailNode *next = n->next;
        const MailKind kind = n->kind;
        const int32_t fd = n->fd;
        MailPool::give_back(*n);
        n = next;

        if (kind == MailKind::AdoptSocket) {
            ++counts_.mail_adopt_refused;
            close_socket(fd);
        }
    }

    // \~english A node still away keeps its block (mailbox.h): the owner reads how many before it comes here.
    // \~spanish Un nodo que sigue fuera conserva su bloque (mailbox.h): el dueno lee cuantos antes de llegar aqui.  \~
    mail_pool_.release();
}

} // namespace http_vx
