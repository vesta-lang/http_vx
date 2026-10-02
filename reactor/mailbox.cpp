/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/mailbox.cpp
 * @brief
 * \~english The mailbox stack, and the sender's pool of messages with its return path.
 * \~spanish La pila del buzon, y el pozo de mensajes del remitente con su camino de vuelta.
 * \~
 */
#include "http_vx/mailbox.h"

#include "util/alloc/alloc_tag.h"
#include "util/alloc/host_allocator.h"

namespace http_vx {

void Mailbox::reset(ShardWake &wake) noexcept {
    wake_ = &wake;
    head_.store(nullptr, std::memory_order_relaxed);
    received_.store(0, std::memory_order_relaxed);
    for (size_t i = 0; i < kMailKinds; ++i) by_kind_[i].store(0, std::memory_order_relaxed);
}

bool Mailbox::push(MailNode &n) noexcept {
    MailNode *h = head_.load(std::memory_order_relaxed);
    do {
        n.next = h;
    } while (!head_.compare_exchange_weak(h, &n, std::memory_order_seq_cst,
                                          std::memory_order_relaxed));

    // \~english Dekker's second half: the push above, THEN "is it sleeping" (shard_wake.h).
    // \~spanish La segunda mitad de Dekker: el push de arriba, DESPUES "esta durmiendo" (shard_wake.h).  \~
    return wake_ != nullptr && wake_->notify();
}

MailNode *Mailbox::take_all() noexcept {
    MailNode *list = head_.exchange(nullptr, std::memory_order_acquire);

    // \~english A stack comes out last first: turned round, the first sent is served first.
    // \~spanish Una pila sale al reves: dada la vuelta, el primero mandado se atiende primero.  \~
    MailNode *ordered = nullptr;
    while (list != nullptr) {
        MailNode *next = list->next;
        list->next = ordered;
        ordered = list;
        list = next;

        bump(received_);
    }

    // \~english The kinds are counted as the shard handles each one: here only what came out.
    // \~spanish Los tipos se cuentan cuando el fragmento atiende cada uno: aqui solo lo que salio.  \~
    for (const MailNode *p = ordered; p != nullptr; p = p->next) bump(by_kind_[static_cast<size_t>(p->kind)]);
    return ordered;
}

MailboxCounts Mailbox::counts() const noexcept {
    MailboxCounts c;
    c.received = received_.load(std::memory_order_relaxed);
    for (size_t i = 0; i < kMailKinds; ++i) c.by_kind[i] = by_kind_[i].load(std::memory_order_relaxed);
    return c;
}

MailPool::~MailPool() { release(); }

bool MailPool::reset(uint32_t nodes) noexcept {
    release();
    if (nodes == 0) return true;

    const util::AllocScope scope(util::AllocUse::Long, util::AllocShape::Fixed,
                                 util::AllocFill::Sparse);

    nodes_ = static_cast<MailNode *>(util::host_alloc(static_cast<size_t>(nodes) * sizeof(MailNode)));
    if (nodes_ == nullptr) return false;

    capacity_ = nodes;
    for (uint32_t i = 0; i < nodes; ++i) {
        MailNode &n = nodes_[i];
        n.home = this;
        n.kind = MailKind::Stop;
        n.fd = -1;
        n.next = free_head_;
        free_head_ = &n;
    }
    free_ = nodes;
    sent_.store(0, std::memory_order_relaxed);
    refused_.store(0, std::memory_order_relaxed);
    returned_count_.store(0, std::memory_order_relaxed);
    return true;
}

size_t MailPool::release() noexcept {
    if (nodes_ == nullptr) return 0;

    reclaim();
    if (free_ != capacity_) return capacity_ - free_;

    util::host_free(nodes_);
    nodes_ = nullptr;
    capacity_ = 0;
    free_head_ = nullptr;
    free_ = 0;
    return 0;
}

size_t MailPool::reclaim() noexcept {
    MailNode *list = returned_.exchange(nullptr, std::memory_order_acquire);
    size_t n = 0;
    while (list != nullptr) {
        MailNode *next = list->next;
        list->next = free_head_;
        free_head_ = list;
        list = next;
        ++n;
    }
    free_ += static_cast<uint32_t>(n);
    for (size_t i = 0; i < n; ++i) bump(returned_count_);
    return n;
}

bool MailPool::send(Mailbox &to, MailKind kind, int32_t fd) noexcept {
    // \~english What came back since last time is free again; only now, so a quiet sender touches nothing.
    // \~spanish Lo que volvio desde la ultima vez vuelve a estar libre; solo ahora, para que un remitente callado no toque nada.  \~
    if (free_head_ == nullptr) reclaim();

    if (free_head_ == nullptr) {
        bump(refused_);
        return false;
    }

    MailNode *n = free_head_;
    free_head_ = n->next;
    --free_;

    n->kind = kind;
    n->fd = fd;
    bump(sent_);

    // \~english Pushed last: from here the receiver owns the node.
    // \~spanish Lo ultimo: desde aqui el nodo es del receptor.  \~
    to.push(*n);
    return true;
}

void MailPool::give_back(MailNode &n) noexcept {
    MailPool &home = *n.home;
    MailNode *h = home.returned_.load(std::memory_order_relaxed);
    do {
        n.next = h;
    } while (!home.returned_.compare_exchange_weak(h, &n, std::memory_order_release,
                                                   std::memory_order_relaxed));
}

MailPoolCounts MailPool::counts() const noexcept {
    MailPoolCounts c;
    c.sent = sent_.load(std::memory_order_relaxed);
    c.refused = refused_.load(std::memory_order_relaxed);
    c.returned = returned_count_.load(std::memory_order_relaxed);
    return c;
}

} // namespace http_vx
