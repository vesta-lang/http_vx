/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/datagram.cpp
 * @brief
 * \~english The header in front of a datagram, written and read in one place.
 * \~spanish La cabecera delante de un datagrama, escrita y leida en un sitio.
 * \~
 */

#include "http_vx/datagram.h"

#include "util/mem/vesta_memcpy.h"

namespace http_vx {

bool same_net_address(const NetAddress &a, const NetAddress &b) noexcept {
    if (a.len != b.len) return false;
    for (size_t i = 0; i < a.len; ++i)
        if (a.bytes[i] != b.bytes[i]) return false;
    return true;
}

EcnMark ecn_from_tos(uint8_t tos) noexcept {
    /* \~english
     * RFC 3168, 5: 00 Not-ECT, 01 ECT(1), 10 ECT(0), 11 CE.  ECT(1) is the
     * SMALLER number, which is exactly the swap a raw pass-through would get
     * wrong.
     * \~spanish
     * RFC 3168, 5: 00 Not-ECT, 01 ECT(1), 10 ECT(0), 11 CE.  ECT(1) es el numero
     * MENOR, que es justo el cambio que se equivocaria pasando los bits tal cual.
     * \~ */
    switch (tos & 3u) {
    case 1:
        return EcnMark::Ect1;
    case 2:
        return EcnMark::Ect0;
    case 3:
        return EcnMark::Ce;
    default:
        return EcnMark::NotEct;
    }
}

uint8_t *datagram_reserve(Buffer &b, size_t room) noexcept {
    /* \~english
     * An empty buffer only.  A datagram appended behind another would have its
     * header in the middle of somebody else's bytes, and the reader that looks
     * for it at the front would find the first datagram's instead.
     * \~spanish
     * Solo un buffer vacio.  Un datagrama anadido detras de otro tendria su
     * cabecera en mitad de los bytes de otro, y el lector que la busca delante
     * encontraria la del primero.
     * \~ */
    if (!b.empty()) return nullptr;

    uint8_t *at = b.reserve(kDatagramHeaderRoom + room);
    if (at == nullptr) return nullptr;
    return at + kDatagramHeaderRoom;
}

void datagram_commit(Buffer &b, const DatagramHeader &h, size_t n) noexcept {
    util::vesta_memcpy(b.tail(), &h, sizeof h);
    b.commit(kDatagramHeaderRoom + n);
}

bool datagram_header(const Buffer &b, DatagramHeader &h) noexcept {
    if (b.size() < kDatagramHeaderRoom) return false;
    util::vesta_memcpy(&h, b.data(), sizeof h);
    return true;
}

bool DatagramSockets::add(int32_t fd, const NetAddress &bound) noexcept {
    if (count_ == kMaxDatagramSockets || fd < 0) return false;
    fd_[count_] = fd;
    bound_[count_] = bound;
    ++count_;
    return true;
}

void DatagramSockets::remove(int32_t fd) noexcept {
    const int32_t at = find(fd);
    if (at < 0) return;

    --count_;
    fd_[at] = fd_[count_];
    bound_[at] = bound_[count_];
}

int32_t DatagramSockets::find(int32_t fd) const noexcept {
    for (size_t i = 0; i < count_; ++i)
        if (fd_[i] == fd) return static_cast<int32_t>(i);
    return -1;
}

} // namespace http_vx
