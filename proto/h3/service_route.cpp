/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h3/service_route.cpp
 * @brief
 * \~english The HTTP/3 service's bookkeeping: a connection's routes in step with its IDs, and who has something to send.
 * \~spanish La contabilidad del servicio HTTP/3: las rutas de una conexion al dia con sus identificadores, y quien tiene algo que mandar.
 * \~
 *
 * \~english
 * The table itself is quic::CidRoutes (quic_routes.h); what is here is
 * knowing which IDs a connection has at a given moment.  It hands out new
 * ones and retires old ones as the peer asks (RFC 9000, 5.1), so after every
 * step the registered set is brought to the connection's -- a handful of IDs
 * each way, never the whole table.
 *
 * \~spanish
 * La tabla en si es quic::CidRoutes (quic_routes.h); lo que hay aqui es saber
 * que identificadores tiene una conexion en cada momento.  Reparte nuevos y
 * retira viejos segun pide el otro (RFC 9000, 5.1), asi que tras cada paso el
 * conjunto registrado se pone al dia con el de la conexion -- un punado de
 * identificadores en cada sentido, nunca la tabla entera.
 * \~
 */
#include "service_slot.h"

namespace http_vx {

namespace {

bool same_cid(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) noexcept {
    if (alen != blen) return false;
    for (size_t i = 0; i < alen; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

} // namespace

void Http3Service::sync_routes(uint32_t i, uint64_t now_us) noexcept {
    Slot &s = slots_[i];
    // \~english What should lead here now: the connection's active IDs, and the client's first.
    // \~spanish Lo que deberia llevar aqui ahora: los identificadores activos de la conexion, y el primero del cliente.  \~
    Cid want[kRoutes];
    size_t wanted = 0;
    uint64_t seq = 0;
    const uint8_t *cid = nullptr;
    const uint8_t *token = nullptr;
    const size_t len = cfg_.connection.local_cid_len;
    for (size_t k = 0; wanted < kRoutes - 1 && s.quic->local_cid(k, seq, cid, token); ++k) {
        for (size_t b = 0; b < len; ++b) want[wanted].bytes[b] = cid[b];
        want[wanted].len = static_cast<uint8_t>(len);
        ++wanted;
    }
    if (s.first.len != 0) want[wanted++] = s.first;

    // \~english Out what went, then in what came.  \~spanish Fuera lo que se fue, y dentro lo que vino.  \~
    for (size_t r = 0; r < s.route_count;) {
        bool keep = false;
        for (size_t w = 0; w < wanted && !keep; ++w)
            keep = same_cid(s.routes[r].bytes, s.routes[r].len, want[w].bytes, want[w].len);
        if (keep) {
            ++r;
            continue;
        }
        routes_.remove(s.routes[r].bytes, s.routes[r].len);
        s.routes[r] = s.routes[--s.route_count];
    }
    for (size_t w = 0; w < wanted; ++w) {
        bool have = false;
        for (size_t r = 0; r < s.route_count && !have; ++r)
            have = same_cid(s.routes[r].bytes, s.routes[r].len, want[w].bytes, want[w].len);
        if (have) continue;
        if (!routes_.add(want[w].bytes, want[w].len, i)) {
            // \~english An ID another connection holds: this one could get the other's packets, so it ends.
            // \~spanish Un identificador que tiene otra conexion: esta podria recibir los paquetes de la otra, asi que acaba.  \~
            s.quic->close(0x01, false, 0, now_us);
            continue;
        }
        s.routes[s.route_count++] = want[w];
    }
}

void Http3Service::queue_send(uint32_t i) noexcept {
    Slot &s = slots_[i];
    if (s.queued) return;
    s.queued = true;
    send_[(send_head_ + send_count_) % capacity_] = i;
    ++send_count_;
}

} // namespace http_vx
