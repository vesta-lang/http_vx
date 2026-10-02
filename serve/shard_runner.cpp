/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/shard_runner.cpp
 * @brief
 * \~english Building one shard on its own thread, and its loop.
 * \~spanish Construir un fragmento en su propio hilo, y su bucle.
 * \~
 */
#include "serve/shard_runner.h"

#include "serve/cpu_affinity.h"

#include <cstdio>

namespace serve {

bool ShardRunner::fail(const char *what) noexcept {
    std::snprintf(why_, sizeof why_, "%s", what);
    return false;
}

bool ShardRunner::build(const RunnerPlan &plan) noexcept {
    plan_ = plan;
    const Options &opt = *plan.options;

    /* \~english
     * Pinned FIRST: memory is placed where it is first touched (Linux) or at
     * the node of the thread's CPU, so everything below must come after.  A
     * refusal is said and the shard goes on unpinned: it still serves, only
     * without the placement (HVX-6, R44).
     * \~spanish
     * Fijado PRIMERO: la memoria se coloca donde se toca por primera vez
     * (Linux) o en el nodo de la CPU del hilo, asi que todo lo de abajo va
     * despues.  Un rechazo se dice y el fragmento sigue sin fijar: sirve igual,
     * solo que sin la colocacion (HVX-6, R44).
     * \~ */
    if (plan.pin) {
        pinned_ = pin_current_thread(plan.index, cpu_);
        if (!pinned_)
            std::fprintf(stderr, "http_vx: shard %u: the system refused to pin its thread to a CPU; it runs unpinned\n",
                         static_cast<unsigned>(plan.index));
    }

    http_vx::ShardConfig cfg;
    cfg.connections = 1024;
    cfg.buffers = 128;
    cfg.idle_ticks = 30;
    cfg.wheel_slots = 1024;

    /* \~english
     * A shard accepts nothing by default, because how accepting is spread
     * across shards is the platform's answer and not the shard's: here each
     * shard with a socket of its own accepts on it.  One without (Windows,
     * until its acceptor hands it sockets) has nothing to accept on.
     * \~spanish
     * Un fragmento no acepta nada por defecto, porque como se reparte aceptar
     * entre fragmentos es la respuesta de la plataforma y no del fragmento:
     * aqui cada fragmento con un socket propio acepta en el.  Uno sin socket
     * (Windows, hasta que su aceptador le pase sockets) no tiene donde aceptar.
     * \~ */
    cfg.accepts = plan.listening == Listening::Off ? 0 : 8;

    greeting_.events = plan.events;

    http_vx::h1::Limits h1;
    if (!service_.reset(cfg.connections, greeting_, h1)) return fail("no memory for the service");

    /* \~english
     * HTTPS, when asked for: the same handler behind HTTP/1.1 and HTTP/2, and
     * TLS in front choosing between them.  Asked for and impossible is a
     * server that does not start -- never one that serves in the clear (R24).
     * \~spanish
     * HTTPS, cuando se pide: el mismo manejador detras de HTTP/1.1 y HTTP/2, y
     * TLS delante eligiendo entre ellos.  Pedido e imposible es un servidor que
     * no arranca -- nunca uno que sirve en claro (R24).
     * \~ */
    http_vx::Service *front = &service_;
    if (opt.cert != nullptr) {
        if (!tls_setup_.load(opt.provider, opt.cert, opt.key, plan.ticket_key)) {
            std::snprintf(why_, sizeof why_, "cannot serve TLS: %s", tls_setup_.why());
            return false;
        }
        const http_vx::h2::Limits h2;
        http_vx::TlsServiceConfig tcfg;
        tcfg.crypto = tls_setup_.crypto();
        tcfg.http1 = &service_;
        tcfg.http2 = &h2_service_;
        tcfg.certificates = tls_setup_.certificates();
        tcfg.certificate_lens = tls_setup_.certificate_lens();
        tcfg.certificate_count = tls_setup_.certificate_count();
        tcfg.signing_key = tls_setup_.signing_key();
        tcfg.scheme = tls_setup_.scheme();
        tcfg.tickets = tls_setup_.tickets();
        tcfg.buffers = cfg.buffers;
        if (!h2_service_.reset(cfg.connections, 256, 1 << 20, greeting_, h2) ||
            !tls_service_.reset(cfg.connections, tcfg)) {
            std::snprintf(why_, sizeof why_, "cannot serve TLS: %s",
                          tls_service_.why() != nullptr ? tls_service_.why() : "no memory for HTTP/2");
            return false;
        }
        tls_service_.set_clock(now_us());
        front = &tls_service_;
        tls_ = true;
    }

    if (!reactors_.make(plan.backend, shard_.buffers(), cfg.connections, opt.host, plan.port, plan.listening)) {
        std::snprintf(why_, sizeof why_, "cannot listen on %s with %s (error %d)", endpoint(opt.host, plan.port).text,
                      plan.backend, reactors_.error());
        return false;
    }

    if (!shard_.reset(cfg, *reactors_.io(), *front, now_ticks())) return fail("no memory for the shard");

    // \~english HTTP/3: the same identity as TLS over TCP, on UDP at the port TCP got.
    // \~spanish HTTP/3: la misma identidad que TLS sobre TCP, sobre UDP en el puerto que obtuvo TCP.  \~
    if (plan.serves_h3) {
        http_vx::NetAddress bound;
        const int32_t udp = reactors_.open_udp(opt.host, reactors_.port(), bound);
        if (udp < 0) {
            std::snprintf(why_, sizeof why_, "cannot open UDP on %s (error %d)", endpoint(opt.host, reactors_.port()).text,
                          reactors_.error());
            return false;
        }
        http_vx::DatagramConfig dcfg;
        dcfg.receives = 16;
        if (!h3_.start(tls_setup_, greeting_, cfg.connections) || !shard_.attach_datagrams(h3_.datagrams(), dcfg) ||
            !shard_.add_datagram_socket(udp, bound)) {
            std::snprintf(why_, sizeof why_, "cannot serve HTTP/3: %s",
                          h3_.why() != nullptr ? h3_.why() : "the shard would not take the datagram side");
            return false;
        }
        h3_active_ = true;
        std::fprintf(stderr, "http_vx: HTTP/3 on udp %s, 0-RTT after the replay window (%llu s)\n",
                     endpoint(opt.host, reactors_.port()).text,
                     static_cast<unsigned long long>(H3Setup::kReplayWindowMs / 1000));
    }
    return true;
}

void ShardRunner::run() noexcept {
    uint64_t last = now_ticks();
    uint64_t printed = last;

    while (!shard_.stop_requested()) {
        /* \~english
         * The wait is BOUNDED rather than endless, and the bound is what makes
         * deadlines happen.  A loop that waited for ever would notice a
         * connection had gone quiet only when some OTHER connection woke it
         * up, so a server with nothing to do would never hang up on anybody --
         * and a server with nothing to do is exactly when the connections
         * piling up are the ones that stopped talking.
         *
         * \~spanish
         * La espera esta ACOTADA y no es infinita, y la cota es lo que hace que
         * los plazos ocurran.  Un bucle que esperara para siempre se enteraria de
         * que una conexion se ha callado solo cuando lo despertara OTRA, asi que
         * un servidor sin nada que hacer no le colgaria nunca a nadie -- y un
         * servidor sin nada que hacer es justo cuando las conexiones que se
         * amontonan son las que dejaron de hablar.
         * \~ */
        if (tls_) tls_service_.set_clock(now_us());
        // \~english QUIC's timers are finer than a tick: the wait ends when the next one is due.
        // \~spanish Los temporizadores de QUIC son mas finos que un tic: la espera acaba cuando vence el siguiente.  \~
        shard_.poll(now_ticks(), h3_active_ ? h3_.datagrams().wait_ms(250) : 250);
        if (tls_) report_.tls(tls_service_);
        if (h3_active_) report_.h3(h3_.service());

        const uint64_t now = now_ticks();
        if (now != last) {
            shard_.expire(now);
            last = now;
        }

        // \~english With several shards, a line of counters every ten seconds if anything moved: the imbalance is read by comparing them (HVX-6, 8).
        // \~spanish Con varios fragmentos, una linea de contadores cada diez segundos si algo se movio: el desequilibrio se lee comparandolos (HVX-6, 8).  \~
        if (plan_.count > 1 && now - printed >= 10) {
            printed = now;
            if (counts_moved()) print_counts("");
        }
    }
}

bool ShardRunner::counts_moved() noexcept {
    const http_vx::ShardCounts &c = shard_.counts();
    const uint64_t sum = c.accepted + c.accept_refused + c.mail_adopted + c.mail_adopt_refused +
                         shard_.mail_received().received + shard_.mail_pool().counts().sent +
                         shard_.mail_pool().counts().refused + static_cast<uint64_t>(shard_.conns().count());
    const bool moved = sum != last_moved_;
    last_moved_ = sum;
    return moved;
}

void ShardRunner::print_counts(const char *when) noexcept {
    const http_vx::ShardCounts &c = shard_.counts();
    const http_vx::MailPoolCounts s = shard_.mail_pool().counts();
    const http_vx::WakeCounts w = shard_.wake_counts();
    std::fprintf(stderr,
                 "http_vx: shard %u%s: accepted %llu (refused %llu), open %zu, adopted %llu (refused %llu), "
                 "mail sent %llu refused %llu received %llu, wakes %llu failed %llu\n",
                 static_cast<unsigned>(plan_.index), when, static_cast<unsigned long long>(c.accepted),
                 static_cast<unsigned long long>(c.accept_refused), shard_.conns().count(),
                 static_cast<unsigned long long>(c.mail_adopted), static_cast<unsigned long long>(c.mail_adopt_refused),
                 static_cast<unsigned long long>(s.sent), static_cast<unsigned long long>(s.refused),
                 static_cast<unsigned long long>(shard_.mail_received().received),
                 static_cast<unsigned long long>(w.wakes), static_cast<unsigned long long>(w.failed_wakes));
}

void ShardRunner::finish() noexcept {
    // \~english Final counters, before release clears them; with one shard there is nothing to compare, so nothing is said.
    // \~spanish Contadores finales, antes de que release los borre; con un fragmento no hay nada que comparar, asi que no se dice nada.  \~
    if (plan_.count > 1) print_counts(" (final)");

    // \~english A node still away keeps its block (mailbox.h): said, never silent.
    // \~spanish Un nodo que sigue fuera conserva su bloque (mailbox.h): se dice, nunca en silencio.  \~
    shard_.mail_pool().reclaim();
    const uint32_t away = shard_.mail_pool().capacity() - shard_.mail_pool().free_count();
    if (away != 0)
        std::fprintf(stderr, "http_vx: shard %u: %u mailbox node(s) never came back and their block was kept\n",
                     static_cast<unsigned>(plan_.index), static_cast<unsigned>(away));

    shard_.release();
}

} // namespace serve
