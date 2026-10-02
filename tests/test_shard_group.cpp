/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_shard_group.cpp
 * @brief
 * \~english The runnable server's group of shards: the command line, the CPU pinning, N shards serving, and a start that fails.
 * \~spanish El grupo de fragmentos del servidor ejecutable: la linea de ordenes, el fijado a CPU, N fragmentos sirviendo, y un arranque que falla.
 * \~
 *
 * \~english
 * HVX-6, 3.  Whatever the platform, a group of three shards starts (each on
 * its own thread, building its own backend and services), answers a dozen
 * requests, and stops through the mailboxes with every thread joined.  A group
 * whose address is taken does NOT start, says why, and leaves no thread
 * behind.  On Windows only shard 0 listens until the acceptor exists
 * (HVX-6, 4.2); the others run without a socket, and the requests prove that
 * the one that listens is enough.
 * \~spanish
 * HVX-6, 3.  Sea cual sea la plataforma, un grupo de tres fragmentos arranca
 * (cada uno en su hilo, construyendo su propio backend y sus servicios),
 * contesta una docena de peticiones, y para por los buzones con cada hilo
 * esperado.  Un grupo cuya direccion esta cogida NO arranca, dice por que, y no
 * deja ningun hilo.  En Windows solo escucha el fragmento 0 hasta que exista el
 * aceptador (HVX-6, 4.2); los demas corren sin socket, y las peticiones prueban
 * que basta con el que escucha.
 * \~
 */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif
#include <winsock2.h>

#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "serve/cpu_affinity.h"
#include "serve/options.h"
#include "serve/shard_group.h"

#include <cstdio>
#include <cstring>
#include <thread>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/* ------------------------------------------------------------------------- *
 * The command line.
 * ------------------------------------------------------------------------- */

/// \~english Parses @p args as the program would be given them.  \~spanish Analiza @p args como se los daria el programa.  \~
serve::Options parse(std::initializer_list<const char *> args) {
    char *argv[16];
    int argc = 0;
    static char program[] = "http_vx_listen";
    argv[argc++] = program;
    for (const char *a : args) argv[argc++] = const_cast<char *>(a);
    serve::Options opt;
    opt.parse(argc, argv);
    return opt;
}

void test_the_shards_option() {
    check(parse({}).shards == 0 && parse({}).error == nullptr, "no --shards must mean 'one per CPU' (zero), without an error");
    check(parse({"--shards", "1"}).shards == 1, "--shards 1");
    check(parse({"--shards", "4", "127.0.0.1", "9"}).shards == 4, "--shards before the positionals");
    check(parse({"127.0.0.1", "9", "--shards", "7"}).shards == 7, "--shards after the positionals");
    check(parse({"--shards", "1024"}).shards == 1024, "the largest number of shards");
    check(parse({"--shards", "1025"}).error != nullptr, "more shards than the limit was taken");
    check(parse({"--shards", "0"}).error != nullptr, "zero shards was taken: it would mean 'default', which is not asked by writing 0");
    check(parse({"--shards", "-1"}).error != nullptr, "a negative number of shards was taken");
    check(parse({"--shards", "4x"}).error != nullptr, "a number followed by letters was taken");
    check(parse({"--shards", ""}).error != nullptr, "an empty number of shards was taken");
    check(parse({"--shards"}).error != nullptr, "--shards with no number was taken");
}

/* ------------------------------------------------------------------------- *
 * CPUs.
 * ------------------------------------------------------------------------- */

struct PinJob {
    bool pinned = false;
    uint32_t cpu = 0;
};

void pin_on_a_thread(PinJob *j) { j->pinned = serve::pin_current_thread(0, j->cpu); }

void test_cpus() {
    check(serve::usable_cpus() >= 1, "a process that may run on no CPU");

    // \~english On a thread of its own: pinning the test's main thread would pin everything else this process does.
    // \~spanish En un hilo propio: fijar el hilo principal de la prueba fijaria todo lo demas que hace este proceso.  \~
    PinJob j;
    std::thread t(pin_on_a_thread, &j);
    t.join();
    check(j.pinned, "the thread could not be pinned to the first allowed CPU");
}

/* ------------------------------------------------------------------------- *
 * The group.
 * ------------------------------------------------------------------------- */

#ifdef _WIN32
using Sock = SOCKET;
constexpr Sock kNoSock = INVALID_SOCKET;
void close_sock(Sock s) { closesocket(s); }
#else
using Sock = int;
constexpr Sock kNoSock = -1;
void close_sock(Sock s) { ::close(s); }
#endif

/// \~english One blocking request to loopback; whether it was answered with the greeting.  \~spanish Una peticion bloqueante al bucle local; si le contestaron con el saludo.  \~
bool one_request(uint16_t port, int n) {
    const Sock s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kNoSock) return false;

#ifndef _WIN32
    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#else
    DWORD ms = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof ms);
#endif

    sockaddr_in to;
    std::memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    bool answered = false;
    if (connect(s, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0) {
        char req[128];
        const int len = std::snprintf(req, sizeof req, "GET /r%d HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", n);
        if (send(s, req, len, 0) == len) {
            char got[1024] = {};
            size_t have = 0;
            for (;;) {
                const int r = static_cast<int>(recv(s, got + have, static_cast<int>(sizeof got - have - 1), 0));
                if (r <= 0) break;
                have += static_cast<size_t>(r);
            }
            char want[64];
            std::snprintf(want, sizeof want, "you asked for /r%d", n);
            answered = std::strstr(got, "HTTP/1.1 200") != nullptr && std::strstr(got, want) != nullptr;
        }
    }
    close_sock(s);
    return answered;
}

void test_three_shards_serve_and_stop() {
    serve::Reactors reactors;
    serve::Options opt;
    opt.host = "127.0.0.1";
    opt.port = 0;

    serve::GroupPlan plan;
    plan.options = &opt;
    plan.backend = reactors.default_name();
    plan.count = 3;

    serve::ShardGroup group;
    check(group.start(plan), "a group of three shards did not start");
    if (group.port() == 0) {
        check(false, "the group did not say which port it listens on");
        group.stop();
        return;
    }

    int answered = 0;
    for (int i = 0; i < 12; ++i)
        if (one_request(group.port(), i)) ++answered;
    check(answered == 12, "not every request was answered");

    // \~english Stops every thread through its mailbox; a shard that did not stop would hang here and the test's timeout would say so.
    // \~spanish Para cada hilo por su buzon; un fragmento que no parara colgaria aqui y el plazo de la prueba lo diria.  \~
    group.stop();
}

void test_a_taken_address_does_not_start() {
    // \~english A listening socket of this program's own, with no sharing option: the address is taken.
    // \~spanish Un socket de escucha de este mismo programa, sin la opcion de compartir: la direccion esta cogida.  \~
    serve::Reactors reactors;
    serve::Options opt;
    opt.host = "127.0.0.1";
    opt.port = 0;

    serve::GroupPlan plan;
    plan.options = &opt;
    plan.backend = reactors.default_name();
    plan.count = 1;
    serve::ShardGroup first;
    check(first.start(plan), "the first group did not start");
    if (first.port() == 0) return;

    for (uint32_t count = 1; count <= 2; ++count) {
        serve::Options taken;
        taken.host = "127.0.0.1";
        taken.port = first.port();
        serve::GroupPlan again;
        again.options = &taken;
        again.backend = reactors.default_name();
        again.count = count;

        serve::ShardGroup second;
        // \~english With one shard it listens alone; with two on Linux it asks to share, which the other socket did not.
        // \~spanish Con un fragmento escucha solo; con dos en Linux pide compartir, lo que el otro socket no hizo.  \~
        check(!second.start(again), "a group started on an address another socket holds");
        check(std::strstr(second.why(), "shard 0 did not start") != nullptr, "a group that did not start did not say which shard failed");
    }

    first.stop();
}

} // namespace

int main() {
    test_the_shards_option();
    test_cpus();
    test_three_shards_serve_and_stop();
    test_a_taken_address_does_not_start();

    if (failures != 0) {
        std::fprintf(stderr, "shard group: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("shard group: OK\n");
    return 0;
}
