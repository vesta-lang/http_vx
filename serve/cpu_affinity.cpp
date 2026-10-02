/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file serve/cpu_affinity.cpp
 * @brief
 * \~english Allowed CPUs and thread pinning, for Windows and for Linux.
 * \~spanish CPU permitidas y fijado de hilos, para Windows y para Linux.
 * \~
 */
#include "serve/cpu_affinity.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#endif

namespace serve {

#ifdef _WIN32

namespace {

/// \~english The process's affinity mask, or 1 (CPU 0) if the system will not say.  \~spanish La mascara de afinidad del proceso, o 1 (CPU 0) si el sistema no la dice.  \~
DWORD_PTR allowed_mask() noexcept {
    DWORD_PTR process = 0;
    DWORD_PTR system = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process, &system) || process == 0) return 1;
    return process;
}

} // namespace

uint32_t usable_cpus() noexcept {
    const DWORD_PTR mask = allowed_mask();
    uint32_t n = 0;
    for (uint32_t bit = 0; bit < sizeof(DWORD_PTR) * 8; ++bit)
        if ((mask >> bit) & 1) ++n;
    return n == 0 ? 1 : n;
}

bool pin_current_thread(uint32_t index, uint32_t &cpu) noexcept {
    const DWORD_PTR mask = allowed_mask();
    uint32_t want = index % usable_cpus();

    for (uint32_t bit = 0; bit < sizeof(DWORD_PTR) * 8; ++bit) {
        if (((mask >> bit) & 1) == 0) continue;
        if (want-- != 0) continue;

        if (SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << bit) == 0) return false;
        cpu = bit;
        return true;
    }
    return false;
}

#else

uint32_t usable_cpus() noexcept {
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) != 0) return 1;
    const int n = CPU_COUNT(&set);
    return n <= 0 ? 1 : static_cast<uint32_t>(n);
}

bool pin_current_thread(uint32_t index, uint32_t &cpu) noexcept {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof allowed, &allowed) != 0) return false;

    const int count = CPU_COUNT(&allowed);
    if (count <= 0) return false;
    uint32_t want = index % static_cast<uint32_t>(count);

    for (int id = 0; id < CPU_SETSIZE; ++id) {
        if (!CPU_ISSET(id, &allowed)) continue;
        if (want-- != 0) continue;

        cpu_set_t one;
        CPU_ZERO(&one);
        CPU_SET(id, &one);
        if (pthread_setaffinity_np(pthread_self(), sizeof one, &one) != 0) return false;
        cpu = static_cast<uint32_t>(id);
        return true;
    }
    return false;
}

#endif

} // namespace serve
