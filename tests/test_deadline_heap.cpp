/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_deadline_heap.cpp
 * @brief
 * \~english The deadline heap against a model: every change, then the earliest and each one's deadline.
 * \~spanish El monticulo de plazos contra un modelo: cada cambio, y despues el primero y el plazo de cada uno.
 * \~
 */
#include "http_vx/deadline_heap.h"

#include <cstdio>
#include <vector>

namespace {

using http_vx::DeadlineHeap;

int failures = 0;
const char *current = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

uint64_t g_state = 0x2545F4914F6CDD1Dull;
uint64_t next() {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 7;
    g_state ^= g_state << 17;
    return g_state;
}

void test_rules() {
    current = "rules";
    DeadlineHeap h;
    check(!h.reset(0), "no room is refused");
    check(h.reset(4) && h.empty() && h.next() == DeadlineHeap::kNever, "empty after reset");
    h.set(2, 50);
    h.set(1, 70);
    check(h.top() == 2 && h.next() == 50 && h.size() == 2, "the earliest first");
    h.set(1, 10);
    check(h.top() == 1 && h.next() == 10, "moved earlier, it rises");
    h.set(1, 90);
    check(h.top() == 2 && h.when(1) == 90, "moved later, it sinks");
    h.set(2, DeadlineHeap::kNever);
    check(h.top() == 1 && h.size() == 1 && h.when(2) == DeadlineHeap::kNever, "no deadline takes it out");
    h.remove(1);
    h.remove(1);
    check(h.empty() && h.next() == DeadlineHeap::kNever, "removed once, then gone");
    h.set(7, 5);
    check(h.empty(), "an identifier past the capacity is ignored");
    h.release();
    check(h.empty() && h.next() == DeadlineHeap::kNever, "released: nothing left");
}

void test_model() {
    current = "against a model";
    const uint32_t n = 37;
    DeadlineHeap h;
    check(h.reset(n), "reset");
    std::vector<uint64_t> model(n, DeadlineHeap::kNever);
    for (int step = 0; step < 200000; ++step) {
        const uint32_t id = static_cast<uint32_t>(next() % n);
        const uint64_t r = next() % 10;
        if (r < 6) {
            // \~english Few distinct values: ties are common, and must not break anything.
            // \~spanish Pocos valores distintos: los empates son frecuentes, y no deben romper nada.  \~
            const uint64_t when = next() % 50;
            h.set(id, when);
            model[id] = when;
        } else if (r < 8) {
            h.remove(id);
            model[id] = DeadlineHeap::kNever;
        } else {
            h.set(id, DeadlineHeap::kNever);
            model[id] = DeadlineHeap::kNever;
        }
        uint64_t least = DeadlineHeap::kNever;
        size_t live = 0;
        for (uint64_t w : model) {
            if (w < least) least = w;
            if (w != DeadlineHeap::kNever) ++live;
        }
        if (h.next() != least || h.size() != live || (live != 0 && model[h.top()] != least)) {
            check(false, "the earliest and the count agree with the model");
            break;
        }
        bool same = true;
        for (uint32_t i = 0; i < n; ++i) same = same && h.when(i) == model[i];
        if (!same) {
            check(false, "every deadline agrees with the model");
            break;
        }
    }
    // \~english And drained in order, every one at its deadline.
    // \~spanish Y vaciado en orden, cada uno en su plazo.  \~
    uint64_t last = 0;
    while (!h.empty()) {
        const uint32_t id = h.top();
        const uint64_t w = h.next();
        if (w < last || model[id] != w) {
            check(false, "drained in order");
            break;
        }
        last = w;
        h.remove(id);
        model[id] = DeadlineHeap::kNever;
    }
}

} // namespace

int main() {
    test_rules();
    test_model();
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("deadline heap: OK\n");
    return 0;
}
