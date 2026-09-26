/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_quic_routes.cpp
 * @brief
 * \~english The route table against a model: collisions, wrap-around, deletion, the rules, and the key.
 * \~spanish La tabla de rutas contra un modelo: colisiones, vuelta al principio, borrado, las reglas, y la clave.
 * \~
 *
 * \~english
 * A small table and many short IDs, so runs collide and wrap past the end:
 * that is where backward-shift deletion goes wrong if it does.  Every
 * operation is checked against a plain model, and after every removal every
 * ID the model holds is looked up.
 * \~spanish
 * Una tabla pequena y muchos identificadores cortos, para que las tiradas
 * choquen y den la vuelta al final: ahi es donde falla el borrado desplazando
 * hacia atras si falla.  Cada operacion se comprueba contra un modelo simple, y
 * tras cada borrado se busca cada identificador que tiene el modelo.
 * \~
 */
#include "http_vx/quic_routes.h"

#include <cstdio>
#include <map>
#include <vector>

namespace {

using http_vx::quic::CidRoutes;

int failures = 0;
const char *current = "";

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL [%s]: %s\n", current, what);
    ++failures;
}

/// \~english A small deterministic generator.  \~spanish Un generador determinista pequeno.  \~
uint64_t g_state = 0x9E3779B97F4A7C15ull;
uint64_t next() {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 7;
    g_state ^= g_state << 17;
    return g_state;
}

const uint8_t kKey[CidRoutes::kKeySize] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

void test_rules() {
    current = "rules";
    CidRoutes r;
    const uint8_t a[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    const uint8_t b[4] = {1, 1, 1, 1};
    check(r.find(a, 8) == CidRoutes::kNone && !r.add(a, 8, 1) && !r.remove(a, 8), "nothing works before reset");
    check(r.reset(4, kKey), "reset");
    check(r.add(a, 8, 1) && r.find(a, 8) == 1 && r.size() == 1, "an ID routes to its owner");
    check(r.add(a, 8, 1) && r.size() == 1, "the same ID for the same owner again: still one");
    check(!r.add(a, 8, 2) && r.find(a, 8) == 1, "an ID another owner holds is refused, never shared");
    check(r.find(b, 4) == CidRoutes::kNone, "a prefix is another ID");
    check(!r.add(a, 0, 3) && !r.add(a, 21, 3) && r.find(a, 0) == CidRoutes::kNone, "empty and over-long IDs are refused");
    check(!r.add(b, 4, CidRoutes::kNone), "no owner is not an owner");
    uint8_t c[1] = {0};
    for (uint8_t i = 0; i < 3; ++i) {
        c[0] = i;
        check(r.add(c, 1, 5), "room up to the capacity");
    }
    c[0] = 9;
    check(!r.add(c, 1, 5) && r.size() == 4, "and not past it");
    check(r.remove(a, 8) && !r.remove(a, 8) && r.find(a, 8) == CidRoutes::kNone, "removed once, then gone");
    check(r.add(c, 1, 5), "room again after a removal");
    r.release();
    check(r.find(c, 1) == CidRoutes::kNone && r.size() == 0, "released: nothing left");
}

void test_full() {
    current = "full";
    // \~english Sixteen IDs in a table sized for sixteen: a lookup for a missing one must still end.
    // \~spanish Dieciseis identificadores en una tabla para dieciseis: buscar uno que falta tiene que acabar igual.  \~
    CidRoutes r;
    check(r.reset(16, kKey), "reset");
    uint8_t id[1];
    for (uint8_t i = 0; i < 16; ++i) {
        id[0] = i;
        check(r.add(id, 1, i), "filled to the capacity");
    }
    id[0] = 200;
    check(r.find(id, 1) == CidRoutes::kNone, "a missing ID is not found, and the lookup ends");
}

void model_run(size_t capacity, size_t alphabet, int steps) {
    CidRoutes r;
    check(r.reset(capacity, kKey), "reset");
    std::map<std::vector<uint8_t>, uint32_t> model;
    for (int step = 0; step < steps; ++step) {
        // \~english One or two bytes from a small alphabet: many collisions, many repeats.
        // \~spanish Uno o dos bytes de un alfabeto pequeno: muchas colisiones, muchas repeticiones.  \~
        const size_t len = 1 + next() % 2;
        std::vector<uint8_t> id(len);
        for (size_t i = 0; i < len; ++i) id[i] = static_cast<uint8_t>(next() % alphabet);
        const uint32_t owner = static_cast<uint32_t>(next() % 5);
        auto it = model.find(id);
        if (next() % 3 != 0) {
            const bool want = it != model.end() ? it->second == owner : model.size() < capacity;
            const bool got = r.add(id.data(), len, owner);
            if (got != want) {
                check(false, "add agrees with the model");
                break;
            }
            if (got && it == model.end()) model[id] = owner;
        } else {
            const bool got = r.remove(id.data(), len);
            if (got != (it != model.end())) {
                check(false, "remove agrees with the model");
                break;
            }
            if (it != model.end()) model.erase(it);
            // \~english After a removal, everything left is still found: the shift kept every run whole.
            // \~spanish Tras un borrado, todo lo que queda se sigue encontrando: el desplazamiento mantuvo enteras las tiradas.  \~
            bool all = true;
            for (const auto &m : model) all = all && r.find(m.first.data(), m.first.size()) == m.second;
            if (!all) {
                check(false, "every ID left is found after a removal");
                break;
            }
        }
        if (r.size() != model.size()) {
            check(false, "the sizes agree");
            break;
        }
    }
}

void test_model() {
    current = "against a model";
    model_run(24, 7, 200000);
    // \~english Sixteen places and eight IDs: runs cross the end of the table and deletion has to follow them round.
    // \~spanish Dieciseis sitios y ocho identificadores: las tiradas cruzan el final de la tabla y el borrado tiene que seguirlas.  \~
    current = "against a model, a table that wraps";
    model_run(8, 5, 300000);
}

void test_key() {
    current = "key";
    const uint8_t id[8] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4};
    uint64_t k[2] = {1, 2};
    const uint64_t h = CidRoutes::hash(id, 8, k);
    k[0] = 3;
    check(CidRoutes::hash(id, 8, k) != h, "the first word of the key changes the hash");
    k[0] = 1;
    k[1] = 5;
    check(CidRoutes::hash(id, 8, k) != h, "and so does the second");
    k[1] = 2;
    check(CidRoutes::hash(id, 8, k) == h, "the same key, the same hash");
    const uint8_t longer[20] = {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 9, 9, 9, 9, 9, 9, 9, 9, 7, 7, 7, 7};
    uint8_t other[20];
    for (size_t i = 0; i < 20; ++i) other[i] = longer[i];
    other[19] ^= 1;
    check(CidRoutes::hash(longer, 20, k) != CidRoutes::hash(other, 20, k), "the last byte of a long ID counts");
}

} // namespace

int main() {
    test_rules();
    test_full();
    test_model();
    test_key();
    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("quic routes: OK\n");
    return 0;
}
