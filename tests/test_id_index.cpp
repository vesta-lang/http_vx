/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_id_index.cpp
 * @brief
 * \~english The identifier index against a plain map, over many random operations.
 * \~spanish El indice de identificadores contra un mapa corriente, en muchas operaciones al azar.
 * \~
 *
 * \~english
 * Backward-shift deletion is the part that can be wrong without anything
 * crashing: an entry moved into a hole it should not fill, or left behind a
 * hole it should, is an identifier that is suddenly not found -- a request
 * or a stream that stops existing.  A reference map checked after EVERY
 * operation catches it the moment it happens; the table is kept small and
 * nearly full so that runs of probes wrap round its end.
 * \~spanish
 * El borrado desplazando hacia atras es la parte que puede estar mal sin que
 * nada reviente: una entrada movida a un hueco que no debia rellenar, o dejada
 * detras de uno que si, es un identificador que de repente no se encuentra --
 * una peticion o un flujo que deja de existir.  Un mapa de referencia
 * comprobado tras CADA operacion lo pilla en el momento; la tabla se mantiene
 * pequena y casi llena para que las rachas de sondeo den la vuelta a su final.
 * \~
 */
#include "http_vx/id_index.h"

#include <cstdio>
#include <unordered_map>
#include <vector>

namespace {

using http_vx::IdIndex;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/// \~english A small deterministic generator, so a failure repeats.  \~spanish Un generador pequeno y determinista, para que un fallo se repita.  \~
struct Rng {
    uint64_t s = 0x243F6A8885A308D3ull;
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
};

void test_the_basic_contract() {
    IdIndex x;
    check(x.find(4) == IdIndex::kAbsent, "an index never made found something");
    check(!x.reset(0), "an index of no room was made");
    check(x.reset(3), "an index of three would not be made");
    check(x.insert(0, 7) && x.insert(4, 8) && x.insert(8, 9), "three insertions were refused");
    check(!x.insert(12, 10), "a fourth identifier went into room for three");
    check(!x.insert(IdIndex::kNoId, 1), "the identifier that marks empty places was taken");
    check(x.find(4) == 8 && x.find(0) == 7 && x.find(8) == 9, "an identifier maps to the wrong slot");
    check(x.size() == 3, "the count is wrong");
    check(x.erase(4) && !x.erase(4), "erasing twice did not say the second was absent");
    check(x.find(4) == IdIndex::kAbsent && x.find(0) == 7 && x.find(8) == 9,
          "erasing one lost or kept the wrong ones");
    check(x.insert(12, 10) && x.find(12) == 10, "the room freed by an erase was not usable");
    check(x.reset(2) && x.size() == 0 && x.find(0) == IdIndex::kAbsent, "reset kept identifiers");
}

/**
 * @brief
 * \~english Random inserts and erases, checked against a map after every one.
 * \~spanish Inserciones y borrados al azar, comprobados contra un mapa tras cada uno.
 * \~
 */
void test_against_a_reference(size_t most, uint64_t key_space, int rounds) {
    IdIndex x;
    check(x.reset(most), "the index would not be made");
    std::unordered_map<uint64_t, uint32_t> ref;
    std::vector<uint64_t> keys;
    Rng r;
    bool agrees = true;

    for (int round = 0; round < rounds && agrees; ++round) {
        const uint64_t id = r.next() % key_space;
        const bool held = ref.count(id) != 0;
        if (!held && ref.size() < most) {
            const uint32_t slot = static_cast<uint32_t>(r.next());
            if (!x.insert(id, slot)) agrees = false;
            ref[id] = slot;
        } else if (held) {
            if (!x.erase(id)) agrees = false;
            ref.erase(id);
        }
        if (x.size() != ref.size()) agrees = false;
        // \~english Every identifier of the key space: the held ones found, the rest not.
        // \~spanish Cada identificador del espacio de claves: los que estan se encuentran, el resto no.  \~
        for (uint64_t k = 0; k < key_space && agrees; ++k) {
            const auto it = ref.find(k);
            const uint32_t want = it == ref.end() ? IdIndex::kAbsent : it->second;
            if (x.find(k) != want) agrees = false;
        }
    }
    check(agrees, "the index disagreed with the reference map");
}

/**
 * @brief
 * \~english Stream-shaped identifiers: sequential by four, far past the table's size.
 * \~spanish Identificadores con forma de flujo: seguidos de cuatro en cuatro, muy por encima del tamano de la tabla.
 * \~
 */
void test_stream_shaped_identifiers() {
    IdIndex x;
    check(x.reset(64), "the index would not be made");
    bool agrees = true;
    // \~english A sliding window of 64 live streams over a million IDs.
    // \~spanish Una ventana deslizante de 64 flujos vivos sobre un millon de identificadores.  \~
    for (uint64_t n = 0; n < 1000000 && agrees; ++n) {
        const uint64_t id = n * 4;
        if (n >= 64 && !x.erase((n - 64) * 4)) agrees = false;
        if (!x.insert(id, static_cast<uint32_t>(n % 64))) agrees = false;
        if (x.find(id) != n % 64) agrees = false;
        if (n >= 64 && x.find((n - 64) * 4) != IdIndex::kAbsent) agrees = false;
    }
    check(agrees, "a sliding window of stream IDs went wrong");
    check(x.size() == 64, "the window does not hold 64");
}

} // namespace

int main() {
    test_the_basic_contract();
    test_against_a_reference(8, 40, 20000);
    test_against_a_reference(13, 1000, 20000);
    test_against_a_reference(100, 250, 20000);
    test_stream_shaped_identifiers();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("id index: OK\n");
    return 0;
}
