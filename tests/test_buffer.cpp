/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_buffer.cpp
 * @brief
 * \~english The buffer, and the one invariant everything else rests on.
 * \~spanish El buffer, y el unico invariante sobre el que se apoya lo demas.
 * \~
 *
 * \~english
 * An offset recorded from `data()` must still name the same byte after the
 * buffer has grown and after it has slid its leftovers to the front.  Every
 * other structure in the project depends on that -- the fields are offsets,
 * the parser's position is an offset, the body is an offset and a length --
 * and none of them can check it, because none of them knows when the buffer
 * last moved.
 *
 * So it is checked here, by moving the buffer on purpose and then reading back
 * through the offsets that were taken before.
 *
 * \~spanish
 * Un desplazamiento anotado desde `data()` tiene que seguir nombrando el mismo
 * byte despues de que el buffer haya crecido y despues de que haya deslizado lo
 * que sobra hacia delante.  Todas las demas estructuras del proyecto dependen
 * de eso -- las cabeceras son desplazamientos, la posicion del analizador es un
 * desplazamiento, el cuerpo es un desplazamiento y una longitud -- y ninguna
 * puede comprobarlo, porque ninguna sabe cuando se movio el buffer por ultima
 * vez.
 *
 * Asi que se comprueba aqui, moviendo el buffer a proposito y volviendo a leer
 * despues por los desplazamientos que se tomaron antes.
 *
 * \~
 */

#include "http_vx/buffer.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Writes @p n bytes whose value follows from their position.
 * \~spanish Escribe @p n bytes cuyo valor sale de su posicion.
 * \~
 *
 * \~english
 * The pattern depends on the offset, so a byte that ends up somewhere else
 * does not merely differ -- it says where it came from.
 *
 * \~spanish
 * El patron depende del desplazamiento, asi que un byte que acabe en otro sitio
 * no solo difiere: dice de donde venia.
 *
 * \~
 */
void fill(http_vx::Buffer &b, size_t n, uint8_t seed = 0) {
    uint8_t *p = b.reserve(n);
    check(p != nullptr, "the room could not be had");
    if (p == nullptr) return;
    for (size_t i = 0; i < n; ++i)
        p[i] = static_cast<uint8_t>((b.size() + i + seed) & 0xFF);
    b.commit(n);
}

/**
 * @brief
 * \~english The view: where the bytes are, and where they are in the stream.
 * \~spanish La vista: donde estan los bytes, y donde estan dentro del flujo.
 * \~
 *
 * \~english
 * @c has is checked at its edges and past both of them, because it is what
 * stands between a stream position and a pointer.  A position before the
 * origin names a byte that has already been dropped, and resolving one would
 * produce a pointer BEFORE the buffer -- which is not a read of the wrong
 * bytes, it is a read of somebody else's memory.
 *
 * \~spanish
 * @c has se comprueba en sus extremos y pasados los dos, porque es lo que hay
 * entre una posicion del flujo y un puntero.  Una posicion anterior al origen
 * nombra un byte que ya se descarto, y resolverla produciria un puntero
 * ANTERIOR al buffer -- que no es una lectura de los bytes equivocados, es una
 * lectura de la memoria de otro.
 *
 * \~
 */
void test_view() {
    const uint8_t bytes[] = "abcdefgh";
    const http_vx::View v{bytes, 8, 1000};

    check(v.end() == 1008, "the end is not the origin plus the size");
    check(v.at(1000) == bytes, "the origin does not resolve to the first byte");
    check(v.at(1007) == bytes + 7, "the last byte does not resolve to itself");

    check(v.has(1000, 8), "the whole of it is not here");
    check(v.has(1007, 1), "the last byte is not here");
    check(v.has(1008, 0), "an empty piece at the end is not here");
    check(!v.has(1000, 9), "one byte more than there is was reported here");
    check(!v.has(1008, 1), "a byte past the end was reported here");

    /* \~english
     * And behind the origin, which is the case that matters: those bytes were
     * dropped, and a check written as `at + len <= end` would say yes to them
     * because the sum comes out small.
     * \~spanish
     * Y por detras del origen, que es el caso que importa: esos bytes se
     * descartaron, y una comprobacion escrita como `at + len <= end` diria que
     * si porque la suma sale pequena.
     * \~ */
    check(!v.has(999, 1), "a byte that was already dropped was reported here");
    check(!v.has(0, 1), "the start of the connection was reported here");

    /* \~english
     * A length near the top of the range must not wrap the sum into saying
     * yes.  It is the same trick the content length refuses, in the other
     * direction.
     * \~spanish
     * Una longitud cerca del techo del rango no puede dar la vuelta a la suma
     * para que diga que si.  Es el mismo truco que rechaza la longitud de
     * contenido, en el otro sentido.
     * \~ */
    check(!v.has(1000, ~uint64_t{0}), "a length that wraps was reported here");

    const http_vx::View empty{nullptr, 0, 0};
    check(empty.end() == 0, "an empty view ends somewhere");
    check(empty.has(0, 0), "nothing is not here");
    check(!empty.has(0, 1), "something is here in an empty view");
}

/**
 * @brief
 * \~english The origin counts what was dropped, and only that.
 * \~spanish El origen cuenta lo descartado, y solo eso.
 * \~
 */
void test_origin() {
    http_vx::Buffer b;
    check(b.origin() == 0, "a fresh buffer has dropped something");

    fill(b, 100);
    check(b.origin() == 0, "arriving counted as dropping");
    check(b.view().origin == 0, "the view disagrees with the buffer");

    b.consume(40);
    check(b.origin() == 40, "the origin did not follow the dropping");
    check(b.view().origin == 40, "the view disagrees with the buffer");
    check(b.view().end() == 100, "the view ends somewhere else");

    /* \~english
     * Asking to drop more than is here drops what is here, and the origin
     * follows THAT.  Believing the number instead would put the origin ahead
     * of bytes that never arrived, and every position behind it would name a
     * byte that is not the one it meant.
     * \~spanish
     * Pedir que se descarte mas de lo que hay descarta lo que hay, y el origen
     * sigue A ESO.  Creerse el numero pondria el origen por delante de bytes
     * que no llegaron nunca, y toda posicion posterior nombraria un byte que no
     * es el que queria decir.
     * \~ */
    b.consume(1000);
    check(b.origin() == 100, "the origin followed a number instead of the bytes");
    check(b.empty(), "something was left");

    /* \~english
     * Emptying it for the next message does NOT start the stream over: the
     * connection carries on, and a position from before still means what it
     * meant.  Giving the memory back does, because that is a connection
     * ending.
     * \~spanish
     * Vaciarlo para el mensaje siguiente NO reinicia el flujo: la conexion
     * sigue, y una posicion de antes significa lo mismo.  Devolver la memoria
     * si, porque eso es una conexion que acaba.
     * \~ */
    b.clear();
    check(b.origin() == 100, "emptying it started the connection over");

    b.release();
    check(b.origin() == 0, "giving the memory back kept the old stream");
}

/**
 * @brief
 * \~english A fresh buffer owns nothing.
 * \~spanish Un buffer recien hecho no tiene nada.
 * \~
 *
 * \~english
 * R1 in its simplest form: the connection that has not been written to yet is
 * the same as the one that has gone quiet, and neither holds memory.
 *
 * \~spanish
 * R1 en su forma mas simple: la conexion en la que todavia no se ha escrito es
 * lo mismo que la que se ha quedado callada, y ninguna tiene memoria.
 *
 * \~
 */
void test_empty() {
    http_vx::Buffer b;
    check(b.empty(), "a fresh buffer is not empty");
    check(b.size() == 0, "a fresh buffer has a size");
    check(b.capacity() == 0, "a fresh buffer holds memory");
    check(b.tail_room() == 0, "a fresh buffer has room");

    b.release();
    b.release();
    check(b.capacity() == 0, "releasing twice left memory behind");
}

/**
 * @brief
 * \~english Reserve, commit, read, consume.
 * \~spanish Reservar, entregar, leer, consumir.
 * \~
 */
void test_cycle() {
    http_vx::Buffer b;

    uint8_t *p = b.reserve(10);
    check(p != nullptr, "the first reserve failed");
    check(b.size() == 0, "reserving made the bytes exist");
    check(b.capacity() >= http_vx::kBufferInitialCapacity,
          "the first reserve asked for less than a page");

    std::memcpy(p, "GET / HTTP", 10);
    b.commit(10);
    check(b.size() == 10, "the committed bytes are not there");
    check(std::memcmp(b.data(), "GET / HTTP", 10) == 0,
          "the committed bytes are not the ones written");

    b.consume(4);
    check(b.size() == 6, "consuming did not drop what it said");
    check(std::memcmp(b.data(), "/ HTTP", 6) == 0,
          "what is left is not what follows what was consumed");

    b.consume(6);
    check(b.empty(), "consuming everything left something");
}

/**
 * @brief
 * \~english Neither number is believed further than it can go.
 * \~spanish Ninguno de los dos numeros se cree mas alla de donde llega.
 * \~
 *
 * \~english
 * The committed count comes back from an I/O completion.  One that is too
 * large would hand the parser bytes nobody wrote -- whatever the allocator
 * left in the block -- and the parser would read them as a message.
 *
 * \~spanish
 * La cuenta entregada vuelve de una finalizacion de entrada y salida.  Una
 * demasiado grande le daria al analizador bytes que no escribio nadie -- lo que
 * el asignador dejara en el bloque -- y el analizador los leeria como un
 * mensaje.
 *
 * \~
 */
void test_clamping() {
    http_vx::Buffer b;
    b.reserve(16);
    const size_t room = b.tail_room();

    b.commit(room + 1000);
    check(b.size() == room, "a commit past the room was believed");

    b.consume(b.size() + 1000);
    check(b.empty(), "a consume past the end was believed");
    check(b.size() == 0, "the size went negative");
}

/**
 * @brief
 * \~english Offsets survive growing.
 * \~spanish Los desplazamientos sobreviven a crecer.
 * \~
 */
void test_offsets_survive_growth() {
    http_vx::Buffer b;
    fill(b, 100);
    const size_t first_cap = b.capacity();

    /* \~english
     * Copy what is there, then force a reallocation by asking for more than
     * the block can hold.
     * \~spanish
     * Copiar lo que hay, y entonces forzar una realocacion pidiendo mas de lo
     * que cabe en el bloque.
     * \~ */
    uint8_t before[100];
    std::memcpy(before, b.data(), 100);

    uint8_t *p = b.reserve(first_cap * 2);
    check(p != nullptr, "growing failed");
    check(b.capacity() > first_cap, "the buffer did not grow");
    check(b.size() == 100, "growing changed how many bytes are live");
    check(std::memcmp(b.data(), before, 100) == 0,
          "the live bytes did not survive growing");
}

/**
 * @brief
 * \~english Offsets survive sliding the leftovers to the front.
 * \~spanish Los desplazamientos sobreviven a deslizar lo que sobra.
 * \~
 *
 * \~english
 * The case that matters is the overlapping one: most of the buffer is live and
 * the destination lands inside the source.  A copy instead of a move is right
 * whenever the overlap happens to be small, which is most of the time, so this
 * is set up so that it is not.
 *
 * \~spanish
 * El caso que importa es el que se solapa: casi todo el buffer esta vivo y el
 * destino cae dentro del origen.  Una copia en vez de un traslado acierta
 * siempre que el solape resulte ser pequeno, que es casi siempre, asi que esto
 * se monta para que no lo sea.
 *
 * \~
 */
void test_offsets_survive_compaction() {
    http_vx::Buffer b;
    b.reserve(http_vx::kBufferInitialCapacity);
    const size_t cap = b.capacity();

    fill(b, cap - 96);
    const size_t dropped = 100;
    const size_t live = b.size() - dropped;

    /* \~english
     * A fixed copy, not one from the allocator: a test that can itself fail to
     * get memory has two reasons to go red and only reports one of them.
     * \~spanish
     * Una copia de tamano fijo, no una del asignador: una prueba que puede
     * quedarse ella misma sin memoria tiene dos razones para ponerse roja y
     * solo informa de una.
     * \~ */
    static uint8_t kept[http_vx::kBufferInitialCapacity];
    check(live <= sizeof(kept), "the test's own copy does not fit");
    if (live > sizeof(kept)) return;
    std::memcpy(kept, b.data() + dropped, live);

    b.consume(dropped);
    check(b.size() == live, "consuming dropped the wrong amount");

    /* \~english
     * Enough not to fit in the tail, little enough that the dropped hundred
     * bytes at the front cover it: that is the shape that slides instead of
     * growing.
     * \~spanish
     * Bastante para no caber en la cola, poco para que los cien bytes
     * descartados del principio lo cubran: esa es la forma que desliza en vez
     * de crecer.
     * \~ */
    uint8_t *p = b.reserve(150);
    check(p != nullptr, "sliding failed");
    check(b.capacity() == cap, "it grew instead of sliding");
    check(b.size() == live, "sliding changed how many bytes are live");
    check(std::memcmp(b.data(), kept, live) == 0,
          "the live bytes did not survive sliding, which means the overlap "
          "was copied rather than moved");
}

/**
 * @brief
 * \~english Growing drops what was already consumed instead of carrying it.
 * \~spanish Crecer descarta lo ya consumido en vez de arrastrarlo.
 * \~
 */
void test_growth_drops_the_consumed() {
    http_vx::Buffer b;
    fill(b, 200);
    b.consume(150);
    check(b.size() == 50, "consuming dropped the wrong amount");

    uint8_t before[50];
    std::memcpy(before, b.data(), 50);

    b.reserve(b.capacity() * 2);
    check(b.size() == 50, "growing brought back what had been consumed");
    check(std::memcmp(b.data(), before, 50) == 0,
          "the live bytes did not survive growing after a consume");
}

/**
 * @brief
 * \~english Releasing gives the memory back, and the buffer serves again.
 * \~spanish Soltar devuelve la memoria, y el buffer vuelve a servir.
 * \~
 */
void test_release_and_reuse() {
    http_vx::Buffer b;
    fill(b, 64);
    check(b.capacity() != 0, "the buffer holds no memory");

    b.release();
    check(b.capacity() == 0, "releasing kept the memory");
    check(b.empty(), "releasing kept the bytes");

    fill(b, 64);
    check(b.size() == 64, "the buffer does not serve again after releasing");
}

/**
 * @brief
 * \~english Clearing keeps the memory; releasing does not.
 * \~spanish Vaciar conserva la memoria; soltar no.
 * \~
 */
void test_clear_keeps_the_memory() {
    http_vx::Buffer b;
    fill(b, 64);
    const size_t cap = b.capacity();

    b.clear();
    check(b.empty(), "clearing kept the bytes");
    check(b.capacity() == cap, "clearing gave the memory back");
}

/**
 * @brief
 * \~english Moving takes the memory and leaves nothing behind.
 * \~spanish Mover se lleva la memoria y no deja nada detras.
 * \~
 */
void test_move() {
    http_vx::Buffer a;
    fill(a, 32);
    uint8_t before[32];
    std::memcpy(before, a.data(), 32);

    http_vx::Buffer b(static_cast<http_vx::Buffer &&>(a));
    check(b.size() == 32, "the bytes did not move");
    check(std::memcmp(b.data(), before, 32) == 0, "the bytes moved wrong");
    check(a.capacity() == 0, "the source kept the memory");
    check(a.empty(), "the source kept the bytes");

    http_vx::Buffer c;
    fill(c, 8);
    c = static_cast<http_vx::Buffer &&>(b);
    check(c.size() == 32, "assigning did not move the bytes");
    check(b.capacity() == 0, "assigning left the source holding memory");

    /* \~english
     * And moving onto itself keeps what it has instead of freeing it first.
     * \~spanish
     * Y moverse sobre si mismo conserva lo que tiene en vez de liberarlo antes.
     * \~ */
    http_vx::Buffer *self = &c;
    c = static_cast<http_vx::Buffer &&>(*self);
    check(c.size() == 32, "moving onto itself lost the bytes");
}

/**
 * @brief
 * \~english Past the ceiling it refuses and changes nothing.
 * \~spanish Pasado el techo se niega y no cambia nada.
 * \~
 *
 * \~english
 * Refusing is not the interesting half.  What matters is that the buffer is
 * left exactly as it was: a caller that handles the refusal by closing the
 * connection will still touch the buffer on the way out, and a half-grown one
 * would be a second failure on top of the first.
 *
 * \~spanish
 * Negarse no es la mitad interesante.  Lo que importa es que el buffer se queda
 * exactamente como estaba: quien maneje la negativa cerrando la conexion va a
 * tocar el buffer igualmente al salir, y uno crecido a medias seria un segundo
 * fallo encima del primero.
 *
 * \~
 */
void test_ceiling() {
    http_vx::Buffer b;
    fill(b, 32);
    const size_t cap = b.capacity();

    uint8_t before[32];
    std::memcpy(before, b.data(), 32);

    check(b.reserve(http_vx::kBufferMaxCapacity + 1) == nullptr,
          "a reserve past the ceiling was served");
    check(b.capacity() == cap, "a refused reserve changed the capacity");
    check(b.size() == 32, "a refused reserve changed the bytes");
    check(std::memcmp(b.data(), before, 32) == 0,
          "a refused reserve moved the bytes");
}

} // namespace

int main() {
    test_view();
    test_origin();
    test_empty();
    test_cycle();
    test_clamping();
    test_offsets_survive_growth();
    test_offsets_survive_compaction();
    test_growth_drops_the_consumed();
    test_release_and_reuse();
    test_clear_keeps_the_memory();
    test_move();
    test_ceiling();

    if (failures != 0) {
        std::fprintf(stderr, "test_buffer: %d failures\n", failures);
        return 1;
    }
    std::printf("test_buffer: ok\n");
    return 0;
}
