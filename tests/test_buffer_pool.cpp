/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_buffer_pool.cpp
 * @brief
 * \~english Lending buffers, and the stream that must start over.
 * \~spanish Prestar buffers, y el flujo que tiene que empezar de nuevo.
 * \~
 *
 * \~english
 * The case worth writing down is the one that looks like housekeeping: a
 * buffer handed from one connection to another has to start its stream at
 * zero, and the obvious call -- the one that empties it -- does not do that.
 *
 * Nothing about getting it wrong fails.  The buffer is empty either way, the
 * memory is the same memory, and every read and write still lands inside it.
 * What changes is the number the buffer reports as the start of the stream,
 * and the new connection's readers count from the start of the CONNECTION,
 * which is zero.  So every offset they ask about is measured from a point
 * that connection never had, and the reads land somewhere else -- in the same
 * buffer, so nothing traps.
 *
 * The rest is what a pool is for: the memory is reused, an empty pool says so
 * rather than failing, and a buffer that grew enormous for one upload does not
 * keep that memory for everyone who comes after it.
 *
 * \~spanish
 * El caso que merece escribirse es el que parece tarea domestica: un buffer que
 * pasa de una conexion a otra tiene que empezar su flujo en cero, y la llamada
 * evidente -- la que lo vacia -- no hace eso.
 *
 * Equivocarse no falla en nada.  El buffer esta vacio de las dos formas, la
 * memoria es la misma memoria, y todas las lecturas y escrituras siguen cayendo
 * dentro.  Lo que cambia es el numero que el buffer dice que es el principio del
 * flujo, y los lectores de la conexion nueva cuentan desde el principio de la
 * CONEXION, que es cero.  Asi que todos los desplazamientos por los que
 * preguntan se miden desde un punto que esa conexion no tuvo, y las lecturas
 * caen en otro sitio -- dentro del mismo buffer, asi que no salta nada.
 *
 * Lo demas es para lo que sirve un pozo: la memoria se reutiliza, un pozo vacio
 * lo dice en vez de fallar, y un buffer que se hizo enorme por una subida no se
 * queda esa memoria para todos los que vengan detras.
 *
 * \~
 */

#include "http_vx/buffer_pool.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Buffer;
using http_vx::BufferPool;
using http_vx::kNoBuffer;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Writes @p n bytes into @p b.
 * \~spanish Escribe @p n bytes en @p b.
 * \~
 */
void fill(Buffer &b, size_t n) {
    uint8_t *room = b.reserve(n);
    if (room == nullptr) return;
    std::memset(room, 'x', n);
    b.commit(n);
}

/**
 * @brief
 * \~english A buffer is lent, used and taken back.
 * \~spanish Un buffer se presta, se usa y se recoge.
 * \~
 */
void test_the_ordinary_life_of_a_buffer() {
    BufferPool p;
    check(p.reset(4, 1 << 20), "the pool would not be made");
    check(p.count() == 4, "the pool is not the size it was asked for");
    check(p.lent() == 0, "a fresh pool has buffers lent out");

    /* \~english
     * Nothing has been allocated yet, which is what makes a shard cheap to
     * start.  A pool that reserved its memory up front would cost the same
     * whether or not anybody ever connected.
     * \~spanish
     * Todavia no se ha reservado nada, que es lo que hace barato arrancar un
     * fragmento.  Un pozo que cogiera su memoria por delante costaria lo mismo
     * se conectara alguien o no.
     * \~ */
    check(p.bytes_held() == 0, "a pool nobody used is holding memory");

    const uint32_t i = p.acquire();
    check(i != kNoBuffer, "a buffer could not be lent");
    check(p.lent() == 1, "the lent buffer was not counted");

    Buffer *b = p.at(i);
    check(b != nullptr, "the lent buffer is not there");
    check(b != nullptr && b->empty(), "a lent buffer is not empty");

    fill(*b, 100);
    check(b->size() == 100, "the buffer did not take what was written");
    check(p.bytes_held() != 0, "a buffer in use is holding nothing");

    p.release(i);
    check(p.lent() == 0, "a returned buffer is still counted as lent");

    /* \~english
     * And the memory stayed, which is what a pool is.
     * \~spanish
     * Y la memoria se quedo, que es lo que es un pozo.
     * \~ */
    check(p.bytes_held() != 0, "the pool gave back the memory it should keep");
}

/**
 * @brief
 * \~english A buffer handed to somebody else starts its stream at zero.
 * \~spanish Un buffer entregado a otro empieza su flujo en cero.
 * \~
 *
 * \~english
 * The silent one.  A connection that read and consumed half a megabyte leaves
 * the buffer reporting half a megabyte as the start of what is in it -- which
 * was true, for that connection.  Given to the next one without resetting it,
 * every offset that connection's readers ask about is measured from a point
 * it never had.
 *
 * \~spanish
 * El silencioso.  Una conexion que leyo y consumio medio megabyte deja el buffer
 * diciendo que medio megabyte es el principio de lo que tiene dentro -- que era
 * cierto, para esa conexion --.  Entregado al siguiente sin reiniciarlo, todos
 * los desplazamientos por los que pregunten los lectores de esa conexion se
 * miden desde un punto que no tuvo nunca.
 *
 * \~
 */
void test_a_lent_buffer_starts_the_stream_over() {
    BufferPool p;
    check(p.reset(1, 1 << 20), "the pool would not be made");

    const uint32_t first = p.acquire();
    check(first != kNoBuffer, "a buffer could not be lent");

    Buffer *b = p.at(first);
    check(b != nullptr, "the lent buffer is not there");

    /* \~english
     * A connection that talked for a while: bytes written, bytes consumed, so
     * the stream has moved on from where it started.
     * \~spanish
     * Una conexion que hablo un rato: bytes escritos, bytes consumidos, asi que
     * el flujo se ha movido de donde empezo.
     * \~ */
    fill(*b, 1000);
    b->consume(1000);
    check(b->origin() != 0, "the stream did not move while the buffer was used");

    p.release(first);

    const uint32_t second = p.acquire();
    check(second == first, "the test did not get the same buffer back");

    Buffer *c = p.at(second);
    check(c != nullptr, "the lent buffer is not there");
    check(c != nullptr && c->empty(), "a buffer lent again is not empty");

    /* \~english
     * This is the whole test.  Empty is not enough; the stream has to start
     * over as well, or the new connection's offsets mean nothing.
     * \~spanish
     * Esta es toda la prueba.  Con estar vacio no basta; el flujo tambien tiene
     * que empezar de nuevo, o los desplazamientos de la conexion nueva no
     * significan nada.
     * \~ */
    check(c != nullptr && c->origin() == 0,
          "a buffer lent to another connection kept the previous stream position");

    /* \~english
     * And what it reports is usable from the start, which is what the readers
     * assume when they are reset to zero.
     * \~spanish
     * Y lo que dice se puede usar desde el principio, que es lo que dan por
     * hecho los lectores cuando se ponen a cero.
     * \~ */
    fill(*c, 10);
    const http_vx::View v = c->view();
    check(v.origin == 0, "the view of a lent buffer starts somewhere else");
    check(v.has(0, 10), "the first ten bytes of the stream are not reachable");
}

/**
 * @brief
 * \~english An empty pool says so rather than failing.
 * \~spanish Un pozo vacio lo dice en vez de fallar.
 * \~
 *
 * \~english
 * It is the server at its limit, not the server in trouble.  A connection
 * that cannot get a buffer does not read this time round; the bytes stay in
 * the kernel's receive queue, which is a place designed to hold them, and TCP
 * slows the peer down by itself.
 *
 * \~spanish
 * Es el servidor en su limite, no el servidor con un problema.  Una conexion que
 * no consigue buffer no lee esta vuelta; los bytes se quedan en la cola de
 * recepcion del nucleo, que es un sitio hecho para guardarlos, y TCP frena al
 * otro extremo el solo.
 *
 * \~
 */
void test_an_empty_pool_says_so() {
    BufferPool p;
    check(p.reset(2, 1 << 20), "the pool would not be made");

    const uint32_t a = p.acquire();
    const uint32_t b = p.acquire();
    check(a != kNoBuffer && b != kNoBuffer, "two buffers could not be lent");
    check(a != b, "the pool lent the same buffer twice");
    check(p.lent() == 2, "the lent buffers were not counted");

    check(p.acquire() == kNoBuffer, "an empty pool lent a third buffer");
    check(p.lent() == 2, "a refused loan changed the count");

    /* \~english
     * And one coming back makes room again, which is what turns the limit into
     * a limit on CONCURRENCY rather than on how many connections may ever be
     * served.
     * \~spanish
     * Y uno que vuelve hace sitio otra vez, que es lo que convierte el limite en
     * un limite de CONCURRENCIA y no de cuantas conexiones se pueden servir en
     * total.
     * \~ */
    p.release(a);
    const uint32_t again = p.acquire();
    check(again == a, "the buffer that came back was not the one lent again");
}

/**
 * @brief
 * \~english A buffer that grew enormous does not keep the memory.
 * \~spanish Un buffer que se hizo enorme no se queda la memoria.
 * \~
 *
 * \~english
 * One upload makes one buffer huge.  A pool that simply kept it would let
 * every slot creep up to the largest thing that ever went through it, and
 * settle at the peak times the count -- on a server that never looked like it
 * was leaking, because every byte of it is genuinely pooled.
 *
 * \~spanish
 * Una subida hace enorme un buffer.  Un pozo que se lo quedara sin mas dejaria
 * que todas las plazas subieran hasta lo mas grande que haya pasado por ellas, y
 * se asentaria en el pico por el numero -- en un servidor que no pareceria tener
 * ninguna fuga, porque todos sus bytes estan de verdad en el pozo.
 *
 * \~
 */
void test_a_buffer_that_grew_too_big_is_given_up() {
    BufferPool p;
    check(p.reset(2, 4096), "the pool would not be made");

    const uint32_t small = p.acquire();
    Buffer *b = p.at(small);
    check(b != nullptr, "the lent buffer is not there");

    fill(*b, 100);
    p.release(small);
    check(p.bytes_held() != 0, "an ordinary buffer gave its memory back");

    const uint32_t big = p.acquire();
    Buffer *c = p.at(big);
    check(c != nullptr, "the lent buffer is not there");

    fill(*c, 100000);
    check(c->size() == 100000, "the big write did not go in");
    const size_t peak = p.bytes_held();
    check(peak > 100000, "the pool is not holding what was written");

    p.release(big);
    check(p.bytes_held() < peak,
          "a buffer past the ceiling kept its memory for the next tenant");

    /* \~english
     * And it is still a buffer: the slot did not go anywhere, only what it was
     * holding.
     * \~spanish
     * Y sigue siendo un buffer: la plaza no se fue a ningun sitio, solo lo que
     * tenia dentro.
     * \~ */
    const uint32_t again = p.acquire();
    check(again != kNoBuffer, "the slot was lost with its memory");
    Buffer *d = p.at(again);
    check(d != nullptr && d->empty(), "the recovered buffer is not empty");
    fill(*d, 50);
    check(d->size() == 50, "the recovered buffer would not take anything");
}

/**
 * @brief
 * \~english Everything gets used, and comes back, many times over.
 * \~spanish Se usa todo, y vuelve, muchas veces.
 * \~
 */
void test_round_and_round() {
    BufferPool p;
    check(p.reset(8, 1 << 20), "the pool would not be made");

    for (int round = 0; round < 1000; ++round) {
        uint32_t held[8];
        for (int i = 0; i < 8; ++i) {
            held[i] = p.acquire();
            check(held[i] != kNoBuffer, "a buffer could not be lent");

            Buffer *b = p.at(held[i]);
            check(b != nullptr && b->empty() && b->origin() == 0,
                  "a buffer came back from the pool not ready to use");
            fill(*b, 64);
        }

        check(p.lent() == 8, "the pool did not lend everything");
        check(p.acquire() == kNoBuffer, "an empty pool lent another buffer");

        for (int i = 0; i < 8; ++i) p.release(held[i]);
        check(p.lent() == 0, "the pool did not get everything back");
    }

    /* \~english
     * Eight thousand loans and the memory is still eight buffers' worth, which
     * is the statement a pool exists to be able to make.
     * \~spanish
     * Ocho mil prestamos y la memoria sigue siendo la de ocho buffers, que es la
     * afirmacion que existe un pozo para poder hacer.
     * \~ */
    check(p.bytes_held() < 8 * 65536,
          "a thousand rounds of lending grew the pool");
}

} // namespace

int main() {
    test_the_ordinary_life_of_a_buffer();
    test_a_lent_buffer_starts_the_stream_over();
    test_an_empty_pool_says_so();
    test_a_buffer_that_grew_too_big_is_given_up();
    test_round_and_round();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
