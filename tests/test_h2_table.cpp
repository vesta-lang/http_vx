/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_table.cpp
 * @brief
 * \~english What a connection remembers, and when it forgets.
 * \~spanish Lo que recuerda una conexion, y cuando olvida.
 * \~
 *
 * \~english
 * Everything here is about ONE MOMENT: when an entry leaves.  Both ends work
 * it out separately and they have to get the same answer, because from the
 * first disagreement every index names a different field -- on a connection
 * that keeps working, decoding messages nobody sent.
 *
 * So the cases are the moment and its edges: the entry that exactly fills the
 * table, the one that is one byte too big, the one that is bigger than the
 * table itself, and the limit changing under a table that is already full.
 *
 * \~spanish
 * Todo lo de aqui va de UN MOMENTO: cuando se va una entrada.  Los dos extremos
 * lo calculan por separado y tienen que llegar a la misma respuesta, porque
 * desde la primera discrepancia todos los indices nombran otra cabecera -- en
 * una conexion que sigue funcionando, descodificando mensajes que no mando
 * nadie.
 *
 * Asi que los casos son el momento y sus extremos: la entrada que llena
 * exactamente la tabla, la que se pasa por un byte, la que es mayor que la
 * tabla misma, y el limite cambiando bajo una tabla que ya esta llena.
 *
 * \~
 */

#include "http_vx/h2_table.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::hpack::DynamicTable;
using http_vx::h2::hpack::kEntryOverhead;
using http_vx::h2::hpack::Pseudo;
using http_vx::h2::hpack::TableEntry;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

void add(DynamicTable &t, const char *name, const char *value,
         http_vx::FieldId id = http_vx::FieldId::Unknown) {
    t.add(reinterpret_cast<const uint8_t *>(name), std::strlen(name),
          reinterpret_cast<const uint8_t *>(value), std::strlen(value), id,
          Pseudo::None);
}

/**
 * @brief
 * \~english Whether entry @p i is the name and value it should be.
 * \~spanish Si la entrada @p i es el nombre y el valor que deberia.
 * \~
 */
bool entry_is(const DynamicTable &t, size_t i, const char *name,
              const char *value) {
    const TableEntry *e = t.at(i);
    if (e == nullptr) return false;

    uint8_t buf[512];
    const size_t n = t.copy_name(i, buf, sizeof(buf));
    if (n != std::strlen(name) || std::memcmp(buf, name, n) != 0) return false;

    const size_t v = t.copy_value(i, buf, sizeof(buf));
    if (v != std::strlen(value) || std::memcmp(buf, value, v) != 0) return false;

    return e->name_len == n && e->value_len == v;
}

/**
 * @brief
 * \~english Nothing is made until something is remembered.
 * \~spanish No se hace nada hasta que se recuerda algo.
 * \~
 *
 * \~english
 * Four kilobytes on a million connections is four gigabytes, and most
 * connections never remember a field: a `GET` whose headers all come from the
 * static table asks the peer to remember nothing.  Announcing a size is not
 * reserving it, and the difference is the difference between a number and a
 * gigabyte.
 *
 * \~spanish
 * Cuatro kilobytes en un millon de conexiones son cuatro gigabytes, y casi
 * ninguna conexion recuerda una cabecera: un `GET` cuyas cabeceras salgan todas
 * de la tabla estatica no le pide al otro extremo que recuerde nada.  Anunciar
 * un tamano no es reservarlo, y la diferencia es la que hay entre un numero y
 * un gigabyte.
 *
 * \~
 */
void test_nothing_until_used() {
    DynamicTable t;
    t.reset(4096);

    check(t.count() == 0, "a fresh table remembers something");
    check(t.size() == 0, "a fresh table costs something");
    check(t.max_size() == 4096, "the limit is not what was announced");
    check(t.announced() == 4096, "the announcement was not remembered");
    check(t.at(0) == nullptr, "a fresh table has a first entry");

    /* \~english
     * And a size update on a table nobody has used still makes nothing.
     * \~spanish
     * Y un cambio de tamano en una tabla que nadie ha usado tampoco hace nada.
     * \~ */
    check(t.set_max_size(1024), "a smaller limit within the announcement was refused");
    check(t.max_size() == 1024, "the limit did not change");
    check(t.count() == 0, "changing the limit invented an entry");
}

/**
 * @brief
 * \~english The newest is index zero, which is the opposite of the order.
 * \~spanish La mas nueva es el indice cero, que es al reves del orden.
 * \~
 */
void test_order() {
    DynamicTable t;
    t.reset(4096);

    add(t, "one", "1");
    add(t, "two", "2");
    add(t, "three", "3");

    check(t.count() == 3, "three entries did not go in");
    check(entry_is(t, 0, "three", "3"), "index zero is not the newest");
    check(entry_is(t, 1, "two", "2"), "index one is not the one before");
    check(entry_is(t, 2, "one", "1"), "index two is not the oldest");
    check(t.at(3) == nullptr, "there is a fourth entry");

    /* \~english
     * And what they cost between them: the bytes, plus thirty-two each.  The
     * thirty-two is not an estimate of anything here -- it is what the other
     * end also adds, so that both evict at the same moment.
     * \~spanish
     * Y lo que cuestan entre todas: los bytes, mas treinta y dos cada una.  Los
     * treinta y dos no son una estimacion de nada de aqui -- son lo que suma
     * tambien el otro extremo, para que los dos desalojen en el mismo momento.
     * \~ */
    const uint32_t want = (3 + 1) + (3 + 1) + (5 + 1) + 3 * kEntryOverhead;
    check(t.size() == want, "the cost is not the bytes plus thirty-two each");
}

/**
 * @brief
 * \~english The moment an entry leaves, at its edges.
 * \~spanish El momento en que se va una entrada, en sus extremos.
 * \~
 */
void test_eviction() {
    /* \~english
     * A table that fits exactly two entries and not three.  Each is one byte
     * of name and one of value, so thirty-four apiece.
     * \~spanish
     * Una tabla en la que caben exactamente dos entradas y no tres.  Cada una
     * es un byte de nombre y uno de valor, asi que treinta y cuatro cada una.
     * \~ */
    DynamicTable t;
    t.reset(68);

    add(t, "a", "1");
    add(t, "b", "2");
    check(t.count() == 2, "two entries that fit exactly did not both go in");
    check(t.size() == 68, "two entries that fill it do not add up to the limit");

    /* \~english One more, and the oldest goes.  \~spanish Una mas, y se va la mas vieja.  \~ */
    add(t, "c", "3");
    check(t.count() == 2, "the table grew past its limit");
    check(entry_is(t, 0, "c", "3"), "the new entry is not the newest");
    check(entry_is(t, 1, "b", "2"), "the wrong entry was thrown out");

    /* \~english
     * An entry that needs more room than one costs two of them.
     * \~spanish
     * Una entrada que necesita mas sitio que una cuesta dos de ellas.
     * \~ */
    add(t, "longer", "value");
    check(t.count() == 1, "one big entry did not push out both small ones");
    check(entry_is(t, 0, "longer", "value"), "the big entry is not there");
}

/**
 * @brief
 * \~english An entry bigger than the table empties it, and is not an error.
 * \~spanish Una entrada mayor que la tabla la vacia, y no es un error.
 * \~
 *
 * \~english
 * RFC 7541 section 4.4, and the reason it is a rule rather than a refusal is
 * that the encoder does the same thing: after this, both ends have the same
 * empty table, so the next index means the same on both sides.  A decoder that
 * answered with an error would be refusing a message an encoder is entitled to
 * send -- and one that kept the old entries would disagree about every index
 * from here on.
 *
 * \~spanish
 * RFC 7541 seccion 4.4, y la razon de que sea una regla y no un rechazo es que
 * el codificador hace lo mismo: despues de esto los dos extremos tienen la
 * misma tabla vacia, asi que el indice siguiente significa lo mismo en los dos
 * lados.  Un descodificador que contestara con un error estaria rechazando un
 * mensaje que un codificador puede mandar -- y uno que se quedara las entradas
 * viejas discreparia sobre todos los indices de ahi en adelante.
 *
 * \~
 */
void test_too_big_empties_it() {
    DynamicTable t;
    t.reset(68);

    add(t, "a", "1");
    add(t, "b", "2");
    check(t.count() == 2, "the two entries did not go in");

    char big[64];
    std::memset(big, 'x', sizeof(big));
    big[sizeof(big) - 1] = '\0';

    add(t, big, "");
    check(t.count() == 0, "an entry bigger than the table did not empty it");
    check(t.size() == 0, "the table still costs something after being emptied");
    check(t.at(0) == nullptr, "the oversized entry was added anyway");
}

/**
 * @brief
 * \~english A smaller limit throws things out now, not later.
 * \~spanish Un limite menor tira cosas ahora, no despues.
 * \~
 *
 * \~english
 * Both ends evict at the same moment or they stop agreeing about what an index
 * means, and "when the next field arrives" is not the same moment as "now".
 *
 * \~spanish
 * Los dos extremos desalojan en el mismo momento o dejan de estar de acuerdo
 * sobre lo que significa un indice, y "cuando llegue la cabecera siguiente" no
 * es el mismo momento que "ahora".
 *
 * \~
 */
void test_shrinking() {
    DynamicTable t;
    t.reset(4096);

    add(t, "a", "1");
    add(t, "b", "2");
    add(t, "c", "3");
    check(t.count() == 3, "three entries did not go in");

    t.set_max_size(68);
    check(t.count() == 2, "making the table smaller did not throw anything out");
    check(entry_is(t, 0, "c", "3"), "the newest was thrown out instead of the oldest");
    check(entry_is(t, 1, "b", "2"), "the wrong one was kept");

    t.set_max_size(0);
    check(t.count() == 0, "a limit of zero kept something");
    check(t.size() == 0, "a limit of zero still costs something");

    /* \~english And it can come back, because zero is a limit and not an end.
     * \~spanish Y puede volver, porque cero es un limite y no un final.  \~ */
    check(t.set_max_size(4096), "the limit could not go back up to the announcement");
    add(t, "again", "yes");
    check(t.count() == 1, "the table does not work again after being emptied");
}

/**
 * @brief
 * \~english More than was announced is refused, not obeyed.
 * \~spanish Mas de lo anunciado se rechaza, no se obedece.
 * \~
 *
 * \~english
 * The announcement is what this end sized its arithmetic for.  A peer asking
 * past it is asking this server to remember more than it said it would, which
 * is exactly what a limit is for -- and obeying would mean writing past the
 * memory that was made for the announced size.
 *
 * \~spanish
 * El anuncio es para lo que este extremo dimensiono su aritmetica.  Un extremo
 * que pida por encima esta pidiendo a este servidor que recuerde mas de lo que
 * dijo, que es justo para lo que existe un limite -- y obedecer seria escribir
 * mas alla de la memoria que se hizo para el tamano anunciado.
 *
 * \~
 */
void test_past_the_announcement() {
    DynamicTable t;
    t.reset(4096);

    check(!t.set_max_size(4097), "a limit past the announcement was accepted");
    check(t.max_size() == 4096, "the refused limit was applied anyway");

    check(!t.set_max_size(0xFFFFFFFFu), "an enormous limit was accepted");
    check(t.max_size() == 4096, "the enormous limit was applied anyway");

    check(t.set_max_size(4096), "the announcement itself was refused");
}

/**
 * @brief
 * \~english Round and round the ring, until it wraps.
 * \~spanish Vuelta y vuelta al anillo, hasta que da la vuelta.
 * \~
 *
 * \~english
 * The bytes live in a ring, so a name or a value eventually straddles the end
 * of it -- and a straddling string is the one that comes back in two pieces,
 * or in one piece and some rubbish.  It takes enough insertions to get there,
 * which is why this is a loop and not a case.
 *
 * \~spanish
 * Los bytes viven en un anillo, asi que un nombre o un valor acaban a caballo
 * del final -- y una cadena a caballo es la que vuelve en dos pedazos, o en uno
 * y algo de basura.  Hacen falta bastantes inserciones para llegar, que es la
 * razon de que esto sea un bucle y no un caso.
 *
 * \~
 */
void test_the_ring_wraps() {
    DynamicTable t;
    t.reset(200);

    char name[16];
    char value[24];

    for (int round = 0; round < 200; ++round) {
        std::snprintf(name, sizeof(name), "n%d", round);
        std::snprintf(value, sizeof(value), "v%d-%d", round, round * 7);
        add(t, name, value);

        /* \~english
         * After every insertion the newest must read back exactly, whatever
         * the ring did underneath.  Checking only at the end would pass a ring
         * that was wrong for a while and came right again.
         * \~spanish
         * Despues de cada insercion la mas nueva tiene que leerse exacta, haga
         * lo que haga el anillo por debajo.  Comprobar solo al final dejaria
         * pasar un anillo que estuvo mal un rato y volvio a estar bien.
         * \~ */
        check(entry_is(t, 0, name, value),
              "the newest entry did not read back after an insertion");

        check(t.size() <= t.max_size(), "the table went past its limit");
    }

    /* \~english
     * And every entry still in it reads back, which is what catches a string
     * whose two pieces were joined in the wrong order.
     * \~spanish
     * Y todas las entradas que siguen dentro se leen, que es lo que pilla una
     * cadena cuyos dos pedazos se unieron en el orden equivocado.
     * \~ */
    for (size_t i = 0; i < t.count(); ++i) {
        const TableEntry *e = t.at(i);
        check(e != nullptr, "an entry inside the table is missing");
        if (e == nullptr) continue;

        uint8_t buf[64];
        check(t.copy_name(i, buf, sizeof(buf)) == e->name_len,
              "a name did not come back the length it says it is");
        check(t.copy_value(i, buf, sizeof(buf)) == e->value_len,
              "a value did not come back the length it says it is");
    }
}

/**
 * @brief
 * \~english What is remembered outlives the bytes it came in.
 * \~spanish Lo recordado sobrevive a los bytes en los que vino.
 * \~
 *
 * \~english
 * This is why the table copies, and it is the one place in this project that
 * copies a header.  An entry is used several requests after the message that
 * carried it, and a span into that message would name bytes the connection
 * dropped long ago.
 *
 * \~spanish
 * Por esto copia la tabla, y es el unico sitio de este proyecto donde se copia
 * una cabecera.  Una entrada se usa varias peticiones despues del mensaje que
 * la llevaba, y un trozo de ese mensaje nombraria bytes que la conexion
 * descarto hace mucho.
 *
 * \~
 */
void test_it_copies() {
    DynamicTable t;
    t.reset(4096);

    char scratch[32];
    std::strcpy(scratch, "x-token");
    char val[32];
    std::strcpy(val, "abc123");

    add(t, scratch, val);

    /* \~english The bytes it came in are gone.  \~spanish Los bytes en los que vino ya no estan.  \~ */
    std::memset(scratch, 0, sizeof(scratch));
    std::memset(val, 0, sizeof(val));

    check(entry_is(t, 0, "x-token", "abc123"),
          "the entry pointed at bytes that belonged to the message");
}

/**
 * @brief
 * \~english Giving the memory back, and using it again.
 * \~spanish Devolver la memoria, y volver a usarla.
 * \~
 */
void test_release() {
    DynamicTable t;
    t.reset(4096);

    add(t, "a", "1");
    check(t.count() == 1, "the entry did not go in");

    t.release();
    check(t.count() == 0, "releasing kept the entries");
    check(t.size() == 0, "releasing kept the cost");

    /* \~english
     * And the announcement survives, because it is what the peer was told and
     * the peer was not told twice.
     * \~spanish
     * Y el anuncio sobrevive, porque es lo que se le dijo al otro extremo y al
     * otro extremo no se le dijo dos veces.
     * \~ */
    check(t.announced() == 4096, "releasing forgot what the peer was told");

    add(t, "b", "2");
    check(t.count() == 1, "the table does not work again after being released");
    check(entry_is(t, 0, "b", "2"), "what came back is not what went in");
}

/**
 * @brief
 * \~english A copy into nowhere near enough room writes nothing.
 * \~spanish Una copia a un sitio mucho menor no escribe nada.
 * \~
 */
void test_no_room() {
    DynamicTable t;
    t.reset(4096);
    add(t, "content-type", "text/html");

    uint8_t small[4];
    check(t.copy_name(0, small, sizeof(small)) == 0,
          "a name was half written into a buffer that was too small");
    check(t.copy_value(0, small, sizeof(small)) == 0,
          "a value was half written into a buffer that was too small");

    uint8_t exact[12];
    check(t.copy_name(0, exact, sizeof(exact)) == 12,
          "a name did not fit a buffer of exactly its size");

    check(t.copy_name(9, small, sizeof(small)) == 0,
          "an entry that is not there was copied");
}

} // namespace

int main() {
    test_nothing_until_used();
    test_order();
    test_eviction();
    test_too_big_empties_it();
    test_shrinking();
    test_past_the_announcement();
    test_the_ring_wraps();
    test_it_copies();
    test_release();
    test_no_room();

    if (failures != 0) {
        std::fprintf(stderr, "test_h2_table: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h2_table: ok\n");
    return 0;
}
