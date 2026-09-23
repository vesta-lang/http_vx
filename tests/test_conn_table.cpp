/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_conn_table.cpp
 * @brief
 * \~english Slots, and the reference from a life that is over.
 * \~spanish Casillas, y la referencia de una vida que ya se acabo.
 * \~
 *
 * \~english
 * One case here matters more than all the others put together: a handle from
 * a connection that has gone, used on a slot somebody else is now in.
 *
 * It is the failure a slot-based table exists to have, and it does not crash.
 * Every field it reads is a valid field of a valid connection.  Nothing
 * reports anything.  What happens is that one client's request is served on
 * another client's socket -- and the two clients are, from the server's point
 * of view, indistinguishable from each other.
 *
 * So the test does it on purpose, from both directions: reading through a
 * stale handle, and CLOSING through one, which is the worse of the two
 * because it is what a deadline that fired late would do.
 *
 * \~spanish
 * Un caso de aqui importa mas que todos los demas juntos: una referencia de una
 * conexion que ya se fue, usada sobre una casilla en la que ahora esta otro.
 *
 * Es el fallo para tener el cual existe una tabla de casillas, y no revienta.
 * Todos los campos que lee son campos validos de una conexion valida.  Nadie
 * informa de nada.  Lo que pasa es que la peticion de un cliente se sirve por el
 * socket de otro -- y los dos clientes son, desde el punto de vista del
 * servidor, indistinguibles entre si.
 *
 * Asi que la prueba lo hace a proposito, por los dos lados: leer con una
 * referencia rancia, y CERRAR con una, que es el peor de los dos porque es lo
 * que haria un plazo que vencio tarde.
 *
 * \~
 */

#include "http_vx/conn_table.h"

#include <cstdio>

namespace {

using http_vx::ConnCold;
using http_vx::ConnHandle;
using http_vx::ConnHot;
using http_vx::ConnTable;
using http_vx::kNoBuffer;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english A connection is opened, read and closed.
 * \~spanish Una conexion se abre, se lee y se cierra.
 * \~
 */
void test_the_ordinary_life_of_a_slot() {
    ConnTable t;
    check(t.reset(8), "the table would not be made");
    check(t.count() == 0, "a fresh table has connections in it");
    check(t.capacity() == 8, "the table is not the size it was asked for");

    const ConnHandle h = t.open(42, 1000);
    check(h.valid(), "a connection could not be opened");
    check(t.count() == 1, "the connection was not counted");
    check(t.alive(h), "a connection that was just opened is not alive");

    ConnHot *hot = t.hot(h);
    check(hot != nullptr, "the hot record is not there");
    check(hot != nullptr && hot->fd == 42, "the socket is not the one given");
    check(hot != nullptr && hot->queue == kNoBuffer,
          "a new connection already has answers queued");
    check(hot != nullptr && hot->flags == 0,
          "a new connection already has something outstanding");

    ConnCold *cold = t.cold(h);
    check(cold != nullptr, "the cold record is not there");
    check(cold != nullptr && cold->opened == 1000,
          "the connection does not know when it arrived");
    check(cold != nullptr && cold->bytes_in == 0,
          "a new connection has already read something");

    check(t.close(h), "the connection could not be closed");
    check(t.count() == 0, "a closed connection is still counted");
    check(!t.alive(h), "a closed connection is still alive");
    check(t.hot(h) == nullptr, "a closed connection still has a hot record");
}

/**
 * @brief
 * \~english A handle from a previous life is refused, and so is a close.
 * \~spanish Una referencia de una vida anterior se rechaza, y un cierre tambien.
 * \~
 *
 * \~english
 * The one this file is for.  The slot is opened, closed, and opened again --
 * so the second connection is a different person in the same seat -- and the
 * first connection's handle is then used on it.
 *
 * The close is the worse half.  A deadline armed for the first connection,
 * firing a moment after it went away, would close the second one: a client
 * that did nothing wrong, disconnected for another client's timeout, on a
 * server where nothing at all went wrong as far as anyone can see.
 *
 * \~spanish
 * El que justifica este fichero.  La casilla se abre, se cierra y se vuelve a
 * abrir -- asi que la segunda conexion es otra persona en el mismo asiento -- y
 * entonces se usa sobre ella la referencia de la primera.
 *
 * El cierre es la peor mitad.  Un plazo armado para la primera conexion,
 * venciendo un momento despues de que se fuera, cerraria a la segunda: un
 * cliente que no hizo nada mal, desconectado por el plazo de otro, en un
 * servidor donde no ha ido nada mal hasta donde puede ver nadie.
 *
 * \~
 */
void test_a_stale_handle_names_nobody() {
    ConnTable t;
    check(t.reset(1), "the table would not be made");

    const ConnHandle first = t.open(10, 0);
    check(first.valid(), "the first connection could not be opened");
    check(t.close(first), "the first connection could not be closed");

    /* \~english
     * With one slot there is only one seat, so the second connection is
     * certainly in it.  That is the arrangement, not a coincidence to be
     * hoped for.
     * \~spanish
     * Con una sola casilla no hay mas que un asiento, asi que la segunda
     * conexion esta en el seguro.  Eso es la disposicion, no una casualidad que
     * haya que esperar.
     * \~ */
    const ConnHandle second = t.open(20, 0);
    check(second.valid(), "the second connection could not be opened");
    check(second.slot == first.slot, "the test did not reuse the slot");
    check(second.life != first.life, "the slot was reused on the same life");

    check(!t.alive(first), "a handle from a previous life says it is alive");
    check(t.hot(first) == nullptr,
          "a handle from a previous life reached a hot record");
    check(t.cold(first) == nullptr,
          "a handle from a previous life reached a cold record");

    /* \~english
     * And the close, which is the one that would disconnect somebody.
     * \~spanish
     * Y el cierre, que es el que desconectaria a alguien.
     * \~ */
    check(!t.close(first), "a handle from a previous life closed a connection");
    check(t.alive(second), "a stale close took out the connection that was there");
    check(t.count() == 1, "a stale close changed the count");

    ConnHot *hot = t.hot(second);
    check(hot != nullptr && hot->fd == 20,
          "the connection that was there lost its socket");
}

/**
 * @brief
 * \~english A freed slot waits its turn rather than coming straight back.
 * \~spanish Una casilla liberada espera su turno en vez de volver en el acto.
 * \~
 *
 * \~english
 * A queue and not a stack, and this is what the difference is for: the slot
 * that was just freed is the LAST to be handed out again, so a reference to it
 * has the whole table's worth of openings to be caught in rather than none.
 *
 * It is checked because the natural way to write a free list is a stack -- it
 * is one line shorter and warmer in cache -- and nothing about a stack would
 * ever fail.
 *
 * \~spanish
 * Una cola y no una pila, y para esto es la diferencia: la casilla recien
 * liberada es la ULTIMA en volver a repartirse, asi que una referencia a ella
 * tiene toda una tabla de aperturas para que la pillen en vez de ninguna.
 *
 * Se comprueba porque la forma natural de escribir una lista de libres es una
 * pila -- es una linea mas corta y esta mas caliente en cache -- y nada de una
 * pila fallaria nunca.
 *
 * \~
 */
void test_a_freed_slot_goes_to_the_back() {
    ConnTable t;
    check(t.reset(4), "the table would not be made");

    ConnHandle h[4];
    for (int i = 0; i < 4; ++i) {
        h[i] = t.open(100 + i, 0);
        check(h[i].valid(), "a connection could not be opened");
    }
    check(t.count() == 4, "four connections were not counted");

    /* \~english
     * The table is full, so the next one is refused -- which is the accept
     * loop being told to stop, not an error.
     * \~spanish
     * La tabla esta llena, asi que la siguiente se rechaza -- que es decirle al
     * bucle de aceptacion que pare, no un error.
     * \~ */
    check(!t.open(200, 0).valid(), "a full table opened another connection");

    check(t.close(h[1]), "a connection could not be closed");
    check(t.close(h[2]), "a connection could not be closed");

    /* \~english
     * Slot one was freed first, so it is the first to come back.  A stack
     * would hand back slot two.
     * \~spanish
     * La casilla uno se libero antes, asi que es la primera en volver.  Una pila
     * devolveria la dos.
     * \~ */
    const ConnHandle next = t.open(300, 0);
    check(next.slot == h[1].slot,
          "the slot that had been free longest was not the one handed back");
}

/**
 * @brief
 * \~english A bare index becomes a handle only by asking the table.
 * \~spanish Un indice desnudo se convierte en referencia solo preguntandole a la tabla.
 * \~
 *
 * \~english
 * An event queue hands back a number, and that number has to become a handle
 * somewhere.  Doing it here means the life is READ from the table instead of
 * being carried along by whoever had the number -- which is the only way a
 * number that arrived from outside can be trusted at all.
 *
 * \~spanish
 * Una cola de sucesos devuelve un numero, y ese numero tiene que convertirse en
 * una referencia en algun sitio.  Hacerlo aqui quiere decir que la vida se LEE
 * de la tabla en vez de traerla quien tuviera el numero -- que es la unica forma
 * de que un numero llegado de fuera se pueda creer en absoluto.
 *
 * \~
 */
void test_an_index_is_turned_back_into_a_handle() {
    ConnTable t;
    check(t.reset(4), "the table would not be made");

    const ConnHandle h = t.open(55, 0);
    check(h.valid(), "a connection could not be opened");

    const ConnHandle again = t.at(h.slot);
    check(again.valid(), "a live slot did not give back a handle");
    check(again.slot == h.slot && again.life == h.life,
          "the slot gave back a different handle than it was opened with");
    check(t.alive(again), "the handle from the table is not alive");

    /* \~english
     * A free slot gives back nothing, which is what stops a number from an old
     * completion being turned into a handle for a connection that has gone.
     * \~spanish
     * Una casilla libre no devuelve nada, que es lo que impide convertir un
     * numero de una finalizacion vieja en una referencia a una conexion que ya
     * se fue.
     * \~ */
    check(t.close(h), "the connection could not be closed");
    check(!t.at(h.slot).valid(), "a free slot gave back a handle");
    check(!t.at(t.capacity()).valid(), "a slot past the table gave back a handle");
}

/**
 * @brief
 * \~english A default handle reaches nothing.
 * \~spanish Una referencia sin rellenar no llega a nada.
 * \~
 *
 * \~english
 * A handle that was never filled in is what a caller has before it opens
 * anything and after it gives up, and it turns up wherever somebody forgot a
 * branch.  It must reach nothing, including in a table where slot zero is
 * open -- which is why the lives start at one and not at zero.
 *
 * \~spanish
 * Una referencia que no se relleno nunca es lo que tiene quien llama antes de
 * abrir nada y despues de rendirse, y aparece dondequiera que alguien se dejo
 * una rama.  No puede llegar a nada, ni siquiera en una tabla donde la casilla
 * cero esta abierta -- que es la razon de que las vidas empiecen en uno y no en
 * cero.
 *
 * \~
 */
void test_a_handle_nobody_filled_in() {
    ConnTable t;
    check(t.reset(4), "the table would not be made");

    const ConnHandle zero = t.open(7, 0);
    check(zero.valid() && zero.slot == 0, "the first slot is not slot zero");

    const ConnHandle none;
    check(!none.valid(), "a default handle says it names a slot");
    check(!t.alive(none), "a default handle is alive");
    check(t.hot(none) == nullptr, "a default handle reached a record");
    check(!t.close(none), "a default handle closed something");
    check(t.alive(zero), "a default close took out slot zero");

    /* \~english
     * And the same made by hand with slot zero in it, which is the shape a
     * zeroed structure has.
     * \~spanish
     * Y la misma hecha a mano con la casilla cero dentro, que es la forma que
     * tiene una estructura puesta a cero.
     * \~ */
    const ConnHandle zeroed{0, 0};
    check(!t.alive(zeroed), "a zeroed handle matched a live slot");
    check(!t.close(zeroed), "a zeroed handle closed a live connection");
    check(t.alive(zero), "a zeroed close took out slot zero");
}

/**
 * @brief
 * \~english Every slot gets used, and every life is a new one.
 * \~spanish Se usan todas las casillas, y toda vida es nueva.
 * \~
 *
 * \~english
 * Round and round the table, keeping the handle from each life and checking it
 * against the next.  A table that reused a life -- because the counter was per
 * table rather than per slot, say, or because it was bumped on open rather
 * than on close -- would be caught here and nowhere else.
 *
 * \~spanish
 * Vueltas y vueltas a la tabla, guardando la referencia de cada vida y
 * comprobandola contra la siguiente.  Una tabla que reutilizara una vida --
 * porque el contador fuera de la tabla y no de la casilla, pongamos, o porque
 * subiera al abrir en vez de al cerrar -- se pillaria aqui y en ningun otro
 * sitio.
 *
 * \~
 */
void test_going_all_the_way_round() {
    ConnTable t;
    check(t.reset(3), "the table would not be made");

    /* \~english
     * The handles of the round BEFORE this one.  They are kept separately from
     * the ones being opened now, because the ones being opened now are alive
     * on purpose -- checking those would be checking that a live connection is
     * dead, which is how the first version of this test failed sixty times and
     * was right about none of them.
     * \~spanish
     * Las referencias de la ronda ANTERIOR a esta.  Se guardan aparte de las que
     * se estan abriendo ahora, porque las que se abren ahora estan vivas a
     * proposito -- comprobar esas seria comprobar que una conexion viva esta
     * muerta, que es como la primera version de esta prueba fallo sesenta veces
     * sin tener razon en ninguna.
     * \~ */
    ConnHandle before[3];
    for (int i = 0; i < 3; ++i) before[i] = ConnHandle{};

    for (int round = 0; round < 20; ++round) {
        ConnHandle now[3];

        for (int i = 0; i < 3; ++i) {
            now[i] = t.open(1000 + i, 0);
            check(now[i].valid(), "a connection could not be opened");

            for (int j = 0; j < 3; ++j)
                check(!t.alive(before[j]),
                      "a handle from an earlier life came back alive");
        }

        check(t.count() == 3, "the table did not fill up");
        check(!t.open(9, 0).valid(), "a full table opened another connection");

        for (int i = 0; i < 3; ++i) {
            check(t.close(now[i]), "a close was refused");
            before[i] = now[i];
        }
        check(t.count() == 0, "the table did not empty");
    }
}

} // namespace

int main() {
    test_the_ordinary_life_of_a_slot();
    test_a_stale_handle_names_nobody();
    test_a_freed_slot_goes_to_the_back();
    test_an_index_is_turned_back_into_a_handle();
    test_a_handle_nobody_filled_in();
    test_going_all_the_way_round();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
