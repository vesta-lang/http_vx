/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_settings.cpp
 * @brief
 * \~english What the two ends agreed on, and the allowance that can go negative.
 * \~spanish En que quedaron los dos extremos, y el credito que puede ser negativo.
 * \~
 *
 * \~english
 * Two things are being tested and only one of them looks like parsing.
 *
 * The first is the six values and their edges, which is ordinary: a frame size
 * below the floor, a push flag that is neither zero nor one, a window past what
 * the field holds.  Each is refused with a DIFFERENT error, and the test
 * checks which -- because the error is what goes out in the GOAWAY, and a
 * connection closed with the wrong reason is a connection whose peer cannot
 * tell a bug from an attack.
 *
 * The second is the one that is really about arithmetic: a window that goes
 * into DEBT.  It cannot happen by sending -- nobody may send more than they
 * are allowed -- and it happens anyway, when the peer lowers the initial
 * window on streams that already exist.  The test drives that case on purpose,
 * because an implementation that held windows unsigned does not fail it with
 * an error: it wraps, and hands out four gigabytes.
 *
 * \~spanish
 * Se prueban dos cosas y solo una tiene pinta de analisis.
 *
 * La primera son los seis valores y sus extremos, que es lo corriente: un
 * tamano de trama por debajo del suelo, una marca de empuje que no es cero ni
 * uno, una ventana pasada de lo que cabe en el campo.  Cada uno se rechaza con
 * un error DISTINTO, y la prueba comprueba cual -- porque el error es lo que
 * sale en el GOAWAY, y una conexion cerrada con la razon equivocada es una
 * cuyo extremo no puede distinguir un fallo de un ataque.
 *
 * La segunda es la que va de aritmetica de verdad: una ventana que se queda en
 * DEUDA.  No puede pasar mandando -- nadie puede mandar mas de lo que le dejan
 * -- y pasa igualmente, cuando el otro extremo baja la ventana inicial sobre
 * flujos que ya existen.  La prueba lleva ese caso a proposito, porque una
 * implementacion que guardara las ventanas sin signo no falla aqui con un
 * error: da la vuelta, y reparte cuatro gigabytes.
 *
 * \~
 */

#include "http_vx/h2_flow.h"
#include "http_vx/h2_settings.h"

#include <cstdio>

namespace {

using http_vx::h2::ErrorCode;
using http_vx::h2::kMaxWindow;
using http_vx::h2::Settings;
using http_vx::h2::SettingsChange;
using http_vx::h2::SettingId;
using http_vx::h2::Window;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Writes one setting into @p p.
 * \~spanish Escribe un ajuste en @p p.
 * \~
 */
void one(uint8_t *p, SettingId id, uint32_t value) {
    http_vx::h2::put_be16(p, static_cast<uint16_t>(id));
    http_vx::h2::put_be32(p + 2, value);
}

/**
 * @brief
 * \~english A connection nobody has spoken on already has the right numbers.
 * \~spanish Una conexion en la que nadie ha hablado ya tiene los numeros buenos.
 * \~
 *
 * \~english
 * It matters more than it looks.  The first SETTINGS is not instantaneous --
 * it is a frame, and there is a round trip before it arrives -- so a
 * connection that treated "not told yet" as zero would spend that round trip
 * believing the peer accepts nothing at all.
 *
 * \~spanish
 * Importa mas de lo que parece.  El primer SETTINGS no es instantaneo -- es una
 * trama, y hay una ida y vuelta antes de que llegue -- asi que una conexion que
 * tomara "todavia no me lo han dicho" por cero se pasaria esa ida y vuelta
 * creyendo que el otro extremo no acepta absolutamente nada.
 *
 * \~
 */
void test_a_fresh_connection_is_already_right() {
    const Settings s;
    check(s.header_table_size == 4096, "the default header table is not 4096");
    check(s.initial_window_size == 65535,
          "the default window is not the specification's 65535");
    check(s.max_frame_size == 16384, "the default frame size is not 16384");
    check(s.enable_push, "push does not start allowed");
    check(s.max_concurrent_streams == 0xFFFFFFFF,
          "concurrency starts limited when nobody has said so");
}

/**
 * @brief
 * \~english Each bad value is refused, and with its own error.
 * \~spanish Cada valor malo se rechaza, y con su propio error.
 * \~
 */
void test_a_bad_value_says_which_kind_it_is() {
    uint8_t buf[6];
    Settings s;

    /* \~english
     * A payload that is not a whole number of settings says the sender's frame
     * header disagreed with the sender's own payload, which is a different
     * failure from a value this end refuses.
     * \~spanish
     * Una carga que no es un numero entero de ajustes dice que la cabecera de
     * trama de quien envia discrepaba de su propia carga, que es un fallo
     * distinto de un valor que este extremo rechaza.
     * \~ */
    check(http_vx::h2::apply_settings(buf, 5, s).error ==
              ErrorCode::FrameSizeError,
          "a payload that is not a whole number of settings was accepted");

    one(buf, SettingId::EnablePush, 2);
    check(http_vx::h2::apply_settings(buf, sizeof buf, s).error ==
              ErrorCode::ProtocolError,
          "a push flag that is neither zero nor one was accepted");

    one(buf, SettingId::MaxFrameSize, 16383);
    check(http_vx::h2::apply_settings(buf, sizeof buf, s).error ==
              ErrorCode::ProtocolError,
          "a frame size below the floor every peer may assume was accepted");

    one(buf, SettingId::MaxFrameSize, 16777216);
    check(http_vx::h2::apply_settings(buf, sizeof buf, s).error ==
              ErrorCode::ProtocolError,
          "a frame size above the ceiling was accepted");

    /* \~english
     * This one is a flow-control error and not a protocol one, because what it
     * breaks is the arithmetic rather than the grammar.
     * \~spanish
     * Este es un error de control de flujo y no de protocolo, porque lo que
     * rompe es la aritmetica y no la gramatica.
     * \~ */
    one(buf, SettingId::InitialWindowSize, 0x80000000u);
    check(http_vx::h2::apply_settings(buf, sizeof buf, s).error ==
              ErrorCode::FlowControlError,
          "a window larger than the field holds was accepted");
}

/**
 * @brief
 * \~english A setting nobody here knows is ignored, not refused.
 * \~spanish Un ajuste que aqui no conoce nadie se ignora, no se rechaza.
 * \~
 *
 * \~english
 * The one place in this project where ignoring something is right, and it is
 * worth a test of its own because the instinct everywhere else is the
 * opposite.  An implementation that refused what it did not recognise would
 * break the connection with every peer newer than this build -- which is the
 * failure that froze HTTP/1.1 in place for fifteen years.
 *
 * \~spanish
 * El unico sitio de este proyecto donde ignorar algo esta bien, y merece una
 * prueba propia porque en todos los demas el instinto es el contrario.  Una
 * implementacion que rechazara lo que no reconoce romperia la conexion con
 * todos los extremos mas nuevos que esta construccion -- que es el fallo que
 * dejo congelado HTTP/1.1 durante quince anos.
 *
 * \~
 */
void test_an_unknown_setting_is_carried_past() {
    uint8_t buf[12];
    one(buf, static_cast<SettingId>(0xBEEF), 1234);
    one(buf + 6, SettingId::MaxFrameSize, 32768);

    Settings s;
    const SettingsChange c = http_vx::h2::apply_settings(buf, sizeof buf, s);

    check(c.error == ErrorCode::NoError, "an unknown setting was refused");
    check(s.max_frame_size == 32768,
          "an unknown setting stopped the one after it being read");
}

/**
 * @brief
 * \~english The window delta is measured across the whole payload.
 * \~spanish La diferencia de ventana se mide sobre la carga entera.
 * \~
 *
 * \~english
 * A payload may name the same identifier three times.  What the connection
 * ends up with is the last value, and what every open stream must move by is
 * the difference between where the window STARTED and where it ended -- not
 * the sum of the steps, and not the last step.  A peer that read the payload
 * as a whole will have done exactly that, and a server that did anything else
 * would have every stream's allowance off by the same wrong amount.
 *
 * \~spanish
 * Una carga puede nombrar tres veces el mismo identificador.  Con lo que se
 * queda la conexion es con el ultimo valor, y lo que tiene que moverse cada
 * flujo abierto es la diferencia entre donde EMPEZO la ventana y donde acabo --
 * no la suma de los pasos, ni el ultimo paso.  Un extremo que leyera la carga
 * entera habra hecho exactamente eso, y un servidor que hiciera otra cosa
 * tendria el credito de todos sus flujos desviado en la misma cantidad
 * equivocada.
 *
 * \~
 */
void test_the_delta_is_from_before_the_payload() {
    uint8_t buf[18];
    one(buf, SettingId::InitialWindowSize, 100000);
    one(buf + 6, SettingId::InitialWindowSize, 5000);
    one(buf + 12, SettingId::InitialWindowSize, 20000);

    Settings s;
    const SettingsChange c = http_vx::h2::apply_settings(buf, sizeof buf, s);

    check(c.error == ErrorCode::NoError, "three window settings were refused");
    check(s.initial_window_size == 20000, "the last value is not the one kept");
    check(c.window_delta == 20000 - 65535,
          "the delta is not measured from before the payload");
}

/**
 * @brief
 * \~english A window may go into debt, and must then let nothing through.
 * \~spanish Una ventana puede quedar en deuda, y entonces no deja pasar nada.
 * \~
 *
 * \~english
 * The case the whole signed type exists for.  A stream with allowance left,
 * on a connection whose initial window drops below what it has already spent,
 * is in debt through no fault of its own -- and what it must do is send
 * nothing at all until a WINDOW_UPDATE pays the debt off.
 *
 * Zero is checked separately from the rest, because a zero-length DATA frame
 * is legal -- it is how a sender says `END_STREAM` with nothing left to say --
 * and a window in debt must still not allow one byte.
 *
 * \~spanish
 * El caso para el que existe todo el tipo con signo.  Un flujo al que le
 * quedaba credito, en una conexion cuya ventana inicial baja por debajo de lo
 * que ya habia gastado, esta en deuda sin haber hecho nada -- y lo que tiene
 * que hacer es no mandar absolutamente nada hasta que un WINDOW_UPDATE pague la
 * deuda.
 *
 * El cero se comprueba aparte del resto, porque una trama DATA de longitud cero
 * es legal -- es como dice quien envia `END_STREAM` sin nada mas que decir -- y
 * una ventana en deuda sigue sin poder dejar pasar un byte.
 *
 * \~
 */
void test_a_window_can_go_into_debt() {
    Window w(65535);
    check(w.take(60000), "a window would not spend what it had");
    check(w.left() == 5535, "a window did not spend what it was asked for");

    /* \~english
     * Now the peer lowers the initial window to sixteen kilobytes.  This stream
     * has already spent sixty thousand of what used to be sixty-five, so the
     * move is minus forty-nine thousand and it lands well below zero.
     * \~spanish
     * Ahora el otro extremo baja la ventana inicial a dieciseis kilobytes.  Este
     * flujo ya ha gastado sesenta mil de lo que eran sesenta y cinco, asi que el
     * movimiento es de menos cuarenta y nueve mil y cae muy por debajo de cero.
     * \~ */
    check(w.adjust(16384 - 65535) == ErrorCode::NoError,
          "lowering the initial window was refused");
    check(w.left() < 0, "the window did not go into debt");
    check(w.left() == 5535 + 16384 - 65535,
          "the debt is not the difference that was applied");

    check(!w.allows(1), "a window in debt let a byte through");
    check(w.allows(0), "a window in debt refused a zero-length frame");
    check(!w.take(1), "a window in debt spent a byte");

    /* \~english
     * And it climbs out the only way it can: the peer gives the allowance back.
     * Until the debt is paid the stream is still stopped, which is the part an
     * implementation that clamped at zero would get wrong -- it would start
     * sending again a whole window too early.
     * \~spanish
     * Y sale de ahi por el unico camino que hay: el otro extremo devuelve el
     * credito.  Hasta que la deuda este pagada el flujo sigue parado, que es la
     * parte en la que se equivocaria una implementacion que recortara en cero --
     * empezaria a mandar otra vez una ventana entera antes de tiempo.
     * \~ */
    check(w.give(40000) == ErrorCode::NoError, "a window update was refused");
    check(w.left() < 0, "the debt was paid off by less than it was");
    check(!w.allows(1), "a window still in debt let a byte through");

    check(w.give(10000) == ErrorCode::NoError, "a window update was refused");
    check(w.left() > 0, "the debt was not paid off");
    check(w.allows(1), "a window back in credit would not let a byte through");
}

/**
 * @brief
 * \~english What a WINDOW_UPDATE may not say.
 * \~spanish Lo que no puede decir un WINDOW_UPDATE.
 * \~
 *
 * \~english
 * Two refusals and they are different errors, because they are different
 * accusations.  An increment of ZERO is a frame that says nothing, and a peer
 * sending a stream of them is spending this end's time without spending its
 * own window -- the same shape as a flood of empty CONTINUATION frames.
 * Going past the CEILING says one of the two ends has lost count.
 *
 * \~spanish
 * Dos rechazos y son errores distintos, porque son acusaciones distintas.  Un
 * incremento de CERO es una trama que no dice nada, y un extremo que mande una
 * riada de ellas esta gastando el tiempo de este sin gastar su propia ventana
 * -- la misma forma que una riada de CONTINUATION vacias.  Pasarse del TECHO
 * dice que uno de los dos extremos ha perdido la cuenta.
 *
 * \~
 */
void test_an_update_that_says_nothing_is_refused() {
    Window w(65535);

    check(w.give(0) == ErrorCode::ProtocolError,
          "an increment of zero was accepted");

    check(w.give(static_cast<uint32_t>(kMaxWindow)) ==
              ErrorCode::FlowControlError,
          "an increment past the ceiling was accepted");
    check(w.left() == 65535,
          "a refused increment still moved the window");

    /* \~english
     * Right up to the ceiling is fine, and it is the case an implementation
     * that compared after the addition in thirty-two bits would get wrong --
     * signed overflow is not a large number in C++, it is a program the
     * compiler may assume never happens.
     * \~spanish
     * Justo hasta el techo vale, y es el caso en el que se equivocaria una
     * implementacion que comparara despues de sumar en treinta y dos bits -- el
     * desbordamiento con signo no es un numero grande en C++, es un programa que
     * el compilador puede dar por imposible.
     * \~ */
    Window full;
    check(full.give(static_cast<uint32_t>(kMaxWindow) - 65535) ==
              ErrorCode::NoError,
          "filling a window exactly to the ceiling was refused");
    check(full.left() == kMaxWindow, "the window did not reach the ceiling");
    check(full.give(1) == ErrorCode::FlowControlError,
          "one byte past a full window was accepted");
}

/**
 * @brief
 * \~english This server announces what it actually enforces.
 * \~spanish Este servidor anuncia lo que de verdad hace cumplir.
 * \~
 *
 * \~english
 * Announcing one number and enforcing another is a connection that refuses
 * what it asked for, and it only shows up against a peer that believed the
 * announcement.  So the test reads this server's own SETTINGS back with this
 * server's own reader and compares the result against the limits it came from.
 *
 * \~spanish
 * Anunciar un numero y hacer cumplir otro es una conexion que rechaza lo que
 * pidio, y solo sale con un extremo que se creyo el anuncio.  Asi que la prueba
 * vuelve a leer el SETTINGS propio de este servidor con el lector propio de
 * este servidor y compara el resultado con los limites de los que salio.
 *
 * \~
 */
void test_what_is_announced_is_what_is_enforced() {
    http_vx::h2::Limits limits;

    uint8_t buf[64];
    const size_t n = http_vx::h2::write_settings(buf, sizeof buf, limits);
    check(n != 0, "this server could not write its own settings");
    check(n % 6 == 0, "the settings payload is not a whole number of settings");

    Settings s;
    check(http_vx::h2::apply_settings(buf, n, s).error == ErrorCode::NoError,
          "this server's own settings were refused by its own reader");

    check(s.max_concurrent_streams == limits.max_concurrent_streams,
          "the announced concurrency is not the one enforced");
    check(s.max_header_list_size == limits.max_header_list_size,
          "the announced header list size is not the one enforced");
    check(s.initial_window_size == limits.initial_window_size,
          "the announced window is not the one enforced");
    check(s.max_frame_size == limits.max_frame_size,
          "the announced frame size is not the one enforced");

    /* \~english
     * And push is turned off by saying so, although the default is on: a
     * server that never pushes and stays quiet leaves the peer holding room
     * for promises that will not come.
     * \~spanish
     * Y el empuje se apaga diciendolo, aunque por defecto este encendido: un
     * servidor que no empuja nunca y se calla deja al otro extremo guardando
     * sitio para promesas que no van a llegar.
     * \~ */
    check(!s.enable_push, "a server that never pushes did not say so");

    /* \~english
     * What has not changed is not announced.  Not to save six bytes -- a
     * setting written is a setting the peer must acknowledge and then honour,
     * and announcing the default asks it to do work to arrive where it was.
     *
     * Asked by looking for the identifier rather than by counting the bytes.
     * A byte count is the same claim written as arithmetic somebody has to
     * redo every time a default changes, and the first version of this check
     * was exactly that, with the sum done wrong.
     *
     * \~spanish
     * Lo que no ha cambiado no se anuncia.  No por ahorrar seis bytes -- un
     * ajuste escrito es un ajuste que el otro extremo tiene que confirmar y
     * luego cumplir, y anunciar el de por defecto es pedirle trabajo para llegar
     * a donde estaba.
     *
     * Se pregunta buscando el identificador y no contando los bytes.  Una cuenta
     * de bytes es la misma afirmacion escrita como una aritmetica que alguien
     * tiene que rehacer cada vez que cambia un valor por defecto, y la primera
     * version de esta comprobacion era justo eso, con la suma mal hecha.
     * \~ */
    const Settings fresh;
    if (limits.header_table_size == fresh.header_table_size) {
        bool announced = false;
        for (size_t at = 0; at < n; at += 6) {
            if (http_vx::h2::be16(buf + at) ==
                static_cast<uint16_t>(SettingId::HeaderTableSize))
                announced = true;
        }
        check(!announced,
              "a setting that is already the default was announced anyway");
    }
}

} // namespace

int main() {
    test_a_fresh_connection_is_already_right();
    test_a_bad_value_says_which_kind_it_is();
    test_an_unknown_setting_is_carried_past();
    test_the_delta_is_from_before_the_payload();
    test_a_window_can_go_into_debt();
    test_an_update_that_says_nothing_is_refused();
    test_what_is_announced_is_what_is_enforced();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
