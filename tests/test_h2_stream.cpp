/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_stream.cpp
 * @brief
 * \~english Identifiers that only go up, and the frame that arrives too late.
 * \~spanish Identificadores que solo suben, y la trama que llega tarde.
 * \~
 *
 * \~english
 * Three things are worth testing here and the third is the one that gets
 * written wrong.
 *
 * The first two are the identifier rules -- odd, and strictly increasing --
 * and they are refused as CONNECTION errors, because a peer that numbers
 * differently is a peer this end can no longer agree with about anything.
 *
 * The third is a frame for a stream that has finished.  It is the easy one to
 * treat as an error, and it is not one: it left before the peer could have
 * known, so it must be discarded AND still counted against the connection's
 * window.  A server that dropped it without counting would lose a little
 * allowance on every reset stream, and after enough of them the connection
 * stops for good with neither end able to say why.  That failure is invisible
 * in any test that only asks "was this rejected", so what is checked here is
 * WHICH of the four verdicts came back.
 *
 * \~spanish
 * Aqui merecen probarse tres cosas y la tercera es la que se escribe mal.
 *
 * Las dos primeras son las reglas del identificador -- impar, y estrictamente
 * creciente -- y se rechazan como errores de CONEXION, porque un extremo que
 * numera de otra forma es un extremo con el que este ya no puede estar de
 * acuerdo en nada.
 *
 * La tercera es una trama de un flujo que ha terminado.  Es la que es facil
 * tratar como un error, y no lo es: salio antes de que el otro extremo pudiera
 * saberlo, asi que hay que descartarla Y contarla igual contra la ventana de la
 * conexion.  Un servidor que la tirara sin contarla perderia un poco de credito
 * en cada flujo abortado, y despues de bastantes la conexion se para para
 * siempre sin que ninguno de los dos sepa decir por que.  Ese fallo es invisible
 * en cualquier prueba que solo pregunte "se rechazo esto", asi que lo que se
 * comprueba aqui es CUAL de los cuatro veredictos volvio.
 *
 * \~
 */

#include "http_vx/h2_stream.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::ErrorCode;
using http_vx::h2::Outcome;
using http_vx::h2::Stream;
using http_vx::h2::StreamSet;
using http_vx::h2::StreamState;
using http_vx::h2::Verdict;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

bool is(const Outcome &o, Verdict v, ErrorCode e) {
    return o.verdict == v && o.error == e;
}

bool accepted(const Outcome &o) {
    return o.verdict == Verdict::Accept && o.error == ErrorCode::NoError;
}

/**
 * @brief
 * \~english A client numbers its requests 1, 3, 5, and never any other way.
 * \~spanish Un cliente numera sus peticiones 1, 3, 5, y nunca de otra forma.
 * \~
 *
 * \~english
 * Both refusals are connection errors and not stream errors, and that is the
 * part worth checking rather than the refusal itself.  A peer numbering the
 * server's way, or reusing a number, is a peer this end has stopped agreeing
 * with -- answering with a stream error would keep the connection open and
 * carry on reading frames whose meaning is already in doubt.
 *
 * \~spanish
 * Los dos rechazos son errores de conexion y no de flujo, y esa es la parte que
 * merece comprobarse mas que el rechazo en si.  Un extremo que numera como el
 * servidor, o que reutiliza un numero, es un extremo con el que este ha dejado
 * de estar de acuerdo -- contestar con un error de flujo dejaria la conexion
 * abierta y seguiria leyendo tramas cuyo significado ya esta en duda.
 *
 * \~
 */
void test_identifiers_are_odd_and_only_go_up() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, true)), "the first request was refused");
    check(set.count() == 1, "the first request was not remembered");
    check(set.highest_seen() == 1, "the highest identifier was not recorded");

    check(accepted(set.open(3, true)), "the second request was refused");

    check(is(set.open(5, true), Verdict::Accept, ErrorCode::NoError),
          "the third request was refused");

    /* \~english
     * Zero is the connection, not a stream.
     * \~spanish
     * El cero es la conexion, no un flujo.
     * \~ */
    check(is(set.open(0, true), Verdict::ConnectionError,
             ErrorCode::ProtocolError),
          "stream zero was opened as a stream");

    /* \~english
     * An even number is one this server would have opened.
     * \~spanish
     * Un numero par es uno que habria abierto este servidor.
     * \~ */
    check(is(set.open(6, true), Verdict::ConnectionError,
             ErrorCode::ProtocolError),
          "an even identifier from a client was accepted");

    /* \~english
     * Going backwards, and using the same one twice.  Both land in the same
     * place on purpose: telling them apart would mean remembering every
     * identifier ever used, which is the memory this rule exists to avoid.
     * \~spanish
     * Ir hacia atras, y usar el mismo dos veces.  Los dos caen en el mismo sitio
     * a proposito: distinguirlos obligaria a recordar todos los identificadores
     * usados, que es la memoria que esta regla existe para evitar.
     * \~ */
    check(is(set.open(3, true), Verdict::ConnectionError,
             ErrorCode::ProtocolError),
          "an identifier below the highest seen was accepted");
    check(is(set.open(5, true), Verdict::ConnectionError,
             ErrorCode::ProtocolError),
          "an identifier that was already used was accepted");
}

/**
 * @brief
 * \~english Asking for too many at once is not the peer misbehaving.
 * \~spanish Pedir demasiados a la vez no es el otro extremo portandose mal.
 * \~
 *
 * \~english
 * The one refusal in this file that must NOT be a connection error.  A client
 * that opened one stream too many did nothing wrong, and `REFUSED_STREAM` is
 * the one code that tells it the request may simply be sent again -- so a
 * connection error here would turn a busy moment into a dropped connection for
 * every other request already on it.
 *
 * And the identifier still counts as used.  A refused stream is a stream the
 * peer opened, and letting it try the same number again after a refusal would
 * be letting it reuse one.
 *
 * \~spanish
 * El unico rechazo de este fichero que NO puede ser un error de conexion.  Un
 * cliente que abrio un flujo de mas no ha hecho nada mal, y `REFUSED_STREAM` es
 * el unico codigo que le dice que puede volver a mandar la peticion tal cual --
 * asi que un error de conexion aqui convertiria un momento de mucho trabajo en
 * una conexion caida para todas las demas peticiones que ya van por ella.
 *
 * Y el identificador cuenta igual como usado.  Un flujo rechazado es un flujo
 * que el otro extremo abrio, y dejarle probar el mismo numero otra vez despues
 * de un rechazo seria dejarle reutilizar uno.
 *
 * \~
 */
void test_one_too_many_is_refused_and_retryable() {
    http_vx::h2::Limits limits;
    limits.max_concurrent_streams = 2;

    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, false)), "the first request was refused");
    check(accepted(set.open(3, false)), "the second request was refused");

    const Outcome refused = set.open(5, false);
    check(is(refused, Verdict::StreamError, ErrorCode::RefusedStream),
          "one stream too many was not refused as retryable");
    check(refused.why != nullptr && std::strstr(refused.why, "SETTINGS_MAX_CONCURRENT_STREAMS") != nullptr,
          "one stream too many does not say which rule");
    check(set.count() == 2, "a refused stream was remembered anyway");
    check(set.highest_seen() == 5,
          "a refused identifier may be used again");

    /* \~english
     * And room comes back when one finishes, which is what makes the limit a
     * limit on CONCURRENCY rather than on how many requests a connection may
     * ever serve.
     * \~spanish
     * Y el sitio vuelve cuando uno acaba, que es lo que hace del limite un
     * limite de CONCURRENCIA y no de cuantas peticiones puede servir una
     * conexion en toda su vida.
     * \~ */
    check(accepted(set.on_reset(1)), "resetting an open stream was refused");
    check(set.count() == 1, "a reset stream was not forgotten");
    check(accepted(set.open(7, false)),
          "a stream did not fit after one finished");
}

/**
 * @brief
 * \~english A frame for a finished stream is discarded, not refused.
 * \~spanish Una trama de un flujo terminado se descarta, no se rechaza.
 * \~
 *
 * \~english
 * The verdict is what is being tested, not whether something was rejected.
 * `Discard` and `StreamError` both mean "do not act on it" and they are
 * completely different to the connection: one owes the connection window and
 * the other has already ended the stream.  Getting this wrong is a slow leak
 * that ends in a connection stalled for good.
 *
 * \~spanish
 * Lo que se prueba es el veredicto, no si se rechazo algo.  `Discard` y
 * `StreamError` quieren decir los dos "no la atiendas" y son completamente
 * distintos para la conexion: uno le debe la ventana de la conexion y el otro ya
 * ha terminado el flujo.  Equivocarse aqui es una fuga lenta que acaba en una
 * conexion atascada para siempre.
 *
 * \~
 */
void test_a_late_frame_is_discarded_not_refused() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, false)), "the request was refused");
    check(accepted(set.on_data(1, 100, 100, false)), "data on an open stream was refused");

    set.on_reset_sent(1);
    check(set.count() == 0, "the stream this end reset was not forgotten");

    /* \~english
     * Now the data the peer had already sent arrives.  It must be discarded
     * and it must NOT be an error, because the peer sent it before it could
     * have known -- this end is the one that reset the stream.
     * \~spanish
     * Ahora llegan los datos que el otro extremo ya habia mandado.  Hay que
     * descartarlos y NO puede ser un error, porque el otro los mando antes de
     * poder saberlo -- el que reinicio el flujo es este extremo.
     * \~ */
    check(is(set.on_data(1, 4096, 4096, false), Verdict::Discard, ErrorCode::NoError),
          "data for a stream this end reset was treated as an error");
    check(is(set.on_data(1, 4096, 4096, true), Verdict::Discard, ErrorCode::NoError),
          "the last data for a stream this end reset was treated as an error");
    check(is(set.open(1, true), Verdict::Discard, ErrorCode::NoError),
          "a HEADERS for a stream this end reset was treated as an error");
    check(is(set.on_reset(1), Verdict::Discard, ErrorCode::NoError),
          "a reset crossing this end's reset was treated as an error");

    /* \~english
     * A stream refused at the door never had an entry, and it is remembered
     * all the same: its body is the one most surely on its way.
     * \~spanish
     * Un flujo rechazado en la puerta no tuvo nunca entrada, y se recuerda
     * igual: su cuerpo es el que con mas seguridad viene de camino.
     * \~ */
    http_vx::h2::Limits one;
    one.max_concurrent_streams = 1;
    StreamSet door;
    door.reset(one);
    check(accepted(door.open(1, false)), "the first request was refused");
    check(is(door.open(3, false), Verdict::StreamError, ErrorCode::RefusedStream),
          "one stream too many was not refused");
    door.on_reset_sent(3);
    check(door.count() == 1, "resetting a stream that had no entry touched the table");
    check(is(door.on_data(3, 1, 1, false), Verdict::Discard, ErrorCode::NoError),
          "data for a stream refused at the door was treated as an error");
    check(is(door.open(3, true), Verdict::Discard, ErrorCode::NoError),
          "trailers for a stream refused at the door were treated as an error");

    // \~english A reset of one never opened is not remembered.  \~spanish Un reinicio de uno que no se abrio no se recuerda.  \~
    door.on_reset_sent(5);
    check(is(door.on_data(5, 1, 1, false), Verdict::ConnectionError, ErrorCode::ProtocolError),
          "a reset of a stream not yet opened made it exist");

    check(accepted(set.open(3, false)), "the second request was refused");

    /* \~english
     * But when the PEER reset the stream it knew it was over, and so it was
     * when both ends had finished: a frame after that is the peer's mistake,
     * a connection error STREAM_CLOSED (RFC 9113, 5.1).
     * \~spanish
     * Pero cuando el flujo lo reinicio el OTRO, el otro sabia que se habia
     * acabado, y lo mismo cuando habian acabado los dos: una trama despues es
     * un error del otro, error de conexion STREAM_CLOSED (RFC 9113, 5.1).
     * \~ */
    check(accepted(set.on_reset(3)), "the peer's reset was refused");
    const Outcome after_reset = set.on_data(3, 10, 10, false);
    check(is(after_reset, Verdict::ConnectionError, ErrorCode::StreamClosed) && after_reset.why != nullptr,
          "data after the peer's own reset was not STREAM_CLOSED");
    check(is(set.on_reset(3), Verdict::Discard, ErrorCode::NoError),
          "a second reset from the peer was treated as an error");

    StreamSet ended;
    ended.reset(limits);
    check(accepted(ended.open(1, true)), "the request was refused");
    ended.finish(1);
    check(ended.count() == 0, "a stream both ends finished was kept");
    check(is(ended.on_data(1, 1, 1, false), Verdict::ConnectionError, ErrorCode::StreamClosed),
          "data on a stream both ends finished was not STREAM_CLOSED");
    const Outcome again = ended.open(1, true);
    check(is(again, Verdict::ConnectionError, ErrorCode::StreamClosed) && again.why != nullptr,
          "a HEADERS on a stream both ends finished was not STREAM_CLOSED");

    /* \~english
     * And an identifier skipped over is not a closed stream to reuse: a
     * HEADERS for it is out of order (5.1.1), a DATA a frame on a closed
     * stream (5.1).  An even one was never opened by anybody (idle).
     * \~spanish
     * Y un identificador saltado no es un flujo cerrado que reutilizar: un
     * HEADERS suyo va fuera de orden (5.1.1), un DATA es una trama de un flujo
     * cerrado (5.1).  Uno par no lo abrio nunca nadie (inactivo).
     * \~ */
    check(accepted(ended.open(7, true)), "the request was refused");
    check(is(ended.open(5, true), Verdict::ConnectionError, ErrorCode::ProtocolError),
          "a HEADERS on a skipped identifier was not PROTOCOL_ERROR");
    check(is(ended.on_data(3, 1, 1, false), Verdict::ConnectionError, ErrorCode::StreamClosed),
          "data on a skipped identifier was not STREAM_CLOSED");
    check(is(ended.on_data(4, 1, 1, false), Verdict::ConnectionError, ErrorCode::ProtocolError),
          "data on an even identifier was not PROTOCOL_ERROR");
    const Outcome idle_reset = ended.on_reset(4);
    check(is(idle_reset, Verdict::ConnectionError, ErrorCode::ProtocolError) && idle_reset.why != nullptr,
          "a reset on an even identifier was not PROTOCOL_ERROR, or not said why");
    check(ended.on_reset(0).why != nullptr && ended.on_data(0, 1, 1, false).why != nullptr,
          "a frame on stream 0 does not say why");

    /* \~english
     * A table reset for a new connection forgets how the old one's streams
     * ended: a stream 3 reset there is not one reset here.
     * \~spanish
     * Una tabla reiniciada para una conexion nueva olvida como acabaron los
     * flujos de la vieja: un flujo 3 reiniciado alli no lo es aqui.
     * \~ */
    StreamSet reused;
    reused.reset(limits);
    for (uint32_t id = 1; id <= 21; id += 2) check(accepted(reused.open(id, true)), "a request was refused");
    reused.on_reset_sent(3);
    reused.reset(limits);
    check(accepted(reused.open(5, true)), "a request on the new connection was refused");
    check(is(reused.on_data(3, 1, 1, false), Verdict::ConnectionError, ErrorCode::StreamClosed),
          "the new connection remembered a reset of the old one");
    check(is(ended.on_reset(3), Verdict::Discard, ErrorCode::NoError),
          "a reset on a closed stream was treated as an error");
    check(ended.never_opened(4) && ended.never_opened(9) && !ended.never_opened(7) && !ended.never_opened(3),
          "never_opened does not tell idle from closed");

    /* \~english
     * But data for a stream ABOVE the highest seen is a different thing
     * entirely: it is not late, it is a stream the peer never opened, and
     * there is no request to attach it to.
     * \~spanish
     * Pero datos de un flujo POR ENCIMA del mayor visto son otra cosa
     * completamente: no llegan tarde, son de un flujo que el otro extremo no
     * abrio nunca, y no hay peticion a la que pegarlos.
     * \~ */
    check(is(set.on_data(9, 10, 10, false), Verdict::ConnectionError,
             ErrorCode::ProtocolError),
          "data for a stream nobody opened was accepted as late");
}

/**
 * @brief
 * \~english Saying more after saying it was the end.
 * \~spanish Decir mas despues de decir que era el final.
 * \~
 *
 * \~english
 * This one IS the peer misbehaving, and it is a stream error rather than a
 * connection one: only this request is confused, and the hundreds of others on
 * the connection are fine.
 *
 * \~spanish
 * Este SI es el otro extremo portandose mal, y es un error de flujo y no de
 * conexion: la unica confundida es esta peticion, y las otras cientos que van
 * por la conexion estan bien.
 *
 * \~
 */
void test_data_after_the_end_ends_the_stream() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, true)), "the request was refused");

    const Stream *s = set.find(1);
    check(s != nullptr, "the request was not remembered");
    check(s != nullptr && s->state == StreamState::HalfClosedRemote,
          "a request that said it was done is not half closed");

    const Outcome o = set.on_data(1, 1, 1, false);
    check(is(o, Verdict::StreamError, ErrorCode::StreamClosed) && o.why != nullptr,
          "data after the end of the request was accepted, or not said why");
}

/**
 * @brief
 * \~english More than this end said it would take.
 * \~spanish Mas de lo que dijo este extremo que aceptaria.
 * \~
 *
 * \~english
 * The check that makes the announced window a promise rather than a
 * suggestion.  Without it, the limit this server publishes is a number nobody
 * enforces -- and the memory sized by that number is the memory a peer
 * overruns.
 *
 * \~spanish
 * La comprobacion que hace de la ventana anunciada una promesa y no una
 * sugerencia.  Sin ella, el limite que publica este servidor es un numero que no
 * hace cumplir nadie -- y la memoria dimensionada por ese numero es la que se
 * pasa un extremo.
 *
 * \~
 */
void test_more_than_the_window_is_refused() {
    http_vx::h2::Limits limits;
    limits.initial_window_size = 1000;

    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, false)), "the request was refused");
    check(accepted(set.on_data(1, 600, 600, false)), "data within the window was refused");
    check(accepted(set.on_data(1, 400, 400, false)),
          "data filling the window exactly was refused");

    const Outcome o = set.on_data(1, 1, 1, false);
    check(is(o, Verdict::StreamError, ErrorCode::FlowControlError) && o.why != nullptr &&
              std::strstr(o.why, "flow-control") != nullptr,
          "one byte past the announced window was accepted, or not said why");
}

/**
 * @brief
 * \~english A changed initial window moves the streams already running.
 * \~spanish Una ventana inicial cambiada mueve los flujos que ya corren.
 * \~
 *
 * \~english
 * The join between this file and the settings, and the reason they were
 * written together.  A peer's new initial window says two things at once: what
 * a stream opened from now on starts at, and how far the ones already open
 * move.  An implementation that did only the first would be out of step with
 * its peer in a way that shows up as a stall much later, on a connection where
 * nothing ever reported an error.
 *
 * \~spanish
 * La union entre este fichero y los ajustes, y la razon de que se escribieran
 * juntos.  La ventana inicial nueva de un extremo dice dos cosas a la vez: en
 * cuanto empieza un flujo que se abra a partir de ahora, y cuanto se mueven los
 * que ya estan abiertos.  Una implementacion que hiciera solo la primera se
 * quedaria desacompasada con su extremo de una forma que sale como un atasco
 * mucho despues, en una conexion donde nunca dio error nada.
 *
 * \~
 */
void test_a_new_initial_window_moves_both_ways() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, false)), "the request was refused");

    Stream *s = set.find(1);
    check(s != nullptr, "the request was not remembered");
    check(s != nullptr && s->send.left() == 65535,
          "a stream did not start at the peer's default window");

    /* \~english
     * The peer raises its window to a hundred thousand.  The stream already
     * open moves by the difference; a stream opened after this starts at the
     * new value outright.
     * \~spanish
     * El otro extremo sube su ventana a cien mil.  El flujo ya abierto se mueve
     * la diferencia; uno que se abra despues de esto empieza directamente en el
     * valor nuevo.
     * \~ */
    check(set.adjust_send_windows(100000 - 65535) == ErrorCode::NoError,
          "raising the initial window was refused");
    set.set_peer_initial_window(100000);

    check(s->send.left() == 100000,
          "an open stream did not move with the initial window");

    check(accepted(set.open(3, false)), "the second request was refused");
    const Stream *t = set.find(3);
    check(t != nullptr && t->send.left() == 100000,
          "a new stream did not start at the new initial window");

    /* \~english
     * And the stream opened first, which has spent nothing, must not be pushed
     * past the ceiling by a peer that keeps raising it.
     * \~spanish
     * Y el flujo abierto primero, que no ha gastado nada, no se puede empujar
     * por encima del techo por un extremo que siga subiendola.
     * \~ */
    check(set.adjust_send_windows(http_vx::h2::kMaxWindow) ==
              ErrorCode::FlowControlError,
          "a window pushed past the ceiling was accepted");
}

/**
 * @brief
 * \~english The content counted against a declared length, to the byte (RFC 9113, 8.1.1).
 * \~spanish El contenido contado contra una longitud declarada, al byte (RFC 9113, 8.1.1).
 * \~
 */
void test_the_content_is_counted() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    // \~english Exactly to the byte, padding not counted.  \~spanish Justo al byte, sin contar el relleno.  \~
    check(accepted(set.open(1, false)), "the request was refused");
    check(accepted(set.expect_content(1, 5)), "a content-length was refused");
    check(accepted(set.on_data(1, 16, 3, false)), "content under the length was refused");
    check(accepted(set.on_data(1, 2, 2, true)), "content reaching the length exactly was refused");
    check(set.find(1) != nullptr && set.find(1)->state == StreamState::HalfClosedRemote,
          "an exact body did not end the stream");

    // \~english One byte over.  \~spanish Un byte de mas.  \~
    check(accepted(set.open(3, false)), "the request was refused");
    check(accepted(set.expect_content(3, 5)), "a content-length was refused");
    const Outcome over = set.on_data(3, 6, 6, false);
    check(is(over, Verdict::StreamError, ErrorCode::ProtocolError) && over.why != nullptr,
          "one byte over the content-length was accepted");

    // \~english One byte short, at the end.  \~spanish Un byte de menos, al final.  \~
    check(accepted(set.open(5, false)), "the request was refused");
    check(accepted(set.expect_content(5, 5)), "a content-length was refused");
    const Outcome under = set.on_data(5, 4, 4, true);
    check(is(under, Verdict::StreamError, ErrorCode::ProtocolError) && under.why != nullptr,
          "one byte short of the content-length was accepted");

    // \~english No length declared: nothing is counted.  \~spanish Sin longitud declarada: no se cuenta nada.  \~
    check(accepted(set.open(7, false)), "the request was refused");
    check(accepted(set.on_data(7, 100, 100, true)), "a body without a content-length was refused");

    // \~english A HEADERS that ended the stream: only zero is the content.  \~spanish Un HEADERS que acabo el flujo: solo el cero es el contenido.  \~
    check(accepted(set.open(9, true)), "the request was refused");
    check(accepted(set.expect_content(9, 0)), "content-length: 0 without DATA was refused");
    check(accepted(set.open(11, true)), "the request was refused");
    check(is(set.expect_content(11, 1), Verdict::StreamError, ErrorCode::ProtocolError),
          "a content-length without DATA was accepted");

    // \~english A stream that is not there has nothing to count.  \~spanish Un flujo que no esta no tiene nada que contar.  \~
    check(is(set.expect_content(99, 1), Verdict::Discard, ErrorCode::NoError),
          "a length for a stream that is not there was acted on");

    /* \~english
     * A slot a counted stream left behind does not count for the next one:
     * the length is the request's, not the entry's.
     * \~spanish
     * Una plaza que dejo un flujo contado no cuenta para el siguiente: la
     * longitud es de la peticion, no de la entrada.
     * \~ */
    StreamSet again;
    again.reset(limits);
    check(accepted(again.open(1, false)), "the request was refused");
    check(accepted(again.expect_content(1, 1)), "a content-length was refused");
    check(accepted(again.on_data(1, 1, 1, true)), "an exact body was refused");
    again.finish(1);
    check(again.find(1) == nullptr && again.count() == 0, "a finished stream was kept");
    check(accepted(again.open(3, false)), "the next request was refused");
    check(accepted(again.on_data(3, 5, 5, true)), "the previous request's length was counted against the next");
}

/**
 * @brief
 * \~english What a second HEADERS means to the stream (RFC 9113, 5.1, 8.1, 8.1.1).
 * \~spanish Que significa un segundo HEADERS para el flujo (RFC 9113, 5.1, 8.1, 8.1.1).
 * \~
 */
void test_trailers_end_the_stream() {
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);

    check(accepted(set.open(1, false)), "the request was refused");
    check(accepted(set.on_trailers(1, true)), "trailers were refused");
    check(set.find(1) != nullptr && set.find(1)->state == StreamState::HalfClosedRemote,
          "the trailers did not end the stream");
    check(is(set.on_trailers(1, true), Verdict::StreamError, ErrorCode::StreamClosed),
          "a third HEADERS was accepted");

    check(accepted(set.open(3, false)), "the request was refused");
    check(is(set.on_trailers(3, false), Verdict::StreamError, ErrorCode::ProtocolError),
          "a second HEADERS without END_STREAM was accepted");

    // \~english Too little content, ended by the trailers.  \~spanish Poco contenido, acabado por los remolques.  \~
    check(accepted(set.open(5, false)), "the request was refused");
    check(accepted(set.expect_content(5, 2)), "a content-length was refused");
    check(accepted(set.on_data(5, 1, 1, false)), "content under the length was refused");
    check(is(set.on_trailers(5, true), Verdict::StreamError, ErrorCode::ProtocolError),
          "trailers ending the content short were accepted");
    check(accepted(set.on_data(5, 1, 1, false)), "the last byte was refused");
    check(accepted(set.on_trailers(5, true)), "trailers after the whole content were refused");

    /* \~english
     * This end had already answered: the trailers end the stream for good.
     * \~spanish
     * Este extremo ya habia contestado: los remolques acaban el flujo del todo.
     * \~ */
    check(accepted(set.open(7, false)), "the request was refused");
    set.finish(7);
    check(accepted(set.on_trailers(7, true)), "trailers after the answer were refused");
    check(set.find(7) == nullptr, "a stream both ends finished was not forgotten");

    // \~english Likewise a DATA that ends it.  \~spanish Igual un DATA que lo acaba.  \~
    check(accepted(set.open(9, false)), "the request was refused");
    set.finish(9);
    check(accepted(set.on_data(9, 1, 1, true)), "the last DATA after the answer was refused");
    check(set.find(9) == nullptr, "a stream both ends finished was not forgotten");

    check(is(set.on_trailers(99, true), Verdict::Discard, ErrorCode::NoError),
          "trailers for a stream that is not there were acted on");
}

/**
 * @brief
 * \~english The ring that remembers how recent streams ended, and what falls off it.
 * \~spanish El anillo que recuerda como acabaron los flujos recientes, y lo que se cae de el.
 * \~
 *
 * \~english
 * Bounded is the point: a peer that opens a million streams leaves the same
 * sixteen words behind as one that opens two.  What is checked is that the
 * slots a jump skips over are cleared -- across the word boundary and all
 * the way round -- so no stale bit from a stream a ring older ever answers
 * for a new one, and that what falls off answers @c Forgotten.
 * \~spanish
 * Acotado es la cuestion: un extremo que abre un millon de flujos deja atras
 * las mismas dieciseis palabras que uno que abre dos.  Lo que se comprueba es
 * que las plazas que salta un salto se limpian -- cruzando el borde de palabra
 * y dando la vuelta entera -- para que ningun bit rancio de un flujo un anillo
 * mas viejo conteste nunca por uno nuevo, y que lo que se cae contesta
 * @c Forgotten.
 * \~
 */
void test_the_recent_streams_ring() {
    using http_vx::h2::Past;
    using http_vx::h2::RecentStreams;
    const uint32_t ring = http_vx::h2::kRecentStreams;

    RecentStreams r;
    r.reset();
    check(r.past(1) == Past::Skipped, "a ring that saw nothing remembered something");

    r.opened(1);
    check(r.past(1) == Past::Closed, "an opened stream was not remembered as opened");
    r.reset_here(1);
    check(r.past(1) == Past::ResetHere, "a stream this end reset was not remembered as such");

    r.opened(5);
    check(r.past(3) == Past::Skipped, "a skipped identifier was remembered as opened");
    check(r.past(1) == Past::ResetHere, "opening a higher stream forgot a lower one");
    r.opened(3);
    check(r.past(3) == Past::Skipped, "an opening below the highest was taken");

    // \~english Exactly one ring later, the first falls off.  \~spanish Justo un anillo despues, el primero se cae.  \~
    for (uint32_t id = 7; id <= 2 * ring + 1; id += 2) r.opened(id);
    check(r.past(1) == Past::Forgotten, "a stream a whole ring old was still answered for");
    check(r.past(3) == Past::Skipped, "the oldest slot still in the ring was lost");
    check(r.past(5) == Past::Closed, "a slot the ring did not pass over was cleared");
    const uint32_t top = 2 * ring + 1;
    r.reset_here(1);
    check(r.past(1) == Past::Forgotten, "a forgotten stream was marked");
    check(r.past(top) == Past::Closed, "marking a forgotten stream marked the one in its slot now");

    // \~english A jump past the whole ring clears it all.  \~spanish Un salto de mas de un anillo lo limpia entero.  \~
    r.reset_here(top);
    check(r.past(top) == Past::ResetHere, "the highest stream could not be marked");
    r.opened(top + 2 * (ring + 88));
    check(r.past(top) == Past::Forgotten, "a jump past the ring kept the old top");
    check(r.past(top + 2 * 300) == Past::Skipped, "a jump past the ring left a stale bit");
    check(r.past(4 * ring + 1) == Past::Skipped, "a jump past the ring left a stale reset in the top's old slot");

    /* \~english
     * A jump of part of a ring, across a word boundary: every slot is opened
     * and reset, then a hundred new slots are opened over the first hundred
     * positions -- and none of them may answer with what the old ones said.
     * \~spanish
     * Un salto de parte de un anillo, cruzando un borde de palabra: se abren y
     * se reinician todas las plazas, y luego se abren cien plazas nuevas sobre
     * las cien primeras posiciones -- y ninguna puede contestar lo que decian
     * las viejas.
     * \~ */
    RecentStreams q;
    q.reset();
    for (uint32_t slot = 0; slot < ring; ++slot) {
        q.opened(2 * slot + 1);
        q.reset_here(2 * slot + 1);
    }
    q.opened(2 * (ring + 99) + 1);
    bool clean = true;
    for (uint32_t slot = ring; slot < ring + 99; ++slot)
        clean = clean && q.past(2 * slot + 1) == Past::Skipped;
    check(clean, "a partial jump left stale bits in the slots it passed over");
    check(q.past(2 * (ring + 99) + 1) == Past::Closed, "the stream that jumped was not opened");
    check(q.past(2 * (ring - 1) + 1) == Past::ResetHere, "a partial jump cleared past where it went");
    check(q.past(2 * 100 + 1) == Past::ResetHere, "the oldest slot of the ring was cleared");
    check(q.past(2 * 99 + 1) == Past::Forgotten, "a slot the jump pushed out was still answered for");

    // \~english A partial jump that wraps round the end of the ring.  \~spanish Un salto parcial que da la vuelta al final del anillo.  \~
    RecentStreams w;
    w.reset();
    for (uint32_t slot = 0; slot < ring + 450; ++slot) {
        w.opened(2 * slot + 1);
        w.reset_here(2 * slot + 1);
    }
    w.opened(2 * (ring + 549) + 1);
    bool wrapped = true;
    for (uint32_t slot = ring + 450; slot < ring + 549; ++slot)
        wrapped = wrapped && w.past(2 * slot + 1) == Past::Skipped;
    check(wrapped, "a jump round the end of the ring left stale bits");
    check(w.past(2 * (ring + 449) + 1) == Past::ResetHere, "a wrapping jump cleared behind where it started");

    q.reset();
    check(q.past(1) == Past::Skipped && q.past(2 * (ring - 1) + 1) == Past::Skipped,
          "a reset ring still remembered");

    /* \~english
     * And in the table: a stream that closed normally, once forgotten, gets
     * the lenient answer -- which is safe whatever it really was.
     * \~spanish
     * Y en la tabla: un flujo que se cerro normalmente, una vez olvidado,
     * recibe la respuesta indulgente -- que es segura sea lo que fuera.
     * \~ */
    http_vx::h2::Limits limits;
    StreamSet set;
    set.reset(limits);
    for (uint32_t id = 1; id <= 2 * ring + 1; id += 2) {
        check(accepted(set.open(id, true)), "a request was refused");
        set.finish(id);
    }
    check(is(set.on_data(1, 1, 1, false), Verdict::Discard, ErrorCode::NoError),
          "a forgotten stream was not treated as possibly reset here");
    check(is(set.on_data(3, 1, 1, false), Verdict::ConnectionError, ErrorCode::StreamClosed),
          "a remembered closed stream was treated as forgotten");
}

} // namespace

int main() {
    test_identifiers_are_odd_and_only_go_up();
    test_one_too_many_is_refused_and_retryable();
    test_a_late_frame_is_discarded_not_refused();
    test_data_after_the_end_ends_the_stream();
    test_more_than_the_window_is_refused();
    test_a_new_initial_window_moves_both_ways();
    test_the_content_is_counted();
    test_trailers_end_the_stream();
    test_the_recent_streams_ring();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
