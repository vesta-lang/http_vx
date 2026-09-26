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

    check(is(set.open(5, false), Verdict::StreamError,
             ErrorCode::RefusedStream),
          "one stream too many was not refused as retryable");
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

    check(accepted(set.on_reset(1)), "resetting the stream was refused");
    check(set.count() == 0, "the reset stream was not forgotten");

    /* \~english
     * Now the data the peer had already sent arrives.  It must be discarded
     * and it must NOT be an error, because the peer sent it before it could
     * have known.
     * \~spanish
     * Ahora llegan los datos que el otro extremo ya habia mandado.  Hay que
     * descartarlos y NO puede ser un error, porque el otro los mando antes de
     * poder saberlo.
     * \~ */
    check(is(set.on_data(1, 4096, 4096, false), Verdict::Discard, ErrorCode::NoError),
          "data for a finished stream was treated as an error");
    check(is(set.on_data(1, 4096, 4096, true), Verdict::Discard, ErrorCode::NoError),
          "the last data for a finished stream was treated as an error");
    check(is(set.on_reset(1), Verdict::Discard, ErrorCode::NoError),
          "a reset crossing this end's reset was treated as an error");

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

    check(is(set.on_data(1, 1, 1, false), Verdict::StreamError,
             ErrorCode::StreamClosed),
          "data after the end of the request was accepted");
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

    check(is(set.on_data(1, 1, 1, false), Verdict::StreamError,
             ErrorCode::FlowControlError),
          "one byte past the announced window was accepted");
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

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
