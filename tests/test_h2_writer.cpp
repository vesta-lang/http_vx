/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_writer.cpp
 * @brief
 * \~english A response cut into the pieces the peer will take.
 * \~spanish Una respuesta partida en los pedazos que aceptara el otro extremo.
 * \~
 *
 * \~english
 * Almost everything here is about a response that does NOT fit in one frame,
 * because everything that fits works whatever the code does.  A header block
 * under sixteen kilobytes is one HEADERS with both flags on it, and a writer
 * that put `END_STREAM` on the last piece instead of the first would pass
 * every test made of ordinary responses -- and then send a stream the peer
 * never sees the end of, the first time a response carried a large cookie.
 *
 * So the cases are the ones with a seam in them: a block that needs
 * CONTINUATIONs, a body larger than a frame, and a body larger than what the
 * peer has said it will take.
 *
 * \~spanish
 * Casi todo lo de aqui va de una respuesta que NO cabe en una trama, porque todo
 * lo que cabe funciona haga lo que haga el codigo.  Un bloque de cabeceras de
 * menos de dieciseis kilobytes es un HEADERS con las dos banderas puestas, y un
 * escritor que pusiera `END_STREAM` en el ultimo pedazo en vez de en el primero
 * pasaria todas las pruebas hechas de respuestas corrientes -- y luego mandaria
 * un flujo cuyo final el otro extremo no ve nunca, la primera vez que una
 * respuesta llevara una cookie grande.
 *
 * Asi que los casos son los que tienen una costura dentro: un bloque que
 * necesita CONTINUATIONs, un cuerpo mayor que una trama, y un cuerpo mayor que
 * lo que el otro extremo ha dicho que aceptara.
 *
 * \~
 */

#include "http_vx/h2_writer.h"

#include <cstdio>

namespace {

using http_vx::h2::FrameError;
using http_vx::h2::FrameHeader;
using http_vx::h2::FrameType;
using http_vx::h2::HeaderFramer;
using http_vx::h2::Window;
using http_vx::IoList;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Reads back the frame header of piece @p i of @p list.
 * \~spanish Vuelve a leer la cabecera de trama del pedazo @p i de @p list.
 * \~
 *
 * \~english
 * Read back with this project's own decoder rather than by reaching into the
 * bytes.  What is being tested is what the peer will see, and what the peer
 * does is decode -- so a test that read the bytes its own way could agree with
 * a writer that both of them had wrong.
 *
 * \~spanish
 * Se vuelve a leer con el descodificador propio del proyecto y no metiendo mano
 * en los bytes.  Lo que se prueba es lo que va a ver el otro extremo, y lo que
 * hace el otro extremo es descodificar -- asi que una prueba que leyera los
 * bytes a su manera podria estar de acuerdo con un escritor en algo que los dos
 * tuvieran mal.
 *
 * \~
 */
FrameHeader head_of(const IoList &list, size_t i) {
    FrameHeader h;
    http_vx::h2::decode_frame_header(list.slices()[i * 2].data, h);
    return h;
}

bool is_headers(const FrameHeader &h) {
    return h.type == static_cast<uint8_t>(FrameType::Headers);
}

bool is_continuation(const FrameHeader &h) {
    return h.type == static_cast<uint8_t>(FrameType::Continuation);
}

bool ends_headers(const FrameHeader &h) {
    return (h.flags & http_vx::h2::kEndHeaders) != 0;
}

bool ends_stream(const FrameHeader &h) {
    return (h.flags & http_vx::h2::kEndStream) != 0;
}

/**
 * @brief
 * \~english A block that fits is one frame with both flags.
 * \~spanish Un bloque que cabe es una trama con las dos banderas.
 * \~
 */
void test_a_short_block_is_one_frame() {
    uint8_t block[100];
    for (size_t i = 0; i < sizeof block; ++i) block[i] = static_cast<uint8_t>(i);

    HeaderFramer f;
    IoList list;

    check(f.frame(list, 1, block, sizeof block, 16384, true) == FrameError::Ok,
          "a short header block was refused");
    check(f.pieces() == 1, "a short header block was cut up anyway");
    check(list.count() == 2, "a frame is not a header and a payload");
    check(list.total() == 9 + sizeof block,
          "the write is not the header plus the block");

    const FrameHeader h = head_of(list, 0);
    check(is_headers(h), "the frame is not a HEADERS");
    check(h.stream_id == 1, "the frame is for the wrong stream");
    check(h.length == sizeof block, "the frame does not say how long it is");
    check(ends_headers(h), "a block that fits did not say it had ended");
    check(ends_stream(h), "the end of the response was not said");

    /* \~english
     * And the block itself is not copied: what is in the list points at the
     * caller's bytes.  R13 and R14 are the same decision seen from two sides,
     * and this is where it is either true or quietly not.
     * \~spanish
     * Y el bloque no se copia: lo que hay en la lista apunta a los bytes de
     * quien llamo.  R13 y R14 son la misma decision vista por dos lados, y aqui
     * es donde es cierta o deja de serlo por lo bajo.
     * \~ */
    check(list.slices()[1].data == block,
          "the header block was copied instead of pointed at");
}

/**
 * @brief
 * \~english A block that does not fit becomes HEADERS and CONTINUATIONs.
 * \~spanish Un bloque que no cabe se convierte en HEADERS y CONTINUATIONs.
 * \~
 *
 * \~english
 * The case the two flags are about.  `END_HEADERS` belongs to the block, so it
 * goes on the LAST piece; `END_STREAM` belongs to the stream, so it goes on
 * the FIRST -- and a CONTINUATION has nowhere to put it even if somebody
 * wanted to.
 *
 * \~spanish
 * El caso del que van las dos banderas.  `END_HEADERS` es del bloque, asi que va
 * en el ULTIMO pedazo; `END_STREAM` es del flujo, asi que va en el PRIMERO -- y
 * una CONTINUATION no tiene donde ponerla aunque alguien quisiera.
 *
 * \~
 */
void test_a_long_block_is_cut_at_the_frame_size() {
    uint8_t block[250];
    for (size_t i = 0; i < sizeof block; ++i) block[i] = static_cast<uint8_t>(i);

    HeaderFramer f;
    IoList list;

    check(f.frame(list, 3, block, sizeof block, 100, true) == FrameError::Ok,
          "a long header block was refused");
    check(f.pieces() == 3, "a 250-byte block at 100 is not three pieces");

    const FrameHeader first = head_of(list, 0);
    const FrameHeader middle = head_of(list, 1);
    const FrameHeader last = head_of(list, 2);

    check(is_headers(first), "the first piece is not a HEADERS");
    check(is_continuation(middle), "the second piece is not a CONTINUATION");
    check(is_continuation(last), "the third piece is not a CONTINUATION");

    check(first.stream_id == 3 && middle.stream_id == 3 &&
              last.stream_id == 3,
          "the pieces of one block are not all for the same stream");

    check(first.length == 100 && middle.length == 100 && last.length == 50,
          "the block was not cut at the frame size");

    /* \~english
     * The end of the BLOCK is on the last piece and nowhere else.
     * \~spanish
     * El final del BLOQUE esta en el ultimo pedazo y en ningun otro.
     * \~ */
    check(!ends_headers(first), "the first piece claimed the block had ended");
    check(!ends_headers(middle), "a middle piece claimed the block had ended");
    check(ends_headers(last), "the last piece did not end the block");

    /* \~english
     * And the end of the STREAM is on the first, which is the one that is easy
     * to put in the same place as the other.
     * \~spanish
     * Y el final del FLUJO esta en el primero, que es el que es facil poner en
     * el mismo sitio que el otro.
     * \~ */
    check(ends_stream(first), "the end of the response was not on the HEADERS");
    check(!ends_stream(middle) && !ends_stream(last),
          "a CONTINUATION claimed to end the stream");

    /* \~english
     * The three payloads are the three parts of the block, in order and with
     * nothing missing.  Checked by where they point rather than by comparing
     * bytes, because a writer that pointed at the right place cannot have
     * copied the wrong bytes.
     * \~spanish
     * Las tres cargas son las tres partes del bloque, en orden y sin que falte
     * nada.  Se comprueba por donde apuntan y no comparando bytes, porque un
     * escritor que apunte al sitio bueno no puede haber copiado bytes malos.
     * \~ */
    check(list.slices()[1].data == block, "the first piece is not the start");
    check(list.slices()[3].data == block + 100,
          "the second piece does not carry on where the first stopped");
    check(list.slices()[5].data == block + 200,
          "the third piece does not carry on where the second stopped");
    check(list.total() == 3 * 9 + sizeof block,
          "the write is not three headers plus the whole block");
}

/**
 * @brief
 * \~english A block needing more pieces than fit writes nothing at all.
 * \~spanish Un bloque que necesita mas pedazos de los que caben no escribe nada.
 * \~
 *
 * \~english
 * Half a header block on the wire is worse than none: the peer's decompressor
 * stops and waits for a CONTINUATION that is not coming, and there is no way
 * back from that except closing the connection.  So the count is worked out
 * before anything is written, and a refusal leaves the list untouched.
 *
 * \~spanish
 * Medio bloque de cabeceras en el cable es peor que ninguno: el descompresor
 * del otro extremo se para a esperar una CONTINUATION que no va a llegar, y de
 * ahi no se vuelve mas que cerrando la conexion.  Asi que la cuenta se hace
 * antes de escribir nada, y un rechazo deja la lista como estaba.
 *
 * \~
 */
void test_a_refusal_writes_nothing() {
    uint8_t block[1000];

    HeaderFramer f;
    IoList list;

    check(f.frame(list, 1, block, sizeof block, 10, true) ==
              FrameError::TooManyPieces,
          "a block needing a hundred pieces was accepted");
    check(list.empty(), "a refused block still wrote part of itself");
    check(f.pieces() == 0, "a refused block reported pieces");

    /* \~english
     * And a frame size of zero is refused rather than divided by.
     * \~spanish
     * Y un tamano de trama de cero se rechaza en vez de dividir por el.
     * \~ */
    check(f.frame(list, 1, block, sizeof block, 0, true) ==
              FrameError::BadFrameSize,
          "a frame size of zero was used as one");
}

/**
 * @brief
 * \~english An empty block is still a frame.
 * \~spanish Un bloque vacio sigue siendo una trama.
 * \~
 *
 * \~english
 * A `204` has nothing to say about itself, and sending no frame at all would
 * be sending no response.  It is the kind of case a loop over `n / max_frame`
 * gets wrong by sending nothing and reporting success.
 *
 * \~spanish
 * Un `204` no tiene nada que decir de si mismo, y no mandar ninguna trama seria
 * no mandar respuesta.  Es la clase de caso en la que un bucle sobre
 * `n / max_frame` se equivoca mandando nada y diciendo que fue bien.
 *
 * \~
 */
void test_an_empty_block_is_still_sent() {
    HeaderFramer f;
    IoList list;

    check(f.frame(list, 1, nullptr, 0, 16384, true) == FrameError::Ok,
          "an empty header block was refused");
    check(f.pieces() == 1, "an empty header block sent no frame");
    check(list.count() == 1, "an empty frame listed a payload");

    const FrameHeader h = head_of(list, 0);
    check(h.length == 0, "an empty frame says it carries bytes");
    check(ends_headers(h) && ends_stream(h),
          "an empty response did not end the block and the stream");
}

/**
 * @brief
 * \~english The body goes out in what the smaller of the two windows allows.
 * \~spanish El cuerpo sale en lo que deje la menor de las dos ventanas.
 * \~
 *
 * \~english
 * Three bounds and the answer is the smallest, and the part worth testing is
 * that BOTH windows are spent.  A writer that charged only the stream would
 * work perfectly on a connection with one stream on it -- which is every test
 * anybody writes by hand -- and would overrun the connection window as soon as
 * a second stream existed.
 *
 * \~spanish
 * Tres cotas y la respuesta es la menor, y la parte que merece probarse es que
 * se gastan LAS DOS ventanas.  Un escritor que cobrara solo al flujo
 * funcionaria perfectamente en una conexion con un solo flujo -- que son todas
 * las pruebas que escribe uno a mano -- y se pasaria de la ventana de la
 * conexion en cuanto hubiera un segundo.
 *
 * \~
 */
void test_the_body_spends_both_windows() {
    uint8_t body[1000];
    uint8_t head[9];

    Window stream(600);
    Window connection(65535);
    IoList list;
    size_t sent = 0;

    check(http_vx::h2::frame_body(list, head, 5, body, sizeof body, 16384,
                                  stream, connection, sent) == FrameError::Ok,
          "a body within the window was refused");
    check(sent == 600, "the body was not cut at the smaller window");
    check(stream.left() == 0, "the stream window was not spent");
    check(connection.left() == 65535 - 600,
          "the connection window was not spent");

    const FrameHeader h = head_of(list, 0);
    check(h.type == static_cast<uint8_t>(FrameType::Data),
          "the body frame is not a DATA");
    check(h.length == 600, "the frame does not say how much it carries");
    check(!ends_stream(h), "a body frame that is not the last ended the stream");
    check(list.slices()[1].data == body, "the body was copied");

    /* \~english
     * With the stream window closed nothing goes out, and that is not an
     * error: it is the peer saying "wait", which is what flow control is.
     * \~spanish
     * Con la ventana del flujo cerrada no sale nada, y eso no es un error: es el
     * otro extremo diciendo "espera", que es lo que es el control de flujo.
     * \~ */
    IoList again;
    check(http_vx::h2::frame_body(again, head, 5, body + 600, 400, 16384,
                                  stream, connection,
                                  sent) == FrameError::WouldBlock,
          "a closed stream window let the body through");
    check(sent == 0, "a blocked write reported bytes sent");
    check(again.empty(), "a blocked write listed a frame");
    check(connection.left() == 65535 - 600,
          "a blocked write spent the connection window anyway");
}

/**
 * @brief
 * \~english A stream in debt sends nothing, not a wrapped-around amount.
 * \~spanish Un flujo en deuda no manda nada, ni una cantidad que dio la vuelta.
 * \~
 *
 * \~english
 * The join with the settings layer.  A stream can be in debt without having
 * done anything -- the peer lowered its initial window -- and the bound here
 * is a comparison against a NEGATIVE number.  Done unsigned it is an enormous
 * allowance and the body goes out in full.
 *
 * \~spanish
 * La union con la capa de ajustes.  Un flujo puede estar en deuda sin haber
 * hecho nada -- el otro extremo bajo su ventana inicial -- y la cota de aqui es
 * una comparacion contra un numero NEGATIVO.  Hecha sin signo es un credito
 * enorme y el cuerpo sale entero.
 *
 * \~
 */
void test_a_stream_in_debt_sends_nothing() {
    uint8_t body[1000];
    uint8_t head[9];

    Window stream(65535);
    check(stream.take(60000), "the stream would not spend what it had");
    check(stream.adjust(16384 - 65535) == http_vx::h2::ErrorCode::NoError,
          "lowering the initial window was refused");
    check(stream.left() < 0, "the stream did not go into debt");

    Window connection(65535);
    IoList list;
    size_t sent = 0;

    check(http_vx::h2::frame_body(list, head, 7, body, sizeof body, 16384,
                                  stream, connection,
                                  sent) == FrameError::WouldBlock,
          "a stream in debt sent a body");
    check(sent == 0, "a stream in debt reported bytes sent");
    check(list.empty(), "a stream in debt listed a frame");
}

/**
 * @brief
 * \~english The end of a body costs no window.
 * \~spanish El final de un cuerpo no cuesta ventana.
 * \~
 *
 * \~english
 * A zero-length DATA with `END_STREAM` is how a response says it is over when
 * the last byte has already gone.  It spends nothing, so it goes out even when
 * both windows are shut -- and a writer that routed it through the body path
 * would hold the end of a response behind a window that will only open when
 * the peer has read a response it has not been told is finished.
 *
 * \~spanish
 * Un DATA de longitud cero con `END_STREAM` es como dice una respuesta que se ha
 * acabado cuando el ultimo byte ya salio.  No gasta nada, asi que sale aunque
 * las dos ventanas esten cerradas -- y un escritor que lo mandara por el camino
 * del cuerpo dejaria el final de una respuesta detenido detras de una ventana
 * que solo se abrira cuando el otro extremo haya leido una respuesta de la que
 * no le han dicho que ha terminado.
 *
 * \~
 */
void test_the_end_of_a_body_costs_nothing() {
    uint8_t head[9];
    IoList list;

    check(http_vx::h2::frame_end_of_body(list, head, 9),
          "the end of the response would not go out");
    check(list.count() == 1, "an empty DATA listed a payload");
    check(list.total() == 9, "an empty DATA is not nine bytes");

    const FrameHeader h = head_of(list, 0);
    check(h.type == static_cast<uint8_t>(FrameType::Data),
          "the end of the response is not a DATA");
    check(h.length == 0, "the end of the response carries bytes");
    check(h.stream_id == 9, "the end of the response is for the wrong stream");
    check(ends_stream(h), "the end of the response does not end the stream");
}

} // namespace

int main() {
    test_a_short_block_is_one_frame();
    test_a_long_block_is_cut_at_the_frame_size();
    test_a_refusal_writes_nothing();
    test_an_empty_block_is_still_sent();
    test_the_body_spends_both_windows();
    test_a_stream_in_debt_sends_nothing();
    test_the_end_of_a_body_costs_nothing();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
