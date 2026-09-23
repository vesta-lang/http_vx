/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_connection.cpp
 * @brief
 * \~english A whole connection, from the preface to a request, without a socket.
 * \~spanish Una conexion entera, del preambulo a una peticion, sin socket.
 * \~
 *
 * \~english
 * This is the test the project's shape was chosen for.  Every layer takes a
 * view of bytes and hands back what it found, so a connection can be driven
 * from an array in a test binary and the code exercised is byte for byte the
 * code that would run on a socket.  Nothing here is a mock.
 *
 * Two things get the most attention.  The first is the ordinary path all the
 * way through: preface, settings, a real header block out of RFC 7541, and a
 * @c Request coming out the far end with the same method and target an
 * HTTP/1.1 request line would have produced.
 *
 * The second is what happens when a peer asks for more answers than can be
 * written.  That one has no correct-looking wrong answer: a server that grew
 * its buffer would pass every functional test and let a peer choose how much
 * memory it uses.  So what is checked is that reading STOPS and the buffer
 * does not move.
 *
 * \~spanish
 * Esta es la prueba para la que se eligio la forma del proyecto.  Cada capa
 * recibe una vista de bytes y devuelve lo que encontro, asi que una conexion se
 * puede mover desde un array en un binario de prueba y el codigo que se ejercita
 * es byte a byte el que correria sobre un socket.  Aqui no hay ningun simulacro.
 *
 * Dos cosas se llevan casi toda la atencion.  La primera es el camino corriente
 * de punta a punta: preambulo, ajustes, un bloque de cabeceras de verdad sacado
 * del RFC 7541, y un @c Request saliendo por el otro lado con el mismo metodo y
 * el mismo destino que habria producido una linea de peticion de HTTP/1.1.
 *
 * La segunda es que pasa cuando un extremo pide mas respuestas de las que caben.
 * Esa no tiene ninguna respuesta equivocada que parezca correcta: un servidor
 * que hiciera crecer su buffer pasaria todas las pruebas funcionales y dejaria
 * que el otro extremo eligiera cuanta memoria usa.  Asi que lo que se comprueba
 * es que la lectura SE PARA y el buffer no se mueve.
 *
 * \~
 */

#include "http_vx/h2_connection.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::Connection;
using http_vx::h2::ErrorCode;
using http_vx::h2::Event;
using http_vx::h2::EventKind;
using http_vx::h2::FrameHeader;
using http_vx::h2::FrameType;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Builds the bytes a client would send.
 * \~spanish Construye los bytes que mandaria un cliente.
 * \~
 *
 * \~english
 * A client, not a mock of one: what goes in is the bytes an HTTP/2 client puts
 * on a socket, written by hand so that the test does not depend on this
 * project's own writer being right.  A test whose input came from the code
 * under test would agree with it about anything.
 *
 * \~spanish
 * Un cliente, no un simulacro: lo que entra son los bytes que un cliente HTTP/2
 * pone en un socket, escritos a mano para que la prueba no dependa de que el
 * escritor de este mismo proyecto acierte.  Una prueba cuya entrada saliera del
 * codigo que prueba estaria de acuerdo con el en cualquier cosa.
 *
 * \~
 */
class Peer {
  public:
    void preface() {
        put(http_vx::h2::kClientPreface, sizeof(http_vx::h2::kClientPreface));
    }

    void frame(FrameType type, uint8_t flags, uint32_t id,
               const uint8_t *payload, size_t n) {
        FrameHeader h;
        h.length = static_cast<uint32_t>(n);
        h.type = static_cast<uint8_t>(type);
        h.flags = flags;
        h.stream_id = id;

        uint8_t head[9];
        http_vx::h2::encode_frame_header(head, h);
        put(head, sizeof head);
        if (n != 0) put(payload, n);
    }

    void settings() { frame(FrameType::Settings, 0, 0, nullptr, 0); }

    void put(const void *p, size_t n) {
        uint8_t *room = buf.reserve(n);
        std::memcpy(room, p, n);
        buf.commit(n);
    }

    http_vx::View view() const { return buf.view(); }

    http_vx::Buffer buf;
};

/**
 * @brief
 * \~english Reads until something is reported, or nothing more can be.
 * \~spanish Lee hasta que se informe de algo, o hasta que no se pueda mas.
 * \~
 *
 * \~english
 * What a real caller does, and the reason it is a helper is that the obvious
 * loop is WRONG: @c None does not mean "there is nothing left", it means
 * "nothing came of this call".  A SETTINGS is read and answered and reports
 * @c None, so a loop that stopped on the first one would stop before the
 * connection had done anything -- and would then pass a test about a ping it
 * never read.
 *
 * The condition that actually ends it is no progress: a call that reported
 * nothing AND consumed nothing has nothing more to give until more bytes
 * arrive or the answers are flushed.
 *
 * \~spanish
 * Lo que hace quien llama de verdad, y la razon de que sea un ayudante es que
 * el bucle evidente esta MAL: @c None no quiere decir "ya no queda nada", quiere
 * decir "de esta llamada no salio nada".  Un SETTINGS se lee, se contesta e
 * informa @c None, asi que un bucle que parara en el primero pararia antes de
 * que la conexion hubiera hecho nada -- y luego pasaria una prueba sobre un ping
 * que no llego a leer.
 *
 * La condicion que de verdad lo acaba es que no haya avance: una llamada que no
 * informo de nada Y no consumio nada no tiene nada mas que dar hasta que lleguen
 * mas bytes o se vacien las respuestas.
 *
 * \~
 */
Event pump(Connection &c, const Peer &p, http_vx::Buffer &headers,
           http_vx::Request &req) {
    for (;;) {
        const uint64_t before = c.consumed();
        const Event e = c.read(p.view(), headers, req);

        if (e.kind != EventKind::None) return e;
        if (c.consumed() == before) return e;
    }
}

/**
 * @brief
 * \~english Walks the answers waiting to go out.
 * \~spanish Recorre las respuestas que esperan para salir.
 * \~
 */
size_t count_answers(const Connection &c, FrameType type, uint8_t flags) {
    size_t found = 0;
    size_t at = 0;

    while (at + 9 <= c.pending_size()) {
        FrameHeader h;
        http_vx::h2::decode_frame_header(c.pending() + at, h);

        if (h.type == static_cast<uint8_t>(type) && (h.flags & flags) == flags)
            ++found;

        at += 9 + h.length;
    }

    return found;
}

/**
 * @brief
 * \~english The first request of RFC 7541 appendix C.3, as a client sends it.
 * \~spanish La primera peticion del apendice C.3 del RFC 7541, como la manda un cliente.
 * \~
 *
 * \~english
 * `:method GET :scheme http :path / :authority www.example.com`, with the
 * first three as static-table indices and the fourth spelled out.  Taken from
 * the specification rather than made up, so that what is being checked is
 * agreement with the protocol and not agreement with this project.
 *
 * \~spanish
 * `:method GET :scheme http :path / :authority www.example.com`, con las tres
 * primeras como indices de la tabla estatica y la cuarta escrita.  Sacada de la
 * especificacion y no inventada, para que lo que se comprueba sea el acuerdo con
 * el protocolo y no el acuerdo con este proyecto.
 *
 * \~
 */
const uint8_t kRequestBlock[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77,
                                 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
                                 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d};

bool span_is(uint32_t off, uint32_t len, const http_vx::Buffer &out,
             const char *want) {
    if (len != std::strlen(want)) return false;
    return std::memcmp(out.data() + off, want, len) == 0;
}

/**
 * @brief
 * \~english Bytes in, a request out.
 * \~spanish Entran bytes, sale una peticion.
 * \~
 */
void test_a_request_comes_out_the_far_end() {
    http_vx::h2::Limits limits;
    Connection c;
    c.reset(limits);

    /* \~english
     * This end speaks first: the opening SETTINGS is written before a byte has
     * been read, because the peer may start sending requests the moment it has
     * written its preface.
     * \~spanish
     * Este extremo habla primero: el SETTINGS de apertura se escribe antes de
     * haber leido un byte, porque el otro puede empezar a mandar peticiones en
     * cuanto haya escrito su preambulo.
     * \~ */
    check(count_answers(c, FrameType::Settings, 0) == 1,
          "the opening SETTINGS was not written before reading");
    c.flushed(c.pending_size());

    Peer p;
    p.preface();
    p.settings();
    p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream,
            1, kRequestBlock, sizeof kRequestBlock);

    http_vx::Buffer headers;
    http_vx::Request req;

    /* \~english
     * The peer's SETTINGS is read and acknowledged, and nothing is reported
     * for it: a settings frame is not an event, it is the connection changing
     * shape underneath one.
     * \~spanish
     * El SETTINGS del otro se lee y se confirma, y no se informa de nada: una
     * trama de ajustes no es un suceso, es la conexion cambiando de forma
     * debajo de uno.
     * \~ */
    Event e = pump(c, p, headers, req);
    check(count_answers(c, FrameType::Settings, http_vx::h2::kAck) == 1,
          "the peer's settings were not acknowledged");

    check(e.kind == EventKind::Request, "the request did not come out");
    check(e.stream_id == 1, "the request is on the wrong stream");
    check(e.ends, "a request with END_STREAM did not say it had ended");

    /* \~english
     * And here is the claim the whole project has been making since
     * `semantics/`: what comes out is a @c Request with a method and a target
     * and an authority, and it is the same one the HTTP/1.1 parser builds out
     * of a line of text.  Nothing above this layer has to know which version
     * it came from.
     * \~spanish
     * Y aqui esta la afirmacion que viene haciendo el proyecto entero desde
     * `semantics/`: lo que sale es un @c Request con su metodo, su destino y su
     * anfitrion, y es el mismo que construye de una linea de texto el analizador
     * de HTTP/1.1.  Nada por encima de esta capa tiene que saber de que version
     * vino.
     * \~ */
    check(req.method == http_vx::MethodId::Get, "the method is not GET");
    check(span_is(req.target.off, req.target.len, headers, "/"),
          "the target is not /");
    check(span_is(req.authority.off, req.authority.len, headers,
                  "www.example.com"),
          "the authority is not the one that was sent");
    check(span_is(req.scheme.off, req.scheme.len, headers, "http"),
          "the scheme is not http");

    check(c.consumed() == p.buf.size(),
          "the connection did not finish with everything that arrived");
}

/**
 * @brief
 * \~english A PING is echoed, and an echo is not.
 * \~spanish Un PING se devuelve, y un eco no.
 * \~
 *
 * \~english
 * The second half is the one worth writing down.  Two servers that both echoed
 * everything would ping each other forever at the speed of the network, and
 * neither of them would be doing anything wrong.
 *
 * \~spanish
 * La segunda mitad es la que merece escribirse.  Dos servidores que devolvieran
 * todo se harian ping el uno al otro para siempre a la velocidad de la red, y
 * ninguno de los dos estaria haciendo nada mal.
 *
 * \~
 */
void test_a_ping_is_echoed_but_an_echo_is_not() {
    http_vx::h2::Limits limits;
    Connection c;
    c.reset(limits);
    c.flushed(c.pending_size());

    Peer p;
    p.preface();
    p.settings();

    const uint8_t token[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    p.frame(FrameType::Ping, 0, 0, token, sizeof token);

    http_vx::Buffer headers;
    http_vx::Request req;

    pump(c, p, headers, req);

    check(count_answers(c, FrameType::Ping, http_vx::h2::kAck) == 1,
          "the ping was not echoed");

    /* \~english
     * And the echo carries the same eight bytes, which is what a ping is FOR:
     * a peer measuring a round trip matches the answer to the question by
     * them.
     * \~spanish
     * Y el eco lleva los mismos ocho bytes, que es PARA lo que sirve un ping: un
     * extremo que mide una ida y vuelta empareja la respuesta con la pregunta
     * por ellos.
     * \~ */
    bool same = false;
    size_t at = 0;
    while (at + 9 <= c.pending_size()) {
        FrameHeader h;
        http_vx::h2::decode_frame_header(c.pending() + at, h);
        if (h.type == static_cast<uint8_t>(FrameType::Ping) &&
            std::memcmp(c.pending() + at + 9, token, sizeof token) == 0)
            same = true;
        at += 9 + h.length;
    }
    check(same, "the echo does not carry what was pinged");

    c.flushed(c.pending_size());

    /* \~english
     * Now the peer sends an answer of its own.  It must not be answered.
     * \~spanish
     * Ahora el otro extremo manda una respuesta suya.  No se le puede contestar.
     * \~ */
    Connection d;
    d.reset(limits);
    d.flushed(d.pending_size());

    Peer r;
    r.preface();
    r.settings();
    r.frame(FrameType::Ping, http_vx::h2::kAck, 0, token, sizeof token);

    pump(d, r, headers, req);
    d.flushed(0);

    check(count_answers(d, FrameType::Ping, 0) == 0,
          "an echo was echoed back");
}

/**
 * @brief
 * \~english A peer that asks for too many answers is not answered faster.
 * \~spanish A un extremo que pide demasiadas respuestas no se le contesta mas deprisa.
 * \~
 *
 * \~english
 * The one with no correct-looking wrong answer.  A server that grew its
 * buffer would pass every functional test there is and let a peer decide how
 * much memory it spends -- and the peer does not even have to read the
 * answers, which is what makes it cheap for the attacker and expensive for the
 * server.
 *
 * So what is checked is that reading STOPS: the pending bytes never go past
 * the fixed room, and the connection has NOT consumed everything that arrived.
 * The second part is the one that matters -- a server that read the frames and
 * dropped the answers would also keep its buffer small, and would leave a peer
 * waiting for pings that were never coming.
 *
 * \~spanish
 * La que no tiene ninguna respuesta equivocada que parezca correcta.  Un
 * servidor que hiciera crecer su buffer pasaria todas las pruebas funcionales
 * que hay y dejaria que el otro extremo decidiera cuanta memoria gasta -- y el
 * otro ni siquiera tiene que leer las respuestas, que es lo que lo hace barato
 * para el atacante y caro para el servidor.
 *
 * Asi que lo que se comprueba es que la lectura SE PARA: los bytes pendientes no
 * pasan nunca del sitio fijo, y la conexion NO ha consumido todo lo que llego.
 * La segunda parte es la que importa -- un servidor que leyera las tramas y
 * tirara las respuestas tambien mantendria pequeno su buffer, y dejaria a un
 * extremo esperando unos pings que no iban a llegar.
 *
 * \~
 */
void test_a_flood_of_questions_stops_the_reading() {
    http_vx::h2::Limits limits;
    Connection c;
    c.reset(limits);
    c.flushed(c.pending_size());

    Peer p;
    p.preface();
    p.settings();

    const uint8_t token[8] = {0};
    for (int i = 0; i < 500; ++i) p.frame(FrameType::Ping, 0, 0, token, sizeof token);

    http_vx::Buffer headers;
    http_vx::Request req;

    pump(c, p, headers, req);

    check(c.pending_size() <= http_vx::h2::kControlRoom,
          "the answers grew past the room they have");
    check(c.pending_size() != 0, "nothing was answered at all");
    check(c.consumed() < p.buf.size(),
          "every ping was read although the answers could not be written");

    /* \~english
     * And it picks up exactly where it stopped once there is room again.  The
     * rate the peer gets its answers at is the rate its own socket drains
     * them, which is the whole idea.
     * \~spanish
     * Y sigue exactamente por donde se paro en cuanto vuelve a haber sitio.  El
     * ritmo al que el otro extremo recibe sus respuestas es el ritmo al que las
     * vacia su propio socket, que es toda la idea.
     * \~ */
    const uint64_t before = c.consumed();
    c.flushed(c.pending_size());

    pump(c, p, headers, req);

    check(c.consumed() > before, "reading did not carry on after flushing");
    check(c.pending_size() <= http_vx::h2::kControlRoom,
          "the answers grew past the room they have");
}

/**
 * @brief
 * \~english Window is given back when the body is used, not when it arrives.
 * \~spanish La ventana se devuelve cuando se usa el cuerpo, no cuando llega.
 * \~
 *
 * \~english
 * That difference is the whole of flow control.  Giving it back on arrival
 * says "keep sending" to a peer whose data is piling up unread, which is the
 * same as having no flow control while paying for it.
 *
 * \~spanish
 * Esa diferencia es todo el control de flujo.  Devolverla al llegar le dice
 * "sigue mandando" a un extremo cuyos datos se estan amontonando sin leer, que
 * es lo mismo que no tener control de flujo pero pagandolo.
 *
 * \~
 */
void test_the_window_comes_back_when_the_body_is_used() {
    http_vx::h2::Limits limits;
    Connection c;
    c.reset(limits);
    c.flushed(c.pending_size());

    uint8_t body[100];
    for (size_t i = 0; i < sizeof body; ++i) body[i] = static_cast<uint8_t>(i);

    Peer p;
    p.preface();
    p.settings();
    p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, kRequestBlock,
            sizeof kRequestBlock);
    p.frame(FrameType::Data, http_vx::h2::kEndStream, 1, body, sizeof body);

    http_vx::Buffer headers;
    http_vx::Request req;

    Event e = pump(c, p, headers, req);
    check(e.kind == EventKind::Request, "the request did not come out");
    check(!e.ends, "a request with a body said it had already ended");

    c.flushed(c.pending_size());

    e = pump(c, p, headers, req);
    check(e.kind == EventKind::Body, "the body did not come out");
    check(e.size == sizeof body, "the body is not the size it was sent");
    check(e.ends, "the last body frame did not end the request");
    check(e.data != nullptr && std::memcmp(e.data, body, sizeof body) == 0,
          "the body is not the bytes that were sent");

    /* \~english
     * Nothing has been given back yet, although the bytes have arrived.
     * \~spanish
     * Todavia no se ha devuelto nada, aunque los bytes hayan llegado.
     * \~ */
    check(count_answers(c, FrameType::WindowUpdate, 0) == 0,
          "window was given back before the body had been used");

    check(c.release_window(1, sizeof body), "the window could not be given back");

    /* \~english
     * Two of them: one for the stream and one for the connection.  The peer
     * keeps two counts, and giving back only one stalls the connection just as
     * surely -- only later.
     * \~spanish
     * Dos: uno del flujo y otro de la conexion.  El otro extremo lleva dos
     * cuentas, y devolver solo una atasca la conexion igual de seguro -- solo
     * que mas tarde.
     * \~ */
    check(count_answers(c, FrameType::WindowUpdate, 0) == 2,
          "the window was not given back on both counts");
}

/**
 * @brief
 * \~english A connection that ends says why before it goes.
 * \~spanish Una conexion que se acaba dice por que antes de irse.
 * \~
 *
 * \~english
 * A GOAWAY costs seventeen bytes and it is the difference between a peer that
 * can log what happened and one whose socket simply died.  It carries the last
 * stream this end looked at, so the peer knows which of its requests were seen
 * and which it may send again.
 *
 * \~spanish
 * Un GOAWAY cuesta diecisiete bytes y es la diferencia entre un extremo que
 * puede anotar que paso y uno cuyo socket se murio sin mas.  Lleva el ultimo
 * flujo que miro este extremo, para que el otro sepa cuales de sus peticiones
 * se vieron y cuales puede volver a mandar.
 *
 * \~
 */
void test_a_broken_connection_says_why() {
    http_vx::h2::Limits limits;
    Connection c;
    c.reset(limits);
    c.flushed(c.pending_size());

    Peer p;
    p.preface();
    p.settings();
    p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream,
            1, kRequestBlock, sizeof kRequestBlock);

    /* \~english
     * An even identifier is one this server would have opened, which means the
     * two ends disagree about who numbers what.
     * \~spanish
     * Un identificador par es uno que habria abierto este servidor, lo que
     * quiere decir que los dos extremos discrepan sobre quien numera que.
     * \~ */
    p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream,
            2, kRequestBlock, sizeof kRequestBlock);

    http_vx::Buffer headers;
    http_vx::Request req;

    Event e = pump(c, p, headers, req);
    while (e.kind != EventKind::Closed && e.kind != EventKind::None)
        e = pump(c, p, headers, req);

    check(e.kind == EventKind::Closed, "an even identifier did not end the connection");
    check(e.error == ErrorCode::ProtocolError,
          "the connection did not end with a protocol error");
    check(count_answers(c, FrameType::Goaway, 0) == 1,
          "the connection ended without saying why");

    /* \~english
     * And once it is over nothing more is read, whatever else is in the
     * buffer.  A connection that carried on would be acting on frames from a
     * peer it has already told to go away.
     * \~spanish
     * Y una vez acabada no se lee nada mas, haya lo que haya en el buffer.  Una
     * conexion que siguiera estaria atendiendo tramas de un extremo al que ya le
     * ha dicho que se vaya.
     * \~ */
    const uint64_t at = c.consumed();
    check(c.read(p.view(), headers, req).kind == EventKind::None,
          "a closed connection went on reading");
    check(c.consumed() == at, "a closed connection consumed more bytes");
}

} // namespace

int main() {
    test_a_request_comes_out_the_far_end();
    test_a_ping_is_echoed_but_an_echo_is_not();
    test_a_flood_of_questions_stops_the_reading();
    test_the_window_comes_back_when_the_body_is_used();
    test_a_broken_connection_says_why();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
