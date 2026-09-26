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

/**
 * @brief
 * \~english One literal field, not remembered (RFC 7541, 6.2.2), or remembered (6.2.1).
 * \~spanish Una cabecera literal, sin recordar (RFC 7541, 6.2.2), o recordada (6.2.1).
 * \~
 */
void literal(uint8_t *at, size_t &n, const char *name, const char *value,
             bool remember = false) {
    const size_t nlen = std::strlen(name);
    const size_t vlen = std::strlen(value);

    at[n++] = remember ? 0x40 : 0x00;
    at[n++] = static_cast<uint8_t>(nlen);
    std::memcpy(at + n, name, nlen);
    n += nlen;
    at[n++] = static_cast<uint8_t>(vlen);
    std::memcpy(at + n, value, vlen);
    n += vlen;
}

/**
 * @brief
 * \~english A POST head: :method POST, :scheme https, :path /, and a content-length if @p length is not null.
 * \~spanish Una cabecera de POST: :method POST, :scheme https, :path /, y una content-length si @p length no es nulo.
 * \~
 */
size_t post_head(uint8_t *at, const char *length) {
    size_t n = 0;
    at[n++] = 0x83;
    at[n++] = 0x87;
    at[n++] = 0x84;
    if (length != nullptr) literal(at, n, "content-length", length);
    return n;
}

/**
 * @brief
 * \~english A connection past the preface and settings, and what a caller keeps.
 * \~spanish Una conexion pasado el preambulo y los ajustes, y lo que guarda quien llama.
 * \~
 */
struct Session {
    http_vx::h2::Limits limits;
    Connection c;
    Peer p;
    http_vx::Buffer headers;
    http_vx::Request req;

    Session() {
        c.reset(limits);
        c.flushed(c.pending_size());
        p.preface();
        p.settings();
    }

    Event next() {
        c.flushed(c.pending_size());
        return pump(c, p, headers, req);
    }

    void data(uint32_t id, const char *text, bool ends) {
        p.frame(FrameType::Data, ends ? http_vx::h2::kEndStream : 0, id,
                reinterpret_cast<const uint8_t *>(text), std::strlen(text));
    }
};

/**
 * @brief
 * \~english The code of the RST_STREAM waiting for @p id; ~0 if there is none.
 * \~spanish El codigo del RST_STREAM que espera para @p id; ~0 si no hay.
 * \~
 */
uint32_t reset_code(const Connection &c, uint32_t id) {
    size_t at = 0;
    while (at + 9 <= c.pending_size()) {
        FrameHeader h;
        http_vx::h2::decode_frame_header(c.pending() + at, h);
        if (h.type == static_cast<uint8_t>(FrameType::RstStream) && h.stream_id == id)
            return http_vx::h2::be32(c.pending() + at + 9);
        at += 9 + h.length;
    }
    return ~uint32_t{0};
}

/// \~english Whether @p why says @p what.  \~spanish Si @p why dice @p what.  \~
bool says(const char *why, const char *what) {
    return why != nullptr && std::strstr(why, what) != nullptr;
}

/**
 * @brief
 * \~english A stream error for a malformed request, told to the peer and kept for the log.
 * \~spanish Un error de flujo por una peticion mal formada, dicho al otro extremo y guardado para anotarlo.
 * \~
 */
bool malformed(const Session &s, const Event &e, uint32_t id, const char *what) {
    return e.kind == EventKind::StreamEnded && e.stream_id == id &&
           e.error == ErrorCode::ProtocolError &&
           reset_code(s.c, id) == static_cast<uint32_t>(ErrorCode::ProtocolError) &&
           says(s.c.why(), what);
}

/**
 * @brief
 * \~english The content-length has to be the sum of the DATA, no more and no less (RFC 9113, 8.1.1).
 * \~spanish La content-length tiene que ser la suma de los DATA, ni mas ni menos (RFC 9113, 8.1.1).
 * \~
 */
void test_the_content_length_is_the_data() {
    uint8_t block[128];

    {
        // \~english Exactly: 2 + 3 = 5.  \~spanish Exacto: 2 + 3 = 5.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "5"));
        s.data(1, "ab", false);
        s.data(1, "cde", true);

        check(s.next().kind == EventKind::Request, "a request with a content-length did not come out");
        Event e = s.next();
        check(e.kind == EventKind::Body && !e.ends && e.size == 2, "the first piece of an exact body was refused");
        e = s.next();
        check(e.kind == EventKind::Body && e.ends && e.size == 3, "the last piece of an exact body was refused");
        check(count_answers(s.c, FrameType::RstStream, 0) == 0, "an exact body was reset");
        check(s.c.why() == nullptr, "an exact body gave a reason");
    }
    {
        /* \~english
         * Too much, and refused on the frame that crosses the line, not at the
         * end: 3 is fine, 3 + 3 is past 5.
         * \~spanish
         * De mas, y rechazado en la trama que pasa de la raya, no al final: 3
         * vale, 3 + 3 pasa de 5.
         * \~ */
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "5"));
        s.data(1, "abc", false);
        s.data(1, "def", false);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        check(s.next().kind == EventKind::Body, "data within the content-length was refused");
        const Event e = s.next();
        check(malformed(s, e, 1, "more DATA"), "more DATA than the content-length was not refused (8.1.1)");

        /* \~english
         * A stream error, not the connection's: the next request is served.
         * \~spanish
         * Un error de flujo, no de la conexion: la peticion siguiente se sirve.
         * \~ */
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 3,
                  kRequestBlock, sizeof kRequestBlock);
        const Event n = s.next();
        check(n.kind == EventKind::Request && n.stream_id == 3, "a malformed request ended the connection");
        check(s.c.why() == nullptr, "the reason of a refusal stayed on the next event");
        check(count_answers(s.c, FrameType::Goaway, 0) == 0, "a malformed request sent a GOAWAY");
    }
    {
        // \~english One byte over, in a single frame.  \~spanish Un byte de mas, en una sola trama.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "5"));
        s.data(1, "abcdef", true);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        check(malformed(s, s.next(), 1, "more DATA"), "one byte over the content-length was not refused");
    }
    {
        // \~english Too little: 4 of 5 and the stream ends.  \~spanish De menos: 4 de 5 y el flujo acaba.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "5"));
        s.data(1, "abcd", true);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        check(malformed(s, s.next(), 1, "less DATA"), "less DATA than the content-length was not refused (8.1.1)");
    }
    {
        // \~english No content-length: nothing to compare with.  \~spanish Sin content-length: nada con que comparar.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, nullptr));
        s.data(1, "anything", true);

        check(s.next().kind == EventKind::Request, "a request without a content-length did not come out");
        const Event e = s.next();
        check(e.kind == EventKind::Body && e.ends && e.size == 8, "a body without a content-length was refused");
        check(count_answers(s.c, FrameType::RstStream, 0) == 0, "a body without a content-length was reset");
    }
    {
        /* \~english
         * Padding is not content: four bytes of data and eleven of padding
         * meet a content-length of four.
         * \~spanish
         * El relleno no es contenido: cuatro bytes de datos y once de relleno
         * cumplen una content-length de cuatro.
         * \~ */
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "4"));
        uint8_t padded[16] = {};
        padded[0] = 11;
        std::memcpy(padded + 1, "four", 4);
        s.p.frame(FrameType::Data, http_vx::h2::kEndStream | 0x08, 1, padded, sizeof padded);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        const Event e = s.next();
        check(e.kind == EventKind::Body && e.ends && e.size == 4, "padding was counted as content");
    }
}

/**
 * @brief
 * \~english A content-length that cannot be the content is malformed as soon as the head is read (RFC 9113, 8.1.1).
 * \~spanish Una content-length que no puede ser el contenido esta mal formada en cuanto se lee la cabecera (RFC 9113, 8.1.1).
 * \~
 */
void test_a_content_length_that_cannot_be() {
    struct Case {
        const char *value;
        bool ends;
        const char *why;
    };
    const Case cases[] = {
        {"5x", false, "not a number"},
        {"", false, "not a number"},
        {"5, 6", false, "disagree"},
        {"99999999999999999999999", false, "larger"},
        // \~english No DATA at all, but a length: the content is empty.  \~spanish Ningun DATA, pero una longitud: el contenido esta vacio.  \~
        {"3", true, "no DATA"},
    };

    for (const Case &k : cases) {
        Session s;
        uint8_t block[128];
        const uint8_t flags = http_vx::h2::kEndHeaders | (k.ends ? http_vx::h2::kEndStream : 0);
        s.p.frame(FrameType::Headers, flags, 1, block, post_head(block, k.value));

        const Event e = s.next();
        check(malformed(s, e, 1, k.why), k.why);
    }

    {
        // \~english But "5, 5" is one length, and "0" with END_STREAM is exact.
        // \~spanish Pero "5, 5" es una longitud, y "0" con END_STREAM es exacto.  \~
        Session s;
        uint8_t block[128];
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "5, 5"));
        s.data(1, "abcde", true);
        check(s.next().kind == EventKind::Request, "a repeated agreeing content-length was refused");
        check(s.next().kind == EventKind::Body, "the body of a repeated content-length was refused");

        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 3, block,
                  post_head(block, "0"));
        const Event e = s.next();
        check(e.kind == EventKind::Request && e.ends, "content-length: 0 with END_STREAM was refused");
        check(s.c.why() == nullptr, "an accepted request gave a reason");
    }
}

/**
 * @brief
 * \~english A second HEADERS that ends the stream is the trailer section, added to the request (RFC 9113, 8.1).
 * \~spanish Un segundo HEADERS que acaba el flujo es la seccion de remolques, anadida a la peticion (RFC 9113, 8.1).
 * \~
 */
void test_trailers_are_added_to_the_request() {
    uint8_t block[128];
    uint8_t tail[64];

    {
        Session s;
        size_t n = post_head(block, "2");
        literal(block, n, "x-a", "1");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, n);
        s.data(1, "hi", false);

        size_t t = 0;
        literal(tail, t, "x-sum", "42");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        check(s.next().kind == EventKind::Body, "the body did not come out");

        const Event e = s.next();
        check(e.kind == EventKind::Trailers, "the trailer section did not come out");
        check(e.stream_id == 1 && e.ends, "the trailer section did not end its stream");
        check(count_answers(s.c, FrameType::RstStream, 0) == 0, "a trailer section was reset");

        /* \~english
         * Into the request that was there: the head and the trailers, over
         * one buffer.
         * \~spanish
         * En la peticion que habia: la cabecera y los remolques, sobre un
         * buffer.
         * \~ */
        check(s.req.method == http_vx::MethodId::Post, "the trailers emptied the request");
        check(s.req.fields.size() == 3, "the trailers were not added to the head's fields");
        const http_vx::Field &f = s.req.fields.begin()[2];
        check(span_is(f.name_off, f.name_len, s.headers, "x-sum") &&
                  span_is(f.value_off, f.value_len, s.headers, "42"),
              "the trailer field is not the one that was sent");
        const http_vx::Field &g = s.req.fields.begin()[1];
        check(span_is(g.name_off, g.name_len, s.headers, "x-a"), "the head's field was lost to the trailers");

        // \~english Every span, the head's too, inside what the buffer holds.
        // \~spanish Todos los trozos, tambien los de la cabecera, dentro de lo que tiene el buffer.  \~
        bool inside = s.req.target.off + s.req.target.len <= s.headers.size();
        for (const http_vx::Field *h = s.req.fields.begin(); h != s.req.fields.end(); ++h)
            inside = inside && h->name_off + h->name_len <= s.headers.size() &&
                     h->value_off + h->value_len <= s.headers.size();
        check(inside, "the trailers were written over the head");

        /* \~english
         * And the stream is over: a DATA after the trailers is data after the
         * end (RFC 9113, 5.1).
         * \~spanish
         * Y el flujo acabo: un DATA detras de los remolques es un dato
         * despues del final (RFC 9113, 5.1).
         * \~ */
        s.data(1, "late", false);
        const Event d = s.next();
        check(d.kind == EventKind::StreamEnded && d.error == ErrorCode::StreamClosed,
              "DATA after the trailers was accepted");
    }
    {
        // \~english Split over a CONTINUATION, and still trailers.  \~spanish Partido en una CONTINUATION, y siguen siendo remolques.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, nullptr));
        size_t t = 0;
        literal(tail, t, "x-one", "1");
        const size_t half = t;
        literal(tail, t, "x-two", "2");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndStream, 1, tail, half);
        s.p.frame(FrameType::Continuation, http_vx::h2::kEndHeaders, 1, tail + half, t - half);

        check(s.next().kind == EventKind::Request, "the request did not come out");
        const Event e = s.next();
        check(e.kind == EventKind::Trailers && e.ends, "trailers split over a CONTINUATION were not trailers");
        check(s.req.fields.size() == 2, "a piece of the split trailers was lost");
    }
    {
        // \~english An exact content-length ended by the trailers.  \~spanish Una content-length exacta que acaban los remolques.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "3"));
        s.data(1, "abc", false);
        size_t t = 0;
        literal(tail, t, "x-sum", "1");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);

        s.next();
        s.next();
        check(s.next().kind == EventKind::Trailers, "trailers after an exact body were refused");
    }
}

/**
 * @brief
 * \~english What a second HEADERS may not be (RFC 9113, 5.1, 8.1, 8.1.1).
 * \~spanish Lo que no puede ser un segundo HEADERS (RFC 9113, 5.1, 8.1, 8.1.1).
 * \~
 */
void test_what_trailers_may_not_be() {
    uint8_t block[128];
    uint8_t tail[64];

    {
        // \~english A pseudo-header field in trailers.  \~spanish Una pseudo-cabecera en los remolques.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, nullptr));
        const uint8_t pseudo[] = {0x84};
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, pseudo,
                  sizeof pseudo);

        s.next();
        check(malformed(s, s.next(), 1, "pseudo-header"), "a pseudo-header field in trailers was accepted (8.1)");
    }
    {
        /* \~english
         * A second HEADERS without END_STREAM, which remembers a field: the
         * request is refused, and the block is read anyway -- the next
         * request names that field by index and has to find it.
         * \~spanish
         * Un segundo HEADERS sin END_STREAM, que recuerda una cabecera: la
         * peticion se rechaza, y el bloque se lee igual -- la peticion
         * siguiente nombra esa cabecera por indice y tiene que encontrarla.
         * \~ */
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, nullptr));
        size_t t = 0;
        literal(tail, t, "x-k", "v", true);
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, tail, t);

        s.next();
        check(malformed(s, s.next(), 1, "without END_STREAM"),
              "a second HEADERS without END_STREAM was accepted (8.1)");

        const uint8_t again[] = {0x82, 0x87, 0x84, 0xbe};
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 3, again,
                  sizeof again);
        const Event e = s.next();
        check(e.kind == EventKind::Request && e.stream_id == 3, "the request after the refusal was lost");
        // \~english First in the buffer, the name :method, and the value right after it.
        // \~spanish Lo primero del buffer, el nombre :method, y el valor justo detras.  \~
        check(s.req.method_text.off == 7, "a new head did not start the header buffer afresh");
        check(s.req.fields.size() == 1 && span_is(s.req.fields.begin()[0].name_off,
                                                  s.req.fields.begin()[0].name_len, s.headers, "x-k"),
              "the refused block did not reach the table");
    }
    {
        // \~english A third HEADERS, after the trailers ended the stream.  \~spanish Un tercer HEADERS, despues de que los remolques acabaran el flujo.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, nullptr));
        size_t t = 0;
        literal(tail, t, "x-sum", "1");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);

        s.next();
        check(s.next().kind == EventKind::Trailers, "the trailers did not come out");
        const Event e = s.next();
        check(e.kind == EventKind::StreamEnded && e.error == ErrorCode::StreamClosed &&
                  reset_code(s.c, 1) == static_cast<uint32_t>(ErrorCode::StreamClosed) &&
                  says(s.c.why(), "after the stream had ended"),
              "a third HEADERS was accepted (5.1)");
        check(count_answers(s.c, FrameType::Goaway, 0) == 0, "a third HEADERS ended the connection");
    }
    {
        // \~english A second HEADERS on a stream the first one already ended.  \~spanish Un segundo HEADERS en un flujo que ya acabo el primero.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, block,
                  post_head(block, nullptr));
        size_t t = 0;
        literal(tail, t, "x-sum", "1");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);

        s.next();
        const Event e = s.next();
        check(e.kind == EventKind::StreamEnded && e.error == ErrorCode::StreamClosed,
              "trailers after a HEADERS with END_STREAM were accepted (5.1)");
    }
    {
        // \~english Trailers that end the content short.  \~spanish Remolques que acaban el contenido corto.  \~
        Session s;
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, block, post_head(block, "10"));
        s.data(1, "abcd", false);
        size_t t = 0;
        literal(tail, t, "x-sum", "1");
        s.p.frame(FrameType::Headers, http_vx::h2::kEndHeaders | http_vx::h2::kEndStream, 1, tail, t);

        s.next();
        s.next();
        check(malformed(s, s.next(), 1, "less DATA"), "trailers ending the content short were accepted (8.1.1)");
    }
}

} // namespace

int main() {
    test_a_request_comes_out_the_far_end();
    test_a_ping_is_echoed_but_an_echo_is_not();
    test_a_flood_of_questions_stops_the_reading();
    test_the_window_comes_back_when_the_body_is_used();
    test_a_broken_connection_says_why();
    test_the_content_length_is_the_data();
    test_a_content_length_that_cannot_be();
    test_trailers_are_added_to_the_request();
    test_what_trailers_may_not_be();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
