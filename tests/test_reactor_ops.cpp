/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_reactor_ops.cpp
 * @brief
 * \~english Operations, completions, and the one that comes back too late.
 * \~spanish Operaciones, finalizaciones, y la que vuelve demasiado tarde.
 * \~
 *
 * \~english
 * The case worth the whole file is a completion arriving for a connection
 * that has gone.  It is not a corner: the peer disappeared, a read was already
 * submitted, and the kernel finishes it either way.  On a busy server it
 * happens constantly.
 *
 * What makes it dangerous is that by then the slot may belong to somebody
 * else, and the completion is carrying bytes.  Handing them to whoever is in
 * the slot now is one client's data appearing inside another client's
 * request -- silently, on a server where every field involved is valid.
 *
 * Against a real network that takes a race to see.  Here it takes two lines,
 * which is the reason this backend exists.
 *
 * \~spanish
 * El caso que justifica el fichero entero es una finalizacion que llega por una
 * conexion que ya se fue.  No es una esquina: el otro extremo desaparecio, ya
 * habia una lectura entregada, y el nucleo la acaba igual.  En un servidor con
 * trabajo pasa constantemente.
 *
 * Lo que lo hace peligroso es que para entonces la casilla puede ser de otro, y
 * la finalizacion lleva bytes.  Darselos a quien este ahora en la casilla son
 * los datos de un cliente apareciendo dentro de la peticion de otro -- en
 * silencio, en un servidor donde todos los campos implicados son validos.
 *
 * Contra una red de verdad eso cuesta una carrera verlo.  Aqui cuesta dos
 * lineas, que es la razon de que exista este backend.
 *
 * \~
 */

#include "http_vx/memory_backend.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::Buffer;
using http_vx::BufferPool;
using http_vx::Completion;
using http_vx::ConnHandle;
using http_vx::ConnTable;
using http_vx::kNoBuffer;
using http_vx::MemoryBackend;
using http_vx::Op;
using http_vx::OpKind;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Everything one shard has, made together.
 * \~spanish Todo lo que tiene un fragmento, hecho junto.
 * \~
 */
struct Shard {
    ConnTable conns;
    BufferPool pool;
    MemoryBackend io;

    Shard() : io(pool) {
        conns.reset(4);
        pool.reset(4, 1 << 20);
    }
};

/**
 * @brief
 * \~english A read is asked for and comes back with what was sent.
 * \~spanish Se pide una lectura y vuelve con lo que se mando.
 * \~
 */
void test_a_read_comes_back_with_the_bytes() {
    Shard s;

    const ConnHandle c = s.conns.open(3, 0);
    check(c.valid(), "a connection could not be opened");

    const uint32_t b = s.pool.acquire();
    check(b != kNoBuffer, "a buffer could not be lent");

    Op op;
    op.conn = c;
    op.kind = OpKind::Recv;
    op.buffer = b;
    op.length = 4096;

    check(s.io.submit(op), "the read was not taken");
    check(s.io.pending() == 1, "the read is not outstanding");

    /* \~english
     * Nothing has arrived, so nothing finishes.  The operation stays
     * outstanding, which is what a socket does -- and the buffer stays the
     * operating system's for as long as it does.
     * \~spanish
     * No ha llegado nada, asi que no acaba nada.  La operacion sigue pendiente,
     * que es lo que hace un socket -- y el buffer sigue siendo del sistema
     * operativo todo ese rato.
     * \~ */
    Completion done[8];
    check(s.io.wait(done, 8, 0) == 0, "a read finished with nothing to read");
    check(s.io.pending() == 1, "the read stopped being outstanding");

    const char *msg = "GET / HTTP/1.1\r\n\r\n";
    check(s.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    check(s.io.wait(done, 8, 0) == 1, "the read did not finish");
    check(s.io.pending() == 0, "the read is still outstanding");

    check(done[0].ok(), "the read failed");
    check(!done[0].eof(), "the read reported end of stream");
    check(done[0].result == static_cast<int32_t>(std::strlen(msg)),
          "the read did not move what was sent");

    /* \~english
     * The completion hands back the buffer it was on, so the loop can return
     * it without looking anything up -- and cannot return a different one.
     * \~spanish
     * La finalizacion devuelve el buffer sobre el que iba, para que el bucle
     * pueda devolverlo sin consultar nada -- y no pueda devolver otro.
     * \~ */
    check(done[0].buffer == b, "the completion named a different buffer");

    Buffer *buf = s.pool.at(done[0].buffer);
    check(buf != nullptr && buf->size() == std::strlen(msg),
          "the bytes did not land in the buffer");
    check(buf != nullptr &&
              std::memcmp(buf->data(), msg, std::strlen(msg)) == 0,
          "the bytes in the buffer are not the ones sent");
}

/**
 * @brief
 * \~english A completion for a connection that has gone names nobody.
 * \~spanish Una finalizacion de una conexion que ya se fue no nombra a nadie.
 * \~
 *
 * \~english
 * The one.  A read is outstanding, the connection goes away, the slot is
 * taken by somebody else, and only THEN does the read finish.  Every field in
 * the completion is valid; the slot it names is a live connection.  What says
 * it is not the right one is the life.
 *
 * \~spanish
 * El caso.  Hay una lectura pendiente, la conexion se va, la casilla la coge
 * otro, y SOLO ENTONCES acaba la lectura.  Todos los campos de la finalizacion
 * son validos; la casilla que nombra es una conexion viva.  Lo que dice que no
 * es la buena es la vida.
 *
 * \~
 */
void test_a_completion_that_arrives_too_late() {
    Shard s;

    const ConnHandle first = s.conns.open(3, 0);
    check(first.valid(), "a connection could not be opened");

    const uint32_t b = s.pool.acquire();
    check(b != kNoBuffer, "a buffer could not be lent");

    Op op;
    op.conn = first;
    op.kind = OpKind::Recv;
    op.buffer = b;
    op.length = 4096;
    check(s.io.submit(op), "the read was not taken");

    /* \~english
     * The connection goes, and every slot in this table is handed out again
     * before it comes round -- so the one that takes this slot is definitely a
     * different connection and definitely the same index.
     * \~spanish
     * La conexion se va, y todas las casillas de esta tabla se reparten otra vez
     * antes de que vuelva -- asi que la que coja esta casilla es seguro otra
     * conexion y seguro el mismo indice.
     * \~ */
    check(s.conns.close(first), "the connection could not be closed");

    ConnHandle others[3];
    for (int i = 0; i < 3; ++i) others[i] = s.conns.open(10 + i, 0);
    for (int i = 0; i < 3; ++i) check(s.conns.close(others[i]), "a close failed");

    const ConnHandle second = s.conns.open(9, 0);
    check(second.valid(), "the second connection could not be opened");
    check(second.slot == first.slot, "the test did not reuse the slot");

    /* \~english
     * Now the kernel finishes the read that was submitted for the first one.
     * \~spanish
     * Ahora el nucleo acaba la lectura que se entrego por la primera.
     * \~ */
    const char *msg = "secret";
    check(s.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    Completion done[8];
    check(s.io.wait(done, 8, 0) == 1, "the read did not finish");
    check(done[0].ok(), "the read failed");

    /* \~english
     * It names a slot that is live, and it is NOT the connection that is in
     * it.  A loop that only checked the index would hand these bytes to the
     * second connection.
     * \~spanish
     * Nombra una casilla que esta viva, y NO es la conexion que hay dentro.  Un
     * bucle que solo comprobara el indice le daria estos bytes a la segunda
     * conexion.
     * \~ */
    check(done[0].conn.slot == second.slot,
          "the completion does not name the slot it was for");
    check(!s.conns.alive(done[0].conn),
          "a completion from a previous life reached a live connection");
    check(s.conns.hot(done[0].conn) == nullptr,
          "a completion from a previous life reached a hot record");

    /* \~english
     * And the connection that IS in the slot is untouched and still itself.
     * \~spanish
     * Y la conexion que SI esta en la casilla esta intacta y sigue siendo ella.
     * \~ */
    check(s.conns.alive(second), "the connection in the slot was disturbed");
    const http_vx::ConnHot *hot = s.conns.hot(second);
    check(hot != nullptr && hot->fd == 9,
          "the connection in the slot lost its socket");
}

/**
 * @brief
 * \~english A partial write leaves the rest, and the rest is named.
 * \~spanish Una escritura parcial deja el resto, y el resto se nombra.
 * \~
 *
 * \~english
 * On a real socket a partial write is the ordinary case, and in a test it is
 * the case somebody forgets: a loop that assumed a send moved everything works
 * perfectly until the first response that does not fit in the kernel's send
 * buffer, which is every response that matters.
 *
 * The offset on an operation is what carries it on, and this is why it is
 * there rather than the buffer simply being consumed: the buffer is the
 * operating system's until the completion arrives, so nothing may move inside
 * it while a write is in flight.
 *
 * \~spanish
 * En un socket de verdad una escritura parcial es el caso corriente, y en una
 * prueba es el caso que se olvida: un bucle que diera por hecho que un envio
 * movio todo funciona perfectamente hasta la primera respuesta que no cabe en el
 * buffer de envio del nucleo, que son todas las que importan.
 *
 * El desplazamiento de una operacion es lo que la continua, y por eso esta ahi
 * en vez de consumir el buffer sin mas: el buffer es del sistema operativo hasta
 * que llegue la finalizacion, asi que nada se puede mover dentro mientras hay
 * una escritura en vuelo.
 *
 * \~
 */
void test_a_partial_write_names_what_is_left() {
    Shard s;

    const ConnHandle c = s.conns.open(3, 0);
    const uint32_t b = s.pool.acquire();
    check(c.valid() && b != kNoBuffer, "the shard would not hand anything out");

    Buffer *buf = s.pool.at(b);
    check(buf != nullptr, "the buffer is not there");

    const char *body = "HTTP/1.1 200 OK\r\n\r\nhello";
    const size_t n = std::strlen(body);
    uint8_t *room = buf->reserve(n);
    check(room != nullptr, "the buffer would not take the response");
    std::memcpy(room, body, n);
    buf->commit(n);

    /* \~english
     * The kernel takes ten bytes at a time, which is what a full send buffer
     * looks like from here.
     * \~spanish
     * El nucleo coge diez bytes cada vez, que es lo que parece desde aqui un
     * buffer de envio lleno.
     * \~ */
    s.io.chunk(10);

    size_t sent = 0;
    Completion done[8];

    while (sent < n) {
        Op op;
        op.conn = c;
        op.kind = OpKind::Send;
        op.buffer = b;
        op.offset = static_cast<uint32_t>(sent);
        op.length = static_cast<uint32_t>(n - sent);

        check(s.io.submit(op), "the write was not taken");
        check(s.io.wait(done, 8, 0) == 1, "the write did not finish");
        check(done[0].ok(), "the write failed");
        check(done[0].result > 0, "the write moved nothing");

        sent += static_cast<size_t>(done[0].result);
    }

    check(s.io.written_size() == n, "the whole response did not go out");
    check(std::memcmp(s.io.written(), body, n) == 0,
          "what went out is not the response");
}

/**
 * @brief
 * \~english A read that finds nothing after the peer closed is end of stream.
 * \~spanish Una lectura sin nada tras cerrar el otro extremo es fin de flujo.
 * \~
 *
 * \~english
 * Zero is not an error and not a short read, and a loop that took it for
 * either would spin forever or report a failure nobody caused.  It is the one
 * result whose meaning cannot be worked out from the number alone, which is
 * why @c eof asks the kind as well.
 *
 * \~spanish
 * El cero no es un error ni una lectura corta, y un bucle que lo tomara por
 * cualquiera de las dos cosas daria vueltas para siempre o informaria de un
 * fallo que no causo nadie.  Es el unico resultado cuyo significado no sale del
 * numero solo, que es la razon de que @c eof pregunte tambien la clase.
 *
 * \~
 */
void test_the_peer_closing_is_not_an_error() {
    Shard s;

    const ConnHandle c = s.conns.open(3, 0);
    const uint32_t b = s.pool.acquire();
    check(c.valid() && b != kNoBuffer, "the shard would not hand anything out");

    s.io.end_of_stream();

    Op op;
    op.conn = c;
    op.kind = OpKind::Recv;
    op.buffer = b;
    op.length = 4096;
    check(s.io.submit(op), "the read was not taken");

    Completion done[8];
    check(s.io.wait(done, 8, 0) == 1, "the read did not finish");
    check(done[0].ok(), "end of stream was reported as a failure");
    check(done[0].result == 0, "end of stream moved bytes");
    check(done[0].eof(), "end of stream does not say it is end of stream");

    /* \~english
     * And a write of nothing is not end of anything, which is what the kind
     * in the check is for.
     * \~spanish
     * Y una escritura de nada no es el fin de nada, que es para lo que esta la
     * clase en la comprobacion.
     * \~ */
    Completion w;
    w.kind = OpKind::Send;
    w.result = 0;
    check(!w.eof(), "a write of zero bytes says it is end of stream");
}

/**
 * @brief
 * \~english A failure is a negative result, and it moves nothing.
 * \~spanish Un fallo es un resultado negativo, y no mueve nada.
 * \~
 */
void test_a_failure_moves_nothing() {
    Shard s;

    const ConnHandle c = s.conns.open(3, 0);
    const uint32_t b = s.pool.acquire();
    check(c.valid() && b != kNoBuffer, "the shard would not hand anything out");

    const char *msg = "hello";
    check(s.io.feed(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg)),
          "the peer could not send");

    s.io.fail_next(1, -104);

    Op op;
    op.conn = c;
    op.kind = OpKind::Recv;
    op.buffer = b;
    op.length = 4096;
    check(s.io.submit(op), "the read was not taken");

    Completion done[8];
    check(s.io.wait(done, 8, 0) == 1, "the read did not finish");
    check(!done[0].ok(), "a failed read says it worked");
    check(done[0].result == -104, "the failure lost which one it was");
    check(!done[0].eof(), "a failed read says it is end of stream");

    Buffer *buf = s.pool.at(b);
    check(buf != nullptr && buf->empty(),
          "a failed read wrote into the buffer anyway");

    /* \~english
     * And the next one works, so the failure was the operation's and not the
     * connection's.
     * \~spanish
     * Y la siguiente funciona, asi que el fallo era de la operacion y no de la
     * conexion.
     * \~ */
    check(s.io.submit(op), "the second read was not taken");
    check(s.io.wait(done, 8, 0) == 1, "the second read did not finish");
    check(done[0].ok(), "the second read failed too");
}

/**
 * @brief
 * \~english A read with nothing to read does not hold up the writes behind it.
 * \~spanish Una lectura sin nada que leer no retiene a las escrituras de detras.
 * \~
 *
 * \~english
 * A kernel finishes whichever operation is ready, in whatever order they
 * become so.  A backend that worked strictly in order would deadlock a shard
 * whose response was queued behind an idle read -- against a peer that is
 * waiting for exactly that response.
 *
 * And it would deadlock ONLY against that backend, which is the worst possible
 * place for a difference: the loop would be correct everywhere except in the
 * place it is tested.
 *
 * \~spanish
 * Un nucleo acaba la operacion que este lista, en el orden en que lo esten.  Un
 * backend que fuera estrictamente en orden abrazaria a un fragmento cuya
 * respuesta estuviera encolada detras de una lectura parada -- contra un extremo
 * que espera justo esa respuesta.
 *
 * Y se abrazaria SOLO contra ese backend, que es el peor sitio posible para una
 * diferencia: el bucle seria correcto en todas partes menos donde se prueba.
 *
 * \~
 */
void test_an_idle_read_does_not_hold_up_a_write() {
    Shard s;

    const ConnHandle c = s.conns.open(3, 0);
    const uint32_t rb = s.pool.acquire();
    const uint32_t wb = s.pool.acquire();
    check(c.valid() && rb != kNoBuffer && wb != kNoBuffer,
          "the shard would not hand anything out");

    Buffer *out = s.pool.at(wb);
    const char *body = "answer";
    uint8_t *room = out->reserve(std::strlen(body));
    std::memcpy(room, body, std::strlen(body));
    out->commit(std::strlen(body));

    Op read;
    read.conn = c;
    read.kind = OpKind::Recv;
    read.buffer = rb;
    read.length = 4096;
    check(s.io.submit(read), "the read was not taken");

    Op write;
    write.conn = c;
    write.kind = OpKind::Send;
    write.buffer = wb;
    write.length = static_cast<uint32_t>(std::strlen(body));
    check(s.io.submit(write), "the write was not taken");

    Completion done[8];
    const size_t made = s.io.wait(done, 8, 0);

    check(made == 1, "the write did not finish while the read waited");
    check(made == 1 && done[0].kind == OpKind::Send,
          "the completion is not the write");
    check(s.io.pending() == 1, "the read stopped being outstanding");
    check(s.io.written_size() == std::strlen(body),
          "the response did not go out");
}

/// \~english A made-up address of @p len bytes, all @p fill.
/// \~spanish Una direccion inventada de @p len bytes, todos @p fill.  \~
http_vx::NetAddress made_up(uint8_t fill, uint8_t len) {
    http_vx::NetAddress a;
    std::memset(a.bytes, fill, len);
    a.len = len;
    return a;
}

/**
 * @brief
 * \~english A datagram comes back with who sent it and to where, not as a stream read.
 * \~spanish Un datagrama vuelve con quien lo mando y a donde, no como una lectura de flujo.
 * \~
 *
 * \~english
 * Before, a @c RecvFrom was served as a @c Recv: it read the stream's bytes
 * and no address came back at all.
 * \~spanish
 * Antes, un @c RecvFrom se servia como un @c Recv: leia los bytes del flujo y
 * no volvia ninguna direccion.
 * \~
 */
void test_a_datagram_comes_back_with_its_path() {
    Shard s;

    http_vx::DatagramPath path;
    path.peer = made_up(0xAA, 16);
    path.local = made_up(0xBB, 16);

    check(s.io.feed_datagram(path, reinterpret_cast<const uint8_t *>("ping"), 4,
                             http_vx::EcnMark::Ce),
          "the datagram would not fit");

    /* \~english
     * Stream bytes waiting at the same time must not be what a datagram
     * receive takes.
     * \~spanish
     * Unos bytes de flujo esperando a la vez no pueden ser lo que coge una
     * recepcion de datagramas.
     * \~ */
    check(s.io.feed(reinterpret_cast<const uint8_t *>("stream"), 6),
          "the stream bytes would not fit");

    const uint32_t b = s.pool.acquire();

    Op op;
    op.kind = OpKind::RecvFrom;
    op.buffer = b;
    op.length = 1500;
    check(s.io.submit(op), "the receive was not taken");

    Completion done[4];
    check(s.io.wait(done, 4, 0) == 1, "the receive did not finish");
    check(done[0].ok() && done[0].result == 4, "the datagram's size is wrong");

    Buffer *buf = s.pool.at(b);
    http_vx::DatagramHeader h;
    check(buf != nullptr && http_vx::datagram_header(*buf, h),
          "the datagram came back without its header");
    check(http_vx::same_net_address(h.path.peer, path.peer),
          "the peer's address did not come back");
    check(http_vx::same_net_address(h.path.local, path.local),
          "the local address did not come back");
    check(h.ecn == http_vx::EcnMark::Ce, "the ECN mark did not come back");
    check(buf != nullptr && http_vx::datagram_size(*buf) == 4 &&
              std::memcmp(http_vx::datagram_payload(*buf), "ping", 4) == 0,
          "the payload is not the datagram's");
}

/**
 * @brief
 * \~english An empty datagram is not the end of anything, and a cut one is not delivered.
 * \~spanish Un datagrama vacio no es el final de nada, y uno cortado no se entrega.
 * \~
 */
void test_empty_and_cut_datagrams() {
    Shard s;

    http_vx::DatagramPath path;
    path.peer = made_up(1, 16);

    uint8_t big[64];
    std::memset(big, 'x', sizeof big);

    check(s.io.feed_datagram(path, nullptr, 0), "the empty one would not fit");
    check(s.io.feed_datagram(path, big, sizeof big), "the big one would not fit");

    uint32_t bufs[2];
    for (int i = 0; i < 2; ++i) {
        bufs[i] = s.pool.acquire();
        Op op;
        op.kind = OpKind::RecvFrom;
        op.buffer = bufs[i];
        op.length = 16;
        check(s.io.submit(op), "a receive was not taken");
    }

    Completion done[4];
    check(s.io.wait(done, 4, 0) == 2, "the receives did not finish");

    check(done[0].ok() && done[0].result == 0, "the empty datagram failed");
    check(!done[0].eof(), "an empty datagram was taken for the end of a stream");

    check(!done[1].ok(), "a cut datagram was reported as a success");
    check(done[1].truncated(), "a cut datagram was not said to be cut");
    check(s.pool.at(bufs[1])->empty(), "a cut datagram was left in its buffer");
    check(s.io.datagrams().truncated == 1, "the cut was not counted");

    /* \~english
     * And the cut result means nothing on any other kind.
     * \~spanish
     * Y el resultado de corte no quiere decir nada en ninguna otra clase.
     * \~ */
    Completion other;
    other.kind = OpKind::Recv;
    other.result = http_vx::kTruncated;
    check(!other.truncated(), "a stream read was said to be a cut datagram");

    other.kind = OpKind::RecvFrom;
    other.result = -1;
    check(!other.truncated(), "a failed receive was said to be a cut datagram");

    /* \~english
     * A send whose length is not the datagram's is refused, not sent short
     * or long.
     * \~spanish
     * Un envio cuya longitud no es la del datagrama se rechaza, no se manda ni
     * corto ni largo.
     * \~ */
    Buffer *out = s.pool.at(bufs[0]);
    out->recycle();
    uint8_t *room = http_vx::datagram_reserve(*out, 16);
    std::memcpy(room, "12345", 5);
    http_vx::DatagramHeader h;
    h.path.peer = made_up(2, 16);
    http_vx::datagram_commit(*out, h, 5);

    Op send;
    send.kind = OpKind::SendTo;
    send.buffer = bufs[0];
    send.length = 4;
    check(s.io.submit(send), "the send was not taken");
    check(s.io.wait(done, 4, 0) == 1 && !done[0].ok(),
          "a send of the wrong length went out");
    check(s.io.datagrams_out() == 0 && s.io.datagrams().send_errors == 1,
          "the refused send was not counted");
}

/**
 * @brief
 * \~english The small rules a datagram buffer and an ECN byte are read by.
 * \~spanish Las reglas pequenas con las que se leen un buffer de datagrama y un byte ECN.
 * \~
 */
void test_the_datagram_helpers() {
    /* \~english
     * RFC 3168, 5: ECT(1) is 01 and ECT(0) is 10 -- the swap a pass-through
     * would get wrong -- and only the two low bits count.
     * \~spanish
     * RFC 3168, 5: ECT(1) es 01 y ECT(0) es 10 -- el cambio que se equivocaria
     * pasandolos tal cual -- y solo cuentan los dos bits bajos.
     * \~ */
    check(http_vx::ecn_from_tos(0x00) == http_vx::EcnMark::NotEct, "00 is not Not-ECT");
    check(http_vx::ecn_from_tos(0x01) == http_vx::EcnMark::Ect1, "01 is not ECT(1)");
    check(http_vx::ecn_from_tos(0x02) == http_vx::EcnMark::Ect0, "10 is not ECT(0)");
    check(http_vx::ecn_from_tos(0xB7) == http_vx::EcnMark::Ce, "11 is not CE");

    BufferPool pool;
    pool.reset(1, 1 << 20);
    Buffer *b = pool.at(pool.acquire());

    uint8_t *room = http_vx::datagram_reserve(*b, 32);
    check(room != nullptr, "an empty buffer had no room for a datagram");
    http_vx::DatagramHeader h;
    h.path.peer = made_up(7, 16);
    std::memcpy(room, "abc", 3);
    http_vx::datagram_commit(*b, h, 3);

    check(http_vx::datagram_size(*b) == 3, "the payload's size is wrong");
    check(http_vx::datagram_reserve(*b, 32) == nullptr,
          "a second datagram was put behind the first");

    http_vx::DatagramHeader back;
    check(http_vx::datagram_header(*b, back) &&
              http_vx::same_net_address(back.path.peer, h.path.peer),
          "the header did not come back");

    Buffer small;
    check(!http_vx::datagram_header(small, back),
          "a buffer with no datagram gave a header");

    check(!http_vx::same_net_address(made_up(7, 16), made_up(7, 28)),
          "addresses of two lengths were the same");
    check(!http_vx::same_net_address(made_up(7, 16), made_up(8, 16)),
          "two different addresses were the same");

    /* \~english
     * A closed socket is forgotten, and the one moved into its place is
     * still found.
     * \~spanish
     * Un socket cerrado se olvida, y el que se mueve a su sitio se sigue
     * encontrando.
     * \~ */
    http_vx::DatagramSockets set;
    check(set.add(5, made_up(1, 16)) && set.add(6, made_up(2, 28)), "sockets not added");
    set.remove(5);
    check(set.find(5) < 0, "a removed socket is still found");
    check(set.find(6) == 0 && set.bound(0).len == 28, "the other socket was lost");
    check(!set.add(-1, made_up(1, 16)), "a socket that is none was added");
}

} // namespace

/**
 * @brief
 * \~english A cancelled read comes back once, as a failure, with its buffer; a write beside it is left alone.
 * \~spanish Una lectura cancelada vuelve una vez, como fallo, con su buffer; una escritura al lado no se toca.
 * \~
 */
void test_a_cancelled_read_fails_and_nothing_else_does() {
    Shard s;
    const ConnHandle c = s.conns.open(3, 0);
    check(c.valid(), "a connection could not be opened");

    const uint32_t rb = s.pool.acquire();
    Op read;
    read.conn = c;
    read.kind = OpKind::Recv;
    read.buffer = rb;
    read.length = 4096;
    read.fd = 3;
    check(s.io.submit(read), "the read was not taken");

    const uint32_t wb = s.pool.acquire();
    Buffer *w = s.pool.at(wb);
    uint8_t *room = w->reserve(2);
    room[0] = 'o';
    room[1] = 'k';
    w->commit(2);
    Op write;
    write.conn = c;
    write.kind = OpKind::Send;
    write.buffer = wb;
    write.length = 2;
    write.fd = 3;
    check(s.io.submit(write), "the write was not taken");

    Op cancel;
    cancel.conn = c;
    cancel.kind = OpKind::Cancel;
    cancel.buffer = kNoBuffer;
    cancel.fd = 3;
    check(s.io.submit(cancel), "the cancel was refused");

    Completion done[8];
    const size_t n = s.io.wait(done, 8, 0);
    check(n == 2, "not exactly the read and the write came back");
    bool read_failed = false;
    bool write_ok = false;
    for (size_t i = 0; i < n; ++i) {
        if (done[i].kind == OpKind::Recv) read_failed = !done[i].ok() && done[i].buffer == rb;
        if (done[i].kind == OpKind::Send) write_ok = done[i].ok() && done[i].result == 2;
    }
    check(read_failed, "the cancelled read did not come back as a failure with its buffer");
    check(write_ok, "the write beside it did not go out");
    check(s.io.cancelled() == 1, "the cancel was not counted");

    // \~english Nothing outstanding: a cancel does nothing and produces nothing.
    // \~spanish Nada pendiente: una cancelacion no hace nada ni produce nada.  \~
    check(s.io.submit(cancel), "a cancel with nothing to cancel was refused");
    check(s.io.wait(done, 8, 0) == 0 && s.io.cancelled() == 1, "a cancel with nothing to cancel did something");
}

int main() {
    test_a_cancelled_read_fails_and_nothing_else_does();
    test_the_datagram_helpers();
    test_a_datagram_comes_back_with_its_path();
    test_empty_and_cut_datagrams();
    test_a_read_comes_back_with_the_bytes();
    test_a_completion_that_arrives_too_late();
    test_a_partial_write_names_what_is_left();
    test_the_peer_closing_is_not_an_error();
    test_a_failure_moves_nothing();
    test_an_idle_read_does_not_hold_up_a_write();

    if (failures != 0) {
        std::fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    std::printf("ok\n");
    return 0;
}
