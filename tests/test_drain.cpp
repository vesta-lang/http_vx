/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_drain.cpp
 * @brief
 * \~english Dropping bytes while a message is still arriving.
 * \~spanish Descartar bytes mientras el mensaje todavia esta llegando.
 * \~
 *
 * \~english
 * This is the seam between the buffer and the readers, and it belongs to
 * neither: the buffer does not know what a message is and a reader does not
 * own memory.  What is checked here is the thing that only shows up when they
 * are put together -- that a body of any size costs a buffer the size of one
 * piece of it.
 *
 * Without that, a reader that hands over a gigabyte in pieces still holds a
 * gigabyte, because the bytes behind the piece it just handed over cannot be
 * dropped while its own position counts from where they are.  The buffer would
 * grow to the whole message and the limit that bounds it would be the only
 * thing standing between one peer and the machine's memory.
 *
 * So the check is not that it works.  It is **how much memory it took**.
 *
 * \~spanish
 * Esta es la costura entre el buffer y los lectores, y no es de ninguno de los
 * dos: el buffer no sabe lo que es un mensaje y un lector no es dueno de
 * memoria.  Lo que se comprueba aqui es lo que solo aparece al juntarlos -- que
 * un cuerpo de cualquier tamano cueste un buffer del tamano de un pedazo de el.
 *
 * Sin eso, un lector que entregue un gigabyte a pedazos sigue teniendo un
 * gigabyte, porque los bytes de detras del pedazo que acaba de entregar no se
 * pueden descartar mientras su propia posicion cuente desde donde estan.  El
 * buffer creceria hasta el mensaje entero y el limite que lo acota seria lo
 * unico entre un solo extremo y la memoria de la maquina.
 *
 * Asi que lo que se comprueba no es que funcione.  Es **cuanta memoria costo**.
 *
 * \~
 */

#include "http_vx/buffer.h"
#include "http_vx/h1_chunked.h"
#include "http_vx/h2_reader.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Writes @p n bytes into @p b, as a read would.
 * \~spanish Escribe @p n bytes en @p b, como haria una lectura.
 * \~
 */
bool arrive(http_vx::Buffer &b, const void *p, size_t n) {
    uint8_t *room = b.reserve(n);
    if (room == nullptr) return false;
    std::memcpy(room, p, n);
    b.commit(n);
    return true;
}

/**
 * @brief
 * \~english A chunked body arriving in pieces, dropped as it is dealt with.
 * \~spanish Un cuerpo troceado que llega a pedazos, descartado segun se atiende.
 * \~
 *
 * \~english
 * The loop is what a connection does: bytes arrive, whatever can be read is
 * read, and whatever the reader has finished with goes.  How much to drop is
 * the difference between where the reader has finished and where the buffer
 * begins, and there is nothing to adjust afterwards -- which is the point.  A
 * step that had to be remembered would be a step that is forgotten, and
 * forgetting it would not fail here, it would read the body of one message as
 * the head of the next.
 *
 * \~spanish
 * El bucle es lo que hace una conexion: llegan bytes, se lee lo que se pueda, y
 * lo que el lector haya terminado se va.  Cuanto descartar es la diferencia
 * entre donde ha terminado el lector y donde empieza el buffer, y despues no
 * hay nada que ajustar -- que es de lo que se trata.  Un paso que hubiera que
 * recordar seria un paso que se olvida, y olvidarlo no fallaria aqui: leeria el
 * cuerpo de un mensaje como la cabeza del siguiente.
 *
 * \~
 */
void test_chunked_body_does_not_grow_the_buffer() {
    /* \~english
     * Two hundred chunks of a kilobyte: two hundred kilobytes of body, which
     * is fifty times the page the buffer starts with.
     * \~spanish
     * Doscientos trozos de un kilobyte: doscientos kilobytes de cuerpo, que son
     * cincuenta veces la pagina con la que empieza el buffer.
     * \~ */
    const size_t kChunks = 200;
    const size_t kChunkBytes = 1024;

    uint8_t payload[kChunkBytes];
    for (size_t i = 0; i < kChunkBytes; ++i)
        payload[i] = static_cast<uint8_t>(i);

    http_vx::Buffer buf;
    http_vx::h1::Limits limits;
    limits.max_body_bytes = kChunks * kChunkBytes;

    http_vx::h1::ChunkedReader reader(limits);
    reader.reset(0);
    http_vx::Fields trailers;

    uint64_t delivered = 0;
    bool done = false;

    for (size_t i = 0; i < kChunks && !done; ++i) {
        char head[32];
        const int n = std::snprintf(head, sizeof(head), "%x\r\n",
                                    static_cast<unsigned>(kChunkBytes));
        check(n > 0, "the test could not write a chunk header");
        if (n <= 0) return;

        check(arrive(buf, head, static_cast<size_t>(n)), "no room for a header");
        check(arrive(buf, payload, kChunkBytes), "no room for a chunk");
        check(arrive(buf, "\r\n", 2), "no room for a chunk ending");

        for (;;) {
            const http_vx::h1::ChunkResult res =
                reader.read(buf.view(), trailers);

            if (res == http_vx::h1::ChunkResult::Data) {
                const http_vx::Span s = reader.chunk();
                check(s.len <= buf.size(), "a piece names bytes that are not here");
                delivered += s.len;
                continue;
            }
            if (res == http_vx::h1::ChunkResult::Done) done = true;
            break;
        }

        /* \~english
         * And what the reader has finished with goes.  One subtraction, no
         * adjustment, nothing to remember.
         * \~spanish
         * Y lo que el lector ha terminado se va.  Una resta, ningun ajuste,
         * nada que recordar.
         * \~ */
        buf.consume(static_cast<size_t>(reader.consumed() - buf.origin()));
    }

    check(!done, "the body ended before it was sent");

    /* \~english The last chunk, and the trailers.
     * \~spanish El ultimo trozo, y los remolques.  \~ */
    check(arrive(buf, "0\r\nX-Sum: abc\r\n\r\n", 17), "no room for the end");

    for (;;) {
        const http_vx::h1::ChunkResult res = reader.read(buf.view(), trailers);
        if (res == http_vx::h1::ChunkResult::Data) {
            delivered += reader.chunk().len;
            continue;
        }
        check(res == http_vx::h1::ChunkResult::Done, "the body did not finish");
        break;
    }

    check(delivered == kChunks * kChunkBytes, "not all of the body arrived");
    check(reader.body_bytes() == delivered, "the reader counted something else");
    check(trailers.size() == 1, "the trailer was lost");

    /* \~english
     * THIS is the check.  Two hundred kilobytes went through a buffer that
     * never held more than a chunk and its framing, so what it asked the
     * allocator for stayed within a few pages.  Without the drain it would
     * have been the whole two hundred.
     *
     * \~spanish
     * ESTA es la comprobacion.  Pasaron doscientos kilobytes por un buffer que
     * nunca tuvo mas de un trozo y su troceado, asi que lo que le pidio al
     * asignador se quedo en unas pocas paginas.  Sin el drenaje habrian sido
     * los doscientos enteros.
     * \~ */
    check(buf.capacity() <= 4 * kChunkBytes,
          "the buffer grew to hold the whole body instead of one piece of it");

    /* \~english
     * And the connection's position went with it: the origin counts what was
     * dropped, so it and the reader agree about where the stream is.
     * \~spanish
     * Y la posicion de la conexion fue con el: el origen cuenta lo descartado,
     * asi que el y el lector coinciden en donde esta el flujo.
     * \~ */
    check(buf.origin() + buf.size() == reader.position(),
          "the buffer and the reader disagree about where the stream is");
}

/**
 * @brief
 * \~english The same thing for HTTP/2, one frame at a time.
 * \~spanish Lo mismo para HTTP/2, trama a trama.
 * \~
 */
void test_frames_do_not_grow_the_buffer() {
    const size_t kFrames = 200;
    const size_t kPayload = 1024;

    uint8_t payload[kPayload];
    for (size_t i = 0; i < kPayload; ++i) payload[i] = static_cast<uint8_t>(i);

    http_vx::Buffer buf;
    http_vx::h2::FrameReader reader;
    reader.reset(0, true);

    check(arrive(buf, http_vx::h2::kClientPreface, 24), "no room for the preface");

    uint64_t delivered = 0;
    size_t frames = 0;

    for (size_t i = 0; i < kFrames; ++i) {
        http_vx::h2::FrameHeader h{};
        h.length = static_cast<uint32_t>(kPayload);
        h.type = static_cast<uint8_t>(http_vx::h2::FrameType::Data);
        h.stream_id = 1;

        uint8_t head[http_vx::h2::kFrameHeaderSize];
        http_vx::h2::encode_frame_header(head, h);

        check(arrive(buf, head, sizeof(head)), "no room for a frame header");
        check(arrive(buf, payload, kPayload), "no room for a frame payload");

        for (;;) {
            const http_vx::h2::ReadResult res = reader.read(buf.view());
            if (res == http_vx::h2::ReadResult::Frame) {
                delivered += reader.payload().len;
                ++frames;
                continue;
            }
            check(res == http_vx::h2::ReadResult::NeedMore,
                  "the connection was refused");
            break;
        }

        buf.consume(static_cast<size_t>(reader.consumed() - buf.origin()));
    }

    check(frames == kFrames, "not every frame arrived");
    check(delivered == kFrames * kPayload, "not all of the payload arrived");
    check(buf.capacity() <= 4 * kPayload,
          "the buffer grew to hold every frame instead of one at a time");
    check(buf.empty(), "something was left after everything was read");
}

/**
 * @brief
 * \~english A piece that arrives split still comes out whole across a drain.
 * \~spanish Un pedazo que llega partido sigue saliendo entero tras un drenaje.
 * \~
 *
 * \~english
 * The hard case for a position that counts from the connection: bytes are
 * dropped BETWEEN two reads of the same chunk.  The reader's position survives
 * because it never counted from the buffer, and the piece comes back in two
 * halves that add up.
 *
 * \~spanish
 * El caso dificil para una posicion que cuenta desde la conexion: se descartan
 * bytes ENTRE dos lecturas del mismo trozo.  La posicion del lector sobrevive
 * porque nunca conto desde el buffer, y el pedazo vuelve en dos mitades que
 * suman.
 *
 * \~
 */
void test_drain_in_the_middle_of_a_chunk() {
    http_vx::Buffer buf;
    http_vx::h1::ChunkedReader reader;
    reader.reset(0);
    http_vx::Fields trailers;

    uint8_t body[64];
    for (size_t i = 0; i < sizeof(body); ++i) body[i] = static_cast<uint8_t>(i);

    check(arrive(buf, "40\r\n", 4), "no room for the header");
    check(arrive(buf, body, 20), "no room for the first half");

    uint64_t delivered = 0;
    for (;;) {
        const http_vx::h1::ChunkResult res = reader.read(buf.view(), trailers);
        if (res == http_vx::h1::ChunkResult::Data) {
            delivered += reader.chunk().len;
            continue;
        }
        break;
    }
    check(delivered == 20, "the first half did not come out");

    /* \~english
     * Drop it all, in the middle of a chunk whose data has not finished
     * arriving.  The reader is left with nothing in front of it and a position
     * that still means what it meant.
     * \~spanish
     * Descartarlo todo, en mitad de un trozo cuyos datos no han terminado de
     * llegar.  El lector se queda sin nada delante y con una posicion que sigue
     * significando lo que significaba.
     * \~ */
    buf.consume(static_cast<size_t>(reader.consumed() - buf.origin()));
    check(buf.empty(), "something was left that the reader had finished with");
    check(buf.origin() == 24, "the origin is not where the reading stopped");

    check(arrive(buf, body + 20, 44), "no room for the second half");
    check(arrive(buf, "\r\n0\r\n\r\n", 7), "no room for the end");

    for (;;) {
        const http_vx::h1::ChunkResult res = reader.read(buf.view(), trailers);
        if (res == http_vx::h1::ChunkResult::Data) {
            const http_vx::Span s = reader.chunk();
            check(std::memcmp(buf.data() + s.off, body + delivered, s.len) == 0,
                  "the second half is not the bytes that were sent");
            delivered += s.len;
            continue;
        }
        check(res == http_vx::h1::ChunkResult::Done,
              "the body did not finish after the drain");
        break;
    }

    check(delivered == 64, "the two halves do not add up to the chunk");
    check(reader.body_bytes() == 64, "the reader counted something else");
}

} // namespace

int main() {
    test_chunked_body_does_not_grow_the_buffer();
    test_frames_do_not_grow_the_buffer();
    test_drain_in_the_middle_of_a_chunk();

    if (failures != 0) {
        std::fprintf(stderr, "test_drain: %d failures\n", failures);
        return 1;
    }
    std::printf("test_drain: ok\n");
    return 0;
}
