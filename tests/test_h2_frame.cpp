/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_frame.cpp
 * @brief
 * \~english The frames: nine bytes, the rules they obey, and reading them.
 * \~spanish Las tramas: nueve bytes, las reglas que cumplen, y leerlas.
 * \~
 *
 * \~english
 * A binary format fails differently from a text one, and the tests follow.
 * There is no ambiguity about where a frame ends, so there is nothing here
 * about two readers disagreeing.  What replaces it is arithmetic, and
 * arithmetic fails at its edges: a padding length exactly equal to what is
 * left, one byte more, a frame of exactly the size limit, one byte over.
 * Those are the cases.
 *
 * \~spanish
 * Un formato binario falla de otra forma que uno de texto, y las pruebas van
 * detras.  No hay ambiguedad sobre donde acaba una trama, asi que aqui no hay
 * nada de dos lectores discrepando.  Lo que la sustituye es aritmetica, y la
 * aritmetica falla en sus extremos: un relleno exactamente igual a lo que
 * queda, un byte mas, una trama de exactamente el limite, un byte por encima.
 * Esos son los casos.
 *
 * \~
 */

#include "http_vx/h2_reader.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::ErrorCode;
using http_vx::h2::FrameHeader;
using http_vx::h2::FrameReader;
using http_vx::h2::FrameType;
using http_vx::h2::ReadResult;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english A connection being built, byte by byte.
 * \~spanish Una conexion en construccion, byte a byte.
 * \~
 */
struct Wire {
    uint8_t bytes[4096];
    size_t used = 0;

    void raw(const void *p, size_t n) {
        if (used + n > sizeof(bytes)) return;
        std::memcpy(bytes + used, p, n);
        used += n;
    }

    void preface() { raw(http_vx::h2::kClientPreface, 24); }

    void frame(FrameType type, uint8_t flags, uint32_t stream,
               const void *payload, size_t len) {
        FrameHeader h{};
        h.length = static_cast<uint32_t>(len);
        h.type = static_cast<uint8_t>(type);
        h.flags = flags;
        h.stream_id = stream;

        uint8_t head[http_vx::h2::kFrameHeaderSize];
        http_vx::h2::encode_frame_header(head, h);
        raw(head, sizeof(head));
        raw(payload, len);
    }

    void empty(FrameType type, uint8_t flags, uint32_t stream) {
        frame(type, flags, stream, nullptr, 0);
    }
};

/**
 * @brief
 * \~english Reads @p w to the end and says how it went.
 * \~spanish Lee @p w hasta el final y dice como fue.
 * \~
 */
struct Reading {
    ReadResult result;
    ErrorCode error;
    int frames;
    size_t consumed;
};

Reading run(const Wire &w, const http_vx::h2::Limits &limits, bool preface,
            size_t step = 0) {
    FrameReader r(limits);
    r.reset(0, preface);

    Reading out{};
    size_t given = step == 0 ? w.used : 0;

    for (;;) {
        const ReadResult res = r.read(http_vx::View{w.bytes, given, 0});

        if (res == ReadResult::Frame) {
            ++out.frames;
            continue;
        }
        if (res == ReadResult::NeedMore) {
            if (given == w.used) {
                out.result = res;
                break;
            }
            given += step == 0 ? w.used : step;
            if (given > w.used) given = w.used;
            continue;
        }
        out.result = res;
        break;
    }

    out.error = r.error();
    out.consumed = static_cast<size_t>(r.consumed());
    return out;
}

/**
 * @brief
 * \~english The nine bytes, out and back.
 * \~spanish Los nueve bytes, de ida y de vuelta.
 * \~
 */
void test_header_round_trip() {
    FrameHeader out{};
    out.length = 0x123456;
    out.type = static_cast<uint8_t>(FrameType::Headers);
    out.flags = http_vx::h2::kEndHeaders | http_vx::h2::kEndStream;
    out.stream_id = 0x7FFFFFFF;

    uint8_t bytes[http_vx::h2::kFrameHeaderSize];
    http_vx::h2::encode_frame_header(bytes, out);

    FrameHeader back{};
    http_vx::h2::decode_frame_header(bytes, back);

    check(back.length == out.length, "the length did not survive the trip");
    check(back.type == out.type, "the type did not survive the trip");
    check(back.flags == out.flags, "the flags did not survive the trip");
    check(back.stream_id == out.stream_id, "the stream did not survive the trip");

    /* \~english
     * Big-endian, and written out so the bytes are checked and not only the
     * numbers.  A pair of functions that agreed with each other and not with
     * the wire would pass a round trip and fail against everything else.
     * \~spanish
     * Big-endian, y escrito para que se comprueben los bytes y no solo los
     * numeros.  Un par de funciones de acuerdo entre ellas y no con el cable
     * pasaria un viaje de ida y vuelta y fallaria contra todo lo demas.
     * \~ */
    check(bytes[0] == 0x12 && bytes[1] == 0x34 && bytes[2] == 0x56,
          "the length is not big-endian");
    check(bytes[3] == 0x01, "the type is not where it should be");
    check(bytes[4] == 0x05, "the flags are not where they should be");
}

/**
 * @brief
 * \~english The reserved bit is ignored, and never written.
 * \~spanish El bit reservado se ignora, y no se escribe nunca.
 * \~
 *
 * \~english
 * Left in, a stream identifier is two thousand million larger than the one the
 * peer meant.  Refusing it instead would refuse a message that a later version
 * of the protocol makes legal, which is what the bit is reserved for.
 *
 * \~spanish
 * Si se deja, un identificador de flujo es dos mil millones mayor que el que
 * queria decir el otro extremo.  Rechazarlo en vez de eso rechazaria un mensaje
 * que una version posterior del protocolo hace legal, que es para lo que el bit
 * esta reservado.
 *
 * \~
 */
void test_reserved_bit() {
    uint8_t bytes[http_vx::h2::kFrameHeaderSize] = {0, 0, 0, 0, 0,
                                                    0x80, 0, 0, 1};
    FrameHeader h{};
    http_vx::h2::decode_frame_header(bytes, h);
    check(h.stream_id == 1, "the reserved bit was read as part of the stream");

    FrameHeader out{};
    out.stream_id = 0x80000001u;
    uint8_t written[http_vx::h2::kFrameHeaderSize];
    http_vx::h2::encode_frame_header(written, out);
    check((written[5] & 0x80) == 0, "the reserved bit was written set");
}

/**
 * @brief
 * \~english Where a frame may live, and how big it may be.
 * \~spanish Donde puede vivir una trama, y cuanto puede medir.
 * \~
 */
void test_validation() {
    const http_vx::h2::Limits limits;

    FrameHeader h{};
    h.type = static_cast<uint8_t>(FrameType::Settings);
    h.length = 0;
    h.stream_id = 0;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "a settings frame on the connection was refused");

    h.stream_id = 1;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::ProtocolError,
          "a settings frame on a stream was accepted");

    h.type = static_cast<uint8_t>(FrameType::Data);
    h.stream_id = 0;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::ProtocolError,
          "a data frame on the connection was accepted");

    /* \~english
     * The frames whose size IS their meaning.  A RST_STREAM of three bytes is
     * a frame whose error code would have to be read from where it is not.
     * \~spanish
     * Las tramas cuyo tamano ES su significado.  Una RST_STREAM de tres bytes
     * es una trama cuyo codigo de error habria que leer de donde no esta.
     * \~ */
    h.type = static_cast<uint8_t>(FrameType::RstStream);
    h.stream_id = 1;
    h.length = 4;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "a four-byte reset was refused");
    h.length = 3;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "a three-byte reset was accepted");
    h.length = 5;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "a five-byte reset was accepted");

    h.type = static_cast<uint8_t>(FrameType::Ping);
    h.stream_id = 0;
    h.length = 8;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "an eight-byte ping was refused");
    h.length = 9;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "a nine-byte ping was accepted");

    /* \~english Settings are pairs; a partial pair is not a setting.
     * \~spanish Los ajustes son parejas; media pareja no es un ajuste.  \~ */
    h.type = static_cast<uint8_t>(FrameType::Settings);
    h.length = 12;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "two settings were refused");
    h.length = 13;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "two settings and a byte were accepted");

    /* \~english An acknowledgement that carries something is not one.
     * \~spanish Un acuse de recibo que lleva algo no lo es.  \~ */
    h.length = 6;
    h.flags = http_vx::h2::kAck;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "an acknowledgement with a payload was accepted");
    h.length = 0;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "an empty acknowledgement was refused");

    /* \~english
     * The size limit, at it and one over.  Those are the two values an
     * off-by-one gets wrong, in opposite directions.
     * \~spanish
     * El limite de tamano, en el y uno por encima.  Son los dos valores que
     * yerra un desplazamiento de uno, en sentidos opuestos.
     * \~ */
    h.type = static_cast<uint8_t>(FrameType::Data);
    h.flags = 0;
    h.stream_id = 1;
    h.length = limits.max_frame_size;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "a frame of exactly the limit was refused");
    h.length = limits.max_frame_size + 1;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::FrameSizeError,
          "a frame one byte over the limit was accepted");
}

/**
 * @brief
 * \~english A type nobody defined passes, because the future has to.
 * \~spanish Un tipo que nadie definio pasa, porque el futuro tiene que pasar.
 * \~
 *
 * \~english
 * This is the one place in this codec where being strict would be wrong.  The
 * rule that a recipient ignores what it does not know is how the protocol gets
 * extended, and a server that refused would be refusing everything added after
 * it was written.
 *
 * \~spanish
 * Este es el unico sitio de este codec donde ser estricto estaria mal.  La
 * regla de que quien recibe ignora lo que no conoce es como se extiende el
 * protocolo, y un servidor que rechazara estaria rechazando todo lo que se
 * anadiera despues de escribirlo.
 *
 * \~
 */
void test_unknown_type_is_ignored() {
    const http_vx::h2::Limits limits;

    FrameHeader h{};
    h.type = 0x63;
    h.length = 100;
    h.stream_id = 0;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "an unknown type on the connection was refused");
    h.stream_id = 7;
    check(http_vx::h2::validate_frame(h, limits) == ErrorCode::NoError,
          "an unknown type on a stream was refused");

    check(std::strcmp(http_vx::h2::frame_type_name(0x63), "UNKNOWN") == 0,
          "an unknown type has a name");
    check(std::strcmp(http_vx::h2::frame_type_name(0), "DATA") == 0,
          "DATA is not called DATA");

    /* \~english
     * And the reader discards it rather than handing it over: two frames go
     * in, one of them unknown, and one comes out.
     * \~spanish
     * Y el lector la descarta en vez de entregarla: entran dos tramas, una de
     * ellas desconocida, y sale una.
     * \~ */
    Wire w;
    w.preface();
    const uint8_t junk[16] = {0};
    w.frame(static_cast<FrameType>(0x63), 0xFF, 3, junk, sizeof(junk));
    w.frame(FrameType::Ping, 0, 0, "12345678", 8);

    const Reading r = run(w, limits, true);
    check(r.result == ReadResult::NeedMore, "the connection was refused");
    check(r.frames == 1, "an unknown frame was handed over instead of discarded");
    check(r.consumed == w.used, "the unknown frame was not skipped over");
}

/**
 * @brief
 * \~english The preface, and what a connection that is not HTTP/2 gets.
 * \~spanish El preambulo, y lo que recibe una conexion que no es HTTP/2.
 * \~
 */
void test_preface() {
    const http_vx::h2::Limits limits;

    {
        Wire w;
        w.preface();
        w.empty(FrameType::Settings, 0, 0);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::NeedMore, "a good preface was refused");
        check(r.frames == 1, "the frame after the preface was not read");
    }
    {
        /* \~english
         * A connection that is not HTTP/2 is refused from its first wrong
         * byte, not after twenty-four of them.  Those bytes may be an HTTP/1.1
         * request another part of this server could have answered.
         * \~spanish
         * Una conexion que no es HTTP/2 se rechaza desde su primer byte
         * equivocado, no despues de veinticuatro.  Esos bytes pueden ser una
         * peticion de HTTP/1.1 que otra parte de este servidor si podria haber
         * contestado.
         * \~ */
        Wire w;
        w.raw("GET / HTTP/1.1\r\n", 16);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error, "an HTTP/1.1 request was accepted");
        check(r.error == ErrorCode::ProtocolError,
              "it was refused for the wrong reason");
    }
    {
        /* \~english
         * And half a preface is not an error yet: it is a preface that has not
         * finished arriving.
         * \~spanish
         * Y medio preambulo todavia no es un error: es un preambulo que no ha
         * terminado de llegar.
         * \~ */
        Wire w;
        w.raw(http_vx::h2::kClientPreface, 10);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::NeedMore, "half a preface was refused");
    }
}

/**
 * @brief
 * \~english Padding, at its edges.
 * \~spanish El relleno, en sus extremos.
 * \~
 *
 * \~english
 * This is where a frame gets read past its end.  A padding length larger than
 * what is left produces a remainder that would be negative, and a negative
 * length treated as unsigned is enormous -- which is a read of the rest of the
 * process's memory, reported as a payload.
 *
 * \~spanish
 * Aqui es por donde se lee una trama pasado su final.  Una longitud de relleno
 * mayor que lo que queda produce un resto que seria negativo, y una longitud
 * negativa tratada como sin signo es enorme -- que es una lectura del resto de
 * la memoria del proceso, informada como una carga.
 *
 * \~
 */
void test_padding() {
    const http_vx::h2::Limits limits;

    {
        /* \~english Two bytes of padding around three of data.
         * \~spanish Dos bytes de relleno alrededor de tres de datos.  \~ */
        Wire w;
        w.preface();
        const uint8_t body[] = {2, 'a', 'b', 'c', 0, 0};
        w.frame(FrameType::Data, http_vx::h2::kPadded, 1, body, sizeof(body));

        FrameReader r(limits);
        r.reset(0, true);
        check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Frame, "a padded frame was refused");
        check(r.payload().len == 3, "the padding was counted as payload");
        check(std::memcmp(w.bytes + r.payload().off, "abc", 3) == 0,
              "the payload is not what was padded");
    }
    {
        /* \~english
         * A frame that is all padding.  It says nothing, which a sender is
         * allowed to say, so it is legal -- and it is the edge one byte below
         * the one that is not.
         * \~spanish
         * Una trama que es toda relleno.  No dice nada, que es algo que quien
         * envia puede decir, asi que es legal -- y es el extremo un byte por
         * debajo del que no lo es.
         * \~ */
        Wire w;
        w.preface();
        const uint8_t body[] = {3, 0, 0, 0};
        w.frame(FrameType::Data, http_vx::h2::kPadded, 1, body, sizeof(body));

        FrameReader r(limits);
        r.reset(0, true);
        check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Frame,
              "a frame that is all padding was refused");
        check(r.payload().len == 0, "a frame that is all padding has a payload");
    }
    {
        /* \~english One byte more.  \~spanish Un byte mas.  \~ */
        Wire w;
        w.preface();
        const uint8_t body[] = {4, 0, 0, 0};
        w.frame(FrameType::Data, http_vx::h2::kPadded, 1, body, sizeof(body));

        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a padding longer than its frame was accepted");
        check(r.error == ErrorCode::ProtocolError,
              "it was refused for the wrong reason");
    }
    {
        /* \~english
         * And a padded frame with no room for the length byte itself.
         * \~spanish
         * Y una trama con relleno sin sitio ni para el byte de la longitud.
         * \~ */
        Wire w;
        w.preface();
        w.empty(FrameType::Data, http_vx::h2::kPadded, 1);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a padded frame with nothing in it was accepted");
    }
    {
        /* \~english
         * HEADERS with both padding and the deprecated priority: one byte of
         * pad length, five of priority, then the block.
         * \~spanish
         * HEADERS con relleno y con la prioridad retirada: un byte de longitud
         * de relleno, cinco de prioridad, y despues el bloque.
         * \~ */
        Wire w;
        w.preface();
        const uint8_t body[] = {1, 0, 0, 0, 1, 16, 'x', 'y', 0};
        w.frame(FrameType::Headers,
                http_vx::h2::kPadded | http_vx::h2::kPriority |
                    http_vx::h2::kEndHeaders,
                1, body, sizeof(body));

        FrameReader r(limits);
        r.reset(0, true);
        check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Frame,
              "a padded HEADERS with priority was refused");
        check(r.payload().len == 2, "the priority bytes were counted as block");
        check(std::memcmp(w.bytes + r.payload().off, "xy", 2) == 0,
              "the block is not what was between the padding");
    }
    {
        /* \~english
         * And one that claims priority without room for it.
         * \~spanish
         * Y una que dice llevar prioridad sin sitio para ella.
         * \~ */
        Wire w;
        w.preface();
        const uint8_t body[] = {0, 0, 0};
        w.frame(FrameType::Headers,
                http_vx::h2::kPriority | http_vx::h2::kEndHeaders, 1, body,
                sizeof(body));
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a HEADERS too short for its priority was accepted");
    }
}

/**
 * @brief
 * \~english A header block is finished before anything else happens.
 * \~spanish Un bloque de cabeceras se termina antes de que pase otra cosa.
 * \~
 *
 * \~english
 * The rule is that strict because a header block is compressed against a table
 * both ends update as they read it.  A frame that arrived in the middle would
 * be decompressed against a table in a state neither end agreed on, and from
 * there the two ends disagree about every header that follows.
 *
 * \~spanish
 * La regla es asi de estricta porque un bloque de cabeceras va comprimido
 * contra una tabla que los dos extremos actualizan segun la leen.  Una trama
 * que llegara en medio se descomprimiria contra una tabla en un estado en el
 * que no quedo ninguno, y a partir de ahi los dos discrepan sobre todas las
 * cabeceras que sigan.
 *
 * \~
 */
void test_continuation_sequencing() {
    const http_vx::h2::Limits limits;

    {
        Wire w;
        w.preface();
        w.frame(FrameType::Headers, 0, 1, "ab", 2);
        w.frame(FrameType::Continuation, 0, 1, "cd", 2);
        w.frame(FrameType::Continuation, http_vx::h2::kEndHeaders, 1, "ef", 2);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::NeedMore, "a split header block was refused");
        check(r.frames == 3, "not every piece of the block was handed over");
    }
    {
        /* \~english A PING in the middle.  \~spanish Un PING en medio.  \~ */
        Wire w;
        w.preface();
        w.frame(FrameType::Headers, 0, 1, "ab", 2);
        w.frame(FrameType::Ping, 0, 0, "12345678", 8);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a frame arrived in the middle of a header block");
        check(r.error == ErrorCode::ProtocolError,
              "it was refused for the wrong reason");
    }
    {
        /* \~english
         * A CONTINUATION of somebody else's block, which is the same mistake
         * wearing the right frame type.
         * \~spanish
         * Una CONTINUATION del bloque de otro, que es la misma equivocacion
         * vestida con el tipo de trama correcto.
         * \~ */
        Wire w;
        w.preface();
        w.frame(FrameType::Headers, 0, 1, "ab", 2);
        w.frame(FrameType::Continuation, http_vx::h2::kEndHeaders, 3, "cd", 2);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a continuation of another stream was accepted");
    }
    {
        /* \~english
         * And one with nothing to continue: a block fragment that would be
         * decompressed against a table this end never opened.
         * \~spanish
         * Y una sin nada que continuar: un fragmento de bloque que se
         * descomprimiria contra una tabla que este extremo no abrio nunca.
         * \~ */
        Wire w;
        w.preface();
        w.frame(FrameType::Continuation, http_vx::h2::kEndHeaders, 1, "cd", 2);
        const Reading r = run(w, limits, true);
        check(r.result == ReadResult::Error,
              "a continuation with nothing to continue was accepted");
    }
}

/**
 * @brief
 * \~english The flood: frames that are legal, endless, and empty.
 * \~spanish La riada: tramas legales, infinitas y vacias.
 * \~
 *
 * \~english
 * Each frame here is correct on its own, and none of them ends the block.  The
 * byte limit never fires because the frames carry no bytes; what stops it is
 * counting them, and that is why there are two limits and not one.
 *
 * \~spanish
 * Cada trama de aqui es correcta por su cuenta, y ninguna termina el bloque.
 * El limite de bytes no salta nunca porque las tramas no llevan bytes; lo que
 * lo para es contarlas, y por eso hay dos limites y no uno.
 *
 * \~
 */
void test_continuation_flood() {
    http_vx::h2::Limits limits;
    limits.max_continuation_frames = 4;

    Wire w;
    w.preface();
    w.frame(FrameType::Headers, 0, 1, "a", 1);
    for (int i = 0; i < 10; ++i) w.empty(FrameType::Continuation, 0, 1);

    const Reading r = run(w, limits, true);
    check(r.result == ReadResult::Error, "an endless header block was accepted");
    check(r.error == ErrorCode::EnhanceYourCalm,
          "a flood was refused as if it were malformed rather than too much");
    check(r.frames == 1 + 4,
          "it stopped at a different number of frames than the limit");

    /* \~english
     * And the byte limit, which catches the other shape of the same attack:
     * frames that are not empty and still never end.
     * \~spanish
     * Y el limite de bytes, que pilla la otra forma del mismo ataque: tramas
     * que no van vacias y que tampoco terminan nunca.
     * \~ */
    http_vx::h2::Limits tight;
    tight.max_header_block_bytes = 8;

    Wire big;
    big.preface();
    big.frame(FrameType::Headers, 0, 1, "aaaaaa", 6);
    big.frame(FrameType::Continuation, 0, 1, "bbbbbb", 6);

    const Reading rb = run(big, tight, true);
    check(rb.result == ReadResult::Error, "an oversized header block was accepted");
    check(rb.error == ErrorCode::EnhanceYourCalm,
          "an oversized header block was refused for the wrong reason");
}

/**
 * @brief
 * \~english Arriving a byte at a time changes nothing.
 * \~spanish Llegar byte a byte no cambia nada.
 * \~
 */
void test_dripping() {
    const http_vx::h2::Limits limits;

    Wire w;
    w.preface();
    w.empty(FrameType::Settings, 0, 0);
    w.frame(FrameType::Headers, http_vx::h2::kEndHeaders, 1, "abcd", 4);
    w.frame(FrameType::Data, http_vx::h2::kEndStream, 1, "hello", 5);

    const Reading whole = run(w, limits, true);
    const Reading drip = run(w, limits, true, 1);

    check(whole.frames == 3, "not every frame was read");
    check(drip.frames == whole.frames,
          "a different number of frames arrived a byte at a time");
    check(drip.consumed == whole.consumed,
          "a different amount was consumed a byte at a time");
    check(drip.result == whole.result && drip.error == whole.error,
          "the answer changed when the frames arrived in pieces");
}

/**
 * @brief
 * \~english Half a frame does not move the boundary.
 * \~spanish Media trama no mueve la frontera.
 * \~
 *
 * \~english
 * Found by the property harness, not by anybody thinking of it.  The reader
 * understands a frame's header as soon as it arrives -- it has to, to know how
 * long the payload will be -- so for a moment it has read nine bytes it has
 * not finished with.  Reporting those as consumed would tell a caller to
 * discard a header whose payload has not arrived, and the next read would take
 * that payload for the header of a frame that does not exist.
 *
 * Which is why what @c consumed reports is where the last whole frame ended
 * and not how far the reader has looked.
 *
 * \~spanish
 * Lo encontro el arnes de propiedades, no alguien pensandolo.  El lector
 * entiende la cabecera de una trama en cuanto llega -- tiene que hacerlo, para
 * saber cuanto va a medir la carga -- asi que por un momento ha leido nueve
 * bytes con los que no ha terminado.  Informarlos como consumidos le diria a
 * quien llama que descarte una cabecera cuya carga no ha llegado, y la lectura
 * siguiente tomaria esa carga por la cabecera de una trama que no existe.
 *
 * Por eso lo que informa @c consumed es donde acabo la ultima trama entera y no
 * hasta donde ha mirado el lector.
 *
 * \~
 */
void test_boundary_stays_put() {
    const http_vx::h2::Limits limits;

    Wire w;
    w.preface();
    w.frame(FrameType::Ping, 0, 0, "12345678", 8);
    w.frame(FrameType::Data, 0, 1, "hello", 5);

    const size_t after_ping = 24 + http_vx::h2::kFrameHeaderSize + 8;

    FrameReader r(limits);
    r.reset(0, true);

    check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Frame, "the ping was not read");
    check(r.consumed() == after_ping, "the boundary is not after the ping");

    /* \~english
     * Now the header of the second frame and two bytes of its payload: the
     * reader has understood the header and cannot finish the frame.
     * \~spanish
     * Ahora la cabecera de la segunda trama y dos bytes de su carga: el lector
     * ha entendido la cabecera y no puede terminar la trama.
     * \~ */
    const size_t partial = after_ping + http_vx::h2::kFrameHeaderSize + 2;
    check(r.read(http_vx::View{w.bytes, partial, 0}) == ReadResult::NeedMore,
          "half a frame was handed over");
    check(r.consumed() == after_ping,
          "the boundary moved into a frame that had not arrived");

    /* \~english
     * And the rest of it finishes the frame without the header being read
     * again from the buffer -- it was understood once and kept.
     * \~spanish
     * Y el resto la termina sin volver a leer la cabecera del buffer -- se
     * entendio una vez y se guardo.
     * \~ */
    check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Frame,
          "the frame did not finish when the rest arrived");
    check(r.consumed() == w.used, "the boundary is not at the end");
    check(r.payload().len == 5, "the payload is not the whole of it");
}

/**
 * @brief
 * \~english Once it has refused, it keeps refusing.
 * \~spanish Una vez ha rechazado, sigue rechazando.
 * \~
 */
void test_sticky() {
    const http_vx::h2::Limits limits;

    Wire w;
    w.preface();
    w.empty(FrameType::Data, 0, 0);
    w.empty(FrameType::Ping, 0, 0);

    FrameReader r(limits);
    r.reset(0, true);
    check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Error, "it was not refused");
    const ErrorCode first = r.error();
    check(r.read(http_vx::View{w.bytes, w.used, 0}) == ReadResult::Error,
          "calling again after a refusal changed the answer");
    check(r.error() == first, "the reason changed");
}

} // namespace

int main() {
    test_header_round_trip();
    test_reserved_bit();
    test_validation();
    test_unknown_type_is_ignored();
    test_preface();
    test_padding();
    test_continuation_sequencing();
    test_continuation_flood();
    test_dripping();
    test_boundary_stays_put();
    test_sticky();

    if (failures != 0) {
        std::fprintf(stderr, "test_h2_frame: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h2_frame: ok\n");
    return 0;
}
