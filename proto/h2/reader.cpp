/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/reader.cpp
 * @brief
 * \~english The state machine that reads frames off a connection.
 * \~spanish La maquina de estados que lee tramas de una conexion.
 * \~
 */

#include "http_vx/h2_reader.h"

namespace http_vx {
namespace h2 {
namespace {

/// \~english The five bytes a deprecated priority takes.
/// \~spanish Los cinco bytes que ocupa una prioridad retirada.  \~
constexpr size_t kPriorityLen = 5;

/// \~english The four bytes a promised stream identifier takes.
/// \~spanish Los cuatro bytes que ocupa un identificador de flujo prometido.  \~
constexpr size_t kPromisedIdLen = 4;

/**
 * @brief
 * \~english Whether a frame of this type carries a piece of a header block.
 * \~spanish Si una trama de este tipo lleva un pedazo de bloque de cabeceras.
 * \~
 */
inline bool carries_header_block(uint8_t type) noexcept {
    return type == static_cast<uint8_t>(FrameType::Headers) ||
           type == static_cast<uint8_t>(FrameType::PushPromise) ||
           type == static_cast<uint8_t>(FrameType::Continuation);
}

} // namespace

void FrameReader::reset(uint64_t start, bool preface) noexcept {
    state_ = preface ? State::Preface : State::Header;
    error_ = ErrorCode::NoError;
    pos_ = start;
    boundary_ = start;
    header_ = FrameHeader{};
    payload_ = Span{0, 0};
    continuing_ = false;
    continuing_stream_ = 0;
    continuation_frames_ = 0;
    header_block_bytes_ = 0;
}

ReadResult FrameReader::fail(ErrorCode e) noexcept {
    state_ = State::Failed;
    error_ = e;
    return ReadResult::Error;
}

bool FrameReader::strip(const View &v, uint64_t &off,
                        size_t &len) noexcept {
    /* \~english
     * Every step here subtracts, and every subtraction is preceded by the
     * check that makes it possible.  That order is the whole function: a
     * length that goes below zero does not become negative, it becomes
     * enormous, and an enormous length is a read of the rest of the process's
     * memory reported as a header block.
     *
     * \~spanish
     * Todos los pasos de aqui restan, y a todas las restas les precede la
     * comprobacion que las hace posibles.  Ese orden es toda la funcion: una
     * longitud que baja de cero no se vuelve negativa, se vuelve enorme, y una
     * longitud enorme es una lectura del resto de la memoria del proceso
     * informada como un bloque de cabeceras.
     * \~ */
    size_t pad = 0;

    if (header_.has(kPadded)) {
        if (len < 1) return false;
        pad = *v.at(off);
        ++off;
        --len;
    }

    if (header_.type == static_cast<uint8_t>(FrameType::Headers) &&
        header_.has(kPriority)) {
        if (len < kPriorityLen) return false;
        off += kPriorityLen;
        len -= kPriorityLen;
    }

    if (header_.type == static_cast<uint8_t>(FrameType::PushPromise)) {
        if (len < kPromisedIdLen) return false;
        off += kPromisedIdLen;
        len -= kPromisedIdLen;
    }

    /* \~english
     * And the padding itself, last, because what it has to fit inside is what
     * is left after everything else came off.  A pad length equal to what is
     * left is legal -- a frame that is all padding says nothing, which is a
     * thing a sender is allowed to say; one byte more is not.
     *
     * \~spanish
     * Y el relleno mismo, el ultimo, porque dentro de lo que tiene que caber es
     * lo que queda despues de quitar todo lo demas.  Un relleno igual a lo que
     * queda es legal -- una trama que sea toda relleno no dice nada, que es
     * algo que quien envia puede decir --; un byte mas no.
     * \~ */
    if (pad > len) return false;
    len -= pad;

    return true;
}

ErrorCode FrameReader::check_continuation() noexcept {
    const bool is_block = carries_header_block(header_.type);
    const bool is_continuation =
        header_.type == static_cast<uint8_t>(FrameType::Continuation);

    if (continuing_) {
        /* \~english
         * While a header block is open, nothing else may arrive -- not a frame
         * on another stream, not a PING, not even a CONTINUATION belonging to
         * somebody else.  The rule is that strict for a reason: a header block
         * is compressed against a table that both ends are updating as they
         * read it, so a frame that arrived in the middle would be decompressed
         * against a table in a state neither end agreed on.
         *
         * \~spanish
         * Mientras hay un bloque de cabeceras abierto no puede llegar nada mas
         * -- ni una trama de otro flujo, ni un PING, ni siquiera una
         * CONTINUATION de otro --.  La regla es asi de estricta por una razon:
         * un bloque de cabeceras va comprimido contra una tabla que los dos
         * extremos van actualizando segun la leen, asi que una trama que
         * llegara en medio se descomprimiria contra una tabla en un estado en
         * el que no quedo ninguno de los dos.
         * \~ */
        if (!is_continuation || header_.stream_id != continuing_stream_)
            return ErrorCode::ProtocolError;

        ++continuation_frames_;

        /* \~english
         * And it cannot go on forever.  A peer that sends HEADERS and then
         * CONTINUATION without end, each frame legal and none of them carrying
         * END_HEADERS, makes this connection hold an unfinished message while
         * spending almost nothing itself -- the frames can be empty.  Counting
         * them is what makes that cheap to refuse, because the byte limit
         * below never fires on frames that carry no bytes.
         *
         * \~spanish
         * Y no puede seguir para siempre.  Un extremo que mande HEADERS y
         * despues CONTINUATION sin parar, cada trama legal y ninguna con
         * END_HEADERS, hace que esta conexion guarde un mensaje sin terminar
         * gastando el casi nada -- las tramas pueden ir vacias --.  Contarlas
         * es lo que hace barato rechazarlo, porque el limite de bytes de abajo
         * no salta nunca con tramas que no llevan bytes.
         * \~ */
        if (continuation_frames_ > limits_.max_continuation_frames)
            return ErrorCode::EnhanceYourCalm;
    } else if (is_continuation) {
        /* \~english
         * A CONTINUATION with nothing to continue.  It is not a stray frame:
         * it is a header block fragment that would be decompressed against a
         * table this end never opened.
         * \~spanish
         * Una CONTINUATION sin nada que continuar.  No es una trama perdida: es
         * un fragmento de bloque de cabeceras que se descomprimiria contra una
         * tabla que este extremo no abrio nunca.
         * \~ */
        return ErrorCode::ProtocolError;
    }

    if (is_block) {
        header_block_bytes_ += payload_.len;
        if (header_block_bytes_ > limits_.max_header_list_size)
            return ErrorCode::EnhanceYourCalm;

        if (header_.has(kEndHeaders)) {
            continuing_ = false;
            continuation_frames_ = 0;
            header_block_bytes_ = 0;
        } else {
            continuing_ = true;
            continuing_stream_ = header_.stream_id;
        }
    }

    return ErrorCode::NoError;
}

ReadResult FrameReader::read(const View &v) noexcept {
    if (state_ == State::Failed) return ReadResult::Error;

    for (;;) {
        switch (state_) {

        case State::Preface: {
            const uint64_t have = v.end() - pos_;
            if (have < sizeof(kClientPreface)) {
                /* \~english
                 * What has arrived must still be the beginning of it.  A
                 * connection that is not HTTP/2 is refused from its first
                 * wrong byte rather than after twenty-four of them, and the
                 * difference matters: those bytes could be an HTTP/1.1 request
                 * that some other part of this server could have answered.
                 *
                 * \~spanish
                 * Lo que haya llegado tiene que seguir siendo el principio de
                 * el.  Una conexion que no es HTTP/2 se rechaza desde su primer
                 * byte equivocado y no despues de veinticuatro, y la diferencia
                 * importa: esos bytes podrian ser una peticion de HTTP/1.1 que
                 * otra parte de este servidor si podria haber contestado.
                 * \~ */
                for (uint64_t i = 0; i < have; ++i)
                    if (*v.at(pos_ + i) != kClientPreface[i])
                        return fail(ErrorCode::ProtocolError);
                return ReadResult::NeedMore;
            }

            for (uint64_t i = 0; i < sizeof(kClientPreface); ++i)
                if (*v.at(pos_ + i) != kClientPreface[i])
                    return fail(ErrorCode::ProtocolError);

            pos_ += sizeof(kClientPreface);
            boundary_ = pos_;
            state_ = State::Header;
            break;
        }

        case State::Header: {
            if (v.end() - pos_ < kFrameHeaderSize) return ReadResult::NeedMore;

            decode_frame_header(v.at(pos_), header_);

            /* \~english
             * Validated from the header alone, before a byte of payload is
             * waited for.  A frame that says it is larger than this connection
             * accepts is refused now, rather than after the bytes it announced
             * have been read into memory to prove it.
             *
             * \~spanish
             * Validada solo con la cabecera, antes de esperar un byte de carga.
             * Una trama que dice ser mayor de lo que acepta esta conexion se
             * rechaza ahora, y no despues de haber leido a memoria los bytes
             * que anuncio para demostrarlo.
             * \~ */
            const ErrorCode e = validate_frame(header_, limits_);
            if (e != ErrorCode::NoError) return fail(e);

            pos_ += kFrameHeaderSize;
            state_ = State::Payload;
            break;
        }

        case State::Payload: {
            if (v.end() - pos_ < header_.length) return ReadResult::NeedMore;

            uint64_t off = pos_;
            size_t len = header_.length;

            if (header_.known() && !strip(v, off, len))
                return fail(ErrorCode::ProtocolError);

            /* \~english
             * The payload comes back as an offset from the VIEW and not as
             * a position in the stream, because it is read now and dies
             * now: the caller looks at it before it reads again, and the
             * next read is what may drop it.  Thirty-two bits are enough
             * for that and sixty-four would not fit a span.
             * \~spanish
             * La carga vuelve como desplazamiento desde la VISTA y no como
             * posicion del flujo, porque se lee ahora y muere ahora: quien
             * llama la mira antes de volver a leer, y la lectura siguiente
             * es la que puede descartarla.  Treinta y dos bits bastan para
             * eso y sesenta y cuatro no cabrian en un trozo.
             * \~ */
            payload_ = Span{static_cast<uint32_t>(off - v.origin),
                            static_cast<uint32_t>(len)};
            pos_ += header_.length;
            boundary_ = pos_;
            state_ = State::Header;

            /* \~english
             * A type nobody defined is discarded and not handed over.  The
             * specification requires ignoring it, and handing it up would make
             * every layer above decide for itself what to do with something it
             * also does not know -- which is how one of them ends up guessing.
             *
             * \~spanish
             * Un tipo que nadie definio se descarta y no se entrega.  La
             * especificacion exige ignorarlo, y entregarlo haria que cada capa
             * de arriba decidiera por su cuenta que hacer con algo que tampoco
             * conoce -- que es como una de ellas acaba adivinando.
             * \~ */
            if (!header_.known()) break;

            const ErrorCode e = check_continuation();
            if (e != ErrorCode::NoError) return fail(e);

            return ReadResult::Frame;
        }

        case State::Failed:
            return ReadResult::Error;
        }
    }
}

} // namespace h2
} // namespace http_vx
