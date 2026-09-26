/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/stream_verdicts.h
 * @brief
 * \~english The verdicts the stream table gives, shared by the files that give them.
 * \~spanish Los veredictos que da la tabla de flujos, compartidos por los ficheros que los dan.
 * \~
 *
 * \~english
 * Private to `proto/h2/`: the table's bookkeeping (stream.cpp) and its
 * answers to frames (stream_frames.cpp) say the same few things, and each is
 * written once so that "late" cannot become an error in one file and stay a
 * drop in the other.
 *
 * \~spanish
 * Privado de `proto/h2/`: la contabilidad de la tabla (stream.cpp) y sus
 * respuestas a las tramas (stream_frames.cpp) dicen las mismas pocas cosas, y
 * cada una se escribe una vez para que "tarde" no pueda volverse un error en un
 * fichero y seguir siendo un descarte en el otro.
 * \~
 */
#ifndef HTTP_VX_PROTO_H2_STREAM_VERDICTS_H
#define HTTP_VX_PROTO_H2_STREAM_VERDICTS_H

#include "http_vx/h2_stream.h"

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english The verdict for a frame that is simply late.
 * \~spanish El veredicto de una trama que solo llega tarde.
 * \~
 *
 * \~english
 * Written once because it is said from several places and it is the one that
 * is easy to write as an error by mistake.  A frame for a stream this end
 * reset is not the peer misbehaving: it left before the peer could know, and
 * the only thing owed for it is the connection window.
 *
 * \~spanish
 * Escrito una vez porque se dice desde varios sitios y es el que es facil poner
 * como error por equivocacion.  Una trama de un flujo que reinicio este extremo
 * no es el otro extremo portandose mal: salio antes de que el otro pudiera
 * saberlo, y lo unico que se debe por ella es la ventana de la conexion.
 *
 * \~
 */
constexpr Outcome late() noexcept {
    return Outcome{Verdict::Discard, ErrorCode::NoError, nullptr};
}

/// \~english The frame is accepted.  \~spanish La trama se acepta.  \~
constexpr Outcome ok() noexcept {
    return Outcome{Verdict::Accept, ErrorCode::NoError, nullptr};
}

/// \~english The stream ends with @p e, and why.  \~spanish El flujo acaba con @p e, y por que.  \~
constexpr Outcome stream_error(ErrorCode e, const char *why) noexcept {
    return Outcome{Verdict::StreamError, e, why};
}

/// \~english A malformed request: a stream error, PROTOCOL_ERROR, and why (RFC 9113, 8.1.1).
/// \~spanish Una peticion mal formada: error de flujo, PROTOCOL_ERROR, y por que (RFC 9113, 8.1.1).  \~
constexpr Outcome malformed(const char *why) noexcept {
    return Outcome{Verdict::StreamError, ErrorCode::ProtocolError, why};
}

/// \~english The connection ends with @p e, and why.  \~spanish La conexion acaba con @p e, y por que.  \~
constexpr Outcome connection_error(ErrorCode e, const char *why) noexcept {
    return Outcome{Verdict::ConnectionError, e, why};
}

/// \~english The refusal of one stream too many, said from the two places that refuse it.
/// \~spanish El rechazo de un flujo de mas, dicho desde los dos sitios que lo rechazan.  \~
constexpr Outcome too_many() noexcept {
    return stream_error(ErrorCode::RefusedStream,
                        "more concurrent streams than "
                        "SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113, 5.1.2)");
}

/**
 * @brief
 * \~english Whether a frame on a stream that ended in @p p is late, and so dropped.
 * \~spanish Si una trama de un flujo que acabo en @p p llega tarde, y por eso se tira.
 * \~
 *
 * \~english
 * When this end reset the stream, and when it is too old to know -- the
 * choice the RFC allows for every closed stream (RFC 9113, 5.1), and the one
 * that cannot drop a connection that did nothing wrong.
 * \~spanish
 * Cuando el flujo lo reinicio este extremo, y cuando es demasiado viejo para
 * saberlo -- la eleccion que el RFC permite para todo flujo cerrado (RFC
 * 9113, 5.1), y la que no puede tirar una conexion que no hizo nada mal.
 * \~
 */
constexpr bool is_late(Past p) noexcept {
    return p == Past::ResetHere || p == Past::Forgotten;
}

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_PROTO_H2_STREAM_VERDICTS_H
