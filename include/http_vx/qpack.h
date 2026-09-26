/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/qpack.h
 * @brief
 * \~english QPACK's pieces that hold no state: its integers, its strings, its static table and its errors (RFC 9204).
 * \~spanish Las piezas de QPACK que no guardan estado: sus enteros, sus cadenas, su tabla estatica y sus errores (RFC 9204).
 * \~
 *
 * \~english
 * QPACK takes HPACK's integer and string literal (4.1) and widens them: an
 * integer MUST decode up to 62 bits -- HPACK's here stop at 32 --, and a
 * string may start mid-byte, after up to six bits of something else (an
 * "N-bit prefix string literal").  So these are their own, and HPACK's are
 * left as they are.  The Huffman code is HPACK's, unchanged (4.1.2), and is
 * reused.
 *
 * The static table is a different one from HPACK's, indexed from zero
 * (3.1): ninety-nine lines taken from the RFC's Appendix A.
 *
 * \~spanish
 * QPACK toma el entero y la cadena literal de HPACK (4.1) y los ensancha: un
 * entero DEBE poder leerse hasta 62 bits -- los de HPACK de aqui se paran en 32
 * --, y una cadena puede empezar a mitad de byte, tras hasta seis bits de otra
 * cosa (una "cadena literal con prefijo de N bits").  Asi que estos son propios,
 * y los de HPACK se quedan como estan.  El codigo Huffman es el de HPACK, sin
 * cambios (4.1.2), y se reutiliza.
 *
 * La tabla estatica es otra que la de HPACK, indexada desde cero (3.1): noventa
 * y nueve lineas tomadas del apendice A del RFC.
 * \~
 */
#ifndef HTTP_VX_QPACK_H
#define HTTP_VX_QPACK_H

#include "http_vx/buffer.h"
#include "http_vx/span.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace qpack {

/* \~english The error codes QPACK adds to HTTP/3's (6).  \~spanish Los codigos de error que QPACK anade a los de HTTP/3 (6).  \~ */
constexpr uint64_t kDecompressionFailed = 0x0200;
constexpr uint64_t kEncoderStreamError = 0x0201;
constexpr uint64_t kDecoderStreamError = 0x0202;

/* \~english Its two settings and its two stream types (5, 4.2).  \~spanish Sus dos parametros y sus dos tipos de flujo (5, 4.2).  \~ */
constexpr uint64_t kSettingMaxTableCapacity = 0x01;
constexpr uint64_t kSettingBlockedStreams = 0x07;
constexpr uint64_t kEncoderStreamType = 0x02;
constexpr uint64_t kDecoderStreamType = 0x03;

/// \~english What an entry costs beyond its name and value (3.2.1).  \~spanish Lo que cuesta una entrada ademas de su nombre y su valor (3.2.1).  \~
constexpr uint64_t kEntryOverhead = 32;

/// \~english The largest integer QPACK must read: 62 bits (4.1.1).  \~spanish El mayor entero que QPACK debe leer: 62 bits (4.1.1).  \~
constexpr uint64_t kMaxInt = (uint64_t{1} << 62) - 1;

/// \~english The most bytes a 62-bit integer takes with the smallest prefix.  \~spanish Los bytes que ocupa como mucho un entero de 62 bits con el prefijo mas corto.  \~
constexpr size_t kMaxIntBytes = 10;

/**
 * @brief
 * \~english How reading something went.  \~spanish Como fue leer algo.
 * \~
 */
enum class Status : uint8_t {
    Ok,
    /// \~english The bytes ran out inside it: on a stream, wait for more.  \~spanish Se acabaron los bytes dentro: en un flujo, esperar a mas.  \~
    Truncated,
    /// \~english It is not one.  \~spanish No lo es.  \~
    Malformed,
    /// \~english Larger than this end reads (7.4).  \~spanish Mayor de lo que lee este extremo (7.4).  \~
    TooLarge,
    /// \~english The output could not grow.  \~spanish La salida no pudo crecer.  \~
    NoMemory,
};

/**
 * @brief
 * \~english A prefixed integer read: its value and how many bytes it took.
 * \~spanish Un entero con prefijo leido: su valor y cuantos bytes ocupo.
 * \~
 */
struct Int {
    Status status = Status::Malformed;
    uint64_t value = 0;
    size_t used = 0;
};

/**
 * @brief
 * \~english Reads an integer whose first byte gives it its low @p prefix bits, 1 to 8 (RFC 7541, 5.1).
 * \~spanish Lee un entero al que el primer byte da sus @p prefix bits bajos, de 1 a 8 (RFC 7541, 5.1).
 * \~
 *
 * \~english
 * Past 62 bits is TooLarge; so is a continuation that could only add
 * zeros past that -- the value is what is bounded, and a run of bytes that
 * never ends is refused before it ends.
 * \~spanish
 * Pasado de 62 bits es TooLarge; y tambien una continuacion que solo podria
 * anadir ceros mas alla -- lo que se acota es el valor, y una tira de bytes que
 * no acaba se rechaza antes de que acabe.
 * \~
 */
Int read_int(const uint8_t *p, size_t n, unsigned prefix) noexcept;

/**
 * @brief
 * \~english Writes @p value with a @p prefix-bit prefix; @p high are the bits above it in the first byte.
 * \~spanish Escribe @p value con un prefijo de @p prefix bits; @p high son los bits de encima en el primer byte.
 * \~
 *
 * @return \~english the bytes written, at most kMaxIntBytes; 0 if @p value is past 62 bits
 *         \~spanish los bytes escritos, como mucho kMaxIntBytes; 0 si @p value pasa de 62 bits  \~
 */
size_t write_int(uint8_t *out, uint64_t value, unsigned prefix, uint8_t high) noexcept;

/**
 * @brief
 * \~english A string literal read: where it landed in the output, and how many input bytes it took.
 * \~spanish Una cadena literal leida: donde quedo en la salida, y cuantos bytes de entrada ocupo.
 * \~
 */
struct Str {
    Status status = Status::Malformed;
    Span span{0, 0};
    /// \~english Bytes taken; when Truncated, the bytes the whole literal needs, or 0 if its length is not in yet.
    /// \~spanish Bytes tomados; si Truncated, los que necesita el literal entero, o 0 si su longitud aun no llego.  \~
    size_t used = 0;
};

/**
 * @brief
 * \~english Reads an @p prefix-bit prefix string literal (4.1.2) into @p out, decoding Huffman.
 * \~spanish Lee una cadena literal con prefijo de @p prefix bits (4.1.2) en @p out, deshaciendo Huffman.
 * \~
 *
 * \~english
 * @p prefix is 2 to 8: the H flag is its top bit, the length the rest.
 * @p max bounds what comes out, the decoded string; more is TooLarge
 * (7.4).  What comes out is appended to @p out, and the span says where.
 * \~spanish
 * @p prefix va de 2 a 8: la marca H es su bit alto, la longitud el resto.
 * @p max acota lo que sale, la cadena ya descodificada; mas es TooLarge (7.4).
 * Lo que sale se anade a @p out, y el tramo dice donde.
 * \~
 */
Str read_str(const uint8_t *p, size_t n, unsigned prefix, size_t max, Buffer &out) noexcept;

/**
 * @brief
 * \~english The bytes a string literal of @p n bytes takes on the wire, Huffman-coded if that is shorter.
 * \~spanish Los bytes que ocupa en el cable una cadena literal de @p n bytes, en Huffman si asi es mas corta.
 * \~
 */
size_t str_size(const uint8_t *s, size_t n, unsigned prefix) noexcept;

/**
 * @brief
 * \~english Writes a string literal, Huffman-coded if that is shorter; @p high are the bits above the prefix.
 * \~spanish Escribe una cadena literal, en Huffman si asi es mas corta; @p high son los bits de encima del prefijo.
 * \~
 *
 * @return \~english the bytes written, str_size() of them; 0 if they do not fit in @p cap
 *         \~spanish los bytes escritos, str_size() de ellos; 0 si no caben en @p cap  \~
 */
size_t write_str(uint8_t *out, size_t cap, const uint8_t *s, size_t n, unsigned prefix, uint8_t high) noexcept;

/**
 * @brief
 * \~english A line of the static table.  \~spanish Una linea de la tabla estatica.
 * \~
 */
struct StaticLine {
    const char *name;
    uint8_t name_len;
    const char *value;
    uint8_t value_len;
};

/// \~english How many lines the static table has (Appendix A).  \~spanish Cuantas lineas tiene la tabla estatica (apendice A).  \~
constexpr size_t kStaticLines = 99;

/// \~english Line @p i, or null past the last.  \~spanish La linea @p i, o nulo pasada la ultima.  \~
const StaticLine *static_line(uint64_t i) noexcept;

/**
 * @brief
 * \~english Where a field is in the static table: exactly, by name only, or not at all.
 * \~spanish Donde esta un campo en la tabla estatica: exacto, solo por nombre, o nada.
 * \~
 */
struct StaticMatch {
    /// \~english The line, or kStaticLines for none.  \~spanish La linea, o kStaticLines para ninguna.  \~
    size_t index = kStaticLines;
    /// \~english Name and value both match.  \~spanish Casan el nombre y el valor.  \~
    bool exact = false;
};

/// \~english The best line for @p name and @p value: an exact one if any, else the first with that name.
/// \~spanish La mejor linea para @p name y @p value: una exacta si la hay, si no la primera con ese nombre.  \~
StaticMatch find_static(const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen) noexcept;

} // namespace qpack
} // namespace http_vx

#endif // HTTP_VX_QPACK_H
