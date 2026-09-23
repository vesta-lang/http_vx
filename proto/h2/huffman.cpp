/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/huffman.cpp
 * @brief
 * \~english The code, and the tree that is built from it at compile time.
 * \~spanish El codigo, y el arbol que se construye de el al compilar.
 * \~
 *
 * \~english
 * ONE TABLE, and it is the one the specification writes: a code and a length
 * per symbol.  What reading needs is a tree, and the tree is DERIVED from the
 * table while this file is compiled rather than written next to it.
 *
 * That is not tidiness.  A hand-written decoding tree is a second statement of
 * the same code, and two statements of the same thing disagree eventually --
 * here by decoding one character as another, on a connection that otherwise
 * works.  Derived, the two cannot differ: there is only one.
 *
 * And the derivation checks the table on the way past.  A prefix code has
 * properties that a table with a mistake in it does not have, and they are
 * asserted below -- so a wrong length fails the build rather than a message.
 *
 * \~spanish
 * UNA TABLA, y es la que escribe la especificacion: un codigo y una longitud
 * por simbolo.  Lo que hace falta para leer es un arbol, y el arbol se DERIVA
 * de la tabla mientras se compila este fichero en vez de escribirse al lado.
 *
 * No es por orden.  Un arbol de descodificacion escrito a mano es una segunda
 * declaracion del mismo codigo, y dos declaraciones de lo mismo acaban
 * discrepando -- aqui descodificando un caracter como otro, en una conexion que
 * por lo demas funciona.  Derivado, los dos no pueden diferir: solo hay uno.
 *
 * Y la derivacion comprueba la tabla al pasar.  Un codigo de prefijo tiene
 * propiedades que no tiene una tabla con una equivocacion, y se afirman abajo
 * -- asi que una longitud mal puesta rompe la construccion y no un mensaje.
 *
 * \~
 */

#include "http_vx/h2_huffman.h"

namespace http_vx {
namespace h2 {
namespace hpack {
namespace {

/// \~english The symbol that says a string ends.  It may not appear in one.
/// \~spanish El simbolo que dice que una cadena acaba.  No puede aparecer en una.  \~
constexpr uint16_t kEos = 256;

/// \~english How many symbols there are: the bytes, and the end.
/// \~spanish Cuantos simbolos hay: los bytes, y el final.  \~
constexpr size_t kSymbols = 257;

/**
 * @brief
 * \~english One symbol: what it is written as, and in how many bits.
 * \~spanish Un simbolo: como se escribe, y en cuantos bits.
 * \~
 */
struct Code {
    uint32_t bits;
    uint8_t len;
};

/**
 * @brief
 * \~english The code, RFC 7541 appendix B.
 * \~spanish El codigo, RFC 7541 apendice B.
 * \~
 *
 * \~english
 * Measured once over real traffic and fixed forever, which is why neither end
 * sends it.  The short codes are what HTTP is mostly made of -- digits, the
 * lower-case letters that spell `content`, the slash -- and the long ones are
 * the bytes that never appear in a header and cost thirty bits when they do.
 *
 * \~spanish
 * Medido una vez sobre trafico real y fijado para siempre, que es la razon de
 * que ninguno de los dos extremos lo mande.  Los codigos cortos son de lo que
 * esta hecho HTTP casi siempre -- digitos, las minusculas que deletrean
 * `content`, la barra -- y los largos son los bytes que no aparecen nunca en
 * una cabecera y cuestan treinta bits cuando lo hacen.
 *
 * \~
 */
constexpr Code kCodes[kSymbols] = {
    {0x1ff8, 13},     {0x7fffd8, 23},   {0xfffffe2, 28},  {0xfffffe3, 28},
    {0xfffffe4, 28},  {0xfffffe5, 28},  {0xfffffe6, 28},  {0xfffffe7, 28},
    {0xfffffe8, 28},  {0xffffea, 24},   {0x3ffffffc, 30}, {0xfffffe9, 28},
    {0xfffffea, 28},  {0x3ffffffd, 30}, {0xfffffeb, 28},  {0xfffffec, 28},
    {0xfffffed, 28},  {0xfffffee, 28},  {0xfffffef, 28},  {0xffffff0, 28},
    {0xffffff1, 28},  {0xffffff2, 28},  {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28},  {0xffffff5, 28},  {0xffffff6, 28},  {0xffffff7, 28},
    {0xffffff8, 28},  {0xffffff9, 28},  {0xffffffa, 28},  {0xffffffb, 28},

    // 32-63: el espacio, la puntuacion y los digitos.
    {0x14, 6},        {0x3f8, 10},      {0x3f9, 10},      {0xffa, 12},
    {0x1ff9, 13},     {0x15, 6},        {0xf8, 8},        {0x7fa, 11},
    {0x3fa, 10},      {0x3fb, 10},      {0xf9, 8},        {0x7fb, 11},
    {0xfa, 8},        {0x16, 6},        {0x17, 6},        {0x18, 6},
    {0x0, 5},         {0x1, 5},         {0x2, 5},         {0x19, 6},
    {0x1a, 6},        {0x1b, 6},        {0x1c, 6},        {0x1d, 6},
    {0x1e, 6},        {0x1f, 6},        {0x5c, 7},        {0xfb, 8},
    {0x7ffc, 15},     {0x20, 6},        {0xffb, 12},      {0x3fc, 10},

    // 64-95: las mayusculas, que en una cabecera casi no aparecen.
    {0x1ffa, 13},     {0x21, 6},        {0x5d, 7},        {0x5e, 7},
    {0x5f, 7},        {0x60, 7},        {0x61, 7},        {0x62, 7},
    {0x63, 7},        {0x64, 7},        {0x65, 7},        {0x66, 7},
    {0x67, 7},        {0x68, 7},        {0x69, 7},        {0x6a, 7},
    {0x6b, 7},        {0x6c, 7},        {0x6d, 7},        {0x6e, 7},
    {0x6f, 7},        {0x70, 7},        {0x71, 7},        {0x72, 7},
    {0xfc, 8},        {0x73, 7},        {0xfd, 8},        {0x1ffb, 13},
    {0x7fff0, 19},    {0x1ffc, 13},     {0x3ffc, 14},     {0x22, 6},

    // 96-127: las minusculas, que son casi todo.
    {0x7ffd, 15},     {0x3, 5},         {0x23, 6},        {0x4, 5},
    {0x24, 6},        {0x5, 5},         {0x25, 6},        {0x26, 6},
    {0x27, 6},        {0x6, 5},         {0x74, 7},        {0x75, 7},
    {0x28, 6},        {0x29, 6},        {0x2a, 6},        {0x7, 5},
    {0x2b, 6},        {0x76, 7},        {0x2c, 6},        {0x8, 5},
    {0x9, 5},         {0x2d, 6},        {0x77, 7},        {0x78, 7},
    {0x79, 7},        {0x7a, 7},        {0x7b, 7},        {0x7ffe, 15},
    {0x7fc, 11},      {0x3ffd, 14},     {0x1ffd, 13},     {0xffffffc, 28},

    // 128-255: lo que no es ASCII, y cuesta lo que cuesta.
    {0xfffe6, 20},    {0x3fffd2, 22},   {0xfffe7, 20},    {0xfffe8, 20},
    {0x3fffd3, 22},   {0x3fffd4, 22},   {0x3fffd5, 22},   {0x7fffd9, 23},
    {0x3fffd6, 22},   {0x7fffda, 23},   {0x7fffdb, 23},   {0x7fffdc, 23},
    {0x7fffdd, 23},   {0x7fffde, 23},   {0xffffeb, 24},   {0x7fffdf, 23},
    {0xffffec, 24},   {0xffffed, 24},   {0x3fffd7, 22},   {0x7fffe0, 23},
    {0xffffee, 24},   {0x7fffe1, 23},   {0x7fffe2, 23},   {0x7fffe3, 23},
    {0x7fffe4, 23},   {0x1fffdc, 21},   {0x3fffd8, 22},   {0x7fffe5, 23},
    {0x3fffd9, 22},   {0x7fffe6, 23},   {0x7fffe7, 23},   {0xffffef, 24},
    {0x3fffda, 22},   {0x1fffdd, 21},   {0xfffe9, 20},    {0x3fffdb, 22},
    {0x3fffdc, 22},   {0x7fffe8, 23},   {0x7fffe9, 23},   {0x1fffde, 21},
    {0x7fffea, 23},   {0x3fffdd, 22},   {0x3fffde, 22},   {0xfffff0, 24},
    {0x1fffdf, 21},   {0x3fffdf, 22},   {0x7fffeb, 23},   {0x7fffec, 23},
    {0x1fffe0, 21},   {0x1fffe1, 21},   {0x3fffe0, 22},   {0x1fffe2, 21},
    {0x7fffed, 23},   {0x3fffe1, 22},   {0x7fffee, 23},   {0x7fffef, 23},
    {0xfffea, 20},    {0x3fffe2, 22},   {0x3fffe3, 22},   {0x3fffe4, 22},
    {0x7ffff0, 23},   {0x3fffe5, 22},   {0x3fffe6, 22},   {0x7ffff1, 23},
    {0x3ffffe0, 26},  {0x3ffffe1, 26},  {0xfffeb, 20},    {0x7fff1, 19},
    {0x3fffe7, 22},   {0x7ffff2, 23},   {0x3fffe8, 22},   {0x1ffffec, 25},
    {0x3ffffe2, 26},  {0x3ffffe3, 26},  {0x3ffffe4, 26},  {0x7ffffde, 27},
    {0x7ffffdf, 27},  {0x3ffffe5, 26},  {0xfffff1, 24},   {0x1ffffed, 25},
    {0x7fff2, 19},    {0x1fffe3, 21},   {0x3ffffe6, 26},  {0x7ffffe0, 27},
    {0x7ffffe1, 27},  {0x3ffffe7, 26},  {0x7ffffe2, 27},  {0xfffff2, 24},
    {0x1fffe4, 21},   {0x1fffe5, 21},   {0x3ffffe8, 26},  {0x3ffffe9, 26},
    {0xffffffd, 28},  {0x7ffffe3, 27},  {0x7ffffe4, 27},  {0x7ffffe5, 27},
    {0xfffec, 20},    {0xfffff3, 24},   {0xfffed, 20},    {0x1fffe6, 21},
    {0x3fffe9, 22},   {0x1fffe7, 21},   {0x1fffe8, 21},   {0x7ffff3, 23},
    {0x3fffea, 22},   {0x3fffeb, 22},   {0x1ffffee, 25},  {0x1ffffef, 25},
    {0xfffff4, 24},   {0xfffff5, 24},   {0x3ffffea, 26},  {0x7ffff4, 23},
    {0x3ffffeb, 26},  {0x7ffffe6, 27},  {0x3ffffec, 26},  {0x3ffffed, 26},
    {0x7ffffe7, 27},  {0x7ffffe8, 27},  {0x3ffffee, 26},  {0x7ffffe9, 27},
    {0x7ffffea, 27},  {0x7ffffeb, 27},  {0x7ffffec, 27},  {0x7ffffed, 27},
    {0x7ffffee, 27},  {0xffffffe, 28},  {0x7ffffef, 27},  {0x7fffff0, 27},

    // 256: el final, que no puede aparecer dentro de una cadena.
    {0x3fffffff, 30},
};

/**
 * @brief
 * \~english The shortest code in the table.
 * \~spanish El codigo mas corto de la tabla.
 * \~
 *
 * \~english
 * Computed rather than written, and asserted rather than trusted, because a
 * bound in the header rests on it: @c huffman_max_decoded says a string cannot
 * grow by more than eight fifths, and that is only true while no code is
 * shorter than five bits.  A table with a four-bit code in it would make that
 * bound a lie, and a bound that is a lie is a buffer that is too small.
 *
 * \~spanish
 * Calculado y no escrito, y afirmado y no supuesto, porque hay una cota de la
 * cabecera que se apoya en el: @c huffman_max_decoded dice que una cadena no
 * puede crecer mas de ocho quintos, y eso solo es cierto mientras ningun codigo
 * baje de cinco bits.  Una tabla con un codigo de cuatro bits convertiria esa
 * cota en una mentira, y una cota que miente es un buffer que se queda corto.
 *
 * \~
 */
constexpr uint8_t shortest_code() noexcept {
    uint8_t m = 255;
    for (const Code &c : kCodes)
        if (c.len < m) m = c.len;
    return m;
}

static_assert(shortest_code() == 5,
              "huffman_max_decoded bounds the growth of a string at eight "
              "fifths, which holds only while the shortest code is five bits");

/**
 * @brief
 * \~english The most nodes a tree of these codes can have.
 * \~spanish Los nodos mas que puede tener un arbol de estos codigos.
 * \~
 *
 * \~english
 * A complete binary tree with two hundred and fifty-seven leaves has two
 * hundred and fifty-six branches, so five hundred and thirteen in all.  The
 * number is here as a ceiling for the array, and the build asserts what it
 * actually used -- so a table that produced a different shape would not fit
 * quietly, it would stop the compiler.
 *
 * \~spanish
 * Un arbol binario completo con doscientas cincuenta y siete hojas tiene
 * doscientas cincuenta y seis ramas, asi que quinientos trece en total.  El
 * numero esta aqui como techo del array, y la construccion afirma lo que uso de
 * verdad -- asi que una tabla que produjera otra forma no cabria en silencio,
 * pararia al compilador.
 *
 * \~
 */
constexpr size_t kMaxNodes = 513;

/**
 * @brief
 * \~english A branch of the tree: where each bit leads.
 * \~spanish Una rama del arbol: a donde lleva cada bit.
 * \~
 *
 * \~english
 * A positive value is another branch, by index.  A negative one is a symbol,
 * written as @c -(symbol + 1) so that symbol zero -- which is a real byte --
 * does not collide with "nothing here".  Zero is nothing here, and it cannot
 * be a branch index because index zero is the root and nothing points back at
 * it.
 *
 * \~spanish
 * Un valor positivo es otra rama, por indice.  Uno negativo es un simbolo,
 * escrito como @c -(simbolo + 1) para que el simbolo cero -- que es un byte de
 * verdad -- no choque con "aqui no hay nada".  El cero es "aqui no hay nada", y
 * no puede ser indice de rama porque el indice cero es la raiz y nadie apunta
 * hacia atras a ella.
 *
 * \~
 */
struct Node {
    int16_t next[2];
};

struct Tree {
    Node nodes[kMaxNodes];
    size_t used;
};

/**
 * @brief
 * \~english Builds the tree from the table, while this is compiled.
 * \~spanish Construye el arbol de la tabla, mientras se compila esto.
 * \~
 */
constexpr Tree build_tree() noexcept {
    Tree t{};
    t.used = 1;

    for (size_t sym = 0; sym < kSymbols; ++sym) {
        const Code c = kCodes[sym];
        size_t at = 0;

        for (uint8_t i = 0; i < c.len; ++i) {
            const unsigned bit =
                static_cast<unsigned>(c.bits >> (c.len - 1 - i)) & 1u;
            const bool last = i + 1 == c.len;

            if (last) {
                t.nodes[at].next[bit] = -static_cast<int16_t>(sym + 1);
                break;
            }

            if (t.nodes[at].next[bit] == 0) {
                t.nodes[at].next[bit] = static_cast<int16_t>(t.used);
                ++t.used;
            }
            at = static_cast<size_t>(t.nodes[at].next[bit]);
        }
    }

    return t;
}

constexpr Tree kTree = build_tree();

/**
 * @brief
 * \~english Whether the tree has no branch that leads nowhere.
 * \~spanish Si el arbol no tiene ninguna rama que no lleve a ninguna parte.
 * \~
 *
 * \~english
 * A prefix code fills its tree: every branch has two ways out, and every way
 * out is another branch or a symbol.  A hole means the table has a length that
 * is wrong somewhere -- and a hole is a bit pattern a sender can write that
 * this would have no answer for.
 *
 * \~spanish
 * Un codigo de prefijo llena su arbol: toda rama tiene dos salidas, y toda
 * salida es otra rama o un simbolo.  Un hueco quiere decir que la tabla tiene
 * una longitud mal en alguna parte -- y un hueco es un patron de bits que quien
 * envia puede escribir y para el que esto no tendria respuesta.
 *
 * \~
 */
constexpr bool tree_is_complete() noexcept {
    for (size_t i = 0; i < kTree.used; ++i)
        if (kTree.nodes[i].next[0] == 0 || kTree.nodes[i].next[1] == 0)
            return false;
    return true;
}

static_assert(kTree.used == 256,
              "the tree of a prefix code with 257 leaves has 256 branches: "
              "another number means the table has a length that is wrong");

static_assert(tree_is_complete(),
              "a branch of the tree leads nowhere, which is a bit pattern a "
              "sender can write and this would have no answer for");

/**
 * @brief
 * \~english Whether the code fills exactly the space it has.
 * \~spanish Si el codigo llena exactamente el sitio que tiene.
 * \~
 *
 * \~english
 * Kraft's equality: the lengths of a complete prefix code sum to one when each
 * is counted as two to the minus its length.  It is checked over a common
 * denominator so it is arithmetic on whole numbers, and it catches a length
 * that is wrong even when the tree happens to come out the right size.
 *
 * \~spanish
 * La igualdad de Kraft: las longitudes de un codigo de prefijo completo suman
 * uno contando cada una como dos elevado a menos su longitud.  Se comprueba
 * sobre un denominador comun para que sea aritmetica de numeros enteros, y
 * pilla una longitud mal puesta aunque el arbol salga del tamano correcto.
 *
 * \~
 */
constexpr bool kraft_holds() noexcept {
    uint64_t sum = 0;
    for (size_t i = 0; i < kSymbols; ++i)
        sum += uint64_t{1} << (30 - kCodes[i].len);
    return sum == (uint64_t{1} << 30);
}

static_assert(kraft_holds(),
              "the code lengths do not fill their space exactly, which means "
              "one of them is wrong");

} // namespace

HuffmanResult huffman_decode(uint8_t *out, size_t cap, const uint8_t *in,
                             size_t n) noexcept {
    if (n == 0) return HuffmanResult{Status::Ok, 0};
    if (in == nullptr) return HuffmanResult{Status::Malformed, 0};

    size_t written = 0;
    size_t at = 0;

    /* \~english
     * How many bits have been walked since the last symbol came out, and
     * whether all of them were ones.  Both are only needed at the very end --
     * the padding is what they describe -- but they are kept as it goes
     * because working them out afterwards would mean looking at the input
     * again, from a position that is not a byte boundary.
     *
     * \~spanish
     * Cuantos bits se han recorrido desde que salio el ultimo simbolo, y si
     * todos eran unos.  Los dos solo hacen falta al final -- el relleno es lo
     * que describen -- pero se llevan sobre la marcha porque averiguarlos
     * despues seria mirar la entrada otra vez, desde una posicion que no es
     * frontera de byte.
     * \~ */
    unsigned since = 0;
    bool all_ones = true;

    for (size_t i = 0; i < n; ++i) {
        const uint8_t byte = in[i];

        for (int b = 7; b >= 0; --b) {
            const unsigned bit = (byte >> b) & 1u;
            ++since;
            if (bit == 0) all_ones = false;

            const int16_t step = kTree.nodes[at].next[bit];

            if (step > 0) {
                at = static_cast<size_t>(step);
                continue;
            }

            const uint16_t sym = static_cast<uint16_t>(-step - 1);

            /* \~english
             * The end-of-string symbol inside a string.  A string already
             * knows how long it is -- HPACK wrote the length in front of
             * it -- so this symbol has nothing to say, and letting it through
             * would be letting a sender end a string in a second place.
             *
             * \~spanish
             * El simbolo de fin de cadena dentro de una cadena.  Una cadena ya
             * sabe cuanto mide -- HPACK escribio la longitud delante -- asi que
             * este simbolo no tiene nada que decir, y dejarlo pasar seria dejar
             * que quien envia terminara una cadena en un segundo sitio.
             * \~ */
            if (sym == kEos) return HuffmanResult{Status::Malformed, 0};

            if (written == cap) return HuffmanResult{Status::TooLarge, 0};
            out[written] = static_cast<uint8_t>(sym);
            ++written;

            at = 0;
            since = 0;
            all_ones = true;
        }
    }

    /* \~english
     * What is left over.  It must be the beginning of the end-of-string
     * symbol, which is all ones, and there must be less than a byte of it --
     * because a whole byte of padding is a byte the sender did not have to
     * send, and the only reason to send one is to put something in it.
     *
     * \~spanish
     * Lo que sobra.  Tiene que ser el principio del simbolo de fin de cadena,
     * que son todo unos, y tiene que haber menos de un byte -- porque un byte
     * entero de relleno es un byte que quien envia no tenia que mandar, y la
     * unica razon de mandarlo es meter algo dentro.
     * \~ */
    if (since >= 8 || !all_ones) return HuffmanResult{Status::Malformed, 0};

    return HuffmanResult{Status::Ok, written};
}

size_t huffman_encoded_length(const uint8_t *in, size_t n) noexcept {
    uint64_t bits = 0;
    for (size_t i = 0; i < n; ++i) bits += kCodes[in[i]].len;
    return static_cast<size_t>((bits + 7) / 8);
}

size_t huffman_encode(uint8_t *out, size_t cap, const uint8_t *in,
                      size_t n) noexcept {
    const size_t need = huffman_encoded_length(in, n);
    if (need > cap) return 0;

    uint64_t hold = 0;
    unsigned held = 0;
    size_t written = 0;

    for (size_t i = 0; i < n; ++i) {
        const Code c = kCodes[in[i]];
        hold = (hold << c.len) | c.bits;
        held += c.len;

        while (held >= 8) {
            held -= 8;
            out[written] = static_cast<uint8_t>((hold >> held) & 0xFF);
            ++written;
        }
    }

    /* \~english
     * And the bits left over are filled with ones, which is the beginning of
     * the end-of-string symbol.  That is what makes padding recognisable as
     * padding to whoever reads it -- and a reader that finds anything else
     * there knows something was hidden in it.
     *
     * \~spanish
     * Y los bits que sobran se llenan de unos, que es el principio del simbolo
     * de fin de cadena.  Eso es lo que hace que el relleno sea reconocible como
     * relleno para quien lo lee -- y quien lea y encuentre otra cosa ahi sabe
     * que se escondio algo.
     * \~ */
    if (held != 0) {
        const unsigned pad = 8 - held;
        out[written] = static_cast<uint8_t>(((hold << pad) | ((1u << pad) - 1)) &
                                            0xFF);
        ++written;
    }

    return written;
}

} // namespace hpack
} // namespace h2
} // namespace http_vx
