/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_content_length.cpp
 * @brief
 * \~english Every way a content length can be wrong, one case each.
 * \~spanish Cada forma de que una longitud de contenido este mal, un caso cada una.
 * \~
 *
 * \~english
 * These cases are not hypothetical.  Each shape below -- the duplicate that
 * disagrees, the value in hexadecimal, the one with a sign, the list with a
 * hole in it, the number that wraps -- has been accepted by some
 * implementation and refused by the one next to it in a chain, and the gap
 * between the two is a request the second one served and the first one never
 * saw.
 *
 * So the test is written the way the attack is: not "does it parse a five",
 * but "is there anything it takes that a stricter reader would not".
 *
 * \~spanish
 * Estos casos no son hipoteticos.  Cada forma de abajo -- el duplicado que
 * discrepa, el valor en hexadecimal, el que lleva signo, la lista con un
 * hueco, el numero que da la vuelta -- la ha aceptado alguna implementacion y
 * la ha rechazado la de al lado en una cadena, y la diferencia entre las dos es
 * una peticion que la segunda sirvio y la primera no vio nunca.
 *
 * Asi que la prueba se escribe como el ataque: no "sabe leer un cinco", sino
 * "hay algo que acepte que un lector mas estricto no aceptaria".
 *
 * \~
 */

#include "http_vx/content_length.h"

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
 * \~english A message being assembled: bytes, and fields pointing into them.
 * \~spanish Un mensaje en construccion: bytes, y cabeceras que apuntan a ellos.
 * \~
 *
 * \~english
 * The values go into one array and the fields hold offsets into it, which is
 * the shape a real message has -- and the reason the parser is handed a base
 * pointer rather than strings.
 *
 * \~spanish
 * Los valores van a un array y las cabeceras guardan desplazamientos dentro de
 * el, que es la forma que tiene un mensaje de verdad -- y la razon de que al
 * analizador se le de un puntero base y no cadenas.
 *
 * \~
 */
struct Msg {
    uint8_t bytes[512];
    size_t used = 0;
    http_vx::Fields fields;

    void add(const char *value, size_t len) {
        http_vx::Field f{};
        f.id = http_vx::FieldId::ContentLength;
        f.name_off = 0;
        f.name_len = 14;
        f.value_off = static_cast<uint32_t>(used);
        f.value_len = static_cast<uint16_t>(len);
        if (len != 0) std::memcpy(bytes + used, value, len);
        used += len;
        fields.add(f);
    }

    void add(const char *value) { add(value, std::strlen(value)); }

    http_vx::ContentLength parse() const {
        return http_vx::parse_content_length(fields, bytes);
    }
};

/**
 * @brief
 * \~english Checks that @p value reads as the number @p want.
 * \~spanish Comprueba que @p value se lee como el numero @p want.
 * \~
 */
void accepts(const char *value, uint64_t want, const char *what) {
    Msg m;
    m.add(value);
    const http_vx::ContentLength r = m.parse();
    check(r.status == http_vx::ContentLengthStatus::Present, what);
    check(r.value == want, what);
}

/**
 * @brief
 * \~english Checks that @p value is refused for the reason @p why.
 * \~spanish Comprueba que @p value se rechaza por el motivo @p why.
 * \~
 */
void refuses(const char *value, http_vx::ContentLengthStatus why,
             const char *what) {
    Msg m;
    m.add(value);
    check(m.parse().status == why, what);
}

/**
 * @brief
 * \~english No field is not a length of zero.
 * \~spanish Que no haya cabecera no es una longitud de cero.
 * \~
 *
 * \~english
 * A request without one has no body, and a response without one runs until the
 * connection closes.  Those are decided elsewhere, from the absence -- which
 * is why the absence has to be reportable and not folded into a zero.
 *
 * \~spanish
 * Una peticion sin ella no tiene cuerpo, y una respuesta sin ella corre hasta
 * que se cierra la conexion.  Eso se decide en otro sitio, a partir de la
 * ausencia -- que es la razon de que la ausencia tenga que poder informarse y
 * no colapsarse en un cero.
 *
 * \~
 */
void test_absent() {
    Msg m;
    const http_vx::ContentLength r = m.parse();
    check(r.status == http_vx::ContentLengthStatus::Absent,
          "an absent field was not reported absent");
    check(r.value == 0, "an absent field carries a value");
}

/**
 * @brief
 * \~english What the grammar allows, and it is more than it looks.
 * \~spanish Lo que la gramatica permite, y es mas de lo que parece.
 * \~
 */
void test_accepted() {
    accepts("0", 0, "zero was not read as zero");
    accepts("5", 5, "five was not read as five");
    accepts("1234567890", 1234567890, "a long number was not read");

    /* \~english
     * Leading zeros are legal.  They look like something to refuse, and
     * refusing what the grammar allows is how a proxy starts dropping traffic
     * that works everywhere else.
     * \~spanish
     * Los ceros a la izquierda son legales.  Parecen algo que rechazar, y
     * rechazar lo que la gramatica permite es como un intermediario empieza a
     * tirar trafico que funciona en todas partes.
     * \~ */
    accepts("007", 7, "leading zeros were refused");
    accepts("0000000000000000000000000000005", 5,
            "many leading zeros were refused, or overflowed");

    /* \~english
     * The whole of the unsigned range, exactly.  One less than the ceiling and
     * the ceiling itself are the two values an off-by-one in the overflow
     * check gets wrong, in opposite directions.
     * \~spanish
     * El rango sin signo entero, exacto.  Uno menos que el techo y el techo
     * mismo son los dos valores que una comprobacion de desbordamiento
     * desplazada en uno yerra, en sentidos opuestos.
     * \~ */
    accepts("18446744073709551614", 18446744073709551614ull,
            "one below the ceiling was refused");
    accepts("18446744073709551615", 18446744073709551615ull,
            "the ceiling itself was refused");
}

/**
 * @brief
 * \~english What is not a number, however much it looks like one.
 * \~spanish Lo que no es un numero, por mucho que lo parezca.
 * \~
 */
void test_malformed() {
    using http_vx::ContentLengthStatus;

    refuses("", ContentLengthStatus::Malformed, "the empty value was accepted");
    refuses(" ", ContentLengthStatus::Malformed, "a lone space was accepted");
    refuses("abc", ContentLengthStatus::Malformed, "letters were accepted");

    /* \~english
     * Hexadecimal is the one that matters most, because the chunked encoding
     * writes its sizes that way: a reader that accepted `0x10` here would be
     * reading sixteen where the sender wrote a length of zero followed by
     * something else.
     * \~spanish
     * El hexadecimal es el que mas importa, porque la codificacion por trozos
     * escribe asi sus tamanos: un lector que aceptara `0x10` aqui estaria
     * leyendo dieciseis donde quien envia escribio una longitud de cero
     * seguida de otra cosa.
     * \~ */
    refuses("0x10", ContentLengthStatus::Malformed, "hexadecimal was accepted");

    refuses("+5", ContentLengthStatus::Malformed, "a plus sign was accepted");
    refuses("-5", ContentLengthStatus::Malformed, "a minus sign was accepted");
    refuses("5a", ContentLengthStatus::Malformed, "a trailing letter was accepted");
    refuses("5.0", ContentLengthStatus::Malformed, "a decimal point was accepted");
    refuses("5\t5", ContentLengthStatus::Malformed,
            "an interior tab was accepted");

    /* \~english
     * A list with a hole in it.  A hole is what a value looks like once a
     * recipient in the chain has removed something the next one would have
     * seen, so it is refused rather than skipped.
     * \~spanish
     * Una lista con un hueco.  Un hueco es lo que parece un valor cuando un
     * receptor de la cadena ha quitado algo que el siguiente si habria visto,
     * asi que se rechaza en vez de saltarselo.
     * \~ */
    refuses("5,,5", ContentLengthStatus::Malformed, "an empty element was skipped");
    refuses("5,", ContentLengthStatus::Malformed, "a trailing comma was accepted");
    refuses(",5", ContentLengthStatus::Malformed, "a leading comma was accepted");
}

/**
 * @brief
 * \~english A number that does not fit is not a number that wrapped.
 * \~spanish Un numero que no cabe no es un numero que dio la vuelta.
 * \~
 */
void test_too_large() {
    using http_vx::ContentLengthStatus;
    refuses("18446744073709551616", ContentLengthStatus::TooLarge,
            "one past the ceiling was accepted");
    refuses("99999999999999999999999999999999", ContentLengthStatus::TooLarge,
            "a far larger number was accepted");
}

/**
 * @brief
 * \~english Repeats and lists: all of them, and they must agree.
 * \~spanish Repeticiones y listas: todas, y tienen que coincidir.
 * \~
 *
 * \~english
 * This is the case the attack is built on.  Taking the first and stopping, or
 * the last, frames the message the way whoever wrote it chose out of a pair
 * that a stricter reader would have refused outright.
 *
 * \~spanish
 * Este es el caso sobre el que se construye el ataque.  Coger el primero y
 * parar, o el ultimo, trocea el mensaje como eligiera quien lo escribio de un
 * par que un lector mas estricto habria rechazado directamente.
 *
 * \~
 */
void test_repeats_and_lists() {
    using http_vx::ContentLengthStatus;

    {
        Msg m;
        m.add("5, 5");
        const http_vx::ContentLength r = m.parse();
        check(r.status == ContentLengthStatus::Present,
              "a list of equal values was refused");
        check(r.value == 5, "a list of equal values read wrong");
    }
    {
        Msg m;
        m.add("5,5");
        check(m.parse().status == ContentLengthStatus::Present,
              "a list without spacing was refused");
    }
    {
        Msg m;
        m.add("5, 6");
        check(m.parse().status == ContentLengthStatus::Conflicting,
              "a list of different values was accepted");
    }
    {
        Msg m;
        m.add("5");
        m.add("5");
        const http_vx::ContentLength r = m.parse();
        check(r.status == ContentLengthStatus::Present,
              "two fields agreeing were refused");
        check(r.value == 5, "two fields agreeing read wrong");
    }
    {
        Msg m;
        m.add("5");
        m.add("6");
        check(m.parse().status == ContentLengthStatus::Conflicting,
              "two fields disagreeing were accepted, which is the smuggle");
    }
    {
        /* \~english
         * The disagreement is in the third field, so a reader that stopped at
         * the first agreement would have accepted this one.
         * \~spanish
         * La discrepancia esta en la tercera cabecera, asi que un lector que
         * parara en el primer acuerdo habria aceptado esta.
         * \~ */
        Msg m;
        m.add("5");
        m.add("5");
        m.add("6");
        check(m.parse().status == ContentLengthStatus::Conflicting,
              "the walk stopped before the last field");
    }
    {
        /* \~english
         * And the malformed one is in the second, so a reader that stopped at
         * the first would have accepted that too.
         * \~spanish
         * Y la mal formada esta en la segunda, asi que un lector que parara en
         * la primera tambien la habria aceptado.
         * \~ */
        Msg m;
        m.add("5");
        m.add("0x10");
        check(m.parse().status == ContentLengthStatus::Malformed,
              "the walk stopped before a malformed later field");
    }
}

/**
 * @brief
 * \~english What is written reads back as the same number, at both ends of the range.
 * \~spanish Lo que se escribe se lee como el mismo numero, en los dos extremos del rango.
 * \~
 */
void test_written() {
    using http_vx::kContentLengthDigits;
    using http_vx::write_content_length;

    const uint64_t values[] = {0, 5, 10, 1234567890, 18446744073709551615ull};
    const char *texts[] = {"0", "5", "10", "1234567890", "18446744073709551615"};

    for (size_t i = 0; i < sizeof values / sizeof values[0]; ++i) {
        uint8_t out[kContentLengthDigits] = {};
        const size_t n = write_content_length(out, values[i]);
        check(n == std::strlen(texts[i]) && std::memcmp(out, texts[i], n) == 0,
              "a length was not written as its decimal digits");

        Msg m;
        char text[kContentLengthDigits + 1] = {};
        std::memcpy(text, out, n);
        m.add(text);
        const http_vx::ContentLength cl = m.parse();
        check(cl.status == http_vx::ContentLengthStatus::Present && cl.value == values[i],
              "a written length did not read back as itself");
    }
}

} // namespace

int main() {
    test_absent();
    test_accepted();
    test_malformed();
    test_too_large();
    test_repeats_and_lists();
    test_written();

    if (failures != 0) {
        std::fprintf(stderr, "test_content_length: %d failures\n", failures);
        return 1;
    }
    std::printf("test_content_length: ok\n");
    return 0;
}
