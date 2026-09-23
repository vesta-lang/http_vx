/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h1_fuzz.cpp
 * @brief
 * \~english The parser's properties, against input nobody wrote.
 * \~spanish Las propiedades del analizador, contra entrada que no escribio nadie.
 * \~
 *
 * \~english
 * This generates its own input and checks the properties in
 * @c fuzz/h1_invariants against every one of them.  It is not a replacement
 * for a real fuzzer -- it explores far less, and it cannot see a read past the
 * end of a buffer without a sanitiser watching.  What it is for is that the
 * check RUNS.
 *
 * A property check that only exists inside a fuzz target is a check that runs
 * on the machines that have the toolchain, which in practice means it runs
 * when somebody remembers.  This one runs on every build, on every machine,
 * and it costs a fraction of a second.
 *
 * The generator is deterministic, from a fixed seed.  A failure is
 * reproducible by running the test again, and the input is printed as hex so
 * it can be turned into a case with a name.
 *
 * \~spanish
 * Esto genera su propia entrada y comprueba contra cada una de ellas las
 * propiedades de @c fuzz/h1_invariants.  No sustituye a un fuzzer de verdad --
 * explora muchisimo menos, y no puede ver una lectura pasada del final de un
 * buffer sin un sanitizador mirando --.  Para lo que sirve es para que la
 * comprobacion SE EJECUTE.
 *
 * Una comprobacion de propiedades que solo existe dentro de un objetivo de
 * fuzzing es una comprobacion que corre en las maquinas que tienen la
 * herramienta, que en la practica quiere decir que corre cuando alguien se
 * acuerda.  Esta corre en cada construccion, en cada maquina, y cuesta una
 * fraccion de segundo.
 *
 * El generador es determinista, de una semilla fija.  Un fallo se reproduce
 * volviendo a correr la prueba, y la entrada se imprime en hexadecimal para
 * poder convertirla en un caso con nombre.
 *
 * \~
 */

#include "h1_invariants.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::fuzz::Breach;

int failures = 0;

/**
 * @brief
 * \~english A deterministic source of numbers.
 * \~spanish Una fuente determinista de numeros.
 * \~
 *
 * \~english
 * Deterministic because a property test that finds something once a week and
 * cannot say with what is a property test that reports weather.
 *
 * \~spanish
 * Determinista porque una prueba de propiedades que encuentra algo una vez por
 * semana y no sabe decir con que es una prueba de propiedades que informa del
 * tiempo que hace.
 *
 * \~
 */
class Rng {
  public:
    explicit Rng(uint64_t seed) noexcept : s_(seed) {}

    uint64_t next() noexcept {
        s_ ^= s_ << 13;
        s_ ^= s_ >> 7;
        s_ ^= s_ << 17;
        return s_;
    }

    uint32_t below(uint32_t n) noexcept {
        return n == 0 ? 0 : static_cast<uint32_t>(next() % n);
    }

  private:
    uint64_t s_;
};

/**
 * @brief
 * \~english Reports a broken property and the input that broke it.
 * \~spanish Informa de una propiedad rota y de la entrada que la rompio.
 * \~
 */
void report(Breach b, const uint8_t *data, size_t size) {
    std::fprintf(stderr, "FAIL: %s\n  input: ", http_vx::fuzz::breach_name(b));
    for (size_t i = 0; i < size; ++i) std::fprintf(stderr, "%02x", data[i]);
    std::fprintf(stderr, "\n");
    ++failures;
}

/**
 * @brief
 * \~english Which reader an input is meant for.
 * \~spanish Para cual de los dos lectores es una entrada.
 * \~
 *
 * \~english
 * The two are exercised from separate seeds rather than by giving every input
 * to both.  A request head is not a chunked body: handing one to the other
 * spends the run on inputs that are refused at the first byte, which explores
 * one state instead of the machine.
 *
 * \~spanish
 * Los dos se ejercitan desde semillas separadas y no dando cada entrada a los
 * dos.  Una cabeza de peticion no es un cuerpo troceado: darle una al otro
 * gasta la corrida en entradas que se rechazan al primer byte, que explora un
 * estado en vez de la maquina.
 *
 * \~
 */
enum class Reader { Head, Body };

void check_input(Reader which, const uint8_t *data, size_t size) {
    const Breach b = which == Reader::Head
                         ? http_vx::fuzz::check_parse(data, size)
                         : http_vx::fuzz::check_chunked(data, size);
    if (b != Breach::None) report(b, data, size);
}

/**
 * @brief
 * \~english The requests the mutations start from.
 * \~spanish Las peticiones de las que parten las mutaciones.
 * \~
 *
 * \~english
 * Starting from something valid matters more than it looks.  Random bytes are
 * refused on the first one almost every time, so they only ever exercise the
 * first state; a request with one byte changed gets deep into the machine
 * before anything goes wrong, which is where the states that hand over to each
 * other live.
 *
 * \~spanish
 * Partir de algo valido importa mas de lo que parece.  Unos bytes al azar se
 * rechazan en el primero casi siempre, asi que solo ejercitan el primer estado;
 * una peticion con un byte cambiado se mete hondo en la maquina antes de que
 * nada vaya mal, que es donde viven los estados que se pasan el testigo unos a
 * otros.
 *
 * \~
 */
const char *const kHeadSeeds[] = {
    "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
    "POST /a/b?c=d HTTP/1.1\r\nHost: example.com\r\n"
    "Content-Length: 12\r\nContent-Type: text/plain\r\n\r\nhello world!",
    "PUT /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
    "HEAD / HTTP/1.0\r\n\r\n",
    "OPTIONS * HTTP/1.1\r\nHost: h\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n",
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
};

/**
 * @brief
 * \~english The bodies the mutations start from.
 * \~spanish Los cuerpos de los que parten las mutaciones.
 * \~
 *
 * \~english
 * Small on purpose.  What is interesting about a chunked body is the grammar
 * between the pieces -- the sizes, the extensions, the endings, the
 * trailers -- and a body with many short chunks has more of that per byte than
 * one with a single long one.
 *
 * \~spanish
 * Pequenos a proposito.  Lo interesante de un cuerpo troceado es la gramatica
 * que hay entre los pedazos -- los tamanos, las extensiones, los finales, los
 * remolques -- y un cuerpo con muchos trozos cortos tiene mas de eso por byte
 * que uno con un solo trozo largo.
 *
 * \~
 */
const char *const kBodySeeds[] = {
    "0\r\n\r\n",
    "5\r\nhello\r\n0\r\n\r\n",
    "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n",
    "a;x=y\r\n0123456789\r\n0;last\r\n\r\n",
    "5\r\nhello\r\n0\r\nX-Sum: abc\r\nX-Other: 1\r\n\r\n",
    "0005\r\nhello\r\n000\r\n\r\n",
};

constexpr size_t kHeadSeedCount = sizeof(kHeadSeeds) / sizeof(kHeadSeeds[0]);
constexpr size_t kBodySeedCount = sizeof(kBodySeeds) / sizeof(kBodySeeds[0]);

const char *const *seeds_of(Reader which) noexcept {
    return which == Reader::Head ? kHeadSeeds : kBodySeeds;
}

size_t seed_count_of(Reader which) noexcept {
    return which == Reader::Head ? kHeadSeedCount : kBodySeedCount;
}

/**
 * @brief
 * \~english Bytes worth putting where they do not belong.
 * \~spanish Bytes que merece la pena poner donde no van.
 * \~
 *
 * \~english
 * A uniformly random byte lands on one of these about once in twenty tries,
 * and these are the ones that change how a message is divided: the line
 * endings, the colon, the space, the comma that separates a list.  Weighting
 * them is the difference between exploring the grammar and exploring the
 * bytes that are not in it.
 *
 * \~spanish
 * Un byte uniformemente al azar cae en uno de estos una de cada veinte veces, y
 * estos son los que cambian como se divide un mensaje: los finales de linea,
 * los dos puntos, el espacio, la coma que separa una lista.  Darles peso es la
 * diferencia entre explorar la gramatica y explorar los bytes que no estan en
 * ella.
 *
 * \~
 */
const uint8_t kInteresting[] = {'\r', '\n', ':', ' ', '\t', ',', ';',
                                '/',  '.',  '0', '9', 0x00, 0x7F, 0x80,
                                0xFF, 'H',  'T', 'P', '1'};

constexpr size_t kInterestingCount =
    sizeof(kInteresting) / sizeof(kInteresting[0]);

/**
 * @brief
 * \~english The seeds themselves, unchanged.
 * \~spanish Las propias semillas, sin cambiar.
 * \~
 */
void test_the_seeds(Reader which) {
    const char *const *seeds = seeds_of(which);
    for (size_t i = 0; i < seed_count_of(which); ++i)
        check_input(which, reinterpret_cast<const uint8_t *>(seeds[i]),
                    std::strlen(seeds[i]));
}

/**
 * @brief
 * \~english Every prefix of every seed.
 * \~spanish Todos los prefijos de todas las semillas.
 * \~
 *
 * \~english
 * A truncated message is not an exotic case: it is what every message looks
 * like until its last byte arrives.  Checking all of them covers every point
 * at which the parser can be interrupted.
 *
 * \~spanish
 * Un mensaje truncado no es un caso exotico: es lo que parece cualquier mensaje
 * hasta que llega su ultimo byte.  Comprobarlos todos cubre todos los puntos en
 * los que se puede interrumpir al analizador.
 *
 * \~
 */
void test_every_prefix(Reader which) {
    const char *const *seeds = seeds_of(which);
    for (size_t i = 0; i < seed_count_of(which); ++i) {
        const uint8_t *d = reinterpret_cast<const uint8_t *>(seeds[i]);
        const size_t len = std::strlen(seeds[i]);
        for (size_t n = 0; n <= len; ++n) check_input(which, d, n);
    }
}

/**
 * @brief
 * \~english Seeds with bytes changed, inserted and taken out.
 * \~spanish Semillas con bytes cambiados, metidos y quitados.
 * \~
 */
void test_mutations(Reader which, uint64_t seed_value, int rounds) {
    Rng rng(seed_value);
    uint8_t buf[512];

    const char *const *seeds = seeds_of(which);
    const size_t count = seed_count_of(which);

    for (int round = 0; round < rounds; ++round) {
        const char *seed = seeds[rng.below(static_cast<uint32_t>(count))];
        size_t len = std::strlen(seed);
        if (len > sizeof(buf)) len = sizeof(buf);
        std::memcpy(buf, seed, len);

        const uint32_t edits = 1 + rng.below(4);
        for (uint32_t e = 0; e < edits; ++e) {
            if (len == 0) break;
            const uint32_t what = rng.below(3);
            const size_t at = rng.below(static_cast<uint32_t>(len));

            if (what == 0) {
                /* \~english Change one.  \~spanish Cambiar uno.  \~ */
                buf[at] = rng.below(2) == 0
                              ? kInteresting[rng.below(kInterestingCount)]
                              : static_cast<uint8_t>(rng.next());
            } else if (what == 1 && len < sizeof(buf)) {
                /* \~english Put one in.  \~spanish Meter uno.  \~ */
                std::memmove(buf + at + 1, buf + at, len - at);
                buf[at] = kInteresting[rng.below(kInterestingCount)];
                ++len;
            } else {
                /* \~english Take one out.  \~spanish Quitar uno.  \~ */
                std::memmove(buf + at, buf + at + 1, len - at - 1);
                --len;
            }
        }

        check_input(which, buf, len);
        if (failures > 4) return;
    }
}

/**
 * @brief
 * \~english Bytes with no message behind them at all.
 * \~spanish Bytes sin ningun mensaje detras.
 * \~
 */
void test_noise(Reader which, uint64_t seed_value, int rounds) {
    Rng rng(seed_value);
    uint8_t buf[256];

    for (int round = 0; round < rounds; ++round) {
        const size_t len = rng.below(sizeof(buf) + 1);
        for (size_t i = 0; i < len; ++i) {
            buf[i] = rng.below(3) == 0
                         ? kInteresting[rng.below(kInterestingCount)]
                         : static_cast<uint8_t>(rng.next());
        }
        check_input(which, buf, len);
        if (failures > 4) return;
    }
}

} // namespace

int main() {
    /* \~english
     * Each reader gets its own seeds and its own stream of numbers.  Sharing
     * one stream would make the second reader's inputs depend on how many the
     * first one took, so adding a case to one of them would silently change
     * every input the other sees -- and a property test whose coverage moves
     * when an unrelated case is added cannot say what it has covered.
     *
     * \~spanish
     * Cada lector tiene sus semillas y su propia tirada de numeros.  Compartir
     * una haria que las entradas del segundo dependieran de cuantas cogiera el
     * primero, asi que anadir un caso a uno cambiaria calladamente todas las
     * entradas que ve el otro -- y una prueba de propiedades cuya cobertura se
     * mueve al anadir un caso que no tiene que ver no puede decir que ha
     * cubierto.
     * \~ */
    test_the_seeds(Reader::Head);
    test_every_prefix(Reader::Head);
    test_mutations(Reader::Head, 0x9E3779B97F4A7C15ull, 20000);
    test_noise(Reader::Head, 0xD1B54A32D192ED03ull, 5000);

    test_the_seeds(Reader::Body);
    test_every_prefix(Reader::Body);
    test_mutations(Reader::Body, 0xBF58476D1CE4E5B9ull, 20000);
    test_noise(Reader::Body, 0x94D049BB133111EBull, 5000);

    if (failures != 0) {
        std::fprintf(stderr, "test_h1_fuzz: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h1_fuzz: ok\n");
    return 0;
}
