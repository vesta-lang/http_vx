/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file bench/main.cpp
 * @brief
 * \~english What the project promises, measured instead of claimed.
 * \~spanish Lo que promete el proyecto, medido en vez de afirmado.
 * \~
 *
 * \~english
 * Four numbers, and each one answers a requirement rather than flattering the
 * code.  A benchmark that measured whatever was easy would be a benchmark that
 * gets faster while the thing it was built for gets worse.
 *
 *  - **how fast** a request is served, end to end;
 *  - **whether cutting the input up costs anything** -- R12 says the parser
 *    walks each byte once with no backtracking, and a parser that backtracks
 *    is not merely slow, it is quadratic against an input chosen to provoke
 *    it.  That makes this the only measurement here that is about SECURITY:
 *    what it looks for is not a big number but a FLAT one;
 *  - **how many system calls a request costs** -- R15 says a simple request
 *    should be one read and one write, and that is counted rather than timed
 *    because a count cannot be noisy;
 *  - **how many bytes a connection holds** -- R1 and R2, which is the number
 *    a server promising a million connections has to be able to show.
 *
 * Every result carries a machine and a date, because a measurement without
 * them compares with nothing.
 *
 * \~spanish
 * Cuatro numeros, y cada uno contesta a un requisito en vez de halagar al
 * codigo.  Un banco que midiera lo que sea facil seria un banco que mejora
 * mientras empeora aquello para lo que se hizo.
 *
 *  - **cuanto se tarda** en servir una peticion, de punta a punta;
 *  - **si partir la entrada cuesta algo** -- la R12 dice que el analizador
 *    recorre cada byte una vez sin retroceder, y uno que retrocede no es solo
 *    lento, es cuadratico ante una entrada elegida para provocarlo.  Eso hace
 *    que esta sea la unica medida de aqui que va de SEGURIDAD: lo que busca no
 *    es un numero grande sino uno PLANO;
 *  - **cuantas llamadas al sistema cuesta una peticion** -- la R15 dice que una
 *    sencilla deberia ser una lectura y una escritura, y eso se CUENTA en vez
 *    de cronometrarse porque una cuenta no tiene ruido;
 *  - **cuantos bytes tiene una conexion** -- la R1 y la R2, que es el numero que
 *    tiene que poder ensenar un servidor que promete un millon.
 *
 * Todo resultado lleva maquina y fecha, porque una medida sin ellas no se
 * compara con nada.
 *
 * \~
 */

#include "http_vx/http1_service.h"
#include "http_vx/memory_backend.h"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace {

using Clock = std::chrono::steady_clock;

/**
 * @brief
 * \~english A backend that counts what was asked of the operating system.
 * \~spanish Un backend que cuenta lo que se le pidio al sistema operativo.
 * \~
 *
 * \~english
 * It delegates every operation, so what is being measured is the real path.
 * Counting here rather than inside @c MemoryBackend keeps the counter out of
 * the code that ships: a number nobody reads in production is a number that
 * costs something in production.
 *
 * \~spanish
 * Delega todas las operaciones, asi que lo que se mide es el camino de verdad.
 * Contar aqui y no dentro de @c MemoryBackend deja el contador fuera del codigo
 * que se publica: un numero que no lee nadie en produccion es un numero que
 * cuesta algo en produccion.
 *
 * \~
 */
class Counted final : public http_vx::Backend {
  public:
    explicit Counted(http_vx::BufferPool &pool) noexcept : inner_(pool) {}

    bool submit(const http_vx::Op &op) noexcept override {
        if (!inner_.submit(op)) return false;

        if (op.kind == http_vx::OpKind::Recv) ++reads;
        if (op.kind == http_vx::OpKind::Send) ++writes;
        return true;
    }

    size_t wait(http_vx::Completion *done, size_t cap,
                int timeout_ms) noexcept override {
        return inner_.wait(done, cap, timeout_ms);
    }

    const char *name() const noexcept override { return "counted"; }

    http_vx::MemoryBackend &inner() noexcept { return inner_; }

    size_t reads = 0;
    size_t writes = 0;

  private:
    http_vx::MemoryBackend inner_;
};

/**
 * @brief
 * \~english The smallest handler that is still one.
 * \~spanish El manejador mas pequeno que sigue siendolo.
 * \~
 */
class Fixed final : public http_vx::Handler {
  public:
    void handle(const http_vx::Request &req, const uint8_t *head,
                const uint8_t *body, size_t n,
                http_vx::ResponseBuilder &res) noexcept override {
        (void)req;
        (void)head;
        (void)body;
        (void)n;
        ++served;

        res.status(200);
        res.field(http_vx::FieldId::ContentType, "text/plain", 10);
        res.body("ok\n", 3);
    }

    size_t served = 0;
};

/**
 * @brief
 * \~english A server, assembled the way the runnable one is.
 * \~spanish Un servidor, montado como el que se ejecuta.
 * \~
 */
struct Rig {
    Fixed handler;
    http_vx::Http1Service service;
    http_vx::Shard shard;
    Counted io;

    explicit Rig(uint32_t connections, uint32_t buffers)
        : io(shard.buffers()) {
        http_vx::h1::Limits h1;
        service.reset(connections, handler, h1);

        http_vx::ShardConfig cfg;
        cfg.connections = connections;
        cfg.buffers = buffers;
        cfg.idle_ticks = 60;
        cfg.wheel_slots = 4096;
        shard.reset(cfg, io, service, 0);
    }
};

const char *kRequest = "GET /bench HTTP/1.1\r\nHost: example.com\r\n"
                       "user-agent: http_vx-bench\r\n"
                       "accept: */*\r\n\r\n";

/**
 * @brief
 * \~english Serves @p rounds requests and says how long each took.
 * \~spanish Sirve @p rounds peticiones y dice cuanto tardo cada una.
 * \~
 *
 * \~english
 * The bytes are fed in @p pieces, which is what turns this one function into
 * both the speed measurement and the one about cutting the input up: the same
 * work split more ways should cost the same, and a parser that backtracked
 * would make it cost more every time the number goes up.
 *
 * \~spanish
 * Los bytes se dan en @p pieces trozos, que es lo que convierte esta funcion en
 * la medida de velocidad Y en la de partir la entrada: el mismo trabajo repartido
 * en mas trozos deberia costar lo mismo, y un analizador que retrocediera lo
 * haria costar mas cada vez que sube el numero.
 *
 * \~
 */
double serve_many(size_t rounds, size_t pieces, size_t *served,
                  size_t *reads, size_t *writes) {
    Rig rig(8, 8);

    const http_vx::ConnHandle c = rig.shard.adopt(7, 0);
    if (!c.valid()) return 0.0;

    const size_t n = std::strlen(kRequest);
    const size_t each = n / pieces == 0 ? 1 : n / pieces;

    const Clock::time_point start = Clock::now();

    for (size_t r = 0; r < rounds; ++r) {
        size_t at = 0;
        while (at < n) {
            const size_t take = n - at < each ? n - at : each;
            rig.io.inner().feed(
                reinterpret_cast<const uint8_t *>(kRequest) + at, take);
            at += take;

            /* \~english
             * Driven after every piece, which is what a reactor does: the
             * bytes arrive when they arrive and the loop runs on each of
             * them.  Feeding it all and running once would measure a case
             * that does not happen.
             * \~spanish
             * Se mueve despues de cada trozo, que es lo que hace un reactor: los
             * bytes llegan cuando llegan y el bucle corre con cada uno.  Darlo
             * todo y correr una vez mediria un caso que no ocurre.
             * \~ */
            for (int i = 0; i < 4; ++i) rig.shard.poll(1, 0);
        }
    }

    const Clock::time_point end = Clock::now();

    if (served != nullptr) *served = rig.handler.served;
    if (reads != nullptr) *reads = rig.io.reads;
    if (writes != nullptr) *writes = rig.io.writes;

    return std::chrono::duration<double>(end - start).count();
}

/**
 * @brief
 * \~english What a connection holds when it has nothing to say.
 * \~spanish Lo que tiene una conexion cuando no tiene nada que decir.
 * \~
 *
 * \~english
 * Worked out from the structures rather than asked of the allocator, because
 * what is wanted is what a connection COSTS and not what the heap happens to
 * have rounded it up to.  The buffers are measured and not computed: whether
 * an idle connection holds one is R1, and computing it would be assuming the
 * answer.
 *
 * \~spanish
 * Se saca de las estructuras y no se le pregunta al asignador, porque lo que se
 * quiere es lo que CUESTA una conexion y no a lo que el monticulo lo haya
 * redondeado.  Los buffers se miden y no se calculan: si una conexion parada
 * tiene uno es la R1, y calcularlo seria dar por hecha la respuesta.
 *
 * \~
 */
void report_memory(const char *tag) {
    const uint32_t kConnections = 1024;

    Rig rig(kConnections, 64);

    for (uint32_t i = 0; i < kConnections; ++i) {
        const http_vx::ConnHandle c =
            rig.shard.adopt(static_cast<int32_t>(100 + i), 0);
        if (!c.valid()) break;
    }

    const size_t fixed_per_conn =
        sizeof(http_vx::ConnHot) + sizeof(http_vx::ConnCold) +
        sizeof(uint32_t) /* la casilla libre */ +
        12 /* la entrada del plazo */;

    const size_t held = rig.shard.buffers().bytes_held();
    const size_t lent = rig.shard.buffers().lent();

    std::printf("\n  memoria por conexion (%s)\n", tag);
    std::printf("    %-34s %8zu B\n", "registro caliente",
                sizeof(http_vx::ConnHot));
    std::printf("    %-34s %8zu B\n", "registro frio",
                sizeof(http_vx::ConnCold));
    std::printf("    %-34s %8zu B\n", "plazo + casilla libre",
                sizeof(uint32_t) + 12);
    std::printf("    %-34s %8zu B\n", "FIJO POR CONEXION", fixed_per_conn);
    std::printf("    %-34s %8.1f MB\n", "un millon de conexiones",
                static_cast<double>(fixed_per_conn) * 1000000.0 /
                    (1024.0 * 1024.0));

    std::printf("    %-34s %8zu B\n", "bytes en el pozo", held);

    /* \~english
     * And the finding this measurement exists to make.  R1 says an idle
     * connection has no buffer, and on a COMPLETION interface that is not
     * free: to notice that anything arrived at all, a read has to be
     * outstanding, and a read names the buffer the kernel will write into.  So
     * a connection that has said nothing since it arrived is holding one.
     *
     * At sixteen kilobytes and a million connections that is sixteen
     * gigabytes, which is exactly the number R1 exists to prevent.
     *
     * The answer is not to change the interface: it is the zero-length read
     * that both real backends have for this -- IOCP's zero-byte receive, and
     * io_uring's provided buffers.  A read of nothing completes when there is
     * something, and only THEN is a buffer taken.  Neither backend is written
     * yet, so the number below is what it would be today and is printed rather
     * than explained away.
     *
     * \~spanish
     * Y el hallazgo para el que existe esta medida.  La R1 dice que una conexion
     * parada no tiene buffer, y en una interfaz por FINALIZACION eso no sale
     * gratis: para enterarse siquiera de que llego algo tiene que haber una
     * lectura pendiente, y una lectura nombra el buffer en el que escribira el
     * nucleo.  Asi que una conexion que no ha dicho nada desde que llego tiene
     * uno.
     *
     * A dieciseis kilobytes y un millon de conexiones eso son dieciseis
     * gigabytes, que es exactamente el numero que la R1 existe para evitar.
     *
     * La respuesta no es cambiar la interfaz: es la lectura de longitud cero que
     * los dos backends de verdad tienen para esto -- la recepcion de cero bytes
     * de IOCP, y los buffers provistos de io_uring --.  Una lectura de nada
     * acaba cuando hay algo, y solo ENTONCES se coge un buffer.  Ninguno de los
     * dos backends esta escrito todavia, asi que el numero de abajo es el que
     * seria hoy y se imprime en vez de explicarse.
     * \~ */
    std::printf("\n    conexiones adoptadas %zu, buffers prestados %zu\n",
                static_cast<size_t>(rig.shard.conns().count()), lent);
    std::printf("    en una interfaz por FINALIZACION, una conexion parada\n"
                "    tiene un buffer: para enterarse de que llega algo hace\n"
                "    falta una lectura pendiente, y una lectura nombra el\n"
                "    buffer.  A 16 KB y un millon, 16 GB -- que es lo que la\n"
                "    R1 existe para evitar.  Lo arregla la lectura de LONGITUD\n"
                "    CERO (recepcion de cero bytes de IOCP, buffers provistos\n"
                "    de io_uring): acaba cuando hay algo, y solo entonces se\n"
                "    coge buffer.  Falta, y por eso sale aqui.\n");
}

/**
 * @brief
 * \~english How much slower the same work gets when it is cut up.
 * \~spanish Cuanto mas lento va el mismo trabajo cuando se parte.
 * \~
 */
/**
 * @brief
 * \~english How much slower one head gets when it is delivered in @p pieces.
 * \~spanish Cuanto mas lenta va una cabeza cuando se entrega en @p pieces trozos.
 * \~
 */
double slicing_cost(const char *head, size_t rounds, size_t pieces) {
    const size_t n = std::strlen(head);
    const size_t each = n / pieces == 0 ? 1 : n / pieces;

    const Clock::time_point start = Clock::now();
    size_t done = 0;

    for (size_t r = 0; r < rounds; ++r) {
        http_vx::h1::RequestParser parser;
        http_vx::Request req;

        size_t have = 0;
        while (have < n) {
            const size_t take = n - have < each ? n - have : each;
            have += take;

            if (parser.parse(reinterpret_cast<const uint8_t *>(head), have,
                             req) == http_vx::h1::ParseResult::Done)
                ++done;
        }
    }

    const Clock::time_point end = Clock::now();
    if (done == 0) return 0.0;

    return std::chrono::duration<double>(end - start).count();
}

/**
 * @brief
 * \~english A head with @p extra fields, built once.
 * \~spanish Una cabeza con @p extra cabeceras, construida una vez.
 * \~
 */
const char *big_head(char *into, size_t cap, size_t extra) {
    size_t at = 0;
    at += static_cast<size_t>(
        std::snprintf(into + at, cap - at, "GET /bench HTTP/1.1\r\nHost: a\r\n"));

    for (size_t i = 0; i < extra && cap - at > 64; ++i)
        at += static_cast<size_t>(std::snprintf(
            into + at, cap - at, "x-filler-%03zu: 0123456789abcdef\r\n", i));

    std::snprintf(into + at, cap - at, "\r\n");
    return into;
}

void report_slicing(const char *tag) {
    const size_t kRounds = 200000;

    /* \~english
     * The column heads say what the numbers ARE.  The first version called
     * one of them just "seconds", and it is the total for two hundred thousand
     * heads -- which somebody read as the time for one request, and would have
     * been right to, because that is what the word says.  A number whose units
     * have to be worked out from somewhere else is a number that will be read
     * wrong.
     * \~spanish
     * Las cabeceras de columna dicen lo que SON los numeros.  La primera version
     * llamaba a una de ellas "segundos" a secas, y es el total de doscientas mil
     * cabeceras -- que alguien leyo como el tiempo de una peticion, y con razon,
     * porque es lo que dice la palabra.  Un numero cuyas unidades hay que sacar
     * de otro sitio es un numero que se va a leer mal.
     * \~ */
    std::printf("\n  partir la entrada (%s) -- R12: sin retroceso\n", tag);
    std::printf("    (cada fila analiza la MISMA cabeza %zu veces, entregada\n"
                "     en mas o menos trozos)\n",
                kRounds);
    std::printf("    %-10s %14s %12s %10s\n", "trozos", "seg (las 200k)",
                "cab/s", "vs 1 trozo");

    double first = 0.0;

    for (size_t pieces : {size_t(1), size_t(2), size_t(4), size_t(8),
                          size_t(16), size_t(32)}) {
        const size_t n = std::strlen(kRequest);
        const size_t each = n / pieces == 0 ? 1 : n / pieces;

        const Clock::time_point start = Clock::now();
        size_t done = 0;

        for (size_t r = 0; r < kRounds; ++r) {
            /* \~english
             * The PARSER on its own, with no loop, no buffers and no
             * completions around it.  The first version of this measurement
             * drove the whole server and reported that cutting the input into
             * thirty-two made it forty-six times slower -- which was mostly
             * the harness turning the loop thirty-two times as often, and said
             * nothing at all about whether the parser goes back.
             *
             * What R12 is about is exactly one thing: does the same head cost
             * more when it is delivered in more pieces.  So that is the only
             * thing in the timer.
             *
             * \~spanish
             * El ANALIZADOR solo, sin bucle, sin buffers y sin finalizaciones
             * alrededor.  La primera version de esta medida movia el servidor
             * entero e informaba de que partir la entrada en treinta y dos lo
             * hacia cuarenta y seis veces mas lento -- que era sobre todo el
             * banco dando treinta y dos veces mas vueltas al bucle, y no decia
             * absolutamente nada de si el analizador vuelve atras.
             *
             * La R12 va de una sola cosa: cuesta mas la misma cabeza cuando se
             * entrega en mas trozos.  Asi que es lo unico que hay en el reloj.
             * \~ */
            http_vx::h1::RequestParser parser;
            http_vx::Request req;

            size_t have = 0;
            while (have < n) {
                const size_t take = n - have < each ? n - have : each;
                have += take;

                if (parser.parse(reinterpret_cast<const uint8_t *>(kRequest),
                                 have, req) == http_vx::h1::ParseResult::Done)
                    ++done;
            }
        }

        const Clock::time_point end = Clock::now();
        const double secs = std::chrono::duration<double>(end - start).count();
        if (secs <= 0.0 || done == 0) continue;

        if (first == 0.0) first = secs;

        std::printf("    %-10zu %14.4f %12.0f %9.2fx\n", pieces, secs,
                    static_cast<double>(done) / secs, secs / first);
    }

    /* \~english
     * What to look at is the last column.  Flat is the requirement met; a
     * number that climbs with the pieces is a parser that starts over, and
     * that is quadratic against somebody who sends a request one byte at a
     * time on purpose.
     * \~spanish
     * Lo que hay que mirar es la ultima columna.  Plana es el requisito
     * cumplido; un numero que sube con los trozos es un analizador que vuelve a
     * empezar, y eso es cuadratico contra alguien que mande una peticion byte a
     * byte a proposito.
     * \~ */
    /* \~english
     * That column is not flat and it does not have to be: thirty-two calls
     * cost thirty-two calls' worth of setting up, and that is linear in the
     * pieces and unavoidable.  What R12 forbids is the OTHER growth, and the
     * two are told apart by asking the same question of a bigger head.
     *
     * A parser that resumes reads each byte once whatever the pieces, so its
     * ratio is per-call overhead over the work -- and the work grows with the
     * head while the overhead does not, so the ratio goes DOWN.  A parser that
     * started over would read the first piece thirty-two times, and that grows
     * WITH the head: the ratio would go up, and keep going up.
     *
     * \~spanish
     * Esa columna no es plana y no tiene por que serlo: treinta y dos llamadas
     * cuestan treinta y dos preparaciones, y eso es lineal en los trozos e
     * inevitable.  Lo que prohibe la R12 es el OTRO crecimiento, y los dos se
     * distinguen haciendole la misma pregunta a una cabeza mayor.
     *
     * Un analizador que reanuda lee cada byte una vez sean los trozos que sean,
     * asi que su proporcion es el coste fijo por llamada partido por el trabajo
     * -- y el trabajo crece con la cabeza y el coste fijo no, asi que la
     * proporcion BAJA.  Uno que volviera a empezar leeria el primer trozo
     * treinta y dos veces, y eso crece CON la cabeza: la proporcion subiria, y
     * seguiria subiendo.
     * \~ */
    char big[8192];
    big_head(big, sizeof big, 40);

    const double big_one = slicing_cost(big, 20000, 1);
    const double big_many = slicing_cost(big, 20000, 32);

    std::printf("\n    la misma pregunta a una cabeza %zu veces mayor:\n",
                std::strlen(big) / std::strlen(kRequest));
    std::printf("    %-10s %14s %12s %10s\n", "trozos", "seg (las 20k)",
                "cab/s", "vs 1 trozo");
    std::printf("    %-10d %14.4f %12.0f %9.2fx\n", 1, big_one,
                20000.0 / big_one, 1.0);
    std::printf("    %-10d %14.4f %12.0f %9.2fx\n", 32, big_many,
                20000.0 / big_many, big_many / big_one);

    std::printf("\n    la proporcion de la cabeza GRANDE debe ser MENOR o igual\n"
                "    que la de la pequena.  Si es mayor, el analizador\n"
                "    vuelve a empezar, y eso es cuadratico contra quien mande\n"
                "    una peticion byte a byte a proposito.\n");
}

/**
 * @brief
 * \~english How many operations one request costs.
 * \~spanish Cuantas operaciones cuesta una peticion.
 * \~
 */
void report_syscalls(const char *tag) {
    /* \~english
     * Few rounds on purpose.  The memory backend keeps what it wrote so a test
     * can look at it, so a long run fills that room and the writes start
     * coming back short -- and a short write is answered with another write,
     * which would show up here as a server that needs two where it needs one.
     * The count would be of the harness, not of the server.
     * \~spanish
     * Pocas rondas a proposito.  El backend de memoria se guarda lo que
     * escribio para que una prueba pueda mirarlo, asi que una corrida larga
     * llena ese sitio y las escrituras empiezan a volver cortas -- y una
     * escritura corta se contesta con otra escritura, que aqui saldria como un
     * servidor que necesita dos donde necesita una.  La cuenta seria del banco,
     * no del servidor.
     * \~ */
    const size_t kRounds = 400;

    size_t served = 0;
    size_t reads = 0;
    size_t writes = 0;
    serve_many(kRounds, 1, &served, &reads, &writes);

    if (served == 0) return;

    std::printf("\n  llamadas por peticion (%s) -- R15\n", tag);
    std::printf("    %-34s %8.2f\n", "lecturas",
                static_cast<double>(reads) / static_cast<double>(served));
    std::printf("    %-34s %8.2f\n", "escrituras",
                static_cast<double>(writes) / static_cast<double>(served));
    std::printf("    una peticion sencilla deberia ser una y una\n");
}

/**
 * @brief
 * \~english Serving, with nothing in the way.
 * \~spanish Servir, sin nada de por medio.
 * \~
 */
void report_speed(const char *tag) {
    /* \~english
     * A batch that fits in what the backend keeps.  It holds everything it
     * wrote so a test can look at it, so a longer run fills that room and the
     * writes start failing -- which would be measuring the harness giving up,
     * not the server working.  Each round builds a fresh one, so three rounds
     * of this is three honest runs.
     * \~spanish
     * Un lote que cabe en lo que se guarda el backend.  Se queda todo lo que
     * escribio para que una prueba pueda mirarlo, asi que una corrida mas larga
     * llena ese sitio y las escrituras empiezan a fallar -- que seria medir al
     * banco rindiendose, no al servidor funcionando.  Cada ronda hace uno
     * nuevo, asi que tres rondas de esto son tres corridas honestas.
     * \~ */
    const size_t kRounds = 900;

    /* \~english
     * Three rounds and the best is kept, which is the honest statistic for a
     * measurement whose noise is one-sided: nothing makes a machine faster
     * than it is, so the fastest run is the one with the least interference.
     * An average would be an average of this machine's interruptions.
     * \~spanish
     * Tres rondas y se guarda la mejor, que es el estadistico honesto para una
     * medida cuyo ruido va en un solo sentido: nada hace a una maquina mas
     * rapida de lo que es, asi que la corrida mas rapida es la que tuvo menos
     * estorbos.  Una media seria una media de las interrupciones de esta
     * maquina.
     * \~ */
    double best = 0.0;
    size_t served = 0;

    for (int round = 0; round < 3; ++round) {
        size_t got = 0;
        const double secs = serve_many(kRounds, 1, &got, nullptr, nullptr);
        if (secs <= 0.0 || got == 0) continue;

        const double rate = static_cast<double>(got) / secs;
        if (rate > best) {
            best = rate;
            served = got;
        }
    }

    std::printf("\n  servir (%s)\n", tag);
    std::printf("    %-34s %8zu\n", "peticiones por ronda", served);
    std::printf("    %-34s %8.0f\n", "peticiones por segundo", best);
    std::printf("    %-34s %8.0f ns\n", "por peticion",
                best > 0.0 ? 1e9 / best : 0.0);
}

} // namespace

/**
 * @brief
 * \~english Measures and prints, tagged by machine.
 * \~spanish Mide e imprime, etiquetado por maquina.
 * \~
 *
 * @param argc \~english how many arguments  \~spanish cuantos argumentos  \~
 * @param argv \~english the machine tag, if one was given
 *             \~spanish la etiqueta de la maquina, si se dio  \~
 * @return     \~english zero  \~spanish cero  \~
 */
int main(int argc, char **argv) {
    /* \~english
     * The tag is asked for and not guessed.  There is no portable way to ask a
     * machine what it is, and a benchmark that made one up would produce
     * results that all look comparable and are not.
     * \~spanish
     * La etiqueta se pide y no se adivina.  No hay forma portable de preguntarle
     * a una maquina que es, y un banco que se la inventara produciria resultados
     * que parecen comparables todos y no lo son.
     * \~ */
    const char *tag = argc > 1 ? argv[1] : "sin-etiqueta";

    std::printf("http_vx -- medidas\n");
    std::printf("  maquina: %s\n", tag);
    std::printf("  fecha:   %s\n", __DATE__);
    std::printf("  guardar en bench/baseline/<maquina>.txt\n");

    report_speed(tag);
    report_syscalls(tag);
    report_slicing(tag);
    report_memory(tag);

    std::printf("\n");
    return 0;
}
