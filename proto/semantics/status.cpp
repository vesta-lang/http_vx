/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/semantics/status.cpp
 * @brief
 * \~english The reason phrases, and the body rule.
 * \~spanish Las frases de motivo, y la regla del cuerpo.
 * \~
 *
 * \~english
 * The codes are sparse -- a hundred values of range hold sixty-one registered
 * codes -- so the table is not indexed by the code the way the field and
 * method tables are indexed by their identifier.  It is sorted and searched by
 * halves, six comparisons at most.
 *
 * Which puts a precondition on the table: sorted, and without repeats.  A row
 * inserted in the wrong place does not fail to build and does not fail to
 * answer -- it answers that a code is unknown when it is in the table, three
 * rows below where the search stopped looking.  So the order is checked at
 * build time, and getting it wrong is a compiler error rather than a phrase
 * that quietly goes missing.
 *
 * \~spanish
 * Los codigos son dispersos -- cien valores de rango contienen sesenta y un
 * codigos registrados --, asi que la tabla no se indexa por el codigo como las
 * de cabeceras y metodos se indexan por su identificador.  Esta ordenada y se
 * busca por mitades, seis comparaciones como mucho.
 *
 * Lo que le pone una condicion previa a la tabla: ordenada, y sin repetidos.
 * Una fila metida en el sitio equivocado no falla al construir y no falla al
 * contestar -- contesta que un codigo es desconocido cuando esta en la tabla,
 * tres filas por debajo de donde la busqueda dejo de mirar.  Asi que el orden
 * se comprueba al construir, y errarlo es un error del compilador y no una
 * frase que desaparece sin decir nada.
 *
 * \~
 */

#include "http_vx/status.h"

namespace http_vx {
namespace {

/**
 * @brief
 * \~english One row: the code and its reason phrase.
 * \~spanish Una fila: el codigo y su frase de motivo.
 * \~
 */
struct StatusRow {
    StatusCode code;
    const char *reason;
    uint8_t len;
};

/**
 * @brief
 * \~english Builds a row measuring the literal at compile time.
 * \~spanish Construye una fila midiendo el literal al compilar.
 * \~
 */
template <size_t N>
constexpr StatusRow row(StatusCode code, const char (&text)[N]) {
    return StatusRow{code, text, static_cast<uint8_t>(N - 1)};
}

/**
 * @brief
 * \~english The registered codes, in order.
 * \~spanish Los codigos registrados, en orden.
 * \~
 *
 * \~english
 * The phrases are the ones RFC 9110 registers, including the two it renamed:
 * `413` is "Content Too Large" and no longer "Payload Too Large", and `422` is
 * "Unprocessable Content" and no longer "Unprocessable Entity".  The old names
 * are still what most implementations write, which is precisely why they are
 * worth naming here: the phrase is prose for a human and carries no meaning on
 * the wire, so there is nothing to be gained by lagging behind the register.
 *
 * The gaps are not oversights.  `306` was defined and withdrawn, `418` is
 * reserved as a joke that never became a status, and neither is something a
 * server should answer.
 *
 * \~spanish
 * Las frases son las que registra el RFC 9110, incluidas las dos que renombro:
 * `413` es "Content Too Large" y ya no "Payload Too Large", y `422` es
 * "Unprocessable Content" y ya no "Unprocessable Entity".  Los nombres viejos
 * siguen siendo lo que escriben casi todas las implementaciones, que es justo
 * la razon de nombrarlos aqui: la frase es prosa para una persona y no
 * significa nada en el cable, asi que no se gana nada yendo por detras del
 * registro.
 *
 * Los huecos no son descuidos.  `306` se definio y se retiro, `418` esta
 * reservado como una broma que nunca llego a ser un estado, y ninguno de los
 * dos es algo que un servidor deba contestar.
 *
 * \~
 */
constexpr StatusRow kStatuses[] = {
    row(100, "Continue"),
    row(101, "Switching Protocols"),
    row(102, "Processing"),
    row(103, "Early Hints"),

    row(200, "OK"),
    row(201, "Created"),
    row(202, "Accepted"),
    row(203, "Non-Authoritative Information"),
    row(204, "No Content"),
    row(205, "Reset Content"),
    row(206, "Partial Content"),
    row(207, "Multi-Status"),
    row(208, "Already Reported"),
    row(226, "IM Used"),

    row(300, "Multiple Choices"),
    row(301, "Moved Permanently"),
    row(302, "Found"),
    row(303, "See Other"),
    row(304, "Not Modified"),
    row(305, "Use Proxy"),
    row(307, "Temporary Redirect"),
    row(308, "Permanent Redirect"),

    row(400, "Bad Request"),
    row(401, "Unauthorized"),
    row(402, "Payment Required"),
    row(403, "Forbidden"),
    row(404, "Not Found"),
    row(405, "Method Not Allowed"),
    row(406, "Not Acceptable"),
    row(407, "Proxy Authentication Required"),
    row(408, "Request Timeout"),
    row(409, "Conflict"),
    row(410, "Gone"),
    row(411, "Length Required"),
    row(412, "Precondition Failed"),
    row(413, "Content Too Large"),
    row(414, "URI Too Long"),
    row(415, "Unsupported Media Type"),
    row(416, "Range Not Satisfiable"),
    row(417, "Expectation Failed"),
    row(421, "Misdirected Request"),
    row(422, "Unprocessable Content"),
    row(423, "Locked"),
    row(424, "Failed Dependency"),
    row(425, "Too Early"),
    row(426, "Upgrade Required"),
    row(428, "Precondition Required"),
    row(429, "Too Many Requests"),
    row(431, "Request Header Fields Too Large"),
    row(451, "Unavailable For Legal Reasons"),

    row(500, "Internal Server Error"),
    row(501, "Not Implemented"),
    row(502, "Bad Gateway"),
    row(503, "Service Unavailable"),
    row(504, "Gateway Timeout"),
    row(505, "HTTP Version Not Supported"),
    row(506, "Variant Also Negotiates"),
    row(507, "Insufficient Storage"),
    row(508, "Loop Detected"),
    row(510, "Not Extended"),
    row(511, "Network Authentication Required"),
};

constexpr size_t kCount = sizeof(kStatuses) / sizeof(kStatuses[0]);

/**
 * @brief
 * \~english Whether the table is strictly increasing by code.
 * \~spanish Si la tabla es estrictamente creciente por codigo.
 * \~
 *
 * \~english
 * Strictly, so it rules out a repeat as well as a swap.  A repeated code would
 * give two phrases for one status and the search would return whichever half
 * it landed in, which is a result that changes with the size of the table.
 *
 * \~spanish
 * Estrictamente, asi que descarta tanto un repetido como un cambio de orden.
 * Un codigo repetido daria dos frases para un estado y la busqueda devolveria
 * la de la mitad en la que cayera, que es un resultado que cambia con el tamano
 * de la tabla.
 *
 * \~
 */
constexpr bool codes_are_sorted() noexcept {
    for (size_t i = 1; i < kCount; ++i)
        if (kStatuses[i - 1].code >= kStatuses[i].code) return false;
    return true;
}

static_assert(codes_are_sorted(),
              "the status table must be sorted by code and have no repeats: "
              "the search halves it, and an out-of-place row answers that a "
              "registered code is unknown");

/**
 * @brief
 * \~english Finds the row for @p code, or null.
 * \~spanish Encuentra la fila de @p code, o nulo.
 * \~
 */
const StatusRow *find_row(StatusCode code) noexcept {
    size_t lo = 0;
    size_t hi = kCount;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const StatusCode c = kStatuses[mid].code;
        if (c == code) return &kStatuses[mid];
        if (c < code)
            lo = mid + 1;
        else
            hi = mid;
    }
    return nullptr;
}

} // namespace

const char *status_reason(StatusCode code) noexcept {
    const StatusRow *r = find_row(code);
    return r != nullptr ? r->reason : "";
}

uint8_t status_reason_len(StatusCode code) noexcept {
    const StatusRow *r = find_row(code);
    return r != nullptr ? r->len : uint8_t{0};
}

bool response_can_have_body(MethodId method, StatusCode code) noexcept {
    /* \~english
     * The method first, because it is the rule that holds whatever the status
     * is: a response to HEAD is written like the one to GET and then stops.
     * \~spanish
     * El metodo primero, porque es la regla que vale sea cual sea el estado:
     * una respuesta a HEAD se escribe como la de GET y entonces se para.
     * \~ */
    if (method_forbids_response_body(method)) return false;

    const StatusClass cls = status_class(code);

    /* \~english
     * Then the three statuses that never carry one.  A 1xx is interim -- the
     * real response is still coming -- and 204 and 304 say in themselves that
     * there is nothing to send.
     * \~spanish
     * Despues los tres estados que nunca llevan.  Un 1xx es provisional -- la
     * respuesta de verdad todavia esta por llegar -- y el 204 y el 304 dicen de
     * por si que no hay nada que mandar.
     * \~ */
    if (cls == StatusClass::Informational) return false;
    if (code == status::kNoContent || code == status::kNotModified)
        return false;

    /* \~english
     * And the tunnel.  A CONNECT that succeeded has handed the connection to
     * whoever is at the far end, so anything written after the fields would be
     * bytes of the tunnel and not of the response.
     * \~spanish
     * Y el tunel.  Un CONNECT que triunfo ha entregado la conexion a quien este
     * al otro extremo, asi que lo que se escribiera tras las cabeceras serian
     * bytes del tunel y no de la respuesta.
     * \~ */
    if (method == MethodId::Connect && cls == StatusClass::Successful)
        return false;

    return true;
}

} // namespace http_vx
