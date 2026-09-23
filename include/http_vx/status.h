/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/status.h
 * @brief
 * \~english The response status code, and what it decides about the body.
 * \~spanish El codigo de estado de una respuesta, y lo que decide del cuerpo.
 * \~
 *
 * \~english
 * A status code is **not** an enumeration here, and that is the difference from
 * @c FieldId and @c MethodId.  Those two are identifiers the project assigns,
 * whose numbers are an implementation detail; a status code is the number that
 * travels on the wire, and any three-digit number is legal.  A server is
 * entitled to answer `599`, and an enumeration would suggest that the set is
 * closed when the specification says in as many words that it is not.
 *
 * So the type is the number, the well-known codes are names for numbers, and
 * the interesting operations are the two that a recipient must get right:
 *
 *  - **what class it belongs to**, because RFC 9110 section 15 requires an
 *    unrecognised code to be handled as the x00 of its class -- a `499` is a
 *    `400` as far as anyone who does not recognise it is concerned;
 *  - **whether the response has a body**, which is not a question about the
 *    status alone and is the one thing in this file that breaks connections
 *    rather than responses when it is wrong.
 *
 * \~spanish
 * Un codigo de estado **no** es una enumeracion aqui, y esa es la diferencia
 * con @c FieldId y @c MethodId.  Esos dos son identificadores que asigna el
 * proyecto, cuyos numeros son un detalle de implementacion; un codigo de estado
 * es el numero que viaja por el cable, y cualquier numero de tres cifras es
 * legal.  Un servidor tiene derecho a contestar `599`, y una enumeracion
 * sugeriria que el conjunto es cerrado cuando la especificacion dice con todas
 * las letras que no lo es.
 *
 * Asi que el tipo es el numero, los codigos conocidos son nombres para numeros,
 * y las operaciones interesantes son las dos que quien recibe tiene que acertar:
 *
 *  - **a que clase pertenece**, porque el RFC 9110 seccion 15 exige tratar un
 *    codigo no reconocido como el x00 de su clase -- un `499` es un `400` para
 *    cualquiera que no lo reconozca;
 *  - **si la respuesta lleva cuerpo**, que no es una pregunta sobre el estado
 *    solo y es lo unico de este fichero que cuando se yerra rompe la conexion y
 *    no la respuesta.
 *
 * \~
 */
#ifndef HTTP_VX_STATUS_H
#define HTTP_VX_STATUS_H

#include "http_vx/method.h"

#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english A status code, as it travels: three digits.
 * \~spanish Un codigo de estado, tal como viaja: tres cifras.
 * \~
 */
using StatusCode = uint16_t;

/**
 * @brief
 * \~english The class of a status code, which is its first digit.
 * \~spanish La clase de un codigo de estado, que es su primera cifra.
 * \~
 *
 * \~english
 * The class is what a recipient acts on when it does not recognise the code
 * itself, so it is the part of the code that always means something.
 *
 * \~spanish
 * La clase es sobre lo que actua quien recibe cuando no reconoce el codigo, asi
 * que es la parte del codigo que siempre significa algo.
 *
 * \~
 */
enum class StatusClass : uint8_t {
    /// \~english Not a status code at all.  \~spanish Ni siquiera es un codigo de estado.  \~
    Invalid = 0,
    /// \~english 1xx: interim, the request goes on.  \~spanish 1xx: provisional, la peticion sigue.  \~
    Informational = 1,
    /// \~english 2xx: it worked.  \~spanish 2xx: salio bien.  \~
    Successful = 2,
    /// \~english 3xx: look elsewhere.  \~spanish 3xx: mira en otro sitio.  \~
    Redirection = 3,
    /// \~english 4xx: the request was at fault.  \~spanish 4xx: la peticion tenia la culpa.  \~
    ClientError = 4,
    /// \~english 5xx: the server was.  \~spanish 5xx: la tenia el servidor.  \~
    ServerError = 5,
};

/**
 * \~english
 * The registered codes, as names.  They are constants and not an enumeration
 * for the reason at the top of this file: naming a number does not close the
 * set of numbers.
 *
 * \~spanish
 * Los codigos registrados, como nombres.  Son constantes y no una enumeracion
 * por la razon del principio de este fichero: poner nombre a un numero no
 * cierra el conjunto de los numeros.
 * \~
 */
namespace status {

constexpr StatusCode kContinue = 100;
constexpr StatusCode kSwitchingProtocols = 101;
constexpr StatusCode kProcessing = 102;
constexpr StatusCode kEarlyHints = 103;

constexpr StatusCode kOk = 200;
constexpr StatusCode kCreated = 201;
constexpr StatusCode kAccepted = 202;
constexpr StatusCode kNonAuthoritative = 203;
constexpr StatusCode kNoContent = 204;
constexpr StatusCode kResetContent = 205;
constexpr StatusCode kPartialContent = 206;
constexpr StatusCode kMultiStatus = 207;
constexpr StatusCode kAlreadyReported = 208;
constexpr StatusCode kImUsed = 226;

constexpr StatusCode kMultipleChoices = 300;
constexpr StatusCode kMovedPermanently = 301;
constexpr StatusCode kFound = 302;
constexpr StatusCode kSeeOther = 303;
constexpr StatusCode kNotModified = 304;
constexpr StatusCode kUseProxy = 305;
constexpr StatusCode kTemporaryRedirect = 307;
constexpr StatusCode kPermanentRedirect = 308;

constexpr StatusCode kBadRequest = 400;
constexpr StatusCode kUnauthorized = 401;
constexpr StatusCode kPaymentRequired = 402;
constexpr StatusCode kForbidden = 403;
constexpr StatusCode kNotFound = 404;
constexpr StatusCode kMethodNotAllowed = 405;
constexpr StatusCode kNotAcceptable = 406;
constexpr StatusCode kProxyAuthRequired = 407;
constexpr StatusCode kRequestTimeout = 408;
constexpr StatusCode kConflict = 409;
constexpr StatusCode kGone = 410;
constexpr StatusCode kLengthRequired = 411;
constexpr StatusCode kPreconditionFailed = 412;
constexpr StatusCode kContentTooLarge = 413;
constexpr StatusCode kUriTooLong = 414;
constexpr StatusCode kUnsupportedMediaType = 415;
constexpr StatusCode kRangeNotSatisfiable = 416;
constexpr StatusCode kExpectationFailed = 417;
constexpr StatusCode kMisdirectedRequest = 421;
constexpr StatusCode kUnprocessableContent = 422;
constexpr StatusCode kLocked = 423;
constexpr StatusCode kFailedDependency = 424;
constexpr StatusCode kTooEarly = 425;
constexpr StatusCode kUpgradeRequired = 426;
constexpr StatusCode kPreconditionRequired = 428;
constexpr StatusCode kTooManyRequests = 429;
constexpr StatusCode kHeaderFieldsTooLarge = 431;
constexpr StatusCode kUnavailableForLegalReasons = 451;

constexpr StatusCode kInternalServerError = 500;
constexpr StatusCode kNotImplemented = 501;
constexpr StatusCode kBadGateway = 502;
constexpr StatusCode kServiceUnavailable = 503;
constexpr StatusCode kGatewayTimeout = 504;
constexpr StatusCode kVersionNotSupported = 505;
constexpr StatusCode kVariantAlsoNegotiates = 506;
constexpr StatusCode kInsufficientStorage = 507;
constexpr StatusCode kLoopDetected = 508;
constexpr StatusCode kNotExtended = 510;
constexpr StatusCode kNetworkAuthRequired = 511;

} // namespace status

/**
 * @brief
 * \~english Whether @p code is a status code at all.
 * \~spanish Si @p code es siquiera un codigo de estado.
 * \~
 *
 * \~english
 * Three digits, from 100 to 599.  Nothing outside that is a status code, and
 * this is worth checking on the way IN as well as on the way out: a proxy
 * reading `1000` from upstream has read something that is not a response, and
 * accepting it would be forwarding whatever came after it as if it were.
 *
 * \~spanish
 * Tres cifras, de 100 a 599.  Nada fuera de eso es un codigo de estado, y
 * compensa comprobarlo tanto a la ENTRADA como a la salida: un intermediario
 * que lea `1000` del otro lado ha leido algo que no es una respuesta, y
 * aceptarlo seria reenviar lo que viniera detras como si lo fuera.
 *
 * \~
 * @param code \~english the code  \~spanish el codigo  \~
 * @return     \~english true if it is in range  \~spanish true si esta en rango  \~
 */
constexpr bool status_is_valid(StatusCode code) noexcept {
    return code >= 100 && code <= 599;
}

/**
 * @brief
 * \~english The class of @p code.
 * \~spanish La clase de @p code.
 * \~
 * @param code \~english the code  \~spanish el codigo  \~
 * @return     \~english the class, or @c Invalid  \~spanish la clase, o @c Invalid  \~
 */
constexpr StatusClass status_class(StatusCode code) noexcept {
    return status_is_valid(code) ? static_cast<StatusClass>(code / 100)
                                 : StatusClass::Invalid;
}

/**
 * @brief
 * \~english The code to fall back on when @p code is not recognised.
 * \~spanish El codigo al que recurrir cuando @p code no se reconoce.
 * \~
 *
 * \~english
 * RFC 9110 section 15: a recipient that does not understand a status code MUST
 * treat it as the x00 of its class.  It is one division, and it has a name
 * because the rule is easier to see at a call site than the arithmetic is --
 * and because the alternative, refusing what is not recognised, is the mistake
 * the rule exists to prevent.
 *
 * \~spanish
 * RFC 9110 seccion 15: quien recibe y no entiende un codigo de estado DEBE
 * tratarlo como el x00 de su clase.  Es una division, y tiene nombre porque la
 * regla se ve mejor en un sitio de llamada que la aritmetica -- y porque la
 * alternativa, rechazar lo que no se reconoce, es la equivocacion que la regla
 * existe para evitar.
 *
 * \~
 * @param code \~english the code  \~spanish el codigo  \~
 * @return     \~english the x00 of its class, or 0 if it is not valid
 *             \~spanish el x00 de su clase, o 0 si no es valido  \~
 */
constexpr StatusCode status_class_base(StatusCode code) noexcept {
    return status_is_valid(code) ? static_cast<StatusCode>((code / 100) * 100)
                                 : StatusCode{0};
}

/**
 * @brief
 * \~english Whether the response to @p method with @p code carries a body.
 * \~spanish Si la respuesta a @p method con @p code lleva cuerpo.
 * \~
 *
 * \~english
 * This is the whole answer, deliberately.  The method contributes to it and so
 * does the status, and neither half is offered on its own: a caller holding
 * only the status-based rule would answer that a `200` has a body and would be
 * right about every response except the ones to `HEAD`, which is the sort of
 * almost-right that survives testing and breaks in production.
 *
 * Three rules, from RFC 9110 section 6.4.1 and RFC 9112 section 6.3:
 *
 *  - any response to `HEAD` -- the fields are written as for a `GET`,
 *    `Content-Length` included, and then nothing follows;
 *  - `1xx`, `204` and `304`, whatever the method;
 *  - a `2xx` to `CONNECT`, because the tunnel takes the connection over.
 *
 * Everything else may have one, possibly of zero length, which is not the same
 * thing as having none: a zero-length body still means the framing says so.
 *
 * What makes this worth a function rather than a comment is the failure mode.
 * A body written where the peer does not expect one is not read as a body: it
 * is read as the beginning of the next response, and everything after it on
 * that connection is wrong.  A body omitted where one is expected leaves the
 * peer waiting for bytes that will not come.  Both outlive the request.
 *
 * \~spanish
 * Esta es la respuesta entera, a proposito.  Contribuyen el metodo y el estado,
 * y ninguna de las dos mitades se ofrece por separado: quien tuviera solo la
 * regla del estado contestaria que un `200` lleva cuerpo y acertaria en todas
 * las respuestas salvo en las de `HEAD`, que es de los casi-aciertos que
 * sobreviven a las pruebas y se rompen en produccion.
 *
 * Tres reglas, del RFC 9110 seccion 6.4.1 y del RFC 9112 seccion 6.3:
 *
 *  - cualquier respuesta a `HEAD` -- las cabeceras se escriben como las de un
 *    `GET`, `Content-Length` incluido, y despues no va nada;
 *  - `1xx`, `204` y `304`, sea cual sea el metodo;
 *  - un `2xx` a `CONNECT`, porque el tunel se queda con la conexion.
 *
 * Lo demas puede llevarlo, quiza de longitud cero, que no es lo mismo que no
 * llevarlo: un cuerpo de longitud cero sigue queriendo decir que el troceado lo
 * dice.
 *
 * Lo que hace que esto merezca una funcion y no un comentario es su modo de
 * fallo.  Un cuerpo escrito donde el otro extremo no lo espera no se lee como
 * cuerpo: se lee como el principio de la respuesta siguiente, y todo lo que
 * venga despues en esa conexion esta mal.  Un cuerpo omitido donde se esperaba
 * deja al otro extremo esperando bytes que no van a llegar.  Los dos sobreviven
 * a la peticion.
 *
 * \~
 * @param method \~english the method of the request  \~spanish el metodo de la peticion  \~
 * @param code   \~english the status of the response  \~spanish el estado de la respuesta  \~
 * @return       \~english true if a body may follow  \~spanish true si puede ir un cuerpo detras  \~
 */
bool response_can_have_body(MethodId method, StatusCode code) noexcept;

/**
 * @brief
 * \~english The reason phrase of @p code, or an empty string.
 * \~spanish La frase de motivo de @p code, o una cadena vacia.
 * \~
 *
 * \~english
 * Only HTTP/1.1 writes it; HTTP/2 and HTTP/3 dropped it, which is why it lives
 * apart from everything else here rather than inside the status type.
 *
 * An empty phrase is not a failure and does not need one substituted.  RFC
 * 9112 section 4 makes the phrase optional, so `HTTP/1.1 499 ` is a
 * well-formed status line and a server answering a code nobody registered has
 * nothing to say about it.
 *
 * \~spanish
 * Solo la escribe HTTP/1.1; HTTP/2 y HTTP/3 la retiraron, que es la razon de
 * que viva aparte de todo lo demas de aqui y no dentro del tipo del estado.
 *
 * Una frase vacia no es un fallo y no hay que sustituirla por nada.  El RFC
 * 9112 seccion 4 hace la frase opcional, asi que `HTTP/1.1 499 ` es una linea
 * de estado bien formada y un servidor que conteste un codigo que nadie
 * registro no tiene nada que decir de el.
 *
 * \~
 * @param code \~english the code  \~spanish el codigo  \~
 * @return     \~english the phrase, or ""  \~spanish la frase, o ""  \~
 */
const char *status_reason(StatusCode code) noexcept;

/**
 * @brief
 * \~english The length of the reason phrase of @p code.
 * \~spanish La longitud de la frase de motivo de @p code.
 * \~
 * @param code \~english the code  \~spanish el codigo  \~
 * @return     \~english how many bytes, zero if there is none
 *             \~spanish cuantos bytes, cero si no hay  \~
 */
uint8_t status_reason_len(StatusCode code) noexcept;

} // namespace http_vx

#endif // HTTP_VX_STATUS_H
