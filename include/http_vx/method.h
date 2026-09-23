/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/method.h
 * @brief
 * \~english The request method: an identifier, and what it imposes.
 * \~spanish El metodo de una peticion: un identificador, y lo que impone.
 * \~
 *
 * \~english
 * The parser does not interpret the method (R19).  Any token is accepted and
 * passed on as it arrived, because the set is open -- WebDAV alone adds a
 * dozen, and a server is entitled to define its own -- and a parser that
 * refused what it did not recognise would be refusing messages that are legal.
 *
 * But a handful of methods change **how the bytes are written**, and that is
 * not the server's business to decide afterwards.  A response to `HEAD` must
 * carry the content length that the body would have had and then not send the
 * body; `CONNECT` stops being request-and-response at all.  Those are decided
 * before the handler runs, so they need an answer that costs nothing.
 *
 * Hence the same shape as the field names: recognised methods become a small
 * integer once, and everything downstream compares with `==`.  What is not
 * recognised is @c Unknown, which is not a failure -- the raw token travels
 * with the message and the server sees it intact.
 *
 * \~spanish
 * El analizador no interpreta el metodo (R19).  Se acepta cualquier token y se
 * pasa tal como llego, porque el conjunto es abierto -- solo WebDAV anade una
 * docena, y un servidor tiene derecho a definir los suyos -- y un analizador
 * que rechazara lo que no reconoce estaria rechazando mensajes legales.
 *
 * Pero un punado de metodos cambian **como se escriben los bytes**, y eso no es
 * cosa que el servidor decida despues.  Una respuesta a `HEAD` tiene que llevar
 * la longitud que habria tenido el cuerpo y luego no mandar el cuerpo;
 * `CONNECT` deja de ser peticion y respuesta.  Eso se decide antes de que corra
 * el manejador, asi que necesita una respuesta que no cueste nada.
 *
 * De ahi la misma forma que los nombres de cabecera: los metodos reconocidos
 * pasan a ser un entero pequeno una vez, y todos los de mas abajo comparan con
 * `==`.  Lo que no se reconoce es @c Unknown, que no es un fallo -- el token en
 * bruto viaja con el mensaje y el servidor lo ve intacto.
 *
 * \~
 */
#ifndef HTTP_VX_METHOD_H
#define HTTP_VX_METHOD_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english A method the transport recognises.
 * \~spanish Un metodo que el transporte reconoce.
 * \~
 *
 * \~english
 * These are the nine of RFC 9110 and no more.  The criterion for being here is
 * not how common a method is but whether the transport has to behave
 * differently because of it: everything else is the server's business and
 * travels as text.
 *
 * As with @c FieldId, the numeric values come from the order of the table and
 * are not an ABI.
 *
 * \~spanish
 * Son los nueve del RFC 9110 y ninguno mas.  El criterio para estar aqui no es
 * lo comun que sea un metodo sino si el transporte tiene que comportarse de
 * otra forma por su causa: lo demas es cosa del servidor y viaja como texto.
 *
 * Igual que con @c FieldId, los valores numericos salen del orden de la tabla y
 * no son una ABI.
 *
 * \~
 */
enum class MethodId : uint8_t {
    Unknown = 0,

    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,

    /// \~english How many there are.  Not a method.  \~spanish Cuantos hay.  No es un metodo.  \~
    Count
};

/**
 * @brief
 * \~english The canonical spelling of @p id, in upper case.
 * \~spanish La grafia canonica de @p id, en mayusculas.
 * \~
 *
 * \~english
 * Upper case because that is the spelling the specification registers, and
 * because unlike field names a method token is **case-sensitive**: `get` is not
 * `GET`, it is a different method that happens to be unregistered.
 *
 * \~spanish
 * En mayusculas porque es la grafia que registra la especificacion, y porque a
 * diferencia de los nombres de cabecera un token de metodo **distingue
 * mayusculas**: `get` no es `GET`, es otro metodo que resulta no estar
 * registrado.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english the name, or an empty string for @c Unknown and @c Count
 *           \~spanish el nombre, o cadena vacia para @c Unknown y @c Count  \~
 */
const char *method_name(MethodId id) noexcept;

/**
 * @brief
 * \~english The length of the canonical spelling of @p id.
 * \~spanish La longitud de la grafia canonica de @p id.
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english how many bytes  \~spanish cuantos bytes  \~
 */
uint8_t method_name_len(MethodId id) noexcept;

/**
 * @brief
 * \~english Resolves the token in @p name / @p len to an identifier.
 * \~spanish Resuelve el token de @p name / @p len a un identificador.
 * \~
 *
 * \~english
 * **Case-sensitive**, which is the difference from @c field_id_of and the one
 * that is easy to get wrong by analogy.  RFC 9110 section 9.1 says so in as
 * many words, and it matters for more than pedantry: a server that treated
 * `head` as `HEAD` would answer it without a body, and a client that wrote it
 * in lower case meant something else.
 *
 * It does not validate the token -- see @c token_is_valid for that.  A token
 * with a byte the grammar does not allow simply fails to match any row and
 * comes back as @c Unknown, so validation and recognition stay separate: one
 * says whether the message is well formed, the other what it says.
 *
 * \~spanish
 * **Distingue mayusculas**, que es la diferencia con @c field_id_of y la que es
 * facil de errar por analogia.  El RFC 9110 seccion 9.1 lo dice con todas las
 * letras, y importa por algo mas que por rigor: un servidor que tratara `head`
 * como `HEAD` lo contestaria sin cuerpo, y un cliente que lo escribio en
 * minusculas queria decir otra cosa.
 *
 * No valida el token -- para eso esta @c token_is_valid --.  Un token con un
 * byte que la gramatica no permite simplemente no casa con ninguna fila y
 * vuelve como @c Unknown, asi que validar y reconocer siguen separados: uno
 * dice si el mensaje esta bien formado, el otro que dice.
 *
 * \~
 * @param name \~english the bytes; it does not need to be nul-terminated
 *             \~spanish los bytes; no hace falta que termine en nulo  \~
 * @param len  \~english how many  \~spanish cuantos  \~
 * @return     \~english the identifier, or @c MethodId::Unknown
 *             \~spanish el identificador, o @c MethodId::Unknown  \~
 */
MethodId method_id_of(const char *name, size_t len) noexcept;

/**
 * @brief
 * \~english Whether the method is safe: it does not ask for a change of state.
 * \~spanish Si el metodo es seguro: no pide un cambio de estado.
 * \~
 *
 * \~english
 * @c Unknown answers false, and that is a decision rather than a default.  Not
 * being able to prove that something is safe is not proving that it is unsafe,
 * but the consequence of the two answers is not symmetric: treating an unknown
 * method as safe would authorise a cache or a prefetch to repeat it, and a
 * method nobody registered is exactly the one likeliest to do something.
 *
 * \~spanish
 * @c Unknown contesta false, y eso es una decision y no un valor por defecto.
 * No poder demostrar que algo es seguro no es demostrar que es inseguro, pero
 * la consecuencia de las dos respuestas no es simetrica: tratar un metodo
 * desconocido como seguro autorizaria a una cache o a una precarga a repetirlo,
 * y un metodo que nadie registro es justo el que mas probablemente haga algo.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true if it is safe  \~spanish true si es seguro  \~
 */
bool method_is_safe(MethodId id) noexcept;

/**
 * @brief
 * \~english Whether repeating the request has the same effect as making it once.
 * \~spanish Si repetir la peticion tiene el mismo efecto que hacerla una vez.
 * \~
 *
 * \~english
 * This is what authorises a retry, so @c Unknown answers false for the same
 * reason as above.  Every safe method is idempotent; @c PUT and @c DELETE are
 * idempotent without being safe, and @c POST and @c PATCH are neither.
 *
 * \~spanish
 * Es lo que autoriza a reintentar, asi que @c Unknown contesta false por la
 * misma razon de arriba.  Todo metodo seguro es idempotente; @c PUT y
 * @c DELETE lo son sin ser seguros, y @c POST y @c PATCH no son ninguna de las
 * dos cosas.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true if it is idempotent  \~spanish true si es idempotente  \~
 */
bool method_is_idempotent(MethodId id) noexcept;

/**
 * @brief
 * \~english Whether the response to this method never carries a body.
 * \~spanish Si la respuesta a este metodo nunca lleva cuerpo.
 * \~
 *
 * \~english
 * True only for @c HEAD, and it is the single most consequential thing in this
 * file.  The response must be written exactly as the one to a @c GET -- same
 * status, same fields, same `Content-Length` -- and then stop.  Getting it
 * wrong in either direction breaks the connection rather than the response: a
 * body that should not be there is read as the start of the next response, and
 * a length that is missing leaves the client waiting.
 *
 * The handler needs the answer BEFORE it generates the body, which is why this
 * is a property of the method and not something noticed while writing.
 *
 * \~spanish
 * Cierto solo para @c HEAD, y es lo de mas consecuencia de este fichero.  La
 * respuesta tiene que escribirse igual que la de un @c GET -- mismo estado,
 * mismas cabeceras, mismo `Content-Length` -- y entonces pararse.  Errarlo en
 * cualquiera de los dos sentidos rompe la conexion y no la respuesta: un cuerpo
 * que no deberia estar se lee como el principio de la respuesta siguiente, y
 * una longitud que falta deja al cliente esperando.
 *
 * El manejador necesita la respuesta ANTES de generar el cuerpo, que es la
 * razon de que esto sea una propiedad del metodo y no algo que se note al
 * escribir.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true for @c HEAD  \~spanish true para @c HEAD  \~
 */
bool method_forbids_response_body(MethodId id) noexcept;

/**
 * @brief
 * \~english Whether the method turns the connection into a tunnel.
 * \~spanish Si el metodo convierte la conexion en un tunel.
 * \~
 *
 * \~english
 * True for @c CONNECT.  A successful one stops the request-and-response
 * exchange: from then on the bytes belong to whoever is at the far end and the
 * codec has nothing more to say about them (R21).  In HTTP/2 and HTTP/3 the
 * extended form of this method is also how WebSocket travels.
 *
 * \~spanish
 * Cierto para @c CONNECT.  Uno que triunfa termina el intercambio de peticion y
 * respuesta: a partir de ahi los bytes son de quien este al otro extremo y el
 * codec no tiene nada mas que decir de ellos (R21).  En HTTP/2 y HTTP/3 la
 * forma extendida de este metodo es ademas por donde viaja WebSocket.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true for @c CONNECT  \~spanish true para @c CONNECT  \~
 */
bool method_is_tunnel(MethodId id) noexcept;

/**
 * @brief
 * \~english Whether the method asks the server to echo the request back.
 * \~spanish Si el metodo pide al servidor que devuelva la peticion.
 * \~
 *
 * \~english
 * True for @c TRACE, and the reason it is worth a predicate rather than a
 * comparison against text is that it is the one method disabled by default.
 * Echoing a request returns headers the client's own code could not read --
 * cookies and authorisation among them -- which is the cross-site tracing
 * attack.  A policy that keys on this is a policy that cannot be bypassed by
 * spelling.
 *
 * \~spanish
 * Cierto para @c TRACE, y la razon de que merezca un predicado en vez de una
 * comparacion contra texto es que es el unico metodo desactivado por defecto.
 * Devolver una peticion entrega cabeceras que el propio codigo del cliente no
 * podia leer -- cookies y autorizacion entre ellas --, que es el ataque de
 * trazado entre sitios.  Una politica que se apoye en esto es una politica que
 * no se puede rodear escribiendolo de otra forma.
 *
 * \~
 * @param id \~english the identifier  \~spanish el identificador  \~
 * @return   \~english true for @c TRACE  \~spanish true para @c TRACE  \~
 */
bool method_reflects_request(MethodId id) noexcept;

} // namespace http_vx

#endif // HTTP_VX_METHOD_H
