/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_limits.h
 * @brief
 * \~english What the HTTP/2 codec refuses to exceed.
 * \~spanish Lo que el codec de HTTP/2 se niega a pasar.
 * \~
 *
 * \~english
 * HTTP/2 limits are not the same shape as HTTP/1.1's, and the difference is
 * worth stating because it is where the version's own dangers come from.
 *
 * In HTTP/1.1 a connection carries one message at a time, so a limit on a
 * message is a limit on the connection.  In HTTP/2 a connection carries
 * hundreds of streams at once and the peer decides how many, so **a limit per
 * message is not a limit at all** -- a hundred streams each under the limit
 * are a hundred times the limit.  Half of what is here is about that.
 *
 * Some of these are ALSO announced to the peer, in a SETTINGS frame, which is
 * a thing HTTP/1.1 has no equivalent of: the peer is told the rules before it
 * breaks them.  That does not make enforcing them optional -- a peer that
 * ignores a setting is exactly the peer worth having a limit for.
 *
 * \~spanish
 * Los limites de HTTP/2 no tienen la misma forma que los de HTTP/1.1, y la
 * diferencia merece decirse porque es de donde salen los peligros propios de la
 * version.
 *
 * En HTTP/1.1 una conexion lleva un mensaje a la vez, asi que un limite sobre
 * un mensaje es un limite sobre la conexion.  En HTTP/2 una conexion lleva
 * cientos de flujos a la vez y cuantos lo decide el otro extremo, asi que **un
 * limite por mensaje no es ningun limite** -- cien flujos cada uno por debajo
 * del limite son cien veces el limite.  La mitad de lo que hay aqui va de eso.
 *
 * Algunos de estos ADEMAS se le anuncian al otro extremo, en una trama
 * SETTINGS, que es algo de lo que HTTP/1.1 no tiene equivalente: al otro
 * extremo se le dicen las reglas antes de que las rompa.  Eso no hace opcional
 * imponerlas -- un extremo que ignore un ajuste es justo el extremo por el que
 * merece la pena tener un limite.
 *
 * \~
 */
#ifndef HTTP_VX_H2_LIMITS_H
#define HTTP_VX_H2_LIMITS_H

#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english The limits of one HTTP/2 connection.
 * \~spanish Los limites de una conexion HTTP/2.
 * \~
 */
struct Limits {
    /**
     * \~english
     * The largest frame payload this server will accept, and what it announces
     * as `SETTINGS_MAX_FRAME_SIZE`.
     *
     * Sixteen kilobytes is the value the specification starts every connection
     * at, and it is a floor as well as a default: a peer may not be told to
     * accept less.  Raising it lets fewer, larger frames carry the same bytes,
     * which is fewer headers to parse and fewer completions to handle -- and
     * it also means one stream can occupy a read for longer, which is the part
     * that matters when a connection has hundreds.
     *
     * \~spanish
     * La carga de trama mas grande que este servidor acepta, y lo que anuncia
     * como `SETTINGS_MAX_FRAME_SIZE`.
     *
     * Dieciseis kilobytes es el valor con el que la especificacion empieza
     * todas las conexiones, y es un suelo ademas de un valor por defecto: a un
     * extremo no se le puede pedir que acepte menos.  Subirlo hace que menos
     * tramas, mayores, lleven los mismos bytes, que son menos cabeceras que
     * analizar y menos finalizaciones que atender -- y tambien que un flujo
     * pueda ocupar una lectura mas tiempo, que es la parte que importa cuando
     * una conexion tiene cientos.
     * \~
     */
    uint32_t max_frame_size = 16384;

    /**
     * \~english
     * How many bytes of header block one message may take ON THE WIRE, across
     * every frame that carries it.
     *
     * This is not `SETTINGS_MAX_HEADER_LIST_SIZE`, and the difference matters
     * enough to be two fields: that setting counts the fields AFTER they are
     * decompressed, and this counts the compressed bytes as they arrive.  One
     * bounds what a message means and the other bounds what has to be held to
     * find out -- and HPACK exists precisely so that the two numbers are
     * nothing like each other.
     *
     * \~spanish
     * Cuantos bytes de bloque de cabeceras puede ocupar un mensaje EN EL CABLE,
     * contando todas las tramas que lo llevan.
     *
     * Esto no es `SETTINGS_MAX_HEADER_LIST_SIZE`, y la diferencia importa lo
     * bastante para ser dos campos: ese ajuste cuenta las cabeceras DESPUES de
     * descomprimirlas, y este cuenta los bytes comprimidos segun llegan.  Uno
     * acota lo que un mensaje significa y el otro lo que hay que guardar para
     * averiguarlo -- y HPACK existe justamente para que los dos numeros no se
     * parezcan en nada.
     * \~
     */
    uint32_t max_header_block_bytes = 32768;

    /**
     * \~english
     * How many bytes the fields of one message may take once they are
     * decompressed, counted the specification's way: name plus value plus
     * thirty-two, per field.  Announced as `SETTINGS_MAX_HEADER_LIST_SIZE`.
     *
     * **This is the one that bounds the bomb.**  A block of a few hundred
     * bytes can name a remembered field thousands of times, and each naming
     * costs one byte on the wire and whatever the field is worth once it is
     * written out.  The limit above never fires on that -- the block really is
     * small -- and this one does.
     *
     * \~spanish
     * Cuantos bytes pueden ocupar las cabeceras de un mensaje una vez
     * descomprimidas, contadas como dice la especificacion: nombre mas valor
     * mas treinta y dos, por cabecera.  Se anuncia como
     * `SETTINGS_MAX_HEADER_LIST_SIZE`.
     *
     * **Este es el que acota la bomba.**  Un bloque de unos cientos de bytes
     * puede nombrar miles de veces una cabecera recordada, y cada mencion
     * cuesta un byte en el cable y lo que valga la cabecera una vez escrita.
     * El limite de arriba no salta nunca con eso -- el bloque es pequeno de
     * verdad -- y este si.
     * \~
     */
    uint32_t max_header_list_size = 32768;

    /**
     * \~english
     * How many CONTINUATION frames may follow one HEADERS before it has to be
     * finished.
     *
     * **This is not a tuning knob.**  A header block may be split across as
     * many frames as the sender likes, and until the one with END_HEADERS
     * arrives the recipient is holding an unfinished message and cannot act on
     * it.  A peer that sends HEADERS and then CONTINUATION forever, each one
     * perfectly legal and none of them ending it, makes the server hold state
     * that grows without bound -- and it costs the attacker almost nothing,
     * because the frames can be nearly empty.
     *
     * The size limit above does not catch it on its own: a flood of empty
     * frames adds no bytes to the header list and still costs a read, a parse
     * and a completion each.  So the count is limited too, and the two
     * together are what make an unfinished message cheap to refuse.
     *
     * \~spanish
     * Cuantas tramas CONTINUATION pueden seguir a una HEADERS antes de que haya
     * que terminarla.
     *
     * **Esto no es un ajuste de afinado.**  Un bloque de cabeceras se puede
     * partir en tantas tramas como quiera quien envia, y hasta que llega la que
     * lleva END_HEADERS quien recibe tiene un mensaje sin terminar sobre el que
     * no puede actuar.  Un extremo que mande HEADERS y despues CONTINUATION sin
     * parar, cada una perfectamente legal y ninguna terminandolo, hace que el
     * servidor guarde estado que crece sin tope -- y al atacante casi no le
     * cuesta nada, porque las tramas pueden ir casi vacias.
     *
     * El limite de tamano de arriba no lo pilla por su cuenta: una riada de
     * tramas vacias no anade bytes a la lista de cabeceras y sigue costando una
     * lectura, un analisis y una finalizacion cada una.  Asi que se limita
     * tambien la cuenta, y las dos juntas son lo que hace barato rechazar un
     * mensaje sin terminar.
     * \~
     */
    uint32_t max_continuation_frames = 16;

    /**
     * \~english
     * How many streams may be open at once.  Announced as
     * `SETTINGS_MAX_CONCURRENT_STREAMS`.
     *
     * This is the one that turns every other per-message limit into a real
     * limit on the connection: without it, the answer to "how much can one
     * peer make this server hold" is the per-message limit times a number the
     * peer chooses.
     *
     * \~spanish
     * Cuantos flujos pueden estar abiertos a la vez.  Se anuncia como
     * `SETTINGS_MAX_CONCURRENT_STREAMS`.
     *
     * Este es el que convierte todos los demas limites por mensaje en un limite
     * de verdad sobre la conexion: sin el, la respuesta a "cuanto puede hacer
     * que guarde este servidor un solo extremo" es el limite por mensaje
     * multiplicado por un numero que elige el extremo.
     * \~
     */
    uint32_t max_concurrent_streams = 128;

    /**
     * \~english
     * How many bytes of remembered fields this server will keep per
     * connection, and what it announces as `SETTINGS_HEADER_TABLE_SIZE`.
     *
     * **This is the one limit that is about the MACHINE and not about a
     * message.**  Four kilobytes is the value the specification starts every
     * connection at, and it is four kilobytes EACH: at the million connections
     * this project is built for, a table on every one of them is four
     * gigabytes of remembered headers.
     *
     * Which is why the table is not made until a peer uses it.  A connection
     * whose headers all come out of the static table -- which is most of a
     * `GET` -- never needs one, and never pays for one.  Announcing a size is
     * not the same as reserving it, and the difference is the difference
     * between a number and a gigabyte.
     *
     * \~spanish
     * Cuantos bytes de cabeceras recordadas guarda este servidor por conexion,
     * y lo que anuncia como `SETTINGS_HEADER_TABLE_SIZE`.
     *
     * **Este es el unico limite que habla de la MAQUINA y no de un mensaje.**
     * Cuatro kilobytes es el valor con el que la especificacion empieza todas
     * las conexiones, y son cuatro kilobytes CADA UNA: al millon de conexiones
     * para el que esta hecho este proyecto, una tabla en cada una son cuatro
     * gigabytes de cabeceras recordadas.
     *
     * Que es la razon de que la tabla no se haga hasta que un extremo la use.
     * Una conexion cuyas cabeceras salgan todas de la tabla estatica -- que es
     * casi todo un `GET` -- no necesita una nunca, y no la paga nunca.
     * Anunciar un tamano no es lo mismo que reservarlo, y la diferencia es la
     * que hay entre un numero y un gigabyte.
     * \~
     */
    uint32_t header_table_size = 4096;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_LIMITS_H
