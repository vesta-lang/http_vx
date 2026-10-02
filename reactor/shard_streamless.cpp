/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file reactor/shard_streamless.cpp
 * @brief
 * \~english A shard with no stream side: datagrams only, and what it does with a stream completion anyway.
 * \~spanish Un fragmento sin lado de flujos: solo datagramas, y lo que hace igualmente con una finalizacion de flujo.
 * \~
 *
 * \~english
 * An HTTP/3 server is UDP from end to end, and a shard serving it has no
 * connection in the stream sense at all.  Making it pass a stream service it
 * would never call -- which is what the tests had to do -- is an interface
 * saying something untrue, and the untrue part is where the crash hides: a
 * stream completion reaching such a shard would be handed to a service that
 * is not there.
 *
 * So the stream side is optional.  Without it the shard refuses to accept
 * (at @c reset, as a configuration), refuses to adopt (counted), and a
 * stream completion that arrives anyway is given back whole -- buffer to the
 * pool, accepted socket closed -- and counted, never dropped.
 *
 * \~spanish
 * Un servidor HTTP/3 es UDP de punta a punta, y un fragmento que lo sirve no
 * tiene ninguna conexion en el sentido de los flujos.  Obligarle a pasar un
 * servicio de flujos al que no llamaria nunca -- que es lo que tenian que hacer
 * las pruebas -- es una interfaz diciendo algo que no es cierto, y la parte que
 * no es cierta es donde se esconde el fallo: una finalizacion de flujo que le
 * llegara a un fragmento asi se le daria a un servicio que no esta.
 *
 * Asi que el lado de flujos es opcional.  Sin el, el fragmento se niega a
 * aceptar (en @c reset, como configuracion), se niega a adoptar (contado), y
 * una finalizacion de flujo que llegue igualmente se devuelve entera -- el
 * buffer al pozo, el socket aceptado cerrado -- y se cuenta, nunca se tira.
 * \~
 */

#include "http_vx/shard.h"

namespace http_vx {

bool Shard::reset(const ShardConfig &cfg, Backend &io, uint64_t now) noexcept {
    return start(cfg, io, nullptr, now);
}

void Shard::unserved(const Completion &done) noexcept {
    ++counts_.unserved;

    if (done.buffer != kNoBuffer) pool_.release(done.buffer);

    /* \~english
     * An accepted socket belongs to nobody here, and one left open is a
     * descriptor leaked -- so it is shut, exactly as a full table shuts one.
     * \~spanish
     * Un socket aceptado no es de nadie aqui, y uno que se quede abierto es un
     * descriptor perdido -- asi que se cierra, igual que cierra uno una tabla
     * llena.
     * \~ */
    if (done.kind == OpKind::Accept && done.ok() && done.fd >= 0) close_socket(done.fd);
}

} // namespace http_vx
