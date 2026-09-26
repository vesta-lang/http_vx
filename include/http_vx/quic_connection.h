/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_connection.h
 * @brief
 * \~english A QUIC connection: datagrams in, datagrams out, and everything in between.
 * \~spanish Una conexion QUIC: datagramas que entran, datagramas que salen, y todo lo de en medio.
 * \~
 *
 * \~english
 * The object that joins the pieces.  A datagram comes in: its coalesced
 * packets are unprotected one by one, duplicates dropped, and their frames
 * handed to where they belong -- ACKs to recovery, stream data to the
 * streams, limits to the table, CRYPTO to the handshake's buffers.  When
 * asked for a datagram it composes one: an ACK when one is owed, the control
 * frames that are owed, CRYPTO, then stream data, within the congestion
 * window and the anti-amplification limit, coalescing packets of different
 * spaces and padding where the RFC says.
 *
 * **It performs no I/O and reads no clock**, like every other piece: bytes
 * and time go in, bytes and deadlines come out, so the whole transport runs
 * between two connections in a test, over a simulated network, in
 * simulated time.
 *
 * **What each packet carried is remembered** in a fixed ring beside
 * recovery's, so that when a packet is lost exactly what it carried is sent
 * again -- stream bytes, a MAX_DATA, a RESET_STREAM -- and when it is
 * acknowledged, exactly that is done.
 *
 * **1-RTT keys change during the connection** (RFC 9001, 6): either end may
 * start an update, and they also start on their own before the AEAD's
 * limit.  The next read keys are ready in advance and the previous ones are
 * kept for late packets; an end that breaks the rules is closed with
 * KEY_UPDATE_ERROR.
 *
 * **Connection IDs come and go** (5.1): each end hands the other as many as
 * it takes, each with a stateless reset token from a key, retires what it is
 * asked to and moves to another ID when the one in use goes.  A datagram that
 * ends in the token of an ID in use tells this end that the peer lost the
 * connection (10.3).
 *
 * **Every datagram carries its path** (8.2, 9): the addresses at both ends,
 * as the host gives them.  A peer address is validated with PATH_CHALLENGE
 * before more than three times what came from it is sent there; a client
 * that moves is followed on its highest-numbered non-probing packet, with an
 * ID never used on another path, and congestion control starts over once
 * its address is proven.  A move that is not proven falls back to the last
 * validated address.  A client moves or probes a new local address itself.
 *
 * The connection knows nothing of TLS.  It takes secrets through
 * `install_secrets` and `install_early_secret`, learns the handshake is done
 * through `handshake_confirmed`, and is given the peer's transport parameters
 * by `on_peer_transport_params`; tls_quic.h is what calls them.  0-RTT: a
 * client seals application data in 0-RTT packets until it has 1-RTT keys,
 * on the limits it remembered; a server opens them with its 0-RTT keys, in
 * the application space's numbering, and turned down, opens none.
 *
 * \~spanish
 * El objeto que junta las piezas.  Entra un datagrama: sus paquetes pegados se
 * desprotegen uno a uno, se tiran los duplicados, y sus tramas van a donde
 * corresponden -- los ACK a la recuperacion, los datos a los flujos, los limites
 * a la tabla, CRYPTO a los buffers del saludo.  Cuando se le pide un datagrama,
 * compone uno: un ACK si se debe, las tramas de control que se deben, CRYPTO, y
 * despues datos de flujos, dentro de la ventana de congestion y del limite
 * antiamplificacion, pegando paquetes de espacios distintos y rellenando donde
 * lo dice el RFC.
 *
 * **No hace entrada ni salida ni lee el reloj**, como todas las demas piezas:
 * entran bytes y tiempo, salen bytes y plazos, asi que todo el transporte corre
 * entre dos conexiones en una prueba, sobre una red simulada, en tiempo
 * simulado.
 *
 * **Se recuerda que llevaba cada paquete** en un anillo fijo al lado del de la
 * recuperacion, para que cuando un paquete se pierda se mande otra vez
 * exactamente lo que llevaba -- bytes de flujo, un MAX_DATA, un RESET_STREAM --, y
 * cuando se confirme, se haga exactamente eso.
 *
 * **Las claves 1-RTT cambian durante la conexion** (RFC 9001, 6): cualquiera de
 * los dos extremos puede empezar una actualizacion, y tambien empiezan solas
 * antes del limite del AEAD.  Las claves de lectura siguientes estan listas de
 * antemano y las anteriores se guardan para los paquetes tardios; un extremo que
 * rompe las reglas se cierra con KEY_UPDATE_ERROR.
 *
 * **Los identificadores de conexion van y vienen** (5.1): cada extremo le da al
 * otro tantos como acepte, cada uno con un testigo de reinicio sin estado sacado
 * de una clave, retira los que le piden y pasa a otro identificador cuando se va
 * el que usa.  Un datagrama que acaba en el testigo de un identificador en uso le
 * dice a este extremo que el otro perdio la conexion (10.3).
 *
 * **Cada datagrama lleva su camino** (8.2, 9): las direcciones de los dos
 * extremos, como las da el anfitrion.  La direccion del otro se valida con
 * PATH_CHALLENGE antes de mandarle mas de tres veces lo que llego de ella; a un
 * cliente que se mueve se le sigue con su paquete no de sondeo de numero mas
 * alto, con un identificador nunca usado en otro camino, y el control de
 * congestion empieza de cero cuando su direccion queda probada.  Una mudanza
 * que no se prueba vuelve a la ultima direccion validada.  Un cliente se mueve
 * o sondea una direccion local nueva por si mismo.
 *
 * La conexion no sabe nada de TLS.  Recibe los secretos por `install_secrets` e
 * `install_early_secret`, se entera de que el saludo acabo por
 * `handshake_confirmed`, y le dan los parametros de transporte del otro por
 * `on_peer_transport_params`; tls_quic.h es quien los llama.  0-RTT: un cliente
 * sella datos de aplicacion en paquetes 0-RTT hasta tener claves 1-RTT, con los
 * limites que recordo; un servidor los abre con sus claves 0-RTT, en la
 * numeracion del espacio de aplicacion, y si los rechazo, no abre ninguno.
 * \~
 */
#ifndef HTTP_VX_QUIC_CONNECTION_H
#define HTTP_VX_QUIC_CONNECTION_H

#include "http_vx/quic_ack.h"
#include "http_vx/quic_crypto.h"
#include "http_vx/quic_frame.h"
#include "http_vx/quic_packet.h"
#include "http_vx/quic_path.h"
#include "http_vx/quic_protection.h"
#include "http_vx/quic_recovery.h"
#include "http_vx/quic_reset.h"
#include "http_vx/quic_stream_recv.h"
#include "http_vx/quic_stream_send.h"
#include "http_vx/quic_streams.h"
#include "http_vx/quic_transport_params.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english How a connection starts.
 * \~spanish Como empieza una conexion.
 * \~
 */
struct ConnectionConfig {
    bool is_server = true;
    uint32_t version = kVersion1;

    /// \~english This end's connection ID: what the peer puts as destination.
    /// \~spanish El identificador de conexion de este extremo: lo que el otro pone como destino.  \~
    uint8_t local_cid[kMaxConnectionId] = {};
    size_t local_cid_len = 8;

    /**
     * \~english
     * The peer's connection ID.  A client starts with the random one it chose
     * for its first Initial (the "original destination"); both ends learn the
     * real one from the first long header the peer sends.
     * \~spanish
     * El identificador de conexion del otro extremo.  Un cliente empieza con el
     * aleatorio que eligio para su primer Initial (el "destino original"); los
     * dos extremos aprenden el de verdad de la primera cabecera larga que manda
     * el otro.
     * \~
     */
    uint8_t peer_cid[kMaxConnectionId] = {};
    size_t peer_cid_len = 8;

    /// \~english The largest datagram this end sends.  \~spanish El datagrama mas grande que manda este extremo.  \~
    size_t max_datagram = 1200;

    /// \~english Silence after which the connection is gone (10.1).  \~spanish Silencio tras el que la conexion desaparece (10.1).  \~
    uint64_t idle_timeout_us = 30000000;

    /// \~english The application space's acknowledgement policy.  \~spanish La politica de confirmacion del espacio de aplicacion.  \~
    AckPolicy ack;
    RecoveryConfig recovery;
    StreamConfig streams;

    /// \~english This end's MAX_DATA window, and the peer's initial_max_data.
    /// \~spanish La ventana MAX_DATA de este extremo, y el initial_max_data del otro.  \~
    uint64_t data_window = 16u << 20;
    uint64_t peer_max_data = 0;

    /// \~english How much handshake data each space may buffer (CRYPTO_BUFFER_EXCEEDED past it).
    /// \~spanish Cuantos datos del saludo puede guardar cada espacio (CRYPTO_BUFFER_EXCEEDED pasado eso).  \~
    uint64_t crypto_window = 65536;

    /**
     * \~english
     * After how many 1-RTT packets sealed with one key a key update starts on
     * its own (RFC 9001, 6).  Zero: half the AEAD's confidentiality limit, so
     * the update always comes well before the limit (6.6).
     * \~spanish
     * Tras cuantos paquetes 1-RTT sellados con una clave empieza sola una
     * actualizacion de claves (RFC 9001, 6).  Cero: la mitad del limite de
     * confidencialidad del AEAD, asi que la actualizacion llega siempre mucho
     * antes del limite (6.6).
     * \~
     */
    uint64_t key_update_packets = 0;

    /**
     * \~english
     * The AEAD limits of RFC 9001, 6.6; zero means the AEAD's own.  Only a
     * test has a reason to lower them: the real ones are millions of packets.
     * \~spanish
     * Los limites del AEAD del RFC 9001, 6.6; cero es el del propio AEAD.  Solo
     * una prueba tiene motivo para bajarlos: los de verdad son millones de
     * paquetes.
     * \~
     */
    uint64_t confidentiality_limit = 0;
    uint64_t integrity_limit = 0;

    /**
     * \~english
     * The key this end's stateless reset tokens come from (RFC 9000, 10.3.2).
     * A server gives its connections the same key as its acceptor, so that
     * the token a connection hands out is the one the acceptor answers with
     * once the connection is gone.
     * \~spanish
     * La clave de la que salen los testigos de reinicio sin estado de este
     * extremo (RFC 9000, 10.3.2).  Un servidor da a sus conexiones la misma clave
     * que a su acceptor, para que el testigo que entrega una conexion sea con el
     * que contesta el acceptor cuando ya no exista.
     * \~
     */
    uint8_t reset_key[kResetKeySize] = {};

    /// \~english This end's active_connection_id_limit: how many of the peer's IDs it keeps (2 to 8).
    /// \~spanish El active_connection_id_limit de este extremo: cuantos identificadores del otro guarda (2 a 8).  \~
    size_t active_cid_limit = 4;
    /// \~english The peer's active_connection_id_limit: how many IDs this end may have handed out at once.
    /// \~spanish El active_connection_id_limit del otro: cuantos identificadores puede tener repartidos a la vez este extremo.  \~
    size_t peer_active_cid_limit = 2;

    /// \~english The reset token of the peer's first ID, if known (a server's, from its transport parameters).
    /// \~spanish El testigo de reinicio del primer identificador del otro, si se sabe (el de un servidor, de sus parametros de transporte).  \~
    uint8_t peer_reset_token[kResetTokenSize] = {};
    bool peer_reset_token_known = false;

    /**
     * \~english
     * The path the handshake runs on: a client's own address and the
     * server's; a server's own address and the client's, as the acceptor saw
     * them.  The addresses are the host's, opaque; see quic_path.h.
     * \~spanish
     * El camino por el que va el saludo: la direccion propia de un cliente y la
     * del servidor; la propia de un servidor y la del cliente, como las vio el
     * acceptor.  Las direcciones son las del anfitrion, opacas; ver
     * quic_path.h.
     * \~
     */
    Path path;

    /**
     * \~english
     * disable_active_migration (18.2): a server that announces it drops the
     * packets of a client that moves anyway -- without a stateless reset, so
     * that no third party can end the connection by forging an address (9).
     * On a client, the peer's: it may not move.  Both come with the transport
     * parameters; until then they are set here.
     * \~spanish
     * disable_active_migration (18.2): un servidor que lo anuncia tira los
     * paquetes de un cliente que se mueva igualmente -- sin reinicio sin estado,
     * para que nadie ajeno pueda acabar la conexion falsificando una direccion
     * (9).  En un cliente, el del otro: no puede moverse.  Los dos llegan con los
     * parametros de transporte; hasta entonces se ponen aqui.
     * \~
     */
    bool disable_active_migration = false;
    bool peer_disable_active_migration = false;
};

/**
 * @brief
 * \~english What happened on paths, counted.
 * \~spanish Lo que paso en los caminos, contado.
 * \~
 */
struct PathCounts {
    /// \~english PATH_CHALLENGE and PATH_RESPONSE frames sent.  \~spanish Tramas PATH_CHALLENGE y PATH_RESPONSE mandadas.  \~
    uint64_t challenges_sent = 0;
    uint64_t responses_sent = 0;
    /// \~english Validations that succeeded, and those abandoned when their time ran out (8.2.4).
    /// \~spanish Validaciones que salieron bien, y las abandonadas al acabarse su tiempo (8.2.4).  \~
    uint64_t validated = 0;
    uint64_t abandoned = 0;
    /// \~english Validations repeated in a full-size datagram because the first could not be (8.2.1).
    /// \~spanish Validaciones repetidas en un datagrama de tamano completo porque la primera no pudo serlo (8.2.1).  \~
    uint64_t revalidated_mtu = 0;
    /// \~english The peer moved (9.3), and this end moved (9.2).  \~spanish El otro se movio (9.3), y este extremo se movio (9.2).  \~
    uint64_t peer_migrations = 0;
    uint64_t migrations = 0;
    /// \~english Back to the last validated path when a new one failed (9.3.2).
    /// \~spanish Vuelta al ultimo camino validado cuando fallo uno nuevo (9.3.2).  \~
    uint64_t reverted = 0;
    /// \~english Congestion control and RTT started over on a new path (9.4).
    /// \~spanish Control de congestion y RTT empezados de cero en un camino nuevo (9.4).  \~
    uint64_t congestion_resets = 0;
    /// \~english Datagrams from a server address a client did not know (9).
    /// \~spanish Datagramas de una direccion del servidor que el cliente no conocia (9).  \~
    uint64_t unknown_address = 0;
    /// \~english Datagrams from a new address before the handshake was confirmed (9).
    /// \~spanish Datagramas de una direccion nueva antes de confirmar el saludo (9).  \~
    uint64_t before_confirmed = 0;
    /// \~english Datagrams from a new address when migration is disabled (9).
    /// \~spanish Datagramas de una direccion nueva con la migracion desactivada (9).  \~
    uint64_t migration_disabled = 0;
    /// \~english Times a path had no unused connection ID of the peer to send with (9.5).
    /// \~spanish Veces que un camino no tenia un identificador sin usar del otro con el que mandar (9.5).  \~
    uint64_t no_connection_id = 0;
    /// \~english A PATH_RESPONSE matching no challenge sent (19.18).  \~spanish Un PATH_RESPONSE que no casa con ningun desafio mandado (19.18).  \~
    uint64_t stray_responses = 0;
    /// \~english A PATH_RESPONSE that could not be sent at all within the anti-amplification limit (8.2.2).
    /// \~spanish Un PATH_RESPONSE que no se pudo mandar ni siquiera dentro del limite antiamplificacion (8.2.2).  \~
    uint64_t responses_dropped = 0;
};

/**
 * @brief
 * \~english What asking a client to probe or move to a path got (RFC 9000, 9.1, 9.2).
 * \~spanish Lo que consiguio pedir a un cliente que sondee o se mueva a un camino (RFC 9000, 9.1, 9.2).
 * \~
 */
enum class Migration : uint8_t {
    Started,
    /// \~english Clients start every migration (9).  \~spanish Los clientes empiezan todas las migraciones (9).  \~
    NotClient,
    /// \~english Not before the handshake is confirmed (9).  \~spanish No antes de confirmar el saludo (9).  \~
    NotConfirmed,
    /// \~english The peer sent disable_active_migration (9).  \~spanish El otro mando disable_active_migration (9).  \~
    Disabled,
    /// \~english The peer uses a zero-length ID: the paths would be linkable (9.5).
    /// \~spanish El otro usa un identificador de longitud cero: los caminos serian enlazables (9.5).  \~
    ZeroLengthId,
    /// \~english Only the server's address in use: there is no preferred address yet (9.6).
    /// \~spanish Solo la direccion del servidor en uso: aun no hay direccion preferida (9.6).  \~
    UnknownServer,
    /// \~english That is already the path in use.  \~spanish Ese ya es el camino en uso.  \~
    SamePath,
    /// \~english No unused ID of the peer for the new local address (9.5).
    /// \~spanish Ningun identificador sin usar del otro para la direccion local nueva (9.5).  \~
    NoConnectionId,
    /// \~english The provider could not draw the challenge's data.  \~spanish El proveedor no pudo sortear los datos del desafio.  \~
    Failed,
};

/// \~english A short name for @p m.  \~spanish Un nombre corto para @p m.  \~
const char *migration_name(Migration m) noexcept;

/**
 * @brief
 * \~english What happened to connection IDs, counted.
 * \~spanish Lo que les paso a los identificadores de conexion, contado.
 * \~
 */
struct CidCounts {
    /// \~english IDs this end handed out, and how many of them the peer retired.
    /// \~spanish Identificadores que repartio este extremo, y cuantos de ellos retiro el otro.  \~
    uint64_t issued = 0;
    uint64_t retired_by_peer = 0;
    /// \~english IDs the peer handed out that were kept, and how many this end retired.
    /// \~spanish Identificadores que repartio el otro y se guardaron, y cuantos retiro este extremo.  \~
    uint64_t received = 0;
    uint64_t retired = 0;
    /// \~english Times the destination ID in use changed.  \~spanish Veces que cambio el identificador de destino en uso.  \~
    uint64_t switched = 0;
};

/**
 * @brief
 * \~english What asking for a key update got (RFC 9001, 6).
 * \~spanish Lo que consiguio pedir una actualizacion de claves (RFC 9001, 6).
 * \~
 */
enum class KeyUpdate : uint8_t {
    Started,
    /// \~english No 1-RTT keys yet.  \~spanish Aun no hay claves 1-RTT.  \~
    NoKeys,
    /// \~english Not before the handshake is confirmed (6.1).  \~spanish No antes de confirmar el saludo (6.1).  \~
    NotConfirmed,
    /// \~english No packet of the current phase acknowledged yet (6.5).
    /// \~spanish Aun no se confirmo ningun paquete de la fase actual (6.5).  \~
    Unacknowledged,
    /// \~english The previous keys are still kept for late packets (6.5).
    /// \~spanish Las claves anteriores siguen guardadas para paquetes tardios (6.5).  \~
    OldKeysKept,
    /// \~english Less than three PTO since the ACK that confirmed the previous update (6.5).
    /// \~spanish Menos de tres PTO desde el ACK que confirmo la actualizacion anterior (6.5).  \~
    TooSoon,
    /// \~english The provider failed: said, not guessed around.  \~spanish Fallo el proveedor: dicho, no rodeado.  \~
    Failed,
};

/// \~english A short name for @p k.  \~spanish Un nombre corto para @p k.  \~
const char *key_update_name(KeyUpdate k) noexcept;

/**
 * @brief
 * \~english What happened to the 1-RTT keys, counted.
 * \~spanish Lo que les paso a las claves 1-RTT, contado.
 * \~
 */
struct KeyUpdateCounts {
    /// \~english Updates this end started.  \~spanish Actualizaciones que empezo este extremo.  \~
    uint64_t initiated = 0;
    /// \~english Updates the peer started, answered with new write keys.
    /// \~spanish Actualizaciones que empezo el otro extremo, contestadas con claves de escritura nuevas.  \~
    uint64_t answered = 0;
    /// \~english Read keys rolled forward, whoever started.  \~spanish Claves de lectura avanzadas, empezara quien empezara.  \~
    uint64_t read_rolled = 0;
    /// \~english Late packets opened with the previous keys.  \~spanish Paquetes tardios abiertos con las claves anteriores.  \~
    uint64_t opened_with_old = 0;
    /// \~english Previous keys thrown away once their time was up.  \~spanish Claves anteriores tiradas al acabar su plazo.  \~
    uint64_t old_discarded = 0;
    /// \~english KEY_UPDATE_ERROR: old keys on a packet numbered after new ones (6.4).
    /// \~spanish KEY_UPDATE_ERROR: claves viejas en un paquete numerado despues de otros con las nuevas (6.4).  \~
    uint64_t old_after_new = 0;
    /// \~english KEY_UPDATE_ERROR: the peer updated again before its last update was acknowledged (6.2).
    /// \~spanish KEY_UPDATE_ERROR: el otro extremo actualizo otra vez antes de que se confirmara la anterior (6.2).  \~
    uint64_t updated_twice = 0;
};

/// \~english Where a connection is in its life (10).  \~spanish En que punto de su vida esta una conexion (10).  \~
enum class ConnState : uint8_t {
    Active,
    /// \~english This end closed: it repeats CONNECTION_CLOSE and nothing else.
    /// \~spanish Este extremo cerro: repite CONNECTION_CLOSE y nada mas.  \~
    Closing,
    /// \~english The peer closed: nothing is sent at all.  \~spanish El otro extremo cerro: no se manda nada.  \~
    Draining,
    Closed,
};

/**
 * @brief
 * \~english Why a connection ended: the first cause, kept.
 * \~spanish Por que acabo una conexion: la primera causa, guardada.
 * \~
 *
 * \~english
 * Several ways out send nothing at all -- the idle timeout, running out of
 * packet numbers, a key used to its limit -- and from outside they looked
 * the same as any other close.  Each has its name, so whoever runs the
 * connection can count them and say which.
 * \~spanish
 * Varias salidas no mandan nada -- el plazo de inactividad, quedarse sin
 * numeros de paquete, una clave usada hasta su limite -- y desde fuera
 * parecian iguales que cualquier otro cierre.  Cada una tiene su nombre, para
 * que quien lleve la conexion pueda contarlas y decir cual.
 * \~
 */
enum class EndReason : uint8_t {
    /// \~english Not ended.  \~spanish No acabo.  \~
    None,
    /// \~english This end closed, with close_code() (10.2).  \~spanish Este extremo cerro, con close_code() (10.2).  \~
    Closed,
    /// \~english The peer sent CONNECTION_CLOSE (10.2.2).  \~spanish El otro mando CONNECTION_CLOSE (10.2.2).  \~
    PeerClosed,
    /// \~english A stateless reset from the peer (10.3.1).  \~spanish Un reinicio sin estado del otro (10.3.1).  \~
    StatelessReset,
    /// \~english Silence past the idle timeout (10.1).  \~spanish Silencio pasado el plazo de inactividad (10.1).  \~
    IdleTimeout,
    /// \~english No version in common (6.2).  \~spanish Ninguna version en comun (6.2).  \~
    VersionNegotiation,
    /// \~english Packet numbers used up (12.3).  \~spanish Numeros de paquete agotados (12.3).  \~
    PacketNumbers,
    /// \~english A key sealed its limit of packets and could not be updated (RFC 9001, 6.6).
    /// \~spanish Una clave sello su limite de paquetes y no se pudo actualizar (RFC 9001, 6.6).  \~
    ConfidentialityLimit,
    /// \~english A failed path with no validated one to fall back to (9.3.2).
    /// \~spanish Un camino fallido sin otro validado al que volver (9.3.2).  \~
    NoValidatedPath,
    kCount,
};

/// \~english A short name for @p r.  \~spanish Un nombre corto para @p r.  \~
const char *end_reason_name(EndReason r) noexcept;

/**
 * @brief
 * \~english Why packets were dropped: counted, never silent.
 * \~spanish Por que se tiraron paquetes: contado, nunca en silencio.
 * \~
 */
struct DropCounts {
    uint64_t bad_header = 0;
    uint64_t wrong_cid = 0;
    uint64_t no_keys = 0;
    uint64_t forged = 0;
    uint64_t duplicate = 0;
    uint64_t unsupported = 0;
    uint64_t after_close = 0;
    /// \~english Packets kept until their keys arrived, and then opened.
    /// \~spanish Paquetes guardados hasta que llegaron sus claves, y luego abiertos.  \~
    uint64_t buffered = 0;
    /// \~english A Version Negotiation that came too late, or listed the version in use (6.2).
    /// \~spanish Un Version Negotiation que llego tarde, o que lista la version en uso (6.2).  \~
    uint64_t version_negotiation = 0;
    /// \~english A Retry that came too late, repeated, empty, or naming the ID it answers (17.2.5.2).
    /// \~spanish Un Retry que llego tarde, repetido, vacio, o con el identificador al que contesta (17.2.5.2).  \~
    uint64_t retry = 0;
    /// \~english A long header whose source ID is not the one the peer first gave (7.2).
    /// \~spanish Una cabecera larga cuyo identificador de origen no es el que dio primero el otro (7.2).  \~
    uint64_t changed_source = 0;
    /// \~english A long header of another version than the one this connection uses (5.2.1).
    /// \~spanish Una cabecera larga de otra version que la que usa esta conexion (5.2.1).  \~
    uint64_t wrong_version = 0;
    /// \~english A server's Initial in a datagram under 1200 bytes (14.1).
    /// \~spanish Un Initial en un datagrama de menos de 1200 bytes, en el servidor (14.1).  \~
    uint64_t small_initial = 0;
    /// \~english An Initial from a server carrying a token (17.2.2).
    /// \~spanish Un Initial de un servidor que lleva testigo (17.2.2).  \~
    uint64_t initial_with_token = 0;
    /**
     * \~english
     * 0-RTT packets not opened: at a client, which never does (RFC 9001,
     * 5.6); at a server that turned 0-RTT down, which MUST NOT (4.6.2); or
     * once their keys were gone (4.9.3).
     * \~spanish
     * Paquetes 0-RTT no abiertos: en un cliente, que nunca lo hace (RFC 9001,
     * 5.6); en un servidor que rechazo el 0-RTT, que NO DEBE (4.6.2); o cuando ya
     * no estaban sus claves (4.9.3).
     * \~
     */
    uint64_t early = 0;
};

/**
 * @brief
 * \~english Control frames sent, retransmissions included: what the connection said, counted.
 * \~spanish Tramas de control mandadas, retransmisiones incluidas: lo que dijo la conexion, contado.
 * \~
 */
struct SendCounts {
    uint64_t handshake_done = 0;
    uint64_t max_data = 0;
    uint64_t max_stream_data = 0;
    uint64_t max_streams = 0;
    uint64_t reset_stream = 0;
    uint64_t stop_sending = 0;
    uint64_t ping = 0;
    uint64_t connection_close = 0;
    uint64_t new_connection_id = 0;
    uint64_t retire_connection_id = 0;
    uint64_t data_blocked = 0;
    uint64_t stream_data_blocked = 0;
    uint64_t streams_blocked = 0;
};

/**
 * @brief
 * \~english One QUIC connection.
 * \~spanish Una conexion QUIC.
 * \~
 */
class Connection final : private RecoveryListener {
public:
    Connection(Crypto &crypto, const ConnectionConfig &config) noexcept;
    ~Connection() override;

    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    /// \~english Whether every table could be allocated.  \~spanish Si se pudieron reservar todas las tablas.  \~
    bool ready() const noexcept;

    /**
     * @brief
     * \~english Derives the Initial keys from the destination ID of the client's first Initial.
     * \~spanish Saca las claves Initial del identificador de destino del primer Initial del cliente.
     * \~
     *
     * \~english
     * A client passes the ID it chose.  A server passes the destination of the
     * Initial the acceptor admitted -- after a Retry, the Retry's own ID, which
     * is what the client derives its keys from by then.
     * \~spanish
     * Un cliente pasa el identificador que eligio.  Un servidor pasa el destino
     * del Initial que admitio el acceptor -- tras un Retry, el del propio Retry,
     * que es del que saca el cliente sus claves para entonces.
     * \~
     */
    bool set_initial_keys(const uint8_t *odcid, size_t len) noexcept;

    /**
     * @brief
     * \~english A server whose client came back with a valid Retry token: no amplification limit (8.1.2).
     * \~spanish Un servidor cuyo cliente volvio con un testigo de Retry valido: sin limite de amplificacion (8.1.2).
     * \~
     */
    void set_address_validated(uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english A client's attempt ended in Version Negotiation: the versions the server offered.
     * \~spanish El intento de un cliente acabo en Version Negotiation: las versiones que ofrecio el servidor.
     * \~
     *
     * \~english
     * The connection is Closed, silently (6.2): no version in common with
     * this one.  Starting again with one of these is a decision for whoever
     * created the connection -- and it has to be a new connection.
     * \~spanish
     * La conexion queda Closed, en silencio (6.2): ninguna version en comun con
     * esta.  Empezar de nuevo con una de estas es una decision de quien creo la
     * conexion -- y tiene que ser una conexion nueva.
     * \~
     *
     * @return \~english how many were offered; at most @p room are written
     *         \~spanish cuantas se ofrecieron; se escriben como mucho @p room  \~
     */
    size_t offered_versions(uint32_t *out, size_t room) const noexcept;
    bool ended_in_version_negotiation() const noexcept { return vn_received_; }

    /// \~english Whether a Retry was accepted, and the ID it came from (for retry_source_connection_id).
    /// \~spanish Si se acepto un Retry, y el identificador del que llego (para retry_source_connection_id).  \~
    bool retried() const noexcept { return retried_; }
    const uint8_t *retry_source_cid(size_t &len) const noexcept {
        len = retry_scid_len_;
        return retry_scid_;
    }

    /**
     * @brief
     * \~english Installs the secrets of a space, as the handshake produces them (RFC 9001, 4.1).
     * \~spanish Instala los secretos de un espacio, segun los produce el saludo (RFC 9001, 4.1).
     * \~
     *
     * \~english
     * Secrets, not keys: the keys of every later 1-RTT phase come from the
     * secret (6.1), so the connection needs it, and it is what TLS hands out.
     * The connection derives and keeps them; the caller's copies are its own.
     * \~spanish
     * Secretos, no claves: las claves de cada fase 1-RTT posterior salen del
     * secreto (6.1), asi que la conexion lo necesita, y es lo que entrega TLS.
     * La conexion deriva y guarda; las copias de quien llama son suyas.
     * \~
     */
    bool install_secrets(Space s, Aead a, const uint8_t *read_secret, const uint8_t *write_secret,
                         size_t len, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Server: the IDs the acceptor saw, which the transport parameters must name (RFC 9000, 7.3).
     * \~spanish Servidor: los identificadores que vio el acceptor, que los parametros de transporte deben nombrar (RFC 9000, 7.3).
     * \~
     *
     * \~english
     * @p odcid is the destination of the client's very first Initial --
     * before any Retry.  @p retry_scid is the Retry's source ID when there was
     * one, and empty otherwise.  Without this call a server names the ID its
     * Initial keys came from, which is right only when there was no Retry.
     * \~spanish
     * @p odcid es el destino del primerisimo Initial del cliente -- antes de
     * cualquier Retry.  @p retry_scid es el identificador de origen del Retry
     * cuando lo hubo, y vacio si no.  Sin esta llamada un servidor nombra el
     * identificador del que salieron sus claves Initial, lo que solo es correcto
     * cuando no hubo Retry.
     * \~
     */
    bool set_original_ids(const uint8_t *odcid, size_t odcid_len, const uint8_t *retry_scid,
                          size_t retry_len) noexcept;

    /**
     * @brief
     * \~english This end's transport parameters, encoded: what it runs with, and the IDs of 7.3.
     * \~spanish Los parametros de transporte de este extremo, codificados: con lo que funciona, y los identificadores de 7.3.
     * \~
     *
     * \~english
     * Built from the configuration the connection actually uses -- its
     * windows, its stream limits, its ACK delay -- so what it announces and
     * what it enforces cannot drift apart.
     * \~spanish
     * Hechos con la configuracion que la conexion usa de verdad -- sus ventanas,
     * sus limites de flujos, su retardo de ACK --, asi que lo que anuncia y lo
     * que hace cumplir no pueden separarse.
     * \~
     *
     * @return \~english the size, or 0 if it does not fit  \~spanish el tamano, o 0 si no cabe  \~
     */
    size_t local_transport_params(uint8_t *out, size_t room) const noexcept;

    /**
     * @brief
     * \~english Server: the part of its transport parameters a client may remember for 0-RTT (RFC 9000, 7.4.1).
     * \~spanish Servidor: la parte de sus parametros de transporte que un cliente puede recordar para 0-RTT (RFC 9000, 7.4.1).
     * \~
     *
     * \~english
     * Bound into the tickets it issues and compared when 0-RTT comes back: 0-RTT is only
     * accepted with them unchanged, so no remembered limit is ever lowered.
     * \~spanish
     * Atada a los tickets que emite y comparada cuando vuelve el 0-RTT: solo se
     * acepta con ella sin cambios, asi que nunca baja ningun limite recordado.
     * \~
     */
    size_t early_context(uint8_t *out, size_t room) const noexcept;

    /**
     * @brief
     * \~english The peer's transport parameters, as the handshake brought them: checked, authenticated, applied.
     * \~spanish Los parametros de transporte del otro, tal como los trajo el saludo: comprobados, autenticados, aplicados.
     * \~
     *
     * \~english
     * An invalid value, or IDs that do not match the ones the Initial
     * packets carried (7.3), closes the connection with
     * TRANSPORT_PARAMETER_ERROR; the answer is false then.  Applied as soon
     * as they arrive: a server needs the client's limits for what it sends
     * before the handshake completes.  A second call changes nothing.
     * \~spanish
     * Un valor invalido, o identificadores que no casan con los que llevaron los
     * paquetes Initial (7.3), cierra la conexion con TRANSPORT_PARAMETER_ERROR;
     * la respuesta es falso entonces.  Se aplican en cuanto llegan: un servidor
     * necesita los limites del cliente para lo que manda antes de que acabe el
     * saludo.  Una segunda llamada no cambia nada.
     * \~
     */
    bool on_peer_transport_params(const uint8_t *data, size_t n, uint64_t now_us) noexcept;
    bool has_peer_transport_params() const noexcept { return peer_params_known_; }

    /**
     * @brief
     * \~english Client: the server's transport parameters from an earlier connection, for 0-RTT (RFC 9000, 7.4.1).
     * \~spanish Cliente: los parametros de transporte del servidor de una conexion anterior, para 0-RTT (RFC 9000, 7.4.1).
     * \~
     *
     * \~english
     * Only what may be remembered is applied -- the limits, the idle
     * timeout, the datagram size, migration -- never the ACK timing, the IDs,
     * the preferred address or the reset token; the handshake's values
     * replace them.  False if they do not decode, or it is too late.
     * \~spanish
     * Solo se aplica lo que se puede recordar -- los limites, el plazo de
     * inactividad, el tamano de datagrama, la migracion --, nunca el tiempo de
     * ACK, los identificadores, la direccion preferida ni el testigo; los valores
     * del saludo los sustituyen.  Falso si no se decodifican, o ya es tarde.
     * \~
     */
    bool remember_transport_params(const uint8_t *data, size_t n) noexcept;

    /**
     * @brief
     * \~english The 0-RTT secret: a client seals its early packets with it, a server opens them (RFC 9001, 4.6, 5.6).
     * \~spanish El secreto de 0-RTT: un cliente sella con el sus paquetes tempranos, un servidor los abre (RFC 9001, 4.6, 5.6).
     * \~
     *
     * \~english
     * A client sends in 0-RTT packets what it has for the application space
     * until it has 1-RTT keys; what goes there is what the application chose
     * to send before the handshake -- this does not decide it (5.6).
     * \~spanish
     * Un cliente manda en paquetes 0-RTT lo que tiene para el espacio de
     * aplicacion hasta tener claves 1-RTT; lo que va ahi es lo que la aplicacion
     * decidio mandar antes del saludo -- esto no lo decide (5.6).
     * \~
     */
    bool install_early_secret(Aead a, const uint8_t *secret, size_t len, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english 0-RTT turned down (RFC 9001, 4.6.2).
     * \~spanish 0-RTT rechazado (RFC 9001, 4.6.2).
     * \~
     *
     * \~english
     * A server opens no 0-RTT packet from then on, kept ones included.  A
     * client stops sending them, forgets their recovery state (RFC 9002,
     * 6.4) and resets every stream and the connection's flow control: its
     * application sees `early_rejected()` and starts over.
     * \~spanish
     * Un servidor no abre ningun paquete 0-RTT desde entonces, tampoco los
     * guardados.  Un cliente deja de mandarlos, olvida su estado de recuperacion
     * (RFC 9002, 6.4) y reinicia todos los flujos y el control de flujo de la
     * conexion: su aplicacion ve `early_rejected()` y empieza de nuevo.
     * \~
     */
    void reject_early(uint64_t now_us) noexcept;
    bool early_rejected() const noexcept { return early_rejected_; }
    /// \~english 0-RTT packets sealed (client) and opened (server).  \~spanish Paquetes 0-RTT sellados (cliente) y abiertos (servidor).  \~
    uint64_t early_sent() const noexcept { return early_sent_; }
    uint64_t early_opened() const noexcept { return early_opened_; }
    /// \~english Whether the 0-RTT keys are still held (RFC 9001, 4.9.3).  \~spanish Si aun se tienen las claves 0-RTT (RFC 9001, 4.9.3).  \~
    bool has_early_keys() const noexcept { return early_have_; }
    /// \~english What the peer's MAX_DATA still lets this end send.  \~spanish Lo que el MAX_DATA del otro aun deja mandar a este extremo.  \~
    uint64_t send_credit() const noexcept { return send_flow_.credit(); }

    /**
     * @brief
     * \~english Starts a 1-RTT key update now, if the rules allow it (RFC 9001, 6).
     * \~spanish Empieza ahora una actualizacion de claves 1-RTT, si las reglas lo permiten (RFC 9001, 6).
     * \~
     *
     * \~english
     * They also start on their own before the AEAD's limit; this is for
     * whoever wants one sooner.  When it cannot start, the answer says why.
     * \~spanish
     * Tambien empiezan solas antes del limite del AEAD; esto es para quien
     * quiera una antes.  Cuando no puede empezar, la respuesta dice por que.
     * \~
     */
    KeyUpdate update_keys(uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Hands out fresh connection IDs and asks the peer to retire all the earlier ones (19.15).
     * \~spanish Reparte identificadores de conexion nuevos y pide al otro que retire todos los anteriores (19.15).
     * \~
     *
     * \~english
     * The old ones keep working until the peer retires them, so nothing is
     * lost in between; what the peer sees is one Retire Prior To.  Refused
     * (false) while the peer has not yet retired everything the previous one
     * asked for (5.1.2).
     * \~spanish
     * Los viejos siguen valiendo hasta que el otro los retira, asi que no se
     * pierde nada por el camino; lo que ve el otro es un Retire Prior To.  Se
     * niega (falso) mientras el otro no haya retirado todo lo que pidio el
     * anterior (5.1.2).
     * \~
     */
    bool renew_connection_ids() noexcept;

    /// \~english Whether @p cid is one of this end's active IDs: what a router needs to know.
    /// \~spanish Si @p cid es uno de los identificadores activos de este extremo: lo que necesita saber un enrutador.  \~
    bool owns_cid(const uint8_t *cid, size_t len) const noexcept;

    /**
     * @brief
     * \~english The @p i-th of this end's active IDs, with its sequence number and reset token.
     * \~spanish El @p i-esimo de los identificadores activos de este extremo, con su numero de secuencia y su testigo.
     * \~
     *
     * \~english What a router walks to send each ID's packets here.  False past the last one.
     * \~spanish Lo que recorre un enrutador para mandar aqui los paquetes de cada identificador.  Falso pasado el ultimo.  \~
     */
    bool local_cid(size_t i, uint64_t &seq, const uint8_t *&cid, const uint8_t *&token) const noexcept;

    /// \~english The sequence number of the destination ID in use.  \~spanish El numero de secuencia del identificador de destino en uso.  \~
    uint64_t peer_cid_sequence() const noexcept { return peer_seq_in_use_; }
    const CidCounts &cids() const noexcept { return cid_counts_; }

    /// \~english The peer said, statelessly, that it has no such connection (10.3.1).
    /// \~spanish El otro dijo, sin estado, que no tiene esta conexion (10.3.1).  \~
    bool closed_by_reset() const noexcept { return closed_by_reset_; }

    /// \~english The key phase this end seals with.  \~spanish La fase de clave con la que sella este extremo.  \~
    bool key_phase() const noexcept { return one_rtt_.write_phase; }
    const KeyUpdateCounts &key_updates() const noexcept { return key_counts_; }

    /// \~english Throws a space's keys away, and what it had in flight.
    /// \~spanish Tira las claves de un espacio, y lo que tenia en vuelo.  \~
    void discard_keys(Space s, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english The handshake is confirmed (RFC 9001, 4.1.2).
     * \~spanish El saludo esta confirmado (RFC 9001, 4.1.2).
     * \~
     *
     * \~english
     * A server says so to the client with HANDSHAKE_DONE; a client learns it
     * by receiving one, and calls nothing.
     * \~spanish
     * Un servidor se lo dice al cliente con HANDSHAKE_DONE; un cliente lo sabe al
     * recibir uno, y no llama a nada.
     * \~
     */
    void handshake_confirmed(uint64_t now_us) noexcept;
    bool is_handshake_confirmed() const noexcept { return confirmed_; }

    /**
     * @brief
     * \~english A datagram arrived on @p path; it is unprotected in place.
     * \~spanish Llego un datagrama por @p path; se desprotege en su sitio.
     * \~
     */
    void on_datagram(const Path &path, uint8_t *data, size_t n, Ecn ecn, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Composes the next datagram to send, and the path it goes on; zero if there is nothing now.
     * \~spanish Compone el siguiente datagrama a mandar, y el camino por el que va; cero si ahora no hay nada.
     * \~
     *
     * \~english
     * Most go on the path in use; a path being validated gets its own
     * datagrams, carrying only PATH_CHALLENGE and PATH_RESPONSE (8.2).
     * \~spanish
     * La mayoria van por el camino en uso; un camino que se esta validando recibe
     * sus propios datagramas, que solo llevan PATH_CHALLENGE y PATH_RESPONSE
     * (8.2).
     * \~
     */
    size_t build_datagram(Path &path, uint8_t *out, size_t room, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english A client checks it can reach the server from a new local address, without moving (9.1).
     * \~spanish Un cliente comprueba que llega al servidor desde una direccion local nueva, sin moverse (9.1).
     * \~
     *
     * \~english
     * @p path is the new local address and the server's address in use.  The
     * probes go out with an ID of the server's not used on any other path
     * (9.5); failing only means that path is not usable.
     * \~spanish
     * @p path es la direccion local nueva y la del servidor en uso.  Los sondeos
     * salen con un identificador del servidor que no se uso en ningun otro camino
     * (9.5); que falle solo significa que ese camino no sirve.
     * \~
     */
    Migration probe_path(const Path &path, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english A client moves to a new local address: everything from now on goes from it (9.2).
     * \~spanish Un cliente se mueve a una direccion local nueva: todo lo de ahora en adelante sale de ella (9.2).
     * \~
     *
     * \~english
     * The server's address was proven during the handshake, so it does not
     * wait: the path is validated alongside, and once it is, congestion
     * control and RTT start over on it (9.4).
     * \~spanish
     * La direccion del servidor quedo probada en el saludo, asi que no espera: el
     * camino se valida a la vez, y cuando lo esta, el control de congestion y el
     * RTT empiezan de cero en el (9.4).
     * \~
     */
    Migration migrate(const Path &path, uint64_t now_us) noexcept;

    /// \~english The path in use, and whether its peer address is proven.
    /// \~spanish El camino en uso, y si la direccion del otro esta probada.  \~
    const Path &path() const noexcept { return paths_[active_].addr; }
    bool address_validated() const noexcept { return paths_[active_].validated; }
    const PathCounts &paths() const noexcept { return path_counts_; }

    /// \~english The earliest moment something has to happen; kNever if nothing will.
    /// \~spanish El primer momento en que algo tiene que pasar; kNever si nada.  \~
    uint64_t timer() const noexcept;

    /// \~english Handles whatever was due at @p now_us.  \~spanish Atiende lo que tocaba en @p now_us.  \~
    void on_timer(uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Closes the connection with an error or NO_ERROR (10.2).
     * \~spanish Cierra la conexion con un error o NO_ERROR (10.2).
     * \~
     *
     * @param application \~english the code is the application's (0x1d), not the transport's (0x1c)
     *                    \~spanish el codigo es de la aplicacion (0x1d), no del transporte (0x1c)  \~
     */
    void close(uint64_t code, bool application, uint64_t trigger_frame, uint64_t now_us) noexcept;

    ConnState state() const noexcept { return state_; }
    /// \~english Who closed, and with what.  \~spanish Quien cerro, y con que.  \~
    bool closed_by_peer() const noexcept { return closed_by_peer_; }
    uint64_t close_code() const noexcept { return close_code_; }
    bool close_is_application() const noexcept { return close_app_; }
    uint64_t close_frame() const noexcept { return close_frame_; }
    /// \~english Why it ended, or None.  \~spanish Por que acabo, o None.  \~
    EndReason end_reason() const noexcept { return end_; }

    StreamTable &streams() noexcept { return streams_; }

    /**
     * @brief
     * \~english The application read @p n bytes from @p s: returns them to both windows.
     * \~spanish La aplicacion leyo @p n bytes de @p s: los devuelve a las dos ventanas.
     * \~
     */
    void consume(Stream &s, size_t n) noexcept;

    /// \~english The handshake's buffers, per space.  \~spanish Los buffers del saludo, por espacio.  \~
    SendStream &crypto_send(Space s) noexcept { return *crypto_send_[static_cast<size_t>(s)]; }
    RecvStream &crypto_recv(Space s) noexcept { return *crypto_recv_[static_cast<size_t>(s)]; }

    /// \~english The handshake read @p n bytes of a space's CRYPTO data: its window moves on.
    /// \~spanish El saludo leyo @p n bytes de los datos CRYPTO de un espacio: su ventana avanza.  \~
    void consume_crypto(Space s, size_t n) noexcept;

    Recovery &recovery() noexcept { return recovery_; }
    const DropCounts &drops() const noexcept { return drops_; }
    const SendCounts &sent() const noexcept { return sent_; }
    /// \~english Every byte in and out, on every path.  \~spanish Todos los bytes de entrada y salida, por todos los caminos.  \~
    uint64_t bytes_received() const noexcept { return bytes_in_; }
    uint64_t bytes_sent() const noexcept { return bytes_out_; }

private:
    struct Keys {
        PacketKeys read;
        PacketKeys write;
        bool have = false;
    };

    /// \~english One retransmittable thing a packet carried.
    /// \~spanish Una cosa retransmisible que llevaba un paquete.  \~
    struct FrameRecord {
        uint8_t kind;
        bool fin;
        uint16_t len;
        uint64_t id;
        uint64_t offset;
    };
    static constexpr size_t kRecordsPerPacket = 6;
    struct PacketRecord {
        uint64_t tag;
        uint8_t count;
        FrameRecord frames[kRecordsPerPacket];
    };

    void on_acked(Space space, const SentPacket &p) noexcept override;
    void on_lost(Space space, const SentPacket &p) noexcept override;

    void fail(TransportError e, uint64_t frame_type, uint64_t now_us) noexcept;
    bool process_packet(uint8_t *p, const PacketHeader &h, Ecn ecn, uint64_t now_us) noexcept;
    bool on_packet_path(Space s, uint64_t pn, bool probing, const uint8_t *dcid, size_t dcid_len,
                        uint64_t now_us) noexcept;
    /// \~english How a 1-RTT packet opened.  \~spanish Como se abrio un paquete 1-RTT.  \~
    enum class Opened : uint8_t { Ok, Forged, Failed, ReservedBits, KeyUpdateViolation };
    Opened open_one_rtt(uint8_t *p, const PacketHeader &h, Unprotected &u,
                        uint64_t now_us) noexcept;
    bool make_generation(const uint8_t *secret, PacketKeys &out) noexcept;
    void drop_generation(PacketKeys &k) noexcept;
    bool roll_read(uint64_t pn, uint64_t now_us) noexcept;
    bool roll_write() noexcept;
    void forget_one_rtt() noexcept;
    uint64_t confidentiality_limit() const noexcept;
    uint64_t integrity_limit() const noexcept;
    void process_version_negotiation(const uint8_t *p, const PacketHeader &h) noexcept;
    void process_retry(const uint8_t *p, const PacketHeader &h, uint64_t now_us) noexcept;
    bool derive_initial_keys(const uint8_t *dcid, size_t len) noexcept;
    bool process_frames(Space s, const uint8_t *payload, size_t n, PacketType type,
                        bool &eliciting, bool &probing, uint64_t now_us) noexcept;
    /// \~english When a packet is padded to a full datagram (14.1).  \~spanish Cuando un paquete se rellena a un datagrama entero (14.1).  \~
    enum class Pad : uint8_t { Never, Always, IfEliciting };

    struct PathState;
    struct PeerCid;
    /**
     * \~english
     * @p probe: a path-validation packet for that path, sealed with its ID
     * @p dest and carrying only its PATH_RESPONSE and PATH_CHALLENGE frames.
     * Null: an ordinary packet on the path in use.
     * \~spanish
     * @p probe: un paquete de validacion para ese camino, sellado con su
     * identificador @p dest y que solo lleva sus PATH_RESPONSE y PATH_CHALLENGE.
     * Nulo: un paquete normal por el camino en uso.
     * \~
     */
    size_t build_packet(Space s, uint8_t *out, size_t room, Pad pad, bool &padded,
                        uint64_t now_us, PathState *probe = nullptr,
                        const PeerCid *dest = nullptr, bool early = false) noexcept;
    /// \~english @p early: a 0-RTT packet, where no ACK, CRYPTO or connection-ID frame goes (RFC 9000, 12.5).
    /// \~spanish @p early: un paquete 0-RTT, donde no va ninguna trama ACK, CRYPTO ni de identificadores (RFC 9000, 12.5).  \~
    size_t write_frames(Space s, uint8_t *p, size_t room, PacketRecord &rec,
                        bool &eliciting, uint64_t &ack_largest, uint64_t now_us, bool early = false) noexcept;
    size_t write_probe_frames(PathState &path, uint8_t *p, size_t room, bool padded) noexcept;
    size_t amplification_budget(size_t path) const noexcept;
    void restart_idle(uint64_t now_us) noexcept;
    bool can_open(Space s) const noexcept;
    bool keep_for_later(const uint8_t *p, size_t n, Space s, Ecn ecn, bool early = false) noexcept;
    /// \~english @p early: the 0-RTT packets kept, and only those.  \~spanish @p early: los paquetes 0-RTT guardados, y solo esos.  \~
    void replay(Space s, uint64_t now_us, bool early = false) noexcept;

    /**
     * \~english
     * Packets that arrived before their keys: a client's Handshake packets
     * right behind the server's Initial, or 1-RTT packets a server may not
     * open until the handshake completes (RFC 9001, 5.7).  A few, of bounded
     * size, allocated only if ever needed.
     * \~spanish
     * Paquetes que llegaron antes que sus claves: los Handshake justo detras del
     * Initial del servidor, o paquetes 1-RTT que un servidor no puede abrir hasta
     * completar el saludo (RFC 9001, 5.7).  Unos pocos, de tamano acotado,
     * reservados solo si alguna vez hacen falta.
     * \~
     */
    struct Pending {
        uint8_t bytes[1500];
        /// \~english The path it came on: opened later, it is still that path's packet.
        /// \~spanish El camino por el que llego: abierto despues, sigue siendo un paquete de ese camino.  \~
        Path path;
        uint64_t arrived_us;
        uint16_t len;
        uint8_t space;
        Ecn ecn;
        /// \~english A 0-RTT packet: it waits for the 0-RTT keys, not the 1-RTT ones.
        /// \~spanish Un paquete 0-RTT: espera a las claves 0-RTT, no a las 1-RTT.  \~
        bool early;
        bool used;
    };
    static constexpr size_t kPendingPackets = 4;
    Pending *pending_ = nullptr;
    bool discarded_[kSpaces] = {false, false, false};
    uint64_t pto_duration() const noexcept;
    PacketRecord *record_for(uint64_t tag) noexcept;
    static void add_record(PacketRecord &rec, uint8_t kind, uint64_t id, uint64_t offset,
                           size_t len, bool fin) noexcept;
    static bool full(const PacketRecord &rec) noexcept { return rec.count >= kRecordsPerPacket; }

    Crypto &crypto_;
    ConnectionConfig cfg_;
    ConnState state_ = ConnState::Active;

    Keys keys_[kSpaces];

    /* \~english
     * 0-RTT: one direction only -- a client's write keys, a server's read
     * keys (RFC 9001, 5.6) -- in the application space's numbering.
     * \~spanish
     * 0-RTT: una sola direccion -- las claves de escritura de un cliente, las de
     * lectura de un servidor (RFC 9001, 5.6) -- en la numeracion del espacio de
     * aplicacion.
     * \~ */
    void own_params(TransportParams &tp) const noexcept;
    PacketKeys early_keys_;
    bool early_have_ = false;
    bool early_gone_ = false;
    bool early_rejected_ = false;
    uint64_t early_discard_at_ = kNever;
    uint64_t early_sent_ = 0;
    uint64_t early_opened_ = 0;
    void forget_early() noexcept;

    /**
     * \~english
     * The 1-RTT key phases (RFC 9001, 6).  `keys_[Application]` holds the
     * CURRENT generation and owns both header-protection states, which never
     * change; `next` (read side, prepared in advance so that trying it takes
     * no more time than any other key, 6.3) and `prev` (kept 3 PTO for late
     * packets) hold only an AEAD state and an IV, and borrow nothing.
     * \~spanish
     * Las fases de clave 1-RTT (RFC 9001, 6).  `keys_[Application]` tiene la
     * generacion ACTUAL y es dueno de los dos estados de proteccion de cabecera,
     * que no cambian nunca; `next` (lado de lectura, preparado de antemano para
     * que probarlo no tarde mas que cualquier otra clave, 6.3) y `prev` (guardado
     * 3 PTO para paquetes tardios) solo tienen un estado AEAD y un IV, y no
     * toman prestado nada.
     * \~
     */
    struct OneRtt {
        Aead aead = Aead::Aes128Gcm;
        size_t secret_len = 0;
        /// \~english The secrets of the CURRENT read and write generations.
        /// \~spanish Los secretos de las generaciones ACTUALES de lectura y escritura.  \~
        uint8_t read_secret[kMaxSecret] = {};
        uint8_t write_secret[kMaxSecret] = {};
        PacketKeys read_next;
        PacketKeys read_prev;
        uint64_t prev_until = kNever;
        bool read_phase = false;
        bool write_phase = false;
        /// \~english The lowest packet number opened with the current read keys (6.4).
        /// \~spanish El numero de paquete mas bajo abierto con las claves de lectura actuales (6.4).  \~
        uint64_t first_recv_pn = kNever;
        /// \~english The first packet number sealed with the current write keys (6.5).
        /// \~spanish El primer numero de paquete sellado con las claves de escritura actuales (6.5).  \~
        uint64_t first_sent_pn = kNever;
        /// \~english When a packet of the current write phase was first acknowledged (6.5).
        /// \~spanish Cuando se confirmo por primera vez un paquete de la fase de escritura actual (6.5).  \~
        uint64_t phase_acked_at = kNever;
        uint64_t sealed = 0;
        /**
         * \~english
         * The packet that brought an update the PEER started, until an ACK
         * covering it goes out under the new keys: another update the peer
         * starts before that is it updating twice without waiting (6.2).  Its
         * answers to this end's updates never count.
         * \~spanish
         * El paquete que trajo una actualizacion que EMPEZO el otro extremo, hasta
         * que sale un ACK que lo cubra con las claves nuevas: otra actualizacion
         * que empiece el otro antes de eso es el actualizando dos veces sin
         * esperar (6.2).  Sus respuestas a las actualizaciones de este extremo no
         * cuentan nunca.
         * \~
         */
        uint64_t unanswered_pn = kNever;
    };
    OneRtt one_rtt_;
    KeyUpdateCounts key_counts_;

    /**
     * \~english
     * Connection IDs (RFC 9000, 5.1).  This end's: the ones handed out, each
     * with its reset token, owed until a NEW_CONNECTION_ID carrying it is
     * acknowledged.  The peer's: the ones received, one of them in use as
     * destination; retiring one owes a RETIRE_CONNECTION_ID.  Both tables are
     * fixed: the peer cannot make them grow.
     * \~spanish
     * Identificadores de conexion (RFC 9000, 5.1).  Los de este extremo: los
     * repartidos, cada uno con su testigo de reinicio, debidos hasta que se
     * confirma un NEW_CONNECTION_ID que lo lleve.  Los del otro: los recibidos,
     * uno de ellos en uso como destino; retirar uno debe un
     * RETIRE_CONNECTION_ID.  Las dos tablas son fijas: el otro no puede hacerlas
     * crecer.
     * \~
     */
    static constexpr size_t kMaxCids = 8;
    struct LocalCid {
        uint64_t seq = 0;
        uint8_t cid[kMaxConnectionId] = {};
        uint8_t token[kResetTokenSize] = {};
        bool active = false;
        bool owed = false;
    };
    struct PeerCid {
        uint64_t seq = 0;
        uint8_t cid[kMaxConnectionId] = {};
        uint8_t len = 0;
        uint8_t token[kResetTokenSize] = {};
        bool active = false;
        bool has_token = false;
        /// \~english Packets were sent to it: only then may its token end the connection (10.3.1).
        /// \~spanish Se mandaron paquetes a el: solo entonces puede su testigo acabar la conexion (10.3.1).  \~
        bool used = false;
    };
    LocalCid local_cids_[kMaxCids];
    uint64_t next_local_seq_ = 1;
    uint64_t local_retire_prior_to_ = 0;
    PeerCid peer_cids_[kMaxCids];
    uint64_t peer_retire_prior_to_ = 0;
    uint64_t peer_seq_in_use_ = 0;
    /**
     * \~english
     * RETIRE_CONNECTION_ID frames owed: room for twice the most IDs this end
     * keeps, as 5.1.2 asks.  An ID is never forgotten without retiring it;
     * past this room the connection closes instead.
     * \~spanish
     * Tramas RETIRE_CONNECTION_ID que se deben: sitio para el doble de los
     * identificadores que guarda como mucho este extremo, como pide 5.1.2.  Un
     * identificador nunca se olvida sin retirarlo; pasado este sitio, la
     * conexion se cierra en su lugar.
     * \~
     */
    uint64_t retire_owed_[2 * kMaxCids] = {};
    size_t retire_owed_count_ = 0;
    /// \~english Owed plus sent and not yet acknowledged: what the room is measured against.
    /// \~spanish Debidas mas mandadas y aun sin confirmar: contra lo que se mide el sitio.  \~
    size_t retire_outstanding_ = 0;
    /// \~english The highest sequence number this end has sent (19.16).  \~spanish El numero de secuencia mas alto que ha mandado este extremo (19.16).  \~
    uint64_t max_sent_local_seq_ = 0;
    /// \~english The destination ID of the packet being processed: RETIRE_CONNECTION_ID may not name it.
    /// \~spanish El identificador de destino del paquete que se procesa: RETIRE_CONNECTION_ID no puede nombrarlo.  \~
    const uint8_t *packet_dcid_ = nullptr;
    size_t packet_dcid_len_ = 0;
    /// \~english The size of the datagram being processed: an Initial in a small one is dropped (14.1).
    /// \~spanish El tamano del datagrama que se procesa: un Initial en uno pequeno se tira (14.1).  \~
    size_t datagram_len_ = 0;
    /**
     * \~english
     * When the packet being processed arrived: now, or -- for one kept until
     * its keys came -- the moment it was kept.  The wait for keys belongs in
     * the ACK Delay (13.2.5).
     * \~spanish
     * Cuando llego el paquete que se procesa: ahora, o -- para uno guardado hasta
     * que llegaron sus claves -- el momento en que se guardo.  La espera por las
     * claves va dentro del ACK Delay (13.2.5).
     * \~
     */
    uint64_t arrival_us_ = 0;
    void run_loss_timer(uint64_t now_us) noexcept;
    bool closed_by_reset_ = false;
    CidCounts cid_counts_;

    void top_up_cids() noexcept;
    PeerCid *peer_cid_by_seq(uint64_t seq) noexcept;
    bool owe_retire(uint64_t seq) noexcept;
    void requeue_retire(uint64_t seq) noexcept;
    bool use_peer_cid(PeerCid &c) noexcept;
    void learn_peer_cid(const uint8_t *cid, size_t len) noexcept;
    bool on_new_connection_id(const Frame &f, const uint8_t *payload, uint64_t now_us) noexcept;
    bool on_retire_connection_id(const Frame &f, uint64_t now_us) noexcept;
    bool check_stateless_reset(const uint8_t *tail, const Address &from) const noexcept;
    AckTracker acks_[kSpaces];
    uint64_t next_pn_[kSpaces] = {0, 0, 0};
    Recovery recovery_;
    StreamTable streams_;
    RecvFlow recv_flow_;
    SendFlow send_flow_;
    RecvStream *crypto_recv_[kSpaces] = {nullptr, nullptr, nullptr};
    SendStream *crypto_send_[kSpaces] = {nullptr, nullptr, nullptr};

    PacketRecord *records_ = nullptr;
    size_t record_cap_ = 0;
    uint64_t next_tag_ = 1;

    bool peer_cid_known_ = false;
    uint8_t odcid_[kMaxConnectionId] = {};
    size_t odcid_len_ = 0;

    /**
     * \~english
     * What happens before the server's first real packet, on the client.  Once
     * any packet from the server has been processed, neither a Version
     * Negotiation nor a Retry is believed any more (6.2, 17.2.5.2).
     * \~spanish
     * Lo que pasa antes del primer paquete de verdad del servidor, en el
     * cliente.  En cuanto se proceso cualquier paquete del servidor, ya no se
     * cree ni un Version Negotiation ni un Retry (6.2, 17.2.5.2).
     * \~
     */
    bool received_any_ = false;
    bool vn_received_ = false;
    static constexpr size_t kOfferedVersions = 8;
    uint32_t offered_[kOfferedVersions] = {};
    size_t offered_count_ = 0;
    bool retried_ = false;
    uint8_t retry_scid_[kMaxConnectionId] = {};
    size_t retry_scid_len_ = 0;
    /// \~english Server: the IDs of 7.3, as the acceptor saw them.  \~spanish Servidor: los identificadores de 7.3, como los vio el acceptor.  \~
    uint8_t original_dcid_[kMaxConnectionId] = {};
    size_t original_dcid_len_ = 0;
    bool original_known_ = false;
    bool peer_params_known_ = false;
    /// \~english The Retry token, repeated in every Initial from then on.  \~spanish El testigo del Retry, repetido en cada Initial desde entonces.  \~
    uint8_t *token_ = nullptr;
    size_t token_len_ = 0;

    bool confirmed_ = false;
    uint64_t bytes_in_ = 0;
    uint64_t bytes_out_ = 0;

    /**
     * \~english
     * Paths (RFC 9000, 8.2 and 9).  A fixed table: the one in use, the last
     * validated one to fall back to while a new one is being proven (9.3.2),
     * and a few being probed.  Each keeps what is said per path: whether its
     * peer address is proven, the challenges in flight and the responses
     * owed, what went in and out of it -- the anti-amplification limit is per
     * address (8) -- and the peer's ID used on it, since one ID MUST NOT go
     * to two addresses (9.5).  A peer cannot make the table grow: a new
     * address takes the place of the least useful one.
     * \~spanish
     * Caminos (RFC 9000, 8.2 y 9).  Una tabla fija: el que esta en uso, el ultimo
     * validado al que volver mientras se prueba uno nuevo (9.3.2), y unos pocos
     * que se sondean.  Cada uno guarda lo que se dice por camino: si la direccion
     * del otro esta probada, los desafios en vuelo y las respuestas debidas, lo
     * que entro y salio por el -- el limite antiamplificacion es por direccion
     * (8) -- y el identificador del otro que se usa en el, porque un mismo
     * identificador NO DEBE ir a dos direcciones (9.5).  El otro no puede hacer
     * crecer la tabla: una direccion nueva ocupa el sitio de la menos util.
     * \~
     */
    static constexpr size_t kMaxPaths = 4;
    static constexpr size_t kNoPath = kMaxPaths;
    static constexpr size_t kChallengesKept = 3;
    static constexpr size_t kResponsesOwed = 2;
    struct PathState {
        Path addr;
        bool used = false;
        /// \~english The peer address is proven (8.1, 8.2.3).  \~spanish La direccion del otro esta probada (8.1, 8.2.3).  \~
        bool validated = false;
        /// \~english A validation is under way.  \~spanish Hay una validacion en marcha.  \~
        bool challenging = false;
        /// \~english A challenge is owed now.  \~spanish Se debe un desafio ahora.  \~
        bool challenge_owed = false;
        /**
         * \~english
         * The data of the latest challenges, and whether each went in a full
         * datagram: an answer to any of them proves the path, and only one
         * sent in 1200 bytes proves its MTU too (8.2.1).
         * \~spanish
         * Los datos de los ultimos desafios, y si cada uno fue en un datagrama
         * completo: la respuesta a cualquiera prueba el camino, y solo uno mandado
         * en 1200 bytes prueba ademas su MTU (8.2.1).
         * \~
         */
        uint8_t challenge[kChallengesKept][kPathDataSize] = {};
        bool challenge_full[kChallengesKept] = {};
        uint8_t challenges = 0;
        uint64_t next_challenge_at = kNever;
        uint64_t challenge_interval = 0;
        uint64_t validation_deadline = kNever;
        /// \~english PATH_RESPONSE data owed, each sent exactly once (8.2.2).
        /// \~spanish Datos de PATH_RESPONSE debidos, cada uno mandado exactamente una vez (8.2.2).  \~
        uint8_t response[kResponsesOwed][kPathDataSize] = {};
        uint8_t responses = 0;
        uint64_t bytes_in = 0;
        uint64_t bytes_out = 0;
        /// \~english The peer's ID this end sends with on this path; kNever: none yet.
        /// \~spanish El identificador del otro con el que manda este extremo por este camino; kNever: aun ninguno.  \~
        uint64_t peer_seq = kNever;
        /// \~english Which of this end's IDs the peer sent to on this path (9.5).
        /// \~spanish A cual de los identificadores de este extremo mando el otro por este camino (9.5).  \~
        uint64_t local_seq_seen = kNever;
        uint64_t last_used = 0;
    };
    PathState paths_[kMaxPaths];
    size_t active_ = 0;
    size_t fallback_ = kNoPath;
    /// \~english The path the congestion control and RTT estimate belong to (9.4).
    /// \~spanish El camino al que pertenecen el control de congestion y la estimacion de RTT (9.4).  \~
    size_t cc_path_ = 0;
    /// \~english The path of the datagram being processed; kNoPath until one of its packets opens.
    /// \~spanish El camino del datagrama que se procesa; kNoPath hasta que se abre uno de sus paquetes.  \~
    size_t rx_path_ = 0;
    Path rx_addr_;
    /// \~english Only the highest-numbered non-probing packet moves the connection (9.3).
    /// \~spanish Solo el paquete no de sondeo de numero mas alto mueve la conexion (9.3).  \~
    uint64_t largest_nonprobing_pn_ = kNever;
    /// \~english A non-probing packet owed on the path in use, after a challenge on it (9.3.3).
    /// \~spanish Un paquete no de sondeo debido por el camino en uso, tras un desafio en el (9.3.3).  \~
    bool nonprobing_owed_ = false;
    PathCounts path_counts_;

    size_t find_path(const Path &p) const noexcept;
    size_t claim_path(const Path &p, uint64_t now_us) noexcept;
    void free_path(size_t i) noexcept;
    bool assign_peer_cid(size_t i, bool may_share) noexcept;
    PeerCid *unused_peer_cid() noexcept;
    uint64_t local_seq_of(const uint8_t *cid, size_t len) const noexcept;
    bool start_validation(size_t i, uint64_t now_us) noexcept;
    void on_path_response(const uint8_t *data, uint64_t now_us) noexcept;
    void path_validated(size_t i, bool full, uint64_t now_us) noexcept;
    void switch_to(size_t i, uint64_t now_us) noexcept;
    void run_path_timers(uint64_t now_us) noexcept;
    uint64_t path_timer() const noexcept;
    size_t build_probe(size_t i, uint8_t *out, size_t room, uint64_t now_us) noexcept;
    uint64_t initial_pto() const noexcept;
    Migration check_migration(const Path &p) const noexcept;

    /// \~english Control frames owed.  \~spanish Tramas de control que se deben.  \~
    bool max_data_owed_ = false;
    bool max_streams_owed_[2] = {false, false};
    bool handshake_done_owed_ = false;
    bool probe_owed_[kSpaces] = {false, false, false};
    /// \~english Packets received while closing: the answers are spaced out by it (10.2.1).
    /// \~spanish Paquetes recibidos mientras se cierra: las respuestas se espacian con esto (10.2.1).  \~
    uint64_t close_rx_ = 0;
    /// \~english The random spin bit of the ID in use (17.4).  \~spanish El bit de espin aleatorio del identificador en uso (17.4).  \~
    bool spin_bit_ = false;
    void draw_spin_bit() noexcept;
    /// \~english The limits *_BLOCKED frames were last sent at (kNever: none since), and when.
    /// \~spanish Los limites en los que se mandaron los ultimos *_BLOCKED (kNever: ninguno desde entonces), y cuando.  \~
    uint64_t data_blocked_at_ = kNever;
    uint64_t data_blocked_time_ = 0;
    uint64_t streams_blocked_at_[2] = {kNever, kNever};
    void write_blocked(uint8_t *p, size_t room, size_t &used, PacketRecord &rec, bool &eliciting,
                       uint64_t now_us) noexcept;
    uint64_t round_robin_ = 0;

    uint64_t idle_deadline_ = kNever;
    bool sent_eliciting_since_receipt_ = false;
    uint64_t close_deadline_ = kNever;
    bool close_owed_ = false;
    bool closed_by_peer_ = false;
    uint64_t close_code_ = 0;
    bool close_app_ = false;
    uint64_t close_frame_ = 0;
    EndReason end_ = EndReason::None;
    /// \~english Keeps @p r as the reason, unless one was kept already.
    /// \~spanish Guarda @p r como motivo, salvo que ya hubiera uno.  \~
    void ended(EndReason r) noexcept {
        if (end_ == EndReason::None) end_ = r;
    }

    DropCounts drops_;
    SendCounts sent_;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_CONNECTION_H
