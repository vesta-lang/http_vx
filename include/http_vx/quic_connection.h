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
 * This is the core the rest stands on, and it is not the whole of QUIC.  What
 * follows, in this order, each with its own tests: new connection IDs,
 * migration and stateless reset; and the TLS handshake with 0-RTT.  Until
 * the handshake is here, the connection takes secrets through
 * `install_secrets` and learns that the handshake is done through
 * `handshake_confirmed` -- which is exactly what the handshake will call.
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
 * Este es el nucleo sobre el que se apoya el resto, y no es todo QUIC.  Lo que
 * sigue, en este orden, cada cosa con sus pruebas: los identificadores de
 * conexion nuevos, la migracion y el reinicio sin estado; y el saludo de TLS con
 * 0-RTT.  Hasta que el saludo este aqui, la conexion recibe los secretos por
 * `install_secrets` y se entera de que el saludo acabo por `handshake_confirmed`
 * -- que es justo lo que llamara el saludo.
 * \~
 */
#ifndef HTTP_VX_QUIC_CONNECTION_H
#define HTTP_VX_QUIC_CONNECTION_H

#include "http_vx/quic_ack.h"
#include "http_vx/quic_crypto.h"
#include "http_vx/quic_frame.h"
#include "http_vx/quic_packet.h"
#include "http_vx/quic_protection.h"
#include "http_vx/quic_recovery.h"
#include "http_vx/quic_stream_recv.h"
#include "http_vx/quic_stream_send.h"
#include "http_vx/quic_streams.h"

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
    /// \~english A long header whose source ID is not the one the server first gave (7.2).
    /// \~spanish Una cabecera larga cuyo identificador de origen no es el que dio primero el servidor (7.2).  \~
    uint64_t changed_source = 0;
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
    uint64_t path_response = 0;
    uint64_t ping = 0;
    uint64_t connection_close = 0;
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
     * \~english A datagram arrived; it is unprotected in place.
     * \~spanish Llego un datagrama; se desprotege en su sitio.
     * \~
     */
    void on_datagram(uint8_t *data, size_t n, Ecn ecn, uint64_t now_us) noexcept;

    /**
     * @brief
     * \~english Composes the next datagram to send, or returns zero if there is nothing now.
     * \~spanish Compone el siguiente datagrama a mandar, o devuelve cero si ahora no hay nada.
     * \~
     */
    size_t build_datagram(uint8_t *out, size_t room, uint64_t now_us) noexcept;

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
    bool address_validated() const noexcept { return validated_; }
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
                        bool &eliciting, uint64_t now_us) noexcept;
    /// \~english When a packet is padded to a full datagram (14.1).  \~spanish Cuando un paquete se rellena a un datagrama entero (14.1).  \~
    enum class Pad : uint8_t { Never, Always, IfEliciting };

    size_t build_packet(Space s, uint8_t *out, size_t room, Pad pad, bool &padded,
                        uint64_t now_us) noexcept;
    size_t write_frames(Space s, uint8_t *p, size_t room, PacketRecord &rec,
                        bool &eliciting, uint64_t &ack_largest, uint64_t now_us) noexcept;
    size_t amplification_budget() const noexcept;
    void restart_idle(uint64_t now_us) noexcept;
    bool can_open(Space s) const noexcept;
    bool keep_for_later(const uint8_t *p, size_t n, Space s, Ecn ecn) noexcept;
    void replay(Space s, uint64_t now_us) noexcept;

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
        uint16_t len;
        uint8_t space;
        Ecn ecn;
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
    /// \~english The Retry token, repeated in every Initial from then on.  \~spanish El testigo del Retry, repetido en cada Initial desde entonces.  \~
    uint8_t *token_ = nullptr;
    size_t token_len_ = 0;

    bool confirmed_ = false;
    bool validated_ = false;
    uint64_t bytes_in_ = 0;
    uint64_t bytes_out_ = 0;

    /// \~english Control frames owed.  \~spanish Tramas de control que se deben.  \~
    bool max_data_owed_ = false;
    bool max_streams_owed_[2] = {false, false};
    bool handshake_done_owed_ = false;
    bool path_response_owed_ = false;
    uint8_t path_response_[kPathDataSize] = {};
    bool probe_owed_[kSpaces] = {false, false, false};
    bool data_blocked_sent_ = false;
    uint64_t round_robin_ = 0;

    uint64_t idle_deadline_ = kNever;
    bool sent_eliciting_since_receipt_ = false;
    uint64_t close_deadline_ = kNever;
    bool close_owed_ = false;
    bool closed_by_peer_ = false;
    uint64_t close_code_ = 0;
    bool close_app_ = false;
    uint64_t close_frame_ = 0;

    DropCounts drops_;
    SendCounts sent_;
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_CONNECTION_H
