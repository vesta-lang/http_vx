/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/quic_routes.h
 * @brief
 * \~english Which connection a connection ID leads to: what a QUIC server looks up for every datagram (RFC 9000, 5.2).
 * \~spanish A que conexion lleva un identificador de conexion: lo que un servidor QUIC busca con cada datagrama (RFC 9000, 5.2).
 * \~
 *
 * \~english
 * Open addressing with linear probing and backward-shift deletion, like the
 * stream table: no tombstones, so a table that sees millions of IDs come and
 * go never slows down with dead entries.  It is never more than half full --
 * add() refuses past that -- so a probe always ends, and ends soon.
 *
 * One thing is particular to this table: some of its keys are chosen by a
 * stranger.  A client's first destination ID is whatever it wrote, so a hash
 * a client could predict would let it pile every connection it opens onto
 * one run of the table and make each lookup walk it.  The hash is keyed with
 * a secret given at reset(), which is the difference between a table and a
 * denial of service.
 *
 * \~spanish
 * Direccionamiento abierto con sondeo lineal y borrado desplazando hacia
 * atras, como la tabla de flujos: sin lapidas, asi que una tabla que ve ir y
 * venir millones de identificadores nunca se ralentiza con entradas muertas.
 * Nunca esta mas que medio llena -- add() lo rechaza pasado eso --, asi que un
 * sondeo siempre acaba, y acaba pronto.
 *
 * Una cosa es propia de esta tabla: algunas de sus claves las elige un
 * desconocido.  El primer identificador de destino de un cliente es lo que el
 * escribiera, asi que un hash que un cliente pudiera predecir le dejaria
 * amontonar cada conexion que abra en una tirada de la tabla y hacer que cada
 * busqueda la recorra.  El hash va con una clave secreta dada en reset(), que
 * es la diferencia entre una tabla y una denegacion de servicio.
 * \~
 */
#ifndef HTTP_VX_QUIC_ROUTES_H
#define HTTP_VX_QUIC_ROUTES_H

#include "http_vx/quic_packet.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace quic {

/**
 * @brief
 * \~english Connection IDs to owners, keyed with a secret.
 * \~spanish Identificadores de conexion a duenos, con una clave secreta.
 * \~
 */
class CidRoutes {
  public:
    /// \~english No owner.  \~spanish Ningun dueno.  \~
    static constexpr uint32_t kNone = 0xFFFFFFFF;
    /// \~english The secret's size.  \~spanish El tamano del secreto.  \~
    static constexpr size_t kKeySize = 16;

    CidRoutes() noexcept = default;
    ~CidRoutes() { release(); }
    CidRoutes(const CidRoutes &) = delete;
    CidRoutes &operator=(const CidRoutes &) = delete;

    /**
     * @brief
     * \~english Room for @p capacity IDs, hashed with @p key; false if the memory could not be had.
     * \~spanish Sitio para @p capacity identificadores, con hash de clave @p key; falso si no se pudo conseguir la memoria.
     * \~
     */
    bool reset(size_t capacity, const uint8_t *key) noexcept;

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

    /// \~english The owner of @p cid, or kNone.  \~spanish El dueno de @p cid, o kNone.  \~
    uint32_t find(const uint8_t *cid, size_t len) const noexcept;

    /**
     * @brief
     * \~english Routes @p cid to @p owner.
     * \~spanish Lleva @p cid a @p owner.
     * \~
     *
     * \~english
     * One ID, one owner: an ID another owner holds is refused, never shared
     * -- whoever took it second would get the first one's packets.  Also
     * refused: an empty or over-long ID, and one past the capacity.
     * \~spanish
     * Un identificador, un dueno: uno que tiene otro dueno se rechaza, nunca
     * se comparte -- quien lo cogiera segundo recibiria los paquetes del
     * primero --.  Se rechaza tambien uno vacio o demasiado largo, y uno pasada
     * la capacidad.
     * \~
     * @return \~english true if it routes to @p owner now  \~spanish true si ahora lleva a @p owner  \~
     */
    bool add(const uint8_t *cid, size_t len, uint32_t owner) noexcept;

    /// \~english Forgets @p cid; false if it was not there.  \~spanish Olvida @p cid; falso si no estaba.  \~
    bool remove(const uint8_t *cid, size_t len) noexcept;

    /// \~english How many IDs route somewhere.  \~spanish Cuantos identificadores llevan a alguna parte.  \~
    size_t size() const noexcept { return count_; }

    /**
     * @brief
     * \~english The keyed hash: exposed so a test can see that the key changes it.
     * \~spanish El hash con clave: expuesto para que una prueba vea que la clave lo cambia.
     * \~
     */
    static uint64_t hash(const uint8_t *cid, size_t len, const uint64_t *key) noexcept;

  private:
    struct Entry {
        uint8_t cid[kMaxConnectionId];
        uint8_t len;
        uint32_t owner;
    };

    size_t slot_of(const uint8_t *cid, size_t len) const noexcept;

    Entry *entries_ = nullptr;
    size_t mask_ = 0;
    size_t capacity_ = 0;
    size_t count_ = 0;
    uint64_t key_[2] = {0, 0};
};

} // namespace quic
} // namespace http_vx

#endif // HTTP_VX_QUIC_ROUTES_H
