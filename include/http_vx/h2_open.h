/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h2_open.h
 * @brief
 * \~english Where the HTTP/2 service keeps its open responses: a table of its own, apart from the requests (HVX-5, 7.2).
 * \~spanish Donde guarda el servicio HTTP/2 sus respuestas abiertas: una tabla propia, aparte de las peticiones (HVX-5, 7.2).
 * \~
 *
 * \~english
 * An open response lives for as long as its source has something to say --
 * a Server-Sent Events stream may live for hours.  If it held one of the
 * entries the service keeps for requests being read and answered, a few long
 * streams would leave every other request on the shard refused with
 * REFUSED_STREAM.  So they get their own table, sized apart and bounded, and
 * the request pool never sees them.
 *
 * An entry holds no buffer while its source is quiet (R34): the only memory it
 * may hold is what the handler wrote before opening and the windows did not
 * let out yet, and that goes back as soon as it has gone.
 *
 * \~spanish
 * Una respuesta abierta vive mientras su fuente tenga algo que decir -- un
 * flujo de Server-Sent Events puede vivir horas --.  Si ocupara una de las
 * entradas que el servicio guarda para las peticiones que se leen y se
 * contestan, unos pocos flujos largos dejarian a todas las demas peticiones del
 * fragmento rechazadas con REFUSED_STREAM.  Asi que tienen su propia tabla, con
 * su tamano y acotada, y el pozo de peticiones no las ve nunca.
 *
 * Una entrada no tiene ningun buffer mientras su fuente calla (R34): la unica
 * memoria que puede tener es lo que escribio el manejador antes de abrir y las
 * ventanas no dejaron salir todavia, y esa vuelve en cuanto ha salido.
 * \~
 */
#ifndef HTTP_VX_H2_OPEN_H
#define HTTP_VX_H2_OPEN_H

#include "http_vx/buffer.h"
#include "http_vx/open_response.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace h2 {

/**
 * @brief
 * \~english What names no open response.
 * \~spanish Lo que no nombra ninguna respuesta abierta.
 * \~
 */
constexpr uint32_t kNoOpen = 0xFFFFFFFF;

/**
 * @brief
 * \~english One open response: which stream, fed by which source, and whether it wants to be asked.
 * \~spanish Una respuesta abierta: que flujo, alimentado por que fuente, y si quiere que se le pregunte.
 * \~
 */
struct OpenStream {
    /// \~english The application's source; lives until its gone.  \~spanish La fuente de la aplicacion; vive hasta su gone.  \~
    BodySource *source = nullptr;

    /**
     * \~english
     * What the handler wrote with @c body before opening and the windows have
     * not let out yet.  Empty -- and holding no memory -- in the ordinary case,
     * where the windows took all of it at once.
     * \~spanish
     * Lo que escribio el manejador con @c body antes de abrir y las ventanas
     * todavia no han dejado salir.  Vacio -- y sin memoria -- en el caso
     * corriente, en que las ventanas se lo llevaron todo de una vez.
     * \~
     */
    Buffer prefix;

    /// \~english Which stream it answers.  \~spanish Que flujo contesta.  \~
    uint32_t stream = 0;

    /// \~english The next one of the same connection, or of the free list.  \~spanish La siguiente de la misma conexion, o de la lista de libres.  \~
    uint32_t next = kNoOpen;

    /// \~english Kicked since its last fill.  \~spanish Avisada desde su ultimo relleno.  \~
    bool kicked = false;

    /// \~english Its last fill took all the room: asked again when there is more (HVX-5, 4.3).
    /// \~spanish Su ultimo relleno uso todo el sitio: se le vuelve a pedir cuando haya mas (HVX-5, 4.3).  \~
    bool hungry = false;
};

/**
 * @brief
 * \~english The open responses of one connection, in the order they are served.
 * \~spanish Las respuestas abiertas de una conexion, en el orden en que se atienden.
 * \~
 *
 * \~english
 * A queue and not just a list: the one served is put at the back, so a
 * budget that runs out before the end starts the next call where this one
 * stopped, and one busy stream cannot starve the others of its connection.
 * \~spanish
 * Una cola y no solo una lista: la que se atiende pasa al final, asi que un
 * presupuesto que se acaba antes del final empieza la llamada siguiente donde
 * paro esta, y un flujo con mucho que decir no deja sin turno a los demas de su
 * conexion.
 * \~
 */
struct OpenList {
    uint32_t head = kNoOpen;
    uint32_t tail = kNoOpen;
    /// \~english How many are in it.  \~spanish Cuantas hay.  \~
    uint32_t count = 0;
};

/**
 * @brief
 * \~english The table of open responses: fixed at reset, entries threaded into one list per connection.
 * \~spanish La tabla de respuestas abiertas: fija al reiniciar, con las entradas enhebradas en una lista por conexion.
 * \~
 */
class OpenTable {
  public:
    OpenTable() noexcept = default;
    ~OpenTable();

    OpenTable(const OpenTable &) = delete;
    OpenTable &operator=(const OpenTable &) = delete;

    /**
     * @brief
     * \~english Makes room for @p n open responses at once.
     * \~spanish Hace sitio para @p n respuestas abiertas a la vez.
     * \~
     *
     * @param n \~english how many; zero opens none  \~spanish cuantas; cero no abre ninguna  \~
     * @return  \~english false if the memory could not be had  \~spanish false si no se pudo conseguir la memoria  \~
     */
    bool reset(uint32_t n) noexcept;

    /// \~english Gives the memory back.  \~spanish Devuelve la memoria.  \~
    void release() noexcept;

    /// \~english Whether no entry is free.  \~spanish Si no queda ninguna entrada libre.  \~
    bool full() const noexcept { return free_ == kNoOpen; }

    /// \~english How many entries are taken.  \~spanish Cuantas entradas estan cogidas.  \~
    uint32_t in_use() const noexcept { return in_use_; }

    /**
     * @brief
     * \~english Takes a free entry for @p stream, fed by @p s; it is in no list yet.
     * \~spanish Coge una entrada libre para @p stream, alimentada por @p s; todavia no esta en ninguna lista.
     * \~
     *
     * @return \~english its index, or @c kNoOpen if the table is full  \~spanish su indice, o @c kNoOpen si la tabla esta llena  \~
     */
    uint32_t take(BodySource &s, uint32_t stream) noexcept;

    /**
     * @brief
     * \~english Gives entry @p i back, and the memory its prefix held; it must be in no list.
     * \~spanish Devuelve la entrada @p i, y la memoria que tenia su prefijo; no puede estar en ninguna lista.
     * \~
     */
    void give_back(uint32_t i) noexcept;

    /// \~english Entry @p i.  \~spanish La entrada @p i.  \~
    OpenStream &at(uint32_t i) noexcept { return entries_[i]; }

    /// \~english Puts @p i at the back of @p list.  \~spanish Pone @p i al final de @p list.  \~
    void push(OpenList &list, uint32_t i) noexcept;

    /// \~english Takes the front of @p list out of it, or @c kNoOpen.  \~spanish Saca de @p list la primera, o @c kNoOpen.  \~
    uint32_t pop(OpenList &list) noexcept;

    /// \~english Takes @p i out of @p list, wherever it is.  \~spanish Saca @p i de @p list, este donde este.  \~
    void unlink(OpenList &list, uint32_t i) noexcept;

    /// \~english The entry of @p list answering @p stream, or @c kNoOpen.  \~spanish La entrada de @p list que contesta @p stream, o @c kNoOpen.  \~
    uint32_t find(const OpenList &list, uint32_t stream) const noexcept;

    /// \~english The entry of @p list fed by @p s, or @c kNoOpen.  \~spanish La entrada de @p list alimentada por @p s, o @c kNoOpen.  \~
    uint32_t find(const OpenList &list, const BodySource *s) const noexcept;

  private:
    OpenStream *entries_ = nullptr;
    uint32_t capacity_ = 0;
    uint32_t free_ = kNoOpen;
    uint32_t in_use_ = 0;
};

} // namespace h2
} // namespace http_vx

#endif // HTTP_VX_H2_OPEN_H
