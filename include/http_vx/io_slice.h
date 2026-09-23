/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/io_slice.h
 * @brief
 * \~english Bytes from several places, written as one.
 * \~spanish Bytes de varios sitios, escritos como uno.
 * \~
 *
 * \~english
 * A response is a head this server just built and a body it did not: a file
 * that was mapped, a buffer the application owns, a piece of a request being
 * forwarded.  They are in different places and they go out in order.
 *
 * There are two ways to send them.  One is to copy them into a single buffer
 * and write that, which costs a copy of the body -- and the body is the big
 * part.  The other is to hand the operating system the list and let it read
 * from each in turn, which is what `writev`, `WSASend` and `io_uring` all take
 * natively.  R14 says it must be the second, so this is the type that says so.
 *
 * It holds no memory and owns nothing.  Each entry points at bytes somebody
 * else is keeping alive until the write completes, which for a completion-
 * based reactor means until the completion arrives -- not until the call
 * returns.
 *
 * \~spanish
 * Una respuesta es una cabeza que este servidor acaba de construir y un cuerpo
 * que no: un fichero mapeado, un buffer de la aplicacion, un pedazo de una
 * peticion que se esta reenviando.  Estan en sitios distintos y salen en orden.
 *
 * Hay dos formas de mandarlos.  Una es copiarlos a un solo buffer y escribir
 * ese, que cuesta una copia del cuerpo -- y el cuerpo es la parte grande --.
 * La otra es darle al sistema operativo la lista y dejar que lea de cada uno
 * por turno, que es lo que toman de forma nativa `writev`, `WSASend` e
 * `io_uring`.  R14 dice que tiene que ser la segunda, asi que este es el tipo
 * que lo dice.
 *
 * No tiene memoria ni es dueno de nada.  Cada entrada apunta a bytes que
 * mantiene vivos algun otro hasta que la escritura termine, que en un reactor
 * por finalizacion quiere decir hasta que llegue la finalizacion -- no hasta
 * que vuelva la llamada.
 *
 * \~
 */
#ifndef HTTP_VX_IO_SLICE_H
#define HTTP_VX_IO_SLICE_H

#include <cstddef>
#include <cstdint>

namespace http_vx {

/**
 * @brief
 * \~english One run of bytes, somewhere.
 * \~spanish Una tirada de bytes, en algun sitio.
 * \~
 *
 * \~english
 * The layout is the one `iovec` and `WSABUF` have, in that order, so a
 * platform can hand the array to the system without building a second one.
 * Whether it can is the platform's business; what matters here is not making
 * it impossible.
 *
 * \~spanish
 * La disposicion es la que tienen `iovec` y `WSABUF`, en ese orden, para que
 * una plataforma pueda darle el array al sistema sin construir otro.  Si puede
 * o no es cosa de la plataforma; lo que importa aqui es no hacerlo imposible.
 *
 * \~
 */
struct IoSlice {
    /// \~english Where the bytes are.  \~spanish Donde estan los bytes.  \~
    const uint8_t *data;
    /// \~english How many.  \~spanish Cuantos.  \~
    size_t len;
};

/**
 * @brief
 * \~english How many runs one write may gather.
 * \~spanish Cuantas tiradas puede juntar una escritura.
 * \~
 *
 * \~english
 * Sixteen, and it is a ceiling rather than a target.  A response is a head and
 * a body, which is two; a chunked one is a size, a piece and an ending, which
 * is three per chunk.  What the number buys is that the list lives in the
 * connection and never allocates -- and past it the answer is another write,
 * not a bigger list, because every system that takes one of these has a limit
 * of its own and exceeding it fails the whole call rather than the extra part.
 *
 * \~spanish
 * Dieciseis, y es un techo y no un objetivo.  Una respuesta es una cabeza y un
 * cuerpo, que son dos; una troceada es un tamano, un pedazo y un final, que son
 * tres por trozo.  Lo que compra el numero es que la lista viva en la conexion
 * y no reserve nunca -- y pasado el, la respuesta es otra escritura y no una
 * lista mayor, porque todos los sistemas que toman una de estas tienen un
 * limite propio y pasarse falla la llamada entera y no la parte de mas.
 *
 * \~
 */
constexpr size_t kMaxIoSlices = 16;

/**
 * @brief
 * \~english The runs of one write, in order.
 * \~spanish Las tiradas de una escritura, en orden.
 * \~
 */
class IoList {
  public:
    /**
     * @brief
     * \~english Adds a run at the end.
     * \~spanish Anade una tirada al final.
     * \~
     *
     * \~english
     * An empty run is dropped rather than recorded.  It would write nothing
     * and it takes one of the sixteen, and some systems treat a zero-length
     * entry as the end of the list -- which would silently drop everything
     * after it.
     *
     * \~spanish
     * Una tirada vacia se descarta en vez de anotarse.  No escribiria nada y
     * ocupa una de las dieciseis, y algunos sistemas tratan una entrada de
     * longitud cero como el final de la lista -- lo que se llevaria por delante
     * en silencio todo lo que fuera detras.
     *
     * \~
     * @param data \~english where the bytes are  \~spanish donde estan los bytes  \~
     * @param len  \~english how many  \~spanish cuantos  \~
     * @return     \~english false if there was no room  \~spanish false si no habia sitio  \~
     */
    bool push(const uint8_t *data, size_t len) noexcept {
        if (len == 0) return true;
        if (count_ == kMaxIoSlices) return false;
        slices_[count_].data = data;
        slices_[count_].len = len;
        ++count_;
        total_ += len;
        return true;
    }

    /// \~english The runs.  \~spanish Las tiradas.  \~
    const IoSlice *slices() const noexcept { return slices_; }
    /// \~english How many there are.  \~spanish Cuantas hay.  \~
    size_t count() const noexcept { return count_; }
    /// \~english Whether there is none.  \~spanish Si no hay ninguna.  \~
    bool empty() const noexcept { return count_ == 0; }
    /// \~english How many bytes in all.  \~spanish Cuantos bytes en total.  \~
    size_t total() const noexcept { return total_; }
    /// \~english Whether another run would fit.  \~spanish Si cabria otra tirada.  \~
    bool full() const noexcept { return count_ == kMaxIoSlices; }

    /// \~english Empties it for the next write.  \~spanish La vacia para la escritura siguiente.  \~
    void clear() noexcept {
        count_ = 0;
        total_ = 0;
    }

    /**
     * @brief
     * \~english Drops the first @p n bytes, which have been written.
     * \~spanish Descarta los primeros @p n bytes, que ya se escribieron.
     * \~
     *
     * \~english
     * A write may take less than it was given, and what is left has to be
     * offered again from exactly where it stopped.  Doing it here rather than
     * in each platform is what keeps a partial write from being three
     * implementations of the same arithmetic -- and getting it wrong sends a
     * run of bytes twice, which for a body is corruption and for a head is a
     * second set of fields.
     *
     * \~spanish
     * Una escritura puede coger menos de lo que se le dio, y lo que queda hay
     * que volver a ofrecerlo justo desde donde se paro.  Hacerlo aqui y no en
     * cada plataforma es lo que impide que una escritura parcial sean tres
     * implementaciones de la misma aritmetica -- y errarla manda una tirada de
     * bytes dos veces, que en un cuerpo es corrupcion y en una cabeza es un
     * segundo juego de cabeceras.
     *
     * \~
     * @param n \~english how many bytes went out  \~spanish cuantos bytes salieron  \~
     */
    void advance(size_t n) noexcept {
        size_t i = 0;
        while (i < count_ && n != 0) {
            if (n < slices_[i].len) {
                slices_[i].data += n;
                slices_[i].len -= n;
                total_ -= n;
                break;
            }
            n -= slices_[i].len;
            total_ -= slices_[i].len;
            ++i;
        }

        if (i == 0) return;
        for (size_t j = i; j < count_; ++j) slices_[j - i] = slices_[j];
        count_ -= i;
    }

  private:
    IoSlice slices_[kMaxIoSlices] = {};
    size_t count_ = 0;
    size_t total_ = 0;
};

} // namespace http_vx

#endif // HTTP_VX_IO_SLICE_H
