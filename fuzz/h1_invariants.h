/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file fuzz/h1_invariants.h
 * @brief
 * \~english What must hold of the parser for ANY bytes at all.
 * \~spanish Lo que tiene que cumplir el analizador para CUALESQUIERA bytes.
 * \~
 *
 * \~english
 * A test written by hand checks the cases somebody thought of.  What is here
 * is the other half: properties that hold whatever the input, so they can be
 * checked against input nobody wrote.
 *
 * They are in a file of their own because two things check them and both must
 * check the same ones.  One is a real fuzzer, which needs a toolchain that has
 * one.  The other is an ordinary test that generates its own input from a
 * fixed seed and runs on every build, everywhere.  Without the second, this
 * would be a check that exists on the machines that have the tooling and
 * nowhere else -- and a test that does not run is not a test.
 *
 * \~spanish
 * Una prueba escrita a mano comprueba los casos que se le ocurrieron a alguien.
 * Lo de aqui es la otra mitad: propiedades que se cumplen sea cual sea la
 * entrada, asi que se pueden comprobar contra entrada que no escribio nadie.
 *
 * Estan en un fichero propio porque las comprueban dos cosas y las dos tienen
 * que comprobar las mismas.  Una es un fuzzer de verdad, que necesita un
 * entorno que lo tenga.  La otra es una prueba corriente que genera su propia
 * entrada de una semilla fija y corre en cada construccion, en todas partes.
 * Sin la segunda, esto seria una comprobacion que existe en las maquinas que
 * tienen la herramienta y en ningun otro sitio -- y una prueba que no se
 * ejecuta no es una prueba.
 *
 * \~
 */
#ifndef HTTP_VX_FUZZ_H1_INVARIANTS_H
#define HTTP_VX_FUZZ_H1_INVARIANTS_H

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace fuzz {

/**
 * @brief
 * \~english Which property was broken, if one was.
 * \~spanish Que propiedad se rompio, si se rompio alguna.
 * \~
 */
enum class Breach : uint8_t {
    /// \~english None.  \~spanish Ninguna.  \~
    None = 0,

    /**
     * \~english
     * It asked for more input while it still had input it had not looked at.
     * That is what a state that forgets to advance looks like from outside,
     * and the other thing it looks like is a server that never answers.
     * \~spanish
     * Pidio mas entrada teniendo todavia entrada sin mirar.  Es lo que parece
     * desde fuera un estado que se olvida de avanzar, y lo otro que parece es
     * un servidor que no contesta nunca.
     * \~
     */
    AskedForMoreWithInputLeft,

    /// \~english It reported a head longer than the bytes it was given.
    /// \~spanish Informo de una cabeza mas larga que los bytes que se le dieron.  \~
    ConsumedPastTheEnd,

    /// \~english It finished and reported a reason for refusing.
    /// \~spanish Termino e informo de un motivo de rechazo.  \~
    DoneWithAReason,

    /// \~english It refused and did not say why.
    /// \~spanish Rechazo y no dijo por que.  \~
    RefusedWithoutAReason,

    /**
     * \~english
     * A piece of the request names bytes outside the request.  This is the one
     * the whole offset design exists to prevent, and it is the one that does
     * not announce itself: the piece reads, it has content, and the content
     * belongs to something else.
     * \~spanish
     * Una pieza de la peticion nombra bytes de fuera de la peticion.  Esta es
     * la que todo el diseno de desplazamientos existe para evitar, y es la que
     * no se anuncia: la pieza se lee, tiene contenido, y el contenido es de
     * otra cosa.
     * \~
     */
    PieceOutsideTheMessage,

    /**
     * \~english
     * The same bytes gave one answer whole and another in pieces.  How a
     * message is split is a property of the network on the day, so an answer
     * that depends on it is an answer that depends on the weather.
     * \~spanish
     * Los mismos bytes dieron una respuesta enteros y otra a trozos.  Como se
     * parte un mensaje es propiedad de la red ese dia, asi que una respuesta
     * que dependa de ello es una respuesta que depende del tiempo que haga.
     * \~
     */
    SplittingChangedTheAnswer,

    /**
     * \~english
     * A piece of the body was handed over that starts before the previous one
     * ended.  The pieces of a body are a partition of it in order, and one
     * that goes backwards means the same bytes are delivered twice -- which a
     * handler counting or hashing them cannot see and cannot recover from.
     * \~spanish
     * Se entrego un pedazo de cuerpo que empieza antes de que acabara el
     * anterior.  Los pedazos de un cuerpo son una particion de el en orden, y
     * uno que retroceda quiere decir que los mismos bytes se entregan dos
     * veces -- que un manejador que los cuente o los resuma no puede ver ni
     * remediar.
     * \~
     */
    PieceWentBackwards,

    /**
     * \~english
     * The body's length does not match the pieces that were handed over.  One
     * of the two is what a handler believes and the other is what it received,
     * and nothing downstream can tell which.
     * \~spanish
     * La longitud del cuerpo no coincide con los pedazos entregados.  Una de
     * las dos es lo que cree un manejador y la otra lo que recibio, y nada de
     * mas abajo puede decir cual.
     * \~
     */
    BodyLengthDisagrees,
};

/**
 * @brief
 * \~english The name of @p b, for a message a human reads.
 * \~spanish El nombre de @p b, para un mensaje que lee una persona.
 * \~
 * @param b \~english the property  \~spanish la propiedad  \~
 * @return  \~english its name  \~spanish su nombre  \~
 */
const char *breach_name(Breach b) noexcept;

/**
 * @brief
 * \~english Parses @p data twice and checks every property.
 * \~spanish Analiza @p data dos veces y comprueba todas las propiedades.
 * \~
 *
 * \~english
 * Twice: once with everything at hand and once a byte at a time.  Neither pass
 * is allowed to fail on its own, and they are not allowed to disagree.
 *
 * It says nothing about whether the bytes were a valid request.  Most of them
 * will not be, and being refused is a correct outcome -- what is checked is
 * that the refusal, or the acceptance, is well formed.
 *
 * \~spanish
 * Dos veces: una con todo a mano y otra byte a byte.  Ninguna de las dos puede
 * fallar por su cuenta, y no pueden discrepar entre si.
 *
 * No dice nada sobre si los bytes eran una peticion valida.  La mayoria no lo
 * seran, y que se rechacen es un resultado correcto -- lo que se comprueba es
 * que el rechazo, o la aceptacion, esta bien formado.
 *
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english what was broken, or @c Breach::None
 *             \~spanish que se rompio, o @c Breach::None  \~
 */
Breach check_parse(const uint8_t *data, size_t size) noexcept;

/**
 * @brief
 * \~english Reads @p data as a chunked body twice and checks every property.
 * \~spanish Lee @p data como cuerpo troceado dos veces y comprueba todas las
 *           propiedades.
 * \~
 *
 * \~english
 * The same two passes, and three properties more that only a body has: the
 * pieces handed over must go forwards, they must add up to the length that is
 * reported, and the two passes must hand over the SAME BYTES -- which is not
 * the same as the same pieces.  A chunk split across two reads comes back as
 * two pieces rather than one, so the passes are allowed to differ in how the
 * body is divided and in nothing else.
 *
 * \~spanish
 * Las mismas dos pasadas, y tres propiedades mas que solo tiene un cuerpo: los
 * pedazos entregados tienen que ir hacia delante, tienen que sumar la longitud
 * que se informa, y las dos pasadas tienen que entregar LOS MISMOS BYTES -- que
 * no es lo mismo que los mismos pedazos.  Un trozo partido entre dos lecturas
 * vuelve como dos pedazos y no como uno, asi que las pasadas pueden diferir en
 * como se divide el cuerpo y en nada mas.
 *
 * \~
 * @param data \~english the bytes  \~spanish los bytes  \~
 * @param size \~english how many  \~spanish cuantos  \~
 * @return     \~english what was broken, or @c Breach::None
 *             \~spanish que se rompio, o @c Breach::None  \~
 */
Breach check_chunked(const uint8_t *data, size_t size) noexcept;

} // namespace fuzz
} // namespace http_vx

#endif // HTTP_VX_FUZZ_H1_INVARIANTS_H
