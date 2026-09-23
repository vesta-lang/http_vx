/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/h1_limits.h
 * @brief
 * \~english What the HTTP/1.1 codec refuses to exceed.
 * \~spanish Lo que el codec de HTTP/1.1 se niega a pasar.
 * \~
 *
 * \~english
 * These are the real limits -- the ones that answer a status code instead of
 * dropping a connection -- and they are one structure because they are one
 * policy.  A server that allows thirty-two kilobytes of header fields and an
 * unbounded body has not made two decisions; it has made one and forgotten the
 * other half.
 *
 * They live apart from the buffer's ceiling on purpose.  That one is a
 * backstop against a bug and is measured in what a machine can survive; these
 * are measured in what an application wants to serve, and refusing at this
 * level can still be explained to the peer.
 *
 * The defaults are what the common servers use.  That matters more than what
 * is defensible in the abstract: a limit nobody else has is a limit that makes
 * requests fail here and nowhere else, and the report that comes back says the
 * site is broken rather than that the request was too big.
 *
 * \~spanish
 * Estos son los limites de verdad -- los que contestan un codigo de estado en
 * vez de tirar una conexion -- y son una estructura porque son una politica.
 * Un servidor que permite treinta y dos kilobytes de cabeceras y un cuerpo sin
 * tope no ha tomado dos decisiones; ha tomado una y se ha olvidado de la otra
 * mitad.
 *
 * Viven aparte del techo del buffer a proposito.  Aquel es un tope de seguridad
 * contra un error y se mide en lo que una maquina puede aguantar; estos se
 * miden en lo que una aplicacion quiere servir, y rechazar a este nivel
 * todavia se le puede explicar al otro extremo.
 *
 * Los valores por defecto son los que usan los servidores corrientes.  Eso
 * importa mas que lo que sea defendible en abstracto: un limite que no tiene
 * nadie mas es un limite que hace que las peticiones fallen aqui y en ningun
 * otro sitio, y el informe que vuelve dice que el sitio esta roto y no que la
 * peticion era demasiado grande.
 *
 * \~
 */
#ifndef HTTP_VX_H1_LIMITS_H
#define HTTP_VX_H1_LIMITS_H

#include <cstdint>

namespace http_vx {
namespace h1 {

/**
 * @brief
 * \~english The limits of one HTTP/1.1 codec.
 * \~spanish Los limites de un codec de HTTP/1.1.
 * \~
 */
struct Limits {
    // --- The head / la cabeza ---

    /// \~english How long the request line may be.  Answers 414.
    /// \~spanish Cuanto puede medir la linea de peticion.  Contesta 414.  \~
    uint32_t max_request_line = 8192;

    /// \~english How many bytes the field section may take.  Answers 431.
    /// \~spanish Cuantos bytes puede ocupar la seccion de cabeceras.  Contesta 431.  \~
    uint32_t max_header_bytes = 32768;

    /// \~english How many fields there may be.  Answers 431.
    /// \~spanish Cuantas cabeceras puede haber.  Contesta 431.  \~
    uint16_t max_fields = 128;

    /**
     * \~english
     * Whether to ignore an empty line before the request line.  The
     * specification says a server SHOULD, for clients that used to write a
     * spare CRLF after a body -- which is the point: those bytes come after a
     * body, so accepting them is accepting bytes that could not be attributed
     * to the message that carried them.
     *
     * So it is off, and it is an option rather than a decision made for
     * everybody: a server talking to something old may need it, and a server
     * behind an untrusted chain must not have it.
     *
     * \~spanish
     * Si ignorar una linea vacia antes de la linea de peticion.  La
     * especificacion dice que un servidor DEBERIA, por los clientes que
     * escribian un CRLF de mas tras un cuerpo -- que es justo lo que importa:
     * esos bytes vienen DESPUES de un cuerpo, asi que aceptarlos es aceptar
     * bytes que no se pudieron atribuir al mensaje que los llevaba.
     *
     * Asi que esta apagado, y es una opcion y no una decision tomada por todos:
     * un servidor que hable con algo antiguo puede necesitarlo, y uno que este
     * detras de una cadena en la que no confia no debe tenerlo.
     * \~
     */
    bool allow_leading_crlf = false;

    // --- The body / el cuerpo ---

    /**
     * \~english
     * How long a body may be.  Answers 413.
     *
     * This is the one an application will almost certainly change, in both
     * directions: an API that takes small documents wants it far lower, and
     * one that takes uploads wants it far higher.  The default is a number
     * rather than no limit because no limit is the permissive default that
     * does not fail -- it just lets one peer decide how much memory the
     * machine spends.
     *
     * \~spanish
     * Cuanto puede medir un cuerpo.  Contesta 413.
     *
     * Este es el que casi con seguridad va a cambiar una aplicacion, y en los
     * dos sentidos: una API que recibe documentos pequenos lo quiere mucho mas
     * bajo, y una que recibe subidas mucho mas alto.  El valor por defecto es
     * un numero y no "sin limite" porque "sin limite" es el valor permisivo que
     * no falla -- solo deja que un extremo decida cuanta memoria gasta la
     * maquina.
     * \~
     */
    uint64_t max_body_bytes = 16ull * 1024ull * 1024ull;

    /**
     * \~english
     * How many hexadecimal digits a chunk size may have.
     *
     * Sixteen is what fits in the number, and a size needs no more.  A run of
     * leading zeros longer than that is legal by the grammar and is refused
     * anyway: it names no size that could not be named in sixteen digits, and
     * what it does name is a peer that writes forever without sending a chunk.
     *
     * \~spanish
     * Cuantos digitos hexadecimales puede tener el tamano de un trozo.
     *
     * Dieciseis es lo que cabe en el numero, y un tamano no necesita mas.  Una
     * tirada de ceros a la izquierda mas larga es legal por la gramatica y se
     * rechaza igual: no nombra ningun tamano que no se pueda nombrar en
     * dieciseis digitos, y lo que si nombra es un extremo que escribe sin parar
     * sin mandar un trozo.
     * \~
     */
    uint8_t max_chunk_size_digits = 16;

    /// \~english How long a chunk's extensions may be.
    /// \~spanish Cuanto pueden medir las extensiones de un trozo.  \~
    uint32_t max_chunk_extension = 256;

    /// \~english How many bytes the trailer section may take.
    /// \~spanish Cuantos bytes puede ocupar la seccion de remolque.  \~
    uint32_t max_trailer_bytes = 8192;

    /// \~english How many trailer fields there may be.
    /// \~spanish Cuantas cabeceras de remolque puede haber.  \~
    uint16_t max_trailers = 32;
};

} // namespace h1
} // namespace http_vx

#endif // HTTP_VX_H1_LIMITS_H
