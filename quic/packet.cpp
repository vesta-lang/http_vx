/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file quic/packet.cpp
 * @brief
 * \~english Reading a QUIC header up to where the protection starts.
 * \~spanish Leer una cabecera QUIC hasta donde empieza la proteccion.
 * \~
 */

#include "http_vx/quic_packet.h"

#include "http_vx/quic_varint.h"

namespace http_vx {
namespace quic {

namespace {

/// \~english The largest UDP payload there is.
/// \~spanish La mayor carga UDP que existe.  \~
constexpr size_t kMaxDatagram = 65535;

uint32_t be32(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

Span span_of(size_t off, size_t len) noexcept {
    return Span{static_cast<uint32_t>(off), static_cast<uint32_t>(len)};
}

/**
 * @brief
 * \~english What the two type bits of a long header mean in @p version.
 * \~spanish Que significan los dos bits de tipo de una cabecera larga en @p version.
 * \~
 *
 * \~english
 * Version 2 renumbered them on purpose (RFC 9369, section 3.2), so that no
 * middlebox could keep working by recognising version 1's exact bits.  The
 * mapping is therefore per version, and a table that assumed one would read a
 * version 2 Initial as a 0-RTT packet.
 * \~spanish
 * La version 2 los renumero a proposito (RFC 9369, seccion 3.2), para que ningun
 * equipo intermedio pudiera seguir funcionando reconociendo los bits exactos de
 * la version 1.  Asi que la correspondencia va por version, y una tabla que
 * supusiera una leeria un Initial de version 2 como un paquete 0-RTT.
 * \~
 */
PacketType long_type(uint32_t version, uint8_t bits) noexcept {
    if (version == kVersion2) {
        switch (bits) {
        case 1:
            return PacketType::Initial;
        case 2:
            return PacketType::ZeroRtt;
        case 3:
            return PacketType::Handshake;
        default:
            return PacketType::Retry;
        }
    }

    switch (bits) {
    case 0:
        return PacketType::Initial;
    case 1:
        return PacketType::ZeroRtt;
    case 2:
        return PacketType::Handshake;
    default:
        return PacketType::Retry;
    }
}

/// \~english Whether @p version is one whose packets this end can read.
/// \~spanish Si @p version es una cuyos paquetes sabe leer este extremo.  \~
bool spoken(uint32_t version) noexcept {
    return version == kVersion1 || version == kVersion2;
}

} // namespace

HeaderError parse_packet(const uint8_t *p, size_t n, const HeaderContext &ctx,
                         PacketHeader &out) noexcept {
    out = PacketHeader();

    if (n > kMaxDatagram) return HeaderError::DatagramTooLarge;
    if (n == 0) return HeaderError::Truncated;

    const uint8_t b0 = p[0];
    out.first = b0;

    /* \~english
     * The fixed bit is checked everywhere EXCEPT Version Negotiation and
     * unknown versions, and the exception is the point.  Those two are what
     * RFC 8999 describes -- the part of QUIC that no version may change -- and
     * the fixed bit is not in it: a future version is free to use that bit
     * for something else, and refusing its packets for it would mean never
     * being able to tell it which versions this end speaks.
     * \~spanish
     * El bit fijo se comprueba en todas partes MENOS en Version Negotiation y en
     * versiones desconocidas, y la excepcion es lo importante.  Esas dos son lo
     * que describe el RFC 8999 -- la parte de QUIC que ninguna version puede
     * cambiar -- y el bit fijo no esta en ella: una version futura puede usar ese
     * bit para otra cosa, y rechazar sus paquetes por eso seria no poder decirle
     * nunca que versiones habla este extremo.
     * \~ */
    const bool fixed_ok = (b0 & 0x40) != 0 || ctx.fixed_bit_may_be_clear;

    if ((b0 & 0x80) == 0) {
        /* \~english
         * A short header: the first byte, the connection ID -- whose length
         * only the receiver knows -- and then the protected packet number.
         * Nothing says where the packet ends, because nothing needs to: a
         * short-header packet is always the last one in its datagram.
         * \~spanish
         * Una cabecera corta: el primer byte, el identificador de conexion -- cuya
         * longitud solo sabe quien recibe -- y luego el numero de paquete
         * protegido.  Nada dice donde acaba el paquete, porque no hace falta: un
         * paquete de cabecera corta es siempre el ultimo de su datagrama.
         * \~ */
        if (!fixed_ok) return HeaderError::FixedBitClear;
        if (ctx.short_dcid_len > kMaxConnectionId)
            return HeaderError::ConnectionIdTooLong;

        const size_t pn = 1 + ctx.short_dcid_len;
        if (n < pn) return HeaderError::Truncated;
        if (n - pn < kSampleOffset + kSampleSize)
            return HeaderError::TooShortToProtect;

        out.type = PacketType::OneRtt;
        out.dcid = span_of(1, ctx.short_dcid_len);
        out.pn_offset = static_cast<uint32_t>(pn);
        out.size = static_cast<uint32_t>(n);
        return HeaderError::None;
    }

    /* \~english
     * A long header.  First what RFC 8999 fixes for ever -- the version and
     * both connection IDs, each with its length in front -- which is readable
     * whatever the version is.
     * \~spanish
     * Una cabecera larga.  Primero lo que el RFC 8999 fija para siempre -- la
     * version y los dos identificadores de conexion, cada uno con su longitud
     * delante -- que se puede leer sea cual sea la version.
     * \~ */
    if (n < 6) return HeaderError::Truncated;

    const uint32_t version = be32(p + 1);
    out.version = version;

    /* \~english
     * The twenty-byte limit is a VERSION 1 rule, applied only to the versions
     * that have it.  The invariants allow up to two hundred and fifty-five, and
     * a server has to be able to read those: answering an unknown version with
     * a Version Negotiation packet means echoing its connection IDs back.
     * \~spanish
     * El limite de veinte bytes es una regla de la VERSION 1, y se aplica solo a
     * las versiones que la tienen.  Los invariantes permiten hasta doscientos
     * cincuenta y cinco, y un servidor tiene que poder leerlos: contestar a una
     * version desconocida con un Version Negotiation quiere decir devolverle sus
     * identificadores de conexion.
     * \~ */
    const bool limited = spoken(version);

    size_t pos = 5;

    const size_t dcid_len = p[pos++];
    if (limited && dcid_len > kMaxConnectionId)
        return HeaderError::ConnectionIdTooLong;
    if (n - pos < dcid_len) return HeaderError::Truncated;
    out.dcid = span_of(pos, dcid_len);
    pos += dcid_len;

    if (pos >= n) return HeaderError::Truncated;

    const size_t scid_len = p[pos++];
    if (limited && scid_len > kMaxConnectionId)
        return HeaderError::ConnectionIdTooLong;
    if (n - pos < scid_len) return HeaderError::Truncated;
    out.scid = span_of(pos, scid_len);
    pos += scid_len;

    if (version == 0) {
        /* \~english
         * Version Negotiation: what follows is a list of four-byte versions,
         * and it runs to the end of the datagram.  An empty list, or one that
         * is not a whole number of versions, is not a list -- and a list that
         * a server read short would be a client told this server speaks a
         * version it never offered.
         * \~spanish
         * Version Negotiation: lo que sigue es una lista de versiones de cuatro
         * bytes, y llega hasta el final del datagrama.  Una lista vacia, o que no
         * es un numero entero de versiones, no es una lista -- y una lista que un
         * servidor leyera corta seria un cliente al que le dicen que este
         * servidor habla una version que no ofrecio nunca.
         * \~ */
        const size_t rest = n - pos;
        if (rest == 0 || rest % 4 != 0) return HeaderError::BadVersionList;

        out.type = PacketType::VersionNegotiation;
        out.versions = span_of(pos, rest);
        out.size = static_cast<uint32_t>(n);
        return HeaderError::None;
    }

    if (!limited) {
        /* \~english
         * A version this end does not speak.  Its layout past the connection
         * IDs is unknown by definition, so nothing more is read and the packet
         * is taken to run to the end of the datagram -- which is also all that
         * is needed to answer it.
         * \~spanish
         * Una version que este extremo no habla.  Su forma pasados los
         * identificadores de conexion es desconocida por definicion, asi que no
         * se lee nada mas y se da el paquete por extendido hasta el final del
         * datagrama -- que es ademas todo lo que hace falta para contestarlo.
         * \~ */
        out.type = PacketType::UnsupportedVersion;
        out.size = static_cast<uint32_t>(n);
        return HeaderError::None;
    }

    if (!fixed_ok) return HeaderError::FixedBitClear;

    out.type = long_type(version, static_cast<uint8_t>((b0 >> 4) & 0x03));

    if (out.type == PacketType::Retry) {
        /* \~english
         * A Retry is a token and a sixteen-byte integrity tag, and the tag is
         * found by counting from the END: the token has no length in front of
         * it.  So the datagram has to hold at least the tag, and whatever is
         * between the connection IDs and the tag is the token.
         * \~spanish
         * Un Retry es un testigo y una marca de integridad de dieciseis bytes, y
         * la marca se encuentra contando desde el FINAL: el testigo no lleva
         * longitud delante.  Asi que el datagrama tiene que tener por lo menos la
         * marca, y lo que haya entre los identificadores y la marca es el
         * testigo.
         * \~ */
        const size_t rest = n - pos;
        if (rest < kRetryTagSize) return HeaderError::Truncated;

        out.token = span_of(pos, rest - kRetryTagSize);
        out.tag = span_of(n - kRetryTagSize, kRetryTagSize);
        out.size = static_cast<uint32_t>(n);
        return HeaderError::None;
    }

    if (out.type == PacketType::Initial) {
        uint64_t token_len = 0;
        const size_t used = decode_varint(p + pos, n - pos, token_len);
        if (used == 0) return HeaderError::Truncated;
        pos += used;

        /* \~english
         * Compared as the remaining room and not as `pos + token_len`, because
         * the length is up to sixty-two bits and the sum could wrap into a
         * small number that passes.
         * \~spanish
         * Se compara con el sitio que queda y no como `pos + token_len`, porque la
         * longitud llega a sesenta y dos bits y la suma podria dar la vuelta hasta
         * un numero pequeno que pasa.
         * \~ */
        if (token_len > n - pos) return HeaderError::LengthTooLong;

        out.token = span_of(pos, static_cast<size_t>(token_len));
        pos += static_cast<size_t>(token_len);
    }

    uint64_t length = 0;
    const size_t used = decode_varint(p + pos, n - pos, length);
    if (used == 0) return HeaderError::Truncated;
    pos += used;

    if (length > n - pos) return HeaderError::LengthTooLong;

    /* \~english
     * Long enough to take the sample from.  The sample starts four bytes past
     * the packet number whatever that number's real length, and runs sixteen;
     * a packet shorter than that would have header protection read past its
     * own end -- into the next coalesced packet, or past the datagram.
     * \~spanish
     * Lo bastante largo para sacarle la muestra.  La muestra empieza cuatro bytes
     * detras del numero de paquete mida lo que mida ese numero, y ocupa
     * dieciseis; un paquete mas corto haria que la proteccion de cabecera leyera
     * mas alla de su propio final -- en el paquete pegado siguiente, o fuera del
     * datagrama.
     * \~ */
    if (length < kSampleOffset + kSampleSize)
        return HeaderError::TooShortToProtect;

    out.pn_offset = static_cast<uint32_t>(pos);
    out.size = static_cast<uint32_t>(pos + static_cast<size_t>(length));
    return HeaderError::None;
}

const char *header_error_name(HeaderError e) noexcept {
    switch (e) {
    case HeaderError::None:
        return "none";
    case HeaderError::Truncated:
        return "truncated";
    case HeaderError::FixedBitClear:
        return "fixed bit clear";
    case HeaderError::ConnectionIdTooLong:
        return "connection id too long";
    case HeaderError::LengthTooLong:
        return "length past the datagram";
    case HeaderError::TooShortToProtect:
        return "too short to protect";
    case HeaderError::BadVersionList:
        return "bad version list";
    case HeaderError::DatagramTooLarge:
        return "datagram too large";
    }
    return "unknown";
}

} // namespace quic
} // namespace http_vx
