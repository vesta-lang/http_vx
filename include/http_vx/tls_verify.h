/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file http_vx/tls_verify.h
 * @brief
 * \~english Whether to trust the peer's certificate chain: the question, asked of whoever can answer it.
 * \~spanish Si fiarse de la cadena de certificados del otro: la pregunta, hecha a quien sabe responderla.
 * \~
 *
 * \~english
 * TLS leaves certificate validation out of its scope (RFC 8446, 4.4.2.4):
 * building a path to a trust anchor, dates, revocation, key usage, and
 * whether the name in the certificate is the one the client asked for are
 * the rules of other documents, and of the system's own policy -- which
 * anchors it trusts, which it distrusts, which signatures it no longer
 * accepts.  **This does not implement them.**  It asks the question of a
 * verifier, and each verifier hands it to a library that already answers it
 * for the whole system: the chain engine of Windows, the X509 store of
 * OpenSSL.
 *
 * What TLS itself says is kept here: the verdict comes back as one of the
 * alerts TLS names for it (6.2), so the peer learns why, and the handshake
 * fails with that alert.  The system's own reason travels with it, as a
 * number, for whoever has to find out what happened.
 *
 * \~spanish
 * TLS deja la validacion de certificados fuera de su alcance (RFC 8446,
 * 4.4.2.4): construir un camino hasta un ancla de confianza, las fechas, la
 * revocacion, el uso de la clave, y si el nombre del certificado es el que pidio
 * el cliente son reglas de otros documentos, y de la politica del propio
 * sistema -- que anclas acepta, de cuales desconfia, que firmas ya no admite.
 * **Esto no las implementa.**  Le hace la pregunta a un verificador, y cada
 * verificador se la pasa a una biblioteca que ya la responde para todo el
 * sistema: el motor de cadenas de Windows, el almacen X509 de OpenSSL.
 *
 * Lo que dice el propio TLS se guarda aqui: el veredicto vuelve como una de las
 * alertas que TLS nombra para ello (6.2), para que el otro sepa por que, y el
 * saludo falla con esa alerta.  La razon del propio sistema viaja con el, como
 * numero, para quien tenga que averiguar que paso.
 * \~
 */
#ifndef HTTP_VX_TLS_VERIFY_H
#define HTTP_VX_TLS_VERIFY_H

#include "http_vx/tls_messages.h"

#include <cstddef>
#include <cstdint>

namespace http_vx {
namespace tls {

/**
 * @brief
 * \~english What a verifier decided about a chain.  \~spanish Lo que decidio un verificador sobre una cadena.
 * \~
 */
enum class Trust : uint8_t {
    /// \~english A path to a trusted anchor, valid now, for this use and this name.
    /// \~spanish Un camino hasta un ancla de confianza, valido ahora, para este uso y este nombre.  \~
    Trusted,
    /// \~english No path to an anchor this end trusts.  \~spanish Ningun camino hasta un ancla en la que confie este extremo.  \~
    UnknownIssuer,
    /// \~english A certificate expired, or is not valid yet.  \~spanish Un certificado caduco, o aun no es valido.  \~
    Expired,
    /// \~english Revoked by its issuer.  \~spanish Revocado por quien lo emitio.  \~
    Revoked,
    /// \~english Revocation was asked for and could not be found out.  \~spanish Se pidio la revocacion y no se pudo averiguar.  \~
    RevocationUnknown,
    /// \~english Not for the name the client asked for.  \~spanish No es para el nombre que pidio el cliente.  \~
    NameMismatch,
    /// \~english Not for this use: a server's certificate for a client, a leaf acting as a CA...
    /// \~spanish No es para este uso: el certificado de un servidor para un cliente, una hoja haciendo de CA...  \~
    WrongUsage,
    /// \~english A signature that does not verify, or one too weak to be accepted (4.4.2.4).
    /// \~spanish Una firma que no verifica, o una demasiado debil para aceptarla (4.4.2.4).  \~
    BadSignature,
    /// \~english Corrupt: it does not parse, or breaks the rules of its own format.
    /// \~spanish Corrupto: no se lee, o rompe las reglas de su propio formato.  \~
    Invalid,
    /// \~english A kind of certificate or key this end does not handle.  \~spanish Un tipo de certificado o de clave que este extremo no maneja.  \~
    Unsupported,
    /// \~english Rejected for a reason none of the above names.  \~spanish Rechazado por una razon que ninguna de las anteriores nombra.  \~
    Rejected,
    /// \~english The verifier itself failed: out of memory, a system call that failed.
    /// \~spanish Fallo el propio verificador: sin memoria, una llamada al sistema que fallo.  \~
    Failed,
};

/**
 * @brief
 * \~english A verdict, with the system's own reason when it gave one.
 * \~spanish Un veredicto, con la razon del propio sistema cuando la dio.
 * \~
 */
struct Verdict {
    Trust trust = Trust::Failed;
    /// \~english The library's own code (an HRESULT, an X509_V_ERR_...); 0 when there is none.
    /// \~spanish El codigo de la propia biblioteca (un HRESULT, un X509_V_ERR_...); 0 cuando no hay.  \~
    uint32_t code = 0;
};

/**
 * @brief
 * \~english A peer's certificate chain as it came: DER, end-entity first.
 * \~spanish La cadena de certificados de un par tal como llego: DER, la hoja primero.
 * \~
 *
 * \~english
 * The certificates after the first are whatever the peer chose to send
 * (4.4.2): maybe the path, maybe more, maybe less.  Building the path is
 * the verifier's job.
 * \~spanish
 * Los certificados tras el primero son lo que el otro quiso mandar (4.4.2):
 * quiza el camino, quiza mas, quiza menos.  Construir el camino es cosa del
 * verificador.
 * \~
 */
struct Chain {
    const uint8_t *const *certs = nullptr;
    const size_t *lens = nullptr;
    size_t count = 0;
};

/**
 * @brief
 * \~english Whose certificate is checked: it decides the key usage asked for.
 * \~spanish De quien es el certificado que se comprueba: decide el uso de clave que se pide.
 * \~
 */
enum class Role : uint8_t { Server, Client };

/**
 * @brief
 * \~english Decides whether a chain is to be trusted.  \~spanish Decide si hay que fiarse de una cadena.
 * \~
 *
 * \~english
 * Called once per handshake, after the peer proved it holds the leaf's key
 * (4.4.3).  It may take its time -- the libraries behind it read stores
 * from disk --, but it must not wait on the network: the handshake is not
 * where a server should stall.
 * \~spanish
 * Se llama una vez por saludo, despues de que el otro demostrara que tiene la
 * clave de la hoja (4.4.3).  Puede tardar -- las bibliotecas de detras leen
 * almacenes del disco --, pero no debe esperar a la red: el saludo no es donde
 * deba pararse un servidor.
 * \~
 */
class CertVerifier {
public:
    virtual ~CertVerifier() = default;

    /**
     * @brief
     * \~english The verdict on @p chain for @p role; @p host is the name asked for, or null to check none.
     * \~spanish El veredicto sobre @p chain para @p role; @p host es el nombre pedido, o nulo para no comprobar ninguno.
     * \~
     */
    virtual Verdict verify(const Chain &chain, Role role, const char *host) noexcept = 0;
};

/**
 * @brief
 * \~english The alert TLS sends for a verdict (RFC 8446, 6.2); Alert::None for Trusted.
 * \~spanish La alerta que manda TLS para un veredicto (RFC 8446, 6.2); Alert::None para Trusted.
 * \~
 */
Alert trust_alert(Trust t) noexcept;

/// \~english A short name for @p t.  \~spanish Un nombre corto para @p t.  \~
const char *trust_name(Trust t) noexcept;

} // namespace tls
} // namespace http_vx

#endif // HTTP_VX_TLS_VERIFY_H
