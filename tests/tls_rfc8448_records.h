/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/tls_rfc8448_records.h
 * @brief
 * \~english RFC 8448, section 3: the traffic secrets and the protected records, as the trace prints them.
 * \~spanish RFC 8448, seccion 3: los secretos de trafico y los registros protegidos, tal como los imprime la traza.
 * \~
 *
 * \~english
 * The messages themselves are in tls_rfc8448.h; this adds what the record
 * layer is checked against: the four traffic secrets and every "complete
 * record" the trace sends under them, byte for byte.
 * \~spanish
 * Los propios mensajes estan en tls_rfc8448.h; esto anade aquello contra lo que
 * se comprueba la capa de registros: los cuatro secretos de trafico y cada
 * "complete record" que la traza manda con ellos, byte a byte.
 * \~
 */
#ifndef HTTP_VX_TESTS_TLS_RFC8448_RECORDS_H
#define HTTP_VX_TESTS_TLS_RFC8448_RECORDS_H

namespace rfc8448 {

// \~english The traffic secrets ("tls13 c hs traffic" and the rest), and the IVs they give.
// \~spanish Los secretos de trafico ("tls13 c hs traffic" y los demas), y los IV que dan.  \~
inline const char *kClientHsSecret = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
inline const char *kServerHsSecret = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
inline const char *kClientApSecret = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
inline const char *kServerApSecret = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
inline const char *kServerHsIv = "5d313eb2671276ee13000b30";
inline const char *kClientHsIv = "5bd3c71b836e0b76bb73265f";
inline const char *kServerApIv = "cf782b88dd83549aadf1e984";
inline const char *kClientApIv = "5b78923dee08579033e523d9";

// \~english EncryptedExtensions to Finished, in one record under the server's handshake keys.
// \~spanish De EncryptedExtensions a Finished, en un registro con las claves del saludo del servidor.  \~
inline const char *kServerFlightRecord =
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e"
    "df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78"
    "b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b"
    "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9"
    "d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e"
    "d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092"
    "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694"
    "5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368"
    "4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f"
    "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26"
    "f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531"
    "7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e"
    "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da"
    "8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4"
    "61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe"
    "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb"
    "992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859"
    "77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038"
    "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84"
    "5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5"
    "d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e"
    "750edc53370d2b";

// \~english The client's Finished, under the client's handshake keys.  \~spanish El Finished del cliente, con las claves del saludo del cliente.  \~
inline const char *kClientFinishedRecord =
    "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc"
    "44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546";

// \~english The NewSessionTicket: the first record under the server's application keys.
// \~spanish El NewSessionTicket: el primer registro con las claves de aplicacion del servidor.  \~
inline const char *kTicketRecord =
    "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d4"
    "1d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a3"
    "8efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0"
    "9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406"
    "f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c8651"
    "9d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74"
    "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf159"
    "85684f";

// \~english Fifty bytes 00..31 each way: the client's first application record, the server's second.
// \~spanish Cincuenta bytes 00..31 en cada sentido: el primer registro de aplicacion del cliente, el segundo del servidor.  \~
inline const char *kClientDataRecord =
    "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f"
    "2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6"
    "3aeebb21694915e4";
inline const char *kServerDataRecord =
    "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36"
    "e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf33254"
    "0dd032e167c2955d";

// \~english close_notify each way, as 01 00: the client's second record, the server's third.
// \~spanish close_notify en cada sentido, como 01 00: el segundo registro del cliente, el tercero del servidor.  \~
inline const char *kClientAlertRecord = "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3";
inline const char *kServerAlertRecord = "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9";

} // namespace rfc8448

#endif // HTTP_VX_TESTS_TLS_RFC8448_RECORDS_H
