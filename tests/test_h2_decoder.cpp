/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file tests/test_h2_decoder.cpp
 * @brief
 * \~english A header block becoming a request, and the blocks that must not.
 * \~spanish Un bloque de cabeceras convirtiendose en peticion, y los que no deben.
 * \~
 *
 * \~english
 * The examples in RFC 7541 appendix C are a SEQUENCE, and they are used as
 * one: the same decoder reads all of them in order, because what the third
 * block means depends on what the first two put in the table.  Reading them
 * one at a time with a fresh decoder would check the arithmetic and miss the
 * only thing that is hard about HPACK.
 *
 * \~spanish
 * Los ejemplos del apendice C del RFC 7541 son una SUCESION, y se usan como
 * tal: el mismo descodificador los lee todos en orden, porque lo que significa
 * el tercer bloque depende de lo que los dos primeros pusieran en la tabla.
 * Leerlos de uno en uno con un descodificador nuevo comprobaria la aritmetica y
 * se dejaria fuera lo unico dificil de HPACK.
 *
 * \~
 */

#include "http_vx/h2_decoder.h"

#include <cstdio>
#include <cstring>

namespace {

using http_vx::h2::ErrorCode;
using http_vx::h2::hpack::Decoder;

int failures = 0;

void check(bool ok, const char *what) {
    if (ok) return;
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

/**
 * @brief
 * \~english Whether @p s names exactly @p want in @p out.
 * \~spanish Si @p s nombra exactamente @p want dentro de @p out.
 * \~
 */
bool span_is(const http_vx::Span &s, const http_vx::Buffer &out,
             const char *want) {
    const size_t len = std::strlen(want);
    if (s.len != len) return false;
    return std::memcmp(out.data() + s.off, want, len) == 0;
}

bool field_is(const http_vx::Request &req, const http_vx::Buffer &out,
              size_t i, const char *name, const char *value) {
    if (i >= req.fields.size()) return false;
    const http_vx::Field &f = req.fields.begin()[i];
    return span_is(http_vx::Span{f.name_off, f.name_len}, out, name) &&
           span_is(http_vx::Span{f.value_off, f.value_len}, out, value);
}

/**
 * @brief
 * \~english The three requests of RFC 7541 appendix C.3, in order.
 * \~spanish Las tres peticiones del apendice C.3 del RFC 7541, en orden.
 * \~
 *
 * \~english
 * Written out as the specification writes them: the first spells everything,
 * the second is shorter because the first was remembered, and the third is
 * shorter still.  That shrinking IS the test -- it only happens if the table
 * is being kept the way the encoder believes.
 *
 * And here is the claim this project has been making since `semantics/`: what
 * comes out is a @c Request, with a method and a target and an authority, and
 * it is the same one the HTTP/1.1 parser builds out of a line of text.
 *
 * \~spanish
 * Escritas como las escribe la especificacion: la primera deletrea todo, la
 * segunda es mas corta porque la primera se recordo, y la tercera todavia mas.
 * Ese encogimiento ES la prueba -- solo ocurre si la tabla se esta llevando
 * como cree el codificador.
 *
 * Y aqui esta la afirmacion que viene haciendo este proyecto desde
 * `semantics/`: lo que sale es un @c Request, con su metodo y su destino y su
 * anfitrion, y es el mismo que construye de una linea de texto el analizador de
 * HTTP/1.1.
 *
 * \~
 */
void test_the_specification_sequence() {
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    // C.3.1: :method GET, :scheme http, :path /, :authority www.example.com
    const uint8_t first[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77,
                             0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
                             0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d};
    check(d.decode(first, sizeof(first), out, req) == ErrorCode::NoError,
          "the first request was refused");

    check(req.method == http_vx::MethodId::Get, "the method is not GET");
    check(span_is(req.method_text, out, "GET"), "the method spelling is wrong");
    check(span_is(req.target, out, "/"), "the target is not the root");
    check(span_is(req.scheme, out, "http"), "the scheme is wrong");
    check(span_is(req.authority, out, "www.example.com"), "the authority is wrong");
    check(req.version == http_vx::Version::Http2, "the version is not HTTP/2");
    check(req.fields.empty(), "an ordinary field appeared from nowhere");

    /* \~english
     * The authority was remembered, which is what makes the next one shorter.
     * \~spanish
     * El anfitrion se recordo, que es lo que hace mas corta la siguiente.
     * \~ */
    check(d.table().count() == 1, "the first request remembered nothing");
    check(d.table().size() == 57, "what was remembered costs something else");

    // C.3.2: lo mismo mas cache-control: no-cache, que tambien se recuerda.
    const uint8_t second[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f,
                              0x2d, 0x63, 0x61, 0x63, 0x68, 0x65};
    out.clear();
    check(d.decode(second, sizeof(second), out, req) == ErrorCode::NoError,
          "the second request was refused");

    check(span_is(req.authority, out, "www.example.com"),
          "the remembered authority did not come back");
    check(req.fields.size() == 1, "the second request has the wrong fields");
    check(field_is(req, out, 0, "cache-control", "no-cache"),
          "the cache directive is wrong");
    check(d.table().count() == 2, "the second request remembered nothing");

    // C.3.3: :method GET, :scheme https, :path /index.html, y una propia.
    const uint8_t third[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75,
                             0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
                             0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d,
                             0x76, 0x61, 0x6c, 0x75, 0x65};
    out.clear();
    check(d.decode(third, sizeof(third), out, req) == ErrorCode::NoError,
          "the third request was refused");

    check(span_is(req.scheme, out, "https"), "the scheme did not change");
    check(span_is(req.target, out, "/index.html"), "the target did not change");
    check(span_is(req.authority, out, "www.example.com"),
          "the authority remembered two requests ago did not come back");
    check(req.fields.size() == 1, "the third request has the wrong fields");
    check(field_is(req, out, 0, "custom-key", "custom-value"),
          "the custom field is wrong");
    check(d.table().count() == 3, "the third request remembered nothing");
}

/**
 * @brief
 * \~english The same sequence written in Huffman, from appendix C.4.
 * \~spanish La misma sucesion escrita en Huffman, del apendice C.4.
 * \~
 *
 * \~english
 * The same requests and the same table after each, which is the point: how a
 * string was written is this layer's business and changes nothing above it.
 *
 * \~spanish
 * Las mismas peticiones y la misma tabla despues de cada una, que es de lo que
 * se trata: como se escribio una cadena es cosa de esta capa y no cambia nada
 * de las de arriba.
 *
 * \~
 */
void test_the_same_thing_in_huffman() {
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    const uint8_t first[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3,
                             0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                             0x90, 0xf4, 0xff};
    check(d.decode(first, sizeof(first), out, req) == ErrorCode::NoError,
          "the first Huffman request was refused");
    check(span_is(req.authority, out, "www.example.com"),
          "the Huffman authority did not come out");
    check(d.table().size() == 57,
          "the Huffman request remembered a different amount");

    const uint8_t second[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x86,
                              0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    out.clear();
    check(d.decode(second, sizeof(second), out, req) == ErrorCode::NoError,
          "the second Huffman request was refused");
    check(field_is(req, out, 0, "cache-control", "no-cache"),
          "the Huffman cache directive is wrong");

    const uint8_t third[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8,
                             0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25,
                             0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf};
    out.clear();
    check(d.decode(third, sizeof(third), out, req) == ErrorCode::NoError,
          "the third Huffman request was refused");
    check(field_is(req, out, 0, "custom-key", "custom-value"),
          "the Huffman custom field is wrong");
    check(d.table().count() == 3, "the Huffman sequence remembered the wrong number");
}

/**
 * @brief
 * \~english The bomb: a small block that means a great deal.
 * \~spanish La bomba: un bloque pequeno que significa muchisimo.
 * \~
 *
 * \~english
 * One remembered field of four thousand bytes, and then a hundred bytes of
 * block that name it a hundred times.  The frame layer's limit never fires --
 * the block really is a hundred bytes -- so the only thing between this and
 * four hundred kilobytes of header list is the limit counted here, on what
 * comes out.
 *
 * \~spanish
 * Una cabecera recordada de cuatro mil bytes, y despues cien bytes de bloque
 * que la nombran cien veces.  El limite de la capa de tramas no salta -- el
 * bloque mide cien bytes de verdad -- asi que lo unico entre esto y
 * cuatrocientos kilobytes de lista de cabeceras es el limite que se cuenta
 * aqui, sobre lo que sale.
 *
 * \~
 */
void test_the_bomb() {
    Decoder d;
    http_vx::h2::Limits limits;
    limits.max_header_list_size = 4096;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    /* \~english
     * A literal that gets remembered: a short name and a value of a thousand
     * bytes.  One block, and the table holds it afterwards.
     * \~spanish
     * Un literal que se recuerda: un nombre corto y un valor de mil bytes.  Un
     * bloque, y la tabla se lo queda despues.
     * \~ */
    uint8_t big[1200];
    size_t n = 0;
    big[n++] = 0x40;  // literal, con indexado incremental, nombre nuevo
    big[n++] = 0x01;  // nombre de un byte, sin Huffman
    big[n++] = 'x';
    big[n++] = 0x7F;  // valor: prefijo de 7 bits lleno
    big[n++] = 0xE9;  // 1000 - 127 = 873 = 0xE9 0x06
    big[n++] = 0x06;
    for (size_t i = 0; i < 1000; ++i) big[n++] = 'a';

    check(d.decode(big, n, out, req) == ErrorCode::NoError,
          "the big field was refused");
    check(d.table().count() == 1, "the big field was not remembered");

    /* \~english
     * And now the block that costs nothing to send.  Each byte after the first
     * is one mention of a field worth a thousand and thirty-three.
     * \~spanish
     * Y ahora el bloque que no cuesta nada mandar.  Cada byte a partir del
     * primero es una mencion de una cabecera que vale mil treinta y tres.
     * \~ */
    uint8_t bomb[64];
    for (size_t i = 0; i < sizeof(bomb); ++i) bomb[i] = 0xBE;  // indice 62

    out.clear();
    const ErrorCode e = d.decode(bomb, sizeof(bomb), out, req);
    check(e == ErrorCode::EnhanceYourCalm,
          "a block that names a big field many times was not stopped");

    /* \~english
     * And it stopped where the limit is, not after everything was written.
     * A check made at the end would have written the four hundred kilobytes
     * first, which is the only thing that matters about where the check is.
     * \~spanish
     * Y paro donde esta el limite, no despues de escribirlo todo.  Una
     * comprobacion hecha al final habria escrito antes los cuatrocientos
     * kilobytes, que es lo unico que importa de donde esta la comprobacion.
     * \~ */
    check(out.size() < 3 * limits.max_header_list_size,
          "it wrote far more than the limit before noticing the limit");
}

/**
 * @brief
 * \~english The indices that name nothing.
 * \~spanish Los indices que no nombran nada.
 * \~
 */
void test_bad_indices() {
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    /* \~english
     * Index zero.  It is the one index a block may not use, and reading it as
     * the first entry would shift every index in the block by one.
     * \~spanish
     * El indice cero.  Es el unico indice que un bloque no puede usar, y leerlo
     * como la primera entrada desplazaria todos los indices del bloque en uno.
     * \~ */
    const uint8_t zero[] = {0x80};
    check(d.decode(zero, sizeof(zero), out, req) == ErrorCode::CompressionError,
          "index zero was read as an entry");

    /* \~english
     * And an index past what is remembered.  It is a connection error and not
     * a bad request: the two ends disagree about what the table holds, so
     * every index after this one is a guess.
     * \~spanish
     * Y un indice mas alla de lo recordado.  Es un error de conexion y no una
     * peticion mala: los dos extremos discrepan sobre lo que hay en la tabla,
     * asi que todos los indices de ahi en adelante son conjeturas.
     * \~ */
    d.reset(limits);
    out.clear();
    const uint8_t past[] = {0xFF, 0x00};  // 127 + 0 = 127, muy pasado
    check(d.decode(past, sizeof(past), out, req) == ErrorCode::CompressionError,
          "an index past the table was read");
}

/**
 * @brief
 * \~english The pseudo-headers, and the rules about where they go.
 * \~spanish Las pseudo-cabeceras, y las reglas de donde van.
 * \~
 */
void test_pseudo_rules() {
    http_vx::h2::Limits limits;
    http_vx::Buffer out;
    http_vx::Request req;

    {
        /* \~english
         * An ordinary field before a pseudo-header.  A recipient decides what
         * to do with a message from the pseudo-headers, and one that arrived
         * after the fields would be deciding after acting.
         * \~spanish
         * Una cabecera corriente antes de una pseudo-cabecera.  Quien recibe
         * decide que hacer con un mensaje a partir de las pseudo-cabeceras, y
         * una que llegara detras estaria decidiendo despues de actuar.
         * \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t late[] = {0x0f, 0x10, 0x01, 'x', 0x82};
        check(d.decode(late, sizeof(late), out, req) == ErrorCode::ProtocolError,
              "a pseudo-header after an ordinary field was accepted");
    }
    {
        /* \~english Twice is two answers to one question.
         * \~spanish Dos veces son dos respuestas a una pregunta.  \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t twice[] = {0x82, 0x83};  // :method GET, :method POST
        check(d.decode(twice, sizeof(twice), out, req) == ErrorCode::ProtocolError,
              "a method given twice was accepted");
    }
    {
        /* \~english A status is what a response carries.
         * \~spanish Un estado es lo que lleva una respuesta.  \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t status[] = {0x88};  // :status 200
        check(d.decode(status, sizeof(status), out, req) == ErrorCode::ProtocolError,
              "a status in a request was accepted");
    }
    {
        /* \~english
         * A name with a colon that nobody has defined.  The colon is reserved
         * for the protocol, so this is a name from a version this end does not
         * speak -- and passing it on as an ordinary field would be inventing a
         * meaning for it.
         * \~spanish
         * Un nombre con dos puntos que nadie ha definido.  Los dos puntos estan
         * reservados para el protocolo, asi que es un nombre de una version que
         * este extremo no habla -- y pasarlo como cabecera corriente seria
         * inventarle un significado.
         * \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t made_up[] = {0x00, 0x05, ':', 'w', 'h', 'a', 't',
                                   0x01, 'x'};
        check(d.decode(made_up, sizeof(made_up), out, req) ==
                  ErrorCode::ProtocolError,
              "a pseudo-header nobody has defined was accepted");
    }
}

/**
 * @brief
 * \~english The names HTTP/2 will not carry.
 * \~spanish Los nombres que HTTP/2 no lleva.
 * \~
 */
void test_field_rules() {
    http_vx::h2::Limits limits;
    http_vx::Buffer out;
    http_vx::Request req;

    {
        /* \~english
         * A capital letter.  It is refused and not folded: folding would make
         * this server accept what the one beside it refuses, which is where
         * two recipients start disagreeing about a message.
         * \~spanish
         * Una mayuscula.  Se rechaza y no se pliega: plegarla haria que este
         * servidor aceptara lo que rechaza el de al lado, que es por donde dos
         * receptores empiezan a discrepar sobre un mensaje.
         * \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t upper[] = {0x00, 0x04, 'H', 'o', 's', 't', 0x01, 'x'};
        check(d.decode(upper, sizeof(upper), out, req) == ErrorCode::ProtocolError,
              "a capital letter in a field name was accepted");
    }
    {
        /* \~english
         * A connection field.  HTTP/2 answers all of those itself, for the
         * whole connection at once, so one in a message is HTTP/1.1 wearing
         * HTTP/2's clothes.
         * \~spanish
         * Una cabecera de conexion.  HTTP/2 contesta a todas ellas el mismo,
         * para la conexion entera, asi que una en un mensaje es HTTP/1.1
         * disfrazado de HTTP/2.
         * \~ */
        const char *const forbidden[] = {"connection", "keep-alive",
                                         "transfer-encoding", "upgrade",
                                         "proxy-connection"};
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            Decoder d;
            d.reset(limits);
            out.clear();

            uint8_t block[64];
            size_t n = 0;
            block[n++] = 0x00;
            const size_t len = std::strlen(forbidden[i]);
            block[n++] = static_cast<uint8_t>(len);
            std::memcpy(block + n, forbidden[i], len);
            n += len;
            block[n++] = 0x01;
            block[n++] = 'x';

            check(d.decode(block, n, out, req) == ErrorCode::ProtocolError,
                  "a connection field was carried in HTTP/2");
        }
    }
    {
        /* \~english
         * `TE` survives, and only saying `trailers`.  It is the one connection
         * field HTTP/2 keeps, because what it asks for is about the message.
         * \~spanish
         * `TE` sobrevive, y solo diciendo `trailers`.  Es la unica cabecera de
         * conexion que conserva HTTP/2, porque lo que pide es del mensaje.
         * \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t ok[] = {0x00, 0x02, 't', 'e', 0x08, 't', 'r',
                              'a',  'i',  'l', 'e', 'r',  's'};
        check(d.decode(ok, sizeof(ok), out, req) == ErrorCode::NoError,
              "te: trailers was refused");

        Decoder d2;
        d2.reset(limits);
        out.clear();
        const uint8_t bad[] = {0x00, 0x02, 't', 'e', 0x07, 'c', 'h',
                               'u',  'n',  'k', 'e', 'd'};
        check(d2.decode(bad, sizeof(bad), out, req) == ErrorCode::ProtocolError,
              "te saying something other than trailers was accepted");
    }
}

/**
 * @brief
 * \~english A size update may only come at the front of a block.
 * \~spanish Un cambio de tamano solo puede ir al principio de un bloque.
 * \~
 *
 * \~english
 * Once a field has been read the table has changed underneath, and a limit
 * arriving then would evict things the encoder still believes are there --
 * which is a disagreement that does not announce itself.
 *
 * \~spanish
 * Una vez leida una cabecera la tabla ha cambiado por debajo, y un limite que
 * llegara entonces desalojaria cosas que el codificador todavia cree que estan
 * -- que es una discrepancia que no se anuncia.
 *
 * \~
 */
void test_size_updates() {
    http_vx::h2::Limits limits;
    http_vx::Buffer out;
    http_vx::Request req;

    {
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t first[] = {0x3F, 0xE1, 0x1F, 0x82};  // 4096, luego GET
        check(d.decode(first, sizeof(first), out, req) == ErrorCode::NoError,
              "a size update at the front of a block was refused");
        check(d.table().max_size() == 4096, "the limit did not change");
    }
    {
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t late[] = {0x82, 0x20};  // GET, luego un limite de cero
        check(d.decode(late, sizeof(late), out, req) == ErrorCode::CompressionError,
              "a size update after a field was accepted");
    }
    {
        /* \~english
         * And past what was announced.  A peer asking for more is asking this
         * server to remember more than it said it would.
         * \~spanish
         * Y por encima de lo anunciado.  Un extremo que pida mas esta pidiendo
         * a este servidor que recuerde mas de lo que dijo.
         * \~ */
        Decoder d;
        d.reset(limits);
        out.clear();
        const uint8_t huge[] = {0x3F, 0xE2, 0xFF, 0xFF, 0xFF, 0x0F};
        check(d.decode(huge, sizeof(huge), out, req) == ErrorCode::CompressionError,
              "a limit past the announcement was accepted");
    }
}

/**
 * @brief
 * \~english A block that ends in the middle of itself.
 * \~spanish Un bloque que acaba en mitad de si mismo.
 * \~
 *
 * \~english
 * There is no waiting here: the frame layer already holds a block until its
 * last CONTINUATION, so one that runs out inside a string is a block that lies
 * about its own contents.
 *
 * \~spanish
 * Aqui no se espera: la capa de tramas ya guarda un bloque hasta su ultima
 * CONTINUATION, asi que uno que se acabe dentro de una cadena es un bloque que
 * miente sobre su propio contenido.
 *
 * \~
 */
void test_truncated() {
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    const uint8_t cut[] = {0x00, 0x0A, 'x'};  // dice diez bytes de nombre, da uno
    check(d.decode(cut, sizeof(cut), out, req) == ErrorCode::CompressionError,
          "a name that promises more than the block has was read");

    out.clear();
    const uint8_t half[] = {0x00, 0x01, 'x'};  // nombre bien, sin valor
    check(d.decode(half, sizeof(half), out, req) == ErrorCode::CompressionError,
          "a field with no value at all was read");
}

/**
 * @brief
 * \~english Reading one message does not leave the next one anything.
 * \~spanish Leer un mensaje no le deja nada al siguiente.
 * \~
 *
 * \~english
 * The table survives between messages and everything else must not: a
 * pseudo-header counted in the last request would refuse this one for giving
 * it twice, and a field from the last one would be served as part of this.
 *
 * \~spanish
 * La tabla sobrevive entre mensajes y todo lo demas no: una pseudo-cabecera
 * contada en la peticion anterior rechazaria esta por darla dos veces, y una
 * cabecera de la anterior se serviria como parte de esta.
 *
 * \~
 */
void test_between_messages() {
    Decoder d;
    http_vx::h2::Limits limits;
    d.reset(limits);

    http_vx::Buffer out;
    http_vx::Request req;

    const uint8_t one[] = {0x82, 0x86, 0x84};
    check(d.decode(one, sizeof(one), out, req) == ErrorCode::NoError,
          "the first request was refused");

    out.clear();
    check(d.decode(one, sizeof(one), out, req) == ErrorCode::NoError,
          "the same request again was refused, so something was counted twice");
    check(req.fields.empty(), "a field from the previous request survived");
    check(span_is(req.target, out, "/"), "the target did not come back");

    /* \~english And the table did survive, which is the half that must.
     * \~spanish Y la tabla si sobrevivio, que es la mitad que debe.  \~ */
    const uint8_t remembering[] = {0x40, 0x01, 'a', 0x01, 'b'};
    out.clear();
    d.decode(remembering, sizeof(remembering), out, req);
    check(d.table().count() == 1, "the table did not keep what it was given");

    out.clear();
    check(d.decode(one, sizeof(one), out, req) == ErrorCode::NoError,
          "a later request was refused");
    check(d.table().count() == 1, "the table forgot between messages");
}

} // namespace

int main() {
    test_the_specification_sequence();
    test_the_same_thing_in_huffman();
    test_the_bomb();
    test_bad_indices();
    test_pseudo_rules();
    test_field_rules();
    test_size_updates();
    test_truncated();
    test_between_messages();

    if (failures != 0) {
        std::fprintf(stderr, "test_h2_decoder: %d failures\n", failures);
        return 1;
    }
    std::printf("test_h2_decoder: ok\n");
    return 0;
}
