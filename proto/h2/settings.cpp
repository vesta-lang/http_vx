/*
 * http_vx -- servidor HTTP/1.1, HTTP/2 y HTTP/3
 *
 * Copyright (c) 2026 David Lopez T. (DesmonHak)
 * Licencia: MIT (ver LICENSE).
 */

/**
 * @file proto/h2/settings.cpp
 * @brief
 * \~english Reading and writing what the two ends agreed on.
 * \~spanish Leer y escribir aquello en lo que quedaron los dos extremos.
 * \~
 */

#include "http_vx/h2_settings.h"

namespace http_vx {
namespace h2 {

namespace {

/**
 * @brief
 * \~english Writes one setting at @p at, if it fits.
 * \~spanish Escribe un ajuste en @p at, si cabe.
 * \~
 *
 * @param out   \~english where the payload goes  \~spanish donde va la carga  \~
 * @param cap   \~english how much room there is  \~spanish cuanto sitio hay  \~
 * @param at    \~english how far in; advanced by what was written
 *              \~spanish cuanto se lleva; se avanza con lo escrito  \~
 * @param id    \~english which setting  \~spanish que ajuste  \~
 * @param value \~english its value  \~spanish su valor  \~
 * @return      \~english false if it did not fit
 *              \~spanish false si no cabia  \~
 */
bool put_setting(uint8_t *out, size_t cap, size_t &at, SettingId id,
                 uint32_t value) noexcept {
    if (cap - at < kSettingSize) return false;
    put_be16(out + at, static_cast<uint16_t>(id));
    put_be32(out + at + 2, value);
    at += kSettingSize;
    return true;
}

} // namespace

SettingsChange apply_settings(const uint8_t *p, size_t n,
                              Settings &s) noexcept {
    SettingsChange out;

    /* \~english
     * A payload that is not a whole number of settings is a FRAME SIZE error
     * and not a protocol one, and the distinction is not bookkeeping: it says
     * the sender's frame header disagreed with the sender's own payload, which
     * is a different failure from a sender that wrote a value this end refuses.
     *
     * \~spanish
     * Una carga que no es un numero entero de ajustes es un error de TAMANO DE
     * TRAMA y no de protocolo, y la distincion no es contabilidad: dice que la
     * cabecera de trama de quien envia discrepaba de su propia carga, que es un
     * fallo distinto del de quien escribe un valor que este extremo rechaza.
     * \~ */
    if (n % kSettingSize != 0) {
        out.error = ErrorCode::FrameSizeError;
        return out;
    }

    /* \~english
     * The window delta is measured from where the initial window was BEFORE
     * this payload, not from the previous setting in it.  A payload that names
     * the identifier three times moves every existing stream once, by the
     * difference between where it started and where it ended -- which is what
     * a peer that read the payload as a whole will have done.
     *
     * \~spanish
     * La diferencia de ventana se mide desde donde estaba la ventana inicial
     * ANTES de esta carga, no desde el ajuste anterior de dentro.  Una carga que
     * nombre el identificador tres veces mueve una sola vez cada flujo abierto,
     * por la diferencia entre donde empezo y donde acabo -- que es lo que habra
     * hecho un extremo que leyo la carga entera.
     * \~ */
    const uint32_t window_before = s.initial_window_size;

    for (size_t at = 0; at < n; at += kSettingSize) {
        const uint16_t id = be16(p + at);
        const uint32_t value = be32(p + at + 2);

        switch (static_cast<SettingId>(id)) {
        case SettingId::HeaderTableSize:
            s.header_table_size = value;
            break;

        case SettingId::EnablePush:
            /* \~english
             * Nothing but zero or one.  It is a boolean written in four bytes,
             * and a peer that wrote anything else did not mean either of them.
             * \~spanish
             * Nada que no sea cero o uno.  Es un booleano escrito en cuatro
             * bytes, y un extremo que escribiera otra cosa no queria decir
             * ninguno de los dos.
             * \~ */
            if (value > 1) {
                out.error = ErrorCode::ProtocolError;
                return out;
            }
            s.enable_push = value != 0;
            break;

        case SettingId::MaxConcurrentStreams:
            s.max_concurrent_streams = value;
            break;

        case SettingId::InitialWindowSize:
            /* \~english
             * The one value whose own limit is a flow-control error rather than
             * a protocol one, because what it breaks is the arithmetic and not
             * the grammar: a window larger than the field would make every
             * later sum wrong rather than making this frame unreadable.
             * \~spanish
             * El unico valor cuyo limite propio es un error de control de flujo
             * y no de protocolo, porque lo que rompe es la aritmetica y no la
             * gramatica: una ventana mayor que el campo haria mal todas las
             * sumas posteriores en vez de hacer ilegible esta trama.
             * \~ */
            if (value > kMaxWindow) {
                out.error = ErrorCode::FlowControlError;
                return out;
            }
            s.initial_window_size = value;
            break;

        case SettingId::MaxFrameSize:
            if (value < kMinFrameSize || value > kMaxFrameSize) {
                out.error = ErrorCode::ProtocolError;
                return out;
            }
            s.max_frame_size = value;
            break;

        case SettingId::MaxHeaderListSize:
            s.max_header_list_size = value;
            break;

        default:
            /* \~english
             * Ignored, and this is the one place in this project where
             * ignoring something is right.  An identifier nobody here knows is
             * one a later version of the protocol defined, and refusing it
             * would break the connection with every peer newer than this
             * build.  It is not silence either: what an unknown setting means
             * is exactly "an end that does not know this one carries on", so
             * carrying on IS the defined behaviour rather than a guess at one.
             *
             * \~spanish
             * Se ignora, y este es el unico sitio de este proyecto donde
             * ignorar algo esta bien.  Un identificador que aqui no conoce
             * nadie es uno que definio una version posterior del protocolo, y
             * rechazarlo romperia la conexion con todos los extremos mas nuevos
             * que esta construccion.  Y tampoco es callarse: lo que significa
             * un ajuste desconocido es exactamente "un extremo que no conozca
             * este sigue", asi que seguir ES el comportamiento definido y no
             * una conjetura sobre cual seria.
             * \~ */
            break;
        }
    }

    out.window_delta = static_cast<int64_t>(s.initial_window_size) -
                       static_cast<int64_t>(window_before);
    return out;
}

size_t write_settings(uint8_t *out, size_t cap, const Limits &limits) noexcept {
    /**
     * \~english
     * The defaults this compares against are @c Settings's own, so that adding
     * a setting there and forgetting it here does not silently announce a value
     * nobody meant.  The comparison is against a fresh one rather than against
     * literals for the same reason the reverse static index is derived: two
     * statements of what the default is disagree by announcing the wrong
     * number, on a connection that works.
     *
     * \~spanish
     * Los valores por defecto contra los que se compara son los de @c Settings,
     * para que anadir un ajuste alli y olvidarlo aqui no anuncie por lo bajo un
     * valor que nadie queria.  La comparacion es contra uno recien hecho y no
     * contra literales por lo mismo que se deriva el indice estatico inverso:
     * dos declaraciones de cual es el valor por defecto discrepan anunciando el
     * numero equivocado, en una conexion que funciona.
     * \~
     */
    const Settings fresh;
    size_t at = 0;

    if (limits.header_table_size != fresh.header_table_size &&
        !put_setting(out, cap, at, SettingId::HeaderTableSize,
                     limits.header_table_size))
        return 0;

    if (limits.max_concurrent_streams != fresh.max_concurrent_streams &&
        !put_setting(out, cap, at, SettingId::MaxConcurrentStreams,
                     limits.max_concurrent_streams))
        return 0;

    if (limits.initial_window_size != fresh.initial_window_size &&
        !put_setting(out, cap, at, SettingId::InitialWindowSize,
                     limits.initial_window_size))
        return 0;

    if (limits.max_frame_size != fresh.max_frame_size &&
        !put_setting(out, cap, at, SettingId::MaxFrameSize,
                     limits.max_frame_size))
        return 0;

    if (limits.max_header_list_size != fresh.max_header_list_size &&
        !put_setting(out, cap, at, SettingId::MaxHeaderListSize,
                     limits.max_header_list_size))
        return 0;

    /* \~english
     * And push is turned off explicitly, although the default is on.  A server
     * that never pushes and says nothing leaves the peer holding room for
     * promises that will not come -- and worse, leaves this end having to
     * refuse a PUSH_PROMISE it told the peer it would accept.
     *
     * \~spanish
     * Y el empuje se apaga diciendolo, aunque por defecto este encendido.  Un
     * servidor que no empuja nunca y no dice nada deja al otro extremo
     * guardando sitio para promesas que no van a llegar -- y peor, deja a este
     * teniendo que rechazar un PUSH_PROMISE que le dijo al otro que aceptaria.
     * \~ */
    if (!put_setting(out, cap, at, SettingId::EnablePush, 0)) return 0;

    return at;
}

} // namespace h2
} // namespace http_vx
