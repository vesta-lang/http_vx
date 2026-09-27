# http_vx -- Respuestas abiertas

    Documento:  HVX-5
    Estado:     BORRADOR
    Fecha:      2026-09-27
    Sustituye:  --
    Ver tambien: HVX-1 (arquitectura: R1, R4, R9, R14, R20), HVX-3 (el contrato publico)

## Resumen

Una **respuesta abierta** es una respuesta cuyo cuerpo no existe entero
cuando el manejador vuelve: sale a trozos, durante un tiempo que no se sabe de
antemano.  Es lo que piden los Server-Sent Events y el transporte HTTP de MCP,
y es la R20 de HVX-1.

Este documento fija como se produce ese cuerpo, como se entera el servidor de
que hay mas, como se hace desde otro hilo, que hace cada version del protocolo
y que no se puede romper.  No fija firmas definitivas -- eso es HVX-3 --, pero
si las decisiones que cualquier firma tiene que respetar.

## 1. Terminologia

Las palabras **DEBE**, **NO DEBE**, **DEBERIA** y **PUEDE** se usan con el
sentido del RFC 2119.

- **Respuesta abierta**: una respuesta cuyo cuerpo sigue saliendo despues de
  que el manejador vuelve.
- **Fuente** (`BodySource`): el objeto de la aplicacion que produce el cuerpo
  de una respuesta abierta.
- **Rellenar** (`fill`): que el fragmento le pida a la fuente bytes para un
  sitio que ya tiene.
- **Aviso** (`kick`): que la aplicacion le diga al fragmento "esta fuente tiene
  algo".  No lleva datos.
- **Fragmento**, **conexion**, **flujo**: como en HVX-1.
- **Despertar**: sacar a un fragmento de su espera en el sistema operativo.

## 2. Requisitos

> **R32. El cuerpo de una respuesta abierta DEBE producirse cuando el
> transporte tiene sitio para mandarlo, y no antes.**

> **R33. Producir un trozo NO DEBE costar una copia intermedia: la fuente
> escribe en el buffer del que sale el trozo, con su enmarcado ya reservado.**

> **R34. Una respuesta abierta callada NO DEBE tener ningun buffer (R1).**

> **R35. Cualquier hilo DEBE poder avisar de que una fuente tiene algo, sin
> cerrojos, en tiempo constante y sin reservar memoria; y un aviso NO DEBE
> perderse.**

> **R36. Muchos avisos sobre la misma fuente DEBEN costar lo mismo que uno:
> la fuente esta en la cola como mucho una vez.**

> **R37. Despertar a un fragmento DEBE costar como mucho una llamada al
> sistema por cada vez que el fragmento se durmio, y ninguna si esta
> despierto.**

> **R38. El final de una respuesta abierta que no decidio la fuente --
> reinicio del otro extremo, cierre, plazo -- DEBE llegarle a la fuente, con su
> motivo.**

> **R39. Una respuesta que no se abre NO DEBE pagar nada de esto.**

## 3. El modelo: el servidor pide, la aplicacion rellena

Hay dos formas de producir un cuerpo que no existe entero:

| | quien decide cuando | lo que no cabe |
| :-- | :-- | :-- |
| **empujar** (`push(bytes)`) | la aplicacion | hay que guardarlo: memoria que crece, un estado de "lleno", un aviso de "ya hay sitio" |
| **pedir y rellenar** (`fill(dst, room)`) | el fragmento, cuando hay sitio | no existe: nunca se pide mas de lo que cabe |

Se elige **pedir y rellenar**.  Empujar obliga a guardar lo que el transporte
todavia no puede mandar, y eso es exactamente la memoria que la R1 prohibe: un
cliente lento o una ventana de control de flujo cerrada convierten cada byte
empujado en un byte retenido.  Pidiendo, la contrapresion no es un estado sino
la ausencia de una llamada: con la ventana cerrada no se llama a `fill`.

El aviso no lleva datos por lo mismo: los datos siguen donde los tiene la
aplicacion hasta que el fragmento tiene sitio para ellos.

## 4. El contrato de la aplicacion

### 4.1 Abrir

El manejador abre la respuesta dentro de su llamada, con el estado y los campos
ya escritos en el constructor de respuestas:

    OpenResponse r = res.open(source);

- El estado y los campos salen **ya**.  Lo que el manejador haya escrito con
  `body()` antes de abrir es el primer trozo.
- `OpenResponse` identifica la respuesta: la referencia de la conexion **con
  su generacion** y el identificador de flujo (cero en HTTP/1.1).  Es un valor
  que se copia; una referencia a una conexion que ya no existe no encuentra
  nada, nunca otra conexion.
- Abrir PUEDE rechazarse: una peticion `HEAD` (la respuesta no tiene cuerpo,
  y sale entera con la cabecera), el tope de respuestas abiertas del fragmento
  o de la conexion, o una conexion que se esta cerrando.  El rechazo devuelve
  una `OpenResponse` invalida y la fuente no se usa nunca; el tope agotado se
  contesta 503 (HVX-1, 12).

### 4.2 La fuente

    class BodySource {
        virtual size_t fill(OpenResponse r, uint8_t *dst, size_t room, bool &done) noexcept = 0;
        virtual void gone(OpenResponse r, GoneReason why) noexcept = 0;
        void kick() noexcept;          // desde cualquier hilo
    };

- **`fill`** escribe hasta `room` bytes en `dst` y devuelve cuantos.  `dst` es
  el sitio del buffer de salida del que saldran, con el enmarcado de la version
  ya reservado delante: la fuente escribe cuerpo y nada mas.  `done = true`
  acaba la respuesta despues de esos bytes.  Devolver cero sin `done` es
  correcto: "ahora no tengo nada".
- **`gone`** dice que la respuesta acabo sin que la fuente lo decidiera, y por
  que: el otro extremo la reinicio, la conexion se cerro, vencio el plazo, o el
  fragmento se suelta.  Despues de `gone` no se vuelve a llamar a `fill`.
- **`kick`** dice "tengo algo".  Se puede llamar desde cualquier hilo y
  cualquier numero de veces.

`fill` y `gone` se llaman **siempre en el hilo del fragmento** que tiene la
conexion (R4).  La fuente no necesita cerrojos para lo que hacen ellas; solo
para lo que comparta con los hilos que la avisan.

### 4.3 Cuando se llama a `fill`

- Al abrir, si hay sitio.
- Despues de un aviso, en la vuelta siguiente del fragmento, si hay sitio.
- Cuando el transporte recupera sitio -- una ventana que se abre, un envio que
  acaba -- **si el ultimo `fill` lleno todo el sitio que se le dio**.  Una
  fuente que devolvio menos que `room` ha dicho que no tiene mas: hasta su
  siguiente aviso no se le pregunta.

Es el mismo borde que "escribible" en un socket: se pregunta mientras se
contesta lleno, y despues se espera a que avise.

### 4.4 Vida de la fuente

> **Toda fuente recibe exactamente un `gone()`, tambien cuando acaba ella
> misma (`done`, motivo `Finished`).  La fuente es de la aplicacion, DEBE vivir
> hasta su `gone()` y NO DEBE avisarse despues.**

Es el mismo contrato que tiene cerrar un `uv_async_t` en libuv o una tasklet en
HAProxy: el nodo de la cola vive dentro de la fuente, y liberar una fuente con
un aviso en vuelo seria el fragmento leyendo memoria liberada.  Por eso el
final no es el `fill` que pone `done`: mientras ese `fill` corre, otro hilo
puede estar avisando y metiendo la fuente en la pila.

El fragmento entrega `gone()` solo cuando la fuente no esta en la pila: pone su
marca `queued` a 1 con un intercambio.  Si valia 0, nadie la tiene y `gone()`
sale en el acto; si valia 1, esta en la pila -- o un hilo la esta metiendo en
este instante --, y `gone()` sale cuando el fragmento la saque, en su vuelta
siguiente.  La marca se queda a 1: un aviso tardio ya no la vuelve a meter.
Quien avise desde otros hilos es responsable de que hayan dejado de hacerlo al
recibir `gone()`.

## 5. Del lado del fragmento

Una vuelta del fragmento con respuestas abiertas:

1. Espera en el backend (IOCP, io_uring, epoll), acotada por el plazo mas
   cercano.
2. Al volver, **pone `sleeping` a 0** y se lleva toda la pila de avisos de una
   vez (6.2).
3. Por cada fuente avisada: **limpia su marca `queued` ANTES** de pedirle
   nada, y despues, si su respuesta sigue viva y hay sitio, llama a `fill`.
   Limpiar antes hace que un aviso que llega mientras se rellena vuelva a
   encolar la fuente en lugar de perderse.
4. Procesa las finalizaciones del backend como siempre.  Un envio acabado o
   una ventana abierta pueden hacer escribible una respuesta abierta (4.3).
5. Antes de volver a esperar, aplica el protocolo de 6.3.

El sitio que se ofrece a `fill` es el minimo de lo que admite el transporte y
de lo que cabe en el buffer de salida menos su enmarcado:

| version | limita el sitio |
| :-- | :-- |
| HTTP/1.1 | el buffer de salida de la conexion |
| HTTP/2 | la ventana del flujo, la de la conexion, `SETTINGS_MAX_FRAME_SIZE` y el buffer |
| HTTP/3 | el credito de control de flujo del flujo y de la conexion QUIC, y lo que admite el envio del flujo |

Cada trozo mandado **rearma el plazo de inactividad** de la conexion.  Una
respuesta abierta que no dice nada durante el plazo acaba con
`gone(IdleTimeout)`: el plazo protege contra un extremo muerto, y el latido
-- un comentario SSE vacio, por ejemplo -- es politica de la aplicacion.

### 5.1 La puerta del fragmento

Lo que no es de ninguna version lo da el fragmento a sus servicios como una
interfaz.  Un servicio de flujo recibe una `StreamPort` al arrancar el
fragmento (`Service::attach`; un servicio que envuelve a otro, como TLS, se la
pasa); un servicio de datagramas recibe una `OpenPort` a secas al conectarse
(`DatagramService::attach`), porque sus conexiones son suyas: su puerta
comprueba el tope del fragmento, el tope por conexion lo lleva el servicio,
no busca nada en la tabla de conexiones del fragmento, y lo que haya que
mandar se saca despues de vaciar los avisos.  Al soltar el fragmento, el
servicio de datagramas recibe `on_shutdown` y acaba lo abierto con
`Shutdown`.

| llamada | puerta | que hace |
| :-- | :-- | :-- |
| `open(conn, stream, fuente, destino)` | las dos | comprueba los topes, registra la fuente en la pila de avisos con el servicio como destino, y cuenta; con un tope agotado devuelve una respuesta invalida y cuenta el rechazo |
| `fill(fuente, dst, room, done)` | las dos | el unico sitio desde el que se llama a `BodySource::fill`: cuenta llamadas y bytes, y recorta a `room` lo que devuelva la fuente |
| `end(fuente, motivo)` | las dos | acaba la respuesta; su `gone` sale ahora o en el vaciado siguiente (4.4) |
| `want_writable(conn)` | `StreamPort` | pide `Service::on_writable` en cuanto no salga nada de esa conexion |
| `hold_reads(conn, bool)` | `StreamPort` | deja de entregar y de leer los bytes de la conexion, o lo reanuda entregando antes lo que quedo |
| `closing_reason(conn)` | `StreamPort` | el motivo del `gone` de lo que siga abierto: plazo vencido, cierre, o fragmento que se suelta |

El servicio es el destino de los avisos de sus fuentes, porque es el que sabe
a que flujo alimenta cada una; al recibir uno, marca el flujo y pide sitio.
El manejador abre con `ResponseBuilder::open(fuente)`, que el servicio solo
habilita donde la respuesta puede tener cuerpo (no en un `HEAD`).

Ninguna de estas llamadas vuelve a entrar en el servicio: `want_writable` y
`hold_reads` apuntan la conexion en una lista enhebrada por casilla -- una
entrada por conexion, nada reservado al pedir -- que el fragmento atiende al
final de cada vuelta, despues de vaciar los avisos.  `on_writable` recibe un
buffer nuevo del pozo y lo que escriba sale por la cola de la conexion, detras
de lo que ya hubiera: una respuesta abierta tiene como mucho un buffer
saliendo (R34), y el siguiente se le da cuando acaba ese envio.  Sin buffer
libre, la peticion se repite en la vuelta siguiente y se cuenta.

Una conexion que tiene pendiente reanudar no lee: lo que llego mientras estuvo
retenida se entrega antes que cualquier lectura nueva.

## 6. Avisar desde otro hilo

### 6.1 Lo que hacen los disenos serios

El mecanismo sale de leer el codigo de libuv, Netty, Tokio y mio, Seastar,
HAProxy, H2O, nginx y Envoy, y de medir los mecanismos del sistema.  Todos los
que resuelven "muchos productores, un bucle" comparten cuatro reglas, y los que
se saltan alguna la tienen documentada como su punto debil:

1. **Una marca atomica en el propio objeto** para que este en la cola como
   mucho una vez (`TASK_QUEUED` de HAProxy, `NOTIFIED` de Tokio).  La cola
   queda acotada por los objetos vivos, no por los avisos.
2. **El nodo dentro del objeto**, para que avisar no reserve memoria.  Los que
   reservan por aviso -- la cola de hilos externos de Seastar, el
   `std::function` de Envoy, el `Runnable` de Netty -- crecen sin limite con
   una rafaga.
3. **Un despertar agrupado**: un atomico "dormido" por bucle, y solo el
   primer aviso desde que el bucle se durmio hace la llamada al sistema
   (Netty `nextWakeupNanos`, HAProxy `SLEEPING`/`NOTIFIED`, Seastar
   `_sleeping`).
4. **Publicar "me duermo" y despues volver a mirar la cola**, con orden
   secuencial en los dos lados.  Al reves se pierden despertares; Netty
   documenta esa carrera.

Medido en la maquina de desarrollo: un intercambio atomico sobre una marca ya
puesta cuesta del orden de 3 ns; la llamada al sistema que despierta, entre 110
y 350 ns.  Eso es lo que la R37 ahorra en cada aviso que no hace falta.

### 6.2 La cola: una pila sin cerrojos, un nodo por fuente

Cada fuente lleva, invisibles para la aplicacion, una marca atomica `queued`,
un puntero `next` y el fragmento al que pertenece su respuesta.

- **Avisar**: `queued.exchange(1)`.  Si ya valia 1, se acabo -- la fuente
  esta en la cola, y lo que tenga lo va a pedir el fragmento (R36).  Si valia
  0, se mete en la cabeza de la pila del fragmento con un CAS, y se pasa a
  6.3.
- **Vaciar** (solo el fragmento): `head.exchange(nullptr)` se lleva la pila
  entera en una operacion, y se le da la vuelta para atender por orden de
  llegada.

Es una pila de Treiber de un solo consumidor.  Nunca hay que borrar del medio
-- la marca garantiza un nodo por fuente --, asi que no hay ABA que resolver ni
enlaces que bloquear: HAProxy bloquea enlaces en su lista, y un productor que
se queda sin CPU con un enlace bloqueado frena a los demas.  Aqui meter es un
CAS, y un productor lento no frena a nadie.

La cola esta acotada por las respuestas abiertas del fragmento, sin reservar
nada: el nodo es la fuente.

### 6.3 Despertar: `sleeping` y el protocolo de Dekker

Cada fragmento tiene un atomico `sleeping`.

- **El que avisa**, despues de meter la fuente: si `sleeping.exchange(0)`
  valia 1, despierta al fragmento (6.4).  Si valia 0, el fragmento esta
  despierto y va a mirar la pila: no hace nada mas.
- **El fragmento, antes de esperar**: `sleeping.store(1)` con orden
  secuencial, y **despues vuelve a mirar la pila**.  Si no esta vacia, pone
  `sleeping` a 0 y la atiende sin esperar.  Si esta vacia, espera.
- **El fragmento, al volver**: `sleeping.store(0)` y vacia la pila.

Con orden secuencial en los dos lados, o el que avisa ve `sleeping = 1` y
despierta, o el fragmento ve la fuente en la pila y no se duerme.  Una carrera
en este orden solo puede dar un despertar de mas, que el fragmento tolera; en
el orden contrario daria uno de menos, que es una respuesta que no sale nunca.

La marca tambien acota lo que se le manda al sistema: como mucho un despertar
pendiente por fragmento, asi que ni la cola de finalizaciones de IOCP ni la de
io_uring pueden crecer por avisos.

### 6.4 El despertar de cada backend

| backend | despertar | por que |
| :-- | :-- | :-- |
| IOCP | `PostQueuedCompletionStatus` sin `OVERLAPPED` | ninguna operacion de verdad acaba sin el suyo, asi que eso identifica al despertar sin reservar una clave; lo que el sistema ofrece para esto; el mas rapido medido; no necesita el handle del hilo ni ejecuta nada en mitad de la espera, como una APC |
| epoll | `eventfd` en modo de flanco (`EPOLLET`), sin leerlo en cada despertar | cada escritura vuelve a disparar, asi que no hace falta leer para rearmar; se lee solo si el contador se desborda (`EAGAIN`).  Es lo que hacen libuv, Netty y nginx; en modo de nivel habria que leerlo en cada vuelta, una llamada al sistema mas |
| io_uring | el mismo `eventfd`, con una lectura suya siempre armada en el anillo | el anillo solo se despierta por lo que completa; una lectura del `eventfd` completa cuando alguien escribe.  Se vuelve a armar en cada finalizacion: sin eso, el siguiente despertar se pierde en silencio |
| stdio (POSIX) | un `eventfd`, y la lectura espera con `poll` sobre la entrada y el `eventfd`, con el plazo de la espera | una lectura de tuberia bloquea hasta que el otro extremo habla; `poll` sobre los dos la acaba con lo primero que pase, sin perderla: la operacion sigue pendiente |
| stdio (Windows) | un hilo auxiliar hace la lectura; el fragmento espera con `WaitForMultipleObjects` sobre "lectura hecha" y un suceso de despertar | ver abajo |
| memoria | una bandera | las pruebas deciden cuando pasa cada cosa |

En Windows una tuberia anonima no se lee de forma asincrona ni se puede
reabrir para ello (`ReOpenFile` responde `ERROR_PIPE_BUSY`), y toda operacion
sobre un handle sincrono toma el cerrojo de su objeto de fichero: mientras un
hilo esta en `ReadFile`, cualquier otra llamada sobre la tuberia --
`PeekNamedPipe` incluida -- espera a esa lectura.  Por eso UN solo hilo toca la
tuberia de entrada: un auxiliar que hace para este backend lo que el nucleo
hace para IOCP.  El fragmento le entrega el sitio ya reservado en el buffer de
la operacion, que desde ese momento es del auxiliar como un buffer entregado a
IOCP es del nucleo, y espera por los dos sucesos con su plazo.  Despertar es
`SetEvent`.  Una lectura cortada por un despertar o por el plazo sigue en vuelo
y se vuelve a esperar, sobre la misma reserva, en la espera siguiente.

Cancelar con `CancelSynchronousIo` la lectura del propio fragmento desde el
hilo que despierta NO sirve: entre ver al fragmento bloqueado y cancelar, este
puede haber pasado a una escritura sincrona en la tuberia de salida, y la
cancelacion la aborta.  El auxiliar solo lee, asi que la unica cancelacion que
queda -- la suya, al soltar el backend -- no puede dar con otra operacion.

`IORING_OP_MSG_RING` publica una finalizacion en otro anillo sin `eventfd`,
pero un hilo sin anillo propio solo puede usarlo desde el nucleo 6.13
(`IORING_REGISTER_SEND_MSG_RING`).  Queda como mecanismo para los mensajes
entre fragmentos, que si tienen anillo; con `IORING_SETUP_DEFER_TASKRUN` el
fragmento DEBE esperar con `min_complete = 1`, porque un mensaje no lo despierta
hasta completar el numero pedido.

Un `eventfd` o un puerto no se cierran mientras otro hilo puede estar
despertando por ellos: el fragmento que se suelta deja de admitir avisos antes
de cerrar su mecanismo.

## 7. Cada version

### 7.1 HTTP/1.1

- En 1.1, la respuesta abierta va **por trozos** (`Transfer-Encoding:
  chunked`, RFC 9112, 7.1): cada `fill` es un trozo, con su tamano delante en
  el sitio reservado, y `done` escribe el trozo final.
- En 1.0 no hay trozos: la respuesta acaba cerrando la conexion (RFC 9112,
  6.3), y no se reutiliza.
- **Las peticiones que vengan detras en la misma conexion esperan**: HTTP/1.1
  contesta en orden (RFC 9112, 9.3.2).  Mientras la respuesta esta abierta la
  conexion no lee mas alla de lo que ya tiene, y ese freno llega al cliente
  por TCP.  Al acabar, sigue con lo que habia esperado.

### 7.2 HTTP/2

- `HEADERS` sin `END_STREAM`; cada `fill` es una trama `DATA` con su cabecera
  de 9 bytes en el sitio reservado; `done` pone `END_STREAM` en la ultima.
- El sitio lo limitan las dos ventanas (RFC 9113, 5.2): con cualquiera de las
  dos cerrada no se llama a `fill`, y un `WINDOW_UPDATE` hace escribible la
  respuesta.
- Las respuestas abiertas **no salen del pozo de los cuerpos entrantes**:
  tienen el suyo, acotado.  Un SSE largo no puede dejar sin sitio a las
  peticiones de otros (`REFUSED_STREAM`).
- Un `RST_STREAM` del otro extremo acaba en `gone(PeerReset)`.

### 7.3 HTTP/3

- La cabecera sin fin de flujo; cada `fill` es una trama `DATA`, con su tipo y
  su longitud -- dos enteros de longitud variable -- en el sitio reservado;
  `done` acaba el flujo QUIC.
- El sitio lo limitan el control de flujo de QUIC (RFC 9000, 4) y lo que
  admite el envio del flujo.
- Un `RESET_STREAM` o un `STOP_SENDING` del otro extremo acaban en
  `gone(PeerReset)`.

### 7.4 TLS sobre TCP

La salida de una respuesta abierta pasa por el mismo sellado que el resto:
`fill` escribe en claro en la carga del registro, y se cifra en su sitio.  La
fuente no sabe que TLS esta ahi, igual que no lo sabe el manejador.

Lo que lo hace posible es que `Service::on_writable` recibe un presupuesto:
cuantos bytes puede anadir esa llamada, enmarcado incluido.  El servicio TLS
guarda la cabecera de un registro, llama al servicio de dentro con un
presupuesto de 2^14 -- un registro --, y sella en su sitio lo que este escribio
justo detras: tipo, relleno y marca se anaden detras y el proveedor cifra el
texto interior donde esta.  Mientras el de dentro escriba y quepa otro registro
entero en el presupuesto del fragmento, le vuelve a pedir.  Una llamada que no
escribe nada no deja registro: la cabecera guardada se retira.  Una
actualizacion de claves debida sale antes de guardar el sitio.

La cabecera de la respuesta y el primer relleno salen con la peticion, por el
camino corriente de TLS, que copia el texto en claro al sellarlo; los rellenos
siguientes no copian.

Al reanudar una conexion de HTTP/1.1 retenida, el fragmento llama al servicio
aunque el no guarde nada de ella, y TLS entrega al de dentro siempre que tenga
texto en claro: las peticiones que esperaron detras ya estan descifradas en su
buffer, y si no, esperarian a que el otro extremo dijera algo nuevo.

## 8. Memoria

- Una respuesta abierta ocupa su entrada de la tabla de respuestas abiertas
  del fragmento y lo que su version ya guarda por flujo.  **Ningun buffer
  mientras calla** (R34): el buffer de salida se coge del pozo para rellenar y
  vuelve al acabar el envio.
- Un aviso no reserva nada (6.2).
- Los topes -- respuestas abiertas por fragmento y por conexion -- se fijan al
  construir el fragmento y se comprueban al abrir.
- Una respuesta que no se abre no toca nada de esto (R39): la tabla, la pila y
  el despertar solo se usan desde `open`.

## 9. Consideraciones de seguridad

- **Un cliente que no lee** no hace crecer nada: sin sitio no se llama a
  `fill`, y lo retenido es lo que ya admite el transporte.
- **Muchas respuestas abiertas** estan acotadas por fragmento y por conexion,
  y el tope agotado se contesta, no se calla.
- **Una rafaga de avisos** cuesta, como mucho, una entrada por fuente y un
  despertar por vez que el fragmento se durmio.
- **Un extremo muerto** acaba en el plazo de inactividad (5).

## 10. Lo que se observa

Nada de esto se calla.  Cada fragmento cuenta, por separado: respuestas
abiertas y rechazadas al abrir, avisos, avisos que ya estaban en la cola,
despertares hechos, llamadas a `fill` y bytes producidos, y `gone` por motivo.

## 11. Lo que no cubre

- **El cuerpo de la PETICION a trozos**: el manejador lo recibe entero.
  Recibirlo a trozos es la otra direccion, y otro diseno.
- **Mensajes entre fragmentos**: un fragmento que avise a otro usa el mismo
  `kick`; un canal propio entre fragmentos (colas por pareja, `MSG_RING`) es
  una mejora que no cambia este contrato.
- **Trailers al final de una respuesta abierta**: `done` acaba sin ellos.
- **R21** (una conexion que deja de ser peticion y respuesta: `CONNECT`,
  WebSocket) es otro requisito, aunque reutiliza la fuente y el aviso.

## 12. Como se prueba

- **Sin red**, con el backend de memoria: abrir, rellenar a trozos, `done`,
  cada motivo de `gone`, el borde de 4.3, los topes, y las peticiones que
  esperan detras en HTTP/1.1.
- **Contra cada version**: los mismos casos en HTTP/1.1, HTTP/2 y HTTP/3,
  y con TLS.
- **Entre hilos**: varios productores avisando a la vez a muchas fuentes, y la
  prueba de que ningun aviso se pierde -- cada aviso seguido, antes de un
  plazo, de un `fill`.  Bajo ThreadSanitizer ademas de AddressSanitizer: los
  errores de orden de memoria no revientan, dan una respuesta que no sale.
- **Contra clientes ajenos**: un flujo SSE a curl (`-N`) y a aioquic, en cada
  backend.
- **Mutantes**: quitar la vuelta a mirar la pila de 6.3, limpiar la marca
  despues de `fill`, o ofrecer sitio sin descontar el enmarcado tiene que poner
  alguna prueba en rojo.
