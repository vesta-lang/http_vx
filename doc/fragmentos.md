# http_vx -- Varios fragmentos

    Documento:  HVX-6
    Estado:     BORRADOR
    Fecha:      2026-09-27
    Sustituye:  --
    Ver tambien: HVX-1 (arquitectura: R4, R5, R9, R17, R26), HVX-5 (respuestas abiertas: la cola de avisos)

## Resumen

Un **fragmento** es un hilo con todo lo suyo: tabla de conexiones, pozo de
buffers, rueda de plazos, backend y cola de avisos.  Un servidor con un solo
fragmento usa un nucleo.  Este documento fija como se reparte el trabajo entre
varios sin que compartan nada mutable en el camino caliente: como llega cada
conexion TCP a un fragmento, como llega cada datagrama QUIC al fragmento que
tiene su conexion aunque el cliente cambie de direccion, como se hablan los
fragmentos cuando hace falta, y las pocas cosas que de verdad se comparten.

Las decisiones salen de leer el codigo del nucleo de Linux, de nginx, HAProxy,
Envoy, Seastar, glommio, H2O/quicly, Pingora, mvfst, msquic, quic-go, Google
QUICHE, libuv, Kestrel, y la documentacion de Microsoft, ademas de RFC 9000,
RFC 8446 y el borrador QUIC-LB.

## 1. Terminologia

Las palabras **DEBE**, **NO DEBE**, **DEBERIA** y **PUEDE** se usan con el
sentido del RFC 2119.

- **Fragmento**: un hilo y lo que posee (HVX-1, 5.4).
- **Buzon**: la cola por la que otros hilos le mandan trabajo a un fragmento.
- **Traspaso**: mandar a otro fragmento un socket aceptado o un datagrama que
  llego al fragmento que no era.
- **Propietario** de una conexion QUIC: el fragmento que tiene su estado.

## 2. Requisitos

> **R40. Nada mutable se comparte entre fragmentos en el camino de una
> peticion.**  Lo que se comparte es de solo lectura (claves, configuracion)
> o esta en la seccion 7, con su razon.

> **R41. Una conexion DEBE atenderse entera en su fragmento (R4), tambien
> una conexion QUIC cuyo cliente cambia de direccion (RFC 9000, 9).**

> **R42. Repartir no DEBE depender de que la aplicacion elija bien: el
> reparto sale del sistema operativo o del propio servidor, y se mide.**

> **R43. Un traspaso DEBE ser raro en el camino corriente y DEBE contarse.**
> Un datagrama que llega al fragmento que no era se traspasa, no se tira.

> **R44. Cada fragmento DEBE reservar su memoria desde su propio hilo (R9),
> despues de fijarse a su nucleo, para que la memoria caiga en su nodo.**

## 3. Arranque

- Se hace un fragmento por nucleo disponible, o los que diga la
  configuracion.  Cada uno corre en su hilo, fijado a un nucleo.
- Cada hilo construye y reinicia SU fragmento, su backend y sus servicios: la
  memoria se toca por primera vez en su nucleo (Linux coloca la pagina en el
  primer fallo; en Windows las tablas grandes se piden con
  `VirtualAllocExNuma` al nodo del nucleo).  El hilo principal no reserva
  nada de un fragmento.
- Un fragmento que no arranca hace que el servidor no arranque, y lo dice.

## 4. TCP: como llega cada conexion a un fragmento

### 4.1 Linux: un socket de escucha por fragmento

Cada fragmento abre su propio socket de escucha con `SO_REUSEPORT` en la
misma direccion.  El nucleo reparte cada conexion entrante por un hash de su
cuadrupla, y la conexion se acepta en el fragmento que la recibio: no hay
traspaso.  Es lo que hace glommio, lo que ofrecen nginx y HAProxy, y lo que
Envoy usa por defecto.

- Aceptar en varios anillos sobre UN socket compartido NO se usa: la
  aceptacion de io_uring despierta al primer anillo de la cola, y la
  aceptacion repetida (multishot) vacia la cola entera en el; `EPOLLEXCLUSIVE`
  despierta al primero que espera.  Las dos concentran la carga.
- Cerrar un socket de escucha aborta las conexiones que tuviera en cola
  salvo que `net.ipv4.tcp_migrate_req` este activo: el servidor lo comprueba
  al arrancar y avisa si no lo esta, porque parar un fragmento perderia
  conexiones.
- El hash no mira la carga.  Cada fragmento cuenta lo que acepta, y el
  desequilibrio se mide (R42) antes de anadir un reparto propio.

### 4.2 Windows: un aceptador que traspasa

Windows no reparte conexiones entre sockets de escucha: varios con
`SO_REUSEADDR` en el mismo puerto es "indeterminado", no un reparto, y un
socket pertenece a un solo puerto de finalizacion.  Lo que si permite es que
el socket ACEPTADO -- otro handle, creado sin puerto -- se asocie despues al
puerto que se quiera.  Es lo que hace msquic, y el modelo de Kestrel y libuv.

- Un fragmento hace de aceptador: tiene el socket de escucha en su puerto y
  mantiene varias `AcceptEx` pendientes, sin bytes de recepcion.
- Al acabar una, hace `SO_UPDATE_ACCEPT_CONTEXT`, elige el fragmento de
  destino y le traspasa el socket por su buzon (seccion 6).  El destino lo
  asocia a su puerto y lo adopta.  El socket no se asocia a ningun puerto
  antes de saber su destino.
- El destino se elige por **menos cargado de dos** candidatos que rotan
  (conexiones abiertas de cada uno), como HAProxy.
- El aceptador tambien sirve conexiones.  Cuantas acepta por segundo se
  mide: si fuera el techo, se aparta a un hilo propio.

## 5. QUIC: como llega cada datagrama al propietario

### 5.1 El reparto lo hace el sistema; el identificador nombra al propietario

- **Linux**: un socket UDP por fragmento con `SO_REUSEPORT`; el nucleo
  reparte por la cuadrupla.
- **Windows**: un socket UDP por procesador con `SIO_CPU_AFFINITY` (Windows
  10 2004 en adelante), como msquic: el RSS de la tarjeta reparte por la
  cuadrupla, y el procesador `i` va al fragmento `i mod N`.  Sin ese control
  (sistema mas viejo) se usa un solo socket en un fragmento y todo se
  traspasa, y se dice al arrancar.

En los dos, mientras la cuadrupla no cambia, todos los datagramas de una
conexion caen en el mismo fragmento: el que recibio su Initial, que pasa a ser
su propietario.  El traspaso es solo para lo que cambio de camino.

### 5.2 El identificador de conexion lleva al propietario, cifrado

Cada identificador que emite un fragmento (RFC 9000, 5.1) lleva el indice del
fragmento propietario, CIFRADO con una clave del servidor: RFC 9000 5.1 dice
que un identificador NO DEBE llevar informacion que permita correlacionarlo
con otros de la misma conexion, y un indice en claro lo haria (es lo que
hacen nginx y Envoy, y los dos lo exponen).  Es el esquema del borrador
QUIC-LB: el indice y un relleno aleatorio, cifrados con una clave de solo
lectura que comparten todos los fragmentos.

- Al llegar un datagrama con cabecera corta, el fragmento descifra el
  identificador; si el propietario es otro, lo traspasa (R43).
- Un Initial o un paquete 0-RTT con un identificador que no es nuestro se
  atiende donde cayo: esa conexion todavia no tiene propietario.  Un Initial
  repetido cuyo identificador ya lo emitio otro fragmento se traspasa, como
  hace mvfst.
- El nucleo no dirige por identificador (hace falta descifrar, y un programa
  BPF no puede): con la cuadrupla estable no hace falta, y tras una migracion
  el traspaso lo resuelve.  Se cuentan los traspasos por fragmento.
- Si un fragmento se para, el reparto de Linux cambia y todo lo que caia en el
  se traspasa hasta que acaba: sigue siendo correcto, solo mas caro.

### 5.3 Lo que se traspasa

El datagrama se COPIA en un mensaje del buzon: un buffer de un fragmento NO
DEBE liberarse en el pozo de otro.  El receptor lo procesa como recibido por
el con la direccion de origen que traia.  Lo que el propietario responde lo
manda por SU socket; el origen es la misma direccion y puerto, asi que el
cliente no ve diferencia.

## 6. El buzon entre fragmentos

- Uno por fragmento, con el mismo mecanismo que la cola de avisos de HVX-5:
  pila sin cerrojos de varios productores y un consumidor, un despertar solo
  si el fragmento duerme.  El trafico entre fragmentos es raro (sockets
  aceptados en Windows, datagramas de conexiones que migraron), y el coste
  que manda es el despertar, no la operacion atomica.
- Los mensajes salen de un pozo fijo del REMITENTE y vuelven a el cuando el
  destino acaba (como las liberaciones entre nucleos de Seastar): nada se
  reserva al mandar, y nada se libera en el pozo de otro.  Un pozo agotado
  rechaza el traspaso y lo cuenta.
- Tipos de mensaje: socket aceptado, datagrama traspasado, parar.

## 7. Lo que se comparte

| que | como | por que |
| :-- | :-- | :-- |
| configuracion, certificados, claves de tickets, de reinicio sin estado, de Retry, de identificadores | solo lectura desde el arranque | no cambian mientras sirven |
| el guardian de 0-RTT (`ReplayGuard`) | ver 7.1 | RFC 8446, 8: como mucho una vez POR INSTANCIA de servidor |
| el socket de escucha en Windows | solo lo usa el aceptador | 4.2 |
| el manejador de la aplicacion | ver 7.2 | es codigo de otro |

### 7.1 0-RTT

RFC 8446 (8) pide que unos datos tempranos se acepten como mucho una vez por
instancia de servidor.  Un guardian por fragmento lo romperia: un ClientHello
repetido que cayera en otro fragmento se aceptaria otra vez.  Hay dos formas
de cumplirlo:

- **Un guardian compartido**, con casillas que se toman con una operacion
  atomica (comparar e intercambiar): la unica estructura mutable compartida,
  tocada solo por los saludos que traen 0-RTT.
- **Un guardian por fragmento y el saludo al emisor**: el ticket lleva, dentro
  de su parte cifrada, el fragmento que lo emitio, y un ClientHello con 0-RTT
  se traspasa a ese fragmento.  Pero la conexion se queda alli mientras su
  cuadrupla cae en otro: cada datagrama suyo se traspasaria.

Se elige el guardian compartido.

### 7.2 El manejador

El manejador se llama desde el hilo de cada fragmento.  Se construye uno por
fragmento (el servidor recibe una fabrica), para que la aplicacion no tenga que
saber que hay hilos: si comparte algo entre sus instancias, lo protege ella,
como ya hace una fuente con quien la avisa (HVX-5, 4.2).

## 8. Lo que se observa

Por fragmento: conexiones aceptadas y traspasadas (entrantes y salientes),
datagramas traspasados y rechazados por pozo agotado, mensajes del buzon, y su
carga (conexiones abiertas).  El desequilibrio entre fragmentos se ve
comparandolos.

## 9. Lo que no cubre

- **Mover una conexion QUIC** al fragmento donde ahora llegan sus datagramas
  (lo que hace msquic): se traspasa en su lugar.  Si los traspasos medidos lo
  justificaran, es una mejora que no cambia este contrato.
- **Dirigir por identificador en el nucleo** con eBPF: exige identificadores
  en claro (5.2).
- **Reparto propio en Linux** encima de `SO_REUSEPORT`: solo si el
  desequilibrio medido lo pide (4.1).
- **Varios procesos** y relevo sin cortes entre versiones del servidor.

## 10. Como se prueba

- Sin red: dos fragmentos en hilos con el backend de memoria; un socket y un
  datagrama traspasados por el buzon llegan, se atienden y el mensaje vuelve
  a su pozo.
- Identificadores: el indice sale bien de un identificador cifrado para cada
  fragmento; dos identificadores de la misma conexion no comparten ningun
  byte fijo.
- Con sockets reales: muchas conexiones contra N fragmentos, repartidas; en
  Windows, todas traspasadas desde el aceptador.
- Migracion: un cliente que cambia de puerto a mitad de conexion sigue siendo
  atendido por su propietario, y el traspaso se cuenta.
- 0-RTT: un ClientHello repetido contra otro fragmento se rechaza.
- Clientes ajenos (curl, aioquic) contra N fragmentos, en cada backend.
