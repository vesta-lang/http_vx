# http_vx -- Arquitectura

    Documento:  HVX-1
    Estado:     BORRADOR
    Fecha:      2026-09-23
    Sustituye:  --
    Ver tambien: HVX-2 (seguridad), HVX-3 (el contrato publico)

## Resumen

`http_vx` es un servidor HTTP/1.1 pensado para sostener del orden de un millon
de conexiones concurrentes en una maquina, con la parte expuesta a la red
escrita de forma que pueda probarse y fuzzearse sin abrir un socket.

Este documento fija **donde se corta el proyecto y por que**.  No describe la
API -- eso es HVX-3 -- ni las amenazas concretas -- eso es HVX-2.

El proyecto nace para dar transporte al servidor MCP del compilador de Vesta,
pero no depende de el: el bucle de eventos y el analizador sirven a cualquier
otro consumidor, y esa independencia es una restriccion del diseno, no una
consecuencia agradable.

## 1. Terminologia

Las palabras **DEBE**, **NO DEBE**, **DEBERIA**, **NO DEBERIA** y **PUEDE** se
usan con el sentido del RFC 2119.  Cuando aparecen en mayusculas son
normativas; en minusculas son prosa corriente.

Ademas, en este documento:

- **Reactor**: el bucle que espera a que el sistema operativo termine
  operaciones y las entrega.
- **Fragmento** (*shard*): un reactor con su hilo, sus conexiones y su memoria.
  Una conexion pertenece a un fragmento desde que se acepta hasta que muere.
- **Conexion ociosa**: la que tiene la sesion abierta y ninguna peticion en
  curso.
- **Peticion en vuelo**: desde que llega el primer byte de la linea de peticion
  hasta que se escribe el ultimo de la respuesta.

## 2. Los dos costes

Un servidor de esta escala tiene **dos** problemas, y confundirlos lleva a
optimizar el que no es:

| | que se agota | se mide en |
| :-- | :-- | :-- |
| **coste residente** | memoria, por conexion ABIERTA | bytes x conexiones |
| **coste por peticion** | trabajo, por peticion ATENDIDA | llamadas al sistema, copias y ciclos |

El primero decide **cuantas** conexiones caben.  El segundo decide **cuantas
peticiones por segundo** se atienden.  Un servidor puede sostener un millon de
sesiones ociosas y hundirse con diez mil peticiones, o al reves.

Las secciones 3 y 4 los tratan por separado porque tienen soluciones
distintas.

## 3. El coste residente

    1 000 000 conexiones x 8 KiB de buffer  =  8 GiB
    1 000 000 conexiones x 128 B de estado  =  128 MiB

De ahi sale el requisito del que cuelgan los demas de esta seccion:

> **R1. Una conexion ociosa NO DEBE tener buffer de lectura ni de escritura
> asignado.**

Los buffers se piden prestados a un pozo cuando hay bytes en vuelo y se
devuelven al terminar la peticion.  Una sesion abierta sin trafico DEBE costar
solo su estado.

- **R2.** El estado por conexion DEBE ser de tamano fijo y vivir en memoria
  contigua indexada, no en un objeto reservado por conexion.
- **R3.** Los plazos DEBEN ser O(1) al alta y al vencimiento.  Un monticulo con
  un millon de entradas no sirve, y un temporizador por conexion tampoco.
- **R4.** Una conexion NO DEBE cambiar de fragmento en toda su vida.  Es lo que
  permite que el camino caliente no tome un solo cerrojo.
- **R5.** Aceptar DEBE repartirse entre fragmentos.  Un unico hilo aceptando es
  un cuello antes de llegar a cien mil.

> **R17. El estado por conexion DEBE separar lo CALIENTE de lo FRIO.**

Lo que el reactor toca en cada vuelta -- estado de la maquina, indice del
buffer prestado, plazo -- va en un array denso; lo que solo se mira al
diagnosticar o al cerrar -- direccion del par, marcas de tiempo, contadores --
va en otro.  Con un millon de conexiones, mezclarlos multiplica por diez los
fallos de cache del bucle sin anadir una sola instruccion.

## 4. El coste por peticion

La escala no sirve de nada si atender una peticion cuesta cuatro llamadas al
sistema y tres copias del cuerpo.  El objetivo declarado:

> **R15. Una peticion sencilla DEBERIA costar una lectura y una escritura.**

Y lo que hace falta para acercarse:

- **R12.** El analizador DEBE recorrer cada byte UNA vez, sin retroceso y sin
  estados que reanalicen lo ya visto.  Un analizador que vuelve atras al
  encontrar una cabecera partida entre dos lecturas es cuadratico ante una
  entrada elegida para provocarlo, y eso ademas es un vector de agotamiento.
- **R13.** El cuerpo NO DEBE copiarse.  Al manejador se le entrega una vista
  sobre el buffer de la conexion.  Copiar un cuerpo de 1 MiB para pasarlo a
  quien solo va a leerlo es trabajo que nadie pidio.
- **R14.** Una respuesta DEBE poder escribirse con una sola operacion de
  escritura DISPERSA -- cabeceras y cuerpo desde sitios distintos --, sin
  concatenar antes en un buffer intermedio.  Concatenar es una copia y una
  reserva por respuesta.
- **R16.** Con reutilizacion de conexion, las peticiones que ya esten en el
  buffer DEBEN analizarse sin volver a leer del socket.
- **R18.** Las operaciones DEBEN agruparse en las llamadas al sistema que lo
  permitan: io_uring envia muchas en una sola, e IOCP retira muchas
  terminaciones de una vez.  A un millon de conexiones, una llamada por
  operacion es el techo antes que cualquier otra cosa.

Las respuestas fijas -- `404`, `503`, `100 Continue` -- DEBERIAN estar
preserializadas: no hay nada que formatear en ellas y se envian mucho.

## 5. El corte

    http_vx/
      include/   el contrato publico
      core/      slab, rueda de tiempos, pozo de buffers
      proto/     HTTP/1.1: analizador y maquina de conexion
      reactor/   la interfaz por finalizacion
      windows/   IOCP
      linux/     io_uring y epoll
      tests/     sobre core/ y proto/
      fuzz/      el analizador
      bench/     con medidas fechadas por maquina

### 5.1 La regla que lo sostiene

> **R6. `core/` y `proto/` NO DEBEN incluir ninguna cabecera del sistema
> operativo.**

No es purismo.  El analizador de HTTP es **la superficie no confiable del
proyecto**: es el codigo al que un desconocido le da bytes.  Si para
ejercitarlo hace falta abrir un socket, entonces se prueba poco, se fuzzea
menos y se cubren los caminos faciles.  Sin cabeceras del sistema, se le dan
bytes desde un `tests/` corriente y bytes torcidos desde `fuzz/`, en la misma
maquina y sin permisos especiales.

Es la misma regla que sostiene `common/` en `vesta_prof`, y por el mismo motivo.

### 5.2 Por que el reactor va aparte del HTTP

Porque son dos cosas con vidas distintas.  Un bucle de eventos por finalizacion
es util sin HTTP, y HTTP es util sin ese bucle concreto: el analizador funciona
sobre cualquier cosa que le entregue bytes.

`reactor/` NO DEBE incluir nada de `proto/`.

## 6. El modelo de entrada y salida

### 6.1 Por finalizacion, no por disponibilidad

| | pregunta | ejemplos |
| :-- | :-- | :-- |
| disponibilidad | "avisame cuando se pueda leer" | epoll, kqueue |
| finalizacion | "lee esto y avisame cuando este" | IOCP, io_uring |

> **R7. La interfaz de `reactor/` DEBE ser por finalizacion.**

Windows solo ofrece finalizacion de verdad (IOCP) y Linux ofrece las dos.
Eligiendo finalizacion arriba, IOCP e io_uring son traducciones finas de la
misma idea y solo epoll necesita adaptacion.  Al reves habria que emular IOCP
sobre una interfaz que no lo es, y esa emulacion es donde viven los errores que
no se reproducen.

### 6.2 epoll no es un respaldo

> **R8. `linux/` DEBE ofrecer io_uring y epoll como backends de PRIMERA, y el
> backend DEBE poder elegirse en configuracion.**

io_uring es lo que hace que haya un solo modelo, y es tambien una superficie de
ataque del nucleo con historial de vulnerabilidades serias; hay distribuciones
que lo desactivan por politica.  Un servidor expuesto DEBE poder correr sin el
sin perder funcionalidad.  Tratar epoll como "el respaldo" acaba en un camino
que nadie prueba hasta que hace falta, que es cuando no se puede depurar.

### 6.3 Fragmentos

> **R9. Cada fragmento DEBE reservar de su propio hilo.**

`vesta_alloc` mantiene listas libres por hilo, asi que con R4 y R9 juntas el
camino caliente no comparte memoria con nadie y no toma cerrojos.  Esa es la
razon de que R4 no sea negociable: en cuanto una conexion pudiera migrar,
haria falta sincronizacion en el sitio donde menos cabe.

El reparto de `accept` se hace con `SO_REUSEPORT` en Linux -- el nucleo reparte
entre fragmentos, mas barato y mas justo que hacerlo en espacio de usuario -- y
con varias operaciones de aceptacion pendientes por escucha en Windows.

## 7. Los metodos

> **R19. El analizador DEBE aceptar cualquier token de metodo sin
> interpretarlo.  La semantica es del servidor, no del analizador.**

Asi un metodo nuevo, o uno propio de un consumidor, no obliga a tocar el codigo
que mira bytes de la red.

Lo que si es del transporte, porque cambia como se lee o se escribe:

| metodo | lo que impone |
| :-- | :-- |
| `GET`, `DELETE` | nada especial |
| `HEAD` | misma respuesta que `GET` pero sin cuerpo, **con el mismo `Content-Length`**.  El manejador DEBE poder saberlo ANTES de generar el cuerpo: generarlo para tirarlo es pagar entero por nada |
| `POST`, `PUT`, `PATCH` | cuerpo: limites, `Expect: 100-continue` y `chunked` |
| `OPTIONS` | capacidades; puede responderse sin llegar al manejador |
| `CONNECT` | tunel: la conexion **deja de ser peticion/respuesta** y pasa a ser un flujo en dos sentidos |
| `TRACE` | refleja la peticion, que es el ataque XST.  DEBE estar desactivado por defecto |

## 8. Lo que va POR ENCIMA de HTTP

Aqui hay una confusion que conviene deshacer antes de prometer nada: la mitad
de lo que suele pedirse **no es transporte**, y este proyecto no tiene que
hacer nada para soportarlo.

| | que es de verdad | toca a `http_vx`? |
| :-- | :-- | :-- |
| **GraphQL** | un `POST` con JSON a un unico punto | **No.**  Es capa de aplicacion; funciona ya |
| **SOAP** | un `POST` con XML y una cabecera `SOAPAction` | **No.**  Igual, y ademas heredado |
| **JSON-RPC / MCP** | un `POST` con JSON, y flujo de vuelta | Solo el flujo: ver SSE |
| **SSE** | una respuesta que no termina, con eventos | **Si**, y hace falta: MCP lo usa |
| **WebSocket** | negociacion de cambio de protocolo + trama propia | **Si**, y es el candidato real |
| **gRPC** | HTTP/2 + protobuf + *trailers* | **Si, y por eso no**: exige HTTP/2 |

De esa tabla salen tres decisiones:

> **R20. `proto/` DEBE soportar respuestas de longitud indefinida con envio
> incremental (SSE).**  Sin eso MCP no funciona, y es ademas lo que necesita
> cualquier panel que informe en vivo.

> **R21. WebSocket NO se implementa ahora, pero la maquina de conexion DEBERIA
> admitir que una conexion deje de ser peticion/respuesta.**  Es el mismo
> cambio de modelo que exige `CONNECT`, asi que sale casi gratis si se tiene en
> cuenta al disenar; y muy caro si no.

**gRPC queda fuera mientras no haya HTTP/2**, y conviene decirlo asi de claro
en vez de dejarlo como intencion: gRPC no es "HTTP con protobuf", usa tramas,
multiplexado y *trailers* de HTTP/2.  Lo que si podria hacerse sobre 1.1 es
gRPC-Web, que es otro protocolo con el mismo nombre comercial.

**GraphQL y SOAP no necesitan nada.**  Quien los quiera los escribe encima, y
`http_vx` ya le da lo que hace falta: un `POST` con su cuerpo y una respuesta.
Anunciar que "se soportan" seria un error de categoria.

## 9. La memoria

`http_vx` NO trae asignador propio.  Usa `vesta_alloc`:

| pieza | aqui sirve para |
| :-- | :-- |
| listas libres por hilo | R9: cada fragmento sin contencion |
| arena de fase (`scratch_arena`) | **una peticion es una fase** |
| vector con posiciones dentro (`small_vector`) | las cabeceras: casi siempre diminutas, a veces no |
| etiqueta de proposito (`alloc_tag`) | declarar que algo vive poco y no crece |

La arena cambia el orden de magnitud: medida en su proyecto, reservar cuesta
1,95 ns frente a 10,03 del asignador general.  Una peticion encaja en el caso
exacto que describe -- todo lo que nace atendiendola muere al responder --.

> **R10. La memoria de una peticion DEBE salir de una arena de fase, y liberarse
> reiniciando la arena.**

## 10. Lo que no se hace, y por que

**HTTP/2.**  Exige HPACK, tramas y control de flujo, y a cambio da multiplexado
sobre una conexion.  Para los consumidores previstos, HTTP/1.1 con
reutilizacion da lo mismo con una fraccion del codigo y de la superficie de
ataque.  No se descarta para siempre; se descarta ahora, y la interfaz de
`proto/` DEBERIA dejar sitio para otra version sin rehacerse.  Su ausencia
arrastra la de gRPC (seccion 8).

**Una biblioteca de terceros.**  Este ecosistema tiene enlazador, ensamblador,
asignador y perfilador propios.  Y las bibliotecas HTTP serias traen mucho mas
de lo que aqui se necesita, con su superficie de ataque y su ciclo de
publicacion.

**Criptografia propia.**  Ni propia ni ajena: ver la seccion 11.

## 11. TLS es un SERVICIO que alguien PROVEE

> **R22. `http_vx` NO DEBE enlazar ninguna biblioteca de TLS.**

No trae criptografia propia -- seria una mala idea -- ni ajena.  Define la
interfaz del transporte cifrado y ya esta; el proveedor lo pone quien construye.

Es el mismo modelo de ganchos que usa el lenguaje de este ecosistema para el
asignador, el panico o el desenrollado: **el servicio lo provee el programador,
una biblioteca o el SISTEMA OPERATIVO**, y quien lo consume solo conoce la
interfaz.

Tres consecuencias, y ninguna es teorica:

1. **`http_vx` queda sin una sola dependencia con licencia.**  Quien lo enlace
   resuelve su propio problema: el compilador con lo que ya use, un tercero con
   lo que quiera.  Sin esto, la licencia del proveedor se contagiaria a un
   proyecto que se distribuye bajo MIT justamente para que se lo lleve
   cualquiera.
2. **El sistema operativo ES un proveedor valido**, y en Windows es el natural:
   Schannel hace negociacion y registros sin traer nada de fuera.
3. **Para lo que hay delante no hace falta ninguno.**  El servidor MCP habla por
   loopback.  La decision del proveedor se aplaza sin bloquear nada.

### 11.1 Los proveedores no tienen todos la misma forma

Esta es la parte que hay que acertar en la interfaz, porque hay dos familias y
no se parecen:

| forma | que hace | ejemplos |
| :-- | :-- | :-- |
| **transforma bytes** | se le dan bytes cifrados y devuelve claros, y al reves | mbedTLS, OpenSSL, Schannel |
| **no transforma nada** | tras la negociacion, el nucleo cifra bajo el socket | kTLS de Linux |

> **R23. La interfaz DEBE admitir las dos formas, y el servidor DEBE PREGUNTAR
> cual es en vez de suponerlo.**

Con la segunda, el camino de lectura y escritura **no cambia**: no hay copia
extra, no hay buffer intermedio, y las operaciones dispersas de R14 siguen
valiendo.  Ahi esta justo la ventaja, y se pierde entera si la interfaz obliga a
pasar por una transformacion que en ese caso no existe.

### 11.2 Sin proveedor no se degrada

> **R24. Si se pide transporte cifrado y no hay proveedor, DEBE fallar
> DICIENDOLO -- al construir o al arrancar --.  NO DEBE caer a texto claro.**

Un servidor que pide TLS, no lo encuentra y sigue sirviendo sin cifrar no falla:
funciona, y eso es lo peligroso.  Es el mismo criterio que el resto del
ecosistema aplica a los ganchos que no tienen proveedor.

## 12. Consideraciones de seguridad

El detalle esta en HVX-2.  Lo que fija este documento:

- **La entrada de red no es confiable, y el analizador es quien la toca.**  De
  ahi R6.
- **Nada se reserva por lo que diga el que llama.**  Un `Content-Length`
  enorme DEBE rechazarse antes de reservar nada, no despues de intentarlo.
- **El contrabando de peticiones no es un caso raro.**  Una peticion con
  `Content-Length` y `Transfer-Encoding` a la vez DEBE rechazarse; interpretarla
  es como dos servidores de la misma cadena acaban viendo peticiones distintas.
- **Agotar por lentitud es agotar igual.**  Cada fase -- linea de peticion,
  cabeceras, cuerpo, inactividad -- DEBE tener su plazo, y de ahi R3.
- **Un analizador que retrocede es un ataque.**  R12 no es solo rendimiento.
- **`TRACE` desactivado por defecto** (seccion 7).
- **Quedarse sin recursos DEBE decirse.**  Con la cola llena se responde 503 y
  se sigue; lo que no se hace es aceptar trabajo que no se puede atender.

## 13. Observabilidad

> **R11. Cada fragmento DEBE poder informar, por conexion y por peticion, del
> tiempo EN COLA separado del tiempo DE TRABAJO.**

Sin esa separacion no se distingue "el consumidor es lento" de "el servidor
esta saturado", que son dos problemas con dos arreglos opuestos.

Las palancas van en la tabla de banderas del proyecto que lo incruste, no
repartidas por el codigo: una bandera que no esta en una tabla no se puede
listar y acaba siendo folclore.

## 14. Lo que este documento NO lleva

Este documento fija requisitos, cortes y el porque de cada uno.  **No lleva el
estado del proyecto** -- que esta hecho, que falta, que se probo, contra que se
interopero --: un documento que lo lleva envejece en cada cambio y sigue
leyendose como autoridad cuando ya miente.  Lo que hace cada pieza lo dice su
codigo y la documentacion de su cabecera; lo que se hizo y por que, el
historial de git.

Se corrige cuando el codigo demuestra que un corte estaba mal, no al reves.
