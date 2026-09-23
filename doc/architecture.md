# http_vx -- Arquitectura

    Documento:  HVX-1
    Estado:     BORRADOR
    Fecha:      2026-09-23
    Sustituye:  --
    Ver tambien: HVX-2 (seguridad), HVX-3 (el contrato publico)

## Resumen

`http_vx` es un servidor HTTP para sostener del orden de un millon de
conexiones concurrentes en una maquina, con **las tres versiones del protocolo
-- HTTP/1.1, HTTP/2 y HTTP/3 --** y con la parte expuesta a la red escrita de
forma que pueda probarse y fuzzearse sin abrir un socket.

Este documento fija **donde se corta el proyecto y por que**.  No describe la
API -- eso es HVX-3 -- ni las amenazas concretas -- eso es HVX-2.

El proyecto no depende del compilador de Vesta.  Dar transporte a su servidor
MCP es el destino, no el alcance: un servidor que solo sirviera para eso no
necesitaria ni tres versiones ni un millon de conexiones, y en cuanto se
disenara para ese caso dejaria de servir para lo demas.

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
- **Peticion en vuelo**: desde el primer byte de la peticion hasta el ultimo de
  la respuesta.
- **Semantica**: lo que una peticion SIGNIFICA -- metodo, cabeceras, estado,
  cuerpo --, que es lo mismo en las tres versiones.
- **Codec**: la traduccion entre esa semantica y los bytes de una version
  concreta.

## 2. Las tres versiones

Desde 2022 las especificaciones estan partidas a proposito, y ese reparto es la
forma del proyecto:

| | define |
| :-- | :-- |
| RFC 9110 | la **semantica**: metodos, cabeceras, codigos de estado, cuerpos |
| RFC 9112 | HTTP/1.1 -- sintaxis de texto |
| RFC 9113 | HTTP/2 -- tramas binarias, multiplexado, HPACK |
| RFC 9114 | HTTP/3 -- tramas y QPACK, sobre QUIC |

La semantica es **la misma en las tres**.  Un `GET` con sus cabeceras y su
`404` son identicos; lo que cambia es como se escriben los bytes.

> **R25. `proto/` DEBE separar la SEMANTICA de la SINTAXIS DEL CABLE.  Una
> version es un codec sobre la semantica comun, no otro servidor.**

> **R30. Un manejador NO DEBE necesitar saber por que version llego la
> peticion.**  Lo que no exista en una version -- el multiplexado en 1.1, por
> ejemplo -- se resuelve en el codec, no se filtra hacia arriba.

> **R29. Cada version DEBE poder desactivarse al construir.**  Quien solo
> quiera 1.1 no DEBE arrastrar QUIC ni su superficie de ataque.

Las referencias de RFC de esta seccion se citan de memoria y DEBEN contrastarse
contra los documentos reales al escribir la seccion de referencias.

## 3. Los dos costes

Un servidor de esta escala tiene **dos** problemas, y confundirlos lleva a
optimizar el que no es:

| | que se agota | se mide en |
| :-- | :-- | :-- |
| **coste residente** | memoria, por conexion ABIERTA | bytes x conexiones |
| **coste por peticion** | trabajo, por peticion ATENDIDA | llamadas al sistema, copias y ciclos |

El primero decide **cuantas** conexiones caben.  El segundo decide **cuantas
peticiones por segundo** se atienden.  Un servidor puede sostener un millon de
sesiones ociosas y hundirse con diez mil peticiones, o al reves.

### 3.1 El coste residente

    1 000 000 conexiones x 8 KiB de buffer  =  8 GiB
    1 000 000 conexiones x 128 B de estado  =  128 MiB

> **R1. Una conexion ociosa NO DEBE tener buffer de lectura ni de escritura
> asignado.**

Los buffers se piden prestados a un pozo cuando hay bytes en vuelo y se
devuelven al terminar la peticion.

- **R2.** El estado por conexion DEBE ser de tamano fijo y vivir en memoria
  contigua indexada, no en un objeto reservado por conexion.
- **R3.** Los plazos DEBEN ser O(1) al alta y al vencimiento.
- **R4.** Una conexion NO DEBE cambiar de fragmento en toda su vida.
- **R5.** Aceptar DEBE repartirse entre fragmentos.
- **R17.** El estado por conexion DEBE separar lo CALIENTE de lo FRIO.  Lo que
  el reactor toca cada vuelta va en un array denso; lo que solo se mira al
  diagnosticar, en otro.  Con un millon de conexiones, mezclarlos multiplica
  los fallos de cache sin anadir una instruccion.

En HTTP/2 y HTTP/3 el estado no es solo por conexion sino **por flujo**, y una
conexion puede tener cientos abiertos.  R1 y R2 se aplican igual al flujo: un
flujo sin datos en vuelo NO DEBE tener buffer.

### 3.2 El coste por peticion

> **R15. Una peticion sencilla DEBERIA costar una lectura y una escritura.**

- **R12.** El analizador DEBE recorrer cada byte UNA vez, sin retroceso.  Uno
  que vuelve atras al encontrar una cabecera partida entre dos lecturas es
  cuadratico ante una entrada elegida para provocarlo: no es solo lentitud, es
  un vector de agotamiento.
- **R13.** El cuerpo NO DEBE copiarse.  Al manejador se le entrega una vista.
- **R14.** Una respuesta DEBE poder escribirse con una sola operacion DISPERSA
  -- cabeceras y cuerpo desde sitios distintos --, sin concatenar antes.
- **R16.** Con reutilizacion de conexion, lo que ya este en el buffer DEBE
  analizarse sin volver a leer del socket.
- **R18.** Las operaciones DEBEN agruparse en las llamadas que lo permitan.  A
  un millon de conexiones, una llamada por operacion es el techo antes que
  cualquier otra cosa.

Las respuestas fijas -- `404`, `503`, `100 Continue` -- DEBERIAN estar
preserializadas.

## 4. El corte

    http_vx/
      include/     el contrato publico
      core/        slab, rueda de tiempos, pozo de buffers
      proto/
        semantics/ RFC 9110: lo que una peticion significa.  Comun
        h1/        RFC 9112: texto
        h2/        RFC 9113: tramas + HPACK
        h3/        RFC 9114: tramas + QPACK
      quic/        paquetes, perdida, congestion, flujo, migracion
      reactor/     la interfaz por finalizacion
      windows/     IOCP
      linux/       io_uring y epoll
      tests/       sobre core/ y proto/
      fuzz/        los codecs y la pila QUIC
      bench/       con medidas fechadas por maquina

### 4.1 La regla que lo sostiene

> **R6. `core/` y `proto/` NO DEBEN incluir ninguna cabecera del sistema
> operativo.**

No es purismo.  Los codecs son **la superficie no confiable del proyecto**: el
codigo al que un desconocido le da bytes.  Si para ejercitarlos hiciera falta
abrir un socket, se probarian poco y se fuzzearian menos.  Sin cabeceras del
sistema se les dan bytes desde un `tests/` corriente y bytes torcidos desde
`fuzz/`, en la misma maquina y sin permisos.

Es la misma regla que sostiene `common/` en `vesta_prof`.

### 4.2 QUIC es un TRANSPORTE, no parte de HTTP

> **R27. `quic/` va al lado de `reactor/`, no debajo de `proto/`.  `proto/h3`
> NO DEBE conocer paquetes, perdida ni congestion.**

QUIC esta al nivel de TCP: entrega flujos fiables y ordenados.  Que naciera
para HTTP/3 no lo hace parte de HTTP, y meterlo ahi impediria usarlo para otra
cosa -- que es justo lo contrario de para que existe este proyecto.

### 4.3 Por que el reactor va aparte

`reactor/` NO DEBE incluir nada de `proto/` ni de `quic/`.  Un bucle de eventos
por finalizacion vale sin HTTP, y los codecs valen sobre cualquier cosa que
entregue bytes.

## 5. El modelo de entrada y salida

### 5.1 Por finalizacion, no por disponibilidad

| | pregunta | ejemplos |
| :-- | :-- | :-- |
| disponibilidad | "avisame cuando se pueda leer" | epoll, kqueue |
| finalizacion | "lee esto y avisame cuando este" | IOCP, io_uring |

> **R7. La interfaz de `reactor/` DEBE ser por finalizacion.**

Windows solo ofrece finalizacion de verdad y Linux ofrece las dos.  Eligiendo
finalizacion arriba, IOCP e io_uring son traducciones finas de la misma idea y
solo epoll necesita adaptacion.  Al reves habria que emular IOCP sobre una
interfaz que no lo es, y esa emulacion es donde viven los errores que no se
reproducen.

### 5.2 Datagramas, y por lotes

> **R26. El reactor DEBE cubrir DATAGRAMAS ademas de flujos, y DEBE poder
> enviarlos y recibirlos POR LOTES.**

QUIC va sobre UDP.  Una llamada al sistema por datagrama es el techo mucho
antes que el cifrado o el analisis, asi que hacen falta las operaciones
agrupadas de cada plataforma -- `sendmmsg`/`recvmmsg` y segmentacion en Linux,
recepcion multishot en io_uring, `WSARecvFrom` sobre IOCP --.

### 5.3 epoll no es un respaldo

> **R8. `linux/` DEBE ofrecer io_uring y epoll como backends de PRIMERA, y el
> backend DEBE poder elegirse en configuracion.**

io_uring es lo que hace que haya un solo modelo, y es tambien una superficie de
ataque del nucleo con historial de vulnerabilidades serias; hay distribuciones
que lo desactivan por politica.  Tratar epoll como "el respaldo" acaba en un
camino que nadie prueba hasta que hace falta, que es cuando no se puede
depurar.

### 5.4 Fragmentos

> **R9. Cada fragmento DEBE reservar de su propio hilo.**

`vesta_alloc` mantiene listas libres por hilo, asi que con R4 y R9 juntas el
camino caliente no comparte memoria con nadie y no toma cerrojos.  Esa es la
razon de que R4 no sea negociable.

El reparto de `accept` se hace con `SO_REUSEPORT` en Linux y con varias
operaciones de aceptacion pendientes por escucha en Windows.  Con QUIC no hay
`accept`: el reparto se hace por identificador de conexion, y DEBE elegirse de
forma que una conexion caiga siempre en el mismo fragmento aunque el cliente
cambie de direccion (migracion).

## 6. Los metodos

> **R19. El analizador DEBE aceptar cualquier token de metodo sin
> interpretarlo.  La semantica es del servidor, no del analizador.**

Lo que si es del transporte, porque cambia como se lee o se escribe:

| metodo | lo que impone |
| :-- | :-- |
| `GET`, `DELETE` | nada especial |
| `HEAD` | misma respuesta que `GET` sin cuerpo, **con el mismo `Content-Length`**.  El manejador DEBE poder saberlo ANTES de generar el cuerpo |
| `POST`, `PUT`, `PATCH` | cuerpo: limites, `Expect: 100-continue` y troceado |
| `OPTIONS` | capacidades; puede responderse sin llegar al manejador |
| `CONNECT` | tunel: deja de ser peticion/respuesta.  En h2 y h3 ademas existe la variante extendida, que es como viaja WebSocket |
| `TRACE` | refleja la peticion, que es el ataque XST.  DEBE estar desactivado por defecto |

## 7. Lo que va POR ENCIMA

Conviene deshacer una confusion antes de prometer nada: la mitad de lo que
suele pedirse **no es transporte**.

| | que es de verdad | toca a `http_vx`? |
| :-- | :-- | :-- |
| **GraphQL** | un `POST` con JSON a un unico punto | **No.**  Capa de aplicacion; funciona ya |
| **SOAP** | un `POST` con XML y una cabecera | **No.**  Igual, y heredado |
| **JSON-RPC / MCP** | un `POST` con JSON, y flujo de vuelta | solo el flujo: ver SSE |
| **SSE** | una respuesta que no termina | **Si** |
| **WebSocket** | cambio de protocolo + trama propia | **Si**, y en h2/h3 viaja sobre `CONNECT` extendido |
| **gRPC** | HTTP/2 + protobuf + *trailers* | **Si**, y con h2 en el alcance pasa a ser posible |

> **R20. Los codecs DEBEN soportar respuestas de longitud indefinida con envio
> incremental (SSE).**

> **R21. La maquina de conexion DEBE admitir que una conexion deje de ser
> peticion/respuesta** -- lo exigen `CONNECT` y WebSocket --.

**GraphQL y SOAP no necesitan nada.**  Quien los quiera los escribe encima.
Anunciar que "se soportan" seria un error de categoria.

## 8. La memoria

`http_vx` NO trae asignador propio.  Usa `vesta_alloc`:

| pieza | aqui sirve para |
| :-- | :-- |
| listas libres por hilo | R9: cada fragmento sin contencion |
| arena de fase (`scratch_arena`) | **una peticion es una fase** |
| vector con posiciones dentro (`small_vector`) | las cabeceras: casi siempre diminutas, a veces no |
| etiqueta de proposito (`alloc_tag`) | declarar que algo vive poco y no crece |

> **R10. La memoria de una peticion DEBE salir de una arena de fase, y
> liberarse reiniciando la arena.**

Las tablas dinamicas de HPACK y QPACK son la excepcion: viven lo que la
conexion, no lo que la peticion, y tienen su propio tope negociado.

## 9. TLS es un SERVICIO que alguien PROVEE

> **R22. `http_vx` NO DEBE enlazar ninguna biblioteca de TLS.**

No trae criptografia propia -- seria una mala idea -- ni ajena.  Define la
interfaz y el proveedor lo pone quien construye.  Es el mismo modelo de ganchos
que usa el lenguaje de este ecosistema para el asignador o el panico: **lo
provee el programador, una biblioteca o el SISTEMA OPERATIVO**.

Con eso `http_vx` queda sin una sola dependencia con licencia, y el sistema
operativo es un proveedor valido -- en Windows, el natural.

### 9.1 Los proveedores tienen TRES formas

> **R23. La interfaz DEBE admitir las tres, y el servidor DEBE PREGUNTAR cual
> es en vez de suponerlo.**

| forma | que hace | ejemplos |
| :-- | :-- | :-- |
| transforma bytes | cifra y descifra un flujo | mbedTLS, OpenSSL, Schannel |
| no transforma nada | el nucleo cifra bajo el socket | kTLS |
| **solo negocia** | da los mensajes del handshake y las claves; la proteccion la hace quien llama | el interfaz QUIC de OpenSSL 3.2+, BoringSSL, picotls |

La tercera es la que permite HTTP/3 sin romper R22, y merece explicarse porque
parece una contradiccion: **QUIC no usa la capa de registros de TLS**.  Usa el
handshake -- transcripcion, agenda de claves y exportadores -- y protege los
paquetes el mismo.  Un proveedor para HTTP/3 tiene que saber hacer esa forma, y
eso reduce el conjunto de candidatos; es una consecuencia que hay que escribir,
no un obstaculo.

Con la segunda forma el camino de lectura y escritura **no cambia**: sin copia
extra y sin buffer intermedio, y R14 sigue valiendo.  Esa ventaja se pierde
entera si la interfaz obliga a pasar por una transformacion que ahi no existe.

### 9.2 Sin proveedor no se degrada

> **R24. Si se pide transporte cifrado y no hay proveedor, DEBE fallar
> DICIENDOLO -- al construir o al arrancar --.  NO DEBE caer a texto claro.**

Un servidor que pide TLS, no lo encuentra y sigue sirviendo sin cifrar no
falla: funciona, y eso es lo peligroso.

## 10. Como se sabe que funciona

Las pruebas propias bastan para `core/` y para la semantica.  Para los codecs
binarios y para QUIC, no:

> **R28. El criterio de aceptacion de HTTP/2, HTTP/3 y QUIC es la
> INTEROPERABILIDAD con otras implementaciones, no las pruebas propias.**

Una pila QUIC no se autocertifica.  Hay implementaciones maduras -- quiche,
msquic, ngtcp2, picoquic -- y una matriz publica de interoperabilidad entre
ellas; "funciona" significa aparecer ahi, no pasar los tests de casa.  Se dice
desde el principio porque descubrirlo al final es rehacer.

Y conviene no minimizarlo: esas pilas son decenas de miles de lineas con anos
de pruebas cruzadas.  QUIC es el trozo grande de este proyecto.

## 11. Lo que no se hace, y por que

**Una biblioteca de terceros para HTTP.**  Este ecosistema tiene enlazador,
ensamblador, asignador y perfilador propios.  Y las bibliotecas serias traen
mucho mas de lo que aqui se necesita, con su superficie de ataque y su ciclo de
publicacion.

**Criptografia propia.**  Ni propia ni ajena: seccion 9.

**HTTP/0.9 y HTTP/1.0.**  Se reconocen lo justo para responder un error claro.
Aceptarlos es superficie de ataque a cambio de nada.

## 12. Consideraciones de seguridad

El detalle esta en HVX-2.  Lo que fija este documento:

- **La entrada de red no es confiable, y los codecs son quienes la tocan.**  De
  ahi R6.
- **Nada se reserva por lo que diga el que llama.**  Un `Content-Length`
  enorme, una tabla de cabeceras enorme o un flujo que promete mas de lo que
  manda DEBEN rechazarse antes de reservar.
- **El contrabando de peticiones no es un caso raro.**  `Content-Length` y
  troceado a la vez DEBE rechazarse; interpretarlo es como dos servidores de la
  misma cadena acaban viendo peticiones distintas.  En h2 y h3 la variante es
  la discrepancia entre la longitud declarada y los datos del flujo.
- **Agotar por lentitud es agotar igual.**  Cada fase DEBE tener su plazo, y de
  ahi R3.  En h2 esto incluye la inundacion de tramas de control, que fue un
  ataque real y masivo.
- **Un analizador que retrocede es un ataque** (R12).
- **QUIC trae amenazas propias**: amplificacion antes de validar la direccion
  -- de ahi el limite de respuesta --, agotamiento por identificadores de
  conexion, validacion de camino al migrar, y repeticion en los datos de
  0-RTT, que por eso no son seguros para peticiones que cambian estado.
- **`TRACE` desactivado por defecto.**
- **Quedarse sin recursos DEBE decirse.**  Con la cola llena se responde 503 y
  se sigue.

## 13. Observabilidad

> **R11. Cada fragmento DEBE poder informar, por conexion y por peticion, del
> tiempo EN COLA separado del tiempo DE TRABAJO.**

Sin esa separacion no se distingue "el consumidor es lento" de "el servidor
esta saturado", que son dos problemas con arreglos opuestos.

Las palancas van en la tabla de banderas del proyecto que lo incruste, no
repartidas por el codigo: una bandera que no esta en una tabla no se puede
listar y acaba siendo folclore.

## 14. Orden de construccion

No es orden de prioridad de uso, sino de **cuando se puede comprobar que el
corte es correcto**:

1. **`core/`** y **`proto/semantics/`** -- el nucleo comun.
2. **`proto/h1/`** -- el codec mas simple.
3. **`proto/h2/`** -- y esto va tercero por una razon: **h1 solo no demuestra
   que la separacion sea correcta.**  Un codec de texto puede compartir
   estructura con la semantica por casualidad.  El primer formato binario, con
   tramas y compresion de cabeceras, es el que lo prueba; y si el corte esta
   mal, ahi se ve todavia barato.
4. **`reactor/`** y un backend.
5. **`quic/`** y **`proto/h3/`**, con interoperabilidad como criterio (R28).

## 15. Lo que este documento NO lleva

Este documento fija requisitos, cortes y el porque de cada uno.  **No lleva el
estado del proyecto** -- que esta hecho, que falta, que se probo, contra que se
interopero --: un documento que lo lleva envejece en cada cambio y sigue
leyendose como autoridad cuando ya miente.  Lo que hace cada pieza lo dice su
codigo y la documentacion de su cabecera; lo que se hizo y por que, el
historial de git.

Se corrige cuando el codigo demuestra que un corte estaba mal, no al reves.
