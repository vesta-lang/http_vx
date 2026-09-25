# http_vx -- Servir HTTP sin red

    Documento:  HVX-4
    Estado:     BORRADOR
    Fecha:      2026-09-25
    Sustituye:  --
    Ver tambien: HVX-1 (arquitectura), HVX-3 (el contrato publico)

## Resumen

Un servidor HTTP no necesita un socket.  Necesita **un par de flujos de bytes
que conserven el orden**, y eso lo es una tuberia, un socket de dominio Unix,
una tuberia con nombre de Windows, un par de descriptores heredados del proceso
padre, o dos ficheros.

Este documento fija **como se enchufa `http_vx` a un transporte que no es la
red, y como se sirve un recurso por el**.  No fija firmas: eso es HVX-3, y la
seccion 7 explica por que va aparte.

Lo que SI se puede dar por estable es lo de aqui, porque no son nombres de
funcion sino decisiones: donde estan las costuras, de quien es un buffer y
cuando, y que reglas no se pueden romper sin que la conexion se desincronice.

## 1. Terminologia

Las palabras **DEBE**, **NO DEBE**, **DEBERIA** y **PUEDE** se usan con el
sentido del RFC 2119.

Ademas:

- **transporte** -- lo que mueve los bytes.  Un socket, una tuberia, un par de
  descriptores, memoria.
- **backend** -- la pieza que convierte operaciones en llamadas al sistema y
  devuelve finalizaciones.  Es lo unico que sabe que transporte hay debajo.
- **servicio** -- la pieza que convierte bytes en mensajes y mensajes en bytes.
  Habla un protocolo y no sabe nada del transporte.
- **manejador** -- lo que contesta una peticion.  No sabe nada ni del
  transporte ni del protocolo.

## 2. Por que esto no es un apano

Es, con diferencia, el uso mas extendido de HTTP que no es una web:

- **Docker** -- el cliente habla HTTP/1.1 con el demonio por un socket de
  dominio Unix.  No hay ninguna red por medio.
- **gRPC es HTTP/2** -- literalmente: tramas, HPACK, flujos.  La mayor parte de
  su uso es servicio a servicio, mucho por bucle local o socket de dominio.
- **containerd y Kubernetes** -- el kubelet habla con el runtime por gRPC sobre
  socket de dominio.
- **MCP** -- su transporte, ademas de la entrada y salida estandar, es HTTP.

Y hay tres razones para elegirlo por encima de un protocolo propio:

1. **Porque la frontera puede moverse.**  Hoy el mismo proceso, manana otra
   maquina, sin reescribir nada.  Es la razon que mas veces acierta.
2. **Por las herramientas.**  `curl` contra tu IPC, un proxy en medio para ver
   el trafico, un cliente en cualquier lenguaje sin escribirlo.  Depurar un
   protocolo propio es escribir tambien sus herramientas.
3. **Porque la semantica ya esta decidida**: codigos de error, negociacion de
   contenido, cache, autenticacion.  No hay que inventarla ni discutirla.

Y una para no elegirlo: **si lo que hace falta es latencia de microsegundos**,
analizar cabeceras cuesta mas que copiar un struct, y memoria compartida con un
anillo gana por ordenes de magnitud.

### 2.1 Un detalle de seguridad que se salta casi todo el mundo

> **Un servidor local DEBERIA escuchar en un socket de dominio o una tuberia
> con nombre, NO en un puerto TCP de `127.0.0.1`.**

Un puerto en el bucle local es alcanzable por **cualquier** proceso de la
maquina sin credenciales y, peor, ha sido alcanzable desde navegadores por
reenlace de DNS -- hay una historia larga de ataques asi contra servicios
locales que daban por hecho que "localhost es privado".  Un socket de dominio
tiene dueno y permisos de fichero, que es control de acceso de verdad, y ademas
se salta la pila de red entera.

`http_vx` no elige por ti: eligiendo el transporte, eliges esto.

## 3. Donde estan las costuras

Tres, y cada una es una frontera de lo que se sabe:

```
    bytes del transporte
          |
       BACKEND        sabe que hay un socket, una tuberia o memoria
          |           no sabe que es HTTP
    operaciones y finalizaciones
          |
       SERVICIO       sabe que es HTTP, y cual version
          |           no sabe de donde salieron los bytes
    peticiones y respuestas
          |
       MANEJADOR      sabe que contesta
                      no sabe ni lo uno ni lo otro
```

La R6 de HVX-1 dice que `core/` y `proto/` no incluyen ninguna cabecera del
sistema operativo, y esto es la consecuencia practica: **todo lo que hay por
encima del backend ya esta escrito y probado sin que exista ningun transporte.**
Enchufar uno nuevo no cambia nada de lo de arriba.

Al manejador **NO se le da** un socket, ni el pozo de buffers, ni una
referencia de conexion.  No es disciplina, es que no los recibe: un manejador
que pudiera llegar a ellos seria un manejador que se podria escribir para
depender de ellos, y entonces cambiar de transporte dejaria de ser gratis.

## 4. Escribir un backend

Un backend hace tres cosas: acepta una operacion, la acaba mas tarde, y
devuelve una finalizacion.  Eso es todo lo que es un backend, y por eso uno
sobre memoria y uno sobre descriptores son el mismo tipo de cosa.

Hay dos en el arbol y los dos son de verdad:

| backend | transporte | para que |
| :------ | :--------- | :------- |
| `MemoryBackend` | memoria que provee quien llama | preparar casos exactos, incluido el que necesita una carrera para verse |
| `StdioBackend` | dos descriptores | tuberias, sockets de dominio, descriptores heredados, ficheros |

### 4.1 Las reglas que no se pueden romper

> **Un buffer nombrado por una operacion es del sistema operativo hasta que
> vuelva su finalizacion.**

Es la regla que separa una interfaz por finalizacion de una por
disponibilidad, y la unica cuyo incumplimiento no revienta.  Devolver ese
buffer al pozo antes de tiempo es un uso despues de liberar **que hace el
nucleo**, sobre una memoria que para entonces es de otra conexion: los bytes de
un cliente aparecen en mitad de la peticion de otro, en silencio.

> **Como mucho una lectura y como mucho una escritura en vuelo por conexion.**

Y no es una limitacion: dos lecturas pendientes sobre un flujo acaban en el
orden en que las termine el nucleo, asi que los bytes llegarian en dos buffers
sin forma de decir cual iba antes.  Un flujo que se puede desordenar no es un
flujo.  Lo mismo al reves para las escrituras, que se entrelazarian en el
cable.

Las dos SI se solapan entre si, porque son sentidos independientes.

> **En un transporte que bloquea, las escrituras se acaban antes que las
> lecturas.**

Una lectura de tuberia espera hasta que el otro extremo diga algo.  Acabar una
escritura detras de una lectura retiene una respuesta ya lista hasta la
peticion siguiente -- y un extremo que espera esa respuesta antes de mandar
nada espera para siempre.  Los dos esperandose es un abrazo mortal que se
inventa el backend.

Esto no se puede probar con ficheros: ahi una lectura no espera nunca, asi que
el orden da igual.  La prueba de `tests/test_stdio_backend.cpp` usa una tuberia
de verdad con un extremo en otro hilo, y por eso todas las pruebas tienen
plazo: con el orden invertido, la que falla no da un resultado malo, no termina.

> **Una lectura DEBE devolver lo que haya llegado, no esperar a llenar lo que
> se le pidio.**

De ahi que el backend de descriptores use `read` y no una lectura con buffer:
pedir dieciseis kilobytes de una peticion de cuarenta bytes esperaria a que el
otro extremo mandara la SIGUIENTE.

## 5. Servir recursos

Un manejador recibe la peticion y un escritor de respuestas, y con eso:

- decide el estado;
- escribe las cabeceras que quiera;
- cierra la cabeza diciendo **como se trocea** el cuerpo (una longitud, por
  trozos, o ninguno);
- y escribe el cuerpo **por el mismo escritor**.

El ejemplo que el build compila y las pruebas corren esta en
[`serve/main.cpp`](../serve/main.cpp).  Es deliberadamente el manejador mas
pequeno que sigue siendo un manejador, y sirve un recurso generado en el
momento.

> **El cuerpo DEBE pasar por el escritor, no ir directo al transporte.**

Un manejador que escriba su cuerpo por su cuenta esta escribiendo por un
segundo camino sin ningun orden contra el primero: la cabeza sale por el bucle,
mas tarde, y lo que llega al cliente es **el cuerpo y despues la linea de
estado**, que no es una respuesta.

Un recurso estatico que ya este en memoria se sirve igual: el manejador escribe
sus bytes.

### 5.1 Lo que queda por encima del manejador

Un servidor de ficheros -- abrir un fichero, mirar su fecha, calcular un
`ETag`, contestar un `304` -- es una capa por encima del manejador, no parte
del transporte ni del codec.

Un cuerpo que vive en otro sitio -- un fichero mapeado, un recurso estatico
grande -- es el caso de la R14 de HVX-1: una respuesta DEBE poder escribirse
con una sola operacion dispersa, sin juntar antes la cabeza y el cuerpo.  Un
cuerpo que el manejador hace en el momento no vive en ningun otro sitio, y ahi
la regla no cuesta nada; para uno que ya existe, es la diferencia entre
servirlo y copiarlo.

Una pareja de descriptores es UNA conexion: hay una entrada estandar, asi que
hay un extremo.  Para varias hace falta un transporte que acepte -- un socket
de dominio, una tuberia con nombre --.

Sobre una tuberia entre procesos de la misma maquina, TLS normalmente no hace
falta: lo que protege ahi son los permisos del socket (seccion 2.1).

## 6. Para el servidor de lenguaje de Vesta

El caso que motivo este documento.  Un servidor LSP ya tiene un transporte sin
red -- habla por su entrada y salida estandar -- y ya usa un entramado con la
longitud por delante, que es el de HTTP sin serlo del todo.

Dos formas de darle ordenes desde fuera, y no son lo mismo:

1. **HTTP por una tuberia o un socket de dominio aparte**, dejando el LSP
   donde esta.  Es lo que encaja con MCP, cuyo transporte estandar es HTTP, y lo
   que permite `curl` contra el servidor de lenguaje.  Es lo que este documento
   describe.
2. **Reemplazar el entramado propio del depurador** (`[u32 LE][JSON]`) por
   HTTP.  NO se recomienda: ese protocolo es un flujo de sucesos asincronos
   difundidos a varios clientes, y eso encaja mal con peticion y respuesta.  Su
   entramado no esta mal elegido.

## 7. Por que el recetario va aparte

Este documento fija decisiones.  **El recetario con firmas y codigo para copiar
es HVX-3**, y va aparte porque envejece a otro ritmo: una decision de este
documento dura lo que dure el diseno, y una firma cambia cada vez que una pieza
aprende algo.  Un documento rancio sobre una API es peor que ninguno: alguien
lo sigue.

Por eso HVX-3 se escribe cuando la forma de arrancar un servidor y la de
servir un recurso dejan de moverse, no antes.  La referencia que no miente es
[`serve/main.cpp`](../serve/main.cpp): el build lo compila y las pruebas lo
corren, asi que si deja de ser cierto, se rompe.
