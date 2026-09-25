# Medidas fechadas, por maquina

Una medida sin maquina y sin fecha no se compara con nada, asi que aqui no se
guarda ninguna que no lleve las dos.

    cmake --build <build> --target http_vx_bench
    <build>/http_vx_bench "<maquina>" > bench/baseline/<maquina>.txt

El nombre de la maquina se **pide** y no se adivina: no hay forma portable de
preguntarle a una maquina que es, y un banco que se la inventara produciria
resultados que parecen comparables todos y no lo son.

## Que significa cada numero

| | |
| :-- | :-- |
| **servir** | una peticion completa por el camino de verdad -- analizador, troceado, manejador, escritor, bucle -- con el backend de memoria.  Es el limite de arriba: lo que costaria si el sistema operativo fuera gratis. |
| **llamadas por peticion** | la R15.  Se CUENTA en vez de cronometrarse, porque una cuenta no tiene ruido.  Una peticion sencilla debe ser una lectura y una escritura. |
| **partir la entrada** | la R12, y la unica medida de aqui que va de SEGURIDAD.  Un analizador que retrocede no es solo lento: es cuadratico contra quien mande una peticion byte a byte a proposito. |
| **memoria por conexion** | la R1 y la R2.  Lo que tiene que poder ensenar un servidor que promete un millon de conexiones. |

## Como se lee la de partir la entrada

La columna `vs 1 trozo` de la tabla pequena **no tiene que ser plana**: treinta y
dos llamadas cuestan treinta y dos preparaciones, y eso es lineal en los trozos
e inevitable.

Lo que decide es **la comparacion entre las dos tablas**.  Un analizador que
reanuda lee cada byte una vez sean los trozos que sean, asi que su proporcion es
coste fijo partido por trabajo -- y el trabajo crece con la cabeza mientras el
coste fijo no, asi que con una cabeza mayor la proporcion **baja**.  Uno que
volviera a empezar leeria el primer trozo treinta y dos veces, y eso crece CON
la cabeza: subiria, y seguiria subiendo.

## Con que se compara esto, y con que no

**El numero de `servir` NO se compara con el de nginx ni con un TechEmpower.**
Aqui no hay ninguna llamada al sistema: el backend entrega los bytes desde
memoria.  Es el coste de la maquinaria de HTTP sola, y sobre un socket una
lectura y una escritura cuestan mas que todo ello junto.

Eso no es un descargo.  Es el argumento de como esta hecho este servidor: si
manda la llamada al sistema, lo que importa es hacer MENOS -- que es lo que
cuenta la R15 y agrupa la R18 --, no que analizar sea un poco mas rapido.  Un
servidor que hiciera este numero el doble de bueno y dos llamadas por peticion
iria mas lento.

**Lo que SI se compara es el MB/s de analizar**, porque los bytes son la unidad
en la que esta el numero de cualquier otro analizador.  Una cabecera mide lo que
alguien eligio; un byte es un byte.

Y aun asi, la unica comparacion que vale es la que se corre **en la misma
maquina y el mismo dia**.  Una cifra recordada de otro sitio, con otra CPU, otro
compilador y otra cabecera de ejemplo, no dice quien es mas rapido: dice que dos
maquinas son distintas.  Por eso aqui no hay una tabla de rivales, y si alguna
vez la hay tendra que salir de correr al rival con este mismo fichero.

## Lo que ya ha encontrado

- **33 us por peticion**, que eran 8 KB de operaciones pendientes copiadas a la
  pila en cada espera del backend de memoria.  Quitando la copia: 400 ns.
  Ochenta veces, y en codigo que ninguna prueba iba a mirar nunca porque todas
  pasaban.
- **Una conexion parada tiene un buffer.**  En una interfaz por finalizacion hay
  que tener una lectura pendiente para enterarse de que llega algo, y una
  lectura nombra el buffer.  A 16 KB y un millon son 16 GB, que es justo lo que
  la R1 existe para evitar.  Lo arregla la lectura de longitud cero -- la
  recepcion de cero bytes de IOCP, los buffers provistos de io_uring --, que
  acaba cuando hay algo y solo entonces coge buffer.  Ninguno de los dos
  backends esta escrito, asi que el numero sale como esta.
