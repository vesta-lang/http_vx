# http_vx

Un servidor HTTP/1.1 para sostener del orden de un millon de conexiones en una
maquina, con la parte que toca la red escrita de forma que se pueda probar y
fuzzear **sin abrir un socket**.

Este fichero responde a **donde vive cada cosa y como se construye**. El porque
de cada decision esta en [`doc/`](doc/), indexado al final.

## Como se construye

```bash
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

Suelto o dentro de otro proyecto (`add_subdirectory`), como `vesta_alloc` y
`vesta_prof`.

## Disposicion

```text
http_vx/
  include/   el contrato publico
  core/      slab, rueda de tiempos, pozo de buffers
  proto/     HTTP/1.1: analizador y maquina de conexion
  reactor/   la interfaz por finalizacion
  windows/   IOCP
  linux/     io_uring y epoll
  tests/     sobre core/ y proto/
  fuzz/      el analizador
  bench/     cuanto cuesta, medido aqui
  doc/       el porque de cada decision
```

**`core/` y `proto/` no incluyen una sola cabecera del sistema.** No es
purismo: el analizador de HTTP es el codigo al que un desconocido le da bytes,
y si para ejercitarlo hiciera falta abrir un socket se probaria poco y se
fuzzearia menos. Asi se le dan bytes desde `tests/` como a cualquier funcion, y
bytes torcidos desde `fuzz/`, sin red y sin permisos.

Es la misma regla que sostiene `common/` en `vesta_prof`.

**`reactor/` no incluye nada de `proto/`.** Un bucle de eventos por
finalizacion vale sin HTTP, y el analizador vale sobre cualquier cosa que le
entregue bytes. Mezclarlos daria un servidor mas corto y una pieza inseparable.

**`bench/` no es opcional.** Un servidor que promete un millon de conexiones
tiene que poder ensenar cuanto ocupa cada una en la maquina de quien pregunta.
Con su `baseline/` fechado y etiquetado por maquina, como en el asignador: una
medida sin maquina y sin fecha no se compara con nada.

## De donde sale la memoria

De [`vesta_alloc`](https://github.com/vesta-lang/vesta_alloc). No hay asignador
propio aqui, y las cuatro piezas que se usan no son una eleccion de comodidad:

| pieza | para que |
| --- | --- |
| listas libres por hilo | cada fragmento reserva de su hilo, sin contencion |
| `scratch_arena` | **una peticion es una fase**: todo lo que nace atendiendola muere al responder |
| `small_vector` | las cabeceras: casi siempre diminutas, a veces no |
| `alloc_tag` | declarar que algo vive poco y no crece |

## Es un proyecto aparte

Mismo trato que `vesta_alloc` y `vesta_prof`, y por el mismo motivo:

> **No depende de nada del compilador.** Se puede sacar de aqui y llevarselo.

Nace para dar transporte al servidor MCP del compilador de Vesta, pero esa
independencia es una restriccion del diseno y no una consecuencia agradable: en
cuanto dependiera, dejaria de servir para lo demas.

## El porque de cada decision

| | |
| --- | --- |
| [`doc/architecture.md`](doc/architecture.md) | donde se corta y por que: el modelo de E/S, los fragmentos, la memoria, y lo que NO se hace |
