# Reto 2 — Monitor Defensivo de Comportamiento C2 Simulado

**Materia:** Programación Avanzada para Ciberseguridad · LSTI · FCFM UANL  
**Entrega:** tag `reto2-entrega` en este repositorio

## Descripción

Construye dos programas en C++ que corren en VMs distintas de la misma
red Internal Network:

| Programa | Archivo | VM |
|---|---|---|
| Emisor C2 simulado | `src/emisor.cpp` | VM-1 |
| Detector defensivo | `src/detector.cpp` | VM-2 |

## Compilar

```bash
make all
```

## Ejecutar

```bash
# VM-2 primero (detector escucha)
./detector 4444 5A

# VM-1 después (emisor envía heartbeats)
./emisor 192.168.56.101 4444 5 5A
```

## Especificaciones completas

Consulta el documento **RETO2_PAC_AD2026.pdf** publicado en Teams.

## Integrantes

| Nombre | Matrícula | Módulo |
|---|---|---|
| | | Emisor |
| | | Detector |
