# Windows.exe

Script PowerShell para optimizar Windows 11 (22H2+) para gaming, centrado en CS2. Incluye punto de restauración, menú interactivo y función de reversión completa.

## Uso rápido
1. Abrir PowerShell **como Administrador** en esta carpeta.
2. Ejecutar: `powershell -ExecutionPolicy Bypass -File .\Optimize-CS2.ps1`
3. Elegir en el menú:
   - 1) Optimización completa (agresiva, desactiva servicios y quita bloat no crítico)
   - 2) Optimización ligera (mantiene servicios/apps, pero aplica tweaks de rendimiento)
   - 3) Restaurar valores por defecto (revierte todo lo respaldado)

## Qué hace
- Crea un punto de restauración (si está disponible).
- Respalda claves de registro, servicios, tareas y apps removidas en `C:\ProgramData\CS2_Optimize_Backup.json`.
- Optimiza scheduler multimedia, prioridad GPU, GameDVR off, HAGS on.
- Crea y activa plan de energía "CS2 Ultimate Performance" (duplica Ultimate Performance). Desactiva reposo en CA.
- Solicita timer resolution 0.5 ms mientras el script viva.
- Optimiza red: TCP tuning seguro, desactiva ahorro de energía en NICs, desactiva Nagle en interfaces activas.
- Desactiva servicios no críticos para gaming: Print Spooler, Fax, DiagTrack, RetailDemo, MapsBroker, WSearch.
- Deshabilita tareas de telemetría conocidas.
- Quita bloatware no crítico (mantiene Xbox/Store/Update/audio/red/GPUs).
- Opcional UI: desactiva animaciones de Explorer y acelera menús.

## Restaurar
- Opción 3 del menú carga el respaldo y revierte registro, servicios, tareas, apps y plan de energía previo.

## Notas
- Requiere reiniciar tras aplicar o restaurar para que todo tome efecto.
- No toca Microsoft Store, Windows Update, servicios de audio/red ni drivers.
- Probado para Windows 11 22H2+. Ejecutar siempre como Administrador.
