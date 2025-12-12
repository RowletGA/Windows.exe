# Windows.exe

Script PowerShell para optimizar Windows 11 (22H2+) para gaming, centrado en CS2. Incluye punto de restauracion, menu interactivo y funcion de reversion completa.

## Uso rapido
1. Abrir PowerShell **como Administrador** en esta carpeta.
2. Ejecutar: `powershell -ExecutionPolicy Bypass -File .\Optimize-CS2.ps1`
3. Elegir en el menu:
   - 1) Optimizacion completa (agresiva, desactiva servicios y quita bloat no critico). Pregunta si deseas optimizar Wi-Fi.
   - 2) Optimizacion ligera (mantiene servicios/apps, pero aplica tweaks de rendimiento). Pregunta si deseas optimizar Wi-Fi.
   - 3) Restaurar valores por defecto (revierte todo lo respaldado).

## Que hace
- Crea un punto de restauracion (si esta disponible).
- Respalda claves de registro, servicios, tareas, apps removidas y ajustes de red en `C:\ProgramData\CS2_Optimize_Backup.json`.
- Optimiza scheduler multimedia, prioridad GPU, GameDVR off, HAGS on.
- Crea/renombra/activa de forma robusta el plan de energia "CS2 Ultimate Performance" (duplica Ultimate Performance si no existe) y desactiva reposo en CA. Si estaba activo otro plan, se guarda para restaurar.
- Solicita timer resolution 0.5 ms mientras el script viva.
- Optimiza red: TCP tuning seguro, desactiva ahorro de energia en NICs, desactiva Nagle en interfaces activas. Opcional Wi-Fi: desactiva ahorro de energia, habilita Wake on Magic Packet, fuerza metrica IPv4 10 y desactiva metrica automatica para priorizar el adaptador Wi-Fi.
- Desactiva servicios no criticos para gaming: Print Spooler, Fax, DiagTrack, RetailDemo, MapsBroker, WSearch.
- Deshabilita tareas de telemetria conocidas.
- Quita bloatware no critico (mantiene Xbox/Store/Update/audio/red/GPUs).
- Opcional UI: desactiva animaciones de Explorer y acelera menus.

## Restaurar
- Opcion 3 del menu carga el respaldo y revierte registro, servicios, tareas, apps, plan de energia previo y ajustes de red/metrica.

## Notas
- Requiere reiniciar tras aplicar o restaurar para que todo tome efecto.
- No toca Microsoft Store, Windows Update, servicios de audio/red ni drivers.
- Probado para Windows 11 22H2+. Ejecutar siempre como Administrador.
