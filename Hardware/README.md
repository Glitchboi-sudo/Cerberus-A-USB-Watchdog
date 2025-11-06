# Hardware

Resumen
- Carpeta con recursos de hardware relacionados a Cerberus.

Contenido
- `PCB_PCB_usb_protect_breakout_2025-11-05.json`: diseno de una breakout board con proteccion de sobrevoltaje (VBUS) para USB. Pensado para prototipos en breadboard o pruebas de laboratorio.

Notas de uso
- Opcional: no es necesario para la version final del dispositivo. Puedes usarlo si quieres armar tu propio montaje o intercalar proteccion entre host y dispositivo.
- Conexiones esperadas: VBUS 5V, D+, D-, GND. La proteccion actua sobre VBUS.
- Estado/Disclaimer: la version actual funciona pero tiene conexiones invertidas; se corregira mas adelante.

Relacion con el firmware
- El firmware soporta modo host (PIO-USB) en RP2040 usando GPIO27 (D+) y GPIO28 (D-), y reporta actividad por OLED/serie. Este breakout puede ayudar a proteger VBUS durante pruebas.

