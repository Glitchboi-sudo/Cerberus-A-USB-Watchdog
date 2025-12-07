# Cerberus

![Alpha V3 del proyecto](1.jpeg)

<p align="center">
  <strong>Desarrollado por Glitchboi</strong><br>
  Seguridad desde México para todos
</p>

![Estado](https://img.shields.io/badge/status-En_desarollo-gree)
![License](https://img.shields.io/badge/license-GNU_AGPLv3-blue)

---

## Descripción

Este proyecto es un dispositivo compacto diseñado para proteger computadoras de ataques por USB, detectando lecturas o escrituras automáticas que podrían indicar malware, y diferenciando dispositivos maliciosos como Rubber Ducky o USB Killer. A diferencia de otras soluciones que solo cortan las líneas de datos, este dispositivo muestra en tiempo real la actividad USB, brindando visibilidad sobre lo que realmente ocurre. Nace de la necesidad de entender y prevenir ataques físicos de forma proactiva, aportando seguridad con transparencia y control para el usuario.

Enfocado a expertos en ciberseguridad (SOC, blue teamers y red teamers). Cerberus extiende USBvalve para pruebas de USB, debugging de payloads BadUSB y analisis forense basico ante sospecha de infeccion. Muestra actividad de almacenamiento/HID en OLED y por serie para su uso en laboratorio.

---

## Instalación

### Prerequisitos
- Instalar ArduinoIDE
- `Adafruit TinyUSB Library` version `3.6.0`
- `Pico-PIO-USB` version `0.7.2`
- Boards `Raspberry Pi RP2040 (4.5.4)` con CPU Speed at `133MHz` y Tools=>USB Stack en `Adafruit TinyUSB`
- `Adafruit_SSD1306` OLED library version `2.5.14`
- Raspberry Pi Pico 1 o 2 (u otra devboars basada en RP2040)
- Pantalla I2C OLED de 128x64 o 128x32 (SSD1306)

### Pasos
---
#### Usando la version precompilada

Dentro del github ve a releases y busca el archivo .uf2 mas reciente, descargalo

Para flashear la imagen debes:
- Conecta la Raspberry Pi Pico con un cable USB, manten el boton _BOOTSEL/BOOT_ presionado.
- Suelta el boton.
- Veremos un nuevo dispositivo en el sistema, llamado `RPI-RP2` (En linux probablemente tendras que hacerlo manualmente).
- Copia el archivo creado `.uf2` en el folder, dependiendo de la pantalla OLED.
- Espera unos segundos hasta que desaparezca el dispositivo

#### Compila tu version

Obten el repo de forma local
``` bash
git clone https://github.com/Glitchboi-sudo/Cerberus-A-USB-Watchdog.git
```

Con Arduino IDE
- Abre `Software/Cerberus/Cerberus.ino` (la carpeta ya coincide con el nombre del sketch, el IDE no pedira moverlo).
- Conecta  la Raspberry Pi Pico con un cable USB
- Selecciona la Pico en Arduino
- Click en `Upload`

---

## Uso

- Conecta la Pico al PC por USB (puerto nativo del RP2040). La OLED mostrara la version y el LED quedara encendido si todo esta OK.
- Observa los eventos en pantalla y en el LED:
  - Lecturas del sistema: "[!] README (R)" y "[+] AUTORUN (R)"
  - Escrituras/Borrados: "[!] WRITING" / "[!] DELETING"
  - Dispositivo HID detectado o enviando datos: "[!!] HID Device" y "[!!] HID Sending data"
  - USB Killer detectado: "[!!] USB Killer"
- Boton BOOTSEL:
  - Pulsacion corta: "[+] RESETTING" (reinicia el dispositivo)
  - \>2 s: muestra "[+] HID Evt# N" (conteo de eventos HID)
- Debug por serie: abre `SerialTinyUSB` para ver logs y hexdumps de bloques leidos/escritos.

---

## Hardware

- El archivo `Hardware/PCB_PCB_usb_protect_breakout_2025-11-05.json` es un diseño de una breakout board con circuito de proteccion de sobrevoltaje (VBUS) para USB.
- No es necesario para la version final del dispositivo. Si quieres armar tu propio prototipo en breadboard o similar, puedes usar este componente.
- Disclaimer: la version actual esta mal hecha; funciona pero las conexiones estan invertidas. Se arreglara mas adelante.

---
## TODO

- [ ] Documentar el cableado exacto.
- [ ] Agregar fotos/diagramas de conexion y lista de materiales.
- [ ] Publicar binarios `.uf2` en Releases para OLED 128x64 y 128x32.
- [ ] Mejorar soporte/auto‑deteccion de pantallas OLED 128x32/64.
- [ ] Guia del circuito para deteccion USB Killer en `KILLER_PIN`.
- [ ] Anadir hardware externo para almacenar el RAM Disk en lugar de la flash interna del RP2040.
- [ ] Funciones para detectar/identificar el dispositivo conectado (clase, VID/PID, fabricante) y heuristicas de posible ataque.
- [ ] Interfaz por CLI mas amigable para configuracion/inspeccion (filtros, niveles de log, export de evidencias).

---

## Contribuir

Este proyecto no solo es un repositorio: es un espacio abierto para aprender, experimentar y construir juntos. **Buscamos activamente contribuciones**, ya sea en la parte técnica o incluso en la documentación.
- **En hardware:** Si detectas oportunidades para mejorar la eficiencia (por ejemplo, usando otros chips, optimizando el consumo de energía o cambiando componentes por alternativas más confiables), ¡tus sugerencias son bienvenidas!    
- **En software:** Desde corrección de bugs, optimización de rendimiento, hasta mejoras en la legibilidad del código o documentación; todo aporte, grande o pequeño, suma muchísimo.
No necesitas ser experto para ayudar: si crees que algo puede explicarse mejor, que el código puede ser más claro, o que hay una forma más elegante de hacer algo, **cuéntanos o abre un Pull Request**.

---

## Créditos

- Proyecto basado en [USBvalve](https://github.com/cecio/USBvalve) hecho por *[Cecio](https://github.com/cecio)* 
- Modificado / Creado por:
  - [Erik Alcantara](https://www.linkedin.com/in/erik-alc%C3%A1ntara-covarrubias-29a97628a/)
