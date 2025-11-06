# Software

Resumen
- Firmware y recursos para Cerberus (RP2040). Incluye el sketch principal y datos del RAM Disk.

Contenido
- `Cerberus.ino`: firmware principal.
  - Presenta un dispositivo Mass Storage (MSC) con RAM Disk y muestra actividad en OLED/serie.
  - Detecta dispositivos HID como host (PIO-USB) y cuenta eventos.
  - Indicadores en OLED: lecturas/escrituras/borrados, autorun, HID, y USB Killer.
  - LED de estado (OK encendido; eventos de riesgo apagan el LED).
  - Boton BOOTSEL: pulsacion corta reinicia; >2s muestra conteo de eventos HID.
- `ramdisk.h`: imagen FAT en memoria (bloques predefinidos). Dispara avisos al leer `README.TXT`/`AUTORUN.INF` y hace hexdumps por serie.
- `background.h`: recursos graficos (logo) para OLED.

Pines/ajustes relevantes
- OLED I2C: addr `0x3C` (SSD1306), tamano 128x64 por defecto.
- LED: GPIO25.
- USB Killer: `KILLER_PIN` GPIO8.
- Host USB (PIO-USB): `HOST_PIN_DP` GPIO27 (D+), D- = GPIO28.
- Descriptores USB personalizados (VID/PID/strings) para anti-deteccion.

Dependencias (Arduino IDE)
- Adafruit TinyUSB, Pico-PIO-USB, Adafruit_GFX, Adafruit_SSD1306.
- Board: Raspberry Pi RP2040, USB Stack: Adafruit TinyUSB.

Uso rapido
- Abre `Cerberus.ino`, compila y sube a la Pico.
- Conecta al PC y observa mensajes en OLED y por `SerialTinyUSB`.

