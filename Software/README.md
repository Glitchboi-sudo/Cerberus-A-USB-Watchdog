# Software

Estructura lista para Arduino IDE
- `Cerberus/` contiene el sketch con el mismo nombre (`Cerberus.ino`), asi el IDE no pedira crear una carpeta al abrirlo.
- `Cerberus/ramdisk.h` es la imagen FAT que se presenta como RAM Disk.

Contenido del firmware
- `Cerberus.ino`: firmware principal (RAM Disk MSC, detector HID host con PIO-USB, avisos OLED/serie, LED neopixel y detector USB Killer).
- `ramdisk.h`: bloques predefinidos para el disco (README/AUTORUN en sectores fijos; hexdumps en serie).

Pines/ajustes relevantes
- OLED I2C: addr `0x3C` (SSD1306), tamano 128x64 por defecto.
- NeoPixel de estado: GPIO28.
- USB Killer: `KILLER_PIN` GPIO8.
- Host USB (PIO-USB): `HOST_PIN_DP` GPIO0 (D- = GPIO1).
- Descriptores USB personalizados (VID/PID/strings) para anti-deteccion.

Dependencias (Arduino IDE)
- Adafruit TinyUSB, Pico-PIO-USB, Adafruit_GFX, Adafruit_SSD1306.
- Board: Raspberry Pi RP2040, USB Stack: Adafruit TinyUSB.

Uso rapido
- Abre `Software/Cerberus/Cerberus.ino` en Arduino IDE y sube a la Pico.
- Conecta al PC y observa mensajes en la OLED y por `SerialTinyUSB`.
