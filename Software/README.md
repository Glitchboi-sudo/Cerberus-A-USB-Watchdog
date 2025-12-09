# Software

Estructura lista para Arduino IDE
- `Cerberus/` contiene el sketch con el mismo nombre (`Cerberus.ino`), asi el IDE no pedira crear una carpeta al abrirlo.
- `Cerberus/ramdisk.h` es la imagen FAT que se presenta como RAM Disk.

Contenido del firmware
- `Cerberus.ino`: firmware principal (RAM Disk MSC, detector HID host con PIO-USB, avisos OLED/serie, LED neopixel y detector USB Killer).
- `ramdisk.h`: bloques predefinidos para el disco (README/AUTORUN en sectores fijos; hexdumps en serie).
- `cerberus_listener.py`: script PC (GUI) para detectar el puerto serie de Cerberus, visualizar el log en vivo y guardar el contenido a un archivo de texto.

Pines/ajustes relevantes
- OLED I2C: addr `0x3C` (SSD1306), tamano 128x64 por defecto.
- NeoPixel de estado: GPIO29.
- USB Killer: `KILLER_PIN` GPIO8.
- Host USB (PIO-USB): `HOST_PIN_DP` GPIO0 (D- = GPIO1).
- Descriptores USB personalizados (VID/PID/strings) para anti-deteccion.

Dependencias (Arduino IDE)
- Adafruit TinyUSB, Pico-PIO-USB, Adafruit_GFX, Adafruit_SSD1306.
- Board: Raspberry Pi RP2040, USB Stack: Adafruit TinyUSB.

Script de escucha en PC (`cerberus_listener.py`)
- Prerequisitos: Python 3 y `pyserial` (`pip install pyserial`). Usa `tkinter` (incluido en instalaciones estándar).
- Funciona: intenta detectar el puerto por VID/PID o nombre, permite elegir manualmente si no lo halla, muestra las lineas recibidas en una ventana con scroll y permite guardarlas a texto.
- Uso rapido: `python Software/cerberus_listener.py`; si no auto-detecta, selecciona el puerto en el combo y pulsa Conectar. Para guardar el log visible, pulsa “Guardar log…” y elige nombre/ruta.

Uso rapido
- Abre `Software/Cerberus/Cerberus.ino` en Arduino IDE y sube a la Pico.
- Conecta al PC y observa mensajes en la OLED y por `SerialTinyUSB`.
