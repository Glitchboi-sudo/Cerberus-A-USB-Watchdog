# Hardware

## Resumen

Carpeta con los recursos de hardware del proyecto Cerberus USB Watchdog.

## Contenido

### CerberusZero_V1.epro

PCB completa del proyecto Cerberus. Este es el diseño principal del dispositivo.

- **Formato:** Proyecto de EasyEDA Pro (`.epro`)
- **Cómo abrir:** Importar directamente en EasyEDA Pro desde `Archivo → Abrir`

### ADUM3160 USB Isolator/

Módulo aislador USB basado en el chip ADUM3160. Proporciona **protección contra ataques USB-Killer** mediante aislamiento galvánico.

- **Función:** Aísla eléctricamente el host del dispositivo USB, bloqueando picos de alto voltaje
- **Uso:** Complemento opcional para añadir una capa extra de seguridad física
- **Más información:** Ver el README dentro de la subcarpeta

## Relación con el firmware

El firmware de Cerberus soporta modo host (PIO-USB) en RP2040 usando GPIO0 (D+) y GPIO1 (D-), y reporta actividad por OLED/puerto serie. El hardware aquí documentado complementa esa funcionalidad con protección eléctrica.
