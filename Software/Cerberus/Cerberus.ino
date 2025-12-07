/*********************************************************************

  USBProtector
  
  written by Cesare Pizzi && Glitchboi
  This project extensively reuse code done by Adafruit and TinyUSB. 
  Please support them!

*********************************************************************/

/*********************************************************************
  Adafruit invests time and resources providing this open source code,
  please support Adafruit and open-source hardware by purchasing
  products from Adafruit!

  MIT license, check LICENSE for more information
  Copyright (c) 2019 Ha Thach for Adafruit Industries
  All text above, and the splash screen below must be included in
  any redistribution
*********************************************************************/

#include <pio_usb.h>
#include "Adafruit_TinyUSB.h"
#include <XxHash_arduino.h>
#include <pico/stdlib.h>
#include <hardware/clocks.h>  // set_sys_clock_khz
#include <SPI.h>
#include <Wire.h>
#include <pico/util/queue.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_NeoPixel.h>

extern "C" {
  #include "tusb.h"
}

//
// BADUSB detector section
//

/*
 * Requirements:
 * - [Pico-PIO-USB](https://github.com/sekigon-gonnoc/Pico-PIO-USB) library
 * - 2 consecutive GPIOs: D+ is defined by HOST_PIN_DP (gpio2), D- = D+ +1 (gpio3)
 * - CPU Speed must be either 120 or 240 Mhz. Selected via "Menu -> CPU Speed"
 */

#define HOST_PIN_DP 0       // Pin used as D+ for host, D- = D+ + 1
#define LANGUAGE_ID 0x0409  // English

// USB Host object
Adafruit_USBH_Host USBHost;

// USB_Desc Structure
typedef struct {
  tusb_desc_device_t desc_device;
  uint16_t manufacturer[32];
  uint16_t product[48];
  uint16_t serial[16];
  bool mounted;
} dev_info_t;

// CFG_TUH_DEVICE_MAX is defined by tusb_config header
dev_info_t dev_info[CFG_TUH_DEVICE_MAX] = { 0 };

// END of BADUSB detector section

#define I2C_ADDRESS 0x3C  // 0X3C+SA0 - 0x3C or 0x3D
#define RST_PIN -1        // Sin pin de reset externo para la OLED
#define OLED_WIDTH  128
#define OLED_HEIGHT 64    // 64 or 32 depending on the OLED

Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, RST_PIN);

typedef struct {
  char text[64];
} DisplayMsg;

// Define the dimension of RAM DISK. We have a "real" one (for which
// a real array is created) and a "fake" one, presented to the OS
#define DISK_BLOCK_NUM 0x150
#define FAKE_DISK_BLOCK_NUM 0x800
#define DISK_BLOCK_SIZE 0x200
#include "ramdisk.h"

Adafruit_USBD_MSC usb_msc;

// Botón de reset manual (GP3 a GND)
#define BTN_RST 3

// Botón de reset manual (GP6 a GND)
#define BTN_OK 6

//
// USBKiller Globals
//
#define KILLER_PIN 8
#define NEOPIXEL_PIN 29
#define NEOPIXEL_COUNT 1

//
// USBvalve globals
//
#define VERSION "Cerberus - 0.1.5"
boolean readme = false;
boolean autorun = false;
boolean written = false;
boolean deleted = false;
boolean written_reported = false;
boolean deleted_reported = false;
boolean hid_sent = false;
boolean hid_reported = false;
boolean usbkiller = false;
uint hid_event_num = 0;

Adafruit_NeoPixel statusPixel(NEOPIXEL_COUNT, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);
queue_t display_queue;  // Thread-safe queue for cross-core OLED messages

//
// Anti-Detection settings.
//
// Set USB IDs strings and numbers, to avoid possible detections.
// Remember that you can cusotmize FAKE_DISK_BLOCK_NUM as well
// for the same reason. Also DISK_LABEL in ramdisk.h can be changed.
//
// You can see here for inspiration: https://the-sz.com/products/usbid/
//
// Example:
// 0x0951 0x16D5    VENDORID_STR: Kingston   PRODUCTID_STR: DataTraveler
//
#define USB_VENDORID 0x0951               // This override the Pi Pico default 0x2E8A
#define USB_PRODUCTID 0x16D5              // This override the Pi Pico default 0x000A
#define USB_DESCRIPTOR "DataTraveler"     // This override the Pi Pico default "Pico"
#define USB_MANUF "Kingston"              // This override the Pi Pico default "Raspberry Pi"
#define USB_SERIAL "123456789A"           // This override the Pi Pico default. Disabled by default. \
                                          // See "setSerialDescriptor" in setup() if needed
#define USB_VENDORID_STR "Kingston"       // Up to 8 chars
#define USB_PRODUCTID_STR "DataTraveler"  // Up to 16 chars
#define USB_VERSION_STR "1.0"             // Up to 4 chars

#define BLOCK_AUTORUN 102       // Block where Autorun.inf file is saved
#define BLOCK_README 100        // Block where README.txt file is saved
#define MAX_DUMP_BYTES 16       // Used by the dump of the debug facility: do not increase this too much
#define BYTES_TO_HASH 512 * 2   // Number of bytes of the RAM disk used to check consistency
#define BYTES_TO_HASH_OFFSET 7  // Starting sector to check for consistency (FAT_DIRECTORY is 7)

// Burned hash to check consistency
uint valid_hash = 2362816530;

// Main USB Killer code
void detectUSBKiller() {
  if (digitalRead(KILLER_PIN) == LOW) {
    usbkiller = true;
  }
}

// Core 0 Setup: will be used for the USB mass device functions
void setup() {
  // Init queue used to pass text from host callbacks (core1) to OLED (core0)
  queue_init(&display_queue, sizeof(DisplayMsg), 16);

  // Change all the USB Pico settings
  TinyUSBDevice.setID(USB_VENDORID, USB_PRODUCTID);
  TinyUSBDevice.setProductDescriptor(USB_DESCRIPTOR);
  TinyUSBDevice.setManufacturerDescriptor(USB_MANUF);
  // This could be used to change the serial number as well
  TinyUSBDevice.setSerialDescriptor(USB_SERIAL);

#if defined(ARDUINO_ARCH_MBED) && defined(ARDUINO_ARCH_RP2040)
  // Manual begin() is required on core without built-in support for TinyUSB such as
  // - mbed rp2040
  TinyUSB_Device_Init(0);
#endif

  // Set disk vendor id, product id and revision with string up to 8, 16, 4 characters respectively
  usb_msc.setID(USB_VENDORID_STR, USB_PRODUCTID_STR, USB_VERSION_STR);

  // Set disk size (using the "fake" size)
  usb_msc.setCapacity(FAKE_DISK_BLOCK_NUM, DISK_BLOCK_SIZE);

  // Set the callback functions
  usb_msc.setReadWriteCallback(msc_read_callback, msc_write_callback, msc_flush_callback);

  // Set Lun ready (RAM disk is always ready)
  usb_msc.setUnitReady(true);

  pinMode(BTN_RST, INPUT_PULLUP);

  //USB Killer Detection Setup
   pinMode(KILLER_PIN, INPUT_PULLUP);
   attachInterrupt(digitalPinToInterrupt(KILLER_PIN), detectUSBKiller, FALLING);

  // Check consistency of RAM FS
  // Add 11 bytes to skip the DISK_LABEL from the hashing
  // The startup of the USB has been moved before initialization of the 
  // screen because sometimes it inserts some delay preventing
  // proper initialization of the mass device
  uint computed_hash;
  computed_hash = XXH32(msc_disk[BYTES_TO_HASH_OFFSET] + 11, BYTES_TO_HASH, 0);
  if (computed_hash == valid_hash) {
      usb_msc.begin();
  }

  Wire.setSDA(4);
  Wire.setSCL(5);
  display.begin(SSD1306_SWITCHCAPVCC, I2C_ADDRESS);

  cls();  // Clear display
  statusPixel.begin();
  statusPixel.setBrightness(50);
  setNeoColor(0, 0, 255);  // Azul como estado inicial

  // Now outputs the result of the check
  if (computed_hash == valid_hash) {
    printout("\n[+] Selftest: OK");
  } else {
    printout("\n[!] Selftest: KO");
    printout("\n[!] Stopping...");
    while (1) {
      delay(1000);  // Loop forever
    }
  }

}

// Core 1 Setup: will be used for the USB host functions for BADUSB detector
void setup1() {
  set_sys_clock_khz(240000, true);
  pio_usb_configuration_t pio_cfg = PIO_USB_DEFAULT_CONFIG;
  pio_cfg.pin_dp = HOST_PIN_DP;
  USBHost.configure_pio_usb(1, &pio_cfg);

  // run host stack on controller (rhport) 1
  // Note: For rp2040 pico-pio-usb, calling USBHost.begin() on core1 will have most of the
  // host bit-banging processing works done in core1
  USBHost.begin(1);
}

// Main Core0 loop: managing display
void loop() {
  // Drain any text queued from host callbacks (running on core1)
  DisplayMsg msg;
  while (queue_try_remove(&display_queue, &msg)) {
    printout(msg.text);
  }

  static bool rst_prev = true;
  bool rst_now = digitalRead(BTN_RST);
  if (rst_now != rst_prev) {
    SerialTinyUSB.printf("BTN_RST %s\n", rst_now == LOW ? "PRESSED -> resetting" : "released");
    rst_prev = rst_now;
    if (rst_now == LOW) {
      swreset();
    }
  }

  if (usbkiller == true) {
    printout("\n[!!] USB Killer");
    usbkiller = false;
    setNeoColor(255, 0, 0);       // Rojo
  }

  if (readme == true) {
    printout("\n[!] README (R)");
    readme = false;
    setNeoColor(0, 0, 255);       // Azul
  }

  if (autorun == true) {
    printout("\n[+] AUTORUN (R)");
    autorun = false;
    setNeoColor(0, 0, 255);       // Azul
  }

  if (deleted == true && deleted_reported == false) {
    printout("\n[!] DELETING");
    deleted = false;
    deleted_reported = true;
    setNeoColor(0, 0, 255);       // Azul
  }

  if (written == true && written_reported == false) {
    printout("\n[!] WRITING");
    written = false;
    written_reported = true;
    setNeoColor(0, 0, 255);       // Azul
  }

  if (hid_sent == true && hid_reported == false) {
    printout("\n[!!] HID Sending data");
    hid_sent = false;
    hid_reported = true;
    setNeoColor(255, 0, 0);       // Rojo
  }

  if (BOOTSEL) {
    uint32_t press_start = to_ms_since_boot(get_absolute_time());
    while (BOOTSEL) {
      sleep_ms(10);
    }
    uint32_t press_end = to_ms_since_boot(get_absolute_time());
    uint32_t press_duration = press_end - press_start;

    if (press_duration > 2000) {              // Press duration > 2sec
      // Print the number of HID events detected so far
      char outstr[22];
      snprintf(outstr, 21, "\n[+] HID Evt# %d", hid_event_num);
      printout(outstr);
    } else {
      printout("\n[+] RESETTING");
      swreset();
    }
  }
}


// Main Core1 loop: managing USB Host
void loop1() {
  USBHost.task();
}

// Callback invoked when received READ10 command.
// Copy disk's data to buffer (up to bufsize) and
// return number of copied bytes (must be multiple of block size).
// This happens only for the "real" size of disk
int32_t msc_read_callback(uint32_t lba, void* buffer, uint32_t bufsize) {

  // Check for README.TXT
  if (lba == BLOCK_README) {
    readme = true;
  }

  // Check for AUTORUN.INF
  if (lba == BLOCK_AUTORUN) {
    autorun = true;
  }

  // We are declaring a bigger size than what is actually allocated, so
  // this is protecting our memory integrity
  if (lba < DISK_BLOCK_NUM - 1) {
    uint8_t const* addr = msc_disk[lba];
    memcpy(buffer, addr, bufsize);
  }

  SerialTinyUSB.print("Read LBA: ");
  SerialTinyUSB.print(lba);
  SerialTinyUSB.print("   Size: ");
  SerialTinyUSB.println(bufsize);
  if (lba < DISK_BLOCK_NUM - 1) {
    hexDump(msc_disk[lba], MAX_DUMP_BYTES);
  }
  SerialTinyUSB.flush();

  return bufsize;
}

// Callback invoked when received WRITE10 command.
// Process data in buffer to disk's storage and
// return number of written bytes (must be multiple of block size).
// This happens only for the "real" size of disk
int32_t msc_write_callback(uint32_t lba, uint8_t* buffer, uint32_t bufsize) {

  // Check for file deletion at Block 7
  // The first char of filename is replaced with 0xE5, we are going
  // to check for it
  if (lba == 7) {
    if (buffer[32] == 0xE5 || buffer[64] == 0xE5 || buffer[160] == 0xE5) {
      deleted = true;
    }
  }

  // This check for writing of space. The LBA > 10 is set to avoid some
  // false positives, in particular on Windows Systems
  if (lba > 10) {
    written = true;
  }

  // We are declaring a bigger size than what is actually allocated, so
  // this is protecting our memory integrity
  if (lba < DISK_BLOCK_NUM - 1) {
    // Writing buffer to "disk"
    uint8_t* addr = msc_disk[lba];
    memcpy(addr, buffer, bufsize);
  }

  SerialTinyUSB.print("Write LBA: ");
  SerialTinyUSB.print(lba);
  SerialTinyUSB.print("   Size: ");
  SerialTinyUSB.println(bufsize);
  if (lba < DISK_BLOCK_NUM - 1) {
    hexDump(msc_disk[lba], MAX_DUMP_BYTES);
  }
  SerialTinyUSB.flush();

  return bufsize;
}

// Callback invoked when WRITE10 command is completed (status received and accepted by host).
// used to flush any pending cache.
void msc_flush_callback(void) {
  // Nothing to do
}

void scrollUp(uint8_t pixels) {
  // Read the current content of the display, shift it up by 'pixels' rows
  display.startscrollright(0x00, 0x07); // Dummy values to initiate scroll
  display.stopscroll(); // Immediately stop to manually shift pixels in memory
  for (int i = 0; i < display.height() - pixels; i++) {
    for (int j = 0; j < display.width(); j++) {
      uint8_t color = display.getPixel(j, i + pixels);
      display.drawPixel(j, i, color);
    }
  }

  // Clear the freed space after scrolling
  display.fillRect(0, display.height() - pixels, display.width(), pixels, SSD1306_BLACK);
  // Refresh the display to show the changes
  display.display();
}

void checkAndScroll() {
  // Assumes text height of 8 pixels, but check for 16 because newline is not used
  if ((display.getCursorY() + 16) > display.height()) {
    // Scroll up by 8 pixels
    scrollUp(8);
    display.setCursor(0, display.getCursorY() - 8);
  }
}

// Queue-safe enqueue to avoid cross-core I2C usage
void enqueue_display(const char *str) {
  DisplayMsg msg;
  strncpy(msg.text, str, sizeof(msg.text) - 1);
  msg.text[sizeof(msg.text) - 1] = '\0';
  // If queue is full we drop the message silently to avoid blocking
  queue_try_add(&display_queue, &msg);
}

void printout(const char *str)
{
  checkAndScroll();
  display.print(str);
  display.display();

  // Output on serial device
  SerialTinyUSB.println(str);
}

// Clear display
void cls(void) {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  printout(VERSION);
  printout("\n-----------------");
}

// HexDump
void hexDump(unsigned char* data, size_t size) {
  char asciitab[17];
  size_t i, j;
  asciitab[16] = '\0';

  for (i = 0; i < size; ++i) {

    SerialTinyUSB.print(data[i] >> 4, HEX);
    SerialTinyUSB.print(data[i] & 0x0F, HEX);

    if ((data)[i] >= ' ' && (data)[i] <= '~') {
      asciitab[i % 16] = (data)[i];
    } else {
      asciitab[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      SerialTinyUSB.print(" ");
      if ((i + 1) % 16 == 0) {
        SerialTinyUSB.println(asciitab);
      } else if (i + 1 == size) {
        asciitab[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          SerialTinyUSB.print(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          SerialTinyUSB.print("   ");
        }
        SerialTinyUSB.print("|  ");
        SerialTinyUSB.println(asciitab);
      }
    }
  }
  SerialTinyUSB.println();
}

// Reset the Pico
void swreset() {
  watchdog_enable(1500, 1);
  while (1)
    ;
}

//
// Device info gathering 
//
static void print_device_descriptor(tuh_xfer_t *xfer);
void utf16_to_utf8(uint16_t *temp_buf, size_t buf_len);

// Invocado cuando cualquier dispositivo se monta (configurado)
void tuh_mount_cb(uint8_t daddr)
{
  SerialTinyUSB.printf("Device attached, address = %d\r\n", daddr);

  dev_info_t *dev = &dev_info[daddr - 1];
  dev->mounted = true;

  // Pide el Device Descriptor, cuando llegue se llama a print_device_descriptor()
  tuh_descriptor_get_device(daddr,
                            &dev->desc_device,
                            sizeof(tusb_desc_device_t),
                            print_device_descriptor,
                            0);
}

/// Invocado cuando el dispositivo se desmonta (reset/unplug)
void tuh_umount_cb(uint8_t daddr)
{
  SerialTinyUSB.printf("Device removed, address = %d\r\n", daddr);

  dev_info_t *dev = &dev_info[daddr - 1];
  dev->mounted = false;
}

static void print_device_descriptor(tuh_xfer_t *xfer)
{
  if (XFER_RESULT_SUCCESS != xfer->result) {
    SerialTinyUSB.printf("Failed to get device descriptor\r\n");
    return;
  }

  uint8_t const daddr = xfer->daddr;
  dev_info_t *dev = &dev_info[daddr - 1];
  tusb_desc_device_t *desc = &dev->desc_device;

  // Show a short summary on the OLED/serial right away
  char summary[48];
  SerialTinyUSB.printf("\r\nDevice %u: ID %04x:%04x\r\n",
                       daddr, desc->idVendor, desc->idProduct);

  SerialTinyUSB.printf("Device Descriptor:\r\n");
  SerialTinyUSB.printf("  bLength             %u\r\n"     , desc->bLength);
  SerialTinyUSB.printf("  bDescriptorType     %u\r\n"     , desc->bDescriptorType);
  SerialTinyUSB.printf("  bcdUSB              %04x\r\n"   , desc->bcdUSB);
  SerialTinyUSB.printf("  bDeviceClass        %u\r\n"     , desc->bDeviceClass);
  SerialTinyUSB.printf("  bDeviceSubClass     %u\r\n"     , desc->bDeviceSubClass);
  SerialTinyUSB.printf("  bDeviceProtocol     %u\r\n"     , desc->bDeviceProtocol);
  SerialTinyUSB.printf("  bMaxPacketSize0     %u\r\n"     , desc->bMaxPacketSize0);
  SerialTinyUSB.printf("  idVendor            0x%04x\r\n" , desc->idVendor);
  SerialTinyUSB.printf("  idProduct           0x%04x\r\n" , desc->idProduct);
  SerialTinyUSB.printf("  bcdDevice           %04x\r\n"   , desc->bcdDevice);
  // -------- Manufacturer String --------
  SerialTinyUSB.printf("  iManufacturer       %u\r", desc->iManufacturer);
  if (desc->iManufacturer &&
      XFER_RESULT_SUCCESS ==
        tuh_descriptor_get_manufacturer_string_sync(daddr,
                                                    LANGUAGE_ID,
                                                    dev->manufacturer,
                                                    sizeof(dev->manufacturer))) {

    utf16_to_utf8(dev->manufacturer, sizeof(dev->manufacturer));
    SerialTinyUSB.printf(" --- %s\r", (char *) dev->manufacturer);
  }
  SerialTinyUSB.printf("\n");

  // -------- Product String --------
  SerialTinyUSB.printf("  iProduct            %u\r", desc->iProduct);
  if (desc->iProduct &&
      XFER_RESULT_SUCCESS ==
        tuh_descriptor_get_product_string_sync(daddr,
                                               LANGUAGE_ID,
                                               dev->product,
                                               sizeof(dev->product))) {

    utf16_to_utf8(dev->product, sizeof(dev->product));
    SerialTinyUSB.printf(" --- %s\r", (char *) dev->product);
  }
  SerialTinyUSB.printf("\n");
  // -------- Serial Number String --------
  SerialTinyUSB.printf("  iSerialNumber       %u\r", desc->iSerialNumber);
  if (desc->iSerialNumber &&
      XFER_RESULT_SUCCESS ==
        tuh_descriptor_get_serial_string_sync(daddr,
                                              LANGUAGE_ID,
                                              dev->serial,
                                              sizeof(dev->serial))) {

    utf16_to_utf8(dev->serial, sizeof(dev->serial));
    SerialTinyUSB.printf(" --- %s\r", (char *) dev->serial);
  }
  SerialTinyUSB.printf("\n");
  SerialTinyUSB.printf("  bNumConfigurations  %u\r\n", desc->bNumConfigurations);
  SerialTinyUSB.printf("======================================\r\n");
}

//--------------------------------------------------------------------+
// String Descriptor Helper
//--------------------------------------------------------------------+

static void _convert_utf16le_to_utf8(const uint16_t *utf16, size_t utf16_len, uint8_t *utf8, size_t utf8_len) {
  // TODO: Check for runover.
  (void) utf8_len;
  // Get the UTF-16 length out of the data itself.

  for (size_t i = 0; i < utf16_len; i++) {
    uint16_t chr = utf16[i];
    if (chr < 0x80) {
      *utf8++ = chr & 0xff;
    } else if (chr < 0x800) {
      *utf8++ = (uint8_t) (0xC0 | (chr >> 6 & 0x1F));
      *utf8++ = (uint8_t) (0x80 | (chr >> 0 & 0x3F));
    } else {
      // TODO: Verify surrogate.
      *utf8++ = (uint8_t) (0xE0 | (chr >> 12 & 0x0F));
      *utf8++ = (uint8_t) (0x80 | (chr >> 6 & 0x3F));
      *utf8++ = (uint8_t) (0x80 | (chr >> 0 & 0x3F));
    }
    // TODO: Handle UTF-16 code points that take two entries.
  }
}

// Count how many bytes a utf-16-le encoded string will take in utf-8.
static int _count_utf8_bytes(const uint16_t *buf, size_t len) {
  size_t total_bytes = 0;
  for (size_t i = 0; i < len; i++) {
    uint16_t chr = buf[i];
    if (chr < 0x80) {
      total_bytes += 1;
    } else if (chr < 0x800) {
      total_bytes += 2;
    } else {
      total_bytes += 3;
    }
    // TODO: Handle UTF-16 code points that take two entries.
  }
  return total_bytes;
}

void utf16_to_utf8(uint16_t *temp_buf, size_t buf_len) {
  size_t utf16_len = ((temp_buf[0] & 0xff) - 2) / sizeof(uint16_t);
  size_t utf8_len = _count_utf8_bytes(temp_buf + 1, utf16_len);

  _convert_utf16le_to_utf8(temp_buf + 1, utf16_len, (uint8_t *) temp_buf, buf_len);
  ((uint8_t *) temp_buf)[utf8_len] = '\0';
}

//
// BADUSB detector section
//

static uint8_t const keycode2ascii[128][2] = { HID_KEYCODE_TO_ASCII };

// Invoked when device with hid interface is mounted
void tuh_hid_mount_cb(uint8_t dev_addr, uint8_t instance, uint8_t const* desc_report, uint16_t desc_len) {

  uint16_t vid, pid;
  const char* protocol_str[] = { "None", "Keyboard", "Mouse" };

  // Read the HID protocol
  uint8_t const itf_protocol = tuh_hid_interface_protocol(dev_addr, instance);

  tuh_vid_pid_get(dev_addr, &vid, &pid);

  printout("\n[!!] HID Device");
  setNeoColor(255, 0, 0);       // Rojo

  SerialTinyUSB.printf("HID device address = %d, instance = %d mounted\r\n", dev_addr, instance);
  SerialTinyUSB.printf("VID = %04x, PID = %04x\r\n", vid, pid);
  SerialTinyUSB.printf("HID Interface Protocol = %s\r\n", protocol_str[itf_protocol]);

  if (!tuh_hid_receive_report(dev_addr, instance)) {
    SerialTinyUSB.printf("Error: cannot request to receive report\r\n");
  }
}

// Invoked when device with hid interface is un-mounted
void tuh_hid_umount_cb(uint8_t dev_addr, uint8_t instance) {
  SerialTinyUSB.printf("HID device address = %d, instance = %d unmounted\r\n", dev_addr, instance);

  // Reset HID sent flag
  hid_sent = false;
  hid_reported = false;
  hid_event_num = 0;
}

// Invoked when received report from device
void tuh_hid_report_received_cb(uint8_t dev_addr, uint8_t instance, uint8_t const* report, uint16_t len) {

  static bool kbd_printed = false;
  static bool mouse_printed = false;

  // Used in main loop to write output to OLED
  hid_sent = true;

  // Read the HID protocol
  uint8_t const itf_protocol = tuh_hid_interface_protocol(dev_addr, instance);

  switch (itf_protocol) {
    case HID_ITF_PROTOCOL_KEYBOARD:
      if (kbd_printed == false) {
        SerialTinyUSB.println("HID received keyboard report");
        kbd_printed = true;
        mouse_printed = false;
      }
      process_kbd_report((hid_keyboard_report_t const*)report);
      hid_event_num++;
      break;

    case HID_ITF_PROTOCOL_MOUSE:
      if (kbd_printed == false) {
        SerialTinyUSB.println("HID receive mouse report");
        mouse_printed = true;
        kbd_printed = false;
      }
      process_mouse_report((hid_mouse_report_t const*)report);
      hid_event_num++;
      break;

    default:
      // Generic report: for the time being we use kbd for this as well
      process_kbd_report((hid_keyboard_report_t const*)report);
      hid_event_num++;
      break;
  }

  if (!tuh_hid_receive_report(dev_addr, instance)) {
    SerialTinyUSB.println("Error: cannot request to receive report");
  }
}

static inline bool find_key_in_report(hid_keyboard_report_t const* report, uint8_t keycode) {
  for (uint8_t i = 0; i < 6; i++) {
    if (report->keycode[i] == keycode) return true;
  }

  return false;
}

static void process_kbd_report(hid_keyboard_report_t const* report) {
  // Previous report to check key released
  static hid_keyboard_report_t prev_report = { 0, 0, { 0 } };

  for (uint8_t i = 0; i < 6; i++) {
    if (report->keycode[i]) {
      if (find_key_in_report(&prev_report, report->keycode[i])) {
        // Exist in previous report means the current key is holding
      } else {
        // Not existed in previous report means the current key is pressed

        // Check for modifiers. It looks that in specific cases, they are not correctly recognized (probably
        // for timing issues in fast input)
        bool const is_shift = report->modifier & (KEYBOARD_MODIFIER_LEFTSHIFT | KEYBOARD_MODIFIER_RIGHTSHIFT);
        uint8_t ch = keycode2ascii[report->keycode[i]][is_shift ? 1 : 0];

        bool const is_gui = report->modifier & (KEYBOARD_MODIFIER_LEFTGUI | KEYBOARD_MODIFIER_RIGHTGUI);
        if (is_gui == true) SerialTinyUSB.printf("GUI+");

        bool const is_alt = report->modifier & (KEYBOARD_MODIFIER_LEFTALT | KEYBOARD_MODIFIER_RIGHTALT);
        if (is_alt == true) SerialTinyUSB.printf("ALT+");

        // Check for "special" keys
        check_special_key(report->keycode[i]);

        // Finally, print out the decoded char
        SerialTinyUSB.printf("%c", ch);
        if (ch == '\r') SerialTinyUSB.print("\n");  // New line for enter

        fflush(stdout);  // flush right away, else nanolib will wait for newline
      }
    }
  }

  prev_report = *report;
}

static void check_special_key(uint8_t code) {

  if (code == HID_KEY_ARROW_RIGHT) SerialTinyUSB.print("<ARROWRIGHT>");
  if (code == HID_KEY_ARROW_LEFT) SerialTinyUSB.print("<ARROWLEFT>");
  if (code == HID_KEY_ARROW_DOWN) SerialTinyUSB.print("<ARROWDOWN>");
  if (code == HID_KEY_ARROW_UP) SerialTinyUSB.print("<ARROWUP>");
  if (code == HID_KEY_HOME) SerialTinyUSB.print("<HOME>");
  if (code == HID_KEY_KEYPAD_1) SerialTinyUSB.print("<KEYPAD_1>");
  if (code == HID_KEY_KEYPAD_2) SerialTinyUSB.print("<KEYPAD_2>");
  if (code == HID_KEY_KEYPAD_3) SerialTinyUSB.print("<KEYPAD_3>");
  if (code == HID_KEY_KEYPAD_4) SerialTinyUSB.print("<KEYPAD_4>");
  if (code == HID_KEY_KEYPAD_5) SerialTinyUSB.print("<KEYPAD_5>");
  if (code == HID_KEY_KEYPAD_6) SerialTinyUSB.print("<KEYPAD_6>");
  if (code == HID_KEY_KEYPAD_7) SerialTinyUSB.print("<KEYPAD_7>");
  if (code == HID_KEY_KEYPAD_8) SerialTinyUSB.print("<KEYPAD_8>");
  if (code == HID_KEY_KEYPAD_9) SerialTinyUSB.print("<KEYPAD_9>");
  if (code == HID_KEY_KEYPAD_0) SerialTinyUSB.print("<KEYPAD_0>");
  if (code == HID_KEY_F1) SerialTinyUSB.print("<F1>");
  if (code == HID_KEY_F2) SerialTinyUSB.print("<F2>");
  if (code == HID_KEY_F3) SerialTinyUSB.print("<F3>");
  if (code == HID_KEY_F4) SerialTinyUSB.print("<F4>");
  if (code == HID_KEY_F5) SerialTinyUSB.print("<F5>");
  if (code == HID_KEY_F6) SerialTinyUSB.print("<F6>");
  if (code == HID_KEY_F7) SerialTinyUSB.print("<F7>");
  if (code == HID_KEY_F8) SerialTinyUSB.print("<F8>");
  if (code == HID_KEY_F9) SerialTinyUSB.print("<F9>");
  if (code == HID_KEY_F10) SerialTinyUSB.print("<F10>");
  if (code == HID_KEY_F11) SerialTinyUSB.print("<F11>");
  if (code == HID_KEY_F12) SerialTinyUSB.print("<F12>");
  if (code == HID_KEY_PRINT_SCREEN) SerialTinyUSB.print("<PRNT>");
  if (code == HID_KEY_SCROLL_LOCK) SerialTinyUSB.print("<SCRLL>");
  if (code == HID_KEY_PAUSE) SerialTinyUSB.print("<PAUSE>");
  if (code == HID_KEY_INSERT) SerialTinyUSB.print("<INSERT>");
  if (code == HID_KEY_PAGE_UP) SerialTinyUSB.print("<PAGEUP>");
  if (code == HID_KEY_DELETE) SerialTinyUSB.print("<DEL>");
  if (code == HID_KEY_END) SerialTinyUSB.print("<END>");
  if (code == HID_KEY_PAGE_DOWN) SerialTinyUSB.print("<PAGEDOWN>");
  if (code == HID_KEY_NUM_LOCK) SerialTinyUSB.print("<ARROWRIGHT>");
  if (code == HID_KEY_KEYPAD_DIVIDE) SerialTinyUSB.print("<KEYPAD_DIV>");
  if (code == HID_KEY_KEYPAD_MULTIPLY) SerialTinyUSB.print("<KEYPAD_MUL>");
  if (code == HID_KEY_KEYPAD_SUBTRACT) SerialTinyUSB.print("<KEYPAD_SUB>");
  if (code == HID_KEY_KEYPAD_ADD) SerialTinyUSB.print("<KEYPAD_ADD>");
  if (code == HID_KEY_KEYPAD_DECIMAL) SerialTinyUSB.print("<KEYPAD_DECIMAL>");
}

static void process_mouse_report(hid_mouse_report_t const* report) {
  static hid_mouse_report_t prev_report = { 0 };

  //------------- button state  -------------//
  uint8_t button_changed_mask = report->buttons ^ prev_report.buttons;
  if (button_changed_mask & report->buttons) {
    SerialTinyUSB.printf("MOUSE: %c%c%c ",
                         report->buttons & MOUSE_BUTTON_LEFT ? 'L' : '-',
                         report->buttons & MOUSE_BUTTON_MIDDLE ? 'M' : '-',
                         report->buttons & MOUSE_BUTTON_RIGHT ? 'R' : '-');
  }

  cursor_movement(report->x, report->y, report->wheel);
}

void cursor_movement(int8_t x, int8_t y, int8_t wheel) {
  SerialTinyUSB.printf("(%d %d %d)\r\n", x, y, wheel);
}

void setNeoColor(uint8_t r, uint8_t g, uint8_t b) {
  statusPixel.setPixelColor(0, statusPixel.Color(r, g, b));
  statusPixel.show();
}

// END of BADUSB detector section

//
// OTHER Host devices detection section
//

// Invoked when a device with MassStorage interface is mounted
void tuh_msc_mount_cb(uint8_t dev_addr) {
  printout("\n[++] Mass Device");
  setNeoColor(0, 255, 0);  // Verde
  SerialTinyUSB.printf("Mass Device attached, address = %d\r\n", dev_addr);
}

// Invoked when a device with MassStorage interface is unmounted
void tuh_msc_umount_cb(uint8_t dev_addr) {
  SerialTinyUSB.printf("Mass Device unmounted, address = %d\r\n", dev_addr);
}

// Invoked when a device with CDC (Communication Device Class) interface is mounted
void tuh_cdc_mount_cb(uint8_t idx) {
  printout("\n[++] CDC Device");
  setNeoColor(0, 255, 0);  // Verde
  SerialTinyUSB.printf("CDC Device attached, idx = %d\r\n", idx);
}

// Invoked when a device with CDC (Communication Device Class) interface is unmounted
void tuh_cdc_umount_cb(uint8_t idx) {
  SerialTinyUSB.printf("CDC Device unmounted, idx = %d\r\n", idx);
}

// END of OTHER Host devices detector section
