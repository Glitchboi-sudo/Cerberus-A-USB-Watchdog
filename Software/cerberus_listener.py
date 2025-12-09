"""
Listener con interfaz gráfica para Cerberus.

- Intenta detectar automáticamente el puerto por VID/PID o pistas de nombre.
- Si no lo encuentra, permite seleccionar manualmente entre los puertos disponibles.
- Muestra las líneas recibidas en una ventana con scroll.

Requisitos: pyserial (`pip install pyserial`)
"""
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from serial import Serial
    from serial.tools import list_ports
except ImportError:
    sys.stderr.write("Falta pyserial. Instala con: pip install pyserial\n")
    sys.exit(1)

# Ajusta estos valores si cambiaste los IDs o las cadenas USB
TARGET_VID = 0x0951
TARGET_PID = 0x16D5
NAME_HINTS = ("Cerberus", "Kingston", "DataTraveler")


def pick_port(ports):
    """Busca el primer puerto que coincida con VID/PID o pistas de nombre."""
    for p in ports:
        if p.vid == TARGET_VID and p.pid == TARGET_PID:
            return p
    for p in ports:
        name = (p.description or "") + " " + (p.manufacturer or "")
        if any(hint.lower() in name.lower() for hint in NAME_HINTS):
            return p
    return None


class CerberusGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cerberus Listener")
        self.geometry("720x480")

        self.port_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Sin conectar")
        self.serial = None
        self.stop_event = threading.Event()
        self.reader_thread = None

        self._build_ui()
        self._refresh_ports(auto_select=True)

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(header, text="Cerberus Watchdog", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(header, textvariable=self.status_var, foreground="#0A6CFF").pack(side="right")

        top = ttk.LabelFrame(self, text="Conexión")
        top.pack(fill="x", padx=10, pady=4)

        ttk.Label(top, text="Puerto:").pack(side="left")
        self.port_combo = ttk.Combobox(top, textvariable=self.port_var, state="readonly", width=35)
        self.port_combo.pack(side="left", padx=4)

        ttk.Button(top, text="Refrescar", command=self._refresh_ports).pack(side="left", padx=4)
        self.connect_btn = ttk.Button(top, text="Conectar", command=self.toggle_connection)
        self.connect_btn.pack(side="left", padx=4)
        ttk.Button(top, text="Guardar log...", command=self.save_log).pack(side="left", padx=4)

        text_frame = ttk.Frame(self)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.text = tk.Text(
            text_frame,
            wrap="word",
            state="disabled",
            font=("Consolas", 10),
            bg="#0c0c0c",
            fg="#e5e5e5",
            insertbackground="#e5e5e5",
        )
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def log(self, msg):
        self.text.configure(state="normal")
        self.text.insert("end", msg)
        self.text.see("end")
        self.text.configure(state="disabled")

    def save_log(self):
        content = self.text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("Guardar log", "No hay texto para guardar.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")],
            title="Guardar log de Cerberus",
        )
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Guardar log", f"Guardado en:\n{filename}")
            except OSError as exc:
                messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{exc}")

    def _refresh_ports(self, auto_select=False):
        ports = list_ports.comports()
        display_list = [f"{p.device} - {p.description}" for p in ports]
        self.port_combo["values"] = display_list

        chosen = pick_port(ports) if auto_select else None
        if chosen:
            self.port_var.set(f"{chosen.device} - {chosen.description}")
            self.status_var.set(f"Auto: {chosen.device}")
        elif display_list:
            self.port_var.set(display_list[0])
            self.status_var.set("Selecciona un puerto")
        else:
            self.port_var.set("")
            self.status_var.set("No hay puertos")

    def toggle_connection(self):
        if self.serial:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        selection = self.port_var.get()
        if not selection:
            messagebox.showerror("Error", "No hay puerto seleccionado.")
            return
        device = selection.split(" - ")[0]
        try:
            self.serial = Serial(device, baudrate=115200, timeout=0.2)
        except OSError as exc:
            messagebox.showerror("Error", f"No se pudo abrir {device}:\n{exc}")
            self.serial = None
            return

        self.status_var.set(f"Conectado a {device}")
        self.connect_btn.configure(text="Desconectar")
        self.stop_event.clear()
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self.log(f"\n--- Abierto {device} ---\n")

    def disconnect(self):
        self.stop_event.set()
        if self.reader_thread:
            self.reader_thread.join(timeout=1)
            self.reader_thread = None
        if self.serial:
            try:
                self.serial.close()
            except OSError:
                pass
            self.serial = None
        self.status_var.set("Sin conectar")
        self.connect_btn.configure(text="Conectar")
        self.log("\n--- Desconectado ---\n")

    def _reader_loop(self):
        while not self.stop_event.is_set():
            try:
                line = self.serial.readline()
            except OSError as exc:
                self.after(0, lambda: messagebox.showerror("Error", f"Lectura falló: {exc}"))
                self.after(0, self.disconnect)
                break
            if line:
                try:
                    decoded = line.decode(errors="replace")
                except Exception:
                    decoded = repr(line)
                self.after(0, lambda d=decoded: self.log(d))
            else:
                time.sleep(0.05)

    def on_close(self):
        self.disconnect()
        self.destroy()


def main():
    app = CerberusGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
