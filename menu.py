import tkinter as tk
from tkinter import ttk
import subprocess

def ejecutar_archivo(nombre_archivo):
    try:
        subprocess.run(["python", nombre_archivo], check=True)
    except FileNotFoundError:
        print(f"Error: {nombre_archivo} no encontrado.")
    except Exception as e:
        print(f"Error al ejecutar {nombre_archivo}: {e}")

def salir():
    ventana.quit()

# Configuración de la interfaz
ventana = tk.Tk()
ventana.title("Menú de Archivos Python")
ventana.geometry("300x250")
ventana.configure(bg="#2C3E50")  # Fondo oscuro

# Estilo de botones y etiquetas
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), background="#2980B9", foreground="white")
style.configure("TLabel", font=("Arial", 14), background="#2C3E50", foreground="white")

# Etiqueta de bienvenida
ttk.Label(ventana, text="Selecciona un archivo para ejecutar:", style="TLabel").pack(pady=20)

# Botones para ejecutar los archivos
btn1 = ttk.Button(ventana, text="Escanear Puertos", command=lambda: ejecutar_archivo("escaneo.py"))
btn1.pack(pady=10)

btn2 = ttk.Button(ventana, text="Generar contrasenias seguras", command=lambda: ejecutar_archivo("contrsenias.py"))
btn2.pack(pady=10)

btn3 = ttk.Button(ventana, text="Sniffer", command=lambda: ejecutar_archivo("red.py"))
btn3.pack(pady=10)

btn3 = ttk.Button(ventana, text="Keylogger", command=lambda: ejecutar_archivo("keylogger_test/server.py"))
btn3.pack(pady=10)

# Botón para salir
btn4 = ttk.Button(ventana, text="Salir", command=salir)
btn4.pack(pady=10)

ventana.mainloop()
