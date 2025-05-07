import tkinter as tk
from tkinter import messagebox
import nmap

def escanear_puertos():
    objetivo = entry_objetivo.get().strip()
    opcion = var_opcion.get()
    
    # Limpiar el área de resultados
    resultado.delete(1.0, tk.END)
    resultado.insert(tk.END, f"--- Escaneo de Puertos con nmap ---\n")
    
    if not objetivo:
        resultado.insert(tk.END, "Error: Debe ingresar una IP o hostname válido.\n")
        messagebox.showerror("Error", "Ingrese una IP o hostname válido.")
        return
    
    try:
        nm = nmap.PortScanner()
        
        if opcion == 1:  # Puerto específico
            puerto = entry_puerto.get().strip()
            if not puerto.isdigit() or int(puerto) < 1 or int(puerto) > 65535:
                resultado.insert(tk.END, "Error: El puerto debe ser un número entre 1 y 65535.\n")
                messagebox.showerror("Error", "El puerto debe ser un número entre 1 y 65535.")
                return
            resultado.insert(tk.END, f"Escaneando puerto {puerto} en {objetivo}...\n")
            nm.scan(objetivo, puerto)
        elif opcion == 2:  # Rango de puertos
            rango = entry_rango.get().strip()
            if not '-' in rango or not all(part.isdigit() for part in rango.split('-')):
                resultado.insert(tk.END, "Error: El rango debe tener el formato 'inicio-fin' (ej. 1-1024).\n")
                messagebox.showerror("Error", "El rango debe tener el formato 'inicio-fin' (ej. 1-1024).")
                return
            inicio, fin = map(int, rango.split('-'))
            if inicio < 1 or fin > 65535 or inicio > fin:
                resultado.insert(tk.END, "Error: El rango debe estar entre 1 y 65535 y el inicio debe ser menor o igual al fin.\n")
                messagebox.showerror("Error", "El rango debe estar entre 1 y 65535 y el inicio debe ser menor o igual al fin.")
                return
            resultado.insert(tk.END, f"Escaneando rango {rango} en {objetivo}...\n")
            nm.scan(objetivo, rango)
        elif opcion == 3:  # Todos los puertos
            resultado.insert(tk.END, f"Escaneando todos los puertos (1-65535) en {objetivo}...\n")
            nm.scan(objetivo, '1-65535')
        else:
            resultado.insert(tk.END, "Opción no válida. Por favor, seleccione 1, 2 o 3.\n")
            return

        # Verificar si el escaneo fue exitoso
        if objetivo not in nm.all_hosts():
            resultado.insert(tk.END, f"No se pudo escanear {objetivo}. Verifique la conexión o la validez del objetivo.\n")
            return

        # Mostrar resultados
        resultado.insert(tk.END, f"\nResultados para {objetivo}:\n")
        for host in nm.all_hosts():
            resultado.insert(tk.END, f"Host: {host}\n")
            if not nm[host].all_protocols():
                resultado.insert(tk.END, "No se encontraron protocolos disponibles.\n")
                continue
            for proto in nm[host].all_protocols():  # Corrección aquí
                resultado.insert(tk.END, f"Protocolo: {proto}\n")
                lport = nm[host][proto].keys()
                puertos_abiertos = False
                for port in lport:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        resultado.insert(tk.END, f"Puerto {port}: {state}\n")
                        puertos_abiertos = True
                if not puertos_abiertos:
                    resultado.insert(tk.END, "No se encontraron puertos abiertos para este protocolo.\n")
    except ValueError as e:
        resultado.insert(tk.END, f"Error: Entrada inválida - {e}\n")
        messagebox.showerror("Error", f"Entrada inválida: {e}")
    except Exception as e:
        resultado.insert(tk.END, f"Error durante el escaneo: {e}\n")
        messagebox.showerror("Error", f"Error durante el escaneo: {e}")

# Configuración de la interfaz
ventana = tk.Tk()
ventana.title("Escaneo de Puertos con Nmap")
ventana.geometry("500x500")

# Campo para el objetivo
tk.Label(ventana, text="Ingrese la IP o hostname del objetivo:").grid(row=0, column=0, columnspan=2, pady=5)
entry_objetivo = tk.Entry(ventana, width=30)
entry_objetivo.grid(row=1, column=0, columnspan=2, padx=5)

# Opciones de escaneo
tk.Label(ventana, text="Opciones de escaneo:").grid(row=2, column=0, columnspan=2, pady=5)
var_opcion = tk.IntVar(value=1)
tk.Radiobutton(ventana, text="1. Escanear un puerto específico", variable=var_opcion, value=1).grid(row=3, column=0, columnspan=2, sticky="w", padx=5)
tk.Radiobutton(ventana, text="2. Escanear un rango de puertos", variable=var_opcion, value=2).grid(row=4, column=0, columnspan=2, sticky="w", padx=5)
tk.Radiobutton(ventana, text="3. Escanear todos los puertos", variable=var_opcion, value=3).grid(row=5, column=0, columnspan=2, sticky="w", padx=5)

# Campo para puerto específico
tk.Label(ventana, text="Puerto a escanear:").grid(row=6, column=0, pady=5)
entry_puerto = tk.Entry(ventana, width=10)
entry_puerto.grid(row=6, column=1, padx=5)

# Campo para rango de puertos
tk.Label(ventana, text="Rango de puertos:").grid(row=7, column=0, pady=5)
entry_rango = tk.Entry(ventana, width=20)
entry_rango.grid(row=7, column=1, padx=5)

# Botón para escanear
tk.Button(ventana, text="Escanear", command=escanear_puertos).grid(row=8, column=0, columnspan=2, pady=10)

# Área de resultados
tk.Label(ventana, text="Resultados:").grid(row=9, column=0, columnspan=2)
resultado = tk.Text(ventana, height=20, width=60)
resultado.grid(row=10, column=0, columnspan=2, padx=5, pady=5)

# Iniciar la ventana
ventana.mainloop()