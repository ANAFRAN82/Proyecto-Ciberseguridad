import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string

def generar_contraseña(longitud):
    if longitud < 8:
        messagebox.showerror("Error", "La longitud mínima debe ser 8 caracteres.")
        return None
    
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))

def generar():
    try:
        cantidad = int(entry_cantidad.get())
        longitud = int(entry_longitud.get())
        
        resultado.config(state=tk.NORMAL)
        resultado.delete(1.0, tk.END)
        
        for _ in range(cantidad):
            contraseña = generar_contraseña(longitud)
            if contraseña:
                resultado.insert(tk.END, f"{contraseña}\n")
        
        resultado.config(state=tk.DISABLED)
    except ValueError:
        messagebox.showerror("Error", "Ingrese valores numéricos válidos para cantidad y longitud.")

# Configuración de la interfaz
ventana = tk.Tk()
ventana.title("Generador de Contraseñas Seguras")
ventana.geometry("420x450")
ventana.resizable(False, False)
ventana.configure(bg="#2C3E50")

# Estilos
style = ttk.Style()
style.configure("TLabel", font=("Arial", 12), background="#2C3E50", foreground="white")
style.configure("TButton", font=("Arial", 12), background="#2980B9", foreground="white")
style.configure("TEntry", font=("Arial", 12))

# Encabezado
ttk.Label(ventana, text="Generador de Contraseñas", font=("Arial", 16, "bold")).pack(pady=10)

# Entrada de cantidad
ttk.Label(ventana, text="Cantidad de contraseñas:").pack()
entry_cantidad = ttk.Entry(ventana, width=10)
entry_cantidad.pack(pady=5)

# Entrada de longitud
ttk.Label(ventana, text="Longitud de las contraseñas:").pack()
entry_longitud = ttk.Entry(ventana, width=10)
entry_longitud.pack(pady=5)

# Botón para generar
boton_generar = ttk.Button(ventana, text="Generar", command=generar)
boton_generar.pack(pady=10)

# Área de resultados
ttk.Label(ventana, text="Contraseñas generadas:").pack()
resultado = tk.Text(ventana, height=12, width=50, font=("Courier", 10), state=tk.DISABLED, bg="#ECF0F1")
resultado.pack(padx=5, pady=5)

# Iniciar la ventana
ventana.mainloop()