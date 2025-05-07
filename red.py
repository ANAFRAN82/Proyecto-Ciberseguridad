import tkinter as tk
from tkinter import messagebox
from scapy.all import *
import threading
import os
import paramiko
from datetime import datetime
import binascii
from scp import SCPClient

def capturar_y_enviar():
    ip_objetivo = entry_ip.get().strip()
    interfaz = entry_interfaz.get().strip()
    remote_host = entry_remote_host.get().strip()
    remote_user = entry_remote_user.get().strip()
    remote_pass = entry_remote_pass.get().strip()
    remote_path = entry_remote_path.get().strip()
    
    # Validar campos requeridos
    if not ip_objetivo or not interfaz:
        messagebox.showerror("Error", "Debes completar la IP y la interfaz.")
        return
    
    resultado.delete(1.0, tk.END)
    resultado.insert(tk.END, f"[📡] Iniciando captura para la IP {ip_objetivo} en {interfaz}...\n")
    
    def captura():
        try:
            # Filtro BPF para la IP específica
            filtro = f"host {ip_objetivo}"
            # Capturar con timeout de 10 segundos
            paquetes = sniff(iface=interfaz, filter=filtro, timeout=10)
            
            if not paquetes:
                resultado.insert(tk.END, f"[⚠] No se capturaron paquetes en 10 segundos para la IP {ip_objetivo}.\n")
                return
            
            # Preparar archivo de texto plano
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            nombre_texto = f"captura_texto_{timestamp}.txt"
            nombre_pcap = f"captura_remota_{timestamp}.pcap"
            
            with open(nombre_texto, 'w', encoding='utf-8') as f:
                f.write(f"Captura de tráfico para IP {ip_objetivo} - {datetime.now()}\n")
                f.write("Solo paquetes HTTP (puerto 80) con payloads en texto plano\n\n")
            
            # Mostrar contenido completo de cada paquete en la GUI
            http_count = 0
            for i, paquete in enumerate(paquetes, 1):
                resultado.insert(tk.END, f"\n--- Paquete {i} ---\n")
                
                # Información básica
                if IP in paquete:
                    src = paquete[IP].src
                    dst = paquete[IP].dst
                    proto = "Desconocido"
                    src_port = dst_port = "N/A"
                    
                    # Identificar protocolo y puertos
                    if TCP in paquete:
                        proto = "TCP"
                        src_port = paquete[TCP].sport
                        dst_port = paquete[TCP].dport
                    elif UDP in paquete:
                        proto = "UDP"
                        src_port = paquete[UDP].sport
                        dst_port = paquete[UDP].dport
                    elif ICMP in paquete:
                        proto = "ICMP"
                    
                    resultado.insert(tk.END, f"Origen: {src}:{src_port}\n")
                    resultado.insert(tk.END, f"Destino: {dst}:{dst_port}\n")
                    resultado.insert(tk.END, f"Protocolo: {proto}\n")
                
                # Mostrar todas las capas del paquete
                resultado.insert(tk.END, "Capas: " + ", ".join(paquete.layers().__str__().split("'")[1::2]) + "\n")
                
                # Mostrar payload (texto plano o hexadecimal)
                if Raw in paquete:
                    raw_data = paquete[Raw].load
                    try:
                        texto_plano = raw_data.decode('utf-8', errors='ignore')
                        resultado.insert(tk.END, f"Payload (Texto plano): {texto_plano[:100]}...\n")
                    except:
                        hex_data = binascii.hexlify(raw_data).decode('ascii')
                        resultado.insert(tk.END, f"Payload (Hex): {hex_data[:100]}...\n")
                
                # Guardar en archivo plano solo paquetes HTTP (puerto 80) con texto plano
                if TCP in paquete and paquete[TCP].dport == 80 and Raw in paquete:
                    try:
                        texto_plano = paquete[Raw].load.decode('utf-8', errors='ignore')
                        with open(nombre_texto, 'a', encoding='utf-8') as f:
                            f.write(f"--- Paquete HTTP {http_count + 1} ---\n")
                            f.write(f"Origen: {src}:{src_port}\n")
                            f.write(f"Destino: {dst}:{dst_port}\n")
                            f.write(f"Protocolo: TCP (HTTP)\n")
                            f.write(f"Payload (Texto plano): {texto_plano[:500]}...\n")
                            f.write("\n")
                        http_count += 1
                    except:
                        pass
                
                # Mostrar detalles completos del paquete en la GUI
                resultado.insert(tk.END, f"Resumen completo:\n{paquete.show(dump=True)}\n")
            
            # Guardar paquetes en archivo .pcap
            wrpcap(nombre_pcap, paquetes)
            resultado.insert(tk.END, f"[✔] Captura guardada localmente en {nombre_pcap}\n")
            resultado.insert(tk.END, f"[✔] Datos HTTP guardados en {nombre_texto} ({http_count} paquetes)\n")
            
            # Enviar ambos archivos a equipo remoto si se proporcionaron datos
            if remote_host and remote_user and remote_pass and remote_path:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=remote_host, username=remote_user, password=remote_pass, port=22)
                    with SCPClient(ssh.get_transport()) as scp:
                        scp.put([nombre_pcap, nombre_texto], remote_path)
                    ssh.close()
                    resultado.insert(tk.END, f"[✅] Archivos enviados a {remote_host}:{remote_path}/\n")
                except Exception as e:
                    resultado.insert(tk.END, f"[❌] Error al enviar al equipo remoto: {e}\n")
                    messagebox.showerror("Error", f"Error al enviar al equipo remoto: {e}")
        
        except PermissionError:
            resultado.insert(tk.END, "[❌] Error: Permisos insuficientes. Ejecuta con 'sudo'.\n")
            messagebox.showerror("Error", "Permisos insuficientes. Ejecuta con 'sudo'.")
        except Exception as e:
            resultado.insert(tk.END, f"[❌] Error durante la captura: {e}\n")
            messagebox.showerror("Error", f"Error durante la captura: {e}")
    
    threading.Thread(target=captura, daemon=True).start()

# Configuración de la interfaz gráfica
ventana = tk.Tk()
ventana.title("Sniffer de Red para IP Específica")
ventana.geometry("700x700")

# Campos de entrada
tk.Label(ventana, text="=== Sniffer de Red ===").grid(row=0, column=0, columnspan=2, pady=10)
tk.Label(ventana, text="IP objetivo (ej. 192.168.1.1):").grid(row=1, column=0, pady=5, padx=5)
entry_ip = tk.Entry(ventana, width=20)
entry_ip.grid(row=1, column=1, pady=5)

tk.Label(ventana, text="Interfaz de red (ej. wlan0):").grid(row=2, column=0, pady=5, padx=5)
entry_interfaz = tk.Entry(ventana, width=20)
entry_interfaz.grid(row=2, column=1, pady=5)

tk.Label(ventana, text="Configuración de equipo remoto (dejar en blanco si no se usa):").grid(row=3, column=0, columnspan=2, pady=5)
tk.Label(ventana, text="Host remoto (IP o hostname):").grid(row=4, column=0, pady=5, padx=5)
entry_remote_host = tk.Entry(ventana, width=20)
entry_remote_host.grid(row=4, column=1, pady=5)

tk.Label(ventana, text="Usuario remoto:").grid(row=5, column=0, pady=5, padx=5)
entry_remote_user = tk.Entry(ventana, width=20)
entry_remote_user.grid(row=5, column=1, pady=5)

tk.Label(ventana, text="Contraseña remota:").grid(row=6, column=0, pady=5, padx=5)
entry_remote_pass = tk.Entry(ventana, width=20, show="*")
entry_remote_pass.grid(row=6, column=1, pady=5)

tk.Label(ventana, text="Ruta destino remota (ej. /home/user/capturas):").grid(row=7, column=0, pady=5, padx=5)
entry_remote_path = tk.Entry(ventana, width=20)
entry_remote_path.grid(row=7, column=1, pady=5)

# Botón para iniciar
tk.Button(ventana, text="Iniciar Captura", command=capturar_y_enviar).grid(row=8, column=0, columnspan=2, pady=10)

# Área de resultados
tk.Label(ventana, text="Resultados:").grid(row=9, column=0, columnspan=2)
resultado = tk.Text(ventana, height=25, width=80)
resultado.grid(row=10, column=0, columnspan=2, padx=5, pady=5)

ventana.mainloop()