import tkinter as tk
from tkinter import messagebox
import re


# Funciones de análisis
def analizar_remitente(remitente):
    """Analiza el dominio del remitente"""
    dominio = remitente.split('@')[-1]
    dominios_sospechosos = ['example.com', 'fakesite.com', 'phishingdomain.com', 'fraudsite.net', 'scamsite.org', 'malicious.com']
    if dominio in dominios_sospechosos:
        return "Sospechoso"
    return "Seguro"


def analizar_asunto(asunto):
    """Analiza el asunto para encontrar palabras sospechosas"""
    palabras_sospechosas = ['URGENTE', 'ACTUALIZA TU CUENTA', 'CONFIRMA TU INFORMACION', 'PRIVILEGIADO', 'HURGENCIA', 'ACTIVAR', 'CONFIRMAR', 'OFERTA EXCLUSIVA', 'RECLAMAR AHORA']
    for palabra in palabras_sospechosas:
        if re.search(palabra, asunto, re.IGNORECASE):
            return "Sospechoso"
    return "Seguro"


def verificar_enlaces(cuerpo_email):
    """Verifica si el cuerpo del email contiene enlaces sospechosos"""
    enlaces_sospechosos = ['fakesite.com', 'malicious.com', 'example.com', 'phishingsite.org', 'dangerouslink.net']
    enlaces_encontrados = re.findall(r'(https?://\S+)', cuerpo_email)
    for enlace in enlaces_encontrados:
        for dominio in enlaces_sospechosos:
            if dominio in enlace:
                return "Sospechoso"
    return "Seguro"


def comprobar_adjuntos(adjuntos):
    """Verifica si los archivos adjuntos tienen extensiones peligrosas"""
    extensiones_peligrosas = ['.exe', '.vbs', '.bat', '.scr', '.js', '.pif', '.com', '.dll', '.wsf', '.jse']
    for archivo in adjuntos:
        if any(archivo.endswith(ext) for ext in extensiones_peligrosas):
            return "Sospechoso"
    return "Seguro"


def comprobar_dominio(remitente):
    """Verifica si el dominio del remitente es sospechoso"""
    dominio = remitente.split('@')[-1]
    dominios_legitimos = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com']
    if dominio not in dominios_legitimos:
        return "Sospechoso"
    return "Seguro"


# Función para manejar el análisis cuando el usuario hace clic en el botón
def analizar_correo():
    """Función que recoge los datos y muestra los resultados del análisis"""
    # Obtener los valores del formulario
    remitente = entry_remitente.get()
    asunto = entry_asunto.get()
    cuerpo = text_cuerpo.get("1.0", "end-1c")  # Obtener el cuerpo del correo
    adjuntos = entry_adjuntos.get()


    # Validar que todos los campos requeridos estén completos
    if not remitente or not asunto or not cuerpo:
        messagebox.showerror("Error", "Por favor, completa todos los campos.")
        return


    # Realizar el análisis
    resultado_remitente = analizar_remitente(remitente)
    resultado_asunto = analizar_asunto(asunto)
    resultado_enlaces = verificar_enlaces(cuerpo)
    resultado_adjuntos = comprobar_adjuntos(adjuntos.split(','))
    resultado_dominio = comprobar_dominio(remitente)


    # Mostrar los resultados en la interfaz (ventana de texto)
    resultado_texto = f"Remitente: {resultado_remitente}\n"
    resultado_texto += f"Asunto: {resultado_asunto}\n"
    resultado_texto += f"Enlaces: {resultado_enlaces}\n"
    resultado_texto += f"Adjuntos: {resultado_adjuntos}\n"
    resultado_texto += f"Dominio: {resultado_dominio}"


    text_resultados.config(state=tk.NORMAL)  # Habilitar el widget de texto
    text_resultados.delete(1.0, tk.END)  # Limpiar el área de resultados
    text_resultados.insert(tk.END, resultado_texto)  # Insertar los resultados
    text_resultados.config(state=tk.DISABLED)  # Deshabilitar la edición del widget de texto


# Función para verificar si el correo electrónico tiene un formato válido
def es_correo_valido(correo):
    """Verifica que el correo ingresado tenga un formato válido"""
    patron = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(patron, correo) is not None


# Crear la ventana principal
root = tk.Tk()
root.title("Detector de phishing")


# Crear los widgets (etiquetas, entradas, etc.)
label_remitente = tk.Label(root, text="Remitente (Correo Electrónico):")
label_remitente.pack(padx=10, pady=5)


entry_remitente = tk.Entry(root, width=50)
entry_remitente.pack(padx=10, pady=5)


label_asunto = tk.Label(root, text="Asunto del Correo:")
label_asunto.pack(padx=10, pady=5)


entry_asunto = tk.Entry(root, width=50)
entry_asunto.pack(padx=10, pady=5)


label_cuerpo = tk.Label(root, text="Cuerpo del Correo:")
label_cuerpo.pack(padx=10, pady=5)


text_cuerpo = tk.Text(root, width=50, height=10)
text_cuerpo.pack(padx=10, pady=5)


label_adjuntos = tk.Label(root, text="Archivos Adjuntos (separados por comas):")
label_adjuntos.pack(padx=10, pady=5)


entry_adjuntos = tk.Entry(root, width=50)
entry_adjuntos.pack(padx=10, pady=5)


# Crear el botón para analizar el correo
boton_analizar = tk.Button(root, text="Analizar Correo", command=analizar_correo)
boton_analizar.pack(padx=10, pady=20)


# Área para mostrar los resultados
label_resultados = tk.Label(root, text="Resultados del Análisis:")
label_resultados.pack(padx=10, pady=5)


text_resultados = tk.Text(root, width=50, height=10, wrap=tk.WORD, state=tk.DISABLED)
text_resultados.pack(padx=10, pady=5)


# Ejecutar la aplicación
root.mainloop()

