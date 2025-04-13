# 🔎 Auditoría DNS con Python y Shodan

Este proyecto permite realizar una auditoría automatizada de servidores DNS expuestos, utilizando la API de Shodan y herramientas de análisis DNS.

> ⚠️ **Uso exclusivo con fines académicos y éticos. No ejecutar sobre redes o dispositivos sin autorización expresa.**

## 🚀 Funcionalidades

La herramienta realiza un análisis de servidores DNS en dos niveles:

### 🔍 Análisis Básico

- Búsqueda de servidores con puerto 53 abierto utilizando la API de Shodan.

### 🧠 Análisis Avanzado

- **Recursividad:** Detecta si el servidor permite consultas recursivas desde IPs externas.
- **Amplificación DNS:** Realiza una consulta tipo `ANY` y evalúa el tamaño de la respuesta.

---

## 📦 Requisitos

- Python 3.x
- API Key de [Shodan](https://www.shodan.io/)
- Librerías de Python:

---

## ⚙️ Ejecución Paso a Paso

1. Clona el repositorio:
   ```bash
   git clone https://github.com/aliss-55/DNS-Script-con-IA-.git
   ```

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

---
