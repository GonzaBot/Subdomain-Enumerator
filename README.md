Aquí lo tienes limpio y listo en **Markdown puro** para copiar:

````markdown
# SubDomEnum 🔍

**SubDomEnum** es una herramienta de reconocimiento y enumeración de subdominios diseñada para ser rápida, eficiente y extremadamente fácil de usar. Combina la potencia del descubrimiento pasivo (vía `crt.sh`) con la fuerza bruta activa y validación en tiempo real.

---

## ✨ Características Principales

* 📦 **Gestión Automática:** El launcher verifica e instala las dependencias (`requests`, `rich`, `urllib3`) por ti.
* 💬 **Modo Interactivo:** No necesitas recordar comandos complejos; sigue las instrucciones en pantalla.
* 🚀 **Híbrido y Veloz:** Usa hilos (*threading*) para validar cientos de subdominios en segundos.
* ✅ **Validación Real:** Comprobación de estado HTTP/HTTPS y resolución de direcciones IP.

---

## 🛠️ Instalación y Uso

### Opción A: Modo Fácil (Recomendado) 🌟
Ideal para una ejecución rápida e interactiva. El script se encargará de preparar el entorno y te preguntará el dominio y el tipo de reporte que deseas:

```bash
python run.py
```

### Opción B: Modo Avanzado (Línea de Comandos) 💻

Si prefieres integrar la herramienta en tus propios scripts o pipelines de reconocimiento:

```bash
python SubDomEnum.py dominio.com [opciones]
```

**Ejemplos:**

* **Reporte completo:** `python SubDomEnum.py target.com --html mi_auditoria --csv resultados`
* **Escaneo agresivo:** `python SubDomEnum.py target.com -t 150 --no-validate`
* **Wordlist externa:** `python SubDomEnum.py target.com -w /ruta/diccionario.txt`

---

## ⚙️ Parámetros Técnicos

| Argumento | Descripción | Default |
| :--- | :--- | :--- |
| `domain` | Dominio objetivo (ej: google.com). | *Requerido* |
| `-w, --wordlist` | Ruta a una wordlist externa (opcional). | Interna |
| `-t, --threads` | Cantidad de hilos concurrentes. | 50 |
| `--timeout` | Tiempo de espera para peticiones HTTP (segundos). | 5 |
| `--no-validate` | Salta la validación HTTP/HTTPS (solo muestra hallazgos). | False |
| `--json` | Exporta los resultados en formato JSON. | None |
| `--csv` | Exporta los resultados en formato CSV. | None |
| `--html` | Genera un reporte visual detallado. | None |

---

## 📊 Formatos de Reporte

* **HTML:** Un reporte elegante con estadísticas, códigos de estado (200, 404, etc.) e IPs resueltas.
* **JSON/CSV:** Formatos estructurados listos para ser importados en otras herramientas de auditoría o bases de datos.
* **Terminal:** Salida visualmente organizada gracias a la librería `rich`.

---

## 📂 Estructura del Proyecto

* `SubDomEnum.py`: El núcleo de la herramienta (lógica de escaneo y validación).
* `run.py`: Launcher interactivo y gestor de dependencias.
* `requirements.txt`: (Opcional) Listado de dependencias para instalación manual.

---

## ⚠️ Aviso Legal

> Esta herramienta ha sido creada con fines exclusivamente **educativos y de auditoría ética**. El uso de **SubDomEnum** para atacar objetivos sin autorización previa es ilegal y responsabilidad única del usuario final.

---

**Desarrollado para proyectos de Ciberseguridad y Pentesting Ético.** 🚀
````
