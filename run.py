#!/usr/bin/env python3
"""
run.py — Launcher de subenum
Instala dependencias automaticamente si no estan, luego corre la tool.
Funciona en Windows, Linux y macOS.
"""

import subprocess
import sys
import os

REQUIRED = ["requests", "rich", "urllib3"]

# Nombre real del archivo principal — cambialo si lo renombraste
MAIN_SCRIPT = "SubDomEnum.py"

def check_and_install():
    missing = []
    for pkg in REQUIRED:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", pkg],
            capture_output=True
        )
        if result.returncode != 0:
            missing.append(pkg)

    if missing:
        print(f"[*] Instalando: {', '.join(missing)} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        print("[OK] Dependencias instaladas.\n")
    else:
        print("[OK] Dependencias listas.\n")

def ask(prompt, default=None):
    val = input(prompt).strip()
    return val if val else default

def main():
    # Verificar que el script principal existe
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), MAIN_SCRIPT)
    if not os.path.exists(script_path):
        print(f"[!] No se encontro {MAIN_SCRIPT} en la misma carpeta que run.py")
        print(f"    Ruta buscada: {script_path}")
        input("\nPresiona Enter para salir...")
        sys.exit(1)

    check_and_install()

    print("=" * 40)
    print("  subenum — Subdomain Enumerator")
    print("=" * 40)
    print()

    dominio = ask("[?] Dominio objetivo (ej: example.com): ")
    if not dominio:
        print("[!] Dominio requerido.")
        input("\nPresiona Enter para salir...")
        sys.exit(1)

    reporte = ask("[?] Generar reporte HTML? (s/n): ").lower()

    cmd = [sys.executable, script_path, dominio]

    if reporte == "s":
        nombre = ask("[?] Nombre del archivo (sin extension): ", default="reporte")
        cmd += ["--html", nombre]

    print()
    subprocess.run(cmd)
    input("\nPresiona Enter para salir...")

if __name__ == "__main__":
    main()
