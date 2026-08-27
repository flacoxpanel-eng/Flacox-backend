import os
import tarfile
import zipfile
import tempfile
from typing import List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="FLACO X Forensic Engine", version="8.5")

# Permitir conexiones desde GitHub Pages o cualquier cliente
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lista de Keys VIP válidas
VALID_KEYS = [
    "FLACOX-VIP-S9RRY8",
    "FLACOX-VIP-ADMIN",
    "FLACOX-VIP-TEST"
]

# Diccionario de firma de patrones por categoría
CATEGORY_RULES = {
    "PROXY DNS": ["dns", "dnsproxyd", "nextdns", "adguard", "dnscloak", "1.1.1.1", "quad9"],
    "FREE FIRE": ["com.dts.freefireth", "freefire", "ff.app", "shadowrealm"],
    "FREE FIRE MAX": ["com.dts.freefiremax", "freefiremax", "ffmax"],
    "FILZA": ["com.tigersoftware.filza", "filza", "filza.app"],
    "FILZA IOS 27": ["filza27", "filza_ios27", "com.filza.ios27"],
    "TROLLSTORE": ["com.opa334.trollstore", "trollstore", "trollstorehelper", "trollstore.app"],
    "IPA Y TIPA": [".ipa", ".tipa", "payload/", "application.app"],
    "AIMBOT": ["aimbot", "silentaim", "aimlock", "autoaim", "aim_helper", "headshot_hook"],
    "Flork": ["flork", "flork_cheat", "flork_injector", "flork_mod"],
    "EXTERNAL": ["external", "external_overlay", "esp_external", "esp_overlay", "cheat_external"],
    "Bypass": ["bypass", "anti-anti-cheat", "bypass_guard", "jb_bypass", "shadow_bypass", "choicy"],
    "Trollsfol": ["trollsfol", "trolls_fool", "trollfool", "com.trollfool"],
    "Jailbreak": ["jailbreak", "cydia", "substitute", "substrate", "ellekit", "libhooker"],
    "Sileo": ["org.coolstar.sileo", "sileo", "sileo.app"],
    "Dopamine": ["com.opa334.dopamine", "dopamine", "dopamine.app"],
    "Paleran": ["palera1n", "palerain", "palera1n_helper"],
    "Proxy cheast": ["proxy_cheat", "charles", "mitmproxy", "httpcacher", "burp", "proxyman"],
    "Ipa": ["custom_ipa", "signed_ipa", "sideloaded_ipa"],
    "Relojeo": ["time_tamper", "clock_manipulation", "ntp_cheat", "relojeo", "speedhack_time"]
}

@app.get("/")
def read_root():
    return {"status": "online", "system": "FLACO X Forensic Engine v8.5 Ready"}

@app.post("/scan")
async def scan_file(
    key: str = Form(...),
    serial: str = Form(None),
    file: UploadFile = File(...)
):
    # 1. Validación de Key VIP
    if key not in VALID_KEYS:
        raise HTTPException(status_code=401, detail="Clave VIP de acceso inválida o expirada.")

    if not file:
        raise HTTPException(status_code=400, detail="No se ha recibido ningún archivo de diagnóstico.")

    # 2. Guardar y procesar archivo temporalmente
    file_matches: Dict[str, List[str]] = {cat: [] for cat in CATEGORY_RULES}
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path = os.path.join(temp_dir, file.filename)
        with open(temp_file_path, "wb") as buffer:
            buffer.write(await file.read())

        extracted_files = []
        try:
            if file.filename.endswith(".tar.gz") or file.filename.endswith(".tgz") or file.filename.endswith(".gz"):
                with tarfile.open(temp_file_path, "r:*") as tar:
                    for member in tar.getmembers()[:2000]: # Límite para optimizar memoria RAM
                        extracted_files.append(member.name.lower())
            elif file.filename.endswith(".zip"):
                with zipfile.ZipFile(temp_file_path, "r") as zip_ref:
                    for name in zip_ref.namelist()[:2000]:
                        extracted_files.append(name.lower())
            else:
                extracted_files.append(file.filename.lower())
        except Exception:
            # Fallback en caso de que el archivo esté plano
            extracted_files.append(file.filename.lower())

        # 3. Análisis forense de coincidencias
        for path in extracted_files:
            for cat_name, keywords in CATEGORY_RULES.items():
                for kw in keywords:
                    if kw in path and kw not in file_matches[cat_name]:
                        file_matches[cat_name].append(kw)

    # 4. Formatear la lista de resultados para el Frontend
    results = []

    # Agregar la categoría general de registro completado al inicio
    results.append({
        "name": "REGISTRO COMPLETADO",
        "desc": f"Dispositivo analizado: {serial if serial else 'No especificado'}",
        "status": "COMPLETADO",
        "count": 0,
        "matches": []
    })

    for cat_name, matches in file_matches.items():
        is_threat = len(matches) > 0
        results.append({
            "name": cat_name,
            "desc": f"Búsqueda de rastro y ejecución de {cat_name}",
            "status": f"AMENAZA DETECTADA ({len(matches)})" if is_threat else "LIMPIO",
            "count": len(matches),
            "matches": matches
        })

    return {
        "status": "success",
        "serial": serial or "N/A",
        "results": results
    }