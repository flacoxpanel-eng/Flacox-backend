import os
import tarfile
import zipfile
import tempfile
import shutil
from typing import List, Dict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="FLACO X Forensic Engine", version="8.6")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VALID_KEYS = [
    "FLACOX-VIP-S9RRY8",
    "FLACOX-VIP-ADMIN",
    "FLACOX-VIP-TEST"
]

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
    return {"status": "online", "system": "FLACO X Forensic Engine v8.6 Ready"}

@app.post("/scan")
async def scan_file(
    key: str = Form(...),
    serial: str = Form(None),
    file: UploadFile = File(...)
):
    if key not in VALID_KEYS:
        raise HTTPException(status_code=401, detail="Clave VIP de acceso inválida o expirada.")

    if not file:
        raise HTTPException(status_code=400, detail="No se ha recibido ningún archivo de diagnóstico.")

    file_matches: Dict[str, List[str]] = {cat: [] for cat in CATEGORY_RULES}
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path = os.path.join(temp_dir, file.filename)
        
        # Escritura por bloques (streams) para no saturar la RAM
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        filename_lower = file.filename.lower()

        try:
            if filename_lower.endswith(".tar.gz") or filename_lower.endswith(".tgz") or filename_lower.endswith(".gz"):
                with tarfile.open(temp_file_path, "r:*") as tar:
                    for member in tar.getmembers():
                        path_name = member.name.lower()
                        for cat_name, keywords in CATEGORY_RULES.items():
                            for kw in keywords:
                                if kw in path_name and kw not in file_matches[cat_name]:
                                    file_matches[cat_name].append(kw)
            elif filename_lower.endswith(".zip"):
                with zipfile.ZipFile(temp_file_path, "r") as zip_ref:
                    for name in zip_ref.namelist():
                        path_name = name.lower()
                        for cat_name, keywords in CATEGORY_RULES.items():
                            for kw in keywords:
                                if kw in path_name and kw not in file_matches[cat_name]:
                                    file_matches[cat_name].append(kw)
        except Exception as e:
            pass

    results = [{
        "name": "REGISTRO COMPLETADO",
        "desc": f"Dispositivo analizado: {serial if serial else 'No especificado'}",
        "status": "COMPLETADO",
        "count": 0,
        "matches": []
    }]

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
