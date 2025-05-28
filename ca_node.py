"""
Универсальный промежуточный УЦ.
Запуск (пример для CA A):
    python ca_node.py --name "CA A" --port 8001 --root-url http://localhost:8000
Запуск CA B:
    python ca_node.py --name "CA B" --port 8002 --root-url http://localhost:8000
"""

import argparse, json, requests, threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import rsa_utils as ru

# ---------- подготовка CLI ----------
parser = argparse.ArgumentParser()
parser.add_argument("--name", required=True, help="имя УЦ (CA A / CA B)")
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--root-url", default="http://localhost:8000")
args = parser.parse_args()

CA_DIR   = Path(__file__).parent / args.name.replace(" ", "_")
CA_DIR.mkdir(exist_ok=True)

KEY_FILE  = CA_DIR / "ca_key.json"
CERT_FILE = CA_DIR / "ca_cert.json"
DB_FILE   = CA_DIR / "clients.json"

# ---------- инициализация ключей ----------
def init_keys():
    if KEY_FILE.exists():
        key = json.loads(KEY_FILE.read_text())
    else:
        k = ru.generate_rsa_keys(bits=256)
        key = {"d": k["private"][0], "n": k["private"][1],
               "e": k["public"][0]}
        KEY_FILE.write_text(json.dumps(key))
    return key

ca_key = init_keys()

# ---------- получение корневого сертификата ----------
root_cert = requests.get(f"{args.root_url}/ca_cert").json()

# ---------- получение собственного сертификата от Root ----------
if CERT_FILE.exists():
    ca_cert = json.loads(CERT_FILE.read_text())
else:
    csr = {
        "subject": args.name,
        "pubkey": {"e": ca_key["e"], "n": ca_key["n"]}
    }
    ca_cert = requests.post(f"{args.root_url}/sign", json=csr).json()
    CERT_FILE.write_text(json.dumps(ca_cert))

# ---------- база данных выданных клиентских сертификатов ----------
if DB_FILE.exists():
    client_db = json.loads(DB_FILE.read_text())
else:
    client_db = {}
    DB_FILE.write_text(json.dumps(client_db))

# ---------- FastAPI ----------
app = FastAPI(title=args.name)

class CSR(BaseModel):
    subject: str
    pubkey: dict

@app.get("/ca_cert")
async def get_ca_cert():
    return ca_cert

@app.get("/root_cert")
async def get_root():
    return root_cert

@app.post("/sign")
async def sign_client(csr: CSR):
    if csr.subject in client_db:
        raise HTTPException(400, "Сертификат уже выдан")
    body = {
        "subject": csr.subject,
        "issuer": args.name,
        "pubkey": csr.pubkey,
    }
    to_sign = ru.text_to_int(json.dumps(body, sort_keys=True))
    body["signature"] = ru.rsa_sign(to_sign, (ca_key["d"], ca_key["n"]))

    client_db[csr.subject] = body
    DB_FILE.write_text(json.dumps(client_db))
    return body

@app.get("/cert/{client_id}")
async def get_client_cert(client_id: str):
    cert = client_db.get(client_id)
    if not cert:
        raise HTTPException(404, "Неизвестный клиент")
    return cert

# ---------- run ----------
if __name__ == "__main__":
    import uvicorn, sys
    uvicorn.run("ca_node:app", host="0.0.0.0", port=args.port, log_level="info")
