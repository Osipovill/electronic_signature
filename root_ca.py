"""
Запуск:
    uvicorn root_ca:app --port 8000
Корневой УЦ (Root CA):
  • генерирует пару ключей RSA
  • создает самоподписанный сертификат
  • подписывает сертификаты промежуточных УЦ
"""

import json, threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import rsa_utils as ru

ROOT_DIR = Path(__file__).parent
KEY_FILE = ROOT_DIR / "root_key.json"
CERT_FILE = ROOT_DIR / "root_cert.json"

app = FastAPI(title="Root CA")

# ---------- инициализация ----------
def init_root():
    if KEY_FILE.exists() and CERT_FILE.exists():
        priv = json.loads(KEY_FILE.read_text())
        cert = json.loads(CERT_FILE.read_text())
        return priv, cert

    k = ru.generate_rsa_keys(bits=256)  # Тестовый размер ключа, для продакшена использовать 2048+ бит
    priv = {"d": k["private"][0], "n": k["private"][1]}
    pub  = {"e": k["public"][0],  "n": k["public"][1]}

    cert_body = {
        "subject": "Root CA",
        "issuer": "Root CA",
        "pubkey": pub,
    }
    to_sign = ru.text_to_int(json.dumps(cert_body, sort_keys=True))
    cert_body["signature"] = ru.rsa_sign(to_sign, (priv["d"], priv["n"]))

    KEY_FILE.write_text(json.dumps(priv))
    CERT_FILE.write_text(json.dumps(cert_body))
    return priv, cert_body

root_priv, root_cert = init_root()

# ---------- модели ----------
class CSR(BaseModel):
    subject: str
    pubkey: dict  # Открытый ключ в формате {"e": int, "n": int}

# ---------- роуты ----------
@app.get("/ca_cert")
async def get_ca_cert():
    return root_cert

@app.post("/sign")
async def sign_intermediate(csr: CSR):
    if csr.subject.startswith("Root"):
        raise HTTPException(400, "Root CA не подписывает сам себя")
    cert_body = {
        "subject": csr.subject,
        "issuer": "Root CA",
        "pubkey": csr.pubkey,
    }
    to_sign = ru.text_to_int(json.dumps(cert_body, sort_keys=True))
    cert_body["signature"] = ru.rsa_sign(to_sign, (root_priv["d"], root_priv["n"]))
    return cert_body
