"""
GUI-клиент (Tkinter) + приём входящих сообщений (FastAPI).
Пример A1:
    python client_gui.py --id A1 --ca-url http://localhost:8001 --listen 9001
Пример B1:
    python client_gui.py --id B1 --ca-url http://localhost:8002 --listen 9002
"""

import argparse, json, threading, requests
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
from fastapi import FastAPI, Request
import rsa_utils as ru
import uvicorn

# ---------- CLI ----------
p = argparse.ArgumentParser()
p.add_argument("--id", required=True, help="имя клиента (A1 / B1 / ...)")
p.add_argument("--ca-url", required=True, help="URL своего УЦ")
p.add_argument("--listen", type=int, required=True, help="порт входящих сообщений")
args = p.parse_args()

# Загружаем настройки
SETTINGS_FILE = Path(__file__).parent / "settings.json"
with open(SETTINGS_FILE) as f:
    settings = json.load(f)
ROOT_URL = f"http://localhost:{settings['root']['port']}"

CLIENT_DIR  = Path(__file__).parent / args.id
CLIENT_DIR.mkdir(exist_ok=True)
KEY_FILE    = CLIENT_DIR / "key.json"
CERT_FILE   = CLIENT_DIR / "cert.json"
CHAIN_FILE  = CLIENT_DIR / "chain.json"   # [client, CA, root]

# ---------- RSA-ключи ----------
def init_keys():
    if KEY_FILE.exists():
        return json.loads(KEY_FILE.read_text())
    k = ru.generate_rsa_keys(bits=256)
    key = {"d": k["private"][0], "n": k["private"][1],
           "e": k["public"][0]}
    KEY_FILE.write_text(json.dumps(key))
    return key
my_key = init_keys()

# ---------- Tkinter helpers ----------
root = tk.Tk()
root.title(f"Client {args.id}")

text_msg   = tk.Text(root, height=4, width=50)
text_log   = tk.Text(root, height=10, width=70)
entry_to   = tk.Entry(root, width=15)

def log(msg: str):
    text_log.insert(tk.END, msg + "\n")
    text_log.see(tk.END)

# ---------- выдача сертификата ----------
def request_cert():
    csr = {"subject": args.id,
           "pubkey": {"e": my_key["e"], "n": my_key["n"]}}
    try:
        cert = requests.post(f"{args.ca_url}/sign", json=csr).json()
    except Exception as ex:
        messagebox.showerror("Ошибка", str(ex)); return
    # цепочка: client -> CA -> Root
    ca_cert   = requests.get(f"{args.ca_url}/ca_cert").json()
    root_cert = requests.get(f"{ROOT_URL}/ca_cert").json()
    for obj, name in [(cert, "client"), (ca_cert, "CA"), (root_cert, "root")]:
        if "signature" not in obj:
            messagebox.showerror("Ошибка", f"{name} cert без подписи"); return
    # сохраняем
    CERT_FILE.write_text(json.dumps(cert))
    CHAIN_FILE.write_text(json.dumps([cert, ca_cert, root_cert]))
    log("Сертификат получен и сохранён")

# ---------- получение чужого сертификата ----------
def fetch_remote_cert(remote_id: str):
    ca_url = entry_to.get().strip()
    if not ca_url.startswith("http"):
        # если ввели id, пытаемся определить CAURL автоматически
        if remote_id.startswith("A"):
            ca_url = "http://localhost:8001"
        else:
            ca_url = "http://localhost:8002"
    try:
        cert = requests.get(f"{ca_url}/cert/{remote_id}").json()
        ca_cert   = requests.get(f"{ca_url}/ca_cert").json()
        root_cert = requests.get(f"{ROOT_URL}/ca_cert").json()
    except Exception as e:
        messagebox.showerror("Ошибка", str(e)); return
    return [cert, ca_cert, root_cert]

# ---------- отправка ----------
def send_message():
    to_id = entry_to.get().strip()
    if not to_id:
        messagebox.showwarning("Введите получателя", "") ; return
    chain_remote = fetch_remote_cert(to_id)
    if not chain_remote:
        return
    remote_pub = chain_remote[0]["pubkey"]
    text = text_msg.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Пустое сообщение", ""); return
    m_int = ru.text_to_int(text)
    s_int = ru.rsa_sign(m_int, (my_key["d"], my_key["n"]))
    c_int = ru.rsa_encrypt(m_int, (remote_pub["e"], remote_pub["n"]))
    # прикладываем СВОЮ цепочку
    my_chain = json.loads(CHAIN_FILE.read_text())
    packet = {"from": args.id, "to": to_id,
              "cipher": c_int, "signature": s_int,
              "chain": my_chain}
    remote_port = 9001 if to_id.startswith("A") else 9002
    try:
        requests.post(f"http://localhost:{remote_port}/receive", json=packet, timeout=5)
        log(f"→ {to_id}: отправлено")
    except Exception as e:
        messagebox.showerror("Ошибка отправки", str(e))

# ---------- проверка цепочки ----------
def verify_chain(chain):
    def verify(cert, issuer_cert):
        body = cert.copy(); sig = body.pop("signature")
        to_int = ru.text_to_int(json.dumps(body, sort_keys=True))
        pub = issuer_cert["pubkey"]
        return ru.rsa_verify(to_int, sig, (pub["e"], pub["n"]))
    # client -> CA -> Root
    client, ca, root = chain
    if not verify(client, ca): return False
    if not verify(ca,    root): return False
    # root самоподписан
    root_body = root.copy(); sig = root_body.pop("signature")
    to_int = ru.text_to_int(json.dumps(root_body, sort_keys=True))
    return ru.rsa_verify(to_int, sig, (root["pubkey"]["e"], root["pubkey"]["n"]))

# ---------- FastAPI приёмник ----------
api = FastAPI()
@api.post("/receive")
async def receive(req: Request):
    data = await req.json()
    cipher = int(data["cipher"]); signature = int(data["signature"])
    chain  = data["chain"]
    if not verify_chain(chain):
        log("!! Недействительна цепочка сертификатов"); return {"ok": False}
    sender_pub = chain[0]["pubkey"]
    m_int = ru.rsa_decrypt(cipher, (my_key["d"], my_key["n"]))
    if not ru.rsa_verify(m_int, signature, (sender_pub["e"], sender_pub["n"])):
        log("!! Подпись недействительна"); return {"ok": False}
    text = ru.int_to_text(m_int)
    log(f"← {data['from']}: {text}")
    return {"ok": True}

def start_api():
    uvicorn.run(api, host="0.0.0.0", port=args.listen, log_level="warning")

threading.Thread(target=start_api, daemon=True).start()

# ---------- GUI layout ----------
tk.Label(root, text="Получатель (ID):").grid(row=0, column=0, sticky="e")
entry_to.grid(row=0, column=1)
tk.Button(root, text="Запросить свой сертификат", command=request_cert
          ).grid(row=0, column=2, padx=5)
tk.Label(root, text="Сообщение:").grid(row=1, column=0, sticky="nw")
text_msg.grid(row=1, column=1, columnspan=2)
tk.Button(root, text="Отправить", command=send_message
          ).grid(row=2, column=1, pady=3, sticky="e")
tk.Label(root, text="Лог:").grid(row=3, column=0, sticky="nw")
text_log.grid(row=3, column=1, columnspan=2)

log(f"Клиент {args.id} запущен, слушаю порт {args.listen}")
root.mainloop()
