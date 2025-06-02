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
from tkinter import messagebox, ttk
from fastapi import FastAPI, Request
import rsa_utils as ru
import uvicorn

# Интерфейс командной строки
p = argparse.ArgumentParser()
p.add_argument("--id", required=True, help="имя клиента (A1 / B1 / ...)")
p.add_argument("--ca-url", required=True, help="URL своего УЦ")
p.add_argument("--listen", type=int, required=True, help="порт входящих сообщений")
args = p.parse_args()

# Загрузка конфигурации
SETTINGS_FILE = Path(__file__).parent / "settings.json"
with open(SETTINGS_FILE) as f:
    settings = json.load(f)
ROOT_URL = f"http://{settings['root']['host']}:{settings['root']['port']}"

CLIENT_DIR  = Path(__file__).parent / args.id
CLIENT_DIR.mkdir(exist_ok=True)
KEY_FILE    = CLIENT_DIR / "key.json"
CERT_FILE   = CLIENT_DIR / "cert.json"
CHAIN_FILE  = CLIENT_DIR / "chain.json"   # Цепочка сертификатов [клиент, УЦ, корневой УЦ]

# Криптографические ключи RSA
def init_keys():
    if KEY_FILE.exists():
        return json.loads(KEY_FILE.read_text())
    k = ru.generate_rsa_keys(bits=256)
    key = {"d": k["private"][0], "n": k["private"][1],
           "e": k["public"][0]}
    KEY_FILE.write_text(json.dumps(key))
    return key
my_key = init_keys()

# Вспомогательные функции Tkinter
root = tk.Tk()
root.title(f"Client {args.id}")

# Создание вкладок
notebook = ttk.Notebook(root)
notebook.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

# Вкладка сообщений
msg_frame = ttk.Frame(notebook)
notebook.add(msg_frame, text="Сообщения")

text_msg   = tk.Text(msg_frame, height=4, width=50)
text_log   = tk.Text(msg_frame, height=10, width=70)
entry_to   = tk.Entry(msg_frame, width=15)

# Вкладка ключей и сертификатов
keys_frame = ttk.Frame(notebook)
notebook.add(keys_frame, text="Ключи и сертификаты")

# Создание фреймов для ключей и сертификатов
keys_subframe = ttk.LabelFrame(keys_frame, text="Ключи")
keys_subframe.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

cert_subframe = ttk.LabelFrame(keys_frame, text="Сертификаты")
cert_subframe.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

# Поля для отображения и редактирования ключей
tk.Label(keys_subframe, text="Закрытый ключ (d):").grid(row=0, column=0, sticky="w", padx=5)
private_key_d = tk.Entry(keys_subframe, width=40)
private_key_d.grid(row=0, column=1, padx=5, pady=2)

tk.Label(keys_subframe, text="Модуль (n):").grid(row=1, column=0, sticky="w", padx=5)
key_n = tk.Entry(keys_subframe, width=40)
key_n.grid(row=1, column=1, padx=5, pady=2)

tk.Label(keys_subframe, text="Открытый ключ (e):").grid(row=2, column=0, sticky="w", padx=5)
public_key_e = tk.Entry(keys_subframe, width=40)
public_key_e.grid(row=2, column=1, padx=5, pady=2)

# Поля для отображения и редактирования сертификатов
tk.Label(cert_subframe, text="Сертификат:").grid(row=0, column=0, sticky="w", padx=5)
cert_text = tk.Text(cert_subframe, height=6, width=50)
cert_text.grid(row=0, column=1, padx=5, pady=2)

tk.Label(cert_subframe, text="Цепочка сертификатов:").grid(row=1, column=0, sticky="w", padx=5)
chain_text = tk.Text(cert_subframe, height=10, width=50)
chain_text.grid(row=1, column=1, padx=5, pady=2)

# Кнопки для управления ключами и сертификатами
def save_keys():
    try:
        new_key = {
            "d": int(private_key_d.get()),
            "n": int(key_n.get()),
            "e": int(public_key_e.get())
        }
        KEY_FILE.write_text(json.dumps(new_key))
        global my_key
        my_key = new_key
        messagebox.showinfo("Успех", "Ключи успешно сохранены")
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректные числовые значения")

def save_certs():
    try:
        cert_data = json.loads(cert_text.get("1.0", tk.END))
        chain_data = json.loads(chain_text.get("1.0", tk.END))
        CERT_FILE.write_text(json.dumps(cert_data))
        CHAIN_FILE.write_text(json.dumps(chain_data))
        messagebox.showinfo("Успех", "Сертификаты успешно сохранены")
    except json.JSONDecodeError:
        messagebox.showerror("Ошибка", "Неверный формат JSON")
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def load_keys_to_gui():
    private_key_d.delete(0, tk.END)
    key_n.delete(0, tk.END)
    public_key_e.delete(0, tk.END)
    private_key_d.insert(0, str(my_key["d"]))
    key_n.insert(0, str(my_key["n"]))
    public_key_e.insert(0, str(my_key["e"]))

def load_certs_to_gui():
    cert_text.delete("1.0", tk.END)
    chain_text.delete("1.0", tk.END)
    if CERT_FILE.exists():
        cert_text.insert("1.0", CERT_FILE.read_text())
    if CHAIN_FILE.exists():
        chain_text.insert("1.0", CHAIN_FILE.read_text())

# Кнопки для ключей
keys_btn_frame = ttk.Frame(keys_subframe)
keys_btn_frame.grid(row=3, column=0, columnspan=2, pady=5)
tk.Button(keys_btn_frame, text="Сохранить ключи", command=save_keys).pack(side=tk.LEFT, padx=5)
tk.Button(keys_btn_frame, text="Показать ключи", command=load_keys_to_gui).pack(side=tk.LEFT, padx=5)

# Кнопки для сертификатов
cert_btn_frame = ttk.Frame(cert_subframe)
cert_btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
tk.Button(cert_btn_frame, text="Сохранить сертификаты", command=save_certs).pack(side=tk.LEFT, padx=5)
tk.Button(cert_btn_frame, text="Показать сертификаты", command=load_certs_to_gui).pack(side=tk.LEFT, padx=5)


# Загрузка начальных значений
load_keys_to_gui()
load_certs_to_gui()

def log(msg: str):
    text_log.insert(tk.END, msg + "\n")
    text_log.see(tk.END)

# Процедура получения сертификата
def request_cert():
    csr = {"subject": args.id,
           "pubkey": {"e": my_key["e"], "n": my_key["n"]}}
    try:
        cert = requests.post(f"{args.ca_url}/sign", json=csr).json()
    except Exception as ex:
        messagebox.showerror("Ошибка", str(ex)); return
    # Формирование цепочки: клиент -> УЦ -> корневой УЦ
    ca_cert   = requests.get(f"{args.ca_url}/ca_cert").json()
    root_cert = requests.get(f"{ROOT_URL}/ca_cert").json()
    for obj, name in [(cert, "client"), (ca_cert, "CA"), (root_cert, "root")]:
        if "signature" not in obj:
            messagebox.showerror("Ошибка", f"{name} cert без подписи"); return
    # Сохранение сертификата
    CERT_FILE.write_text(json.dumps(cert))
    CHAIN_FILE.write_text(json.dumps([cert, ca_cert, root_cert]))
    log("Сертификат получен и сохранён")

# Получение сертификата другого пользователя
def fetch_remote_cert(remote_id: str):
    ca_url = entry_to.get().strip()
    if not ca_url.startswith("http"):
        # Автоматическое определение URL удостоверяющего центра по идентификатору
        if remote_id.startswith("A"):
            ca_url = f"http://{settings['CA A']['host']}:8001"
        else:
            ca_url = f"http://{settings['CA B']['host']}:8002"
    try:
        cert = requests.get(f"{ca_url}/cert/{remote_id}").json()
        ca_cert   = requests.get(f"{ca_url}/ca_cert").json()
        root_cert = requests.get(f"{ROOT_URL}/ca_cert").json()
    except Exception as e:
        messagebox.showerror("Ошибка", str(e)); return
    return [cert, ca_cert, root_cert]

# Отправка сообщения
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
    # Добавление собственной цепочки сертификатов
    my_chain = json.loads(CHAIN_FILE.read_text())
    packet = {"from": args.id, "to": to_id,
              "cipher": c_int, "signature": s_int,
              "chain": my_chain}

    try:
        requests.post(f"http://{settings[to_id]['host']}:{settings[to_id]['listen']}/receive", json=packet, timeout=5)
        log(f"→ {to_id}: отправлено")
    except Exception as e:
        messagebox.showerror("Ошибка отправки", str(e))

# Проверка цепочки сертификатов
def verify_chain(chain):
    def verify(cert, issuer_cert):
        body = cert.copy(); sig = body.pop("signature")
        to_int = ru.text_to_int(json.dumps(body, sort_keys=True))
        pub = issuer_cert["pubkey"]
        return ru.rsa_verify(to_int, sig, (pub["e"], pub["n"]))
    # Проверка цепочки: клиент -> УЦ -> корневой УЦ
    client, ca, root = chain
    if not verify(client, ca): return False
    if not verify(ca,    root): return False
    # Проверка самоподписанного корневого сертификата
    root_body = root.copy(); sig = root_body.pop("signature")
    to_int = ru.text_to_int(json.dumps(root_body, sort_keys=True))
    return ru.rsa_verify(to_int, sig, (root["pubkey"]["e"], root["pubkey"]["n"]))

# Обработчик входящих сообщений FastAPI
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

# Размещение элементов на вкладке сообщений
tk.Label(msg_frame, text="Получатель (ID):").grid(row=0, column=0, sticky="e")
entry_to.grid(row=0, column=1)
tk.Button(msg_frame, text="Запросить свой сертификат", command=request_cert
          ).grid(row=0, column=2, padx=5)
tk.Label(msg_frame, text="Сообщение:").grid(row=1, column=0, sticky="nw")
text_msg.grid(row=1, column=1, columnspan=2)
tk.Button(msg_frame, text="Отправить", command=send_message
          ).grid(row=2, column=1, pady=3, sticky="e")
tk.Label(msg_frame, text="Лог:").grid(row=3, column=0, sticky="nw")
text_log.grid(row=3, column=1, columnspan=2)

log(f"Клиент {args.id} запущен, слушаю порт {args.listen}")
root.mainloop()
