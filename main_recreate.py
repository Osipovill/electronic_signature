import tkinter as tk
from tkinter import messagebox
from rsa_utils import (
    generate_rsa_keys, text_to_int, int_to_text,
    rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify, is_prime_fermat, is_prime_trial, generate_prime
)

# Глобальные переменные для хранения ключей
keys_sender = None         # Ключи отправителя для генерации и заполнения полей
keys_receiver = None       # Ключи получателя для генерации и заполнения полей

# Буферы для обмена открытыми ключами
sender_pub_buffer = None   # Открытый ключ отправителя (e, n) для получателя
receiver_pub_buffer = None # Открытый ключ получателя (e, n) для отправителя

# Буфер для передачи зашифрованного сообщения и цифровой подписи
message_buffer = None      # Пара (шифротекст, подпись)

# Инициализация окон TKinter
root_sender = tk.Tk()
root_sender.title("Отправитель")

root_receiver = tk.Toplevel(root_sender)
root_receiver.title("Получатель")

# Переменные интерфейса отправителя
sender_e_var = tk.StringVar()  # Открытая экспонента отправителя
sender_n_var = tk.StringVar()  # Модуль отправителя
sender_d_var = tk.StringVar()  # Закрытая экспонента отправителя

# Открытый ключ получателя в интерфейсе отправителя
receiver_e_var = tk.StringVar() # Открытая экспонента получателя
receiver_n_var = tk.StringVar() # Модуль получателя

# Переменные интерфейса получателя
# Собственные ключи получателя
receiver_e_on_receiver_var = tk.StringVar()  # Открытая экспонента получателя
receiver_n_on_receiver_var = tk.StringVar()  # Модуль получателя
receiver_d_on_receiver_var = tk.StringVar()  # Закрытая экспонента получателя

# Открытый ключ отправителя в интерфейсе получателя
sender_pub_on_receiver_e_var = tk.StringVar()  # Открытая экспонента отправителя
sender_pub_on_receiver_n_var = tk.StringVar()  # Модуль отправителя

# Служебные переменные интерфейса
cipher_var = tk.StringVar()        # Зашифрованное сообщение
signature_var = tk.StringVar()     # Цифровая подпись
verify_result_var = tk.StringVar() # Результат проверки подписи

# Функции генерации криптографических ключей

def generate_sender_keys():
    """
    Генерация ключей RSA для отправителя.
    Записываем e, n, d в соответствующие текстовые поля отправителя.
    """
    global keys_sender
    keys_sender = generate_rsa_keys()
    e_s, n_s = keys_sender['public']
    d_s, _   = keys_sender['private']
    sender_e_var.set(str(e_s))
    sender_n_var.set(str(n_s))
    sender_d_var.set(str(d_s))

    messagebox.showinfo(
        "Ключи отправителя",
        f"Ключи отправителя сформированы:\n"
        f"p = {keys_sender['p']}\nq = {keys_sender['q']}\n"
        f"e = {e_s}, n = {n_s}\n"
        f"d = {d_s}"
    )

def generate_receiver_keys():
    """
    Генерация ключей RSA для получателя.
    Записываем e, n, d в соответствующие поля получателя.
    """
    global keys_receiver
    keys_receiver = generate_rsa_keys()
    e_r, n_r = keys_receiver['public']
    d_r, _   = keys_receiver['private']
    receiver_e_on_receiver_var.set(str(e_r))
    receiver_n_on_receiver_var.set(str(n_r))
    receiver_d_on_receiver_var.set(str(d_r))

    messagebox.showinfo(
        "Ключи получателя",
        f"Ключи получателя сформированы:\n"
        f"p = {keys_receiver['p']}\nq = {keys_receiver['q']}\n"
        f"e = {e_r}, n = {n_r}\n"
        f"d = {d_r}"
    )

# Функции эмуляции передачи данных

def send_sender_pub():
    """
    Отправка (эмуляция) открытого ключа отправителя (e, n) получателю.
    Берётся из полей отправителя, кладётся в буфер sender_pub_buffer.
    """
    global sender_pub_buffer
    try:
        e_s = int(sender_e_var.get())
        n_s = int(sender_n_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные открытого ключа отправителя: {ex}")
        return
    sender_pub_buffer = (e_s, n_s)
    messagebox.showinfo("Отправка ключа", "Открытый ключ отправителя отправлен получателю.")

def get_sender_pub():
    """
    Получение (эмуляция) открытого ключа отправителя в окне получателя.
    Копирует значение из sender_pub_buffer в текстовые поля получателя.
    """
    global sender_pub_buffer
    if sender_pub_buffer is None:
        messagebox.showwarning("Ошибка", "Нет открытого ключа отправителя. Сначала нажмите 'Послать ключ' у отправителя.")
        return
    e_s, n_s = sender_pub_buffer
    sender_pub_on_receiver_e_var.set(str(e_s))
    sender_pub_on_receiver_n_var.set(str(n_s))
    sender_pub_buffer = None
    messagebox.showinfo("Получение ключа", "Открытый ключ отправителя получен получателем.")

def send_receiver_pub():
    """
    Отправка (эмуляция) открытого ключа получателя (e, n) отправителю.
    Берём из полей получателя, кладём в буфер receiver_pub_buffer.
    """
    global receiver_pub_buffer
    try:
        e_r = int(receiver_e_on_receiver_var.get())
        n_r = int(receiver_n_on_receiver_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные открытого ключа получателя: {ex}")
        return
    receiver_pub_buffer = (e_r, n_r)
    messagebox.showinfo("Передача ключа", "Открытый ключ получателя отправлен отправителю.")

def get_receiver_pub():
    """
    Получение (эмуляция) открытого ключа получателя в окне отправителя.
    Копирует значение из receiver_pub_buffer в текстовые поля отправителя.
    """
    global receiver_pub_buffer
    if receiver_pub_buffer is None:
        messagebox.showwarning("Ошибка", "Нет нового ключа для получения. Сначала нажмите 'Послать ключ' у получателя.")
        return
    e_r, n_r = receiver_pub_buffer
    receiver_e_var.set(str(e_r))
    receiver_n_var.set(str(n_r))
    receiver_pub_buffer = None
    messagebox.showinfo("Получение ключа", "Открытый ключ получателя получен отправителем.")

# Шифрование и формирование цифровой подписи

def encrypt_and_sign_message():
    """
    Отправитель берёт:
      - Свой (d_s, n_s) из полей для подписи (чтобы подписать).
      - Открытый ключ получателя (e_r, n_r) из полей для шифрования.
    """
    global message_buffer

    try:
        # Парсим закрытый ключ отправителя
        d_s = int(sender_d_var.get())
        n_s = int(sender_n_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные закрытого ключа отправителя: {ex}")
        return

    try:
        # Парсим открытый ключ получателя
        e_r = int(receiver_e_var.get())
        n_r = int(receiver_n_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные открытого ключа получателя: {ex}")
        return

    # Считываем сообщение
    msg_text = message_entry.get("1.0", tk.END).rstrip('\n')
    if not msg_text:
        messagebox.showwarning("Ошибка", "Введите сообщение для отправки.")
        return

    m_int = text_to_int(msg_text)
    if m_int >= n_r:
        messagebox.showwarning(
            "Внимание",
            "Сообщение слишком длинное и будет усечено по модулю n. "
            "Лучше используйте более короткое сообщение или увеличьте размер ключа."
        )

    # Подпись отправителя
    s_int = rsa_sign(m_int, (d_s, n_s))
    # Шифрование для получателя
    c_int = rsa_encrypt(m_int, (e_r, n_r))

    cipher_var.set(str(c_int))
    signature_var.set(str(s_int))
    message_buffer = (c_int, s_int)

    messagebox.showinfo("Сообщение готово", "Сообщение зашифровано и подписано. Можно отправлять.")

def send_message():
    """
    Эмуляция отправки зашифрованного сообщения (c_int) и подписи (s_int).
    Фактически сообщение уже находится в message_buffer.
    """
    global message_buffer
    if message_buffer is None:
        messagebox.showwarning("Ошибка", "Нет данных для отправки. Сначала нажмите 'Закодировать и подписать'.")
        return
    messagebox.showinfo("Отправка", "Зашифрованное и подписанное сообщение отправлено получателю.")

# Расшифрование и проверка цифровой подписи

def verify_message():
    """
    Получатель берёт:
      - Свой (d_r, n_r) из полей (чтобы расшифровать).
      - Открытый ключ отправителя (e_s, n_s) из полей (чтобы проверить подпись).
    """
    global message_buffer
    if message_buffer is None:
        messagebox.showwarning("Ошибка", "Нет полученного сообщения для проверки.")
        return

    # Парсим закрытый ключ получателя
    try:
        d_r = int(receiver_d_on_receiver_var.get())
        n_r = int(receiver_n_on_receiver_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные закрытого ключа получателя: {ex}")
        return

    # Парсим открытый ключ отправителя
    try:
        e_s = int(sender_pub_on_receiver_e_var.get())
        n_s = int(sender_pub_on_receiver_n_var.get())
    except ValueError as ex:
        messagebox.showerror("Ошибка", f"Некорректные данные открытого ключа отправителя: {ex}")
        return

    c_int, s_int = message_buffer

    # Расшифрование
    m_int = rsa_decrypt(c_int, (d_r, n_r))
    # Проверка подписи
    valid = rsa_verify(m_int, s_int, (e_s, n_s))
    plaintext = int_to_text(m_int)

    received_text.delete("1.0", tk.END)
    received_text.insert(tk.END, plaintext)

    verify_result_var.set("Подпись действительна" if valid else "Подпись недействительна")
    if not valid:
        messagebox.showwarning("Результат проверки", "Подпись недействительна! Ключи не совпадают или сообщение изменено.")
    else:
        messagebox.showinfo("Результат проверки", "Подпись сообщения успешно подтверждена.")

# Формирование интерфейса отправителя

# Блок управления подписью
frame_sender_sign = tk.LabelFrame(root_sender, text="Отправитель: Для подписи", padx=5, pady=5)
frame_sender_sign.grid(row=0, column=0, padx=5, pady=5, sticky="nwe")

tk.Label(frame_sender_sign, text="Открытый ключ (e):").grid(row=0, column=0, sticky="w")
tk.Entry(frame_sender_sign, textvariable=sender_e_var, width=30).grid(row=0, column=1, sticky="w")

tk.Label(frame_sender_sign, text="Модуль (n):").grid(row=1, column=0, sticky="w")
tk.Entry(frame_sender_sign, textvariable=sender_n_var, width=30).grid(row=1, column=1, sticky="w")

tk.Label(frame_sender_sign, text="Закрытый ключ (d):").grid(row=2, column=0, sticky="w")
tk.Entry(frame_sender_sign, textvariable=sender_d_var, width=30).grid(row=2, column=1, sticky="w")

tk.Button(frame_sender_sign, text="Сформировать ключи", command=generate_sender_keys).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="we")
tk.Button(frame_sender_sign, text="Послать ключ (pub)", command=send_sender_pub).grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Блок параметров сообщения
frame_sender_msg = tk.LabelFrame(root_sender, text="Отправитель: Для сообщения", padx=5, pady=5)
frame_sender_msg.grid(row=0, column=1, padx=5, pady=5, sticky="nwe")

tk.Label(frame_sender_msg, text="Открытый ключ получателя (e):").grid(row=0, column=0, sticky="w")
tk.Entry(frame_sender_msg, textvariable=receiver_e_var, width=30).grid(row=0, column=1, sticky="w")

tk.Label(frame_sender_msg, text="Модуль получателя (n):").grid(row=1, column=0, sticky="w")
tk.Entry(frame_sender_msg, textvariable=receiver_n_var, width=30).grid(row=1, column=1, sticky="w")

tk.Button(frame_sender_msg, text="Получить ключ (pub)", command=get_receiver_pub).grid(row=2, column=0, padx=5, pady=5, sticky="we")
tk.Button(frame_sender_msg, text="Закодировать и подписать", command=encrypt_and_sign_message).grid(row=2, column=1, padx=5, pady=5, sticky="we")
tk.Button(frame_sender_msg, text="Послать сообщение", command=send_message).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Поле ввода сообщения
tk.Label(root_sender, text="Сообщение:").grid(row=1, column=0, columnspan=2, sticky="w", padx=5)
message_entry = tk.Text(root_sender, height=5, width=60)
message_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Отображение зашифрованного сообщения и подписи
tk.Label(root_sender, text="Зашифрованное сообщение:").grid(row=3, column=0, sticky="w", padx=5)
tk.Entry(root_sender, textvariable=cipher_var, width=50).grid(row=3, column=1, padx=5, sticky="w")

tk.Label(root_sender, text="Подпись:").grid(row=4, column=0, sticky="w", padx=5)
tk.Entry(root_sender, textvariable=signature_var, width=50).grid(row=4, column=1, padx=5, sticky="w")

# Блок генерации и проверки простых чисел
frame_primes = tk.LabelFrame(root_sender, text="Генерация и проверка простых чисел", padx=5, pady=5)
frame_primes.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="nwe")

# Генерация простого числа
tk.Label(frame_primes, text="Количество бит:").grid(row=0, column=0, sticky="w")
prime_bits_entry = tk.Entry(frame_primes, width=10)
prime_bits_entry.grid(row=0, column=1, sticky="w")
prime_bits_entry.insert(0, "16")  # Значение по умолчанию

tk.Label(frame_primes, text="Сгенерированное простое число:").grid(row=1, column=0, sticky="w")
prime_result_var = tk.StringVar()
tk.Entry(frame_primes, textvariable=prime_result_var, width=50).grid(row=1, column=1, sticky="w")

def generate_prime_and_show():
    try:
        bits = int(prime_bits_entry.get())
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректное количество бит.")
        return
    prime = generate_prime(bits)
    prime_result_var.set(str(prime))
    messagebox.showinfo("Сгенерировано простое число", f"Сгенерировано простое число {prime} для {bits} бит.")

tk.Button(frame_primes, text="Сгенерировать простое число", command=generate_prime_and_show).grid(row=0, column=2, padx=5, pady=5)

def check_prime():
    try:
        num = int(prime_result_var.get())
    except ValueError:
        messagebox.showerror("Ошибка", "Введите корректное число для проверки.")
        return
    # Выполняем тесты: пробное деление и тест Ферма
    trial = is_prime_trial(num)
    fermat = is_prime_fermat(num)
    result = (f"Число: {num}\n"
              f"Пробное деление: {'Простое' if trial else 'Составное'}, \n"
              f"Тест Ферма: {'Простое' if fermat else 'Составное'}")

    messagebox.showinfo("Результат проверки", result)

tk.Button(frame_primes, text="Проверить число", command=check_prime).grid(row=3, column=1, padx=5, pady=5, sticky="w")

# Формирование интерфейса получателя

# Блок ключей получателя
frame_receiver_keys = tk.LabelFrame(root_receiver, text="Получатель: Свои ключи", padx=5, pady=5)
frame_receiver_keys.grid(row=0, column=0, padx=5, pady=5, sticky="nwe")

tk.Label(frame_receiver_keys, text="Открытый ключ (e):").grid(row=0, column=0, sticky="w")
tk.Entry(frame_receiver_keys, textvariable=receiver_e_on_receiver_var, width=30).grid(row=0, column=1, sticky="w")

tk.Label(frame_receiver_keys, text="Модуль (n):").grid(row=1, column=0, sticky="w")
tk.Entry(frame_receiver_keys, textvariable=receiver_n_on_receiver_var, width=30).grid(row=1, column=1, sticky="w")

tk.Label(frame_receiver_keys, text="Закрытый ключ (d):").grid(row=2, column=0, sticky="w")
tk.Entry(frame_receiver_keys, textvariable=receiver_d_on_receiver_var, width=30).grid(row=2, column=1, sticky="w")

tk.Button(frame_receiver_keys, text="Сформировать ключи", command=generate_receiver_keys).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="we")
tk.Button(frame_receiver_keys, text="Послать ключ (pub)", command=send_receiver_pub).grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Блок ключа отправителя
frame_receiver_sender_pub = tk.LabelFrame(root_receiver, text="Получатель: Ключ отправителя", padx=5, pady=5)
frame_receiver_sender_pub.grid(row=0, column=1, padx=5, pady=5, sticky="nwe")

tk.Label(frame_receiver_sender_pub, text="Открытый ключ отправителя (e):").grid(row=0, column=0, sticky="w")
tk.Entry(frame_receiver_sender_pub, textvariable=sender_pub_on_receiver_e_var, width=30).grid(row=0, column=1, sticky="w")

tk.Label(frame_receiver_sender_pub, text="Модуль отправителя (n):").grid(row=1, column=0, sticky="w")
tk.Entry(frame_receiver_sender_pub, textvariable=sender_pub_on_receiver_n_var, width=30).grid(row=1, column=1, sticky="w")

tk.Button(frame_receiver_sender_pub, text="Получить ключ (pub)", command=get_sender_pub).grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Кнопка проверки сообщения
tk.Button(root_receiver, text="Получить и проверить сообщение", command=verify_message).grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="we")

# Поле отображения расшифрованного сообщения
tk.Label(root_receiver, text="Принятое сообщение:").grid(row=2, column=0, columnspan=2, sticky="w", padx=5)
received_text = tk.Text(root_receiver, height=5, width=60)
received_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

tk.Label(root_receiver, text="Результат проверки подписи:").grid(row=4, column=0, sticky="w", padx=5)
tk.Label(root_receiver, textvariable=verify_result_var).grid(row=4, column=1, sticky="w", padx=5)

root_sender.mainloop()
