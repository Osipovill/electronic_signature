import time

# Параметры генератора линейной конгруэнтности для 31-битной реализации
# Параметры взяты из библиотеки "Numerical Recipes" для оптимальной генерации случайных чисел
a = 1597
c = 51749
m = 2**31 - 1  # Число Мерсенна 2^31-1 = 2147483647

# Инициализация начального значения на основе системного времени
seed = int(time.time() * 1000) % m

def set_seed(s):
    """Установить начальное значение генератора."""
    global seed
    seed = s % m

def my_random():
    """Возвращает следующее псевдослучайное число."""
    global seed
    seed = (a * seed + c) % m
    return seed

def my_getrandbits(n):
    """
    Возвращает целое число, полученное путем генерации n случайных бит.
    Для генерации используется несколько вызовов my_random().
    """
    result = 0
    bits_per_call = 31  # Количество бит, генерируемых за один вызов my_random()
    calls = (n + bits_per_call - 1) // bits_per_call
    for _ in range(calls):
        # Сдвиг накопленных бит влево на 31 позицию
        # Добавление новых случайных бит через побитовое ИЛИ
        result = (result << bits_per_call) | my_random()
    # Обрезка избыточных бит до требуемой длины
    mask = (1 << n) - 1  # Битовая маска длины n
    result = result & mask
    return result

def my_randint(a, b):
    """
    Возвращает случайное целое число из диапазона [a, b] включительно.
    Для равномерного распределения используется метод отбора (rejection sampling).
    """
    import math
    rng = b - a + 1
    bits = math.ceil(math.log2(rng))
    while True:
        r = my_getrandbits(bits)
        if r < rng:
            return a + r

def my_pow(a, b, mod):
    """
    Вычисляет (a^b) mod с помощью алгоритма быстрого возведения в степень.
    """
    result = 1
    a = a % mod
    while b > 0:
        if b & 1:  # Проверка младшего бита на единицу
            result = (result * a) % mod
        a = (a * a) % mod
        b //= 2
    return result

# Функции генерации простых чисел и RSA-ключей
def is_prime_trial(n):
    """Проверка числа n на простоту методом пробного деления."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    # Оптимизированная проверка делимости на малые простые числа
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True

def is_prime_fermat(n, k=5):
    """Проверка числа n на простоту с помощью теста Ферма."""
    if n < 4:
        return n in [2, 3]
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = my_randint(2, n - 2)
        if my_pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits):
    """Генерация простого числа заданной битовой длины."""
    if bits < 2:
        bits = 2
    while True:
        cand = my_getrandbits(bits)
        cand |= (1 << (bits - 1))  # Установка старшего бита
        cand |= 1                  # Обеспечение нечетности числа
        if is_prime_trial(cand) and is_prime_fermat(cand):
            return cand

def egcd(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    """Нахождение обратного элемента e (mod phi), если он существует."""
    gcd_val, x, _ = egcd(e, phi)
    if gcd_val != 1:
        return None
    return x % phi

def generate_rsa_keys(bits=64):
    """
    Генерация упрощённых RSA-ключей (e, d, n) для демонстрационных целей.
    Возвращает словарь с ключами.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Стандартное значение открытой экспоненты, взаимно простое с функцией Эйлера
    if e >= phi or egcd(e, phi)[0] != 1:
        e = 3
        while e < phi and egcd(e, phi)[0] != 1:
            e += 2
    d = mod_inverse(e, phi)
    return {'public': (e, n), 'private': (d, n), 'p': p, 'q': q, 'phi': phi}

# ---------- Вспомогательные функции конвертации ----------
def text_to_int(text):
    """Преобразование текста в целое число (байты big-endian)."""
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_text(num):
    """Преобразование большого целого числа обратно в строку (UTF-8)."""
    if num == 0:
        return ""
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, 'big').decode('utf-8', errors='ignore')

# ---------- Основные RSA-функции (шифрование/дешифрование/подпись/проверка) ----------
def rsa_encrypt(m_int, pubkey):
    """RSA-шифрование числа m_int открытым ключом (e, n)."""
    e, n = pubkey
    return my_pow(m_int, e, n)

def rsa_decrypt(c_int, privkey):
    """RSA-расшифрование числа c_int закрытым ключом (d, n)."""
    d, n = privkey
    return my_pow(c_int, d, n)

def rsa_sign(m_int, privkey):
    """RSA-подпись числа m_int закрытым ключом (d, n)."""
    d, n = privkey
    return my_pow(m_int, d, n)

def rsa_verify(m_int, s_int, pubkey):
    """Проверка подписи s_int для сообщения m_int открытым ключом (e, n)."""
    e, n = pubkey
    return m_int % n == my_pow(s_int, e, n)
