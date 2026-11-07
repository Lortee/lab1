"""Хеширование, шифрование и генерация паролей"""

import base64
import hashlib
import json
import secrets
import string

from cryptography.fernet import Fernet

ITERATIONS = 600_000


def derive_keys(
    password: str, salt: bytes, iterations: int = ITERATIONS
) -> tuple[bytes, bytes]:
    """Создание хеша для проверки пароля и ключа"""
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=64
    )
    return derived[:32], base64.urlsafe_b64encode(derived[32:])


def encode_salt(salt: bytes) -> str:
    """Кодирование соли"""
    return base64.b64encode(salt).decode("utf-8")


def decode_salt(value: str) -> bytes:
    """Чтение сохранённой соли"""
    return base64.b64decode(value)


def encode_hash(value: bytes) -> str:
    """Кодирование хеша пароля для сохранения в JSON"""
    return base64.b64encode(value).decode("utf-8")


def decode_hash(value: str) -> bytes:
    """Чтение сохранённого хеша пароля"""
    return base64.b64decode(value)


def encrypt_data(data: dict[str, str], key: bytes) -> str:
    """Шифрование записи"""
    token = Fernet(key).encrypt(json.dumps(data).encode("utf-8"))
    return token.decode("utf-8")


def decrypt_data(token: str, key: bytes) -> dict[str, str]:
    """Расшифровка и проверка записи"""
    result = json.loads(Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8"))
    if not isinstance(result, dict):
        raise TypeError("Некорректный формат данных")
    validated: dict[str, str] = {}
    for key_part, value in result.items():
        if not isinstance(key_part, str) or not isinstance(value, str):
            raise TypeError("Некорректный формат данных")
        validated[key_part] = value
    return validated


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Генерация пароля с выбранными символами"""
    groups: list[str] = []
    if use_uppercase:
        groups.append(string.ascii_uppercase)
    if use_lowercase:
        groups.append(string.ascii_lowercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append(string.punctuation)
    if not groups:
        raise ValueError("Не выбраны символы для генерации")
    if length < len(groups):
        raise ValueError("Длина слишком мала для выбранных типов символов")
    alphabet = "".join(groups)
    password = [secrets.choice(group) for group in groups]
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
