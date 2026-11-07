"""Основные функции менеджера паролей"""

import hmac
import secrets
from pathlib import Path
from typing import Any

from .crypto import (
    decode_hash,
    decode_salt,
    decrypt_data,
    derive_keys,
    encode_hash,
    encode_salt,
    encrypt_data,
    generate_password,
)
from .storage import JsonStorage


class PasswordManager:
    """Управление паролями и учётными записями"""

    def __init__(self, storage_file: str | Path = "storage.json") -> None:
        """Создание менеджера для работы с указанным JSON-файлом"""
        self.storage = JsonStorage(storage_file)
        self.data: dict[str, Any] = {}
        self.master_key: bytes | None = None

    def _load(self) -> dict[str, Any]:
        """Загрузка данных из JSON-файла"""
        self.data = self.storage.load()
        return self.data

    def _persist(self) -> None:
        """Сохранение текущих данных в файл"""
        self.storage.persist(self.data)

    def init_master(self, password: str) -> bool:
        """Создание хеша мастер-пароля"""
        data = self._load()
        if "master" in data or not password:
            return False
        salt = secrets.token_bytes(16)
        master_hash, encryption_key = derive_keys(password, salt)
        self.data = {
            "master": {
                "salt": encode_salt(salt),
                "hash": encode_hash(master_hash),
                "iterations": 600_000,
            },
            "entries": {},
        }
        self.master_key = encryption_key
        self._persist()
        return True

    def unlock(self, password: str) -> bool:
        """Проверка мастер-пароля и разблокировка зашифрованных записей"""
        data = self._load()
        master = data.get("master")
        if not isinstance(master, dict) or not password:
            self.master_key = None
            return False
        try:
            salt = decode_salt(str(master["salt"]))
            stored_hash = decode_hash(str(master["hash"]))
            iterations = int(master["iterations"])
        except (KeyError, TypeError, ValueError):
            self.master_key = None
            return False
        calculated_hash, encryption_key = derive_keys(password, salt, iterations)
        if not hmac.compare_digest(calculated_hash, stored_hash):
            self.master_key = None
            return False
        self.master_key = encryption_key
        return True

    def verify_master_password(self, password: str) -> bool:
        """Проверка мастер-пароля без изменения состояния блокировки"""
        data = self._load()
        master = data.get("master")
        if not isinstance(master, dict) or not password:
            return False
        try:
            salt = decode_salt(str(master["salt"]))
            stored_hash = decode_hash(str(master["hash"]))
            iterations = int(master["iterations"])
        except (KeyError, TypeError, ValueError):
            return False
        calculated_hash, _ = derive_keys(password, salt, iterations)
        return hmac.compare_digest(calculated_hash, stored_hash)

    def encrypt(self, data: dict[str, str]) -> str:
        """Шифрование записи"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        return encrypt_data(data, self.master_key)

    def decrypt(self, token: str) -> dict[str, str]:
        """Расшифровка записи"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        return decrypt_data(token, self.master_key)

    def add_entry(self, site: str, login: str, password: str) -> bool:
        """Добавление или обновление записи"""
        if self.master_key is None:
            raise RuntimeError("Сначала разблокируйте хранилище")
        if not site.strip() or not login or not password:
            raise ValueError("Все поля должны быть заполнены")
        storage = self._load()
        entries = storage.setdefault("entries", {})
        if not isinstance(entries, dict):
            raise ValueError("Некорректный формат записей")
        entries[site] = self.encrypt(
            {"site": site, "login": login, "password": password}
        )
        self.data = storage
        self._persist()
        return True

    def get_entry(self, site: str) -> dict[str, str] | None:
        """Получение расшифрованной записи"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        storage = self._load()
        entries = storage.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError("Некорректный формат записей")
        encrypted_data = entries.get(site)
        return self.decrypt(encrypted_data) if isinstance(encrypted_data, str) else None

    def delete_entry(self, site: str) -> bool:
        """Удаление записи"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        storage = self._load()
        entries = storage.get("entries", {})
        if not isinstance(entries, dict) or site not in entries:
            return False
        del entries[site]
        self.data = storage
        self._persist()
        return True

    def list_entries(self) -> list[str]:
        """Получение списка названий сервисов"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        entries = self._load().get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError("Некорректный формат записей")
        return [name for name in entries if isinstance(name, str)]

    def update_entry(self, site: str, login: str, password: str) -> bool:
        """Обновление существующей записи"""
        if self.master_key is None:
            raise RuntimeError("Хранилище заблокировано")
        storage = self._load()
        entries = storage.get("entries", {})
        if not isinstance(entries, dict) or site not in entries:
            return False
        if not login or not password:
            raise ValueError("Все поля должны быть заполнены")
        entries[site] = self.encrypt(
            {"site": site, "login": login, "password": password}
        )
        self.data = storage
        self._persist()
        return True

    def generate_password(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        """Генерация надёжного пароля с выбранными группами символов"""
        return generate_password(
            length, use_uppercase, use_lowercase, use_digits, use_symbols
        )
