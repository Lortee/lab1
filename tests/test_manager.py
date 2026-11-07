"""Проверка работы менеджера паролей"""

import json

import pytest

from password_manager import PasswordManager


def test_master_password_unlock(tmp_path) -> None:
    """Проверка входа с правильным и неправильным паролем"""
    manager = PasswordManager(tmp_path / "storage.json")
    assert manager.init_master("correct-password") is True
    assert manager.unlock("correct-password") is True
    assert manager.unlock("wrong-password") is False


def test_master_password_cannot_be_reinitialized(tmp_path) -> None:
    """Проверка защиты хеша от перезаписи"""
    path = tmp_path / "storage.json"
    manager = PasswordManager(path)
    assert manager.init_master("first-password") is True
    original = path.read_text(encoding="utf-8")
    assert manager.init_master("second-password") is False
    assert path.read_text(encoding="utf-8") == original


def test_add_list_and_get_entry(tmp_path) -> None:
    """Проверка отображения и расшифровки записей"""
    manager = PasswordManager(tmp_path / "storage.json")
    manager.init_master("master-password")
    assert manager.add_entry("example.com", "user", "secret") is True
    assert manager.list_entries() == ["example.com"]
    assert manager.get_entry("example.com") == {
        "site": "example.com",
        "login": "user",
        "password": "secret",
    }


def test_delete_entry(tmp_path) -> None:
    """Проверка удаления записи из списка"""
    manager = PasswordManager(tmp_path / "storage.json")
    manager.init_master("master-password")
    manager.add_entry("example.com", "user", "secret")
    assert manager.delete_entry("example.com") is True
    assert manager.list_entries() == []


def test_storage_does_not_contain_plaintext_passwords(tmp_path) -> None:
    """Проверка защиты паролей в JSON"""
    path = tmp_path / "storage.json"
    manager = PasswordManager(path)
    manager.init_master("master-password")
    manager.add_entry("example.com", "user", "service-secret")
    content = path.read_text(encoding="utf-8")
    assert "master-password" not in content
    assert "service-secret" not in content
    assert "hash" in json.loads(content)["master"]


def test_generate_password_has_requested_length(tmp_path) -> None:
    """Проверка длины пароля"""
    manager = PasswordManager(tmp_path / "storage.json")
    assert len(manager.generate_password(24)) == 24


def test_locked_storage_rejects_access(tmp_path) -> None:
    """Проверка доступа к паролям"""
    manager = PasswordManager(tmp_path / "storage.json")
    with pytest.raises(RuntimeError):
        manager.list_entries()


def test_encryption_round_trip(tmp_path) -> None:
    """Проверка обратимости шифрования"""
    manager = PasswordManager(tmp_path / "storage.json")
    manager.init_master("master-password")
    value = {"site": "site", "login": "login", "password": "secret"}
    assert manager.decrypt(manager.encrypt(value)) == value
