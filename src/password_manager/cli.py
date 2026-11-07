"""Интерфейс командной строки"""

import getpass
import json

from cryptography.fernet import InvalidToken

from .manager import PasswordManager


def start_manager(manager: PasswordManager) -> bool:
    """Создание мастер-пароля при первом запуске или вход"""
    try:
        data = manager._load()
    except (json.JSONDecodeError, OSError, ValueError):
        print("Ошибка чтения файла хранилища!")
        return False

    if "master" not in data:
        print("Первый запуск. Создание мастер-пароля.")

        while True:
            password = getpass.getpass("Создайте мастер-пароль: ")
            confirmation = getpass.getpass("Повторите мастер-пароль: ")

            if not password:
                print("Пароль не может быть пустым!")
                continue

            if password != confirmation:
                print("Пароли не совпадают!")
                continue

            if manager.init_master(password):
                print("Мастер-пароль успешно создан!")
                return True

    print("Введите мастер-пароль для входа.")

    if not manager.unlock(getpass.getpass("Мастер-пароль: ")):
        print("Неверный мастер-пароль!")
        return False

    print("Доступ разрешён!")
    return True


def run_cli() -> None:
    """Запуск главного меню программы"""
    manager = PasswordManager()

    print("\n=== PASSWORD MANAGER ===")

    if not start_manager(manager):
        return

    while True:
        print("\n========== МЕНЮ ==========")
        print("1. Добавить запись\n2. Список сайтов\n3. Получить запись")
        print("4. Удалить запись\n5. Сгенерировать пароль\n6. Выход")

        choice = input("\nВыберите действие: ").strip()

        try:
            if choice == "1":
                site = input("Название сайта: ").strip()
                login = input("Логин: ").strip()
                password = getpass.getpass("Пароль сайта: ")

                manager.add_entry(site, login, password)
                print("Запись успешно добавлена!")

            elif choice == "2":
                entries = manager.list_entries()

                if entries:
                    print("\n".join(f"- {name}" for name in entries))
                else:
                    print("Список записей пуст!")

            elif choice == "3":
                site = input("Название сайта: ").strip()
                confirm = getpass.getpass("Подтвердите мастер-пароль: ")

                if not manager.verify_master_password(confirm):
                    print("Неверный мастер-пароль!")
                    continue

                entry = manager.get_entry(site)

                if entry is None:
                    print("Запись не найдена!")
                else:
                    print("Логин:", entry["login"])
                    print("Пароль:", entry["password"])

            elif choice == "4":
                site = input("Название сайта: ").strip()

                if manager.delete_entry(site):
                    print("Запись удалена.")
                else:
                    print("Запись не найдена!")

            elif choice == "5":
                password = manager.generate_password()
                print("Сгенерированный пароль:", password)

            elif choice == "6":
                print("Работа завершена.")
                return

            else:
                print("Неизвестная команда!")

        except InvalidToken:
            print(
                "Ошибка расшифровки: данные повреждены "
                "или не соответствуют ключу шифрования."
            )

        except (ValueError, RuntimeError, OSError) as error:
            print("Ошибка:", error)
