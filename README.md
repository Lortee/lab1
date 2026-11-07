# Password Manager

Консольный менеджер паролей. Создаёт мастер-пароль, хранит его проверочный хэш с
уникальной солью, шифрует записи через Fernet и позволяет добавлять, просматривать,
получать и удалять сохранённые данные. Также есть генератор надёжных паролей.

## Структура

```text
password-manager/
├── .github/workflows/ci.yml
├── src/password_manager/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── crypto.py
│   ├── manager.py
│   └── storage.py
├── tests/test_manager.py
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Установка и запуск

Требуется Python 3.10 или новее. С `uv`:

```bash
uv sync --extra dev
uv run password-manager
```


При первом запуске приложение попросит создать мастер-пароль. При следующих
запусках потребуется его ввести. Ввод паролей скрыт. Файл `storage.json`
создаётся автоматически в текущей рабочей папке.

## Команды меню

- Добавить запись (название сервиса, логин и пароль).
- Посмотреть список названий без раскрытия паролей.
- Получить запись после повторного подтверждения мастер-пароля.
- Удалить запись.
- Сгенерировать надёжный пароль.

## Тестирование и проверки качества

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src/password_manager
```

GitHub Actions автоматически запускает тесты и проверки Ruff/mypy при push и pull request.
