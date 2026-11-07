"""JSON-хранилище менеджера паролей"""

import json
from pathlib import Path
from typing import Any


class JsonStorage:
    """Чтение и запись данных в JSON-файл"""

    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)

    def load(self) -> dict[str, Any]:
        """Загрузка данных из JSON"""
        if not self.file_path.exists():
            return {}
        with self.file_path.open("r", encoding="utf-8") as file:
            content = file.read()
        if not content.strip():
            return {}
        data: Any = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Некорректный формат хранилища")
        return data

    def persist(self, data: dict[str, Any]) -> None:
        """Сохранение данных в JSON-файл"""
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
