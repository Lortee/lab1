"""Точка входа в пакет"""

from .cli import run_cli


def main() -> None:
    """Запуск приложения через командную строку"""
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\nРабота завершена.")


if __name__ == "__main__":
    main()
