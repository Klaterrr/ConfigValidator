# Валидатор конфигурации (cli)

[**English README available here (README_en.md)**](README_en.md)

## Настройка

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Использование

```bash
export CONFIG_PATH=/путь/к/вашему/config.ini
python run_validator.py
```
*(Примечание: Замените `/путь/к/вашему/config.ini` на реальный путь к вашему файлу `config.ini`)*

## Запуск тестов

```bash
pytest
```
