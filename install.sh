#!/bin/bash

echo "============================================"
echo " Установка и запуск чатбота"
echo "============================================"

# Проверяем Python
if ! command -v python3 &> /dev/null; then
    echo "[ОШИБКА] Python3 не найден!"
    echo "Установите Python3 с помощью менеджера пакетов:"
    echo "  macOS: brew install python"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  Fedora: sudo dnf install python3 python3-pip"
    exit 1
fi

# Создаем виртуальное окружение
echo "[1/3] Создаем виртуальное окружение..."
python3 -m venv .venv

# Активируем его
echo "[2/3] Активируем окружение..."
source .venv/bin/activate

# Обновляем pip и устанавливаем зависимости
echo "[3/3] Устанавливаем зависимости..."
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "Установка прошла успешно! Для запуска используйте скрипт start.sh"