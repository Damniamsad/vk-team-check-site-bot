@echo off
echo ============================================
echo  Установка и запуск чатбота
echo ============================================

REM Проверяем Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден!
    echo Установите Python с сайта python.org
    pause
    exit /b 1
)

REM Создаем виртуальное окружение
echo [1/3] Создаем виртуальное окружение...
python -m venv .venv

REM Активируем его
echo [2/3] Активируем окружение...
call .venv\Scripts\activate.bat

REM Обновляем pip и устанавливаем зависимости
echo [3/3] Устанавливаем зависимости...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo Установка прошла успешно для зауска используйте скрипт start.bat