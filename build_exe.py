# build_exe.py
import PyInstaller.__main__
import os
import shutil

# Очистка предыдущих сборок
if os.path.exists('chatbot/dist'):
    shutil.rmtree('chatbot/dist')
if os.path.exists('chatbot/build'):
    shutil.rmtree('chatbot/build')

# Сборка EXE
PyInstaller.__main__.run([
    'chatbot/main.py',
    '--name=SiteAnalyzerBot',
    '--onefile',  # Один файл EXE
    '--windowed',  # Без консоли (или убрать для отладки)
    # '--icon=bot_icon.ico',  # Опционально: иконка
    '--add-data=requirements.txt;.',  # Включаем файл зависимостей
    '--hidden-import=whois',
    '--hidden-import=bot',
    '--hidden-import=bot.handler',
    '--hidden-import=bot.bot',
    '--collect-all=bot',
    '--clean',
])