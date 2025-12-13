import logging

from bot.bot import Bot
from bot.handler import MessageHandler

from chatbot.site_analyzer import SiteAnalyzer
from config import Config

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)




# Инициализация бота VK Teams
bot = Bot(token=Config.TEAMS_BOT_TOKEN)
analyzer = SiteAnalyzer()


def message_callback(bot, event):
    """Обработчик сообщений"""
    try:
        text = event.text.strip()
        chat_id = event.from_chat

        logger.info(f"Получено сообщение: {text} от {event.message_author}")

        # Проверяем команду /check
        if text.startswith('/check'):
            parts = text.split(' ', 1)
            if len(parts) < 2:
                bot.send_text(
                    chat_id=chat_id,
                    text="❌ Использование: `/check https://example.com`\nОтправьте ссылку для анализа."
                )
                return

            url = parts[1].strip()

            # Отправляем сообщение о начале анализа
            bot.send_text(
                chat_id=chat_id,
                text=f"🔍 Начинаю анализ сайта: {url}\nПожалуйста, подождите 10-20 секунд..."
            )

            # Выполняем анализ
            report = analyzer.analyze_site(url)

            # Отправляем результаты
            bot.send_text(
                chat_id=chat_id,
                text=report
            )

        elif text.startswith('/help'):
            help_text = """📋 *Доступные команды:*

*/check <URL>* - проанализировать сайт
Пример: `/check https://example.com`

*/help* - показать это сообщение

*Проверяемые параметры:*
1. Возраст домена (< 4 мес. = негатив)
2. Обновления контента (> 1 года = негатив)
3. Владелец (частное лицо = негатив)
4. Отзывы (нет отзывов или мошенничество = негатив)
5. Конструктор (бесплатный конструктор = негатив)
6. Структура (одностраничный = негатив)

*Рекомендация:*
⚠️ Если 2 и более негативных факторов - сайт не рекомендуется
"""
            bot.send_text(chat_id=chat_id, text=help_text)

        else:
            # Если команда не распознана
            bot.send_text(
                chat_id=chat_id,
                text="ℹ️ Для анализа сайта используйте команду:\n`/check https://example.com`\nДля справки: `/help`"
            )

    except Exception as e:
        logger.error(f"Ошибка в обработчике: {e}")
        bot.send_text(
            chat_id=event.from_chat,
            text="❌ Произошла ошибка при обработке запроса. Пожалуйста, попробуйте позже."
        )


# Добавляем обработчик сообщений
bot.dispatcher.add_handler(MessageHandler(callback=message_callback))

def main():
    logger.info("Бот запускается...")
    print("Бот анализатора сайтов запущен!")
    print("Используйте команду /check для анализа сайта")
    print("Пример: /check https://example.com")

    try:
        bot.start_polling()
        bot.idle()
    except KeyboardInterrupt:
        logger.info("Бот остановлен пользователем")
    except Exception as e:
        logger.error(f"Ошибка при запуске бота: {e}")