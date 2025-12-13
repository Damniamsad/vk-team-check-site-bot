import smtplib
import ssl
from bot.bot import Bot
from bot.handler import MessageHandler

from config import Config

# Конфигурация бота
bot = Bot(token=Config.TEAMS_BOT_TOKEN,
          name='SiteAnalyzerBot',
          )


def send_email(to, subject, text):
    message = f"""\
Subject: {subject}
To: {", ".join(to)}
{text}"""

    port = 465
    smtp_server = "smtp.mail.ru"
    sender_email = "your.server@YOUR.MAIL"
    receiver_email = ''
    for user in to:
        receiver_email += f"{user},"
    ext_application_password = "YOUR_PASS"

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, ext_application_password)
        server.sendmail(sender_email, to, message.encode("utf8"))


def on_message_event(bot, event):
    raw_message = event.text.lower()
    chat_id_to_reply = event.from_chat

    if raw_message != 'send_email':
        bot.send_text(chat_id=chat_id_to_reply,
                      text="Сообщение некоректное" + raw_message)

    message = ""

    msg_from = event.message_author
    event_data = event.data

    data_parts = event_data.get('parts', [])

    for part in data_parts:
        print('part' + part)
        payload_message = part['payload']['message']
        part_msg_from = payload_message['from']['userId']
        reporters.append(part_msg_from)
        message += f"{part_msg_from}:\n{payload_message['text']}\n\n"

    if message:
        send_email(to=["dogman113636@gmail.com"],
                   subject=f"Важное сообщение от {msg_from}",
                   text=message)
        bot.send_text(chat_id=chat_id_to_reply,
                      text="Сообщение отправлено" + message)
    else:
        bot.send_text(chat_id=chat_id_to_reply,
                      text="Не получилось отправить")


# Добавление обработчика сообщений
bot.dispatcher.add_handler(MessageHandler(callback=on_message_event))

# Запуск бота
bot.start_polling()