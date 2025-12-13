# site_analyzer.py
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
import logging
# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SiteAnalyzer:
    def __init__(self):
        self.results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

    def analyze_site(self, url):
        """Основной метод анализа сайта"""
        try:
            if not self.is_valid_url(url):
                return "❌ Ошибка: Некорректный URL"

            # Добавляем протокол если нужно
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            domain = self.extract_domain(url)
            logger.info(f"Начинаем анализ сайта: {domain}")

            # Очищаем предыдущие результаты
            self.results.clear()

            # Выполняем проверки
            self.check_domain_age(domain)

            # Получаем контент сайта
            try:
                response = requests.get(url, headers=self.headers, timeout=15, verify=True)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')

                self.check_content_updates(soup, response)
                self.check_page_structure(soup)
                self.check_builder(soup, url, response)
            except requests.RequestException as e:
                logger.warning(f"Ошибка загрузки сайта: {e}")
                self.results['Доступность'] = '🔴 Негатив (сайт недоступен)'

            self.check_owner(domain)
            self.check_reviews(domain)

            return self.generate_report()

        except Exception as e:
            logger.error(f"Ошибка анализа: {e}")
            return f"❌ Ошибка при анализе сайта: {str(e)}"

    def is_valid_url(self, url):
        """Проверка валидности URL"""
        pattern = re.compile(
            r'^(https?://)?'  # протокол
            r'((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|'  # домен
            r'((\d{1,3}\.){3}\d{1,3}))'  # или IP
            r'(:\d+)?'  # порт
            r'(/[-a-z\d%_.~+]*)*'  # путь
            r'(\?[;&a-z\d%_.~+=-]*)?'  # query string
            r'(#[-a-z\d_]*)?$', re.IGNORECASE)
        return pattern.match(url) is not None

    def extract_domain(self, url):
        """Извлечение домена из URL"""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path

    def check_domain_age(self, domain):
        """Проверка возраста домена"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age = datetime.now() - creation_date
                days = age.days
                months = days // 30

                if days < 120:  # 4 месяца
                    self.results['Возраст домена'] = f'🔴 Негатив ({months} мес.)'
                else:
                    self.results['Возраст домена'] = f'🟢 Не негатив ({months} мес.)'
            else:
                self.results['Возраст домена'] = '🟡 Негатив (не удалось определить)'

        except Exception as e:
            logger.error(f"Ошибка WHOIS: {e}")
            self.results['Возраст домена'] = '🟡 Негатив (ошибка проверки)'

    def check_content_updates(self, soup, response):
        """Проверка обновлений контента"""
        try:
            current_year = datetime.now().year
            current_month = datetime.now().month

            # Проверяем дату в headers
            if 'last-modified' in response.headers:
                last_modified = response.headers['last-modified']
                self.results['Обновления'] = f'🟢 Не негатив (последнее: {last_modified[:20]})'
                return

            # Ищем даты в тексте
            text = soup.get_text()
            date_patterns = [
                r'\b\d{2}[./-]\d{2}[./-]\d{4}\b',  # DD.MM.YYYY
                r'\b\d{4}[./-]\d{2}[./-]\d{2}\b',  # YYYY-MM-DD
                r'\b(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}\b',
            ]

            found_dates = []
            for pattern in date_patterns:
                dates = re.findall(pattern, text, re.IGNORECASE)
                found_dates.extend(dates)

            # Ищем copyright
            copyright_pattern = r'©.*?(\d{4})|copyright.*?(\d{4})'
            copyright_matches = re.findall(copyright_pattern, text, re.IGNORECASE)
            for match in copyright_matches:
                year = match[0] or match[1]
                if year:
                    found_dates.append(year)

            # Анализируем найденные даты
            recent_dates = []
            for date_str in found_dates[:10]:  # Проверяем первые 10 дат
                # Извлекаем год
                year_match = re.search(r'(\d{4})', date_str)
                if year_match:
                    year = int(year_match.group(1))
                    if year >= current_year - 1:
                        recent_dates.append(year)

            if recent_dates:
                self.results['Обновления'] = f'🟢 Не негатив (обновлен в {max(recent_dates)})'
            else:
                self.results['Обновления'] = '🔴 Негатив (нет свежих обновлений)'

        except Exception as e:
            logger.error(f"Ошибка проверки обновлений: {e}")
            self.results['Обновления'] = '🟡 Негатив (ошибка проверки)'

    def check_page_structure(self, soup):
        """Проверка структуры сайта"""
        try:
            # Ищем навигационные элементы
            nav_elements = soup.find_all(['nav', 'ul', 'ol', 'menu'])

            # Считаем внутренние ссылки
            links = soup.find_all('a', href=True)
            internal_links = 0
            for link in links:
                href = link.get('href', '')
                if href.startswith(('#', '/')) or 'http' not in href:
                    internal_links += 1

            # Проверяем наличие форм (признак интерактивности)
            forms = soup.find_all('form')

            # Проверяем различные элементы страницы
            if len(nav_elements) < 1 and internal_links < 8 and len(forms) < 1:
                self.results['Структура'] = '🔴 Негатив (одностраничный)'
            else:
                self.results['Структура'] = f'🟢 Не негатив ({internal_links} ссылок, {len(nav_elements)} навигаций)'

        except Exception as e:
            logger.error(f"Ошибка проверки структуры: {e}")
            self.results['Структура'] = '🟡 Негатив (ошибка проверки)'

    def check_builder(self, soup, url, response):
        """Проверка использования конструктора"""
        try:
            domain = self.extract_domain(url).lower()
            page_text = str(soup).lower()
            html_text = response.text.lower()

            # Признаки бесплатных конструкторов
            free_builders = {
                'Wix': ['wix', 'wixpress', 'wixsite.com'],
                'Weebly': ['weebly', 'weebly.com'],
                'WordPress.com': ['wordpress.com', 'wp.com', 'wp-content'],
                'Blogger': ['blogger', 'blogspot'],
                'Tilda': ['tilda', 'tilda.ws', 'tilda.cc'],
                'Ucoz': ['ucoz', 'ucoz.ru'],
                'Jimdo': ['jimdo', 'jimdosite'],
                'Webnode': ['webnode'],
            }

            # Признаки бесплатных хостингов
            free_hosting = [
                'github.io', 'netlify.app', 'vercel.app',
                'herokuapp.com', '000webhostapp.com',
                'glitch.me', 'repl.co', 'firebaseapp.com',
                'surge.sh', 'web.app'
            ]

            # Проверяем конструкторы
            for builder_name, keywords in free_builders.items():
                if any(keyword in domain for keyword in keywords) or \
                        any(keyword in html_text for keyword in keywords):
                    self.results['Конструктор'] = f'🔴 Негатив ({builder_name})'
                    return

            # Проверяем бесплатный хостинг
            if any(host in domain for host in free_hosting):
                self.results['Конструктор'] = '🔴 Негатив (бесплатный хостинг)'
                return

            # Проверяем мета-теги
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                content = meta_generator['content'].lower()
                for builder_name, keywords in free_builders.items():
                    if any(keyword in content for keyword in keywords):
                        self.results['Конструктор'] = f'🔴 Негатив ({builder_name})'
                        return

            # Проверяем JavaScript файлы
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '').lower()
                for builder_name, keywords in free_builders.items():
                    if any(keyword in src for keyword in keywords):
                        self.results['Конструктор'] = f'🔴 Негатив ({builder_name})'
                        return

            self.results['Конструктор'] = '🟢 Не негатив'

        except Exception as e:
            logger.error(f"Ошибка проверки конструктора: {e}")
            self.results['Конструктор'] = '🟡 Негатив (ошибка проверки)'

    def check_owner(self, domain):
        """Проверка владельца домена"""
        try:
            w = whois.whois(domain)

            # Проверяем организацию
            if w.org:
                self.results['Владелец'] = f'🟢 Не негатив (организация: {w.org[:50]})'
                return

            # Проверяем наличие имени физического лица
            if w.name:
                name = str(w.name)
                # Паттерн для русских ФИО
                ru_name_pattern = r'^[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+(\s+[А-ЯЁ][а-яё]+)?$'
                # Паттерн для английских имен
                en_name_pattern = r'^[A-Z][a-z]+\s+[A-Z][a-z]+$'

                if re.match(ru_name_pattern, name) or re.match(en_name_pattern, name):
                    self.results['Владелец'] = f'🔴 Негатив (частное лицо: {name[:30]})'
                else:
                    self.results['Владелец'] = f'🟡 Не определено ({name[:30]})'
            else:
                self.results['Владелец'] = '🟡 Не определено'

        except Exception as e:
            logger.error(f"Ошибка проверки владельца: {e}")
            self.results['Владелец'] = '🟡 Негатив (ошибка проверки)'

    def check_reviews(self, domain):
        """Базовая проверка отзывов"""
        try:
            # Упрощенная проверка (в реальном проекте нужно API)
            clean_domain = domain.replace('www.', '').split('/')[0]

            # Здесь можно добавить вызов API для проверки отзывов
            # Например: trustpilot, Яндекс.Отзывы и т.д.

            # Временная заглушка
            self.results['Отзывы'] = '🟡 Требует ручной проверки'
            # self.results['Отзывы'] = '🔴 Негатив (нет отзывов)'
            # self.results['Отзывы'] = '🟢 Не негатив (есть положительные отзывы)'

        except Exception as e:
            logger.error(f"Ошибка проверки отзывов: {e}")
            self.results['Отзывы'] = '🟡 Негатив (ошибка проверки)'

    def generate_report(self):
        """Генерация отчета"""
        negative_count = 0
        warning_count = 0

        for value in self.results.values():
            if '🔴' in value:
                negative_count += 1
            elif '🟡' in value and 'Негатив' in value:
                negative_count += 1
                warning_count += 1
            elif '🟡' in value:
                warning_count += 1

        report = "📊 *Результаты анализа сайта*\n\n"

        for key, value in self.results.items():
            report += f"• *{key}*: {value}\n"

        report += "\n" + "=" * 40 + "\n\n"

        if negative_count >= 2:
            report += "❌ *РЕКОМЕНДАЦИЯ:* НЕ ПРОВОДИТЬ ОПЕРАЦИИ НА ДАННОМ САЙТЕ\n\n"
            report += f"*Причина:* {negative_count} негативных факторов"
            if warning_count > 0:
                report += f" и {warning_count} предупреждений"
        else:
            report += "⚠️ *РЕКОМЕНДАЦИЯ:* МОЖНО ИСПОЛЬЗОВАТЬ С ОСТОРОЖНОСТЬЮ\n\n"
            report += f"*Статус:* {negative_count} негативных факторов"
            if warning_count > 0:
                report += f", {warning_count} предупреждений"

        return report