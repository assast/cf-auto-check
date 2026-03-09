import threading
import time
import requests
from .config import Config
from .logger import logger


class TelegramBotController:
    """Simple Telegram long-polling command controller."""

    def __init__(self, service, notifier):
        self.service = service
        self.notifier = notifier
        self.enabled = Config.TG_ENABLED and Config.TG_BOT_COMMANDS_ENABLED and bool(Config.TG_BOT_TOKEN)
        self.bot_token = Config.TG_BOT_TOKEN
        self.allowed_chat_id = str(Config.TG_CHAT_ID).strip() if Config.TG_CHAT_ID else ''
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else ''
        self.offset = None

    def _get_proxies(self):
        return self.notifier._get_proxies()

    def _api_post(self, method, payload):
        url = f"{self.base_url}/{method}"
        return requests.post(url, json=payload, proxies=self._get_proxies(), timeout=60)

    def _api_get(self, method, params=None, timeout=70):
        url = f"{self.base_url}/{method}"
        return requests.get(url, params=params or {}, proxies=self._get_proxies(), timeout=timeout)

    def send_message(self, chat_id, text, reply_to_message_id=None):
        payload = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML'
        }
        if reply_to_message_id:
            payload['reply_parameters'] = {'message_id': reply_to_message_id}
        try:
            resp = self._api_post('sendMessage', payload)
            if resp.ok:
                return True
            logger.error(f"Telegram bot send failed: {resp.status_code} - {resp.text}")
            return False
        except Exception as e:
            logger.error(f"Telegram bot send exception: {e}")
            return False

    def start(self):
        if not self.enabled:
            logger.info("Telegram bot command listener disabled")
            return

        self._register_commands()

        thread = threading.Thread(target=self._poll_loop, daemon=True)
        thread.start()
        logger.info("Telegram bot command listener started")

    def _register_commands(self):
        commands = [
            {'command': 'start', 'description': '显示完整帮助'},
            {'command': 'cfst', 'description': '触发 CFST 检测（详见 /start）'},
            {'command': 'cfst_status', 'description': '查看 CFST 检测状态'},
            {'command': 'cfst_health', 'description': '查看 CFST 健康检查'},
            {'command': 'cf_sync', 'description': '手动同步指定 IP 到 Cloudflare'}
        ]

        payload = {'commands': commands}
        if self.allowed_chat_id:
            payload['scope'] = {
                'type': 'chat',
                'chat_id': int(self.allowed_chat_id)
            }

        try:
            resp = self._api_post('setMyCommands', payload)
            if resp.ok:
                logger.info('Telegram bot commands registered successfully')
            else:
                logger.error(f"Telegram setMyCommands failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Telegram setMyCommands exception: {e}")

    def _poll_loop(self):
        while self.service.running:
            try:
                params = {
                    'timeout': 60,
                    'allowed_updates': ['message']
                }
                if self.offset is not None:
                    params['offset'] = self.offset

                resp = self._api_get('getUpdates', params=params)
                if not resp.ok:
                    logger.error(f"Telegram getUpdates failed: {resp.status_code} - {resp.text}")
                    time.sleep(5)
                    continue

                data = resp.json()
                if not data.get('ok'):
                    logger.error(f"Telegram getUpdates API error: {data}")
                    time.sleep(5)
                    continue

                for update in data.get('result', []):
                    self.offset = update['update_id'] + 1
                    self._handle_update(update)
            except Exception as e:
                logger.error(f"Telegram poll loop error: {e}")
                time.sleep(5)

    def _normalize_command(self, raw):
        cmd = raw.strip()
        if not cmd:
            return ''
        parts = cmd.split()
        if parts and parts[0].startswith('/') and '@' in parts[0]:
            parts[0] = parts[0].split('@', 1)[0]
        return ' '.join(parts)

    def _handle_update(self, update):
        message = update.get('message') or {}
        chat = message.get('chat') or {}
        chat_id = str(chat.get('id', ''))
        text = (message.get('text') or '').strip()
        message_id = message.get('message_id')

        if not text.startswith('/'):
            return

        if self.allowed_chat_id and chat_id != self.allowed_chat_id:
            logger.warning(f"Ignoring Telegram command from unauthorized chat_id={chat_id}")
            self.send_message(chat_id, "❌ Unauthorized chat", reply_to_message_id=message_id)
            return

        cmd = self._normalize_command(text)
        response = self._dispatch_command(cmd)
        if response:
            self.send_message(chat_id, response, reply_to_message_id=message_id)

    def _dispatch_command(self, cmd):
        lower = cmd.lower().strip()

        if lower.startswith('/cfst'):
            return self._handle_cfst(lower)
        if lower == '/cfst_status':
            return self.service.format_status_html()
        if lower == '/cfst_health':
            return self.service.format_health_html()
        if lower.startswith('/cf_sync '):
            ip = cmd.split(None, 1)[1].strip()
            return self.service.handle_manual_cf_sync(ip)
        if lower == '/cf_sync_help':
            return (
                "🛠 <b>CF Sync 命令</b>\n\n"
                "<code>/cf_sync 1.2.3.4</code> - 手动同步指定 IP 到 Cloudflare A 记录"
            )
        if lower in ['/help', '/start']:
            return self._help_text()

        return (
            "❓ <b>未知命令</b>\n\n"
            f"收到: <code>{cmd}</code>\n\n"
            f"{self._help_text()}"
        )

    def _handle_cfst(self, lower):
        parts = lower.split()
        force = 'force' in parts[1:]

        phase = 'all'
        if len(parts) >= 2:
            if parts[1] in ['latency', 'speed', 'reprocess', 'force']:
                if parts[1] != 'force':
                    phase = parts[1]
            elif parts[1] not in ['force']:
                return self._help_text()

        if phase == 'reprocess' and force:
            return "⚠️ <b>reprocess</b> 不支持 force；它只使用缓存数据重新生成结果。"

        return self.service.trigger_manual_check(phase=phase, force_refresh=force, source='telegram')

    def _help_text(self):
        return (
            "🤖 <b>CF Auto Check Bot 命令</b>\n\n"
            "<code>/cfst</code> - 触发全量检测\n"
            "<code>/cfst latency</code> - 只跑延迟测试\n"
            "<code>/cfst speed</code> - 只跑速度测试（用缓存延迟数据）\n"
            "<code>/cfst reprocess</code> - 使用缓存延迟+速度数据重新生成结果\n"
            "<code>/cfst force</code> - 强制重跑（删除缓存）\n"
            "<code>/cfst latency force</code> - 强制重跑延迟\n"
            "<code>/cfst speed force</code> - 强制重跑速度\n"
            "<code>/cfst_status</code> - 查看检测状态\n"
            "<code>/cfst_health</code> - 健康检查\n"
            "<code>/cf_sync &lt;IP&gt;</code> - 手动同步指定 IP 到 Cloudflare A 记录\n"
        )
