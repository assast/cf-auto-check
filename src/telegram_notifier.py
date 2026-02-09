import requests
import time
from .config import Config
from .logger import logger


class TelegramNotifier:
    """Telegram notification service with separate proxy support"""
    
    def __init__(self):
        self.enabled = Config.TG_ENABLED
        self.bot_token = Config.TG_BOT_TOKEN
        self.chat_id = Config.TG_CHAT_ID
        self.proxy = Config.TG_PROXY
        
        if self.enabled and (not self.bot_token or not self.chat_id):
            logger.warning("Telegram notification enabled but TG_BOT_TOKEN or TG_CHAT_ID not set")
            self.enabled = False
    
    def _get_proxies(self):
        """Get proxy config for requests (only for TG API calls)"""
        if self.proxy:
            return {
                'http': self.proxy,
                'https': self.proxy
            }
        return None
    
    def send_message(self, message: str, parse_mode: str = 'HTML', max_retries: int = 3) -> bool:
        """Send a message to Telegram with retry logic"""
        if not self.enabled:
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': parse_mode
        }
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url,
                    json=payload,
                    proxies=self._get_proxies(),
                    timeout=30
                )
                
                if response.status_code == 200:
                    logger.info("Telegram notification sent successfully")
                    return True
                else:
                    logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying... (attempt {attempt + 2}/{max_retries})")
                        time.sleep(2 * (attempt + 1))  # Exponential backoff
                    
            except Exception as e:
                logger.error(f"Failed to send Telegram notification: {str(e)}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying... (attempt {attempt + 2}/{max_retries})")
                    time.sleep(2 * (attempt + 1))
        
        logger.error(f"Failed to send Telegram notification after {max_retries} attempts")
        return False
    
    def send_cfip_results(self, results: list, top_count: int = 30):
        """Send CF IP test results to Telegram"""
        if not self.enabled or not results:
            return False
        
        # Build message
        lines = [
            "🚀 <b>CF Auto Check Results</b>",
            f"📊 Top {min(len(results), top_count)} IPs:",
            ""
        ]
        
        for i, r in enumerate(results[:top_count], 1):
            addr = r.get('address', 'N/A')
            port = r.get('port', 443)
            latency = r.get('latency', 0)
            speed = r.get('speed', 0)
            region = r.get('region', '')
            
            latency_str = f"{latency:.0f}ms" if latency > 0 else "N/A"
            speed_str = f"{speed:.2f}MB/s" if speed > 0 else "N/A"
            region_str = f" [{region}]" if region else ""
            
            lines.append(f"{i}. <code>{addr}:{port}</code>{region_str}")
            lines.append(f"   ⏱ {latency_str} | 📥 {speed_str}")
        
        lines.append("")
        lines.append(f"✅ Total tested: {len(results)} IPs")
        
        message = "\n".join(lines)
        return self.send_message(message)

    def send_dns_update(self, record_name: str, old_ip: str, new_ip: str):
        """Send DNS update notification to Telegram"""
        if not self.enabled:
            return False
        
        if old_ip and old_ip != new_ip:
            message = (
                f"🔄 <b>CF DNS Updated</b>\n\n"
                f"📍 Record: <code>{record_name}</code>\n"
                f"🔴 Old IP: <code>{old_ip}</code>\n"
                f"🟢 New IP: <code>{new_ip}</code>"
            )
        else:
            message = (
                f"✅ <b>CF DNS Created</b>\n\n"
                f"📍 Record: <code>{record_name}</code>\n"
                f"🟢 IP: <code>{new_ip}</code>"
            )
        
        return self.send_message(message)
