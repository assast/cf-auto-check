import requests
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
    
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send a message to Telegram"""
        if not self.enabled:
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': parse_mode
        }
        
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
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Telegram notification: {str(e)}")
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
            latency = r.get('latency', 0)
            speed = r.get('speed', 0)
            region = r.get('region', '')
            
            latency_str = f"{latency:.0f}ms" if latency > 0 else "N/A"
            speed_str = f"{speed:.2f}MB/s" if speed > 0 else "N/A"
            region_str = f" [{region}]" if region else ""
            
            lines.append(f"{i}. <code>{addr}</code>{region_str}")
            lines.append(f"   ⏱ {latency_str} | 📥 {speed_str}")
        
        lines.append("")
        lines.append(f"✅ Total tested: {len(results)} IPs")
        
        message = "\n".join(lines)
        return self.send_message(message)
