import requests
import time
from typing import Optional
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
        
        if old_ip and old_ip == new_ip:
            message = (
                f"✅ <b>CF DNS Unchanged</b>\n\n"
                f"📍 Record: <code>{record_name}</code>\n"
                f"🟢 IP: <code>{new_ip}</code>\n"
                f"ℹ️ Already points to best IP, no update needed"
            )
        elif old_ip and old_ip != new_ip:
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

    def send_trigger_notification(self, phase: str = 'all', force: bool = False):
        """Send notification when a manual check is triggered via API"""
        if not self.enabled:
            return False
        
        phase_labels = {
            'all': '全量检测 (延迟+速度)',
            'latency': '仅延迟测试',
            'speed': '仅速度测试'
        }
        phase_label = phase_labels.get(phase, phase)
        force_label = ' [强制刷新]' if force else ''
        
        message = (
            f"🔔 <b>手动触发检测</b>\n\n"
            f"📋 模式: {phase_label}{force_label}\n"
            f"⏰ 时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        return self.send_message(message)

    def send_dns_sync_result(self, record_name: str, best_ip: str, latency: float, 
                              tested_count: int, old_ip: str = '', updated: bool = False):
        """Send DNS sync cron result notification to Telegram"""
        if not self.enabled:
            return False
        
        if updated:
            status = "🔄 已更新"
            ip_line = (
                f"🔴 旧 IP: <code>{old_ip}</code>\n"
                f"🟢 新 IP: <code>{best_ip}</code>"
            )
        else:
            status = "✅ 无变更"
            ip_line = f"🟢 IP: <code>{best_ip}</code>"
        
        message = (
            f"⏰ <b>CF DNS 定时同步</b> {status}\n\n"
            f"📍 Record: <code>{record_name}</code>\n"
            f"{ip_line}\n"
            f"⏱ 延迟: {latency:.2f}ms\n"
            f"📊 测试 IP 数: {tested_count}"
        )
        return self.send_message(message)

    def send_enabled_maintenance_result(self, source: str, success: bool, summary: Optional[dict] = None):
        """Send enabled maintenance task result summary to Telegram."""
        if not self.enabled:
            return False

        summary = summary or {}
        source_labels = {
            'sync_cron': '定时任务',
            'telegram': 'Telegram',
            'api': 'API',
            'manual': '手动',
            'test': '测试'
        }
        source_label = source_labels.get(source, source or 'unknown')

        if success:
            lines = [
                "✅ <b>启用数据维护完成</b>",
                "",
                f"来源: <code>{source_label}</code>",
                f"参与记录: <code>{summary.get('tested_count', 0)}</code>",
                f"写回结果: <code>{summary.get('api_success', 0)}/{summary.get('updated_count', 0)}</code>",
                f"更新成功: <code>{summary.get('enabled_count', 0)}</code>",
                f"更新失效: <code>{summary.get('invalid_count', 0)}</code>",
            ]

            best_result = summary.get('best_sync_result') or {}
            if best_result:
                lines.append(
                    f"同步候选: <code>{best_result.get('address', 'N/A')}:{best_result.get('port', 443)}</code>"
                )
                lines.append(
                    f"速度/延迟: <code>{best_result.get('speed', 0):.2f}MB/s / {best_result.get('latency', 0):.2f}ms</code>"
                )

            sync_message = summary.get('sync_message')
            if sync_message:
                lines.append(f"同步结果: <code>{sync_message}</code>")

            message = "\n".join(lines)
            return self.send_message(message)

        error_message = summary.get('error') or summary.get('message') or 'unknown error'
        message = (
            "❌ <b>启用数据维护失败</b>\n\n"
            f"来源: <code>{source_label}</code>\n"
            f"错误: <code>{error_message}</code>"
        )
        return self.send_message(message)
