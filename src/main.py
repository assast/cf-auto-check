import time
import signal
import sys
import os
import csv
import subprocess
import platform
import urllib3
import socket
import threading
import json
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from croniter import croniter
from .config import Config
from .logger import logger
from .api_client import ApiClient
from .telegram_notifier import TelegramNotifier
from .telegram_bot import TelegramBotController

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CFAutoCheck:
    def __init__(self):
        self.api_client = ApiClient()
        self.telegram = TelegramNotifier()
        self.cron_expression = Config.CHECK_CRON
        self.latency_threads = Config.LATENCY_THREADS
        self.test_mode = Config.TEST_MODE
        self.enable_auto_update = Config.ENABLE_AUTO_UPDATE
        self.enable_cron_scheduler = Config.ENABLE_CRON_SCHEDULER
        self.enable_api_trigger = Config.ENABLE_API_TRIGGER
        self.api_trigger_key = Config.API_TRIGGER_KEY
        self.api_trigger_port = Config.API_TRIGGER_PORT
        self.speed_test_count = Config.SPEED_TEST_COUNT
        self.speed_test_count_443 = Config.SPEED_TEST_COUNT_443
        self.speed_test_url = Config.SPEED_TEST_URL
        self.max_latency = Config.MAX_LATENCY
        self.max_loss = Config.MAX_LOSS
        self.speed_enable_count = Config.SPEED_ENABLE_COUNT
        self.speed_enable_count_443 = Config.SPEED_ENABLE_COUNT_443
        self.sync_to_cf = Config.SYNC_TO_CF
        self.select_mode = Config.SELECT_MODE
        self.sync_to_cf_filter_port = Config.SYNC_TO_CF_FILTER_PORT
        self.cf_api_token = Config.CF_API_TOKEN
        self.cf_zone_id = Config.CF_ZONE_ID
        self.cf_record_name = Config.CF_RECORD_NAME
        self.sync_to_cf_cron = Config.SYNC_TO_CF_CRON
        self.telegram_bot = TelegramBotController(self, self.telegram)
        self.last_check_meta = {
            'status': 'idle',
            'phase': None,
            'force_refresh': False,
            'source': None,
            'started_at': None,
            'finished_at': None,
            'message': 'Idle',
            'last_error': None
        }
        
        self.running = True
        self.check_running = False  # Flag to prevent concurrent checks
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.cfst_dir = os.path.join(self.base_dir, 'cfst_data')
        self.cfst_path = os.path.join(self.cfst_dir, 'cfst')
        self.ips_file = os.path.join(self.cfst_dir, 'ips.txt')
        self.result_file = os.path.join(self.cfst_dir, 'result.csv')
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

    def handle_exit(self, signum, frame):
        logger.info("Shutdown signal received. Stopping service...")
        self.running = False
        sys.exit(0)

    def _split_results_by_port_group(self, results):
        port_443_results = []
        non_443_results = []
        for result in results:
            if result.get('port') == 443:
                port_443_results.append(result)
            else:
                non_443_results.append(result)
        return port_443_results, non_443_results

    def _select_top_results_with_zero_fill(self, results, limit):
        if limit <= 0 or not results:
            return []

        nonzero_results = [r for r in results if r.get('speed', 0) > 0]
        zero_results = [r for r in results if r.get('speed', 0) == 0]

        if len(nonzero_results) >= limit:
            return nonzero_results[:limit]

        remaining_count = limit - len(nonzero_results)
        return nonzero_results + zero_results[:remaining_count]

    def _sort_speed_results_by_mode(self, results):
        if not results:
            return []

        sorted_results = list(results)
        if self.select_mode == 'lowest_latency':
            sorted_results.sort(key=lambda x: (x['latency'], -x['speed']))
        elif self.select_mode == 'lowest_latency_nonzero':
            nonzero_results = [r for r in sorted_results if r['speed'] > 0]
            zero_results = [r for r in sorted_results if r['speed'] == 0]
            nonzero_results.sort(key=lambda x: (x['latency'], -x['speed']))
            zero_results.sort(key=lambda x: x['latency'])
            sorted_results = nonzero_results + zero_results
        else:
            sorted_results.sort(key=lambda x: (-x['speed'], x['latency']))

        return sorted_results

    def _sort_results_by_highest_speed(self, results):
        return sorted(
            results,
            key=lambda x: (-x.get('speed', 0), x.get('latency', float('inf')), x.get('address', ''))
        )

    def _build_latency_lookup(self, latency_results):
        ip_port_to_latency = {}
        for port_results in latency_results.values():
            for result in port_results:
                ip_port_to_latency[(result['address'], result.get('port', 0))] = result
        return ip_port_to_latency

    def _normalize_positive_int(self, value):
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number if number > 0 else None

    def _is_sync_blacklisted(self, cfip):
        value = cfip.get('sync_blacklisted')
        if value is None:
            value = cfip.get('blacklisted')
        if isinstance(value, str):
            return value.strip().lower() in ['1', 'true', 'yes', 'on']
        return bool(value)

    def _filter_sync_allowed_cfips(self, cfips, context):
        allowed = [cfip for cfip in cfips if not self._is_sync_blacklisted(cfip)]
        skipped = len(cfips) - len(allowed)
        if skipped:
            logger.info(f"{context}: skipped {skipped} sync-blacklisted CFIP(s)")
        return allowed

    def _cfip_ref_from_record(self, cfip):
        cfip_id = self._normalize_positive_int(cfip.get('id'))
        if not cfip_id:
            return None
        return {
            'id': cfip_id,
            'address': str(cfip.get('address') or '').strip(),
            'port': self._normalize_positive_int(cfip.get('port')) or 443,
            'sync_blacklisted': 1 if self._is_sync_blacklisted(cfip) else 0
        }

    def _dedupe_cfip_refs(self, refs):
        deduped = []
        seen = set()
        for ref in refs or []:
            if not isinstance(ref, dict):
                continue
            cfip_id = self._normalize_positive_int(ref.get('id'))
            if not cfip_id or cfip_id in seen:
                continue
            item = dict(ref)
            item['id'] = cfip_id
            item['port'] = self._normalize_positive_int(item.get('port')) or 443
            seen.add(cfip_id)
            deduped.append(item)
        return deduped

    def _find_cfip_refs_for_ip(self, ip_address, port=None):
        target_port = self._normalize_positive_int(port)
        cfips = self.api_client.get_cf_ips() or []
        exact_refs = []

        for cfip in cfips:
            record_port = self._normalize_positive_int(cfip.get('port')) or 443
            if target_port and record_port != target_port:
                continue
            address = str(cfip.get('address') or '').strip()
            if address == ip_address:
                ref = self._cfip_ref_from_record(cfip)
                if ref:
                    exact_refs.append(ref)

        if exact_refs:
            return self._dedupe_cfip_refs(exact_refs)

        resolved_refs = []
        for cfip in cfips:
            record_port = self._normalize_positive_int(cfip.get('port')) or 443
            if target_port and record_port != target_port:
                continue
            address = str(cfip.get('address') or '').strip()
            if not address or address == ip_address:
                continue
            try:
                socket.inet_aton(address)
                continue
            except OSError:
                pass

            resolved = self._resolve_domain(address)
            if resolved == ip_address:
                ref = self._cfip_ref_from_record(cfip)
                if ref:
                    resolved_refs.append(ref)

        return self._dedupe_cfip_refs(resolved_refs)

    def blacklist_current_cf_and_trigger_maintenance(self, source='api'):
        if self.check_running:
            return {
                'success': False,
                'error': 'Check already in progress',
                'phase': self.last_check_meta.get('phase'),
                'source': self.last_check_meta.get('source')
            }, 409

        if not self.cf_api_token or not self.cf_zone_id or not self.cf_record_name:
            return {
                'success': False,
                'error': 'Cloudflare DNS configuration incomplete'
            }, 400

        current_ip = self._get_current_cf_dns_ip()
        if not current_ip:
            return {
                'success': False,
                'error': 'No current Cloudflare DNS A record IP found'
            }, 404

        target_port = self.sync_to_cf_filter_port if self.sync_to_cf_filter_port > 0 else None
        refs = self._find_cfip_refs_for_ip(current_ip, target_port)
        if not refs:
            refs = self._find_cfip_refs_for_ip(current_ip)

        ids = [ref['id'] for ref in refs]
        if not ids:
            return {
                'success': False,
                'error': 'Current Cloudflare sync IP has no matching CFIP record',
                'current_ip': current_ip,
                'port': target_port
            }, 404

        blacklist_result = self.api_client.batch_blacklist_cf_ips(ids, sync_blacklisted=True)
        if not blacklist_result.get('success'):
            return {
                'success': False,
                'error': 'Failed to blacklist current CFIP records',
                'current_ip': current_ip,
                'port': target_port,
                'blacklist': blacklist_result
            }, 502

        maintenance_message = self.trigger_enabled_maintenance(source=source)
        return {
            'success': True,
            'message': 'Current Cloudflare sync IP blacklisted and enabled maintenance triggered',
            'current_ip': current_ip,
            'port': target_port,
            'blacklisted_ids': ids,
            'blacklist': blacklist_result,
            'maintenance': maintenance_message,
            'cfip_refs': refs
        }, 200

    def start(self):
        logger.info("CF Auto Check Service Started (Python + CFST)")
        logger.info(f"API URL: {Config.API_URL}")
        logger.info(f"Cron Scheduler: {'Enabled' if self.enable_cron_scheduler else 'Disabled'}")
        logger.info(f"API Trigger: {'Enabled on port ' + str(self.api_trigger_port) if self.enable_api_trigger else 'Disabled'}")
        logger.info(f"Test Mode: {self.test_mode}")
        logger.info(f"Select Mode: {self.select_mode}")
        logger.info(
            f"CFST Threads: {self.latency_threads}, Speed Test Count(non-443): {self.speed_test_count}, "
            f"Speed Test Count(443): {self.speed_test_count_443}, Enable Count(non-443): {self.speed_enable_count}, "
            f"Enable Count(443): {self.speed_enable_count_443}"
        )
        logger.info(f"Sync to CF Filter Port: {self.sync_to_cf_filter_port if self.sync_to_cf_filter_port > 0 else 'All ports'}")
        logger.info(f"Sync to CF: {'Enabled' if self.sync_to_cf else 'Disabled'}")
        logger.info(f"Sync to CF Cron: {self.sync_to_cf_cron if self.sync_to_cf_cron else 'Disabled'}")
        
        self.telegram_bot.start()

        # Start API server if enabled
        if self.enable_api_trigger:
            api_thread = threading.Thread(target=self._run_api_server, daemon=True)
            api_thread.start()
        
        # Start enabled-CFIP maintenance scheduler if configured
        if self.sync_to_cf_cron:
            maintenance_thread = threading.Thread(target=self._run_cf_dns_sync_scheduler, daemon=True)
            maintenance_thread.start()
            logger.info(f"Enabled CFIP maintenance scheduler enabled: {self.sync_to_cf_cron}")
        
        # Run immediately on startup if cron is enabled
        if self.enable_cron_scheduler:
            logger.info(f"Cron Schedule: {self.cron_expression}")
            try:
                self.run_check()
            except Exception as e:
                logger.error(f"Unexpected error in initial check: {str(e)}")
            
            # Then wait for cron schedule
            cron = croniter(self.cron_expression, datetime.now())
            
            while self.running:
                next_run = cron.get_next(datetime)
                wait_seconds = (next_run - datetime.now()).total_seconds()
                
                if wait_seconds > 0:
                    logger.info(f"Next check scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')} (in {wait_seconds:.0f}s)")
                    
                    # Sleep in small intervals to allow for graceful shutdown
                    while wait_seconds > 0 and self.running:
                        sleep_time = min(wait_seconds, 60)  # Check every minute
                        time.sleep(sleep_time)
                        wait_seconds -= sleep_time
                
                if self.running:
                    try:
                        self.run_check()
                    except Exception as e:
                        logger.error(f"Unexpected error in main loop: {str(e)}")
        else:
            # Keep the main thread alive when background services are enabled
            if self.enable_api_trigger or self.sync_to_cf_cron:
                wait_reasons = []
                if self.enable_api_trigger:
                    wait_reasons.append('API trigger')
                if self.sync_to_cf_cron:
                    wait_reasons.append('enabled maintenance scheduler')
                logger.info(f"Cron scheduler disabled, waiting for {', '.join(wait_reasons)}...")
                while self.running:
                    time.sleep(60)
            else:
                logger.warning("Both cron scheduler and API trigger are disabled. Running single check and exiting.")
                try:
                    self.run_check()
                except Exception as e:
                    logger.error(f"Unexpected error in single check: {str(e)}")

    def _run_api_server(self):
        """Run HTTP server for API trigger"""
        service = self
        
        class TriggerHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logger.debug(f"API: {args[0]}")

            def _write_json(self, status_code, payload):
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(payload, ensure_ascii=False).encode())
            
            def do_GET(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                
                # Health check - no auth required
                if parsed.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok'}).encode())
                    return
                
                # Check API key for all other endpoints
                provided_key = query.get('key', [''])[0]
                if parsed.path == '/blacklist-current-cf' and not service.api_trigger_key:
                    self._write_json(403, {'error': 'API_TRIGGER_KEY is required for this endpoint'})
                    return
                if service.api_trigger_key and provided_key != service.api_trigger_key:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Invalid API key'}).encode())
                    return
                
                if parsed.path == '/trigger':
                    if service.check_running:
                        self.send_response(409)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': 'Check already in progress'}).encode())
                        return
                    
                    # Check for force and phase parameters
                    force_refresh = query.get('force', [''])[0].lower() in ['true', '1', 'yes']
                    phase = query.get('phase', ['all'])[0].lower()
                    if phase not in ['all', 'latency', 'speed', 'reprocess']:
                        phase = 'all'
                    
                    # Send TG notification for manual trigger
                    service.telegram.send_trigger_notification(phase=phase, force=force_refresh)
                    response = service.trigger_manual_check(phase=phase, force_refresh=force_refresh, source='api')
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    msg = f'Check triggered (phase={phase})'
                    if force_refresh:
                        msg += ' (force refresh)'
                    self.wfile.write(json.dumps({'message': msg, 'phase': phase, 'force': force_refresh, 'detail': response}).encode())

                elif parsed.path == '/blacklist-current-cf':
                    result, status_code = service.blacklist_current_cf_and_trigger_maintenance(source='api')
                    self._write_json(status_code, result)
                
                elif parsed.path == '/status':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    status = {
                        'running': service.running,
                        'check_in_progress': service.check_running,
                        'cron_enabled': service.enable_cron_scheduler,
                        'cron_expression': service.cron_expression if service.enable_cron_scheduler else None
                    }
                    self.wfile.write(json.dumps(status).encode())
                
                else:
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Not found'}).encode())
        
        try:
            server = HTTPServer(('0.0.0.0', service.api_trigger_port), TriggerHandler)
            logger.info(f"API server started on port {service.api_trigger_port}")
            server.serve_forever()
        except Exception as e:
            logger.error(f"Failed to start API server: {str(e)}")

    def clear_result_cache(self, phase='all'):
        """Clear cached result files for the specified phase
        
        Args:
            phase: 'all' - clear all caches
                   'latency' - clear only latency caches
                   'speed' - clear only speed caches
        """
        if not os.path.exists(self.cfst_dir):
            return
        
        prefixes = []
        if phase in ['all', 'latency']:
            prefixes.append('latency_')
        if phase in ['all', 'speed']:
            prefixes.append('speed_')
        # Also clear legacy result_ files when clearing all
        if phase == 'all':
            prefixes.append('result_')
        
        count = 0
        for filename in os.listdir(self.cfst_dir):
            if filename.endswith('.csv') and any(filename.startswith(p) for p in prefixes):
                filepath = os.path.join(self.cfst_dir, filename)
                try:
                    os.remove(filepath)
                    count += 1
                    logger.info(f"Deleted cached result: {filename}")
                except Exception as e:
                    logger.warning(f"Failed to delete {filename}: {str(e)}")
        
        if count > 0:
            logger.info(f"Cleared {count} cached {phase} result file(s)")

    def run_check(self, force_refresh=False, phase='all', source='system'):
        """Run check cycle
        
        Args:
            force_refresh: If True, delete relevant caches before running
            phase: 'all' - run both latency and speed phases
                   'latency' - run only latency phase
                   'speed' - run only speed phase (uses cached latency data)
                   'reprocess' - use cached latency+speed data to regenerate results
        """
        if self.check_running:
            logger.warning("Check already in progress, skipping...")
            return
        
        self.check_running = True
        self.last_check_meta.update({
            'status': 'running',
            'phase': phase,
            'force_refresh': force_refresh,
            'source': source,
            'started_at': self.last_check_meta.get('started_at') or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'finished_at': None,
            'message': f'Running check: phase={phase}, force={force_refresh}',
            'last_error': None
        })
        try:
            if force_refresh:
                logger.info(f"Force refresh requested for phase={phase}, clearing caches...")
                self.clear_result_cache(phase=phase)
            
            logger.info(f"Starting check cycle (phase={phase})...")
            
            if self.test_mode in ['all', 'cfip']:
                self.check_cf_ips(phase=phase)
                
            if self.test_mode in ['all', 'proxyip']:
                self.check_proxy_ips()
                
            if self.test_mode in ['all', 'outbound']:
                self.check_outbounds()
                
            logger.info("Check cycle completed")
            self.last_check_meta.update({
                'status': 'success',
                'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f'Check completed successfully: phase={phase}'
            })
        except Exception as e:
            self.last_check_meta.update({
                'status': 'error',
                'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f'Check failed: {e}',
                'last_error': str(e)
            })
            raise
        finally:
            self.check_running = False

    def check_cfst_binary(self):
        """Check and download CFST binary if not present"""
        if os.path.exists(self.cfst_path):
            return True
        
        logger.info("CFST binary not found, attempting to download...")
        
        # Determine platform
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == 'darwin':
            if 'arm' in machine:
                filename = 'cfst_darwin_arm64.zip'
            else:
                filename = 'cfst_darwin_amd64.zip'
            is_zip = True
        elif system == 'linux':
            if 'arm' in machine or 'aarch' in machine:
                filename = 'cfst_linux_arm64.tar.gz'
            else:
                filename = 'cfst_linux_amd64.tar.gz'
            is_zip = False
        else:
            logger.error("Windows not supported for auto-download")
            return False
        
        version = "v2.3.4"
        base_url = f"https://github.com/XIU2/CloudflareSpeedTest/releases/download/{version}/{filename}"
        
        # Multiple mirror URLs to try
        mirrors = [
            base_url,
            f"https://ghfast.top/{base_url}",
            f"https://gh-proxy.com/{base_url}",
            f"https://ghproxy.net/{base_url}",
            f"https://mirror.ghproxy.com/{base_url}",
        ]
        
        archive_path = os.path.join(self.cfst_dir, filename)
        
        # Ensure cfst_dir exists
        os.makedirs(self.cfst_dir, exist_ok=True)
        
        for url in mirrors:
            try:
                logger.info(f"Trying to download from: {url}")
                import requests
                response = requests.get(url, timeout=60, stream=True, allow_redirects=True)
                
                # Check content length and status
                content_length = response.headers.get('content-length', '0')
                if response.status_code == 200 and int(content_length) > 1000:
                    with open(archive_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract archive
                    if is_zip:
                        import zipfile
                        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                            zip_ref.extractall(self.cfst_dir)
                    else:
                        import tarfile
                        with tarfile.open(archive_path, 'r:gz') as tar:
                            tar.extractall(path=self.cfst_dir)
                    
                    # Remove archive file
                    os.remove(archive_path)
                    
                    # Make executable
                    os.chmod(self.cfst_path, 0o755)
                    
                    logger.info("CFST binary downloaded and extracted successfully")
                    return True
                else:
                    logger.debug(f"Download failed, status: {response.status_code}, size: {content_length}")
                    
            except Exception as e:
                logger.debug(f"Download failed from {url}: {str(e)}")
                continue
        
        logger.error("Failed to download CFST binary from all mirrors")
        return False

    def export_ips_by_port(self, cfips):
        """Group CF IPs by port and export to separate files for CFST."""
        # Store mapping from (IP, port) to list of original cfips for port-specific lookup
        self.ip_port_to_cfips = {}  # (IP, port) -> list of cfips
        # Track IP occurrence count for duplicate marking
        self.ip_occurrence_count = {}  # IP -> count (across all ports)
        # Track unresolved cfips for later
        self.unresolved_cfips = []
        # Group IPs by port
        self.port_groups = {}
        # Track which cfip IDs have domain addresses (not raw IPs)
        self.cfip_is_domain = {}  # cfip_id -> True if address is domain
        
        for cfip in cfips:
            address = cfip.get('address')
            port = cfip.get('port', 443)
            cfip_id = cfip.get('id')
            
            # Check if address is a domain name
            try:
                socket.inet_aton(address)  # This is already an IP
                ip_addr = address
                self.cfip_is_domain[cfip_id] = False
            except socket.error:
                # It's a domain, resolve it with multiple methods
                self.cfip_is_domain[cfip_id] = True
                ip_addr = self._resolve_domain(address)
                if ip_addr is None:
                    logger.warning(f"Could not resolve {address}, keeping current status")
                    self.unresolved_cfips.append(cfip)
                    continue
                logger.info(f"Resolved {address} -> {ip_addr}")
            
            # Group by port
            if port not in self.port_groups:
                self.port_groups[port] = []
            
            # Avoid duplicate IPs in same port group
            if ip_addr not in self.port_groups[port]:
                self.port_groups[port].append(ip_addr)
            
            # Store mapping ((IP, port) -> list of cfips), append to list
            key = (ip_addr, port)
            if key not in self.ip_port_to_cfips:
                self.ip_port_to_cfips[key] = []
            self.ip_port_to_cfips[key].append(cfip)
            
            # Count IP occurrences across all ports
            self.ip_occurrence_count[ip_addr] = self.ip_occurrence_count.get(ip_addr, 0) + 1
        
        total_cfips = sum(len(cfips) for cfips in self.ip_port_to_cfips.values())
        unique_ips = len(set(ip for ip, _ in self.ip_port_to_cfips.keys()))
        dup_ips = sum(1 for count in self.ip_occurrence_count.values() if count > 1)
        logger.info(f"Grouped {total_cfips} CFIPs into {unique_ips} unique IPs, {len(self.port_groups)} port groups, {len(self.unresolved_cfips)} unresolved, {dup_ips} duplicate IPs")

    def _cleanup_stale_port_files(self):
        """Remove stale ips/result files for ports no longer in current data"""
        if not os.path.exists(self.cfst_dir):
            return

        import re
        active_ports = set(str(p) for p in self.port_groups.keys())
        # Patterns: ips_{port}.txt, speed_ips_{port}.txt, latency_{port}.csv, speed_{port}.csv, result_{port}.csv
        patterns = [
            (re.compile(r'^ips_(\d+)\.txt$'), 'txt'),
            (re.compile(r'^speed_ips_(\d+)\.txt$'), 'txt'),
            (re.compile(r'^latency_(\d+)\.csv$'), 'csv'),
            (re.compile(r'^speed_(\d+)\.csv$'), 'csv'),
            (re.compile(r'^result_(\d+)\.csv$'), 'csv'),
        ]

        count = 0
        for filename in os.listdir(self.cfst_dir):
            for pattern, _ in patterns:
                m = pattern.match(filename)
                if m and m.group(1) not in active_ports:
                    filepath = os.path.join(self.cfst_dir, filename)
                    try:
                        os.remove(filepath)
                        count += 1
                        logger.debug(f"Cleaned up stale file: {filename}")
                    except Exception as e:
                        logger.warning(f"Failed to delete stale file {filename}: {str(e)}")
                    break

        if count > 0:
            logger.info(f"Cleaned up {count} stale port file(s)")

    def _resolve_domain(self, domain):
        """Resolve domain using multiple methods"""
        # Method 1: Standard socket resolution
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            logger.debug(f"socket.gethostbyname failed for {domain}")
        
        # Method 2: Try with getaddrinfo
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_INET)
            if results:
                return results[0][4][0]
        except socket.gaierror:
            logger.debug(f"socket.getaddrinfo failed for {domain}")
        
        # Method 3: Use system dig/nslookup command
        for cmd in [['dig', '+short', domain], ['nslookup', domain]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        # Check if line is an IP address
                        try:
                            socket.inet_aton(line)
                            return line
                        except socket.error:
                            continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return None

    def _get_ip_info(self, ip_addr):
        """Get IP information from ipapi.is API"""
        # Check cache first
        if hasattr(self, '_ip_info_cache') and ip_addr in self._ip_info_cache:
            return self._ip_info_cache[ip_addr]
        try:
            import requests
            response = requests.get(f'https://api.ipapi.is/?q={ip_addr}', timeout=10)
            if response.ok:
                data = response.json()
                info = {
                    'country': data.get('location', {}).get('country_code') or 'N/A',
                    'city': data.get('location', {}).get('city') or 'N/A',
                    'isp': data.get('asn', {}).get('org') or 'N/A',
                    'asn': f"AS{data.get('asn', {}).get('asn')}" if data.get('asn', {}).get('asn') else 'N/A'
                }
                if not hasattr(self, '_ip_info_cache'):
                    self._ip_info_cache = {}
                self._ip_info_cache[ip_addr] = info
                return info
        except Exception as e:
            logger.debug(f"Failed to get IP info for {ip_addr}: {str(e)}")
        return None

    def _prefetch_ip_info(self, unique_ips):
        """Pre-fetch IP info for all unique IPs in parallel using ThreadPoolExecutor"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        if not unique_ips:
            return
        
        self._ip_info_cache = {}
        logger.info(f"Pre-fetching IP info for {len(unique_ips)} unique IPs...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._get_ip_info, ip): ip for ip in unique_ips}
            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        self._ip_info_cache[ip] = result
                except Exception as e:
                    logger.debug(f"Failed to get IP info for {ip}: {str(e)}")
        
        logger.info(f"IP info pre-fetch completed: {len(self._ip_info_cache)}/{len(unique_ips)} succeeded")

    def _run_cfst_process(self, cmd, port, timeout=600):
        """Run a CFST subprocess with real-time output streaming
        
        Args:
            cmd: Command list to execute
            port: Port number for logging prefix
            timeout: Process timeout in seconds
        
        Returns:
            True if process completed successfully, False otherwise
        """
        try:
            process = subprocess.Popen(
                cmd,
                cwd=self.cfst_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"[CFST:{port}] {line}")

            process.wait(timeout=timeout)

            if process.returncode != 0:
                logger.error(f"CFST failed for port {port} with exit code {process.returncode}")
                return False

            return True

        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"CFST timed out for port {port}")
            return False
        except Exception as e:
            logger.error(f"Error running CFST for port {port}: {str(e)}")
            return False

    def _check_cache(self, cache_file, cache_hours):
        """Check if a cache file exists and is within TTL
        
        Returns:
            True if cache is valid, False otherwise
        """
        if not os.path.exists(cache_file) or cache_hours <= 0:
            return False
        
        file_mtime = os.path.getmtime(cache_file)
        file_age_hours = (time.time() - file_mtime) / 3600
        if file_age_hours < cache_hours:
            return True
        return False

    def run_latency_test_for_port(self, port, ips, result_filename=None, ips_filename=None, use_cache=True):
        """Phase 1: Run latency-only CFST test for a specific port
        
        Uses -dd flag to disable download testing for pure latency measurement.
        Uses LATENCY_THREADS for high concurrency.
        
        Returns:
            List of result dicts or None on failure
        """
        if not self.check_cfst_binary():
            return None

        # Write IPs to temp file
        port_ips_file = os.path.join(self.cfst_dir, ips_filename or f'ips_{port}.txt')
        with open(port_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")

        latency_result_file = os.path.join(self.cfst_dir, result_filename or f'latency_{port}.csv')

        # Check cache
        cache_hours = Config.RESULT_CACHE_HOURS
        if use_cache and self._check_cache(latency_result_file, cache_hours):
            file_age_hours = (time.time() - os.path.getmtime(latency_result_file)) / 3600
            logger.info(f"[Phase1] Using cached latency result for port {port} (age: {file_age_hours:.1f}h, TTL: {cache_hours}h)")
            cached_results = self.parse_cfst_results(latency_result_file)
            if cached_results:
                return cached_results
            logger.warning(f"[Phase1] Failed to parse cached latency result for port {port}, re-testing...")

        # Build CFST command - latency only
        cmd = [
            self.cfst_path,
            '-f', port_ips_file,
            '-o', latency_result_file,
            '-tp', str(port),
            '-n', str(self.latency_threads),
            '-dd',  # Disable download testing
            '-tl', str(self.max_latency),
            '-tlr', str(self.max_loss),
            '-p', str(len(ips)),  # Output all results to file
            '-debug'
        ]

        logger.info(f"[Phase1] Running latency test for port {port} with {len(ips)} IPs (threads: {self.latency_threads})")
        logger.info(f"[Phase1] Command: {' '.join(cmd)}")

        if self._run_cfst_process(cmd, port):
            return self.parse_cfst_results(latency_result_file)
        return None

    def run_speed_test_for_port(self, port, ips, download_count, result_filename=None, ips_filename=None, use_cache=True):
        """Phase 2: Run speed test for selected IPs on a specific port
        
        Tests both latency and download speed on the pre-selected IPs.
        
        Args:
            port: Port number
            ips: List of pre-selected IP addresses (top by latency)
            download_count: Number of IPs to speed test (CFST -dn)
        
        Returns:
            List of result dicts or None on failure
        """
        if not self.check_cfst_binary():
            return None

        if not ips:
            logger.warning(f"[Phase2] No IPs to speed test for port {port}")
            return None

        # Write selected IPs to temp file
        speed_ips_file = os.path.join(self.cfst_dir, ips_filename or f'speed_ips_{port}.txt')
        with open(speed_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")

        speed_result_file = os.path.join(self.cfst_dir, result_filename or f'speed_{port}.csv')

        # Check cache
        cache_hours = Config.RESULT_CACHE_HOURS
        if use_cache and self._check_cache(speed_result_file, cache_hours):
            file_age_hours = (time.time() - os.path.getmtime(speed_result_file)) / 3600
            logger.info(f"[Phase2] Using cached speed result for port {port} (age: {file_age_hours:.1f}h, TTL: {cache_hours}h)")
            cached_results = self.parse_cfst_results(speed_result_file)
            if cached_results:
                return cached_results
            logger.warning(f"[Phase2] Failed to parse cached speed result for port {port}, re-testing...")

        # Build CFST command - with speed testing
        dn = min(download_count, len(ips))  # Don't test more than available IPs
        cmd = [
            self.cfst_path,
            '-f', speed_ips_file,
            '-o', speed_result_file,
            '-tp', str(port),
            '-n', str(self.latency_threads),
            '-url', self.speed_test_url,
            '-dn', str(dn),
            '-tl', str(self.max_latency),
            '-tlr', str(self.max_loss),
            '-p', str(len(ips)),  # Output all results to file
            '-debug'
        ]

        logger.info(f"[Phase2] Running speed test for port {port} with {len(ips)} IPs (download test: {dn} IPs)")
        logger.info(f"[Phase2] Command: {' '.join(cmd)}")

        if self._run_cfst_process(cmd, port):
            return self.parse_cfst_results(speed_result_file)
        return None

    def run_latency_phase(self):
        """Phase 1: Run latency tests for all port groups in parallel
        
        Returns:
            Dict of {port: [results]} or None on failure
        """
        total_ports = len(self.port_groups)
        total_ips_all = sum(len(ips) for ips in self.port_groups.values())
        logger.info("=" * 60)
        logger.info(f"[Phase1] LATENCY TESTING - {total_ports} ports, {total_ips_all} IPs (threads: {self.latency_threads})")
        logger.info("=" * 60)

        latency_results = {}

        # Run latency tests for each port sequentially
        port_items = list(self.port_groups.items())
        for idx, (port, ips) in enumerate(port_items, 1):
            logger.info(f"[Phase1] [{idx}/{total_ports}] Running latency test for port {port} ({len(ips)} IPs)")
            try:
                results = self.run_latency_test_for_port(port, ips)
                if results:
                    for r in results:
                        r['port'] = port
                    latency_results[port] = results
                    passed_total = sum(len(r) for r in latency_results.values())
                    logger.info(f"[Phase1] [{idx}/{total_ports}] Port {port}: {len(results)} IPs passed (total passed: {passed_total})")
                else:
                    logger.warning(f"[Phase1] [{idx}/{total_ports}] Port {port}: No results")
            except Exception as e:
                logger.error(f"[Phase1] [{idx}/{total_ports}] Port {port} failed: {str(e)}")

        if not latency_results:
            logger.error("[Phase1] No latency results from any port")
            return None

        total_ips = sum(len(r) for r in latency_results.values())
        logger.info(f"[Phase1] Latency phase completed: {total_ips} IPs across {len(latency_results)} ports")

        # Log top 10 by latency across all ports
        all_latency = []
        for port_results in latency_results.values():
            all_latency.extend(port_results)
        all_latency.sort(key=lambda x: x['latency'])
        
        logger.info(f"[Phase1] Top 10 by latency:")
        for i, r in enumerate(all_latency[:10], 1):
            logger.info(f"  {i}. {r['address']} - {r['latency']:.2f}ms (port {r.get('port', 'N/A')})")

        return latency_results

    def run_speed_phase(self, latency_results):
        """Phase 2: Select top IPs by latency and run speed tests

        Args:
            latency_results: Dict of {port: [results]} from Phase 1

        Returns:
            List of all speed test results, sorted by select_mode, or None
        """
        logger.info("=" * 60)
        logger.info(
            f"[Phase2] SPEED TESTING (non-443 top {self.speed_test_count}, 443 top {self.speed_test_count_443})"
        )
        logger.info("=" * 60)

        all_latency = []
        for port, results in latency_results.items():
            for r in results:
                all_latency.append({**r, 'port': port})
        all_latency.sort(key=lambda x: x['latency'])

        latency_443, latency_non_443 = self._split_results_by_port_group(all_latency)
        selected_443 = latency_443[:self.speed_test_count_443]
        selected_non_443 = latency_non_443[:self.speed_test_count]
        selected_global = selected_443 + selected_non_443

        logger.info(
            f"[Phase2] Selected {len(selected_443)} port-443 IPs (from {len(latency_443)} total, limit {self.speed_test_count_443})"
        )
        logger.info(
            f"[Phase2] Selected {len(selected_non_443)} non-443 IPs (from {len(latency_non_443)} total, limit {self.speed_test_count})"
        )
        logger.info(
            f"[Phase2] Selected {len(selected_global)} total IPs for speed test (from {len(all_latency)} latency results)"
        )

        # Group selected IPs back by port for speed testing
        speed_tasks = {}  # port -> (list of IPs, count)
        for r in selected_global:
            port = r['port']
            if port not in speed_tasks:
                speed_tasks[port] = ([], 0)
            ips, count = speed_tasks[port]
            ips.append(r['address'])
            speed_tasks[port] = (ips, len(ips))

        for port, (ips, count) in speed_tasks.items():
            total_for_port = len(latency_results.get(port, []))
            logger.info(f"[Phase2] Port {port}: selected {count} IPs for speed test (from {total_for_port} latency-tested)")

        # Run speed tests for each port sequentially
        total_speed_ports = len(speed_tasks)
        total_speed_ips = sum(len(ips) for ips, _ in speed_tasks.values())
        logger.info(f"[Phase2] Starting speed tests: {total_speed_ports} ports, {total_speed_ips} IPs")
        all_speed_results = []
        speed_items = list(speed_tasks.items())
        for idx, (port, (ips, download_count)) in enumerate(speed_items, 1):
            logger.info(f"[Phase2] [{idx}/{total_speed_ports}] Running speed test for port {port} ({len(ips)} IPs)")
            try:
                results = self.run_speed_test_for_port(port, ips, download_count)
                if results:
                    for r in results:
                        r['port'] = port
                    all_speed_results.extend(results)
                    logger.info(f"[Phase2] [{idx}/{total_speed_ports}] Port {port}: {len(results)} IPs speed tested (total done: {len(all_speed_results)})")
                else:
                    logger.warning(f"[Phase2] [{idx}/{total_speed_ports}] Port {port}: No speed results")
            except Exception as e:
                logger.error(f"[Phase2] [{idx}/{total_speed_ports}] Port {port} speed test failed: {str(e)}")

        if not all_speed_results:
            logger.error("[Phase2] No speed test results")
            return None

        # Sort results based on select_mode
        all_speed_results = self._sort_speed_results_by_mode(all_speed_results)
        if self.select_mode == 'lowest_latency':
            mode_desc = 'lowest latency'
        elif self.select_mode == 'lowest_latency_nonzero':
            mode_desc = 'lowest latency (non-zero speed first)'
        else:
            mode_desc = 'highest speed'

        logger.info(f"[Phase2] Speed phase completed: {len(all_speed_results)} IPs tested, sorted by {mode_desc}")
        logger.info(f"[Phase2] Top 10 results:")
        for i, r in enumerate(all_speed_results[:10], 1):
            logger.info(f"  {i}. {r['address']} - {r['speed']:.2f}MB/s, {r['latency']:.2f}ms (port {r.get('port', 'N/A')})")

        return all_speed_results

    def _cleanup_maintenance_files(self):
        if not os.path.exists(self.cfst_dir):
            return

        prefixes = ('maint_ips_', 'maint_speed_ips_', 'maint_latency_', 'maint_speed_')
        for filename in os.listdir(self.cfst_dir):
            if filename.startswith(prefixes):
                filepath = os.path.join(self.cfst_dir, filename)
                try:
                    os.remove(filepath)
                except Exception as e:
                    logger.debug(f"[Maintenance] Failed to delete temp file {filename}: {str(e)}")

    def _run_enabled_cfip_tests(self, enabled_cfips):
        logger.info(f"[Maintenance] Preparing {len(enabled_cfips)} enabled CFIPs for stability re-test")
        self.export_ips_by_port(enabled_cfips)

        if not self.port_groups:
            logger.warning("[Maintenance] No enabled IPs available after address resolution")
            return None, []

        total_ports = len(self.port_groups)
        latency_results = {}
        for idx, (port, ips) in enumerate(self.port_groups.items(), 1):
            logger.info(f"[Maintenance] [Latency {idx}/{total_ports}] Port {port}: testing {len(ips)} enabled IPs")
            results = self.run_latency_test_for_port(
                port,
                ips,
                result_filename=f'maint_latency_{port}.csv',
                ips_filename=f'maint_ips_{port}.txt',
                use_cache=False
            )
            if results:
                for result in results:
                    result['port'] = port
                latency_results[port] = results
                logger.info(f"[Maintenance] [Latency {idx}/{total_ports}] Port {port}: {len(results)} IPs passed latency test")
            else:
                logger.warning(f"[Maintenance] [Latency {idx}/{total_ports}] Port {port}: no latency results")

        if not latency_results:
            logger.error("[Maintenance] No latency results available for enabled CFIPs")
            return None, []

        all_speed_results = []
        speed_ports = list(latency_results.items())
        for idx, (port, port_latency_results) in enumerate(speed_ports, 1):
            speed_test_ips = [result['address'] for result in port_latency_results]
            logger.info(f"[Maintenance] [Speed {idx}/{len(speed_ports)}] Port {port}: testing {len(speed_test_ips)} enabled IPs")
            results = self.run_speed_test_for_port(
                port,
                speed_test_ips,
                len(speed_test_ips),
                result_filename=f'maint_speed_{port}.csv',
                ips_filename=f'maint_speed_ips_{port}.txt',
                use_cache=False
            )
            if results:
                for result in results:
                    result['port'] = port
                all_speed_results.extend(results)
                logger.info(f"[Maintenance] [Speed {idx}/{len(speed_ports)}] Port {port}: {len(results)} IPs completed speed test")
            else:
                logger.warning(f"[Maintenance] [Speed {idx}/{len(speed_ports)}] Port {port}: speed test returned no results")

        all_speed_results = self._sort_results_by_highest_speed(all_speed_results)
        if all_speed_results:
            logger.info(f"[Maintenance] Completed enabled CFIP speed test for {len(all_speed_results)} IPs")
        else:
            logger.warning("[Maintenance] No speed results were produced; will fall back to latency-only data for status updates")

        return latency_results, all_speed_results

    def _update_enabled_cfip_results(self, speed_results, latency_results):
        """Update only currently enabled CFIPs after maintenance re-test."""
        ip_port_to_result = {(result['address'], result['port']): result for result in speed_results}
        ip_port_to_latency = self._build_latency_lookup(latency_results)

        ips_need_api = set()
        for (ip_addr, port), _ in self.ip_port_to_cfips.items():
            effective_result = ip_port_to_result.get((ip_addr, port)) or ip_port_to_latency.get((ip_addr, port))
            if effective_result and not effective_result.get('region', '').strip():
                ips_need_api.add(ip_addr)

        if ips_need_api:
            self._prefetch_ip_info(ips_need_api)
        else:
            self._ip_info_cache = {}

        batch_updates = []
        enabled_count = 0
        invalid_count = 0

        for (ip_addr, port), cfip_list in self.ip_port_to_cfips.items():
            result = ip_port_to_result.get((ip_addr, port))
            latency_result = ip_port_to_latency.get((ip_addr, port))
            effective_result = result or latency_result

            is_duplicate = self.ip_occurrence_count.get(ip_addr, 0) > 1
            dup_count = self.ip_occurrence_count.get(ip_addr, 0)
            dup_mark = f"[DUP:{dup_count}] " if is_duplicate else ""

            country = 'N/A'
            isp = 'N/A'
            if effective_result:
                cfst_region = effective_result.get('region', '').strip()
                if cfst_region:
                    country = cfst_region
                    ip_info = self._ip_info_cache.get(ip_addr)
                    isp = ip_info['isp'] if ip_info else 'N/A'
                else:
                    ip_info = self._ip_info_cache.get(ip_addr)
                    if ip_info:
                        country = ip_info['country']
                        isp = ip_info['isp']

            for cfip in cfip_list:
                ip_id = cfip.get('id')
                original_addr = cfip.get('address')
                current_fail_count = int(cfip.get('fail_count') or 0)
                current_status = cfip.get('status') or 'enabled'
                is_domain = self.cfip_is_domain.get(ip_id, False)

                if effective_result:
                    latency_val = effective_result['latency']
                    speed_mb = result['speed'] if result else 0
                    speed_val = speed_mb * 1024
                    name = f"{speed_mb:.2f}MB/s|{latency_val:.2f}ms|{country} {original_addr}{dup_mark}"
                    update_data = {
                        'name': name,
                        'fail_count': 0,
                        'latency': round(latency_val, 2),
                        'speed': round(speed_val, 2),
                        'country': country,
                        'isp': isp
                    }
                    enabled_count += 1
                    if is_domain:
                        logger.info(
                            f"[Maintenance] Updating {original_addr}:{port}: {latency_val:.2f}ms, {speed_mb:.2f}MB/s, {country} "
                            f"(keeping status={current_status}){' [DUP]' if is_duplicate else ''} [DOMAIN-KEEP]"
                        )
                    else:
                        update_data['status'] = 'enabled'
                        logger.info(
                            f"[Maintenance] Updating {original_addr}:{port}: {latency_val:.2f}ms, {speed_mb:.2f}MB/s, {country} (enabled)"
                            f"{' [DUP]' if is_duplicate else ''}"
                        )
                else:
                    new_fail_count = current_fail_count + 1
                    update_data = {
                        'name': f"N/A|N/A|N/A {original_addr}{dup_mark}",
                        'fail_count': new_fail_count,
                        'latency': 0,
                        'speed': 0,
                        'country': 'N/A',
                        'isp': 'N/A'
                    }
                    if is_domain:
                        logger.info(
                            f"[Maintenance] Updating {original_addr}:{port} (failed test, fail_count={new_fail_count}, "
                            f"keeping status={current_status}){' [DUP]' if is_duplicate else ''} [DOMAIN-KEEP]"
                        )
                    else:
                        update_data['status'] = 'invalid'
                        invalid_count += 1
                        logger.info(
                            f"[Maintenance] Setting invalid {original_addr}:{port} (no valid result, fail_count={new_fail_count})"
                            f"{' [DUP]' if is_duplicate else ''}"
                        )

                batch_updates.append((ip_id, update_data))

        for cfip in self.unresolved_cfips:
            cfip_id = cfip.get('id')
            original_addr = cfip.get('address')
            current_fail_count = int(cfip.get('fail_count') or 0)
            current_status = cfip.get('status') or 'enabled'
            new_fail_count = current_fail_count + 1
            update_data = {
                'name': f"N/A|N/A|N/A {original_addr}",
                'fail_count': new_fail_count,
                'latency': 0,
                'speed': 0,
                'country': 'N/A',
                'isp': 'N/A'
            }
            if self.cfip_is_domain.get(cfip_id, False):
                logger.info(
                    f"[Maintenance] Updating {original_addr} (unresolved, fail_count={new_fail_count}, "
                    f"keeping status={current_status}) [DOMAIN-KEEP]"
                )
            else:
                update_data['status'] = 'invalid'
                invalid_count += 1
                logger.info(f"[Maintenance] Setting invalid {original_addr} (unresolved, fail_count={new_fail_count})")
            batch_updates.append((cfip_id, update_data))

        success = failed = 0
        if batch_updates:
            logger.info(f"[Maintenance] Starting batch update for {len(batch_updates)} enabled CFIPs...")
            success, failed = self.api_client.batch_update_cf_ips_api(batch_updates)
            logger.info(f"[Maintenance] Batch update completed: {success} success, {failed} failed")

        return {
            'enabled_count': enabled_count,
            'invalid_count': invalid_count,
            'updated_count': len(batch_updates),
            'api_success': success,
            'api_failed': failed
        }

    def parse_cfst_results(self, result_file=None):
        """Parse CFST result.csv file"""
        if result_file is None:
            result_file = self.result_file
            
        if not os.path.exists(result_file):
            logger.error(f"Result file not found: {result_file}")
            return None
        
        results = []
        try:
            with open(result_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)  # Skip header
                
                for row in reader:
                    if len(row) >= 6:
                        # Format: IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
                        ip_addr = row[0]
                        latency = float(row[4]) if row[4] else 0
                        speed = float(row[5]) if row[5] else 0
                        region = row[6] if len(row) > 6 else ''
                        
                        results.append({
                            'address': ip_addr,
                            'latency': latency,
                            'speed': speed,
                            'region': region
                        })
            
            logger.info(f"Parsed {len(results)} results from {os.path.basename(result_file)}")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing CFST results: {str(e)}")
            return None

    def check_cf_ips(self, phase='all'):
        """Check CF IPs using two-phase approach
        
        Args:
            phase: 'all' - run both latency and speed phases
                   'latency' - run only latency phase (no API update)
                   'speed' - run only speed phase (uses cached latency data)
                   'reprocess' - use cached latency+speed data to regenerate results
        """
        try:
            logger.info("Fetching CF IPs...")
            cfips = self.api_client.get_cf_ips()

            if not cfips:
                logger.warning("No CF IPs found")
                return

            logger.info(f"Found {len(cfips)} CF IPs")
            cfips = self._filter_sync_allowed_cfips(cfips, "Full check")
            if not cfips:
                logger.warning("No sync-allowed CF IPs found")
                return

            # Group IPs by port
            self.export_ips_by_port(cfips)

            # Clean up stale files for ports no longer in current data
            self._cleanup_stale_port_files()

            # === Phase 1: Latency Testing ===
            latency_results = None
            if phase in ['all', 'latency']:
                latency_results = self.run_latency_phase()
                if latency_results is None:
                    logger.error("Latency phase failed, no results")
                    return
            
            if phase == 'latency':
                logger.info("Latency-only phase completed. Use phase=speed or phase=all to run speed tests.")
                return

            # === Phase 2: Speed Testing ===
            # If we didn't run latency phase (speed-only or reprocess mode), load from cache
            if latency_results is None:
                logger.info("Loading cached latency results...")
                latency_results = {}
                for port, ips in self.port_groups.items():
                    latency_file = os.path.join(self.cfst_dir, f'latency_{port}.csv')
                    if os.path.exists(latency_file):
                        cached = self.parse_cfst_results(latency_file)
                        if cached:
                            for r in cached:
                                r['port'] = port
                            latency_results[port] = cached
                            logger.info(f"Loaded {len(cached)} cached latency results for port {port}")
                    else:
                        logger.warning(f"No cached latency results for port {port}, run phase=latency first")
                
                if not latency_results:
                    logger.error("No cached latency data available. Run phase=latency or phase=all first.")
                    return

            # Reprocess mode: load cached speed results instead of running CFST
            if phase == 'reprocess':
                logger.info("[Reprocess] Loading cached speed results...")
                cfst_results = []
                for port in self.port_groups.keys():
                    speed_file = os.path.join(self.cfst_dir, f'speed_{port}.csv')
                    if os.path.exists(speed_file):
                        cached = self.parse_cfst_results(speed_file)
                        if cached:
                            for r in cached:
                                r['port'] = port
                            cfst_results.extend(cached)
                            logger.info(f"[Reprocess] Loaded {len(cached)} cached speed results for port {port}")
                    else:
                        logger.warning(f"[Reprocess] No cached speed results for port {port}")
                
                if not cfst_results:
                    logger.error("[Reprocess] No cached speed data available. Run a full test first.")
                    return
                
                # Sort results based on select_mode
                cfst_results = self._sort_speed_results_by_mode(cfst_results)
                
                logger.info(f"[Reprocess] Loaded {len(cfst_results)} total speed results from cache")
            else:
                cfst_results = self.run_speed_phase(latency_results)

                if cfst_results is None:
                    logger.error("Speed phase failed, no results to update")
                    return

            # === Update API with results ===
            self._update_cfip_results(cfips, cfst_results, latency_results)

        except Exception as e:
            logger.error(f"Error checking CF IPs: {str(e)}")

    def _update_cfip_results(self, cfips, cfst_results, latency_results):
        """Update API with CFST results (called after both phases complete)"""
        speed_results_443, speed_results_non_443 = self._split_results_by_port_group(cfst_results)
        nonzero_speed_results = [r for r in cfst_results if r.get('speed', 0) > 0]
        zero_speed_results = [r for r in cfst_results if r.get('speed', 0) == 0]
        logger.info(f"IPs with non-zero speed: {len(nonzero_speed_results)}, zero speed: {len(zero_speed_results)} (from {len(cfst_results)} total)")
        logger.info(
            f"Enable selection groups: 443={len(speed_results_443)} candidates (limit {self.speed_enable_count_443}), "
            f"non-443={len(speed_results_non_443)} candidates (limit {self.speed_enable_count})"
        )

        top_results_443 = self._select_top_results_with_zero_fill(speed_results_443, self.speed_enable_count_443)
        top_results_non_443 = self._select_top_results_with_zero_fill(speed_results_non_443, self.speed_enable_count)
        top_results = top_results_443 + top_results_non_443

        if len([r for r in speed_results_443 if r.get('speed', 0) > 0]) >= self.speed_enable_count_443:
            logger.info(f"Using top {len(top_results_443)} non-zero speed port-443 IPs (available: {len([r for r in speed_results_443 if r.get('speed', 0) > 0])})")
        elif self.speed_enable_count_443 > 0:
            logger.info(
                f"Not enough non-zero speed port-443 IPs ({len([r for r in speed_results_443 if r.get('speed', 0) > 0])}), "
                f"adding {len(top_results_443) - len([r for r in top_results_443 if r.get('speed', 0) > 0])} zero-speed IPs to reach {self.speed_enable_count_443}"
            )

        if len([r for r in speed_results_non_443 if r.get('speed', 0) > 0]) >= self.speed_enable_count:
            logger.info(f"Using top {len(top_results_non_443)} non-zero speed non-443 IPs (available: {len([r for r in speed_results_non_443 if r.get('speed', 0) > 0])})")
        elif self.speed_enable_count > 0:
            logger.info(
                f"Not enough non-zero speed non-443 IPs ({len([r for r in speed_results_non_443 if r.get('speed', 0) > 0])}), "
                f"adding {len(top_results_non_443) - len([r for r in top_results_non_443 if r.get('speed', 0) > 0])} zero-speed IPs to reach {self.speed_enable_count}"
            )

        # Log diagnostic info
        zero_in_top = len([r for r in top_results if r.get('speed', 0) == 0])
        if zero_in_top > 0:
            logger.warning(f"Top results contain {zero_in_top} IPs with zero speed")

        # Get top N IPs to enable (using (IP, port) combination)
        top_ip_ports = set((r['address'], r['port']) for r in top_results)
        logger.info(f"Enabling top {len(top_ip_ports)} IP:port combinations by {self.select_mode}")

        # Create mapping from (IP, port) to CFST result
        ip_port_to_result = {(r['address'], r['port']): r for r in cfst_results}

        # Also build a latency-only lookup for IPs that passed latency but weren't speed tested
        ip_port_to_latency = {}
        for port_results in latency_results.values():
            for r in port_results:
                ip_port_to_latency[(r['address'], r.get('port', 0))] = r

        # Update API
        if self.enable_auto_update:
            # Only fetch IP info via API for top enabled IPs that lack CFST region
            top_ips_set = set(ip for ip, _ in top_ip_ports)
            ips_need_api = set()
            for (ip_addr, port) in top_ip_ports:
                result = ip_port_to_result.get((ip_addr, port))
                latency_result = ip_port_to_latency.get((ip_addr, port))
                effective = result or latency_result
                if effective:
                    region = effective.get('region', '').strip()
                    if not region:
                        ips_need_api.add(ip_addr)

            if ips_need_api:
                self._prefetch_ip_info(ips_need_api)
            else:
                self._ip_info_cache = {}
                logger.info(f"All top IPs have CFST region info, skipping IP info API calls")

            enabled_count = 0
            batch_updates = []
            enable_ids = []   # IDs to set enabled
            disable_ids = []  # IDs to set disabled
            invalid_ids = []  # IDs to set invalid

            for (ip_addr, port), cfip_list in self.ip_port_to_cfips.items():
                result = ip_port_to_result.get((ip_addr, port))
                latency_result = ip_port_to_latency.get((ip_addr, port))

                # Use speed result if available, otherwise use latency result
                effective_result = result or latency_result

                is_duplicate = self.ip_occurrence_count.get(ip_addr, 0) > 1
                dup_count = self.ip_occurrence_count.get(ip_addr, 0)
                dup_mark = f"[DUP:{dup_count}] " if is_duplicate else ""

                # Get country/ISP: prioritize CFST region code, fall back to API
                if effective_result:
                    cfst_region = effective_result.get('region', '').strip()
                    if cfst_region:
                        country = cfst_region
                        # Try to get ISP from API cache if available
                        ip_info = self._ip_info_cache.get(ip_addr)
                        isp = ip_info['isp'] if ip_info else 'N/A'
                    else:
                        ip_info = self._ip_info_cache.get(ip_addr)
                        if ip_info:
                            country = ip_info['country']
                            isp = ip_info['isp']
                        else:
                            country = 'N/A'
                            isp = 'N/A'

                for cfip in cfip_list:
                    ip_id = cfip.get('id')
                    original_addr = cfip.get('address')
                    current_fail_count = int(cfip.get('fail_count') or 0)
                    current_status = cfip.get('status') or 'enabled'
                    is_domain = self.cfip_is_domain.get(ip_id, False)

                    if effective_result:
                        new_fail_count = 0
                        latency_val = effective_result['latency']
                        # Use speed from speed result if available, otherwise 0
                        speed_mb = result['speed'] if result else 0
                        speed_val = speed_mb * 1024  # Convert MB/s to KB/s

                        speed_str = f"{speed_mb:.2f}MB/s"
                        latency_str = f"{latency_val:.2f}ms"
                        name = f"{speed_str}|{latency_str}|{country} {original_addr}{dup_mark}"

                        update_data = {
                            'name': name,
                            'fail_count': new_fail_count,
                            'latency': round(latency_val, 2),
                            'speed': round(speed_val, 2),
                            'country': country,
                            'isp': isp
                        }

                        if is_domain:
                            logger.info(f"Updating {original_addr}:{port}: {latency_str}, {speed_str}, {country} (keeping status={current_status}){' [DUP]' if is_duplicate else ''} [DOMAIN-KEEP]")
                        else:
                            is_top = (ip_addr, port) in top_ip_ports
                            new_status = 'enabled' if is_top else 'disabled'
                            update_data['status'] = new_status
                            if new_status == 'enabled':
                                enabled_count += 1
                                enable_ids.append(ip_id)
                            else:
                                disable_ids.append(ip_id)
                            logger.info(f"Updating {original_addr}:{port}: {latency_str}, {speed_str}, {country} ({new_status}){' [DUP]' if is_duplicate else ''}")
                    else:
                        new_fail_count = current_fail_count + 1
                        name = f"N/A|N/A|N/A {original_addr}{dup_mark}"
                        update_data = {
                            'name': name,
                            'fail_count': new_fail_count,
                            'latency': 0,
                            'speed': 0,
                            'country': 'N/A',
                            'isp': 'N/A'
                        }

                        if is_domain:
                            logger.info(f"Updating {original_addr}:{port} (failed test, fail_count={new_fail_count}, keeping status={current_status}){' [DUP]' if is_duplicate else ''} [DOMAIN-KEEP]")
                        else:
                            update_data['status'] = 'invalid'
                            invalid_ids.append(ip_id)
                            logger.info(f"Setting invalid {original_addr}:{port} (failed test, fail_count={new_fail_count}){' [DUP]' if is_duplicate else ''}")

                    batch_updates.append((ip_id, update_data))

            # Update unresolved cfips
            for cfip in self.unresolved_cfips:
                cfip_id = cfip.get('id')
                original_addr = cfip.get('address')
                current_fail_count = int(cfip.get('fail_count') or 0)
                current_status = cfip.get('status') or 'enabled'

                new_fail_count = current_fail_count + 1
                name = f"N/A|N/A|N/A {original_addr}"
                update_data = {
                    'name': name,
                    'fail_count': new_fail_count,
                    'latency': 0,
                    'speed': 0,
                    'country': 'N/A',
                    'isp': 'N/A'
                }
                batch_updates.append((cfip_id, update_data))
                logger.info(f"Updating {original_addr} (unresolved, fail_count={new_fail_count}, keeping status={current_status}) [DOMAIN-KEEP]")

            # Execute batch update using batch API
            if batch_updates:
                logger.info(f"Starting batch update for {len(batch_updates)} CFIPs...")
                success, failed = self.api_client.batch_update_cf_ips_api(batch_updates)
                logger.info(f"Batch update completed: {success} success, {failed} failed")

        logger.info(f"CF IP checks completed. {enabled_count} IP-based CFIPs enabled (top {len(top_ip_ports)} IP:port combinations).")

        # Sync best IP to Cloudflare A record if enabled
        if self.sync_to_cf and cfst_results:
            if self.sync_to_cf_filter_port > 0:
                port_filtered = [r for r in cfst_results if r.get('port') == self.sync_to_cf_filter_port]
                if port_filtered:
                    best_ip = port_filtered[0]['address']
                    logger.info(
                        f"Full check best candidate on port {self.sync_to_cf_filter_port}: {best_ip}. "
                        f"Automatic DNS sync is handled by SYNC_TO_CF_CRON maintenance scheduler."
                    )
                else:
                    logger.warning(f"DNS sync candidate search: No IPs found on port {self.sync_to_cf_filter_port}")
            else:
                best_ip = cfst_results[0]['address']
                logger.info(
                    f"Full check best candidate: {best_ip}. "
                    f"Automatic DNS sync is handled by SYNC_TO_CF_CRON maintenance scheduler."
                )

        # Send Telegram notification
        self.telegram.send_cfip_results(top_results, top_count=len(top_results))

    def sync_cf_dns(self, ip_address, silent=False):
        """Sync best IP to Cloudflare DNS A record"""
        if not self.cf_api_token or not self.cf_zone_id or not self.cf_record_name:
            logger.warning("CF DNS sync enabled but missing configuration (CF_API_TOKEN, CF_ZONE_ID, or CF_RECORD_NAME)")
            return False
        
        import requests
        
        headers = {
            'Authorization': f'Bearer {self.cf_api_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            # First, get the record ID by listing DNS records
            list_url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/dns_records"
            params = {'name': self.cf_record_name, 'type': 'A'}
            
            response = requests.get(list_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if not data.get('success'):
                logger.error(f"CF DNS API error: {data.get('errors', 'Unknown error')}")
                return False
            
            records = data.get('result', [])
            
            if records:
                # Update existing record
                record_id = records[0]['id']
                current_ip = records[0].get('content', '')
                
                if current_ip == ip_address:
                    logger.info(f"CF DNS A record {self.cf_record_name} already points to {ip_address}, skipping update")
                    if not silent:
                        self.telegram.send_dns_update(self.cf_record_name, ip_address, ip_address)
                    return True
                
                update_url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/dns_records/{record_id}"
                update_data = {
                    'type': 'A',
                    'name': self.cf_record_name,
                    'content': ip_address,
                    'ttl': 60,  # 1 minute TTL for fast updates
                    'proxied': False  # Don't proxy the A record
                }
                
                response = requests.put(update_url, headers=headers, json=update_data, timeout=30)
                response.raise_for_status()
                result = response.json()
                
                if result.get('success'):
                    logger.info(f"CF DNS A record {self.cf_record_name} updated: {current_ip} -> {ip_address}")
                    # Send TG notification
                    if not silent:
                        self.telegram.send_dns_update(self.cf_record_name, current_ip, ip_address)
                    return True
                else:
                    logger.error(f"CF DNS update failed: {result.get('errors', 'Unknown error')}")
                    return False
            else:
                # Create new record
                create_url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/dns_records"
                create_data = {
                    'type': 'A',
                    'name': self.cf_record_name,
                    'content': ip_address,
                    'ttl': 60,
                    'proxied': False
                }
                
                response = requests.post(create_url, headers=headers, json=create_data, timeout=30)
                response.raise_for_status()
                result = response.json()
                
                if result.get('success'):
                    logger.info(f"CF DNS A record {self.cf_record_name} created with IP {ip_address}")
                    # Send TG notification
                    if not silent:
                        self.telegram.send_dns_update(self.cf_record_name, '', ip_address)
                    return True
                else:
                    logger.error(f"CF DNS create failed: {result.get('errors', 'Unknown error')}")
                    return False
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"CF DNS sync failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"CF DNS sync error: {str(e)}")
            return False

    def _get_current_cf_dns_ip(self):
        if not self.cf_api_token or not self.cf_zone_id or not self.cf_record_name:
            return ''

        import requests

        try:
            headers = {
                'Authorization': f'Bearer {self.cf_api_token}',
                'Content-Type': 'application/json'
            }
            list_url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/dns_records"
            params = {'name': self.cf_record_name, 'type': 'A'}
            response = requests.get(list_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            if not data.get('success'):
                return ''
            records = data.get('result', [])
            if not records:
                return ''
            return records[0].get('content', '')
        except Exception as e:
            logger.debug(f"Failed to query current CF DNS IP: {str(e)}")
            return ''

    def _finalize_enabled_maintenance(self, source, success, message, summary=None, error=None):
        finished_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.last_check_meta.update({
            'status': 'success' if success else 'error',
            'finished_at': finished_at,
            'message': message,
            'last_error': error
        })

        notify_summary = dict(summary or {})
        notify_summary.setdefault('message', message)
        if error:
            notify_summary['error'] = error
        self.telegram.send_enabled_maintenance_result(source=source, success=success, summary=notify_summary)

    def trigger_enabled_maintenance(self, source='telegram'):
        """Trigger enabled-CFIP maintenance in background."""
        if self.check_running:
            running_phase = self.last_check_meta.get('phase') or 'unknown'
            return (
                "⏳ <b>任务正在运行</b>\n\n"
                f"当前阶段: <code>{html.escape(str(running_phase))}</code>\n"
                f"来源: <code>{html.escape(str(self.last_check_meta.get('source') or 'unknown'))}</code>"
            )

        self.last_check_meta.update({
            'status': 'starting',
            'phase': 'enabled_maintenance',
            'force_refresh': True,
            'source': source,
            'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'finished_at': None,
            'message': 'Enabled maintenance queued',
            'last_error': None
        })

        def run_async_maintenance():
            try:
                self.run_cf_dns_sync(source=source)
            except Exception as e:
                logger.error(f"Error in manual enabled maintenance thread: {str(e)}")

        thread = threading.Thread(target=run_async_maintenance, daemon=True)
        thread.start()
        return (
            "🚀 <b>已启动启用数据维护</b>\n\n"
            "会重测已启用记录的延迟和速度，并尝试同步配置端口下最快的结果到 Cloudflare。\n"
            "请稍后用 <code>/cfst_status</code> 查看状态。"
        )

    def _run_cf_dns_sync_scheduler(self):
        """Run cron scheduler for enabled CFIP maintenance and optional CF sync."""
        logger.info(f"[Maintenance] Starting enabled CFIP maintenance scheduler with cron: {self.sync_to_cf_cron}")

        # Optionally run once on startup (controlled by RUN_MAINTENANCE_ON_STARTUP, default false)
        if Config.RUN_MAINTENANCE_ON_STARTUP:
            try:
                self.run_cf_dns_sync(source='sync_cron')
            except Exception as e:
                logger.error(f"[Maintenance] Error in initial enabled maintenance: {str(e)}")
        else:
            logger.info("[Maintenance] Skipping initial run on startup (RUN_MAINTENANCE_ON_STARTUP=false)")
        
        cron = croniter(self.sync_to_cf_cron, datetime.now())
        
        while self.running:
            next_run = cron.get_next(datetime)
            wait_seconds = (next_run - datetime.now()).total_seconds()
            
            if wait_seconds > 0:
                logger.info(f"[Maintenance] Next enabled maintenance scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')} (in {wait_seconds:.0f}s)")
                
                while wait_seconds > 0 and self.running:
                    sleep_time = min(wait_seconds, 60)
                    time.sleep(sleep_time)
                    wait_seconds -= sleep_time
            
            if self.running:
                try:
                    self.run_cf_dns_sync(source='sync_cron')
                except Exception as e:
                    logger.error(f"[Maintenance] Error in scheduled enabled maintenance: {str(e)}")

    def run_cf_dns_sync(self, source='sync_cron'):
        """Re-test enabled CFIPs, update their status, then sync fastest 443 result to Cloudflare."""
        if self.check_running:
            logger.warning("[Maintenance] Another check is already running, skipping enabled maintenance cycle")
            return

        self.check_running = True
        started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.last_check_meta.update({
            'status': 'running',
            'phase': 'enabled_maintenance',
            'force_refresh': True,
            'source': source,
            'started_at': started_at,
            'finished_at': None,
            'message': 'Running enabled maintenance cycle',
            'last_error': None
        })

        try:
            logger.info("[Maintenance] Starting enabled CFIP maintenance cycle...")
            self._cleanup_maintenance_files()

            if not self.check_cfst_binary():
                raise RuntimeError("CFST binary not available")

            cfips = self.api_client.get_cf_ips()
            if not cfips:
                message = "No CF IPs found from API"
                logger.warning(f"[Maintenance] {message}")
                self._finalize_enabled_maintenance(
                    source=source,
                    success=True,
                    message=message,
                    summary={'tested_count': 0, 'enabled_count': 0, 'invalid_count': 0, 'sync_message': 'No data'}
                )
                return

            enabled_cfips = [
                ip for ip in cfips
                if ip.get('status') == 'enabled' and not self._is_sync_blacklisted(ip)
            ]
            skipped_blacklisted = len([ip for ip in cfips if ip.get('status') == 'enabled' and self._is_sync_blacklisted(ip)])
            if skipped_blacklisted:
                logger.info(f"[Maintenance] Skipped {skipped_blacklisted} sync-blacklisted enabled CFIP(s)")
            if not enabled_cfips:
                message = "No enabled CF IPs found"
                logger.warning(f"[Maintenance] {message}")
                self._finalize_enabled_maintenance(
                    source=source,
                    success=True,
                    message=message,
                    summary={'tested_count': 0, 'enabled_count': 0, 'invalid_count': 0, 'sync_message': 'No enabled records'}
                )
                return

            latency_results, speed_results = self._run_enabled_cfip_tests(enabled_cfips)
            if not latency_results:
                raise RuntimeError("No latency results from enabled CFIPs")

            summary = self._update_enabled_cfip_results(speed_results, latency_results)
            logger.info(
                f"[Maintenance] Enabled maintenance updated {summary['updated_count']} records: "
                f"{summary['enabled_count']} enabled, {summary['invalid_count']} invalid"
            )

            sync_message = "Cloudflare sync skipped"
            best_result_summary = None
            filter_port = self.sync_to_cf_filter_port
            filtered_sync_results = [result for result in speed_results if result.get('speed', 0) > 0]
            if filter_port > 0:
                filtered_sync_results = [
                    result for result in filtered_sync_results
                    if result.get('port') == filter_port
                ]
            filtered_sync_results = self._sort_results_by_highest_speed(filtered_sync_results)

            if filtered_sync_results:
                best_result = filtered_sync_results[0]
                best_ip = best_result['address']
                best_result_summary = {
                    'address': best_result['address'],
                    'port': best_result.get('port', filter_port if filter_port > 0 else 443),
                    'speed': best_result.get('speed', 0),
                    'latency': best_result.get('latency', 0)
                }
                logger.info(
                    f"[Maintenance] Best sync candidate on port {best_result_summary['port']}: {best_ip} "
                    f"({best_result['speed']:.2f}MB/s, {best_result['latency']:.2f}ms)"
                )

                if self.sync_to_cf:
                    old_ip = self._get_current_cf_dns_ip()
                    if self.sync_cf_dns(best_ip, silent=True):
                        if old_ip and old_ip != best_ip:
                            sync_message = f"{old_ip} -> {best_ip}"
                        elif old_ip == best_ip:
                            sync_message = f"unchanged {best_ip}"
                        else:
                            sync_message = f"created {best_ip}"
                    else:
                        sync_message = f"Cloudflare sync failed for {best_ip}"
                else:
                    sync_message = f"best sync candidate {best_ip}:{best_result_summary['port']} (SYNC_TO_CF disabled)"
                    logger.info(f"[Maintenance] {sync_message}")
            else:
                if filter_port > 0:
                    sync_message = f"No positive-speed result available on port {filter_port} for Cloudflare sync"
                else:
                    sync_message = "No positive-speed result available for Cloudflare sync"
                logger.warning(f"[Maintenance] {sync_message}")

            final_message = (
                f"Enabled maintenance completed: updated={summary['updated_count']}, "
                f"enabled={summary['enabled_count']}, invalid={summary['invalid_count']}; {sync_message}"
            )
            self._finalize_enabled_maintenance(
                source=source,
                success=True,
                message=final_message,
                summary={
                    'tested_count': len(enabled_cfips),
                    'updated_count': summary['updated_count'],
                    'enabled_count': summary['enabled_count'],
                    'invalid_count': summary['invalid_count'],
                    'api_success': summary['api_success'],
                    'api_failed': summary['api_failed'],
                    'best_sync_result': best_result_summary,
                    'sync_message': sync_message
                }
            )
            logger.info(f"[Maintenance] Cycle completed. {sync_message}")

        except Exception as e:
            logger.error(f"[Maintenance] Enabled maintenance failed: {str(e)}")
            self._finalize_enabled_maintenance(
                source=source,
                success=False,
                message=f'Enabled maintenance failed: {e}',
                summary={'tested_count': 0},
                error=str(e)
            )
            raise
        finally:
            self._cleanup_maintenance_files()
            self.check_running = False

    def trigger_manual_check(self, phase='all', force_refresh=False, source='manual'):
        """Trigger a manual check in background."""
        if self.check_running:
            running_phase = self.last_check_meta.get('phase') or 'unknown'
            return (
                "⏳ <b>CFST 正在运行</b>\n\n"
                f"当前阶段: <code>{html.escape(str(running_phase))}</code>\n"
                f"来源: <code>{html.escape(str(self.last_check_meta.get('source') or 'unknown'))}</code>"
            )

        self.last_check_meta.update({
            'status': 'starting',
            'phase': phase,
            'force_refresh': force_refresh,
            'source': source,
            'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'finished_at': None,
            'message': f'Manual check queued: phase={phase}, force={force_refresh}',
            'last_error': None
        })

        def run_async_check():
            try:
                self.run_check(force_refresh=force_refresh, phase=phase, source=source)
            except Exception as e:
                logger.error(f"Error in manual async check: {str(e)}")
                self.last_check_meta.update({
                    'status': 'error',
                    'finished_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': f'Check failed: {e}',
                    'last_error': str(e)
                })

        thread = threading.Thread(target=run_async_check, daemon=True)
        thread.start()

        labels = {
            'all': '全量检测',
            'latency': '仅延迟测试',
            'speed': '仅速度测试',
            'reprocess': '缓存重处理'
        }
        suffix = '（强制刷新）' if force_refresh else ''
        return f"🚀 <b>已启动{labels.get(phase, phase)}</b>{suffix}\n\n请稍后用 <code>/cfst_status</code> 查看状态。"

    def format_status_html(self):
        meta = self.last_check_meta
        lines = [
            "📊 <b>CFST 检测状态</b>",
            "",
            f"状态: <code>{html.escape(str(meta.get('status') or 'idle'))}</code>",
            f"阶段: <code>{html.escape(str(meta.get('phase') or '-'))}</code>",
            f"来源: <code>{html.escape(str(meta.get('source') or '-'))}</code>",
            f"强制刷新: <code>{'yes' if meta.get('force_refresh') else 'no'}</code>",
            f"运行中: <code>{'yes' if self.check_running else 'no'}</code>",
            f"开始时间: <code>{html.escape(str(meta.get('started_at') or '-'))}</code>",
            f"结束时间: <code>{html.escape(str(meta.get('finished_at') or '-'))}</code>",
            f"信息: <code>{html.escape(str(meta.get('message') or '-'))}</code>"
        ]
        if meta.get('last_error'):
            lines.append(f"错误: <code>{html.escape(str(meta.get('last_error')))}</code>")
        return "\n".join(lines)

    def format_health_html(self):
        checks = []
        checks.append(("CFST binary", 'ok' if os.path.exists(self.cfst_path) else 'missing'))
        checks.append(("Cron scheduler", 'enabled' if self.enable_cron_scheduler else 'disabled'))
        checks.append(("API trigger", 'enabled' if self.enable_api_trigger else 'disabled'))
        checks.append(("Telegram bot", 'enabled' if self.telegram_bot.enabled else 'disabled'))
        checks.append(("Telegram target chat", self.telegram.chat_id or 'unset'))
        checks.append(("Telegram proxy", Config.TG_PROXY or 'not set'))
        checks.append(("Auto update CFIP", 'enabled' if self.enable_auto_update else 'disabled'))
        checks.append(("Auto sync to Cloudflare", 'enabled' if self.sync_to_cf else 'disabled'))
        checks.append(("Enabled maintenance cron", self.sync_to_cf_cron or 'disabled'))
        checks.append(("CF API token", 'set' if self.cf_api_token else 'missing'))
        checks.append(("CF zone", self.cf_zone_id or 'missing'))
        checks.append(("CF record", self.cf_record_name or 'missing'))
        checks.append(("Cache dir", self.cfst_dir))

        lines = ["🩺 <b>CFST 健康检查</b>", ""]
        for k, v in checks:
            lines.append(f"{html.escape(str(k))}: <code>{html.escape(str(v))}</code>")
        return "\n".join(lines)

    def handle_import_cf_ip(self, ip: str, port: int, remark: str = '', from_user_id: str = '未知', src_chat_id: str = '', src_message_id: str = ''):
        """Import an IP:port from a Telegram report.

        Preferred path: call a dedicated import API (CFIP_IMPORT_API_URL) with key.
        Fallback: try to create/update via the existing /api/cfip endpoints.

        Returns: (user_reply_html, broadcast_text)
        """
        try:
            socket.inet_aton(ip)
        except OSError:
            msg = f"❌ <b>入库失败</b>：IP 格式无效：<code>{html.escape(ip)}</code>"
            return msg, f"✗ 导入失败: {ip}:{port} (IP无效)"

        if port <= 0 or port > 65535:
            msg = f"❌ <b>入库失败</b>：端口无效：<code>{html.escape(str(port))}</code>"
            return msg, f"✗ 导入失败: {ip}:{port} (端口无效)"

        remark = remark or ip

        # --- Preferred: dedicated import API ---
        import_url = (Config.CFIP_IMPORT_API_URL or '').strip()
        import_key = (Config.CFIP_IMPORT_API_KEY or '').strip()
        if import_url and import_key:
            try:
                import requests
                resp = requests.post(
                    import_url,
                    json={
                        'address': ip,
                        'port': int(port),
                        'remark': remark,
                        'apiKey': import_key,
                    },
                    headers={
                        'Content-Type': 'application/json',
                        'X-API-Key': import_key,
                    },
                    timeout=10,
                )

                # Try parse json; if not json, fallback to text
                try:
                    data = resp.json()
                except Exception:
                    data = None

                # Success
                if resp.status_code == 200 and isinstance(data, dict) and data.get('success'):
                    new_id = ((data.get('data') or {}) if isinstance(data.get('data'), dict) else {}).get('id')
                    content = (
                        "✅ <b>导入成功</b>\n\n"
                        f"IP: <code>{html.escape(ip)}</code>\n"
                        f"Port: <code>{html.escape(str(port))}</code>\n"
                        + (f"ID: <code>{html.escape(str(new_id))}</code>\n" if new_id else "")
                        + f"备注: <code>{html.escape(remark)}</code>"
                    )
                    broadcast = (
                        f"✓ 导入成功: {ip}:{port}\n"
                        + (f"ID: {new_id}\n" if new_id else "")
                        + f"备注: {remark}\n"
                        + f"来源用户: {from_user_id}\n"
                        + f"原始消息: {src_chat_id}/{src_message_id}"
                    )
                    return content, broadcast

                # Already exists
                if resp.status_code == 409:
                    existing_id = None
                    if isinstance(data, dict):
                        existing_id = data.get('existingId') or ((data.get('data') or {}) if isinstance(data.get('data'), dict) else {}).get('id')
                    content = (
                        "⚠️ <b>已存在</b>\n\n"
                        f"IP: <code>{html.escape(ip)}</code>\n"
                        f"Port: <code>{html.escape(str(port))}</code>\n"
                        + (f"ID: <code>{html.escape(str(existing_id))}</code>\n" if existing_id else "")
                        + f"备注: <code>{html.escape(remark)}</code>"
                    )
                    broadcast = (
                        f"⚠️ 已存在: {ip}:{port}\n"
                        + (f"ID: {existing_id}\n" if existing_id else "")
                        + f"备注: {remark}\n"
                        + f"来源用户: {from_user_id}\n"
                        + f"原始消息: {src_chat_id}/{src_message_id}"
                    )
                    return content, broadcast

                # Other failures
                err = ''
                if isinstance(data, dict):
                    err = str(data.get('error') or data.get('message') or '')
                err = err or getattr(resp, 'text', '')
                msg = (
                    "❌ <b>导入失败</b>\n\n"
                    f"IP: <code>{html.escape(ip)}</code>\n"
                    f"Port: <code>{html.escape(str(port))}</code>\n"
                    f"错误: <code>{html.escape(err[:500])}</code>"
                )
                return msg, f"✗ 导入失败: {ip}:{port} ({err[:120]})"

            except requests.exceptions.Timeout:
                msg = f"❌ <b>导入失败</b>：API 请求超时（10s）: <code>{html.escape(ip)}:{html.escape(str(port))}</code>"
                return msg, f"✗ API超时: {ip}:{port}"
            except Exception as e:
                logger.error(f"CFIP import API call failed: {e}")
                msg = "❌ <b>导入失败</b>：API 请求异常。请查看日志。"
                return msg, f"✗ API异常: {ip}:{port}"

        # --- Fallback: existing API CRUD ---
        cfips = self.api_client.get_cf_ips() or []
        existing = None
        for item in cfips:
            if str(item.get('address') or '').strip() == ip and int(item.get('port') or 443) == int(port):
                existing = item
                break

        if existing and existing.get('id'):
            ip_id = existing['id']
            try:
                self.api_client.update_cf_ip(ip_id, {'name': remark})
            except Exception:
                pass
            content = (
                "✅ <b>已存在，已更新备注</b>\n\n"
                f"IP: <code>{html.escape(ip)}</code>\n"
                f"Port: <code>{html.escape(str(port))}</code>\n"
                f"ID: <code>{html.escape(str(ip_id))}</code>\n"
                f"备注: <code>{html.escape(remark)}</code>"
            )
            broadcast = f"✓ 已存在并更新备注: {ip}:{port} (ID:{ip_id})"
            return content, broadcast

        payload = {
            'address': ip,
            'port': int(port),
            'status': 'disabled',
            'name': remark,
        }

        created = self.api_client.create_cf_ip(payload)
        if created and (created.get('success') or created.get('data') or created.get('id')):
            created_id = (created.get('data') or {}).get('id') or created.get('id') or ''
            content = (
                "✅ <b>入库成功</b>\n\n"
                f"IP: <code>{html.escape(ip)}</code>\n"
                f"Port: <code>{html.escape(str(port))}</code>\n"
                + (f"ID: <code>{html.escape(str(created_id))}</code>\n" if created_id else "")
                + f"备注: <code>{html.escape(remark)}</code>"
            )
            return content, f"✓ 入库成功: {ip}:{port} (ID:{created_id})"

        content = (
            "❌ <b>入库失败</b>\n\n"
            "原因：未配置 <code>CFIP_IMPORT_API_URL/KEY</code>，且后端可能不支持 <code>POST /api/cfip</code> 创建。"
        )
        return content, f"✗ 入库失败: {ip}:{port}"

    def handle_blacklist_current_cf_sync(self):
        result, status_code = self.blacklist_current_cf_and_trigger_maintenance(source='telegram')
        if result.get('success'):
            blacklist = result.get('blacklist') or {}
            ids = ','.join(str(i) for i in result.get('blacklisted_ids') or [])
            port = result.get('port') or '-'
            return (
                "✅ <b>已拉黑当前 CF 同步 IP</b>\n\n"
                f"IP: <code>{html.escape(str(result.get('current_ip') or '-'))}</code>\n"
                f"Port: <code>{html.escape(str(port))}</code>\n"
                f"CFIP ID: <code>{html.escape(ids or '-')}</code>\n"
                f"黑名单写入: <code>{html.escape(str(blacklist.get('changes', 0)))}/{html.escape(str(blacklist.get('requested', 0)))}</code>\n\n"
                "已重新触发启用数据维护任务，请稍后用 <code>/cfst_status</code> 查看状态。"
            )

        if status_code == 409:
            return (
                "⏳ <b>任务正在运行</b>\n\n"
                f"当前阶段: <code>{html.escape(str(result.get('phase') or 'unknown'))}</code>\n"
                f"来源: <code>{html.escape(str(result.get('source') or 'unknown'))}</code>"
            )

        return (
            "❌ <b>拉黑当前 CF 同步 IP 失败</b>\n\n"
            f"错误: <code>{html.escape(str(result.get('error') or 'unknown'))}</code>"
        )

    def handle_manual_cf_sync(self, ip_address):
        try:
            socket.inet_aton(ip_address)
        except OSError:
            return f"❌ <b>IP 格式无效</b>\n\n收到: <code>{html.escape(ip_address)}</code>"

        if not self.cf_api_token or not self.cf_zone_id or not self.cf_record_name:
            return "❌ <b>Cloudflare 同步配置不完整</b>\n\n请检查 CF_API_TOKEN / CF_ZONE_ID / CF_RECORD_NAME"

        ok = self.sync_cf_dns(ip_address, silent=False)
        if ok:
            return (
                "✅ <b>已手动同步到 Cloudflare</b>\n\n"
                f"Record: <code>{html.escape(self.cf_record_name)}</code>\n"
                f"IP: <code>{html.escape(ip_address)}</code>"
            )
        return (
            "❌ <b>同步 Cloudflare 失败</b>\n\n"
            f"Record: <code>{html.escape(self.cf_record_name)}</code>\n"
            f"IP: <code>{html.escape(ip_address)}</code>"
        )

    def check_proxy_ips(self):
        pass

    def check_outbounds(self):
        pass

if __name__ == "__main__":
    service = CFAutoCheck()
    service.start()
