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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from croniter import croniter
from .config import Config
from .logger import logger
from .api_client import ApiClient
from .telegram_notifier import TelegramNotifier

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
        self.speed_test_url = Config.SPEED_TEST_URL
        self.max_latency = Config.MAX_LATENCY
        self.max_loss = Config.MAX_LOSS
        self.speed_enable_count = Config.SPEED_ENABLE_COUNT
        self.sync_to_cf = Config.SYNC_TO_CF
        self.select_mode = Config.SELECT_MODE
        self.sync_to_cf_filter_port = Config.SYNC_TO_CF_FILTER_PORT
        self.cf_api_token = Config.CF_API_TOKEN
        self.cf_zone_id = Config.CF_ZONE_ID
        self.cf_record_name = Config.CF_RECORD_NAME
        self.sync_to_cf_cron = Config.SYNC_TO_CF_CRON
        
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

    def start(self):
        logger.info("CF Auto Check Service Started (Python + CFST)")
        logger.info(f"API URL: {Config.API_URL}")
        logger.info(f"Cron Scheduler: {'Enabled' if self.enable_cron_scheduler else 'Disabled'}")
        logger.info(f"API Trigger: {'Enabled on port ' + str(self.api_trigger_port) if self.enable_api_trigger else 'Disabled'}")
        logger.info(f"Test Mode: {self.test_mode}")
        logger.info(f"Select Mode: {self.select_mode}")
        logger.info(f"CFST Threads: {self.latency_threads}, Speed Test Count: {self.speed_test_count}")
        logger.info(f"Sync to CF Filter Port: {self.sync_to_cf_filter_port if self.sync_to_cf_filter_port > 0 else 'All ports'}")
        logger.info(f"Sync to CF: {'Enabled' if self.sync_to_cf else 'Disabled'}")
        logger.info(f"Sync to CF Cron: {self.sync_to_cf_cron if self.sync_to_cf_cron else 'Disabled'}")
        
        # Start API server if enabled
        if self.enable_api_trigger:
            api_thread = threading.Thread(target=self._run_api_server, daemon=True)
            api_thread.start()
        
        # Start CF DNS sync cron scheduler if enabled
        if self.sync_to_cf and self.sync_to_cf_cron:
            dns_sync_thread = threading.Thread(target=self._run_cf_dns_sync_scheduler, daemon=True)
            dns_sync_thread.start()
        
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
            # If cron scheduler is disabled, just keep the main thread alive for API server
            if self.enable_api_trigger:
                logger.info("Cron scheduler disabled, waiting for API trigger...")
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
                    
                    # Trigger check in background thread
                    def run_async_check():
                        try:
                            service.run_check(force_refresh=force_refresh, phase=phase)
                        except Exception as e:
                            logger.error(f"Error in triggered check: {str(e)}")
                    
                    thread = threading.Thread(target=run_async_check, daemon=True)
                    thread.start()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    msg = f'Check triggered (phase={phase})'
                    if force_refresh:
                        msg += ' (force refresh)'
                    self.wfile.write(json.dumps({'message': msg, 'phase': phase, 'force': force_refresh}).encode())
                
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

    def run_check(self, force_refresh=False, phase='all'):
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

    def run_latency_test_for_port(self, port, ips):
        """Phase 1: Run latency-only CFST test for a specific port
        
        Uses -dd flag to disable download testing for pure latency measurement.
        Uses LATENCY_THREADS for high concurrency.
        
        Returns:
            List of result dicts or None on failure
        """
        if not self.check_cfst_binary():
            return None

        # Write IPs to temp file
        port_ips_file = os.path.join(self.cfst_dir, f'ips_{port}.txt')
        with open(port_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")

        latency_result_file = os.path.join(self.cfst_dir, f'latency_{port}.csv')

        # Check cache
        cache_hours = Config.RESULT_CACHE_HOURS
        if self._check_cache(latency_result_file, cache_hours):
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

    def run_speed_test_for_port(self, port, ips, download_count):
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
        speed_ips_file = os.path.join(self.cfst_dir, f'speed_ips_{port}.txt')
        with open(speed_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")

        speed_result_file = os.path.join(self.cfst_dir, f'speed_{port}.csv')

        # Check cache
        cache_hours = Config.RESULT_CACHE_HOURS
        if self._check_cache(speed_result_file, cache_hours):
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
        logger.info(f"[Phase2] SPEED TESTING (top {self.speed_test_count} total across all ports)")
        logger.info("=" * 60)

        # Merge all latency results, sort globally by latency, pick top N
        all_latency = []
        for port, results in latency_results.items():
            for r in results:
                all_latency.append({**r, 'port': port})
        all_latency.sort(key=lambda x: x['latency'])
        
        # Select top SPEED_TEST_COUNT IPs globally by lowest latency
        selected_global = all_latency[:self.speed_test_count]
        logger.info(f"[Phase2] Selected {len(selected_global)} IPs globally by lowest latency (from {len(all_latency)} total)")
        
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
        if self.select_mode == 'lowest_latency':
            all_speed_results.sort(key=lambda x: (x['latency'], -x['speed']))
            mode_desc = 'lowest latency'
        elif self.select_mode == 'lowest_latency_nonzero':
            nonzero_results = [r for r in all_speed_results if r['speed'] > 0]
            zero_results = [r for r in all_speed_results if r['speed'] == 0]
            nonzero_results.sort(key=lambda x: (x['latency'], -x['speed']))
            zero_results.sort(key=lambda x: x['latency'])
            all_speed_results = nonzero_results + zero_results
            mode_desc = 'lowest latency (non-zero speed first)'
        else:  # highest_speed (default)
            all_speed_results.sort(key=lambda x: (-x['speed'], x['latency']))
            mode_desc = 'highest speed'

        logger.info(f"[Phase2] Speed phase completed: {len(all_speed_results)} IPs tested, sorted by {mode_desc}")
        logger.info(f"[Phase2] Top 10 results:")
        for i, r in enumerate(all_speed_results[:10], 1):
            logger.info(f"  {i}. {r['address']} - {r['speed']:.2f}MB/s, {r['latency']:.2f}ms (port {r.get('port', 'N/A')})")

        return all_speed_results

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
                if self.select_mode == 'lowest_latency':
                    cfst_results.sort(key=lambda x: (x['latency'], -x['speed']))
                elif self.select_mode == 'lowest_latency_nonzero':
                    nonzero = [r for r in cfst_results if r['speed'] > 0]
                    zero = [r for r in cfst_results if r['speed'] == 0]
                    nonzero.sort(key=lambda x: (x['latency'], -x['speed']))
                    zero.sort(key=lambda x: x['latency'])
                    cfst_results = nonzero + zero
                else:  # highest_speed
                    cfst_results.sort(key=lambda x: (-x['speed'], x['latency']))
                
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
        # Filter out IPs with zero download speed for enabling
        nonzero_speed_results = [r for r in cfst_results if r.get('speed', 0) > 0]
        zero_speed_results = [r for r in cfst_results if r.get('speed', 0) == 0]
        logger.info(f"IPs with non-zero speed: {len(nonzero_speed_results)}, zero speed: {len(zero_speed_results)} (from {len(cfst_results)} total)")

        # Priority: non-zero speed IPs first, then fill with zero-speed IPs if needed
        if len(nonzero_speed_results) >= self.speed_enable_count:
            top_results = nonzero_speed_results[:self.speed_enable_count]
            logger.info(f"Using top {len(top_results)} non-zero speed IPs (available: {len(nonzero_speed_results)})")
        else:
            remaining_count = self.speed_enable_count - len(nonzero_speed_results)
            top_results = nonzero_speed_results + zero_speed_results[:remaining_count]
            logger.info(f"Not enough non-zero speed IPs ({len(nonzero_speed_results)}), adding {len(top_results) - len(nonzero_speed_results)} zero-speed IPs to reach {self.speed_enable_count}")
        
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
                    logger.info(f"DNS sync: Selected best IP {best_ip} from port {self.sync_to_cf_filter_port} ({len(port_filtered)} candidates)")
                    self.sync_cf_dns(best_ip)
                else:
                    logger.warning(f"DNS sync: No IPs found on port {self.sync_to_cf_filter_port}, skipping")
            else:
                best_ip = cfst_results[0]['address']
                self.sync_cf_dns(best_ip)

        # Send Telegram notification
        self.telegram.send_cfip_results(top_results, top_count=self.speed_enable_count)

    def sync_cf_dns(self, ip_address):
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

    def _run_cf_dns_sync_scheduler(self):
        """Run independent cron scheduler for CF DNS sync"""
        logger.info(f"[DNS-Sync] Starting CF DNS sync scheduler with cron: {self.sync_to_cf_cron}")
        
        # Run once on startup
        try:
            self.run_cf_dns_sync()
        except Exception as e:
            logger.error(f"[DNS-Sync] Error in initial DNS sync: {str(e)}")
        
        cron = croniter(self.sync_to_cf_cron, datetime.now())
        
        while self.running:
            next_run = cron.get_next(datetime)
            wait_seconds = (next_run - datetime.now()).total_seconds()
            
            if wait_seconds > 0:
                logger.info(f"[DNS-Sync] Next DNS sync scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')} (in {wait_seconds:.0f}s)")
                
                while wait_seconds > 0 and self.running:
                    sleep_time = min(wait_seconds, 60)
                    time.sleep(sleep_time)
                    wait_seconds -= sleep_time
            
            if self.running:
                try:
                    self.run_cf_dns_sync()
                except Exception as e:
                    logger.error(f"[DNS-Sync] Error in scheduled DNS sync: {str(e)}")

    def run_cf_dns_sync(self):
        """Run lightweight latency-only test on enabled IPs and sync best to CF DNS.
        
        This is independent from the main check cycle. It:
        1. Fetches enabled CFIPs from API
        2. Filters by SYNC_TO_CF_FILTER_PORT
        3. Runs latency-only CFST test
        4. Syncs lowest-latency IP to CF DNS
        """
        logger.info("[DNS-Sync] Starting CF DNS sync cycle...")
        
        # Check prerequisites
        if not self.cf_api_token or not self.cf_zone_id or not self.cf_record_name:
            logger.warning("[DNS-Sync] Missing CF DNS configuration (CF_API_TOKEN, CF_ZONE_ID, or CF_RECORD_NAME)")
            return
        
        if not self.check_cfst_binary():
            logger.error("[DNS-Sync] CFST binary not available")
            return
        
        # Fetch enabled CFIPs from API
        try:
            cfips = self.api_client.get_cf_ips()
            if not cfips:
                logger.warning("[DNS-Sync] No CF IPs found from API")
                return
        except Exception as e:
            logger.error(f"[DNS-Sync] Failed to fetch CF IPs: {str(e)}")
            return
        
        # Filter: only enabled IPs
        enabled_cfips = [ip for ip in cfips if ip.get('status') == 'enabled']
        if not enabled_cfips:
            logger.warning("[DNS-Sync] No enabled CF IPs found")
            return
        
        # Filter by port
        filter_port = self.sync_to_cf_filter_port
        if filter_port > 0:
            port_filtered = [ip for ip in enabled_cfips if ip.get('port', 443) == filter_port]
            if not port_filtered:
                logger.warning(f"[DNS-Sync] No enabled IPs found on port {filter_port}")
                return
            logger.info(f"[DNS-Sync] Filtered {len(port_filtered)} enabled IPs on port {filter_port} (from {len(enabled_cfips)} enabled)")
            enabled_cfips = port_filtered
        else:
            filter_port = 443  # Default port for CFST test
            logger.info(f"[DNS-Sync] Using all {len(enabled_cfips)} enabled IPs")
        
        # Resolve addresses to IPs
        test_ips = []
        ip_to_address = {}  # Map resolved IP back to original address
        for cfip in enabled_cfips:
            address = cfip.get('address')
            try:
                socket.inet_aton(address)
                ip_addr = address
            except socket.error:
                ip_addr = self._resolve_domain(address)
                if ip_addr is None:
                    logger.warning(f"[DNS-Sync] Could not resolve {address}, skipping")
                    continue
                logger.debug(f"[DNS-Sync] Resolved {address} -> {ip_addr}")
            
            if ip_addr not in test_ips:
                test_ips.append(ip_addr)
                ip_to_address[ip_addr] = address
        
        if not test_ips:
            logger.warning("[DNS-Sync] No IPs available after resolution")
            return
        
        logger.info(f"[DNS-Sync] Testing {len(test_ips)} unique IPs for latency (port {filter_port})")
        
        # Write IPs to temp file
        dns_sync_ips_file = os.path.join(self.cfst_dir, 'dns_sync_ips.txt')
        dns_sync_result_file = os.path.join(self.cfst_dir, 'dns_sync_result.csv')
        
        with open(dns_sync_ips_file, 'w') as f:
            for ip in test_ips:
                f.write(f"{ip}\n")
        
        # Build CFST command - latency only
        cmd = [
            self.cfst_path,
            '-f', dns_sync_ips_file,
            '-o', dns_sync_result_file,
            '-tp', str(filter_port),
            '-n', str(self.latency_threads),
            '-dd',  # Disable download testing
            '-tl', str(self.max_latency),
            '-tlr', str(self.max_loss),
            '-p', str(len(test_ips)),
        ]
        
        logger.info(f"[DNS-Sync] Command: {' '.join(cmd)}")
        
        if not self._run_cfst_process(cmd, f'dns-sync-{filter_port}'):
            logger.error("[DNS-Sync] CFST latency test failed")
            return
        
        # Parse results
        results = self.parse_cfst_results(dns_sync_result_file)
        if not results:
            logger.error("[DNS-Sync] No results from latency test")
            return
        
        # Sort by latency (ascending)
        results.sort(key=lambda x: x['latency'])
        
        best = results[0]
        best_ip = best['address']
        best_latency = best['latency']
        
        logger.info(f"[DNS-Sync] Best IP: {best_ip} ({best_latency:.2f}ms) from {len(results)} results")
        
        # Log top 5 for reference
        for i, r in enumerate(results[:5], 1):
            logger.info(f"[DNS-Sync]   {i}. {r['address']} - {r['latency']:.2f}ms")
        
        # Get current DNS record IP for notification
        import requests as req_lib
        old_ip = ''
        try:
            headers = {
                'Authorization': f'Bearer {self.cf_api_token}',
                'Content-Type': 'application/json'
            }
            list_url = f"https://api.cloudflare.com/client/v4/zones/{self.cf_zone_id}/dns_records"
            params = {'name': self.cf_record_name, 'type': 'A'}
            response = req_lib.get(list_url, headers=headers, params=params, timeout=30)
            if response.ok:
                data = response.json()
                records = data.get('result', [])
                if records:
                    old_ip = records[0].get('content', '')
        except Exception:
            pass
        
        # Sync to CF DNS
        updated = (old_ip != best_ip)
        success = self.sync_cf_dns(best_ip)
        
        if success:
            # Send TG notification with result
            self.telegram.send_dns_sync_result(
                record_name=self.cf_record_name,
                best_ip=best_ip,
                latency=best_latency,
                tested_count=len(results),
                old_ip=old_ip,
                updated=updated
            )
        
        # Cleanup temp files
        for f in [dns_sync_ips_file, dns_sync_result_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass
        
        logger.info("[DNS-Sync] DNS sync cycle completed")

    def check_proxy_ips(self):
        pass

    def check_outbounds(self):
        pass

if __name__ == "__main__":
    service = CFAutoCheck()
    service.start()
