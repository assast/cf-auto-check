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
        self.concurrent_tests = Config.CONCURRENT_TESTS
        self.test_mode = Config.TEST_MODE
        self.enable_auto_update = Config.ENABLE_AUTO_UPDATE
        self.enable_cron_scheduler = Config.ENABLE_CRON_SCHEDULER
        self.enable_api_trigger = Config.ENABLE_API_TRIGGER
        self.api_trigger_key = Config.API_TRIGGER_KEY
        self.api_trigger_port = Config.API_TRIGGER_PORT
        self.speed_test_count = Config.SPEED_TEST_COUNT
        self.speed_test_count_443 = Config.SPEED_TEST_COUNT_443
        self.speed_enable_count = Config.SPEED_ENABLE_COUNT
        self.sync_to_cf = Config.SYNC_TO_CF
        self.select_mode = Config.SELECT_MODE
        self.filter_port = Config.FILTER_PORT
        self.cf_api_token = Config.CF_API_TOKEN
        self.cf_zone_id = Config.CF_ZONE_ID
        self.cf_record_name = Config.CF_RECORD_NAME
        
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
        logger.info(f"Filter Port: {self.filter_port if self.filter_port > 0 else 'All ports'}")
        logger.info(f"Sync to CF: {'Enabled' if self.sync_to_cf else 'Disabled'}")
        
        # Start API server if enabled
        if self.enable_api_trigger:
            api_thread = threading.Thread(target=self._run_api_server, daemon=True)
            api_thread.start()
        
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
                
                # Check API key
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
                    
                    # Check for force parameter
                    force_refresh = query.get('force', [''])[0].lower() in ['true', '1', 'yes']
                    
                    # Trigger check in background thread
                    def run_async_check():
                        try:
                            service.run_check(force_refresh=force_refresh)
                        except Exception as e:
                            logger.error(f"Error in triggered check: {str(e)}")
                    
                    thread = threading.Thread(target=run_async_check, daemon=True)
                    thread.start()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    msg = 'Check triggered successfully' + (' (force refresh)' if force_refresh else '')
                    self.wfile.write(json.dumps({'message': msg, 'force': force_refresh}).encode())
                
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
                
                elif parsed.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok'}).encode())
                
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

    def clear_result_cache(self):
        """Clear all cached result files"""
        if not os.path.exists(self.cfst_dir):
            return
        
        count = 0
        for filename in os.listdir(self.cfst_dir):
            if filename.startswith('result_') and filename.endswith('.csv'):
                filepath = os.path.join(self.cfst_dir, filename)
                try:
                    os.remove(filepath)
                    count += 1
                    logger.info(f"Deleted cached result: {filename}")
                except Exception as e:
                    logger.warning(f"Failed to delete {filename}: {str(e)}")
        
        if count > 0:
            logger.info(f"Cleared {count} cached result file(s)")

    def run_check(self, force_refresh=False):
        if self.check_running:
            logger.warning("Check already in progress, skipping...")
            return
        
        self.check_running = True
        try:
            if force_refresh:
                logger.info("Force refresh requested, clearing result cache...")
                self.clear_result_cache()
            
            logger.info("Starting check cycle...")
            
            if self.test_mode in ['all', 'cfip']:
                self.check_cf_ips()
                
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
        try:
            import requests
            response = requests.get(f'https://api.ipapi.is/?q={ip_addr}', timeout=10)
            if response.ok:
                data = response.json()
                return {
                    'country': data.get('location', {}).get('country_code') or 'N/A',
                    'city': data.get('location', {}).get('city') or 'N/A',
                    'isp': data.get('asn', {}).get('org') or 'N/A',
                    'asn': f"AS{data.get('asn', {}).get('asn')}" if data.get('asn', {}).get('asn') else 'N/A'
                }
        except Exception as e:
            logger.debug(f"Failed to get IP info for {ip_addr}: {str(e)}")
        return None

    def run_cfst_for_port(self, port, ips, download_count):
        """Run CFST for a specific port group

        Args:
            port: Port number
            ips: List of IP addresses
            download_count: Number of IPs to test download speed (CFST -dn parameter)
        """
        if not self.check_cfst_binary():
            return None

        # Write IPs to temp file for this port
        port_ips_file = os.path.join(self.cfst_dir, f'ips_{port}.txt')
        with open(port_ips_file, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")

        port_result_file = os.path.join(self.cfst_dir, f'result_{port}.csv')

        # Check if cached result exists and is still valid
        cache_hours = Config.RESULT_CACHE_HOURS
        if os.path.exists(port_result_file) and cache_hours > 0:
            file_mtime = os.path.getmtime(port_result_file)
            file_age_hours = (time.time() - file_mtime) / 3600
            if file_age_hours < cache_hours:
                logger.info(f"Using cached result for port {port} (age: {file_age_hours:.1f}h, TTL: {cache_hours}h)")
                cached_results = self.parse_cfst_results(port_result_file)
                if cached_results:
                    return cached_results
                logger.warning(f"Failed to parse cached result for port {port}, re-testing...")

        # Build CFST command
        cmd = [
            self.cfst_path,
            '-f', port_ips_file,
            '-o', port_result_file,
            '-tp', str(port),
            '-n', str(self.concurrent_tests),
            '-url', 'https://download.parallels.com/desktop/v17/17.1.1-51537/ParallelsDesktop-17.1.1-51537.dmg',
            '-dn', str(download_count),
            '-p', str(download_count*5),
            '-debug'
        ]

        logger.info(f"Running CFST for port {port} with {len(ips)} IPs (download test: {download_count} IPs)")

        try:
            # Use Popen to stream output in real-time
            process = subprocess.Popen(
                cmd,
                cwd=self.cfst_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Stream output line by line
            for line in process.stdout:
                line = line.strip()
                if line:
                    print(f"[CFST:{port}] {line}")

            process.wait(timeout=600)

            if process.returncode != 0:
                logger.error(f"CFST failed for port {port} with exit code {process.returncode}")
                return None

            return self.parse_cfst_results(port_result_file)

        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"CFST timed out for port {port}")
            return None
        except Exception as e:
            logger.error(f"Error running CFST for port {port}: {str(e)}")
            return None

    def run_cfst(self):
        """Run CFST: test latency for all IPs, then test speed for top N by latency"""
        logger.info("=" * 60)
        logger.info(f"Running CFST (download test: {self.speed_test_count_443} IPs for port 443, {self.speed_test_count} IPs for others)")
        logger.info("=" * 60)

        all_results = []

        for port, ips in self.port_groups.items():
            # Use different download count for port 443 vs others
            download_count = self.speed_test_count_443 if port == 443 else self.speed_test_count
            logger.info(f"Testing {len(ips)} IPs on port {port} (download test: {download_count} IPs)")
            results = self.run_cfst_for_port(port, ips, download_count=download_count)
            if results:
                # Add port info to each result
                for r in results:
                    r['port'] = port
                all_results.extend(results)

        if not all_results:
            logger.error("CFST failed: No results")
            return None

        # Sort results based on select_mode
        if self.select_mode == 'lowest_latency':
            # Sort by latency (ascending)
            all_results.sort(key=lambda x: (x['latency'], -x['speed']))
            mode_desc = 'lowest latency'
        elif self.select_mode == 'lowest_latency_nonzero':
            # Filter to non-zero speed IPs, then sort by latency
            nonzero_results = [r for r in all_results if r['speed'] > 0]
            zero_results = [r for r in all_results if r['speed'] == 0]
            nonzero_results.sort(key=lambda x: (x['latency'], -x['speed']))
            zero_results.sort(key=lambda x: x['latency'])
            # Non-zero speed IPs first, then zero speed IPs
            all_results = nonzero_results + zero_results
            mode_desc = 'lowest latency (non-zero speed first)'
        else:  # highest_speed (default)
            # Sort by download speed (descending), then by latency (ascending) if speed is equal
            all_results.sort(key=lambda x: (-x['speed'], x['latency']))
            mode_desc = 'highest speed'

        logger.info(f"CFST completed: {len(all_results)} IPs tested, sorted by {mode_desc}")
        logger.info(f"Top 10 results:")
        for i, r in enumerate(all_results[:10], 1):
            logger.info(f"  {i}. {r['address']} - {r['speed']:.2f}MB/s, {r['latency']:.2f}ms (port {r.get('port', 'N/A')})")

        return all_results

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
            
            logger.info(f"Parsed {len(results)} results from CFST")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing CFST results: {str(e)}")
            return None

    def check_cf_ips(self):
        try:
            logger.info("Fetching CF IPs...")
            cfips = self.api_client.get_cf_ips()

            if not cfips:
                logger.warning("No CF IPs found")
                return

            logger.info(f"Found {len(cfips)} CF IPs")

            # Group IPs by port (this also populates self.ip_to_cfip)
            self.export_ips_by_port(cfips)

            # Run CFST testing
            cfst_results = self.run_cfst()

            if cfst_results is None:
                logger.error("CFST failed, no results to update")
                return

            # Filter results by port if specified
            if self.filter_port > 0:
                filtered_results = [r for r in cfst_results if r.get('port') == self.filter_port]
                logger.info(f"Filtered to {len(filtered_results)} IPs on port {self.filter_port} (from {len(cfst_results)} total)")
            else:
                filtered_results = cfst_results

            # Get top N IPs to enable (using (IP, port) combination)
            top_ip_ports = set((r['address'], r['port']) for r in filtered_results[:self.speed_enable_count])

            logger.info(f"Enabling top {len(top_ip_ports)} IP:port combinations by {self.select_mode}")

            # Create mapping from (IP, port) to CFST result for port-specific matching
            ip_port_to_result = {(r['address'], r['port']): r for r in cfst_results}

            # Update API using ip_port_to_cfips mapping (handles port-specific results)
            if self.enable_auto_update:
                enabled_count = 0
                for (ip_addr, port), cfip_list in self.ip_port_to_cfips.items():
                    result = ip_port_to_result.get((ip_addr, port))
                    
                    # Check if this IP appears multiple times (duplicate)
                    is_duplicate = self.ip_occurrence_count.get(ip_addr, 0) > 1
                    dup_count = self.ip_occurrence_count.get(ip_addr, 0)
                    dup_mark = f"[DUP:{dup_count}] " if is_duplicate else ""
                    
                    # Get IP info once for all cfips mapping to this (IP, port)
                    if result:
                        ip_info = self._get_ip_info(ip_addr)
                        if ip_info:
                            country = ip_info['country']
                            isp = ip_info['isp']
                        else:
                            country = result['region'] or 'N/A'
                            isp = 'N/A'
                    
                    # Update all cfips that resolved to this (IP, port)
                    for cfip in cfip_list:
                        ip_id = cfip.get('id')
                        original_addr = cfip.get('address')
                        current_fail_count = int(cfip.get('fail_count') or 0)
                        current_status = cfip.get('status') or 'enabled'
                        
                        # Check if this cfip address is a domain (优选域名)
                        is_domain = self.cfip_is_domain.get(ip_id, False)

                        if result:
                            # Success: Reset fail_count
                            new_fail_count = 0
                            
                            latency_val = result['latency']  # ms
                            speed_val = result['speed'] * 1024  # Convert MB/s to KB/s for API

                            # Build name: 速度|延迟|地区 原始地址[DUP:x]
                            speed_str = f"{result['speed']:.2f}MB/s"
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

                            # For domain addresses (优选域名), do NOT change status
                            # For IP addresses (优选IP), update status based on speed ranking
                            if is_domain:
                                domain_mark = " [DOMAIN-KEEP]"
                                logger.info(f"Updating {original_addr}:{port}: {latency_str}, {speed_str}, {country} (keeping status={current_status}){' [DUP]' if is_duplicate else ''}{domain_mark}")
                            else:
                                is_top = (ip_addr, port) in top_ip_ports
                                new_status = 'enabled' if is_top else 'disabled'
                                update_data['status'] = new_status
                                if new_status == 'enabled':
                                    enabled_count += 1
                                logger.info(f"Updating {original_addr}:{port}: {latency_str}, {speed_str}, {country} ({new_status}){' [DUP]' if is_duplicate else ''}")
                        else:
                            # Failure: Increment fail_count
                            new_fail_count = current_fail_count + 1

                            # IP not in CFST results (failed test), update with N/A
                            name = f"N/A|N/A|N/A {original_addr}{dup_mark}"
                            update_data = {
                                'name': name,
                                'fail_count': new_fail_count,
                                'latency': 0,
                                'speed': 0,
                                'country': 'N/A',
                                'isp': 'N/A'
                            }
                            
                            # For domain addresses (优选域名), do NOT change status
                            # For IP addresses (优选IP), update status based on fail_count
                            if is_domain:
                                domain_mark = " [DOMAIN-KEEP]"
                                logger.info(f"Updating {original_addr}:{port} (failed test, fail_count={new_fail_count}, keeping status={current_status}){' [DUP]' if is_duplicate else ''}{domain_mark}")
                            else:
                                if new_fail_count >= 10:
                                    new_status = 'invalid'
                                elif current_status == 'invalid':
                                    new_status = 'invalid'  # Keep invalid
                                else:
                                    new_status = 'disabled'
                                update_data['status'] = new_status
                                logger.info(f"Disabling {original_addr}:{port} (failed test, fail_count={new_fail_count}, status={new_status}){' [DUP]' if is_duplicate else ''}")

                        self.api_client.update_cf_ip(ip_id, update_data)

                # Update unresolved cfips (these are all domain addresses that couldn't be resolved)
                # 优选域名无法解析时，不更新状态
                for cfip in self.unresolved_cfips:
                    cfip_id = cfip.get('id')
                    original_addr = cfip.get('address')
                    current_fail_count = int(cfip.get('fail_count') or 0)
                    current_status = cfip.get('status') or 'enabled'
                    
                    new_fail_count = current_fail_count + 1
                            
                    name = f"N/A|N/A|N/A {original_addr}"
                    # Only update test results, do NOT change status for domains
                    update_data = {
                        'name': name,
                        'fail_count': new_fail_count,
                        'latency': 0,
                        'speed': 0,
                        'country': 'N/A',
                        'isp': 'N/A'
                    }
                    self.api_client.update_cf_ip(cfip_id, update_data)
                    logger.info(f"Updated {original_addr} (unresolved, fail_count={new_fail_count}, keeping status={current_status}) [DOMAIN-KEEP]")

            logger.info(f"CF IP checks completed. {enabled_count} IP-based CFIPs enabled (top {len(top_ip_ports)} IP:port combinations).")

            # Sync best IP to Cloudflare A record if enabled
            if self.sync_to_cf and filtered_results:
                best_ip = filtered_results[0]['address']
                self.sync_cf_dns(best_ip)

            # Send Telegram notification
            self.telegram.send_cfip_results(cfst_results, top_count=self.speed_enable_count)

        except Exception as e:
            logger.error(f"Error checking CF IPs: {str(e)}")

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

    def check_proxy_ips(self):
        pass

    def check_outbounds(self):
        pass

if __name__ == "__main__":
    service = CFAutoCheck()
    service.start()
