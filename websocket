#!/usr/bin/env python3
"""
WebSocket Tunnel Server - Complete Implementation
Tunnels WebSocket/HTTP traffic to a backend service (SSH, etc.)
"""

# ============================================================================
# BANNER - Edit this to customize the startup banner
# ============================================================================
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           WebSocket Tunnel Server by kunshakolime            ║
║                    Version 2.0 - Optimized                   ║
╚══════════════════════════════════════════════════════════════╝"""

# ============================================================================
# IMPORTS
# ============================================================================
import sys
import signal
import threading
import argparse
import logging
import yaml
import socket
import ssl
import select
import time
import hashlib
import base64
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

# ============================================================================
# DEFAULT CONFIGURATION
# ============================================================================
"""
websocket:
  # WebSocket Tunnel Server Configuration
  ports: # Port Configuration
    http: [80, 8080, 8000, 8880]      # HTTP ports (plain text)
    https: [8443]           # HTTPS ports (SSL/TLS)
    enable_ssl: true             # Enable HTTPS servers
  backend: # Backend Server (SSH, telnet, etc.)
    host: "127.0.0.1"           # Backend server address
    port: 23                     # Backend server port
    max_retries: 3               # Connection retry attempts
    retry_delay: 0.5             # Seconds between retries
  ssl: # SSL/TLS Settings
    cert_file: "./server.crt"   # SSL certificate file
    key_file: "./server.key"    # SSL private key file
    min_tls_version: "1.1"      # Minimum TLS version (1.0, 1.1, 1.2, 1.3) (1.0 deprecated error)
  server: # Server Settings
    bind_address: "0.0.0.0"     # Listen on all interfaces
    max_connections: 100         # Maximum concurrent connections per port
    buffer_size: 8192            # Socket buffer size in bytes
  timeouts: # Timeout Settings (seconds)
    initial: 3                   # Wait for initial client data
    split: 2                     # Wait for split HTTP packets
    connection: 60               # Data forwarding timeout
  http: # HTTP/WebSocket Behavior
    response_mode: "auto"        # Response mode: auto, 101 Switching Protocols, 200 OK, 100 Continue
    handle_split: true           # Handle split HTTP requests
    custom_response_text: ""     # Custom status text (e.g., "Tunnel Ready"), empty = defaults
  performance: # Performance Tuning
    enable_nodelay: true         # Disable Nagle's algorithm (lower latency)
    enable_keepalive: true       # Enable TCP keepalive
    keepalive_idle: 60           # Seconds before sending keepalive probes
    keepalive_interval: 10       # Seconds between keepalive probes
    keepalive_count: 3           # Failed probes before closing connection
  logging: # Logging Configuration
    level: "INFO"                # Log level: DEBUG, INFO, WARNING, ERROR
    file: "./websocket.log"      # Log file path (empty to disable)
    format: "detailed"           # Log format: simple or detailed
  monitoring: # Monitoring & Statistics
    stats_interval: 60          # Log statistics every N seconds (0 = disabled, recommended: 60-600)
    log_connections: true        # Log individual connection open/close
    show_bytes_human: true       # Display KB/MB instead of raw bytes
  errors: # Error Handling
    ignore_early_reset: true     # Don't log immediate disconnects (reduces noise)
"""

class Config:
  
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = config_file
        self.data = self._load_config()
    

    def _load_config(self) -> Dict[str, Any]:
        """Load config from YAML file. Exit if missing or incomplete."""
        config_path = Path(self.config_file)

        if not config_path.exists():
            logging.error(f"Config file not found at {self.config_file}. Please create one.")
            time.sleep(5)
            sys.exit(1)  # Exit program

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                raw = yaml.safe_load(f) or {}
            data = raw.get("websocket")
            if not data:
                logging.error(f"{self.config_file} missing 'websocket' block. Please fix the config.")
                time.sleep(5)
                sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to read {self.config_file}: {e}")
            time.sleep(5)
            sys.exit(1)

        return data

    def get(self, *keys, default=None):
        """Get nested config value with fallback"""
        value = self.data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def setup_logging(self):
        """Configure logging with UTF-8 support"""
        log_level = getattr(logging, self.get('logging', 'level', default='INFO').upper())
        log_file = self.get('logging', 'file')
        log_format = self.get('logging', 'format', default='detailed')
        
        # Choose format style
        if log_format == 'simple':
            fmt = '%(levelname)s: %(message)s'
        else:
            fmt = '%(asctime)s [%(levelname)s] %(message)s'
        
        handlers = []
        
        # Console handler
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter(fmt))
        handlers.append(console)
        
        # File handler
        if log_file:
            try:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setFormatter(logging.Formatter(fmt))
                handlers.append(file_handler)
            except Exception as e:
                print(f"Warning: Could not create log file: {e}")
        
        logging.basicConfig(level=log_level, format=fmt, handlers=handlers, force=True)
    
    @staticmethod
    def normalize_ports(ports) -> list:
        """Ensure ports is always a list"""
        if isinstance(ports, int):
            return [ports]
        elif isinstance(ports, (list, tuple)):
            return list(ports)
        return [ports]

# ============================================================================
# UTILITIES
# ============================================================================

def format_bytes(bytes_count: int, human: bool = True) -> str:
    """Format bytes for display"""
    if not human:
        return f"{bytes_count}B"
    
    if bytes_count < 1024:
        return f"{bytes_count}B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.2f}KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.2f}MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.2f}GB"

def format_duration(seconds: float) -> str:
    """Format duration as Xh Ym or Ym Zs"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if hours > 0:
        return f"{hours}h{minutes}m"
    elif minutes > 0:
        return f"{minutes}m{secs}s"
    else:
        return f"{secs}s"

# ============================================================================
# HTTP/WEBSOCKET PROTOCOL
# ============================================================================

class HTTPParser:
    """Parse HTTP requests and build responses"""
    
    @staticmethod
    def parse_request(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HTTP request from raw bytes"""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            lines = decoded.split('\n')
            
            if not lines or not lines[0].strip():
                return None
            
            parts = lines[0].strip().split()
            if len(parts) < 1:
                return None
            
            method = parts[0].upper()
            
            # Ignore SSH protocol attempts
            if method.startswith('SSH-'):
                return None
            
            path = parts[1] if len(parts) > 1 else '/'
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                elif not line:
                    break
            
            # Check request completeness and WebSocket upgrade
            is_complete = b'\r\n\r\n' in data or b'\n\n' in data
            upgrade = headers.get('upgrade', '').lower()
            connection = headers.get('connection', '').lower()
            is_websocket = 'websocket' in upgrade and 'upgrade' in connection
            
            return {
                'method': method,
                'path': path,
                'headers': headers,
                'complete': is_complete,
                'is_websocket': is_websocket
            }
        except Exception:
            return None
    
    @staticmethod
    def build_response(request: dict, mode: str = 'auto', custom_text: str = '') -> bytes:
        """Build HTTP response with optional WebSocket upgrade"""
        # Auto-detect response mode
        if mode == 'auto':
            mode = '101' if request['is_websocket'] else '200'
        
        headers = request['headers']
        
        # Build status line
        if mode == '101':
            status = custom_text or "Switching Protocols"
            response = f"HTTP/1.1 101 {status}\r\n".encode('utf-8')
            response += b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            
            # WebSocket handshake
            if 'sec-websocket-key' in headers:
                GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                key = headers['sec-websocket-key'] + GUID
                accept = base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()
                response += f"Sec-WebSocket-Accept: {accept}\r\n".encode()
                response += b"Sec-WebSocket-Version: 13\r\n"
        
        elif mode == '100':
            status = custom_text or "Continue"
            response = f"HTTP/1.1 100 {status}\r\n".encode('utf-8')
        
        else:  # 200
            status = custom_text or "OK"
            response = f"HTTP/1.1 200 {status}\r\n".encode('utf-8')
            response += b"Connection: Upgrade\r\n"
        
        # Add server headers
        if mode != '100':
            response += b"Server: nginx/1.20.2\r\n"
            timestamp = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            response += f"Date: {timestamp}\r\n".encode()
        
        response += b"\r\n"
        return response

# ============================================================================
# CONNECTION HANDLER
# ============================================================================

class TunnelHandler:
    """Handle individual client connection and tunnel to backend"""
    
    def __init__(self, client_socket: socket.socket, address: tuple, 
                 use_ssl: bool, config: Config):
        self.client = client_socket
        self.address = address
        self.use_ssl = use_ssl
        self.config = config
        self.backend = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.start_time = time.time()
        
        # Enable TCP_NODELAY for lower latency
        if config.get('performance', 'enable_nodelay'):
            try:
                self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
    
    def handle(self):
        """Main handler logic"""
        try:
            proto = 'SSL' if self.use_ssl else 'Plain'
            logging.info(f"New connection: {self.address[0]}:{self.address[1]} [{proto}]")
            
            # Receive initial data
            self.client.settimeout(self.config.get('timeouts', 'initial'))
            
            try:
                initial_data = self.client.recv(self.config.get('server', 'buffer_size'))
            except (ConnectionResetError, BrokenPipeError, OSError):
                if self.config.get('errors', 'ignore_early_reset'):
                    logging.debug(f"Early disconnect from {self.address[0]}")
                    return
                raise
            
            if not initial_data:
                logging.debug(f"No data from {self.address[0]}")
                return
            
            # Parse HTTP request
            request = HTTPParser.parse_request(initial_data)
            
            # Handle split packets (some clients send headers in multiple packets)
            if self.config.get('http', 'handle_split'):
                if not request or (request and not request['complete']):
                    if len(initial_data) < 50:  # Likely incomplete
                        self.client.settimeout(self.config.get('timeouts', 'split'))
                        try:
                            more_data = self.client.recv(self.config.get('server', 'buffer_size'))
                            if more_data:
                                initial_data += more_data
                                request = HTTPParser.parse_request(initial_data)
                        except socket.timeout:
                            pass
                        except (ConnectionResetError, BrokenPipeError):
                            return
            
            # Log request info
            if request:
                ws_tag = " [WS]" if request['is_websocket'] else ""
                logging.info(f"  {request['method']} {request['path']}{ws_tag}")
            
            # Connect to backend
            if not self._connect_backend():
                return
            
            # Send HTTP response if this is an HTTP request
            if request:
                time.sleep(0.05)  # Small delay for stability
                custom_text = self.config.get('http', 'custom_response_text', default='')
                response = HTTPParser.build_response(
                    request,
                    mode=self.config.get('http', 'response_mode'),
                    custom_text=custom_text
                )
                try:
                    self.client.sendall(response)
                except (ConnectionResetError, BrokenPipeError):
                    return
            
            # Start bidirectional forwarding
            self.client.settimeout(self.config.get('timeouts', 'connection'))
            self._forward_data()
            
        except socket.timeout:
            logging.debug(f"Timeout: {self.address[0]}")
        except (ConnectionResetError, BrokenPipeError):
            pass  # Normal disconnection
        except Exception as e:
            logging.error(f"Handler error ({self.address[0]}): {e}", exc_info=True)
        finally:
            self._cleanup()
    
    def _connect_backend(self) -> bool:
        """Connect to backend server with retry logic"""
        max_retries = self.config.get('backend', 'max_retries')
        retry_delay = self.config.get('backend', 'retry_delay')
        host = self.config.get('backend', 'host')
        port = self.config.get('backend', 'port')
        
        for attempt in range(max_retries):
            try:
                self.backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.backend.settimeout(self.config.get('timeouts', 'connection'))
                
                if self.config.get('performance', 'enable_nodelay'):
                    try:
                        self.backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except Exception:
                        pass
                
                self.backend.connect((host, port))
                logging.debug(f"  Backend connected: {host}:{port}")
                return True
                
            except ConnectionRefusedError:
                if attempt < max_retries - 1:
                    logging.warning(f"Backend refused, retry {attempt + 1}/{max_retries}")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"Backend unavailable after {max_retries} attempts")
                    return False
            except Exception as e:
                logging.error(f"Backend error: {e}")
                return False
        
        return False
    
    def _forward_data(self):
        """Bidirectional data forwarding between client and backend"""
        sockets = [self.client, self.backend]
        buffer_size = self.config.get('server', 'buffer_size')
        timeout = self.config.get('timeouts', 'connection')
        
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, timeout)
                
                if exceptional:
                    break
                
                if not readable:
                    continue
                
                for sock in readable:
                    try:
                        data = sock.recv(buffer_size)
                        if not data:
                            return
                        
                        if sock is self.client:
                            self.bytes_received += len(data)
                            self.backend.sendall(data)
                        else:
                            self.bytes_sent += len(data)
                            self.client.sendall(data)
                            
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        return
                    
            except socket.timeout:
                continue
            except Exception:
                break
    
    def _cleanup(self):
        """Close sockets and log stats"""
        duration = time.time() - self.start_time
        
        # Log connection close
        if self.config.get('monitoring', 'log_connections'):
            human = self.config.get('monitoring', 'show_bytes_human', default=True)
            down = format_bytes(self.bytes_sent, human)
            up = format_bytes(self.bytes_received, human)
            dur = format_duration(duration)
            
            logging.info(f"Closed: {self.address[0]} (↓{down} ↑{up}, {dur})")
        
        # Close sockets
        for sock in [self.backend, self.client]:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

# ============================================================================
# SERVER
# ============================================================================

class TunnelServer:
    """Main server managing connections on a single port"""
    
    def __init__(self, port: int, use_ssl: bool, config: Config):
        self.port = port
        self.use_ssl = use_ssl
        self.config = config
        self.ssl_context = None
        self.running = False
        self.server = None
        
        # Statistics
        self.active_connections = 0
        self.total_connections = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.lock = threading.Lock()
        self.start_time = None
        
        if use_ssl:
            self._setup_ssl()
    
    def _setup_ssl(self):
        """Configure SSL context"""
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(
                certfile=self.config.get('ssl', 'cert_file'),
                keyfile=self.config.get('ssl', 'key_file')
            )
            
            # Set minimum TLS version
            tls_version = self.config.get('ssl', 'min_tls_version', default='1.2')
            version_map = {
                '1.0': ssl.TLSVersion.TLSv1,
                '1.1': ssl.TLSVersion.TLSv1_1,
                '1.2': ssl.TLSVersion.TLSv1_2,
                '1.3': ssl.TLSVersion.TLSv1_3
            }
            self.ssl_context.minimum_version = version_map.get(tls_version, ssl.TLSVersion.TLSv1_2)
            
        except FileNotFoundError as e:
            logging.error(f"SSL cert/key not found: {e}")
            raise
        except Exception as e:
            logging.error(f"SSL setup error: {e}")
            raise
    
    def start(self):
        """Start server and accept connections"""
        try:
            # Create server socket
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Configure keepalive
            if self.config.get('performance', 'enable_keepalive'):
                self.server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    idle = self.config.get('performance', 'keepalive_idle')
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    interval = self.config.get('performance', 'keepalive_interval')
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    count = self.config.get('performance', 'keepalive_count')
                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
            
            # Bind and listen
            bind_addr = self.config.get('server', 'bind_address')
            self.server.bind((bind_addr, self.port))
            self.server.listen(self.config.get('server', 'max_connections'))
            
            proto = "HTTPS" if self.use_ssl else "HTTP"
            logging.info(f"> {proto} server listening on {bind_addr}:{self.port}")
            
            self.running = True
            self.start_time = time.time()
            
            # Start stats logger thread
            stats_interval = self.config.get('monitoring', 'stats_interval')
            if stats_interval and stats_interval > 0:
                threading.Thread(target=self._stats_logger, daemon=True).start()
            
            # Accept loop
            while self.running:
                try:
                    self.server.settimeout(1.0)  # Allow periodic running check
                    try:
                        client, address = self.server.accept()
                    except socket.timeout:
                        continue
                    
                    # Check connection limit
                    with self.lock:
                        if self.active_connections >= self.config.get('server', 'max_connections'):
                            logging.warning(f"Connection limit reached, rejecting {address[0]}")
                            client.close()
                            continue
                        
                        self.active_connections += 1
                        self.total_connections += 1
                    
                    # SSL handshake
                    if self.use_ssl and self.ssl_context:
                        try:
                            client = self.ssl_context.wrap_socket(client, server_side=True)
                        except ssl.SSLError as e:
                            logging.debug(f"SSL handshake failed: {address[0]} - {e}")
                            with self.lock:
                                self.active_connections -= 1
                            client.close()
                            continue
                    
                    # Handle in new thread
                    handler = TunnelHandler(client, address, self.use_ssl, self.config)
                    threading.Thread(
                        target=self._handle_wrapper,
                        args=(handler,),
                        daemon=True
                    ).start()
                    
                except KeyboardInterrupt:
                    break
                except OSError as e:
                    if self.running:
                        logging.error(f"Accept error: {e}")
                except Exception as e:
                    if self.running:
                        logging.error(f"Unexpected error: {e}", exc_info=True)
                        
        except Exception as e:
            logging.error(f"Server start error: {e}")
        finally:
            self.stop()
    
    def _handle_wrapper(self, handler: TunnelHandler):
        """Wrapper to track handler stats"""
        try:
            handler.handle()
        finally:
            # Update server totals
            with self.lock:
                self.active_connections -= 1
                self.total_bytes_sent += handler.bytes_sent
                self.total_bytes_received += handler.bytes_received
    
    def _stats_logger(self):
        """Periodically log server statistics"""
        interval = self.config.get('monitoring', 'stats_interval')
        
        while self.running:
            time.sleep(interval)
            if not self.running:
                break
            
            uptime = time.time() - self.start_time
            human = self.config.get('monitoring', 'show_bytes_human', default=True)
            
            with self.lock:
                active = self.active_connections
                total = self.total_connections
                sent = format_bytes(self.total_bytes_sent, human)
                recv = format_bytes(self.total_bytes_received, human)
            
            uptime_str = format_duration(uptime)
            logging.info(f"[Stats] Port {self.port}: Active={active}, Total={total}, "
                        f"↑{sent} ↓{recv}, Uptime={uptime_str}")
    
    def stop(self):
        """Stop server and log final stats"""
        if not self.running and not self.start_time:
            return
            
        logging.info(f"Stopping server on port {self.port}...")
        
        if self.start_time:
            uptime = time.time() - self.start_time
            human = self.config.get('monitoring', 'show_bytes_human', default=True)
            
            with self.lock:
                sent = format_bytes(self.total_bytes_sent, human)
                recv = format_bytes(self.total_bytes_received, human)
            
            uptime_str = format_duration(uptime)
            logging.info(f"Port {self.port}: {self.total_connections} connections, "
                        f"↑{sent} ↓{recv}, Uptime: {uptime_str}")
        
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass

# ============================================================================
# SSL CERTIFICATE GENERATION
# ============================================================================

def generate_cert(cert_file: str, key_file: str) -> bool:
    """Generate self-signed SSL certificate"""
    Path(cert_file).parent.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-nodes', '-out', cert_file, '-keyout', key_file,
        '-days', '365', '-subj', '/CN=localhost'
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        logging.info(f"> Generated certificate: {cert_file}")
        return True
    except FileNotFoundError:
        logging.error("X OpenSSL not found. Please install OpenSSL.")
        return False
    except Exception as e:
        logging.error(f"X Certificate generation failed: {e}")
        return False

# ============================================================================
# MAIN
# ============================================================================

servers = []
shutdown_event = threading.Event()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nShutting down...")
    shutdown_event.set()
    
    for server in servers:
        server.running = False
        server.stop()
    
    time.sleep(0.5)
    sys.exit(0)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='WebSocket Tunnel Server',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-c', '--config', default='config.yaml', 
                       help='Config file (default: config.yaml)')
    parser.add_argument('--generate-cert', action='store_true',
                       help='Generate self-signed SSL certificate and exit')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    args = parser.parse_args()
    
    # Load config
    config = Config(args.config)
    
    if args.debug:
        config.data['logging']['level'] = 'DEBUG'
    
    config.setup_logging()
    
    # Show banner
    print(BANNER)
    print()
    
    # Handle cert generation
    if args.generate_cert:
        cert_file = config.get('ssl', 'cert_file')
        key_file = config.get('ssl', 'key_file')
        generate_cert(cert_file, key_file)
        return
    
    # Check SSL setup
    enable_ssl = config.get('ports', 'enable_ssl')
    if enable_ssl:
        cert_file = config.get('ssl', 'cert_file')
        key_file = config.get('ssl', 'key_file')

        if not Path(cert_file).exists():
            logging.warning("SSL certificate not found. Attempting to generate self-signed certificate...")
            if not generate_cert(cert_file, key_file):
                logging.error("Failed to generate SSL certificate. Disabling SSL.")
                enable_ssl = False
            else:
                logging.info("Self-signed SSL certificate generated successfully.")
                
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Get port lists
        http_ports = Config.normalize_ports(config.get('ports', 'http'))
        https_ports = Config.normalize_ports(config.get('ports', 'https'))
        
        # Display configuration
        logging.info("=" * 60)
        logging.info(f"Backend: {config.get('backend', 'host')}:{config.get('backend', 'port')}")
        logging.info(f"HTTP Ports: {', '.join(map(str, http_ports))}")
        if enable_ssl:
            logging.info(f"HTTPS Ports: {', '.join(map(str, https_ports))}")
        
        custom_text = config.get('http', 'custom_response_text', default='')
        if custom_text:
            logging.info(f"Custom Response: '{custom_text}'")
        
        stats_interval = config.get('monitoring', 'stats_interval')
        if stats_interval and stats_interval > 0:
            logging.info(f"Stats Interval: {stats_interval}s")
        
        logging.info("=" * 60)
        
        # Start servers
        threads = []
        
        for port in http_ports:
            server = TunnelServer(port, use_ssl=False, config=config)
            servers.append(server)
            thread = threading.Thread(target=server.start, daemon=False)
            thread.start()
            threads.append(thread)
        
        if enable_ssl:
            for port in https_ports:
                server = TunnelServer(port, use_ssl=True, config=config)
                servers.append(server)
                thread = threading.Thread(target=server.start, daemon=False)
                thread.start()
                threads.append(thread)
        
        # Wait for shutdown signal
        while not shutdown_event.is_set():
            time.sleep(0.5)
            if not any(t.is_alive() for t in threads):
                break
        
    except KeyboardInterrupt:
        print("\n\nInterrupted...")
        for server in servers:
            server.stop()
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        for server in servers:
            server.stop()
        sys.exit(1)

if __name__ == '__main__':
    main()
