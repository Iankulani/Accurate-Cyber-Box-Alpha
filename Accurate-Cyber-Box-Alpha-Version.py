#!/usr/bin/env python3
"""
CyberThreat Monitor - Advanced Network Security Monitoring Tool
Version: 1.0.0
Author: Security Operations
Description: Real-time network threat detection and analysis system
"""

import os
import sys
import time
import socket
import struct
import random
import threading
import subprocess
import configparser
from datetime import datetime
from collections import deque, defaultdict
import json
import platform
import select
import dpkt
import requests
import dns.resolver
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff, sendp, sr1, sr
from scapy.utils import wrpcap
import netifaces
import geoip2.database
import matplotlib.pyplot as plt
import numpy as np
from colorama import init, Fore, Style
import telegram
from telegram.ext import Updater

# Initialize colorama
init()

# Constants
CONFIG_FILE = "ctm_config.ini"
HISTORY_FILE = "ctm_history.log"
THREAT_DB_FILE = "threat_database.json"
MAX_HISTORY = 100
SCAN_THRESHOLD = 20  # Ports scanned within TIME_WINDOW to trigger alert
TIME_WINDOW = 60  # Seconds
FLOOD_THRESHOLD = 1000  # Packets per second to consider as flood
MAX_TELEGRAM_MESSAGE_LENGTH = 4096

# Global variables
monitored_ips = set()
command_history = deque(maxlen=MAX_HISTORY)
threat_log = []
active_monitors = {}
telegram_bot = None
telegram_chat_id = None
geoip_reader = None
current_color = Fore.BLUE
packet_counts = defaultdict(lambda: defaultdict(int))
interface = None
should_stop = False

# Threat types
THREAT_PORT_SCAN = "Port Scan"
THREAT_DOS = "Denial of Service"
THREAT_DDOS = "Distributed Denial of Service"
THREAT_UDP_FLOOD = "UDP Flood"
THREAT_TCP_FLOOD = "TCP Flood"
THREAT_HTTP_FLOOD = "HTTP Flood"
THREAT_HTTPS_FLOOD = "HTTPS Flood"
THREAT_SUSPICIOUS = "Suspicious Activity"

class ThreatDetector:
    def __init__(self):
        self.port_scan_tracker = defaultdict(lambda: defaultdict(int))
        self.flood_tracker = defaultdict(lambda: defaultdict(int))
        self.last_reset = time.time()
        
    def detect_port_scan(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            current_time = time.time()
            if current_time - self.last_reset > TIME_WINDOW:
                self.port_scan_tracker.clear()
                self.last_reset = current_time
                
            self.port_scan_tracker[src_ip][dst_port] += 1
            
            if len(self.port_scan_tracker[src_ip]) > SCAN_THRESHOLD:
                return THREAT_PORT_SCAN, src_ip
        return None, None
    
    def detect_flood(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            protocol = None
            
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
                
            if protocol:
                current_time = time.time()
                self.flood_tracker[src_ip][protocol] += 1
                
                if current_time - self.last_reset > 1:  # Check every second
                    for ip, protocols in self.flood_tracker.items():
                        for proto, count in protocols.items():
                            if count > FLOOD_THRESHOLD:
                                if proto == "UDP":
                                    return THREAT_UDP_FLOOD, ip
                                elif proto == "TCP":
                                    return THREAT_TCP_FLOOD, ip
                                elif proto == "ICMP":
                                    return THREAT_DOS, ip
                    self.flood_tracker.clear()
                    self.last_reset = current_time
        return None, None

class NetworkUtils:
    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def get_public_ip():
        try:
            return requests.get('https://api.ipify.org').text
        except Exception:
            return "Unknown"
    
    @staticmethod
    def get_interface():
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith('lo'):
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return iface
            return interfaces[0] if interfaces else "eth0"
        except Exception:
            return "eth0"
    
    @staticmethod
    def get_mac(ip):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].src
        except Exception:
            pass
        return "Unknown"
    
    @staticmethod
    def traceroute(target, max_hops=30, timeout=2):
        results = []
        dest_addr = socket.gethostbyname(target)
        port = 33434
        
        for ttl in range(1, max_hops + 1):
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            recv_socket.bind(("", port))
            send_socket.sendto(b"", (target, port))
            
            current_time = time.time()
            while True:
                if time.time() - current_time > timeout:
                    results.append(f"{ttl}\t*\t*\t*")
                    break
                
                ready = select.select([recv_socket], [], [], timeout)
                if ready[0]:
                    data, addr = recv_socket.recvfrom(512)
                    ip_header = data[20:36]
                    ip = socket.inet_ntoa(ip_header[12:16])
                    
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = ip
                    
                    results.append(f"{ttl}\t{ip}\t{hostname}")
                    break
            
            send_socket.close()
            recv_socket.close()
            
            if ip == dest_addr:
                break
        
        return results
    
    @staticmethod
    def udp_traceroute(target, max_hops=30, timeout=2):
        results = []
        dest_addr = socket.gethostbyname(target)
        port = 33434
        
        for ttl in range(1, max_hops + 1):
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            
            recv_socket.bind(("", port))
            send_socket.sendto(b"", (target, port))
            
            current_time = time.time()
            while True:
                if time.time() - current_time > timeout:
                    results.append(f"{ttl}\t*\t*\t*")
                    break
                
                ready = select.select([recv_socket], [], [], timeout)
                if ready[0]:
                    data, addr = recv_socket.recvfrom(512)
                    ip_header = data[20:36]
                    ip = socket.inet_ntoa(ip_header[12:16])
                    
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = ip
                    
                    results.append(f"{ttl}\t{ip}\t{hostname}")
                    break
            
            send_socket.close()
            recv_socket.close()
            
            if ip == dest_addr:
                break
        
        return results
    
    @staticmethod
    def port_scan(target, ports=None, timeout=1):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5900, 8080]
        
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    
    @staticmethod
    def get_geoip_info(ip):
        try:
            if geoip_reader:
                response = geoip_reader.city(ip)
                return {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                }
        except Exception:
            pass
        return None

class TelegramNotifier:
    def __init__(self, token, chat_id):
        self.bot = telegram.Bot(token=token)
        self.chat_id = chat_id
    
    def send_message(self, message):
        try:
            if len(message) > MAX_TELEGRAM_MESSAGE_LENGTH:
                chunks = [message[i:i+MAX_TELEGRAM_MESSAGE_LENGTH] for i in range(0, len(message), MAX_TELEGRAM_MESSAGE_LENGTH)]
                for chunk in chunks:
                    self.bot.send_message(chat_id=self.chat_id, text=chunk)
            else:
                self.bot.send_message(chat_id=self.chat_id, text=message)
            return True
        except Exception as e:
            print(f"{Fore.RED}Telegram Error: {str(e)}{Style.RESET_ALL}")
            return False
    
    def test_connection(self):
        try:
            self.bot.get_me()
            return True
        except Exception:
            return False

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface or NetworkUtils.get_interface()
        self.detector = ThreatDetector()
        self.running = False
    
    def start(self, ip_filter=None):
        self.running = True
        try:
            sniff(iface=self.interface, prn=self.packet_handler, filter=ip_filter, store=0)
        except Exception as e:
            print(f"{Fore.RED}Sniffing Error: {str(e)}{Style.RESET_ALL}")
    
    def stop(self):
        self.running = False
    
    def packet_handler(self, packet):
        if not self.running:
            return
        
        # Detect threats
        threat_type, src_ip = self.detector.detect_port_scan(packet)
        if threat_type:
            self.log_threat(threat_type, src_ip)
        
        threat_type, src_ip = self.detector.detect_flood(packet)
        if threat_type:
            self.log_threat(threat_type, src_ip)
        
        # Count packets for analysis
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            packet_counts[src_ip]['total'] += 1
            packet_counts[src_ip][protocol] += 1
            
            if dst_ip in monitored_ips:
                packet_counts[dst_ip]['inbound'] += 1
                packet_counts[src_ip]['outbound'] += 1
    
    def log_threat(self, threat_type, src_ip):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threat_entry = {
            'timestamp': timestamp,
            'threat_type': threat_type,
            'source_ip': src_ip,
            'action': 'detected'
        }
        threat_log.append(threat_entry)
        
        geo_info = NetworkUtils.get_geoip_info(src_ip)
        geo_str = ""
        if geo_info:
            geo_str = f" ({geo_info['country']}, {geo_info['city']})"
        
        message = f"{Fore.RED}[!] Threat Detected: {threat_type} from {src_ip}{geo_str} at {timestamp}{Style.RESET_ALL}"
        print(message)
        
        if telegram_bot and telegram_chat_id:
            telegram_bot.send_message(chat_id=telegram_chat_id, text=message)

class TrafficGenerator:
    @staticmethod
    def generate_tcp_traffic(target_ip, target_port, count=100):
        for _ in range(count):
            ip = IP(dst=target_ip)
            tcp = TCP(dport=target_port, flags="S")
            send(ip/tcp, verbose=0)
            time.sleep(0.1)
    
    @staticmethod
    def generate_udp_traffic(target_ip, target_port, count=100):
        for _ in range(count):
            ip = IP(dst=target_ip)
            udp = UDP(dport=target_port)
            send(ip/udp, verbose=0)
            time.sleep(0.1)
    
    @staticmethod
    def generate_icmp_traffic(target_ip, count=100):
        for _ in range(count):
            ip = IP(dst=target_ip)
            icmp = ICMP()
            send(ip/icmp, verbose=0)
            time.sleep(0.1)

class ConfigManager:
    @staticmethod
    def load_config():
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
        else:
            config['DEFAULT'] = {
                'telegram_token': '',
                'telegram_chat_id': '',
                'interface': NetworkUtils.get_interface(),
                'color': 'blue'
            }
            ConfigManager.save_config(config)
        return config
    
    @staticmethod
    def save_config(config):
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    
    @staticmethod
    def load_history():
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                for line in f:
                    command_history.append(line.strip())
    
    @staticmethod
    def save_history():
        with open(HISTORY_FILE, 'w') as f:
            for cmd in command_history:
                f.write(f"{cmd}\n")
    
    @staticmethod
    def load_threat_db():
        if os.path.exists(THREAT_DB_FILE):
            with open(THREAT_DB_FILE, 'r') as f:
                return json.load(f)
        return []
    
    @staticmethod
    def save_threat_db():
        with open(THREAT_DB_FILE, 'w') as f:
            json.dump(threat_log, f)

class CommandHandler:
    @staticmethod
    def handle_command(cmd):
        global current_color, telegram_bot, telegram_chat_id, interface, should_stop, geoip_reader
        
        parts = cmd.split()
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1:]
        
        try:
            if command == "help":
                CommandHandler.show_help()
            
            elif command == "ping" and args:
                CommandHandler.ping(args[0])
            
            elif command == "traceroute" and args:
                CommandHandler.traceroute(args[0])
            
            elif command == "udptraceroute" and args:
                CommandHandler.udp_traceroute(args[0])
            
            elif command == "add" and args:
                monitored_ips.add(args[0])
                print(f"{current_color}Added {args[0]} to monitoring list{Style.RESET_ALL}")
            
            elif command == "remove" and args:
                if args[0] in monitored_ips:
                    monitored_ips.remove(args[0])
                    print(f"{current_color}Removed {args[0]} from monitoring list{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}IP {args[0]} not in monitoring list{Style.RESET_ALL}")
            
            elif command == "histo":
                CommandHandler.show_history()
            
            elif command == "config" and len(args) >= 2:
                if args[0] == "telegram" and args[1] == "token":
                    config = ConfigManager.load_config()
                    config['DEFAULT']['telegram_token'] = ' '.join(args[2:])
                    ConfigManager.save_config(config)
                    print(f"{current_color}Telegram token updated{Style.RESET_ALL}")
                elif args[0] == "telegram" and args[1] == "chat_id":
                    config = ConfigManager.load_config()
                    config['DEFAULT']['telegram_chat_id'] = ' '.join(args[2:])
                    ConfigManager.save_config(config)
                    print(f"{current_color}Telegram chat ID updated{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Invalid config command{Style.RESET_ALL}")
            
            elif command == "scan" and args:
                CommandHandler.scan_ip(args[0])
            
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
            
            elif command == "exit":
                should_stop = True
                ConfigManager.save_history()
                ConfigManager.save_threat_db()
                print(f"{current_color}Exiting...{Style.RESET_ALL}")
                sys.exit(0)
            
            elif command == "kill" and args:
                CommandHandler.kill_ip(args[0])
            
            elif command == "test" and args and args[0] == "telegram":
                CommandHandler.test_telegram()
            
            elif command == "export" and len(args) >= 2 and args[0] == "telegram":
                CommandHandler.export_to_telegram(args[1])
            
            elif command == "generate" and len(args) >= 2 and args[0] == "traffic":
                CommandHandler.generate_traffic(args[1])
            
            elif command == "change" and len(args) >= 2 and args[0] == "color":
                CommandHandler.change_color(args[1])
            
            elif command == "status":
                CommandHandler.show_status()
            
            elif command == "view" and len(args) >= 1 and args[0] == "threats":
                CommandHandler.view_threats()
            
            elif command == "sniff" and args:
                CommandHandler.sniff_ip(args[0])
            
            elif command == "ifconfig" or command == "ifconfig /all":
                CommandHandler.show_network_info()
            
            elif command == "map" and args:
                CommandHandler.map_ip(args[0])
            
            elif command == "analyze" and args:
                CommandHandler.analyze_ip(args[0])
            
            elif command == "nslookup" and args:
                CommandHandler.nslookup(args[0])
            
            else:
                print(f"{Fore.RED}Unknown command: {command}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}Error executing command: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def show_help():
        help_text = f"""
{current_color}CyberThreat Monitor Commands:{Style.RESET_ALL}

{current_color}Network Operations:{Style.RESET_ALL}
  ping <ip>              - Ping an IP address
  traceroute <ip>        - Trace route to an IP (ICMP)
  udptraceroute <ip>     - Trace route to an IP (UDP)
  scan <ip>              - Scan common ports on an IP
  sniff <ip>             - Start sniffing traffic for an IP
  ifconfig /all          - Show network interface information
  nslookup <ip/domain>   - Perform DNS lookup

{current_color}Monitoring:{Style.RESET_ALL}
  add <ip>               - Add IP to monitoring list
  remove <ip>            - Remove IP from monitoring list
  status                 - Show monitoring status
  view threats           - View detected threats
  kill <ip>              - Block an IP (requires root)

{current_color}Telegram Integration:{Style.RESET_ALL}
  config telegram token <token>  - Set Telegram bot token
  config telegram chat_id <id>   - Set Telegram chat ID
  test telegram          - Test Telegram connection
  export telegram <type> - Export data to Telegram

{current_color}Utility:{Style.RESET_ALL}
  histo                  - Show command history
  clear                  - Clear the screen
  change color <color>   - Change interface color
  generate traffic <ip>  - Generate test traffic
  exit                   - Exit the program
"""
        print(help_text)
    
    @staticmethod
    def ping(ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            subprocess.run(command)
        except Exception as e:
            print(f"{Fore.RED}Ping failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def traceroute(ip):
        try:
            results = NetworkUtils.traceroute(ip)
            for line in results:
                print(f"{current_color}{line}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Traceroute failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def udp_traceroute(ip):
        try:
            results = NetworkUtils.udp_traceroute(ip)
            for line in results:
                print(f"{current_color}{line}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}UDP Traceroute failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def show_history():
        for i, cmd in enumerate(command_history, 1):
            print(f"{current_color}{i}: {cmd}{Style.RESET_ALL}")
    
    @staticmethod
    def scan_ip(ip):
        try:
            open_ports = NetworkUtils.port_scan(ip)
            if open_ports:
                print(f"{current_color}Open ports on {ip}: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
            else:
                print(f"{current_color}No open ports found on {ip}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Scan failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def kill_ip(ip):
        try:
            if platform.system().lower() == 'linux':
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                print(f"{current_color}Blocked all traffic from {ip}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Blocking only supported on Linux{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to block IP: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def test_telegram():
        global telegram_bot, telegram_chat_id
        
        config = ConfigManager.load_config()
        token = config['DEFAULT'].get('telegram_token', '')
        chat_id = config['DEFAULT'].get('telegram_chat_id', '')
        
        if not token or not chat_id:
            print(f"{Fore.RED}Telegram token or chat ID not configured{Style.RESET_ALL}")
            return
        
        telegram_bot = TelegramNotifier(token, chat_id)
        if telegram_bot.test_connection():
            print(f"{current_color}Telegram connection successful{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Telegram connection failed{Style.RESET_ALL}")
    
    @staticmethod
    def export_to_telegram(data_type):
        global telegram_bot, telegram_chat_id
        
        if not telegram_bot or not telegram_chat_id:
            print(f"{Fore.RED}Telegram not configured{Style.RESET_ALL}")
            return
        
        if data_type == "threats":
            if not threat_log:
                telegram_bot.send_message("No threats detected yet")
                return
            
            message = "Detected Threats:\n"
            for threat in threat_log[-10:]:  # Send last 10 threats
                message += f"{threat['timestamp']} - {threat['threat_type']} from {threat['source_ip']}\n"
            
            telegram_bot.send_message(message)
            print(f"{current_color}Threats exported to Telegram{Style.RESET_ALL}")
        
        elif data_type == "status":
            status = CommandHandler.get_status_report()
            telegram_bot.send_message(status)
            print(f"{current_color}Status exported to Telegram{Style.RESET_ALL}")
        
        else:
            print(f"{Fore.RED}Unknown export type: {data_type}{Style.RESET_ALL}")
    
    @staticmethod
    def generate_traffic(ip):
        try:
            print(f"{current_color}Generating test traffic to {ip}...{Style.RESET_ALL}")
            TrafficGenerator.generate_tcp_traffic(ip, 80, 10)
            TrafficGenerator.generate_udp_traffic(ip, 53, 10)
            TrafficGenerator.generate_icmp_traffic(ip, 5)
            print(f"{current_color}Test traffic generation completed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Traffic generation failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def change_color(color):
        global current_color
        
        color = color.lower()
        if color == "blue":
            current_color = Fore.BLUE
        elif color == "green":
            current_color = Fore.GREEN
        elif color == "red":
            current_color = Fore.RED
        elif color == "yellow":
            current_color = Fore.YELLOW
        elif color == "magenta":
            current_color = Fore.MAGENTA
        elif color == "cyan":
            current_color = Fore.CYAN
        elif color == "white":
            current_color = Fore.WHITE
        else:
            print(f"{Fore.RED}Invalid color. Available: blue, green, red, yellow, magenta, cyan, white{Style.RESET_ALL}")
            return
        
        config = ConfigManager.load_config()
        config['DEFAULT']['color'] = color
        ConfigManager.save_config(config)
        print(f"{current_color}Interface color changed to {color}{Style.RESET_ALL}")
    
    @staticmethod
    def show_status():
        status = CommandHandler.get_status_report()
        print(status)
    
    @staticmethod
    def get_status_report():
        global monitored_ips, interface
        
        config = ConfigManager.load_config()
        local_ip = NetworkUtils.get_local_ip()
        public_ip = NetworkUtils.get_public_ip()
        
        status = f"""
{current_color}=== CyberThreat Monitor Status ==={Style.RESET_ALL}

{current_color}System Information:{Style.RESET_ALL}
  Hostname: {socket.gethostname()}
  OS: {platform.system()} {platform.release()}
  Local IP: {local_ip}
  Public IP: {public_ip}
  Interface: {interface}

{current_color}Monitoring:{Style.RESET_ALL}
  Monitored IPs: {', '.join(monitored_ips) if monitored_ips else 'None'}
  Detected Threats: {len(threat_log)}

{current_color}Telegram Integration:{Style.RESET_ALL}
  Configured: {'Yes' if config['DEFAULT'].get('telegram_token') else 'No'}
  Active: {'Yes' if telegram_bot else 'No'}
"""
        return status
    
    @staticmethod
    def view_threats():
        if not threat_log:
            print(f"{current_color}No threats detected yet{Style.RESET_ALL}")
            return
        
        print(f"{current_color}=== Detected Threats ==={Style.RESET_ALL}")
        for threat in threat_log[-10:]:  # Show last 10 threats
            geo_info = NetworkUtils.get_geoip_info(threat['source_ip'])
            geo_str = ""
            if geo_info:
                geo_str = f" ({geo_info['country']}, {geo_info['city']})"
            
            print(f"{current_color}{threat['timestamp']} - {Fore.RED}{threat['threat_type']}{current_color} from {threat['source_ip']}{geo_str}{Style.RESET_ALL}")
    
    @staticmethod
    def sniff_ip(ip):
        global active_monitors
        
        if ip in active_monitors:
            print(f"{Fore.RED}Already sniffing traffic for {ip}{Style.RESET_ALL}")
            return
        
        sniffer = PacketSniffer(interface)
        monitor_thread = threading.Thread(target=sniffer.start, args=(f"host {ip}",))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        active_monitors[ip] = {
            'thread': monitor_thread,
            'sniffer': sniffer
        }
        
        print(f"{current_color}Started sniffing traffic for {ip}{Style.RESET_ALL}")
    
    @staticmethod
    def show_network_info():
        try:
            interfaces = netifaces.interfaces()
            print(f"{current_color}=== Network Interfaces ==={Style.RESET_ALL}")
            
            for iface in interfaces:
                print(f"\n{current_color}Interface: {iface}{Style.RESET_ALL}")
                addrs = netifaces.ifaddresses(iface)
                
                if netifaces.AF_INET in addrs:
                    print(f"{current_color}  IPv4 Addresses:{Style.RESET_ALL}")
                    for addr in addrs[netifaces.AF_INET]:
                        for key, val in addr.items():
                            print(f"    {key}: {val}")
                
                if netifaces.AF_LINK in addrs:
                    print(f"{current_color}  MAC Address:{Style.RESET_ALL}")
                    for addr in addrs[netifaces.AF_LINK]:
                        print(f"    {addr['addr']}")
        except Exception as e:
            print(f"{Fore.RED}Failed to get network info: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def map_ip(ip):
        try:
            geo_info = NetworkUtils.get_geoip_info(ip)
            if geo_info:
                print(f"{current_color}=== Geolocation Info for {ip} ==={Style.RESET_ALL}")
                print(f"{current_color}Country: {geo_info['country']}{Style.RESET_ALL}")
                print(f"{current_color}City: {geo_info['city']}{Style.RESET_ALL}")
                print(f"{current_color}Coordinates: {geo_info['latitude']}, {geo_info['longitude']}{Style.RESET_ALL}")
                
                # Simple ASCII map representation
                print(f"\n{current_color}Approximate Location:{Style.RESET_ALL}")
                print("    ^    ")
                print("    |    ")
                print("    •    ")
                print("   /|\\   ")
                print("  / | \\  ")
                print("-----------")
            else:
                print(f"{Fore.RED}No geolocation data available for {ip}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Geolocation failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def analyze_ip(ip):
        try:
            print(f"{current_color}=== Analysis for {ip} ==={Style.RESET_ALL}")
            
            # Basic ping test
            print(f"\n{current_color}Ping Test:{Style.RESET_ALL}")
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            subprocess.run(command)
            
            # Port scan
            print(f"\n{current_color}Port Scan:{Style.RESET_ALL}")
            open_ports = NetworkUtils.port_scan(ip)
            if open_ports:
                print(f"Open ports: {', '.join(map(str, open_ports))}")
            else:
                print("No open ports found")
            
            # DNS lookup
            print(f"\n{current_color}DNS Lookup:{Style.RESET_ALL}")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"Hostname: {hostname}")
            except socket.herror:
                print("No reverse DNS entry found")
            
            # Geolocation
            print(f"\n{current_color}Geolocation:{Style.RESET_ALL}")
            geo_info = NetworkUtils.get_geoip_info(ip)
            if geo_info:
                print(f"Country: {geo_info['country']}")
                print(f"City: {geo_info['city']}")
                print(f"Coordinates: {geo_info['latitude']}, {geo_info['longitude']}")
            else:
                print("No geolocation data available")
            
            # Traffic analysis
            print(f"\n{current_color}Traffic Analysis:{Style.RESET_ALL}")
            if ip in packet_counts:
                counts = packet_counts[ip]
                print(f"Total packets: {counts.get('total', 0)}")
                print(f"Inbound packets: {counts.get('inbound', 0)}")
                print(f"Outbound packets: {counts.get('outbound', 0)}")
                print("Protocol distribution:")
                for proto, count in counts.items():
                    if proto not in ['total', 'inbound', 'outbound']:
                        print(f"  Protocol {proto}: {count}")
            else:
                print("No traffic data available")
        except Exception as e:
            print(f"{Fore.RED}Analysis failed: {str(e)}{Style.RESET_ALL}")
    
    @staticmethod
    def nslookup(domain):
        try:
            print(f"{current_color}=== DNS Lookup for {domain} ==={Style.RESET_ALL}")
            
            # A records
            print(f"\n{current_color}A Records:{Style.RESET_ALL}")
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                print(rdata.address)
            
            # MX records
            print(f"\n{current_color}MX Records:{Style.RESET_ALL}")
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"{rdata.preference} {rdata.exchange}")
            
            # NS records
            print(f"\n{current_color}NS Records:{Style.RESET_ALL}")
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                print(rdata.target)
            
            # TXT records
            print(f"\n{current_color}TXT Records:{Style.RESET_ALL}")
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    for txt_string in rdata.strings:
                        print(txt_string.decode())
            except dns.resolver.NoAnswer:
                print("No TXT records found")
        except Exception as e:
            print(f"{Fore.RED}DNS lookup failed: {str(e)}{Style.RESET_ALL}")

def initialize():
    global interface, telegram_bot, telegram_chat_id, geoip_reader
    
    # Load configuration
    config = ConfigManager.load_config()
    
    # Set interface
    interface = config['DEFAULT'].get('interface', NetworkUtils.get_interface())
    
    # Set color
    color = config['DEFAULT'].get('color', 'blue').lower()
    CommandHandler.change_color(color)
    
    # Initialize Telegram
    token = config['DEFAULT'].get('telegram_token', '')
    chat_id = config['DEFAULT'].get('telegram_chat_id', '')
    if token and chat_id:
        telegram_bot = TelegramNotifier(token, chat_id)
        telegram_chat_id = chat_id
    
    # Load GeoIP database if available
    try:
        geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    except:
        print(f"{Fore.YELLOW}Warning: GeoLite2 database not found. Geolocation features disabled.{Style.RESET_ALL}")
        geoip_reader = None
    
    # Load history
    ConfigManager.load_history()
    
    # Load threat database
    global threat_log
    threat_log = ConfigManager.load_threat_db()

def main():
    initialize()
    
    print(f"""{current_color}
          
                                                                                                           
                                                                                                             
{Style.RESET_ALL}""")
    
    print(f"{current_color}Type 'help' for available commands{Style.RESET_ALL}")
    
    try:
        while not should_stop:
            try:
                cmd = input(f"{current_color}accurateBox> {Style.RESET_ALL}").strip()
                if cmd:
                    command_history.append(cmd)
                    CommandHandler.handle_command(cmd)
            except KeyboardInterrupt:
                print("\nType 'exit' to quit")
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
    finally:
        ConfigManager.save_history()
        ConfigManager.save_threat_db()

if __name__ == "__main__":
       
    main()