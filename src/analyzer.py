# In src/analyzer.py

import scapy.all as sc
from collections import Counter, defaultdict
from datetime import datetime
import pandas as pd
import re
import ipaddress
from scapy.layers.tls.all import *

PORT_FILE_PATH = "assets/service-names-port-numbers.txt"

def load_ports_from_file(file_path):
    ports = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip() or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) >= 2 and '/' in parts[1]:
                    port_str = parts[1].split('/')[0]
                    if port_str.isdigit():
                        ports.add(int(port_str))
    except FileNotFoundError:
        print(f"Warning: Port file not found at {file_path}. High-interest port feature will be disabled.")
        return set()
        
    return ports

HIGH_INTEREST_PORTS = load_ports_from_file(PORT_FILE_PATH)

def format_bytes(size):
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def identify_host_server(packet):
    if not packet.haslayer(sc.IP):
        return "N/A", "N/A"

    src_ip_str, dst_ip_str = packet[sc.IP].src, packet[sc.IP].dst
    
    try:
        src_ip = ipaddress.ip_address(src_ip_str)
        dst_ip = ipaddress.ip_address(dst_ip_str)

        if src_ip.is_private and not dst_ip.is_private: return src_ip_str, dst_ip_str
        if dst_ip.is_private and not src_ip.is_private: return dst_ip_str, src_ip_str

        if packet.haslayer(sc.TCP) or packet.haslayer(sc.UDP):
            sport = packet.sport
            dport = packet.dport
            if dport < 1024 and sport >= 49152: return src_ip_str, dst_ip_str
            if sport < 1024 and dport >= 49152: return dst_ip_str, src_ip_str
    except ValueError:
        return src_ip_str, dst_ip_str

    return src_ip_str, dst_ip_str

def add_finding(hostname, source_method, pkt, findings_list, found_set):

    unique_key = (hostname, source_method)
    if hostname and unique_key not in found_set:
        host_ip, server_ip = identify_host_server(pkt)
        
        findings_list.append({
            "Hostname": hostname,
            "Source": source_method,
            "Host IP (Client)": host_ip,
            "Server IP": server_ip,
            "Evidence": pkt.summary()
        })
        found_set.add(unique_key)

def analyze_pcap(file_path):
    try:
        all_ips, all_ports, flows, sessions, protocol_counts = [], [], set(), set(), Counter()
        total_data = 0; traffic_over_time = []; tcp_handshakes = {}; open_ports_details = set()
        hostname_findings = []; found_hostnames = set()
        packet_count = 0; start_time, end_time = None, None
        host_details = {}
        connections = Counter() 
        dns_log = [] 

        with sc.PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                
                packet_time = datetime.fromtimestamp(float(packet.time))
                if start_time is None: start_time = packet_time
                end_time = packet_time
                total_data += len(packet)
                traffic_over_time.append({'time': packet_time, 'bytes': len(packet)})

                if packet.haslayer(sc.IP):
                    ip_layer = packet[sc.IP]
                    all_ips.extend([ip_layer.src, ip_layer.dst])

                    connections[(ip_layer.src, ip_layer.dst)] += len(packet)

                    for ip_addr in [ip_layer.src, ip_layer.dst]:
                        if ip_addr not in host_details:
                            host_details[ip_addr] = {"total_packets": 0}
                        host_details[ip_addr]["total_packets"] += 1
                    
                    if packet.haslayer(sc.TCP):
                        proto = "TCP"; tcp_layer = packet[sc.TCP]; protocol_counts[proto] += 1
                        sport, dport = tcp_layer.sport, tcp_layer.dport; all_ports.extend([sport, dport])
                        flows.add((ip_layer.src, sport, ip_layer.dst, dport, proto))
                        sessions.add(tuple(sorted(((ip_layer.src, sport), (ip_layer.dst, dport)))) + (proto,))
                        if tcp_layer.flags == 'S': tcp_handshakes[(ip_layer.src, sport, ip_layer.dst, dport)] = packet.time
                        elif tcp_layer.flags == 'SA':
                            key = (ip_layer.dst, dport, ip_layer.src, sport)
                            if key in tcp_handshakes:
                                open_ports_details.add((ip_layer.src, f"{tcp_layer.sport}/{proto}")); del tcp_handshakes[key]
                    elif packet.haslayer(sc.UDP):
                        proto = "UDP"; protocol_counts[proto] += 1
                        sport, dport = packet[sc.UDP].sport, packet[sc.UDP].dport; all_ports.extend([sport, dport])
                        flows.add((ip_layer.src, sport, ip_layer.dst, dport, proto))
                        sessions.add(tuple(sorted(((ip_layer.src, sport), (ip_layer.dst, dport)))) + (proto,))
                    elif packet.haslayer(sc.ICMP): protocol_counts["ICMP"] += 1
                
                if packet.haslayer(TLS_Ext_ServerName):
                    try:
                        for sn in packet[TLS_Ext_ServerName].servernames: add_finding(sn.servername.decode('utf-8'), "TLS SNI", packet, hostname_findings, found_hostnames)
                    except Exception: pass
                
                if packet.haslayer(sc.TCP) and packet.haslayer(sc.Raw) and (packet.sport in [80, 8080] or packet.dport in [80, 8080]):
                    try:
                        payload = packet[sc.Raw].load.decode('utf-8', errors='ignore')
                        for line in payload.split('\r\n'):
                            if line.lower().startswith('host:'): add_finding(line.split(' ')[1].strip(), "HTTP Host Header", packet, hostname_findings, found_hostnames)
                    except Exception: pass

                if packet.haslayer(sc.UDP) and (packet.sport == 88 or packet.dport == 88) and packet.haslayer(sc.Raw):
                    try:
                        matches = re.findall(b'([a-z0-9-]+\\.[a-z0-9-.]+)', packet[sc.Raw].load, re.IGNORECASE)
                        for match in matches:
                            realm = match.decode()
                            if "." in realm and len(realm) > 5: add_finding(realm, "Kerberos Realm", packet, hostname_findings, found_hostnames)
                    except Exception: pass

                if packet.haslayer(sc.DNSQR):
                    try:
                        query_name = packet[sc.DNSQR].qname.decode('utf-8').strip('.')
                        add_finding(query_name, "DNS Query", packet, hostname_findings, found_hostnames)
                        if packet.haslayer(sc.IP):
                            dns_log.append({"type": "Query", "name": query_name, "client": packet[sc.IP].src, "server": packet[sc.IP].dst})
                    except Exception: pass
                
                # Check if it's a DNS response packet with answers
                if packet.haslayer(sc.DNS) and packet[sc.DNS].qr == 1 and packet.haslayer(sc.DNSRR):
                    try:
                        # Iterate through all answer records
                        for i in range(packet[sc.DNS].ancount):
                            answer = packet[sc.DNS].an[i]
                            
                            # Check for A (IPv4) or AAAA (IPv6) records
                            if answer.type in [1, 28]: 
                                dns_name = answer.rrname.decode('utf-8').strip('.')
                                resolved_ip = answer.rdata
                                
                                # Use a unique source to distinguish from queries
                                unique_key = (dns_name, "DNS Answer") 
                                
                                # Add finding if it's new
                                if unique_key not in found_hostnames:
                                    hostname_findings.append({
                                        "Hostname": dns_name,
                                        "Source": "DNS Answer", 
                                        "Host IP (Client)": packet[sc.IP].dst, 
                                        "Server IP": resolved_ip, 
                                        "Evidence": f"DNS Answer: {dns_name} -> {resolved_ip}"
                                    })
                                    found_hostnames.add(unique_key)
                                
                                # Log the answer event
                                dns_log.append({"type": "Answer", "name": dns_name, "ip": resolved_ip, "server": packet[sc.IP].src})

                    except Exception:
                        pass

                if packet.haslayer(sc.DHCP) and packet[sc.DHCP].options[0][1] in [1, 3]:
                    for option in packet[sc.DHCP].options:
                        if isinstance(option, tuple) and option[0] == 'hostname':
                            try: add_finding(option[1].decode(), "DHCP Request", packet, hostname_findings, found_hostnames)
                            except Exception: pass

                if packet.haslayer(sc.NBNSQueryRequest):
                    try: add_finding(packet[sc.NBNSQueryRequest].QUESTION_NAME.strip().decode('utf-8', 'ignore'), "NBNS", packet, hostname_findings, found_hostnames)
                    except Exception: pass
                
                if packet.haslayer(sc.LLMNRQuery):
                    try: add_finding(packet[sc.LLMNRQuery].qname.decode('utf-8'), "LLMNR", packet, hostname_findings, found_hostnames)
                    except Exception: pass
                
                if packet.haslayer(sc.DNS) and packet.haslayer(sc.IP) and packet.getlayer(sc.IP).dst == '224.0.0.251':
                    if packet[sc.DNS].qd and hasattr(packet[sc.DNS].qd, 'qname'):
                        try:
                            hostname_raw = packet[sc.DNS].qd.qname.decode('utf-8')
                            if "_tcp.local" in hostname_raw or "_udp.local" in hostname_raw:
                                add_finding(hostname_raw.split('.')[0], "mDNS", packet, hostname_findings, found_hostnames)
                        except Exception: pass

        if packet_count == 0:
            return {"error": "PCAP file is empty or could not be read."}

        flow_details = [f"Flow {i}: {s_ip}:{s_p} → {d_ip}:{d_p} ({p})" for i, (s_ip, s_p, d_ip, d_p, p) in enumerate(sorted(list(flows)), 1)]

        return {
            "total_packets": packet_count,
            "total_unique_ips": len(set(all_ips)),
            "total_data_transferred": format_bytes(total_data),
            "capture_duration": f"{(end_time - start_time).total_seconds():.2f} s" if start_time and end_time else "N/A",
            "total_sessions": len(sessions),
            "total_flows": len(flows),
            "flow_details": flow_details,
            "top_talkers": Counter(all_ips).most_common(10),
            "top_ports": Counter(all_ports).most_common(10),
            "traffic_over_time": traffic_over_time,
            "total_unique_ports": len(set(all_ports)),
            "open_ports_details": sorted(list(open_ports_details)),
            "total_open_ports": len(open_ports_details),
            "hostname_analysis": hostname_findings,
            "host_details": host_details,
            "raw_flows": list(flows),
            "protocol_connections": list(flows), 
            "connections": connections,
            "dns_log": dns_log 
        }

    except Exception as e:
        return {"error": f"An unexpected error occurred during analysis: {e}"}