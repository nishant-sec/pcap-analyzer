# In src/ui/networks.py

import streamlit as st
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config
import os
import IP2Location
from collections import Counter
import ipaddress
import math

# Load protocol names 
def load_protocol_names(file_path):
    protocol_map = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('#') or not line.strip(): continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].isidentifier():
                    service_name = parts[0]
                    try:
                        port, proto = parts[1].split('/')
                        if port.isdigit():
                            protocol_map[(int(port), proto.lower())] = service_name
                    except ValueError: continue
    except FileNotFoundError:
        st.warning(f"Service names file not found at {file_path}. Graph labels will be basic.")
    return protocol_map

# Get geo info
def get_geo_info(ip, db, ip_to_dns_name):
    try:
        if ipaddress.ip_address(ip).is_private:
            return ip
        
        rec = db.get_all(ip)
        country_code = rec.country_short if rec and rec.country_short != '-' else '??'
        
        display_name = ip_to_dns_name.get(ip, ip)
        
        return f"{country_code} {display_name}"
    except Exception:
        return f"?? {ip}"

def networks():
    st.markdown("## :material/hub: Network Geolocation Graph")

    db_path = os.path.join("assets", "IP2LOCATION-LITE-DB9.BIN")
    try:
        geo_db = IP2Location.IP2Location(db_path)
    except Exception as e:
        st.error(f"Could not load IP2Location database from '{db_path}'. Please ensure the file exists. Error: {e}")
        return

    # Load Protocol Names
    service_names_file = os.path.join("assets", "service-names-port-numbers.txt")
    load_protocol_names(service_names_file)

    # Retrieve analysis results
    stats = st.session_state.get('analysis_results', {})
    if not stats or stats.get("error"):
        st.error("Analysis has not been performed. Please upload a PCAP file first.")
        return

    connections = stats.get("raw_flows", []) 
    hostname_analysis = stats.get("hostname_analysis", [])
    
    ip_to_dns_name = {}
    ip_to_any_hostname = {}

    for finding in hostname_analysis:
        ip = finding.get("Server IP")
        hostname = finding.get("Hostname")
        source = finding.get("Source")
        if not ip or not hostname:
            continue
        
        if source == "DNS Answer":
            ip_to_dns_name[ip] = hostname
            ip_to_any_hostname[ip] = hostname

    for finding in hostname_analysis:
        ip = finding.get("Server IP")
        hostname = finding.get("Hostname")
        if not ip or not hostname:
            continue
            
        if ip not in ip_to_any_hostname:
            ip_to_any_hostname[ip] = hostname

    if not connections:
        st.info("No connection data available to generate a network graph.")
        return

    # Identify the main local host IP
    all_ips = [ip for conn in connections for ip in (conn[0], conn[2])]
    local_host_ip = None
    ip_counts = Counter(all_ips)
    for ip, count in ip_counts.most_common():
        try:
            if ipaddress.ip_address(ip).is_private:
                local_host_ip = ip
                break
        except ValueError:
            continue
    
    if not local_host_ip:
        st.warning("Could not automatically determine the primary local host IP.")
        local_host_ip = ip_counts.most_common(1)[0][0] if ip_counts else None
        if not local_host_ip: return

    # Graph Generation
    nodes, edges = [], []
    
    with st.container(border=True):

        # Get a unique, sorted list of external IPs
        unique_external_ips = set()
        for src_ip, _, dst_ip, _, _ in connections:
            if src_ip == local_host_ip and not ipaddress.ip_address(dst_ip).is_private:
                unique_external_ips.add(dst_ip)
            elif dst_ip == local_host_ip and not ipaddress.ip_address(src_ip).is_private:
                unique_external_ips.add(src_ip)
        
        external_nodes_list = sorted(list(unique_external_ips))
        num_external_nodes = len(external_nodes_list)

        local_host_id = "local_host_node"
        local_host_x, local_host_y = 300, 0
        nodes.append(Node(id=local_host_id, 
                          label=local_host_ip,
                          shape="image",
                          image="https://raw.githubusercontent.com/sk211221/pcap-analyzer/main/assets/laptop.png",
                          size=40,
                          x=local_host_x, 
                          y=local_host_y,
                          font={'size': 18, 'color': '#00F0FF', 'face': 'monospace', 'strokeWidth': 0, 'strokeColor': '#000000'},
                          title=f"IP: {local_host_ip}\nType: Local Host",
                          physics=False))

        if num_external_nodes > 0:
            radius = 400                 
            angle_start = math.pi / 3    
            angle_end = 5 * math.pi / 3  

            angle_range = angle_end - angle_start

            for i, external_ip in enumerate(external_nodes_list):
                if num_external_nodes > 1:
                    angle = angle_start + (i / (num_external_nodes - 1)) * angle_range
                else:
                    angle = math.pi 

                node_x = local_host_x + radius * math.cos(angle)
                node_y = local_host_y + radius * math.sin(angle)
                
                geo_label = get_geo_info(external_ip, geo_db, ip_to_dns_name)
                hostname_for_tip = ip_to_any_hostname.get(external_ip, 'N/A')
                tooltip = f"IP: {external_ip}\nHostname: {hostname_for_tip}"
                external_id = external_ip.replace('.', '_')

                nodes.append(Node(id=external_id, 
                                  label=geo_label, 
                                  x=node_x, 
                                  y=node_y,
                                  shape="text",
                                  font={'size': 12, 'color': '#FFFFFF'},
                                  title=tooltip,
                                  physics=False))
                
                edges.append(Edge(source=local_host_id, target=external_id, color="#505050"))

        if len(nodes) > 1:
            config = Config(width="100%", 
                            height=800, 
                            directed=False, 
                            physics=False,
                            interaction={'navigationButtons': True, 'tooltipDelay': 30, 'zoomView': True})
            
            agraph(nodes=nodes, edges=edges, config=config)
        else:
            st.info("No external connections found for the primary local host.")