# In src/ui/ports.py

import streamlit as st
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config
import ipaddress
import math
from collections import defaultdict

def ports():
    st.markdown("""
    <style>
    /* Custom styles for the page */
    h6 {
        margin-bottom: -40px;
    }
    hr {
        margin-top: 10px;
        margin-bottom: 20px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("## :material/lan: Open Ports")
    
    # Retrieve the analysis results from session state
    stats = st.session_state.get('analysis_results', {})
    if not stats or stats.get("error"):
        st.error(stats.get("error", "Analysis has not been performed yet. Please upload a PCAP file on the main page."))
        return

    # Create a mapping from IP to Hostname
    hostname_analysis = stats.get("hostname_analysis", [])
    ip_to_hostname_map = {}
    if hostname_analysis:
        for finding in hostname_analysis:
            server_ip = finding.get("Server IP")
            hostname = finding.get("Hostname")
            if server_ip and hostname and server_ip not in ip_to_hostname_map:
                ip_to_hostname_map[server_ip] = hostname

    # Display Port Information
    col1, col2 = st.columns(2)
    
    with col1:
        with st.container(border=True):
            st.metric(
                ":material/pin: Total Unique Ports", 
                stats.get("total_unique_ports", 0),
                help="The total number of unique source and destination ports seen in the capture."
            )
    
    with col2:
        with st.container(border=True):
            st.metric(
                ":material/lock_open: Detected Open Ports", 
                stats.get("total_open_ports", 0),
                help="Estimated count of open TCP ports based on successful handshakes (SYN-SYN/ACK)."
            )

    st.markdown("")
    
    graph_col, = st.columns(1)
    with graph_col:
        st.markdown("### :material/graph_3: Open Ports Network Graph")

        filter1, filter2, filter3 = st.columns(3)
        with filter1:
            show_private = st.toggle("Private IPs", value=True, help="Show connections to/from private IP ranges (e.g., 192.168.x.x).")
        with filter2:
            show_public = st.toggle("Public IPs", value=True, help="Show connections to/from public IP addresses.")
        with filter3:
            show_dns = st.toggle("DNS", value=True, help="Specifically show DNS-related connections (port 53).")
            
        with st.container(border=True):
            open_ports_data = stats.get("open_ports_details", [])
            if open_ports_data:
                nodes = []
                edges = []
                node_set = set()

                host_details = stats.get("host_details", {})
                top_ports_data = stats.get("top_ports", [])
                port_counts = {port: count for port, count in top_ports_data}

                for ip_addr_str, port_protocol in open_ports_data:
                    try:
                        ip_obj = ipaddress.ip_address(ip_addr_str)
                        is_private = ip_obj.is_private
                        is_dns_port = port_protocol.startswith('53/')

                        display_connection = False
                        if is_dns_port and show_dns:
                            display_connection = True
                        elif is_private and show_private and not is_dns_port:
                            display_connection = True
                        elif not is_private and show_public and not is_dns_port:
                            display_connection = True

                        if display_connection:
                            if is_private:
                                ip_node_color = "#1976D2"
                            else:
                                ip_node_color = "#FF9800"

                            if is_dns_port:
                                port_node_color = "#FFEB3B"
                                ip_node_color = "#D32F2F"
                            else:
                                port_node_color = "#9C27B0"

                            ip_packets = host_details.get(ip_addr_str, {}).get("total_packets", 1)
                            port_packets = port_counts.get(port_protocol, 1)

                            LOG_BASE_FACTOR = 2.5
                            
                            ip_node_size = 15 + LOG_BASE_FACTOR * math.log(1 + ip_packets)
                            ip_font_size = 16 + LOG_BASE_FACTOR * math.log(1 + ip_packets)

                            port_node_size = 10 + LOG_BASE_FACTOR * math.log(1 + port_packets)
                            port_font_size = 14 + LOG_BASE_FACTOR * math.log(1 + port_packets)

                            node_label = ip_to_hostname_map.get(ip_addr_str, ip_addr_str)
                            
                            if ip_addr_str not in node_set:
                                nodes.append(Node(
                                    id=ip_addr_str, label=node_label, size=ip_node_size, 
                                    color=ip_node_color, font={'size': ip_font_size, 'color': ip_node_color}
                                ))
                                node_set.add(ip_addr_str)
                            
                            unique_port_id = f"{ip_addr_str}:{port_protocol}"
                            
                            if unique_port_id not in node_set:
                                nodes.append(Node(
                                    id=unique_port_id, label=port_protocol, size=port_node_size, 
                                    color=port_node_color, font={'size': port_font_size, 'color': port_node_color}
                                ))
                                node_set.add(unique_port_id)
                            
                            edges.append(Edge(source=ip_addr_str, target=unique_port_id))
                            
                    except ValueError:
                        continue

                if nodes:
                    config = Config(width="100%", height=600, directed=False, physics=True, hierarchical=False,
                                    interaction={'navigationButtons': True, 'tooltipDelay': 50})
                    agraph(nodes=nodes, edges=edges, config=config)
                else:
                    st.info("No open ports match the current filter settings.")
            else:
                st.info("No open ports were detected, so no graph can be generated.")

    st.markdown("<br>", unsafe_allow_html=True)

    open_ports_data = stats.get("open_ports_details", [])

    if not open_ports_data:
        st.info("No open port data to display in the table.")
    else:
        grouped_ports = defaultdict(list)
        for ip, port in open_ports_data:
            grouped_ports[ip].append(port)

        display_data = []
        for ip, ports in sorted(grouped_ports.items()):
            hostname = ip_to_hostname_map.get(ip)
            if hostname:
                host_display = f"{hostname} ({ip})"
            else:
                host_display = ip
            
            ports_display = "\n".join(sorted(ports))
            
            display_data.append({
                "Host Name/IP": host_display,
                "Port/Protocol": ports_display
            })

        df = pd.DataFrame(display_data)

        search_col1, search_col2 = st.columns(2)
        with search_col1:
            host_query = st.text_input(
                "Search by Host or IP", 
                placeholder="e.g., example.com or 172.16.80.153",
                key="host_search_input"
            )
        with search_col2:
            port_query = st.text_input(
                "Search by Port or Protocol", 
                placeholder="e.g., 443 or https",
                key="port_search_input"
            )

        filtered_df = df
        if host_query:
            filtered_df = filtered_df[filtered_df["Host Name/IP"].str.lower().str.contains(host_query.lower())]
        
        if port_query:
            filtered_df = filtered_df[filtered_df["Port/Protocol"].str.lower().str.contains(port_query.lower())]

        st.dataframe(filtered_df, use_container_width=True, hide_index=True)