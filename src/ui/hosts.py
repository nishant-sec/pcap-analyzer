# In src/ui/hosts.py

import streamlit as st
import pandas as pd
from collections import defaultdict

def hosts():
    # Creates the Streamlit page for displaying all discovered IPs and their associated hostnames.
    
    st.markdown("## :material/dns: Discovered IP Addresses")

    # Retrieve analysis results from session state
    stats = st.session_state.get('analysis_results', {})
    if not stats or stats.get("error"):
        st.error("Analysis has not been performed. Please upload a PCAP file first.")
        return

    hostname_findings = stats.get("hostname_analysis", [])

    if not hostname_findings:
        st.info("No hostnames were discovered in the capture file.")
        return

    # Group all hostnames associated with a single IP
    ip_to_hostnames = defaultdict(set)

    for finding in hostname_findings:
        hostname = finding.get("Hostname")
        server_ip = finding.get("Server IP")
        
        if hostname and server_ip and server_ip != "N/A":
            ip_to_hostnames[server_ip].add(hostname)

    # Convert the grouped data into a list of dictionaries for the DataFrame
    display_data = []
    for ip, hostname_set in sorted(ip_to_hostnames.items()):
        hostnames_display = "\n".join(sorted(list(hostname_set)))
        display_data.append({
            "IP Address": ip,
            "Associated Hostname(s)": hostnames_display
        })

    if not display_data:
        st.info("Could not map any valid IP addresses to hostnames.")
        return
        
    df = pd.DataFrame(display_data)

    st.write("This table shows all unique IP addresses found in the network traffic and the hostnames they were mapped to.")
    
    search_query = st.text_input(
        "Search by IP or Hostname",
        placeholder="e.g., 142.250.200.42 or google.com"
    )

    # Apply the filter if a search query is entered
    if search_query:
        mask = (
            df["IP Address"].str.contains(search_query) |
            df["Associated Hostname(s)"].str.lower().str.contains(search_query.lower())
        )
        filtered_df = df[mask]
    else:
        filtered_df = df

    st.dataframe(filtered_df, use_container_width=True, hide_index=True)