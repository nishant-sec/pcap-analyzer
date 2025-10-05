# In src/ui/geomap.py

import streamlit as st
import folium
from streamlit_folium import st_folium
from folium.plugins import MarkerCluster
import IP2Location
import ipaddress
import os
import pandas as pd
from collections import Counter

# Helper function to format byte counts into a readable format
def format_bytes(size):
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def display_connections_table(stats):
    
    # Processes and displays the connections data in a filterable table.
    connections = stats.get("connections", {})
    hostname_findings = stats.get("hostname_analysis", [])

    if not connections:
        st.info("No connection data found in the analysis results.")
        return

    # Hostname mapping to IP
    hostname_map = {}
    for finding in hostname_findings:
        server_ip = finding.get("Server IP")
        hostname = finding.get("Hostname")
        # Add the mapping if the server IP is valid and not already mapped
        if server_ip and server_ip != "N/A" and server_ip not in hostname_map:
            hostname_map[server_ip] = hostname

    # Process the raw connection data into a list for the DataFrame
    processed_data = []
    for (src_ip, dst_ip), byte_count in connections.items():
        # Get the display name for source (hostname or IP)
        from_display = hostname_map.get(src_ip, src_ip)
        if from_display != src_ip:
            from_display = f"{from_display} ({src_ip})"

        # Get the display name for destination (hostname or IP)
        to_display = hostname_map.get(dst_ip, dst_ip)
        if to_display != dst_ip:
            to_display = f"{to_display} ({dst_ip})"

        processed_data.append({
            "From": from_display,
            "To": to_display,
            "Bytes Transferred": format_bytes(byte_count),
            "bytes_raw": byte_count 
        })

    if not processed_data:
        st.info("No connections to display.")
        return

    # Create a DataFrame and sort by data transferred
    df = pd.DataFrame(processed_data)
    df = df.sort_values(by="bytes_raw", ascending=False).drop(columns=["bytes_raw"])
    
    # Create filter inputs
    col1, col2 = st.columns([1, 1])
    from_filter = col1.text_input("Filter by Source", placeholder="e.g., hacker.local or 192.168.110.130")
    to_filter = col2.text_input("Filter by Destination", placeholder="e.g., googleapis.com or 142.250.200.42")
    
    # Apply filters to the DataFrame
    filtered_df = df
    if from_filter:
        filtered_df = filtered_df[filtered_df['From'].str.contains(from_filter, case=False, na=False)]
    if to_filter:
        filtered_df = filtered_df[filtered_df['To'].str.contains(to_filter, case=False, na=False)]

    # Display the final table
    st.dataframe(filtered_df, use_container_width=True, hide_index=True)


def geomap():
    # Creates the Streamlit page for displaying the GeoIP map and connections table.
    st.markdown("## :material/map: GeoIP Map & Connections")

    stats = st.session_state.get('analysis_results', {})
    if not stats or stats.get("error"):
        st.error(stats.get("error", "Analysis has not been performed yet. Please upload a PCAP file on the main page."))
        return

    db_path = os.path.join("./assets", "IP2LOCATION-LITE-DB9.BIN")

    if not os.path.exists(db_path):
        st.error(f"IP2Location database not found at {db_path}.")
        st.info("Please download the DB9 .BIN file from IP2Location LITE and place it in the 'assets' directory.")
        return
        
    try:
        ip2loc = IP2Location.IP2Location(db_path)
    except Exception as e:
        st.error(f"Error loading IP2Location database: {e}")
        return

    host_details = stats.get("host_details", {})
    if not host_details:
        st.info("No host details found in the analysis results.")
        display_connections_table(stats)
        return

    location_data = []
    for ip_str in host_details.keys():
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private and not ip.is_loopback:
                rec = ip2loc.get_all(ip_str)
                if rec and rec.latitude and rec.longitude:
                    location_data.append({
                        "ip": ip_str,
                        "lat": float(rec.latitude),
                        "lon": float(rec.longitude),
                        "city": rec.city,
                        "region": rec.region,
                        "country": rec.country_long,
                    })
        except (ValueError, Exception):
            continue

    if location_data:
        with st.container(border=True):
            avg_lat = sum(p['lat'] for p in location_data) / len(location_data)
            avg_lon = sum(p['lon'] for p in location_data) / len(location_data)

            m = folium.Map(location=[avg_lat, avg_lon], zoom_start=2)
            marker_cluster = MarkerCluster().add_to(m)

            for point in location_data:
                popup_text = f"""
                    <b>IP Address:</b> {point['ip']}<br>
                    <b>Location:</b> {point['city']}, {point['region']}, {point['country']}
                """
                folium.Marker(
                    location=[point['lat'], point['lon']],
                    popup=folium.Popup(popup_text, max_width=300),
                    icon=folium.Icon(color='blue', icon='info-sign') 
                ).add_to(marker_cluster)

            st_folium(m, use_container_width=True, height=500)
    else:
        st.info("No public IP addresses with location data to display on the map.")

    display_connections_table(stats)