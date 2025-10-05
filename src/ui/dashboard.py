# In src/ui/dashboard.py

import streamlit as st
import pandas as pd
import altair as alt

def dashboard():
    st.markdown("""
    <style>
    /* This targets the div elements created by st.columns */
    [data-testid="stHorizontalBlock"] > div {
        border: 1px solid #5F6366; /* Thin gray border */
        border-radius: 10px;      /* Rounded corners */
        padding: 10px;            /* Space between content and border */
    }
    </style>
    """, unsafe_allow_html=True)
    st.markdown("## :material/dashboard: Dashboard")
    
    # Retrieve the analysis results from session state
    stats = st.session_state.get('analysis_results', {})

    if not stats or stats.get("error"):
        st.error(stats.get("error", "Analysis could not be performed."))
        return

    # Display key metrics
    col1, col2, col3 = st.columns(3)
    col1.metric(":material/all_inbox: Total Packets", stats.get("total_packets", 0))
    col2.metric(":material/group: Total Unique IPs", stats.get("total_unique_ips", 0))
    col3.metric(":material/swap_horiz: Data Transferred", stats.get("total_data_transferred", "0 B"))

    col4, col5, col6 = st.columns(3)
    col4.metric(":material/timer: Capture Duration", stats.get("capture_duration", "0s"))
    col5.metric(":material/lan: Total Sessions", stats.get("total_sessions", 0))
    col6.metric(":material/timeline: Total Flows", stats.get("total_flows", 0))
    st.markdown("")


    # Traffic over time chart
    graph_col, = st.columns(1)
    with graph_col:   
        st.markdown("### :material/traffic: Traffic Over Time")
        traffic_data = stats.get("traffic_over_time", [])
        
        if traffic_data:
            # Create a Pandas DataFrame from the collected data
            df = pd.DataFrame(traffic_data)
            df = df.set_index('time')

            # Count packets and sum bytes for each interval
            resampled_df = df.resample('1S').agg(
                Packets=('bytes', 'count'),
                Bytes=('bytes', 'sum')
            ).reset_index()

            chart_type = st.radio(
                'Select metric to display:', 
                ('Packets per second', 'Bytes per second'),
                horizontal=True,
                label_visibility='collapsed'
            )

            if chart_type == 'Packets per second':
                y_column, y_title = 'Packets', 'Packets/sec'
            else:
                y_column, y_title = 'Bytes', 'Bytes/sec'

            chart = alt.Chart(resampled_df).mark_line(
                interpolate='monotone'
            ).encode(
                x=alt.X('time:T', title='Time'),
                y=alt.Y(f'{y_column}:Q', title=y_title),
                tooltip=[
                    alt.Tooltip('time:T', title='Time'),
                    alt.Tooltip(f'{y_column}:Q', title=y_title)
                ]
            )

            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No traffic data available to plot.")

    # Display top talkers and flow table
    col6, col7 = st.columns(2)
    
    with col6:
        st.markdown("### :material/podcasts: Top 10 Talkers")
        top_talkers_df = pd.DataFrame(stats.get("top_talkers", []), columns=['IP Address', 'Packet Count'])
        st.dataframe(top_talkers_df, use_container_width=True, hide_index=True)

    with col7:
        st.markdown("### :material/route: Network Flows")
        flow_data = stats.get("flow_details", [])
        
        if flow_data:
            flows_df = pd.DataFrame(flow_data, columns=["Flow Details"])
            st.dataframe(flows_df, use_container_width=True, hide_index=True)
        else:
            st.info("No network flows were identified in the capture.")