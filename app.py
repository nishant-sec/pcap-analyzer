# In app.py

import streamlit as st
import os

from src.ui.upload import upload
from src.ui.dashboard import dashboard
from src.ui.ports import ports
from src.analyzer import analyze_pcap
from src.ui.geomap import geomap
from src.ui.networks import networks
from src.ui.hosts import hosts

st.set_page_config(
    page_title="Packet X-Ray",
    page_icon="🔍",
    layout="wide"
)

st.markdown(
    """
    <style>
        /* General sidebar styles */
        section[data-testid="stSidebar"] {
            width: 260px !important;
            border-right: 1px solid #3f3f3f;
        }

        /* Target all buttons within the sidebar */
        section[data-testid="stSidebar"] div[data-testid="stButton"] > button {
            justify-content: flex-start;
            padding-left: 0.5rem;
            border: 1px solid transparent;
            transition: border-color 0.2s ease-in-out, background-color 0.2s ease-in-out;
            background-color: #1F1E1D;
            color: #FFFFFF;
            border-radius: 15px !important;
        }
        
        /* --- THIS IS THE NEW RULE TO PULL BUTTONS TOGETHER --- */
        section[data-testid="stSidebar"] div[data-testid="stButton"] {
            margin-top: -10px !important; 
        }

        section[data-testid="stSidebar"] div[data-testid="stButton"] > button:hover {
        background-color: #333333; /* Example: Lighter gray background */
        }

        /* When a button is actively being clicked */
        section[data-testid="stSidebar"] div[data-testid="stButton"] > button:active {
            border-color: #262624;
        }
        
        /* Remove the default focus outline */
        section[data-testid="stSidebar"] div[data-testid="stButton"] > button:focus:not(:active) {
            border-color: transparent;
            outline: none !important;
            box-shadow: none !important;
        }

        /* Another attempt with Streamlit's internal classes */
        section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
            background-color: #333333 !important;
            border-color: #333333 !important;
        }
        
        .sidebar-info {
            padding-left: 0.5rem; /* Matches button padding */
            margin-top: -10px !important; /* Matches button negative margin */
            text-align: left; /* Explicitly align text to the left */
        }
    </style>
    """,
    unsafe_allow_html=True,
)

if 'file_processed' not in st.session_state:
    st.session_state.file_processed = False
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'file_name' not in st.session_state:
    st.session_state.file_name = None 

# Main application logic
if not st.session_state.file_processed:
    upload()
else:
    # Analyze the file only once after upload
    if st.session_state.analysis_results is None:
        file_path = os.path.join("assets", st.session_state.file_name)
        with st.spinner(f"Analyzing {st.session_state.file_name}..."):
            st.session_state.analysis_results = analyze_pcap(file_path)

    # Sidebar Navigation
    with st.sidebar:
        st.markdown(
            """
            <div class='sidebar-info'>
                <h3>🔍 Packet X-Ray</h3>
                <p style="color: grey; font-size: 14px;">
                    Made by <a href="https://www.linkedin.com/in/nishantchavan1/" target="_blank" style="color: lightblue;">Nishant Chavan</a>
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown(
            f"""
            <div class='sidebar-info'>
                <p><b>File:</b> <code>{st.session_state.file_name}</code></p>
            </div>
            """,
            unsafe_allow_html=True
        )


        st.markdown("")

        selected_page = st.query_params.get("page", "Dashboard")
        pages_with_icons = {
            "Dashboard": "dashboard",
            "Open Ports": "lan",
            "Hosts": "host",
            "Geo Map": "map",
            "Network Graph": "hub"
        }

        for page, icon_name in pages_with_icons.items():
            is_active = (page == selected_page)
            button_clicked = False
            
            try:
                if st.button(
                    page,
                    use_container_width=True,
                    type="primary" if is_active else "secondary",
                    icon=f":material/{icon_name}:"
                ):
                    button_clicked = True

            except st.errors.StreamlitAPIException:
                print(f"Warning: Invalid icon name '{icon_name}' for page '{page}'.")
                
                if st.button(
                    page,
                    use_container_width=True,
                    type="primary" if is_active else "secondary"
                ):
                    button_clicked = True

            if button_clicked:
                st.query_params["page"] = page
                st.rerun()

    # Main Page Content Routing
    if selected_page == "Dashboard":
        dashboard()
    elif selected_page == "Open Ports":
        ports()
    elif selected_page == "Hosts":
        hosts()
    elif selected_page == "Geo Map":
        geomap()
    elif selected_page == "Network Graph":
        networks()