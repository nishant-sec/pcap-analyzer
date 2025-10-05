# In src/ui/upload.py

import os
import streamlit as st

def upload():
    st.markdown("""
    <style>
    /* Main title on the upload page */   
                            
    h1 {
        color: #B3A899;
    }

    /* File uploader widget */
    [data-testid="stFileUploader"] {
        border: 2px dashed #30302e;
        background-color: #1A1918;
        padding: 20px;
        border-radius: 10px;
    }
    
    /* "Drag and drop file here" text */
    [data-testid="stFileUploader"] p {
        background-color: #141413;        
        color: #FAFAFA;
        font-size: 16px;
    }

    /* "Browse files" button */
    [data-testid="stFileUploader"] button {
        background-color: #C6613F;
        color: white;
    }
    
    /* The select box for sample files */
    [data-testid="stSelectbox"] > div {
        background-color: #141413;
    }
    </style>
    """, unsafe_allow_html=True)

    hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    div[data-testid="stToolbar"] {visibility: hidden;}
    </style>
    """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)

    st.header("🔍 Packet X-Ray")
    st.text("Analyze protocols, visualize connections, and see network insights.")

    uploaded_file = st.file_uploader(
        label="Upload your file",
        type=["pcap", "pcapng"],
        label_visibility="collapsed"
    )

    if uploaded_file is not None:
        st.session_state.file_name = uploaded_file.name  
        st.session_state.file_processed = True           
        st.rerun()                                      

    st.text("Or choose a sample file:")
    directory = "./assets"
    files = []
    if os.path.exists(directory):
        files = [f for f in os.listdir(directory) if f.lower().endswith((".pcap", ".pcapng")) and os.path.isfile(os.path.join(directory, f))]
    
    col1, col2 = st.columns([1, 4])
    with col1:
        selected_file = st.selectbox("", files, label_visibility="collapsed", disabled=(not files))
    with col2:
        submit = st.button("Analyze Sample", disabled=(not files))

    if submit and selected_file:
        st.session_state.file_name = selected_file      
        st.session_state.file_processed = True          
        st.rerun()                                      