## Packet X-Ray: A Wireshark PCAP Analyzer
Packet X-Ray is a powerful and user-friendly PCAP analyzer that allows you to decode and visualize network traffic from `.pcap` and `.pcapng` files that are generated from Wireshark. It's designed to help network administrators, security analysts, and developers troubleshoot network issues, analyze security events, and gain insights into network communications.

## Live Demo
You can access a live demo of the application here: **[Packet X-Ray on Streamlit](https://pcap-app.streamlit.app/)**

## Application Screenshot
<img width="1890" height="930" alt="image" src="https://github.com/user-attachments/assets/d2fda621-4a86-43de-926d-16e77bc525f1" />

## Features
- **Comprehensive Dashboard**: Get a high-level overview of the network traffic, including key metrics like total packets, unique IPs, data transferred, and capture duration.
- **Traffic Over Time**: Visualize the network traffic volume (packets/sec or bytes/sec) over time to identify spikes and trends.
- **Top Talkers & Network Flows**: Quickly identify the most active devices on the network and view a detailed list of all network flows.
- **Open Port Detection**: Automatically detects open TCP ports based on successful handshakes and provides a filterable list and interactive graph of open ports.
- **Discovered Hosts**: Displays a list of all discovered IP addresses and their associated hostnames, with search functionality.
- **Geolocation Graph**: Visualizes the geographic location of external IP addresses, showing connections between your local host and servers around the world.
- **Interactive Network Graphs**: Explore the relationships between hosts and ports with interactive and customizable network graphs.
- **Detailed Hostname Analysis**: Discovers hostnames from various sources, including DNS queries and answers, TLS SNI, HTTP Host Headers, and more.
- **File Upload & Sample Data**: Easily upload your own PCAP files or use the provided sample files to get started quickly.

## Getting Started
#### Prerequisites
- Python 3.7+
- The dependencies are listed in the `requirements.txt` file.
#### Installation
1. Clone the repository:
```
git clone https://github.com/nishant-sec/pcap-analyzer.git
cd pcap-analyzer
```

2. Install the dependencies:
```
pip install -r requirements.txt
```

### Usage
1. Run the Streamlit application:
```
streamlit run app.py
```

2. Upload a PCAP file:
	- Drag and drop your `.pcap` or `.pcapng` file into the file uploader.
    - Or, select one of the provided sample files and click "Analyze Sample".

3. Explore the analysis:
    - The application will automatically analyze the file and present the results in the dashboard.
    - Use the sidebar to navigate between the different analysis pages: Dashboard, Open Ports, Hosts, Geo Map, and Network Graph.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Acknowledgements
- This project uses the IP2Location LITE database for <a href="https://lite.ip2location.com">IP geolocation</a>.
- The interactive maps are powered by [Folium](https://python-visualization.github.io/folium/) and use map tiles from [OpenStreetMap](https://www.openstreetmap.org/copyright) and [Esri](https://www.esri.com/en-us/home).
- Service name and port number mappings are provided by the [Internet Assigned Numbers Authority (IANA)](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).
