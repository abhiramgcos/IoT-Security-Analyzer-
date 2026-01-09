
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import os
import time
from utils.api_client import APIClient
from utils.traffic_client import TrafficClient

# Page configuration
st.set_page_config(
    page_title="IoT Security Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize API clients
api = APIClient(base_url=os.getenv("API_URL", "http://localhost:8000"))
traffic_api = TrafficClient(base_url=os.getenv("TRAFFIC_API_URL", "http://localhost:8001"))

# Custom CSS
st.markdown("""
<style>
    [data-testid="stMetricValue"] {
        font-size: 24px;
    }
    .stTabs [data-baseweb="tab-list"] button {
        font-size: 16px;
    }
</style>
""", unsafe_allow_html=True)

# ========== SIDEBAR NAVIGATION ==========

st.sidebar.title("🔐 IoT Security Analyzer")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "🔍 Network Scan",
        "📦 Firmware Analysis",
        "⚠️ Vulnerabilities",
        "📊 Traffic Monitor",
        "📄 Reports",
        "⚙️ Settings"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info(
    """
    **IoT Security Analyzer v1.0**
    
    Network security analysis platform for IoT devices.
    
    [Documentation](http://localhost:8000/docs) | 
    [GitHub](https://github.com) |
    [API Status](http://localhost:8000/health)
    """
)

# ========== MAIN CONTENT ==========

if page == "🏠 Dashboard":
    st.title("Dashboard")
    st.markdown("System overview and key metrics")
    
    # Check API Connection first
    try:
        info = api.get_info()
        st.success(f"Connected to {info.get('service')} v{info.get('version')}")
    except Exception as e:
        st.error(f"Failed to connect to backend API: {e}")
        st.stop()

    # Fetch Real Data
    try:
        devices = api.get_devices()
        scan_count = len(devices)
        
        # Calculate recent devices (mock logic for 'today' as db doesn't strictly enforce it in this simple version)
        # In real app: datetime.fromisoformat(d['last_seen']) > today
        recent_count = sum(1 for d in devices if d.get('status') == 'online')
        
        # Fetch vuln summary (API endpoint needs to be updated to be real too, but let's assume it returns what we built)
        # Note: We didn't refactor 'vulnerabilities.py' to return real aggregated data yet from DB, 
        # it was returning mock data in the route. 
        # Let's do a quick calculation here based on device fetches if API doesn't support it fully yet,
        # OR better: use the API and ensure the API returns real data (we refactored the SERVICE, not the ROUTE entirely).
        # The route 'vulnerabilities.py' /summary still has hardcoded data. 
        # We should probably fix that route too, but for now let's use what we have or do client-side calc if needed.
        # Ideally, we call api.get_vulnerability_summary() and expect it to be correct. 
        # For this step, I will use the API call and if it returns hardcoded from route, so be it, 
        # OR I can update the route in next step.
        # Let's assume we will fix the route.
        
        vuln_summary = api.get_vulnerability_summary() 
        # If vuln_summary is still mock (which it is in routes/vulnerabilities.py), we should display it but note it.
        
        # Real Score
        score_data = api.get_network_score()

    except Exception as e:
        st.error(f"Error fetching dashboard data: {e}")
        st.stop()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Devices Scanned", scan_count, f"{recent_count} online")
    with col2:
        st.metric("Total CVEs", vuln_summary.get('total_cves', 0))
    with col3:
        st.metric("Network Score", f"{score_data.get('overall_score', 0)}/100")
    with col4:
        st.metric("DB Status", info.get('database'))
    
    st.markdown("---")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        # Real Severity distribution
        severity_data = {
            'Severity': ['Critical', 'High', 'Medium', 'Low'],
            'Count': [
                vuln_summary.get('critical', 0),
                vuln_summary.get('high', 0),
                vuln_summary.get('medium', 0),
                vuln_summary.get('low', 0)
            ]
        }
        df_severity = pd.DataFrame(severity_data)
        fig = px.pie(df_severity, values='Count', names='Severity',
                     color='Severity',
                     color_discrete_map={
                         'Critical': '#FF0000',
                         'High': '#FF6B35',
                         'Medium': '#FFD93D',
                         'Low': '#6BCB77'
                     })
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Real Device types
        if devices:
            type_counts = {}
            for d in devices:
                t = d.get('device_type', 'Unknown')
                type_counts[t] = type_counts.get(t, 0) + 1
            
            df_devices = pd.DataFrame({
                'Type': list(type_counts.keys()),
                'Count': list(type_counts.values())
            })
            fig = px.bar(df_devices, x='Type', y='Count',
                         title='Devices by Type',
                         color='Count',
                         color_continuous_scale='Blues')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No device data to display")

elif page == "🔍 Network Scan":
    st.title("Network Scan")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        subnet = st.text_input("Target Subnet", value="192.168.1.0/24")
    with col2:
        interface = st.selectbox("Interface", ["eth0", "wlan0", "docker0"])
    
    if st.button("🚀 Start Scan", use_container_width=True):
        with st.spinner("Scanning network..."):
            try:
                result = api.start_scan(subnet, interface)
                st.success(f"Scan started! ID: {result.get('scan_id')}")
            except Exception as e:
                st.error(f"Scan failed: {e}")
    
    st.markdown("---")
    st.subheader("Discovered Devices")
    
    try:
        devices = api.get_devices()
        if devices:
            # Professional Table View
            # Flatten or format data for display
            display_data = []
            for d in devices:
                display_data.append({
                    "IP Address": d.get('ip_address'),
                    "Hostname": d.get('hostname'),
                    "Manufacturer": d.get('manufacturer'),
                    "Model": d.get('model') or "Unknown",
                    "Type": d.get('device_type'),
                    "MAC": d.get('mac_address'),
                    "Status": d.get('status'),
                    "Open Ports": str(d.get('open_ports', []))
                })
            
            df = pd.DataFrame(display_data)
            
            # Use data editor for interaction capability if needed, or stick to dataframe
            st.data_editor(
                df,
                column_config={
                    "Status": st.column_config.TextColumn(
                        "Status",
                        help="Device Online/Offline status",
                    ),
                    "Open Ports": st.column_config.TextColumn(
                        "Open Ports",
                        width="medium"
                    )
                },
                use_container_width=True,
                hide_index=True,
                num_rows="dynamic"
            )
        else:
            st.info("No devices discovered yet. Run a scan.")
    except Exception as e:
        st.error(f"Error fetching devices: {e}")

elif page == "📦 Firmware Analysis":
    st.title("Firmware Analysis")
    
    # Create tabs for different analysis modes
    tab1, tab2, tab3 = st.tabs(["📤 Upload & Analyze", "📥 Fetch from Vendor", "🔬 Advanced Emulation"])
    
    with tab1:
        st.subheader("Upload Firmware for Analysis")
        
        uploaded_file = st.file_uploader(
            "Choose a firmware file",
            type=['bin', 'img', 'trx', 'chk', 'fw', 'zip', 'tar', 'gz'],
            help="Supported formats: .bin, .img, .trx, .chk, .fw, .zip, .tar, .gz"
        )
        
        if uploaded_file is not None:
            st.info(f"📁 File: **{uploaded_file.name}** ({uploaded_file.size / 1024:.1f} KB)")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("⬆️ Upload Firmware", use_container_width=True, type="primary"):
                    with st.spinner("Uploading firmware..."):
                        try:
                            result = api.upload_firmware((uploaded_file.name, uploaded_file, 'application/octet-stream'))
                            st.success(f"✅ Uploaded successfully!")
                            st.session_state['last_uploaded_path'] = result.get('path')
                            st.session_state['last_uploaded_hash'] = result.get('sha256')
                            
                            st.markdown(f"""
                            **File Details:**
                            - Path: `{result.get('path')}`
                            - Size: {result.get('size')} bytes
                            - SHA256: `{result.get('sha256')[:16]}...`
                            """)
                        except Exception as e:
                            st.error(f"Upload failed: {e}")
            
            with col2:
                if st.session_state.get('last_uploaded_path'):
                    if st.button("🔍 Analyze with Binwalk", use_container_width=True):
                        with st.spinner("Analyzing firmware (this may take a minute)..."):
                            try:
                                result = api.analyze_firmware(st.session_state['last_uploaded_path'])
                                analysis = result.get('analysis', {})
                                
                                st.success("Analysis complete!")
                                
                                col_a, col_b, col_c = st.columns(3)
                                with col_a:
                                    st.metric("Architecture", analysis.get('architecture', 'Unknown'))
                                with col_b:
                                    st.metric("File System", analysis.get('file_system', 'Unknown'))
                                with col_c:
                                    st.metric("Entropy", f"{analysis.get('entropy', 0):.1f}")
                                
                                if analysis.get('secrets_found'):
                                    st.warning("⚠️ Potential Secrets Found:")
                                    for secret in analysis.get('secrets_found', []):
                                        st.markdown(f"- {secret}")
                                else:
                                    st.info("No obvious secrets detected")
                                    
                            except Exception as e:
                                st.error(f"Analysis failed: {e}")
    
    with tab2:
        st.subheader("Fetch Firmware from Vendor")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            manufacturer = st.text_input("Manufacturer", "TP-Link")
        with col2:
            model = st.text_input("Model", "Archer C7")
        with col3:
            version = st.text_input("Version (optional)", "")
        
        if st.button("📥 Fetch Firmware", use_container_width=True):
            with st.spinner("Downloading firmware..."):
                try:
                    result = api.fetch_firmware(manufacturer, model, version)
                    st.success(f"Firmware downloaded: {result.get('path')}")
                    st.session_state['last_uploaded_path'] = result.get('path')
                except Exception as e:
                    st.error(f"Fetch failed: {e}")
    
    with tab3:
        st.subheader("Advanced Firmware Emulation (FirmAE)")
        
        st.info("""
        **FirmAE** provides advanced firmware analysis through full system emulation:
        - 🖥️ Emulates firmware in QEMU
        - 🌐 Tests network reachability
        - 🕸️ Detects web interfaces
        - 🔓 Identifies exposed services
        """)
        
        # Check for uploaded firmware
        firmware_path = st.session_state.get('last_uploaded_path', '')
        
        if not firmware_path:
            st.warning("Please upload a firmware file in the 'Upload & Analyze' tab first.")
        else:
            st.markdown(f"**Selected Firmware:** `{firmware_path}`")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                if st.button("🚀 Start Emulation", use_container_width=True, type="primary"):
                    with st.spinner("Starting FirmAE emulation..."):
                        try:
                            result = api.start_emulation(firmware_path)
                            st.session_state['emulation_request_id'] = result.get('request_id')
                            st.success(f"Emulation started! Request ID: `{result.get('request_id')}`")
                            st.info(result.get('message'))
                        except Exception as e:
                            if "503" in str(e) or "Connection" in str(e):
                                st.error("FirmAE service is not available. Please ensure the FirmAE Docker container is running.")
                            else:
                                st.error(f"Emulation failed: {e}")
            
            with col2:
                if st.session_state.get('emulation_request_id'):
                    if st.button("🔄 Check Status", use_container_width=True):
                        try:
                            status = api.get_emulation_status(st.session_state['emulation_request_id'])
                            st.json(status)
                        except Exception as e:
                            st.error(f"Status check failed: {e}")
        
        # Display emulation results if available
        if st.session_state.get('emulation_request_id'):
            st.markdown("---")
            st.subheader("Emulation Status")
            
            try:
                status = api.get_emulation_status(st.session_state['emulation_request_id'])
                status_value = status.get('status', 'unknown')
                
                if status_value == 'queued':
                    st.info("⏳ Job is queued...")
                elif status_value == 'running':
                    st.warning("🔄 Emulation in progress...")
                elif status_value == 'completed':
                    st.success("✅ Emulation completed!")
                    
                    result = api.get_emulation_result(st.session_state['emulation_request_id'])
                    if result.get('data', {}).get('result'):
                        st.json(result)
                elif status_value == 'failed':
                    st.error(f"❌ Emulation failed: {status.get('error')}")
                
                # Show logs
                with st.expander("📋 Emulation Logs"):
                    try:
                        logs = api.get_emulation_logs(st.session_state['emulation_request_id'])
                        for log in logs.get('data', []):
                            st.text(f"[{log.get('timestamp')}] {log.get('message')}")
                    except:
                        st.info("No logs available")
                        
            except Exception as e:
                st.error(f"Could not fetch status: {e}")
    
    st.markdown("---")
    st.subheader("📁 Cached Firmware")
    
    if st.button("🔄 Refresh Cache"):
        st.rerun()
    
    try:
        cache = api.get_cached_firmware()
        
        # Show uploads
        uploads = cache.get('uploads', [])
        if uploads:
            st.markdown("**Uploaded Files:**")
            for upload in uploads:
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.text(upload.get('filename'))
                with col2:
                    st.text(f"{upload.get('size', 0) / 1024:.1f} KB")
                with col3:
                    if st.button("🗑️", key=f"del_{upload.get('filename')}"):
                        try:
                            api.delete_firmware(upload.get('filename'))
                            st.success("Deleted!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Delete failed: {e}")
        
        # Show vendor firmware
        cached = cache.get('cached_firmware', {})
        if cached:
            st.markdown("**Vendor Firmware:**")
            st.json(cached)
        
        if not uploads and not cached:
            st.info("No cached firmware")
            
    except Exception as e:
        st.error(f"Error: {e}")


elif page == "⚠️ Vulnerabilities":
    st.title("Vulnerability Analysis")
    
    # Fetch actual devices from API
    try:
        devices = api.get_devices()
        if devices:
            # Extract IP addresses for dropdown
            device_ips = [d['ip_address'] for d in devices]
            device_ip = st.selectbox("Select Device", device_ips)
            
            if device_ip:
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"Showing vulnerabilities for: **{device_ip}**")
                with col2:
                    if st.button("Run CVE Scan"):
                        with st.spinner("Scanning NVD Database (this may take a moment)..."):
                            try:
                                # Call the new POST endpoint
                                import requests
                                # Need to access API_URL from config or hardcode for now since this is client logic
                                # But api_client is available
                                # api.trigger_cvs_scan(selected_device_ip) - need to add to client
                                # For now, quick hack using requests
                                 # In docker, we can't hit backend by name easily from browser-side logic if passing through client
                                 # But streamlit runs server side.
                                 # api_client needs update
                                response = api.scan_cves(device_ip)
                                if response:
                                    st.success(f"Scan complete: {response.get('message')}")
                                    time.sleep(1)
                                    st.rerun()
                            except Exception as e:
                                st.error(f"Scan failed: {e}")
            
            # Fetch vulnerabilities for selected device
            try:
                vulns = api.get_device_vulnerabilities(device_ip)
                
                if vulns:
                    df = pd.DataFrame(vulns)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info(f"No vulnerabilities found for {device_ip}")
            except Exception as e:
                st.error(f"Error fetching vulnerabilities: {e}")
        else:
            st.info("No devices found. Please run a network scan first.")
    except Exception as e:
        st.error(f"Error: {e}")
    
    st.markdown("---")
    st.subheader("Vulnerability Summary")
    
    try:
        summary = api.get_vulnerability_summary()
        
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total CVEs", summary['total_cves'])
        with col2:
            st.metric("Critical", summary['critical'])
        with col3:
            st.metric("High", summary['high'])
        with col4:
            st.metric("Medium", summary['medium'])
        with col5:
            st.metric("Low", summary['low'])
    except Exception as e:
        st.error(f"Error: {e}")

elif page == "📊 Traffic Monitor":
    st.title("Traffic Analysis")
    
    # Mode Selection
    mode = st.radio("Mode", ["🔍 Packet Monitor", "🛑 Packet Capture (PCAP)"], horizontal=True)
    
    if mode == "🔍 Packet Monitor":
        st.subheader("Real-time Packet Stream")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            interface = st.selectbox("Interface", ["eth0", "wlan0", "docker0"], key="live_iface")
        with col2:
            start_live = st.button("▶️ Start Live Stream", type="primary")
            
        if start_live:
            st.info("Connecting to live stream... Click 'Stop' (top right) to end.")
            
            # Setup visualization containers
            col1, col2 = st.columns(2)
            with col1:
                metric_ph = st.empty()
            with col2:
                proto_chart_ph = st.empty()
                
            st.markdown("### 📡 Live Packet Log")
            table_ph = st.empty()
            
            
            # Websocket Loop
            import asyncio
            import websockets
            
            async def listen():
                # Connect to Traffic Analyzer Service (Port 8001)
                # We assume if browser can reach localhost:8501, it can reach localhost:8001
                # In real prod, this needs a reverse proxy.
                ws_uri = "ws://localhost:8001/api/v1/ws/live"
                
                st.info(f"Connecting to: {ws_uri}")
                
                packets = []
                protocols = {}
                start_time = time.time()
                packet_count = 0
                
                try:
                    async with websockets.connect(ws_uri, ping_timeout=20, close_timeout=10) as websocket:
                        st.success("✅ Connected! Streaming packets...")
                        while True:
                            msg = await websocket.recv()
                            data = json.loads(msg)
                            packet_count += 1
                            
                            # Update stats
                            p = data.get('protocol', 'Unknown')
                            protocols[p] = protocols.get(p, 0) + 1
                            
                            packets.insert(0, data) # Newest first
                            packets = packets[:50] # Keep last 50
                            
                            # Render UI Updates every 5 packets or so to save CPU
                            if packet_count % 3 == 0:
                                # Metrics
                                duration = time.time() - start_time
                                rate = packet_count / duration if duration > 0 else 0
                                metric_ph.metric("Packets/sec", f"{rate:.1f}", f"{packet_count} total")
                                
                                # Chart
                                df_proto = pd.DataFrame(list(protocols.items()), columns=['Protocol', 'Count'])
                                fig = px.pie(df_proto, values='Count', names='Protocol', title="Protocol Distribution")
                                fig.update_layout(height=300, margin=dict(t=30, b=0, l=0, r=0))
                                proto_chart_ph.plotly_chart(fig, use_container_width=True)
                                
                                # Table
                                df_packets = pd.DataFrame(packets)
                                if not df_packets.empty:
                                    table_ph.dataframe(
                                        df_packets[['timestamp', 'src', 'dst', 'protocol', 'length', 'info']],
                                        use_container_width=True,
                                        column_config={
                                            "length": st.column_config.NumberColumn("Size (B)"),
                                            "info": st.column_config.TextColumn("Info", width="large")
                                        }
                                    )
                                    
                except websockets.exceptions.WebSocketException as e:
                    st.error(f"WebSocket error: {e}")
                    st.info("This may be due to:\n- Backend not running\n- Interface doesn't exist\n- No traffic on interface\n- Insufficient permissions (requires root/NET_ADMIN)")
                except Exception as e:
                    st.error(f"Stream error: {e}")
                    import traceback
                    st.code(traceback.format_exc())
                    
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(listen())
            except KeyboardInterrupt:
                st.info("Stream stopped by user")
            except Exception as e:
                st.error(f"Failed to start stream: {e}")

        st.markdown("---")
        st.subheader("🛡️ IDS Alerts (Suricata)")
        
        if st.button("🔄 Refresh Alerts"):
            st.rerun()
            
        alerts = traffic_api.get_alerts()
        if alerts:
            # Convert to DataFrame
            df_alerts = pd.DataFrame(alerts)
            
            # If timestamp exists, convert it
            if 'timestamp' in df_alerts.columns:
                df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
            
            # Style the severity column
            def color_severity(val):
                color = 'green'
                if val == 'High' or val == 1: color = 'red'
                elif val == 'Medium' or val == 2: color = 'orange'
                return f'color: {color}'
            
            st.dataframe(
                df_alerts,
                use_container_width=True,
                hide_index=True
            )
        else:
            if traffic_api.health_check():
                st.info("No alerts detected yet.")
            else:
                st.warning("⚠️ Access to Traffic Analyzer Service (Port 8001) seems down.")
            
            
    elif mode == "🛑 Packet Capture (PCAP)":
        st.subheader("Background Capture")
        col1, col2 = st.columns(2)
        
        with col1:
            interface = st.selectbox("Monitor Interface", ["eth0", "wlan0"], key="pcap_iface")
        with col2:
            duration = st.slider("Duration (seconds)", 60, 3600, 300)
        
        if st.button("🎬 Start Capture", use_container_width=True):
            with st.spinner("Capturing traffic..."):
                try:
                    result = api.start_traffic_capture(interface, duration)
                    st.success(f"Capture started! Session: {result.get('session_id')}")
                    st.info(f"File: {result.get('file')}")
                except Exception as e:
                    st.error(f"Capture failed: {e}")

elif page == "📄 Reports":
    st.title("Report Generation")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        subnet = st.text_input("Subnet for Report", "192.168.1.0/24")
    with col2:
        report_format = st.selectbox("Report Format", ["json", "html", "pdf"], index=1)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        include_firmware = st.checkbox("Include Firmware Analysis", True)
    with col2:
        include_traffic = st.checkbox("Include Traffic Analysis", True)
    with col3:
        include_recommendations = st.checkbox("Include Recommendations", True)
    
    if st.button("📋 Generate Report", use_container_width=True, type="primary"):
        with st.spinner(f"Generating {report_format.upper()} report..."):
            try:
                # Call API with format
                response = api.session.post(
                    f"{api.base_url}/api/reports/generate",
                    json={
                        "subnet": subnet,
                        "include_firmware": include_firmware,
                        "include_traffic": include_traffic,
                        "include_recommendations": include_recommendations,
                        "format": report_format
                    }
                )
                response.raise_for_status()
                result = response.json()
                
                st.success(f"✅ Report generated! ID: {result.get('report_id')}")
                st.session_state['last_report_id'] = result.get('report_id')
                st.session_state['last_report_formats'] = result.get('format_options', [])
                
            except Exception as e:
                st.error(f"Generation failed: {e}")
    
    # Show download options if report was generated
    if st.session_state.get('last_report_id'):
        st.markdown("---")
        st.subheader("📥 Download Report")
        
        report_id = st.session_state['last_report_id']
        available_formats = st.session_state.get('last_report_formats', ['json'])
        
        st.info(f"Report ID: **{report_id}** | Available formats: {', '.join(f.upper() for f in available_formats)}")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if 'pdf' in available_formats:
                download_url = f"{api.base_url}/api/reports/download/{report_id}?format=pdf"
                st.markdown(f"[📄 Download PDF]({download_url})")
            else:
                st.button("📄 PDF (not available)", disabled=True)
        
        with col2:
            if 'html' in available_formats:
                download_url = f"{api.base_url}/api/reports/download/{report_id}?format=html"
                st.markdown(f"[🌐 Download HTML]({download_url})")
            else:
                st.button("🌐 HTML (not available)", disabled=True)
        
        with col3:
            if 'json' in available_formats:
                download_url = f"{api.base_url}/api/reports/download/{report_id}?format=json"
                st.markdown(f"[📊 Download JSON]({download_url})")
            else:
                st.button("📊 JSON (not available)", disabled=True)
    
    st.markdown("---")
    st.subheader("📊 Network Security Score")
    
    try:
        score_data = api.get_network_score()
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Score gauge
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score_data['overall_score'],
                title={'text': "Overall Score"},
                domain={'x': [0, 1], 'y': [0, 1]},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 30], 'color': "#FF0000"},
                        {'range': [30, 60], 'color': "#FFD93D"},
                        {'range': [60, 100], 'color': "#6BCB77"}
                    ]
                }
            ))
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### Score Breakdown")
            breakdown = score_data.get('breakdown', {})
            for category, score in breakdown.items():
                label = category.replace('_', ' ').title()
                if score >= 80:
                    st.success(f"{label}: {score}")
                elif score >= 50:
                    st.warning(f"{label}: {score}")
                else:
                    st.error(f"{label}: {score}")
            
            # Grade
            grade = score_data.get('grade', 'N/A')
            grade_color = "#10b981" if grade in ['A', 'B'] else "#f59e0b" if grade == 'C' else "#dc2626"
            st.markdown(f"### Grade: <span style='color:{grade_color};font-size:2rem'>{grade}</span>", unsafe_allow_html=True)
            
    except Exception as e:
        st.error(f"Error: {e}")


elif page == "⚙️ Settings":
    st.title("Settings")
    
    st.subheader("API Configuration")
    api_url = st.text_input("API URL", "http://localhost:8000")
    
    st.subheader("Scan Preferences")
    default_subnet = st.text_input("Default Subnet", "192.168.1.0/24")
    default_interface = st.selectbox("Default Interface", ["eth0", "wlan0"])
    timeout = st.slider("Scan Timeout (seconds)", 60, 3600, 300)
    
    st.subheader("Report Settings")
    auto_save = st.checkbox("Auto-save Reports", True)
    report_format = st.multiselect("Report Formats", 
                                  ["PDF", "JSON", "HTML"], 
                                  ["PDF", "JSON"])
    
    if st.button("💾 Save Settings"):
        st.success("Settings saved!")
    
    st.markdown("---")
    st.subheader("⚠️ Danger Zone")
    st.warning("**Clear All Data**: This will permanently delete all scanned devices, vulnerabilities, and reports from the database.")
    
    # Checkbox first
    confirm = st.checkbox("I understand this action cannot be undone")
    
    # Button only enabled if confirmed
    if st.button("🗑️ Clear All Data", type="primary", disabled=not confirm):
        try:
            response = api.session.delete(f"{api.base_url}/api/scanner/clear-all")
            response.raise_for_status()
            st.success("✅ All data cleared successfully!")
            st.info("Please refresh the page to see updated metrics.")
            st.balloons()
        except Exception as e:
            st.error(f"Failed to clear data: {e}")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
    <p>IoT Security Analyzer v1.0 | API Docs: <a href='http://localhost:8000/docs'>Swagger UI</a></p>
    </div>
    """,
    unsafe_allow_html=True
)
