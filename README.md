# IoT Security Analyzer 🔐

A comprehensive security analysis platform for IoT devices featuring network scanning, firmware analysis, vulnerability detection, and traffic monitoring.

## 🚀 Features

- **Network Discovery**: Automated scanning using Nmap to discover IoT devices on your network
- **Firmware Analysis**: Extract and analyze firmware images using Binwalk for security insights
- **CVE Scanning**: Real-time vulnerability lookup via NVD API
- **Traffic Analysis**: Network packet capture and analysis using tcpdump
- **Security Reporting**: Automated report generation with security scores and recommendations
- **Interactive Dashboard**: Modern Streamlit-based web interface for visualization

## 🏗️ Architecture

- **Backend**: FastAPI REST API with SQLite database
- **Frontend**: Streamlit interactive dashboard
- **Services**: Modular security analysis services
- **Deployment**: Docker Compose for easy orchestration

## 📋 Prerequisites

- Docker & Docker Compose
- 2GB+ RAM
- Network access for scanning

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/abhiramgcos/IoT-Security-Analyzer-.git
   cd IoT-Security-Analyzer-
   ```

2. **Configure environment variables**
   ```bash
   # .env file is already included with defaults
   # Optional: Add your NVD API key for enhanced CVE scanning
   # Get one free at: https://nvd.nist.gov/developers/request-an-api-key
   ```

3. **Build and start the containers**
   ```bash
   docker compose build
   docker compose up -d
   ```

4. **Access the application**
   - Frontend Dashboard: http://localhost:8501
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

## 🎯 Usage

### Network Scanning
1. Navigate to **Network Scan** page
2. Specify target subnet (default: `192.168.1.0/24`)
3. Click **Start Scan**
4. View discovered devices in the table

### Firmware Analysis
1. Go to **Firmware Analysis** page
2. Enter manufacturer and model
3. Click **Fetch Firmware**
4. Review analysis results (file system, architecture, secrets)

### Vulnerability Assessment
1. Visit **Vulnerabilities** page
2. Select a device from the dropdown
3. View CVE details with CVSS scores
4. Check network-wide vulnerability summary

### Traffic Monitoring
1. Access **Traffic Monitor** page
2. Select network interface
3. Set capture duration
4. Click **Start Capture**
5. Analyze protocol distribution and anomalies

### Report Generation
1. Navigate to **Reports** page
2. Configure report options
3. Click **Generate Report**
4. Download in JSON format
5. View network security score

## 🗑️ Data Management

To clear all scan data and start fresh:
1. Go to **Settings** page
2. Scroll to **Danger Zone**
3. Check the confirmation box
4. Click **Clear All Data**

## 🔧 Configuration

### Environment Variables (`.env`)

```bash
# Network Scanning
SCAN_SUBNET=192.168.1.0/24
SCAN_INTERFACE=eth0
SCAN_TIMEOUT=300

# Database
DB_PATH=./data/devices.db

# Storage Paths
FIRMWARE_CACHE_DIR=./data/firmware
REPORT_DIR=./data/reports
PCAP_DIR=./data/pcaps
LOG_DIR=./logs

# External APIs
NVD_API_KEY=          # Optional: Enhances CVE scanning

# Logging
LOG_LEVEL=INFO
```

### Docker Compose Ports

- Backend: `8000`
- Frontend: `8501`

To change ports, edit `docker-compose.yml`.

## 📁 Project Structure

```
iot_security_analyzer/
├── backend/
│   ├── config.py              # Application configuration
│   ├── database.py            # SQLite database operations
│   ├── logger.py              # Logging utilities
│   ├── main.py                # FastAPI application
│   ├── routes/                # API endpoints
│   │   ├── scanner.py
│   │   ├── firmware.py
│   │   ├── vulnerabilities.py
│   │   ├── traffic.py
│   │   └── reports.py
│   └── services/              # Business logic
│       ├── network_discovery.py
│       ├── firmware_fetcher.py
│       ├── firmware_analyzer.py
│       ├── cve_scanner.py
│       ├── traffic_analyzer.py
│       └── report_generator.py
├── frontend/
│   ├── streamlit_app.py       # Main Streamlit application
│   └── utils/
│       └── api_client.py      # Backend API client
├── data/                      # Application data (gitignored)
├── logs/                      # Application logs (gitignored)
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.streamlit
├── requirements.txt
└── .env
```

## 🛠️ Development

### Running Locally (without Docker)

1. **Backend**
   ```bash
   pip install -r requirements.txt
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Frontend**
   ```bash
   streamlit run frontend/streamlit_app.py --server.port 8501
   ```

### Viewing Logs

```bash
# All logs
docker compose logs -f

# Backend only
docker compose logs -f backend

# Frontend only
docker compose logs -f frontend

# Application log file
tail -f logs/app.log
```

### Restarting Services

```bash
# Restart all
docker compose restart

# Restart specific service
docker compose restart backend
docker compose restart frontend
```

## 📊 API Endpoints

Full API documentation available at: http://localhost:8000/docs

### Key Endpoints:
- `POST /api/scanner/start` - Start network scan
- `GET /api/scanner/devices` - List discovered devices
- `DELETE /api/scanner/clear-all` - Clear all data
- `POST /api/firmware/fetch` - Download firmware
- `GET /api/vulnerabilities/summary` - Vulnerability statistics
- `GET /api/reports/score` - Network security score

## 🔒 Security Considerations

- **Network Scanning**: Requires appropriate permissions on target networks
- **Root Access**: Traffic capture may require elevated privileges
- **API Keys**: Keep your NVD API key secure in `.env` (not committed to git)
- **Production Use**: Update CORS settings in `backend/main.py` for production

## 🐛 Troubleshooting

### Backend 500 Error
```bash
# Check logs
docker compose logs backend

# Verify database
ls -lh data/devices.db

# Restart backend
docker compose restart backend
```

### Empty Dashboard After Scan
- Ensure backend is running: http://localhost:8000/health
- Check browser console for errors
- Verify API connectivity in Settings

### Permission Denied Errors
```bash
# Fix data directory permissions
chmod -R 755 data/ logs/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Abhiram G**
- GitHub: [@abhiramgcos](https://github.com/abhiramgcos)

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Streamlit](https://streamlit.io/) - Interactive data apps
- [Nmap](https://nmap.org/) - Network discovery
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis
- [NVD](https://nvd.nist.gov/) - Vulnerability database

## 📞 Support

For issues and questions, please open an issue on GitHub:
https://github.com/abhiramgcos/IoT-Security-Analyzer-/issues

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning networks or analyzing devices you don't own.
