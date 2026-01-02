# Professional SOC IoT Security Platform

**Enterprise-grade security platform for SOC analysts to monitor, analyze, and secure IoT networks.**

## 🎯 Features

✅ **Real-time Traffic Monitoring** - Capture and analyze network traffic on any interface  
✅ **Intrusion Detection** - Suricata IDS with custom rule management  
✅ **Automated Device Discovery** - Passive & active IoT device fingerprinting  
✅ **Firmware Analysis** - Automated extraction, emulation, and vulnerability detection  
✅ **Advanced UI** - Professional dashboard with real-time updates  
✅ **Professional Reporting** - PDF reports with compliance mapping  

---

## 🏗️ Architecture

```
┌─────────────┐
│   UI (3000) │  React Dashboard
└──────┬──────┘
       │
┌──────▼──────────┐
│ API Gateway     │ :8000
│ (FastAPI)       │
└─────┬───────────┘
      │
      ├─► PostgreSQL + TimescaleDB :5432
      ├─► Redis Cache :6379
      ├─► Elasticsearch :9200
      │
┌─────┴────────────────────────────┐
│                                  │
▼                                  ▼
Traffic Gateway              Device Scanner
(Packet Capture)            (nmap/Passive)
      │                            │
      ▼                            ▼
  Suricata IDS            Firmware Analyzer
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Docker & Docker Compose
- Linux host (for packet capture capabilities)
- 8GB RAM minimum
- NVD API Key (optional, for CVE data)

### 2. Setup

```bash
cd soc_platform

# Copy environment template
cp .env.example .env

# Edit .env and set:
# - POSTGRES_PASSWORD
# - NVD_API_KEY (get from https://nvd.nist.gov/)
# - MONITOR_INTERFACE (your network interface: wlp0s20f3, eth0, etc.)

# Start infrastructure services first
docker compose up -d postgres redis elasticsearch

# Wait for databases to be ready (30 seconds)
sleep 30

# Start all services
docker compose up -d
```

### 3. Access

- **API Gateway**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **UI Dashboard**: http://localhost:3000 (coming soon)
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **Elasticsearch**: http://localhost:9200

---

## 📋 Services

| Service | Port | Description |
|---------|------|-------------|
| `api-gateway` | 8000 | Unified REST API + WebSocket |
| `postgres` | 5432 | TimescaleDB for time-series data |
| `redis` | 6379 | Caching + message queue |
| `elasticsearch` | 9200 | PCAP indexing |
| `traffic-gateway` | - | Packet capture (host network) |
| `suricata` | - | IDS/IPS engine |
| `device-scanner` | - | Device discovery |
| `firmware-analyzer` | - | Firmware analysis pipeline |
| `ui-dashboard` | 3000 | React frontend |

---

## 🔧 Configuration

### Network Interface Detection

By default, the platform auto-detects your active network interface. To manually specify:

```bash
# In .env file
MONITOR_INTERFACE=wlp0s20f3  # Your Wi-Fi interface
# or
MONITOR_INTERFACE=eth0  # Your Ethernet interface
```

To find your interface:
```bash
ip link show
```

### Gateway Mode (Optional)

To enable transparent proxy mode (intercept all traffic):

```bash
# In .env
TRAFFIC_MODE=gateway
ENABLE_GATEWAY_MODE=true
```

Then configure your network to route through the container.

---

## 📊 Database Schema

- **devices** - Discovered IoT devices
- **flows** - Network traffic (TimescaleDB hypertable)
- **alerts** - Suricata IDS alerts
- **firmware** - Uploaded/fetched firmware
- **firmware_vulnerabilities** - CVE mappings
- **firmware_secrets** - Hardcoded credentials

See `scripts/init-db.sql` for full schema.

---

## 🛠️ Development

### Build individual service
```bash
docker compose build api-gateway
docker compose up -d api-gateway
```

### View logs
```bash
docker compose logs -f api-gateway
docker compose logs -f traffic-gateway
```

### Access database
```bash
docker exec -it soc-postgres psql -U socuser -d iot_soc
```

---

## 📖 API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Example API Calls

```bash
# Get system info
curl http://localhost:8000/info

# List devices
curl http://localhost:8000/api/v1/devices

# Get alerts
curl http://localhost:8000/api/v1/alerts

# WebSocket (live updates)
wscat -c ws://localhost:8000/ws/live
```

---

## 🔐 Security

### Production Checklist

- [ ] Change `POSTGRES_PASSWORD` in `.env`
- [ ] Change `JWT_SECRET` in `.env`
- [ ] Enable firewall rules
- [ ] Configure HTTPS/TLS
- [ ] Set up authentication
- [ ] Review Suricata rules
- [ ] Enable audit logging

---

## 🎓 Next Steps

1. ✅ **Phase 1 Complete** - Infrastructure setup
2. ⏳ **Phase 2** - Implement traffic capture logic
3. ⏳ **Phase 3** - Build device scanner
4. ⏳ **Phase 4** - Firmware analysis pipeline
5. ⏳ **Phase 5** - React UI development

---

## 📝 License

MIT License - See LICENSE file

---

## 🆘 Troubleshooting

### Services won't start
```bash
# Check logs
docker compose logs

# Restart specific service
docker compose restart api-gateway
```

### No packets captured
```bash
# Verify interface
ip link show

# Check permissions
docker exec soc-traffic-gateway ip link show

# Verify capabilities
docker inspect soc-traffic-gateway | grep -A 10 CapAdd
```

### Database connection failed
```bash
# Check PostgreSQL logs
docker logs soc-postgres

# Verify it's running
docker ps | grep postgres

# Test connection
docker exec soc-postgres pg_isready -U socuser
```

---

**Built for SOC Analysts, by Security Professionals** 🛡️
