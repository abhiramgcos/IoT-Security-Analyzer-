# Enterprise IoT Security Platform - Quick Start

## 🚀 Phase 1 Status: Packet Capture Fix

### What Was Changed
1. ✅ Added `CAP_NET_ADMIN` and `CAP_NET_RAW` to traffic analyzer container
2. ✅ Configured interface to `wlp0s20f3` (your active Wi-Fi)
3. ✅ Updated sniffer to broadcast packets to frontend WebSocket
4. ✅ Set `privileged: true` for full network access

### Next Steps (YOU MUST DO THIS)

#### Step 1: Restart Services
```bash
cd /var/home/cos777nnn/code/firmai_v3/iot_security_analyzer
docker compose down
docker compose up -d
```

#### Step 2: Verify Packet Capture
```bash
./verify_packet_capture.sh
```

Expected output: `✅ SUCCESS: Packet capture is working!`

#### Step 3: Test in Dashboard
1. Open: http://localhost:8501
2. Navigate to: **📊 Traffic Monitor**
3. Interface: `wlan0` (or dropdown selection)
4. Click: **▶️ Start Live Stream**
5. **Generate traffic**: Open new tab, visit `http://example.com`
6. Result: You should see packets in the table!

---

## 🔧 Troubleshooting

### Problem: "No packets showing"
**Solution**:
```bash
# Check if container has proper capabilities
docker inspect iot-traffic-analyzer | grep -A 5 "CapAdd"

# Should show: ["NET_ADMIN","NET_RAW"]
```

### Problem: "Permission denied" in logs
**Solution**:
```bash
# Ensure you ran 'docker compose up -d' AFTER editing docker-compose.yml
docker compose down
docker compose up -d --force-recreate
```

### Problem: "Interface wlp0s20f3 not found"
**Solution**:
```bash
# Check your active interface
ip link | grep "state UP"

# Update docker-compose.yml line 74 with YOUR interface
# Then restart: docker compose up -d
```

---

## 📊 Platform Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER BROWSER                          │
│              http://localhost:8501                       │
└──────────────────┬──────────────────────────────────────┘
                   │
          ┌────────▼─────────┐
          │  STREAMLIT UI    │ :8501
          │  (Frontend)      │
          └────────┬─────────┘
                   │
        ┌──────────┴───────────┐
        │                      │
    ┌───▼────┐         ┌──────▼───────┐
    │ Main   │ :8000   │   Traffic    │ :8001
    │Backend │         │  Analyzer    │
    └───┬────┘         └──────┬───────┘
        │                     │
        │              ┌──────▼───────┐
        │              │  Suricata    │
        │              │   (IDS)      │
        │              └──────────────┘
        │
    ┌───▼──────────┐
    │  Database    │
    │  (SQLite)    │
    └──────────────┘
```

---

## 🎯 Current Features

### ✅ Working
- Device scanning (nmap)
- CVE vulnerability detection
- Dashboard UI
- Traffic analyzer backend
- Suricata IDS integration

### ⚠️ In Progress (Phase 1)
- **Packet capture** (testing required)
- WebSocket live stream
- IDS alerts display

### 📋 Planned (Phases 2-7)
- Firmware analysis pipeline
- PDF report generation
- Trust certificate generation
- Enhanced ML anomaly detection
- PostgreSQL migration
- Multi-user authentication

---

## 📁 Project Structure

```
iot_security_analyzer/
├── backend/              # Main API (port 8000)
│   ├── services/         # Scanner, firmware, vulnerabilities
│   └── routes/           # REST API endpoints
├── frontend/             # Streamlit dashboard (port 8501)
│   └── streamlit_app.py  # Main UI
├── traffic_analyzer/     # Submodule (port 8001)
│   ├── src/ingestion/    # Packet sniffer (Scapy)
│   ├── src/ai/          # ML anomaly detection
│   └── src/api/         # WebSocket + alerts
├── docker-compose.yml    # Service orchestration
└── verify_packet_capture.sh  # Diagnostic script
```

---

## 🔐 Security Notes

### Why `privileged: true`?
Packet capture requires raw socket access, which is a privileged operation in Linux. The container needs:
- `CAP_NET_ADMIN`: Configure network interfaces
- `CAP_NET_RAW`: Create raw sockets for sniffing
- `network_mode: host`: See host's network interfaces

### Is this safe?
**For development**: Yes
**For production**: Consider alternatives:
- Run sniffer as separate service with minimal privileges
- Use eBPF for packet capture (more secure)
- Deploy in isolated network segment

---

## 🆘 Getting Help

1. **Check logs**:
   ```bash
   docker logs iot-traffic-analyzer -f
   ```

2. **Restart everything**:
   ```bash
   docker compose down
   docker compose up -d --build
   ```

3. **If still broken**, run:
   ```bash
   ./verify_packet_capture.sh > capture_test.log 2>&1
   # Send capture_test.log for diagnosis
   ```

---

**Next**: Once packet capture is verified, we'll proceed to Phase 2 (Firmware Analysis Pipeline)
