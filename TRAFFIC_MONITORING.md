# Real-time Traffic Analysis - Setup & Troubleshooting

## Overview
The real-time packet monitoring feature uses TShark to capture and stream network packets via WebSocket.

## Requirements

### 1. TShark Installation
- ✅ Already included in Docker image (`tshark` package)

### 2. Network Permissions
The backend needs **elevated privileges** to capture network traffic. Choose one option:

#### Option A: Add NET_ADMIN capability (RECOMMENDED)
Edit `docker-compose.yml`:
```yaml
backend:
  cap_add:
    - NET_ADMIN
```

#### Option B: Run as root
Edit `docker-compose.yml`:
```yaml
backend:
  user: root
```

#### Option C: Configure TShark non-root (in container)
```bash
# Inside the container:
dpkg-reconfigure wireshark-common  # Select "Yes"
usermod -a -G wireshark $(whoami)
```

### 3. Host Network Mode (for laptop WiFi)
To capture traffic from your laptop's WiFi interface (`wlan0`), use host network mode:

Edit `docker-compose.yml`:
```yaml
backend:
  network_mode: "host"
  cap_add:
    - NET_ADMIN
```

**Note**: Host network mode makes the container use the host's network stack directly.

## Testing

### 1. Check TShark
Run the diagnostic script:
```bash
python3 debug_tshark.py wlan0
```

### 2. Test WebSocket
```bash
python3 test_websocket.py
```

### 3. Check Logs
```bash
docker-compose logs -f backend | grep traffic
```

## Common Issues

### "no close frame received or sent"
**Cause**: TShark process fails to start or exits immediately.

**Solutions**:
1. Check permissions (see above)
2. Verify interface exists: `tshark -D`
3. Check backend logs for TShark error messages
4. Try host network mode if capturing WiFi

### "Interface doesn't exist"
- Use `tshark -D` to list available interfaces
- WiFi interfaces are often named: `wlan0`, `wlp2s0`, `en0` (macOS)
- In Docker without host mode, only container interfaces are visible (no `wlan0`)

### No packets appearing
- Generate traffic: `ping 8.8.8.8` in another terminal
- Check if interface has traffic: `tshark -i wlan0 -c 5`
- Firewall might be blocking

## Architecture
```
Frontend (Streamlit) 
    ↓ WebSocket
Backend (FastAPI)
    ↓ spawn
TShark process
    ↓ captures
Network Interface (wlan0)
```
