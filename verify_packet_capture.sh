#!/bin/bash
# Packet Capture Verification Script
# Run this after: docker compose up -d

echo "===== IoT Security Platform - Packet Capture Verification ====="
echo ""

# Check if container is running
echo "1. Checking if traffic-analyzer container is running..."
docker ps --filter "name=iot-traffic-analyzer" --format "table {{.Names}}\t{{.Status}}"
echo ""

# Check capabilities
echo "2. Verifying NET_ADMIN and NET_RAW capabilities..."
docker inspect iot-traffic-analyzer --format='Capabilities: {{.HostConfig.CapAdd}}'
docker inspect iot-traffic-analyzer --format='Privileged: {{.HostConfig.Privileged}}'
echo ""

# Check network interface
echo "3. Checking configured network interface..."
docker exec iot-traffic-analyzer env | grep SNIFF_INTERFACE
echo ""

# Test packet capture with tcpdump
echo "4. Testing packet capture (10 packets)..."
echo "   This should show live network traffic..."
docker exec iot-traffic-analyzer timeout 5 tcpdump -i wlp0s20f3 -c 10 2>&1
TCPDUMP_EXIT=$?

echo ""
if [ $TCPDUMP_EXIT -eq 124 ] || [ $TCPDUMP_EXIT -eq 0 ]; then
    echo "✅ SUCCESS: Packet capture is working!"
    echo ""
    echo "5. Checking if sniffer is broadcasting to WebSocket..."
    docker logs iot-traffic-analyzer --tail 20 | grep -E "(Sniffer|packet|Anomaly)" || echo "   No sniffer logs yet (may need traffic)"
else
    echo "❌ FAILED: Packet capture not working"
    echo "   Exit code: $TCPDUMP_EXIT"
    echo "   Common issues:"
    echo "   - Interface 'wlp0s20f3' doesn't exist"
    echo "   - Insufficient permissions (need to run: docker compose up -d)"
    echo "   - Container not started with new docker-compose.yml"
fi

echo ""
echo "6. Testing WebSocket connection..."
echo "   Open http://localhost:8501 and go to 'Traffic Monitor'"
echo "   Click 'Start Live Stream' - you should see packets!"
echo ""
echo "===== Verification Complete ====="
