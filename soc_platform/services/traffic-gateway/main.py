import asyncio
import logging
import os
import signal
import sys
import json
from datetime import datetime
import netifaces
from scapy.all import sniff, IP, TCP, UDP, Ether, PcapWriter
import websockets
import aiohttp
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("traffic-gateway")

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000")
WS_URL = os.getenv("WS_URL", "ws://localhost:8000/ws/live")
INTERFACE = os.getenv("INTERFACE", "auto")
MODE = os.getenv("MODE", "monitor")

class TrafficSniffer:
    def __init__(self):
        self.interface = self._detect_interface()
        self.running = False
        self.packet_queue = asyncio.Queue()
        self.websocket = None
        
        # PCAP Writer
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_file = f"/pcaps/capture_{timestamp}.pcap"
        self.pcap_writer = PcapWriter(self.pcap_file, append=True, sync=True)
        logger.info(f"Saving PCAP to {self.pcap_file}")
        
    def _detect_interface(self):
        """Auto-detect the best network interface"""
        if INTERFACE != "auto":
            return INTERFACE
            
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
        
        if default_gateway:
            iface = default_gateway[1]
            logger.info(f"Auto-detected default interface: {iface}")
            return iface
            
        # Fallback to first non-loopback
        for iface in netifaces.interfaces():
            if iface != 'lo':
                logger.warning(f"Using fallback interface: {iface}")
                return iface
                
        return "eth0"

    def _process_packet(self, packet):
        """Callback for Scapy sniff (runs in thread)"""
        try:
            # Write to PCAP immediately
            self.pcap_writer.write(packet)
            
            if not packet.haslayer(IP):
                return

            packet_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "length": len(packet),
                "protocol": packet[IP].proto,
                "summary": packet.summary()
            }
            
            if packet.haslayer(TCP):
                packet_data["src_port"] = packet[TCP].sport
                packet_data["dst_port"] = packet[TCP].dport
                packet_data["protocol_name"] = "TCP"
            elif packet.haslayer(UDP):
                packet_data["src_port"] = packet[UDP].sport
                packet_data["dst_port"] = packet[UDP].dport
                packet_data["protocol_name"] = "UDP"
            else:
                packet_data["protocol_name"] = str(packet[IP].proto)

            # Put into thread-safe queue for async loop
            try:
                self.loop.call_soon_threadsafe(self.packet_queue.put_nowait, packet_data)
            except RuntimeError:
                pass # Loop might be closed
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    async def _stream_packets(self):
        """Consume queue and send to WebSocket"""
        while self.running:
            try:
                # connect if not connected
                if not self.websocket:
                    await self._connect_ws()
                    if not self.websocket:
                        # still failed, wait and retry
                        await asyncio.sleep(5)
                        continue

                # Batch packets slightly for performance
                batch = []
                try:
                    # Wait for first packet
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                    batch.append(packet)
                    
                    # Drain rest of queue up to limit
                    for _ in range(50):
                        batch.append(self.packet_queue.get_nowait())
                except asyncio.QueueEmpty:
                    pass
                except asyncio.TimeoutError:
                    continue

                if batch and self.websocket:
                    msg = {
                        "type": "traffic_batch",
                        "data": batch
                    }
                    await self.websocket.send(json.dumps(msg))
                    
            except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError):
                logger.warning("WebSocket closed or refused, reconnecting...")
                self.websocket = None
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"Streaming error: {e}")
                await asyncio.sleep(1)

    async def _connect_ws(self):
        """Connect to API Gateway WebSocket"""
        try:
            logger.info(f"Connecting to WebSocket: {WS_URL}")
            self.websocket = await websockets.connect(WS_URL)
            logger.info("WebSocket connected!")
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            self.websocket = None

    async def start(self):
        self.running = True
        self.loop = asyncio.get_running_loop()
        
        # Connect WS
        await self._connect_ws()
        
        # Start streamer task
        streamer = asyncio.create_task(self._stream_packets())
        
        # Start Sniffer in separate thread (Scapy is blocking)
        logger.info(f"Starting capture on {self.interface}...")
        try:
            # Run sniff in executor to avoid blocking async loop
            await self.loop.run_in_executor(
                None, 
                lambda: sniff(
                    iface=self.interface, 
                    prn=self._process_packet, 
                    store=False,
                    filter="not port 22" # Avoid loop if SSHing
                )
            )
        except Exception as e:
            logger.error(f"Sniffer failed: {e}")
        finally:
            self.running = False
            streamer.cancel()

def handle_sigterm(*args):
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sigterm)
    
    sniffer = TrafficSniffer()
    try:
        asyncio.run(sniffer.start())
    except KeyboardInterrupt:
        pass
