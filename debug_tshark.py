#!/usr/bin/env python3
"""
Debug utility to test TShark permissions and interface availability
"""
import subprocess
import sys
import os

def check_tshark():
    """Check if tshark is installed"""
    try:
        result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ TShark found at: {result.stdout.strip()}")
            return True
        else:
            print("❌ TShark not found in PATH")
            return False
    except Exception as e:
        print(f"❌ Error checking TShark: {e}")
        return False

def check_permissions():
    """Check if running as root or has CAP_NET_ADMIN"""
    uid = os.getuid()
    if uid == 0:
        print("✅ Running as root")
        return True
    else:
        print(f"⚠️  Running as UID {uid} (not root)")
        print("   TShark may require root or CAP_NET_ADMIN capability")
        return False

def list_interfaces():
    """List available network interfaces"""
    try:
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("\n✅ Available interfaces:")
            print(result.stdout)
            return True
        else:
            print(f"\n❌ Failed to list interfaces:")
            print(f"   stdout: {result.stdout}")
            print(f"   stderr: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Timeout listing interfaces")
        return False
    except Exception as e:
        print(f"❌ Error listing interfaces: {e}")
        return False

def test_capture(interface='wlan0'):
    """Test capturing a few packets"""
    print(f"\n🔍 Testing packet capture on {interface}...")
    cmd = [
        'tshark',
        '-i', interface,
        '-c', '3',  # Capture only 3 packets
        '-n',
        '-T', 'ek',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', '_ws.col.Protocol',
    ]
    
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Capture succeeded!")
            print(f"Output (first 500 chars):\n{result.stdout[:500]}")
            return True
        else:
            print(f"❌ Capture failed with return code {result.returncode}")
            print(f"stderr: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Capture timeout (no packets received in 10s)")
        return False
    except Exception as e:
        print(f"❌ Error during capture: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("TShark Diagnostic Utility")
    print("=" * 60)
    
    tshark_ok = check_tshark()
    perms_ok = check_permissions()
    
    if not tshark_ok:
        print("\n⚠️  TShark is not installed. Install with:")
        print("   apt-get install tshark  (Debian/Ubuntu)")
        print("   yum install wireshark     (RHEL/CentOS)")
        sys.exit(1)
    
    interfaces_ok = list_interfaces()
    
    if interfaces_ok:
        # Try to capture on the first available interface
        interface = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
        test_capture(interface)
    
    print("\n" + "=" * 60)
    if not perms_ok:
        print("⚠️  RECOMMENDATION: Run with elevated privileges")
        print("   docker run --cap-add=NET_ADMIN ...")
        print("   OR run backend as root in container")
