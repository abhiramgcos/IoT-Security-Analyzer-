import React, { useState, useEffect, useRef } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Activity, Shield, Wifi, Server, Bell, Menu, Cpu, Lock, Terminal, Radio } from 'lucide-react';

// Configuration
const WS_URL = "ws://localhost:8000/ws/live";
const API_URL = "http://localhost:8000";

function App() {
    const [stats, setStats] = useState({
        packetRate: 0,
        activeDevices: 0,
        alerts: 0,
        bytesPerSec: 0
    });

    const [trafficData, setTrafficData] = useState([]);
    const [devices, setDevices] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [isConnected, setIsConnected] = useState(false);

    const ws = useRef(null);

    // Initial Data Fetch
    useEffect(() => {
        fetch(`${API_URL}/api/v1/devices`)
            .then(res => res.json())
            .then(data => setDevices(data))
            .catch(err => console.error("Failed to fetch devices:", err));
    }, []);

    // WebSocket Connection
    useEffect(() => {
        const connect = () => {
            ws.current = new WebSocket(WS_URL);

            ws.current.onopen = () => {
                console.log("Connected to WebSocket");
                setIsConnected(true);
            };

            ws.current.onclose = () => {
                console.log("WebSocket Disconnected");
                setIsConnected(false);
                setTimeout(connect, 3000);
            };

            ws.current.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);

                    if (msg.type === "traffic_batch") {
                        handleTrafficBatch(msg.data);
                    } else if (msg.type === "device_discovered") {
                        handleDeviceDiscovered(msg.data);
                    }
                } catch (e) {
                    console.error("Parse error:", e);
                }
            };
        };

        connect();

        return () => {
            if (ws.current) ws.current.close();
        };
    }, []);

    const handleTrafficBatch = (packets) => {
        // Calculate stats from batch
        const now = new Date();
        const timeStr = now.toLocaleTimeString();
        const packetCount = packets.length;
        const totalBytes = packets.reduce((acc, p) => acc + (p.length || 0), 0);

        // Update Chart Data
        setTrafficData(prev => {
            const newData = [...prev, { time: timeStr, pps: packetCount, bps: totalBytes }];
            if (newData.length > 30) return newData.slice(newData.length - 30);
            return newData;
        });

        // Update Stats
        setStats(prev => ({
            ...prev,
            packetRate: packetCount, // This is roughly per batch update, not true per sec unless batch interval is 1s
            bytesPerSec: totalBytes
        }));
    };

    const handleDeviceDiscovered = (device) => {
        setDevices(prev => {
            // De-duplicate
            const existing = prev.find(d => d.mac_address === device.mac);
            if (existing) return prev;
            return [...prev, {
                ip_address: device.ip,
                mac_address: device.mac,
                manufacturer: device.vendor,
                hostname: device.hostname,
                status: 'active',
                last_seen: new Date().toISOString()
            }];
        });
        setStats(prev => ({ ...prev, activeDevices: prev.activeDevices + 1 }));
    };

    return (
        <div className="flex h-screen bg-gray-950 text-white font-sans overflow-hidden">
            {/* Sidebar */}
            <aside className="w-64 border-r border-gray-800 bg-gray-900/50 hidden md:flex flex-col">
                <div className="p-6 border-b border-gray-800 flex items-center gap-3">
                    <Shield className="w-8 h-8 text-blue-500" />
                    <div>
                        <h1 className="font-bold text-lg tracking-tight">SOC Platform</h1>
                        <p className="text-xs text-gray-400">IoT Security Analzyer</p>
                    </div>
                </div>

                <nav className="flex-1 p-4 space-y-2">
                    <NavItem icon={<Activity />} label="Dashboard" active />
                    <NavItem icon={<Wifi />} label="Devices" />
                    <NavItem icon={<Terminal />} label="Traffic" />
                    <NavItem icon={<Bell />} label="Alerts" badge={stats.alerts > 0 ? stats.alerts : null} />
                    <NavItem icon={<Lock />} label="Firmware" />
                </nav>

                <div className="p-4 border-t border-gray-800">
                    <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-gray-800/50">
                        <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                        <span className="text-sm font-medium text-gray-300">
                            {isConnected ? 'System Online' : 'Connecting...'}
                        </span>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col overflow-hidden">
                {/* Header */}
                <header className="h-16 border-b border-gray-800 bg-gray-900/30 flex items-center justify-between px-6 backdrop-blur-sm">
                    <div className="flex items-center gap-4">
                        <button className="md:hidden text-gray-400 hover:text-white">
                            <Menu className="w-6 h-6" />
                        </button>
                        <h2 className="text-xl font-semibold">Security Dashboard</h2>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-full text-xs font-mono">
                            MODE: MONITOR
                        </div>
                        <Cpu className="w-5 h-5 text-gray-400" />
                    </div>
                </header>

                {/* Dashboard Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6">

                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <StatCard
                            label="Traffic Rate"
                            value={`${stats.packetRate} pps`}
                            subtext={`${(stats.bytesPerSec / 1024).toFixed(1)} KB/s`}
                            icon={<Activity className="text-blue-500" />}
                            chart={trafficData}
                            dataKey="pps"
                            color="#3b82f6"
                        />
                        <StatCard
                            label="Active Devices"
                            value={devices.length.toString()}
                            subtext="2 new detected"
                            icon={<Wifi className="text-emerald-500" />}
                        />
                        <StatCard
                            label="Threats Detected"
                            value={stats.alerts.toString()}
                            subtext="Last 24 hours"
                            icon={<Shield className="text-red-500" />}
                        />
                        <StatCard
                            label="System Load"
                            value="12%"
                            subtext="Functioning normal"
                            icon={<Server className="text-purple-500" />}
                        />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-96">
                        {/* Main Chart */}
                        <div className="lg:col-span-2 bg-gray-900/50 border border-gray-800 rounded-xl p-6 flex flex-col">
                            <h3 className="text-sm font-semibold text-gray-400 mb-4 flex items-center gap-2">
                                <Radio className="w-4 h-4" /> Live Network Traffic
                            </h3>
                            <div className="flex-1 w-full min-h-0">
                                <ResponsiveContainer width="100%" height="100%">
                                    <AreaChart data={trafficData}>
                                        <defs>
                                            <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                            </linearGradient>
                                        </defs>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                                        <XAxis dataKey="time" hide />
                                        <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} />
                                        <Tooltip
                                            contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '0.5rem' }}
                                            itemStyle={{ color: '#e5e7eb' }}
                                        />
                                        <Area type="monotone" dataKey="pps" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorPps)" />
                                    </AreaChart>
                                </ResponsiveContainer>
                            </div>
                        </div>

                        {/* Alerts Feed */}
                        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-6 overflow-hidden flex flex-col">
                            <h3 className="text-sm font-semibold text-gray-400 mb-4 flex items-center gap-2">
                                <Bell className="w-4 h-4" /> Recent Alerts
                            </h3>
                            <div className="flex-1 overflow-y-auto space-y-3 pr-2">
                                {/* Mock Alerts if empty */}
                                {alerts.length === 0 ? (
                                    <>
                                        <AlertItem title="Port Scan Detected" severity="high" target="192.168.1.5" time="2m ago" />
                                        <AlertItem title="Weak SSH Password" severity="medium" target="10.0.0.12" time="15m ago" />
                                        <AlertItem title="New Device Discovered" severity="info" target="Unknown Vendor" time="1h ago" />
                                    </>
                                ) : alerts.map((a, i) => (
                                    <AlertItem key={i} title={a.signature} severity={a.severity === 1 ? 'high' : 'medium'} target={`${a.src_ip} -> ${a.dst_ip}`} time="Just now" />
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Devices Table */}
                    <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
                        <div className="p-6 border-b border-gray-800 flex items-center justify-between">
                            <h3 className="text-sm font-semibold text-gray-400">Connected Devices ({devices.length})</h3>
                            <button className="text-blue-400 text-sm hover:underline">Scan Network</button>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm text-left">
                                <thead className="bg-gray-800/50 text-gray-400 font-medium">
                                    <tr>
                                        <th className="px-6 py-3">Hostname</th>
                                        <th className="px-6 py-3">IP Address</th>
                                        <th className="px-6 py-3">MAC Address</th>
                                        <th className="px-6 py-3">Manufacturer</th>
                                        <th className="px-6 py-3">Status</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800">
                                    {devices.map((device, i) => (
                                        <tr key={i} className="hover:bg-gray-800/30 transition-colors">
                                            <td className="px-6 py-3 font-medium text-white">{device.hostname || "Unknown"}</td>
                                            <td className="px-6 py-3 text-gray-300 font-mono">{device.ip_address}</td>
                                            <td className="px-6 py-3 text-gray-400 font-mono">{device.mac_address}</td>
                                            <td className="px-6 py-3 text-gray-300">{device.manufacturer || "Unknown"}</td>
                                            <td className="px-6 py-3">
                                                <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-xs border border-emerald-500/20">
                                                    Active
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                    {devices.length === 0 && (
                                        <tr>
                                            <td colSpan="5" className="px-6 py-8 text-center text-gray-500">
                                                No devices using scanner yet. Waiting for scan...
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}

function NavItem({ icon, label, active, badge }) {
    return (
        <button className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-all ${active ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/20' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}>
            <div className="flex items-center gap-3">
                {React.cloneElement(icon, { size: 20 })}
                <span className="font-medium">{label}</span>
            </div>
            {badge && (
                <span className="px-1.5 py-0.5 rounded-full bg-red-500 text-white text-[10px] font-bold">
                    {badge}
                </span>
            )}
        </button>
    );
}

function StatCard({ label, value, subtext, icon }) {
    return (
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-sm font-medium text-gray-400">{label}</p>
                    <h4 className="text-2xl font-bold mt-2 text-white">{value}</h4>
                    <p className="text-xs text-gray-500 mt-1">{subtext}</p>
                </div>
                <div className="p-3 bg-gray-800 rounded-lg opacity-80">
                    {icon}
                </div>
            </div>
        </div>
    );
}

function AlertItem({ title, severity, target, time }) {
    const colors = {
        high: 'border-l-red-500 bg-red-500/5',
        medium: 'border-l-yellow-500 bg-yellow-500/5',
        info: 'border-l-blue-500 bg-blue-500/5'
    };

    return (
        <div className={`p-3 rounded border-l-2 bg-gray-800/30 flex items-start justify-between ${colors[severity]}`}>
            <div>
                <h5 className="text-sm font-medium text-gray-200">{title}</h5>
                <p className="text-xs text-gray-500 mt-0.5">Target: {target}</p>
            </div>
            <span className="text-[10px] text-gray-600 font-mono">{time}</span>
        </div>
    );
}

export default App;
