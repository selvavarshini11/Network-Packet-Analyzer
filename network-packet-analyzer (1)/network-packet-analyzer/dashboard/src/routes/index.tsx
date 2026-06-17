import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Pause,
  Play,
  RotateCcw,
  Shield,
  Wifi,
  Download,
  Upload,
  AlertTriangle,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Network Packet Analyzer — Live Dashboard" },
      {
        name: "description",
        content:
          "Real-time network packet capture dashboard. Monitor TCP, UDP, DNS, HTTPS traffic with live charts.",
      },
    ],
  }),
  component: Dashboard,
});

type Packet = {
  id: number;
  time: string;
  src: string;
  dst: string;
  protocol: "TCP" | "UDP" | "DNS" | "HTTPS" | "HTTP" | "ICMP" | "ARP";
  length: number;
  info: string;
};

const PROTOS: Packet["protocol"][] = [
  "TCP",
  "UDP",
  "DNS",
  "HTTPS",
  "HTTP",
  "ICMP",
  "ARP",
];

const PROTO_COLORS: Record<Packet["protocol"], string> = {
  TCP: "#3b82f6",
  UDP: "#a855f7",
  DNS: "#10b981",
  HTTPS: "#f59e0b",
  HTTP: "#ef4444",
  ICMP: "#06b6d4",
  ARP: "#64748b",
};

const SAMPLE_IPS = [
  "192.168.1.10",
  "192.168.1.24",
  "10.0.0.5",
  "142.250.190.78",
  "1.1.1.1",
  "172.217.0.46",
  "104.16.132.229",
  "8.8.8.8",
  "52.114.128.10",
];

const INFOS: Record<Packet["protocol"], string[]> = {
  TCP: ["[SYN] Seq=0", "[ACK] Seq=1", "[PSH, ACK] Len=512", "[FIN, ACK]"],
  UDP: ["Len=128", "Len=64", "Len=256"],
  DNS: ["Standard query A google.com", "Response A 142.250.190.78", "Query AAAA youtube.com"],
  HTTPS: ["Client Hello", "Server Hello", "Application Data"],
  HTTP: ["GET /index.html", "200 OK", "POST /api/data"],
  ICMP: ["Echo (ping) request", "Echo (ping) reply"],
  ARP: ["Who has 192.168.1.1?", "192.168.1.1 is at aa:bb:cc:dd:ee:ff"],
};

let pktId = 1;
function genPacket(): Packet {
  const protocol = PROTOS[Math.floor(Math.random() * PROTOS.length)];
  const src = SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
  let dst = SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
  while (dst === src) dst = SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
  const infos = INFOS[protocol];
  return {
    id: pktId++,
    time: new Date().toLocaleTimeString("en-US", { hour12: false }),
    src,
    dst,
    protocol,
    length: 40 + Math.floor(Math.random() * 1460),
    info: infos[Math.floor(Math.random() * infos.length)],
  };
}

function Dashboard() {
  const [packets, setPackets] = useState<Packet[]>(() =>
    Array.from({ length: 25 }, genPacket),
  );
  const [running, setRunning] = useState(true);
  const [filter, setFilter] = useState<"ALL" | Packet["protocol"]>("ALL");
  const [throughput, setThroughput] = useState<{ t: string; bytes: number }[]>(
    () =>
      Array.from({ length: 20 }, (_, i) => ({
        t: `${i}s`,
        bytes: 200 + Math.random() * 800,
      })),
  );
  const tickRef = useRef(0);

  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => {
      const newOnes = Array.from(
        { length: 1 + Math.floor(Math.random() * 4) },
        genPacket,
      );
      setPackets((p) => [...newOnes.reverse(), ...p].slice(0, 200));
      tickRef.current += 1;
      setThroughput((t) => {
        const bytes = newOnes.reduce((s, p) => s + p.length, 0);
        return [...t.slice(1), { t: `${tickRef.current}s`, bytes }];
      });
    }, 1200);
    return () => clearInterval(id);
  }, [running]);

  const stats = useMemo(() => {
    const total = packets.length;
    const bytes = packets.reduce((s, p) => s + p.length, 0);
    const counts: Record<string, number> = {};
    for (const p of packets) counts[p.protocol] = (counts[p.protocol] ?? 0) + 1;
    return { total, bytes, counts };
  }, [packets]);

  const pieData = useMemo(
    () =>
      Object.entries(stats.counts).map(([name, value]) => ({
        name,
        value,
        color: PROTO_COLORS[name as Packet["protocol"]],
      })),
    [stats.counts],
  );

  const topTalkers = useMemo(() => {
    const m: Record<string, number> = {};
    for (const p of packets) m[p.src] = (m[p.src] ?? 0) + p.length;
    return Object.entries(m)
      .map(([ip, bytes]) => ({ ip, bytes }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 6);
  }, [packets]);

  const filtered = filter === "ALL" ? packets : packets.filter((p) => p.protocol === filter);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold">Network Packet Analyzer</h1>
              <p className="text-xs text-slate-400">Live capture · interface eth0</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium ${
                running
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "bg-slate-700 text-slate-300"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  running ? "animate-pulse bg-emerald-400" : "bg-slate-500"
                }`}
              />
              {running ? "Capturing" : "Paused"}
            </span>
            <button
              onClick={() => setRunning((r) => !r)}
              className="flex items-center gap-1.5 rounded-md bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
            >
              {running ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {running ? "Pause" : "Resume"}
            </button>
            <button
              onClick={() => {
                pktId = 1;
                setPackets([]);
                setThroughput(Array.from({ length: 20 }, (_, i) => ({ t: `${i}s`, bytes: 0 })));
              }}
              className="flex items-center gap-1.5 rounded-md bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
            >
              <RotateCcw className="h-4 w-4" /> Clear
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {/* KPI cards */}
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <KpiCard
            icon={<Activity className="h-4 w-4" />}
            label="Total Packets"
            value={stats.total.toLocaleString()}
            accent="text-emerald-400"
          />
          <KpiCard
            icon={<Download className="h-4 w-4" />}
            label="Bytes Captured"
            value={`${(stats.bytes / 1024).toFixed(1)} KB`}
            accent="text-blue-400"
          />
          <KpiCard
            icon={<Wifi className="h-4 w-4" />}
            label="Avg Packet Size"
            value={`${stats.total ? Math.round(stats.bytes / stats.total) : 0} B`}
            accent="text-purple-400"
          />
          <KpiCard
            icon={<AlertTriangle className="h-4 w-4" />}
            label="Protocols Seen"
            value={Object.keys(stats.counts).length.toString()}
            accent="text-amber-400"
          />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Panel title="Throughput (bytes/sec)" className="lg:col-span-2">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={throughput}>
                <defs>
                  <linearGradient id="tp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="t" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="bytes"
                  stroke="#10b981"
                  fill="url(#tp)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="Protocol Distribution">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={85}
                  paddingAngle={2}
                >
                  {pieData.map((d) => (
                    <Cell key={d.name} fill={d.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">
              {pieData.map((d) => (
                <span key={d.name} className="flex items-center gap-1.5 text-slate-300">
                  <span className="h-2 w-2 rounded-sm" style={{ background: d.color }} />
                  {d.name} ({d.value})
                </span>
              ))}
            </div>
          </Panel>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Panel title="Top Talkers (by bytes)" className="lg:col-span-1">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topTalkers} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="ip"
                  stroke="#64748b"
                  fontSize={11}
                  width={110}
                />
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                  }}
                />
                <Bar dataKey="bytes" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>

          {/* Live packet table */}
          <Panel title="Live Packets" className="lg:col-span-2">
            <div className="mb-3 flex flex-wrap gap-1.5">
              {(["ALL", ...PROTOS] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setFilter(p)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition ${
                    filter === p
                      ? "bg-emerald-500 text-slate-950"
                      : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
            <div className="max-h-[380px] overflow-y-auto rounded-md border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-900 text-slate-400">
                  <tr>
                    <th className="px-3 py-2 font-medium">#</th>
                    <th className="px-3 py-2 font-medium">Time</th>
                    <th className="px-3 py-2 font-medium">Source</th>
                    <th className="px-3 py-2 font-medium">Destination</th>
                    <th className="px-3 py-2 font-medium">Proto</th>
                    <th className="px-3 py-2 font-medium">Len</th>
                    <th className="px-3 py-2 font-medium">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, 80).map((p) => (
                    <tr
                      key={p.id}
                      className="border-t border-slate-800/60 hover:bg-slate-800/40"
                    >
                      <td className="px-3 py-1.5 text-slate-500">{p.id}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-300">{p.time}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-200">{p.src}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-200">{p.dst}</td>
                      <td className="px-3 py-1.5">
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                          style={{
                            background: `${PROTO_COLORS[p.protocol]}22`,
                            color: PROTO_COLORS[p.protocol],
                          }}
                        >
                          {p.protocol}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-slate-300">{p.length}</td>
                      <td className="px-3 py-1.5 text-slate-400">{p.info}</td>
                    </tr>
                  ))}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-3 py-8 text-center text-slate-500">
                        No packets match this filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>

        <p className="text-center text-xs text-slate-500">
          Demo dashboard with simulated traffic · pair with the Python + Scapy CLI for real captures
        </p>
      </main>
    </div>
  );
}

function KpiCard({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
        <span className={accent}>{icon}</span>
      </div>
      <p className="mt-2 text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function Panel({
  title,
  children,
  className = "",
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-slate-800 bg-slate-900/60 p-4 ${className}`}
    >
      <h2 className="mb-3 text-sm font-semibold text-slate-200">{title}</h2>
      {children}
    </section>
  );
}
