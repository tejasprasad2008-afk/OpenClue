"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Activity, 
  Wifi, 
  Terminal, 
  ArrowRight, 
  Upload,
  AlertTriangle,
  Zap
} from "lucide-react";

// Types based on openclue_triage_db.json schema
interface AuditRecord {
  record_type: string;
  created_at: string;
  audit: {
    audit_summary: {
      total_frames_analyzed: number;
      benign_frames_dropped: number;
      detected_risk_level: "LOW" | "MEDIUM" | "HIGH";
      executive_verdict: string;
    };
    detected_nodes: Array<{
      id: string;
      ip_address: string;
      mac_address: string;
      device_type: string;
      vendor_oui: string;
      status: "SECURE" | "VULNERABLE" | "COMPROMISED";
    }>;
    threat_incidents: Array<{
      incident_id: string;
      source_node: string;
      destination_node: string;
      protocol: string;
      severity: "INFO" | "WARNING" | "CRITICAL";
      type: string;
      technical_details: string;
      remediation_action: string;
    }>;
    visual_topology_edges: Array<{
      from: string;
      to: string;
      relationship: string;
    }>;
  };
}

export default function OpenClueDashboard() {
  const [data, setData] = useState<AuditRecord | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initial load: Simulation data
  useEffect(() => {
    const mockData: AuditRecord = {
      record_type: "threat_audit",
      created_at: new Date().toISOString(),
      audit: {
        audit_summary: {
          total_frames_analyzed: 0,
          benign_frames_dropped: 0,
          detected_risk_level: "LOW",
          executive_verdict: "SYSTEM_IDLE: AWAITING_TELEMETRY_INGESTION."
        },
        detected_nodes: [],
        threat_incidents: [],
        visual_topology_edges: []
      }
    };
    setData(mockData);
  }, []);

  const handleSift = async () => {
    setIsScanning(true);
    setError(null);
    try {
      const response = await fetch("/api/triage", { method: "POST" });
      const result = await response.json();
      
      if (result.status === "completed") {
        setData({
          record_type: "threat_audit",
          created_at: new Date().toISOString(),
          audit: result.audit
        });
      } else if (result.error) {
        setError(result.error);
      }
    } catch (err) {
      setError("Failed to connect to OpenClue Engine.");
    } finally {
      setIsScanning(false);
    }
  };

  if (!data) return <div className="p-20 font-mono">LOADING_ENGINE_CONTEXT...</div>;

  const { audit } = data;

  return (
    <main className="min-h-screen bg-white text-black selection:bg-black selection:text-white">
      {/* SECTION A: HERO BRAND BANNER */}
      <header className="px-6 pt-12 pb-6 md:px-12 md:pt-24 relative">
        {/* Vercel Demo Disclaimer */}
        <div className="absolute top-4 right-6 md:right-12 font-mono text-[10px] uppercase tracking-widest bg-black text-white px-3 py-1 animate-pulse">
          PRE-RELEASE_DEMO // TESTING_PURPOSES_ONLY
        </div>

        <h1 className="font-serif text-[15vw] font-bold tracking-tighter uppercase leading-[0.8] mb-8">
          OpenClue
        </h1>
        <div className="border-t-8 border-black w-full mb-12"></div>
        
        {/* Audit Summary Metadata */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 font-mono text-[10px] md:text-xs uppercase tracking-[0.2em]">
          <div className="space-y-2">
            <span className="opacity-50">Total Frames</span>
            <p className="font-bold text-lg md:text-2xl">{audit.audit_summary.total_frames_analyzed}</p>
          </div>
          <div className="space-y-2">
            <span className="opacity-50">Operational Noise Dropped</span>
            <p className="font-bold text-lg md:text-2xl">{audit.audit_summary.benign_frames_dropped}</p>
          </div>
          <div className="space-y-2">
            <span className="opacity-50">Session ID</span>
            <p className="font-bold text-lg md:text-2xl">OC-{data.created_at.split('T')[0].replace(/-/g, '')}</p>
          </div>
          <div className="space-y-2">
            <span className="opacity-50">Risk Evaluation</span>
            <div className={`bg-black text-white px-4 py-2 mt-1 inline-block font-bold text-xl md:text-3xl ${isScanning ? 'animate-pulse' : ''}`}>
              {isScanning ? "SCANNING..." : audit.audit_summary.detected_risk_level}
            </div>
          </div>
        </div>

        <div className="mt-12 max-w-4xl">
          <p className="font-serif italic text-2xl md:text-4xl leading-tight border-l-4 border-black pl-6 py-2">
            "{isScanning ? "Processing raw telemetry stream via OpenRouter Cloud Brain..." : audit.audit_summary.executive_verdict}"
          </p>
          {error && (
            <div className="mt-4 bg-black text-white p-4 font-mono text-xs uppercase">
              Error: {error}
            </div>
          )}
        </div>
      </header>

      {/* SECTION B: LOG INGESTION DROP ZONE */}
      <section className="px-6 md:px-12 py-12">
        <button 
          onClick={handleSift}
          disabled={isScanning}
          className={`w-full border-2 border-dashed border-black p-12 text-center group transition-all duration-300 hover:bg-black hover:text-white focus-visible:outline focus-visible:outline-4 focus-visible:outline-black focus-visible:outline-offset-4 ${isScanning ? 'cursor-wait opacity-50 bg-black text-white' : ''}`}
        >
          {isScanning ? (
            <Activity className="mx-auto mb-4 w-12 h-12 stroke-[1.5] animate-spin" />
          ) : (
            <Upload className="mx-auto mb-4 w-12 h-12 stroke-[1.5]" />
          )}
          <p className="font-mono text-xs uppercase tracking-widest mb-2 font-bold">
            {isScanning ? "Agentic Sifting in Progress..." : "Initialize Local Agentic Sifting"}
          </p>
          <p className="font-serif italic text-sm opacity-60">
            {isScanning ? "Consulting OpenRouter Cloud Brain (Attempting self-healing)..." : "Drop raw tcpdump wire logs or standard UNIX syslog dumps to start triage..."}
          </p>
        </button>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-black border-y border-black">
        {/* SECTION C: NETWORK TOPOLOGY GRID */}
        <section className="bg-white p-6 md:px-12 md:py-12 border-r border-black">
          <div className="flex items-center justify-between mb-12">
            <h2 className="font-mono text-xs uppercase tracking-[0.3em] font-bold">Network_Topology.map</h2>
            <Zap className="w-4 h-4 fill-black" />
          </div>

          <div className="grid grid-cols-1 gap-6 relative">
            {/* Structural Grid Primitives */}
            <div className="absolute inset-0 grid grid-cols-6 grid-rows-6 opacity-[0.05] pointer-events-none">
              {Array.from({ length: 36 }).map((_, i) => (
                <div key={i} className="border border-black"></div>
              ))}
            </div>

            {/* Nodes */}
            <div className="space-y-8 relative z-10">
              {audit.detected_nodes.map((node) => (
                <div 
                  key={node.id} 
                  className="border border-black p-6 transition-all duration-100 group hover:bg-black hover:text-white cursor-crosshair"
                >
                  <div className="flex justify-between items-start mb-4">
                    <span className="font-mono text-[10px] opacity-50">[{node.id}]</span>
                    <span className={`font-mono text-[10px] px-2 py-1 border border-black ${node.status !== 'SECURE' ? 'bg-black text-white group-hover:bg-white group-hover:text-black' : ''}`}>
                      {node.status}
                    </span>
                  </div>
                  <p className="font-serif text-2xl font-bold mb-1">{node.ip_address}</p>
                  <p className="font-mono text-xs opacity-60">{node.mac_address} // {node.device_type}</p>
                </div>
              ))}
            </div>

            {/* Edges Representation */}
            <div className="mt-12 pt-12 border-t border-black space-y-4">
              <h3 className="font-mono text-[10px] uppercase tracking-widest opacity-50 mb-4">Vector_Relationships</h3>
              {audit.visual_topology_edges.map((edge, i) => (
                <div key={i} className="flex items-center font-mono text-[10px] space-x-4">
                  <span className="border border-black px-2 py-1">{edge.from}</span>
                  <div className="flex-1 border-t border-black relative">
                    <span className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-white px-2 italic">
                      {edge.relationship}
                    </span>
                    <ArrowRight className="absolute right-0 top-1/2 -translate-y-1/2 w-3 h-3 translate-x-1" />
                  </div>
                  <span className="border border-black px-2 py-1">{edge.to}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* SECTION D: INCIDENT TRIAGE LOG */}
        <section className="bg-white p-6 md:px-12 md:py-12">
          <div className="flex items-center justify-between mb-12">
            <h2 className="font-mono text-xs uppercase tracking-[0.3em] font-bold">Threat_Incident_Log.triage</h2>
            <Terminal className="w-4 h-4" />
          </div>

          <div className="space-y-12">
            {audit.threat_incidents.map((incident) => (
              <article key={incident.incident_id} className="relative">
                <div className="flex items-center space-x-4 mb-6">
                  <div className="bg-black text-white p-2 font-mono text-xs font-bold">
                    {incident.severity}
                  </div>
                  <span className="font-mono text-[10px] tracking-widest uppercase opacity-50">
                    ID: {incident.incident_id} // {incident.protocol}
                  </span>
                </div>

                <h3 className="font-serif text-3xl font-bold mb-4 uppercase tracking-tighter">
                  {incident.type.replace(/_/g, ' ')}
                </h3>

                <div className="flex gap-6 items-start">
                  {/* Boxed Drop-Cap */}
                  <div className="flex-shrink-0 w-12 h-12 border-2 border-black flex items-center justify-center font-serif text-2xl font-bold">
                    {incident.remediation_action.charAt(0)}
                  </div>
                  <div className="space-y-6">
                    <p className="font-mono text-xs leading-relaxed opacity-70">
                      {incident.technical_details}
                    </p>
                    <div className="bg-black/5 p-4 border-l-2 border-black">
                      <p className="font-serif italic text-sm">
                        {incident.remediation_action}
                      </p>
                    </div>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </section>
      </div>

      {/* Footer Branding */}
      <footer className="p-12 border-t border-black flex flex-col md:flex-row justify-between items-center font-mono text-[10px] uppercase tracking-[0.5em] opacity-30">
        <div className="flex flex-col space-y-2">
          <span>OpenClue Engine v0.4.0</span>
          <span className="italic">Note: This interface is for testing purposes only. Future updates will include live OS-level packet ingestion.</span>
        </div>
        <span>Standard Library First // cloud_brain_active</span>
        <span>© 2026 OpenClue Platform</span>
      </footer>
    </main>
  );
}
