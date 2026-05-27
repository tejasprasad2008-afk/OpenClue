import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";

const execPromise = promisify(exec);

export async function POST() {
  // Vercel / Production Fallback for Demo Purposes
  if (process.env.NODE_ENV === "production" || process.env.VERCEL) {
    return NextResponse.json({
      status: "completed",
      audit: {
        audit_summary: {
          total_frames_analyzed: 130,
          benign_frames_dropped: 122,
          detected_risk_level: "HIGH",
          executive_verdict: "[DEMO_MODE] CRITICAL SECURITY BREACH DETECTED: UNAUTHORIZED ARP SPOOFING AND PLAINTEXT CREDENTIAL LEAK IDENTIFIED."
        },
        detected_nodes: [
          { id: "node_0", ip_address: "192.168.1.1", mac_address: "88:99:AA:BB:CC:DD", device_type: "GATEWAY", vendor_oui: "Unknown", status: "VULNERABLE" },
          { id: "node_1", ip_address: "192.168.1.45", mac_address: "00:1A:2B:3C:4D:62", device_type: "USER_LAPTOP", vendor_oui: "Apple", status: "COMPROMISED" },
          { id: "node_attacker", ip_address: "192.168.1.200", mac_address: "FF:FF:FF:FF:FF:FF", device_type: "SUSPICIOUS_PROXIED_NODE", vendor_oui: "Unknown", status: "COMPROMISED" }
        ],
        threat_incidents: [
          {
            incident_id: "th_0",
            source_node: "192.168.1.200",
            destination_node: "192.168.1.1",
            protocol: "ARP",
            severity: "CRITICAL",
            type: "ROUTING_SPOOF",
            technical_details: "Unverified ARP Reply detected: 192.168.1.1 is-at 88:99:AA:BB:CC:DD. [DEMO_MOCK]",
            remediation_action: "Disconnect from the current access point immediately."
          },
          {
            incident_id: "th_1",
            source_node: "192.168.1.45",
            destination_node: "198.51.100.23",
            protocol: "HTTP",
            severity: "CRITICAL",
            type: "PLAINTEXT_DATA_LEAK",
            technical_details: "GitHub Personal Access Token leaked in plaintext via GET request on Port 80. [DEMO_MOCK]",
            remediation_action: "Revoke the ghp_ token immediately."
          }
        ],
        visual_topology_edges: [
          { from: "node_attacker", to: "node_0", relationship: "ATTACKING" },
          { from: "node_1", to: "node_attacker", relationship: "ROUTED_THROUGH" }
        ]
      }
    });
  }

  try {
    // Determine the path to the python script (it's in the project root)
    const scriptPath = path.join(process.cwd(), "threat_console_mvp.py");
    
    // Execute the Python backend with increased buffer and timeout (10 mins)
    const { stdout, stderr } = await execPromise(`python3 "${scriptPath}"`, {
      maxBuffer: 1024 * 1024 * 10, // 10MB buffer
      timeout: 1000 * 60 * 10      // 10 minutes
    });
    
    if (stderr && !stdout) {
      return NextResponse.json({ error: stderr }, { status: 500 });
    }

    const result = JSON.parse(stdout);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error("Pipeline Error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to execute OpenClue engine." },
      { status: 500 }
    );
  }
}

export async function GET() {
  // Optional: Add logic here to read the latest record from data/openclue_triage_db.json
  return NextResponse.json({ message: "OpenClue API Active" });
}
