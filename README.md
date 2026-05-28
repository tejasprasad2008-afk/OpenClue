# 🕵️‍♂️ OpenClue
**Open-Source Agentic Threat Detection & Triage Platform**

OpenClue is an automated security engine designed to ingest raw network telemetry and isolate indicators of compromise using local-first LLMs. Modeled after enterprise-grade triage platforms, OpenClue uses an iterative self-healing pipeline to verify threats with high fidelity.

[![Vercel Demo](https://img.shields.io/badge/Demo-Live_on_Vercel-black?style=for-the-badge&logo=vercel)](https://open-clue.vercel.app)
[![Hackathon Status](https://img.shields.io/badge/Hackathon-Day_3_MVP-white?style=for-the-badge)](https://github.com/tejasprasad2008-afk/OpenClue)

---

## ⚡ The Core Innovation
OpenClue addresses the "Semantic Weakness" of small local models (7B) by wrapping them in a **Deterministic Hardening Gate**. 

1. **Passive Ingestion**: Scans raw `tcpdump` and `syslog` streams.
2. **Deterministic Pre-Scan**: A Python-based engine establishes ground-truth markers (Absolute Truth) before the AI analyzes the data.
3. **Iterative Self-Healing**: If the AI (the Brain) misses a critical threat or provides a contradictory verdict, the Engine automatically triggers a correction loop (up to 4 turns) until the audit passes strict semantic validation.

## 🛠️ Tech Stack
- **Engine**: Python 3.12 (Standard Library First)
- **Brain**: Qwen-2.5-Coder-7B (Local/Ollama) or GPT-4o-Mini (Cloud/OpenRouter)
- **Dashboard**: Next.js 14 (App Router), Tailwind CSS, Lucide Icons
- **Visual System**: Minimalist Monochrome (Elite Editorial Aesthetic)

---

## 🛠️ Tools & Tech Stack

*   **Core Orchestration Engine:** Python 3.12 (Standard Library First) – Handles deterministic hardware data parsing, raw network string extraction, and state processing loops cleanly.
*   **AI Agentic Framework:** Codex-Optimized Automation Pipeline – Utilizes structural response formatting via strict `json_schema` constraints coupled with an active **4-turn iterative Semantic Self-Healing Loop** for autonomous threat classification.
*   **Local Inference & Model Routing:** Local Model Execution Layers via OpenRouter – Features integration capabilities for local inference engines (e.g., `Qwen2.5-Coder-7B-Instruct-Uncensored`) utilizing a context depth window of up to 16,384 tokens to preserve operational bandwidth while processing long network logs.
*   **Persistence Layer:** Structured Atomic File-System Storage – Saves state histories, analysis flags, and session records safely to `data/openclue_triage_db.json`.

---

## 🎯 Ideal Customer Profile (ICP) & Target Audience

### 👥 Primary Audience: DevSecOps & Security Analysts
*   **The Pain Point:** Junior incident response teams and defensive security developers who are drowning in daily, unstructured log text and raw packet bytes.
*   **The Value:** OpenClue compresses their toxic, multi-step command-line verification chores down into an instantaneous 3-step automated triage mapping matrix.

### 🌐 Secondary Audience: Remote Engineers & Digital Nomads
*   **The Pain Point:** Privacy-focused individuals and technical remote workers who routinely connect to unverified, hazardous public Wi-Fi networks (cafes, airports, co-working spaces).
*   **The Value:** Provides continuous, zero-config automated verification of local routing table anomalies and token leak exposure, protecting endpoints at a single glance.
## 🚀 Getting Started

### 1. Setup the Backend
---

```bash
# Clone the repo
git clone https://github.com/tejasprasad2008-afk/OpenClue.git
cd OpenClue

# Configure your Brain (OpenRouter or Ollama)
cp .env.example .env 
# Add your OPENROUTER_API_KEY to .env
```

### 2. Launch the Dashboard
```bash
npm install
npm run dev
```
Visit `http://localhost:3000` and click **"Initialize Local Agentic Sifting"** to start a virtual triage scan.

---

## 🗺️ Roadmap (Day 4 - Day 7)
- [x] **Day 1-2**: Backend Engine & Self-Healing Loop implementation.
- [x] **Day 3**: Next.js Monochrome Dashboard & API Bridge.
- [ ] **Day 4**: Real-time log polling & UI animations.
- [ ] **Day 5**: **Live Wireshark/tshark integration** (Real-time packet sniffing).
- [ ] **Day 6**: Vendor OUI database lookup & device inventory.
- [ ] **Day 7**: Apple Watch & iOS critical threat push notifications.

---

## ⚖️ Disclaimer
*This project is built for the **AI Builders Hackathon**. It is currently in a pre-release demo state. Live OS-level packet ingestion is under construction. Use for educational and research purposes only.*

© 2026 OpenClue Platform | Developed by Tejas
