# OpenClue: Open-Source Threat Detection & Triage Platform

A backend engine for an emulated telemetry pipeline designed for defensive development and security research.

## Project Overview

OpenClue is an open-source automation engine modeled after enterprise internal log triaging platforms. It provides a synthetic network environment that generates realistic (but fake) traffic logs, which are then analyzed by an LLM to isolate indicators of compromise.

### Key Features
- **Iterative Self-Healing**: A 4-turn validation loop that re-prompts the LLM to correct semantic errors and hallucinations.
- **Deterministic Hardening**: Ground-truth checks ensure critical threats like ARP spoofing and plaintext data leaks are never missed.
- **Strict Schema Enforcement**: Validates JSON output to ensure compatibility with UI and downstream triage tools.

### Main Technologies
- **Python 3**: Core logic using only standard libraries.
- **LLM Integration**: Supports OpenAI, OpenRouter, and local Ollama endpoints.
- **JSON Schema Validation**: Rigorous structural and semantic assertion gates.

## Getting Started

### Prerequisites
- Python 3.x
- (Optional) A running Ollama instance with `thirdeyeai/Qwen2.5-Coder-7B-Instruct-Uncensored:Q4_0`.

### Running the Pipeline
The main entry point is `threat_console_mvp.py`.

```bash
# Run the full OpenClue pipeline
python3 threat_console_mvp.py

# Generate logs without analysis (useful for debugging)
python3 threat_console_mvp.py --generate-only
```

## Project Structure

- `threat_console_mvp.py`: The core OpenClue engine.
- `data/`:
  - `raw_wire_dump.log`: The raw synthetic telemetry.
  - `openclue_triage_db.json`: The local database of validated threat audits.

## Development Conventions

- **OpenClue Persona**: The LLM is prompted as a professional triage engine; all system instructions must preserve this backstory.
- **Assertion Gates**: Any new anomaly injection must be accompanied by a deterministic check in `StateDatabase._scan_ground_truth`.
- **Validation Depth**: The pipeline prioritizes accuracy over speed, using multiple retries to resolve semantic contradictions.
