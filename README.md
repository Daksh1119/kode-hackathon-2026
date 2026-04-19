# NetMap: Shadow IT & Attack Surface Intelligence

**NetMap** is a comprehensive, automated shadow IT discovery and attack surface mapping pipeline. Designed for both security professionals and non-technical stakeholders, it systematically discovers hidden organizational assets, flags risky exposures, and transforms complex vulnerability data into actionable, plain-English insights using cutting-edge LLMs.

---

## 📖 End-to-End Simplified Breakdown

The heart of NetMap is its 10-Stage Intelligence Pipeline, designed to replicate the methodology of a human adversary discovering corporate infrastructure.

### The 10-Stage Pipeline
1. **Subdomain Enumeration (`subdomain.py`)**: Queries public certificate transparency logs and APIs to discover every registered subdomain belonging to the target organization.
2. **Status Probing (`status_prober.py`)**: Sends concurrent HTTP requests to all discovered subdomains to determine which servers are actually alive and responsive.
3. **Page Classification (`page_classifier.py`)**: Categorizes live pages based on HTML footprints (e.g., Identifying Admin Panels, Login Pages, Default Server Pages, API Endpoints).
4. **Intelligence Engine (`intelligence_engine.py`)**: Runs rule-based pattern matching to flag basic risks like exposed CMS portals, missing security headers, or plaintext HTTP protocols.
5. **Port & Service Scanning (`active_scanner.py` - Nmap)**: Triggers deep active scanning across discovered domains to map open network ports and standard running services.
6. **Vulnerability Scanning (`active_scanner.py` - Nuclei)**: Runs comprehensive active vulnerability templates to detect misconfigurations, out-of-date software, and CVEs.
7. **Cloud Storage Exposure (`cloud_storage_exposure.py`)**: Hunts for unauthenticated AWS S3 buckets, Azure Blobs, GCP storage drops, and generic open web directories publicly associated with the target domain.
8. **Sensitive File & Backup Leaks (`sensitive_file_scanner.py`)**: Brute-forces known directories to identify dangerously exposed configuration artifacts (e.g. `.env` files, `.git` histories, `backup.sql`, SSH private keys).
9. **Deduplication (`active_scanner.py`)**: Merges and standardizes findings across all the different scanning engines to eliminate noise and overlapping results.
10. **Prioritization (`pipeline.py`)**: Enriches the final aggregated intelligence pool by grading the urgency of the issues on standard P0 (Critical) to P3 (Low) prioritizations.

### The Application Stack
The results of the pipeline are beamed directly into a fluid web architecture:

- **The Backend (`server.js`)**: An Express/Node.js backend orchestrates the pipeline execution. When a scan finishes, this layer parses the results JSON and utilizes the **Groq AI API (Llama 3.1 8B)** to serve the **Explain** and **Remediate** endpoints.
- **The Frontend (`netmap-app`)**: A React/Vite-powered dashboard that visually plots the discovered infrastructure, attack charts, and findings.
- **The AI Explanation Engine**: When a user clicks a finding, the Groq LLM translates deep technical jargon (e.g. "Port 443/TCP Open") into literal, jargon-free English explaining the business risk and outlining strict, actionable remediation scripts tailored for non-tech owners.

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- Python (3.9+)
- Valid `GROQ_API_KEY`

### 1. Backend & Pipeline Setup
\`\`\`bash
# Install Python dependencies required for the pipeline
pip install -r requirements.txt

# Install backend dependencies
cd netmap-app
npm install

# Create the environment configuration
touch .env
\`\`\`
Inside your `.env` file, securely add your API key for the AI Explanation engine:
\`\`\`env
GROQ_API_KEY=gsk_your_key_here
\`\`\`

### 2. Frontend Setup
Make sure you are in the `netmap-app` directory alongside the React framework.
\`\`\`bash
npm run dev
\`\`\`

### 3. Launching
In a separate terminal, launch the backend API from the `netmap-app` directory:
\`\`\`bash
node server.js
\`\`\`

Visit `http://localhost:5173` in your browser. Enter any target domain into the Hero input and initiate your first live scan.

---

## 🛡️ Key Features
* **Zero Configuration Scanning:** Input a domain and let the 10-stage pipeline handle enumeration naturally.
* **LLM-Powered Simplification:** Integrates natively with Llama 3 to turn cryptic CLI scanner logs into actionable "plain English and runnable script" IT briefs.
* **Aggressive Exposure Detection:** Unlike typical port mappers, NetMap actively targets unprotected developer environments, `.git` exposures, and forgotten cloud buckets (`cloud_storage_exposure.py`).
* **Visual Attack Graphing:** Automatically clusters discovered domains and their related risks through frontend visualization.

---

*Made for Hackathon 2026. Prioritizing simplicity, automation, and speed for complete infrastructure dominance.*
