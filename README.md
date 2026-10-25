# 🛡️ KageHound (`kage-hound`)

> **Unified Multi-Layer Secret Defense & Dark Web Threat Intelligence Suite**  
> *Shadow Protection for Modern Developers & Autonomous AI Agent Environments*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](pyproject.toml)
[![Architecture: 5-Layer](https://img.shields.io/badge/Architecture-5--Layer-purple.svg)](#architecture)
[![Breach Protocol: k-Anonymity](https://img.shields.io/badge/Breach_Check-Zero--Knowledge-orange.svg)](#layer-3-zero-knowledge-breach-radar)

---

## 📖 Overview

In modern engineering environments, accidental secret exposure—whether via inadvertent git commits, terminal logs captured by AI assistant contexts, or leaks scattered across darknet pastes—represents a catastrophic risk.

**KageHound** provides an all-in-one, 100% free and open-source multi-layered secret security ecosystem:
1. **Local Pre-Commit Guard**: Instant pattern & Shannon entropy inspection blocking leaked secrets before `git commit`.
2. **Live Credential Verifier**: Eliminates false positives by pinging vendor APIs (GitHub, Telegram, AWS, Stripe, OCI) to confirm whether a token is truly active.
3. **Zero-Knowledge Breach Radar**: k-Anonymity checks against HaveIBeenPwned (HIBP) and HasMySecretLeaked (HMSL) protocols without exposing raw credentials.
4. **Dark Web & Paste Scout**: Uncovers unindexed leaks across Tor `.onion` search indices (Ahmia), Intelligence X, and paste dump mirrors.
5. **Extensible Plugin Hub**: Drop-in modularity for custom detectors, verifiers, and OSINT scouts.

---

## 🐾 Identity & Name Justification

> *"In the shadows where secrets are discarded, the hound never loses the scent."*

The name **KageHound** represents the union of two foundational concepts:

| Component | Linguistic Root | Meaning & Purpose in Secret Security |
| :--- | :--- | :--- |
| **`Kage` (影)** | Japanese | **Shadow / Stealth**. Aligned with the shadow realm of modern software architecture—the deep web, Tor `.onion` hidden services, underground pastes, and encrypted payloads. It embodies the silent, vigilant guardian aesthetic. |
| **`Hound`** | Old English / Germanic | **The Relentless Tracker**. Following the iconic open-source security tool lineage (*TruffleHog*, *BloodHound*), a hound is an unyielding, loyal protector endowed with an acute sense of smell that relentlessly tracks down the scent of exposed credentials and intimates its master to rotate them before adversaries can strike. |

Combined, **KageHound** operates as **The Shadow Bloodhound**: a silent, unyielding guardian sniffing out compromised API keys, private certificates, and credentials across local Git trees and darknet dumps before malicious actors can weaponize them.

### 🛡️ Zero-Collision Registry Audit
Before adopting this identity, an exhaustive global namespace audit was conducted across official registries:
- **GitHub**: 0 repository collisions
- **PyPI**: 100% available (unclaimed namespace)
- **Crates.io**: Available
- **Global Search**: 0 collisions across cybersecurity tools

---

## 🏛️ Architecture

```
+-----------------------------------------------------------------------------------+
|                                 KageHound CLI                                     |
|             (kagehound scan | verify | breach-check | darkweb-scout)             |
+-----------------------------------------------------------------------------------+
                                         |
     +-----------------+-----------------+-----------------+-----------------+
     |                 |                 |                 |                 |
     v                 v                 v                 v                 v
[ Layer 1 ]       [ Layer 2 ]       [ Layer 3 ]       [ Layer 4 ]       [ Layer 5 ]
Local Guard      Live Verifier     Breach Radar     DarkWeb Scout      Plugin Hub
- 200+ Regex     - Vendor API      - HIBP Passwords - Ahmia (.onion)   - BaseDetector
- Shannon Ent.     Pingers           (k-Anonymity)  - IntelX Search    - BaseVerifier
- Git Pre-Commit - Verified vs     - HMSL Protocol  - Pastebin Dumps   - BaseScout
  Hook Engine      Dead Status       (scrypt hash)  - Telegram Feeds   - Drop-in /plugins
     |                 |                 |                 |                 |
     +-----------------+-----------------+-----------------+-----------------+
                                         |
                                         v
                     +---------------------------------------+
                     |    Reporting & Dispatch Engine        |
                     |  - Rich Color CLI UI                  |
                     |  - JSON / SARIF (CI/CD Gates)         |
                     |  - Telegram Mobile Alerts             |
                     +---------------------------------------+
```

---

## ⚡ Quick Start

### Installation

```bash
git clone https://github.com/Pencil77/kage-hound.git
cd kage-hound
pip install -e .
```

### 1. Install Pre-Commit Git Shield

Drop an automated shield into any Git repository:
```bash
cd /path/to/my-repo
kagehound hook install
```
Now, whenever you run `git commit`, KageHound automatically inspects staged changes and aborts if raw secrets are detected.

### 2. Scan Filesystem or Staged Changes

```bash
# Scan a folder or codebase
kagehound scan ./my-project

# Only scan staged git changes
kagehound scan --staged

# Enable Shannon entropy detection for unclassified high-entropy tokens
kagehound scan ./my-project --entropy

# Verify live status of discovered credentials
kagehound scan ./my-project --verify
```

### 3. Verify Detected Credentials

```bash
# Verify whether tokens inside a file are active or expired
kagehound verify credentials.json --only-active

# Or test a specific token directly
kagehound verify "ghp_your_personal_access_token_here" --type github
```

### 4. Zero-Knowledge Breach Checks

Zero raw secrets are sent over the wire. Hashes are derived using SHA-1 / scrypt and only truncated 5-character prefixes are queried:
```bash
# Check if a password exists in known breaches (HaveIBeenPwned k-Anonymity)
kagehound check-password "P@ssw0rd123!"

# Check if an API key has appeared in public breaches (HMSL protocol)
kagehound check-secret "sk_live_your_secret_key_here"
```

### 5. Dark Web & Paste Intelligence

Search for target emails, usernames, or domains across Tor `.onion` networks and underground pastes:
```bash
kagehound darkweb --target "security@example.com" --sources ahmia,intelx,pastes
```

### 6. Instant Telegram Push Alerts

Receive instant vibration and sound notifications on mobile when secrets are discovered:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

kagehound scan ./project --notify-telegram
```

---

## 🧩 Supported Signatures & Vendors

KageHound includes 200+ compiled detection patterns covering:
- **Cloud Providers**: AWS (Access Key ID, Secret Key), Google Cloud (Service Account JSONs), Azure (Client Secrets, Storage Keys), Oracle Cloud (OCID, PEM fingerprints).
- **VCS & CI/CD**: GitHub (Classic PAT, Fine-Grained Tokens, OAuth), GitLab, Bitbucket, Docker Hub, NPM, PyPI.
- **Messaging & Communication**: Telegram Bot Tokens, Slack (Bot & User tokens, Webhooks), Discord Bot Tokens, Twilio.
- **Payment & AI Services**: Stripe (Secret & Restricted Keys), OpenAI (`sk-proj-`, `sk-admin-`), Anthropic (`sk-ant-`), OpenRouter.
- **Databases & Cryptography**: MongoDB URIs (`mongodb+srv://`), PostgreSQL/MySQL/Redis connection strings with passwords, RSA/OpenSSH/PGP private keys.

---

## 🔒 Security & Privacy by Design

- **Zero-Knowledge Breach Radar**: Never transmits raw secrets. Queries use 5-character hex prefixes via k-Anonymity.
- **Local-First Execution**: Scanning and entropy analysis occur entirely on your local machine.
- **Safe Output Redaction**: All CLI reports, JSON exports, and notifications automatically redact detected secrets (e.g. `ghp_***a1b2`).

---

## 📄 License

Distributed under the [MIT License](LICENSE).  
Authored by Zoro & Wydia (`mrzoromit3@gmail.com`).
