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
5. **Zero-Knowledge Vault Integration**: Audits **Infisical Vault** secrets against repositories, git commits, and public breach dumps—alerting strictly by **Variable Name** with absolute zero raw secret leakage.
6. **Extensible Plugin Hub**: Drop-in modularity for custom detectors, verifiers, and OSINT scouts.

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
+-----------------------------------------------------------------------------------------------------+
|                                            KageHound CLI                                            |
|                  (kagehound scan | verify | breach-check | darkweb | vault)                         |
+-----------------------------------------------------------------------------------------------------+
                                                   |
      +-----------------+-----------------+-----------------+-----------------+-----------------+
      |                 |                 |                 |                 |                 |
      v                 v                 v                 v                 v                 v
 [ Layer 1 ]       [ Layer 2 ]       [ Layer 3 ]       [ Layer 4 ]       [ Layer 5 ]       [ Layer 6 ]
 Local Guard      Live Verifier     Breach Radar     DarkWeb Scout      Vault Shield       Plugin Hub
 - 200+ Regex     - Vendor API      - HIBP Passwords - Ahmia (.onion)   - Infisical CLI    - BaseDetector
 - Shannon Ent.     Pingers           (k-Anonymity)  - IntelX Search    - Zero-Leakage     - BaseVerifier
 - Git Pre-Commit - Verified vs     - HMSL Protocol  - Pastebin Dumps     In-Memory Match  - BaseScout
   Hook Engine      Dead Status       (scrypt hash)  - Telegram Feeds   - Variable Name    - Drop-in /plugins
      |                 |                 |                 |             Alert Dispatch        |
      +-----------------+-----------------+-----------------+-----------------+-----------------+
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

### 6. Zero-Knowledge Infisical Vault Auditing

Audit secrets managed in your **Infisical Vault** without ever exposing, printing, or serializing their raw secret values. KageHound keeps secret values strictly in volatile memory, searches your codebases and git history, and alerts strictly with the **Variable Name** (e.g., `TELEGRAM_GENERIC_BOT_TOKEN`, `CRON_JOB_TOKEN`):

```bash
# 1. Audit repository files for leaked vault secrets (alerts by Variable Name)
kagehound vault audit ./my-codebase --env dev

# 2. Audit only staged git commits before pushing (pre-commit gate)
kagehound vault audit --staged

# 3. Query zero-knowledge breach feeds (HMSL & HIBP) for any compromised vault secrets
kagehound vault breach-radar --env dev

# 4. Verify live active status of supported credentials in vault
kagehound vault verify --only-active

# 5. Safely inspect tracked variable names and redactions (Zero Raw Values)
kagehound vault list --env dev
```

### 7. Instant Telegram Push Alerts

Receive instant vibration and sound notifications on mobile when secrets are discovered:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

kagehound scan ./project --notify-telegram
kagehound vault audit ./project --notify-telegram
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

- **Vault Zero-Exposure Guarantee**: When auditing Infisical Vault secrets, raw secrets are ingested into volatile memory only. Data models strictly hide the raw secret from `str()` and `repr()`. All CLI displays, JSON summaries, and Telegram alerts alert strictly by **Variable Name** with redacted context.
- **Zero-Knowledge Breach Radar**: Never transmits raw secrets. Queries use 5-character hex prefixes via k-Anonymity (HIBP SHA-1 prefixes and HMSL scrypt prefixes).
- **Local-First Execution**: Scanning and entropy analysis occur entirely on your local machine.
- **Safe Output Redaction**: All CLI reports, JSON exports, and notifications automatically redact detected secrets (e.g. `ghp_***a1b2`).

---

## 📄 License

Distributed under the [MIT License](LICENSE).  
Authored by Zoro & Wydia (`mrzoromit3@gmail.com`).
