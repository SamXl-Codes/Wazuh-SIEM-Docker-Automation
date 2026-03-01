# Wazuh SIEM Docker Automation — Larkspur Retail Group

**Module:** B9CY110 — Communication and Network Security  
**Assessment:** CA1 — Endpoint Security Assessment (60%)  
**Student:** Samuel Oluwasegun Ogunlusi | 20086108 | DBS MSc Cybersecurity  

---

## Overview

This repository contains all artefacts for the CA1 endpoint security assessment. The project deploys Wazuh 4.14.3 as a SIEM platform across an isolated VMware lab with one Windows endpoint and one Linux endpoint, implements five custom MITRE ATT&CK-mapped detection rules, executes four attack simulations, and demonstrates automated remediation via a Dockerised Flask application called `larkspur_automation`.

---

## Lab Architecture

| Host | OS | IP | Role |
|---|---|---|---|
| wazuh-manager | Ubuntu 24.04 | 192.168.60.143 | Wazuh SIEM, Indexer, Dashboard, Filebeat, Docker |
| linux-endpoint | Ubuntu 24.04.1 | 192.168.60.140 | Agent 002 — auditd, FIM, auth.log |
| WIN-ENDPOINT | Windows 11 Pro | 192.168.60.1 | Agent 003 — Sysmon, Script Block Logging |

Network: VMware VMnet2 (host-only, 192.168.60.0/24, no internet access)

---

## Detection Rules

| Rule ID | Description | MITRE ATT&CK | Level |
|---|---|---|---|
| 100001 | Windows logon failures | T1110 — Brute Force | 10 |
| 100002 | SSH brute-force | T1110 — Brute Force | 10 |
| 100003 | Suspicious PowerShell execution | T1059.001 — PowerShell | 12 |
| 100004 | Cron persistence | T1053.003 — Cron | 8 |
| 100005 | Non-existent user SSH | T1078 — Valid Accounts | 8 |

---

## Repository Structure

```
.
├── README.md
├── docker/
│   ├── docker-compose.yml       # larkspur_automation service definition
│   └── app.py                   # Flask webhook, audit, rollback application
├── rules/
│   └── local_rules.xml          # Wazuh custom detection rules (100001-100005)
├── config/
│   ├── sysmon-config.xml        # SwiftOnSecurity Sysmon configuration (hash reference)
│   └── auditd.rules             # Linux auditd rule set
└── evidence/
    └── screenshots/             # Full-resolution evidence screenshots
```

---

## Quick Start — Reproduce the Demo

### 1. Start Wazuh services
```bash
sudo systemctl start wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl status wazuh-manager
```

### 2. Start Docker automation stack
```bash
cd /opt/sec-automation
docker compose up -d
docker ps
curl http://127.0.0.1:5001/audit
```

### 3. Run attack simulations

**C1 — PowerShell encoded command (WIN-ENDPOINT PowerShell as Admin):**
```powershell
$e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output HelloFromLarkspur'))
powershell.exe -EncodedCommand $e
```

**C2 — Windows brute-force (WIN-ENDPOINT PowerShell as Admin):**
```powershell
for ($i=1; $i -le 6; $i++) { net use \\localhost\IPC$ /user:LabUser WRONGPASSWORD 2>&1; Start-Sleep 1 }
```

**C3 — SSH brute-force (linux-endpoint terminal):**
```bash
for i in 1 2 3 4 5 6; do ssh -o StrictHostKeyChecking=no fakeuser@192.168.60.140; sleep 1; done
```

**C4 — Cron persistence (linux-endpoint with sudo):**
```bash
sudo bash -c 'echo "* * * * * root echo cron_beacon >> /tmp/cron_test.log" > /etc/cron.d/larkspur-persist'
```

### 4. Trigger automated remediation
```bash
# Block IP
curl -X POST http://127.0.0.1:5001/webhook \
  -H "Content-Type: application/json" \
  -d '{"rule":{"id":"100002","level":10},"agent":{"name":"linux-endpoint"},"data":{"srcip":"192.168.60.99"}}'

# View audit trail
curl http://127.0.0.1:5001/audit

# Rollback
curl -X POST http://127.0.0.1:5001/rollback \
  -H "Content-Type: application/json" \
  -d '{"action":"unblock_ip","target":"192.168.60.99"}'
```

---

## AI Tool Disclosure

Claude by Anthropic was used to assist with drafting the written report and document formatting. All laboratory implementation, technical configuration, attack simulation, and evidence capture were carried out personally.
