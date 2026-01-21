# APT Detection Framework – SOC-Oriented Lab Project

## Overview

This project presents a practical APT detection framework focused on identifying behaviors associated with APT28 and APT33. Adversary activity is simulated in a controlled lab, Windows telemetry is centrally collected, and observed techniques are translated into MITRE ATT&CK–aligned Sigma detections using the Elastic (ELK) stack.


---

## Goal

The objective of this project is to build and validate a controlled detection environment capable of simulating advanced adversary behavior and converting observed endpoint activity into reliable, behavior-based detections. The project emphasizes visibility assessment, technique-to-detection mapping, and the development of high-confidence detection logic while documenting coverage and limitations.

---

## Architecture

The lab architecture follows a classic **attacker → target → SIEM** flow.

**High-level description:**

* Kali Linux acts as the **attacker machine**
* Windows 10 acts as the **target endpoint**
* Sysmon generates detailed Windows event logs
* Winlogbeat forwards logs securely to Elasticsearch
* Elasticsearch stores and indexes telemetry
* Kibana is used for investigation, visualization, and detection validation

> 📌 A visual architecture diagram will be created using Lucidchart and embedded directly in this README.

---

## Threat Groups Analyzed

### APT28 (Fancy Bear)

APT28 is a well-documented, highly capable threat group known for:

* Spear‑phishing and credential access
* Abuse of Windows-native tools (living-off-the-land)
* Registry manipulation and persistence mechanisms

APT28 techniques are well-suited for detection engineering because they rely heavily on **observable Windows behaviors** rather than custom malware.

### APT33 (Elfin)

APT33 primarily targets:

* Enterprise Windows environments
* Energy and industrial sectors

The group is known for:

* Command-line execution
* Network discovery
* Persistence via scheduled tasks and registry modifications

APT33 provides a complementary detection surface focused on **execution and discovery tactics**.

---

## Technologies Used

| Technology          | Role                                             |
| ------------------- | ------------------------------------------------ |
| Kali Linux          | Attacker virtual machine                         |
| Windows 10          | Target endpoint                                  |
| Evil-WinRM          | Remote command execution and control             |
| Sysmon              | High-fidelity Windows event generation           |
| Winlogbeat          | Log forwarding from Windows to SIEM              |
| Elasticsearch (ELK) | SIEM backend and storage                         |
| Kibana              | Detection, analysis, and visualization interface |
| Sigma Rules         | Generic detection rule format                    |
| MITRE ATT&CK        | Threat modeling and technique mapping            |
| Atomic Red Team     | Attack simulation framework                      |
| VirtualBox          | Virtualization platform                          |
| Ubuntu              | Host operating system                            |

---

## Project Structure

```text
.
├── SigmaRules/        # Sigma YAML detection rules
├── Logs/              # Attack simulation logs
├── Reports/           # Detection reports per technique (PDF/Markdown)
└── README.md          # Project documentation
```

---

## Getting Started – Installation & Configuration (High Level)

### 1️⃣ Virtualization Setup

* Install VirtualBox on Ubuntu host
* Deploy Kali Linux and Windows 10 virtual machines
* Configure network bridging between VMs

### 2️⃣ Windows Endpoint Setup

* Install Sysmon with a tuned configuration
* Install and configure Winlogbeat
* Forward logs securely to Elasticsearch

### 3️⃣ SIEM Backend Setup

* Install Elasticsearch and Kibana
* Enable security and TLS
* Validate log ingestion from Winlogbeat through setting up index patterns 

### 4️⃣ Attacker Tooling

* Configure Kali Linux
* Configure Evil-WinRM for remote access
* Prepare Atomic Red Team scripts for TTP simulation

---

## Testing & Detection Procedure

### Step 1 – Establish a Connected Lab

* Verify network connectivity between VMs
* Ensure logs are visible in Kibana

### Step 2 – Attack Simulation

From Kali Linux:

```bash
evil-winrm -i <windows_ip> -u <username> -p <password>
```

* Gain remote command execution
* Execute Atomic Red Team tests mapped to selected MITRE techniques

### Step 3 – Telemetry Analysis

* Observe generated events in Kibana
* Identify reliable detection fields and patterns

### Step 4 – Detection Engineering

* Write Sigma rules based on observed behavior
* Map each rule to MITRE ATT&CK
* Reduce false positives through tuning

### Step 5 – Documentation

* Document each technique:

  * Attack description
  * Logs generated
  * Detection logic

---

## Outcomes

* Functional APT detection lab
* MITRE-aligned detection rules
* Clear visibility into attacker behavior on Windows endpoints

---

## Results & Findings

> *To be completed after full testing and rule validation.*

---

## Future Enhancements

> *To be completed in later project phases.*

---

## Disclaimer

**Educational Use Only**

This project is intended strictly for **educational and defensive security research purposes**. All attacks and simulations are performed in a **controlled, isolated lab environment**.

**Do NOT test these techniques on production systems or networks without explicit authorization.**