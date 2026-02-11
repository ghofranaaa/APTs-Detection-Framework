# Detection Report: T1105 – Ingress Tool Transfer

**Technique:** Ingress Tool Transfer

---

## 1. Technique Overview

**Technique ID:** T1105
**Technique Name:** Ingress Tool Transfer
**Tactic:** Command and Control  
**Platform:** Windows

**Description:**  
Ingress Tool Transfer enables adversaries to introduce additional tooling into a compromised system after initial access. These tools may include credential dumpers, persistence mechanisms, or C2 implants. By using built-in utilities such as BITSAdmin, attackers can perform stealthy downloads that resemble legitimate background activity.

---

## 2. Attack Simulation

**Test Framework:** Atomic Red Team  
**Atomic Test Number:** Test #9  
**Execution Method:** Evil-WinRM from Kali Linux to Windows 10 VM

**Command Executed:**
```  bitsadmin.exe /transfer qcxjb7 /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt %temp%\Atomic-license.txt

```

**Command Breakdown:**
- `bitsadmin.exe` - Native Windows file transfer utility
- `/transfer` - Initiates a new download job
- `https://raw.githubusercontent.com` - External hosting service context
- `%TEMP%` - Payload staging directory

**Why this is malicious:**  
Although BITSAdmin is a legitimate tool, its usage for downloading executables or scripts from external servers is a common attacker tradecraft. The combination of remote file retrieval, execution from a temporary directory, and high-integrity context strongly suggests post-compromise tool staging rather than benign administration.

---

## 3. Detection Configuration

**SIEM Platform:** Elastic Stack (Elasticsearch + Kibana)  
**Data Source:** Sysmon Event ID 1 (Process Creation)  
**Collection Agent:** Winlogbeat  
**Event Channel:** Microsoft-Windows-Sysmon/Operational

**Kibana Detection Rule:**
```kql
winlog.channel: "Microsoft-Windows-Sysmon/Operational"
AND event.code: "1"
AND process.name: "bitsadmin.exe"
AND process.command_line.text: "*\/transfer*"
AND process.command_line.text: "*https*"
```

**Detection Logic:**
- Monitors Sysmon Event ID 1 (Process Creation)
- Identifies execution of BITSAdmin
- Detects remote file download parameters
- Flags external ingress activity aligned with T1105

**Why this works:**  
BITSAdmin is rarely used interactively on modern systems. When executed manually or via scripts—especially from cmd.exe and writing into %TEMP%—it is a strong indicator of malicious ingress activity. This behavior is commonly observed during payload staging phases of real-world attacks.

---

## 4. Test Results

**Status:** ✅ Successfully Detected

**Alert Details:**
- **Alert Triggered:** Yes, in Kibana Security Alerts interface
- **Timestamp:** Feb 1, 2026 @ 23:37:24.651
- **Severity:** High
- **Host:** DESKTOP-K1Q1TJA

**Evidence Collected:**
- **Process Name:** bitsadmin.exe
- **Command Line:** `bitsadmin.exe /transfer qcxjb7 /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt %temp%\Atomic-license.txt`
- **Parent Process:** cmd.exe
- **User:** Administrator
- **integrity level:** High
- **Destination Directory:** `%TEMP%`
- **Process ID:** 3336

**Observations:**
The download was initiated via a command-line process, stored in a temporary directory, and sourced from an external domain. This aligns closely with attacker ingress patterns rather than routine administrative behavior.

---

## 5. Sigma Rule Effectiveness

**Rule Performance:** Effective  
**Alert Accuracy:** True Positive

**Strengths:**
- Leverages native Windows utility abuse
- Effective against fileless-to-file staging transitions
- High signal-to-noise ratio

---

## 6. False Positive Analysis

**Potential False Positives:**

1. **Internal IT automation using BITS**

2. **Legitimate IT scripts using BITS for downloads**

3. **Software update mechanisms**

**Likelihood:** Medium

**Mitigation Strategies:**
- Exclude known update servers or domains
- Suppress alerts for signed scripts or known admin hosts
- Alert on chained or repeated discovery across hosts
- Correlate with subsequent execution events (T1059, T1204)

---

## 7. Conclusion

This detection reliably identifies Ingress Tool Transfer activity performed via BITSAdmin. By focusing on command-line–based BITS job creation and external downloads, the rule provides high-confidence detection of attacker tool staging while remaining resilient to basic obfuscation techniques.

---

## References

- MITRE ATT&CK T1033: https://attack.mitre.org/techniques/T1105/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105.md