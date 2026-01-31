# Detection Report: T1112 - Modify Registry

**Technique:** Modify Registry

---

## 1. Technique Overview

**Technique ID:** T1112
**Technique Name:** Modify Registry
**Tactic:** Defense Rvasion  
**Platform:** Windows

**Description:**  
Adversaries modify Windows Registry keys to alter system behavior, evade detection, and conceal malicious activity. The registry controls critical aspects of Windows functionality, including file visibility, security settings, and execution behavior. By modifying specific registry values, attackers can weaken user awareness and security posture without deploying additional binaries.

In this attack, the registry value HideFileExt is enabled, causing Windows Explorer to hide file extensions. This allows attackers to disguise malicious executables as legitimate files (e.g., invoice.pdf.exe appearing as invoice.pdf), increasing the likelihood of user execution and reducing detection by both users and security controls.

---

## 2. Attack Simulation

**Test Framework:** Atomic Red Team  
**Atomic Test Number:** Test #1  
**Execution Method:** Evil-WinRM from Kali Linux to Windows 10 VM

**Command Executed:**
```reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f
```

**Command Breakdown:**
- `reg` - Windows registry manipulation tool
- `add` - Adds or modifies a registry value
- `HKEY_CURRENT_USER\...\Explorer\Advanced` – Explorer behavior configuration
- `HideFileExt` - Controls file extension visibility
- `/d 1` - Enables hiding of extensions
- `/f` - Forces the change without user confirmation

**Why this is malicious:**  
Hiding file extensions directly supports social engineering and malware execution. Users rely on extensions to distinguish documents from executables. By removing this visibility, attackers can disguise payloads as benign files, increasing success rates of phishing, lateral movement, and persistence. This modification is unnecessary for normal system operation and is rarely changed through the command line in legitimate scenarios.

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
AND process.name: "reg.exe"
AND process.command_line.text: (*HideFileExt* AND *add*)
```

**Detection Logic:**
- Monitors Sysmon Event ID 1 (Process Creation)
- Filters for execution of reg.exe
- Detects registry modification targeting Explorer Advanced settings
- Flags enabling of HideFileExt, which hides file extensions
- Triggers when all indicators align with defense evasion behavior

**Why this works:**  
Most users configure Explorer settings through the GUI, not via registry commands. The HideFileExt value is a well-known attacker favorite for disguising executables. When this change is performed remotely through WinRM with elevated privileges, it strongly indicates malicious post-exploitation activity rather than benign configuration.

---

## 4. Test Results

**Status:** ✅ Successfully Detected

**Alert Details:**
- **Alert Triggered:** Yes, in Kibana Security Alerts interface
- **Timestamp:** January 25, 2026 @ 22:23:13.803
- **Severity:** High
- **Host:** DESKTOP-K1Q1TJA

**Evidence Collected:**
- **Process Name:** reg.exe
- **Command Line:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f`
- **Parent Process:** cmd.exe (intermediate process from WinRM)
- **Grandparent Process:** wsmprovhost.exe (WinRM provider host)
- **User:** Administrator
- **integrity level:** High
- **Execution Context:** Remote execution via Evil-WinRM
- **Working Directory:** `C:\Users\ADMINI~1\AppData\Local\Temp\`
- **Process ID:** 7960

**Observations:**
The process chain wsmprovhost.exe → cmd.exe → reg.exe confirms remote execution through WinRM. The registry path and value modified are specifically associated with file visibility behavior. Execution from a temporary directory further aligns with remote attacker activity rather than interactive user behavior.

---

## 5. Sigma Rule Effectiveness

**Rule Performance:** Effective  
**Alert Accuracy:** True Positive

**Strengths:**
- High-fidelity indicator tied to known attacker behavior
- Minimal false positives due to specific registry value targeting
- Clear visibility into command-line parameters
- Contextual process chain confirms remote execution
- Simple and maintainable detection logic

---

## 6. False Positive Analysis

**Potential False Positives:**

1. **User Customization Scripts**
   - Advanced users modifying Explorer behavior
   - Rare and usually local, not remote

2. **System Hardening Scripts**
   - Automated configuration during system provisioning
   - Typically executed once and documented

3. **Enterprise Configuration Tools**
   - Group Policy or deployment frameworks
   - Should originate from trusted hosts or service accounts

**Likelihood:** Low

**Mitigation Strategies:**
- Exclude known deployment scripts or management servers
- Monitor for remote execution context (WinRM, RDP)
- Baseline legitimate registry modification behavior
- Alert on repeated registry changes across hosts
- Correlate with additional defense evasion indicators

---

## 7. Conclusion

The detection successfully identified a T1112 registry modification used for defense evasion. The rule captured the full attack context, including remote execution, elevated privileges, and a registry change designed to conceal malicious files. This technique is a strong indicator of post-exploitation activity and should be treated as high priority when observed outside authorized administrative workflows.

---

## References

- MITRE ATT&CK T1112: https://attack.mitre.org/techniques/T1112/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112.md