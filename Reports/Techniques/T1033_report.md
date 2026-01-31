# Detection Report: T1033 - System Owner/User Discovery

**Technique:** System Owner/User Discovery

---

## 1. Technique Overview

**Technique ID:** T1033
**Technique Name:** System Owner/User Discovery
**Tactic:** Discovery  
**Platform:** Windows

**Description:**  
System Owner/User Discovery is a discovery technique used by adversaries to identify the current user, enumerate user accounts, and determine which sessions are active on a compromised system. This information allows attackers to understand their execution context, assess privilege levels, and evaluate whether the system is actively in use.

The Windows operating system provides several built-in utilities that expose user and session information. These tools are commonly abused by attackers because they require no additional payloads and closely resemble legitimate administrative activity.

---

## 2. Attack Simulation

**Test Framework:** Atomic Red Team  
**Atomic Test Number:** Test #1  
**Execution Method:** Evil-WinRM from Kali Linux to Windows 10 VM

**Command Executed:**
```    "cmd.exe /C whoami"
```

**Command Breakdown:**
- `whoami` - Displays the current user and security context

**Why this is malicious:**  
While this commands are legitimate administrative tools, its execution in sequence is indicative of attacker reconnaissance. Enumerating user identities and session information allows adversaries to determine whether they have administrative access, whether other users are logged in, and whether the system is suitable for interactive activity or lateral movement. This behavior commonly appears shortly after initial access and is unnecessary for normal system operation outside of troubleshooting scenarios.

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
AND process.name: "cmd.exe"
AND process.command_line.text: (*whoami* AND *wmic\ useraccount* AND *quser* AND *qwinsta*)
```

**Detection Logic:**
- Monitors Sysmon Event ID 1 (Process Creation)
- Filters for execution of cmd.exe
- Identifies command-line arguments associated with user and session discovery
- Detects chained or scripted reconnaissance activity
- Flags discovery behavior aligned with T1033

**Why this works:**  
User discovery commands are rarely executed together during routine user activity. When multiple enumeration utilities are chained in a single command line or executed rapidly in succession, it strongly indicates post-exploitation reconnaissance rather than benign administration. The presence of these commands within a remote or high-integrity execution context further increases detection confidence.

---

## 4. Test Results

**Status:** ✅ Successfully Detected

**Alert Details:**
- **Alert Triggered:** Yes, in Kibana Security Alerts interface
- **Timestamp:** Jan 26, 2026 @ 18:01:19.917
- **Severity:** High
- **Host:** DESKTOP-K1Q1TJA

**Evidence Collected:**
- **Process Name:** cmd.exe
- **Command Line:** `cmd.exe /C whoami`
- **Parent Command Line:** Chained execution of whoami, wmic useraccount, quser, and qwinsta
- **User:** Administrator
- **integrity level:** High
- **Execution Context:** Local command execution
- **Working Directory:** `C:\Users\ADMINI~1\AppData\Local\Temp\`
- **Process ID:** 3704

**Observations:**
The parent cmd.exe process executed multiple user and session discovery commands in a single chained command line. This behavior is consistent with automated reconnaissance rather than interactive administration. High-integrity execution and use of temporary directories further support a post-exploitation context.

---

## 5. Sigma Rule Effectiveness

**Rule Performance:** Effective  
**Alert Accuracy:** True Positive

**Strengths:**
- Detects multiple discovery utilities commonly abused by attackers
- Leverages command-line visibility for high context
- Uses native Windows tooling indicators aligned with ATT&CK T1033
- Easy to maintain and extend with additional discovery commands

---

## 6. False Positive Analysis

**Potential False Positives:**

1. **Legitimate Administrative Troubleshooting**
   - IT staff checking user sessions or access issues
   - Typically documented and time-bound

2. **Helpdesk or Support Activity**
   - Helpdesk or Support Activity
   - Usually interactive, not scripted

3. **Inventory or Monitoring Scripts**
   - Periodic user enumeration
   - Executed by known service accounts or management hosts

**Likelihood:** Medium

**Mitigation Strategies:**
- Exclude known administrative hosts or service accounts
- Monitor for execution shortly after initial access
- Alert on chained or repeated discovery across hosts
- Combine with subsequent credential access or lateral movement signals

---

## 7. Conclusion

The detection successfully identified System Owner/User Discovery activity consistent with T1033. The observed behavior reflects early-stage attacker reconnaissance aimed at understanding user context and session activity. While individual commands may be benign, their combined execution pattern provides strong evidence of post-exploitation discovery and should be treated as a meaningful indicator when observed outside approved administrative workflows.

---

## References

- MITRE ATT&CK T1033: https://attack.mitre.org/techniques/T1033/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033.md