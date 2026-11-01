# SOC Investigation: Suspicious Document to Suspected Data Exfiltration

**TryHackMe lab case study | Windows endpoint investigation | MITRE ATT&CK**

> Educational simulation, not a production incident or an attributed APT campaign. This write-up is based on my investigation notes; raw event exports, packet captures, and screenshots are not included. Conclusions below distinguish reported observations from hypotheses. External indicators are lab context only, not a current threat-intelligence blocklist.

| Field | Value |
| --- | --- |
| Case reference | LAB-2026-1022 |
| Investigation date | October 22, 2026 |
| Event timezone | Not recorded; timestamps preserved as recorded |
| Scope | THM-MSMITH and THM-SREYES |
| Assessment | Suspected multi-stage compromise with potential source-code exposure |
| Documentation status | Analysis complete; response steps are recommendations only |

**TL;DR:** I investigated a simulated two-host intrusion (THM-MSMITH and THM-SREYES) in Sysmon telemetry across a ~15-minute window: suspicious Word document, encoded PowerShell, credential-store enumeration, service-based persistence, and suspected source-code staging and exfiltration. I mapped 10 ATT&CK techniques and rated each as supported, conditional or unconfirmed, and triaged a separate Office alert (Case 6352) as legitimate activity.

**Tools:** Sysmon, MITRE ATT&CK, Windows event and process analysis

## Executive summary

The investigation covers a Word document followed by encoded PowerShell execution on a marketing workstation, credential-store enumeration, and suspicious service creation on a second host. Subsequent activity includes outbound connections and a 7-Zip command targeting the NeuralNexus build directory.

Taken together, these observations warrant high-priority escalation and containment in a production environment. They support a plausible chain from malicious document execution to data staging. However, the evidence I reviewed does not independently establish the email delivery path, extraction of plaintext passwords, the exact lateral-movement protocol, domain fronting, or successful data exfiltration.

**Potential business impact:** exposure of proprietary source code and misuse of a service account. The volume of data transferred and the full scope of affected systems remain unknown.

## Skills demonstrated

- Reconstructing a cross-host investigation timeline.
- Interpreting suspicious process command lines and network telemetry.
- Separating suspicious Office execution from potentially benign Office activity.
- Mapping behavior to ATT&CK without treating technique labels as proof.
- Identifying evidence gaps and proposing containment and recovery actions.

## Investigation timeline

All events below come from my investigation notes; raw logs are not included in this repository. Times refer to October 22, 2026.

| Time | Host | Reported observation | Assessment / limitation |
| --- | --- | --- | --- |
| 16:51:18.746 | THM-MSMITH | Word opened `Q3_PressKit_Feedback.docm`; hidden encoded PowerShell followed | Suspicious document execution. Macro execution and phishing origin need supporting artifacts. |
| 16:51:21.746 | THM-MSMITH | Outbound connections to `paylink-cdn[.]thm:8067`, reportedly recurring every 30 seconds | Suspected C2; a sequence of network events is needed to substantiate periodicity. |
| 16:51:22.746 | THM-MSMITH | `vaultcmd.exe /listcreds:"Windows Credentials"` | Credential-store enumeration; plaintext credential extraction is not established. |
| 16:58:52.746 | THM-SREYES | `SvcUpdate` service reportedly created as LocalSystem; notes associate `TRYHATME\svc-mktshare` | Suspected service-based persistence and cross-host compromise; authentication and service records are required. |
| 17:03:52.746 | THM-SREYES | SYSTEM-context PowerShell connected to `104[.]18[.]32[.]47:443` | Suspicious in context; destination IP and port alone do not establish HTTPS, C2, or domain fronting. |
| 17:05:43.746–17:06:48.746 | THM-SREYES | 7-Zip targeted source code; later connections to `45[.]147[.]230[.]131:8067` reportedly repeated every 30 seconds | Suspected staging and exfiltration; archive creation success, transmitted contents, and transfer completion need corroboration. |

## Technical findings

### 1. Suspicious document and PowerShell execution

The notes associate `TRYHATME\m.smith` with opening `Q3_PressKit_Feedback.docm` from Downloads on `THM-MSMITH.tryhatmestudios.thm`.

Reported command excerpt:

```text
powershell.exe -NoP -W Hidden -Enc JABzAHQAYQBnAGUAcgAgAD0A...
```

The encoded value is truncated, so a complete independent decode is not possible from this excerpt. My notes describe a downloader that saves `svchost_update.ps1` under the user's temporary directory and starts a second hidden PowerShell process with execution-policy bypass. This is a description of the reported payload behavior, not a verified decoded script.

**Evidence to retain:** full command line, process GUID and parent GUID, executable paths, document hash, PowerShell script-block records if available, and the downloaded script. An encoded command alone does not identify the PowerShell process as 32-bit.

**Delivery limitation:** opening a document from Downloads does not establish that it arrived as a phishing attachment. Email headers, attachment records, or delivery logs would resolve this.

### 2. Separate Office alert: Case 6352

I classified Word spawning `ai.exe` and loading `WordCombinedFloatieLreOnline.onnx` as legitimate Office activity.

That disposition should be supported by the executable's full path, trusted signature, expected command line, and comparison with normal Office behavior. A familiar filename alone is insufficient. This alert can be benign while a separate Word-to-PowerShell branch on the same host is malicious; closing one alert does not clear the host.

### 3. Credential-store enumeration

Reported command:

```text
"C:\Windows\Sysnative\vaultcmd.exe" /listcreds:"Windows Credentials"
```

This is consistent with enumeration of Windows Credential Manager entries. It does not, by itself, prove extraction of plaintext passwords or show that `svc-mktshare` credentials were obtained through this action. Subsequent authentication activity must be correlated with the source host and account.

### 4. Suspicious Windows service on a second host

The notes report service `SvcUpdate` on `THM-SREYES.tryhatmestudios.thm`, configured to run as LocalSystem with this command:

```text
cmd.exe /c start /b powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\svchost_update.ps1
```

A service launching hidden PowerShell from a temporary directory is suspicious in this context. Confirm service installation and configuration, start type, actual process execution, and the initiating account. Correlate service events with authentication records and network activity before asserting how the attacker moved between hosts. The service command is not itself a service-registration command.

### 5. Network activity: Case 6358

The reported SYSTEM-context connection to `104[.]18[.]32[.]47:443` requires process and destination context. This address may belong to Cloudflare infrastructure, but ownership has not been independently established here. Even verified CDN ownership would not prove domain fronting.

Resolve the contacted hostname and examine available proxy, TLS, and HTTP metadata. Domain-fronting attribution requires evidence of the relevant routing behavior, such as an SNI/HTTP Host mismatch, rather than a CDN IP alone.

Sysmon Event ID 3 provides process-associated connection metadata. It does not reveal transferred file contents or establish that a connection successfully exfiltrated an archive.

### 6. Source-code archiving and suspected exfiltration

Reported command:

```text
"C:\Program Files\7-Zip\7z.exe" a -mx=1 C:\Windows\Temp\nx_build_beta.7z C:\Dev\NeuralNexus\Build\*
```

This command attempts to archive the build directory into `nx_build_beta.7z`. Confirm the resulting file, size, creation timestamp, and contents before declaring successful collection.

The later recurring connections to `45[.]147[.]230[.]131:8067` are consistent with possible C2 or data transfer. Establishing exfiltration requires additional evidence such as script logic linking archive reads to sends, upload/proxy records, or packet-level evidence. Thirty-second periodicity alone does not prove chunking, scheduled exfiltration, or successful delivery.

## MITRE ATT&CK assessment

“Supported” below means consistent with my notes, not independently validated against original telemetry.

| Technique | Assessment | Basis / missing evidence |
| --- | --- | --- |
| T1059.001 — PowerShell | Supported | Reported PowerShell execution and command lines. |
| T1204.002 — Malicious File | Conditional | Document interaction reported; malicious content and execution chain need confirmation. |
| T1566.001 — Spearphishing Attachment | Unconfirmed | Email delivery evidence absent. |
| T1555.004 — Windows Credential Manager | Supported for enumeration | VaultCmd command; successful secret extraction not established. |
| T1543.003 — Windows Service | Supported by narrative | Service creation reported; corroborate configuration and execution. |
| T1560.001 — Archive via Utility | Supported for attempted archiving | 7-Zip command; successful output not independently verified. |
| T1071.001 — Web Protocols | Conditional | Requires application-protocol evidence; port 443 alone is insufficient. |
| T1090.004 — Domain Fronting | Unconfirmed | No fronting-specific evidence in my notes. |
| T1568 — Dynamic Resolution | Unsupported by my evidence | Periodic connections do not establish dynamic resolution. |
| T1029 — Scheduled Transfer | Unconfirmed | Need evidence tying periodic transfers to exfiltrated data. |

No threat actor or APT attribution is made. A multi-stage attack alone is insufficient for that conclusion.

## Investigation indicators

Addresses are defanged. These values identify the simulated case and should not be treated as a production blocklist.

| Type | Value | Context |
| --- | --- | --- |
| Document | `Q3_PressKit_Feedback.docm` | Suspected entry document |
| Script | `svchost_update.ps1` | Reported downloaded/executed script |
| Archive | `nx_build_beta.7z` | Reported archive destination |
| Domain | `paylink-cdn[.]thm` | Reported downloader/C2 destination |
| IP and port | `45[.]147[.]230[.]131:8067` | Suspected C2/exfiltration destination in the lab |
| IP and port | `104[.]18[.]32[.]47:443` | Investigative lead; not independently malicious |
| Service | `SvcUpdate` | Reported suspicious service |
| Account | `TRYHATME\svc-mktshare` | Account associated with second-host activity in notes |

File hashes were not provided. Filenames and service names are useful pivots but are not unique malware identifiers.

## Recommended response — not a record of completed actions

1. **Escalate and contain:** escalate the suspected multi-host compromise; isolate affected hosts under the incident-response playbook, accounting for the server's business function.
2. **Preserve evidence:** collect relevant logs, process/network state, service configuration, suspicious files and hashes, and volatile evidence where feasible. Do not delay urgent containment solely to collect evidence.
3. **Contain account misuse:** investigate both named accounts; rotate affected credentials and invalidate relevant sessions/tickets as supported. Coordinate service-account rotation with dependent services.
4. **Restrict confirmed malicious communication:** apply scoped blocks to validated destinations and review egress policy. Do not blanket-block shared CDN infrastructure or all traffic on a port solely because it appears in this case.
5. **Eradicate after preservation:** disable/remove confirmed malicious persistence and quarantine payloads under the playbook. Consider rebuilding compromised hosts if integrity cannot be established.
6. **Hunt for wider impact:** pivot across hosts using script hashes, service configuration, process ancestry, account activity, and destination telemetry.
7. **Validate recovery:** verify persistence removal, credential rotation, business-service health, and absence of recurring malicious activity over an agreed monitoring period.

**Closure criteria:** documented scope, completed containment and eradication, recovery validation, assessment of potential data loss, and approval by the incident owner. These criteria are listed for a production response and are not claimed as completed here.

## Limitations

- Raw event exports, packet captures and screenshots are not included, so the timeline cannot be re-verified from this repository.
- The encoded PowerShell command is truncated in this write-up; a full independent decode requires the complete command line and script.
- Authentication, service-installation and archive-metadata records would be needed to confirm the cross-host sequence and the exfiltration.

## References

- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK: Windows Credential Manager — T1555.004](https://attack.mitre.org/techniques/T1555/004/)
- [MITRE ATT&CK: Windows Service — T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK: Domain Fronting — T1090.004](https://attack.mitre.org/techniques/T1090/004/)
- [MITRE ATT&CK: Dynamic Resolution — T1568](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK: Scheduled Transfer — T1029](https://attack.mitre.org/techniques/T1029/)
